#!/usr/bin/env bun
/**
 * Live Sync Engine Test
 *
 * Tests wallet-sync.js against a real Salvium daemon.
 * Syncs a range of blocks and reports:
 *   - Binary bulk fetch vs JSON fallback path
 *   - Adaptive batch sizing behavior
 *   - Throughput (blocks/sec)
 *   - Transaction scanning (miner_tx / protocol_tx / regular)
 *
 * Usage:
 *   bun test/sync-live.test.js [--daemon URL] [--start HEIGHT] [--blocks N]
 *
 * Defaults:
 *   --daemon  http://core2.whiskymine.io:19081
 *   --start   1000
 *   --blocks  200
 */

import { WalletSync, SYNC_STATUS, DEFAULT_BATCH_SIZE } from '../src/wallet-sync.js';
import { MemoryStorage, WalletOutput } from '../src/wallet-store.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { randomScalar, scalarMultBase, initCrypto } from '../src/crypto/index.js';
import { bytesToHex } from '../src/address.js';

// ── CLI args ──────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
function getArg(name, fallback) {
  const idx = args.indexOf(name);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : fallback;
}

const DAEMON_URL = getArg('--daemon', 'http://core2.whiskymine.io:19081');
const START_HEIGHT = parseInt(getArg('--start', '1000'), 10);
const BLOCK_COUNT = parseInt(getArg('--blocks', '200'), 10);

// ── Stats ─────────────────────────────────────────────────────────────────────
const stats = {
  binaryBatches: 0,
  jsonBatches: 0,
  batchSizes: [],
  msPerBlock: [],
  blocksPerSec: [],
  events: { newBlock: 0, syncProgress: 0, batchComplete: 0 },
  errors: [],
  txCounts: { minerTx: 0, protocolTx: 0, regular: 0 },
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function generateTestKeys() {
  // Generate random wallet keys for scanning (won't find outputs, but exercises the code)
  const viewSec = randomScalar();
  const spendSec = randomScalar();
  const spendPub = scalarMultBase(spendSec);
  return {
    viewSecretKey: bytesToHex(viewSec),
    spendSecretKey: bytesToHex(spendSec),
    spendPublicKey: bytesToHex(spendPub),
  };
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log('=== Live Sync Engine Test ===\n');
  console.log(`Daemon:  ${DAEMON_URL}`);
  console.log(`Range:   ${START_HEIGHT} → ${START_HEIGHT + BLOCK_COUNT}`);
  console.log(`Initial batch size: ${DEFAULT_BATCH_SIZE}\n`);

  // 1. Connect to daemon
  const daemon = new DaemonRPC({ url: DAEMON_URL, timeout: 30000 });
  const info = await daemon.getInfo();
  if (!info.success) {
    console.error('Failed to connect to daemon:', info.error);
    process.exit(1);
  }
  const chainHeight = info.result.height;
  console.log(`Daemon height: ${chainHeight}`);
  if (START_HEIGHT + BLOCK_COUNT > chainHeight) {
    console.error(`Requested range exceeds chain height (${chainHeight}). Adjust --start or --blocks.`);
    process.exit(1);
  }

  // 2. Quick sanity: test binary endpoint availability
  console.log('\nTesting binary endpoint (getBlocksByHeight)...');
  try {
    const binTest = await daemon.getBlocksByHeight([START_HEIGHT]);
    if (binTest.success && binTest.result.blocks?.length === 1) {
      console.log('  Binary endpoint: AVAILABLE');
      const blk = binTest.result.blocks[0];
      console.log(`  Block blob size: ${blk.block?.length || blk.block?.byteLength || '?'} bytes`);
      console.log(`  Embedded txs: ${blk.txs?.length || 0}`);
    } else {
      console.log('  Binary endpoint: NOT AVAILABLE (will use JSON fallback)');
    }
  } catch (e) {
    console.log(`  Binary endpoint: ERROR — ${e.message}`);
  }

  // 3. Create sync engine with test wallet
  const storage = new MemoryStorage();
  await storage.open();
  await storage.setSyncHeight(START_HEIGHT);

  const keys = generateTestKeys();
  const sync = new WalletSync({
    storage,
    daemon,
    keys,
    batchSize: DEFAULT_BATCH_SIZE,
  });

  // 4. Wire up events
  sync.on('newBlock', (data) => {
    stats.events.newBlock++;
    if (data.hasMinerTx) stats.txCounts.minerTx++;
    if (data.hasProtocolTx) stats.txCounts.protocolTx++;
    stats.txCounts.regular += data.txCount || 0;
  });

  sync.on('syncProgress', (data) => {
    stats.events.syncProgress++;
    // Log every 50 blocks
    if (stats.events.syncProgress % 50 === 0) {
      console.log(`  Progress: ${data.currentHeight} / ${data.targetHeight} (${data.percentComplete.toFixed(1)}%)`);
    }
  });

  sync.on('batchComplete', (data) => {
    stats.events.batchComplete++;
    stats.batchSizes.push(data.batchSize);
    stats.msPerBlock.push(data.msPerBlock);
    stats.blocksPerSec.push(data.blocksPerSec);
  });

  sync.on('syncError', (error) => {
    stats.errors.push(error.message);
  });

  // Override target height so we only sync BLOCK_COUNT blocks
  // We do this by patching daemon.getInfo to return our target
  const originalGetInfo = daemon.getInfo.bind(daemon);
  const targetHeight = START_HEIGHT + BLOCK_COUNT;
  daemon.getInfo = async function () {
    const result = await originalGetInfo();
    if (result.success) {
      result.result.height = targetHeight;
    }
    return result;
  };

  // 5. Run sync
  console.log(`\nSyncing ${BLOCK_COUNT} blocks (${START_HEIGHT} → ${targetHeight})...\n`);
  const syncStart = Date.now();

  try {
    await sync.start(START_HEIGHT);
  } catch (e) {
    console.error(`\nSync failed: ${e.message}`);
    if (e.stack) console.error(e.stack);
  }

  const syncElapsed = Date.now() - syncStart;

  // 6. Report results
  console.log('\n=== Results ===\n');
  console.log(`Status: ${sync.status}`);
  console.log(`Time: ${(syncElapsed / 1000).toFixed(1)}s`);
  console.log(`Blocks synced: ${stats.events.newBlock}`);
  console.log(`Overall throughput: ${(stats.events.newBlock / (syncElapsed / 1000)).toFixed(1)} blocks/sec`);

  console.log('\n--- Batch Sizing ---');
  console.log(`Total batches: ${stats.events.batchComplete}`);
  if (stats.batchSizes.length > 0) {
    console.log(`Batch size range: ${Math.min(...stats.batchSizes)} → ${Math.max(...stats.batchSizes)}`);
    const avgBatch = stats.batchSizes.reduce((a, b) => a + b, 0) / stats.batchSizes.length;
    console.log(`Average batch size: ${avgBatch.toFixed(1)}`);
    console.log(`Batch size progression: [${stats.batchSizes.join(', ')}]`);
  }

  console.log('\n--- Per-Block Timing ---');
  if (stats.msPerBlock.length > 0) {
    const avgMs = stats.msPerBlock.reduce((a, b) => a + b, 0) / stats.msPerBlock.length;
    console.log(`Average ms/block: ${avgMs.toFixed(1)}`);
    console.log(`Min ms/block: ${Math.min(...stats.msPerBlock)}`);
    console.log(`Max ms/block: ${Math.max(...stats.msPerBlock)}`);
    const avgBps = stats.blocksPerSec.reduce((a, b) => a + b, 0) / stats.blocksPerSec.length;
    console.log(`Average blocks/sec (batch): ${avgBps.toFixed(1)}`);
  }

  console.log('\n--- Transactions ---');
  console.log(`Miner TXs processed: ${stats.txCounts.minerTx}`);
  console.log(`Protocol TXs processed: ${stats.txCounts.protocolTx}`);
  console.log(`Regular TXs processed: ${stats.txCounts.regular}`);

  console.log('\n--- Events ---');
  console.log(`newBlock events: ${stats.events.newBlock}`);
  console.log(`syncProgress events: ${stats.events.syncProgress}`);
  console.log(`batchComplete events: ${stats.events.batchComplete}`);

  if (stats.errors.length > 0) {
    console.log('\n--- Errors ---');
    for (const err of stats.errors) {
      console.log(`  ${err}`);
    }
  }

  // 7. Verify
  console.log('\n--- Verification ---');
  const finalHeight = await storage.getSyncHeight();
  const expected = targetHeight;
  const pass = sync.status === SYNC_STATUS.COMPLETE && finalHeight >= expected - 1;
  console.log(`Final sync height: ${finalHeight}`);
  console.log(`Expected: >= ${expected - 1}`);
  console.log(`Status: ${pass ? 'PASS' : 'FAIL'}`);

  await storage.close();

  if (!pass) {
    console.log('\nTest FAILED');
    process.exit(1);
  } else {
    console.log('\nTest PASSED');
    process.exit(0);
  }
}

await initCrypto();
main().catch(e => {
  console.error('Fatal:', e);
  process.exit(1);
});
