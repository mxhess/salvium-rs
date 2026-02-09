#!/usr/bin/env bun
/**
 * Live Sync Fallback Test
 *
 * Tests the JSON fallback path by disabling binary endpoint.
 * Compares performance against binary path.
 *
 * Usage:
 *   bun test/sync-live-fallback.test.js [--daemon URL] [--start HEIGHT] [--blocks N]
 */

import { WalletSync, SYNC_STATUS, DEFAULT_BATCH_SIZE } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { randomScalar, scalarMultBase } from '../src/crypto/index.js';
import { bytesToHex } from '../src/address.js';

const args = process.argv.slice(2);
function getArg(name, fallback) {
  const idx = args.indexOf(name);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : fallback;
}

const DAEMON_URL = getArg('--daemon', 'http://core2.whiskymine.io:19081');
const START_HEIGHT = parseInt(getArg('--start', '1000'), 10);
const BLOCK_COUNT = parseInt(getArg('--blocks', '100'), 10);

function generateTestKeys() {
  const viewSec = randomScalar();
  const spendSec = randomScalar();
  const spendPub = scalarMultBase(spendSec);
  return {
    viewSecretKey: bytesToHex(viewSec),
    spendSecretKey: bytesToHex(spendSec),
    spendPublicKey: bytesToHex(spendPub),
  };
}

async function runSync(daemon, label) {
  const storage = new MemoryStorage();
  await storage.open();
  await storage.setSyncHeight(START_HEIGHT);

  const keys = generateTestKeys();
  const sync = new WalletSync({ storage, daemon, keys, batchSize: DEFAULT_BATCH_SIZE });

  const stats = { batches: 0, blocks: 0, batchSizes: [] };

  sync.on('newBlock', () => { stats.blocks++; });
  sync.on('batchComplete', (data) => {
    stats.batches++;
    stats.batchSizes.push(data.batchSize);
  });

  const targetHeight = START_HEIGHT + BLOCK_COUNT;
  const origGetInfo = daemon.getInfo.bind(daemon);
  daemon.getInfo = async () => {
    const r = await origGetInfo();
    if (r.success) r.result.height = targetHeight;
    return r;
  };

  const t0 = Date.now();
  try {
    await sync.start(START_HEIGHT);
  } catch (e) {
    console.error(`  [${label}] Sync failed: ${e.message}`);
  }
  const elapsed = Date.now() - t0;

  // Restore getInfo
  daemon.getInfo = origGetInfo;

  console.log(`  [${label}] ${stats.blocks} blocks in ${(elapsed / 1000).toFixed(2)}s (${(stats.blocks / (elapsed / 1000)).toFixed(1)} blocks/sec)`);
  console.log(`  [${label}] ${stats.batches} batches, sizes: [${stats.batchSizes.join(', ')}]`);
  console.log(`  [${label}] Status: ${sync.status}`);

  await storage.close();
  return { elapsed, blocks: stats.blocks, status: sync.status };
}

async function main() {
  console.log('=== Sync Fallback Path Comparison ===\n');
  console.log(`Daemon:  ${DAEMON_URL}`);
  console.log(`Range:   ${START_HEIGHT} → ${START_HEIGHT + BLOCK_COUNT}\n`);

  const daemon = new DaemonRPC({ url: DAEMON_URL, timeout: 30000 });
  const info = await daemon.getInfo();
  if (!info.success) {
    console.error('Failed to connect:', info.error);
    process.exit(1);
  }
  console.log(`Daemon height: ${info.result.height}\n`);

  // 1. Binary path
  console.log('--- Binary Bulk Fetch ---');
  const binResult = await runSync(daemon, 'binary');

  // 2. JSON fallback path (disable binary endpoint)
  console.log('\n--- JSON Fallback (parallel) ---');
  const origGetBlocksByHeight = daemon.getBlocksByHeight;
  daemon.getBlocksByHeight = null; // Force JSON fallback
  const jsonResult = await runSync(daemon, 'json');
  daemon.getBlocksByHeight = origGetBlocksByHeight; // Restore

  // 3. Compare
  console.log('\n--- Comparison ---');
  const speedup = jsonResult.elapsed / binResult.elapsed;
  console.log(`Binary: ${(binResult.elapsed / 1000).toFixed(2)}s`);
  console.log(`JSON:   ${(jsonResult.elapsed / 1000).toFixed(2)}s`);
  console.log(`Binary is ${speedup.toFixed(1)}x faster`);

  const pass = binResult.status === 'complete' && jsonResult.status === 'complete';
  console.log(`\nBoth paths: ${pass ? 'PASS' : 'FAIL'}`);
  process.exit(pass ? 0 : 1);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
