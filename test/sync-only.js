#!/usr/bin/env bun
/**
 * Sync-only test: resync wallet A with memory monitoring.
 * Used to verify memory optimizations before running full integration tests.
 */
import { setCryptoBackend, commit } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import { loadWalletFromFile } from './test-helpers.js';

await setCryptoBackend('wasm');

const DAEMON_URL = process.env.DAEMON_URL || 'http://web.whiskymine.io:29081';
const WALLET_FILE = `${process.env.HOME}/testnet-wallet/wallet-a.json`;
const CACHE_FILE = WALLET_FILE.replace(/\.json$/, '-sync.json');

const daemon = new DaemonRPC({ url: DAEMON_URL });
const info = await daemon.getInfo();
if (!info.success) throw new Error('Cannot reach daemon');
console.log(`Daemon height: ${info.result.height}`);

// Load wallet
const wallet = await loadWalletFromFile(WALLET_FILE, 'testnet');
wallet.setDaemon(daemon);

// Access internals for memory monitoring (test-only)
const storage = wallet._ensureStorage();
const ws = wallet._ensureSync();

// Monitor memory every 5000 blocks
let lastLog = 0;
ws.on('syncProgress', (progress) => {
  const h = progress.currentHeight;
  if (h - lastLog >= 5000 || h === progress.targetHeight) {
    const rss = process.memoryUsage?.() || {};
    console.log(`  Block ${h}/${progress.targetHeight} | RSS: ${Math.round((rss.rss || 0) / 1024 / 1024)}MB | Heap: ${Math.round((rss.heapUsed || 0) / 1024 / 1024)}MB | Outputs: ${storage._outputs.size} | BlockHashes: ${storage._blockHashes.size}`);
    lastLog = h;
  }
});

console.log('Starting sync from block 0...');
const t0 = Date.now();
await wallet.syncWithDaemon();
const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

const syncHeight = wallet.getSyncHeight();
console.log(`\nSync complete: ${syncHeight} blocks in ${elapsed}s`);
console.log(`Outputs: ${storage._outputs.size}`);
console.log(`Transactions: ${storage._transactions.size}`);
console.log(`Block hashes: ${storage._blockHashes.size}`);

// Save cache
console.log('Saving cache...');
await Bun.write(CACHE_FILE, wallet.dumpSyncCacheJSON());
console.log(`Saved to ${CACHE_FILE}`);

// Verify some outputs
const allOutputs = await storage.getOutputs({ isSpent: false });
const carrotOutputs = allOutputs.filter(o => o.isCarrot);
const withCommitment = carrotOutputs.filter(o => o.commitment);
console.log(`\nUnspent outputs: ${allOutputs.length}`);
console.log(`  CARROT: ${carrotOutputs.length} (${withCommitment.length} with commitment)`);

// Check commitment validity on CARROT outputs
let matchCount = 0, mismatchCount = 0;
for (const o of carrotOutputs) {
  if (!o.mask || !o.commitment) continue;
  const maskBytes = hexToBytes(o.mask);
  const computed = commit(BigInt(o.amount), maskBytes);
  if (bytesToHex(computed) === o.commitment) {
    matchCount++;
  } else {
    mismatchCount++;
    if (mismatchCount <= 3) {
      console.log(`  MISMATCH: ${o.txHash?.slice(0,16)}... idx=${o.outputIndex} enoteType=${o.carrotEnoteType}`);
    }
  }
}
console.log(`\nCommitment verification:`);
console.log(`  Correct: ${matchCount}`);
console.log(`  Mismatch: ${mismatchCount}`);

const rss = process.memoryUsage?.() || {};
console.log(`\nFinal memory: RSS=${Math.round((rss.rss || 0) / 1024 / 1024)}MB Heap=${Math.round((rss.heapUsed || 0) / 1024 / 1024)}MB`);
