#!/usr/bin/env bun
/**
 * Sync-only test: resync wallet A with memory monitoring.
 * Used to verify memory optimizations before running full integration tests.
 */
import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';

await setCryptoBackend('wasm');

const DAEMON_URL = process.env.DAEMON_URL || 'http://web.whiskymine.io:29081';
const WALLET_FILE = `${process.env.HOME}/testnet-wallet/wallet-a.json`;
const CACHE_FILE = WALLET_FILE.replace(/\.json$/, '-sync.json');

const daemon = new DaemonRPC({ url: DAEMON_URL });
const info = await daemon.getInfo();
if (!info.success) throw new Error('Cannot reach daemon');
console.log(`Daemon height: ${info.result.height}`);

// Load wallet keys
const walletJson = JSON.parse(await Bun.file(WALLET_FILE).text());
const keys = {
  viewSecretKey: walletJson.viewSecretKey,
  spendSecretKey: walletJson.spendSecretKey,
  viewPublicKey: walletJson.viewPublicKey,
  spendPublicKey: walletJson.spendPublicKey,
};
const carrotKeys = walletJson.carrotKeys || null;

const storage = new MemoryStorage();
const sync = createWalletSync({ daemon, keys, carrotKeys, storage, network: 'testnet' });

// Monitor memory every 5000 blocks
let lastLog = 0;
sync.on('syncProgress', (progress) => {
  const h = progress.currentHeight;
  if (h - lastLog >= 5000 || h === progress.targetHeight) {
    const rss = process.memoryUsage?.() || {};
    console.log(`  Block ${h}/${progress.targetHeight} | RSS: ${Math.round((rss.rss || 0) / 1024 / 1024)}MB | Heap: ${Math.round((rss.heapUsed || 0) / 1024 / 1024)}MB | Outputs: ${storage._outputs.size} | BlockHashes: ${storage._blockHashes.size}`);
    lastLog = h;
  }
});

console.log('Starting sync from block 0...');
const t0 = Date.now();
await sync.start();
const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

const syncHeight = await storage.getSyncHeight();
console.log(`\nSync complete: ${syncHeight} blocks in ${elapsed}s`);
console.log(`Outputs: ${storage._outputs.size}`);
console.log(`Transactions: ${storage._transactions.size}`);
console.log(`Block hashes: ${storage._blockHashes.size}`);

// Save cache
console.log('Saving cache...');
await Bun.write(CACHE_FILE, storage.dumpJSON());
console.log(`Saved to ${CACHE_FILE}`);

// Verify some outputs
const allOutputs = await storage.getOutputs({ isSpent: false });
const carrotOutputs = allOutputs.filter(o => o.isCarrot);
const withCommitment = carrotOutputs.filter(o => o.commitment);
console.log(`\nUnspent outputs: ${allOutputs.length}`);
console.log(`  CARROT: ${carrotOutputs.length} (${withCommitment.length} with commitment)`);

// Check commitment validity on first few CARROT outputs
import { commit } from '../src/crypto/index.js';
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

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
