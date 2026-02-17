#!/usr/bin/env bun
/**
 * Sweep Consolidation Test
 *
 * Sweeps all outputs from Wallet B back to itself to consolidate
 * many small inputs into fewer outputs.
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { getHfVersionForHeight } from '../src/consensus.js';
import { existsSync } from 'fs';
import { getHeight, fmt, loadWalletFromFile } from './test-helpers.js';

await setCryptoBackend('wasm');

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const DRY_RUN = process.env.DRY_RUN !== '0';

const h = await getHeight(daemon);
const hfVersion = getHfVersionForHeight(h, 1);
const assetType = hfVersion >= 6 ? 'SAL1' : 'SAL';

console.log('=== Sweep Consolidation Test: B → B ===');
console.log(`Height: ${h}, HF: ${hfVersion}, Asset: ${assetType}`);
console.log(`Dry Run: ${DRY_RUN}\n`);

const pathB = process.env.HOME + '/testnet-wallet/wallet-b-new.json';
const cacheB = pathB.replace('.json', '-sync.json');

const wallet = await loadWalletFromFile(pathB, 'testnet');
wallet.setDaemon(daemon);
const addrB = wallet.getAddress();

// Load sync cache
if (existsSync(cacheB)) {
  try {
    wallet.loadSyncCache(JSON.parse(await Bun.file(cacheB).text()));
  } catch { /* ignore bad cache */ }
}

// Sync
console.log('Syncing Wallet B...');
await wallet.syncWithDaemon();
await Bun.write(cacheB, wallet.dumpSyncCacheJSON());

// Report output status using storage internals for detailed breakdown
const storage = wallet._storage;
const outputs = await storage.getOutputs({ isSpent: false });
const unlocked = outputs.filter(o => o.blockHeight <= h - 60 && o.assetType === assetType);
const locked = outputs.filter(o => o.blockHeight > h - 60 || o.assetType !== assetType);
const totalBal = unlocked.reduce((s, o) => s + BigInt(o.amount), 0n);

console.log(`\nWallet B Status:`);
console.log(`  Total outputs: ${outputs.length}`);
console.log(`  Unlocked ${assetType}: ${unlocked.length} outputs (${(Number(totalBal)/1e8).toFixed(2)} ${assetType})`);
console.log(`  Locked/other: ${locked.length} outputs`);

if (locked.length > 0) {
  const maxLockHeight = Math.max(...locked.map(o => o.blockHeight)) + 60;
  console.log(`  All unlock at height: ${maxLockHeight} (${maxLockHeight - h} blocks)`);
}

if (unlocked.length < 2) {
  console.log('\nNeed at least 2 unlocked outputs to test sweep. Exiting.');
  process.exit(0);
}

console.log(`\nSweeping ${unlocked.length} outputs to self (${addrB.slice(0,30)}...)...\n`);

try {
  const result = await wallet.sweep(addrB, {
    priority: 'default',
    dryRun: DRY_RUN,
    assetType,
  });

  console.log('SWEEP SUCCESS!');
  console.log(`  TX Hash: ${result.txHash}`);
  console.log(`  Inputs consolidated: ${result.inputCount}`);
  console.log(`  Output count: ${result.outputCount}`);
  console.log(`  Amount swept: ${(Number(result.amount || result.sweepAmount || 0n)/1e8).toFixed(4)} ${assetType}`);
  console.log(`  Fee: ${(Number(result.fee)/1e8).toFixed(4)} ${assetType}`);
  console.log(`  TX Size: ${result.serializedHex.length / 2} bytes`);

  if (!DRY_RUN) {
    // Wallet.sweep already marks spent outputs
    await Bun.write(cacheB, wallet.dumpSyncCacheJSON());
    console.log('\n  Wallet cache updated.');
  } else {
    console.log('\n  [DRY RUN - not broadcast]');
  }

} catch (e) {
  console.log('SWEEP FAILED:', e.message);
  if (e.stack) console.log(e.stack.split('\n').slice(1, 6).join('\n'));
}
