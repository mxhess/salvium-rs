#!/usr/bin/env bun
/**
 * Quick sweep test — exercises the sweep() function on wallet B.
 * Usage: bun test/sweep-test.js
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { existsSync } from 'node:fs';
import { getHeight, fmt, loadWalletFromFile } from './test-helpers.js';

await setCryptoBackend('wasm');

const DAEMON_URL = 'http://node12.whiskymine.io:29081';
const WALLET_B_PATH = process.env.HOME + '/testnet-wallet/wallet-b.json';
const SYNC_CACHE_B = WALLET_B_PATH.replace(/\.json$/, '-sync.json');

async function main() {
  const daemon = new DaemonRPC({ url: DAEMON_URL });
  const height = await getHeight(daemon);
  console.log(`Height: ${height}`);

  // Load wallet B
  const wallet = await loadWalletFromFile(WALLET_B_PATH, 'testnet');
  wallet.setDaemon(daemon);
  console.log(`B CN addr: ${wallet.getLegacyAddress().slice(0, 20)}...`);

  // Load sync cache if exists
  if (existsSync(SYNC_CACHE_B)) {
    try {
      const cached = JSON.parse(await Bun.file(SYNC_CACHE_B).text());
      if ((cached.syncHeight || 0) > height) {
        console.log(`  Cache stale (cached=${cached.syncHeight}, chain=${height}), resetting`);
      } else {
        wallet.loadSyncCache(cached);
      }
    } catch { /* ignore bad cache */ }
  }

  // Sync
  console.log('Syncing wallet B...');
  await wallet.syncWithDaemon();
  await Bun.write(SYNC_CACHE_B, wallet.dumpSyncCacheJSON());

  const { balance, unlockedBalance } = await wallet.getStorageBalance();
  console.log(`B: balance=${fmt(balance)}, unlocked=${fmt(unlockedBalance)}`);

  if (unlockedBalance === 0n) {
    console.log('No spendable outputs — skipping sweep');
    return;
  }

  // Sweep B -> B (self)
  const addr = wallet.getAddress();
  console.log(`Sweeping B -> B (${addr.slice(0, 20)}...)`);

  try {
    const result = await wallet.sweep(addr);
    console.log(`Sweep OK: ${result.txHash}`);
    console.log(`  fee: ${fmt(result.fee)}`);
    console.log(`  amount: ${fmt(result.amount)}`);
    console.log(`  inputs: ${result.inputCount}, outputs: ${result.outputCount}`);
  } catch (err) {
    console.error(`Sweep FAILED: ${err.message}`);
    if (err.stack) console.error(err.stack.split('\n').slice(1, 5).join('\n'));
    process.exit(1);
  }
}

main().catch(err => { console.error(err); process.exit(1); });
