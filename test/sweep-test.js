#!/usr/bin/env bun
/**
 * Quick sweep test — exercises the sweep() function on wallet B.
 * Usage: bun test/sweep-test.js
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { sweep } from '../src/wallet/transfer.js';
import { bytesToHex } from '../src/address.js';
import { existsSync } from 'node:fs';

await setCryptoBackend('wasm');

const DAEMON_URL = 'http://web.whiskymine.io:29081';
const WALLET_B_PATH = process.env.HOME + '/testnet-wallet/wallet-b.json';
const SYNC_CACHE_B = WALLET_B_PATH.replace(/\.json$/, '-sync.json');
const NETWORK = 'testnet';

function toHex(val) {
  if (typeof val === 'string') return val;
  if (val instanceof Uint8Array) return bytesToHex(val);
  if (val && typeof val === 'object' && '0' in val) {
    const len = Object.keys(val).length;
    const arr = new Uint8Array(len);
    for (let i = 0; i < len; i++) arr[i] = val[i];
    return bytesToHex(arr);
  }
  return val;
}

function loadWalletKeys(data) {
  return {
    keys: {
      viewSecretKey: toHex(data.viewSecretKey),
      spendSecretKey: toHex(data.spendSecretKey),
      viewPublicKey: toHex(data.viewPublicKey),
      spendPublicKey: toHex(data.spendPublicKey),
    },
    carrotKeys: data.carrotKeys || null,
    address: data.address,
    carrotAddress: data.carrotAddress || null,
  };
}

async function main() {
  const daemon = new DaemonRPC({ url: DAEMON_URL });
  const info = await daemon.getInfo();
  const height = info.result?.height;
  console.log(`Height: ${height}`);

  // Load wallet B
  const bData = JSON.parse(await Bun.file(WALLET_B_PATH).text());
  const bWallet = loadWalletKeys(bData);
  const bAddr = bWallet.address;
  console.log(`B CN addr: ${bAddr.slice(0, 20)}...`);

  // Sync wallet B
  const storageB = new MemoryStorage();
  if (existsSync(SYNC_CACHE_B)) {
    try {
      const cached = JSON.parse(await Bun.file(SYNC_CACHE_B).text());
      const cachedSyncHeight = cached.syncHeight || 0;
      if (cachedSyncHeight > height) {
        console.log(`  Cache stale (cached=${cachedSyncHeight}, chain=${height}), resetting`);
      } else {
        storageB.load(cached);
      }
    } catch { /* ignore bad cache */ }
  }

  console.log('Syncing wallet B...');
  const syncB = createWalletSync({ daemon, keys: bWallet.keys, carrotKeys: bWallet.carrotKeys, storage: storageB, network: NETWORK });
  await syncB.start();
  await Bun.write(SYNC_CACHE_B, storageB.dumpJSON());

  const allOutputs = await storageB.getOutputs({ isSpent: false });
  const spendable = allOutputs.filter(o => o.isSpendable(height));
  const balance = spendable.reduce((s, o) => s + o.amount, 0n);
  console.log(`B: ${spendable.length} spendable outputs, balance=${(Number(balance) / 1e8).toFixed(8)} SAL`);

  if (spendable.length === 0) {
    console.log('No spendable outputs — skipping sweep');
    return;
  }

  // Sweep B -> B (self)
  console.log(`Sweeping B -> B (${bAddr.slice(0, 20)}...)`);

  try {
    const result = await sweep({
      wallet: { keys: bWallet.keys, storage: storageB, carrotKeys: bWallet.carrotKeys },
      daemon,
      address: bAddr,
      options: { priority: 'default', network: NETWORK }
    });
    console.log(`Sweep OK: ${result.txHash}`);
    console.log(`  fee: ${(Number(result.fee) / 1e8).toFixed(8)} SAL`);
    console.log(`  amount: ${(Number(result.amount) / 1e8).toFixed(8)} SAL`);
    console.log(`  inputs: ${result.inputCount}, outputs: ${result.outputCount}`);
  } catch (err) {
    console.error(`Sweep FAILED: ${err.message}`);
    if (err.stack) console.error(err.stack.split('\n').slice(1, 5).join('\n'));
    process.exit(1);
  }
}

main().catch(err => { console.error(err); process.exit(1); });
