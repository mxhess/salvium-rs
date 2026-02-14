#!/usr/bin/env bun
/**
 * Quick wallet status check
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { getHfVersionForHeight } from '../src/consensus.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';

await setCryptoBackend('wasm');

const daemon = new DaemonRPC({ url: process.env.DAEMON_URL || 'http://node12.whiskymine.io:29081' });
const info = await daemon.getInfo();
const height = info.result?.height;
const hf = getHfVersionForHeight(height, 1);
const assetType = hf >= 6 ? 'SAL1' : 'SAL';
const useCarrot = hf >= 10;
const UNLOCK = 60;

console.log(`\n=== Wallet Status at Height ${height} (HF${hf}) ===\n`);

async function checkWallet(label, path) {
  const cache = path.replace('.json', '-sync.json');
  const wj = JSON.parse(readFileSync(path));
  const wallet = Wallet.fromJSON({ ...wj, network: 'testnet' });
  const addr = useCarrot ? wallet.getCarrotAddress() : wallet.getLegacyAddress();

  const storage = new MemoryStorage();
  if (existsSync(cache)) storage.load(JSON.parse(readFileSync(cache)));

  const sync = createWalletSync({ daemon, keys: wj, storage, network: 'testnet', carrotKeys: wallet.carrotKeys });
  await sync.start();
  writeFileSync(cache, JSON.stringify(storage.dump()));

  const outputs = await storage.getOutputs({ isSpent: false });
  const unlocked = outputs.filter(o => o.blockHeight <= height - UNLOCK);
  const locked = outputs.filter(o => o.blockHeight > height - UNLOCK);

  const balSAL = unlocked.filter(o => o.assetType === 'SAL').reduce((s, o) => s + BigInt(o.amount), 0n);
  const balSAL1 = unlocked.filter(o => o.assetType === 'SAL1').reduce((s, o) => s + BigInt(o.amount), 0n);

  console.log(`${label}:`);
  console.log(`  Address: ${addr.slice(0, 40)}...`);
  console.log(`  SAL:  ${(Number(balSAL)/1e8).toFixed(2)} (${unlocked.filter(o=>o.assetType==='SAL').length} unlocked)`);
  console.log(`  SAL1: ${(Number(balSAL1)/1e8).toFixed(2)} (${unlocked.filter(o=>o.assetType==='SAL1').length} unlocked)`);
  console.log(`  Locked outputs: ${locked.length}`);
  if (locked.length > 0) {
    const maxH = Math.max(...locked.map(o => o.blockHeight)) + UNLOCK;
    console.log(`  Unlock at height: ${maxH} (${maxH - height} blocks)`);
  }
  console.log('');
}

await checkWallet('Wallet A', process.env.HOME + '/testnet-wallet/wallet-a.json');
await checkWallet('Wallet B', process.env.HOME + '/testnet-wallet/wallet-b-new.json');
