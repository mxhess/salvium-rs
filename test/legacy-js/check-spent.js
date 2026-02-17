#!/usr/bin/env bun
/**
 * Check spent status of wallet outputs and update cache
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';

await setCryptoBackend('wasm');

const daemon = new DaemonRPC({ url: process.env.DAEMON_URL || 'http://node12.whiskymine.io:29081' });

async function checkAndUpdateWallet(label, path) {
  const cache = path.replace('.json', '-sync.json');
  const wj = JSON.parse(readFileSync(path));
  const wallet = Wallet.fromJSON({ ...wj, network: 'testnet' });

  const storage = new MemoryStorage();
  if (existsSync(cache)) {
    storage.load(JSON.parse(readFileSync(cache)));
  }

  // Sync to get all outputs
  console.log(`Syncing ${label}...`);
  const sync = createWalletSync({ daemon, keys: wj, storage, network: 'testnet', carrotKeys: wallet.carrotKeys });
  await sync.start();

  // Get all unspent outputs with key images
  const outputs = await storage.getOutputs({ isSpent: false });
  const withKeyImages = outputs.filter(o => o.keyImage);

  console.log(`  Total unspent outputs: ${outputs.length}`);
  console.log(`  Outputs with key images: ${withKeyImages.length}`);

  if (withKeyImages.length === 0) {
    console.log(`  No key images to check\n`);
    writeFileSync(cache, JSON.stringify(storage.dump()));
    return;
  }

  // Check spent status in batches
  const keyImages = withKeyImages.map(o => o.keyImage);
  const batchSize = 100;
  let spentCount = 0;

  for (let i = 0; i < keyImages.length; i += batchSize) {
    const batch = keyImages.slice(i, i + batchSize);
    const resp = await daemon.isKeyImageSpent(batch);

    if (resp.success && (resp.result?.spent_status || resp.data?.spent_status)) {
      const statuses = resp.result?.spent_status || resp.data?.spent_status;
      for (let j = 0; j < statuses.length; j++) {
        const status = statuses[j];
        const ki = batch[j];
        // status: 0 = unspent, 1 = spent in blockchain, 2 = spent in mempool
        if (status !== 0) {
          await storage.markOutputSpent(ki);
          spentCount++;
        }
      }
    }
  }

  console.log(`  Marked ${spentCount} outputs as spent`);

  // Save updated cache
  writeFileSync(cache, JSON.stringify(storage.dump()));

  // Show final balance
  const remaining = await storage.getOutputs({ isSpent: false });
  const balSAL = remaining.filter(o => o.assetType === 'SAL').reduce((s, o) => s + BigInt(o.amount), 0n);
  const balSAL1 = remaining.filter(o => o.assetType === 'SAL1').reduce((s, o) => s + BigInt(o.amount), 0n);
  console.log(`  Remaining: ${(Number(balSAL)/1e8).toFixed(2)} SAL, ${(Number(balSAL1)/1e8).toFixed(2)} SAL1\n`);
}

console.log('=== Checking Spent Key Images ===\n');
await checkAndUpdateWallet('Wallet A', process.env.HOME + '/testnet-wallet/wallet-a.json');
await checkAndUpdateWallet('Wallet B', process.env.HOME + '/testnet-wallet/wallet-b-new.json');
console.log('Done!');
