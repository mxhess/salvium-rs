#!/usr/bin/env bun
/**
 * Fractional Transfers Test
 *
 * Does many small transfers from A to B to create lots of UTXOs for testing.
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { transfer } from '../src/wallet/transfer.js';
import { getHfVersionForHeight } from '../src/consensus.js';
import { readFileSync, existsSync, writeFileSync } from 'fs';

await setCryptoBackend('wasm');

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const DRY_RUN = process.env.DRY_RUN !== '0';
const NUM_TRANSFERS = parseInt(process.env.NUM || '10');

const info = await daemon.getInfo();
const height = info.result?.height;
const hfVersion = getHfVersionForHeight(height, 1);
const assetType = hfVersion >= 6 ? 'SAL1' : 'SAL';
const useCarrot = hfVersion >= 10;

console.log(`=== Fractional Transfers (${NUM_TRANSFERS}x) ===`);
console.log(`Height: ${height}, HF: ${hfVersion}, Asset: ${assetType}, DryRun: ${DRY_RUN}\n`);

// Load wallets
const pathA = process.env.HOME + '/testnet-wallet/wallet-a.json';
const pathB = process.env.HOME + '/testnet-wallet/wallet-b-new.json';
const cacheA = pathA.replace('.json', '-sync.json');

const wjA = JSON.parse(readFileSync(pathA));
const wjB = JSON.parse(readFileSync(pathB));
const walletA = Wallet.fromJSON({ ...wjA, network: 'testnet' });
const walletB = Wallet.fromJSON({ ...wjB, network: 'testnet' });

const addrB = useCarrot ? walletB.getCarrotAddress() : walletB.getLegacyAddress();

// Sync wallet A
const storageA = new MemoryStorage();
if (existsSync(cacheA)) {
  storageA.load(JSON.parse(readFileSync(cacheA)));
}

console.log('Syncing Wallet A...');
const syncA = createWalletSync({
  daemon, keys: wjA, storage: storageA, network: 'testnet', carrotKeys: walletA.carrotKeys
});
await syncA.start();
writeFileSync(cacheA, JSON.stringify(storageA.dump()));

// Get balance
const outputs = await storageA.getOutputs({ isSpent: false });
const unlocked = outputs.filter(o => o.blockHeight <= height - 60 && o.assetType === assetType);
const balance = unlocked.reduce((s, o) => s + BigInt(o.amount), 0n);
console.log(`Available: ${(Number(balance) / 1e8).toFixed(2)} ${assetType} in ${unlocked.length} outputs\n`);

// Fractional amounts (0.1 to 1.5 SAL)
const amounts = [
  0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.75, 1.0,
  1.1, 1.25, 1.5, 0.33, 0.66, 0.99, 0.11, 0.22, 0.44, 0.55
];

let successCount = 0;
let totalSent = 0n;

for (let i = 0; i < NUM_TRANSFERS; i++) {
  const amt = BigInt(Math.floor(amounts[i % amounts.length] * 1e8));

  // Check if we have enough balance
  const currentOutputs = await storageA.getOutputs({ isSpent: false });
  const currentUnlocked = currentOutputs.filter(o => o.blockHeight <= height - 60 && o.assetType === assetType);
  const currentBal = currentUnlocked.reduce((s, o) => s + BigInt(o.amount), 0n);

  if (currentBal < amt + 50000000n) { // Need amount + ~0.5 for fee
    console.log(`[${i+1}/${NUM_TRANSFERS}] Skipped - insufficient balance`);
    continue;
  }

  try {
    const result = await transfer({
      wallet: { keys: wjA, storage: storageA },
      daemon,
      destinations: [{ address: addrB, amount: amt }],
      options: { priority: 'default', network: 'testnet', dryRun: DRY_RUN, assetType, useCarrot }
    });

    // Mark spent outputs
    if (!DRY_RUN) {
      for (const ki of result.spentKeyImages || []) {
        await storageA.markOutputSpent(ki);
      }
    }

    successCount++;
    totalSent += amt;
    console.log(`[${i+1}/${NUM_TRANSFERS}] ✓ ${(Number(amt)/1e8).toFixed(2)} ${assetType} → B | TX: ${result.txHash.slice(0,12)}...`);
  } catch (e) {
    console.log(`[${i+1}/${NUM_TRANSFERS}] ✗ ${(Number(amt)/1e8).toFixed(2)} ${assetType} - ${e.message.slice(0, 50)}`);
  }
}

// Save updated cache
writeFileSync(cacheA, JSON.stringify(storageA.dump()));

console.log(`\n=== Summary ===`);
console.log(`Success: ${successCount}/${NUM_TRANSFERS}`);
console.log(`Total sent: ${(Number(totalSent)/1e8).toFixed(2)} ${assetType}`);
