#!/usr/bin/env bun
/**
 * Bidirectional Transfer Test
 *
 * Tests transfers in both directions (A→B and B→A).
 * Automatically handles asset type selection based on HF.
 *
 * Usage:
 *   bun test/bidirectional-test.js              # dry run
 *   DRY_RUN=0 bun test/bidirectional-test.js    # live broadcast
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

const DAEMON_URL = process.env.DAEMON_URL || 'http://web.whiskymine.io:29081';
const DRY_RUN = process.env.DRY_RUN !== '0';
const NETWORK = 'testnet';
const UNLOCK_BLOCKS = 60;

const daemon = new DaemonRPC({ url: DAEMON_URL });

// Get current state
const info = await daemon.getInfo();
const height = info.result?.height || info.data?.height;
const hfVersion = getHfVersionForHeight(height, 1);

console.log('=== Bidirectional Transfer Test ===\n');
console.log(`Height: ${height}, HF: ${hfVersion}, Dry Run: ${DRY_RUN}\n`);

const useCarrot = hfVersion >= 10;
const assetType = hfVersion >= 6 ? 'SAL1' : 'SAL';
console.log(`Asset: ${assetType}, Format: ${useCarrot ? 'CARROT' : 'CN'}\n`);

// Load wallets
const pathA = process.env.HOME + '/testnet-wallet/wallet-a.json';
const pathBNew = process.env.HOME + '/testnet-wallet/wallet-b-new.json';
const pathBFallback = process.env.HOME + '/testnet-wallet/wallet-b.json';
const pathB = existsSync(pathBNew) ? pathBNew : pathBFallback;

const wjA = JSON.parse(readFileSync(pathA));
const wjB = JSON.parse(readFileSync(pathB));
const walletA = Wallet.fromJSON({ ...wjA, network: NETWORK });
const walletB = Wallet.fromJSON({ ...wjB, network: NETWORK });

const addrA = useCarrot ? walletA.getCarrotAddress() : walletA.getLegacyAddress();
const addrB = useCarrot ? walletB.getCarrotAddress() : walletB.getLegacyAddress();

// Helper to sync wallet
async function syncWallet(label, wj, wallet, cachePath) {
  const storage = new MemoryStorage();
  if (existsSync(cachePath)) {
    try {
      const cached = JSON.parse(readFileSync(cachePath, 'utf8'));
      storage.load(cached);
    } catch (e) {}
  }

  const sync = createWalletSync({
    daemon, keys: wj, storage, network: NETWORK, carrotKeys: wallet.carrotKeys
  });
  await sync.start();

  writeFileSync(cachePath, JSON.stringify(storage.dump()));

  const outputs = await storage.getOutputs({ isSpent: false });
  const spendable = outputs.filter(o => o.blockHeight <= height - UNLOCK_BLOCKS);
  const bal = spendable.filter(o => o.assetType === assetType)
    .reduce((s, o) => s + BigInt(o.amount), 0n);

  console.log(`${label}: ${(Number(bal) / 1e8).toFixed(2)} ${assetType} (${spendable.filter(o => o.assetType === assetType).length} unlocked)`);

  return { storage, spendable, balance: bal };
}

// Sync both wallets
const cacheA = pathA.replace('.json', '-sync.json');
const cacheB = pathB.replace('.json', '-sync.json');

console.log('Syncing wallets...');
const { storage: storageA, balance: balA } = await syncWallet('Wallet A', wjA, walletA, cacheA);
const { storage: storageB, balance: balB } = await syncWallet('Wallet B', wjB, walletB, cacheB);

// Helper to do transfer
async function doTransfer(label, fromKeys, fromStorage, toAddr, amount) {
  console.log(`\n--- ${label} ---`);
  console.log(`  Amount: ${Number(amount) / 1e8} ${assetType} → ${toAddr.slice(0, 30)}...`);

  try {
    const result = await transfer({
      wallet: { keys: fromKeys, storage: fromStorage },
      daemon,
      destinations: [{ address: toAddr, amount }],
      options: { priority: 'default', network: NETWORK, dryRun: DRY_RUN, assetType, useCarrot }
    });

    console.log(`  TX: ${result.txHash.slice(0, 16)}... | Fee: ${(Number(result.fee) / 1e8).toFixed(4)} | ${result.inputCount}→${result.outputCount}`);
    console.log(`  ${DRY_RUN ? '[DRY RUN]' : 'BROADCAST OK'}`);

    if (!DRY_RUN) {
      for (const ki of result.spentKeyImages || []) {
        await fromStorage.markOutputSpent(ki);
      }
    }
    return true;
  } catch (e) {
    console.log(`  FAILED: ${e.message}`);
    return false;
  }
}

// Test A → B
const amount = 2_00000000n; // 2 units
let successAB = false, successBA = false;

if (balA >= amount + 1_00000000n) { // Need amount + fee buffer
  successAB = await doTransfer('A → B', wjA, storageA, addrB, amount);
} else {
  console.log(`\nSkipping A→B: Insufficient balance (${(Number(balA) / 1e8).toFixed(2)} ${assetType})`);
}

// Test B → A
if (balB >= amount + 1_00000000n) {
  successBA = await doTransfer('B → A', wjB, storageB, addrA, amount);
} else {
  console.log(`\nSkipping B→A: Insufficient balance (${(Number(balB) / 1e8).toFixed(2)} ${assetType}). Need ${UNLOCK_BLOCKS} confirms.`);
}

console.log('\n=== Summary ===');
console.log(`A → B: ${successAB ? '✓' : '✗'}`);
console.log(`B → A: ${successBA ? '✓' : '✗'}`);
