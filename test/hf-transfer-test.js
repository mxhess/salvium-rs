#!/usr/bin/env bun
/**
 * HF-Aware Transfer Test
 *
 * Tests transfers between wallet A and B at any hard fork height.
 * Automatically selects correct asset type and address format.
 *
 * Usage:
 *   bun test/hf-transfer-test.js              # dry run
 *   DRY_RUN=0 bun test/hf-transfer-test.js    # live broadcast
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { transfer } from '../src/wallet/transfer.js';
import { getHfVersionForHeight } from '../src/consensus.js';
import { readFileSync, existsSync } from 'fs';

await setCryptoBackend('wasm');

const DAEMON_URL = process.env.DAEMON_URL || 'http://node12.whiskymine.io:29081';
const DRY_RUN = process.env.DRY_RUN !== '0';
const NETWORK = 'testnet';

const daemon = new DaemonRPC({ url: DAEMON_URL });

// Get current state
const info = await daemon.getInfo();
const height = info.result?.height || info.data?.height;
const hfVersion = getHfVersionForHeight(height, 1); // 1 = testnet

console.log('=== HF-Aware Transfer Test ===\n');
console.log(`Height: ${height}`);
console.log(`HF Version: ${hfVersion}`);
console.log(`Dry Run: ${DRY_RUN}\n`);

// Determine asset type and address format
const useCarrot = hfVersion >= 10;
const assetType = hfVersion >= 6 ? 'SAL1' : 'SAL';
console.log(`Asset Type: ${assetType}`);
console.log(`Address Format: ${useCarrot ? 'CARROT' : 'CryptoNote'}\n`);

// Load wallets
const walletAPath = process.env.HOME + '/testnet-wallet/wallet-a.json';
const walletBPath = process.env.HOME + '/testnet-wallet/wallet-b-new.json';

const wjA = JSON.parse(readFileSync(walletAPath));
const wjB = JSON.parse(readFileSync(walletBPath));

const walletA = Wallet.fromJSON({ ...wjA, network: NETWORK });
const walletB = Wallet.fromJSON({ ...wjB, network: NETWORK });

const addrA = useCarrot ? walletA.getCarrotAddress() : walletA.getLegacyAddress();
const addrB = useCarrot ? walletB.getCarrotAddress() : walletB.getLegacyAddress();

console.log('Wallet A:', addrA?.slice(0, 40) + '...');
console.log('Wallet B:', addrB?.slice(0, 40) + '...');

// Sync wallet A
console.log('\nSyncing Wallet A...');
const storageA = new MemoryStorage();
const cacheFileA = walletAPath.replace('.json', '-sync.json');

if (existsSync(cacheFileA)) {
  try {
    const cached = JSON.parse(readFileSync(cacheFileA, 'utf8'));
    storageA.load(cached);
    console.log(`  Loaded cache from block ${await storageA.getSyncHeight()}`);
  } catch (e) {}
}

const syncA = createWalletSync({
  daemon,
  keys: wjA,
  storage: storageA,
  network: NETWORK,
  carrotKeys: walletA.carrotKeys
});
await syncA.start();

// Save cache
await Bun.write(cacheFileA, JSON.stringify(storageA.dump()));

// Get balance
const outputsA = await storageA.getOutputs({ isSpent: false });
const spendableA = outputsA.filter(o => o.blockHeight <= height - 10);
const balanceSAL = spendableA.filter(o => o.assetType === 'SAL').reduce((s, o) => s + BigInt(o.amount), 0n);
const balanceSAL1 = spendableA.filter(o => o.assetType === 'SAL1').reduce((s, o) => s + BigInt(o.amount), 0n);

console.log(`\nWallet A Balance:`);
console.log(`  SAL:  ${(Number(balanceSAL) / 1e8).toFixed(2)} (${spendableA.filter(o => o.assetType === 'SAL').length} outputs)`);
console.log(`  SAL1: ${(Number(balanceSAL1) / 1e8).toFixed(2)} (${spendableA.filter(o => o.assetType === 'SAL1').length} outputs)`);

// Check if we have funds to transfer
const balance = assetType === 'SAL' ? balanceSAL : balanceSAL1;
if (balance < 10_00000000n) {
  console.log(`\nInsufficient ${assetType} balance for transfer. Need at least 10 ${assetType}.`);
  process.exit(1);
}

// Transfer 5 SAL/SAL1 from A to B
const amount = 5_00000000n; // 5 units
console.log(`\n--- Transfer A → B ---`);
console.log(`  Amount: 5 ${assetType}`);
console.log(`  To: ${addrB?.slice(0, 40)}...`);

try {
  const result = await transfer({
    wallet: { keys: wjA, storage: storageA },
    daemon,
    destinations: [{ address: addrB, amount }],
    options: {
      priority: 'default',
      network: NETWORK,
      dryRun: DRY_RUN,
      assetType,
      useCarrot
    }
  });

  console.log(`  TX Hash: ${result.txHash}`);
  console.log(`  Fee: ${(Number(result.fee) / 1e8).toFixed(4)} ${assetType}`);
  console.log(`  Inputs: ${result.inputCount}, Outputs: ${result.outputCount}`);
  console.log(`  TX Size: ${result.serializedHex.length / 2} bytes`);

  if (DRY_RUN) {
    console.log(`  [DRY RUN - not broadcast]`);
  } else {
    console.log(`  BROADCAST SUCCESS`);
    // Mark spent
    for (const ki of result.spentKeyImages || []) {
      await storageA.markOutputSpent(ki);
    }
  }

  console.log('\n✓ Transfer test passed');
} catch (e) {
  console.error(`\n✗ Transfer failed: ${e.message}`);
  if (e.stack) console.error(e.stack.split('\n').slice(1, 5).join('\n'));
  process.exit(1);
}
