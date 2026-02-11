#!/usr/bin/env bun
/**
 * FFI Storage Tests
 *
 * Tests for wallet-store-ffi.js (SQLCipher backend via Rust FFI).
 * Requires the native library to be built:
 *   cd crates/salvium-crypto && cargo build --release --features ffi
 *
 * Run: CRYPTO_BACKEND=ffi bun test/wallet-store-ffi.test.js
 */

import { FfiStorage } from '../src/wallet-store-ffi.js';
import { WalletOutput, WalletTransaction } from '../src/wallet-store.js';
import { unlinkSync } from 'fs';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function cleanup(path) {
  try { unlinkSync(path); } catch {}
  try { unlinkSync(path + '-wal'); } catch {}
  try { unlinkSync(path + '-shm'); } catch {}
}

// Random DB path for test isolation
let testCounter = 0;
function testDbPath() {
  return `/tmp/salvium_ffi_test_${Date.now()}_${testCounter++}.db`;
}

console.log('=== FFI Storage Tests (SQLCipher) ===\n');

// ─── Lifecycle ──────────────────────────────────────────────────────────────

console.log('--- Lifecycle ---');

await testAsync('open and close', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();
  await store.close();
  cleanup(path);
});

await testAsync('clear all data', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  await store.putOutput(new WalletOutput({
    keyImage: 'ki_clear', txHash: 'tx_clear', amount: '1000'
  }));
  await store.setSyncHeight(5000);
  await store.clear();

  const output = await store.getOutput('ki_clear');
  assertEqual(output, null, 'output should be null after clear');
  const height = await store.getSyncHeight();
  assertEqual(height, 0, 'sync height should be 0 after clear');

  await store.close();
  cleanup(path);
});

// ─── Output Operations ─────────────────────────────────────────────────────

console.log('\n--- Output Operations ---');

await testAsync('put and get output', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  const output = new WalletOutput({
    keyImage: 'ki_abc123',
    publicKey: 'pk_xyz',
    txHash: 'tx_001',
    outputIndex: 0,
    blockHeight: 1000,
    blockTimestamp: 1700000000,
    amount: '500000000000',
    assetType: 'SAL',
  });

  await store.putOutput(output);
  const got = await store.getOutput('ki_abc123');
  assert(got !== null, 'should find output');
  assertEqual(got.txHash, 'tx_001');
  assertEqual(got.amount.toString(), '500000000000');
  assertEqual(got.blockHeight, 1000);

  await store.close();
  cleanup(path);
});

await testAsync('get non-existent output returns null', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  const got = await store.getOutput('nonexistent');
  assertEqual(got, null);

  await store.close();
  cleanup(path);
});

await testAsync('mark output spent', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  await store.putOutput(new WalletOutput({
    keyImage: 'ki_spend', txHash: 'tx_002', amount: '1000', blockHeight: 500,
  }));
  await store.markOutputSpent('ki_spend', 'tx_spending', 600);

  const got = await store.getOutput('ki_spend');
  assert(got !== null);
  assert(got.isSpent === true, 'should be spent');
  assertEqual(got.spentTxHash, 'tx_spending');
  assertEqual(got.spentHeight, 600);

  await store.close();
  cleanup(path);
});

await testAsync('get filtered outputs', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  for (let i = 0; i < 5; i++) {
    await store.putOutput(new WalletOutput({
      keyImage: `ki_filter_${i}`,
      txHash: `tx_filter_${i}`,
      amount: String((i + 1) * 1000),
      assetType: i < 3 ? 'SAL' : 'STAKE',
      blockHeight: 100 + i,
      isSpent: i === 0,
      spentHeight: i === 0 ? 200 : null,
      spentTxHash: i === 0 ? 'tx_spend' : null,
    }));
  }

  // Unspent SAL outputs
  const results = await store.getOutputs({ isSpent: false, assetType: 'SAL' });
  assertEqual(results.length, 2, `expected 2 unspent SAL, got ${results.length}`);

  // All STAKE outputs
  const stakeResults = await store.getOutputs({ assetType: 'STAKE' });
  assertEqual(stakeResults.length, 2, `expected 2 STAKE outputs, got ${stakeResults.length}`);

  await store.close();
  cleanup(path);
});

// ─── Transaction Operations ─────────────────────────────────────────────────

console.log('\n--- Transaction Operations ---');

await testAsync('put and get transaction', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  const tx = new WalletTransaction({
    txHash: 'tx_100',
    blockHeight: 2000,
    blockTimestamp: 1700001000,
    confirmations: 10,
    isIncoming: true,
    isConfirmed: true,
    incomingAmount: '1000000',
    fee: '100',
    note: 'test payment',
  });

  await store.putTransaction(tx);
  const got = await store.getTransaction('tx_100');
  assert(got !== null, 'should find transaction');
  assertEqual(got.incomingAmount.toString(), '1000000');
  assert(got.isIncoming === true);
  assert(got.isConfirmed === true);
  assertEqual(got.note, 'test payment');

  await store.close();
  cleanup(path);
});

await testAsync('get non-existent transaction returns null', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  const got = await store.getTransaction('nonexistent');
  assertEqual(got, null);

  await store.close();
  cleanup(path);
});

await testAsync('get filtered transactions', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  await store.putTransaction(new WalletTransaction({
    txHash: 'tx_in_1', blockHeight: 100, isIncoming: true, isConfirmed: true, incomingAmount: '1000',
  }));
  await store.putTransaction(new WalletTransaction({
    txHash: 'tx_out_1', blockHeight: 200, isOutgoing: true, isConfirmed: true, outgoingAmount: '500',
  }));
  await store.putTransaction(new WalletTransaction({
    txHash: 'tx_in_2', blockHeight: 300, isIncoming: true, isConfirmed: true, incomingAmount: '2000',
  }));

  const incoming = await store.getTransactions({ isIncoming: true });
  assertEqual(incoming.length, 2, `expected 2 incoming, got ${incoming.length}`);

  const outgoing = await store.getTransactions({ isOutgoing: true });
  assertEqual(outgoing.length, 1, `expected 1 outgoing, got ${outgoing.length}`);

  await store.close();
  cleanup(path);
});

// ─── Sync State ─────────────────────────────────────────────────────────────

console.log('\n--- Sync State ---');

await testAsync('get and set sync height', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  assertEqual(await store.getSyncHeight(), 0, 'initial height should be 0');
  await store.setSyncHeight(12345);
  assertEqual(await store.getSyncHeight(), 12345);

  await store.close();
  cleanup(path);
});

await testAsync('put and get block hash', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  await store.putBlockHash(100, 'hash_at_100');
  await store.putBlockHash(101, 'hash_at_101');

  assertEqual(await store.getBlockHash(100), 'hash_at_100');
  assertEqual(await store.getBlockHash(101), 'hash_at_101');
  assertEqual(await store.getBlockHash(999), null);

  await store.close();
  cleanup(path);
});

// ─── Rollback ───────────────────────────────────────────────────────────────

console.log('\n--- Rollback ---');

await testAsync('atomic rollback deletes above height', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  // Insert outputs at heights 100, 200, 300
  for (const h of [100, 200, 300]) {
    await store.putOutput(new WalletOutput({
      keyImage: `ki_${h}`, txHash: `tx_${h}`, amount: '1000', blockHeight: h,
    }));
    await store.putBlockHash(h, `hash_${h}`);
  }

  // Mark ki_100 as spent at height 250
  await store.markOutputSpent('ki_100', 'tx_spend', 250);

  // Rollback to 150
  await store.rollback(150);

  // ki_100 should exist but be unspent (spent at 250 > 150)
  const o100 = await store.getOutput('ki_100');
  assert(o100 !== null, 'ki_100 should exist');
  assert(!o100.isSpent, 'ki_100 should be unspent after rollback');

  // ki_200 and ki_300 should be gone
  assertEqual(await store.getOutput('ki_200'), null, 'ki_200 should be deleted');
  assertEqual(await store.getOutput('ki_300'), null, 'ki_300 should be deleted');

  // Block hashes above 150 should be gone
  assertEqual(await store.getBlockHash(100), 'hash_100');
  assertEqual(await store.getBlockHash(200), null);
  assertEqual(await store.getBlockHash(300), null);

  await store.close();
  cleanup(path);
});

// ─── Balance ────────────────────────────────────────────────────────────────

console.log('\n--- Balance ---');

await testAsync('compute balance (standard outputs)', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  // 3 unspent outputs at height 100
  for (let i = 0; i < 3; i++) {
    await store.putOutput(new WalletOutput({
      keyImage: `ki_bal_${i}`, txHash: `tx_bal_${i}`,
      amount: '1000000000', blockHeight: 100, assetType: 'SAL',
    }));
  }

  // Height 105: only 5 confs, needs 10 → all locked
  let bal = store.getBalance({ currentHeight: 105, assetType: 'SAL' });
  assertEqual(bal.balance.toString(), '3000000000');
  assertEqual(bal.unlockedBalance.toString(), '0');
  assertEqual(bal.lockedBalance.toString(), '3000000000');

  // Height 110: 10 confs → all unlocked
  bal = store.getBalance({ currentHeight: 110, assetType: 'SAL' });
  assertEqual(bal.balance.toString(), '3000000000');
  assertEqual(bal.unlockedBalance.toString(), '3000000000');
  assertEqual(bal.lockedBalance.toString(), '0');

  await store.close();
  cleanup(path);
});

await testAsync('compute balance (coinbase needs 60 confs)', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  await store.putOutput(new WalletOutput({
    keyImage: 'ki_cb', txHash: 'tx_cb',
    amount: '5000000000', blockHeight: 100, assetType: 'SAL',
    txType: 1, // miner
    unlockTime: '60',
  }));

  // Height 150: only 50 confs, coinbase needs 60
  let bal = store.getBalance({ currentHeight: 150, assetType: 'SAL' });
  assertEqual(bal.unlockedBalance.toString(), '0');

  // Height 160: 60 confs → unlocked
  bal = store.getBalance({ currentHeight: 160, assetType: 'SAL' });
  assertEqual(bal.unlockedBalance.toString(), '5000000000');

  await store.close();
  cleanup(path);
});

await testAsync('balance excludes spent and frozen outputs', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  // Unspent output
  await store.putOutput(new WalletOutput({
    keyImage: 'ki_unspent', txHash: 'tx_1',
    amount: '1000', blockHeight: 100,
  }));
  // Spent output
  await store.putOutput(new WalletOutput({
    keyImage: 'ki_spent', txHash: 'tx_2',
    amount: '2000', blockHeight: 100,
    isSpent: true, spentHeight: 150,
  }));
  // Frozen output
  await store.putOutput(new WalletOutput({
    keyImage: 'ki_frozen', txHash: 'tx_3',
    amount: '3000', blockHeight: 100,
    isFrozen: true,
  }));

  const bal = store.getBalance({ currentHeight: 200, assetType: 'SAL' });
  // Only ki_unspent should count
  assertEqual(bal.balance.toString(), '1000');
  assertEqual(bal.unlockedBalance.toString(), '1000');

  await store.close();
  cleanup(path);
});

// ─── Key Image Operations ───────────────────────────────────────────────────

console.log('\n--- Key Image Operations ---');

await testAsync('isKeyImageSpent tracks spending', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  await store.putOutput(new WalletOutput({
    keyImage: 'ki_check', txHash: 'tx_check', amount: '1000', blockHeight: 100,
  }));

  assert(!(await store.isKeyImageSpent('ki_check')), 'should not be spent initially');
  await store.markOutputSpent('ki_check', 'tx_spend', 200);
  assert(await store.isKeyImageSpent('ki_check'), 'should be spent after marking');

  await store.close();
  cleanup(path);
});

await testAsync('getSpentKeyImages returns all spent', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);
  const store = new FfiStorage({ path, key });
  await store.open();

  for (let i = 0; i < 3; i++) {
    await store.putOutput(new WalletOutput({
      keyImage: `ki_ski_${i}`, txHash: `tx_ski_${i}`, amount: '1000', blockHeight: 100,
    }));
  }
  await store.markOutputSpent('ki_ski_0', 'tx_spend_0', 200);
  await store.markOutputSpent('ki_ski_2', 'tx_spend_2', 200);

  const spent = await store.getSpentKeyImages();
  assertEqual(spent.length, 2, `expected 2 spent KIs, got ${spent.length}`);
  assert(spent.includes('ki_ski_0'));
  assert(spent.includes('ki_ski_2'));

  await store.close();
  cleanup(path);
});

// ─── Data Persistence ───────────────────────────────────────────────────────

console.log('\n--- Data Persistence ---');

await testAsync('data survives close/reopen', async () => {
  const path = testDbPath();
  const key = new Uint8Array(32).fill(0x42);

  // Write
  const store1 = new FfiStorage({ path, key });
  await store1.open();
  await store1.putOutput(new WalletOutput({
    keyImage: 'ki_persist', txHash: 'tx_persist', amount: '9999', blockHeight: 500,
  }));
  await store1.setSyncHeight(5000);
  await store1.close();

  // Read
  const store2 = new FfiStorage({ path, key });
  await store2.open();
  const output = await store2.getOutput('ki_persist');
  assert(output !== null, 'output should persist');
  assertEqual(output.amount.toString(), '9999');
  assertEqual(await store2.getSyncHeight(), 5000);
  await store2.close();

  cleanup(path);
});

// ─── Summary ────────────────────────────────────────────────────────────────

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);
