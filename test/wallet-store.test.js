#!/usr/bin/env bun
/**
 * Wallet Storage Tests
 *
 * Tests for wallet-store.js:
 * - WalletOutput model
 * - WalletTransaction model
 * - MemoryStorage implementation
 * - Storage queries and operations
 */

import {
  WalletStorage,
  WalletOutput,
  WalletTransaction,
  MemoryStorage,
  createStorage
} from '../src/wallet-store.js';

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
    throw new Error(message || `Expected ${expected}, got ${actual}`);
  }
}

console.log('=== Wallet Storage Tests ===\n');

// ============================================================================
// WalletOutput Tests
// ============================================================================

console.log('--- WalletOutput Model ---');

test('creates output with default values', () => {
  const output = new WalletOutput();
  assertEqual(output.keyImage, null);
  assertEqual(output.amount, 0n);
  assertEqual(output.assetType, 'SAL');
  assertEqual(output.isSpent, false);
  assertEqual(output.isFrozen, false);
  assertEqual(output.txType, 3);
});

test('creates output with provided values', () => {
  const output = new WalletOutput({
    keyImage: 'abc123',
    publicKey: 'def456',
    txHash: 'tx789',
    outputIndex: 2,
    blockHeight: 1000,
    amount: 5000000000n,
    assetType: 'SAL'
  });
  assertEqual(output.keyImage, 'abc123');
  assertEqual(output.publicKey, 'def456');
  assertEqual(output.txHash, 'tx789');
  assertEqual(output.outputIndex, 2);
  assertEqual(output.blockHeight, 1000);
  assertEqual(output.amount, 5000000000n);
});

test('amount accepts number and converts to BigInt', () => {
  const output = new WalletOutput({ amount: 1000 });
  assertEqual(output.amount, 1000n);
});

test('amount accepts string and converts to BigInt', () => {
  const output = new WalletOutput({ amount: '999999999999' });
  assertEqual(output.amount, 999999999999n);
});

test('isUnlocked returns true for confirmed output with enough confirmations', () => {
  const output = new WalletOutput({
    blockHeight: 100,
    unlockTime: 0n
  });
  assert(output.isUnlocked(115, 10), 'Should be unlocked at 15 confirmations');
  assert(output.isUnlocked(110, 10), 'Should be unlocked at exactly 10 confirmations');
});

test('isUnlocked returns false for insufficient confirmations', () => {
  const output = new WalletOutput({
    blockHeight: 100,
    unlockTime: 0n
  });
  assert(!output.isUnlocked(105, 10), 'Should not be unlocked at 5 confirmations');
  assert(!output.isUnlocked(109, 10), 'Should not be unlocked at 9 confirmations');
});

test('isUnlocked handles block-height unlock time', () => {
  const output = new WalletOutput({
    blockHeight: 100,
    unlockTime: 200n  // Locked until block 200
  });
  assert(!output.isUnlocked(150), 'Should be locked at height 150');
  assert(!output.isUnlocked(199), 'Should be locked at height 199');
  assert(output.isUnlocked(200), 'Should be unlocked at height 200');
  assert(output.isUnlocked(250), 'Should be unlocked at height 250');
});

test('isUnlocked handles timestamp unlock time', () => {
  const futureTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
  const pastTime = Math.floor(Date.now() / 1000) - 3600;   // 1 hour ago

  const lockedOutput = new WalletOutput({
    blockHeight: 100,
    unlockTime: BigInt(futureTime)
  });
  assert(!lockedOutput.isUnlocked(1000), 'Should be locked with future timestamp');

  const unlockedOutput = new WalletOutput({
    blockHeight: 100,
    unlockTime: BigInt(pastTime)
  });
  assert(unlockedOutput.isUnlocked(1000), 'Should be unlocked with past timestamp');
});

test('isSpendable requires key image', () => {
  const outputNoKeyImage = new WalletOutput({
    blockHeight: 100,
    amount: 1000n,
    keyImage: null
  });
  assert(!outputNoKeyImage.isSpendable(200), 'Should not be spendable without key image');

  const outputWithKeyImage = new WalletOutput({
    blockHeight: 100,
    amount: 1000n,
    keyImage: 'abc123'
  });
  assert(outputWithKeyImage.isSpendable(200), 'Should be spendable with key image');
});

test('isSpendable returns false for spent outputs', () => {
  const output = new WalletOutput({
    blockHeight: 100,
    keyImage: 'abc123',
    isSpent: true
  });
  assert(!output.isSpendable(200), 'Spent output should not be spendable');
});

test('isSpendable returns false for frozen outputs', () => {
  const output = new WalletOutput({
    blockHeight: 100,
    keyImage: 'abc123',
    isFrozen: true
  });
  assert(!output.isSpendable(200), 'Frozen output should not be spendable');
});

test('toJSON serializes correctly', () => {
  const output = new WalletOutput({
    keyImage: 'abc',
    amount: 1234567890n,
    unlockTime: 100n
  });
  const json = output.toJSON();
  assertEqual(json.keyImage, 'abc');
  assertEqual(json.amount, '1234567890');
  assertEqual(json.unlockTime, '100');
  assertEqual(typeof json.amount, 'string');
});

test('fromJSON deserializes correctly', () => {
  const json = {
    keyImage: 'xyz',
    amount: '9876543210',
    unlockTime: '500',
    blockHeight: 1000
  };
  const output = WalletOutput.fromJSON(json);
  assertEqual(output.keyImage, 'xyz');
  assertEqual(output.amount, 9876543210n);
  assertEqual(output.unlockTime, 500n);
  assertEqual(output.blockHeight, 1000);
});

test('round-trip JSON serialization preserves BigInt values', () => {
  const original = new WalletOutput({
    amount: 123456789012345678901234n,
    unlockTime: 999999999999n
  });
  const json = original.toJSON();
  const restored = WalletOutput.fromJSON(json);
  assertEqual(restored.amount, original.amount);
  assertEqual(restored.unlockTime, original.unlockTime);
});

// ============================================================================
// WalletTransaction Tests
// ============================================================================

console.log('\n--- WalletTransaction Model ---');

test('creates transaction with default values', () => {
  const tx = new WalletTransaction();
  assertEqual(tx.txHash, null);
  assertEqual(tx.incomingAmount, 0n);
  assertEqual(tx.outgoingAmount, 0n);
  assertEqual(tx.fee, 0n);
  assertEqual(tx.isIncoming, false);
  assertEqual(tx.isOutgoing, false);
  assertEqual(tx.inPool, false);
});

test('creates transaction with provided values', () => {
  const tx = new WalletTransaction({
    txHash: 'hash123',
    blockHeight: 5000,
    isIncoming: true,
    incomingAmount: 10000000000n,
    fee: 50000000n
  });
  assertEqual(tx.txHash, 'hash123');
  assertEqual(tx.blockHeight, 5000);
  assertEqual(tx.isIncoming, true);
  assertEqual(tx.incomingAmount, 10000000000n);
  assertEqual(tx.fee, 50000000n);
});

test('isConfirmed is true when blockHeight is set', () => {
  const confirmedTx = new WalletTransaction({ blockHeight: 1000 });
  const unconfirmedTx = new WalletTransaction({ blockHeight: null });

  assert(confirmedTx.isConfirmed, 'Should be confirmed with block height');
  assert(!unconfirmedTx.isConfirmed, 'Should not be confirmed without block height');
});

test('getNetAmount calculates correctly', () => {
  const tx = new WalletTransaction({
    incomingAmount: 10000n,
    outgoingAmount: 3000n,
    fee: 100n
  });
  assertEqual(tx.getNetAmount(), 6900n); // 10000 - 3000 - 100
});

test('getNetAmount handles negative result', () => {
  const tx = new WalletTransaction({
    incomingAmount: 0n,
    outgoingAmount: 5000n,
    fee: 100n
  });
  assertEqual(tx.getNetAmount(), -5100n);
});

test('toJSON serializes correctly', () => {
  const tx = new WalletTransaction({
    txHash: 'abc',
    incomingAmount: 1000000n,
    fee: 10000n
  });
  const json = tx.toJSON();
  assertEqual(json.txHash, 'abc');
  assertEqual(json.incomingAmount, '1000000');
  assertEqual(json.fee, '10000');
});

test('fromJSON deserializes correctly', () => {
  const json = {
    txHash: 'xyz',
    incomingAmount: '5000000',
    outgoingAmount: '1000000',
    fee: '50000',
    changeAmount: '100000',
    unlockTime: '0'
  };
  const tx = WalletTransaction.fromJSON(json);
  assertEqual(tx.txHash, 'xyz');
  assertEqual(tx.incomingAmount, 5000000n);
  assertEqual(tx.outgoingAmount, 1000000n);
  assertEqual(tx.fee, 50000n);
  assertEqual(tx.changeAmount, 100000n);
});

// ============================================================================
// MemoryStorage Tests
// ============================================================================

console.log('\n--- MemoryStorage ---');

await testAsync('open and close work', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  await storage.close();
});

await testAsync('putOutput and getOutput work', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const output = new WalletOutput({
    keyImage: 'ki_test_1',
    amount: 1000000n,
    blockHeight: 100
  });

  await storage.putOutput(output);
  const retrieved = await storage.getOutput('ki_test_1');

  assertEqual(retrieved.keyImage, 'ki_test_1');
  assertEqual(retrieved.amount, 1000000n);
  assertEqual(retrieved.blockHeight, 100);

  await storage.close();
});

await testAsync('getOutput returns null for nonexistent key', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const result = await storage.getOutput('nonexistent');
  assertEqual(result, null);

  await storage.close();
});

await testAsync('getOutputs returns all outputs', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({ keyImage: 'ki1', amount: 100n }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki2', amount: 200n }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki3', amount: 300n }));

  const outputs = await storage.getOutputs();
  assertEqual(outputs.length, 3);

  await storage.close();
});

await testAsync('getOutputs filters by isSpent', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({ keyImage: 'ki1', isSpent: false }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki2', isSpent: true }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki3', isSpent: false }));

  const unspent = await storage.getOutputs({ isSpent: false });
  const spent = await storage.getOutputs({ isSpent: true });

  assertEqual(unspent.length, 2);
  assertEqual(spent.length, 1);

  await storage.close();
});

await testAsync('getOutputs filters by assetType', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({ keyImage: 'ki1', assetType: 'SAL' }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki2', assetType: 'USD' }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki3', assetType: 'SAL' }));

  const salOutputs = await storage.getOutputs({ assetType: 'SAL' });
  const usdOutputs = await storage.getOutputs({ assetType: 'USD' });

  assertEqual(salOutputs.length, 2);
  assertEqual(usdOutputs.length, 1);

  await storage.close();
});

await testAsync('getOutputs filters by amount range', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({ keyImage: 'ki1', amount: 100n }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki2', amount: 500n }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki3', amount: 1000n }));

  const filtered = await storage.getOutputs({ minAmount: 200n, maxAmount: 800n });
  assertEqual(filtered.length, 1);
  assertEqual(filtered[0].amount, 500n);

  await storage.close();
});

await testAsync('getOutputs filters by account index', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({ keyImage: 'ki1', subaddressIndex: { major: 0, minor: 0 } }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki2', subaddressIndex: { major: 1, minor: 0 } }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki3', subaddressIndex: { major: 0, minor: 1 } }));

  const account0 = await storage.getOutputs({ accountIndex: 0 });
  const account1 = await storage.getOutputs({ accountIndex: 1 });

  assertEqual(account0.length, 2);
  assertEqual(account1.length, 1);

  await storage.close();
});

await testAsync('markOutputSpent updates output', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({ keyImage: 'ki1', amount: 100n }));

  const before = await storage.getOutput('ki1');
  assertEqual(before.isSpent, false);

  await storage.markOutputSpent('ki1', 'spending_tx_hash', 500);

  const after = await storage.getOutput('ki1');
  assertEqual(after.isSpent, true);
  assertEqual(after.spentTxHash, 'spending_tx_hash');
  assertEqual(after.spentHeight, 500);

  await storage.close();
});

await testAsync('putTransaction and getTransaction work', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const tx = new WalletTransaction({
    txHash: 'tx_test_1',
    blockHeight: 1000,
    incomingAmount: 5000000n
  });

  await storage.putTransaction(tx);
  const retrieved = await storage.getTransaction('tx_test_1');

  assertEqual(retrieved.txHash, 'tx_test_1');
  assertEqual(retrieved.blockHeight, 1000);
  assertEqual(retrieved.incomingAmount, 5000000n);

  await storage.close();
});

await testAsync('getTransactions filters by direction', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putTransaction(new WalletTransaction({ txHash: 'tx1', isIncoming: true, blockHeight: 100 }));
  await storage.putTransaction(new WalletTransaction({ txHash: 'tx2', isOutgoing: true, blockHeight: 101 }));
  await storage.putTransaction(new WalletTransaction({ txHash: 'tx3', isIncoming: true, blockHeight: 102 }));

  const incoming = await storage.getTransactions({ isIncoming: true });
  const outgoing = await storage.getTransactions({ isOutgoing: true });

  assertEqual(incoming.length, 2);
  assertEqual(outgoing.length, 1);

  await storage.close();
});

await testAsync('getTransactions sorts by height descending', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putTransaction(new WalletTransaction({ txHash: 'tx1', blockHeight: 100 }));
  await storage.putTransaction(new WalletTransaction({ txHash: 'tx3', blockHeight: 300 }));
  await storage.putTransaction(new WalletTransaction({ txHash: 'tx2', blockHeight: 200 }));

  const txs = await storage.getTransactions();

  assertEqual(txs[0].blockHeight, 300);
  assertEqual(txs[1].blockHeight, 200);
  assertEqual(txs[2].blockHeight, 100);

  await storage.close();
});

await testAsync('sync height operations work', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const initial = await storage.getSyncHeight();
  assertEqual(initial, 0);

  await storage.setSyncHeight(5000);
  const updated = await storage.getSyncHeight();
  assertEqual(updated, 5000);

  await storage.close();
});

await testAsync('state operations work', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.setState('testKey', { foo: 'bar', num: 123 });
  const value = await storage.getState('testKey');

  assertEqual(value.foo, 'bar');
  assertEqual(value.num, 123);

  await storage.close();
});

await testAsync('clear removes all data', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({ keyImage: 'ki1' }));
  await storage.putTransaction(new WalletTransaction({ txHash: 'tx1' }));
  await storage.setSyncHeight(1000);

  await storage.clear();

  const outputs = await storage.getOutputs();
  const txs = await storage.getTransactions();
  const height = await storage.getSyncHeight();

  assertEqual(outputs.length, 0);
  assertEqual(txs.length, 0);
  assertEqual(height, 0);

  await storage.close();
});

await testAsync('key image tracking works', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putKeyImage('ki1', { txHash: 'tx1', outputIndex: 0 });

  const isSpentBefore = await storage.isKeyImageSpent('ki1');
  assertEqual(isSpentBefore, false);

  // Mark output spent (which also marks key image spent)
  await storage.putOutput(new WalletOutput({ keyImage: 'ki1' }));
  await storage.markOutputSpent('ki1', 'spending_tx');

  const isSpentAfter = await storage.isKeyImageSpent('ki1');
  assertEqual(isSpentAfter, true);

  const spentKeyImages = await storage.getSpentKeyImages();
  assert(spentKeyImages.includes('ki1'));

  await storage.close();
});

// ============================================================================
// createStorage Factory Tests
// ============================================================================

console.log('\n--- createStorage Factory ---');

test('createStorage with type=memory returns MemoryStorage', () => {
  const storage = createStorage({ type: 'memory' });
  assert(storage instanceof MemoryStorage);
});

test('createStorage with auto falls back to MemoryStorage (no IndexedDB)', () => {
  // In Node/Bun environment, IndexedDB is not available
  const storage = createStorage({ type: 'auto' });
  assert(storage instanceof MemoryStorage);
});

test('createStorage with no options returns MemoryStorage', () => {
  const storage = createStorage();
  assert(storage instanceof MemoryStorage);
});

// ============================================================================
// Summary
// ============================================================================

console.log('\n--- Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
  console.log('\n✗ Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All wallet storage tests passed!');
  process.exit(0);
}
