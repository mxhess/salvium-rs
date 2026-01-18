#!/usr/bin/env bun
/**
 * Query System Tests
 *
 * Tests for query.js:
 * - OutputQuery class
 * - TxQuery class
 * - TransferQuery class
 * - Query factory functions
 * - Query preset functions
 */

import {
  OutputQuery,
  TxQuery,
  TransferQuery,
  createOutputQuery,
  createTxQuery,
  createTransferQuery,
  unspentOutputs,
  spentOutputs,
  lockedOutputs,
  unlockedOutputs,
  stakingOutputs,
  yieldOutputs,
  incomingTxs,
  outgoingTxs,
  pendingTxs,
  confirmedTxs,
  stakingTxs,
  yieldTxs
} from '../src/query.js';

import { TX_TYPE } from '../src/wallet.js';

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

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${expected}, got ${actual}`);
  }
}

function assertDeepEqual(actual, expected, message) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(message || `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

console.log('=== Query System Tests ===\n');

// ============================================================================
// OutputQuery Tests
// ============================================================================

console.log('--- OutputQuery ---');

test('creates with default values', () => {
  const query = new OutputQuery();
  assertEqual(query.isSpent, null);
  assertEqual(query.isFrozen, null);
  assertEqual(query.isLocked, null);
  assertEqual(query.assetType, null);
  assertEqual(query.minAmount, null);
  assertEqual(query.maxAmount, null);
});

test('creates with provided config', () => {
  const query = new OutputQuery({
    isSpent: false,
    isFrozen: false,
    assetType: 'SAL',
    minAmount: 1000n,
    maxAmount: 10000n,
    accountIndex: 0,
    subaddressIndices: [0, 1, 2]
  });

  assertEqual(query.isSpent, false);
  assertEqual(query.isFrozen, false);
  assertEqual(query.assetType, 'SAL');
  assertEqual(query.minAmount, 1000n);
  assertEqual(query.maxAmount, 10000n);
  assertEqual(query.accountIndex, 0);
  assertDeepEqual(query.subaddressIndices, [0, 1, 2]);
});

test('matches unspent output', () => {
  const query = new OutputQuery({ isSpent: false });
  const output = { isSpent: false, amount: 1000n };

  assert(query.matches(output), 'Should match unspent output');
});

test('rejects spent output when querying unspent', () => {
  const query = new OutputQuery({ isSpent: false });
  const output = { isSpent: true, amount: 1000n };

  assert(!query.matches(output), 'Should not match spent output');
});

test('matches by asset type', () => {
  const query = new OutputQuery({ assetType: 'SAL' });

  assert(query.matches({ assetType: 'SAL' }), 'Should match SAL');
  assert(!query.matches({ assetType: 'USD' }), 'Should not match USD');
});

test('matches by amount range', () => {
  const query = new OutputQuery({ minAmount: 100n, maxAmount: 1000n });

  assert(!query.matches({ amount: 50n }), 'Should not match below min');
  assert(query.matches({ amount: 100n }), 'Should match at min');
  assert(query.matches({ amount: 500n }), 'Should match in range');
  assert(query.matches({ amount: 1000n }), 'Should match at max');
  assert(!query.matches({ amount: 1001n }), 'Should not match above max');
});

test('matches by account index', () => {
  const query = new OutputQuery({ accountIndex: 1 });

  assert(query.matches({ subaddressIndex: { major: 1, minor: 0 } }), 'Should match account 1');
  assert(!query.matches({ subaddressIndex: { major: 0, minor: 0 } }), 'Should not match account 0');
});

test('matches by subaddress indices', () => {
  const query = new OutputQuery({
    subaddressIndices: [
      { major: 0, minor: 1 },
      { major: 0, minor: 2 },
      { major: 0, minor: 3 }
    ]
  });

  assert(query.matches({ subaddressIndex: { major: 0, minor: 1 } }), 'Should match minor 1');
  assert(query.matches({ subaddressIndex: { major: 0, minor: 2 } }), 'Should match minor 2');
  assert(!query.matches({ subaddressIndex: { major: 0, minor: 0 } }), 'Should not match minor 0');
  assert(!query.matches({ subaddressIndex: { major: 0, minor: 5 } }), 'Should not match minor 5');
});

test('matches by tx type', () => {
  const query = new OutputQuery({ txType: TX_TYPE.STAKE });

  assert(query.matches({ txType: TX_TYPE.STAKE }), 'Should match stake');
  assert(!query.matches({ txType: TX_TYPE.TRANSFER }), 'Should not match transfer');
});

test('matches by key images list', () => {
  const query = new OutputQuery({ keyImages: ['ki1', 'ki2', 'ki3'] });

  assert(query.matches({ keyImage: 'ki1' }), 'Should match ki1');
  assert(query.matches({ keyImage: 'ki2' }), 'Should match ki2');
  assert(!query.matches({ keyImage: 'ki4' }), 'Should not match ki4');
});

test('matches by block height range', () => {
  const query = new OutputQuery({ minHeight: 100, maxHeight: 200 });

  assert(!query.matches({ blockHeight: 50 }), 'Should not match below min');
  assert(query.matches({ blockHeight: 100 }), 'Should match at min');
  assert(query.matches({ blockHeight: 150 }), 'Should match in range');
  assert(query.matches({ blockHeight: 200 }), 'Should match at max');
  assert(!query.matches({ blockHeight: 250 }), 'Should not match above max');
});

test('combines multiple criteria (AND logic)', () => {
  const query = new OutputQuery({
    isSpent: false,
    assetType: 'SAL',
    minAmount: 100n
  });

  assert(query.matches({ isSpent: false, assetType: 'SAL', amount: 200n }), 'Should match all criteria');
  assert(!query.matches({ isSpent: true, assetType: 'SAL', amount: 200n }), 'Should fail on isSpent');
  assert(!query.matches({ isSpent: false, assetType: 'USD', amount: 200n }), 'Should fail on assetType');
  assert(!query.matches({ isSpent: false, assetType: 'SAL', amount: 50n }), 'Should fail on amount');
});

test('config values are accessible', () => {
  const query = new OutputQuery({ isSpent: false, assetType: 'SAL' });

  assertEqual(query.isSpent, false);
  assertEqual(query.assetType, 'SAL');
});

// ============================================================================
// TxQuery Tests
// ============================================================================

console.log('\n--- TxQuery ---');

test('creates with default values', () => {
  const query = new TxQuery();
  assertEqual(query.isIncoming, null);
  assertEqual(query.isOutgoing, null);
  assertEqual(query.isConfirmed, null);
  assertEqual(query.inTxPool, null);
});

test('matches by direction', () => {
  const incomingQuery = new TxQuery({ isIncoming: true });
  const outgoingQuery = new TxQuery({ isOutgoing: true });

  assert(incomingQuery.matches({ isIncoming: true, isOutgoing: false }));
  assert(!incomingQuery.matches({ isIncoming: false, isOutgoing: true }));
  assert(outgoingQuery.matches({ isIncoming: false, isOutgoing: true }));
});

test('matches by confirmation status', () => {
  const confirmedQuery = new TxQuery({ isConfirmed: true });
  const pendingQuery = new TxQuery({ inTxPool: true });

  assert(confirmedQuery.matches({ isConfirmed: true, blockHeight: 1000 }));
  assert(!confirmedQuery.matches({ isConfirmed: false, blockHeight: null }));
  assert(pendingQuery.matches({ inTxPool: true }));
  assert(!pendingQuery.matches({ inTxPool: false }));
});

test('matches by tx hash', () => {
  const query = new TxQuery({ hash: 'abc123' });

  assert(query.matches({ txHash: 'abc123' }));
  assert(!query.matches({ txHash: 'xyz789' }));
});

test('matches by tx hashes list', () => {
  const query = new TxQuery({ hashes: ['tx1', 'tx2', 'tx3'] });

  assert(query.matches({ txHash: 'tx1' }));
  assert(query.matches({ txHash: 'tx2' }));
  assert(!query.matches({ txHash: 'tx4' }));
});

test('matches by height range', () => {
  const query = new TxQuery({ minHeight: 100, maxHeight: 200 });

  assert(!query.matches({ blockHeight: 50 }));
  assert(query.matches({ blockHeight: 150 }));
  assert(!query.matches({ blockHeight: 250 }));
});

test('matches by height', () => {
  const query = new TxQuery({ height: 1500 });

  assert(!query.matches({ blockHeight: 500 }));
  assert(query.matches({ blockHeight: 1500 }));
  assert(!query.matches({ blockHeight: 2500 }));
});

test('matches by payment ID', () => {
  const query = new TxQuery({ paymentId: 'pay123' });

  assert(query.matches({ paymentId: 'pay123' }));
  assert(!query.matches({ paymentId: 'pay456' }));
  assert(!query.matches({ paymentId: null }));
});

test('matches by tx type', () => {
  const query = new TxQuery({ txType: TX_TYPE.STAKE });

  assert(query.matches({ txType: TX_TYPE.STAKE }));
  assert(!query.matches({ txType: TX_TYPE.TRANSFER }));
});

test('matches by amount range', () => {
  const query = new TxQuery({ minAmount: 100n, maxAmount: 1000n });

  assert(query.matches({ amount: 500n }));
  assert(!query.matches({ amount: 50n }));
  assert(!query.matches({ amount: 2000n }));
});

// ============================================================================
// TransferQuery Tests
// ============================================================================

console.log('\n--- TransferQuery ---');

test('creates transfer query', () => {
  const query = new TransferQuery({
    isIncoming: true,
    address: 'Salv1...'
  });

  assertEqual(query.isIncoming, true);
  assertEqual(query.address, 'Salv1...');
});

test('matches by address', () => {
  const query = new TransferQuery({ address: 'addr1' });

  assert(query.matches({ address: 'addr1' }));
  assert(!query.matches({ address: 'addr2' }));
});

test('matches by subaddress index', () => {
  const query = new TransferQuery({ accountIndex: 0, subaddressIndex: 5 });

  assert(query.matches({ accountIndex: 0, subaddressIndex: 5 }));
  assert(!query.matches({ accountIndex: 0, subaddressIndex: 3 }));
  assert(!query.matches({ accountIndex: 1, subaddressIndex: 5 }));
});

// ============================================================================
// Factory Functions Tests
// ============================================================================

console.log('\n--- Factory Functions ---');

test('createOutputQuery creates OutputQuery', () => {
  const query = createOutputQuery({ isSpent: false });
  assert(query instanceof OutputQuery);
  assertEqual(query.isSpent, false);
});

test('createTxQuery creates TxQuery', () => {
  const query = createTxQuery({ isConfirmed: true });
  assert(query instanceof TxQuery);
  assertEqual(query.isConfirmed, true);
});

test('createTransferQuery creates TransferQuery', () => {
  const query = createTransferQuery({ isIncoming: true });
  assert(query instanceof TransferQuery);
  assertEqual(query.isIncoming, true);
});

// ============================================================================
// Query Preset Functions Tests
// ============================================================================

console.log('\n--- Query Presets ---');

test('unspentOutputs creates correct query', () => {
  const query = unspentOutputs();
  assertEqual(query.isSpent, false);
});

test('unspentOutputs merges additional config', () => {
  const query = unspentOutputs({ assetType: 'USD' });
  assertEqual(query.isSpent, false);
  assertEqual(query.assetType, 'USD');
});

test('spentOutputs creates correct query', () => {
  const query = spentOutputs();
  assertEqual(query.isSpent, true);
});

test('lockedOutputs creates correct query', () => {
  const query = lockedOutputs();
  assertEqual(query.isLocked, true);
  assertEqual(query.isSpent, false);
});

test('unlockedOutputs creates correct query', () => {
  const query = unlockedOutputs();
  assertEqual(query.isLocked, false);
  assertEqual(query.isSpent, false);
});

test('stakingOutputs creates correct query', () => {
  const query = stakingOutputs();
  assertEqual(query.txType, TX_TYPE.STAKE);
  assertEqual(query.isSpent, false);
});

test('yieldOutputs creates correct query', () => {
  const query = yieldOutputs();
  assertEqual(query.txType, TX_TYPE.PROTOCOL);
  assertEqual(query.isSpent, false);
});

test('incomingTxs creates correct query', () => {
  const query = incomingTxs();
  assertEqual(query.isIncoming, true);
});

test('outgoingTxs creates correct query', () => {
  const query = outgoingTxs();
  assertEqual(query.isOutgoing, true);
});

test('pendingTxs creates correct query', () => {
  const query = pendingTxs();
  assertEqual(query.inTxPool, true);
  assertEqual(query.isConfirmed, false);
});

test('confirmedTxs creates correct query', () => {
  const query = confirmedTxs();
  assertEqual(query.isConfirmed, true);
});

test('stakingTxs creates correct query', () => {
  const query = stakingTxs();
  assertEqual(query.txType, TX_TYPE.STAKE);
});

test('yieldTxs creates correct query', () => {
  const query = yieldTxs();
  assertEqual(query.txType, TX_TYPE.PROTOCOL);
});

// ============================================================================
// Complex Query Tests
// ============================================================================

console.log('\n--- Complex Queries ---');

test('filter array of outputs', () => {
  const outputs = [
    { keyImage: 'ki1', isSpent: false, amount: 100n, assetType: 'SAL' },
    { keyImage: 'ki2', isSpent: true, amount: 200n, assetType: 'SAL' },
    { keyImage: 'ki3', isSpent: false, amount: 300n, assetType: 'USD' },
    { keyImage: 'ki4', isSpent: false, amount: 400n, assetType: 'SAL' },
  ];

  const query = new OutputQuery({ isSpent: false, assetType: 'SAL' });
  const filtered = outputs.filter(o => query.matches(o));

  assertEqual(filtered.length, 2);
  assertEqual(filtered[0].keyImage, 'ki1');
  assertEqual(filtered[1].keyImage, 'ki4');
});

test('filter array of transactions', () => {
  const txs = [
    { txHash: 'tx1', isIncoming: true, isConfirmed: true, blockHeight: 100 },
    { txHash: 'tx2', isIncoming: false, isConfirmed: true, blockHeight: 200 },
    { txHash: 'tx3', isIncoming: true, isConfirmed: false, inPool: true },
    { txHash: 'tx4', isIncoming: true, isConfirmed: true, blockHeight: 300 },
  ];

  const query = new TxQuery({ isIncoming: true, isConfirmed: true });
  const filtered = txs.filter(tx => query.matches(tx));

  assertEqual(filtered.length, 2);
  assertEqual(filtered[0].txHash, 'tx1');
  assertEqual(filtered[1].txHash, 'tx4');
});

test('chain query modifications', () => {
  // Start with unspent, add more criteria
  const baseQuery = unspentOutputs();
  const refinedQuery = new OutputQuery({
    isSpent: baseQuery.isSpent,
    assetType: 'SAL',
    minAmount: 1000n
  });

  assertEqual(refinedQuery.isSpent, false);
  assertEqual(refinedQuery.assetType, 'SAL');
  assertEqual(refinedQuery.minAmount, 1000n);
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
  console.log('\n✓ All query system tests passed!');
  process.exit(0);
}
