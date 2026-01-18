#!/usr/bin/env node
/**
 * UTXO Selection Tests
 *
 * Tests for selectUTXOs function with various strategies:
 * - LARGEST_FIRST: Minimize input count
 * - SMALLEST_FIRST: Consume small UTXOs first
 * - FIFO: Oldest UTXOs first
 * - RANDOM: Randomized selection
 */

import {
  UTXO_STRATEGY,
  selectUTXOs,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
} from '../src/transaction.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(a, b, message) {
  if (a !== b) throw new Error(message || `Expected ${b}, got ${a}`);
}

function assertTrue(condition, message) {
  if (!condition) throw new Error(message || 'Expected true');
}

// Create mock UTXOs for testing
function createMockUTXOs() {
  return [
    { amount: 1000000000n, globalIndex: 100, blockHeight: 1000, txHash: 'a'.repeat(64) },
    { amount: 500000000n, globalIndex: 200, blockHeight: 1050, txHash: 'b'.repeat(64) },
    { amount: 250000000n, globalIndex: 300, blockHeight: 1100, txHash: 'c'.repeat(64) },
    { amount: 100000000n, globalIndex: 400, blockHeight: 1150, txHash: 'd'.repeat(64) },
    { amount: 50000000n, globalIndex: 500, blockHeight: 1200, txHash: 'e'.repeat(64) },
  ];
}

console.log('\n=== UTXO Selection Tests ===\n');

// Strategy constants
console.log('--- Strategy Constants ---');

test('UTXO_STRATEGY.LARGEST_FIRST exists', () => {
  assertEqual(UTXO_STRATEGY.LARGEST_FIRST, 'largest_first');
});

test('UTXO_STRATEGY.SMALLEST_FIRST exists', () => {
  assertEqual(UTXO_STRATEGY.SMALLEST_FIRST, 'smallest_first');
});

test('UTXO_STRATEGY.RANDOM exists', () => {
  assertEqual(UTXO_STRATEGY.RANDOM, 'random');
});

test('UTXO_STRATEGY.FIFO exists', () => {
  assertEqual(UTXO_STRATEGY.FIFO, 'fifo');
});

// Basic selection
console.log('\n--- Basic Selection ---');

test('selects sufficient UTXOs for target amount', () => {
  const utxos = createMockUTXOs();
  const result = selectUTXOs(utxos, 300000000n, 10000000n, { currentHeight: 2000 });

  assertTrue(result.selected.length > 0, 'Should select UTXOs');
  assertTrue(result.totalAmount >= 300000000n + result.estimatedFee, 'Should cover target + fee');
});

test('returns correct structure', () => {
  const utxos = createMockUTXOs();
  const result = selectUTXOs(utxos, 100000000n, 1000000n, { currentHeight: 2000 });

  assert(Array.isArray(result.selected), 'Should have selected array');
  assertEqual(typeof result.totalAmount, 'bigint', 'totalAmount should be bigint');
  assertEqual(typeof result.changeAmount, 'bigint', 'changeAmount should be bigint');
  assertEqual(typeof result.estimatedFee, 'bigint', 'estimatedFee should be bigint');
});

test('calculates change correctly', () => {
  const utxos = [{ amount: 1000000000n, globalIndex: 1 }];
  const targetAmount = 300000000n;
  const feePerInput = 10000000n;

  const result = selectUTXOs(utxos, targetAmount, feePerInput);
  const expectedChange = 1000000000n - targetAmount - feePerInput;

  assertEqual(result.changeAmount, expectedChange);
});

test('fee scales with input count', () => {
  const utxos = [
    { amount: 100000000n, globalIndex: 1 },
    { amount: 100000000n, globalIndex: 2 },
    { amount: 100000000n, globalIndex: 3 }
  ];
  const feePerInput = 5000000n;

  const result = selectUTXOs(utxos, 250000000n, feePerInput);

  // Need 3 inputs to reach 250M, so fee should be 3 * 5M = 15M
  assertEqual(result.estimatedFee, 15000000n);
});

// Strategy tests
console.log('\n--- Selection Strategies ---');

test('LARGEST_FIRST selects biggest UTXOs first', () => {
  const utxos = createMockUTXOs();
  const result = selectUTXOs(utxos, 100000000n, 1000000n, {
    strategy: UTXO_STRATEGY.LARGEST_FIRST,
    currentHeight: 2000
  });

  assertEqual(result.selected[0].amount, 1000000000n, 'Should select 1 SAL first');
});

test('LARGEST_FIRST minimizes input count', () => {
  const utxos = createMockUTXOs();

  const largestFirst = selectUTXOs(utxos, 500000000n, 1000000n, {
    strategy: UTXO_STRATEGY.LARGEST_FIRST,
    currentHeight: 2000
  });

  const smallestFirst = selectUTXOs(utxos, 500000000n, 1000000n, {
    strategy: UTXO_STRATEGY.SMALLEST_FIRST,
    currentHeight: 2000,
    dustThreshold: 10000000n
  });

  assertTrue(largestFirst.selected.length <= smallestFirst.selected.length,
    'LARGEST_FIRST should use fewer or equal inputs');
});

test('SMALLEST_FIRST selects smallest UTXOs first', () => {
  const utxos = createMockUTXOs();
  const result = selectUTXOs(utxos, 40000000n, 1000000n, {
    strategy: UTXO_STRATEGY.SMALLEST_FIRST,
    currentHeight: 2000,
    dustThreshold: 10000000n
  });

  assertEqual(result.selected[0].amount, 50000000n, 'Should select 50M first');
});

test('FIFO selects oldest UTXOs first', () => {
  const utxos = createMockUTXOs();
  const result = selectUTXOs(utxos, 100000000n, 1000000n, {
    strategy: UTXO_STRATEGY.FIFO,
    currentHeight: 2000
  });

  assertEqual(result.selected[0].blockHeight, 1000, 'Should select oldest first');
});

test('RANDOM produces valid selection', () => {
  const utxos = createMockUTXOs();
  const result = selectUTXOs(utxos, 100000000n, 1000000n, {
    strategy: UTXO_STRATEGY.RANDOM,
    currentHeight: 2000
  });

  assertTrue(result.selected.length > 0, 'Should select UTXOs');
  assertTrue(result.totalAmount >= 100000000n + result.estimatedFee, 'Should cover amount');
});

// Filtering tests
console.log('\n--- Filtering ---');

test('respects minConfirmations', () => {
  const utxos = createMockUTXOs();

  // At height 1205, UTXOs at 1200 only have 5 confirmations
  const result = selectUTXOs(utxos, 40000000n, 1000000n, {
    currentHeight: 1205,
    minConfirmations: 10
  });

  for (const utxo of result.selected) {
    const confirmations = 1205 - utxo.blockHeight;
    assertTrue(confirmations >= 10, `UTXO should have at least 10 confirmations, has ${confirmations}`);
  }
});

test('respects dustThreshold', () => {
  const utxos = [
    { amount: 100n, globalIndex: 1 },
    { amount: 500000n, globalIndex: 2 },
    { amount: 1000000000n, globalIndex: 3 }
  ];

  const result = selectUTXOs(utxos, 100000000n, 1000000n, {
    dustThreshold: 1000000n
  });

  for (const utxo of result.selected) {
    assertTrue(utxo.amount >= 1000000n, 'Should not include dust UTXOs');
  }
});

test('respects maxInputs', () => {
  const utxos = [];
  for (let i = 0; i < 20; i++) {
    utxos.push({ amount: 100000000n, globalIndex: i }); // 100M each
  }

  // Request 300M - could be satisfied by 3 inputs, but limit to 5
  const result = selectUTXOs(utxos, 300000000n, 1000000n, { maxInputs: 5 });

  assertTrue(result.selected.length <= 5, 'Should not exceed maxInputs');
});

// Error cases
console.log('\n--- Error Handling ---');

test('throws on insufficient funds', () => {
  const utxos = [{ amount: 1000000n, globalIndex: 1 }];

  let threw = false;
  try {
    selectUTXOs(utxos, 1000000000n, 1000000n);
  } catch (e) {
    threw = true;
    assertTrue(e.message.includes('Insufficient'), 'Should mention insufficient funds');
  }
  assertTrue(threw, 'Should throw error');
});

test('throws on no eligible UTXOs', () => {
  const utxos = [{ amount: 100n, globalIndex: 1 }]; // Below dust threshold

  let threw = false;
  try {
    selectUTXOs(utxos, 50n, 10n, { dustThreshold: 1000000n });
  } catch (e) {
    threw = true;
    assertTrue(e.message.includes('No eligible'), 'Should mention no eligible UTXOs');
  }
  assertTrue(threw, 'Should throw error');
});

test('handles number inputs (converts to bigint)', () => {
  const utxos = [{ amount: 1000000000, globalIndex: 1 }]; // Number, not bigint

  const result = selectUTXOs(utxos, 100000000, 1000000);

  assertTrue(result.selected.length > 0, 'Should handle number amounts');
});

// Summary
console.log(`\n--- Summary ---`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed === 0) {
  console.log('\n✓ All UTXO selection tests passed!');
  process.exit(0);
} else {
  console.log('\n✗ Some tests failed');
  process.exit(1);
}
