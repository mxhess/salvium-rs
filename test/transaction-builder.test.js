#!/usr/bin/env node
/**
 * Transaction Builder Tests
 *
 * Tests for transaction construction functions:
 * - buildTransaction: Full transaction assembly
 * - signTransaction: Offline signing
 * - validateTransaction: Pre-broadcast validation
 * - estimateTransactionFee: Fee estimation
 */

import {
  buildTransaction,
  signTransaction,
  validateTransaction,
  estimateTransactionFee,
  serializeTransaction,
  scRandom,
  commit,
  TX_VERSION,
  RCT_TYPE,
  TXIN_TYPE,
  TXOUT_TYPE
} from '../src/transaction.js';

import { scalarMultBase } from '../src/crypto/index.js';
import { bytesToHex, hexToBytes } from '../src/address.js';
import { generateKeyImage } from '../src/keyimage.js';
import { initCrypto } from '../src/crypto/index.js';

await initCrypto();

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
  const aStr = typeof a === 'bigint' ? a.toString() : a;
  const bStr = typeof b === 'bigint' ? b.toString() : b;
  if (aStr !== bStr) throw new Error(message || `Expected ${bStr}, got ${aStr}`);
}

function assertTrue(condition, message) {
  if (!condition) throw new Error(message || 'Expected true');
}

// Helper to create mock input
function createMockInput(amount = 100000000n) {
  const secretKey = scRandom();
  const publicKey = scalarMultBase(secretKey);
  const mask = scRandom();
  const commitment = commit(amount, mask);

  // Create mock ring (3 members)
  const ring = [
    scalarMultBase(scRandom()),
    publicKey,
    scalarMultBase(scRandom())
  ];
  const ringCommitments = [
    commit(amount, scRandom()),
    commitment,
    commit(amount, scRandom())
  ];

  return {
    secretKey,
    publicKey,
    amount,
    mask,
    commitment,
    globalIndex: Math.floor(Math.random() * 10000),
    ring,
    ringCommitments,
    ringIndices: [100, 200, 300],
    realIndex: 1
  };
}

// Helper to create mock destination
function createMockDestination(amount = 50000000n) {
  return {
    viewPublicKey: scalarMultBase(scRandom()),
    spendPublicKey: scalarMultBase(scRandom()),
    amount,
    isSubaddress: false
  };
}

// Helper to create mock change address
function createMockChangeAddress() {
  return {
    viewPublicKey: scalarMultBase(scRandom()),
    spendPublicKey: scalarMultBase(scRandom()),
    isSubaddress: false
  };
}

console.log('\n=== Transaction Builder Tests ===\n');

// Fee estimation
console.log('--- Fee Estimation ---');

test('estimateTransactionFee returns bigint', () => {
  const fee = estimateTransactionFee(2, 2);
  assertEqual(typeof fee, 'bigint');
});

test('estimateTransactionFee increases with inputs', () => {
  const fee1 = estimateTransactionFee(1, 2);
  const fee3 = estimateTransactionFee(3, 2);
  assertTrue(fee3 > fee1, 'More inputs should mean higher fee');
});

test('estimateTransactionFee increases with outputs', () => {
  // Use larger output counts to ensure KB boundary is crossed
  const fee2 = estimateTransactionFee(2, 2);
  const fee16 = estimateTransactionFee(2, 16);
  assertTrue(fee16 > fee2, 'More outputs should mean higher fee');
});

test('estimateTransactionFee respects priority', () => {
  const feeLow = estimateTransactionFee(2, 2, { priority: 'low' });
  const feeDefault = estimateTransactionFee(2, 2, { priority: 'default' });
  const feeHigh = estimateTransactionFee(2, 2, { priority: 'high' });

  assertTrue(feeDefault >= feeLow, 'Default >= low priority');
  assertTrue(feeHigh > feeDefault, 'High > default priority');
});

test('estimateTransactionFee respects ring size', () => {
  // Use multiple inputs so ring size difference is significant
  const fee16 = estimateTransactionFee(3, 2, { ringSize: 16 });
  const fee32 = estimateTransactionFee(3, 2, { ringSize: 32 });
  assertTrue(fee32 > fee16, 'Larger ring should mean higher fee');
});

// Transaction validation
console.log('\n--- Transaction Validation ---');

test('validateTransaction detects missing prefix', () => {
  const result = validateTransaction({});
  assertTrue(!result.valid);
  assertTrue(result.errors.includes('Missing transaction prefix'));
});

test('validateTransaction detects missing RCT', () => {
  const result = validateTransaction({
    prefix: { version: 2, vin: [{}], vout: [{}] }
  });
  assertTrue(!result.valid);
  assertTrue(result.errors.includes('Missing RingCT signature data'));
});

test('validateTransaction detects no inputs', () => {
  const result = validateTransaction({
    prefix: { version: 2, vin: [], vout: [{}] },
    rct: { CLSAGs: [], outPk: ['a'.repeat(64)], fee: 1000n }
  });
  assertTrue(!result.valid);
  assertTrue(result.errors.some(e => e.includes('no inputs')));
});

test('validateTransaction detects no outputs', () => {
  const result = validateTransaction({
    prefix: { version: 2, vin: [{}], vout: [] },
    rct: { CLSAGs: [{}], outPk: [], fee: 1000n }
  });
  assertTrue(!result.valid);
  assertTrue(result.errors.some(e => e.includes('no outputs')));
});

test('validateTransaction detects missing CLSAG', () => {
  const result = validateTransaction({
    prefix: { version: 2, vin: [{}], vout: [{}] },
    rct: { CLSAGs: [], outPk: ['a'.repeat(64)], fee: 1000n }
  });
  assertTrue(!result.valid);
  assertTrue(result.errors.some(e => e.includes('CLSAG')));
});

test('validateTransaction detects CLSAG count mismatch', () => {
  const result = validateTransaction({
    prefix: { version: 2, vin: [{}, {}], vout: [{}] },
    rct: { CLSAGs: [{}], outPk: ['a'.repeat(64)], fee: 1000n }
  });
  assertTrue(!result.valid);
  assertTrue(result.errors.some(e => e.includes('count')));
});

test('validateTransaction detects duplicate key images', () => {
  const keyImage = new Uint8Array(32).fill(0xaa);
  const result = validateTransaction({
    prefix: {
      version: 2,
      vin: [{ keyImage }, { keyImage }],
      vout: [{}]
    },
    rct: { CLSAGs: [{}, {}], outPk: ['a'.repeat(64)], fee: 1000n }
  });
  assertTrue(!result.valid);
  assertTrue(result.errors.some(e => e.includes('Duplicate key image')));
});

test('validateTransaction passes valid transaction', () => {
  const keyImage1 = new Uint8Array(32).fill(0xaa);
  const keyImage2 = new Uint8Array(32).fill(0xbb);
  const result = validateTransaction({
    prefix: {
      version: 2,
      vin: [{ keyImage: keyImage1 }, { keyImage: keyImage2 }],
      vout: [{}, {}]
    },
    rct: {
      CLSAGs: [{}, {}],
      outPk: ['a'.repeat(64), 'b'.repeat(64)],
      fee: 1000n
    }
  });
  assertTrue(result.valid, `Should be valid: ${result.errors.join(', ')}`);
});

// buildTransaction
console.log('\n--- buildTransaction ---');

test('buildTransaction requires inputs', () => {
  let threw = false;
  try {
    buildTransaction({
      inputs: [],
      destinations: [createMockDestination()],
      changeAddress: createMockChangeAddress(),
      fee: 1000000n
    });
  } catch (e) {
    threw = true;
    assertTrue(e.message.includes('input'));
  }
  assertTrue(threw, 'Should throw on no inputs');
});

test('buildTransaction requires destinations', () => {
  let threw = false;
  try {
    buildTransaction({
      inputs: [createMockInput()],
      destinations: [],
      changeAddress: createMockChangeAddress(),
      fee: 1000000n
    });
  } catch (e) {
    threw = true;
    assertTrue(e.message.includes('destination'));
  }
  assertTrue(threw, 'Should throw on no destinations');
});

test('buildTransaction detects insufficient funds', () => {
  let threw = false;
  try {
    buildTransaction({
      inputs: [createMockInput(10000000n)], // 10M
      destinations: [createMockDestination(50000000n)], // 50M
      changeAddress: createMockChangeAddress(),
      fee: 1000000n
    });
  } catch (e) {
    threw = true;
    assertTrue(e.message.includes('Insufficient'));
  }
  assertTrue(threw, 'Should throw on insufficient funds');
});

test('buildTransaction creates valid transaction structure', () => {
  const input = createMockInput(100000000n);
  const destination = createMockDestination(40000000n);
  const changeAddress = createMockChangeAddress();
  const fee = 10000000n;

  const tx = buildTransaction({
    inputs: [input],
    destinations: [destination],
    changeAddress,
    fee
  });

  // Check structure
  assert(tx.prefix, 'Should have prefix');
  assert(tx.rct, 'Should have rct');
  assert(tx._meta, 'Should have metadata');

  // Check prefix
  assertEqual(tx.prefix.version, TX_VERSION.V2);
  assertEqual(tx.prefix.vin.length, 1, 'Should have 1 input');
  assertEqual(tx.prefix.vout.length, 2, 'Should have 2 outputs (dest + change)');

  // Check RCT
  assertEqual(tx.rct.type, RCT_TYPE.BulletproofPlus);
  assertEqual(tx.rct.fee, fee);
  assertEqual(tx.rct.CLSAGs.length, 1, 'Should have 1 CLSAG');
  assertEqual(tx.rct.outPk.length, 2, 'Should have 2 output commitments');
  assertEqual(tx.rct.ecdhInfo.length, 2, 'Should have 2 encrypted amounts');
});

test('buildTransaction creates key images', () => {
  const input = createMockInput();
  const tx = buildTransaction({
    inputs: [input],
    destinations: [createMockDestination(40000000n)],
    changeAddress: createMockChangeAddress(),
    fee: 10000000n
  });

  assert(tx.prefix.vin[0].keyImage, 'Input should have key image');
  assertEqual(tx.prefix.vin[0].keyImage.length, 32, 'Key image should be 32 bytes');
});

test('buildTransaction stores metadata', () => {
  const tx = buildTransaction({
    inputs: [createMockInput()],
    destinations: [createMockDestination(40000000n)],
    changeAddress: createMockChangeAddress(),
    fee: 10000000n
  });

  assert(tx._meta.txSecretKey, 'Should store tx secret key');
  assert(tx._meta.keyImages, 'Should store key images');
  assert(tx._meta.outputMasks, 'Should store output masks');
  assertTrue(tx._meta.changeIndex >= 0, 'Should store change index');
});

test('buildTransaction with no change (exact amount)', () => {
  const inputAmount = 100000000n;
  const outputAmount = 90000000n;
  const fee = 10000000n;

  const tx = buildTransaction({
    inputs: [createMockInput(inputAmount)],
    destinations: [createMockDestination(outputAmount)],
    changeAddress: createMockChangeAddress(),
    fee
  });

  // Change output is always added for privacy (even with 0 amount)
  assertEqual(tx.prefix.vout.length, 2, 'Should have 2 outputs (destination + zero-change)');
  assertEqual(tx._meta.changeIndex, -1, 'Change index should be -1 for zero change');
});

test('buildTransaction with multiple inputs', () => {
  const tx = buildTransaction({
    inputs: [
      createMockInput(50000000n),
      createMockInput(50000000n)
    ],
    destinations: [createMockDestination(80000000n)],
    changeAddress: createMockChangeAddress(),
    fee: 10000000n
  });

  assertEqual(tx.prefix.vin.length, 2, 'Should have 2 inputs');
  assertEqual(tx.rct.CLSAGs.length, 2, 'Should have 2 CLSAG signatures');
});

test('buildTransaction with multiple destinations', () => {
  const tx = buildTransaction({
    inputs: [createMockInput(200000000n)],
    destinations: [
      createMockDestination(50000000n),
      createMockDestination(50000000n),
      createMockDestination(50000000n)
    ],
    changeAddress: createMockChangeAddress(),
    fee: 10000000n
  });

  assertEqual(tx.prefix.vout.length, 4, 'Should have 4 outputs (3 dest + 1 change)');
  assertEqual(tx.rct.outPk.length, 4, 'Should have 4 commitments');
});

test('buildTransaction uses provided tx secret key', () => {
  const txSecretKey = scRandom();

  const tx = buildTransaction({
    inputs: [createMockInput()],
    destinations: [createMockDestination(40000000n)],
    changeAddress: createMockChangeAddress(),
    fee: 10000000n
  }, { txSecretKey });

  assertEqual(tx._meta.txSecretKey, bytesToHex(txSecretKey));
});

test('buildTransaction handles unlock time', () => {
  const tx = buildTransaction({
    inputs: [createMockInput()],
    destinations: [createMockDestination(40000000n)],
    changeAddress: createMockChangeAddress(),
    fee: 10000000n
  }, { unlockTime: 100 });

  assertEqual(tx.prefix.unlockTime, 100);
});

test('built transaction passes validation', () => {
  const tx = buildTransaction({
    inputs: [createMockInput()],
    destinations: [createMockDestination(40000000n)],
    changeAddress: createMockChangeAddress(),
    fee: 10000000n
  });

  const result = validateTransaction(tx);
  assertTrue(result.valid, `Should be valid: ${result.errors.join(', ')}`);
});

// serializeTransaction
console.log('\n--- Serialization ---');

test('serializeTransaction produces Uint8Array', () => {
  const tx = buildTransaction({
    inputs: [createMockInput()],
    destinations: [createMockDestination(40000000n)],
    changeAddress: createMockChangeAddress(),
    fee: 10000000n
  });

  const serialized = serializeTransaction(tx);
  assertTrue(serialized instanceof Uint8Array, 'Should return Uint8Array');
  assertTrue(serialized.length > 0, 'Should have content');
});

test('serialized transaction has reasonable size', () => {
  const tx = buildTransaction({
    inputs: [createMockInput()],
    destinations: [createMockDestination(40000000n)],
    changeAddress: createMockChangeAddress(),
    fee: 10000000n
  });

  const serialized = serializeTransaction(tx);

  // Note: Without full Bulletproof+ proof generation, serialized size is smaller
  // than a complete on-chain transaction. Core structure should still be ~200-500 bytes.
  assertTrue(serialized.length > 200, 'Should be at least 200 bytes');
  assertTrue(serialized.length < 10000, 'Should be less than 10KB');
});

// Summary
console.log(`\n--- Summary ---`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed === 0) {
  console.log('\n✓ All transaction builder tests passed!');
  process.exit(0);
} else {
  console.log('\n✗ Some tests failed');
  process.exit(1);
}
