#!/usr/bin/env bun
/**
 * Offline Signing Tests
 *
 * Tests for offline.js:
 * - Unsigned transaction creation and parsing
 * - Signed transaction creation and parsing
 * - Key image export/import
 * - Output export/import
 */

import {
  UNSIGNED_TX_VERSION,
  SIGNED_TX_VERSION,
  createUnsignedTx,
  parseUnsignedTx,
  createSignedTx,
  parseSignedTx,
  exportUnsignedTx,
  importUnsignedTx,
  exportSignedTx,
  importSignedTx,
  exportKeyImages,
  importKeyImages,
  exportOutputs,
  importOutputs,
  verifyUnsignedTx,
  summarizeUnsignedTx
} from '../src/offline.js';

import { bytesToHex, hexToBytes } from '../src/address.js';

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

// Helper to create valid test data
function createTestPublicKey() {
  return new Uint8Array(32).fill(0xab);
}

function createTestTxData() {
  return {
    version: 2,
    unlockTime: 10,  // Use non-zero number (0 is falsy, gets replaced with 0n default)
    fee: 100000000n,
    inputs: [
      {
        amount: 1000000000n,
        outputIndex: 0,
        txHash: 'ab'.repeat(32),
        publicKey: createTestPublicKey(),
        ring: [
          { publicKey: new Uint8Array(32).fill(1), commitment: new Uint8Array(32).fill(2), globalIndex: 100n },
          { publicKey: new Uint8Array(32).fill(3), commitment: new Uint8Array(32).fill(4), globalIndex: 200n }
        ],
        realOutputIndex: 0,
        commitment: new Uint8Array(32).fill(5),
        mask: new Uint8Array(32).fill(6)
      }
    ],
    outputs: [
      {
        amount: 900000000n,
        publicKey: new Uint8Array(32).fill(0xcd),
        viewTag: 0x42,
        commitment: new Uint8Array(32).fill(7)
      }
    ],
    extra: new Uint8Array([1, 2, 3, 4]),
    txSecretKey: new Uint8Array(32).fill(0xef)
  };
}

console.log('=== Offline Signing Tests ===\n');

// ============================================================================
// Constants Tests
// ============================================================================

console.log('--- Constants ---');

test('UNSIGNED_TX_VERSION is defined', () => {
  assertEqual(UNSIGNED_TX_VERSION, 1);
});

test('SIGNED_TX_VERSION is defined', () => {
  assertEqual(SIGNED_TX_VERSION, 1);
});

// ============================================================================
// Unsigned Transaction Tests
// ============================================================================

console.log('\n--- Unsigned Transactions ---');

test('createUnsignedTx creates valid structure', () => {
  const txData = createTestTxData();
  const utx = createUnsignedTx(txData);

  assertEqual(utx.version, UNSIGNED_TX_VERSION);
  assert(utx.created > 0, 'Should have created timestamp');
  assert(utx.tx !== undefined, 'Should have tx data');
  assert(utx.tx.inputs.length === 1, 'Should have 1 input');
  assert(utx.tx.outputs.length === 1, 'Should have 1 output');
});

test('createUnsignedTx converts BigInt to string', () => {
  const txData = createTestTxData();
  const utx = createUnsignedTx(txData);

  // BigInts should be converted to strings for JSON serialization
  assertEqual(typeof utx.tx.fee, 'string');
  assertEqual(utx.tx.fee, '100000000');
});

test('createUnsignedTx converts Uint8Array to hex', () => {
  const txData = createTestTxData();
  const utx = createUnsignedTx(txData);

  // Uint8Arrays should be converted to hex strings
  assertEqual(typeof utx.tx.inputs[0].publicKey, 'string');
  assertEqual(typeof utx.tx.outputs[0].publicKey, 'string');
});

test('parseUnsignedTx restores BigInt values', () => {
  const txData = createTestTxData();
  const utx = createUnsignedTx(txData);
  const parsed = parseUnsignedTx(utx);

  // BigInts should be restored
  assertEqual(typeof parsed.tx.fee, 'bigint');
  assertEqual(parsed.tx.fee, 100000000n);
  assertEqual(typeof parsed.tx.inputs[0].amount, 'bigint');
});

test('parseUnsignedTx restores Uint8Array values', () => {
  const txData = createTestTxData();
  const utx = createUnsignedTx(txData);
  const parsed = parseUnsignedTx(utx);

  // Uint8Arrays should be restored
  assert(parsed.tx.inputs[0].publicKey instanceof Uint8Array);
  assert(parsed.tx.outputs[0].publicKey instanceof Uint8Array);
});

test('exportUnsignedTx returns JSON string', () => {
  const txData = createTestTxData();
  const exported = exportUnsignedTx(txData);

  assertEqual(typeof exported, 'string');
  // Should be valid JSON
  const parsed = JSON.parse(exported);
  assert(parsed.version !== undefined);
});

test('importUnsignedTx round-trips correctly', () => {
  const txData = createTestTxData();
  const exported = exportUnsignedTx(txData);
  const imported = importUnsignedTx(exported);

  assertEqual(imported.version, UNSIGNED_TX_VERSION);
  assertEqual(imported.tx.fee, 100000000n);
  assertEqual(imported.tx.inputs.length, 1);
  assertEqual(imported.tx.outputs.length, 1);
});

test('verifyUnsignedTx returns valid for proper tx', () => {
  const txData = createTestTxData();
  const utx = createUnsignedTx(txData);
  const parsed = parseUnsignedTx(utx);
  const result = verifyUnsignedTx(parsed);

  assertEqual(result.valid, true);
  assertEqual(result.errors.length, 0);
});

test('verifyUnsignedTx detects missing inputs', () => {
  const txData = createTestTxData();
  txData.inputs = [];
  const utx = createUnsignedTx(txData);
  const parsed = parseUnsignedTx(utx);
  const result = verifyUnsignedTx(parsed);

  assertEqual(result.valid, false);
  assert(result.errors.some(e => e.includes('input')));
});

test('verifyUnsignedTx detects missing outputs', () => {
  const txData = createTestTxData();
  txData.outputs = [];
  const utx = createUnsignedTx(txData);
  const parsed = parseUnsignedTx(utx);
  const result = verifyUnsignedTx(parsed);

  assertEqual(result.valid, false);
  assert(result.errors.some(e => e.includes('output')));
});

test('summarizeUnsignedTx returns summary', () => {
  const txData = createTestTxData();
  const utx = createUnsignedTx(txData);
  const parsed = parseUnsignedTx(utx);
  const summary = summarizeUnsignedTx(parsed);

  assertEqual(summary.inputCount, 1);
  assertEqual(summary.outputCount, 1);
  assertEqual(summary.fee, 100000000n);
  assert(summary.totalIn !== undefined);
  assert(summary.totalOut !== undefined);
  assert(summary.ringSize === 2);
});

// ============================================================================
// Signed Transaction Tests
// ============================================================================

console.log('\n--- Signed Transactions ---');

test('createSignedTx requires valid transaction', () => {
  // createSignedTx expects a transaction object that can be serialized
  // For testing, we'll verify it handles the expected structure
  let threw = false;
  try {
    createSignedTx(null);
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Should throw for null transaction');
});

test('parseSignedTx validates version', () => {
  let threw = false;
  try {
    parseSignedTx({ version: 999 });
  } catch (e) {
    threw = true;
    assert(e.message.includes('version'), 'Error should mention version');
  }
  assert(threw, 'Should throw for invalid version');
});

test('exportSignedTx returns string', () => {
  const signedTx = {
    version: SIGNED_TX_VERSION,
    created: Date.now(),
    txHash: 'ab'.repeat(32),
    txBlob: 'deadbeef',
    metadata: {}
  };

  const exported = exportSignedTx(signedTx);
  assertEqual(typeof exported, 'string');
});

test('importSignedTx round-trips correctly', () => {
  const original = {
    version: SIGNED_TX_VERSION,
    created: Date.now(),
    txHash: 'ef'.repeat(32),
    txBlob: 'cafebabe',
    metadata: { fee: '1000' }
  };

  const exported = exportSignedTx(original);
  const imported = importSignedTx(exported);

  assertEqual(imported.version, original.version);
  assertEqual(imported.txHash, original.txHash);
});

// ============================================================================
// Key Image Export/Import Tests
// ============================================================================

console.log('\n--- Key Image Export/Import ---');

test('exportKeyImages creates valid export', () => {
  const outputs = [
    {
      keyImage: new Uint8Array(32).fill(0xaa),
      txHash: 'ab'.repeat(32),
      outputIndex: 0,
      amount: 1000000000n
    },
    {
      keyImage: new Uint8Array(32).fill(0xbb),
      txHash: 'cd'.repeat(32),
      outputIndex: 1,
      amount: 2000000000n
    }
  ];

  const exported = exportKeyImages(outputs);

  assertEqual(exported.version, 1);
  assert(exported.created > 0);
  assertEqual(exported.keyImages.length, 2);
  assertEqual(typeof exported.keyImages[0].keyImage, 'string'); // Hex encoded
});

test('importKeyImages parses export', () => {
  const outputs = [
    {
      keyImage: new Uint8Array(32).fill(0xcc),
      txHash: 'ef'.repeat(32),
      outputIndex: 0,
      amount: 5000000000n
    }
  ];

  const exported = exportKeyImages(outputs);
  const imported = importKeyImages(exported);

  assertEqual(imported.length, 1);
  assert(imported[0].keyImage instanceof Uint8Array);
  assertEqual(imported[0].keyImage.length, 32);
  assertEqual(imported[0].amount, 5000000000n);
});

test('key images round-trip correctly', () => {
  const original = [
    {
      keyImage: new Uint8Array(32).fill(0x11),
      txHash: '22'.repeat(32),
      outputIndex: 0,
      amount: 100n
    },
    {
      keyImage: new Uint8Array(32).fill(0x33),
      txHash: '44'.repeat(32),
      outputIndex: 1,
      amount: 200n
    }
  ];

  const exported = exportKeyImages(original);
  const imported = importKeyImages(exported);

  assertEqual(imported.length, 2);
  assertEqual(bytesToHex(imported[0].keyImage), bytesToHex(original[0].keyImage));
  assertEqual(bytesToHex(imported[1].keyImage), bytesToHex(original[1].keyImage));
  assertEqual(imported[0].amount, 100n);
  assertEqual(imported[1].amount, 200n);
});

// ============================================================================
// Output Export/Import Tests
// ============================================================================

console.log('\n--- Output Export/Import ---');

test('exportOutputs creates valid export', () => {
  const outputs = [
    {
      txHash: 'ab'.repeat(32),
      outputIndex: 0,
      globalIndex: 12345n,
      amount: 1000000000n,
      publicKey: new Uint8Array(32).fill(0xaa),
      keyImage: new Uint8Array(32).fill(0xbb),
      commitment: new Uint8Array(32).fill(0xcc),
      mask: new Uint8Array(32).fill(0xdd),
      blockHeight: 100000,
      assetType: 'SAL'
    }
  ];

  const exported = exportOutputs(outputs);

  assertEqual(exported.version, 1);
  assert(exported.created > 0);
  assertEqual(exported.outputs.length, 1);
  assertEqual(typeof exported.outputs[0].publicKey, 'string'); // Hex encoded
  assertEqual(exported.outputs[0].amount, '1000000000'); // String
});

test('importOutputs parses export', () => {
  const original = [
    {
      txHash: 'cd'.repeat(32),
      outputIndex: 1,
      globalIndex: 99999n,
      amount: 2000000000n,
      publicKey: new Uint8Array(32).fill(0xee),
      blockHeight: 50000,
      assetType: 'SAL'
    }
  ];

  const exported = exportOutputs(original);
  const imported = importOutputs(exported);

  assertEqual(imported.length, 1);
  assert(imported[0].publicKey instanceof Uint8Array);
  assertEqual(imported[0].amount, 2000000000n);
  assertEqual(imported[0].globalIndex, 99999n);
});

test('outputs round-trip preserves BigInt amounts', () => {
  const original = [
    {
      txHash: '11'.repeat(32),
      outputIndex: 0,
      globalIndex: 1n,
      amount: 123456789012345n,
      publicKey: new Uint8Array(32).fill(0x11),
      blockHeight: 1000
    },
    {
      txHash: '22'.repeat(32),
      outputIndex: 0,
      globalIndex: 2n,
      amount: 987654321098765n,
      publicKey: new Uint8Array(32).fill(0x22),
      blockHeight: 2000
    }
  ];

  const exported = exportOutputs(original);
  const imported = importOutputs(exported);

  assertEqual(imported[0].amount, 123456789012345n);
  assertEqual(imported[1].amount, 987654321098765n);
});

test('outputs round-trip preserves all fields', () => {
  const original = [
    {
      txHash: 'aa'.repeat(32),
      outputIndex: 1,
      globalIndex: 99999n,
      amount: 1000n,
      publicKey: new Uint8Array(32).fill(0xaa),
      keyImage: new Uint8Array(32).fill(0xbb),
      commitment: new Uint8Array(32).fill(0xcc),
      mask: new Uint8Array(32).fill(0xdd),
      blockHeight: 50000,
      assetType: 'SAL',
      subaddressIndex: { major: 0, minor: 5 }
    }
  ];

  const exported = exportOutputs(original);
  const imported = importOutputs(exported);

  assertEqual(imported[0].txHash, original[0].txHash);
  assertEqual(imported[0].outputIndex, original[0].outputIndex);
  assertEqual(imported[0].globalIndex, 99999n);
  assertEqual(imported[0].blockHeight, original[0].blockHeight);
  assertEqual(imported[0].assetType, 'SAL');
});

// ============================================================================
// Error Handling Tests
// ============================================================================

console.log('\n--- Error Handling ---');

test('importUnsignedTx throws on invalid data', () => {
  let threw = false;
  try {
    importUnsignedTx('not valid json');
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Should throw on invalid data');
});

test('importSignedTx throws on invalid data', () => {
  let threw = false;
  try {
    importSignedTx('not valid json');
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Should throw on invalid data');
});

test('importKeyImages throws on invalid data', () => {
  let threw = false;
  try {
    importKeyImages('garbage');
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Should throw on invalid data');
});

test('importOutputs throws on invalid data', () => {
  let threw = false;
  try {
    importOutputs('garbage');
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Should throw on invalid data');
});

test('parseUnsignedTx throws on wrong version', () => {
  let threw = false;
  try {
    parseUnsignedTx({ version: 999, tx: {} });
  } catch (e) {
    threw = true;
    assert(e.message.includes('version'));
  }
  assert(threw, 'Should throw on invalid version');
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
  console.log('\n✓ All offline signing tests passed!');
  process.exit(0);
}
