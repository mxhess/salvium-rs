/**
 * Key Derivation Tests
 *
 * Tests for Ed25519 operations and key derivation (CryptoNote and CARROT).
 */

import {
  scalarMultBase,
  scalarMultPoint,
  pointAddCompressed,
  getGeneratorG,
  getGeneratorT
} from '../src/crypto/index.js';

// Get generator points
const G = getGeneratorG();
const T = getGeneratorT();

// Simple point validation (check it's 32 bytes and not all zeros)
function isValidPoint(p) {
  if (!p || p.length !== 32) return false;
  for (let i = 0; i < 32; i++) {
    if (p[i] !== 0) return true;
  }
  return false;
}
import { deriveCarrotKeys, deriveKeys } from '../src/carrot.js';
import { bytesToHex, hexToBytes } from '../src/index.js';
import { initCrypto } from '../src/crypto/index.js';

await initCrypto();

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (error) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${error.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, message = '') {
  if (actual !== expected) {
    throw new Error(`${message} Expected ${expected}, got ${actual}`);
  }
}

function assertNotEqual(actual, expected, message = '') {
  if (actual === expected) {
    throw new Error(`${message} Values should not be equal: ${actual}`);
  }
}

function assertTrue(value, message = '') {
  if (!value) {
    throw new Error(`${message} Expected true, got ${value}`);
  }
}

function assertFalse(value, message = '') {
  if (value) {
    throw new Error(`${message} Expected false, got ${value}`);
  }
}

function assertLength(value, length, message = '') {
  if (value.length !== length) {
    throw new Error(`${message} Expected length ${length}, got ${value.length}`);
  }
}

// Test vectors
const TEST_SEED = hexToBytes('8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94');
const SCALAR_ONE = hexToBytes('0100000000000000000000000000000000000000000000000000000000000000');
const SCALAR_TWO = hexToBytes('0200000000000000000000000000000000000000000000000000000000000000');

// ============================================================
// Generator Point Tests
// ============================================================

console.log('\n--- Generator Point Tests ---');

test('G (base point) is 32 bytes', () => {
  assertLength(G, 32);
});

test('T (CARROT generator) is 32 bytes', () => {
  assertLength(T, 32);
});

test('G and T are different points', () => {
  assertNotEqual(bytesToHex(G), bytesToHex(T));
});

test('G is a valid curve point', () => {
  assertTrue(isValidPoint(G));
});

test('T is a valid curve point', () => {
  assertTrue(isValidPoint(T));
});

// ============================================================
// Scalar Multiplication Tests
// ============================================================

console.log('\n--- Scalar Multiplication Tests ---');

test('scalarMultBase returns 32 bytes', () => {
  const result = scalarMultBase(SCALAR_ONE);
  assertLength(result, 32);
});

test('scalarMultBase(1) equals G', () => {
  const result = scalarMultBase(SCALAR_ONE);
  assertEqual(bytesToHex(result), bytesToHex(G));
});

test('scalarMultBase is deterministic', () => {
  const r1 = scalarMultBase(TEST_SEED);
  const r2 = scalarMultBase(TEST_SEED);
  assertEqual(bytesToHex(r1), bytesToHex(r2));
});

test('scalarMultBase with different scalars gives different points', () => {
  const r1 = scalarMultBase(SCALAR_ONE);
  const r2 = scalarMultBase(SCALAR_TWO);
  assertNotEqual(bytesToHex(r1), bytesToHex(r2));
});

test('scalarMultPoint returns 32 bytes', () => {
  const result = scalarMultPoint(SCALAR_TWO, G);
  assertLength(result, 32);
});

test('scalarMultPoint(2, G) equals scalarMultBase(2)', () => {
  const r1 = scalarMultPoint(SCALAR_TWO, G);
  const r2 = scalarMultBase(SCALAR_TWO);
  assertEqual(bytesToHex(r1), bytesToHex(r2));
});

// ============================================================
// Point Addition Tests
// ============================================================

console.log('\n--- Point Addition Tests ---');

test('pointAddCompressed returns 32 bytes', () => {
  const result = pointAddCompressed(G, G);
  assertLength(result, 32);
});

test('G + G equals 2*G', () => {
  const added = pointAddCompressed(G, G);
  const doubled = scalarMultBase(SCALAR_TWO);
  assertEqual(bytesToHex(added), bytesToHex(doubled));
});

test('Point addition is commutative', () => {
  const P1 = scalarMultBase(TEST_SEED);
  const P2 = scalarMultBase(SCALAR_TWO);
  const r1 = pointAddCompressed(P1, P2);
  const r2 = pointAddCompressed(P2, P1);
  assertEqual(bytesToHex(r1), bytesToHex(r2));
});

// ============================================================
// Point Validation Tests
// ============================================================

console.log('\n--- Point Validation Tests ---');

test('isValidPoint accepts valid points', () => {
  assertTrue(isValidPoint(G));
  assertTrue(isValidPoint(T));
  assertTrue(isValidPoint(scalarMultBase(TEST_SEED)));
});

test('isValidPoint rejects all zeros', () => {
  assertFalse(isValidPoint(new Uint8Array(32)));
});

test('isValidPoint rejects wrong length', () => {
  assertFalse(isValidPoint(new Uint8Array(31)));
  assertFalse(isValidPoint(new Uint8Array(33)));
});

// ============================================================
// CryptoNote Key Derivation Tests
// ============================================================

console.log('\n--- CryptoNote Key Derivation Tests ---');

test('deriveKeys returns all expected keys', () => {
  const keys = deriveKeys(TEST_SEED);
  assertLength(keys.spendSecretKey, 32);
  assertLength(keys.spendPublicKey, 32);
  assertLength(keys.viewSecretKey, 32);
  assertLength(keys.viewPublicKey, 32);
});

test('deriveKeys is deterministic', () => {
  const k1 = deriveKeys(TEST_SEED);
  const k2 = deriveKeys(TEST_SEED);
  assertEqual(bytesToHex(k1.spendSecretKey), bytesToHex(k2.spendSecretKey));
  assertEqual(bytesToHex(k1.spendPublicKey), bytesToHex(k2.spendPublicKey));
  assertEqual(bytesToHex(k1.viewSecretKey), bytesToHex(k2.viewSecretKey));
  assertEqual(bytesToHex(k1.viewPublicKey), bytesToHex(k2.viewPublicKey));
});

test('deriveKeys produces different keys for different seeds', () => {
  const k1 = deriveKeys(TEST_SEED);
  const k2 = deriveKeys(hexToBytes('0000000000000000000000000000000000000000000000000000000000000001'));
  assertNotEqual(bytesToHex(k1.spendPublicKey), bytesToHex(k2.spendPublicKey));
  assertNotEqual(bytesToHex(k1.viewPublicKey), bytesToHex(k2.viewPublicKey));
});

test('deriveKeys spend public key is valid point', () => {
  const keys = deriveKeys(TEST_SEED);
  assertTrue(isValidPoint(keys.spendPublicKey));
});

test('deriveKeys view public key is valid point', () => {
  const keys = deriveKeys(TEST_SEED);
  assertTrue(isValidPoint(keys.viewPublicKey));
});

test('deriveKeys accepts hex string input', () => {
  const hexSeed = '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94';
  const keys = deriveKeys(hexSeed);
  const keysFromBytes = deriveKeys(TEST_SEED);
  assertEqual(bytesToHex(keys.spendSecretKey), bytesToHex(keysFromBytes.spendSecretKey));
});

test('deriveKeys throws for wrong seed length', () => {
  let threw = false;
  try {
    deriveKeys(new Uint8Array(31));
  } catch (e) {
    threw = true;
  }
  assertTrue(threw, 'Should throw for 31-byte seed');
});

// ============================================================
// CARROT Key Derivation Tests
// ============================================================

console.log('\n--- CARROT Key Derivation Tests ---');

test('deriveCarrotKeys returns all expected keys', () => {
  const keys = deriveCarrotKeys(TEST_SEED);
  // All keys returned as 64-char hex strings (32 bytes)
  assertLength(keys.proveSpendKey, 64);
  assertLength(keys.generateImageKey, 64);
  assertLength(keys.viewIncomingKey, 64);
  assertLength(keys.generateAddressSecret, 64);
  assertLength(keys.viewBalanceSecret, 64);
  assertLength(keys.masterSecret, 64);
});

test('deriveCarrotKeys is deterministic', () => {
  const k1 = deriveCarrotKeys(TEST_SEED);
  const k2 = deriveCarrotKeys(TEST_SEED);
  assertEqual(k1.proveSpendKey, k2.proveSpendKey);
  assertEqual(k1.generateImageKey, k2.generateImageKey);
  assertEqual(k1.viewIncomingKey, k2.viewIncomingKey);
  assertEqual(k1.generateAddressSecret, k2.generateAddressSecret);
  assertEqual(k1.viewBalanceSecret, k2.viewBalanceSecret);
});

test('deriveCarrotKeys produces different keys for different seeds', () => {
  const k1 = deriveCarrotKeys(TEST_SEED);
  const k2 = deriveCarrotKeys(hexToBytes('0000000000000000000000000000000000000000000000000000000000000001'));
  assertNotEqual(k1.proveSpendKey, k2.proveSpendKey);
  assertNotEqual(k1.viewBalanceSecret, k2.viewBalanceSecret);
});

test('deriveCarrotKeys returns valid hex strings', () => {
  const keys = deriveCarrotKeys(TEST_SEED);
  // All keys should be valid 64-char hex strings
  assertTrue(/^[0-9a-f]{64}$/.test(keys.proveSpendKey));
  assertTrue(/^[0-9a-f]{64}$/.test(keys.viewBalanceSecret));
  assertTrue(/^[0-9a-f]{64}$/.test(keys.generateImageKey));
});

// ============================================================
// Summary
// ============================================================

console.log('\n--- Key Derivation Test Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

if (failed > 0) {
  console.log('\n⚠️  Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All key derivation tests passed!');
}
