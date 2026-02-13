/**
 * Transaction Scanning Tests
 *
 * Tests for output detection, key derivation, and amount decryption.
 * Phase 3 of salvium-js implementation.
 */

import {
  generateKeyDerivation,
  derivationToScalar,
  derivePublicKey,
  deriveSecretKey,
  deriveSubaddressPublicKey,
  deriveViewTag,
  computeSharedSecret,
  ecdhDecode,
  ecdhDecodeFull,
  ecdhEncode,
  checkOutputOwnership,
  scanOutput
} from '../src/scanning.js';
import {
  generateSeed,
  deriveKeys,
  deriveCarrotKeys
} from '../src/carrot.js';
import {
  generateCNSubaddress,
  bytesToHex,
  hexToBytes
} from '../src/index.js';
import { scalarMultBase, scalarMultPoint } from '../src/ed25519.js';
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
    throw new Error(`${message} Expected "${expected}", got "${actual}"`);
  }
}

function assertLength(value, length, message = '') {
  if (value.length !== length) {
    throw new Error(`${message} Expected length ${length}, got ${value.length}`);
  }
}

function assertTrue(value, message = '') {
  if (!value) {
    throw new Error(`${message} Expected true, got ${value}`);
  }
}

function assertNotNull(value, message = '') {
  if (value === null || value === undefined) {
    throw new Error(`${message} Expected non-null value`);
  }
}

// ============================================================
// Generate Test Wallet Keys
// ============================================================

console.log('\n--- Setting Up Test Keys ---');

// Known test seed for reproducible tests
const TEST_SEED = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
const keys = deriveKeys(TEST_SEED);

console.log(`  Spend Public Key: ${bytesToHex(keys.spendPublicKey).substring(0, 16)}...`);
console.log(`  View Public Key: ${bytesToHex(keys.viewPublicKey).substring(0, 16)}...`);

// Generate a random "transaction" secret key (simulating sender)
const TX_SECRET_KEY = hexToBytes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');

// ============================================================
// Key Derivation Tests
// ============================================================

console.log('\n--- Key Derivation Tests ---');

test('generateKeyDerivation produces 32-byte result', () => {
  // Tx public key = TX_SECRET_KEY * G (what sender publishes)
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  assertNotNull(txPubKey, 'txPubKey should not be null');
  assertLength(txPubKey, 32);

  // Recipient computes derivation using their view secret key
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  assertNotNull(derivation, 'derivation should not be null');
  assertLength(derivation, 32);
});

test('generateKeyDerivation is deterministic', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const d1 = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const d2 = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  assertEqual(bytesToHex(d1), bytesToHex(d2));
});

test('generateKeyDerivation accepts hex strings', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const d1 = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const d2 = generateKeyDerivation(bytesToHex(txPubKey), bytesToHex(keys.viewSecretKey));
  assertEqual(bytesToHex(d1), bytesToHex(d2));
});

test('derivationToScalar produces 32-byte scalar', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const scalar = derivationToScalar(derivation, 0);
  assertNotNull(scalar);
  assertLength(scalar, 32);
});

test('derivationToScalar varies with output index', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const scalar0 = derivationToScalar(derivation, 0);
  const scalar1 = derivationToScalar(derivation, 1);
  const scalar2 = derivationToScalar(derivation, 2);

  assertTrue(bytesToHex(scalar0) !== bytesToHex(scalar1), 'Scalars should differ');
  assertTrue(bytesToHex(scalar1) !== bytesToHex(scalar2), 'Scalars should differ');
  assertTrue(bytesToHex(scalar0) !== bytesToHex(scalar2), 'Scalars should differ');
});

test('derivationToScalar handles large output indices', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  // Test various indices including large ones
  const scalar100 = derivationToScalar(derivation, 100);
  const scalar1000 = derivationToScalar(derivation, 1000);
  const scalar65535 = derivationToScalar(derivation, 65535);

  assertLength(scalar100, 32);
  assertLength(scalar1000, 32);
  assertLength(scalar65535, 32);
});

// ============================================================
// Public Key Derivation Tests
// ============================================================

console.log('\n--- Public Key Derivation Tests ---');

test('derivePublicKey produces 32-byte public key', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const derivedPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);
  assertNotNull(derivedPubKey);
  assertLength(derivedPubKey, 32);
});

test('derivePublicKey produces different keys for different indices', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const pk0 = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const pk1 = derivePublicKey(derivation, 1, keys.spendPublicKey);
  const pk2 = derivePublicKey(derivation, 2, keys.spendPublicKey);

  assertTrue(bytesToHex(pk0) !== bytesToHex(pk1), 'Output keys should differ');
  assertTrue(bytesToHex(pk1) !== bytesToHex(pk2), 'Output keys should differ');
});

test('derivePublicKey is deterministic', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const pk1 = derivePublicKey(derivation, 5, keys.spendPublicKey);
  const pk2 = derivePublicKey(derivation, 5, keys.spendPublicKey);
  assertEqual(bytesToHex(pk1), bytesToHex(pk2));
});

// ============================================================
// Secret Key Derivation Tests
// ============================================================

console.log('\n--- Secret Key Derivation Tests ---');

test('deriveSecretKey produces 32-byte secret key', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const derivedSecKey = deriveSecretKey(derivation, 0, keys.spendSecretKey);
  assertNotNull(derivedSecKey);
  assertLength(derivedSecKey, 32);
});

test('deriveSecretKey produces key that matches derivePublicKey', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  // Derive public key
  const derivedPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);

  // Derive secret key
  const derivedSecKey = deriveSecretKey(derivation, 0, keys.spendSecretKey);

  // Secret key * G should equal the derived public key
  const computedPubKey = scalarMultBase(derivedSecKey);

  assertEqual(bytesToHex(computedPubKey), bytesToHex(derivedPubKey),
    'derivedSecKey * G should equal derivedPubKey');
});

test('deriveSecretKey + derivePublicKey relationship holds for multiple indices', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  for (let i = 0; i < 5; i++) {
    const derivedPubKey = derivePublicKey(derivation, i, keys.spendPublicKey);
    const derivedSecKey = deriveSecretKey(derivation, i, keys.spendSecretKey);
    const computedPubKey = scalarMultBase(derivedSecKey);

    assertEqual(bytesToHex(computedPubKey), bytesToHex(derivedPubKey),
      `Index ${i}: derivedSecKey * G should equal derivedPubKey`);
  }
});

// ============================================================
// Subaddress Detection Tests
// ============================================================

console.log('\n--- Subaddress Detection Tests ---');

test('deriveSubaddressPublicKey produces 32-byte result', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  // Create a fake output key
  const outputKey = derivePublicKey(derivation, 0, keys.spendPublicKey);

  const result = deriveSubaddressPublicKey(outputKey, derivation, 0);
  assertNotNull(result);
  assertLength(result, 32);
});

test('deriveSubaddressPublicKey recovers spend key for main address output', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  // Simulate output to main address: P = B + H_s(D,n)*G
  const outputKey = derivePublicKey(derivation, 0, keys.spendPublicKey);

  // Derive subaddress public key: B' = P - H_s(D,n)*G
  // Should recover the original spend public key
  const recoveredSpendKey = deriveSubaddressPublicKey(outputKey, derivation, 0);

  assertEqual(bytesToHex(recoveredSpendKey), bytesToHex(keys.spendPublicKey),
    'Should recover original spend public key');
});

// ============================================================
// View Tag Tests
// ============================================================

console.log('\n--- View Tag Tests ---');

test('deriveViewTag produces single byte', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const viewTag = deriveViewTag(derivation, 0);
  assertTrue(typeof viewTag === 'number', 'View tag should be a number');
  assertTrue(viewTag >= 0 && viewTag <= 255, 'View tag should be 0-255');
});

test('deriveViewTag varies with output index', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const tags = new Set();
  for (let i = 0; i < 100; i++) {
    tags.add(deriveViewTag(derivation, i));
  }

  // With 100 samples, we should see multiple different view tags
  assertTrue(tags.size > 20, 'Should have variety in view tags');
});

test('deriveViewTag is deterministic', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const tag1 = deriveViewTag(derivation, 42);
  const tag2 = deriveViewTag(derivation, 42);
  assertEqual(tag1, tag2, 'Same inputs should produce same view tag');
});

// ============================================================
// Amount Encryption/Decryption Tests
// ============================================================

console.log('\n--- Amount Encryption/Decryption Tests ---');

test('ecdhEncode/ecdhDecode round-trip works', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const sharedSecret = computeSharedSecret(derivation, 0);

  const originalAmount = 123456789000n; // 1234.56789 SAL in atomic units
  const encrypted = ecdhEncode(originalAmount, sharedSecret);
  const decrypted = ecdhDecode(encrypted, sharedSecret);

  assertEqual(decrypted, originalAmount, 'Decrypted amount should match original');
});

test('ecdhEncode produces 8 bytes', () => {
  const sharedSecret = new Uint8Array(32);
  const encrypted = ecdhEncode(100000000n, sharedSecret);
  assertLength(encrypted, 8);
});

test('ecdhDecode with different shared secrets produces different amounts', () => {
  const encrypted = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
  const secret1 = new Uint8Array(32);
  const secret2 = new Uint8Array(32);
  secret2[0] = 1;

  const amount1 = ecdhDecode(encrypted, secret1);
  const amount2 = ecdhDecode(encrypted, secret2);

  assertTrue(amount1 !== amount2, 'Different secrets should produce different amounts');
});

test('ecdhDecodeFull returns amount and mask', () => {
  const sharedSecret = new Uint8Array(32);
  const encrypted = ecdhEncode(500000000n, sharedSecret);
  const result = ecdhDecodeFull(encrypted, sharedSecret);

  assertEqual(result.amount, 500000000n, 'Amount should match');
  assertNotNull(result.mask, 'Mask should be present');
  assertLength(result.mask, 32, 'Mask should be 32 bytes');
});

test('Amount encryption works for zero', () => {
  const sharedSecret = new Uint8Array(32);
  const encrypted = ecdhEncode(0n, sharedSecret);
  const decrypted = ecdhDecode(encrypted, sharedSecret);
  assertEqual(decrypted, 0n);
});

test('Amount encryption works for max supply', () => {
  // Salvium max supply is ~200M SAL = 200e8 atomic units
  const maxAmount = 20000000000000000n;
  const sharedSecret = new Uint8Array(32);
  crypto.getRandomValues(sharedSecret);

  const encrypted = ecdhEncode(maxAmount, sharedSecret);
  const decrypted = ecdhDecode(encrypted, sharedSecret);
  assertEqual(decrypted, maxAmount);
});

// ============================================================
// Output Ownership Check Tests
// ============================================================

console.log('\n--- Output Ownership Tests ---');

test('checkOutputOwnership returns true for owned output', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  // Create output key as sender would
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);

  // Check if we own it
  const isOwned = checkOutputOwnership(
    outputPubKey,
    txPubKey,
    keys.viewSecretKey,
    keys.spendPublicKey,
    0
  );

  assertTrue(isOwned, 'Should detect owned output');
});

test('checkOutputOwnership returns false for wrong index', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  // Create output for index 0
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);

  // Check with wrong index
  const isOwned = checkOutputOwnership(
    outputPubKey,
    txPubKey,
    keys.viewSecretKey,
    keys.spendPublicKey,
    1 // Wrong index
  );

  assertTrue(!isOwned, 'Should not detect output with wrong index');
});

test('checkOutputOwnership returns false for different wallet', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);

  // Create different wallet
  const otherSeed = generateSeed();
  const otherKeys = deriveKeys(otherSeed);

  const isOwned = checkOutputOwnership(
    outputPubKey,
    txPubKey,
    otherKeys.viewSecretKey,
    otherKeys.spendPublicKey,
    0
  );

  assertTrue(!isOwned, 'Should not detect output for different wallet');
});

// ============================================================
// scanOutput Tests
// ============================================================

console.log('\n--- Scan Output Tests ---');

test('scanOutput detects owned output', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);

  // Create encrypted amount
  const sharedSecret = computeSharedSecret(derivation, 0);
  const amount = 123000000n;
  const encryptedAmount = ecdhEncode(amount, sharedSecret);

  const output = {
    key: outputPubKey,
    encrypted_amount: encryptedAmount
  };

  const result = scanOutput(output, txPubKey, keys.viewSecretKey, keys.spendPublicKey, 0);

  assertNotNull(result, 'Should find owned output');
  assertTrue(result.owned, 'Should be marked as owned');
  assertEqual(result.amount, amount, 'Amount should be decrypted correctly');
  assertEqual(result.outputIndex, 0);
});

test('scanOutput rejects non-owned output', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);

  // Create output for different wallet
  const otherSeed = generateSeed();
  const otherKeys = deriveKeys(otherSeed);
  const otherDerivation = generateKeyDerivation(txPubKey, otherKeys.viewSecretKey);
  const outputPubKey = derivePublicKey(otherDerivation, 0, otherKeys.spendPublicKey);

  const output = {
    key: outputPubKey,
    amount: 100000000
  };

  const result = scanOutput(output, txPubKey, keys.viewSecretKey, keys.spendPublicKey, 0);
  assertEqual(result, null, 'Should not find non-owned output');
});

test('scanOutput respects view tag', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const correctViewTag = deriveViewTag(derivation, 0);

  // Test with correct view tag
  const output1 = {
    key: outputPubKey,
    amount: 100000000,
    view_tag: correctViewTag
  };
  const result1 = scanOutput(output1, txPubKey, keys.viewSecretKey, keys.spendPublicKey, 0);
  assertNotNull(result1, 'Should find output with correct view tag');

  // Test with wrong view tag
  const output2 = {
    key: outputPubKey,
    amount: 100000000,
    view_tag: (correctViewTag + 1) % 256
  };
  const result2 = scanOutput(output2, txPubKey, keys.viewSecretKey, keys.spendPublicKey, 0);
  assertEqual(result2, null, 'Should reject output with wrong view tag');
});

// ============================================================
// Full Wallet Scan Simulation
// ============================================================

console.log('\n--- Full Wallet Scan Simulation ---');

test('Can scan multiple outputs in a transaction', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  // Create 5 outputs, 2 belonging to us (index 1 and 3)
  const outputs = [];
  const expectedOwned = [1, 3];

  for (let i = 0; i < 5; i++) {
    if (expectedOwned.includes(i)) {
      // Our output
      const outputPubKey = derivePublicKey(derivation, i, keys.spendPublicKey);
      const sharedSecret = computeSharedSecret(derivation, i);
      const amount = BigInt((i + 1) * 100000000);
      outputs.push({
        key: outputPubKey,
        encrypted_amount: ecdhEncode(amount, sharedSecret),
        view_tag: deriveViewTag(derivation, i)
      });
    } else {
      // Random output (not ours)
      const randomKey = new Uint8Array(32);
      crypto.getRandomValues(randomKey);
      outputs.push({
        key: randomKey,
        amount: 50000000,
        view_tag: Math.floor(Math.random() * 256)
      });
    }
  }

  // Scan all outputs
  const ownedOutputs = [];
  for (let i = 0; i < outputs.length; i++) {
    const result = scanOutput(outputs[i], txPubKey, keys.viewSecretKey, keys.spendPublicKey, i);
    if (result) {
      ownedOutputs.push(result);
    }
  }

  assertEqual(ownedOutputs.length, 2, 'Should find exactly 2 owned outputs');
  assertEqual(ownedOutputs[0].outputIndex, 1);
  assertEqual(ownedOutputs[1].outputIndex, 3);
  assertEqual(ownedOutputs[0].amount, 200000000n); // Index 1 = 2 * 100000000
  assertEqual(ownedOutputs[1].amount, 400000000n); // Index 3 = 4 * 100000000
});

// ============================================================
// Edge Cases
// ============================================================

console.log('\n--- Edge Cases ---');

test('Functions handle hex string inputs', () => {
  const txPubKeyBytes = scalarMultBase(TX_SECRET_KEY);
  const txPubKeyHex = bytesToHex(txPubKeyBytes);
  const viewSecKeyHex = bytesToHex(keys.viewSecretKey);
  const spendPubKeyHex = bytesToHex(keys.spendPublicKey);

  // Test with hex strings
  const derivation = generateKeyDerivation(txPubKeyHex, viewSecKeyHex);
  assertNotNull(derivation);

  const derivedPubKey = derivePublicKey(bytesToHex(derivation), 0, spendPubKeyHex);
  assertNotNull(derivedPubKey);

  // Compare with byte inputs
  const derivation2 = generateKeyDerivation(txPubKeyBytes, keys.viewSecretKey);
  assertEqual(bytesToHex(derivation), bytesToHex(derivation2));
});

test('derivationToScalar handles output index 0', () => {
  const derivation = new Uint8Array(32);
  const scalar = derivationToScalar(derivation, 0);
  assertLength(scalar, 32);
});

test('computeSharedSecret is deterministic', () => {
  const derivation = new Uint8Array(32);
  crypto.getRandomValues(derivation);

  const ss1 = computeSharedSecret(derivation, 5);
  const ss2 = computeSharedSecret(derivation, 5);
  assertEqual(bytesToHex(ss1), bytesToHex(ss2));
});

// ============================================================
// Summary
// ============================================================

console.log('\n--- Scanning Test Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

if (failed > 0) {
  console.log('\n  Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All scanning tests passed!');
}
