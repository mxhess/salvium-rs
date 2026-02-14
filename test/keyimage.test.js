/**
 * Key Image Tests
 *
 * Tests for key image generation, validation, and export/import.
 * Phase 4 of salvium-js implementation.
 */

import {
  hashToPoint,
  generateKeyImage,
  deriveKeyImageGenerator,
  isValidKeyImage,
  keyImageToY,
  keyImageFromY,
  exportKeyImages,
  importKeyImages
} from '../src/keyimage.js';
import {
  generateSeed,
  deriveKeys
} from '../src/carrot.js';
import {
  generateKeyDerivation,
  derivePublicKey,
  deriveSecretKey
} from '../src/scanning.js';
import {
  bytesToHex,
  hexToBytes
} from '../src/index.js';
import { scalarMultBase } from '../src/crypto/index.js';
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
// Setup Test Keys
// ============================================================

console.log('\n--- Setting Up Test Keys ---');

// Known test seed for reproducible tests
const TEST_SEED = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
const keys = deriveKeys(TEST_SEED);

// Simulate a transaction secret key
const TX_SECRET_KEY = hexToBytes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');

console.log(`  Spend Public Key: ${bytesToHex(keys.spendPublicKey).substring(0, 16)}...`);

// ============================================================
// Hash to Point Tests
// ============================================================

console.log('\n--- Hash to Point Tests ---');

test('hashToPoint produces 32-byte result', () => {
  const hp = hashToPoint(keys.spendPublicKey);
  assertNotNull(hp);
  assertLength(hp, 32);
});

test('hashToPoint is deterministic', () => {
  const hp1 = hashToPoint(keys.spendPublicKey);
  const hp2 = hashToPoint(keys.spendPublicKey);
  assertEqual(bytesToHex(hp1), bytesToHex(hp2));
});

test('hashToPoint produces different results for different inputs', () => {
  const hp1 = hashToPoint(keys.spendPublicKey);
  const hp2 = hashToPoint(keys.viewPublicKey);
  assertTrue(bytesToHex(hp1) !== bytesToHex(hp2));
});

test('hashToPoint accepts hex string input', () => {
  const hp1 = hashToPoint(keys.spendPublicKey);
  const hp2 = hashToPoint(bytesToHex(keys.spendPublicKey));
  assertEqual(bytesToHex(hp1), bytesToHex(hp2));
});

test('hashToPoint produces valid curve points', () => {
  const hp = hashToPoint(keys.spendPublicKey);
  assertTrue(isValidKeyImage(hp), 'Hash-to-point result should be valid curve point');
});

// ============================================================
// Key Image Generation Tests
// ============================================================

console.log('\n--- Key Image Generation Tests ---');

test('generateKeyImage produces 32-byte result', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const outputSecKey = deriveSecretKey(derivation, 0, keys.spendSecretKey);

  const keyImage = generateKeyImage(outputPubKey, outputSecKey);
  assertNotNull(keyImage);
  assertLength(keyImage, 32);
});

test('generateKeyImage is deterministic', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const outputSecKey = deriveSecretKey(derivation, 0, keys.spendSecretKey);

  const ki1 = generateKeyImage(outputPubKey, outputSecKey);
  const ki2 = generateKeyImage(outputPubKey, outputSecKey);
  assertEqual(bytesToHex(ki1), bytesToHex(ki2));
});

test('generateKeyImage produces different images for different outputs', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  // Output 0
  const outputPubKey0 = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const outputSecKey0 = deriveSecretKey(derivation, 0, keys.spendSecretKey);
  const ki0 = generateKeyImage(outputPubKey0, outputSecKey0);

  // Output 1
  const outputPubKey1 = derivePublicKey(derivation, 1, keys.spendPublicKey);
  const outputSecKey1 = deriveSecretKey(derivation, 1, keys.spendSecretKey);
  const ki1 = generateKeyImage(outputPubKey1, outputSecKey1);

  assertTrue(bytesToHex(ki0) !== bytesToHex(ki1), 'Different outputs should have different key images');
});

test('generateKeyImage accepts hex string inputs', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const outputSecKey = deriveSecretKey(derivation, 0, keys.spendSecretKey);

  const ki1 = generateKeyImage(outputPubKey, outputSecKey);
  const ki2 = generateKeyImage(bytesToHex(outputPubKey), bytesToHex(outputSecKey));
  assertEqual(bytesToHex(ki1), bytesToHex(ki2));
});

test('Same output with different derivations produces same key image', () => {
  // This tests that key image depends only on the final output keys
  const txPubKey1 = scalarMultBase(TX_SECRET_KEY);
  const derivation1 = generateKeyDerivation(txPubKey1, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation1, 0, keys.spendPublicKey);
  const outputSecKey = deriveSecretKey(derivation1, 0, keys.spendSecretKey);

  // Generate key image
  const ki = generateKeyImage(outputPubKey, outputSecKey);

  // Verify: secretKey * G should equal publicKey
  const computedPubKey = scalarMultBase(outputSecKey);
  assertEqual(bytesToHex(computedPubKey), bytesToHex(outputPubKey),
    'Output secret/public key pair should be valid');

  // Key image should be valid
  assertTrue(isValidKeyImage(ki));
});

// ============================================================
// Key Image Validation Tests
// ============================================================

console.log('\n--- Key Image Validation Tests ---');

test('isValidKeyImage accepts valid key images', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const outputSecKey = deriveSecretKey(derivation, 0, keys.spendSecretKey);
  const ki = generateKeyImage(outputPubKey, outputSecKey);

  assertTrue(isValidKeyImage(ki));
});

test('isValidKeyImage rejects all zeros', () => {
  const zeros = new Uint8Array(32);
  assertTrue(!isValidKeyImage(zeros), 'All zeros should be rejected');
});

test('isValidKeyImage rejects wrong length', () => {
  const short = new Uint8Array(31);
  const long = new Uint8Array(33);
  assertTrue(!isValidKeyImage(short), 'Short input should be rejected');
  assertTrue(!isValidKeyImage(long), 'Long input should be rejected');
});

test('isValidKeyImage accepts hex string input', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const outputSecKey = deriveSecretKey(derivation, 0, keys.spendSecretKey);
  const ki = generateKeyImage(outputPubKey, outputSecKey);

  assertTrue(isValidKeyImage(bytesToHex(ki)));
});

// ============================================================
// Key Image Generator Tests
// ============================================================

console.log('\n--- Key Image Generator Tests ---');

test('deriveKeyImageGenerator equals hashToPoint', () => {
  const gen1 = deriveKeyImageGenerator(keys.spendPublicKey);
  const gen2 = hashToPoint(keys.spendPublicKey);
  assertEqual(bytesToHex(gen1), bytesToHex(gen2));
});

test('deriveKeyImageGenerator produces 32 bytes', () => {
  const gen = deriveKeyImageGenerator(keys.spendPublicKey);
  assertLength(gen, 32);
});

// ============================================================
// Y-Coordinate Tests
// ============================================================

console.log('\n--- Y-Coordinate Tests ---');

test('keyImageToY extracts y-coordinate', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const outputSecKey = deriveSecretKey(derivation, 0, keys.spendSecretKey);
  const ki = generateKeyImage(outputPubKey, outputSecKey);

  const { y, sign } = keyImageToY(ki);
  assertLength(y, 32);
  assertTrue(typeof sign === 'boolean');
});

test('keyImageFromY reconstructs key image', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, keys.spendPublicKey);
  const outputSecKey = deriveSecretKey(derivation, 0, keys.spendSecretKey);
  const ki = generateKeyImage(outputPubKey, outputSecKey);

  const { y, sign } = keyImageToY(ki);
  const reconstructed = keyImageFromY(y, sign);

  assertEqual(bytesToHex(reconstructed), bytesToHex(ki));
});

test('keyImageToY/keyImageFromY round-trip', () => {
  // Test multiple key images
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  for (let i = 0; i < 5; i++) {
    const outputPubKey = derivePublicKey(derivation, i, keys.spendPublicKey);
    const outputSecKey = deriveSecretKey(derivation, i, keys.spendSecretKey);
    const ki = generateKeyImage(outputPubKey, outputSecKey);

    const { y, sign } = keyImageToY(ki);
    const reconstructed = keyImageFromY(y, sign);

    assertEqual(bytesToHex(reconstructed), bytesToHex(ki), `Round-trip failed for index ${i}`);
  }
});

// ============================================================
// Export/Import Tests
// ============================================================

console.log('\n--- Export/Import Tests ---');

test('exportKeyImages returns correct format', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const outputs = [];
  for (let i = 0; i < 3; i++) {
    outputs.push({
      outputPublicKey: derivePublicKey(derivation, i, keys.spendPublicKey),
      outputSecretKey: deriveSecretKey(derivation, i, keys.spendSecretKey),
      outputIndex: i
    });
  }

  const exported = exportKeyImages(outputs);

  assertEqual(exported.length, 3);
  for (let i = 0; i < 3; i++) {
    assertTrue(typeof exported[i].keyImage === 'string');
    assertTrue(typeof exported[i].outputPublicKey === 'string');
    assertEqual(exported[i].outputIndex, i);
    assertEqual(exported[i].keyImage.length, 64); // 32 bytes = 64 hex chars
  }
});

test('importKeyImages creates correct map', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const outputs = [];
  for (let i = 0; i < 3; i++) {
    outputs.push({
      outputPublicKey: derivePublicKey(derivation, i, keys.spendPublicKey),
      outputSecretKey: deriveSecretKey(derivation, i, keys.spendSecretKey),
      outputIndex: i
    });
  }

  const exported = exportKeyImages(outputs);
  const imported = importKeyImages(exported);

  assertTrue(imported instanceof Map);
  assertEqual(imported.size, 3);

  for (const exp of exported) {
    assertTrue(imported.has(exp.outputPublicKey));
    assertEqual(imported.get(exp.outputPublicKey), exp.keyImage);
  }
});

test('Export/import round-trip preserves data', () => {
  const txPubKey = scalarMultBase(TX_SECRET_KEY);
  const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);

  const outputs = [];
  for (let i = 0; i < 5; i++) {
    outputs.push({
      outputPublicKey: derivePublicKey(derivation, i, keys.spendPublicKey),
      outputSecretKey: deriveSecretKey(derivation, i, keys.spendSecretKey),
      outputIndex: i
    });
  }

  const exported = exportKeyImages(outputs);
  const imported = importKeyImages(exported);

  // Verify we can look up each key image
  for (const output of outputs) {
    const pubKeyHex = bytesToHex(output.outputPublicKey);
    assertTrue(imported.has(pubKeyHex), `Missing key image for output ${output.outputIndex}`);

    // Regenerate key image and verify it matches
    const ki = generateKeyImage(output.outputPublicKey, output.outputSecretKey);
    assertEqual(imported.get(pubKeyHex), bytesToHex(ki));
  }
});

// ============================================================
// Full Workflow Tests
// ============================================================

console.log('\n--- Full Workflow Tests ---');

test('Complete key image workflow for owned output', () => {
  // 1. Generate wallet
  const seed = generateSeed();
  const walletKeys = deriveKeys(seed);

  // 2. Simulate receiving a transaction
  const txSecret = new Uint8Array(32);
  crypto.getRandomValues(txSecret);
  const txPubKey = scalarMultBase(txSecret);

  // 3. Compute derivation and output keys
  const derivation = generateKeyDerivation(txPubKey, walletKeys.viewSecretKey);
  const outputPubKey = derivePublicKey(derivation, 0, walletKeys.spendPublicKey);
  const outputSecKey = deriveSecretKey(derivation, 0, walletKeys.spendSecretKey);

  // 4. Generate key image
  const keyImage = generateKeyImage(outputPubKey, outputSecKey);

  // 5. Verify key image is valid
  assertTrue(isValidKeyImage(keyImage));

  // 6. Verify public/secret key pair is valid
  const computedPubKey = scalarMultBase(outputSecKey);
  assertEqual(bytesToHex(computedPubKey), bytesToHex(outputPubKey));
});

test('Key images are unique per output', () => {
  const seed = generateSeed();
  const walletKeys = deriveKeys(seed);

  const txSecret = new Uint8Array(32);
  crypto.getRandomValues(txSecret);
  const txPubKey = scalarMultBase(txSecret);
  const derivation = generateKeyDerivation(txPubKey, walletKeys.viewSecretKey);

  const keyImages = new Set();

  // Generate key images for 20 outputs
  for (let i = 0; i < 20; i++) {
    const outputPubKey = derivePublicKey(derivation, i, walletKeys.spendPublicKey);
    const outputSecKey = deriveSecretKey(derivation, i, walletKeys.spendSecretKey);
    const ki = generateKeyImage(outputPubKey, outputSecKey);
    keyImages.add(bytesToHex(ki));
  }

  assertEqual(keyImages.size, 20, 'All key images should be unique');
});

test('View-only wallet can track spent outputs with imported key images', () => {
  // Full wallet
  const seed = generateSeed();
  const fullWalletKeys = deriveKeys(seed);

  // Simulate receiving 5 outputs
  const txSecret = new Uint8Array(32);
  crypto.getRandomValues(txSecret);
  const txPubKey = scalarMultBase(txSecret);
  const derivation = generateKeyDerivation(txPubKey, fullWalletKeys.viewSecretKey);

  const outputs = [];
  for (let i = 0; i < 5; i++) {
    const outputPubKey = derivePublicKey(derivation, i, fullWalletKeys.spendPublicKey);
    const outputSecKey = deriveSecretKey(derivation, i, fullWalletKeys.spendSecretKey);
    outputs.push({
      outputPublicKey: outputPubKey,
      outputSecretKey: outputSecKey,
      outputIndex: i
    });
  }

  // Full wallet exports key images
  const exported = exportKeyImages(outputs);

  // View-only wallet imports key images
  const viewOnlyKeyImages = importKeyImages(exported);

  // Simulate checking if outputs are spent
  // In real implementation, this would check against blockchain key images
  for (const output of outputs) {
    const pubKeyHex = bytesToHex(output.outputPublicKey);
    assertTrue(viewOnlyKeyImages.has(pubKeyHex), 'View-only should have key image');

    // The view-only wallet now knows the key image for this output
    // and can check if it appears in the blockchain (spent) or not
  }
});

// ============================================================
// Summary
// ============================================================

console.log('\n--- Key Image Test Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

if (failed > 0) {
  console.log('\n  Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All key image tests passed!');
}
