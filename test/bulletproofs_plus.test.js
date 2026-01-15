/**
 * Bulletproofs+ Tests
 *
 * Tests for the pure JavaScript Bulletproofs+ implementation.
 */

import {
  bytesToScalar,
  scalarToBytes,
  bytesToPoint,
  hashToScalar,
  hashToPoint,
  initGenerators,
  initTranscript,
  parseProof,
  multiScalarMul,
  verifyBulletproofPlus,
  verifyBulletproofPlusBatch,
  Point
} from '../src/bulletproofs_plus.js';

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

async function testAsync(name, fn) {
  try {
    await fn();
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

function assertTrue(condition, message = '') {
  if (!condition) {
    throw new Error(message || 'Expected true');
  }
}

function assertExists(value, message = '') {
  if (value === undefined || value === null) {
    throw new Error(`${message} Value is ${value}`);
  }
}

// ============================================================
// Scalar Conversion Tests
// ============================================================

console.log('\n--- Scalar Conversion Tests ---');

test('bytesToScalar converts little-endian bytes', () => {
  const bytes = new Uint8Array(32);
  bytes[0] = 1;
  const scalar = bytesToScalar(bytes);
  assertEqual(scalar, 1n);
});

test('bytesToScalar handles larger values', () => {
  const bytes = new Uint8Array(32);
  bytes[0] = 0xff;
  bytes[1] = 0xff;
  const scalar = bytesToScalar(bytes);
  assertEqual(scalar, 65535n);
});

test('scalarToBytes converts to little-endian', () => {
  const scalar = 256n;
  const bytes = scalarToBytes(scalar);
  assertEqual(bytes[0], 0);
  assertEqual(bytes[1], 1);
});

test('bytesToScalar and scalarToBytes are inverses', () => {
  const original = 12345678901234567890n;
  const bytes = scalarToBytes(original);
  const recovered = bytesToScalar(bytes);
  assertEqual(recovered, original);
});

// ============================================================
// Point Conversion Tests
// ============================================================

console.log('\n--- Point Conversion Tests ---');

test('bytesToPoint decodes base point', () => {
  const baseBytes = Point.BASE.toBytes();
  const point = bytesToPoint(baseBytes);
  assertTrue(point.equals(Point.BASE));
});

test('bytesToPoint throws on invalid encoding', () => {
  const invalidBytes = new Uint8Array(32);
  invalidBytes.fill(0xff);
  let threw = false;
  try {
    bytesToPoint(invalidBytes);
  } catch (e) {
    threw = true;
  }
  assertTrue(threw, 'Should throw on invalid point');
});

// ============================================================
// Hash Functions Tests
// ============================================================

console.log('\n--- Hash Functions Tests ---');

test('hashToScalar produces deterministic output', () => {
  const data = new Uint8Array([1, 2, 3, 4]);
  const scalar1 = hashToScalar(data);
  const scalar2 = hashToScalar(data);
  assertEqual(scalar1, scalar2);
});

test('hashToScalar produces different output for different input', () => {
  const data1 = new Uint8Array([1, 2, 3, 4]);
  const data2 = new Uint8Array([5, 6, 7, 8]);
  const scalar1 = hashToScalar(data1);
  const scalar2 = hashToScalar(data2);
  assertTrue(scalar1 !== scalar2, 'Different inputs should produce different outputs');
});

test('hashToPoint produces valid point', () => {
  const data = new TextEncoder().encode('test data');
  const point = hashToPoint(data);
  assertExists(point);
  // Point should not be identity
  assertTrue(!point.equals(Point.ZERO), 'Should not be identity point');
});

// ============================================================
// Generator Tests
// ============================================================

console.log('\n--- Generator Tests ---');

test('initGenerators creates G and H', () => {
  const gens = initGenerators(64);
  assertExists(gens.G);
  assertExists(gens.H);
  assertTrue(gens.G.equals(Point.BASE));
});

test('initGenerators creates Gi and Hi arrays', () => {
  const gens = initGenerators(64);
  assertEqual(gens.Gi.length, 64);
  assertEqual(gens.Hi.length, 64);
});

test('Gi and Hi are distinct points', () => {
  const gens = initGenerators(64);
  assertTrue(!gens.Gi[0].equals(gens.Hi[0]), 'Gi[0] should differ from Hi[0]');
  assertTrue(!gens.Gi[0].equals(gens.G), 'Gi[0] should differ from G');
});

test('initGenerators is cached', () => {
  const gens1 = initGenerators(64);
  const gens2 = initGenerators(64);
  assertTrue(gens1 === gens2, 'Should return cached generators');
});

// ============================================================
// Transcript Tests
// ============================================================

console.log('\n--- Transcript Tests ---');

test('initTranscript produces deterministic output', () => {
  const t1 = initTranscript();
  const t2 = initTranscript();
  for (let i = 0; i < 32; i++) {
    assertEqual(t1[i], t2[i]);
  }
});

// ============================================================
// Multiscalar Multiplication Tests
// ============================================================

console.log('\n--- Multiscalar Multiplication Tests ---');

test('multiScalarMul with single point', () => {
  const G = Point.BASE;
  const result = multiScalarMul([5n], [G]);
  const expected = G.multiply(5n);
  assertTrue(result.equals(expected));
});

test('multiScalarMul with multiple points', () => {
  const G = Point.BASE;
  const H = G.multiply(7n);
  const result = multiScalarMul([3n, 5n], [G, H]);
  const expected = G.multiply(3n).add(H.multiply(5n));
  assertTrue(result.equals(expected));
});

test('multiScalarMul with zero scalar', () => {
  const G = Point.BASE;
  const result = multiScalarMul([0n, 5n], [G, G]);
  const expected = G.multiply(5n);
  assertTrue(result.equals(expected));
});

test('multiScalarMul with empty arrays', () => {
  const result = multiScalarMul([], []);
  assertTrue(result.equals(Point.ZERO));
});

// ============================================================
// Proof Parsing Tests
// ============================================================

console.log('\n--- Proof Parsing Tests ---');

test('parseProof extracts correct structure', () => {
  // Create a minimal mock proof (6 rounds = 384 bytes for L/R + 192 bytes header)
  const proofBytes = new Uint8Array(32 * 6 + 64 * 6);

  // Fill with valid point encodings (use base point bytes)
  const baseBytes = Point.BASE.toBytes();

  // A, A1, B
  for (let i = 0; i < 3; i++) {
    proofBytes.set(baseBytes, i * 32);
  }

  // r1, s1, d1 (scalars - just use small values)
  proofBytes[96] = 1; // r1
  proofBytes[128] = 2; // s1
  proofBytes[160] = 3; // d1

  // L and R pairs (6 rounds)
  for (let i = 0; i < 12; i++) {
    proofBytes.set(baseBytes, 192 + i * 32);
  }

  const proof = parseProof(proofBytes);
  assertExists(proof.A);
  assertExists(proof.A1);
  assertExists(proof.B);
  assertEqual(proof.r1, 1n);
  assertEqual(proof.s1, 2n);
  assertEqual(proof.d1, 3n);
  assertEqual(proof.L.length, 6);
  assertEqual(proof.R.length, 6);
});

test('parseProof throws on too-short proof', () => {
  const shortProof = new Uint8Array(100);
  let threw = false;
  try {
    parseProof(shortProof);
  } catch (e) {
    threw = true;
  }
  assertTrue(threw, 'Should throw on short proof');
});

// ============================================================
// Performance Benchmark
// ============================================================

console.log('\n--- Performance Benchmark ---');

testAsync('Benchmark: Generator initialization', async () => {
  // Clear cache for benchmark
  const start = performance.now();
  const gens = initGenerators(1024);
  const elapsed = performance.now() - start;
  console.log(`      Generator init (1024 points): ${elapsed.toFixed(2)}ms`);
  assertTrue(elapsed < 30000, 'Should complete in reasonable time');
});

testAsync('Benchmark: 100 scalar multiplications', async () => {
  const G = Point.BASE;
  const start = performance.now();
  for (let i = 0; i < 100; i++) {
    G.multiply(BigInt(i + 1));
  }
  const elapsed = performance.now() - start;
  console.log(`      100 scalar mults: ${elapsed.toFixed(2)}ms (${(elapsed/100).toFixed(2)}ms each)`);
  assertTrue(elapsed < 10000, 'Should complete in reasonable time');
});

testAsync('Benchmark: MSM with 64 points', async () => {
  const gens = initGenerators(64);
  const scalars = [];
  for (let i = 0; i < 64; i++) {
    scalars.push(BigInt(i + 1));
  }

  const start = performance.now();
  const result = multiScalarMul(scalars, gens.Gi.slice(0, 64));
  const elapsed = performance.now() - start;
  console.log(`      MSM (64 points): ${elapsed.toFixed(2)}ms`);
  assertTrue(elapsed < 10000, 'Should complete in reasonable time');
});

testAsync('Benchmark: MSM with 128 points (single output proof size)', async () => {
  const gens = initGenerators(128);
  const scalars = [];
  for (let i = 0; i < 128; i++) {
    scalars.push(BigInt(i + 1));
  }

  const start = performance.now();
  const result = multiScalarMul(scalars, gens.Gi.slice(0, 128));
  const elapsed = performance.now() - start;
  console.log(`      MSM (128 points): ${elapsed.toFixed(2)}ms`);
  assertTrue(elapsed < 20000, 'Should complete in reasonable time');
});

testAsync('Benchmark: MSM with 256 points (full BP+ verification size)', async () => {
  const gens = initGenerators(256);
  const scalars = [];
  for (let i = 0; i < 256; i++) {
    scalars.push(BigInt(i + 1));
  }

  const start = performance.now();
  const result = multiScalarMul(scalars, gens.Gi.slice(0, 256));
  const elapsed = performance.now() - start;
  console.log(`      MSM (256 points): ${elapsed.toFixed(2)}ms`);
  assertTrue(elapsed < 30000, 'Should complete in reasonable time');
});

// ============================================================
// Summary
// ============================================================

console.log('\n--- Bulletproofs+ Test Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

if (failed > 0) {
  console.log('\n⚠️  Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All tests passed!');
}
