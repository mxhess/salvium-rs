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
  hashToPointMonero,
  initGenerators,
  initTranscript,
  parseProof,
  multiScalarMul,
  verifyBulletproofPlus,
  verifyBulletproofPlusBatch,
  Point,
  // Proving functions
  randomScalar,
  bulletproofPlusProve,
  proveRange,
  proveRangeMultiple,
  serializeProof,
  L,
  INV_EIGHT
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

test('hashToPointMonero produces valid point', () => {
  const data = new TextEncoder().encode('test data');
  const point = hashToPointMonero(data);
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
  // Build a proof in Salvium binary format (V is NOT serialized — restored from outPk):
  // A, A1, B, r1, s1, d1, varint(L.len), L[], varint(R.len), R[]
  const baseBytes = Point.BASE.toBytes();
  const chunks = [];

  // A, A1, B
  chunks.push(baseBytes);
  chunks.push(baseBytes);
  chunks.push(baseBytes);

  // r1, s1, d1 (scalars)
  const s1b = new Uint8Array(32); s1b[0] = 1;
  const s2b = new Uint8Array(32); s2b[0] = 2;
  const s3b = new Uint8Array(32); s3b[0] = 3;
  chunks.push(s1b);
  chunks.push(s2b);
  chunks.push(s3b);

  // L: 6 entries
  chunks.push(new Uint8Array([6])); // varint(6)
  for (let i = 0; i < 6; i++) chunks.push(baseBytes);

  // R: 6 entries
  chunks.push(new Uint8Array([6])); // varint(6)
  for (let i = 0; i < 6; i++) chunks.push(baseBytes);

  // Concatenate
  let totalLen = 0;
  for (const c of chunks) totalLen += c.length;
  const proofBytes = new Uint8Array(totalLen);
  let off = 0;
  for (const c of chunks) { proofBytes.set(c, off); off += c.length; }

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
// Proof Generation Tests
// ============================================================

console.log('\n--- Proof Generation Tests ---');

test('randomScalar generates valid scalar', () => {
  const s = randomScalar();
  assertTrue(s >= 0n, 'Scalar should be non-negative');
  assertTrue(s < L, 'Scalar should be less than L');
});

test('randomScalar generates different values', () => {
  const s1 = randomScalar();
  const s2 = randomScalar();
  assertTrue(s1 !== s2, 'Two random scalars should differ');
});

test('proveRange generates proof for single amount', () => {
  const amount = 1000000n; // 1 SAL in atomic units
  const mask = randomScalar();

  const proof = proveRange(amount, mask);

  assertExists(proof.V);
  assertExists(proof.A);
  assertExists(proof.A1);
  assertExists(proof.B);
  assertExists(proof.r1);
  assertExists(proof.s1);
  assertExists(proof.d1);
  assertExists(proof.L);
  assertExists(proof.R);

  assertEqual(proof.V.length, 1, 'Should have 1 commitment');
  assertEqual(proof.L.length, 6, 'Should have 6 L points for 64-bit proof');
  assertEqual(proof.R.length, 6, 'Should have 6 R points');
});

test('proveRange proof verifies correctly', () => {
  const amount = 12345678n;
  const mask = randomScalar();

  const proof = proveRange(amount, mask);

  // Verify the proof
  const valid = verifyBulletproofPlus(proof.V, proof);
  assertTrue(valid, 'Proof should verify');
});

test('proveRange works for zero amount', () => {
  const amount = 0n;
  const mask = randomScalar();

  const proof = proveRange(amount, mask);
  const valid = verifyBulletproofPlus(proof.V, proof);
  assertTrue(valid, 'Zero amount proof should verify');
});

test('proveRange works for max amount (2^64 - 1)', () => {
  const amount = (1n << 64n) - 1n;
  const mask = randomScalar();

  const proof = proveRange(amount, mask);
  const valid = verifyBulletproofPlus(proof.V, proof);
  assertTrue(valid, 'Max amount proof should verify');
});

test('proveRangeMultiple generates proof for 2 amounts', () => {
  const amounts = [100n, 200n];
  const masks = [randomScalar(), randomScalar()];

  const proof = proveRangeMultiple(amounts, masks);

  assertEqual(proof.V.length, 2, 'Should have 2 commitments');
  assertEqual(proof.L.length, 7, 'Should have 7 L points for 2-amount proof');
});

test('proveRangeMultiple proof verifies correctly', () => {
  const amounts = [1000000n, 2000000n];
  const masks = [randomScalar(), randomScalar()];

  const proof = proveRangeMultiple(amounts, masks);
  const valid = verifyBulletproofPlus(proof.V, proof);
  assertTrue(valid, 'Multi-amount proof should verify');
});

test('serializeProof produces correct size', () => {
  const amount = 100n;
  const mask = randomScalar();

  const proof = proveRange(amount, mask);
  const bytes = serializeProof(proof);

  // Salvium binary format (no V): A + A1 + B + r1 + s1 + d1 + varint(L.len) + L + varint(R.len) + R
  // For single amount: 3*32 + 3*32 + 1 + 6*32 + 1 + 6*32 = 578 bytes
  assertEqual(bytes.length, 578, 'Serialized proof should be 578 bytes');
});

test('serialized proof can be parsed and verified', () => {
  const amount = 999n;
  const mask = randomScalar();

  const proof = proveRange(amount, mask);
  const bytes = serializeProof(proof);

  // Parse it back
  const parsed = parseProof(bytes);

  // Verify with original V
  const valid = verifyBulletproofPlus(proof.V, parsed);
  assertTrue(valid, 'Parsed proof should verify');
});

test('invalid amount (>= 2^64) throws error', () => {
  const amount = 1n << 64n; // Exactly 2^64, out of range
  const mask = randomScalar();

  let threw = false;
  try {
    proveRange(amount, mask);
  } catch (e) {
    threw = true;
  }
  assertTrue(threw, 'Should throw for out-of-range amount');
});

test('mismatched amounts/masks throws error', () => {
  const amounts = [100n, 200n];
  const masks = [randomScalar()]; // Only 1 mask

  let threw = false;
  try {
    proveRangeMultiple(amounts, masks);
  } catch (e) {
    threw = true;
  }
  assertTrue(threw, 'Should throw for mismatched arrays');
});

// ============================================================
// Proof Generation Benchmarks
// ============================================================

console.log('\n--- Proof Generation Benchmarks ---');

testAsync('Benchmark: Single amount proof generation', async () => {
  const amount = 1000000000n;
  const mask = randomScalar();

  const start = performance.now();
  const proof = proveRange(amount, mask);
  const elapsed = performance.now() - start;

  console.log(`      Single proof generation: ${elapsed.toFixed(2)}ms`);
  assertTrue(elapsed < 60000, 'Should complete in reasonable time');
});

testAsync('Benchmark: Proof generation + verification round-trip', async () => {
  const amount = 123456789n;
  const mask = randomScalar();

  const start = performance.now();
  const proof = proveRange(amount, mask);
  const genTime = performance.now() - start;

  const verifyStart = performance.now();
  const valid = verifyBulletproofPlus(proof.V, proof);
  const verifyTime = performance.now() - verifyStart;

  console.log(`      Generation: ${genTime.toFixed(2)}ms, Verification: ${verifyTime.toFixed(2)}ms`);
  console.log(`      Round-trip: ${(genTime + verifyTime).toFixed(2)}ms`);
  assertTrue(valid, 'Proof should verify');
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
