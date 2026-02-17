/**
 * Crypto Provider Tests — Backend Switching, Self-Consistency, Benchmark
 *
 * Verifies:
 * - Provider switching between JS (hashing-only) and WASM (full crypto)
 * - JS vs WASM equivalence for hashing (keccak256, blake2b)
 * - JS backend throws for scalar/point ops (Rust required)
 * - WASM self-consistency for scalar, point, key derivation, and commitment ops
 * - Performance benchmarks
 */

import {
  setCryptoBackend,
  getCryptoBackend,
  getCurrentBackendType,
  keccak256,
  blake2b,
  scAdd, scSub, scMul, scMulAdd, scMulSub,
  scReduce32, scReduce64, scInvert, scCheck, scIsZero,
  scalarMultBase, scalarMultPoint, pointAddCompressed,
  pointSubCompressed, pointNegate, doubleScalarMultBase,
  hashToPoint, generateKeyImage, generateKeyDerivation,
  derivePublicKey, deriveSecretKey,
  commit, zeroCommit, genCommitmentMask,
} from '../src/crypto/index.js';
import { JsCryptoBackend } from '../src/crypto/backend-js.js';
import { hexToBytes, bytesToHex } from '../src/index.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  \u2713 ${name}`);
    passed++;
  } catch (error) {
    console.log(`  \u2717 ${name}`);
    console.log(`    Error: ${error.message}`);
    failed++;
  }
}

async function asyncTest(name, fn) {
  try {
    await fn();
    console.log(`  \u2713 ${name}`);
    passed++;
  } catch (error) {
    console.log(`  \u2717 ${name}`);
    console.log(`    Error: ${error.message}`);
    failed++;
  }
}

function assertEqual(a, b, msg) {
  const aHex = a instanceof Uint8Array ? bytesToHex(a) : String(a);
  const bHex = b instanceof Uint8Array ? bytesToHex(b) : String(b);
  if (aHex !== bHex) {
    throw new Error(`${msg || 'Assertion failed'}: ${aHex} !== ${bHex}`);
  }
}

// ─── Test vectors ───────────────────────────────────────────────────────────

const testInputs = [
  new Uint8Array(0),                                           // empty
  new Uint8Array([0x61, 0x62, 0x63]),                         // "abc"
  new Uint8Array(32).fill(0xff),                              // 32 bytes of 0xff
  crypto.getRandomValues(new Uint8Array(1024)),               // 1KB random
];

// Known Keccak-256 vector: keccak256("") with CryptoNote 0x01 padding
const KECCAK_EMPTY = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

// Ed25519 base point G (compressed)
const G_HEX = '5866666666666666666666666666666666666666666666666666666666666666';
const G = hexToBytes(G_HEX);

const ZERO = new Uint8Array(32);
const ONE = new Uint8Array(32); ONE[0] = 1;

// ─── Provider tests ─────────────────────────────────────────────────────────

console.log('\n=== Crypto Provider ===\n');

test('default backend is JS', () => {
  assertEqual(getCurrentBackendType(), 'js');
});

test('getCryptoBackend returns JsCryptoBackend by default', () => {
  const backend = getCryptoBackend();
  if (backend.name !== 'js') throw new Error(`Expected js, got ${backend.name}`);
});

await asyncTest('setCryptoBackend("js") works', async () => {
  await setCryptoBackend('js');
  assertEqual(getCurrentBackendType(), 'js');
});

await asyncTest('setCryptoBackend("wasm") works', async () => {
  await setCryptoBackend('wasm');
  assertEqual(getCurrentBackendType(), 'wasm');
});

// ─── JS backend deprecation: scalar/point ops throw ─────────────────────────

console.log('\n=== JS Backend Deprecation ===\n');

test('JS backend keccak256 still works', () => {
  const js = new JsCryptoBackend();
  const result = js.keccak256(new Uint8Array(0));
  assertEqual(result, hexToBytes(KECCAK_EMPTY));
});

test('JS backend blake2b still works', () => {
  const js = new JsCryptoBackend();
  const result = js.blake2b(new Uint8Array([0x61, 0x62, 0x63]), 32);
  if (result.length !== 32) throw new Error('Expected 32 bytes');
});

test('JS backend sha256 still works', () => {
  const js = new JsCryptoBackend();
  const result = js.sha256(new Uint8Array([0x61, 0x62, 0x63]));
  if (result.length !== 32) throw new Error('Expected 32 bytes');
});

const throwOps = [
  ['scAdd', (b) => b.scAdd(ONE, ONE)],
  ['scSub', (b) => b.scSub(ONE, ONE)],
  ['scMul', (b) => b.scMul(ONE, ONE)],
  ['scMulAdd', (b) => b.scMulAdd(ONE, ONE, ONE)],
  ['scMulSub', (b) => b.scMulSub(ONE, ONE, ONE)],
  ['scReduce32', (b) => b.scReduce32(ONE)],
  ['scReduce64', (b) => b.scReduce64(new Uint8Array(64))],
  ['scInvert', (b) => b.scInvert(ONE)],
  ['scCheck', (b) => b.scCheck(ONE)],
  ['scIsZero', (b) => b.scIsZero(ZERO)],
  ['scalarMultBase', (b) => b.scalarMultBase(ONE)],
  ['scalarMultPoint', (b) => b.scalarMultPoint(ONE, G)],
  ['pointAddCompressed', (b) => b.pointAddCompressed(G, G)],
  ['pointSubCompressed', (b) => b.pointSubCompressed(G, G)],
  ['pointNegate', (b) => b.pointNegate(G)],
  ['doubleScalarMultBase', (b) => b.doubleScalarMultBase(ONE, G, ONE)],
  ['hashToPoint', (b) => b.hashToPoint(G)],
  ['generateKeyImage', (b) => b.generateKeyImage(G, ONE)],
  ['generateKeyDerivation', (b) => b.generateKeyDerivation(G, ONE)],
  ['derivePublicKey', (b) => b.derivePublicKey(G, 0, G)],
  ['deriveSecretKey', (b) => b.deriveSecretKey(G, 0, ONE)],
  ['commit', (b) => b.commit(1n, ONE)],
  ['zeroCommit', (b) => b.zeroCommit(1n)],
  ['genCommitmentMask', (b) => b.genCommitmentMask(ONE)],
  ['x25519ScalarMult', (b) => b.x25519ScalarMult(ONE, G)],
];

for (const [name, fn] of throwOps) {
  test(`JS backend throws for ${name}`, () => {
    const js = new JsCryptoBackend();
    let threw = false;
    try { fn(js); } catch (e) {
      if (e.message.includes('Rust crypto backend required')) threw = true;
      else throw e;
    }
    if (!threw) throw new Error(`Expected ${name} to throw 'Rust crypto backend required'`);
  });
}

// ─── Switch to WASM for all remaining tests ─────────────────────────────────

await setCryptoBackend('wasm');

// ─── Keccak-256 equivalence ─────────────────────────────────────────────────

console.log('\n=== Keccak-256 Equivalence (JS vs WASM) ===\n');

test('JS keccak256 empty matches known vector', () => {
  const js = new JsCryptoBackend();
  const result = js.keccak256(new Uint8Array(0));
  assertEqual(result, hexToBytes(KECCAK_EMPTY));
});

test('WASM keccak256 empty matches known vector', () => {
  const result = keccak256(new Uint8Array(0));
  assertEqual(result, hexToBytes(KECCAK_EMPTY));
});

for (let i = 0; i < testInputs.length; i++) {
  test(`keccak256 equivalence: input[${i}] (${testInputs[i].length} bytes)`, () => {
    const js = new JsCryptoBackend();
    const jsResult = js.keccak256(testInputs[i]);
    const wasmResult = keccak256(testInputs[i]);
    assertEqual(jsResult, wasmResult, 'JS vs WASM mismatch');
  });
}

// ─── Blake2b equivalence ────────────────────────────────────────────────────

console.log('\n=== Blake2b Equivalence (JS vs WASM) ===\n');

const blake2bOutLens = [32, 64];

for (const outLen of blake2bOutLens) {
  for (let i = 0; i < testInputs.length; i++) {
    test(`blake2b(outLen=${outLen}) equivalence: input[${i}] (${testInputs[i].length} bytes)`, () => {
      const js = new JsCryptoBackend();
      const jsResult = js.blake2b(testInputs[i], outLen);
      const wasmResult = blake2b(testInputs[i], outLen);
      assertEqual(jsResult, wasmResult, 'JS vs WASM mismatch');
    });
  }
}

// ─── Blake2b keyed equivalence ──────────────────────────────────────────────

console.log('\n=== Blake2b Keyed Equivalence (JS vs WASM) ===\n');

const testKey = new Uint8Array(32);
testKey.set([0x01, 0x02, 0x03, 0x04]);

for (let i = 0; i < testInputs.length; i++) {
  test(`blake2b_keyed(outLen=32) equivalence: input[${i}] (${testInputs[i].length} bytes)`, () => {
    const js = new JsCryptoBackend();
    const jsResult = js.blake2b(testInputs[i], 32, testKey);
    const wasmResult = blake2b(testInputs[i], 32, testKey);
    assertEqual(jsResult, wasmResult, 'JS vs WASM mismatch');
  });
}

// ─── Scalar ops (WASM self-consistency) ──────────────────────────────────────

console.log('\n=== Scalar Ops (WASM Self-Consistency) ===\n');

const scalarA = crypto.getRandomValues(new Uint8Array(32)); scalarA[31] &= 0x0f;
const scalarB = crypto.getRandomValues(new Uint8Array(32)); scalarB[31] &= 0x0f;

test('scAdd: a + 0 = reduce(a)', () => {
  const result = scAdd(scalarA, ZERO);
  const reduced = scReduce32(scalarA);
  assertEqual(result, reduced, 'scAdd identity');
});

test('scAdd commutativity: a + b = b + a', () => {
  const ab = scAdd(scalarA, scalarB);
  const ba = scAdd(scalarB, scalarA);
  assertEqual(ab, ba, 'scAdd commutativity');
});

test('scSub inverse: a - a = 0', () => {
  const result = scSub(scalarA, scalarA);
  const isZero = scIsZero(result);
  if (!isZero) throw new Error('a - a should be zero');
});

test('scAdd/scSub roundtrip: (a + b) - b = a', () => {
  const sum = scAdd(scalarA, scalarB);
  const result = scSub(sum, scalarB);
  const reduced = scReduce32(scalarA);
  assertEqual(result, reduced, 'add/sub roundtrip');
});

test('scMul: a * 1 = reduce(a)', () => {
  const result = scMul(scalarA, ONE);
  const reduced = scReduce32(scalarA);
  assertEqual(result, reduced, 'scMul identity');
});

test('scMul commutativity: a * b = b * a', () => {
  const ab = scMul(scalarA, scalarB);
  const ba = scMul(scalarB, scalarA);
  assertEqual(ab, ba, 'scMul commutativity');
});

test('scMulAdd: a*b + c = scAdd(scMul(a,b), c)', () => {
  const mulAdd = scMulAdd(scalarA, scalarB, ONE);
  const manual = scAdd(scMul(scalarA, scalarB), ONE);
  assertEqual(mulAdd, manual, 'scMulAdd consistency');
});

test('scMulSub: scMulSub(a,b,c) = c - a*b (CryptoNote convention)', () => {
  const mulSub = scMulSub(scalarA, scalarB, ONE);
  const manual = scSub(ONE, scMul(scalarA, scalarB));
  assertEqual(mulSub, manual, 'scMulSub consistency');
});

test('scReduce64 produces valid scalar', () => {
  const input64 = crypto.getRandomValues(new Uint8Array(64));
  const result = scReduce64(input64);
  if (result.length !== 32) throw new Error('Expected 32 bytes');
  const valid = scCheck(result);
  if (!valid) throw new Error('scReduce64 result failed scCheck');
});

test('scInvert: inv(a) * a = 1', () => {
  const inv = scInvert(scalarA);
  const product = scMul(inv, scalarA);
  assertEqual(product, ONE, 'inverse identity');
});

test('scCheck: valid scalar returns true', () => {
  if (!scCheck(ONE)) throw new Error('scCheck(1) should be true');
});

test('scCheck: 0xff..ff returns false', () => {
  if (scCheck(new Uint8Array(32).fill(0xff))) throw new Error('scCheck(ff) should be false');
});

test('scIsZero: zero returns true', () => {
  if (!scIsZero(ZERO)) throw new Error('scIsZero(0) should be true');
});

test('scIsZero: one returns false', () => {
  if (scIsZero(ONE)) throw new Error('scIsZero(1) should be false');
});

// ─── Point ops (WASM self-consistency) ───────────────────────────────────────

console.log('\n=== Point Ops (WASM Self-Consistency) ===\n');

test('scalarMultBase(1) = G', () => {
  const result = scalarMultBase(ONE);
  assertEqual(result, G, 'scalarMultBase(1) should be G');
});

test('scalarMultPoint(s, G) = scalarMultBase(s)', () => {
  const viaBase = scalarMultBase(scalarA);
  const viaPoint = scalarMultPoint(scalarA, G);
  assertEqual(viaBase, viaPoint, 'scalarMultPoint(s,G) vs scalarMultBase(s)');
});

test('pointAdd(G, G) = scalarMultBase(2)', () => {
  const TWO = new Uint8Array(32); TWO[0] = 2;
  const sum = pointAddCompressed(G, G);
  const doubled = scalarMultBase(TWO);
  assertEqual(sum, doubled, 'G+G vs 2*G');
});

test('pointAdd commutativity: P+Q = Q+P', () => {
  const P = scalarMultBase(scalarA);
  const Q = scalarMultBase(scalarB);
  const pq = pointAddCompressed(P, Q);
  const qp = pointAddCompressed(Q, P);
  assertEqual(pq, qp, 'pointAdd commutativity');
});

test('pointAdd/pointSub roundtrip: (P+Q) - Q = P', () => {
  const P = scalarMultBase(scalarA);
  const Q = scalarMultBase(scalarB);
  const sum = pointAddCompressed(P, Q);
  const result = pointSubCompressed(sum, Q);
  assertEqual(result, P, 'add/sub roundtrip');
});

test('pointNegate roundtrip: -(-P) = P', () => {
  const P = scalarMultBase(scalarA);
  const negP = pointNegate(P);
  const negNegP = pointNegate(negP);
  assertEqual(P, negNegP, 'double negate roundtrip');
});

test('pointSub(P, P) = identity', () => {
  const P = scalarMultBase(scalarA);
  const result = pointSubCompressed(P, P);
  // Identity point on ed25519 is (0,1) compressed = 0x01 followed by 31 zeros
  if (result[0] !== 1) throw new Error('Expected identity point (first byte 0x01)');
  for (let i = 1; i < 32; i++) {
    if (result[i] !== 0) throw new Error(`Expected identity point (byte ${i} should be 0x00, got 0x${result[i].toString(16)})`);
  }
});

test('pointNegate: P + (-P) = identity', () => {
  const P = scalarMultBase(scalarA);
  const negP = pointNegate(P);
  const result = pointAddCompressed(P, negP);
  if (result[0] !== 1) throw new Error('Expected identity point');
  for (let i = 1; i < 32; i++) {
    if (result[i] !== 0) throw new Error('Expected identity point');
  }
});

test('doubleScalarMultBase: a*P + b*G = pointAdd(scalarMultPoint(a,P), scalarMultBase(b))', () => {
  const P = scalarMultBase(scalarA);
  const result = doubleScalarMultBase(scalarB, P, ONE);
  const manual = pointAddCompressed(scalarMultPoint(scalarB, P), scalarMultBase(ONE));
  assertEqual(result, manual, 'doubleScalarMultBase consistency');
});

test('scalar homomorphism: (a+b)*G = a*G + b*G', () => {
  const sum = scAdd(scalarA, scalarB);
  const sumG = scalarMultBase(sum);
  const aG = scalarMultBase(scalarA);
  const bG = scalarMultBase(scalarB);
  const pointSum = pointAddCompressed(aG, bG);
  assertEqual(sumG, pointSum, 'scalar homomorphism');
});

// ─── Hash-to-point & key derivation (WASM self-consistency) ──────────────────

console.log('\n=== Hash-to-Point & Key Derivation (WASM Self-Consistency) ===\n');

const testSecKey = new Uint8Array(32);
testSecKey.set([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
testSecKey[31] &= 0x0f;
const testPubKey = scalarMultBase(testSecKey);

test('hashToPoint returns 32 bytes', () => {
  const result = hashToPoint(testPubKey);
  if (result.length !== 32) throw new Error('Expected 32 bytes');
});

test('hashToPoint deterministic', () => {
  const a = hashToPoint(testPubKey);
  const b = hashToPoint(testPubKey);
  assertEqual(a, b, 'hashToPoint should be deterministic');
});

test('hashToPoint varies with input', () => {
  const a = hashToPoint(testPubKey);
  const b = hashToPoint(scalarMultBase(scalarA));
  if (bytesToHex(a) === bytesToHex(b)) throw new Error('hashToPoint should vary with input');
});

test('generateKeyImage = secKey * hashToPoint(pubKey)', () => {
  const ki = generateKeyImage(testPubKey, testSecKey);
  const hp = hashToPoint(testPubKey);
  const expected = scalarMultPoint(testSecKey, hp);
  assertEqual(ki, expected, 'key image formula');
});

test('generateKeyDerivation deterministic', () => {
  const a = generateKeyDerivation(testPubKey, testSecKey);
  const b = generateKeyDerivation(testPubKey, testSecKey);
  assertEqual(a, b, 'generateKeyDerivation should be deterministic');
});

test('derivePublicKey matches scalarMultBase(deriveSecretKey)', () => {
  const derivation = generateKeyDerivation(testPubKey, testSecKey);
  const derivedSec = deriveSecretKey(derivation, 0, testSecKey);
  const derivedPubFromSec = scalarMultBase(derivedSec);
  const derivedPubDirect = derivePublicKey(derivation, 0, testPubKey);
  assertEqual(derivedPubFromSec, derivedPubDirect, 'derivePublicKey consistency');
});

test('derivePublicKey varies with output index', () => {
  const derivation = generateKeyDerivation(testPubKey, testSecKey);
  const pub0 = derivePublicKey(derivation, 0, testPubKey);
  const pub1 = derivePublicKey(derivation, 1, testPubKey);
  if (bytesToHex(pub0) === bytesToHex(pub1)) throw new Error('Different indices should produce different keys');
});

test('deriveSecretKey varies with output index', () => {
  const derivation = generateKeyDerivation(testPubKey, testSecKey);
  const sec0 = deriveSecretKey(derivation, 0, testSecKey);
  const sec1 = deriveSecretKey(derivation, 1, testSecKey);
  if (bytesToHex(sec0) === bytesToHex(sec1)) throw new Error('Different indices should produce different keys');
});

// ─── Pedersen commitment (WASM self-consistency) ─────────────────────────────

console.log('\n=== Pedersen Commitment (WASM Self-Consistency) ===\n');

test('commit deterministic', () => {
  const a = commit(42n, scalarA);
  const b = commit(42n, scalarA);
  assertEqual(a, b, 'commit should be deterministic');
});

test('zeroCommit deterministic', () => {
  const a = zeroCommit(42n);
  const b = zeroCommit(42n);
  assertEqual(a, b, 'zeroCommit should be deterministic');
});

test('commit varies with amount', () => {
  const a = commit(1n, scalarA);
  const b = commit(2n, scalarA);
  if (bytesToHex(a) === bytesToHex(b)) throw new Error('Different amounts should produce different commitments');
});

test('commit varies with mask', () => {
  const a = commit(42n, scalarA);
  const b = commit(42n, scalarB);
  if (bytesToHex(a) === bytesToHex(b)) throw new Error('Different masks should produce different commitments');
});

test('genCommitmentMask deterministic', () => {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const a = genCommitmentMask(secret);
  const b = genCommitmentMask(secret);
  assertEqual(a, b, 'genCommitmentMask should be deterministic');
});

test('commit homomorphic: commit(a,m) - zeroCommit(a) = (m-1)*G', () => {
  const amount = 42n;
  const mask = scalarA;
  const c = commit(amount, mask);
  const z = zeroCommit(amount);
  // commit(a,m) = m*G + a*H, zeroCommit(a) = 1*G + a*H
  // diff = (m-1)*G
  const diff = pointSubCompressed(c, z);
  const scalarOne = new Uint8Array(32); scalarOne[0] = 1;
  const mMinusOne = scSub(mask, scalarOne);
  const expected = scalarMultBase(mMinusOne);
  assertEqual(diff, expected, 'homomorphic property');
});

test('commit balance: commit(a,m) + commit(b,n) - commit(a+b, m+n) = identity', () => {
  const aAmt = 100n;
  const bAmt = 200n;
  const mMask = scalarA;
  const nMask = scalarB;
  const cA = commit(aAmt, mMask);
  const cB = commit(bAmt, nMask);
  const sumMask = scAdd(mMask, nMask);
  const cSum = commit(aAmt + bAmt, sumMask);
  const lhs = pointAddCompressed(cA, cB);
  assertEqual(lhs, cSum, 'commitment additivity');
});

// ─── Benchmark ──────────────────────────────────────────────────────────────

console.log('\n=== Benchmark ===\n');

const benchData = new Uint8Array(256).fill(0x42);
const ITERATIONS = 10_000;

// Keccak-256 benchmark (JS vs WASM)
{
  const js = new JsCryptoBackend();
  const jsStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) js.keccak256(benchData);
  const jsTime = performance.now() - jsStart;

  const wasmStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) keccak256(benchData);
  const wasmTime = performance.now() - wasmStart;

  const speedup = (jsTime / wasmTime).toFixed(2);
  console.log(`  keccak256:  JS ${jsTime.toFixed(1)}ms  WASM ${wasmTime.toFixed(1)}ms  (${speedup}x)`);
}

// Blake2b benchmark (JS vs WASM)
{
  const js = new JsCryptoBackend();
  const jsStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) js.blake2b(benchData, 32);
  const jsTime = performance.now() - jsStart;

  const wasmStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) blake2b(benchData, 32);
  const wasmTime = performance.now() - wasmStart;

  const speedup = (jsTime / wasmTime).toFixed(2);
  console.log(`  blake2b:    JS ${jsTime.toFixed(1)}ms  WASM ${wasmTime.toFixed(1)}ms  (${speedup}x)`);
}

// Scalar and point benchmarks (WASM only)
const BENCH_SC = 10_000;
const BENCH_PT = 1_000;
const benchScalar = new Uint8Array(32); benchScalar[0] = 42; benchScalar[31] &= 0x0f;
const benchPoint = scalarMultBase(benchScalar);

const benchOps = [
  ['scMulAdd', BENCH_SC, () => scMulAdd(benchScalar, benchScalar, benchScalar)],
  ['scalarMultBase', BENCH_PT, () => scalarMultBase(benchScalar)],
  ['scalarMultPoint', BENCH_PT, () => scalarMultPoint(benchScalar, benchPoint)],
  ['pointAddCompressed', BENCH_PT, () => pointAddCompressed(benchPoint, benchPoint)],
  ['hashToPoint', BENCH_PT, () => hashToPoint(benchPoint)],
  ['generateKeyImage', BENCH_PT, () => generateKeyImage(benchPoint, benchScalar)],
  ['generateKeyDerivation', BENCH_PT, () => generateKeyDerivation(benchPoint, benchScalar)],
];

for (const [name, iters, fn] of benchOps) {
  const start = performance.now();
  for (let i = 0; i < iters; i++) fn();
  const time = performance.now() - start;

  const opsPerSec = (iters / (time / 1000)).toFixed(0);
  const pad = name.padEnd(22);
  console.log(`  ${pad} WASM ${time.toFixed(1)}ms  (${opsPerSec} ops/s) [${iters} iters]`);
}

// ─── Summary ────────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
