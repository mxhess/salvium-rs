/**
 * Crypto Provider Tests — JS vs WASM Equivalence + Benchmark
 *
 * Verifies byte-for-byte equivalence between JS and WASM crypto backends,
 * and benchmarks relative performance.
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
} from '../src/crypto/index.js';
import { JsCryptoBackend } from '../src/crypto/backend-js.js';
import { hexToBytes, bytesToHex } from '../src/index.js';

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

async function asyncTest(name, fn) {
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
// From: https://emn178.github.io/online-tools/keccak_256.html
const KECCAK_EMPTY = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

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
  await setCryptoBackend('js'); // reset
});

// ─── Keccak-256 equivalence ─────────────────────────────────────────────────

console.log('\n=== Keccak-256 Equivalence ===\n');

test('JS keccak256 empty matches known vector', () => {
  const js = new JsCryptoBackend();
  const result = js.keccak256(new Uint8Array(0));
  assertEqual(result, hexToBytes(KECCAK_EMPTY));
});

await asyncTest('WASM keccak256 empty matches known vector', async () => {
  await setCryptoBackend('wasm');
  const result = keccak256(new Uint8Array(0));
  assertEqual(result, hexToBytes(KECCAK_EMPTY));
  await setCryptoBackend('js');
});

for (let i = 0; i < testInputs.length; i++) {
  await asyncTest(`keccak256 equivalence: input[${i}] (${testInputs[i].length} bytes)`, async () => {
    const js = new JsCryptoBackend();
    const jsResult = js.keccak256(testInputs[i]);

    await setCryptoBackend('wasm');
    const wasmResult = keccak256(testInputs[i]);
    await setCryptoBackend('js');

    assertEqual(jsResult, wasmResult, 'JS vs WASM mismatch');
  });
}

// ─── Blake2b equivalence ────────────────────────────────────────────────────

console.log('\n=== Blake2b Equivalence ===\n');

const blake2bOutLens = [32, 64];

for (const outLen of blake2bOutLens) {
  for (let i = 0; i < testInputs.length; i++) {
    await asyncTest(`blake2b(outLen=${outLen}) equivalence: input[${i}] (${testInputs[i].length} bytes)`, async () => {
      const js = new JsCryptoBackend();
      const jsResult = js.blake2b(testInputs[i], outLen);

      await setCryptoBackend('wasm');
      const wasmResult = blake2b(testInputs[i], outLen);
      await setCryptoBackend('js');

      assertEqual(jsResult, wasmResult, 'JS vs WASM mismatch');
    });
  }
}

// ─── Blake2b keyed equivalence ──────────────────────────────────────────────

console.log('\n=== Blake2b Keyed Equivalence ===\n');

const testKey = new Uint8Array(32);
testKey.set([0x01, 0x02, 0x03, 0x04]);

for (let i = 0; i < testInputs.length; i++) {
  await asyncTest(`blake2b_keyed(outLen=32) equivalence: input[${i}] (${testInputs[i].length} bytes)`, async () => {
    const js = new JsCryptoBackend();
    const jsResult = js.blake2b(testInputs[i], 32, testKey);

    await setCryptoBackend('wasm');
    const wasmResult = blake2b(testInputs[i], 32, testKey);
    await setCryptoBackend('js');

    assertEqual(jsResult, wasmResult, 'JS vs WASM mismatch');
  });
}

// ─── Scalar equivalence ─────────────────────────────────────────────────────

console.log('\n=== Scalar Ops Equivalence ===\n');

const ZERO = new Uint8Array(32);
const ONE = new Uint8Array(32); ONE[0] = 1;
const scalarA = crypto.getRandomValues(new Uint8Array(32)); scalarA[31] &= 0x0f; // keep < L
const scalarB = crypto.getRandomValues(new Uint8Array(32)); scalarB[31] &= 0x0f;

const scalarOps = [
  ['scAdd', (b) => b.scAdd(scalarA, scalarB)],
  ['scSub', (b) => b.scSub(scalarA, scalarB)],
  ['scMul', (b) => b.scMul(scalarA, scalarB)],
  ['scMulAdd', (b) => b.scMulAdd(scalarA, scalarB, ONE)],
  ['scMulSub', (b) => b.scMulSub(scalarA, scalarB, ONE)],
  ['scReduce32', (b) => b.scReduce32(new Uint8Array(32).fill(0xff))],
  ['scInvert', (b) => b.scInvert(scalarA)],
];

for (const [name, fn] of scalarOps) {
  await asyncTest(`${name} equivalence`, async () => {
    const js = new JsCryptoBackend();
    const jsResult = fn(js);
    await setCryptoBackend('wasm');
    const wasmResult = fn(getCryptoBackend());
    await setCryptoBackend('js');
    assertEqual(jsResult, wasmResult, `${name} JS vs WASM`);
  });
}

// scReduce64
await asyncTest('scReduce64 equivalence', async () => {
  const input64 = crypto.getRandomValues(new Uint8Array(64));
  const js = new JsCryptoBackend();
  const jsResult = js.scReduce64(input64);
  await setCryptoBackend('wasm');
  const wasmResult = getCryptoBackend().scReduce64(input64);
  await setCryptoBackend('js');
  assertEqual(jsResult, wasmResult, 'scReduce64 JS vs WASM');
});

// scCheck
await asyncTest('scCheck equivalence', async () => {
  const js = new JsCryptoBackend();
  const jsOk = js.scCheck(ONE);
  const jsBad = js.scCheck(new Uint8Array(32).fill(0xff));
  await setCryptoBackend('wasm');
  const wasmOk = getCryptoBackend().scCheck(ONE);
  const wasmBad = getCryptoBackend().scCheck(new Uint8Array(32).fill(0xff));
  await setCryptoBackend('js');
  if (jsOk !== wasmOk) throw new Error(`scCheck(1): JS=${jsOk} WASM=${wasmOk}`);
  if (jsBad !== wasmBad) throw new Error(`scCheck(ff): JS=${jsBad} WASM=${wasmBad}`);
});

// scIsZero
await asyncTest('scIsZero equivalence', async () => {
  const js = new JsCryptoBackend();
  const jsZero = js.scIsZero(ZERO);
  const jsNonzero = js.scIsZero(ONE);
  await setCryptoBackend('wasm');
  const wasmZero = getCryptoBackend().scIsZero(ZERO);
  const wasmNonzero = getCryptoBackend().scIsZero(ONE);
  await setCryptoBackend('js');
  if (jsZero !== wasmZero) throw new Error(`scIsZero(0): JS=${jsZero} WASM=${wasmZero}`);
  if (jsNonzero !== wasmNonzero) throw new Error(`scIsZero(1): JS=${jsNonzero} WASM=${wasmNonzero}`);
});

// Identity: scAdd(a, 0) = a reduced
await asyncTest('scAdd identity: a + 0 = reduce(a)', async () => {
  const js = new JsCryptoBackend();
  const result = js.scAdd(scalarA, ZERO);
  const reduced = js.scReduce32(scalarA);
  assertEqual(result, reduced, 'scAdd identity');
});

// Identity: scInvert(a) * a = 1
await asyncTest('scInvert * a = 1', async () => {
  const js = new JsCryptoBackend();
  const inv = js.scInvert(scalarA);
  const product = js.scMul(inv, scalarA);
  assertEqual(product, ONE, 'inverse identity');
});

// ─── Point equivalence ──────────────────────────────────────────────────────

console.log('\n=== Point Ops Equivalence ===\n');

// Ed25519 base point G (compressed)
const G_HEX = '5866666666666666666666666666666666666666666666666666666666666666';
const G = hexToBytes(G_HEX);

await asyncTest('scalarMultBase(1) = G', async () => {
  const js = new JsCryptoBackend();
  const result = js.scalarMultBase(ONE);
  assertEqual(result, G, 'scalarMultBase(1) should be G');
});

await asyncTest('scalarMultBase equivalence (random scalar)', async () => {
  const js = new JsCryptoBackend();
  const jsResult = js.scalarMultBase(scalarA);
  await setCryptoBackend('wasm');
  const wasmResult = getCryptoBackend().scalarMultBase(scalarA);
  await setCryptoBackend('js');
  assertEqual(jsResult, wasmResult, 'scalarMultBase JS vs WASM');
});

await asyncTest('scalarMultPoint equivalence', async () => {
  const js = new JsCryptoBackend();
  const P = js.scalarMultBase(scalarA);
  const jsResult = js.scalarMultPoint(scalarB, P);
  await setCryptoBackend('wasm');
  const wasmResult = getCryptoBackend().scalarMultPoint(scalarB, P);
  await setCryptoBackend('js');
  assertEqual(jsResult, wasmResult, 'scalarMultPoint JS vs WASM');
});

await asyncTest('scalarMultPoint(s, G) = scalarMultBase(s)', async () => {
  const js = new JsCryptoBackend();
  const viaBase = js.scalarMultBase(scalarA);
  const viaPoint = js.scalarMultPoint(scalarA, G);
  assertEqual(viaBase, viaPoint, 'scalarMultPoint(s,G) vs scalarMultBase(s)');
});

await asyncTest('pointAddCompressed equivalence', async () => {
  const js = new JsCryptoBackend();
  const P = js.scalarMultBase(scalarA);
  const Q = js.scalarMultBase(scalarB);
  const jsResult = js.pointAddCompressed(P, Q);
  await setCryptoBackend('wasm');
  const wasmResult = getCryptoBackend().pointAddCompressed(P, Q);
  await setCryptoBackend('js');
  assertEqual(jsResult, wasmResult, 'pointAdd JS vs WASM');
});

await asyncTest('pointAdd(G, G) = scalarMultBase(2)', async () => {
  const js = new JsCryptoBackend();
  const TWO = new Uint8Array(32); TWO[0] = 2;
  const sum = js.pointAddCompressed(G, G);
  const doubled = js.scalarMultBase(TWO);
  assertEqual(sum, doubled, 'G+G vs 2*G');
});

await asyncTest('pointSubCompressed equivalence', async () => {
  const js = new JsCryptoBackend();
  const P = js.scalarMultBase(scalarA);
  const Q = js.scalarMultBase(scalarB);
  const jsResult = js.pointSubCompressed(P, Q);
  await setCryptoBackend('wasm');
  const wasmResult = getCryptoBackend().pointSubCompressed(P, Q);
  await setCryptoBackend('js');
  assertEqual(jsResult, wasmResult, 'pointSub JS vs WASM');
});

await asyncTest('pointNegate equivalence', async () => {
  const js = new JsCryptoBackend();
  const P = js.scalarMultBase(scalarA);
  const jsResult = js.pointNegate(P);
  await setCryptoBackend('wasm');
  const wasmResult = getCryptoBackend().pointNegate(P);
  await setCryptoBackend('js');
  assertEqual(jsResult, wasmResult, 'pointNegate JS vs WASM');
});

await asyncTest('pointNegate roundtrip: -(-P) = P', async () => {
  const js = new JsCryptoBackend();
  const P = js.scalarMultBase(scalarA);
  const negP = js.pointNegate(P);
  const negNegP = js.pointNegate(negP);
  assertEqual(P, negNegP, 'double negate roundtrip');
});

await asyncTest('doubleScalarMultBase equivalence', async () => {
  const js = new JsCryptoBackend();
  const P = js.scalarMultBase(scalarA);
  const jsResult = js.doubleScalarMultBase(scalarB, P, ONE);
  await setCryptoBackend('wasm');
  const wasmResult = getCryptoBackend().doubleScalarMultBase(scalarB, P, ONE);
  await setCryptoBackend('js');
  assertEqual(jsResult, wasmResult, 'doubleScalarMultBase JS vs WASM');
});

// ─── Benchmark ──────────────────────────────────────────────────────────────

console.log('\n=== Benchmark (10,000 iterations) ===\n');

const benchData = new Uint8Array(256).fill(0x42);
const ITERATIONS = 10_000;

// Keccak-256 benchmark
{
  await setCryptoBackend('js');
  const jsStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) keccak256(benchData);
  const jsTime = performance.now() - jsStart;

  await setCryptoBackend('wasm');
  const wasmStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) keccak256(benchData);
  const wasmTime = performance.now() - wasmStart;

  const speedup = (jsTime / wasmTime).toFixed(2);
  console.log(`  keccak256:  JS ${jsTime.toFixed(1)}ms  WASM ${wasmTime.toFixed(1)}ms  (${speedup}x)`);
}

// Blake2b benchmark
{
  await setCryptoBackend('js');
  const jsStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) blake2b(benchData, 32);
  const jsTime = performance.now() - jsStart;

  await setCryptoBackend('wasm');
  const wasmStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) blake2b(benchData, 32);
  const wasmTime = performance.now() - wasmStart;

  const speedup = (jsTime / wasmTime).toFixed(2);
  console.log(`  blake2b:    JS ${jsTime.toFixed(1)}ms  WASM ${wasmTime.toFixed(1)}ms  (${speedup}x)`);
}

// Scalar and point benchmarks (1,000 iterations — point ops are slower)
const BENCH_SC = 10_000;
const BENCH_PT = 1_000;
const benchScalar = new Uint8Array(32); benchScalar[0] = 42; benchScalar[31] &= 0x0f;
const benchPoint = getCryptoBackend().scalarMultBase(benchScalar);

const benchOps = [
  ['scMulAdd', BENCH_SC, () => scMulAdd(benchScalar, benchScalar, benchScalar)],
  ['scalarMultBase', BENCH_PT, () => scalarMultBase(benchScalar)],
  ['scalarMultPoint', BENCH_PT, () => scalarMultPoint(benchScalar, benchPoint)],
  ['pointAddCompressed', BENCH_PT, () => pointAddCompressed(benchPoint, benchPoint)],
];

for (const [name, iters, fn] of benchOps) {
  await setCryptoBackend('js');
  const jsStart = performance.now();
  for (let i = 0; i < iters; i++) fn();
  const jsTime = performance.now() - jsStart;

  await setCryptoBackend('wasm');
  const wasmStart = performance.now();
  for (let i = 0; i < iters; i++) fn();
  const wasmTime = performance.now() - wasmStart;

  const speedup = (jsTime / wasmTime).toFixed(2);
  const pad = name.padEnd(20);
  console.log(`  ${pad} JS ${jsTime.toFixed(1)}ms  WASM ${wasmTime.toFixed(1)}ms  (${speedup}x) [${iters} iters]`);
}

await setCryptoBackend('js'); // reset

// ─── Summary ────────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
