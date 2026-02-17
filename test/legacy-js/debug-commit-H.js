#!/usr/bin/env bun
/**
 * Verify the Pedersen commitment H generator point matches C++
 */
import { setCryptoBackend, commit, scalarMultBase } from '../src/crypto/index.js';

await setCryptoBackend('wasm');

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// C++ Monero/Salvium H point:
// H = 8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94
const expectedH = '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94';

// commit(amount=1, mask=0) = 0*G + 1*H = H
const zeroMask = new Uint8Array(32);
const computedH = commit(1n, zeroMask);
console.log(`Expected H: ${expectedH}`);
console.log(`Our H:      ${bytesToHex(computedH)}`);
console.log(`H match: ${bytesToHex(computedH) === expectedH}`);

// commit(amount=0, mask=1) = 1*G + 0*H = G
const oneMask = new Uint8Array(32);
oneMask[0] = 1;
const computedG = commit(0n, oneMask);
const expectedG = scalarMultBase(oneMask);
console.log(`\nExpected G: ${bytesToHex(expectedG)}`);
console.log(`Our G:      ${bytesToHex(computedG)}`);
console.log(`G match: ${bytesToHex(computedG) === bytesToHex(expectedG)}`);

// Verify addKeys2: mask*G + amount*H
// commit(10, mask) should equal scalarMultBase(mask) + 10*H
// We can't easily compute 10*H without scalar mult of H, but we can verify linearity
const mask1 = new Uint8Array(32);
mask1[0] = 42;
const c1 = commit(100n, mask1);
const c2 = commit(200n, mask1);
console.log(`\ncommit(100, mask42): ${bytesToHex(c1)}`);
console.log(`commit(200, mask42): ${bytesToHex(c2)}`);
console.log(`Different (good): ${bytesToHex(c1) !== bytesToHex(c2)}`);

// Now the key test: does our scReduce match WASM scReduce?
import { getCryptoBackend } from '../src/crypto/provider.js';
const backend = getCryptoBackend();

// Generate a 64-byte value and reduce both ways
const testInput = new Uint8Array(64);
for (let i = 0; i < 64; i++) testInput[i] = (i * 37 + 13) % 256;

// WASM scReduce64
const wasmReduced = backend.scReduce64(testInput);

// JS scReduce (from carrot-scanning.js)
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
let n = 0n;
for (let i = 63; i >= 0; i--) n = (n << 8n) | BigInt(testInput[i]);
n = n % L;
const jsReduced = new Uint8Array(32);
for (let i = 0; i < 32; i++) { jsReduced[i] = Number(n & 0xffn); n >>= 8n; }

console.log(`\nscReduce64 test:`);
console.log(`  WASM: ${bytesToHex(wasmReduced)}`);
console.log(`  JS:   ${bytesToHex(jsReduced)}`);
console.log(`  Match: ${bytesToHex(wasmReduced) === bytesToHex(jsReduced)}`);
