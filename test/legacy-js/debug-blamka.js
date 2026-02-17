/**
 * Debug BlaMka G function
 *
 * Test with known values to verify the G mixing is correct
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Reference JS implementations for verification
function rotr64(x, n) {
  // BigInt rotation
  const mask = (1n << 64n) - 1n;
  return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & mask;
}

function fBlaMka(x, y) {
  const mask32 = 0xFFFFFFFFn;
  const mask64 = (1n << 64n) - 1n;
  const xy = (x & mask32) * (y & mask32);
  return (x + y + (xy << 1n)) & mask64;
}

function G(v, a, b, c, d) {
  v[a] = fBlaMka(v[a], v[b]);
  v[d] = rotr64(v[d] ^ v[a], 32);
  v[c] = fBlaMka(v[c], v[d]);
  v[b] = rotr64(v[b] ^ v[c], 24);
  v[a] = fBlaMka(v[a], v[b]);
  v[d] = rotr64(v[d] ^ v[a], 16);
  v[c] = fBlaMka(v[c], v[d]);
  v[b] = rotr64(v[b] ^ v[c], 63);
}

function blake2RoundNoMsg(v) {
  // Column mixing
  G(v, 0, 4, 8, 12);
  G(v, 1, 5, 9, 13);
  G(v, 2, 6, 10, 14);
  G(v, 3, 7, 11, 15);
  // Diagonal mixing
  G(v, 0, 5, 10, 15);
  G(v, 1, 6, 11, 12);
  G(v, 2, 7, 8, 13);
  G(v, 3, 4, 9, 14);
}

console.log('=== Debug BlaMka G function ===\n');

// Test fBlaMka
console.log('Testing fBlaMka:');
const testX = 0x6f55a35b4b448c25n;
const testY = 0x1ec0b3ef42e79d76n;
const result = fBlaMka(testX, testY);
console.log(`fBlaMka(0x${testX.toString(16)}, 0x${testY.toString(16)}) = 0x${result.toString(16)}`);

// Expected: x + y + 2 * (x & 0xFFFFFFFF) * (y & 0xFFFFFFFF)
// = 0x6f55a35b4b448c25 + 0x1ec0b3ef42e79d76 + 2 * 0x4b448c25 * 0x42e79d76
const xLow = 0x4b448c25n;
const yLow = 0x42e79d76n;
const xy = xLow * yLow;
const expected = (testX + testY + (xy << 1n)) & ((1n << 64n) - 1n);
console.log(`Expected: 0x${expected.toString(16)}`);
console.log(`Match: ${result === expected}`);
console.log();

// Test rotr64
console.log('Testing rotr64:');
const testVal = 0x1234567890ABCDEFn;
console.log(`rotr64(0x${testVal.toString(16)}, 32) = 0x${rotr64(testVal, 32).toString(16)}`);
console.log(`Expected: 0x90abcdef12345678`);
console.log(`Match: ${rotr64(testVal, 32) === 0x90abcdef12345678n}`);
console.log();

// Test a single G round
console.log('Testing single G round:');
let v = new Array(16).fill(0n);
v[0] = 0x6f55a35b4b448c25n;  // a
v[4] = 0x1ec0b3ef42e79d76n;  // b
v[8] = 0x5ea96ca6ae72330bn;  // c
v[12] = 0x12a341721b934cd7n; // d

console.log('Before G(0, 4, 8, 12):');
console.log(`  v[0] = 0x${v[0].toString(16)}`);
console.log(`  v[4] = 0x${v[4].toString(16)}`);
console.log(`  v[8] = 0x${v[8].toString(16)}`);
console.log(`  v[12] = 0x${v[12].toString(16)}`);

G(v, 0, 4, 8, 12);

console.log('After G(0, 4, 8, 12):');
console.log(`  v[0] = 0x${v[0].toString(16)}`);
console.log(`  v[4] = 0x${v[4].toString(16)}`);
console.log(`  v[8] = 0x${v[8].toString(16)}`);
console.log(`  v[12] = 0x${v[12].toString(16)}`);
console.log();

// Test full blake2 round with 16 values
console.log('Testing full blake2RoundNoMsg:');
let w = [
  0x6f55a35b4b448c25n, 0x1ec0b3ef42e79d76n, 0x5ea96ca6ae72330bn, 0x12a341721b934cd7n,
  0x57735241406f2bd7n, 0x1234567890abcdefn, 0xfedcba0987654321n, 0x1111111111111111n,
  0x2222222222222222n, 0x3333333333333333n, 0x4444444444444444n, 0x5555555555555555n,
  0x6666666666666666n, 0x7777777777777777n, 0x8888888888888888n, 0x9999999999999999n
];

console.log('Before blake2RoundNoMsg:');
for (let i = 0; i < 16; i++) {
  console.log(`  w[${i}] = 0x${w[i].toString(16)}`);
}

blake2RoundNoMsg(w);

console.log('After blake2RoundNoMsg:');
for (let i = 0; i < 16; i++) {
  console.log(`  w[${i}] = 0x${w[i].toString(16)}`);
}

// Now load WASM and test the WASM version
console.log('\n=== Testing WASM implementation ===\n');

const wasmPath = join(__dirname, '../build/randomx.wasm');
const wasmBuffer = readFileSync(wasmPath);

const wasmMemory = new WebAssembly.Memory({
  initial: 512,
  maximum: 1024
});

const imports = {
  env: {
    memory: wasmMemory,
    abort: () => {}
  }
};

const { instance } = await WebAssembly.instantiate(wasmBuffer, imports);
const wasm = instance.exports;

// Check if there's a test function exported, otherwise we need to test via fill_block
// For now, let's just verify the basic functionality is consistent

console.log('WASM module loaded successfully');

// We could add export functions to WASM to test individual components,
// but for now let's focus on the actual Argon2d behavior
