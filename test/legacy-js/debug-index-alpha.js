/**
 * Debug - test indexAlpha directly in WASM vs JS
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ARGON2_SYNC_POINTS = 4;
const RANDOMX_ARGON_MEMORY = 262144;
const RANDOMX_ARGON_LANES = 1;

// JS implementation of indexAlpha for comparison
function jsIndexAlpha(laneLength, segmentLength, pass, slice, index, pseudoRand, sameLane) {
  let referenceAreaSize;

  if (pass === 0) {
    if (slice === 0) {
      referenceAreaSize = index - 1;
    } else {
      if (sameLane) {
        referenceAreaSize = slice * segmentLength + index - 1;
      } else {
        referenceAreaSize = slice * segmentLength + (index === 0 ? -1 : 0);
      }
    }
  } else {
    if (sameLane) {
      referenceAreaSize = laneLength - segmentLength + index - 1;
    } else {
      referenceAreaSize = laneLength - segmentLength + (index === 0 ? -1 : 0);
    }
  }

  // Map pseudo_rand to [0, reference_area_size)
  let relativePos = BigInt(pseudoRand);
  relativePos = (relativePos * relativePos) >> 32n;
  relativePos = BigInt(referenceAreaSize) - 1n - ((BigInt(referenceAreaSize) * relativePos) >> 32n);

  // Starting position
  let startPosition = 0;
  if (pass !== 0) {
    startPosition = (slice === ARGON2_SYNC_POINTS - 1) ? 0 : (slice + 1) * segmentLength;
  }

  return (startPosition + Number(relativePos)) % laneLength;
}

console.log('=== Debug indexAlpha WASM vs JS ===\n');

// Load WASM
const wasmPath = join(__dirname, '../build/randomx.wasm');
const wasmBuffer = readFileSync(wasmPath);

const wasmMemory = new WebAssembly.Memory({
  initial: 4096 + 512,
  maximum: 8192
});

const imports = {
  env: {
    memory: wasmMemory,
    abort: () => {}
  }
};

const { instance } = await WebAssembly.instantiate(wasmBuffer, imports);
const wasm = instance.exports;

// Setup parameters
const memoryBlocks = RANDOMX_ARGON_MEMORY;
const segmentLength = Math.floor(memoryBlocks / (RANDOMX_ARGON_LANES * ARGON2_SYNC_POINTS));
const laneLength = segmentLength * ARGON2_SYNC_POINTS;
const totalBlocks = RANDOMX_ARGON_LANES * laneLength;

// Initialize WASM (to set global variables)
wasm.argon2d_init(0, totalBlocks, laneLength, segmentLength);

console.log('Parameters:');
console.log(`  laneLength: ${laneLength}`);
console.log(`  segmentLength: ${segmentLength}`);
console.log();

// Test cases
const testCases = [
  // Block 2: pass=0, slice=0, index=2, pseudoRand from block 1
  { pass: 0, slice: 0, index: 2, pseudoRand: 0x42e79d76, sameLane: true, expected: 0 },
  // Block 3: pass=0, slice=0, index=3, pseudoRand from block 2
  { pass: 0, slice: 0, index: 3, pseudoRand: 0xae72330b, sameLane: true, expected: 1 },
  // Block 4: pass=0, slice=0, index=4, pseudoRand from block 3
  { pass: 0, slice: 0, index: 4, pseudoRand: 0x73a71a83, sameLane: true, expected: 2 },
];

console.log('Test cases:\n');
for (const tc of testCases) {
  const jsResult = jsIndexAlpha(laneLength, segmentLength, tc.pass, tc.slice, tc.index, tc.pseudoRand, tc.sameLane);
  const wasmResult = wasm.argon2d_test_index_alpha(tc.pass, tc.slice, tc.index, tc.pseudoRand, tc.sameLane ? 1 : 0);

  console.log(`pass=${tc.pass}, slice=${tc.slice}, index=${tc.index}, pseudoRand=0x${tc.pseudoRand.toString(16)}, sameLane=${tc.sameLane}`);
  console.log(`  JS result: ${jsResult}`);
  console.log(`  WASM result: ${wasmResult}`);
  console.log(`  Expected: ${tc.expected}`);
  console.log(`  JS == Expected: ${jsResult === tc.expected}`);
  console.log(`  WASM == Expected: ${wasmResult === tc.expected}`);
  console.log();
}
