#!/usr/bin/env node
/**
 * Benchmark: WASM vs JS Argon2d Cache Init
 *
 * Usage:
 *   source ~/.bash_profile && bun test/benchmark-wasm-argon2d.js
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { blake2b } from '../src/blake2b.js';
import { initCache as initCacheJS } from '../src/randomx/argon2d.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('Argon2d WASM vs JS Benchmark');
console.log('============================\n');

// Constants
const ARGON2_BLOCK_SIZE = 1024;
const ARGON2_QWORDS_IN_BLOCK = 128;
const ARGON2_SYNC_POINTS = 4;
const RANDOMX_ARGON_MEMORY = 262144;
const RANDOMX_ARGON_ITERATIONS = 3;
const RANDOMX_ARGON_LANES = 1;
const RANDOMX_ARGON_SALT = new TextEncoder().encode("RandomX\x03");

// Calculate dimensions
const memoryBlocks = Math.floor(RANDOMX_ARGON_MEMORY / (ARGON2_BLOCK_SIZE / 1024));
const segmentLength = Math.floor(memoryBlocks / (RANDOMX_ARGON_LANES * ARGON2_SYNC_POINTS));
const laneLength = segmentLength * ARGON2_SYNC_POINTS;
const totalBlocks = RANDOMX_ARGON_LANES * laneLength;
const totalBytes = totalBlocks * ARGON2_BLOCK_SIZE;

console.log(`Memory: ${totalBlocks} blocks (${(totalBytes / 1024 / 1024).toFixed(0)}MB)`);
console.log(`Segment length: ${segmentLength} blocks`);
console.log(`Lane length: ${laneLength} blocks\n`);

// Load WASM
console.log('Loading WASM...');
const wasmPath = join(__dirname, '../build/randomx.wasm');
const wasmBuffer = readFileSync(wasmPath);

// Create WASM memory (need 256MB + working space)
const wasmMemory = new WebAssembly.Memory({
  initial: 4096 + 512,  // ~272MB
  maximum: 8192
});

const imports = {
  env: {
    memory: wasmMemory,
    abort: (msg, file, line, column) => {
      console.error(`WASM abort`);
    }
  }
};

const wasmModule = await WebAssembly.instantiate(wasmBuffer, imports);
const wasm = wasmModule.instance.exports;
console.log('WASM loaded\n');

const key = new TextEncoder().encode('benchmark key');

// Progress helper
const progress = (completed, total, pass, slice) => {
  const percent = Math.round((completed / total) * 100);
  const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
  process.stdout.write(`\r[${bar}] ${percent}% (pass ${pass + 1}/3, slice ${slice + 1}/4)`);
};

// ========== WASM Benchmark ==========
console.log('Testing WASM Argon2d...');
const wasmStart = Date.now();

// Get memory view
const mem = new Uint8Array(wasmMemory.buffer);

// Memory layout: blocks start at offset 0
const memPtr = 0;

// Initialize WASM Argon2d
wasm.argon2d_init(memPtr, totalBlocks, laneLength, segmentLength);

// Initial hash (use JS Blake2b for now)
function initialHash() {
  const parts = [];
  const addU32 = (val) => {
    const arr = new Uint8Array(4);
    arr[0] = val & 0xff;
    arr[1] = (val >> 8) & 0xff;
    arr[2] = (val >> 16) & 0xff;
    arr[3] = (val >> 24) & 0xff;
    parts.push(arr);
  };

  addU32(RANDOMX_ARGON_LANES);
  addU32(0);  // outLen
  addU32(RANDOMX_ARGON_MEMORY);
  addU32(RANDOMX_ARGON_ITERATIONS);
  addU32(0x13);  // version
  addU32(0);  // type (Argon2d)
  addU32(key.length);
  parts.push(key);
  addU32(RANDOMX_ARGON_SALT.length);
  parts.push(RANDOMX_ARGON_SALT);
  addU32(0);  // secret length
  addU32(0);  // AD length

  let totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const input = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    input.set(p, offset);
    offset += p.length;
  }

  return blake2b(input, 64);
}

// H' function for variable length output
function blake2bLong(outLen, input) {
  const prefixed = new Uint8Array(4 + input.length);
  prefixed[0] = outLen & 0xff;
  prefixed[1] = (outLen >> 8) & 0xff;
  prefixed[2] = (outLen >> 16) & 0xff;
  prefixed[3] = (outLen >> 24) & 0xff;
  prefixed.set(input, 4);

  if (outLen <= 64) {
    return blake2b(prefixed, outLen);
  }

  const result = new Uint8Array(outLen);
  let v = blake2b(prefixed, 64);
  result.set(v.subarray(0, 32), 0);

  let pos = 32;
  while (pos < outLen - 64) {
    v = blake2b(v, 64);
    result.set(v.subarray(0, 32), pos);
    pos += 32;
  }

  v = blake2b(v, outLen - pos);
  result.set(v, pos);
  return result;
}

// Fill first blocks
const blockHash = initialHash();
const seed = new Uint8Array(72);
seed.set(blockHash);

// Block 0
seed[64] = 0; seed[65] = 0; seed[66] = 0; seed[67] = 0;
seed[68] = 0; seed[69] = 0; seed[70] = 0; seed[71] = 0;
const block0 = blake2bLong(ARGON2_BLOCK_SIZE, seed);

// Copy block0 to WASM memory at a temp location, then write
const tempPtr = totalBytes + 1024;  // After main memory
mem.set(block0, tempPtr);
wasm.argon2d_write_block(0, tempPtr);

// Block 1
seed[64] = 1;
const block1 = blake2bLong(ARGON2_BLOCK_SIZE, seed);
mem.set(block1, tempPtr);
wasm.argon2d_write_block(1, tempPtr);

// Fill remaining blocks using WASM
let completed = 0;
const totalSegments = RANDOMX_ARGON_ITERATIONS * ARGON2_SYNC_POINTS * RANDOMX_ARGON_LANES;

for (let pass = 0; pass < RANDOMX_ARGON_ITERATIONS; pass++) {
  for (let slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
    for (let lane = 0; lane < RANDOMX_ARGON_LANES; lane++) {
      wasm.argon2d_fill_segment(pass, lane, slice);
      completed++;
      progress(completed, totalSegments, pass, slice);
    }
  }
}

const wasmTime = (Date.now() - wasmStart) / 1000;
process.stdout.write('\r' + ' '.repeat(60) + '\r');
console.log(`WASM time: ${wasmTime.toFixed(1)}s\n`);

// ========== JS Benchmark ==========
console.log('Testing JS Argon2d...');
const jsStart = Date.now();

initCacheJS(key, progress);

const jsTime = (Date.now() - jsStart) / 1000;
process.stdout.write('\r' + ' '.repeat(60) + '\r');
console.log(`JS time: ${jsTime.toFixed(1)}s\n`);

// Results
console.log('Results');
console.log('=======');
console.log(`WASM: ${wasmTime.toFixed(1)}s`);
console.log(`JS:   ${jsTime.toFixed(1)}s`);
console.log(`Speedup: ${(jsTime / wasmTime).toFixed(2)}x`);

if (wasmTime < jsTime) {
  console.log(`\n✓ WASM is ${((1 - wasmTime / jsTime) * 100).toFixed(1)}% faster!`);
} else {
  console.log(`\n✗ WASM is ${((wasmTime / jsTime - 1) * 100).toFixed(1)}% slower`);
}
