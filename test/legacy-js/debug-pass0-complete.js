/**
 * Debug - verify pass 0 completes correctly
 * Compare several blocks after pass 0 between pure JS and WASM
 */

import { blake2b } from '../src/blake2b.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ARGON2_BLOCK_SIZE = 1024;
const ARGON2_PREHASH_DIGEST_LENGTH = 64;
const ARGON2_PREHASH_SEED_LENGTH = 72;
const ARGON2_SYNC_POINTS = 4;
const ARGON2_VERSION = 0x13;
const RANDOMX_ARGON_MEMORY = 262144;
const RANDOMX_ARGON_ITERATIONS = 3;
const RANDOMX_ARGON_LANES = 1;
const RANDOMX_ARGON_SALT = new TextEncoder().encode("RandomX\x03");

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

  const remaining = outLen - pos;
  v = blake2b(v, remaining);
  result.set(v, pos);

  return result;
}

function initialHash(ctx) {
  const parts = [];
  const addU32 = (val) => {
    const arr = new Uint8Array(4);
    arr[0] = val & 0xff;
    arr[1] = (val >> 8) & 0xff;
    arr[2] = (val >> 16) & 0xff;
    arr[3] = (val >> 24) & 0xff;
    parts.push(arr);
  };

  addU32(ctx.lanes);
  addU32(ctx.outLen);
  addU32(ctx.mCost);
  addU32(ctx.tCost);
  addU32(ctx.version);
  addU32(ctx.type);
  addU32(ctx.password.length);
  if (ctx.password.length > 0) parts.push(ctx.password);
  addU32(ctx.salt.length);
  if (ctx.salt.length > 0) parts.push(ctx.salt);
  addU32(0);
  addU32(0);

  let totalLen = 0;
  for (const p of parts) totalLen += p.length;
  const input = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    input.set(p, offset);
    offset += p.length;
  }

  return blake2b(input, ARGON2_PREHASH_DIGEST_LENGTH);
}

console.log('=== Verify pass 0 completion ===\n');

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

// Setup
const key = new TextEncoder().encode("test key 000");
const lanes = RANDOMX_ARGON_LANES;
const memoryBlocks = Math.floor(RANDOMX_ARGON_MEMORY / (ARGON2_BLOCK_SIZE / 1024));
const segmentLength = Math.floor(memoryBlocks / (lanes * ARGON2_SYNC_POINTS));
const laneLength = segmentLength * ARGON2_SYNC_POINTS;
const totalBlocks = lanes * laneLength;
const totalBytes = totalBlocks * ARGON2_BLOCK_SIZE;

// Initialize WASM
const memPtr = 0;
wasm.argon2d_init(memPtr, totalBlocks, laneLength, segmentLength);

// Create context
const ctx = {
  password: key,
  salt: RANDOMX_ARGON_SALT,
  tCost: RANDOMX_ARGON_ITERATIONS,
  mCost: RANDOMX_ARGON_MEMORY,
  lanes,
  outLen: 0,
  version: ARGON2_VERSION,
  type: 0
};

// Generate H0
const blockHash = initialHash(ctx);

// Build seed for block 0
const seed = new Uint8Array(ARGON2_PREHASH_SEED_LENGTH);
seed.set(blockHash);

// Fill first two blocks
const mem = new Uint8Array(wasmMemory.buffer);
const tempPtr = totalBytes + 1024;

seed[64] = 0; seed[65] = 0; seed[66] = 0; seed[67] = 0;
seed[68] = 0; seed[69] = 0; seed[70] = 0; seed[71] = 0;
const block0 = blake2bLong(ARGON2_BLOCK_SIZE, seed);
mem.set(block0, tempPtr);
wasm.argon2d_write_block(0, tempPtr);

seed[64] = 1;
const block1 = blake2bLong(ARGON2_BLOCK_SIZE, seed);
mem.set(block1, tempPtr);
wasm.argon2d_write_block(1, tempPtr);

const wasmView = new DataView(wasmMemory.buffer);

console.log('Running pass 0...');
const startTime = Date.now();
for (let slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
  wasm.argon2d_fill_segment(0, 0, slice);
  process.stdout.write(`  Slice ${slice} done\r`);
}
const elapsed = Date.now() - startTime;
console.log(`Pass 0 completed in ${elapsed}ms          `);
console.log();

// Check several key blocks
const checkBlocks = [0, 1, 2, 100, 1000, 65535, 65536, 131071, 196607, 262143];

console.log('Block values after pass 0:');
for (const idx of checkBlocks) {
  const val = wasmView.getBigUint64(idx * 1024, true);
  console.log(`  Block ${idx}: 0x${val.toString(16)}`);
}

// These are the expected values from the C reference (we'll need to fill these in)
// For now, let's check that blocks are non-zero after pass 0
console.log();
let nonZeroCount = 0;
for (let i = 0; i < 10; i++) {
  const idx = Math.floor(Math.random() * totalBlocks);
  const val = wasmView.getBigUint64(idx * 1024, true);
  if (val !== 0n) nonZeroCount++;
}
console.log(`Random block check: ${nonZeroCount}/10 blocks are non-zero`);

// Now let's trace pass 1 slice 0 first iteration manually
console.log('\n=== Tracing pass 1, slice 0, first iteration ===');

const prevBlockIdx = 262143;
const currBlockIdx = 0;

// Read prev block first qword
const prevFirstQword = wasmView.getBigUint64(prevBlockIdx * 1024, true);
console.log(`prev block ${prevBlockIdx} first qword: 0x${prevFirstQword.toString(16)}`);

// In Argon2d, pseudo_rand comes from the first qword of the previous block
const pseudoRand = prevFirstQword;
console.log(`pseudoRand: 0x${pseudoRand.toString(16)}`);

// For pass 1, slice 0:
// startPosition = (slice + 1) * segmentLength = 1 * 65536 = 65536
// referenceAreaSize = laneLength - segmentLength + index - 1 = 262144 - 65536 + 0 - 1 = 196607

// Calculate ref_index using indexAlpha
const pass = 1;
const slice = 0;
const index = 0;
const sameLane = true;

let referenceAreaSize = laneLength - segmentLength + index - 1; // = 196607
console.log(`referenceAreaSize: ${referenceAreaSize}`);

let relativePos = pseudoRand & 0xFFFFFFFFn;
relativePos = (relativePos * relativePos) >> 32n;
relativePos = BigInt(referenceAreaSize) - 1n - ((BigInt(referenceAreaSize) * relativePos) >> 32n);
console.log(`relativePos: ${relativePos}`);

const startPosition = 65536; // (slice + 1) * segmentLength for pass > 0, slice < 3
const refIndex = (startPosition + Number(relativePos)) % laneLength;
console.log(`startPosition: ${startPosition}`);
console.log(`refIndex: ${refIndex}`);

// Read ref block first qword
const refFirstQword = wasmView.getBigUint64(refIndex * 1024, true);
console.log(`ref block ${refIndex} first qword: 0x${refFirstQword.toString(16)}`);

// Read curr block (block 0) first qword before update
const currBeforeQword = wasmView.getBigUint64(0, true);
console.log(`curr block 0 first qword (before): 0x${currBeforeQword.toString(16)}`);

// Now run pass 1 slice 0
console.log('\nRunning pass 1, slice 0...');
wasm.argon2d_fill_segment(1, 0, 0);

// Read curr block after update
const currAfterQword = wasmView.getBigUint64(0, true);
console.log(`curr block 0 first qword (after): 0x${currAfterQword.toString(16)}`);
