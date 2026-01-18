/**
 * Debug - trace block 4 computation (first mismatch point)
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

// JS implementation of indexAlpha for debugging
function indexAlpha(laneLength, segmentLength, pass, slice, index, pseudoRand, sameLane) {
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

  console.log(`  indexAlpha: pass=${pass}, slice=${slice}, index=${index}, sameLane=${sameLane}`);
  console.log(`  referenceAreaSize=${referenceAreaSize}`);

  // Map pseudo_rand to [0, reference_area_size)
  let relativePos = BigInt(pseudoRand) & 0xFFFFFFFFn;
  console.log(`  pseudo_rand & 0xFFFFFFFF = 0x${relativePos.toString(16)}`);

  relativePos = (relativePos * relativePos) >> 32n;
  console.log(`  after square and shift: relativePos = 0x${relativePos.toString(16)}`);

  relativePos = BigInt(referenceAreaSize) - 1n - ((BigInt(referenceAreaSize) * relativePos) >> 32n);
  console.log(`  final relativePos = ${relativePos}`);

  // Starting position
  let startPosition = 0;
  if (pass !== 0) {
    startPosition = (slice === ARGON2_SYNC_POINTS - 1) ? 0 : (slice + 1) * segmentLength;
  }
  console.log(`  startPosition = ${startPosition}`);

  const result = (startPosition + Number(relativePos)) % laneLength;
  console.log(`  refIndex = ${result}`);
  return result;
}

console.log('=== Debug block 4 computation ===\n');

// From C reference:
// Block 4: prev=3, pseudo_rand=0x32a0ba3273a71a83, ref_lane=0, ref_index=2
console.log('C reference for block 4:');
console.log('  prev=3, pseudo_rand=0x32a0ba3273a71a83, ref_lane=0, ref_index=2\n');

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
  tCost: 3,
  mCost: RANDOMX_ARGON_MEMORY,
  lanes,
  outLen: 0,
  version: ARGON2_VERSION,
  type: 0
};

// Generate H0 and fill first two blocks
const blockHash = initialHash(ctx);
const seed = new Uint8Array(ARGON2_PREHASH_SEED_LENGTH);
seed.set(blockHash);
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

// Fill blocks 2 and 3 first
wasm.argon2d_fill_segment(0, 0, 0);  // This fills blocks 2 to 65535

// Now let's trace block 4 computation
// For block 4:
//   pass = 0, lane = 0, slice = 0
//   segment starts at index 2 (starting_index = 2 for pass 0 slice 0)
//   block 4 is at segment index 2 (i.e., startingIndex + 2 = 2 + 2 = 4)
//
// In fillSegment loop:
//   i = 0: currOffset = 2, we fill block 2 using prev=1, ref=indexAlpha(...)
//   i = 1: currOffset = 3, we fill block 3 using prev=2, ref=indexAlpha(...)
//   i = 2: currOffset = 4, we fill block 4 using prev=3, ref=indexAlpha(...)

// Wait - block 4 is filled when i=2 in the segment
// At that point: index = i = 2

console.log('Tracing block 4 computation:\n');

// Read block 3 (which is the prev for block 4)
const block3_qword0 = wasmView.getBigUint64(3 * 1024, true);
console.log(`Block 3 first qword (WASM): 0x${block3_qword0.toString(16)}`);
console.log(`Block 3 first qword (C ref): 0x32a0ba3273a71a83\n`);

// Trace indexAlpha calculation
// For block 4: pass=0, slice=0, index=4 (the loop counter i when filling block 4)
// The loop starts at i=2 (startingIndex), so:
//   i=2 -> block 2, i=3 -> block 3, i=4 -> block 4
const pass = 0;
const slice = 0;
const index = 4;  // This is the loop index i when filling block 4
const pseudoRand = block3_qword0;
const sameLane = true;  // always true in pass 0, slice 0

console.log('My indexAlpha calculation:');
const myRefIndex = indexAlpha(laneLength, segmentLength, pass, slice, index, pseudoRand, sameLane);
console.log();

console.log(`C reference refIndex: 2`);
console.log(`My refIndex: ${myRefIndex}`);
console.log(`Match: ${myRefIndex === 2}`);
