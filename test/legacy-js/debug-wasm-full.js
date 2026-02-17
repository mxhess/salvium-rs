/**
 * Debug WASM - run all passes and check final value
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

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

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

console.log('=== Debug WASM - Full Argon2d run ===\n');

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

// Initialize WASM - use offset 65536 to avoid overlap with AssemblyScript heap
const memPtr = 65536;
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
const tempPtr = memPtr + totalBytes + 1024;

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

console.log('Initial block 0:', '0x' + wasmView.getBigUint64(memPtr, true).toString(16));
console.log('Expected after all passes:', '0x191e0e1d23c02186');
console.log();

// Run all passes
const startTime = Date.now();
for (let pass = 0; pass < RANDOMX_ARGON_ITERATIONS; pass++) {
  for (let slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
    for (let lane = 0; lane < lanes; lane++) {
      wasm.argon2d_fill_segment(pass, lane, slice);
    }
  }
  console.log(`After pass ${pass + 1}: memory[0] = 0x${wasmView.getBigUint64(memPtr, true).toString(16)}`);
}
const elapsed = Date.now() - startTime;

console.log();
console.log('Final memory[0]:', '0x' + wasmView.getBigUint64(memPtr, true).toString(16));
console.log('Expected:       ', '0x191e0e1d23c02186');
console.log('Match:', wasmView.getBigUint64(memPtr, true) === 0x191e0e1d23c02186n);
console.log();
console.log(`Time: ${elapsed}ms`);
