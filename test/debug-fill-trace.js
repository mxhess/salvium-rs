/**
 * Debug - trace exactly what inputs WASM uses for block 4
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

// Reference JS fillBlock for comparison
function rotr64(x, n) {
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
  G(v, 0, 4, 8, 12);
  G(v, 1, 5, 9, 13);
  G(v, 2, 6, 10, 14);
  G(v, 3, 7, 11, 15);
  G(v, 0, 5, 10, 15);
  G(v, 1, 6, 11, 12);
  G(v, 2, 7, 8, 13);
  G(v, 3, 4, 9, 14);
}

function jsFillBlock(prevBlock, refBlock, currBlock, withXor) {
  const blockR = new Array(128);
  for (let i = 0; i < 128; i++) {
    blockR[i] = prevBlock[i] ^ refBlock[i];
  }

  const blockTmp = new Array(128);
  if (withXor) {
    for (let i = 0; i < 128; i++) {
      blockTmp[i] = blockR[i] ^ currBlock[i];
    }
  } else {
    for (let i = 0; i < 128; i++) {
      blockTmp[i] = blockR[i];
    }
  }

  for (let i = 0; i < 8; i++) {
    const v = [];
    for (let j = 0; j < 16; j++) {
      v.push(blockR[i * 16 + j]);
    }
    blake2RoundNoMsg(v);
    for (let j = 0; j < 16; j++) {
      blockR[i * 16 + j] = v[j];
    }
  }

  for (let i = 0; i < 8; i++) {
    const indices = [
      i * 2, i * 2 + 1, i * 2 + 16, i * 2 + 17,
      i * 2 + 32, i * 2 + 33, i * 2 + 48, i * 2 + 49,
      i * 2 + 64, i * 2 + 65, i * 2 + 80, i * 2 + 81,
      i * 2 + 96, i * 2 + 97, i * 2 + 112, i * 2 + 113
    ];
    const v = indices.map(idx => blockR[idx]);
    blake2RoundNoMsg(v);
    for (let j = 0; j < 16; j++) {
      blockR[indices[j]] = v[j];
    }
  }

  const result = new Array(128);
  for (let i = 0; i < 128; i++) {
    result[i] = blockTmp[i] ^ blockR[i];
  }
  return result;
}

console.log('=== Debug fill trace ===\n');

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
const memoryBlocks = Math.floor(RANDOMX_ARGON_MEMORY / (ARGON2_BLOCK_SIZE / 1024));
const segmentLength = Math.floor(memoryBlocks / (RANDOMX_ARGON_LANES * ARGON2_SYNC_POINTS));
const laneLength = segmentLength * ARGON2_SYNC_POINTS;
const totalBlocks = RANDOMX_ARGON_LANES * laneLength;
const totalBytes = totalBlocks * ARGON2_BLOCK_SIZE;

// Use offset 65536 to avoid overlapping with AssemblyScript heap (blockR is at ~3872)
const argonMemOffset = 65536;
wasm.argon2d_init(argonMemOffset, totalBlocks, laneLength, segmentLength);

// Create context and fill initial blocks
const ctx = {
  password: key,
  salt: RANDOMX_ARGON_SALT,
  tCost: 3,
  mCost: RANDOMX_ARGON_MEMORY,
  lanes: RANDOMX_ARGON_LANES,
  outLen: 0,
  version: ARGON2_VERSION,
  type: 0
};

const blockHash = initialHash(ctx);
const seed = new Uint8Array(ARGON2_PREHASH_SEED_LENGTH);
seed.set(blockHash);
const mem = new Uint8Array(wasmMemory.buffer);
const tempPtr = argonMemOffset + totalBytes + 1024;

seed[64] = 0; seed[65] = 0; seed[66] = 0; seed[67] = 0;
seed[68] = 0; seed[69] = 0; seed[70] = 0; seed[71] = 0;
const block0Bytes = blake2bLong(ARGON2_BLOCK_SIZE, seed);
mem.set(block0Bytes, tempPtr);
wasm.argon2d_write_block(0, tempPtr);

seed[64] = 1;
const block1Bytes = blake2bLong(ARGON2_BLOCK_SIZE, seed);
mem.set(block1Bytes, tempPtr);
wasm.argon2d_write_block(1, tempPtr);

const wasmView = new DataView(wasmMemory.buffer);

function readBlockFromWasm(blockIdx) {
  const result = [];
  for (let i = 0; i < 128; i++) {
    result.push(wasmView.getBigUint64(argonMemOffset + blockIdx * 1024 + i * 8, true));
  }
  return result;
}

// Fill blocks 2 and 3 manually to verify
const block0 = readBlockFromWasm(0);
const block1 = readBlockFromWasm(1);

// Manually fill block 2
const jsBlock2 = jsFillBlock(block1, block0, new Array(128).fill(0n), false);
console.log('JS block 2 first qword:', '0x' + jsBlock2[0].toString(16));

// Now use WASM to fill block 2 and verify
// Run fill_segment which will fill blocks 2-65535
wasm.argon2d_fill_segment(0, 0, 0);

const wasmBlock2 = readBlockFromWasm(2);
const wasmBlock3 = readBlockFromWasm(3);
const wasmBlock4 = readBlockFromWasm(4);

console.log('WASM block 2 first qword:', '0x' + wasmBlock2[0].toString(16));
console.log('Match block 2:', jsBlock2[0] === wasmBlock2[0]);
console.log();

// Check block 3 (fill with JS)
const jsBlock3 = jsFillBlock(jsBlock2, block1, new Array(128).fill(0n), false);
console.log('JS block 3 first qword:', '0x' + jsBlock3[0].toString(16));
console.log('WASM block 3 first qword:', '0x' + wasmBlock3[0].toString(16));
console.log('Match block 3:', jsBlock3[0] === wasmBlock3[0]);
console.log();

// Check block 4 (fill with JS using ref=block2)
console.log('For block 4:');
console.log('  prevBlock = block 3');
console.log('  refBlock = block 2 (based on indexAlpha)');
const jsBlock4 = jsFillBlock(jsBlock3, jsBlock2, new Array(128).fill(0n), false);
console.log('JS block 4 first qword:', '0x' + jsBlock4[0].toString(16));
console.log('WASM block 4 first qword:', '0x' + wasmBlock4[0].toString(16));
console.log('Match block 4:', jsBlock4[0] === wasmBlock4[0]);
console.log();

// Let's check if WASM used different input blocks
// Compare all 128 qwords of block 3 in JS vs WASM
let block3MismatchCount = 0;
for (let i = 0; i < 128; i++) {
  if (jsBlock3[i] !== wasmBlock3[i]) {
    if (block3MismatchCount < 5) {
      console.log(`Block 3 mismatch at qword ${i}: JS=0x${jsBlock3[i].toString(16)}, WASM=0x${wasmBlock3[i].toString(16)}`);
    }
    block3MismatchCount++;
  }
}
if (block3MismatchCount === 0) {
  console.log('All 128 qwords of block 3 match between JS and WASM');
} else {
  console.log(`Block 3 total mismatches: ${block3MismatchCount}/128`);
}

// Also compare block 2
let block2Match = true;
for (let i = 0; i < 128; i++) {
  if (jsBlock2[i] !== wasmBlock2[i]) {
    console.log(`Block 2 mismatch at qword ${i}: JS=0x${jsBlock2[i].toString(16)}, WASM=0x${wasmBlock2[i].toString(16)}`);
    block2Match = false;
    break;
  }
}
if (block2Match) {
  console.log('All 128 qwords of block 2 match between JS and WASM');
}

// Expected from C
console.log();
console.log('C reference block 4 first qword: 0xaf9207223075ca2a');
console.log('JS matches C:', jsBlock4[0].toString(16) === 'af9207223075ca2a');
