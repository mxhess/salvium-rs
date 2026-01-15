/**
 * WASM-backed Argon2d implementation for RandomX cache initialization
 *
 * Uses AssemblyScript-compiled WASM for ~37x speedup over pure JavaScript.
 * Provides the same interface as argon2d.js but with WASM acceleration.
 *
 * Reference: external/randomx/src/argon2_ref.c, argon2_core.c
 */

import { blake2b } from '../blake2b.js';

// Constants (same as argon2d.js)
const ARGON2_BLOCK_SIZE = 1024;
const ARGON2_QWORDS_IN_BLOCK = 128;
const ARGON2_PREHASH_DIGEST_LENGTH = 64;
const ARGON2_PREHASH_SEED_LENGTH = 72;
const ARGON2_SYNC_POINTS = 4;
const ARGON2_VERSION = 0x13;

export const RANDOMX_ARGON_MEMORY = 262144;
export const RANDOMX_ARGON_ITERATIONS = 3;
export const RANDOMX_ARGON_LANES = 1;
export const RANDOMX_ARGON_SALT = new TextEncoder().encode("RandomX\x03");

// WASM module state
let wasmInstance = null;
let wasmMemory = null;
let memPtr = 0;

/**
 * Load and initialize WASM module
 */
async function ensureWasm() {
  if (wasmInstance) return;

  // Dynamically import to support both Node and browser
  const { readFileSync } = await import('fs');
  const { fileURLToPath } = await import('url');
  const { dirname, join } = await import('path');

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const wasmPath = join(__dirname, '../../build/randomx.wasm');
  const wasmBuffer = readFileSync(wasmPath);

  // Create memory (256MB + extra for working space)
  wasmMemory = new WebAssembly.Memory({
    initial: 4096 + 512,  // ~288MB
    maximum: 8192         // 512MB max
  });

  const imports = {
    env: {
      memory: wasmMemory,
      abort: (msg, file, line, column) => {
        console.error(`WASM abort at ${file}:${line}:${column}`);
      }
    }
  };

  const wasmModule = await WebAssembly.instantiate(wasmBuffer, imports);
  wasmInstance = wasmModule.instance.exports;
}

/**
 * Blake2b variable length hash (for Argon2)
 * H' function from Argon2 spec
 */
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

/**
 * Create initial hash H_0
 */
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
  addU32(0);  // secret length
  addU32(0);  // AD length

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

/**
 * Initialize RandomX cache using WASM-accelerated Argon2d
 *
 * @param {Uint8Array} key - Cache key (typically block header hash)
 * @param {function} onProgress - Optional progress callback (completed, total, pass, slice)
 * @returns {BigUint64Array} - Cache memory (flat array of qwords)
 */
export async function initCache(key, onProgress = null) {
  await ensureWasm();

  const lanes = RANDOMX_ARGON_LANES;

  // Memory size in blocks
  const memoryBlocks = Math.floor(RANDOMX_ARGON_MEMORY / (ARGON2_BLOCK_SIZE / 1024));
  const segmentLength = Math.floor(memoryBlocks / (lanes * ARGON2_SYNC_POINTS));
  const laneLength = segmentLength * ARGON2_SYNC_POINTS;
  const totalBlocks = lanes * laneLength;
  const totalBytes = totalBlocks * ARGON2_BLOCK_SIZE;

  // Get memory view
  const mem = new Uint8Array(wasmMemory.buffer);

  // Memory layout: blocks start at offset 0
  memPtr = 0;

  // Initialize WASM Argon2d state
  wasmInstance.argon2d_init(memPtr, totalBlocks, laneLength, segmentLength);

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

  // Generate initial hash
  const blockHash = initialHash(ctx);
  const seed = new Uint8Array(ARGON2_PREHASH_SEED_LENGTH);
  seed.set(blockHash);

  // Fill first blocks (using JS Blake2b for the H' function)
  // Block 0: H'(H_0 || 0 || 0)
  seed[64] = 0; seed[65] = 0; seed[66] = 0; seed[67] = 0;  // index = 0
  seed[68] = 0; seed[69] = 0; seed[70] = 0; seed[71] = 0;  // lane = 0
  const block0 = blake2bLong(ARGON2_BLOCK_SIZE, seed);

  // Copy block0 to WASM memory at a temp location
  const tempPtr = totalBytes + 1024;
  mem.set(block0, tempPtr);
  wasmInstance.argon2d_write_block(0, tempPtr);

  // Block 1: H'(H_0 || 1 || 0)
  seed[64] = 1;
  const block1 = blake2bLong(ARGON2_BLOCK_SIZE, seed);
  mem.set(block1, tempPtr);
  wasmInstance.argon2d_write_block(1, tempPtr);

  // Fill remaining blocks using WASM
  const totalSegments = RANDOMX_ARGON_ITERATIONS * ARGON2_SYNC_POINTS * lanes;
  let completed = 0;

  for (let pass = 0; pass < RANDOMX_ARGON_ITERATIONS; pass++) {
    for (let slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
      for (let lane = 0; lane < lanes; lane++) {
        wasmInstance.argon2d_fill_segment(pass, lane, slice);
        completed++;

        if (onProgress) {
          onProgress(completed, totalSegments, pass, slice);
        }
      }
    }
  }

  // Copy result from WASM memory to BigUint64Array
  const cache = new BigUint64Array(totalBlocks * ARGON2_QWORDS_IN_BLOCK);
  const dataView = new DataView(wasmMemory.buffer);

  for (let i = 0; i < cache.length; i++) {
    cache[i] = dataView.getBigUint64(i * 8, true);
  }

  return cache;
}

/**
 * Synchronous cache initialization (for compatibility)
 * Throws if WASM is not already loaded
 */
export function initCacheSync(key, onProgress = null) {
  if (!wasmInstance) {
    throw new Error('WASM not loaded. Call initCache() first or use await initCache()');
  }

  // The async version works synchronously once WASM is loaded
  // But we need to use the promise-returning version
  throw new Error('Use initCache() (async) instead');
}

/**
 * Pre-load WASM module
 */
export async function preloadWasm() {
  await ensureWasm();
}

/**
 * Get cache as Uint8Array for RandomX operations
 */
export function cacheToBytes(cache) {
  const totalQwords = cache.length;
  const bytes = new Uint8Array(totalQwords * 8);

  for (let i = 0; i < totalQwords; i++) {
    const v = cache[i];
    const pos = i * 8;
    bytes[pos] = Number(v & 0xffn);
    bytes[pos + 1] = Number((v >> 8n) & 0xffn);
    bytes[pos + 2] = Number((v >> 16n) & 0xffn);
    bytes[pos + 3] = Number((v >> 24n) & 0xffn);
    bytes[pos + 4] = Number((v >> 32n) & 0xffn);
    bytes[pos + 5] = Number((v >> 40n) & 0xffn);
    bytes[pos + 6] = Number((v >> 48n) & 0xffn);
    bytes[pos + 7] = Number((v >> 56n) & 0xffn);
  }

  return bytes;
}

/**
 * Get a 64-byte item from cache at given index
 */
export function getCacheItem(cache, index) {
  const qwordStart = index * 8;
  const result = new Uint8Array(64);

  for (let i = 0; i < 8; i++) {
    const v = cache[qwordStart + i];
    const pos = i * 8;
    result[pos] = Number(v & 0xffn);
    result[pos + 1] = Number((v >> 8n) & 0xffn);
    result[pos + 2] = Number((v >> 16n) & 0xffn);
    result[pos + 3] = Number((v >> 24n) & 0xffn);
    result[pos + 4] = Number((v >> 32n) & 0xffn);
    result[pos + 5] = Number((v >> 40n) & 0xffn);
    result[pos + 6] = Number((v >> 48n) & 0xffn);
    result[pos + 7] = Number((v >> 56n) & 0xffn);
  }

  return result;
}

export default {
  RANDOMX_ARGON_MEMORY,
  RANDOMX_ARGON_ITERATIONS,
  RANDOMX_ARGON_LANES,
  RANDOMX_ARGON_SALT,
  initCache,
  preloadWasm,
  cacheToBytes,
  getCacheItem
};
