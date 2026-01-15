/**
 * Argon2d implementation for RandomX cache initialization
 *
 * Implements Argon2d with the specific parameters used by RandomX:
 * - Memory: 262144 KiB (256 MB)
 * - Iterations: 3
 * - Parallelism (lanes): 1
 * - Salt: "RandomX\x03"
 *
 * Reference: external/randomx/src/argon2_ref.c, argon2_core.c
 *
 * NOTE: Uses BigUint64Array for memory-efficient storage (~256MB instead of 6GB+)
 */

import { blake2b } from '../blake2b.js';

// Argon2 constants
const ARGON2_BLOCK_SIZE = 1024;  // bytes per block
const ARGON2_QWORDS_IN_BLOCK = 128;  // 64-bit words per block
const ARGON2_PREHASH_DIGEST_LENGTH = 64;
const ARGON2_PREHASH_SEED_LENGTH = 72;
const ARGON2_SYNC_POINTS = 4;
const ARGON2_VERSION = 0x13;

// RandomX-specific Argon2 parameters
export const RANDOMX_ARGON_MEMORY = 262144;  // KiB
export const RANDOMX_ARGON_ITERATIONS = 3;
export const RANDOMX_ARGON_LANES = 1;
export const RANDOMX_ARGON_SALT = new TextEncoder().encode("RandomX\x03");

const MASK64 = (1n << 64n) - 1n;

/**
 * 64-bit rotation right
 */
function rotr64(x, n) {
  n = BigInt(n);
  return ((x >> n) | (x << (64n - n))) & MASK64;
}

/**
 * BlaMka mixing function (Lyra2)
 * f(x, y) = x + y + 2 * trunc(x) * trunc(y)
 * where trunc takes the lower 32 bits
 */
function fBlaMka(x, y) {
  const mask32 = (1n << 32n) - 1n;
  const xy = (x & mask32) * (y & mask32);
  return (x + y + 2n * xy) & MASK64;
}

/**
 * G mixing function used in Blake2b rounds
 */
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

/**
 * Blake2 round without message
 */
function blake2bRoundNoMsg(v) {
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

/**
 * Read a block from memory into BigInt array (for computation)
 */
function readBlock(memory, blockIdx) {
  const block = new Array(ARGON2_QWORDS_IN_BLOCK);
  const baseIdx = blockIdx * ARGON2_QWORDS_IN_BLOCK;
  for (let i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    block[i] = memory[baseIdx + i];
  }
  return block;
}

/**
 * Write a block from BigInt array to memory
 */
function writeBlock(memory, blockIdx, block) {
  const baseIdx = blockIdx * ARGON2_QWORDS_IN_BLOCK;
  for (let i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    memory[baseIdx + i] = block[i];
  }
}

/**
 * Read a single qword from memory
 */
function readQword(memory, blockIdx, qwordIdx) {
  return memory[blockIdx * ARGON2_QWORDS_IN_BLOCK + qwordIdx];
}

/**
 * Convert Uint8Array to BigInt array
 */
function bytesToBlock(bytes, offset = 0) {
  const block = new Array(ARGON2_QWORDS_IN_BLOCK);
  for (let i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    const pos = offset + i * 8;
    block[i] = BigInt(bytes[pos]) |
      (BigInt(bytes[pos + 1]) << 8n) |
      (BigInt(bytes[pos + 2]) << 16n) |
      (BigInt(bytes[pos + 3]) << 24n) |
      (BigInt(bytes[pos + 4]) << 32n) |
      (BigInt(bytes[pos + 5]) << 40n) |
      (BigInt(bytes[pos + 6]) << 48n) |
      (BigInt(bytes[pos + 7]) << 56n);
  }
  return block;
}

/**
 * Convert BigInt array to Uint8Array
 */
function blockToBytes(block, output, offset = 0) {
  for (let i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    const v = block[i];
    const pos = offset + i * 8;
    output[pos] = Number(v & 0xffn);
    output[pos + 1] = Number((v >> 8n) & 0xffn);
    output[pos + 2] = Number((v >> 16n) & 0xffn);
    output[pos + 3] = Number((v >> 24n) & 0xffn);
    output[pos + 4] = Number((v >> 32n) & 0xffn);
    output[pos + 5] = Number((v >> 40n) & 0xffn);
    output[pos + 6] = Number((v >> 48n) & 0xffn);
    output[pos + 7] = Number((v >> 56n) & 0xffn);
  }
}

/**
 * XOR two blocks
 */
function xorBlocks(dst, src) {
  for (let i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    dst[i] ^= src[i];
  }
}

/**
 * Copy block
 */
function copyBlock(dst, src) {
  for (let i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    dst[i] = src[i];
  }
}

/**
 * Fill a new memory block using the compression function
 */
function fillBlock(prevBlock, refBlock, nextBlock, withXor) {
  // blockR = ref_block XOR prev_block
  const blockR = new Array(ARGON2_QWORDS_IN_BLOCK);
  for (let i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    blockR[i] = refBlock[i] ^ prevBlock[i];
  }

  // block_tmp = blockR (copy)
  const blockTmp = new Array(ARGON2_QWORDS_IN_BLOCK);
  copyBlock(blockTmp, blockR);

  if (withXor) {
    xorBlocks(blockTmp, nextBlock);
  }

  // Apply Blake2 on columns of 64-bit words: (0,1,...,15), (16,17,...,31), etc.
  for (let i = 0; i < 8; i++) {
    const v = new Array(16);
    for (let j = 0; j < 16; j++) {
      v[j] = blockR[16 * i + j];
    }
    blake2bRoundNoMsg(v);
    for (let j = 0; j < 16; j++) {
      blockR[16 * i + j] = v[j];
    }
  }

  // Apply Blake2 on rows
  for (let i = 0; i < 8; i++) {
    const v = new Array(16);
    v[0] = blockR[2 * i];
    v[1] = blockR[2 * i + 1];
    v[2] = blockR[2 * i + 16];
    v[3] = blockR[2 * i + 17];
    v[4] = blockR[2 * i + 32];
    v[5] = blockR[2 * i + 33];
    v[6] = blockR[2 * i + 48];
    v[7] = blockR[2 * i + 49];
    v[8] = blockR[2 * i + 64];
    v[9] = blockR[2 * i + 65];
    v[10] = blockR[2 * i + 80];
    v[11] = blockR[2 * i + 81];
    v[12] = blockR[2 * i + 96];
    v[13] = blockR[2 * i + 97];
    v[14] = blockR[2 * i + 112];
    v[15] = blockR[2 * i + 113];

    blake2bRoundNoMsg(v);

    blockR[2 * i] = v[0];
    blockR[2 * i + 1] = v[1];
    blockR[2 * i + 16] = v[2];
    blockR[2 * i + 17] = v[3];
    blockR[2 * i + 32] = v[4];
    blockR[2 * i + 33] = v[5];
    blockR[2 * i + 48] = v[6];
    blockR[2 * i + 49] = v[7];
    blockR[2 * i + 64] = v[8];
    blockR[2 * i + 65] = v[9];
    blockR[2 * i + 80] = v[10];
    blockR[2 * i + 81] = v[11];
    blockR[2 * i + 96] = v[12];
    blockR[2 * i + 97] = v[13];
    blockR[2 * i + 112] = v[14];
    blockR[2 * i + 113] = v[15];
  }

  // next_block = block_tmp XOR blockR
  copyBlock(nextBlock, blockTmp);
  xorBlocks(nextBlock, blockR);
}

/**
 * Blake2b variable length hash (for Argon2)
 * H' function from Argon2 spec
 */
function blake2bLong(outLen, input) {
  // Prefix with output length as 32-bit LE
  const prefixed = new Uint8Array(4 + input.length);
  prefixed[0] = outLen & 0xff;
  prefixed[1] = (outLen >> 8) & 0xff;
  prefixed[2] = (outLen >> 16) & 0xff;
  prefixed[3] = (outLen >> 24) & 0xff;
  prefixed.set(input, 4);

  if (outLen <= 64) {
    return blake2b(prefixed, outLen);
  }

  // For longer outputs, use iterative hashing
  const result = new Uint8Array(outLen);

  // First block
  let v = blake2b(prefixed, 64);
  result.set(v.subarray(0, 32), 0);

  let pos = 32;
  while (pos < outLen - 64) {
    v = blake2b(v, 64);
    result.set(v.subarray(0, 32), pos);
    pos += 32;
  }

  // Final block
  const remaining = outLen - pos;
  v = blake2b(v, remaining);
  result.set(v, pos);

  return result;
}

/**
 * Create initial hash H_0
 */
function initialHash(ctx) {
  // Build input for Blake2b
  const parts = [];

  // Lanes (32-bit LE)
  const lanes = new Uint8Array(4);
  lanes[0] = ctx.lanes & 0xff;
  lanes[1] = (ctx.lanes >> 8) & 0xff;
  lanes[2] = (ctx.lanes >> 16) & 0xff;
  lanes[3] = (ctx.lanes >> 24) & 0xff;
  parts.push(lanes);

  // Output length (32-bit LE)
  const outLen = new Uint8Array(4);
  outLen[0] = ctx.outLen & 0xff;
  outLen[1] = (ctx.outLen >> 8) & 0xff;
  outLen[2] = (ctx.outLen >> 16) & 0xff;
  outLen[3] = (ctx.outLen >> 24) & 0xff;
  parts.push(outLen);

  // Memory cost (32-bit LE)
  const mCost = new Uint8Array(4);
  mCost[0] = ctx.mCost & 0xff;
  mCost[1] = (ctx.mCost >> 8) & 0xff;
  mCost[2] = (ctx.mCost >> 16) & 0xff;
  mCost[3] = (ctx.mCost >> 24) & 0xff;
  parts.push(mCost);

  // Time cost (32-bit LE)
  const tCost = new Uint8Array(4);
  tCost[0] = ctx.tCost & 0xff;
  tCost[1] = (ctx.tCost >> 8) & 0xff;
  tCost[2] = (ctx.tCost >> 16) & 0xff;
  tCost[3] = (ctx.tCost >> 24) & 0xff;
  parts.push(tCost);

  // Version (32-bit LE)
  const version = new Uint8Array(4);
  version[0] = ctx.version & 0xff;
  version[1] = (ctx.version >> 8) & 0xff;
  version[2] = (ctx.version >> 16) & 0xff;
  version[3] = (ctx.version >> 24) & 0xff;
  parts.push(version);

  // Type (32-bit LE) - 0 for Argon2d
  const type = new Uint8Array(4);
  type[0] = ctx.type & 0xff;
  type[1] = (ctx.type >> 8) & 0xff;
  type[2] = (ctx.type >> 16) & 0xff;
  type[3] = (ctx.type >> 24) & 0xff;
  parts.push(type);

  // Password length (32-bit LE)
  const pwdLen = new Uint8Array(4);
  pwdLen[0] = ctx.password.length & 0xff;
  pwdLen[1] = (ctx.password.length >> 8) & 0xff;
  pwdLen[2] = (ctx.password.length >> 16) & 0xff;
  pwdLen[3] = (ctx.password.length >> 24) & 0xff;
  parts.push(pwdLen);

  // Password
  if (ctx.password.length > 0) {
    parts.push(ctx.password);
  }

  // Salt length (32-bit LE)
  const saltLen = new Uint8Array(4);
  saltLen[0] = ctx.salt.length & 0xff;
  saltLen[1] = (ctx.salt.length >> 8) & 0xff;
  saltLen[2] = (ctx.salt.length >> 16) & 0xff;
  saltLen[3] = (ctx.salt.length >> 24) & 0xff;
  parts.push(saltLen);

  // Salt
  if (ctx.salt.length > 0) {
    parts.push(ctx.salt);
  }

  // Secret length (32-bit LE) - 0 for RandomX
  const secretLen = new Uint8Array(4);
  parts.push(secretLen);

  // AD length (32-bit LE) - 0 for RandomX
  const adLen = new Uint8Array(4);
  parts.push(adLen);

  // Concatenate all parts
  let totalLen = 0;
  for (const p of parts) {
    totalLen += p.length;
  }
  const input = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    input.set(p, offset);
    offset += p.length;
  }

  return blake2b(input, ARGON2_PREHASH_DIGEST_LENGTH);
}

/**
 * Fill first two blocks in each lane
 */
function fillFirstBlocks(blockHash, memory, laneLength, lanes) {
  // Extend blockhash to 72 bytes for seed
  const seed = new Uint8Array(ARGON2_PREHASH_SEED_LENGTH);
  seed.set(blockHash);

  for (let l = 0; l < lanes; l++) {
    // Block 0: H'(H_0 || 0 || lane)
    seed[64] = 0;
    seed[65] = 0;
    seed[66] = 0;
    seed[67] = 0;
    seed[68] = l & 0xff;
    seed[69] = (l >> 8) & 0xff;
    seed[70] = (l >> 16) & 0xff;
    seed[71] = (l >> 24) & 0xff;

    const block0Bytes = blake2bLong(ARGON2_BLOCK_SIZE, seed);
    const block0 = bytesToBlock(block0Bytes);
    writeBlock(memory, l * laneLength + 0, block0);

    // Block 1: H'(H_0 || 1 || lane)
    seed[64] = 1;
    seed[65] = 0;
    seed[66] = 0;
    seed[67] = 0;

    const block1Bytes = blake2bLong(ARGON2_BLOCK_SIZE, seed);
    const block1 = bytesToBlock(block1Bytes);
    writeBlock(memory, l * laneLength + 1, block1);
  }
}

/**
 * Calculate index alpha for reference block selection (Argon2d)
 */
function indexAlpha(pass, slice, index, pseudoRand, sameLane, laneLength, segmentLength) {
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
  let relativePosition = BigInt(pseudoRand >>> 0);
  relativePosition = (relativePosition * relativePosition) >> 32n;
  relativePosition = BigInt(referenceAreaSize) - 1n -
    ((BigInt(referenceAreaSize) * relativePosition) >> 32n);

  // Starting position
  let startPosition = 0;
  if (pass !== 0) {
    startPosition = (slice === ARGON2_SYNC_POINTS - 1) ? 0 : (slice + 1) * segmentLength;
  }

  // Absolute position
  return (startPosition + Number(relativePosition)) % laneLength;
}

/**
 * Fill a segment of memory
 */
function fillSegment(memory, position, instance) {
  const { laneLength, segmentLength, lanes, passes, version } = instance;
  let startingIndex = 0;

  if (position.pass === 0 && position.slice === 0) {
    startingIndex = 2;  // First two blocks already generated
  }

  let currOffset = position.lane * laneLength +
    position.slice * segmentLength + startingIndex;

  let prevOffset;
  if (currOffset % laneLength === 0) {
    prevOffset = currOffset + laneLength - 1;
  } else {
    prevOffset = currOffset - 1;
  }

  for (let i = startingIndex; i < segmentLength; i++, currOffset++, prevOffset++) {
    // Rotating prev_offset if needed
    if (currOffset % laneLength === 1) {
      prevOffset = currOffset - 1;
    }

    // Get pseudo-random value from previous block (first qword)
    const pseudoRand = readQword(memory, prevOffset, 0);

    // Determine reference lane (Argon2d uses data-dependent addressing)
    let refLane = Number((pseudoRand >> 32n) % BigInt(lanes));
    if (position.pass === 0 && position.slice === 0) {
      refLane = position.lane;  // Can't reference other lanes yet
    }

    // Calculate reference index
    const refIndex = indexAlpha(
      position.pass,
      position.slice,
      i,
      Number(pseudoRand & 0xffffffffn),
      refLane === position.lane,
      laneLength,
      segmentLength
    );

    // Read blocks for computation
    const refBlock = readBlock(memory, laneLength * refLane + refIndex);
    const prevBlock = readBlock(memory, prevOffset);

    // Create or read current block
    const nextBlock = new Array(ARGON2_QWORDS_IN_BLOCK).fill(0n);

    // Fill block
    const withXor = position.pass !== 0 && version !== 0x10;
    if (withXor) {
      // Read existing block for XOR
      const existing = readBlock(memory, currOffset);
      copyBlock(nextBlock, existing);
    }
    fillBlock(prevBlock, refBlock, nextBlock, withXor);

    // Write result back to memory
    writeBlock(memory, currOffset, nextBlock);
  }
}

/**
 * Fill all memory blocks
 */
function fillMemoryBlocks(memory, instance, onProgress = null) {
  const { passes, lanes } = instance;
  const totalSegments = passes * ARGON2_SYNC_POINTS * lanes;
  let completedSegments = 0;

  for (let r = 0; r < passes; r++) {
    for (let s = 0; s < ARGON2_SYNC_POINTS; s++) {
      for (let l = 0; l < lanes; l++) {
        const position = {
          pass: r,
          lane: l,
          slice: s,
          index: 0
        };
        fillSegment(memory, position, instance);
        completedSegments++;

        if (onProgress) {
          onProgress(completedSegments, totalSegments, r, s);
        }
      }
    }
  }
}

/**
 * Argon2d hash function
 *
 * @param {Uint8Array} password - Input password/key
 * @param {Uint8Array} salt - Salt
 * @param {number} tCost - Time cost (iterations)
 * @param {number} mCost - Memory cost in KiB
 * @param {number} parallelism - Number of lanes
 * @param {number} outLen - Output length
 * @returns {Uint8Array} - Hash output
 */
export function argon2d(password, salt, tCost, mCost, parallelism, outLen) {
  const lanes = parallelism;

  // Memory size in blocks
  const memoryBlocks = Math.floor(mCost / (ARGON2_BLOCK_SIZE / 1024));
  const segmentLength = Math.floor(memoryBlocks / (lanes * ARGON2_SYNC_POINTS));
  const laneLength = segmentLength * ARGON2_SYNC_POINTS;
  const totalBlocks = lanes * laneLength;

  // Allocate memory as BigUint64Array (memory efficient!)
  const memory = new BigUint64Array(totalBlocks * ARGON2_QWORDS_IN_BLOCK);

  // Create context
  const ctx = {
    password,
    salt,
    tCost,
    mCost,
    lanes,
    outLen,
    version: ARGON2_VERSION,
    type: 0  // Argon2d
  };

  // Instance parameters
  const instance = {
    laneLength,
    segmentLength,
    lanes,
    passes: tCost,
    version: ARGON2_VERSION
  };

  // Initial hash
  const blockHash = initialHash(ctx);

  // Fill first blocks
  fillFirstBlocks(blockHash, memory, laneLength, lanes);

  // Fill remaining blocks
  fillMemoryBlocks(memory, instance);

  // Finalize: XOR last blocks of all lanes
  const finalBlock = new Array(ARGON2_QWORDS_IN_BLOCK).fill(0n);
  for (let l = 0; l < lanes; l++) {
    const lastBlock = readBlock(memory, l * laneLength + laneLength - 1);
    xorBlocks(finalBlock, lastBlock);
  }

  // Convert to bytes
  const finalBytes = new Uint8Array(ARGON2_BLOCK_SIZE);
  blockToBytes(finalBlock, finalBytes);

  // Hash to get output
  return blake2bLong(outLen, finalBytes);
}

/**
 * Initialize RandomX cache using Argon2d
 *
 * @param {Uint8Array} key - Cache key (typically block header hash)
 * @param {function} onProgress - Optional progress callback (completed, total, pass, slice)
 * @returns {BigUint64Array} - Cache memory (flat array of qwords)
 */
export function initCache(key, onProgress = null) {
  const lanes = RANDOMX_ARGON_LANES;

  // Memory size in blocks
  const memoryBlocks = Math.floor(RANDOMX_ARGON_MEMORY / (ARGON2_BLOCK_SIZE / 1024));
  const segmentLength = Math.floor(memoryBlocks / (lanes * ARGON2_SYNC_POINTS));
  const laneLength = segmentLength * ARGON2_SYNC_POINTS;
  const totalBlocks = lanes * laneLength;

  // Allocate memory as BigUint64Array (~256MB for RandomX)
  const memory = new BigUint64Array(totalBlocks * ARGON2_QWORDS_IN_BLOCK);

  // Create context (RandomX uses 0 output length for cache init)
  const ctx = {
    password: key,
    salt: RANDOMX_ARGON_SALT,
    tCost: RANDOMX_ARGON_ITERATIONS,
    mCost: RANDOMX_ARGON_MEMORY,
    lanes,
    outLen: 0,
    version: ARGON2_VERSION,
    type: 0  // Argon2d
  };

  // Instance parameters
  const instance = {
    laneLength,
    segmentLength,
    lanes,
    passes: RANDOMX_ARGON_ITERATIONS,
    version: ARGON2_VERSION
  };

  // Initial hash
  const blockHash = initialHash(ctx);

  // Fill first blocks
  fillFirstBlocks(blockHash, memory, laneLength, lanes);

  // Fill remaining blocks
  fillMemoryBlocks(memory, instance, onProgress);

  return memory;
}

/**
 * Get cache as Uint8Array for RandomX operations
 *
 * @param {BigUint64Array} cache - Cache memory
 * @returns {Uint8Array} - Cache as byte array
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
 *
 * @param {BigUint64Array} cache - Cache memory
 * @param {number} index - Item index (64-byte item index)
 * @returns {Uint8Array} - 64-byte cache item
 */
export function getCacheItem(cache, index) {
  const qwordStart = index * 8;  // 8 qwords per 64-byte item
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
  argon2d,
  initCache,
  cacheToBytes,
  getCacheItem
};
