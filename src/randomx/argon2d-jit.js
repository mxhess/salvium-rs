/**
 * JIT-Optimized Argon2d for RandomX Cache Initialization
 *
 * The main bottleneck is the BlaMka G function called millions of times.
 * This JIT version generates optimized code for the hot inner loops.
 */

import { blake2b } from '../blake2b.js';

// Argon2 constants
const ARGON2_BLOCK_SIZE = 1024;
const ARGON2_QWORDS_IN_BLOCK = 128;
const ARGON2_PREHASH_DIGEST_LENGTH = 64;
const ARGON2_PREHASH_SEED_LENGTH = 72;
const ARGON2_SYNC_POINTS = 4;
const ARGON2_VERSION = 0x13;

// RandomX-specific parameters
export const RANDOMX_ARGON_MEMORY = 262144;
export const RANDOMX_ARGON_ITERATIONS = 3;
export const RANDOMX_ARGON_LANES = 1;
export const RANDOMX_ARGON_SALT = new TextEncoder().encode("RandomX\x03");

const MASK64 = (1n << 64n) - 1n;
const MASK32 = (1n << 32n) - 1n;

/**
 * JIT-compile the BlaMka G function
 * This is the hottest code path in Argon2d
 */
const compiledG = new Function('v', 'a', 'b', 'c', 'd', 'MASK64', 'MASK32', `
  // fBlaMka: x + y + 2 * trunc(x) * trunc(y)
  let va = v[a], vb = v[b], vc = v[c], vd = v[d];

  // G round 1
  va = (va + vb + 2n * (va & MASK32) * (vb & MASK32)) & MASK64;
  vd = ((vd ^ va) >> 32n) | ((vd ^ va) << 32n) & MASK64;
  vc = (vc + vd + 2n * (vc & MASK32) * (vd & MASK32)) & MASK64;
  vb = ((vb ^ vc) >> 24n) | ((vb ^ vc) << 40n) & MASK64;

  // G round 2
  va = (va + vb + 2n * (va & MASK32) * (vb & MASK32)) & MASK64;
  vd = ((vd ^ va) >> 16n) | ((vd ^ va) << 48n) & MASK64;
  vc = (vc + vd + 2n * (vc & MASK32) * (vd & MASK32)) & MASK64;
  vb = ((vb ^ vc) >> 63n) | ((vb ^ vc) << 1n) & MASK64;

  v[a] = va; v[b] = vb; v[c] = vc; v[d] = vd;
`);

/**
 * JIT-compiled Blake2 round (no message)
 */
const compiledBlake2Round = new Function('v', 'MASK64', 'MASK32', `
  const G = (a, b, c, d) => {
    let va = v[a], vb = v[b], vc = v[c], vd = v[d];
    va = (va + vb + 2n * (va & MASK32) * (vb & MASK32)) & MASK64;
    vd = ((vd ^ va) >> 32n) | ((vd ^ va) << 32n) & MASK64;
    vc = (vc + vd + 2n * (vc & MASK32) * (vd & MASK32)) & MASK64;
    vb = ((vb ^ vc) >> 24n) | ((vb ^ vc) << 40n) & MASK64;
    va = (va + vb + 2n * (va & MASK32) * (vb & MASK32)) & MASK64;
    vd = ((vd ^ va) >> 16n) | ((vd ^ va) << 48n) & MASK64;
    vc = (vc + vd + 2n * (vc & MASK32) * (vd & MASK32)) & MASK64;
    vb = ((vb ^ vc) >> 63n) | ((vb ^ vc) << 1n) & MASK64;
    v[a] = va; v[b] = vb; v[c] = vc; v[d] = vd;
  };
  // Column mixing
  G(0, 4, 8, 12); G(1, 5, 9, 13); G(2, 6, 10, 14); G(3, 7, 11, 15);
  // Diagonal mixing
  G(0, 5, 10, 15); G(1, 6, 11, 12); G(2, 7, 8, 13); G(3, 4, 9, 14);
`);

/**
 * Read block from memory
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
 * Write block to memory
 */
function writeBlock(memory, blockIdx, block) {
  const baseIdx = blockIdx * ARGON2_QWORDS_IN_BLOCK;
  for (let i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    memory[baseIdx + i] = block[i];
  }
}

/**
 * Convert bytes to block
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
 * XOR blocks
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
 * JIT-optimized block fill using compiled G function
 */
function fillBlockJit(prevBlock, refBlock, nextBlock, withXor) {
  const blockR = new Array(ARGON2_QWORDS_IN_BLOCK);
  for (let i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    blockR[i] = refBlock[i] ^ prevBlock[i];
  }

  const blockTmp = new Array(ARGON2_QWORDS_IN_BLOCK);
  copyBlock(blockTmp, blockR);

  if (withXor) {
    xorBlocks(blockTmp, nextBlock);
  }

  // Apply Blake2 rounds on columns using JIT-compiled function
  for (let i = 0; i < 8; i++) {
    const v = new Array(16);
    for (let j = 0; j < 16; j++) {
      v[j] = blockR[16 * i + j];
    }
    compiledBlake2Round(v, MASK64, MASK32);
    for (let j = 0; j < 16; j++) {
      blockR[16 * i + j] = v[j];
    }
  }

  // Apply Blake2 rounds on rows
  for (let i = 0; i < 8; i++) {
    const v = [
      blockR[2 * i], blockR[2 * i + 1],
      blockR[2 * i + 16], blockR[2 * i + 17],
      blockR[2 * i + 32], blockR[2 * i + 33],
      blockR[2 * i + 48], blockR[2 * i + 49],
      blockR[2 * i + 64], blockR[2 * i + 65],
      blockR[2 * i + 80], blockR[2 * i + 81],
      blockR[2 * i + 96], blockR[2 * i + 97],
      blockR[2 * i + 112], blockR[2 * i + 113]
    ];

    compiledBlake2Round(v, MASK64, MASK32);

    blockR[2 * i] = v[0]; blockR[2 * i + 1] = v[1];
    blockR[2 * i + 16] = v[2]; blockR[2 * i + 17] = v[3];
    blockR[2 * i + 32] = v[4]; blockR[2 * i + 33] = v[5];
    blockR[2 * i + 48] = v[6]; blockR[2 * i + 49] = v[7];
    blockR[2 * i + 64] = v[8]; blockR[2 * i + 65] = v[9];
    blockR[2 * i + 80] = v[10]; blockR[2 * i + 81] = v[11];
    blockR[2 * i + 96] = v[12]; blockR[2 * i + 97] = v[13];
    blockR[2 * i + 112] = v[14]; blockR[2 * i + 113] = v[15];
  }

  copyBlock(nextBlock, blockTmp);
  xorBlocks(nextBlock, blockR);
}

/**
 * Blake2b variable length hash
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
 * Initial hash H_0
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

  let totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const input = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    input.set(p, offset);
    offset += p.length;
  }

  return blake2b(input, ARGON2_PREHASH_DIGEST_LENGTH);
}

/**
 * Fill first blocks
 */
function fillFirstBlocks(blockHash, memory, laneLength, lanes) {
  const seed = new Uint8Array(ARGON2_PREHASH_SEED_LENGTH);
  seed.set(blockHash);

  for (let l = 0; l < lanes; l++) {
    seed[64] = 0; seed[65] = 0; seed[66] = 0; seed[67] = 0;
    seed[68] = l & 0xff;
    seed[69] = (l >> 8) & 0xff;
    seed[70] = (l >> 16) & 0xff;
    seed[71] = (l >> 24) & 0xff;

    const block0Bytes = blake2bLong(ARGON2_BLOCK_SIZE, seed);
    writeBlock(memory, l * laneLength + 0, bytesToBlock(block0Bytes));

    seed[64] = 1;
    const block1Bytes = blake2bLong(ARGON2_BLOCK_SIZE, seed);
    writeBlock(memory, l * laneLength + 1, bytesToBlock(block1Bytes));
  }
}

/**
 * Index alpha calculation
 */
function indexAlpha(pass, slice, index, pseudoRand, sameLane, laneLength, segmentLength) {
  let referenceAreaSize;

  if (pass === 0) {
    if (slice === 0) {
      referenceAreaSize = index - 1;
    } else {
      referenceAreaSize = sameLane
        ? slice * segmentLength + index - 1
        : slice * segmentLength + (index === 0 ? -1 : 0);
    }
  } else {
    referenceAreaSize = sameLane
      ? laneLength - segmentLength + index - 1
      : laneLength - segmentLength + (index === 0 ? -1 : 0);
  }

  let relativePosition = BigInt(pseudoRand >>> 0);
  relativePosition = (relativePosition * relativePosition) >> 32n;
  relativePosition = BigInt(referenceAreaSize) - 1n -
    ((BigInt(referenceAreaSize) * relativePosition) >> 32n);

  let startPosition = 0;
  if (pass !== 0) {
    startPosition = (slice === ARGON2_SYNC_POINTS - 1) ? 0 : (slice + 1) * segmentLength;
  }

  return (startPosition + Number(relativePosition)) % laneLength;
}

/**
 * Fill segment with JIT-optimized block fill
 */
function fillSegmentJit(memory, position, instance) {
  const { laneLength, segmentLength, lanes, passes, version } = instance;
  let startingIndex = (position.pass === 0 && position.slice === 0) ? 2 : 0;

  let currOffset = position.lane * laneLength + position.slice * segmentLength + startingIndex;
  let prevOffset = (currOffset % laneLength === 0) ? currOffset + laneLength - 1 : currOffset - 1;

  for (let i = startingIndex; i < segmentLength; i++, currOffset++, prevOffset++) {
    if (currOffset % laneLength === 1) {
      prevOffset = currOffset - 1;
    }

    const pseudoRand = memory[prevOffset * ARGON2_QWORDS_IN_BLOCK];
    let refLane = Number((pseudoRand >> 32n) % BigInt(lanes));
    if (position.pass === 0 && position.slice === 0) {
      refLane = position.lane;
    }

    const refIndex = indexAlpha(
      position.pass, position.slice, i,
      Number(pseudoRand & 0xffffffffn),
      refLane === position.lane, laneLength, segmentLength
    );

    const refBlock = readBlock(memory, laneLength * refLane + refIndex);
    const prevBlock = readBlock(memory, prevOffset);
    const nextBlock = new Array(ARGON2_QWORDS_IN_BLOCK).fill(0n);

    const withXor = position.pass !== 0 && version !== 0x10;
    if (withXor) {
      copyBlock(nextBlock, readBlock(memory, currOffset));
    }

    fillBlockJit(prevBlock, refBlock, nextBlock, withXor);
    writeBlock(memory, currOffset, nextBlock);
  }
}

/**
 * Fill memory blocks with JIT optimization and progress callback
 */
function fillMemoryBlocksJit(memory, instance, onProgress = null) {
  const { passes, lanes } = instance;
  const totalSegments = passes * ARGON2_SYNC_POINTS * lanes;
  let completedSegments = 0;

  for (let r = 0; r < passes; r++) {
    for (let s = 0; s < ARGON2_SYNC_POINTS; s++) {
      for (let l = 0; l < lanes; l++) {
        fillSegmentJit(memory, { pass: r, lane: l, slice: s, index: 0 }, instance);
        completedSegments++;
        if (onProgress) {
          onProgress(completedSegments, totalSegments, r, s);
        }
      }
    }
  }
}

/**
 * JIT-optimized RandomX cache initialization
 */
export function initCacheJit(key, onProgress = null) {
  const lanes = RANDOMX_ARGON_LANES;
  const memoryBlocks = Math.floor(RANDOMX_ARGON_MEMORY / (ARGON2_BLOCK_SIZE / 1024));
  const segmentLength = Math.floor(memoryBlocks / (lanes * ARGON2_SYNC_POINTS));
  const laneLength = segmentLength * ARGON2_SYNC_POINTS;
  const totalBlocks = lanes * laneLength;

  const memory = new BigUint64Array(totalBlocks * ARGON2_QWORDS_IN_BLOCK);

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

  const instance = {
    laneLength, segmentLength, lanes,
    passes: RANDOMX_ARGON_ITERATIONS,
    version: ARGON2_VERSION
  };

  const blockHash = initialHash(ctx);
  fillFirstBlocks(blockHash, memory, laneLength, lanes);
  fillMemoryBlocksJit(memory, instance, onProgress);

  return memory;
}

export default {
  initCacheJit,
  RANDOMX_ARGON_MEMORY,
  RANDOMX_ARGON_ITERATIONS,
  RANDOMX_ARGON_LANES
};
