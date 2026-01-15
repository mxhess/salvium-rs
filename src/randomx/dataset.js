/**
 * RandomX Dataset Generation
 *
 * Generates dataset items from cache using SuperscalarHash.
 * The dataset is 2GB+ and computed from the 256MB cache.
 *
 * Reference: external/randomx/src/dataset.cpp
 */

import { blake2b } from '../blake2b.js';
import {
  RANDOMX_ARGON_MEMORY,
  RANDOMX_CACHE_ACCESSES,
  RANDOMX_DATASET_BASE_SIZE,
  RANDOMX_DATASET_EXTRA_SIZE,
  RANDOMX_DATASET_ITEM_COUNT
} from './config.js';
import { Blake2Generator, generateSuperscalar, executeSuperscalar, reciprocal, SuperscalarInstructionType } from './superscalar.js';
import { initCache as argon2InitCache } from './argon2d.js';
import { initCacheJit } from './argon2d-jit.js';

// ============================================================================
// Constants for register initialization
// ============================================================================

const SUPERSCALAR_MUL0 = 6364136223846793005n;
const SUPERSCALAR_ADD1 = 9298411001130361340n;
const SUPERSCALAR_ADD2 = 12065312585734608966n;
const SUPERSCALAR_ADD3 = 9306329213124626780n;
const SUPERSCALAR_ADD4 = 5281919268842080866n;
const SUPERSCALAR_ADD5 = 10536153434571861004n;
const SUPERSCALAR_ADD6 = 3398623926847679864n;
const SUPERSCALAR_ADD7 = 9549104520008361294n;

const SUPERSCALAR_ADDS = [
  0n,  // Not used for r0
  SUPERSCALAR_ADD1,
  SUPERSCALAR_ADD2,
  SUPERSCALAR_ADD3,
  SUPERSCALAR_ADD4,
  SUPERSCALAR_ADD5,
  SUPERSCALAR_ADD6,
  SUPERSCALAR_ADD7
];

// Cache line size (64 bytes)
const CACHE_LINE_SIZE = 64;

// Cache size in bytes
const CACHE_SIZE = RANDOMX_ARGON_MEMORY * 1024;

// Mask for cache access (number of cache lines - 1)
const CACHE_LINE_MASK = (CACHE_SIZE / CACHE_LINE_SIZE) - 1;

const MASK64 = (1n << 64n) - 1n;

// ============================================================================
// RandomX Cache
// ============================================================================

export class RandomXCache {
  constructor() {
    this.memory = null;  // Raw byte array (256 MB)
    this.programs = [];  // Pre-generated superscalar programs
    this.reciprocalCache = [];  // Pre-computed reciprocals
  }

  /**
   * Initialize cache from a key
   *
   * @param {Uint8Array} key - Cache initialization key
   * @param {function} onProgress - Optional progress callback (percent, pass, slice)
   * @param {object} options - Options { jit: boolean }
   */
  init(key, onProgress = null, options = {}) {
    const useJit = options.jit !== false;  // Default to JIT

    // Progress wrapper that converts segment counts to percentages
    const progressHandler = onProgress ? (completed, total, pass, slice) => {
      const percent = Math.round((completed / total) * 100);
      onProgress(percent, pass, slice);
    } : null;

    // Initialize cache memory using Argon2d (JIT or interpreted)
    const initFn = useJit ? initCacheJit : argon2InitCache;
    const cacheQwords = initFn(key, progressHandler);

    // Convert BigUint64Array to Uint8Array (more efficient for byte access)
    const totalBytes = cacheQwords.length * 8;
    this.memory = new Uint8Array(totalBytes);

    for (let i = 0; i < cacheQwords.length; i++) {
      const v = cacheQwords[i];
      const pos = i * 8;
      this.memory[pos] = Number(v & 0xffn);
      this.memory[pos + 1] = Number((v >> 8n) & 0xffn);
      this.memory[pos + 2] = Number((v >> 16n) & 0xffn);
      this.memory[pos + 3] = Number((v >> 24n) & 0xffn);
      this.memory[pos + 4] = Number((v >> 32n) & 0xffn);
      this.memory[pos + 5] = Number((v >> 40n) & 0xffn);
      this.memory[pos + 6] = Number((v >> 48n) & 0xffn);
      this.memory[pos + 7] = Number((v >> 56n) & 0xffn);
    }

    // Generate superscalar programs
    this.programs = [];
    this.reciprocalCache = [];

    const gen = new Blake2Generator(key);

    for (let i = 0; i < RANDOMX_CACHE_ACCESSES; i++) {
      const prog = generateSuperscalar(gen);

      // Pre-compute reciprocals for IMUL_RCP instructions
      for (const instr of prog.instructions) {
        if (instr.opcode === SuperscalarInstructionType.IMUL_RCP) {
          const rcp = reciprocal(instr.imm32);
          instr.imm32 = this.reciprocalCache.length;  // Replace with index
          this.reciprocalCache.push(rcp);
        }
      }

      this.programs.push(prog);
    }
  }

  /**
   * Get a 64-byte mix block from cache
   *
   * @param {BigInt} registerValue - Value to compute address from
   * @returns {Uint8Array} - 64-byte cache line
   */
  getMixBlock(registerValue) {
    const index = Number(registerValue & BigInt(CACHE_LINE_MASK));
    const offset = index * CACHE_LINE_SIZE;
    return this.memory.subarray(offset, offset + CACHE_LINE_SIZE);
  }

  /**
   * Read 64-bit value from cache at offset
   *
   * @param {Uint8Array} block - Cache block
   * @param {number} offset - Byte offset (must be 8-byte aligned)
   * @returns {BigInt} - 64-bit value
   */
  static readU64(block, offset) {
    return BigInt(block[offset]) |
      (BigInt(block[offset + 1]) << 8n) |
      (BigInt(block[offset + 2]) << 16n) |
      (BigInt(block[offset + 3]) << 24n) |
      (BigInt(block[offset + 4]) << 32n) |
      (BigInt(block[offset + 5]) << 40n) |
      (BigInt(block[offset + 6]) << 48n) |
      (BigInt(block[offset + 7]) << 56n);
  }
}

/**
 * Initialize a single dataset item
 *
 * @param {RandomXCache} cache - Initialized cache
 * @param {number} itemNumber - Dataset item index
 * @returns {Uint8Array} - 64-byte dataset item
 */
export function initDatasetItem(cache, itemNumber) {
  const itemBig = BigInt(itemNumber);

  // Initialize registers
  const rl = new Array(8);
  rl[0] = ((itemBig + 1n) * SUPERSCALAR_MUL0) & MASK64;
  for (let i = 1; i < 8; i++) {
    rl[i] = rl[0] ^ SUPERSCALAR_ADDS[i];
  }

  let registerValue = itemBig;

  // Process each cache access
  for (let i = 0; i < RANDOMX_CACHE_ACCESSES; i++) {
    // Get mix block from cache
    const mixBlock = cache.getMixBlock(registerValue);

    // Execute superscalar program
    const prog = cache.programs[i];
    executeSuperscalarWithReciprocals(rl, prog, cache.reciprocalCache);

    // XOR mix block into registers
    for (let q = 0; q < 8; q++) {
      rl[q] ^= RandomXCache.readU64(mixBlock, q * 8);
    }

    // Update register value for next iteration
    registerValue = rl[prog.addressRegister];
  }

  // Convert registers to bytes
  const result = new Uint8Array(CACHE_LINE_SIZE);
  for (let i = 0; i < 8; i++) {
    const v = rl[i];
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

/**
 * Execute superscalar program with pre-computed reciprocals
 *
 * @param {BigInt[]} r - Register array
 * @param {object} prog - Superscalar program
 * @param {BigInt[]} reciprocals - Pre-computed reciprocal values
 */
function executeSuperscalarWithReciprocals(r, prog, reciprocals) {
  for (const instr of prog.instructions) {
    const { opcode, dst, src, imm32 } = instr;

    switch (opcode) {
      case SuperscalarInstructionType.ISUB_R:
        r[dst] = (r[dst] - r[src]) & MASK64;
        break;

      case SuperscalarInstructionType.IXOR_R:
        r[dst] = r[dst] ^ r[src];
        break;

      case SuperscalarInstructionType.IADD_RS:
        r[dst] = (r[dst] + (r[src] << BigInt(instr.getModShift()))) & MASK64;
        break;

      case SuperscalarInstructionType.IMUL_R:
        r[dst] = (r[dst] * r[src]) & MASK64;
        break;

      case SuperscalarInstructionType.IROR_C:
        r[dst] = rotr64(r[dst], imm32);
        break;

      case SuperscalarInstructionType.IADD_C7:
      case SuperscalarInstructionType.IADD_C8:
      case SuperscalarInstructionType.IADD_C9:
        r[dst] = (r[dst] + signExtend(imm32)) & MASK64;
        break;

      case SuperscalarInstructionType.IXOR_C7:
      case SuperscalarInstructionType.IXOR_C8:
      case SuperscalarInstructionType.IXOR_C9:
        r[dst] = r[dst] ^ signExtend(imm32);
        break;

      case SuperscalarInstructionType.IMULH_R:
        r[dst] = mulh(r[dst], r[src]);
        break;

      case SuperscalarInstructionType.ISMULH_R:
        r[dst] = smulh(r[dst], r[src]);
        break;

      case SuperscalarInstructionType.IMUL_RCP:
        // Use pre-computed reciprocal (imm32 is index into reciprocals array)
        r[dst] = (r[dst] * reciprocals[imm32]) & MASK64;
        break;
    }
  }
}

// Helper functions
function rotr64(x, n) {
  n = BigInt(n) % 64n;
  return ((x >> n) | (x << (64n - n))) & MASK64;
}

function signExtend(x) {
  const val = BigInt(x >>> 0);
  return val >= (1n << 31n) ? val - (1n << 32n) + (1n << 64n) : val;
}

function mulh(a, b) {
  return ((a * b) >> 64n) & MASK64;
}

function smulh(a, b) {
  const sa = a >= (1n << 63n) ? a - (1n << 64n) : a;
  const sb = b >= (1n << 63n) ? b - (1n << 64n) : b;
  const result = (sa * sb) >> 64n;
  return result < 0n ? result + (1n << 64n) : result;
}

/**
 * Generate full dataset (for full mode - very memory intensive!)
 * Note: Full dataset is 2GB+, use light mode (initDatasetItem) for most cases
 *
 * @param {RandomXCache} cache - Initialized cache
 * @param {number} startItem - Starting item index
 * @param {number} endItem - Ending item index (exclusive)
 * @returns {Uint8Array} - Dataset segment
 */
export function initDataset(cache, startItem, endItem) {
  const itemCount = endItem - startItem;
  const dataset = new Uint8Array(itemCount * CACHE_LINE_SIZE);

  for (let i = 0; i < itemCount; i++) {
    const item = initDatasetItem(cache, startItem + i);
    dataset.set(item, i * CACHE_LINE_SIZE);
  }

  return dataset;
}

export default {
  RandomXCache,
  initDatasetItem,
  initDataset,
  CACHE_LINE_SIZE,
  CACHE_SIZE
};
