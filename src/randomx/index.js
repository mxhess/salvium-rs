/**
 * RandomX Proof-of-Work Implementation
 *
 * WASM-JIT implementation of the RandomX algorithm used by Salvium.
 * Vendored from https://github.com/l1mey112/randomx.js (BSD 3-Clause).
 *
 * Features:
 * - WASM-JIT compiled for maximum performance
 * - Light mode (256MB cache) - suitable for verification and mining
 * - Full mode (2GB dataset) - faster hashing for dedicated miners
 * - Multi-threaded support via Worker pools
 * - Correct hash output matching reference implementation
 *
 * See src/randomx/vendor/LICENSE for third-party attribution.
 */

import { blake2b } from '../blake2b.js';

// WASM-JIT RandomX implementation (vendored randomx.js)
export {
  RandomXNative,
  randomx_init_cache,
  randomx_create_vm,
  randomx_machine_id,
  randomx_superscalarhash
} from './randomx-native.js';

// Multi-threaded worker pool
import { RandomXWorkerPool, getAvailableCores } from './worker-pool.js';
export { RandomXWorkerPool, getAvailableCores };

// Cache and dataset (used by both WASM and dataset generation)
export { RandomXCache, initDatasetItem, initDataset } from './dataset.js';
export * as config from './config.js';
export * as superscalar from './superscalar.js';

// Export individual superscalar functions for direct access
export {
  Blake2Generator,
  generateSuperscalar,
  executeSuperscalar,
  reciprocal
} from './superscalar.js';

// Argon2d for cache initialization
export { argon2d } from './argon2d.js';

// Full mode (2GB dataset)
export {
  RandomXFullMode,
  createFullModeContext,
  RANDOMX_DATASET_ITEM_COUNT,
  RANDOMX_DATASET_ITEM_SIZE,
  RANDOMX_DATASET_SIZE
} from './full-mode.js';

// Import for internal use
import { RandomXNative } from './randomx-native.js';

/**
 * RandomX context for repeated hashing with the same key
 *
 * This is the main API for RandomX hashing in salvium-js.
 * Uses the native WASM-JIT implementation for speed and correctness.
 *
 * @example
 * const ctx = new RandomXContext();
 * await ctx.init('previous block hash');
 * const hash = ctx.hash('block template');
 */
export class RandomXContext {
  constructor() {
    this.native = new RandomXNative();
    this.cacheKey = null;
  }

  /**
   * Initialize context with a key (typically the previous block hash)
   *
   * @param {Uint8Array|string} key - Cache initialization key
   * @param {function} onProgress - Optional progress callback (percent)
   * @returns {Promise<void>}
   */
  async init(key, onProgress = null) {
    await this.native.init(key, onProgress);
    this.cacheKey = typeof key === 'string' ? key : Array.from(key).join(',');
    console.log(`RandomX initialized (256MB cache, WASM-JIT)`);
  }

  /**
   * Synchronous initialization (same as init, just for API compatibility)
   */
  initSync(key, onProgress = null) {
    return this.init(key, onProgress);
  }

  /**
   * Calculate RandomX hash
   *
   * @param {Uint8Array|string} input - Data to hash
   * @returns {Uint8Array} - 32-byte hash
   */
  hash(input) {
    return this.native.hash(input);
  }

  /**
   * Calculate RandomX hash as hex string
   *
   * @param {Uint8Array|string} input - Data to hash
   * @returns {string} - 64-character hex hash
   */
  hashHex(input) {
    return this.native.hashHex(input);
  }

  /**
   * Verify that input produces expected hash
   *
   * @param {Uint8Array|string} input - Input data
   * @param {Uint8Array|string} expectedHash - Expected hash (bytes or hex)
   * @returns {boolean}
   */
  verify(input, expectedHash) {
    const computed = this.hashHex(input);
    const expected = typeof expectedHash === 'string'
      ? expectedHash.toLowerCase()
      : Array.from(expectedHash).map(b => b.toString(16).padStart(2, '0')).join('');
    return computed === expected;
  }

  /**
   * Get machine ID string
   * @returns {string}
   */
  static getMachineId() {
    return RandomXNative.getMachineId();
  }
}

/**
 * One-shot RandomX hash function
 *
 * Convenience function for single hashes. For multiple hashes with the
 * same key, use RandomXContext for better performance.
 *
 * @param {Uint8Array|string} key - Cache key (e.g., previous block hash)
 * @param {Uint8Array|string} input - Data to hash
 * @returns {Promise<Uint8Array>} - 32-byte hash
 */
export async function rxSlowHash(key, input) {
  const ctx = new RandomXContext();
  await ctx.init(key);
  return ctx.hash(input);
}

/**
 * Alias for rxSlowHash
 */
export const randomxHash = rxSlowHash;

/**
 * Calculate mining commitment hash
 *
 * @param {Uint8Array} blockHash - Current block hash
 * @param {Uint8Array} previousHash - Previous block hash
 * @returns {Uint8Array} - 32-byte commitment
 */
export function calculateCommitment(blockHash, previousHash) {
  const combined = new Uint8Array(64);
  combined.set(blockHash, 0);
  combined.set(previousHash, 32);
  return blake2b(combined, 32);
}

/**
 * Verify RandomX hash
 *
 * @param {Uint8Array|string} key - Cache key
 * @param {Uint8Array|string} input - Input data
 * @param {Uint8Array|string} expectedHash - Expected hash
 * @returns {Promise<boolean>}
 */
export async function verifyHash(key, input, expectedHash) {
  const ctx = new RandomXContext();
  await ctx.init(key);
  return ctx.verify(input, expectedHash);
}

/**
 * Check if hash meets difficulty target
 *
 * @param {Uint8Array|string} hash - Hash to check (32 bytes or 64 hex chars)
 * @param {bigint|number} difficulty - Target difficulty
 * @returns {boolean}
 */
export function checkDifficulty(hash, difficulty) {
  if (difficulty === 0n || difficulty === 0) return false;

  const hashBytes = typeof hash === 'string'
    ? new Uint8Array(hash.match(/.{2}/g).map(b => parseInt(b, 16)))
    : hash;

  let hashNum = 0n;
  for (let i = 0; i < 32; i++) {
    hashNum = (hashNum << 8n) | BigInt(hashBytes[i]);
  }

  const maxTarget = (1n << 256n) - 1n;
  const target = maxTarget / BigInt(difficulty);

  return hashNum <= target;
}

/**
 * Simple mining function
 *
 * @param {Uint8Array|string} key - Cache key
 * @param {Uint8Array} blockTemplate - Block template with nonce field
 * @param {number} nonceOffset - Byte offset of nonce in template
 * @param {bigint} difficulty - Target difficulty
 * @param {number} maxIterations - Maximum nonce attempts
 * @returns {Promise<{nonce: number, hash: Uint8Array}|null>}
 */
export async function mine(key, blockTemplate, nonceOffset, difficulty, maxIterations = 1000000) {
  const ctx = new RandomXContext();
  await ctx.init(key);

  const template = new Uint8Array(blockTemplate);
  const view = new DataView(template.buffer);

  for (let nonce = 0; nonce < maxIterations; nonce++) {
    view.setUint32(nonceOffset, nonce, true);
    const hash = ctx.hash(template);

    if (checkDifficulty(hash, difficulty)) {
      return { nonce, hash };
    }
  }

  return null;
}

import { RandomXCache, initDatasetItem, initDataset } from './dataset.js';
import { RandomXFullMode, createFullModeContext } from './full-mode.js';

export default {
  // Main API
  RandomXContext,
  RandomXNative,
  RandomXWorkerPool,
  rxSlowHash,
  randomxHash,
  calculateCommitment,
  verifyHash,
  checkDifficulty,
  mine,
  // Full mode (2GB dataset)
  RandomXFullMode,
  createFullModeContext,
  // Cache/dataset
  RandomXCache,
  initDatasetItem,
  initDataset
};
