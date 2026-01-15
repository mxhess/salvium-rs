/**
 * RandomX JavaScript Implementation
 *
 * A JavaScript implementation of the RandomX proof-of-work algorithm
 * used by Salvium (and Monero). Supports both pure JS and WASM acceleration.
 *
 * Features:
 * - Light mode (cache-based) for memory-constrained environments
 * - Full mode (dataset-based) for mining nodes (optional)
 * - WASM acceleration (37x faster cache init with AssemblyScript)
 * - Pure JavaScript fallback
 *
 * Performance:
 * - WASM mode: Cache init ~4s, suitable for mining
 * - JS mode: Cache init ~157s, suitable for verification only
 *
 * Modes:
 * - Light mode: 256MB cache, compute dataset items on-the-fly
 * - Full mode: 2GB dataset, fastest hashing (requires more memory)
 */

import { blake2b } from '../blake2b.js';
import * as config from './config.js';
import { RandomXCache, initDatasetItem, initDataset } from './dataset.js';
import { RandomXVM, fillAes } from './vm.js';
import { RandomXVMJit } from './vm-jit.js';
import { initCache as argon2InitCache } from './argon2d.js';
import { initCache as argon2InitCacheWasm, preloadWasm } from './argon2d-wasm.js';
import { ParallelDataset, DATASET_SIZE, DATASET_ITEM_SIZE } from './parallel.js';

// Re-export configuration
export * from './config.js';

// Re-export submodules
export { RandomXCache, initDatasetItem, initDataset } from './dataset.js';
export { RandomXVM, fillAes } from './vm.js';
export { RandomXVMJit, clearJitCache, getJitCacheStats } from './vm-jit.js';
export { Blake2Generator, generateSuperscalar, executeSuperscalar, reciprocal } from './superscalar.js';
export { initCache as argon2InitCache, argon2d } from './argon2d.js';
export { initCache as argon2InitCacheWasm, preloadWasm } from './argon2d-wasm.js';
export { ParallelDataset, LightDataset, WorkerDataset, getCpuCount, DATASET_SIZE, DATASET_ITEM_SIZE } from './parallel.js';
export * as aes from './aes.js';

/**
 * RandomX context for repeated hashing with the same key
 *
 * @param {object} options - Configuration options
 * @param {boolean} options.jit - Use JIT-compiled VM (default: true)
 * @param {boolean} options.wasm - Use WASM for cache init (default: true)
 * @param {boolean} options.fullMode - Use full mode with 2GB dataset (default: false)
 */
export class RandomXContext {
  constructor(options = {}) {
    this.cache = null;
    this.dataset = null;  // Full mode dataset (2GB)
    this.vm = null;
    this.cacheKey = null;
    this.useJit = options.jit !== false;  // Default to JIT
    this.useWasm = options.wasm !== false;  // Default to WASM
    this.fullMode = options.fullMode === true;  // Default to light mode
  }

  /**
   * Initialize context with a key (typically the previous block hash)
   * This is an async method when using WASM or full mode.
   *
   * @param {Uint8Array|string} key - Cache initialization key
   * @param {function} onProgress - Optional progress callback (stage, percent, details)
   * @returns {Promise<void>}
   */
  async init(key, onProgress = null) {
    // Convert string to bytes if needed
    if (typeof key === 'string') {
      key = new TextEncoder().encode(key);
    }

    // Check if key changed
    const keyStr = Array.from(key).join(',');
    if (this.cacheKey === keyStr) {
      return;  // Already initialized with this key
    }

    // Default progress handler
    const defaultProgress = (stage, percent, details) => {
      if (typeof process !== 'undefined' && process.stdout && process.stdout.write) {
        const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
        if (stage === 'cache') {
          const info = details.pass !== undefined
            ? `pass ${details.pass + 1}/3, slice ${details.slice + 1}/4`
            : details.message || '';
          process.stdout.write(`\rCache:   [${bar}] ${percent}% ${info}`.padEnd(80));
        } else if (stage === 'dataset') {
          const info = details.eta !== undefined
            ? `${details.itemsPerSec} items/s, ETA: ${details.eta}s`
            : details.message || '';
          process.stdout.write(`\rDataset: [${bar}] ${percent}% ${info}`.padEnd(80));
        }
      }
    };

    const progressHandler = onProgress || defaultProgress;

    // Initialize cache
    if (this.useWasm) {
      // WASM-accelerated cache initialization (async)
      progressHandler('cache', 0, { message: 'Loading WASM...' });

      const cacheQwords = await argon2InitCacheWasm(key, (completed, total, pass, slice) => {
        const percent = Math.round((completed / total) * 100);
        progressHandler('cache', percent, { pass, slice });
      });

      // Create cache object and populate from WASM result
      this.cache = new RandomXCache();
      const totalBytes = cacheQwords.length * 8;
      this.cache.memory = new Uint8Array(totalBytes);

      for (let i = 0; i < cacheQwords.length; i++) {
        const v = cacheQwords[i];
        const pos = i * 8;
        this.cache.memory[pos] = Number(v & 0xffn);
        this.cache.memory[pos + 1] = Number((v >> 8n) & 0xffn);
        this.cache.memory[pos + 2] = Number((v >> 16n) & 0xffn);
        this.cache.memory[pos + 3] = Number((v >> 24n) & 0xffn);
        this.cache.memory[pos + 4] = Number((v >> 32n) & 0xffn);
        this.cache.memory[pos + 5] = Number((v >> 40n) & 0xffn);
        this.cache.memory[pos + 6] = Number((v >> 48n) & 0xffn);
        this.cache.memory[pos + 7] = Number((v >> 56n) & 0xffn);
      }

      // Generate superscalar programs
      const { Blake2Generator, generateSuperscalar, reciprocal, SuperscalarInstructionType } = await import('./superscalar.js');
      this.cache.programs = [];
      this.cache.reciprocalCache = [];

      const gen = new Blake2Generator(key);
      for (let i = 0; i < config.RANDOMX_CACHE_ACCESSES; i++) {
        const prog = generateSuperscalar(gen);
        for (const instr of prog.instructions) {
          if (instr.opcode === SuperscalarInstructionType.IMUL_RCP) {
            const rcp = reciprocal(instr.imm32);
            instr.imm32 = this.cache.reciprocalCache.length;
            this.cache.reciprocalCache.push(rcp);
          }
        }
        this.cache.programs.push(prog);
      }
    } else {
      // Pure JS cache initialization (sync)
      this.cache = new RandomXCache();
      this.cache.init(key, (percent, pass, slice) => {
        progressHandler('cache', percent, { pass, slice });
      });
    }

    progressHandler('cache', 100, { message: 'Cache ready' });

    // Full mode: generate 2GB dataset
    if (this.fullMode) {
      progressHandler('dataset', 0, { message: 'Initializing 2GB dataset...' });

      const totalItems = config.RANDOMX_DATASET_ITEM_COUNT;
      this.dataset = new Uint8Array(totalItems * DATASET_ITEM_SIZE);

      const chunkSize = 1000;
      const startTime = Date.now();
      let completedItems = 0;

      for (let start = 0; start < totalItems; start += chunkSize) {
        const end = Math.min(start + chunkSize, totalItems);

        for (let i = start; i < end; i++) {
          const item = initDatasetItem(this.cache, i);
          this.dataset.set(item, i * DATASET_ITEM_SIZE);
          completedItems++;
        }

        const percent = Math.round((completedItems / totalItems) * 100);
        const elapsed = (Date.now() - startTime) / 1000;
        const itemsPerSec = Math.round(completedItems / elapsed);
        const eta = Math.round((totalItems - completedItems) / itemsPerSec);

        progressHandler('dataset', percent, {
          completedItems,
          totalItems,
          itemsPerSec,
          eta
        });

        // Yield to event loop
        await new Promise(resolve => setImmediate(resolve));
      }

      progressHandler('dataset', 100, { message: 'Dataset ready' });
    }

    // Clear progress line
    if (typeof process !== 'undefined' && process.stdout && process.stdout.write) {
      process.stdout.write('\r' + ' '.repeat(80) + '\r');
    }

    const mode = this.fullMode ? 'full' : 'light';
    const accel = this.useWasm ? 'WASM' : 'JS';
    const vm = this.useJit ? 'JIT' : 'interpreted';
    const memSize = this.fullMode ? '2GB' : '256MB';
    console.log(`RandomX initialized (${memSize}, ${mode} mode, ${accel}, ${vm} VM)`);

    // Create VM (JIT or interpreted)
    this.vm = this.useJit ? new RandomXVMJit(this.cache) : new RandomXVM(this.cache);

    // If full mode, configure VM to use dataset instead of computing items
    if (this.fullMode) {
      this.vm.dataset = this.dataset;
    }

    this.cacheKey = keyStr;
  }

  /**
   * Synchronous init (for backwards compatibility, uses pure JS)
   */
  initSync(key, onProgress = null) {
    // Convert string to bytes if needed
    if (typeof key === 'string') {
      key = new TextEncoder().encode(key);
    }

    // Check if key changed
    const keyStr = Array.from(key).join(',');
    if (this.cacheKey === keyStr) {
      return;
    }

    const progressHandler = onProgress || ((percent, pass, slice) => {
      const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
      const msg = `\rInitializing RandomX cache: [${bar}] ${percent}% (pass ${pass + 1}/3, slice ${slice + 1}/4)`;
      if (typeof process !== 'undefined' && process.stdout && process.stdout.write) {
        process.stdout.write(msg);
      }
    });

    this.cache = new RandomXCache();
    this.cache.init(key, progressHandler, { jit: this.useJit });

    if (typeof process !== 'undefined' && process.stdout && process.stdout.write) {
      process.stdout.write('\r' + ' '.repeat(80) + '\r');
    }
    console.log(`RandomX cache initialized (256MB, light mode, JS)`);

    this.vm = this.useJit ? new RandomXVMJit(this.cache) : new RandomXVM(this.cache);
    this.cacheKey = keyStr;
  }

  /**
   * Calculate hash of input
   *
   * @param {Uint8Array|string} input - Data to hash
   * @returns {Uint8Array} - 32-byte hash
   */
  hash(input) {
    if (!this.cache || !this.vm) {
      throw new Error('RandomX context not initialized. Call init() first.');
    }

    // Convert string to bytes if needed
    if (typeof input === 'string') {
      input = new TextEncoder().encode(input);
    }

    // Initial Blake2b hash to get 64-byte tempHash
    let tempHash = blake2b(input, 64);

    // Initialize scratchpad
    this.vm.initScratchpad(tempHash);

    // Run program chain
    for (let chain = 0; chain < config.RANDOMX_PROGRAM_COUNT - 1; chain++) {
      this.vm.run(tempHash);
      tempHash = blake2b(this.vm.getRegisterFile(), 64);
    }

    // Final run
    this.vm.run(tempHash);

    // Get final result
    return this.vm.getFinalResult();
  }
}

/**
 * Calculate RandomX hash (slow_hash) - async version
 *
 * This is a convenience function that creates a temporary context.
 * For multiple hashes with the same key, use RandomXContext directly.
 *
 * @param {Uint8Array|string} key - Cache initialization key (block header hash)
 * @param {Uint8Array|string} input - Data to hash
 * @param {object} options - Options: { wasm: boolean, fullMode: boolean }
 * @returns {Promise<Uint8Array>} - 32-byte hash
 */
export async function rxSlowHash(key, input, options = {}) {
  const ctx = new RandomXContext(options);
  await ctx.init(key);
  return ctx.hash(input);
}

/**
 * Calculate RandomX hash (sync version, uses pure JS)
 *
 * @param {Uint8Array|string} key - Cache initialization key
 * @param {Uint8Array|string} input - Data to hash
 * @returns {Uint8Array} - 32-byte hash
 */
export function rxSlowHashSync(key, input) {
  const ctx = new RandomXContext({ wasm: false });
  ctx.initSync(key);
  return ctx.hash(input);
}

/**
 * Calculate RandomX hash (legacy alias)
 */
export const randomxHash = rxSlowHash;

/**
 * Calculate RandomX commitment (hash of input + previous hash)
 *
 * @param {Uint8Array} input - Original input
 * @param {Uint8Array} hashIn - Previous hash (32 bytes)
 * @returns {Uint8Array} - 32-byte commitment
 */
export function calculateCommitment(input, hashIn) {
  const combined = new Uint8Array(input.length + 32);
  combined.set(input, 0);
  combined.set(hashIn, input.length);
  return blake2b(combined, 32);
}

/**
 * Verify a RandomX hash
 *
 * @param {Uint8Array|string} key - Cache initialization key
 * @param {Uint8Array|string} input - Data to hash
 * @param {Uint8Array} expectedHash - Expected hash result
 * @returns {boolean} - True if hash matches
 */
export function verifyHash(key, input, expectedHash) {
  const actualHash = rxSlowHash(key, input);

  if (actualHash.length !== expectedHash.length) {
    return false;
  }

  for (let i = 0; i < actualHash.length; i++) {
    if (actualHash[i] !== expectedHash[i]) {
      return false;
    }
  }

  return true;
}

/**
 * Check if a hash meets the difficulty target
 *
 * @param {Uint8Array} hash - 32-byte hash
 * @param {BigInt} difficulty - Target difficulty
 * @returns {boolean} - True if hash meets difficulty
 */
export function checkDifficulty(hash, difficulty) {
  if (difficulty === 0n) return false;

  // Convert hash to BigInt (little-endian)
  let hashVal = 0n;
  for (let i = 31; i >= 0; i--) {
    hashVal = (hashVal << 8n) | BigInt(hash[i]);
  }

  // Check: hash * difficulty <= 2^256 - 1
  const max256 = (1n << 256n) - 1n;
  return hashVal * difficulty <= max256;
}

/**
 * Mine a block (find nonce that meets difficulty)
 *
 * @param {Uint8Array|string} key - Cache key
 * @param {Uint8Array} blockBlob - Block blob with nonce placeholder
 * @param {number} nonceOffset - Offset of nonce in block blob
 * @param {BigInt} difficulty - Target difficulty
 * @param {number} maxNonce - Maximum nonce to try (default: 2^32)
 * @param {function} onProgress - Progress callback (nonce, hashrate)
 * @returns {object|null} - { nonce, hash } if found, null if not
 */
export function mine(key, blockBlob, nonceOffset, difficulty, maxNonce = 0xFFFFFFFF, onProgress = null) {
  const ctx = new RandomXContext();
  ctx.init(key);

  const blob = new Uint8Array(blockBlob);
  const startTime = Date.now();
  let hashCount = 0;

  for (let nonce = 0; nonce <= maxNonce; nonce++) {
    // Set nonce in blob (little-endian)
    blob[nonceOffset] = nonce & 0xff;
    blob[nonceOffset + 1] = (nonce >> 8) & 0xff;
    blob[nonceOffset + 2] = (nonce >> 16) & 0xff;
    blob[nonceOffset + 3] = (nonce >> 24) & 0xff;

    // Calculate hash
    const hash = ctx.hash(blob);
    hashCount++;

    // Check difficulty
    if (checkDifficulty(hash, difficulty)) {
      return { nonce, hash };
    }

    // Progress callback
    if (onProgress && nonce % 100 === 0) {
      const elapsed = (Date.now() - startTime) / 1000;
      const hashrate = hashCount / elapsed;
      onProgress(nonce, hashrate);
    }
  }

  return null;
}

export default {
  RandomXContext,
  rxSlowHash,
  rxSlowHashSync,
  randomxHash,
  calculateCommitment,
  verifyHash,
  checkDifficulty,
  mine,
  preloadWasm,
  config
};
