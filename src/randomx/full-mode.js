/**
 * RandomX Full Mode Implementation
 *
 * Full mode pre-computes the entire 2GB dataset for faster hashing.
 * Uses the vendored randomx.js for dataset generation and VM execution.
 *
 * Memory requirements:
 * - Cache: 256 MB
 * - Dataset: ~2 GB (34,078,719 items × 64 bytes)
 * - Total: ~2.3 GB
 *
 * Performance:
 * - Dataset generation: One-time cost (~30-60 seconds)
 * - Hash computation: Faster than light mode (O(1) lookups vs O(superscalar))
 */

import {
  randomx_init_cache,
  randomx_superscalarhash,
  randomx_machine_id
} from './vendor/index.js';

// Dataset constants from RandomX spec
export const RANDOMX_DATASET_ITEM_COUNT = 34078719;  // (2GB + extra) / 64 bytes
export const RANDOMX_DATASET_ITEM_SIZE = 64;  // 8 x i64 = 64 bytes
export const RANDOMX_DATASET_SIZE = RANDOMX_DATASET_ITEM_COUNT * RANDOMX_DATASET_ITEM_SIZE;

// VM memory size in WASM pages (from vendored library build)
const VM_WASM_PAGES = 33;  // ~2.1 MB for scratchpad

// JIT feature constants
const JIT_BASELINE = 0;
const JIT_RELAXED_SIMD = 1;
const JIT_FMA = 2;

// Feature detection - parse from machine_id
function detectJitFeature() {
  const machineId = randomx_machine_id();
  if (machineId.includes('+fma')) {
    return JIT_FMA | JIT_RELAXED_SIMD;
  } else if (machineId.includes('+relaxed-simd')) {
    return JIT_RELAXED_SIMD;
  }
  return JIT_BASELINE;
}

/**
 * Full mode RandomX context
 *
 * Pre-computes the entire 2GB dataset for faster hashing.
 */
export class RandomXFullMode {
  constructor() {
    this.cache = null;
    this.dataset = null;  // BigInt64Array holding all items
    this.ssHash = null;
    this.cacheKey = null;
    this.vm = null;
  }

  /**
   * Initialize full mode context
   *
   * @param {Uint8Array|string} key - Cache initialization key
   * @param {object} options - Options
   * @param {function} options.onProgress - Progress callback (percent, phase)
   * @returns {Promise<void>}
   */
  async init(key, options = {}) {
    const { onProgress } = options;
    const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;

    // Phase 1: Initialize cache (256MB, ~600ms)
    if (onProgress) onProgress(0, 'cache');
    this.cache = randomx_init_cache(keyBytes);
    this.ssHash = randomx_superscalarhash(this.cache);
    this.cacheKey = typeof key === 'string' ? key : Array.from(keyBytes).join(',');
    if (onProgress) onProgress(5, 'cache');

    // Phase 2: Generate dataset (2GB)
    if (onProgress) onProgress(5, 'dataset');
    await this._generateDataset(onProgress);
    if (onProgress) onProgress(100, 'done');

    // Phase 3: Create VM with dataset lookup
    this._createVM();

    console.log(`RandomX Full Mode initialized (256MB cache + 2GB dataset)`);
  }

  /**
   * Generate the full 2GB dataset
   */
  async _generateDataset(onProgress) {
    // Allocate dataset as BigInt64Array (8 values per item)
    this.dataset = new BigInt64Array(RANDOMX_DATASET_ITEM_COUNT * 8);

    const startTime = Date.now();
    let lastProgress = 5;
    const progressInterval = Math.floor(RANDOMX_DATASET_ITEM_COUNT / 95);  // ~1% per update

    for (let i = 0; i < RANDOMX_DATASET_ITEM_COUNT; i++) {
      // Compute dataset item using superscalar hash
      const item = this.ssHash(BigInt(i));
      const offset = i * 8;
      for (let j = 0; j < 8; j++) {
        this.dataset[offset + j] = item[j];
      }

      // Progress reporting (every ~1%)
      if (onProgress && i % progressInterval === 0) {
        const percent = 5 + Math.floor((i / RANDOMX_DATASET_ITEM_COUNT) * 95);
        if (percent > lastProgress) {
          lastProgress = percent;
          onProgress(percent, 'dataset');
        }
      }

      // Yield to event loop occasionally to prevent blocking
      if (i % 50000 === 0) {
        await new Promise(resolve => setImmediate(resolve));
      }
    }

    const elapsed = (Date.now() - startTime) / 1000;
    console.log(`Dataset generated in ${elapsed.toFixed(1)}s (${(RANDOMX_DATASET_SIZE / 1024 / 1024 / 1024).toFixed(2)} GB)`);
  }

  /**
   * Create the VM with our dataset lookup function
   */
  _createVM() {
    // Create dataset lookup function that returns from pre-computed array
    const dataset = this.dataset;
    const datasetLookup = (itemIndex) => {
      const idx = Number(itemIndex);
      const offset = idx * 8;
      return [
        dataset[offset],
        dataset[offset + 1],
        dataset[offset + 2],
        dataset[offset + 3],
        dataset[offset + 4],
        dataset[offset + 5],
        dataset[offset + 6],
        dataset[offset + 7]
      ];
    };

    // Create VM instance with our lookup function
    // We need to instantiate the VM WASM module with our custom imports
    const cache = this.cache;
    const SCRATCH_SIZE = 16 * 1024;

    // Create our own memory for the VM (33 pages for scratchpad)
    const memory = new WebAssembly.Memory({ initial: VM_WASM_PAGES, maximum: VM_WASM_PAGES });

    // Instantiate VM module
    const vmImports = {
      env: {
        memory
      }
    };

    const vmInstance = new WebAssembly.Instance(cache.vm, vmImports);
    const vmExports = vmInstance.exports;

    // Initialize VM and get scratch buffer pointer
    const feature = detectJitFeature();
    const scratchPtr = vmExports.i(feature);
    const scratch = new Uint8Array(memory.buffer, scratchPtr, SCRATCH_SIZE);

    // JIT imports with our dataset lookup
    const jitImports = {
      e: {
        m: memory,
        d: datasetLookup  // Our pre-computed dataset lookup
      }
    };

    // Hash function
    const hashFn = (input, isHex) => {
      if (typeof input === 'string') {
        input = new TextEncoder().encode(input);
      }

      // Initialize for new hash
      vmExports.I(isHex);

      if (input.length <= SCRATCH_SIZE) {
        scratch.set(input);
        vmExports.H(input.length);
      } else {
        let p = 0;
        while (p < input.length) {
          const chunk = input.subarray(p, p + SCRATCH_SIZE);
          p += SCRATCH_SIZE;
          scratch.set(chunk);
          vmExports.H(chunk.length);
        }
      }

      // Run VM iterations
      let jitSize;
      while (true) {
        jitSize = vmExports.R();
        if (jitSize === 0) break;

        // Compile and execute JIT program
        const jitModule = new WebAssembly.Module(scratch.subarray(0, jitSize));
        const jitInstance = new WebAssembly.Instance(jitModule, jitImports);
        jitInstance.exports.d();
      }
    };

    // Store VM interface
    this.vm = {
      calculate_hash: (input) => {
        hashFn(input, false);
        return new Uint8Array(scratch.subarray(0, 32));
      },
      calculate_hex_hash: (input) => {
        hashFn(input, true);
        return new TextDecoder().decode(scratch.subarray(0, 64));
      }
    };
  }

  /**
   * Calculate RandomX hash
   *
   * @param {Uint8Array|string} input - Data to hash
   * @returns {Uint8Array} - 32-byte hash
   */
  hash(input) {
    if (!this.vm) {
      throw new Error('RandomX Full Mode not initialized. Call init() first.');
    }
    return this.vm.calculate_hash(input);
  }

  /**
   * Calculate RandomX hash as hex string
   *
   * @param {Uint8Array|string} input - Data to hash
   * @returns {string} - 64-character hex hash
   */
  hashHex(input) {
    if (!this.vm) {
      throw new Error('RandomX Full Mode not initialized. Call init() first.');
    }
    return this.vm.calculate_hex_hash(input);
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
   * Check if dataset is initialized
   */
  get isReady() {
    return this.dataset !== null && this.vm !== null;
  }

  /**
   * Get memory usage in bytes
   */
  get memoryUsage() {
    const cacheSize = 256 * 1024 * 1024;  // 256 MB
    const datasetSize = this.dataset ? this.dataset.byteLength : 0;
    return cacheSize + datasetSize;
  }

  /**
   * Get memory usage as human-readable string
   */
  get memoryUsageString() {
    const bytes = this.memoryUsage;
    if (bytes >= 1024 * 1024 * 1024) {
      return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
    }
    return `${(bytes / 1024 / 1024).toFixed(0)} MB`;
  }

  /**
   * Get machine ID string
   * @returns {string}
   */
  static getMachineId() {
    return randomx_machine_id();
  }
}

/**
 * Create and initialize a full mode context
 *
 * @param {Uint8Array|string} key - Cache initialization key
 * @param {object} options - Options
 * @returns {Promise<RandomXFullMode>}
 */
export async function createFullModeContext(key, options = {}) {
  const ctx = new RandomXFullMode();
  await ctx.init(key, options);
  return ctx;
}

export default {
  RandomXFullMode,
  createFullModeContext,
  RANDOMX_DATASET_ITEM_COUNT,
  RANDOMX_DATASET_ITEM_SIZE,
  RANDOMX_DATASET_SIZE
};
