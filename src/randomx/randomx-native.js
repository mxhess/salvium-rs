/**
 * RandomX Native Implementation
 *
 * Wrapper around the vendored randomx.js (BSD 3-Clause licensed)
 * Provides the correct, fast WASM-JIT implementation of RandomX.
 *
 * See src/randomx/vendor/LICENSE for third-party license.
 */

import {
  randomx_init_cache,
  randomx_create_vm,
  randomx_machine_id,
  randomx_superscalarhash
} from './vendor/index.js';

/**
 * Native RandomX context using WASM-JIT
 *
 * This is the recommended implementation for production use.
 * Fast WASM-JIT with correct hash output.
 */
export class RandomXNative {
  constructor() {
    this.cache = null;
    this.vm = null;
    this.cacheKey = null;
  }

  /**
   * Initialize with a key (typically previous block hash)
   *
   * @param {Uint8Array|string} key - Cache initialization key
   * @param {function} onProgress - Optional progress callback (percent)
   * @returns {Promise<void>}
   */
  async init(key, onProgress = null) {
    // Convert string to bytes if needed
    const keyBytes = typeof key === 'string'
      ? new TextEncoder().encode(key)
      : key;

    // Store key for comparison
    const keyStr = typeof key === 'string' ? key : Array.from(keyBytes).join(',');
    if (this.cacheKey === keyStr) {
      return; // Already initialized with this key
    }

    // Initialize cache (this takes ~600ms)
    if (onProgress) onProgress(0);
    this.cache = randomx_init_cache(keyBytes);
    if (onProgress) onProgress(100);

    // Create VM
    this.vm = randomx_create_vm(this.cache);
    this.cacheKey = keyStr;
  }

  /**
   * Calculate RandomX hash
   *
   * @param {Uint8Array|string} input - Data to hash
   * @returns {Uint8Array} - 32-byte hash
   */
  hash(input) {
    if (!this.vm) {
      throw new Error('RandomX not initialized. Call init() first.');
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
      throw new Error('RandomX not initialized. Call init() first.');
    }
    return this.vm.calculate_hex_hash(input);
  }

  /**
   * Get machine ID string
   * @returns {string}
   */
  static getMachineId() {
    return randomx_machine_id();
  }

  /**
   * Get superscalar hash function for dataset generation
   * @returns {function}
   */
  getSuperscalarHash() {
    if (!this.cache) {
      throw new Error('RandomX not initialized. Call init() first.');
    }
    return randomx_superscalarhash(this.cache);
  }
}

// Re-export raw functions for advanced use
export {
  randomx_init_cache,
  randomx_create_vm,
  randomx_machine_id,
  randomx_superscalarhash
};
