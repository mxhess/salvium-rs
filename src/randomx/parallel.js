/**
 * Parallel RandomX Implementation
 *
 * Provides non-blocking dataset generation with progress reporting.
 * For true multi-core parallelism, native code (WASM/addon) is required.
 *
 * This implementation keeps the event loop responsive by yielding
 * between chunks, allowing UI updates and progress reporting.
 */

import { cpus } from 'os';
import { RandomXCache, initDatasetItem } from './dataset.js';
import { RANDOMX_DATASET_ITEM_COUNT } from './config.js';

// Dataset item size in bytes
export const DATASET_ITEM_SIZE = 64;

// Total dataset size (~2GB)
export const DATASET_SIZE = RANDOMX_DATASET_ITEM_COUNT * DATASET_ITEM_SIZE;

/**
 * Get the number of available CPU cores
 */
export function getCpuCount() {
  try {
    return cpus().length;
  } catch {
    if (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) {
      return navigator.hardwareConcurrency;
    }
    return 4;
  }
}

/**
 * Async Dataset Generator
 *
 * Generates dataset items asynchronously with progress reporting.
 * Uses chunked processing to keep event loop responsive.
 */
export class ParallelDataset {
  constructor(options = {}) {
    this.chunkSize = options.chunkSize || 1000;  // Items per chunk
    this.cache = null;
    this.dataset = null;
    this.isInitialized = false;
    this.onProgress = null;
  }

  /**
   * Initialize with cache key
   *
   * @param {Uint8Array} key - Cache key
   * @param {function} onProgress - Progress callback (stage, percent, details)
   */
  async init(key, onProgress = null) {
    this.onProgress = onProgress || this.defaultProgress.bind(this);

    // Stage 1: Initialize cache (sequential, but with progress)
    this.onProgress('cache', 0, { message: 'Initializing 256MB cache...' });

    this.cache = new RandomXCache();
    this.cache.init(key, (percent, pass, slice) => {
      this.onProgress('cache', percent, { pass, slice });
    });

    this.onProgress('cache', 100, { message: 'Cache ready' });

    // Stage 2: Generate dataset with async chunking
    this.onProgress('dataset', 0, { message: 'Allocating 2GB dataset...' });

    await this.generateDataset();

    this.isInitialized = true;
    this.onProgress('complete', 100, { message: 'Dataset ready' });
  }

  /**
   * Generate dataset with async chunking for responsiveness
   */
  async generateDataset() {
    const totalItems = RANDOMX_DATASET_ITEM_COUNT;

    // Allocate dataset buffer (~2GB)
    try {
      this.dataset = new Uint8Array(DATASET_SIZE);
    } catch (e) {
      throw new Error(`Failed to allocate ${DATASET_SIZE} bytes for dataset: ${e.message}`);
    }

    const startTime = Date.now();
    let completedItems = 0;

    // Process in chunks, yielding between each chunk
    for (let start = 0; start < totalItems; start += this.chunkSize) {
      const end = Math.min(start + this.chunkSize, totalItems);

      // Compute chunk synchronously
      for (let i = start; i < end; i++) {
        const item = initDatasetItem(this.cache, i);
        this.dataset.set(item, i * DATASET_ITEM_SIZE);
        completedItems++;
      }

      // Update progress
      const percent = Math.round((completedItems / totalItems) * 100);
      const elapsed = (Date.now() - startTime) / 1000;
      const itemsPerSec = completedItems / elapsed;
      const eta = (totalItems - completedItems) / itemsPerSec;

      this.onProgress('dataset', percent, {
        completedItems,
        totalItems,
        itemsPerSec: Math.round(itemsPerSec),
        eta: Math.round(eta)
      });

      // Yield to event loop
      await new Promise(resolve => setImmediate(resolve));
    }
  }

  /**
   * Default progress handler
   */
  defaultProgress(stage, percent, details) {
    if (typeof process !== 'undefined' && process.stdout) {
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
      } else if (stage === 'complete') {
        process.stdout.write('\r' + ' '.repeat(80) + '\r');
        console.log('RandomX dataset initialized (2GB)');
      }
    }
  }

  /**
   * Get dataset item (fast lookup)
   */
  getItem(index) {
    if (!this.isInitialized) {
      throw new Error('Dataset not initialized');
    }
    const offset = index * DATASET_ITEM_SIZE;
    return this.dataset.subarray(offset, offset + DATASET_ITEM_SIZE);
  }

  /**
   * Destroy and free memory
   */
  destroy() {
    this.dataset = null;
    this.cache = null;
    this.isInitialized = false;
  }
}

/**
 * Lightweight cache-only mode (no full dataset)
 *
 * Uses cache + on-demand dataset item computation.
 * Much lower memory usage (256MB vs 2GB) but slower per-hash.
 */
export class LightDataset {
  constructor() {
    this.cache = null;
    this.isInitialized = false;
  }

  /**
   * Initialize with cache key
   */
  async init(key, onProgress = null) {
    const progress = onProgress || this.defaultProgress.bind(this);

    progress('cache', 0, { message: 'Initializing 256MB cache...' });

    this.cache = new RandomXCache();
    this.cache.init(key, (percent, pass, slice) => {
      progress('cache', percent, { pass, slice });
    });

    this.isInitialized = true;
    progress('complete', 100, { message: 'Light mode ready (256MB)' });
  }

  /**
   * Get dataset item (computed on demand)
   */
  getItem(index) {
    if (!this.isInitialized) {
      throw new Error('Cache not initialized');
    }
    return initDatasetItem(this.cache, index);
  }

  /**
   * Default progress handler
   */
  defaultProgress(stage, percent, details) {
    if (typeof process !== 'undefined' && process.stdout) {
      const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));

      if (stage === 'cache') {
        const info = details.pass !== undefined
          ? `pass ${details.pass + 1}/3, slice ${details.slice + 1}/4`
          : details.message || '';
        process.stdout.write(`\rCache: [${bar}] ${percent}% ${info}`.padEnd(80));
      } else if (stage === 'complete') {
        process.stdout.write('\r' + ' '.repeat(80) + '\r');
        console.log(details.message);
      }
    }
  }

  destroy() {
    this.cache = null;
    this.isInitialized = false;
  }
}

// WorkerDataset is an alias for ParallelDataset until we implement true workers
export const WorkerDataset = ParallelDataset;

export default {
  ParallelDataset,
  LightDataset,
  WorkerDataset,
  getCpuCount,
  DATASET_SIZE,
  DATASET_ITEM_SIZE
};
