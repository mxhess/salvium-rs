/**
 * RandomX Worker Pool for Multi-threaded Hashing
 *
 * Uses Web Workers to parallelize RandomX hashing across multiple CPU cores.
 * Each worker maintains its own cache copy (256MB each).
 *
 * Memory usage: 256MB × number of workers
 */

// Worker code as a blob URL (self-contained)
const WORKER_CODE = `
import { randomx_init_cache, randomx_create_vm } from './vendor/index.js';

let vm = null;
let cacheKey = null;

self.onmessage = async (e) => {
  const { type, id, key, input } = e.data;

  if (type === 'init') {
    try {
      const cache = randomx_init_cache(key);
      vm = randomx_create_vm(cache);
      cacheKey = key;
      self.postMessage({ type: 'ready', id });
    } catch (err) {
      self.postMessage({ type: 'error', id, error: err.message });
    }
  } else if (type === 'hash') {
    if (!vm) {
      self.postMessage({ type: 'error', id, error: 'Worker not initialized' });
      return;
    }
    try {
      const hash = vm.calculate_hash(input);
      self.postMessage({ type: 'result', id, hash });
    } catch (err) {
      self.postMessage({ type: 'error', id, error: err.message });
    }
  } else if (type === 'hashHex') {
    if (!vm) {
      self.postMessage({ type: 'error', id, error: 'Worker not initialized' });
      return;
    }
    try {
      const hash = vm.calculate_hex_hash(input);
      self.postMessage({ type: 'result', id, hash });
    } catch (err) {
      self.postMessage({ type: 'error', id, error: err.message });
    }
  }
};
`;

/**
 * Get available CPU cores
 * @returns {number}
 */
export function getAvailableCores() {
  if (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) {
    return navigator.hardwareConcurrency;
  }
  // Node.js
  try {
    const os = require('os');
    return os.cpus().length;
  } catch (_e) {
    return 4; // Default fallback
  }
}

/**
 * RandomX Worker Pool
 *
 * Manages multiple workers for parallel hashing.
 *
 * @example
 * const pool = new RandomXWorkerPool(4);
 * await pool.init('block hash key');
 * const hashes = await pool.hashBatch(['input1', 'input2', 'input3', 'input4']);
 */
export class RandomXWorkerPool {
  /**
   * Create a worker pool
   * @param {number} numWorkers - Number of workers (default: CPU cores)
   */
  constructor(numWorkers = getAvailableCores()) {
    this.numWorkers = numWorkers;
    this.workers = [];
    this.ready = false;
    this.cacheKey = null;
    this.pendingTasks = new Map();
    this.taskId = 0;
    this.availableWorkers = [];
  }

  /**
   * Initialize all workers with a cache key
   * @param {string|Uint8Array} key - Cache initialization key
   * @param {function} onProgress - Progress callback (workerIndex, total)
   * @returns {Promise<void>}
   */
  async init(key, onProgress = null) {
    const keyBytes = typeof key === 'string'
      ? new TextEncoder().encode(key)
      : key;

    // Check if using Node.js worker_threads or browser Web Workers
    const isNode = typeof window === 'undefined';

    const initPromises = [];

    for (let i = 0; i < this.numWorkers; i++) {
      const promise = this._createWorker(i, keyBytes, isNode);
      initPromises.push(promise);

      // Report progress
      promise.then(() => {
        if (onProgress) onProgress(i + 1, this.numWorkers);
      });
    }

    await Promise.all(initPromises);
    this.cacheKey = typeof key === 'string' ? key : Array.from(keyBytes).join(',');
    this.ready = true;
    this.availableWorkers = [...Array(this.numWorkers).keys()];

    console.log(`RandomX Worker Pool initialized (${this.numWorkers} workers, ${this.numWorkers * 256}MB total)`);
  }

  async _createWorker(index, key, isNode) {
    return new Promise((resolve, reject) => {
      let worker;

      if (isNode) {
        // Node.js worker_threads
        const { Worker } = require('worker_threads');
        const workerPath = new URL('./randomx-worker.js', import.meta.url).pathname;
        worker = new Worker(workerPath);
      } else {
        // Browser Web Worker
        const blob = new Blob([WORKER_CODE], { type: 'application/javascript' });
        worker = new Worker(URL.createObjectURL(blob), { type: 'module' });
      }

      const taskId = this.taskId++;

      const handler = (e) => {
        const data = isNode ? e : e.data;
        if (data.id === taskId) {
          if (data.type === 'ready') {
            resolve();
          } else if (data.type === 'error') {
            reject(new Error(data.error));
          }
        }
      };

      if (isNode) {
        worker.on('message', handler);
        worker.on('error', reject);
      } else {
        worker.onmessage = handler;
        worker.onerror = reject;
      }

      worker.postMessage({ type: 'init', id: taskId, key });
      this.workers[index] = worker;
    });
  }

  /**
   * Hash a single input using an available worker
   * @param {string|Uint8Array} input - Data to hash
   * @returns {Promise<Uint8Array>}
   */
  async hash(input) {
    if (!this.ready) {
      throw new Error('Worker pool not initialized. Call init() first.');
    }

    return this._submitTask('hash', input);
  }

  /**
   * Hash a single input and return hex string
   * @param {string|Uint8Array} input - Data to hash
   * @returns {Promise<string>}
   */
  async hashHex(input) {
    if (!this.ready) {
      throw new Error('Worker pool not initialized. Call init() first.');
    }

    return this._submitTask('hashHex', input);
  }

  /**
   * Hash multiple inputs in parallel
   * @param {Array<string|Uint8Array>} inputs - Array of inputs to hash
   * @returns {Promise<Array<Uint8Array>>}
   */
  async hashBatch(inputs) {
    return Promise.all(inputs.map(input => this.hash(input)));
  }

  /**
   * Hash multiple inputs and return hex strings
   * @param {Array<string|Uint8Array>} inputs - Array of inputs to hash
   * @returns {Promise<Array<string>>}
   */
  async hashBatchHex(inputs) {
    return Promise.all(inputs.map(input => this.hashHex(input)));
  }

  async _submitTask(type, input) {
    return new Promise((resolve, reject) => {
      const taskId = this.taskId++;
      const workerIndex = this.availableWorkers.shift() ?? (taskId % this.numWorkers);
      const worker = this.workers[workerIndex];
      const isNode = typeof window === 'undefined';

      const handler = (e) => {
        const data = isNode ? e : e.data;
        if (data.id === taskId) {
          this.availableWorkers.push(workerIndex);
          if (data.type === 'result') {
            resolve(data.hash);
          } else if (data.type === 'error') {
            reject(new Error(data.error));
          }
        }
      };

      if (isNode) {
        worker.once('message', handler);
      } else {
        const originalHandler = worker.onmessage;
        worker.onmessage = (e) => {
          handler(e);
          worker.onmessage = originalHandler;
        };
      }

      worker.postMessage({ type, id: taskId, input });
    });
  }

  /**
   * Terminate all workers
   */
  terminate() {
    for (const worker of this.workers) {
      if (worker) {
        worker.terminate();
      }
    }
    this.workers = [];
    this.ready = false;
    this.availableWorkers = [];
  }

  /**
   * Get number of workers
   * @returns {number}
   */
  get size() {
    return this.numWorkers;
  }
}

export default RandomXWorkerPool;
