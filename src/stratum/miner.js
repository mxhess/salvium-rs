/**
 * Stratum Miner with Worker Threads
 *
 * Complete mining solution combining:
 * - Stratum protocol client for pool communication
 * - Multi-threaded RandomX hashing via Worker threads
 * - Job management and share submission
 * - Real-time statistics
 */

import { EventEmitter } from 'events';
import { Worker } from 'worker_threads';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import os from 'os';
import { StratumClient } from './client.js';
import { randomx_init_cache, randomx_superscalarhash } from '../randomx/vendor/index.js';
import { RANDOMX_DATASET_ITEM_COUNT } from '../randomx/full-mode.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WORKER_PATH_LIGHT = join(__dirname, 'mining-worker.js');
const WORKER_PATH_ASM = join(__dirname, 'mining-worker-asm.js');

/**
 * Get available CPU cores
 */
export function getAvailableCores() {
  return os.cpus().length;
}

/**
 * Stratum miner with multi-threaded RandomX
 *
 * @fires StratumMiner#started - Mining started
 * @fires StratumMiner#stopped - Mining stopped
 * @fires StratumMiner#job - New job received
 * @fires StratumMiner#share - Share found
 * @fires StratumMiner#accepted - Share accepted by pool
 * @fires StratumMiner#rejected - Share rejected by pool
 * @fires StratumMiner#hashrate - Hashrate update
 * @fires StratumMiner#error - Error occurred
 */
export class StratumMiner extends EventEmitter {
  /**
   * Create a stratum miner
   *
   * @param {Object} options - Configuration
   * @param {string} options.pool - Pool URL
   * @param {string} options.wallet - Wallet address
   * @param {string} options.worker - Worker name
   * @param {string} options.password - Pool password
   * @param {number} options.threads - Number of mining threads (default: CPU cores - 1)
   * @param {string} options.mode - Mining mode: 'light' or 'full' (default: 'light')
   */
  constructor(options = {}) {
    super();

    this.options = {
      pool: options.pool,
      wallet: options.wallet,
      worker: options.worker || 'salvium-js',
      password: options.password || 'x',
      threads: options.threads || Math.max(1, getAvailableCores() - 1),
      rigId: options.rigId || null,
      mode: options.mode || 'light'
    };

    // Full mode dataset (SharedArrayBuffer)
    this.dataset = null;
    this.datasetSeedHash = null;
    this.datasetGenerating = false;  // Lock to prevent concurrent generation
    this.datasetPromise = null;      // Promise for waiting on generation

    // Stratum client
    this.client = new StratumClient({
      pool: this.options.pool,
      wallet: this.options.wallet,
      worker: this.options.worker,
      password: this.options.password,
      rigId: this.options.rigId
    });

    // Mining state
    this.mining = false;
    this.paused = false;
    this.currentJob = null;
    this.currentSeedHash = null;
    this.workers = [];
    this.workersReady = 0;

    // Statistics
    this.stats = {
      hashrate: 0,
      totalHashes: 0,
      sharesFound: 0,
      sharesAccepted: 0,
      sharesRejected: 0,
      startTime: null,
      lastHashrateUpdate: null,
      hashCounts: new Map()
    };

    // Intervals
    this.hashrateInterval = null;

    // Set up stratum event handlers
    this._setupStratumHandlers();
  }

  /**
   * Start mining
   *
   * @returns {Promise<void>}
   */
  async start() {
    if (this.mining) {
      console.log('Already mining');
      return;
    }

    try {
      if (this.options.mode === 'full') {
        // Full mode: Connect first to get seed hash, then generate dataset, then start workers
        console.log('Full mode: Connecting to pool to get seed hash...');

        // Set up one-time handler for first job to get seed hash
        const firstJobPromise = new Promise((resolve) => {
          const handler = (job) => {
            this.client.off('job', handler);
            resolve(job);
          };
          this.client.on('job', handler);
        });

        await this.client.connect();

        // Wait for first job to get seed hash
        console.log('Waiting for job with seed hash...');
        const firstJob = await firstJobPromise;
        console.log(`Got seed hash: ${firstJob.seed_hash.substring(0, 16)}...`);

        // Generate dataset (mute stratum client during generation)
        this.client.mute();
        await this._generateDataset(firstJob.seed_hash);
        this.client.unmute();

        // Now start workers with dataset ready
        console.log(`Starting ${this.options.threads} worker threads...`);
        await this._startWorkers();

        // Store the first job so we can start mining it
        this.currentJob = firstJob;
        this.emit('job', firstJob);

      } else {
        // Light mode: Start workers first, then connect
        console.log(`Starting miner with ${this.options.threads} worker threads`);
        await this._startWorkers();
        await this.client.connect();
      }

      this.mining = true;
      this.stats.startTime = Date.now();
      this.stats.lastHashrateUpdate = Date.now();

      // Start hashrate calculation
      this.hashrateInterval = setInterval(() => this._updateHashrate(), 5000);

      this.emit('started', {
        pool: this.options.pool,
        threads: this.options.threads,
        mode: this.options.mode
      });

      // For full mode, start mining the first job now
      if (this.options.mode === 'full' && this.currentJob) {
        this._startJob(this.currentJob);
      }

    } catch (err) {
      console.error('Failed to start mining:', err);
      this.emit('error', err);
      throw err;
    }
  }

  /**
   * Stop mining
   */
  async stop() {
    if (!this.mining) return;

    console.log('Stopping miner...');

    this.mining = false;

    await this._stopWorkers();

    // Stop hashrate calculation
    if (this.hashrateInterval) {
      clearInterval(this.hashrateInterval);
      this.hashrateInterval = null;
    }

    // Disconnect from pool
    this.client.disconnect();

    this.emit('stopped', this.getStats());
  }

  /**
   * Pause mining (keeps connection, stops hashing)
   */
  pause() {
    if (this.paused) return;
    this.paused = true;
    this._pauseWorkers();
    console.log('Mining paused');
  }

  /**
   * Resume mining
   */
  resume() {
    if (!this.paused) return;
    this.paused = false;

    if (this.currentJob) {
      this._startJob(this.currentJob);
    }
    console.log('Mining resumed');
  }

  /**
   * Get mining statistics
   *
   * @returns {Object}
   */
  getStats() {
    const uptime = this.stats.startTime
      ? Date.now() - this.stats.startTime
      : 0;

    return {
      mining: this.mining,
      paused: this.paused,
      hashrate: this.stats.hashrate,
      totalHashes: this.stats.totalHashes,
      sharesFound: this.stats.sharesFound,
      sharesAccepted: this.stats.sharesAccepted,
      sharesRejected: this.stats.sharesRejected,
      uptime,
      threads: this.options.threads,
      workersReady: this.workersReady,
      pool: this.client.getStats()
    };
  }

  /**
   * Get formatted hashrate string
   */
  getHashrateString() {
    const h = this.stats.hashrate;
    if (h >= 1000000) return `${(h / 1000000).toFixed(2)} MH/s`;
    if (h >= 1000) return `${(h / 1000).toFixed(2)} KH/s`;
    return `${h.toFixed(2)} H/s`;
  }

  // === Private methods ===

  /**
   * Generate full mode dataset
   */
  async _generateDataset(seedHash) {
    if (this.options.mode !== 'full') return;
    if (this.datasetSeedHash === seedHash && this.dataset) return;

    // If already generating for this seed, wait for it to complete
    if (this.datasetGenerating) {
      if (this.datasetPromise) {
        await this.datasetPromise;
      }
      return;
    }

    // Set lock and create promise
    this.datasetGenerating = true;

    // Store the generation promise so others can wait
    this.datasetPromise = this._doGenerateDataset(seedHash);

    try {
      await this.datasetPromise;
    } finally {
      this.datasetGenerating = false;
      this.datasetPromise = null;
    }
  }

  /**
   * Actual dataset generation logic
   */
  async _doGenerateDataset(seedHash) {
    console.log('Generating 2GB dataset for full mode...');
    const startTime = Date.now();

    // Initialize cache with seed
    const seedBytes = Buffer.from(seedHash, 'hex');
    const cache = randomx_init_cache(seedBytes);
    const ssHash = randomx_superscalarhash(cache);

    // Allocate shared buffer for dataset
    // 8 BigInt64 values per item = 64 bytes per item
    const datasetSize = RANDOMX_DATASET_ITEM_COUNT * 8 * 8;  // bytes
    const sharedBuffer = new SharedArrayBuffer(datasetSize);
    const datasetView = new BigInt64Array(sharedBuffer);

    // Generate dataset items
    let lastProgress = 0;
    for (let i = 0; i < RANDOMX_DATASET_ITEM_COUNT; i++) {
      const item = ssHash(BigInt(i));
      const offset = i * 8;
      for (let j = 0; j < 8; j++) {
        datasetView[offset + j] = item[j];
      }

      // Progress reporting
      const progress = Math.floor((i / RANDOMX_DATASET_ITEM_COUNT) * 100);
      if (progress > lastProgress && progress % 5 === 0) {
        lastProgress = progress;
        process.stdout.write(`\rDataset generation: ${progress}%`);
        this.emit('datasetProgress', { percent: progress });
      }

      // Yield to event loop
      if (i % 50000 === 0) {
        await new Promise(resolve => setImmediate(resolve));
      }
    }

    const elapsed = (Date.now() - startTime) / 1000;
    console.log(`\nDataset generated in ${elapsed.toFixed(1)}s`);

    this.dataset = sharedBuffer;
    this.datasetSeedHash = seedHash;

    this.emit('datasetReady', {
      seedHash,
      size: datasetSize,
      timeSeconds: elapsed
    });
  }

  _setupStratumHandlers() {
    this.client.on('job', (job) => {
      // In full mode, ignore jobs until dataset is ready
      if (this.options.mode === 'full' && !this.dataset) {
        return;
      }
      this._handleNewJob(job);
    });

    this.client.on('accepted', (share) => {
      this.stats.sharesAccepted++;
      this.emit('accepted', share);
    });

    this.client.on('rejected', (share) => {
      this.stats.sharesRejected++;
      this.emit('rejected', share);
    });

    this.client.on('error', (err) => {
      this.emit('error', err);
    });

    this.client.on('disconnected', () => {
      this._pauseWorkers();
    });
  }

  async _startWorkers() {
    this.workersReady = 0;

    const workerPromises = [];

    for (let i = 0; i < this.options.threads; i++) {
      const promise = this._createWorker(i);
      workerPromises.push(promise);
    }

    await Promise.all(workerPromises);
    console.log(`All ${this.options.threads} workers ready`);
  }

  _createWorker(workerId) {
    return new Promise((resolve, reject) => {
      // Full mode uses the AssemblyScript WASM VM for best performance
      const workerPath = this.options.mode === 'full'
        ? WORKER_PATH_ASM
        : WORKER_PATH_LIGHT;
      const worker = new Worker(workerPath, {
        workerData: { workerId, mode: this.options.mode }
      });

      worker.on('message', (msg) => {
        this._handleWorkerMessage(workerId, msg);

        if (msg.type === 'ready') {
          this.workersReady++;
          resolve();
        }
      });

      worker.on('error', (err) => {
        console.error(`Worker ${workerId} error:`, err);
        this.emit('error', err);
      });

      worker.on('exit', (code) => {
        if (code !== 0) {
          console.error(`Worker ${workerId} exited with code ${code}`);
        }
      });

      this.workers[workerId] = worker;
    });
  }

  _handleWorkerMessage(workerId, msg) {
    switch (msg.type) {
      case 'initialized':
        console.log(`Worker ${workerId} initialized with seed ${msg.seedHash?.substring(0, 16)}...`);
        break;

      case 'share':
        this.stats.sharesFound++;
        this.emit('share', { nonce: msg.nonce, result: msg.result });

        // Submit to pool
        this.client.submitShare(msg.nonce, msg.result)
          .catch(err => console.error('Share submission error:', err));
        break;

      case 'hashCount':
        // Accumulate hashes from all workers
        const current = this.stats.hashCounts.get('total') || 0;
        this.stats.hashCounts.set('total', current + msg.count);
        break;

      case 'stopped':
        this.stats.totalHashes += msg.hashCount;
        break;
    }
  }

  async _stopWorkers() {
    const stopPromises = this.workers.map((worker, id) => {
      return new Promise((resolve) => {
        if (!worker) {
          resolve();
          return;
        }

        const onMessage = (msg) => {
          if (msg.type === 'stopped') {
            worker.off('message', onMessage);
            resolve();
          }
        };

        worker.on('message', onMessage);
        worker.postMessage({ type: 'stop' });

        // Timeout fallback
        setTimeout(resolve, 2000);
      });
    });

    await Promise.all(stopPromises);

    // Terminate workers
    for (const worker of this.workers) {
      if (worker) {
        worker.terminate();
      }
    }

    this.workers = [];
    this.workersReady = 0;
  }

  _pauseWorkers() {
    for (const worker of this.workers) {
      if (worker) {
        worker.postMessage({ type: 'stop' });
      }
    }
  }

  async _handleNewJob(job) {
    // Don't log during dataset generation
    if (!this.datasetGenerating) {
      console.log(`New job: height=${job.height}, target=${job.target}`);
    }

    this.currentJob = job;

    // Don't emit job events during dataset generation
    if (!this.datasetGenerating) {
      this.emit('job', job);
    }

    if (!this.mining || this.paused) return;

    // For full mode, wait for dataset to be ready
    if (this.options.mode === 'full') {
      // Wait for any ongoing dataset generation
      if (this.datasetGenerating && this.datasetPromise) {
        await this.datasetPromise;
      }

      // Generate dataset if seed changed
      if (job.seed_hash !== this.datasetSeedHash) {
        await this._generateDataset(job.seed_hash);
      }

      // Safety check - don't start if dataset still generating
      if (this.datasetGenerating) {
        return;
      }
    }

    this._startJob(job);
  }

  _startJob(job) {
    const nonceSpace = 0xFFFFFFFF;
    const noncePerWorker = Math.floor(nonceSpace / this.options.threads);

    for (let i = 0; i < this.workers.length; i++) {
      const worker = this.workers[i];
      if (!worker) continue;

      const startNonce = i * noncePerWorker;

      const msg = {
        type: 'job',
        job: job,
        seedHash: job.seed_hash,
        startNonce
      };

      // For full mode, include the shared dataset buffer
      if (this.options.mode === 'full' && this.dataset) {
        msg.dataset = this.dataset;
      }

      worker.postMessage(msg);
    }
  }

  _updateHashrate() {
    // Workers proactively report their hash counts every 5 seconds
    const totalHashes = this.stats.hashCounts.get('total') || 0;

    const now = Date.now();
    const elapsed = (now - this.stats.lastHashrateUpdate) / 1000;

    if (elapsed > 0) {
      if (totalHashes > 0) {
        this.stats.hashrate = totalHashes / elapsed;
        this.stats.totalHashes += totalHashes;
        this.stats.hashCounts.set('total', 0);  // Reset accumulator
      }
      this.stats.lastHashrateUpdate = now;

      // Always emit so UI updates
      this.emit('hashrate', {
        hashrate: this.stats.hashrate,
        formatted: this.getHashrateString(),
        totalHashes: this.stats.totalHashes
      });
    }
  }
}

/**
 * Create and start a miner
 *
 * @param {Object} options - Miner options
 * @returns {Promise<StratumMiner>}
 */
export async function createMiner(options) {
  const miner = new StratumMiner(options);
  await miner.start();
  return miner;
}

export default { StratumMiner, createMiner, getAvailableCores };
