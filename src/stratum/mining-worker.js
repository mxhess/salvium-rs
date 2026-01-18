/**
 * Mining Worker Thread
 *
 * Runs in a separate thread for true parallel hashing.
 * Each worker has its own RandomX context (256MB cache).
 */

import { parentPort, workerData } from 'worker_threads';
import { randomx_init_cache, randomx_create_vm } from '../randomx/vendor/index.js';

// Worker state
let vm = null;
let seedHash = null;
let currentJob = null;
let mining = false;
let nonce = 0;
let hashCount = 0;
let jobGeneration = 0;  // Increments on each new job to stop old mining loops

/**
 * Initialize RandomX with seed hash
 */
async function initRandomX(seed) {
  const seedBytes = hexToBytes(seed);
  const cache = randomx_init_cache(seedBytes);
  vm = randomx_create_vm(cache);
  seedHash = seed;
  parentPort.postMessage({ type: 'initialized', seedHash });
}

/**
 * Start mining a job
 */
function startMining(job, startNonce) {
  // Increment generation to stop any existing mining loop
  const myGeneration = ++jobGeneration;

  currentJob = job;
  nonce = startNonce;
  mining = true;
  // Don't reset hashCount here - let it accumulate across jobs
  // It gets reset only when reported via getHashCount

  // Parse job data
  const blob = hexToBytes(job.blob);
  const target = targetToBytes(job.target);
  const nonceOffset = 39; // Standard nonce position

  // Create template once, reuse for each hash
  const template = new Uint8Array(blob);
  const view = new DataView(template.buffer);

  // Mining loop - optimized batch processing
  const mine = () => {
    // Stop if not mining or if a newer job has started
    if (!mining || myGeneration !== jobGeneration) return;

    // Batch size - each hash takes ~10-20ms in light mode
    const batchSize = 10;

    for (let i = 0; i < batchSize && mining && myGeneration === jobGeneration; i++) {
      // Set nonce in template (reuse buffer)
      view.setUint32(nonceOffset, nonce, true);

      // Hash
      const hash = vm.calculate_hash(template);
      hashCount++;
      nonce++;

      // Check target
      if (checkTarget(hash, target)) {
        const nonceHex = (nonce - 1).toString(16).padStart(8, '0');
        const resultHex = bytesToHex(hash);

        parentPort.postMessage({
          type: 'share',
          nonce: nonceHex,
          result: resultHex,
          jobId: job.job_id
        });
      }
    }

    // Continue mining only if this is still the current job
    // Use small delay to yield to event loop (allows setInterval to run)
    if (mining && myGeneration === jobGeneration) {
      setTimeout(mine, 1);
    }
  };

  mine();
}

/**
 * Stop mining
 */
function stopMining() {
  mining = false;
}

/**
 * Check if hash meets target
 */
function checkTarget(hash, target) {
  for (let i = 0; i < 32; i++) {
    if (hash[i] < target[i]) return true;
    if (hash[i] > target[i]) return false;
  }
  return true;
}

/**
 * Convert target hex to 32-byte array
 */
function targetToBytes(targetHex) {
  // Target is usually 8 hex chars, expand to 32 bytes
  const padded = targetHex.padStart(64, '0');
  return hexToBytes(padded);
}

function hexToBytes(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Handle messages from main thread
parentPort.on('message', async (msg) => {
  switch (msg.type) {
    case 'init':
      await initRandomX(msg.seedHash);
      break;

    case 'job':
      if (msg.seedHash !== seedHash) {
        await initRandomX(msg.seedHash);
      }
      startMining(msg.job, msg.startNonce);
      break;

    case 'stop':
      stopMining();
      parentPort.postMessage({ type: 'stopped', hashCount });
      break;

    case 'getHashCount':
      parentPort.postMessage({ type: 'hashCount', count: hashCount });
      hashCount = 0; // Reset after reporting
      break;
  }
});

// Report ready
parentPort.postMessage({ type: 'ready', workerId: workerData?.workerId });

// Proactively report hash counts every 5 seconds
setInterval(() => {
  if (hashCount > 0) {
    parentPort.postMessage({ type: 'hashCount', count: hashCount });
    hashCount = 0;
  }
}, 5000);
