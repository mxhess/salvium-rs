/**
 * Light Mode Mining Worker - JIT Implementation
 *
 * Uses vendor JIT compilation for optimal performance (~7 H/s).
 * Memory: ~256MB for Argon2d cache per worker.
 */

import { parentPort, workerData } from 'worker_threads';
import { randomx_init_cache, randomx_create_vm } from '../randomx/vendor/index.js';

// Worker state
let vm = null;
let cache = null;
let seedHash = null;
let currentJob = null;
let mining = false;
let nonce = 0;
let hashCount = 0;        // For periodic reporting
let totalHashCount = 0;   // Total hashes since job start
let jobGeneration = 0;

/**
 * Initialize RandomX light mode with seed hash
 */
function initRandomX(seed) {
  const seedBytes = hexToBytes(seed);

  // Initialize Argon2d cache (256MB)
  cache = randomx_init_cache(seedBytes);

  // Create VM in light mode (null dataset)
  vm = randomx_create_vm(cache, null);

  seedHash = seed;
  parentPort.postMessage({ type: 'initialized', seedHash });
}

/**
 * Calculate RandomX hash
 */
function calculateHash(input) {
  return vm.calculate_hash(input);
}

// Utility functions
function hexToBytes(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function targetToBytes(targetHex) {
  return hexToBytes(targetHex.padStart(64, '0'));
}

function checkTarget(hash, target) {
  for (let i = 0; i < 32; i++) {
    if (hash[i] < target[i]) return true;
    if (hash[i] > target[i]) return false;
  }
  return true;
}

/**
 * Start mining loop
 */
function startMining(job, startNonce) {
  const myGeneration = ++jobGeneration;
  currentJob = job;
  nonce = startNonce;
  mining = true;
  totalHashCount = 0;  // Reset for new job

  let blob, target;
  try {
    blob = hexToBytes(job.blob);
    target = targetToBytes(job.target);
  } catch (err) {
    parentPort.postMessage({ type: 'error', message: 'Failed to parse job: ' + err.message });
    return;
  }

  const nonceOffset = 39;
  const template = new Uint8Array(blob);
  const view = new DataView(template.buffer);

  const mine = () => {
    if (!mining || myGeneration !== jobGeneration) return;

    try {
      const batchSize = 10;

      for (let i = 0; i < batchSize && mining && myGeneration === jobGeneration; i++) {
        view.setUint32(nonceOffset, nonce, true);
        const hash = calculateHash(template);
        hashCount++;
        totalHashCount++;
        nonce++;

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

      if (mining && myGeneration === jobGeneration) {
        setImmediate(mine);
      }
    } catch (err) {
      parentPort.postMessage({ type: 'error', message: 'Mining error: ' + err.message });
    }
  };

  mine();
}

function stopMining() {
  mining = false;
}

// Message handler
parentPort.on('message', async (msg) => {
  switch (msg.type) {
    case 'init':
      initRandomX(msg.seedHash);
      break;

    case 'job':
      if (msg.seedHash !== seedHash) {
        initRandomX(msg.seedHash);
      }
      if (vm) {
        startMining(msg.job, msg.startNonce);
      } else {
        parentPort.postMessage({ type: 'error', message: 'VM not initialized' });
      }
      break;

    case 'stop':
      stopMining();
      parentPort.postMessage({ type: 'stopped', hashCount: totalHashCount });
      break;

    case 'getHashCount':
      parentPort.postMessage({ type: 'hashCount', count: hashCount });
      hashCount = 0;
      break;
  }
});

// Periodic hash reporting
setInterval(() => {
  if (hashCount > 0) {
    parentPort.postMessage({ type: 'hashCount', count: hashCount });
    hashCount = 0;
  }
}, 5000);

// Ready signal
parentPort.postMessage({
  type: 'ready',
  workerId: workerData?.workerId,
  mode: 'light-jit'
});
