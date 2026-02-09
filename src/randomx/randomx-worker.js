/**
 * RandomX Worker Thread (WASM-JIT)
 *
 * Each worker maintains its own RandomX VM instance (256MB cache).
 * Uses async chunked mining with generation-based cancellation.
 *
 * Performance optimizations:
 * - Precomputed target for byte-level difficulty comparison (no BigInt per hash)
 * - Large chunk size to minimize yield overhead
 * - Periodic progress reporting
 */

import { parentPort } from 'worker_threads';
import { randomx_init_cache, randomx_create_vm } from './vendor/index.js';

let vm = null;
let cacheKey = null;
let currentMineGeneration = 0;

parentPort.on('message', async (msg) => {
  const { type, id, key, input } = msg;

  if (type === 'init') {
    try {
      const cache = randomx_init_cache(key);
      vm = randomx_create_vm(cache);
      cacheKey = key;
      parentPort.postMessage({ type: 'ready', id });
    } catch (err) {
      parentPort.postMessage({ type: 'error', id, error: err.message });
    }
  } else if (type === 'hash') {
    if (!vm) {
      parentPort.postMessage({ type: 'error', id, error: 'Worker not initialized' });
      return;
    }
    try {
      const hash = vm.calculate_hash(input);
      parentPort.postMessage({ type: 'result', id, hash });
    } catch (err) {
      parentPort.postMessage({ type: 'error', id, error: err.message });
    }
  } else if (type === 'hashHex') {
    if (!vm) {
      parentPort.postMessage({ type: 'error', id, error: 'Worker not initialized' });
      return;
    }
    try {
      const hash = vm.calculate_hex_hash(input);
      parentPort.postMessage({ type: 'result', id, hash });
    } catch (err) {
      parentPort.postMessage({ type: 'error', id, error: err.message });
    }
  } else if (type === 'mine') {
    if (!vm) {
      parentPort.postMessage({ type: 'error', id, error: 'Worker not initialized' });
      return;
    }
    const generation = ++currentMineGeneration;
    mineChunked(input, id, msg.jobId, generation);
  } else if (type === 'cancel') {
    currentMineGeneration++;
  }
});

/**
 * Precompute target as 32-byte big-endian array for fast comparison.
 * target = floor((2^256 - 1) / difficulty)
 */
function computeTarget(difficulty) {
  const diffBig = BigInt(difficulty);
  const max256 = (1n << 256n) - 1n;
  const targetBig = max256 / diffBig;

  const target = new Uint8Array(32);
  let val = targetBig;
  for (let i = 31; i >= 0; i--) {
    target[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return target;
}

/**
 * Fast difficulty check: compare hash (little-endian) against target (big-endian).
 * Compares MSB first — exits after 1-2 bytes for ~99.6% of failing hashes.
 */
function checkHash(hash, target) {
  for (let i = 0; i < 32; i++) {
    const hashByte = hash[31 - i]; // LE → MSB first
    const targetByte = target[i];   // BE → MSB first
    if (hashByte < targetByte) return true;
    if (hashByte > targetByte) return false;
  }
  return true; // equal
}

/**
 * Mine nonces in async chunks, yielding to the event loop periodically
 * so new messages (mine, cancel) can be processed.
 */
async function mineChunked(input, id, jobId, generation) {
  try {
    const { template, nonceOffset, difficulty, startNonce, endNonce } = input;
    const templateBuf = new Uint8Array(template);
    const view = new DataView(templateBuf.buffer);

    // Precompute target once (no BigInt per hash)
    const target = computeTarget(difficulty);

    // Yield every 500 hashes (~70s at 7 H/s light mode).
    // Cancellation response time is bounded by chunk duration.
    const CHUNK_SIZE = 500;
    const PROGRESS_INTERVAL = 100; // Report progress every 100 hashes
    let hashCount = 0;

    for (let nonce = startNonce; nonce < endNonce; nonce++) {
      if (currentMineGeneration !== generation) return;

      view.setUint32(nonceOffset, nonce, true);
      const hash = vm.calculate_hash(templateBuf);
      hashCount++;

      if (checkHash(hash, target)) {
        if (currentMineGeneration !== generation) return;
        parentPort.postMessage({ type: 'found', id, jobId, nonce, hash, hashCount });
        return;
      }

      // Report progress periodically
      if (hashCount % PROGRESS_INTERVAL === 0) {
        parentPort.postMessage({ type: 'progress', id, jobId, hashCount });
      }

      // Yield to event loop periodically for cancel/new-mine messages
      if (hashCount % CHUNK_SIZE === 0) {
        await new Promise(r => setImmediate(r));
        if (currentMineGeneration !== generation) return;
      }
    }

    if (currentMineGeneration === generation) {
      parentPort.postMessage({ type: 'notfound', id, jobId, hashCount });
    }
  } catch (err) {
    if (currentMineGeneration === generation) {
      parentPort.postMessage({ type: 'error', id, jobId, error: err.message });
    }
  }
}
