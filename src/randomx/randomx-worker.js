/**
 * RandomX Worker Thread
 *
 * This file runs in a separate thread/worker.
 * Each worker maintains its own RandomX VM instance.
 */

import { parentPort, workerData } from 'worker_threads';
import { randomx_init_cache, randomx_create_vm } from './vendor/index.js';

let vm = null;
let cacheKey = null;

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
    try {
      const { template, nonceOffset, difficulty, startNonce, endNonce } = input;
      const templateBuf = new Uint8Array(template);
      const view = new DataView(templateBuf.buffer);
      const target = (1n << 256n) / BigInt(difficulty);

      for (let nonce = startNonce; nonce < endNonce; nonce++) {
        view.setUint32(nonceOffset, nonce, true);
        const hash = vm.calculate_hash(templateBuf);

        // Check difficulty
        let hashNum = 0n;
        for (let i = 0; i < 32; i++) {
          hashNum = (hashNum << 8n) | BigInt(hash[i]);
        }

        if (hashNum <= target) {
          parentPort.postMessage({ type: 'found', id, nonce, hash });
          return;
        }
      }

      parentPort.postMessage({ type: 'notfound', id });
    } catch (err) {
      parentPort.postMessage({ type: 'error', id, error: err.message });
    }
  }
});
