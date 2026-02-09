/**
 * Pure JS RandomX Mining Worker
 *
 * Uses the hand-written JavaScript RandomX VM (not the vendor WASM JIT).
 * Each worker initializes its own 256MB Argon2d cache and RandomX VM.
 *
 * Message protocol is identical to randomx-worker.js for compatibility.
 */

import { parentPort, workerData } from 'worker_threads';

let vm = null;
let cache = null;
let blake2bFn = null;
let currentMineGeneration = 0;

parentPort.on('message', async (msg) => {
  const { type, id, key, input } = msg;

  if (type === 'init') {
    try {
      const { RandomXCache } = await import('./dataset.js');
      const { RandomXVM } = await import('./vm.js');
      const { blake2b } = await import('../blake2b.js');
      blake2bFn = blake2b;

      cache = new RandomXCache();
      cache.init(key);
      vm = new RandomXVM(cache);
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
      const hash = computeHash(input);
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
    mineChunked(input, id, generation);
  } else if (type === 'cancel') {
    currentMineGeneration++;
  }
});

function computeHash(input) {
  const seed = blake2bFn(input, 64);
  vm.initScratchpad(seed);
  vm.run(seed);
  return vm.getFinalResult();
}

async function mineChunked(input, id, generation) {
  try {
    const { template, nonceOffset, difficulty, startNonce, endNonce } = input;
    const templateBuf = new Uint8Array(template);
    const view = new DataView(templateBuf.buffer);
    const diffBig = BigInt(difficulty);
    const max256 = (1n << 256n) - 1n;

    const CHUNK_SIZE = 20; // Yield every 20 hashes (JS is ~0.5 H/s, so ~40s chunks)
    let hashCount = 0;

    for (let nonce = startNonce; nonce < endNonce; nonce++) {
      if (currentMineGeneration !== generation) return;

      view.setUint32(nonceOffset, nonce, true);
      const hash = computeHash(templateBuf);
      hashCount++;

      let hashNum = 0n;
      for (let i = 31; i >= 0; i--) {
        hashNum = (hashNum << 8n) | BigInt(hash[i]);
      }

      if (hashNum * diffBig <= max256) {
        if (currentMineGeneration !== generation) return;
        parentPort.postMessage({ type: 'found', id, nonce, hash, hashCount });
        return;
      }

      if (hashCount % CHUNK_SIZE === 0) {
        await new Promise(r => setImmediate(r));
        if (currentMineGeneration !== generation) return;
      }
    }

    if (currentMineGeneration === generation) {
      parentPort.postMessage({ type: 'notfound', id, hashCount });
    }
  } catch (err) {
    if (currentMineGeneration === generation) {
      parentPort.postMessage({ type: 'error', id, error: err.message });
    }
  }
}
