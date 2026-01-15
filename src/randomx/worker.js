/**
 * RandomX Worker for parallel dataset generation
 *
 * This worker computes dataset items in parallel with other workers.
 * Each worker is assigned a range of item indices to compute.
 */

import { RandomXCache, initDatasetItem } from './dataset.js';
import { initCache as argon2InitCache } from './argon2d.js';

let cache = null;

/**
 * Handle messages from main thread
 */
self.onmessage = async (event) => {
  const { type, data } = event.data;

  switch (type) {
    case 'init-cache':
      // Initialize the cache from key
      await initCacheFromKey(data.key, data.workerId);
      break;

    case 'set-cache':
      // Receive serialized cache from main thread
      setCacheFromData(data.memory, data.programs, data.reciprocalCache);
      break;

    case 'compute-items':
      // Compute a range of dataset items
      computeDatasetItems(data.startItem, data.endItem, data.workerId);
      break;

    case 'compute-hash':
      // Compute a single hash (for parallel mining)
      computeHash(data.input, data.jobId);
      break;
  }
};

/**
 * Initialize cache from key (runs Argon2d)
 */
async function initCacheFromKey(keyArray, workerId) {
  const key = new Uint8Array(keyArray);

  cache = new RandomXCache();

  // Progress callback
  const onProgress = (percent, pass, slice) => {
    self.postMessage({
      type: 'progress',
      data: { percent, pass, slice, workerId }
    });
  };

  cache.init(key, onProgress);

  // Send cache data back to main thread for sharing with other workers
  self.postMessage({
    type: 'cache-ready',
    data: {
      workerId,
      // Serialize cache for transfer
      memory: Array.from(cache.memory),
      programs: serializePrograms(cache.programs),
      reciprocalCache: cache.reciprocalCache.map(r => r.toString())
    }
  });
}

/**
 * Set cache from serialized data (received from main thread)
 */
function setCacheFromData(memoryArray, programsData, reciprocalStrings) {
  cache = new RandomXCache();
  cache.memory = new Uint8Array(memoryArray);
  cache.programs = deserializePrograms(programsData);
  cache.reciprocalCache = reciprocalStrings.map(s => BigInt(s));

  self.postMessage({ type: 'cache-set' });
}

/**
 * Compute dataset items for a range
 */
function computeDatasetItems(startItem, endItem, workerId) {
  const itemCount = endItem - startItem;
  const items = new Uint8Array(itemCount * 64);

  for (let i = 0; i < itemCount; i++) {
    const itemIndex = startItem + i;
    const item = initDatasetItem(cache, itemIndex);
    items.set(item, i * 64);

    // Report progress every 1000 items
    if (i % 1000 === 0) {
      self.postMessage({
        type: 'item-progress',
        data: {
          workerId,
          completed: i,
          total: itemCount,
          startItem,
          currentItem: itemIndex
        }
      });
    }
  }

  // Send completed items back
  self.postMessage({
    type: 'items-complete',
    data: {
      workerId,
      startItem,
      endItem,
      items: Array.from(items)
    }
  });
}

/**
 * Serialize superscalar programs for transfer
 */
function serializePrograms(programs) {
  return programs.map(prog => ({
    addressRegister: prog.addressRegister,
    instructions: prog.instructions.map(instr => ({
      opcode: instr.opcode,
      dst: instr.dst,
      src: instr.src,
      mod: instr.mod,
      imm32: instr.imm32
    }))
  }));
}

/**
 * Deserialize superscalar programs
 */
function deserializePrograms(programsData) {
  return programsData.map(prog => ({
    addressRegister: prog.addressRegister,
    instructions: prog.instructions.map(instr => ({
      opcode: instr.opcode,
      dst: instr.dst,
      src: instr.src,
      mod: instr.mod,
      imm32: instr.imm32,
      getModShift: () => instr.mod % 4
    }))
  }));
}

/**
 * Compute hash for mining
 */
function computeHash(inputArray, jobId) {
  // TODO: Implement VM execution in worker
  self.postMessage({
    type: 'hash-complete',
    data: { jobId, hash: null }
  });
}
