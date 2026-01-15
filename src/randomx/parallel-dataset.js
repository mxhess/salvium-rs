/**
 * Parallel Dataset Generation
 *
 * Uses worker threads to generate the 2GB dataset in parallel.
 * With 8 workers, reduces dataset generation from ~46 min to ~6 min.
 */

import { Worker } from 'worker_threads';
import { cpus } from 'os';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { RANDOMX_DATASET_ITEM_COUNT, RANDOMX_CACHE_ACCESSES } from './config.js';
import { initCache as initCacheWasm } from './argon2d-wasm.js';
import { Blake2Generator, generateSuperscalar, reciprocal, SuperscalarInstructionType } from './superscalar.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DATASET_ITEM_SIZE = 64;

/**
 * Generate full dataset using parallel workers
 *
 * @param {Uint8Array} key - Cache initialization key
 * @param {object} options - Options
 * @param {number} options.workers - Number of workers (default: CPU count)
 * @param {number} options.itemCount - Number of items (default: full dataset)
 * @param {function} options.onProgress - Progress callback (stage, percent, details)
 * @returns {Promise<Uint8Array>} - Dataset buffer
 */
export async function generateDatasetParallel(key, options = {}) {
  const numWorkers = options.workers || cpus().length;
  const totalItems = options.itemCount || RANDOMX_DATASET_ITEM_COUNT;
  const onProgress = options.onProgress || defaultProgress;

  // Stage 1: Initialize cache
  onProgress('cache', 0, { message: 'Initializing 256MB cache...' });

  const cacheQwords = await initCacheWasm(key, (completed, total, pass, slice) => {
    const percent = Math.round((completed / total) * 100);
    onProgress('cache', percent, { pass, slice });
  });

  // Convert cache to bytes using SharedArrayBuffer so workers don't copy it
  const cacheSize = cacheQwords.length * 8;
  const sharedCacheBuffer = new SharedArrayBuffer(cacheSize);
  const cacheMemory = new Uint8Array(sharedCacheBuffer);
  for (let i = 0; i < cacheQwords.length; i++) {
    const v = cacheQwords[i];
    const pos = i * 8;
    cacheMemory[pos] = Number(v & 0xffn);
    cacheMemory[pos + 1] = Number((v >> 8n) & 0xffn);
    cacheMemory[pos + 2] = Number((v >> 16n) & 0xffn);
    cacheMemory[pos + 3] = Number((v >> 24n) & 0xffn);
    cacheMemory[pos + 4] = Number((v >> 32n) & 0xffn);
    cacheMemory[pos + 5] = Number((v >> 40n) & 0xffn);
    cacheMemory[pos + 6] = Number((v >> 48n) & 0xffn);
    cacheMemory[pos + 7] = Number((v >> 56n) & 0xffn);
  }

  onProgress('cache', 100, { message: 'Cache ready' });

  // Stage 2: Generate superscalar programs
  onProgress('programs', 0, { message: 'Generating superscalar programs...' });

  const programs = [];
  const reciprocalCache = [];
  const gen = new Blake2Generator(key);

  for (let i = 0; i < RANDOMX_CACHE_ACCESSES; i++) {
    const prog = generateSuperscalar(gen);
    for (const instr of prog.instructions) {
      if (instr.opcode === SuperscalarInstructionType.IMUL_RCP) {
        const rcp = reciprocal(instr.imm32);
        instr.imm32 = reciprocalCache.length;
        reciprocalCache.push(rcp);
      }
    }
    programs.push(prog);
  }

  // Serialize programs for workers
  const programsData = new Uint8Array(8 * 512 * 8);  // 8 programs * max 512 instructions * 8 bytes
  const programMeta = [];
  let instrOffset = 0;

  for (let p = 0; p < programs.length; p++) {
    const prog = programs[p];
    const startOffset = instrOffset;

    for (const instr of prog.instructions) {
      programsData[instrOffset] = instr.opcode;
      programsData[instrOffset + 1] = instr.dst;
      programsData[instrOffset + 2] = instr.src;
      programsData[instrOffset + 3] = instr.mod;
      programsData[instrOffset + 4] = instr.imm32 & 0xff;
      programsData[instrOffset + 5] = (instr.imm32 >> 8) & 0xff;
      programsData[instrOffset + 6] = (instr.imm32 >> 16) & 0xff;
      programsData[instrOffset + 7] = (instr.imm32 >> 24) & 0xff;
      instrOffset += 8;
    }

    programMeta.push({
      offset: startOffset,
      count: prog.instructions.length,
      addressReg: prog.addressRegister
    });
  }

  // Serialize reciprocals
  const reciprocalsData = new BigUint64Array(reciprocalCache.length);
  for (let i = 0; i < reciprocalCache.length; i++) {
    reciprocalsData[i] = reciprocalCache[i];
  }

  onProgress('programs', 100, { message: 'Programs ready' });

  // Stage 3: Parallel dataset generation
  onProgress('dataset', 0, { message: `Starting ${numWorkers} workers...`, workers: numWorkers });

  const itemsPerWorker = Math.ceil(totalItems / numWorkers);

  // Allocate full dataset buffer
  const dataset = new Uint8Array(totalItems * DATASET_ITEM_SIZE);

  // Track progress per worker
  const workerProgress = new Array(numWorkers).fill(0);
  const workerTotals = new Array(numWorkers).fill(0);
  const startTime = Date.now();

  // Create workers
  const workerPath = join(__dirname, 'dataset-worker.js');
  const workerPromises = [];

  for (let w = 0; w < numWorkers; w++) {
    const startItem = w * itemsPerWorker;
    const endItem = Math.min((w + 1) * itemsPerWorker, totalItems);
    workerTotals[w] = endItem - startItem;

    const worker = new Worker(workerPath, {
      workerData: {
        workerId: w,
        startItem,
        endItem,
        cacheBuffer: sharedCacheBuffer,  // SharedArrayBuffer - workers share, don't copy
        programsData: programsData.buffer,
        reciprocalsData: reciprocalsData.buffer,
        programMeta
      }
    });

    const promise = new Promise((resolve, reject) => {
      worker.on('message', (msg) => {
        if (msg.type === 'progress') {
          workerProgress[msg.workerId] = msg.completed;

          // Calculate overall progress
          const totalCompleted = workerProgress.reduce((a, b) => a + b, 0);
          const percent = Math.round((totalCompleted / totalItems) * 100);
          const elapsed = (Date.now() - startTime) / 1000;
          const itemsPerSec = Math.round(totalCompleted / elapsed);
          const eta = Math.round((totalItems - totalCompleted) / itemsPerSec);

          onProgress('dataset', percent, {
            completed: totalCompleted,
            total: totalItems,
            itemsPerSec,
            eta,
            workers: numWorkers
          });
        } else if (msg.type === 'complete') {
          // Copy worker's results to dataset
          const data = new Uint8Array(msg.data);
          dataset.set(data, msg.startItem * DATASET_ITEM_SIZE);
          resolve();
        }
      });

      worker.on('error', reject);
    });

    workerPromises.push(promise);
  }

  // Wait for all workers
  await Promise.all(workerPromises);

  const totalTime = (Date.now() - startTime) / 1000;
  onProgress('complete', 100, {
    message: `Dataset ready (${(totalTime / 60).toFixed(1)} min)`,
    totalTime
  });

  return dataset;
}

/**
 * Default progress handler
 */
function defaultProgress(stage, percent, details) {
  if (typeof process === 'undefined' || !process.stdout) return;

  const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));

  if (stage === 'cache') {
    const info = details.pass !== undefined
      ? `pass ${details.pass + 1}/3, slice ${details.slice + 1}/4`
      : details.message || '';
    process.stdout.write(`\rCache:    [${bar}] ${percent}% ${info}`.padEnd(80));
  } else if (stage === 'programs') {
    process.stdout.write(`\rPrograms: [${bar}] ${percent}% ${details.message || ''}`.padEnd(80));
  } else if (stage === 'dataset') {
    const info = details.eta !== undefined
      ? `${details.itemsPerSec?.toLocaleString()} items/s, ETA: ${Math.floor(details.eta / 60)}m ${details.eta % 60}s`
      : details.message || '';
    process.stdout.write(`\rDataset:  [${bar}] ${percent}% ${info}`.padEnd(80));
  } else if (stage === 'complete') {
    process.stdout.write('\r' + ' '.repeat(80) + '\r');
    console.log(`Dataset initialized (2GB, ${details.totalTime?.toFixed(1)}s)`);
  }
}

export default {
  generateDatasetParallel
};
