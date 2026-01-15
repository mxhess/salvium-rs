/**
 * Dataset Generation Worker
 *
 * Runs in a separate thread to generate dataset items in parallel.
 * Uses WASM-accelerated SuperscalarHash for maximum performance.
 */

import { parentPort, workerData } from 'worker_threads';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { RANDOMX_CACHE_ACCESSES } from './config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Worker initialization data
const {
  workerId,
  startItem,
  endItem,
  cacheBuffer,
  programsData,
  reciprocalsData,
  programMeta
} = workerData;

// Load WASM
const wasmPath = join(__dirname, '../../build/randomx.wasm');
const wasmBuffer = readFileSync(wasmPath);

const wasmMemory = new WebAssembly.Memory({
  initial: 4096 + 512,
  maximum: 8192
});

const imports = {
  env: {
    memory: wasmMemory,
    abort: () => {}
  }
};

const wasmModule = await WebAssembly.instantiate(wasmBuffer, imports);
const wasm = wasmModule.instance.exports;

// Set up WASM memory
const mem = new Uint8Array(wasmMemory.buffer);

// Copy cache to WASM memory at offset 0
const cacheMemory = new Uint8Array(cacheBuffer);
mem.set(cacheMemory, 0);

const cacheLineCount = cacheMemory.length / 64;
wasm.superscalar_init(0, cacheLineCount);

// Set up programs
const programsPtr = cacheMemory.length + 2048;
const reciprocalsWasmPtr = programsPtr + 8 * 512 * 8;

// Copy reciprocals
const reciprocalsArray = new BigUint64Array(reciprocalsData);
const reciprocalsView = new Uint8Array(reciprocalsArray.buffer);
mem.set(reciprocalsView, reciprocalsWasmPtr);

// Copy programs
const programsArray = new Uint8Array(programsData);
mem.set(programsArray, programsPtr);

// Set up program metadata
wasm.setup_programs(programsPtr, reciprocalsWasmPtr, reciprocalsArray.length);
for (let i = 0; i < programMeta.length; i++) {
  const { offset, count, addressReg } = programMeta[i];
  wasm.set_program_meta(i, offset, count, addressReg);
}

// Output buffer - needs space for batch results
const batchSize = 10000;
const outputPtr = reciprocalsWasmPtr + reciprocalsArray.length * 8 + 4096;

// Generate dataset items using batch function
const itemCount = endItem - startItem;
const resultBuffer = new Uint8Array(itemCount * 64);

const numBatches = Math.ceil(itemCount / batchSize);
let completedItems = 0;

for (let batch = 0; batch < numBatches; batch++) {
  const batchStart = startItem + batch * batchSize;
  const batchCount = Math.min(batchSize, endItem - batchStart);

  // Generate batch in WASM using SIMD-optimized function
  wasm.init_dataset_batch_simd(BigInt(batchStart), batchCount, outputPtr, RANDOMX_CACHE_ACCESSES);

  // Copy results to output buffer
  const batchOffset = batch * batchSize * 64;
  resultBuffer.set(mem.slice(outputPtr, outputPtr + batchCount * 64), batchOffset);

  completedItems += batchCount;

  // Report progress
  parentPort.postMessage({
    type: 'progress',
    workerId,
    completed: completedItems,
    total: itemCount
  });
}

// Send final result
parentPort.postMessage({
  type: 'complete',
  workerId,
  startItem,
  endItem,
  data: resultBuffer.buffer
}, [resultBuffer.buffer]);
