#!/usr/bin/env node
/**
 * Benchmark: Batch Dataset Generation
 *
 * Tests the optimized batch WASM function that generates
 * multiple items per call.
 *
 * Usage:
 *   source ~/.bash_profile && bun test/benchmark-batch.js
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { initCache as initCacheWasm } from '../src/randomx/argon2d-wasm.js';
import { Blake2Generator, generateSuperscalar, reciprocal, SuperscalarInstructionType } from '../src/randomx/superscalar.js';
import { RANDOMX_CACHE_ACCESSES, RANDOMX_DATASET_ITEM_COUNT } from '../src/randomx/config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('Batch Dataset Generation Benchmark');
console.log('===================================\n');

const testKey = new TextEncoder().encode('benchmark key');

// Progress helper
const progress = (percent, msg) => {
  const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
  process.stdout.write(`\r[${bar}] ${percent}% ${msg}`.padEnd(70));
};

// ========== Initialize Cache ==========
console.log('Initializing cache with WASM...');
const cacheStart = Date.now();

const cacheQwords = await initCacheWasm(testKey, (completed, total, pass, slice) => {
  const percent = Math.round((completed / total) * 100);
  progress(percent, `pass ${pass + 1}/3, slice ${slice + 1}/4`);
});

const cacheMemory = new Uint8Array(cacheQwords.length * 8);
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
process.stdout.write('\r' + ' '.repeat(70) + '\r');
console.log(`Cache initialized in ${((Date.now() - cacheStart) / 1000).toFixed(1)}s\n`);

// Generate programs
console.log('Generating superscalar programs...');
const programs = [];
const reciprocalCache = [];
const gen = new Blake2Generator(testKey);
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
console.log(`Generated ${RANDOMX_CACHE_ACCESSES} programs\n`);

// ========== Load WASM ==========
console.log('Loading WASM module...');
const wasmPath = join(__dirname, '../build/randomx.wasm');
const wasmBuffer = readFileSync(wasmPath);

const wasmMemory = new WebAssembly.Memory({
  initial: 4096 + 1024,  // 256MB + 64MB working space
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
const mem = new Uint8Array(wasmMemory.buffer);

// Copy cache
mem.set(cacheMemory, 0);
wasm.superscalar_init(0, cacheMemory.length / 64);

// Set up programs
const programsPtr = cacheMemory.length + 4096;
const reciprocalsWasmPtr = programsPtr + 8 * 512 * 8;

const reciprocalsBytes = new BigUint64Array(reciprocalCache.length);
for (let i = 0; i < reciprocalCache.length; i++) {
  reciprocalsBytes[i] = reciprocalCache[i];
}
mem.set(new Uint8Array(reciprocalsBytes.buffer), reciprocalsWasmPtr);

wasm.setup_programs(programsPtr, reciprocalsWasmPtr, reciprocalCache.length);

let instrOffset = 0;
for (let p = 0; p < programs.length; p++) {
  const prog = programs[p];
  const startOffset = instrOffset;
  for (const instr of prog.instructions) {
    const ptr = programsPtr + instrOffset;
    mem[ptr] = instr.opcode;
    mem[ptr + 1] = instr.dst;
    mem[ptr + 2] = instr.src;
    mem[ptr + 3] = instr.mod;
    mem[ptr + 4] = instr.imm32 & 0xff;
    mem[ptr + 5] = (instr.imm32 >> 8) & 0xff;
    mem[ptr + 6] = (instr.imm32 >> 16) & 0xff;
    mem[ptr + 7] = (instr.imm32 >> 24) & 0xff;
    instrOffset += 8;
  }
  wasm.set_program_meta(p, startOffset, prog.instructions.length, prog.addressRegister);
}
console.log('WASM ready\n');

// ========== Benchmark ==========
const batchSizes = [100, 1000, 10000];
const totalTestItems = 100000;  // 100K items for benchmark

// Output buffer after programs and reciprocals (need space for largest batch)
const maxBatchSize = 10000;
const outputPtr = reciprocalsWasmPtr + reciprocalCache.length * 8 + 4096;

console.log('Batch size comparison:');
console.log('----------------------');

for (const batchSize of batchSizes) {
  const batches = Math.ceil(totalTestItems / batchSize);

  const start = Date.now();
  for (let b = 0; b < batches; b++) {
    const startItem = b * batchSize;
    const count = Math.min(batchSize, totalTestItems - startItem);
    wasm.init_dataset_batch(BigInt(startItem), count, outputPtr, RANDOMX_CACHE_ACCESSES);
  }
  const elapsed = (Date.now() - start) / 1000;
  const itemsPerSec = Math.round(totalTestItems / elapsed);

  console.log(`Batch size ${batchSize.toString().padStart(5)}: ${itemsPerSec.toLocaleString().padStart(10)} items/s`);
}

// Full dataset estimate with best batch size
console.log('\nFull Dataset Estimate (34M items):');
const finalBatchSize = 10000;
const testStart = Date.now();
const testBatches = 100;
for (let b = 0; b < testBatches; b++) {
  wasm.init_dataset_batch(BigInt(b * finalBatchSize), finalBatchSize, outputPtr, RANDOMX_CACHE_ACCESSES);
}
const testElapsed = (Date.now() - testStart) / 1000;
const finalRate = (testBatches * finalBatchSize) / testElapsed;
const fullDatasetTime = RANDOMX_DATASET_ITEM_COUNT / finalRate;

console.log(`Rate: ${Math.round(finalRate).toLocaleString()} items/s`);
console.log(`Estimated time: ${(fullDatasetTime / 60).toFixed(1)} minutes (single thread)`);
console.log(`With 8 workers: ~${(fullDatasetTime / 60 / 8).toFixed(1)} minutes`);

// Memory bandwidth estimate
const bytesPerItem = 64;
const cacheReadsPerItem = 8 * 64; // 8 cache line reads per item
const totalBandwidth = finalRate * (bytesPerItem + cacheReadsPerItem);
console.log(`\nMemory bandwidth: ${(totalBandwidth / 1024 / 1024 / 1024).toFixed(2)} GB/s`);
