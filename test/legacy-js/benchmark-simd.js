#!/usr/bin/env node
/**
 * Benchmark: SIMD vs Scalar Dataset Generation
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { initCache as initCacheWasm } from '../src/randomx/argon2d-wasm.js';
import { Blake2Generator, generateSuperscalar, reciprocal, SuperscalarInstructionType } from '../src/randomx/superscalar.js';
import { RANDOMX_CACHE_ACCESSES } from '../src/randomx/config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('SIMD vs Scalar Benchmark');
console.log('========================\n');

const testKey = new TextEncoder().encode('benchmark key');

// Initialize cache
console.log('Initializing cache...');
const cacheQwords = await initCacheWasm(testKey, () => {});
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
console.log('Cache ready\n');

// Generate programs
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

// Load WASM
const wasmPath = join(__dirname, '../build/randomx.wasm');
const wasmBuffer = readFileSync(wasmPath);
const wasmMemory = new WebAssembly.Memory({ initial: 4096 + 1024, maximum: 8192 });
const imports = { env: { memory: wasmMemory, abort: () => {} } };
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

// Output buffer
const outputPtr = reciprocalsWasmPtr + reciprocalCache.length * 8 + 4096;
const testItems = 100000;
const batchSize = 10000;
const batches = testItems / batchSize;

// Warm up
wasm.init_dataset_batch(0n, 1000, outputPtr, RANDOMX_CACHE_ACCESSES);
wasm.init_dataset_batch_simd(0n, 1000, outputPtr, RANDOMX_CACHE_ACCESSES);

// Benchmark scalar
console.log('Testing scalar (init_dataset_batch)...');
const scalarStart = Date.now();
for (let b = 0; b < batches; b++) {
  wasm.init_dataset_batch(BigInt(b * batchSize), batchSize, outputPtr, RANDOMX_CACHE_ACCESSES);
}
const scalarTime = (Date.now() - scalarStart) / 1000;
const scalarRate = Math.round(testItems / scalarTime);
console.log(`  ${scalarRate.toLocaleString()} items/s (${scalarTime.toFixed(2)}s)`);

// Benchmark SIMD
console.log('Testing SIMD (init_dataset_batch_simd)...');
const simdStart = Date.now();
for (let b = 0; b < batches; b++) {
  wasm.init_dataset_batch_simd(BigInt(b * batchSize), batchSize, outputPtr, RANDOMX_CACHE_ACCESSES);
}
const simdTime = (Date.now() - simdStart) / 1000;
const simdRate = Math.round(testItems / simdTime);
console.log(`  ${simdRate.toLocaleString()} items/s (${simdTime.toFixed(2)}s)`);

// Compare
const improvement = ((simdRate - scalarRate) / scalarRate * 100).toFixed(1);
console.log(`\nSIMD vs Scalar: ${improvement}% ${parseFloat(improvement) > 0 ? 'faster' : 'slower'}`);
