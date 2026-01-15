#!/usr/bin/env node
/**
 * Benchmark: WASM vs JS SuperscalarHash (Dataset Item Generation)
 *
 * Usage:
 *   source ~/.bash_profile && bun test/benchmark-wasm-superscalar.js
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { RandomXCache, initDatasetItem } from '../src/randomx/dataset.js';
import { initCache as initCacheWasm } from '../src/randomx/argon2d-wasm.js';
import { Blake2Generator, generateSuperscalar, reciprocal, SuperscalarInstructionType } from '../src/randomx/superscalar.js';
import { RANDOMX_CACHE_ACCESSES } from '../src/randomx/config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('SuperscalarHash WASM vs JS Benchmark');
console.log('====================================\n');

const testKey = new TextEncoder().encode('benchmark key');

// Progress helper
const progress = (percent, msg) => {
  const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
  process.stdout.write(`\r[${bar}] ${percent}% ${msg}`.padEnd(70));
};

// ========== Initialize Cache with WASM ==========
console.log('Initializing cache with WASM...');
const cacheStart = Date.now();

const cacheQwords = await initCacheWasm(testKey, (completed, total, pass, slice) => {
  const percent = Math.round((completed / total) * 100);
  progress(percent, `pass ${pass + 1}/3, slice ${slice + 1}/4`);
});

// Convert to bytes
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
const cacheTime = (Date.now() - cacheStart) / 1000;
console.log(`Cache initialized in ${cacheTime.toFixed(1)}s\n`);

// Generate superscalar programs
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

// Create JS cache for comparison
console.log('Creating JS cache object...');
const jsCache = new RandomXCache();
jsCache.memory = cacheMemory;
jsCache.programs = programs;
jsCache.reciprocalCache = reciprocalCache;
console.log('JS cache ready\n');

// ========== Load WASM ==========
console.log('Loading WASM module...');
const wasmPath = join(__dirname, '../build/randomx.wasm');
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

// Copy cache to WASM memory
const mem = new Uint8Array(wasmMemory.buffer);
mem.set(cacheMemory, 0);

const cacheLineCount = cacheMemory.length / 64;
wasm.superscalar_init(0, cacheLineCount);

const outputPtr = cacheMemory.length + 1024;
console.log('WASM ready\n');

// ========== Benchmark ==========
const testItems = 1000;

// WASM function (per-instruction calls) - slower due to JS<->WASM overhead
function initDatasetItemWasmSlow(itemNumber) {
  wasm.init_registers(BigInt(itemNumber));
  let registerValue = BigInt(itemNumber);

  for (let i = 0; i < RANDOMX_CACHE_ACCESSES; i++) {
    const prog = programs[i];
    wasm.get_cache_block(registerValue);

    for (const instr of prog.instructions) {
      if (instr.opcode === 13) {
        wasm.exec_imul_rcp(instr.dst, reciprocalCache[instr.imm32]);
      } else {
        wasm.exec_instruction(instr.opcode, instr.dst, instr.src, instr.mod, instr.imm32);
      }
    }

    wasm.xor_cache_block();
    registerValue = wasm.get_address_reg(prog.addressRegister);
  }

  wasm.write_registers(outputPtr);
  return mem.slice(outputPtr, outputPtr + 64);
}

// Set up optimized batch execution
console.log('Setting up optimized WASM batch execution...');

// Programs go after cache memory + output buffer
const programsPtr = cacheMemory.length + 2048;
const reciprocalsWasmPtr = programsPtr + 8 * 512 * 8; // 8 programs * 512 instructions * 8 bytes

// Copy reciprocals to WASM memory
const reciprocalsBytes = new BigUint64Array(reciprocalCache.length);
for (let i = 0; i < reciprocalCache.length; i++) {
  reciprocalsBytes[i] = reciprocalCache[i];
}
const reciprocalsView = new Uint8Array(reciprocalsBytes.buffer);
mem.set(reciprocalsView, reciprocalsWasmPtr);

// Set up program storage
wasm.setup_programs(programsPtr, reciprocalsWasmPtr, reciprocalCache.length);

// Serialize programs to WASM memory
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
    // Write imm32 as little-endian
    mem[ptr + 4] = instr.imm32 & 0xff;
    mem[ptr + 5] = (instr.imm32 >> 8) & 0xff;
    mem[ptr + 6] = (instr.imm32 >> 16) & 0xff;
    mem[ptr + 7] = (instr.imm32 >> 24) & 0xff;
    instrOffset += 8;
  }

  wasm.set_program_meta(p, startOffset, prog.instructions.length, prog.addressRegister);
}
console.log(`Serialized ${programs.length} programs (${instrOffset} bytes)\n`);

// Optimized WASM function - single call does everything
function initDatasetItemWasmFast(itemNumber) {
  wasm.init_dataset_item(BigInt(itemNumber), RANDOMX_CACHE_ACCESSES);
  wasm.write_registers(outputPtr);
  return mem.slice(outputPtr, outputPtr + 64);
}

// Warmup
console.log('Warming up...');
for (let i = 0; i < 10; i++) {
  initDatasetItem(jsCache, i);
  initDatasetItemWasmSlow(i);
  initDatasetItemWasmFast(i);
}
console.log('Warmup complete\n');

// JS Benchmark
console.log(`Testing JS SuperscalarHash (${testItems} items)...`);
const jsStart = Date.now();
for (let i = 0; i < testItems; i++) {
  initDatasetItem(jsCache, i);
  if (i % 100 === 0) {
    const percent = Math.round((i / testItems) * 100);
    progress(percent, `${i}/${testItems} items`);
  }
}
const jsTime = (Date.now() - jsStart) / 1000;
process.stdout.write('\r' + ' '.repeat(70) + '\r');
console.log(`JS time: ${jsTime.toFixed(2)}s (${(testItems / jsTime).toFixed(0)} items/s)\n`);

// WASM Slow Benchmark (per-instruction calls)
console.log(`Testing WASM (slow, per-instruction) (${testItems} items)...`);
const wasmSlowStart = Date.now();
for (let i = 0; i < testItems; i++) {
  initDatasetItemWasmSlow(i);
  if (i % 100 === 0) {
    const percent = Math.round((i / testItems) * 100);
    progress(percent, `${i}/${testItems} items`);
  }
}
const wasmSlowTime = (Date.now() - wasmSlowStart) / 1000;
process.stdout.write('\r' + ' '.repeat(70) + '\r');
console.log(`WASM (slow): ${wasmSlowTime.toFixed(2)}s (${(testItems / wasmSlowTime).toFixed(0)} items/s)\n`);

// WASM Fast Benchmark (batch execution)
console.log(`Testing WASM (fast, batch) (${testItems} items)...`);
const wasmFastStart = Date.now();
for (let i = 0; i < testItems; i++) {
  initDatasetItemWasmFast(i);
  if (i % 100 === 0) {
    const percent = Math.round((i / testItems) * 100);
    progress(percent, `${i}/${testItems} items`);
  }
}
const wasmFastTime = (Date.now() - wasmFastStart) / 1000;
process.stdout.write('\r' + ' '.repeat(70) + '\r');
console.log(`WASM (fast): ${wasmFastTime.toFixed(2)}s (${(testItems / wasmFastTime).toFixed(0)} items/s)\n`);

// Results
console.log('Results');
console.log('=======');
console.log(`JS:          ${jsTime.toFixed(2)}s (${(testItems / jsTime).toFixed(0)} items/s)`);
console.log(`WASM (slow): ${wasmSlowTime.toFixed(2)}s (${(testItems / wasmSlowTime).toFixed(0)} items/s) - ${(jsTime / wasmSlowTime).toFixed(1)}x`);
console.log(`WASM (fast): ${wasmFastTime.toFixed(2)}s (${(testItems / wasmFastTime).toFixed(0)} items/s) - ${(jsTime / wasmFastTime).toFixed(1)}x`);

// Estimate full dataset time
const fullDatasetItems = 34078720; // RANDOMX_DATASET_ITEM_COUNT
const jsFullTime = fullDatasetItems / (testItems / jsTime);
const wasmFastFullTime = fullDatasetItems / (testItems / wasmFastTime);

console.log('\nFull Dataset (2GB) Estimate:');
console.log(`JS:          ${(jsFullTime / 3600).toFixed(1)} hours`);
console.log(`WASM (fast): ${(wasmFastFullTime / 60).toFixed(1)} minutes`);

// Verify correctness
console.log('\nVerifying correctness...');
const jsItem = initDatasetItem(jsCache, 12345);
const wasmItemSlow = initDatasetItemWasmSlow(12345);
const wasmItemFast = initDatasetItemWasmFast(12345);

let matchSlow = true;
let matchFast = true;

for (let i = 0; i < 64; i++) {
  if (jsItem[i] !== wasmItemSlow[i]) {
    matchSlow = false;
    console.log(`WASM (slow) mismatch at byte ${i}: JS=${jsItem[i]}, WASM=${wasmItemSlow[i]}`);
    break;
  }
}

for (let i = 0; i < 64; i++) {
  if (jsItem[i] !== wasmItemFast[i]) {
    matchFast = false;
    console.log(`WASM (fast) mismatch at byte ${i}: JS=${jsItem[i]}, WASM=${wasmItemFast[i]}`);
    break;
  }
}

if (matchSlow && matchFast) {
  console.log('All results match!');
} else {
  if (!matchSlow) console.log('WARNING: WASM (slow) results do not match!');
  if (!matchFast) console.log('WARNING: WASM (fast) results do not match!');
}
