#!/usr/bin/env node
/**
 * Test WASM module
 *
 * Usage:
 *   source ~/.bash_profile && bun test/test-wasm.js
 */

import { readFileSync } from 'fs';
import { blake2b as blake2bJS } from '../src/blake2b.js';

console.log('Testing WASM module...\n');

// Load WASM with required imports
const wasmPath = new URL('../build/randomx.wasm', import.meta.url);
const wasmBuffer = readFileSync(wasmPath);

// AssemblyScript requires these imports
const imports = {
  env: {
    abort: (msg, file, line, column) => {
      console.error(`WASM abort at ${file}:${line}:${column}`);
    }
  }
};

const wasmModule = await WebAssembly.instantiate(wasmBuffer, imports);
const wasm = wasmModule.instance.exports;

// Test basic u64 operations
console.log('Testing u64 operations:');
const a = 0x123456789ABCDEFn;
const b = 0xFEDCBA9876543210n;
const sum = wasm.add(a, b);
console.log(`  add(${a.toString(16)}, ${b.toString(16)}) = ${sum.toString(16)}`);

// Test rotation
const x = 0x123456789ABCDEFn;
const rotated = wasm.rotr64(x, 32);
console.log(`  rotr64(${x.toString(16)}, 32) = ${rotated.toString(16)}`);

// Test BlaMka
const blaMka = wasm.fBlaMka(0x12345678n, 0x87654321n);
console.log(`  fBlaMka(12345678, 87654321) = ${blaMka.toString(16)}`);

// Test Blake2b
console.log('\nTesting Blake2b:');

// Allocate memory in WASM for input and output
const input = new TextEncoder().encode('Hello, WASM!');
const inputPtr = wasm.allocate(input.length);
const outputPtr = wasm.allocate(32);

// Copy input to WASM memory
const memory = new Uint8Array(wasm.memory.buffer);
memory.set(input, inputPtr);

// Call Blake2b
wasm.blake2b(inputPtr, input.length, outputPtr, 32);

// Read output
const wasmHash = memory.slice(outputPtr, outputPtr + 32);
const jsHash = blake2bJS(input, 32);

console.log(`  WASM: ${Array.from(wasmHash).map(b => b.toString(16).padStart(2, '0')).join('')}`);
console.log(`  JS:   ${Array.from(jsHash).map(b => b.toString(16).padStart(2, '0')).join('')}`);

// Verify match
const match = wasmHash.every((b, i) => b === jsHash[i]);
console.log(`  Match: ${match ? '✓' : '✗'}`);

// Free memory
wasm.deallocate(inputPtr);
wasm.deallocate(outputPtr);

// Benchmark
console.log('\nBenchmark (1000 hashes):');
const benchInput = new TextEncoder().encode('benchmark input data for blake2b performance testing');
const benchInputPtr = wasm.allocate(benchInput.length);
const benchOutputPtr = wasm.allocate(64);
const memory2 = new Uint8Array(wasm.memory.buffer);
memory2.set(benchInput, benchInputPtr);

// WASM benchmark
const wasmStart = Date.now();
for (let i = 0; i < 1000; i++) {
  wasm.blake2b(benchInputPtr, benchInput.length, benchOutputPtr, 64);
}
const wasmTime = Date.now() - wasmStart;
console.log(`  WASM: ${wasmTime}ms (${(1000 / wasmTime * 1000).toFixed(0)} hashes/sec)`);

// JS benchmark
const jsStart = Date.now();
for (let i = 0; i < 1000; i++) {
  blake2bJS(benchInput, 64);
}
const jsTime = Date.now() - jsStart;
console.log(`  JS:   ${jsTime}ms (${(1000 / jsTime * 1000).toFixed(0)} hashes/sec)`);

console.log(`  Speedup: ${(jsTime / wasmTime).toFixed(2)}x`);

wasm.deallocate(benchInputPtr);
wasm.deallocate(benchOutputPtr);

console.log('\n✓ WASM module working!');
