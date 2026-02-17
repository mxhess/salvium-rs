#!/usr/bin/env node
/**
 * Test: WASM-accelerated RandomX Integration
 *
 * Verifies the full RandomX pipeline with WASM cache initialization.
 *
 * Usage:
 *   source ~/.bash_profile && bun test/test-wasm-integration.js
 */

import { RandomXContext, preloadWasm } from '../src/randomx/index.js';

console.log('RandomX WASM Integration Test');
console.log('==============================\n');

const testKey = new TextEncoder().encode('test key 000');
const testInput = new TextEncoder().encode('This is a test');

// Pre-load WASM
console.log('Pre-loading WASM module...');
await preloadWasm();
console.log('WASM loaded.\n');

// Test 1: WASM-accelerated light mode
console.log('Test 1: WASM-accelerated light mode (256MB)');
console.log('-------------------------------------------');

const ctxWasm = new RandomXContext({ wasm: true, fullMode: false });

console.log('Initializing...');
const wasmStart = Date.now();
await ctxWasm.init(testKey);
const wasmInitTime = (Date.now() - wasmStart) / 1000;
console.log(`Init time: ${wasmInitTime.toFixed(2)}s\n`);

console.log('Computing hash...');
const hashStart = Date.now();
const hash1 = ctxWasm.hash(testInput);
const hashTime = (Date.now() - hashStart) / 1000;

console.log(`Hash: ${Buffer.from(hash1).toString('hex')}`);
console.log(`Hash time: ${hashTime.toFixed(2)}s\n`);

// Test 2: Compare with JS mode (if requested)
if (process.argv.includes('--compare-js')) {
  console.log('Test 2: Pure JS light mode (for comparison)');
  console.log('-------------------------------------------');
  console.log('WARNING: This will take ~3 minutes!\n');

  const ctxJs = new RandomXContext({ wasm: false, fullMode: false });

  console.log('Initializing with pure JS...');
  const jsStart = Date.now();
  ctxJs.initSync(testKey);
  const jsInitTime = (Date.now() - jsStart) / 1000;
  console.log(`Init time: ${jsInitTime.toFixed(2)}s\n`);

  const hash2 = ctxJs.hash(testInput);
  console.log(`Hash: ${Buffer.from(hash2).toString('hex')}`);

  // Compare hashes
  const hashesMatch = hash1.every((v, i) => v === hash2[i]);
  console.log(`\nHashes match: ${hashesMatch ? 'YES' : 'NO (BUG!)'}`);
  console.log(`Speedup: ${(jsInitTime / wasmInitTime).toFixed(1)}x`);
}

// Test 3: Multiple hashes
console.log('Test 3: Multiple hashes with same context');
console.log('-----------------------------------------');

for (let i = 0; i < 3; i++) {
  const input = new TextEncoder().encode(`Test input ${i}`);
  const start = Date.now();
  const hash = ctxWasm.hash(input);
  const time = (Date.now() - start) / 1000;
  console.log(`Hash ${i}: ${Buffer.from(hash).toString('hex').slice(0, 32)}... (${time.toFixed(2)}s)`);
}

console.log('\n=== All tests completed! ===');
