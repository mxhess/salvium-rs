#!/usr/bin/env node
/**
 * Benchmark: Interpreted VM vs JIT-compiled VM
 *
 * Usage:
 *   source ~/.bash_profile && bun test/benchmark-jit.js
 */

import { RandomXCache } from '../src/randomx/dataset.js';
import { RandomXVM } from '../src/randomx/vm.js';
import { RandomXVMJit, clearJitCache, getJitCacheStats } from '../src/randomx/vm-jit.js';
import { blake2b } from '../src/blake2b.js';

console.log('RandomX JIT Benchmark');
console.log('=====================\n');

// Initialize cache first (shared between both VMs)
console.log('Initializing cache (this takes a few minutes)...');
const key = new TextEncoder().encode('benchmark key');
const cache = new RandomXCache();

const cacheStart = Date.now();
cache.init(key, (percent, pass, slice) => {
  const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
  process.stdout.write(`\rCache: [${bar}] ${percent}% (pass ${pass + 1}/3)`);
});
process.stdout.write('\r' + ' '.repeat(60) + '\r');
const cacheTime = (Date.now() - cacheStart) / 1000;
console.log(`Cache initialized in ${cacheTime.toFixed(1)}s\n`);

// Test inputs
const testInputs = [
  new TextEncoder().encode('test input 1'),
  new TextEncoder().encode('test input 2'),
  new TextEncoder().encode('test input 3'),
];

// Benchmark interpreted VM
console.log('Benchmarking Interpreted VM...');
const vmInterpreted = new RandomXVM(cache);

let interpretedTimes = [];
for (let i = 0; i < testInputs.length; i++) {
  const input = testInputs[i];
  const tempHash = blake2b(input, 64);

  vmInterpreted.initScratchpad(tempHash);

  const start = Date.now();
  vmInterpreted.run(tempHash);
  const elapsed = Date.now() - start;

  interpretedTimes.push(elapsed);
  console.log(`  Input ${i + 1}: ${elapsed}ms`);
}

const avgInterpreted = interpretedTimes.reduce((a, b) => a + b, 0) / interpretedTimes.length;
console.log(`  Average: ${avgInterpreted.toFixed(0)}ms\n`);

// Benchmark JIT VM
console.log('Benchmarking JIT-compiled VM...');
clearJitCache();  // Start fresh
const vmJit = new RandomXVMJit(cache);

let jitTimes = [];
for (let i = 0; i < testInputs.length; i++) {
  const input = testInputs[i];
  const tempHash = blake2b(input, 64);

  vmJit.initScratchpad(tempHash);

  const start = Date.now();
  vmJit.run(tempHash);
  const elapsed = Date.now() - start;

  jitTimes.push(elapsed);
  console.log(`  Input ${i + 1}: ${elapsed}ms`);
}

const avgJit = jitTimes.reduce((a, b) => a + b, 0) / jitTimes.length;
console.log(`  Average: ${avgJit.toFixed(0)}ms`);
console.log(`  JIT cache stats: ${JSON.stringify(getJitCacheStats())}\n`);

// Results
console.log('Results');
console.log('=======');
console.log(`Interpreted: ${avgInterpreted.toFixed(0)}ms average`);
console.log(`JIT:         ${avgJit.toFixed(0)}ms average`);
console.log(`Speedup:     ${(avgInterpreted / avgJit).toFixed(2)}x`);

if (avgJit < avgInterpreted) {
  console.log(`\n✓ JIT is ${((1 - avgJit / avgInterpreted) * 100).toFixed(1)}% faster!`);
} else {
  console.log(`\n✗ JIT is ${((avgJit / avgInterpreted - 1) * 100).toFixed(1)}% slower (unexpected)`);
}
