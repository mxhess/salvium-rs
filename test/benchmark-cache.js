#!/usr/bin/env node
/**
 * Benchmark: JIT vs Interpreted Argon2d Cache Init
 *
 * Usage:
 *   source ~/.bash_profile && bun test/benchmark-cache.js
 */

import { initCache as argon2InitCache } from '../src/randomx/argon2d.js';
import { initCacheJit } from '../src/randomx/argon2d-jit.js';

console.log('Argon2d Cache Init Benchmark');
console.log('============================\n');

const key = new TextEncoder().encode('benchmark key');

const progress = (completed, total, pass, slice) => {
  const percent = Math.round((completed / total) * 100);
  const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));
  process.stdout.write(`\r[${bar}] ${percent}% (pass ${pass + 1}/3, slice ${slice + 1}/4)`);
};

// Test JIT version
console.log('Testing JIT-optimized Argon2d...');
const jitStart = Date.now();
const cacheJit = initCacheJit(key, progress);
const jitTime = (Date.now() - jitStart) / 1000;
process.stdout.write('\r' + ' '.repeat(60) + '\r');
console.log(`JIT time: ${jitTime.toFixed(1)}s`);
console.log(`Cache size: ${(cacheJit.length * 8 / 1024 / 1024).toFixed(0)}MB\n`);

// Test interpreted version
console.log('Testing Interpreted Argon2d...');
const interpStart = Date.now();
const cacheInterp = argon2InitCache(key, progress);
const interpTime = (Date.now() - interpStart) / 1000;
process.stdout.write('\r' + ' '.repeat(60) + '\r');
console.log(`Interpreted time: ${interpTime.toFixed(1)}s\n`);

// Verify results match
let match = cacheJit.length === cacheInterp.length;
if (match) {
  for (let i = 0; i < Math.min(1000, cacheJit.length); i++) {
    if (cacheJit[i] !== cacheInterp[i]) {
      match = false;
      break;
    }
  }
}
console.log(`Results match: ${match ? '✓' : '✗'}`);

// Summary
console.log('\nResults');
console.log('=======');
console.log(`JIT:         ${jitTime.toFixed(1)}s`);
console.log(`Interpreted: ${interpTime.toFixed(1)}s`);
console.log(`Speedup:     ${(interpTime / jitTime).toFixed(2)}x`);

if (jitTime < interpTime) {
  console.log(`\n✓ JIT is ${((1 - jitTime / interpTime) * 100).toFixed(1)}% faster!`);
} else {
  console.log(`\n✗ JIT is ${((jitTime / interpTime - 1) * 100).toFixed(1)}% slower`);
}
