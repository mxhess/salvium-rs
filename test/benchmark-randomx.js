/**
 * RandomX Performance Benchmark
 */

import { RandomXContext } from '../src/randomx/index.js';

async function benchmark() {
  console.log('RandomX Performance Benchmark');
  console.log('=============================\n');

  const ctx = new RandomXContext();

  console.log('Initializing cache (256MB)...');
  const initStart = Date.now();
  await ctx.init(new Uint8Array(32)); // 32-byte key
  const initTime = Date.now() - initStart;
  console.log(`Cache init: ${initTime}ms\n`);

  // Warm up
  console.log('Warming up (10 hashes)...');
  for (let i = 0; i < 10; i++) {
    ctx.hash(`warmup ${i}`);
  }

  // Benchmark
  const iterations = 100;
  console.log(`\nBenchmarking ${iterations} hashes...`);

  const hashes = [];
  const start = Date.now();

  for (let i = 0; i < iterations; i++) {
    const hash = ctx.hashHex(`benchmark input ${i}`);
    hashes.push(hash);
  }

  const elapsed = Date.now() - start;
  const hashesPerSecond = (iterations / elapsed) * 1000;

  console.log(`\nResults:`);
  console.log(`  Total time: ${elapsed}ms`);
  console.log(`  Hashes: ${iterations}`);
  console.log(`  Speed: ${hashesPerSecond.toFixed(2)} H/s`);
  console.log(`  Avg per hash: ${(elapsed / iterations).toFixed(2)}ms`);

  // Show sample hashes
  console.log(`\nSample hashes:`);
  console.log(`  [0]: ${hashes[0]}`);
  console.log(`  [1]: ${hashes[1]}`);
  console.log(`  [99]: ${hashes[99]}`);
}

benchmark().catch(console.error);
