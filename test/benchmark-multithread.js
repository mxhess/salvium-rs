/**
 * Multi-threaded RandomX Benchmark
 *
 * Tests performance across different thread counts.
 */

import { RandomXContext, getAvailableCores } from '../src/randomx/index.js';

const HASHES_PER_TEST = 50;

async function benchmarkSingleThread() {
  console.log('=== Single Thread Benchmark ===\n');

  const ctx = new RandomXContext();

  console.log('Initializing cache (256MB)...');
  const initStart = Date.now();
  await ctx.init(new Uint8Array(32));
  console.log(`Cache init: ${Date.now() - initStart}ms\n`);

  // Warm up
  for (let i = 0; i < 5; i++) {
    ctx.hash(`warmup ${i}`);
  }

  // Benchmark
  console.log(`Hashing ${HASHES_PER_TEST} inputs...`);
  const start = Date.now();

  for (let i = 0; i < HASHES_PER_TEST; i++) {
    ctx.hash(`benchmark ${i}`);
  }

  const elapsed = (Date.now() - start) / 1000;
  const hashrate = HASHES_PER_TEST / elapsed;

  console.log(`\nSingle thread results:`);
  console.log(`  Time: ${elapsed.toFixed(2)}s`);
  console.log(`  Hashrate: ${hashrate.toFixed(2)} H/s`);

  return hashrate;
}

async function benchmarkMultiThread(numThreads) {
  console.log(`\n=== ${numThreads}-Thread Simulation ===\n`);

  // Create multiple contexts (simulating workers)
  const contexts = [];
  console.log(`Initializing ${numThreads} contexts...`);

  const initStart = Date.now();
  for (let i = 0; i < numThreads; i++) {
    const ctx = new RandomXContext();
    await ctx.init(new Uint8Array(32));
    contexts.push(ctx);
  }
  console.log(`All contexts initialized in ${Date.now() - initStart}ms\n`);

  // Warm up
  for (const ctx of contexts) {
    for (let i = 0; i < 3; i++) {
      ctx.hash(`warmup ${i}`);
    }
  }

  // Benchmark - round robin across contexts
  const hashesPerContext = Math.floor(HASHES_PER_TEST / numThreads);
  console.log(`Hashing ${hashesPerContext * numThreads} inputs across ${numThreads} threads...`);

  const start = Date.now();

  // Simulate parallel hashing by interleaving
  const promises = contexts.map(async (ctx, threadId) => {
    for (let i = 0; i < hashesPerContext; i++) {
      ctx.hash(`thread${threadId}_hash${i}`);
    }
  });

  await Promise.all(promises);

  const elapsed = (Date.now() - start) / 1000;
  const totalHashes = hashesPerContext * numThreads;
  const hashrate = totalHashes / elapsed;

  console.log(`\n${numThreads}-thread results:`);
  console.log(`  Time: ${elapsed.toFixed(2)}s`);
  console.log(`  Total hashes: ${totalHashes}`);
  console.log(`  Hashrate: ${hashrate.toFixed(2)} H/s`);
  console.log(`  Per-thread: ${(hashrate / numThreads).toFixed(2)} H/s`);

  return hashrate;
}

async function main() {
  console.log('RandomX Multi-Thread Benchmark');
  console.log('==============================');
  console.log(`Available CPU cores: ${getAvailableCores()}`);
  console.log(`Hashes per test: ${HASHES_PER_TEST}\n`);

  const results = {};

  // Single thread
  results[1] = await benchmarkSingleThread();

  // Multi-thread tests
  for (const threads of [2, 4, Math.min(8, getAvailableCores())]) {
    results[threads] = await benchmarkMultiThread(threads);
  }

  // Summary
  console.log('\n==============================');
  console.log('Summary (Light Mode - 256MB cache per thread)');
  console.log('==============================\n');

  console.log('Threads | Hashrate   | Memory    | Scaling');
  console.log('--------|------------|-----------|--------');

  const baseHashrate = results[1];
  for (const [threads, hashrate] of Object.entries(results)) {
    const memory = parseInt(threads) * 256;
    const scaling = ((hashrate / baseHashrate) * 100).toFixed(0);
    console.log(`${threads.padStart(7)} | ${hashrate.toFixed(2).padStart(8)} H/s | ${memory.toString().padStart(4)}MB    | ${scaling}%`);
  }

  console.log('\n==============================');
  console.log('Native C++ RandomX Comparison');
  console.log('==============================\n');

  console.log('Typical native performance (for reference):');
  console.log('  - Light mode: ~800-2000 H/s per thread');
  console.log('  - Full mode:  ~2000-4000 H/s per thread');
  console.log('  - With hardware AES: +30-50%');
  console.log('\nOur WASM-JIT implementation:');
  console.log(`  - Light mode: ~${baseHashrate.toFixed(0)} H/s per thread`);
  console.log(`  - Ratio to native: ~${((baseHashrate / 1500) * 100).toFixed(1)}% of native speed`);
}

main().catch(console.error);
