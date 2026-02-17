/**
 * True Multi-threaded RandomX Benchmark using Worker Threads
 */

import { Worker } from 'worker_threads';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { writeFileSync, unlinkSync } from 'fs';
import os from 'os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BENCHMARK_DURATION = 20000; // 20 seconds
const AVAILABLE_CORES = os.cpus().length;

// Write the worker code to a file
const workerCode = `
import { parentPort, workerData } from 'worker_threads';
import { randomx_init_cache, randomx_create_vm } from '../src/randomx/vendor/index.js';

let vm = null;
let hashes = 0;
let running = false;

async function init() {
  const seed = new Uint8Array(32);
  const cache = randomx_init_cache(seed);
  vm = randomx_create_vm(cache);
  parentPort.postMessage({ type: 'ready' });
}

function mine() {
  if (!running || !vm) return;

  // Hash batch
  for (let i = 0; i < 10 && running; i++) {
    vm.calculate_hash('benchmark input ' + hashes);
    hashes++;
  }

  if (running) {
    setImmediate(mine);
  }
}

parentPort.on('message', async (msg) => {
  if (msg.type === 'init') {
    await init();
  } else if (msg.type === 'start') {
    running = true;
    hashes = 0;
    mine();
  } else if (msg.type === 'stop') {
    running = false;
    parentPort.postMessage({ type: 'result', hashes });
  }
});
`;

const workerPath = join(__dirname, '_temp_benchmark_worker.js');

async function createWorker() {
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerPath);

    worker.once('message', (msg) => {
      if (msg.type === 'ready') {
        resolve(worker);
      }
    });

    worker.on('error', reject);
    worker.postMessage({ type: 'init' });
  });
}

async function benchmarkThreads(numThreads) {
  console.log(`\n=== Benchmarking ${numThreads} Worker Thread${numThreads > 1 ? 's' : ''} ===\n`);

  // Create workers
  console.log(`Creating ${numThreads} workers (each with 256MB cache)...`);
  const initStart = Date.now();

  const workers = [];
  for (let i = 0; i < numThreads; i++) {
    const worker = await createWorker();
    workers.push(worker);
    process.stdout.write(`\rWorker ${i + 1}/${numThreads} ready`);
  }

  const initTime = Date.now() - initStart;
  console.log(`\nAll workers initialized in ${initTime}ms\n`);

  // Start mining
  console.log(`Mining for ${BENCHMARK_DURATION / 1000} seconds...`);
  const startTime = Date.now();

  for (const worker of workers) {
    worker.postMessage({ type: 'start' });
  }

  // Wait for benchmark duration
  await new Promise(r => setTimeout(r, BENCHMARK_DURATION));

  // Stop and collect results
  const results = await Promise.all(workers.map(worker => {
    return new Promise(resolve => {
      worker.once('message', (msg) => {
        if (msg.type === 'result') {
          resolve(msg.hashes);
        }
      });
      worker.postMessage({ type: 'stop' });
    });
  }));

  const elapsed = (Date.now() - startTime) / 1000;
  const totalHashes = results.reduce((a, b) => a + b, 0);
  const hashrate = totalHashes / elapsed;

  // Terminate workers
  for (const worker of workers) {
    worker.terminate();
  }

  console.log(`\nResults (${numThreads} thread${numThreads > 1 ? 's' : ''}):`);
  console.log(`  Total hashes: ${totalHashes.toLocaleString()}`);
  console.log(`  Time: ${elapsed.toFixed(2)}s`);
  console.log(`  Hashrate: ${hashrate.toFixed(2)} H/s`);
  console.log(`  Per thread: ${(hashrate / numThreads).toFixed(2)} H/s`);
  console.log(`  Memory: ${numThreads * 256}MB`);

  return { threads: numThreads, hashrate, perThread: hashrate / numThreads };
}

async function main() {
  console.log('RandomX Worker Threads Benchmark');
  console.log('================================');
  console.log(`Available CPU cores: ${AVAILABLE_CORES}`);
  console.log(`Benchmark duration: ${BENCHMARK_DURATION / 1000}s per test\n`);

  // Write worker file
  writeFileSync(workerPath, workerCode);

  const results = [];

  try {
    // Test different thread counts
    const threadCounts = [1, 2, 4, Math.min(8, AVAILABLE_CORES)].filter((v, i, a) => a.indexOf(v) === i);

    for (const threads of threadCounts) {
      const result = await benchmarkThreads(threads);
      results.push(result);
    }

    // Summary
    console.log('\n================================');
    console.log('SUMMARY');
    console.log('================================\n');

    const baseline = results[0].hashrate;

    console.log('Threads | Hashrate    | Per-Thread  | Memory   | Scaling');
    console.log('--------|-------------|-------------|----------|--------');

    for (const r of results) {
      const scaling = ((r.hashrate / baseline) * 100).toFixed(0);
      console.log(
        `${r.threads.toString().padStart(7)} | ` +
        `${r.hashrate.toFixed(2).padStart(9)} H/s | ` +
        `${r.perThread.toFixed(2).padStart(9)} H/s | ` +
        `${(r.threads * 256).toString().padStart(4)}MB   | ` +
        `${scaling}%`
      );
    }

    console.log('\n================================');
    console.log('Performance Notes');
    console.log('================================\n');
    console.log(`Single-thread baseline: ${results[0].perThread.toFixed(2)} H/s`);
    console.log(`Best multi-thread: ${Math.max(...results.map(r => r.hashrate)).toFixed(2)} H/s`);
    console.log('\nScaling efficiency depends on:');
    console.log('  - Memory bandwidth (256MB cache per thread)');
    console.log('  - CPU cache architecture');
    console.log('  - WASM runtime overhead');

  } finally {
    // Clean up temp file
    try { unlinkSync(workerPath); } catch {}
  }
}

main().catch(console.error);
