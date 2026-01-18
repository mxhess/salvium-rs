/**
 * Test RandomX Parallel Hashing
 *
 * Verifies that RandomX hashing scales across worker threads.
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { fileURLToPath } from 'url';

if (!isMainThread) {
  // Worker code
  const { workerId, duration } = workerData;

  // Dynamic import to ensure fresh module load
  const { randomx_init_cache, randomx_create_vm } = await import('../src/randomx/vendor/index.js');

  // Initialize RandomX
  const seedHash = new TextEncoder().encode('test seed hash');
  const cache = randomx_init_cache(seedHash);
  const vm = randomx_create_vm(cache);

  parentPort.postMessage({ type: 'ready', workerId });

  // Wait for start signal
  await new Promise(resolve => {
    parentPort.on('message', (msg) => {
      if (msg.type === 'start') resolve();
    });
  });

  // Hash for specified duration
  let hashCount = 0;
  const template = new Uint8Array(76);
  const view = new DataView(template.buffer);

  const start = Date.now();
  while (Date.now() - start < duration) {
    view.setUint32(39, hashCount, true);
    vm.calculate_hash(template);
    hashCount++;
  }

  parentPort.postMessage({ type: 'done', workerId, hashCount });
} else {
  // Main thread
  async function runTest(numWorkers, durationMs = 5000) {
    console.log(`\nTesting with ${numWorkers} worker(s) for ${durationMs / 1000}s...`);

    const workerPath = fileURLToPath(import.meta.url);
    const workers = [];
    const readyPromises = [];

    // Create workers
    for (let i = 0; i < numWorkers; i++) {
      const worker = new Worker(workerPath, {
        workerData: { workerId: i, duration: durationMs }
      });

      const ready = new Promise((resolve) => {
        worker.on('message', (msg) => {
          if (msg.type === 'ready') {
            console.log(`  Worker ${i} initialized`);
            resolve();
          }
        });
      });

      workers.push(worker);
      readyPromises.push(ready);
    }

    // Wait for all workers to initialize
    await Promise.all(readyPromises);
    console.log('  All workers ready, starting hash test...');

    // Start all workers simultaneously
    const start = Date.now();
    for (const worker of workers) {
      worker.postMessage({ type: 'start' });
    }

    // Collect results
    const results = await Promise.all(workers.map((worker, i) => {
      return new Promise((resolve) => {
        worker.on('message', (msg) => {
          if (msg.type === 'done') {
            resolve(msg);
            worker.terminate();
          }
        });
      });
    }));

    const elapsed = (Date.now() - start) / 1000;

    let totalHashes = 0;
    for (const { workerId, hashCount } of results) {
      const hps = (hashCount / elapsed).toFixed(2);
      console.log(`  Worker ${workerId}: ${hashCount} hashes (${hps} H/s)`);
      totalHashes += hashCount;
    }

    const totalHps = totalHashes / elapsed;
    console.log(`  Total: ${totalHashes} hashes (${totalHps.toFixed(2)} H/s)`);

    return { totalHashes, hps: totalHps, elapsed };
  }

  async function main() {
    console.log('RandomX Parallel Hashing Test');
    console.log('=============================');
    console.log('Testing if RandomX WASM runs in parallel across workers');
    console.log('(Each hash takes ~100ms, using 3s test windows)\n');

    const result1 = await runTest(1, 3000);
    const result2 = await runTest(2, 3000);
    const result4 = await runTest(4, 3000);

    console.log('\n=== Results ===');
    console.log(`  1 worker:  ${result1.hps.toFixed(2)} H/s (baseline)`);
    console.log(`  2 workers: ${result2.hps.toFixed(2)} H/s (${(result2.hps / result1.hps).toFixed(2)}x)`);
    console.log(`  4 workers: ${result4.hps.toFixed(2)} H/s (${(result4.hps / result1.hps).toFixed(2)}x)`);

    if (result4.hps >= result1.hps * 2) {
      console.log('\n✓ RandomX hashing scales across workers!');
    } else {
      console.log('\n✗ RandomX hashing does NOT scale across workers');
      console.log('  This indicates the WASM module may have shared state');
    }
  }

  main().catch(console.error);
}
