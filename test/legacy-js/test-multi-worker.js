/**
 * Test Multiple Workers
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { fileURLToPath } from 'url';

if (!isMainThread) {
  const { workerId, hashCount } = workerData;

  // Import and initialize
  const { randomx_init_cache, randomx_create_vm } = await import('../src/randomx/vendor/index.js');
  const seedHash = new TextEncoder().encode('test seed');
  const cache = randomx_init_cache(seedHash);
  const vm = randomx_create_vm(cache);

  // Pre-create template
  const template = new Uint8Array(76);
  const view = new DataView(template.buffer);

  parentPort.postMessage({ type: 'ready', workerId });

  // Handle messages
  parentPort.on('message', (msg) => {
    if (msg.type === 'start') {
      // Hash
      const start = Date.now();

      for (let i = 0; i < hashCount; i++) {
        view.setUint32(39, i, true);
        vm.calculate_hash(template);
      }

      const elapsed = Date.now() - start;
      parentPort.postMessage({ type: 'done', workerId, hashCount, elapsed });
    }
  });
} else {
  async function testWorkers(numWorkers, hashesPerWorker) {
    console.log(`\n--- ${numWorkers} worker(s), ${hashesPerWorker} hashes each ---`);

    const workerPath = fileURLToPath(import.meta.url);
    const workers = [];
    const readyPromises = [];

    const initStart = Date.now();

    for (let i = 0; i < numWorkers; i++) {
      const worker = new Worker(workerPath, {
        workerData: { workerId: i, hashCount: hashesPerWorker }
      });

      const ready = new Promise(r => {
        worker.on('message', (msg) => {
          if (msg.type === 'ready') r();
        });
      });

      workers.push(worker);
      readyPromises.push(ready);
    }

    await Promise.all(readyPromises);
    const initTime = Date.now() - initStart;
    console.log(`Init time: ${initTime}ms`);

    // Start all workers
    console.log('Starting workers...');
    const hashStart = Date.now();
    for (const w of workers) {
      w.postMessage({ type: 'start' });
    }
    console.log('Workers started, waiting for results...');

    // Wait for results
    const results = await Promise.all(workers.map(w => {
      return new Promise(r => {
        w.on('message', (msg) => {
          if (msg.type === 'done') {
            r(msg);
            w.terminate();
          }
        });
      });
    }));

    const totalTime = Date.now() - hashStart;
    let totalHashes = 0;
    for (const { workerId, hashCount, elapsed } of results) {
      console.log(`  Worker ${workerId}: ${hashCount} hashes in ${elapsed}ms`);
      totalHashes += hashCount;
    }

    const hps = totalHashes / (totalTime / 1000);
    console.log(`Total: ${totalHashes} hashes in ${totalTime}ms (${hps.toFixed(2)} H/s)`);
    return hps;
  }

  async function main() {
    console.log('Multi-Worker Hash Test');
    console.log('======================');

    const hashesPerWorker = 10;

    const hps1 = await testWorkers(1, hashesPerWorker);
    const hps2 = await testWorkers(2, hashesPerWorker);
    const hps4 = await testWorkers(4, hashesPerWorker);

    console.log('\n=== Summary ===');
    console.log(`1 worker:  ${hps1.toFixed(2)} H/s`);
    console.log(`2 workers: ${hps2.toFixed(2)} H/s (${(hps2/hps1).toFixed(2)}x)`);
    console.log(`4 workers: ${hps4.toFixed(2)} H/s (${(hps4/hps1).toFixed(2)}x)`);
  }

  main().catch(console.error);
}
