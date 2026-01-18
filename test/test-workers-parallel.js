/**
 * Test Worker Threads Parallelism
 *
 * Verifies that worker threads actually run in parallel.
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { fileURLToPath } from 'url';

if (!isMainThread) {
  // Worker code
  const { workerId } = workerData;

  // Do CPU-intensive work
  let count = 0;
  const start = Date.now();

  // Count for 2 seconds
  while (Date.now() - start < 2000) {
    count++;
    // Simulate work
    for (let i = 0; i < 1000; i++) {
      Math.sqrt(i);
    }
  }

  parentPort.postMessage({ workerId, count });
} else {
  // Main thread
  async function runTest(numWorkers) {
    console.log(`\nTesting with ${numWorkers} worker(s)...`);

    const workerPath = fileURLToPath(import.meta.url);
    const promises = [];

    for (let i = 0; i < numWorkers; i++) {
      promises.push(new Promise((resolve, reject) => {
        const worker = new Worker(workerPath, {
          workerData: { workerId: i }
        });

        worker.on('message', (msg) => {
          resolve(msg);
          worker.terminate();
        });

        worker.on('error', reject);
      }));
    }

    const results = await Promise.all(promises);

    let totalCount = 0;
    for (const { workerId, count } of results) {
      console.log(`  Worker ${workerId}: ${count.toLocaleString()} iterations`);
      totalCount += count;
    }

    console.log(`  Total: ${totalCount.toLocaleString()} iterations`);
    return totalCount;
  }

  async function main() {
    console.log('Worker Threads Parallelism Test');
    console.log('================================');

    const result1 = await runTest(1);
    const result2 = await runTest(2);
    const result4 = await runTest(4);

    console.log('\nResults:');
    console.log(`  1 worker:  ${result1.toLocaleString()} iterations (baseline)`);
    console.log(`  2 workers: ${result2.toLocaleString()} iterations (${(result2 / result1).toFixed(2)}x)`);
    console.log(`  4 workers: ${result4.toLocaleString()} iterations (${(result4 / result1).toFixed(2)}x)`);

    if (result4 >= result1 * 2) {
      console.log('\n✓ Worker threads are running in parallel!');
    } else {
      console.log('\n✗ Worker threads may NOT be running in parallel');
      console.log('  Expected 4 workers to do at least 2x work of 1 worker');
    }
  }

  main().catch(console.error);
}
