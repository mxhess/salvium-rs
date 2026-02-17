/**
 * Test Worker Initialization Time
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { fileURLToPath } from 'url';

if (!isMainThread) {
  const { workerId } = workerData;
  const startTime = Date.now();

  parentPort.postMessage({ type: 'started', workerId });

  // Import the module
  const { randomx_init_cache, randomx_create_vm } = await import('../src/randomx/vendor/index.js');
  parentPort.postMessage({ type: 'imported', workerId, time: Date.now() - startTime });

  // Initialize cache
  const seedHash = new TextEncoder().encode('test seed');
  const cache = randomx_init_cache(seedHash);
  parentPort.postMessage({ type: 'cache_ready', workerId, time: Date.now() - startTime });

  // Create VM
  const vm = randomx_create_vm(cache);
  parentPort.postMessage({ type: 'vm_ready', workerId, time: Date.now() - startTime });

  // Do one hash
  const hash = vm.calculate_hash(new Uint8Array(76));
  parentPort.postMessage({ type: 'hashed', workerId, time: Date.now() - startTime });

  parentPort.postMessage({ type: 'done', workerId, totalTime: Date.now() - startTime });
} else {
  async function main() {
    console.log('Worker Initialization Test');
    console.log('==========================\n');

    const workerPath = fileURLToPath(import.meta.url);

    const worker = new Worker(workerPath, {
      workerData: { workerId: 0 }
    });

    worker.on('message', (msg) => {
      console.log(`[${msg.type}] Worker ${msg.workerId}: ${msg.time || msg.totalTime || ''}ms`);

      if (msg.type === 'done') {
        worker.terminate();
        console.log('\nDone!');
      }
    });

    worker.on('error', (err) => {
      console.error('Worker error:', err);
    });
  }

  main().catch(console.error);
}
