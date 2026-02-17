/**
 * Test full mode worker directly
 */

import { Worker } from 'worker_threads';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomx_init_cache, randomx_superscalarhash } from '../src/randomx/vendor/index.js';
import { RANDOMX_DATASET_ITEM_COUNT } from '../src/randomx/full-mode.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WORKER_PATH = join(__dirname, '../src/stratum/mining-worker-asm.js');

const TEST_SEED = '33d64e8899b07bcc1234567890abcdef1234567890abcdef1234567890abcdef';

async function main() {
  console.log('=== Full Mode Worker Test ===\n');

  // Generate a small test dataset
  console.log('Generating small test dataset (1000 items)...');
  const TEST_ITEMS = 1000;
  
  const seedBytes = Buffer.from(TEST_SEED, 'hex');
  const cache = randomx_init_cache(seedBytes);
  const ssHash = randomx_superscalarhash(cache);
  
  // Use SharedArrayBuffer
  const datasetSize = RANDOMX_DATASET_ITEM_COUNT * 8 * 8;
  console.log('Creating SharedArrayBuffer of size:', datasetSize);
  
  try {
    const sharedBuffer = new SharedArrayBuffer(datasetSize);
    const datasetView = new BigInt64Array(sharedBuffer);
    
    // Only fill first 1000 items for testing
    for (let i = 0; i < TEST_ITEMS; i++) {
      const item = ssHash(BigInt(i));
      const offset = i * 8;
      for (let j = 0; j < 8; j++) {
        datasetView[offset + j] = item[j];
      }
    }
    console.log('Test dataset ready\n');
    
    // Create worker
    console.log('Creating worker...');
    const worker = new Worker(WORKER_PATH, {
      workerData: { workerId: 0, mode: 'full' }
    });
    
    worker.on('message', (msg) => {
      console.log('Worker message:', msg);
    });
    
    worker.on('error', (err) => {
      console.error('Worker error:', err);
    });
    
    // Wait for ready
    await new Promise(resolve => {
      worker.once('message', (msg) => {
        if (msg.type === 'ready') {
          console.log('Worker ready');
          resolve();
        }
      });
    });
    
    // Send job with dataset
    console.log('\nSending job to worker...');
    const testJob = {
      job_id: 'test123',
      blob: '0707a5e28db705ede4b8bef6e9dbf2f0d2e2d0d0e5d0d4b8e0d5d0c8c0d0d4b8e5e0c0d0d0c0b8e0e0d0d0b8c0e0d4d0b8',
      target: 'ffffff00',
      height: 12345
    };
    
    worker.postMessage({
      type: 'job',
      job: testJob,
      seedHash: TEST_SEED,
      startNonce: 0,
      dataset: sharedBuffer
    });
    
    // Wait a bit and check hash count
    console.log('Waiting 3 seconds for hashes...');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    worker.postMessage({ type: 'getHashCount' });
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Stop worker
    worker.postMessage({ type: 'stop' });
    await new Promise(resolve => setTimeout(resolve, 500));
    
    worker.terminate();
    console.log('\nTest complete');
    
  } catch (err) {
    console.error('Error:', err);
  }
}

main().catch(console.error);
