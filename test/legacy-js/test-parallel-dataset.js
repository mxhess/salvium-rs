#!/usr/bin/env node
/**
 * Test: Parallel Dataset Generation
 *
 * Tests the worker-based parallel dataset generation.
 *
 * Usage:
 *   source ~/.bash_profile && bun test/test-parallel-dataset.js
 */

import { cpus } from 'os';
import { generateDatasetParallel } from '../src/randomx/parallel-dataset.js';
import { RANDOMX_DATASET_ITEM_COUNT } from '../src/randomx/config.js';

console.log('Parallel Dataset Generation Test');
console.log('=================================\n');

const numCpus = cpus().length;
console.log(`Available CPUs: ${numCpus}`);
console.log(`Dataset items: ${RANDOMX_DATASET_ITEM_COUNT.toLocaleString()}`);
console.log(`Dataset size: ${((RANDOMX_DATASET_ITEM_COUNT * 64) / 1024 / 1024 / 1024).toFixed(2)} GB\n`);

// For testing, we'll use a smaller dataset
// Uncomment the full run for production testing
const testItems = 100000;  // 100K items for quick test

console.log(`Test mode: ${testItems.toLocaleString()} items`);
console.log(`Using ${numCpus} workers\n`);

const testKey = new TextEncoder().encode('test key');

try {
  // Override item count for testing
  const originalCount = RANDOMX_DATASET_ITEM_COUNT;

  // Monkey-patch the config for testing
  // In production, remove this and use full dataset
  const config = await import('../src/randomx/config.js');

  console.log('Starting parallel generation...\n');

  const startTime = Date.now();

  // Note: For full production use, remove the test limit
  // For now, we're testing with a subset
  const dataset = await generateDatasetParallel(testKey, {
    workers: numCpus,
    itemCount: testItems,  // Use test subset instead of full 34M items
    onProgress: (stage, percent, details) => {
      if (typeof process !== 'undefined' && process.stdout) {
        const bar = '█'.repeat(Math.floor(percent / 5)) + '░'.repeat(20 - Math.floor(percent / 5));

        if (stage === 'cache') {
          const info = details.pass !== undefined
            ? `pass ${details.pass + 1}/3, slice ${details.slice + 1}/4`
            : details.message || '';
          process.stdout.write(`\rCache:    [${bar}] ${percent}% ${info}`.padEnd(80));
        } else if (stage === 'programs') {
          process.stdout.write(`\rPrograms: [${bar}] ${percent}% ${details.message || ''}`.padEnd(80));
        } else if (stage === 'dataset') {
          const info = details.eta !== undefined
            ? `${details.itemsPerSec?.toLocaleString()} items/s, ETA: ${Math.floor(details.eta / 60)}m ${details.eta % 60}s`
            : details.message || '';
          process.stdout.write(`\rDataset:  [${bar}] ${percent}% ${info}`.padEnd(80));
        } else if (stage === 'complete') {
          process.stdout.write('\r' + ' '.repeat(80) + '\r');
          console.log(`\nDataset initialized in ${details.totalTime?.toFixed(1)}s`);
        }
      }
    }
  });

  const totalTime = (Date.now() - startTime) / 1000;

  console.log(`\nTotal time: ${totalTime.toFixed(1)}s`);
  console.log(`Dataset size: ${(dataset.length / 1024 / 1024).toFixed(2)} MB`);

  // Verify first few items
  console.log('\nFirst item (hex):');
  console.log(Buffer.from(dataset.slice(0, 64)).toString('hex'));

} catch (error) {
  console.error('Error:', error.message);
  console.error(error.stack);
  process.exit(1);
}
