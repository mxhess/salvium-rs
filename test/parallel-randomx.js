#!/usr/bin/env node
/**
 * Test RandomX light mode (cache only)
 *
 * Usage:
 *   bun test/parallel-randomx.js
 *   bun test/parallel-randomx.js --full   # Full 2GB dataset mode
 */

import { LightDataset, ParallelDataset, getCpuCount } from '../src/randomx/parallel.js';

const args = process.argv.slice(2);
const fullMode = args.includes('--full');

console.log(`CPU cores available: ${getCpuCount()}`);
console.log(`Mode: ${fullMode ? 'Full (2GB dataset)' : 'Light (256MB cache)'}\n`);

const key = new TextEncoder().encode('test key for randomx');

const dataset = fullMode ? new ParallelDataset() : new LightDataset();

try {
  const startTime = Date.now();
  await dataset.init(key);
  const elapsed = (Date.now() - startTime) / 1000;

  console.log(`\nInitialization completed in ${elapsed.toFixed(1)}s`);

  // Test that dataset items are accessible
  console.log('\nTesting dataset item access...');
  const item0 = dataset.getItem(0);
  const item1000 = dataset.getItem(1000);

  console.log(`Item 0:    ${Array.from(item0.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);
  console.log(`Item 1000: ${Array.from(item1000.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);

  console.log('\nRandomX test complete!');
} catch (err) {
  console.error('\nError:', err.message);
  console.error(err.stack);
  process.exit(1);
} finally {
  dataset.destroy();
}
