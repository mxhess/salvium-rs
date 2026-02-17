/**
 * Debug: Test dataset item generation against C++ reference
 *
 * Expected from tests.cpp:
 *   datasetItem[0] = 0x680588a85ae222db
 */

import { RandomXCache, initDatasetItem } from '../src/randomx/dataset.js';

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function readU64LE(bytes, offset = 0) {
  let val = 0n;
  for (let i = 0; i < 8; i++) {
    val |= BigInt(bytes[offset + i]) << BigInt(i * 8);
  }
  return val;
}

console.log('=== Dataset Item Generation Debug ===\n');

const key = new TextEncoder().encode('test key 000');

console.log('Initializing cache (256MB, 3 passes)...');
const startTime = Date.now();
const cache = new RandomXCache();
cache.init(key, (percent, pass, slice) => {
  if (percent % 10 === 0) {
    process.stdout.write(`\rCache init: ${percent}% (pass ${pass + 1}, slice ${slice})`);
  }
});
const cacheTime = Date.now() - startTime;
console.log(`\rCache initialized in ${cacheTime}ms                                    `);
console.log(`Cache memory size: ${cache.memory.length / 1024 / 1024}MB`);
console.log(`Cache memory[0] = 0x${readU64LE(cache.memory, 0).toString(16)}`);
console.log(`Expected:         0x191e0e1d23c02186`);
console.log();

// Generate dataset item 0
console.log('Generating dataset item 0...');
const item0 = initDatasetItem(cache, 0);

// First qword of item 0
const item0Qword = readU64LE(item0, 0);

console.log(`Dataset item 0 (first 64 bytes):`);
console.log(`  ${bytesToHex(item0.slice(0, 32))}`);
console.log(`  ${bytesToHex(item0.slice(32, 64))}`);
console.log();
console.log(`First qword: 0x${item0Qword.toString(16)}`);
console.log(`Expected:    0x680588a85ae222db`);
console.log(`Match: ${item0Qword === 0x680588a85ae222dbn}`);
