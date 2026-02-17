/**
 * Debug: Cache initialization only (no dataset)
 */

import { RandomXCache } from '../src/randomx/dataset.js';

console.log('=== Cache Init Test ===\n');

const key = new TextEncoder().encode('test key 000');

console.log('Initializing cache (256MB, 3 passes)...');
const startTime = Date.now();
const cache = new RandomXCache();

// Init
cache.init(key, (percent, pass, slice) => {
  if (percent % 25 === 0) {
    console.log(`Cache init: ${percent}% (pass ${pass + 1}, slice ${slice})`);
  }
});

const cacheTime = Date.now() - startTime;
console.log(`\nCache initialized in ${cacheTime}ms`);
console.log(`Cache memory size: ${cache.memory.length / 1024 / 1024}MB`);

// Check first few bytes
function readU64LE(bytes, offset = 0) {
  let val = 0n;
  for (let i = 0; i < 8; i++) {
    val |= BigInt(bytes[offset + i]) << BigInt(i * 8);
  }
  return val;
}

console.log(`\nCache memory[0] = 0x${readU64LE(cache.memory, 0).toString(16)}`);
console.log(`Expected:         0x191e0e1d23c02186`);
