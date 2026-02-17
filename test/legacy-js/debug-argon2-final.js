/**
 * Debug Argon2 final cache value after all 3 passes
 */

import { initCache } from '../src/randomx/argon2d-wasm.js';

// Helper to read little-endian uint64
function readLE64(memory, qwordIndex) {
  return memory[qwordIndex];
}

console.log('=== Testing Argon2d initCache (WASM) ===\n');

const key = new TextEncoder().encode("test key 000");
console.log('Key: test key 000');
console.log('Expected cacheMemory[0]: 0x191e0e1d23c02186');
console.log('\nInitializing cache...\n');

const startTime = Date.now();
const cache = await initCache(key, (completed, total, pass, slice) => {
  const percent = Math.floor(completed / total * 100);
  if (percent % 10 === 0) {
    process.stdout.write(`\rProgress: ${percent}% (pass ${pass + 1}/3, slice ${slice + 1}/4)`);
  }
});
const elapsed = Date.now() - startTime;
console.log(`\n\nCache initialized in ${elapsed}ms`);

// Check first qword
const cacheMemory0 = readLE64(cache, 0);
console.log('\ncacheMemory[0]:', '0x' + cacheMemory0.toString(16));
console.log('Expected:      ', '0x191e0e1d23c02186');
console.log('Match:', cacheMemory0 === 0x191e0e1d23c02186n);

// Check other test values
const cacheMemory1568413 = readLE64(cache, 1568413);
console.log('\ncacheMemory[1568413]:', '0x' + cacheMemory1568413.toString(16));
console.log('Expected:            ', '0xf1b62fe6210bf8b1');
console.log('Match:', cacheMemory1568413 === 0xf1b62fe6210bf8b1n);

// Check index 33554431 (this is the last qword)
const cacheLength = cache.length;
console.log('\nCache length:', cacheLength, 'qwords');
if (33554431 < cacheLength) {
  const cacheMemory33554431 = readLE64(cache, 33554431);
  console.log('cacheMemory[33554431]:', '0x' + cacheMemory33554431.toString(16));
  console.log('Expected:             ', '0x1f47f056d05cd99b');
  console.log('Match:', cacheMemory33554431 === 0x1f47f056d05cd99bn);
} else {
  console.log('Index 33554431 out of range (cache length:', cacheLength, ')');
}
