/**
 * Debug: Scratchpad initialization test
 */

import { fillAes1Rx4 } from '../src/randomx/aes.js';
import { blake2b } from '../src/blake2b.js';

function bytesToHex(bytes, limit = bytes.length) {
  return Array.from(bytes.slice(0, limit)).map(b => b.toString(16).padStart(2, '0')).join('');
}

console.log('=== Scratchpad Init Test ===\n');

// Generate seed from input
const input = new TextEncoder().encode('This is a test');
const seed = blake2b(input, 64);

console.log(`Seed (64 bytes): ${bytesToHex(seed)}`);

// Small scratchpad first
console.log('\nTesting small scratchpad (2KB)...');
const startSmall = Date.now();
const smallOutput = fillAes1Rx4(seed, new Uint8Array(2048));
console.log(`Time: ${Date.now() - startSmall}ms`);
console.log(`Output hash: ${bytesToHex(blake2b(smallOutput, 32))}`);

// Medium scratchpad
console.log('\nTesting medium scratchpad (256KB)...');
const startMed = Date.now();
const medOutput = fillAes1Rx4(seed, new Uint8Array(262144));
console.log(`Time: ${Date.now() - startMed}ms`);
console.log(`Output hash: ${bytesToHex(blake2b(medOutput, 32))}`);

// Full scratchpad (2MB)
console.log('\nTesting full scratchpad (2MB)...');
const startFull = Date.now();
const fullOutput = fillAes1Rx4(seed, new Uint8Array(2097152));
console.log(`Time: ${Date.now() - startFull}ms`);
console.log(`Output hash: ${bytesToHex(blake2b(fullOutput, 32))}`);

console.log('\nDone!');
