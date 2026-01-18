/**
 * Debug: Basic AES round function test
 */

import { fillAes1Rx4 } from '../src/randomx/aes.js';

function bytesToHex(bytes, limit = bytes.length) {
  return Array.from(bytes.slice(0, limit)).map(b => b.toString(16).padStart(2, '0')).join('');
}

console.log('=== AES Basic Test ===\n');

// Test seed (64 bytes of zeros)
const seed = new Uint8Array(64);

// Test with small output size
const size = 128;  // 2 iterations
console.log(`Testing fillAes1Rx4 with ${size} byte output...`);

const output = fillAes1Rx4(seed, new Uint8Array(size));

console.log(`Output (${output.length} bytes):`);
console.log(`  First 64: ${bytesToHex(output, 64)}`);
console.log(`  Second 64: ${bytesToHex(output.slice(64, 128))}`);
console.log('\nTest completed.');
