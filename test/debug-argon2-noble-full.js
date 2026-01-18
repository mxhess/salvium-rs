/**
 * Debug using @noble/hashes argon2 directly
 */

import { argon2d } from '@noble/hashes/argon2.js';

// Helper to convert bytes to hex
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper to read little-endian uint64
function readLE64(bytes, offset) {
  let val = 0n;
  for (let i = 0; i < 8; i++) {
    val |= BigInt(bytes[offset + i]) << BigInt(i * 8);
  }
  return val;
}

console.log('=== Test with @noble/hashes argon2d ===\n');

const key = new TextEncoder().encode("test key 000");
const salt = new Uint8Array([0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x58, 0x03]); // "RandomX\x03"

console.log('Key:', new TextDecoder().decode(key), `(${key.length} bytes)`);
console.log('Salt:', bytesToHex(salt), `(${salt.length} bytes)`);
console.log();

// RandomX uses Argon2d with:
// - Memory: 262144 KiB
// - Iterations (time cost): 3
// - Parallelism (lanes): 1
// - Output length: varies

// The noble argon2d function returns the hash output, not the memory
// For RandomX, we need the actual memory state after Argon2d

// Let's try to get the first 64 bytes of output
console.log('Testing noble argon2d with dkLen=64...');

try {
  const result = argon2d(key, salt, {
    t: 3,           // iterations
    m: 262144,      // memory in KiB
    p: 1,           // parallelism
    dkLen: 64       // output length
  });
  console.log('Result (64 bytes):', bytesToHex(result));
} catch (e) {
  console.log('Error:', e.message);
}

// But for RandomX, the cache is the actual Argon2d memory, not the output
// The Argon2d output is derived from the final block, which is different from what RandomX uses
// RandomX uses the raw memory blocks as the cache

console.log('\nNote: RandomX uses the raw Argon2d memory as cache, not the output hash.');
console.log('The expected cacheMemory[0] = 0x191e0e1d23c02186 is the first qword of the first block.');
console.log('This is NOT the same as the Argon2d hash output.');
