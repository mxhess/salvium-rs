/**
 * Debug Argon2 using @noble/hashes blake2b for comparison
 */

import { blake2b as nobleBlake2b } from '@noble/hashes/blake2.js';
import { blake2b as myBlake2b } from '../src/blake2b.js';

// Helper to convert bytes to hex
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Store 32-bit LE
function store32LE(value) {
  const bytes = new Uint8Array(4);
  bytes[0] = value & 0xff;
  bytes[1] = (value >> 8) & 0xff;
  bytes[2] = (value >> 16) & 0xff;
  bytes[3] = (value >> 24) & 0xff;
  return bytes;
}

console.log('=== Compare Blake2b implementations ===\n');

// Test 1: Empty input
const emptyMy = myBlake2b(new Uint8Array(0), 64);
const emptyNoble = nobleBlake2b(new Uint8Array(0), { dkLen: 64 });
console.log('Empty input (my impl):   ', bytesToHex(emptyMy));
console.log('Empty input (noble):     ', bytesToHex(emptyNoble));
console.log('Match:', bytesToHex(emptyMy) === bytesToHex(emptyNoble));
console.log();

// Test 2: "abc"
const abc = new TextEncoder().encode("abc");
const abcMy = myBlake2b(abc, 64);
const abcNoble = nobleBlake2b(abc, { dkLen: 64 });
console.log('abc (my impl):   ', bytesToHex(abcMy));
console.log('abc (noble):     ', bytesToHex(abcNoble));
console.log('Match:', bytesToHex(abcMy) === bytesToHex(abcNoble));
console.log();

// Test 3: Build H0 input and compare
const key = new TextEncoder().encode("test key 000");
const salt = new Uint8Array([0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x58, 0x03]);

const h0Input = new Uint8Array(60);
let offset = 0;
h0Input.set(store32LE(1), offset); offset += 4;           // lanes
h0Input.set(store32LE(0), offset); offset += 4;           // outLen
h0Input.set(store32LE(262144), offset); offset += 4;      // mCost
h0Input.set(store32LE(3), offset); offset += 4;           // tCost
h0Input.set(store32LE(0x13), offset); offset += 4;        // version
h0Input.set(store32LE(0), offset); offset += 4;           // type
h0Input.set(store32LE(key.length), offset); offset += 4;  // pwdLen
h0Input.set(key, offset); offset += key.length;           // pwd
h0Input.set(store32LE(salt.length), offset); offset += 4; // saltLen
h0Input.set(salt, offset); offset += salt.length;         // salt
h0Input.set(store32LE(0), offset); offset += 4;           // secretLen
h0Input.set(store32LE(0), offset); offset += 4;           // adLen

console.log('H0 input:', bytesToHex(h0Input));
console.log();

const h0My = myBlake2b(h0Input, 64);
const h0Noble = nobleBlake2b(h0Input, { dkLen: 64 });
console.log('H0 (my impl):   ', bytesToHex(h0My));
console.log('H0 (noble):     ', bytesToHex(h0Noble));
console.log('Match:', bytesToHex(h0My) === bytesToHex(h0Noble));
console.log();

// Now test blake2b_long using noble's implementation
console.log('=== Test blake2b_long ===\n');

function blake2bLongNoble(outLen, input) {
  // Prefix with output length as 32-bit LE
  const prefixed = new Uint8Array(4 + input.length);
  prefixed[0] = outLen & 0xff;
  prefixed[1] = (outLen >> 8) & 0xff;
  prefixed[2] = (outLen >> 16) & 0xff;
  prefixed[3] = (outLen >> 24) & 0xff;
  prefixed.set(input, 4);

  if (outLen <= 64) {
    return nobleBlake2b(prefixed, { dkLen: outLen });
  }

  const result = new Uint8Array(outLen);

  // First block
  let v = nobleBlake2b(prefixed, { dkLen: 64 });
  result.set(v.subarray(0, 32), 0);

  let pos = 32;
  while (pos < outLen - 64) {
    v = nobleBlake2b(v, { dkLen: 64 });
    result.set(v.subarray(0, 32), pos);
    pos += 32;
  }

  // Final block
  const remaining = outLen - pos;
  v = nobleBlake2b(v, { dkLen: remaining });
  result.set(v, pos);

  return result;
}

// Build seed for first block (H0 || 0 || 0)
const seed = new Uint8Array(72);
seed.set(h0Noble);  // Use noble's H0
seed.set(store32LE(0), 64); // position = 0
seed.set(store32LE(0), 68); // lane = 0

console.log('Seed (H0||0||0):', bytesToHex(seed));
console.log();

const block0Noble = blake2bLongNoble(1024, seed);
console.log('Block 0 first 64 bytes (noble):', bytesToHex(block0Noble.slice(0, 64)));

// Read first qword
function readLE64(bytes, offset) {
  let val = 0n;
  for (let i = 0; i < 8; i++) {
    val |= BigInt(bytes[offset + i]) << BigInt(i * 8);
  }
  return val;
}

const cacheMemory0Noble = readLE64(block0Noble, 0);
console.log('cacheMemory[0] (noble):', '0x' + cacheMemory0Noble.toString(16));
console.log('Expected:              ', '0x191e0e1d23c02186');
console.log('Match:', cacheMemory0Noble === 0x191e0e1d23c02186n);
