/**
 * Debug Argon2 cache initialization
 * Test each step against expected reference values
 */

import { blake2b, blake2bHex } from '../src/blake2b.js';

// Helper to convert hex to bytes
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

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

// Store 32-bit LE
function store32LE(value) {
  const bytes = new Uint8Array(4);
  bytes[0] = value & 0xff;
  bytes[1] = (value >> 8) & 0xff;
  bytes[2] = (value >> 16) & 0xff;
  bytes[3] = (value >> 24) & 0xff;
  return bytes;
}

console.log('=== Debug Argon2 Cache Initialization ===\n');

// Expected values from reference:
// cacheMemory[0] = 0x191e0e1d23c02186
const EXPECTED_CACHE_0 = 0x191e0e1d23c02186n;

// Test parameters
const key = new TextEncoder().encode("test key 000");
const salt = new Uint8Array([0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x58, 0x03]); // "RandomX\x03"

// Argon2 parameters for RandomX
const lanes = 1;
const outLen = 0;
const mCost = 262144;
const tCost = 3;
const version = 0x13;
const type = 0; // Argon2d

console.log('Parameters:');
console.log('  Key:', new TextDecoder().decode(key), `(${key.length} bytes)`);
console.log('  Salt:', bytesToHex(salt), `(${salt.length} bytes)`);
console.log('  Lanes:', lanes);
console.log('  OutLen:', outLen);
console.log('  mCost:', mCost);
console.log('  tCost:', tCost);
console.log('  Version:', '0x' + version.toString(16));
console.log('  Type:', type, '(Argon2d)');
console.log();

// Step 1: Build H0 input
console.log('=== Step 1: Build H0 input ===');
const h0Input = new Uint8Array(
  4 + 4 + 4 + 4 + 4 + 4 + // 6 params
  4 + key.length +        // pwdlen + pwd
  4 + salt.length +       // saltlen + salt
  4 + 4                   // secretlen + adlen
);

let offset = 0;
h0Input.set(store32LE(lanes), offset); offset += 4;
h0Input.set(store32LE(outLen), offset); offset += 4;
h0Input.set(store32LE(mCost), offset); offset += 4;
h0Input.set(store32LE(tCost), offset); offset += 4;
h0Input.set(store32LE(version), offset); offset += 4;
h0Input.set(store32LE(type), offset); offset += 4;
h0Input.set(store32LE(key.length), offset); offset += 4;
h0Input.set(key, offset); offset += key.length;
h0Input.set(store32LE(salt.length), offset); offset += 4;
h0Input.set(salt, offset); offset += salt.length;
h0Input.set(store32LE(0), offset); offset += 4; // secretlen
h0Input.set(store32LE(0), offset); offset += 4; // adlen

console.log('H0 input (' + h0Input.length + ' bytes):');
console.log(bytesToHex(h0Input));
console.log();

// Step 2: Compute H0
console.log('=== Step 2: Compute H0 (initial hash) ===');
const h0 = blake2b(h0Input, 64);
console.log('H0 (' + h0.length + ' bytes):');
console.log(bytesToHex(h0));
console.log();

// Step 3: Build seed for first block (H0 || 0 || 0)
console.log('=== Step 3: Build seed for block 0 (H0 || 0 || 0) ===');
const seed = new Uint8Array(72);
seed.set(h0);
seed.set(store32LE(0), 64); // position = 0
seed.set(store32LE(0), 68); // lane = 0
console.log('Seed (' + seed.length + ' bytes):');
console.log(bytesToHex(seed));
console.log();

// Step 4: Compute blake2b_long(1024, seed)
console.log('=== Step 4: Compute blake2b_long(1024, seed) ===');

// Blake2b_long implementation
function blake2bLong(outLen, input) {
  // Prefix with output length as 32-bit LE
  const prefixed = new Uint8Array(4 + input.length);
  prefixed[0] = outLen & 0xff;
  prefixed[1] = (outLen >> 8) & 0xff;
  prefixed[2] = (outLen >> 16) & 0xff;
  prefixed[3] = (outLen >> 24) & 0xff;
  prefixed.set(input, 4);

  if (outLen <= 64) {
    return blake2b(prefixed, outLen);
  }

  const result = new Uint8Array(outLen);

  // First block
  let v = blake2b(prefixed, 64);
  result.set(v.subarray(0, 32), 0);

  let pos = 32;
  while (pos < outLen - 64) {
    v = blake2b(v, 64);
    result.set(v.subarray(0, 32), pos);
    pos += 32;
  }

  // Final block
  const remaining = outLen - pos;
  v = blake2b(v, remaining);
  result.set(v, pos);

  return result;
}

const block0Bytes = blake2bLong(1024, seed);
console.log('Block 0 first 64 bytes:');
console.log(bytesToHex(block0Bytes.slice(0, 64)));
console.log();

// Step 5: Extract first qword
console.log('=== Step 5: Extract first qword (cacheMemory[0]) ===');
const cacheMemory0 = readLE64(block0Bytes, 0);
console.log('cacheMemory[0]:', '0x' + cacheMemory0.toString(16));
console.log('Expected:      ', '0x' + EXPECTED_CACHE_0.toString(16));
console.log('Match:', cacheMemory0 === EXPECTED_CACHE_0);
console.log();

// Debug: Let's trace through blake2b_long more carefully
console.log('=== Debug blake2b_long steps ===');

// First, hash the prefixed input
const prefixed = new Uint8Array(4 + seed.length);
prefixed[0] = 1024 & 0xff;  // 0x00
prefixed[1] = (1024 >> 8) & 0xff;  // 0x04
prefixed[2] = (1024 >> 16) & 0xff;  // 0x00
prefixed[3] = (1024 >> 24) & 0xff;  // 0x00
prefixed.set(seed, 4);

console.log('Prefixed input first 80 bytes:');
console.log(bytesToHex(prefixed.slice(0, 80)));

const v1 = blake2b(prefixed, 64);
console.log('V1 (first 64-byte hash):');
console.log(bytesToHex(v1));
console.log('V1[0..31] -> output[0..31]:');
console.log(bytesToHex(v1.slice(0, 32)));

// Continue with next hash
const v2 = blake2b(v1, 64);
console.log('V2 (second 64-byte hash):');
console.log(bytesToHex(v2));
console.log('V2[0..31] -> output[32..63]:');
console.log(bytesToHex(v2.slice(0, 32)));

// Let's also check if the very first qword from v1 matches
const qword0FromV1 = readLE64(v1, 0);
console.log('\nFirst qword from V1:', '0x' + qword0FromV1.toString(16));

// Let's verify blake2b is working on a simple test vector
console.log('\n=== Blake2b test vectors ===');
const emptyHash = blake2b(new Uint8Array(0), 64);
console.log('blake2b("", 64):');
console.log(bytesToHex(emptyHash));
// Expected: 786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce

const abcHash = blake2b(new TextEncoder().encode("abc"), 64);
console.log('blake2b("abc", 64):');
console.log(bytesToHex(abcHash));
// Expected: ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923
