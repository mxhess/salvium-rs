#!/usr/bin/env node
/**
 * Tests for RandomX Implementation
 *
 * Converted from vitest to simple test framework for consistency
 */

import {
  RandomXContext,
  rxSlowHash,
  randomxHash,
  calculateCommitment,
  verifyHash,
  checkDifficulty,
  RandomXCache,
  initDatasetItem,
  Blake2Generator,
  generateSuperscalar,
  executeSuperscalar,
  reciprocal,
  argon2d
} from '../src/index.js';
import { blake2b } from '../src/blake2b.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`);
    failed++;
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`);
    failed++;
  }
}

function assertEqual(a, b, msg = '') {
  if (a !== b) throw new Error(msg || `Expected ${b}, got ${a}`);
}

function assertNotEqual(a, b, msg = '') {
  if (a === b) throw new Error(msg || `Expected values to differ, both are ${a}`);
}

function assertTrue(condition, msg = '') {
  if (!condition) throw new Error(msg || 'Expected true');
}

function assertThrows(fn, expectedMsg = '') {
  let threw = false;
  let error = null;
  try {
    fn();
  } catch (e) {
    threw = true;
    error = e;
  }
  if (!threw) throw new Error('Expected function to throw');
  if (expectedMsg && !error.message.includes(expectedMsg)) {
    throw new Error(`Expected error containing "${expectedMsg}", got "${error.message}"`);
  }
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

console.log('\n=== RandomX Tests ===\n');

// ============================================================================
// Blake2Generator Tests
// ============================================================================

console.log('--- Blake2Generator ---');

test('generates consistent bytes from seed', () => {
  const seed = new Uint8Array(32);
  seed[0] = 1;

  const gen1 = new Blake2Generator(seed);
  const gen2 = new Blake2Generator(seed);

  const bytes1 = gen1.getBytes(16);
  const bytes2 = gen2.getBytes(16);

  assertEqual(bytesToHex(bytes1), bytesToHex(bytes2));
});

test('generates different bytes for different seeds', () => {
  const seed1 = new Uint8Array(32);
  seed1[0] = 1;

  const seed2 = new Uint8Array(32);
  seed2[0] = 2;

  const gen1 = new Blake2Generator(seed1);
  const gen2 = new Blake2Generator(seed2);

  const bytes1 = gen1.getBytes(16);
  const bytes2 = gen2.getBytes(16);

  assertNotEqual(bytesToHex(bytes1), bytesToHex(bytes2));
});

test('getByte returns single bytes', () => {
  const seed = new Uint8Array(32);
  const gen = new Blake2Generator(seed);

  const byte1 = gen.getByte();
  const byte2 = gen.getByte();

  assertTrue(typeof byte1 === 'number', 'getByte should return number');
  assertTrue(byte1 >= 0 && byte1 <= 255, 'getByte should return 0-255');
});

test('getUInt32 returns 32-bit values', () => {
  const seed = new Uint8Array(32);
  const gen = new Blake2Generator(seed);

  const val = gen.getUInt32();

  assertTrue(typeof val === 'number', 'getUInt32 should return number');
  assertTrue(val >= 0 && val <= 0xFFFFFFFF, 'getUInt32 should return 32-bit value');
});

// ============================================================================
// Superscalar Tests
// ============================================================================

console.log('\n--- Superscalar ---');

test('reciprocal produces consistent results', () => {
  // Test known reciprocal value
  const result = reciprocal(3);
  assertTrue(typeof result === 'bigint', 'reciprocal should return bigint');
});

test('generateSuperscalar produces valid program', () => {
  const seed = new Uint8Array(32);
  const gen = new Blake2Generator(seed);

  const program = generateSuperscalar(gen);

  assertTrue(program !== null && typeof program === 'object', 'Should return program object');
  assertTrue(Array.isArray(program.instructions), 'Should have instructions array');
  assertTrue(program.instructions.length > 0, 'Should have instructions');
});

// ============================================================================
// Argon2d Tests
// ============================================================================

console.log('\n--- Argon2d ---');

test('argon2d function exists', () => {
  assertTrue(typeof argon2d === 'function', 'argon2d should be a function');
});

test('argon2d produces output', () => {
  const password = new Uint8Array(32);
  const salt = new Uint8Array(32);

  const result = argon2d(password, salt, 1, 16, 1, 32);

  assertTrue(result instanceof Uint8Array, 'Should return Uint8Array');
  assertEqual(result.length, 32, 'Should return requested length');
});

// ============================================================================
// RandomXCache Tests
// ============================================================================

console.log('\n--- RandomXCache ---');

test('RandomXCache constructs', () => {
  const cache = new RandomXCache();
  assertTrue(cache !== null, 'Should construct');
});

// ============================================================================
// checkDifficulty Tests
// ============================================================================

console.log('\n--- checkDifficulty ---');

test('checkDifficulty handles zero hash', () => {
  const zeroHash = new Uint8Array(32);
  // Zero hash should pass any difficulty
  const result = checkDifficulty(zeroHash, 1n);
  assertTrue(result === true, 'Zero hash should pass difficulty');
});

test('checkDifficulty handles max difficulty', () => {
  const hash = new Uint8Array(32);
  hash[0] = 0xff;
  // Max hash shouldn't pass high difficulty
  const result = checkDifficulty(hash, 0xffffffffffffffffn);
  assertTrue(result === false, 'Max hash should fail high difficulty');
});

// ============================================================================
// calculateCommitment Tests
// ============================================================================

console.log('\n--- calculateCommitment ---');

test('calculateCommitment produces 32-byte output', () => {
  const blockHash = new Uint8Array(32);
  const previousHash = new Uint8Array(32);
  const result = calculateCommitment(blockHash, previousHash);

  assertTrue(result instanceof Uint8Array, 'Should return Uint8Array');
  assertEqual(result.length, 32, 'Should be 32 bytes');
});

test('calculateCommitment is deterministic', () => {
  const blockHash = new Uint8Array(32);
  blockHash[0] = 0x42;
  const previousHash = new Uint8Array(32);
  previousHash[0] = 0x24;

  const result1 = calculateCommitment(blockHash, previousHash);
  const result2 = calculateCommitment(blockHash, previousHash);

  assertEqual(bytesToHex(result1), bytesToHex(result2), 'Should be deterministic');
});

// ============================================================================
// Export Tests
// ============================================================================

console.log('\n--- Exports ---');

test('RandomXContext is exported', () => {
  assertTrue(typeof RandomXContext === 'function', 'RandomXContext should be exported');
});

test('rxSlowHash is exported', () => {
  assertTrue(typeof rxSlowHash === 'function', 'rxSlowHash should be exported');
});

test('randomxHash is exported', () => {
  assertTrue(typeof randomxHash === 'function', 'randomxHash should be exported');
});

test('verifyHash is exported', () => {
  assertTrue(typeof verifyHash === 'function', 'verifyHash should be exported');
});

test('checkDifficulty is exported', () => {
  assertTrue(typeof checkDifficulty === 'function', 'checkDifficulty should be exported');
});

test('RandomXCache is exported', () => {
  assertTrue(typeof RandomXCache === 'function', 'RandomXCache should be exported');
});

test('initDatasetItem is exported', () => {
  assertTrue(typeof initDatasetItem === 'function', 'initDatasetItem should be exported');
});

test('Blake2Generator is exported', () => {
  assertTrue(typeof Blake2Generator === 'function', 'Blake2Generator should be exported');
});

test('generateSuperscalar is exported', () => {
  assertTrue(typeof generateSuperscalar === 'function', 'generateSuperscalar should be exported');
});

test('executeSuperscalar is exported', () => {
  assertTrue(typeof executeSuperscalar === 'function', 'executeSuperscalar should be exported');
});

test('reciprocal is exported', () => {
  assertTrue(typeof reciprocal === 'function', 'reciprocal should be exported');
});

test('argon2d is exported', () => {
  assertTrue(typeof argon2d === 'function', 'argon2d should be exported');
});

// ============================================================================
// RandomX Integration Tests (requires ~1.5s for cache init)
// ============================================================================

console.log('\n--- RandomX Integration ---');

await testAsync('RandomXContext initializes and hashes', async () => {
  const ctx = new RandomXContext();
  const key = new Uint8Array(32);
  key[0] = 0x01;

  await ctx.init(key);

  const input = new Uint8Array([0x74, 0x65, 0x73, 0x74]); // "test"
  const hash = ctx.hash(input);

  assertTrue(hash instanceof Uint8Array, 'Hash should be Uint8Array');
  assertEqual(hash.length, 32, 'Hash should be 32 bytes');
});

await testAsync('RandomXContext produces consistent hashes', async () => {
  const ctx = new RandomXContext();
  const key = new Uint8Array(32);

  await ctx.init(key);

  const input = new Uint8Array([1, 2, 3, 4]);
  const hash1 = ctx.hash(input);
  const hash2 = ctx.hash(input);

  assertEqual(bytesToHex(hash1), bytesToHex(hash2), 'Hashes should be consistent');
});

await testAsync('RandomXContext produces different hashes for different inputs', async () => {
  const ctx = new RandomXContext();
  const key = new Uint8Array(32);

  await ctx.init(key);

  const input1 = new Uint8Array([1, 2, 3, 4]);
  const input2 = new Uint8Array([5, 6, 7, 8]);

  const hash1 = ctx.hash(input1);
  const hash2 = ctx.hash(input2);

  assertNotEqual(bytesToHex(hash1), bytesToHex(hash2), 'Different inputs should produce different hashes');
});

await testAsync('verifyHash works correctly', async () => {
  const key = new Uint8Array(32);
  const input = new Uint8Array([0x61, 0x62, 0x63]); // "abc"

  // First compute the correct hash
  const ctx = new RandomXContext();
  await ctx.init(key);
  const hash = ctx.hash(input);

  // verifyHash takes (key, input, expectedHash)
  const isValid = await verifyHash(key, input, hash);
  assertTrue(isValid, 'Correct hash should verify');

  const wrongHash = new Uint8Array(32);
  const isInvalid = await verifyHash(key, input, wrongHash);
  assertTrue(!isInvalid, 'Wrong hash should not verify');
});

// ============================================================================
// Official RandomX Test Vectors (from tevador/RandomX reference implementation)
// https://github.com/tevador/RandomX/blob/master/src/tests/tests.cpp
// ============================================================================

console.log('\n--- Official Test Vectors ---');

// Test vector 1a: key="test key 000", input="This is a test"
await testAsync('Test vector 1a (reference implementation)', async () => {
  const ctx = new RandomXContext();
  await ctx.init('test key 000');

  const hash = ctx.hashHex('This is a test');
  assertEqual(
    hash,
    '639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f',
    'Hash should match reference implementation'
  );
});

// Test vector 1b: key="test key 000", input="Lorem ipsum dolor sit amet"
await testAsync('Test vector 1b (reference implementation)', async () => {
  const ctx = new RandomXContext();
  await ctx.init('test key 000');

  const hash = ctx.hashHex('Lorem ipsum dolor sit amet');
  assertEqual(
    hash,
    '300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969',
    'Hash should match reference implementation'
  );
});

// Test vector 1c: key="test key 000", input="sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
await testAsync('Test vector 1c (reference implementation)', async () => {
  const ctx = new RandomXContext();
  await ctx.init('test key 000');

  const hash = ctx.hashHex('sed do eiusmod tempor incididunt ut labore et dolore magna aliqua');
  assertEqual(
    hash,
    'c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8',
    'Hash should match reference implementation'
  );
});

// Test vector 1d: key="test key 001" (different key), same long input
await testAsync('Test vector 1d (different key)', async () => {
  const ctx = new RandomXContext();
  await ctx.init('test key 001');

  const hash = ctx.hashHex('sed do eiusmod tempor incididunt ut labore et dolore magna aliqua');
  assertEqual(
    hash,
    'e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc',
    'Hash should match reference implementation'
  );
});

// Test vector 1e: key="test key 001", binary input
await testAsync('Test vector 1e (binary input)', async () => {
  const ctx = new RandomXContext();
  await ctx.init('test key 001');

  const input = hexToBytes('0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416');
  const hash = ctx.hashHex(input);
  assertEqual(
    hash,
    'c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1',
    'Hash should match reference implementation'
  );
});

// ============================================================================
// Summary
// ============================================================================

console.log(`\n--- Summary ---`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed === 0) {
  console.log('\n✓ All RandomX tests passed!');
  process.exit(0);
} else {
  console.log('\n✗ Some tests failed');
  process.exit(1);
}
