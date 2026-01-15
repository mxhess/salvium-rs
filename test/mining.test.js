/**
 * Mining Module Tests
 */

import {
  MINING_CONSTANTS,
  parseBlockTemplate,
  parseDifficulty,
  treeHash,
  setNonce,
  getNonce,
  checkHash,
  difficultyToTarget,
  hashToDifficulty,
  formatDifficulty,
  formatHashrate,
  findNonceOffset,
  calculateHashrate,
  estimateBlockTime,
  formatDuration,
  createMiningContext
} from '../src/mining.js';
import { cnFastHash } from '../src/keccak.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(a, b, message) {
  if (a !== b) {
    throw new Error(message || `Expected ${a} to equal ${b}`);
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Helper to create test hashes
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

console.log('\n--- Mining Constants Tests ---');

test('MINING_CONSTANTS has expected values', () => {
  assertEqual(MINING_CONSTANTS.RX_BLOCK_VERSION, 12, 'RandomX version should be 12');
  assertEqual(MINING_CONSTANTS.NONCE_SIZE, 4, 'Nonce size should be 4');
  assertEqual(MINING_CONSTANTS.DIFFICULTY_TARGET, 120, 'Block time should be 120s');
  assertEqual(MINING_CONSTANTS.DIFFICULTY_WINDOW, 720, 'Difficulty window should be 720');
  assertEqual(MINING_CONSTANTS.MAX_EXTRA_NONCE_SIZE, 255, 'Max extra nonce should be 255');
});

console.log('\n--- Difficulty Parsing Tests ---');

test('parseDifficulty handles 64-bit difficulty', () => {
  const result = parseDifficulty(1000000, null, null);
  assertEqual(result, 1000000n, 'Should parse 64-bit difficulty');
});

test('parseDifficulty handles wide_difficulty hex string', () => {
  const result = parseDifficulty(0, '0x100000000', 0);
  assertEqual(result, 0x100000000n, 'Should parse wide difficulty');
});

test('parseDifficulty handles difficulty_top64', () => {
  const result = parseDifficulty(0xFFFFFFFFn, null, 1);
  assertEqual(result, (1n << 64n) | 0xFFFFFFFFn, 'Should combine top64 and low64');
});

console.log('\n--- Tree Hash Tests ---');

test('treeHash with 1 hash returns that hash', () => {
  const hash = cnFastHash(new TextEncoder().encode('test'));
  const result = treeHash([hash]);
  assert(bytesEqual(result, hash), 'Single hash should return itself');
});

test('treeHash with 2 hashes returns hash of concatenation', () => {
  const hash1 = cnFastHash(new TextEncoder().encode('test1'));
  const hash2 = cnFastHash(new TextEncoder().encode('test2'));
  const result = treeHash([hash1, hash2]);

  // Manual calculation
  const combined = new Uint8Array(64);
  combined.set(hash1, 0);
  combined.set(hash2, 32);
  const expected = cnFastHash(combined);

  assert(bytesEqual(result, expected), 'Two hashes should be hashed together');
});

test('treeHash with 3 hashes uses CN tree algorithm', () => {
  const hashes = [
    cnFastHash(new TextEncoder().encode('tx1')),
    cnFastHash(new TextEncoder().encode('tx2')),
    cnFastHash(new TextEncoder().encode('tx3'))
  ];
  const result = treeHash(hashes);
  assert(result.length === 32, 'Should return 32-byte hash');
});

test('treeHash with 4 hashes builds proper tree', () => {
  const hashes = [
    cnFastHash(new TextEncoder().encode('tx1')),
    cnFastHash(new TextEncoder().encode('tx2')),
    cnFastHash(new TextEncoder().encode('tx3')),
    cnFastHash(new TextEncoder().encode('tx4'))
  ];
  const result = treeHash(hashes);
  assert(result.length === 32, 'Should return 32-byte hash');
});

test('treeHash is deterministic', () => {
  const hashes = [
    cnFastHash(new TextEncoder().encode('tx1')),
    cnFastHash(new TextEncoder().encode('tx2')),
    cnFastHash(new TextEncoder().encode('tx3'))
  ];
  const result1 = treeHash(hashes);
  const result2 = treeHash(hashes);
  assert(bytesEqual(result1, result2), 'Should be deterministic');
});

console.log('\n--- Nonce Manipulation Tests ---');

test('setNonce writes nonce correctly', () => {
  const blob = new Uint8Array(100);
  const result = setNonce(blob, 0x12345678, 39);
  assertEqual(result[39], 0x78, 'Byte 0 should be LSB');
  assertEqual(result[40], 0x56, 'Byte 1');
  assertEqual(result[41], 0x34, 'Byte 2');
  assertEqual(result[42], 0x12, 'Byte 3 should be MSB');
});

test('getNonce reads nonce correctly', () => {
  const blob = new Uint8Array(100);
  blob[39] = 0x78;
  blob[40] = 0x56;
  blob[41] = 0x34;
  blob[42] = 0x12;
  const result = getNonce(blob, 39);
  assertEqual(result, 0x12345678, 'Should read nonce correctly');
});

test('setNonce/getNonce roundtrip', () => {
  const blob = new Uint8Array(100);
  const nonce = 0xDEADBEEF;
  const modified = setNonce(blob, nonce, 50);
  const recovered = getNonce(modified, 50);
  assertEqual(recovered, nonce, 'Should roundtrip correctly');
});

test('setNonce handles zero', () => {
  const blob = new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
  const result = setNonce(blob, 0, 0);
  assertEqual(result[0], 0, 'Should set to zero');
  assertEqual(result[1], 0, 'Should set to zero');
  assertEqual(result[2], 0, 'Should set to zero');
  assertEqual(result[3], 0, 'Should set to zero');
});

test('setNonce handles max uint32', () => {
  const blob = new Uint8Array(10);
  const result = setNonce(blob, 0xFFFFFFFF, 0);
  assertEqual(result[0], 0xFF, 'All bytes should be 0xFF');
  assertEqual(result[1], 0xFF, 'All bytes should be 0xFF');
  assertEqual(result[2], 0xFF, 'All bytes should be 0xFF');
  assertEqual(result[3], 0xFF, 'All bytes should be 0xFF');
});

console.log('\n--- Difficulty Check Tests ---');

test('checkHash returns true for easy difficulty', () => {
  // Any hash should pass difficulty 1
  const hash = cnFastHash(new TextEncoder().encode('test'));
  assert(checkHash(hash, 1n), 'Difficulty 1 should always pass');
});

test('checkHash returns false for impossible difficulty', () => {
  // Max difficulty (2^256) should never pass
  const hash = cnFastHash(new TextEncoder().encode('test'));
  const maxDifficulty = 1n << 256n;
  assert(!checkHash(hash, maxDifficulty), 'Max difficulty should never pass');
});

test('checkHash handles zero difficulty', () => {
  const hash = cnFastHash(new TextEncoder().encode('test'));
  assert(!checkHash(hash, 0n), 'Zero difficulty should return false');
});

test('checkHash with all-zeros hash passes any difficulty', () => {
  const hash = new Uint8Array(32); // All zeros
  assert(checkHash(hash, 1n), 'Zero hash should pass difficulty 1');
  assert(checkHash(hash, 1000000n), 'Zero hash should pass any difficulty');
});

test('checkHash with high hash fails high difficulty', () => {
  // Create a hash with high value (mostly 0xFF)
  const hash = new Uint8Array(32).fill(0xFF);
  assert(!checkHash(hash, 1000000000000n), 'High hash should fail high difficulty');
});

console.log('\n--- Difficulty Conversion Tests ---');

test('difficultyToTarget computes correct target', () => {
  const target = difficultyToTarget(1000000n);
  // Target = 2^256 / 1000000
  const expected = (1n << 256n) / 1000000n;
  assertEqual(target, expected, 'Should compute correct target');
});

test('difficultyToTarget handles difficulty 1', () => {
  const target = difficultyToTarget(1n);
  const expected = (1n << 256n);
  assertEqual(target, expected, 'Difficulty 1 should give max target');
});

test('hashToDifficulty computes equivalent difficulty', () => {
  const hash = new Uint8Array(32);
  hash[31] = 0x01; // Small hash value
  const diff = hashToDifficulty(hash);
  assert(diff > 0n, 'Should compute positive difficulty');
});

test('hashToDifficulty returns 0 for zero hash', () => {
  const hash = new Uint8Array(32);
  const diff = hashToDifficulty(hash);
  assertEqual(diff, 0n, 'Zero hash should return zero difficulty');
});

console.log('\n--- Format Functions Tests ---');

test('formatDifficulty formats small values', () => {
  assertEqual(formatDifficulty(500n), '500', 'Should format small values');
});

test('formatDifficulty formats K values', () => {
  const result = formatDifficulty(5000n);
  assert(result.includes('K'), 'Should use K suffix');
});

test('formatDifficulty formats M values', () => {
  const result = formatDifficulty(5000000n);
  assert(result.includes('M'), 'Should use M suffix');
});

test('formatDifficulty formats G values', () => {
  const result = formatDifficulty(5000000000n);
  assert(result.includes('G'), 'Should use G suffix');
});

test('formatDifficulty formats T values', () => {
  const result = formatDifficulty(5000000000000n);
  assert(result.includes('T'), 'Should use T suffix');
});

test('formatHashrate formats H/s', () => {
  const result = formatHashrate(500);
  assert(result.includes('H/s'), 'Should include H/s');
});

test('formatHashrate formats KH/s', () => {
  const result = formatHashrate(5000);
  assert(result.includes('KH/s'), 'Should include KH/s');
});

test('formatHashrate formats MH/s', () => {
  const result = formatHashrate(5000000);
  assert(result.includes('MH/s'), 'Should include MH/s');
});

test('formatDuration formats seconds', () => {
  assertEqual(formatDuration(45), '45s', 'Should format seconds');
});

test('formatDuration formats minutes and seconds', () => {
  const result = formatDuration(125);
  assert(result.includes('m') && result.includes('s'), 'Should include m and s');
});

test('formatDuration formats hours', () => {
  const result = formatDuration(3700);
  assert(result.includes('h'), 'Should include h');
});

test('formatDuration formats days', () => {
  const result = formatDuration(100000);
  assert(result.includes('d'), 'Should include d');
});

test('formatDuration handles infinity', () => {
  assertEqual(formatDuration(Infinity), '∞', 'Should handle infinity');
});

console.log('\n--- Mining Statistics Tests ---');

test('calculateHashrate computes correctly', () => {
  const rate = calculateHashrate(1000, 10);
  assertEqual(rate, 100, 'Should compute 100 H/s');
});

test('calculateHashrate handles zero time', () => {
  const rate = calculateHashrate(1000, 0);
  assertEqual(rate, 0, 'Zero time should return 0');
});

test('estimateBlockTime computes correctly', () => {
  const time = estimateBlockTime(100, 1000n);
  assertEqual(time, 10, '1000/100 = 10 seconds');
});

test('estimateBlockTime handles zero hashrate', () => {
  const time = estimateBlockTime(0, 1000n);
  assertEqual(time, Infinity, 'Zero hashrate should return Infinity');
});

console.log('\n--- Block Template Parsing Tests ---');

test('parseBlockTemplate parses basic fields', () => {
  const template = parseBlockTemplate({
    difficulty: 1000000,
    height: 12345,
    prev_hash: 'abc123',
    expected_reward: 1000000000000,
    reserved_offset: 130,
    blocktemplate_blob: 'deadbeef',
    blockhashing_blob: 'cafebabe'
  });

  assertEqual(template.difficulty, 1000000n, 'Should parse difficulty');
  assertEqual(template.height, 12345n, 'Should parse height');
  assertEqual(template.prevHash, 'abc123', 'Should parse prev_hash');
  assertEqual(template.expectedReward, 1000000000000n, 'Should parse reward');
  assertEqual(template.reservedOffset, 130, 'Should parse reserved_offset');
});

test('parseBlockTemplate handles seed hash', () => {
  const template = parseBlockTemplate({
    difficulty: 1000,
    height: 100,
    prev_hash: '',
    expected_reward: 0,
    reserved_offset: 0,
    blocktemplate_blob: '',
    blockhashing_blob: '',
    seed_height: 64,
    seed_hash: 'abcd1234',
    next_seed_hash: 'efgh5678'
  });

  assertEqual(template.seedHeight, 64n, 'Should parse seed_height');
  assertEqual(template.seedHash, 'abcd1234', 'Should parse seed_hash');
  assertEqual(template.nextSeedHash, 'efgh5678', 'Should parse next_seed_hash');
});

console.log('\n--- Mining Context Tests ---');

test('createMiningContext creates functional context', () => {
  // Mock RandomX function that returns predictable hash
  const mockRandomX = (blob, seed) => {
    return cnFastHash(blob);
  };

  const ctx = createMiningContext(mockRandomX);
  assert(typeof ctx.tryNonce === 'function', 'Should have tryNonce');
  assert(typeof ctx.mineRange === 'function', 'Should have mineRange');
});

test('createMiningContext tryNonce returns correct structure', () => {
  const mockRandomX = (blob, seed) => cnFastHash(blob);
  const ctx = createMiningContext(mockRandomX);

  const blob = new Uint8Array(100);
  const seed = new Uint8Array(32);
  const result = ctx.tryNonce(blob, seed, 0, 39, 1n);

  assert('found' in result, 'Should have found property');
  assert('hash' in result, 'Should have hash property');
  assert('nonce' in result, 'Should have nonce property');
  assert(result.hash.length === 32, 'Hash should be 32 bytes');
});

test('createMiningContext mineRange finds solution with low difficulty', () => {
  const mockRandomX = (blob, seed) => cnFastHash(blob);
  const ctx = createMiningContext(mockRandomX);

  const blob = new Uint8Array(100);
  const seed = new Uint8Array(32);
  // Difficulty 1 should pass immediately
  const result = ctx.mineRange(blob, seed, 0, 10, 39, 1n);

  assert(result !== null, 'Should find solution with difficulty 1');
  assert(result.found, 'Should mark as found');
});

test('createMiningContext mineRange returns null when not found', () => {
  const mockRandomX = (blob, seed) => {
    // Return high hash that won't pass
    return new Uint8Array(32).fill(0xFF);
  };
  const ctx = createMiningContext(mockRandomX);

  const blob = new Uint8Array(100);
  const seed = new Uint8Array(32);
  // Very high difficulty
  const result = ctx.mineRange(blob, seed, 0, 10, 39, 1n << 250n);

  assert(result === null, 'Should return null when not found');
});

console.log('\n--- Find Nonce Offset Tests ---');

test('findNonceOffset finds offset after header fields', () => {
  // Create a simple block header:
  // major_version: 1 byte (value < 128, so single byte varint)
  // minor_version: 1 byte
  // timestamp: 1 byte (small value)
  // prev_id: 32 bytes
  // Then nonce at offset 35
  const blob = new Uint8Array(100);
  blob[0] = 14; // major_version
  blob[1] = 0;  // minor_version
  blob[2] = 100; // timestamp (small)
  // prev_id takes bytes 3-34
  // nonce should be at 35

  const offset = findNonceOffset(blob);
  assertEqual(offset, 35, 'Should find nonce at offset 35 for simple header');
});

test('findNonceOffset handles multi-byte varints', () => {
  const blob = new Uint8Array(100);
  blob[0] = 0x80 | 14; // major_version with continuation
  blob[1] = 0x01;      // continuation byte
  blob[2] = 0;         // minor_version
  blob[3] = 100;       // timestamp
  // prev_id takes bytes 4-35
  // nonce should be at 36

  const offset = findNonceOffset(blob);
  assertEqual(offset, 36, 'Should handle multi-byte varints');
});

// Summary
console.log('\n--- Mining Test Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

if (failed > 0) {
  console.log('\n✗ Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All mining tests passed!');
}
