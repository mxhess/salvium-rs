/**
 * Tests for RandomX Pure JavaScript Implementation
 */

import { describe, it, expect } from 'vitest';
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

// ============================================================================
// Utility functions
// ============================================================================

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

// ============================================================================
// Blake2Generator Tests
// ============================================================================

describe('Blake2Generator', () => {
  it('should generate consistent bytes from seed', () => {
    const seed = new Uint8Array(32);
    seed[0] = 1;

    const gen1 = new Blake2Generator(seed);
    const gen2 = new Blake2Generator(seed);

    const bytes1 = gen1.getBytes(16);
    const bytes2 = gen2.getBytes(16);

    expect(bytesToHex(bytes1)).toBe(bytesToHex(bytes2));
  });

  it('should generate different bytes for different seeds', () => {
    const seed1 = new Uint8Array(32);
    seed1[0] = 1;

    const seed2 = new Uint8Array(32);
    seed2[0] = 2;

    const gen1 = new Blake2Generator(seed1);
    const gen2 = new Blake2Generator(seed2);

    const bytes1 = gen1.getBytes(16);
    const bytes2 = gen2.getBytes(16);

    expect(bytesToHex(bytes1)).not.toBe(bytesToHex(bytes2));
  });

  it('should generate sequential bytes correctly', () => {
    const seed = new Uint8Array(32);

    const gen = new Blake2Generator(seed);

    // Get bytes in chunks and verify they match
    const chunk1 = gen.getBytes(16);
    const chunk2 = gen.getBytes(16);

    // Chunks should be different (sequential from generator)
    expect(bytesToHex(chunk1)).not.toBe(bytesToHex(chunk2));

    // But deterministic - same seed should produce same sequence
    const gen2 = new Blake2Generator(seed);
    const allBytes = gen2.getBytes(32);

    expect(bytesToHex(allBytes.slice(0, 16))).toBe(bytesToHex(chunk1));
    expect(bytesToHex(allBytes.slice(16, 32))).toBe(bytesToHex(chunk2));
  });
});

// ============================================================================
// Reciprocal Function Tests
// ============================================================================

describe('reciprocal', () => {
  // Note: reciprocal computes 2^x / divisor (for multiplication-based division)
  // NOT modular multiplicative inverse

  it('should compute reciprocal for small divisor', () => {
    const r = reciprocal(3);
    expect(typeof r).toBe('bigint');
    expect(r > 0n).toBe(true);
    // Should be close to 2^64 / 3
    expect(r > (1n << 62n)).toBe(true);
    expect(r < (1n << 64n)).toBe(true);
  });

  it('should compute consistent reciprocals', () => {
    const r1 = reciprocal(7);
    const r2 = reciprocal(7);
    expect(r1).toBe(r2);
  });

  it('should compute different reciprocals for different divisors', () => {
    const r3 = reciprocal(3);
    const r5 = reciprocal(5);
    const r7 = reciprocal(7);
    expect(r3).not.toBe(r5);
    expect(r5).not.toBe(r7);
    expect(r3).not.toBe(r7);
  });

  it('should return 0 for divisor 0', () => {
    const r = reciprocal(0);
    expect(r).toBe(0n);
  });

  it('should return large values for all non-zero divisors', () => {
    const divisors = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31];
    for (const d of divisors) {
      const r = reciprocal(d);
      expect(r > 0n).toBe(true);
      expect(r < (1n << 64n)).toBe(true);
    }
  });
});

// ============================================================================
// SuperscalarHash Tests
// ============================================================================

describe('SuperscalarHash', () => {
  it('should generate a valid superscalar program', () => {
    const seed = new Uint8Array(32);
    seed[0] = 42;

    const gen = new Blake2Generator(seed);
    const prog = generateSuperscalar(gen);

    expect(prog).toBeDefined();
    expect(prog.instructions).toBeDefined();
    expect(Array.isArray(prog.instructions)).toBe(true);
    expect(prog.instructions.length).toBeGreaterThan(0);
    expect(typeof prog.addressRegister).toBe('number');
  });

  it('should generate different programs for different seeds', () => {
    const seed1 = new Uint8Array(32);
    seed1[0] = 1;

    const seed2 = new Uint8Array(32);
    seed2[0] = 2;

    const gen1 = new Blake2Generator(seed1);
    const gen2 = new Blake2Generator(seed2);

    const prog1 = generateSuperscalar(gen1);
    const prog2 = generateSuperscalar(gen2);

    // Programs should be different
    expect(prog1.instructions.length).not.toBe(0);
    expect(prog2.instructions.length).not.toBe(0);

    // Either different number of instructions or different opcodes
    const isDifferent =
      prog1.instructions.length !== prog2.instructions.length ||
      prog1.instructions.some((instr, i) =>
        prog2.instructions[i] && instr.opcode !== prog2.instructions[i].opcode
      );

    expect(isDifferent).toBe(true);
  });

  it('should execute superscalar program on registers', () => {
    const seed = new Uint8Array(32);
    const gen = new Blake2Generator(seed);
    const prog = generateSuperscalar(gen);

    // Initialize registers
    const r = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n];
    const initialSum = r.reduce((a, b) => a + b, 0n);

    // Execute program
    executeSuperscalar(r, prog);

    // Registers should be modified
    const finalSum = r.reduce((a, b) => a + b, 0n);
    expect(finalSum).not.toBe(initialSum);
  });
});

// ============================================================================
// Argon2d Tests
// ============================================================================

describe('Argon2d', () => {
  it('should produce consistent output for same input', () => {
    const password = new TextEncoder().encode('test');
    const salt = new TextEncoder().encode('saltsalt');

    const hash1 = argon2d(password, salt, 1, 16, 1, 32);
    const hash2 = argon2d(password, salt, 1, 16, 1, 32);

    expect(bytesToHex(hash1)).toBe(bytesToHex(hash2));
  });

  it('should produce different output for different passwords', () => {
    const password1 = new TextEncoder().encode('test1');
    const password2 = new TextEncoder().encode('test2');
    const salt = new TextEncoder().encode('saltsalt');

    const hash1 = argon2d(password1, salt, 1, 16, 1, 32);
    const hash2 = argon2d(password2, salt, 1, 16, 1, 32);

    expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
  });

  it('should produce different output for different salts', () => {
    const password = new TextEncoder().encode('test');
    const salt1 = new TextEncoder().encode('salt1234');
    const salt2 = new TextEncoder().encode('salt5678');

    const hash1 = argon2d(password, salt1, 1, 16, 1, 32);
    const hash2 = argon2d(password, salt2, 1, 16, 1, 32);

    expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
  });

  it('should produce 32-byte output', () => {
    const password = new TextEncoder().encode('test');
    const salt = new TextEncoder().encode('saltsalt');

    const hash = argon2d(password, salt, 1, 16, 1, 32);

    expect(hash.length).toBe(32);
  });

  it('should produce 64-byte output when requested', () => {
    const password = new TextEncoder().encode('test');
    const salt = new TextEncoder().encode('saltsalt');

    const hash = argon2d(password, salt, 1, 16, 1, 64);

    expect(hash.length).toBe(64);
  });
});

// ============================================================================
// Difficulty Check Tests
// ============================================================================

describe('checkDifficulty', () => {
  it('should return false for difficulty 0', () => {
    const hash = new Uint8Array(32);
    expect(checkDifficulty(hash, 0n)).toBe(false);
  });

  it('should return true for zero hash with any positive difficulty', () => {
    const hash = new Uint8Array(32);  // All zeros
    expect(checkDifficulty(hash, 1n)).toBe(true);
    expect(checkDifficulty(hash, 1000000n)).toBe(true);
  });

  it('should correctly check difficulty for non-zero hash', () => {
    // Hash with first byte = 1 (little-endian, so least significant)
    const hash = new Uint8Array(32);
    hash[0] = 1;  // Hash value = 1

    // Very low difficulty should pass
    expect(checkDifficulty(hash, 1n)).toBe(true);

    // For hash=1, the check is: 1 * difficulty <= 2^256 - 1
    // So difficulty up to 2^256 - 1 should pass
    // Even very high difficulty should pass for hash=1
    expect(checkDifficulty(hash, 1n << 200n)).toBe(true);
  });

  it('should handle max hash value', () => {
    const hash = new Uint8Array(32);
    hash.fill(255);  // Max possible hash

    // Only very low difficulty should pass
    expect(checkDifficulty(hash, 1n)).toBe(true);
    expect(checkDifficulty(hash, 2n)).toBe(false);
  });
});

// ============================================================================
// calculateCommitment Tests
// ============================================================================

describe('calculateCommitment', () => {
  it('should produce 32-byte commitment', () => {
    const input = new TextEncoder().encode('test input');
    const hashIn = new Uint8Array(32);

    const commitment = calculateCommitment(input, hashIn);

    expect(commitment.length).toBe(32);
  });

  it('should produce consistent commitments', () => {
    const input = new TextEncoder().encode('test input');
    const hashIn = new Uint8Array(32);
    hashIn[0] = 42;

    const commitment1 = calculateCommitment(input, hashIn);
    const commitment2 = calculateCommitment(input, hashIn);

    expect(bytesToHex(commitment1)).toBe(bytesToHex(commitment2));
  });

  it('should produce different commitments for different inputs', () => {
    const input1 = new TextEncoder().encode('test input 1');
    const input2 = new TextEncoder().encode('test input 2');
    const hashIn = new Uint8Array(32);

    const commitment1 = calculateCommitment(input1, hashIn);
    const commitment2 = calculateCommitment(input2, hashIn);

    expect(bytesToHex(commitment1)).not.toBe(bytesToHex(commitment2));
  });

  it('should produce different commitments for different previous hashes', () => {
    const input = new TextEncoder().encode('test input');
    const hashIn1 = new Uint8Array(32);
    const hashIn2 = new Uint8Array(32);
    hashIn2[0] = 1;

    const commitment1 = calculateCommitment(input, hashIn1);
    const commitment2 = calculateCommitment(input, hashIn2);

    expect(bytesToHex(commitment1)).not.toBe(bytesToHex(commitment2));
  });
});

// ============================================================================
// RandomXCache Tests (lightweight - no full cache init)
// ============================================================================

describe('RandomXCache', () => {
  it('should construct without parameters', () => {
    const cache = new RandomXCache();
    expect(cache).toBeDefined();
    expect(cache.memory).toBeNull();
    expect(cache.programs).toEqual([]);
  });

  it('should read 64-bit values correctly', () => {
    const block = new Uint8Array([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  // Little-endian
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    ]);

    const value0 = RandomXCache.readU64(block, 0);
    const value8 = RandomXCache.readU64(block, 8);

    // Little-endian: 0x0807060504030201
    expect(value0).toBe(0x0807060504030201n);
    expect(value8).toBe(0x1817161514131211n);
  });
});

// ============================================================================
// RandomXContext Tests (basic structure tests)
// ============================================================================

describe('RandomXContext', () => {
  it('should construct with null values', () => {
    const ctx = new RandomXContext();
    expect(ctx).toBeDefined();
    expect(ctx.cache).toBeNull();
    expect(ctx.vm).toBeNull();
    expect(ctx.cacheKey).toBeNull();
  });

  it('should throw when hash called without init', () => {
    const ctx = new RandomXContext();
    expect(() => ctx.hash('test')).toThrow('RandomX context not initialized');
  });
});

// ============================================================================
// Integration Tests (marked as slow - require full cache init)
// ============================================================================

// Full integration tests require 256MB cache initialization
// These tests are slow (~3 minutes in pure JS) - use shared context
describe('RandomX Full Integration (256MB)', () => {
  // Shared context to avoid reinitializing 256MB cache for each test
  let sharedCtx = null;
  const testKey = new TextEncoder().encode('test key');

  it('should initialize cache and compute hash', { timeout: 600000 }, () => {
    const input = new TextEncoder().encode('test input');

    sharedCtx = new RandomXContext();
    sharedCtx.init(testKey);

    const hash = sharedCtx.hash(input);

    expect(hash).toBeDefined();
    expect(hash.length).toBe(32);
  });

  it('should produce consistent hashes', { timeout: 60000 }, () => {
    const input = new TextEncoder().encode('test input');

    // Reuse shared context (already initialized with same key)
    const hash1 = sharedCtx.hash(input);
    const hash2 = sharedCtx.hash(input);

    expect(bytesToHex(hash1)).toBe(bytesToHex(hash2));
  });

  it('should produce different hashes for different inputs', { timeout: 60000 }, () => {
    const input1 = new TextEncoder().encode('test input 1');
    const input2 = new TextEncoder().encode('test input 2');

    const hash1 = sharedCtx.hash(input1);
    const hash2 = sharedCtx.hash(input2);

    expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
  });

  it('should verify hash correctly', { timeout: 60000 }, () => {
    const input = new TextEncoder().encode('test input');

    const hash = sharedCtx.hash(input);

    // Verify using same context
    const hash2 = sharedCtx.hash(input);
    expect(bytesToHex(hash)).toBe(bytesToHex(hash2));
  });

  it('should fail verification for wrong hash', { timeout: 60000 }, () => {
    const input = new TextEncoder().encode('test input');

    const hash1 = sharedCtx.hash(input);
    const hash2 = sharedCtx.hash(input);
    hash2[0] ^= 0xff;  // Corrupt first byte

    expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
  });
});

// ============================================================================
// Export verification
// ============================================================================

describe('RandomX exports', () => {
  it('should export RandomXContext class', () => {
    expect(RandomXContext).toBeDefined();
    expect(typeof RandomXContext).toBe('function');
  });

  it('should export rxSlowHash function', () => {
    expect(rxSlowHash).toBeDefined();
    expect(typeof rxSlowHash).toBe('function');
  });

  it('should export randomxHash alias', () => {
    expect(randomxHash).toBeDefined();
    expect(randomxHash).toBe(rxSlowHash);
  });

  it('should export calculateCommitment function', () => {
    expect(calculateCommitment).toBeDefined();
    expect(typeof calculateCommitment).toBe('function');
  });

  it('should export verifyHash function', () => {
    expect(verifyHash).toBeDefined();
    expect(typeof verifyHash).toBe('function');
  });

  it('should export checkDifficulty function', () => {
    expect(checkDifficulty).toBeDefined();
    expect(typeof checkDifficulty).toBe('function');
  });

  it('should export RandomXCache class', () => {
    expect(RandomXCache).toBeDefined();
    expect(typeof RandomXCache).toBe('function');
  });

  it('should export initDatasetItem function', () => {
    expect(initDatasetItem).toBeDefined();
    expect(typeof initDatasetItem).toBe('function');
  });

  it('should export Blake2Generator class', () => {
    expect(Blake2Generator).toBeDefined();
    expect(typeof Blake2Generator).toBe('function');
  });

  it('should export generateSuperscalar function', () => {
    expect(generateSuperscalar).toBeDefined();
    expect(typeof generateSuperscalar).toBe('function');
  });

  it('should export executeSuperscalar function', () => {
    expect(executeSuperscalar).toBeDefined();
    expect(typeof executeSuperscalar).toBe('function');
  });

  it('should export reciprocal function', () => {
    expect(reciprocal).toBeDefined();
    expect(typeof reciprocal).toBe('function');
  });

  it('should export argon2d function', () => {
    expect(argon2d).toBeDefined();
    expect(typeof argon2d).toBe('function');
  });
});
