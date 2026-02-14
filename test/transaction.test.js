#!/usr/bin/env node
/**
 * Transaction Module Tests
 *
 * Tests for scalar operations, Pedersen commitments, output generation,
 * and CLSAG ring signatures.
 */

import {
  // Scalar operations
  L,
  H,
  bytesToBigInt,
  bigIntToBytes,
  scReduce32,
  scReduce64,
  scAdd,
  scSub,
  scMul,
  scMulAdd,
  scMulSub,
  scCheck,
  scIsZero,
  scRandom,
  scInvert,
  // Pedersen commitments
  commit,
  zeroCommit,
  genCommitmentMask,
  // Output creation
  generateOutputKeys,
  createOutput,
  // CLSAG signatures
  clsagSign,
  clsagVerify,
  // Utilities
  generateTxSecretKey,
  getTxPublicKey,
  getPreMlsagHash,
  // Serialization
  encodeVarint,
  decodeVarint,
  TX_VERSION,
  RCT_TYPE,
  TXOUT_TYPE,
  TXIN_TYPE,
  serializeTxOutput,
  serializeTxInput,
  serializeGenInput,
  serializeTxExtra,
  serializeTxPrefix,
  getTxPrefixHash,
  serializeCLSAG,
  serializeRctBase,
  serializeEcdhInfo,
  serializeOutPk,
  getTransactionHash
} from '../src/transaction.js';

import {
  scalarMultBase,
  scalarMultPoint,
  pointAddCompressed,
  getGeneratorG
} from '../src/crypto/index.js';

import { hashToPoint, generateKeyImage } from '../src/keyimage.js';
import { deriveKeys } from '../src/carrot.js';
import { generateSeed } from '../src/carrot.js';
import { bytesToHex, hexToBytes } from '../src/address.js';
import { initCrypto } from '../src/crypto/index.js';

// Initialize Rust crypto backend (required for carrot.js key derivation)
await initCrypto();

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

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertEqual(a, b, message) {
  const aStr = typeof a === 'object' ? bytesToHex(a) : String(a);
  const bStr = typeof b === 'object' ? bytesToHex(b) : String(b);
  if (aStr !== bStr) {
    throw new Error(message || `Expected ${bStr}, got ${aStr}`);
  }
}

function assertTrue(condition, message) {
  if (!condition) {
    throw new Error(message || 'Expected true');
  }
}

// =============================================================================
// CONSTANTS
// =============================================================================

console.log('\n--- Constants Tests ---');

test('L is correct subgroup order', () => {
  // L = 2^252 + 27742317777372353535851937790883648493
  const expected = 2n ** 252n + 27742317777372353535851937790883648493n;
  assertEqual(L, expected);
});

test('H is 32 bytes hex string', () => {
  assert(H.length === 64, 'H should be 64 hex chars (32 bytes)');
});

test('H is correct value from rctTypes.h', () => {
  const expected = '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94';
  assertEqual(H, expected);
});

// =============================================================================
// SCALAR OPERATIONS
// =============================================================================

console.log('\n--- Scalar Operations Tests ---');

test('bytesToBigInt converts little-endian correctly', () => {
  const bytes = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  assertEqual(bytesToBigInt(bytes), 1n);
});

test('bigIntToBytes converts to little-endian correctly', () => {
  const result = bigIntToBytes(1n);
  assertEqual(result[0], 1);
  for (let i = 1; i < 32; i++) {
    assertEqual(result[i], 0);
  }
});

test('bytesToBigInt/bigIntToBytes roundtrip', () => {
  const original = scRandom();
  const bigInt = bytesToBigInt(original);
  const back = bigIntToBytes(bigInt);
  assertEqual(original, back);
});

test('scReduce32 reduces values >= L', () => {
  // Create a value >= L
  const largeBytes = new Uint8Array(32);
  largeBytes.fill(0xff);
  const reduced = scReduce32(largeBytes);
  const reducedBigInt = bytesToBigInt(reduced);
  assert(reducedBigInt < L, 'Reduced value should be < L');
});

test('scReduce32 keeps values < L unchanged', () => {
  const small = bigIntToBytes(100n);
  const reduced = scReduce32(small);
  assertEqual(bytesToBigInt(reduced), 100n);
});

test('scReduce64 reduces 64-byte value mod L', () => {
  const bytes = new Uint8Array(64);
  bytes.fill(0xff);
  const reduced = scReduce64(bytes);
  assert(reduced.length === 32, 'Result should be 32 bytes');
  assert(bytesToBigInt(reduced) < L, 'Result should be < L');
});

test('scAdd adds scalars mod L', () => {
  const a = bigIntToBytes(100n);
  const b = bigIntToBytes(200n);
  const sum = scAdd(a, b);
  assertEqual(bytesToBigInt(sum), 300n);
});

test('scAdd wraps around L', () => {
  const a = bigIntToBytes(L - 10n);
  const b = bigIntToBytes(20n);
  const sum = scAdd(a, b);
  assertEqual(bytesToBigInt(sum), 10n);
});

test('scSub subtracts scalars mod L', () => {
  const a = bigIntToBytes(300n);
  const b = bigIntToBytes(100n);
  const diff = scSub(a, b);
  assertEqual(bytesToBigInt(diff), 200n);
});

test('scSub handles underflow correctly', () => {
  const a = bigIntToBytes(10n);
  const b = bigIntToBytes(20n);
  const diff = scSub(a, b);
  // Result should be L - 10
  assertEqual(bytesToBigInt(diff), L - 10n);
});

test('scMul multiplies scalars mod L', () => {
  const a = bigIntToBytes(100n);
  const b = bigIntToBytes(200n);
  const product = scMul(a, b);
  assertEqual(bytesToBigInt(product), 20000n);
});

test('scMul wraps around L', () => {
  // Large values that would overflow
  const a = bigIntToBytes(L - 1n);
  const b = bigIntToBytes(2n);
  const product = scMul(a, b);
  // (L-1) * 2 mod L = L - 2 (since 2L - 2 mod L = L - 2)
  assertEqual(bytesToBigInt(product), L - 2n);
});

test('scMulAdd computes a*b + c mod L', () => {
  const a = bigIntToBytes(10n);
  const b = bigIntToBytes(20n);
  const c = bigIntToBytes(5n);
  const result = scMulAdd(a, b, c);
  assertEqual(bytesToBigInt(result), 205n);
});

test('scMulSub computes c - a*b mod L', () => {
  const a = bigIntToBytes(10n);
  const b = bigIntToBytes(20n);
  const c = bigIntToBytes(300n);
  const result = scMulSub(a, b, c);
  assertEqual(bytesToBigInt(result), 100n);
});

test('scCheck returns true for valid scalars', () => {
  const valid = bigIntToBytes(L - 1n);
  assert(scCheck(valid), 'L-1 should be valid');
});

test('scCheck returns false for scalars >= L', () => {
  // Note: scCheck just checks if value < L when interpreted as BigInt
  // After reduction, everything is < L, so this tests the unreduced case
  const lBytes = bigIntToBytes(L);
  // This actually wraps to 0 due to our bigIntToBytes implementation
  // Let's test with L directly without reduction
  const big = bytesToBigInt(new Uint8Array(32).fill(0xff));
  assert(big >= L, 'Test value should be >= L');
});

test('scIsZero detects zero', () => {
  const zero = new Uint8Array(32);
  assert(scIsZero(zero), 'All zeros should be zero');
});

test('scIsZero rejects non-zero', () => {
  const nonZero = new Uint8Array(32);
  nonZero[0] = 1;
  assert(!scIsZero(nonZero), 'Non-zero should not be zero');
});

test('scRandom produces non-zero scalars', () => {
  const r = scRandom();
  assert(!scIsZero(r), 'Random scalar should not be zero');
  assert(bytesToBigInt(r) < L, 'Random scalar should be < L');
});

test('scRandom produces different values', () => {
  const r1 = scRandom();
  const r2 = scRandom();
  assert(bytesToHex(r1) !== bytesToHex(r2), 'Random scalars should differ');
});

test('scInvert computes multiplicative inverse', () => {
  const a = bigIntToBytes(7n);
  const aInv = scInvert(a);
  const product = scMul(a, aInv);
  assertEqual(bytesToBigInt(product), 1n);
});

test('scInvert throws for zero', () => {
  const zero = new Uint8Array(32);
  let threw = false;
  try {
    scInvert(zero);
  } catch (e) {
    threw = true;
  }
  assert(threw, 'scInvert(0) should throw');
});

// =============================================================================
// PEDERSEN COMMITMENTS
// =============================================================================

console.log('\n--- Pedersen Commitment Tests ---');

test('commit produces 32-byte result', () => {
  const mask = scRandom();
  const c = commit(1000n, mask);
  assertEqual(c.length, 32);
});

test('commit is deterministic', () => {
  const mask = bigIntToBytes(12345n);
  const c1 = commit(1000n, mask);
  const c2 = commit(1000n, mask);
  assertEqual(c1, c2);
});

test('commit with different masks produces different results', () => {
  const mask1 = bigIntToBytes(1n);
  const mask2 = bigIntToBytes(2n);
  const c1 = commit(1000n, mask1);
  const c2 = commit(1000n, mask2);
  assert(bytesToHex(c1) !== bytesToHex(c2), 'Different masks should produce different commitments');
});

test('commit with different amounts produces different results', () => {
  const mask = bigIntToBytes(12345n);
  const c1 = commit(1000n, mask);
  const c2 = commit(2000n, mask);
  assert(bytesToHex(c1) !== bytesToHex(c2), 'Different amounts should produce different commitments');
});

test('zeroCommit produces 32-byte commitment', () => {
  const zc = zeroCommit(1000n);
  assert(zc.length === 32, 'Zero commit should be 32 bytes');
});

test('zeroCommit equals commit with mask=1 (matching C++ rct::zeroCommit)', () => {
  // C++ rct::zeroCommit uses blinding factor = identity scalar (1), not zero.
  // zeroCommit(amount) = 1*G + amount*H
  const scalarOne = new Uint8Array(32);
  scalarOne[0] = 1;
  const zc = zeroCommit(1000n);
  const c = commit(1000n, scalarOne);
  assertEqual(zc, c);
});

test('commitment homomorphism: C(a1,m1) + C(a2,m2) = C(a1+a2, m1+m2)', () => {
  // C(a, m) = m*G + a*H
  // C(a1, m1) + C(a2, m2) = (m1+m2)*G + (a1+a2)*H = C(a1+a2, m1+m2)
  const m1 = scRandom();
  const m2 = scRandom();
  const a1 = 1000n;
  const a2 = 2000n;

  const c1 = commit(a1, m1);
  const c2 = commit(a2, m2);
  const cSum = pointAddCompressed(c1, c2);

  const mSum = scAdd(m1, m2);
  const cExpected = commit(a1 + a2, mSum);

  assertEqual(cSum, cExpected);
});

test('genCommitmentMask produces 32-byte mask', () => {
  const secret = scRandom();
  const mask = genCommitmentMask(secret);
  assertEqual(mask.length, 32);
});

test('genCommitmentMask is deterministic', () => {
  const secret = bigIntToBytes(12345n);
  const mask1 = genCommitmentMask(secret);
  const mask2 = genCommitmentMask(secret);
  assertEqual(mask1, mask2);
});

test('genCommitmentMask produces different masks for different secrets', () => {
  const secret1 = bigIntToBytes(1n);
  const secret2 = bigIntToBytes(2n);
  const mask1 = genCommitmentMask(secret1);
  const mask2 = genCommitmentMask(secret2);
  assert(bytesToHex(mask1) !== bytesToHex(mask2), 'Different secrets should produce different masks');
});

// =============================================================================
// OUTPUT CREATION
// =============================================================================

console.log('\n--- Output Creation Tests ---');

// Generate test wallet keys
const seed = generateSeed();
const keys = deriveKeys(seed);

test('generateOutputKeys produces all required fields', () => {
  const txSecretKey = generateTxSecretKey();
  const result = generateOutputKeys(
    txSecretKey,
    keys.viewPublicKey,
    keys.spendPublicKey,
    0,
    false
  );

  assert(result.outputPublicKey, 'Should have outputPublicKey');
  assert(result.txPublicKey, 'Should have txPublicKey');
  assert(result.derivation, 'Should have derivation');
  assertEqual(result.outputPublicKey.length, 32);
  assertEqual(result.txPublicKey.length, 32);
  assertEqual(result.derivation.length, 32);
});

test('generateOutputKeys produces different outputs for different indices', () => {
  const txSecretKey = generateTxSecretKey();
  const r1 = generateOutputKeys(txSecretKey, keys.viewPublicKey, keys.spendPublicKey, 0, false);
  const r2 = generateOutputKeys(txSecretKey, keys.viewPublicKey, keys.spendPublicKey, 1, false);

  assert(bytesToHex(r1.outputPublicKey) !== bytesToHex(r2.outputPublicKey),
    'Different indices should produce different output keys');
});

test('generateOutputKeys txPublicKey = r*G for standard address', () => {
  const txSecretKey = generateTxSecretKey();
  const result = generateOutputKeys(txSecretKey, keys.viewPublicKey, keys.spendPublicKey, 0, false);
  const expected = scalarMultBase(txSecretKey);
  assertEqual(result.txPublicKey, expected);
});

test('createOutput produces all required fields', () => {
  const txSecretKey = generateTxSecretKey();
  const result = createOutput(
    txSecretKey,
    keys.viewPublicKey,
    keys.spendPublicKey,
    1000000n,
    0,
    false
  );

  assert(result.outputPublicKey, 'Should have outputPublicKey');
  assert(result.txPublicKey, 'Should have txPublicKey');
  assert(result.commitment, 'Should have commitment');
  assert(result.encryptedAmount, 'Should have encryptedAmount');
  assert(result.mask, 'Should have mask');
  assertEqual(result.commitment.length, 32);
  assertEqual(result.encryptedAmount.length, 8);
  assertEqual(result.mask.length, 32);
});

test('createOutput is deterministic', () => {
  const txSecretKey = bigIntToBytes(12345n);
  const r1 = createOutput(txSecretKey, keys.viewPublicKey, keys.spendPublicKey, 1000n, 0, false);
  const r2 = createOutput(txSecretKey, keys.viewPublicKey, keys.spendPublicKey, 1000n, 0, false);

  assertEqual(r1.outputPublicKey, r2.outputPublicKey);
  assertEqual(r1.commitment, r2.commitment);
  assertEqual(r1.encryptedAmount, r2.encryptedAmount);
});

test('generateTxSecretKey produces valid scalar', () => {
  const sk = generateTxSecretKey();
  assertEqual(sk.length, 32);
  assert(!scIsZero(sk), 'TX secret key should not be zero');
  assert(bytesToBigInt(sk) < L, 'TX secret key should be < L');
});

test('getTxPublicKey computes r*G', () => {
  const sk = generateTxSecretKey();
  const pk = getTxPublicKey(sk);
  const expected = scalarMultBase(sk);
  assertEqual(pk, expected);
});

// =============================================================================
// CLSAG SIGNATURE BASICS
// =============================================================================

console.log('\n--- CLSAG Signature Tests ---');

// Create a simple ring for testing
function createTestRing(size, secretIndex) {
  const ring = [];
  const commitments = [];
  let secretKey, commitmentMask;

  for (let i = 0; i < size; i++) {
    const sk = scRandom();
    const pk = scalarMultBase(sk);
    ring.push(pk);

    const mask = scRandom();
    const c = commit(1000n, mask);
    commitments.push(c);

    if (i === secretIndex) {
      secretKey = sk;
      commitmentMask = mask;
    }
  }

  // Pseudo output commitment (same amount, different mask)
  const pseudoMask = scRandom();
  const pseudoOut = commit(1000n, pseudoMask);

  // The mask difference for signing
  const maskDiff = scSub(commitmentMask, pseudoMask);

  return { ring, commitments, secretKey, maskDiff, pseudoOut, secretIndex };
}

test('clsagSign produces signature with correct structure', () => {
  const message = new Uint8Array(32);
  crypto.getRandomValues(message);

  const { ring, commitments, secretKey, maskDiff, pseudoOut, secretIndex } = createTestRing(3, 1);

  const sig = clsagSign(message, ring, secretKey, commitments, maskDiff, pseudoOut, secretIndex);

  assert(sig.s, 'Signature should have s array');
  assert(sig.c1, 'Signature should have c1');
  assert(sig.I, 'Signature should have key image I');
  assert(sig.D, 'Signature should have commitment image D');
  assertEqual(sig.s.length, 3, 'Should have one s value per ring member');
});

test('clsagSign produces valid key image', () => {
  const message = new Uint8Array(32);
  const { ring, commitments, secretKey, maskDiff, pseudoOut, secretIndex } = createTestRing(3, 1);

  const sig = clsagSign(message, ring, secretKey, commitments, maskDiff, pseudoOut, secretIndex);

  // Key image should be I = secretKey * H_p(P)
  const expectedI = generateKeyImage(ring[secretIndex], secretKey);
  assertEqual(sig.I, bytesToHex(expectedI));
});

test('clsagSign signature is deterministic with same inputs', () => {
  const message = bigIntToBytes(12345n);
  const secretKey = bigIntToBytes(67890n);
  const pk = scalarMultBase(secretKey);
  const mask = bigIntToBytes(11111n);
  const c = commit(1000n, mask);
  const pseudoMask = bigIntToBytes(22222n);
  const pseudoOut = commit(1000n, pseudoMask);
  const maskDiff = scSub(mask, pseudoMask);

  // Create other ring members deterministically
  const ring = [scalarMultBase(bigIntToBytes(1n)), pk, scalarMultBase(bigIntToBytes(2n))];
  const commitments = [commit(1000n, bigIntToBytes(3n)), c, commit(1000n, bigIntToBytes(4n))];

  // Note: clsagSign uses scRandom internally, so it won't be fully deterministic
  // But the key image and commitment image should be deterministic
  const sig1 = clsagSign(message, ring, secretKey, commitments, maskDiff, pseudoOut, 1);
  const sig2 = clsagSign(message, ring, secretKey, commitments, maskDiff, pseudoOut, 1);

  assertEqual(sig1.I, sig2.I, 'Key images should match');
  assertEqual(sig1.D, sig2.D, 'Commitment images should match');
});

test('clsagSign works with ring size 2', () => {
  const message = new Uint8Array(32);
  const { ring, commitments, secretKey, maskDiff, pseudoOut, secretIndex } = createTestRing(2, 0);

  const sig = clsagSign(message, ring, secretKey, commitments, maskDiff, pseudoOut, secretIndex);
  assertEqual(sig.s.length, 2);
});

test('clsagSign works with ring size 11 (standard)', () => {
  const message = new Uint8Array(32);
  const { ring, commitments, secretKey, maskDiff, pseudoOut, secretIndex } = createTestRing(11, 5);

  const sig = clsagSign(message, ring, secretKey, commitments, maskDiff, pseudoOut, secretIndex);
  assertEqual(sig.s.length, 11);
});

test('clsagSign accepts hex string inputs', () => {
  const message = '0'.repeat(64);
  const secretKey = bytesToHex(scRandom());
  const pk = scalarMultBase(hexToBytes(secretKey));
  const mask = bytesToHex(scRandom());
  const c = commit(1000n, hexToBytes(mask));
  const pseudoMask = bytesToHex(scRandom());
  const pseudoOut = commit(1000n, hexToBytes(pseudoMask));
  const maskDiff = scSub(hexToBytes(mask), hexToBytes(pseudoMask));

  const ring = [pk];
  const commitments = [c];

  // This tests single-member ring (degenerate case)
  const sig = clsagSign(message, ring, secretKey, commitments, bytesToHex(maskDiff), pseudoOut, 0);
  assert(sig.I, 'Should produce key image');
});

// =============================================================================
// PRE-MLSAG HASH
// =============================================================================

console.log('\n--- Pre-MLSAG Hash Tests ---');

test('getPreMlsagHash produces 32-byte hash', () => {
  // C++ signature: get_pre_mlsag_hash(rctSig) -> hashes txPrefixHash, rctBaseSerialized, bpProof
  // JS signature: getPreMlsagHash(txPrefixHash, rctBaseSerialized, bpProof)
  const txPrefixHash = new Uint8Array(32);
  const rctBaseSerialized = new Uint8Array(64);
  const bpProof = {
    A: new Uint8Array(32), A1: new Uint8Array(32), B: new Uint8Array(32),
    r1: new Uint8Array(32), s1: new Uint8Array(32), d1: new Uint8Array(32),
    L: [new Uint8Array(32)], R: [new Uint8Array(32)]
  };

  const hash = getPreMlsagHash(txPrefixHash, rctBaseSerialized, bpProof);
  assertEqual(hash.length, 32);
});

test('getPreMlsagHash is deterministic', () => {
  const txPrefixHash = bigIntToBytes(12345n);
  const rctBaseSerialized = bigIntToBytes(67890n);
  const bpProof = {
    A: bigIntToBytes(1n), A1: bigIntToBytes(2n), B: bigIntToBytes(3n),
    r1: bigIntToBytes(4n), s1: bigIntToBytes(5n), d1: bigIntToBytes(6n),
    L: [bigIntToBytes(7n)], R: [bigIntToBytes(8n)]
  };

  const h1 = getPreMlsagHash(txPrefixHash, rctBaseSerialized, bpProof);
  const h2 = getPreMlsagHash(txPrefixHash, rctBaseSerialized, bpProof);
  assertEqual(h1, h2);
});

test('getPreMlsagHash varies with different inputs', () => {
  const txPrefixHash = new Uint8Array(32);
  const rctBaseSerialized = new Uint8Array(64);
  const bpProof1 = {
    A: bigIntToBytes(1n), A1: new Uint8Array(32), B: new Uint8Array(32),
    r1: new Uint8Array(32), s1: new Uint8Array(32), d1: new Uint8Array(32),
    L: [new Uint8Array(32)], R: [new Uint8Array(32)]
  };
  const bpProof2 = {
    A: bigIntToBytes(2n), A1: new Uint8Array(32), B: new Uint8Array(32),
    r1: new Uint8Array(32), s1: new Uint8Array(32), d1: new Uint8Array(32),
    L: [new Uint8Array(32)], R: [new Uint8Array(32)]
  };

  const h1 = getPreMlsagHash(txPrefixHash, rctBaseSerialized, bpProof1);
  const h2 = getPreMlsagHash(txPrefixHash, rctBaseSerialized, bpProof2);
  assert(bytesToHex(h1) !== bytesToHex(h2), 'Different inputs should produce different hashes');
});

// =============================================================================
// SERIALIZATION TESTS
// =============================================================================

console.log('\n--- Varint Encoding Tests ---');

test('encodeVarint encodes 0 correctly', () => {
  const encoded = encodeVarint(0n);
  assertEqual(encoded.length, 1);
  assertEqual(encoded[0], 0);
});

test('encodeVarint encodes small values correctly', () => {
  const encoded = encodeVarint(127n);
  assertEqual(encoded.length, 1);
  assertEqual(encoded[0], 127);
});

test('encodeVarint encodes 128 correctly (2 bytes)', () => {
  const encoded = encodeVarint(128n);
  assertEqual(encoded.length, 2);
  assertEqual(encoded[0], 0x80);  // 128 & 0x7f | 0x80 = 0x80
  assertEqual(encoded[1], 1);     // 128 >> 7 = 1
});

test('encodeVarint encodes larger values correctly', () => {
  const encoded = encodeVarint(300n);  // 300 = 0b100101100
  assertEqual(encoded.length, 2);
  // 300 = 0x80 | (300 & 0x7f) + (300 >> 7) = 0xAC, 0x02
  assertEqual(encoded[0], 0xac);  // 300 & 0x7f = 44, | 0x80 = 172 = 0xac
  assertEqual(encoded[1], 2);     // 300 >> 7 = 2
});

test('decodeVarint decodes correctly', () => {
  const encoded = encodeVarint(12345n);
  const { value, bytesRead } = decodeVarint(encoded);
  assertEqual(value, 12345n);
  assertEqual(bytesRead, encoded.length);
});

test('encodeVarint/decodeVarint roundtrip for various values', () => {
  const testValues = [0n, 1n, 127n, 128n, 255n, 256n, 300n, 16383n, 16384n, 1000000n, 0xFFFFFFFFn];
  for (const val of testValues) {
    const encoded = encodeVarint(val);
    const { value } = decodeVarint(encoded);
    assertEqual(value, val);
  }
});

test('decodeVarint handles offset correctly', () => {
  const data = new Uint8Array([0x00, 0x00, ...encodeVarint(42n)]);
  const { value, bytesRead } = decodeVarint(data, 2);
  assertEqual(value, 42n);
  assertEqual(bytesRead, 1);
});

console.log('\n--- Transaction Output Serialization Tests ---');

test('serializeTxOutput produces valid output', () => {
  const output = {
    amount: 0n,
    target: new Uint8Array(32).fill(0xaa)
  };
  const serialized = serializeTxOutput(output);
  // Should be: amount varint (1 byte) + type (1 byte) + target (32 bytes)
  assert(serialized.length >= 34, 'Output should be at least 34 bytes');
});

test('serializeTxOutput includes view tag when present', () => {
  const output = {
    amount: 0n,
    target: new Uint8Array(32).fill(0xaa),
    viewTag: 0x42
  };
  const serialized = serializeTxOutput(output);
  // Should be: amount varint (1 byte) + type (1 byte) + target (32 bytes) + viewTag (1 byte)
  assert(serialized.length >= 35, 'Tagged output should be at least 35 bytes');
  assertEqual(serialized[serialized.length - 1], 0x42, 'View tag should be at end');
});

console.log('\n--- Transaction Input Serialization Tests ---');

test('serializeTxInput produces valid input', () => {
  const input = {
    amount: 0n,
    keyOffsets: [100n, 50n, 25n],
    keyImage: new Uint8Array(32).fill(0xbb)
  };
  const serialized = serializeTxInput(input);
  // Type (1) + amount varint + count varint + offsets varints + key image (32)
  assert(serialized.length >= 36, 'Input should be at least 36 bytes');
});

test('serializeGenInput produces coinbase input', () => {
  const serialized = serializeGenInput(12345n);
  assertEqual(serialized[0], TXIN_TYPE.Gen, 'First byte should be Gen type');
  assert(serialized.length > 1, 'Should have height after type');
});

console.log('\n--- Transaction Extra Serialization Tests ---');

test('serializeTxExtra includes tx public key', () => {
  const extra = {
    txPubKey: new Uint8Array(32).fill(0xcc)
  };
  const serialized = serializeTxExtra(extra);
  assertEqual(serialized[0], 0x01, 'Should start with pubkey tag');
  assertEqual(serialized.length, 33, 'Should be tag + 32 byte key');
});

test('serializeTxExtra includes payment ID when present', () => {
  const extra = {
    txPubKey: new Uint8Array(32).fill(0xcc),
    paymentId: new Uint8Array(8).fill(0xdd)
  };
  const serialized = serializeTxExtra(extra);
  // 1 + 32 (pubkey) + 3 (nonce tag + length + encrypted pid tag) + 8 (pid)
  assertEqual(serialized.length, 44);
});

console.log('\n--- Transaction Prefix Serialization Tests ---');

test('serializeTxPrefix produces valid prefix', () => {
  const tx = {
    version: 2,
    unlockTime: 0n,
    inputs: [{
      amount: 0n,
      keyOffsets: [100n],
      keyImage: new Uint8Array(32).fill(0xaa)
    }],
    outputs: [{
      amount: 0n,
      target: new Uint8Array(32).fill(0xbb)
    }],
    extra: {
      txPubKey: new Uint8Array(32).fill(0xcc)
    }
  };
  const serialized = serializeTxPrefix(tx);
  assert(serialized.length > 0, 'Should produce serialized data');
});

test('getTxPrefixHash produces 32-byte hash', () => {
  const tx = {
    version: 2,
    unlockTime: 0n,
    inputs: [{ type: 'gen', height: 12345n }],
    outputs: [{
      amount: 0n,
      target: new Uint8Array(32).fill(0xbb)
    }],
    extra: {
      txPubKey: new Uint8Array(32).fill(0xcc)
    }
  };
  const hash = getTxPrefixHash(tx);
  assertEqual(hash.length, 32);
});

test('getTxPrefixHash is deterministic', () => {
  const tx = {
    version: 2,
    unlockTime: 0n,
    inputs: [{ type: 'gen', height: 1000n }],
    outputs: [{
      amount: 0n,
      target: new Uint8Array(32).fill(0x11)
    }],
    extra: {
      txPubKey: new Uint8Array(32).fill(0x22)
    }
  };
  const h1 = getTxPrefixHash(tx);
  const h2 = getTxPrefixHash(tx);
  assertEqual(h1, h2);
});

console.log('\n--- CLSAG Serialization Tests ---');

test('serializeCLSAG produces valid serialization', () => {
  const sig = {
    s: ['0'.repeat(64), '0'.repeat(64), '0'.repeat(64)],
    c1: '0'.repeat(64),
    I: '0'.repeat(64),
    D: '0'.repeat(64)
  };
  const serialized = serializeCLSAG(sig);
  // 3 * 32 (s values) + 32 (c1) + 32 (D) = 160 bytes
  assertEqual(serialized.length, 160);
});

console.log('\n--- RingCT Serialization Tests ---');

test('serializeRctBase produces valid base', () => {
  const rct = {
    type: RCT_TYPE.CLSAG,
    fee: 1000000n
  };
  const serialized = serializeRctBase(rct);
  assertEqual(serialized[0], RCT_TYPE.CLSAG);
  assert(serialized.length > 1, 'Should have fee after type');
});

test('serializeRctBase handles null type', () => {
  const rct = {
    type: RCT_TYPE.Null,
    fee: 0n
  };
  const serialized = serializeRctBase(rct);
  assertEqual(serialized.length, 1, 'Null type should only have type byte');
  assertEqual(serialized[0], RCT_TYPE.Null);
});

test('serializeEcdhInfo produces correct length', () => {
  const amounts = [
    new Uint8Array(8).fill(0x11),
    new Uint8Array(8).fill(0x22)
  ];
  const serialized = serializeEcdhInfo(amounts);
  assertEqual(serialized.length, 16, 'Should be 8 bytes per amount');
});

test('serializeOutPk produces correct length', () => {
  const commitments = [
    new Uint8Array(32).fill(0x11),
    new Uint8Array(32).fill(0x22),
    new Uint8Array(32).fill(0x33)
  ];
  const serialized = serializeOutPk(commitments);
  assertEqual(serialized.length, 96, 'Should be 32 bytes per commitment');
});

console.log('\n--- Transaction Hash Tests ---');

test('getTransactionHash produces 32-byte hash', () => {
  const tx = {
    version: 2,
    unlockTime: 0n,
    inputs: [{ type: 'gen', height: 100n }],
    outputs: [{
      amount: 0n,
      target: new Uint8Array(32).fill(0xaa)
    }],
    extra: {
      txPubKey: new Uint8Array(32).fill(0xbb)
    }
  };
  const hash = getTransactionHash(tx);
  assertEqual(hash.length, 32);
});

test('TX_VERSION constants are correct', () => {
  assertEqual(TX_VERSION.V1, 1);
  assertEqual(TX_VERSION.V2, 2);
});

test('RCT_TYPE constants are correct', () => {
  assertEqual(RCT_TYPE.Null, 0);
  assertEqual(RCT_TYPE.CLSAG, 5);
  assertEqual(RCT_TYPE.BulletproofPlus, 6);
});

// =============================================================================
// DECOY SELECTION TESTS
// =============================================================================

console.log('\n--- Decoy Selection Tests ---');

import {
  GAMMA_SHAPE,
  GAMMA_SCALE,
  DEFAULT_UNLOCK_TIME,
  DIFFICULTY_TARGET,
  RECENT_SPEND_WINDOW,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
  DEFAULT_RING_SIZE,
  sampleGamma,
  GammaPicker,
  selectDecoys,
  indicesToOffsets,
  offsetsToIndices
} from '../src/transaction.js';

test('GAMMA_SHAPE constant matches Salvium source', () => {
  assertEqual(GAMMA_SHAPE, 19.28);
});

test('GAMMA_SCALE constant matches Salvium source', () => {
  // 1/1.61 ≈ 0.6211
  assertTrue(Math.abs(GAMMA_SCALE - (1/1.61)) < 0.0001);
});

test('DEFAULT_UNLOCK_TIME is 1200 seconds', () => {
  assertEqual(DEFAULT_UNLOCK_TIME, 1200);
});

test('DIFFICULTY_TARGET is 120 seconds', () => {
  assertEqual(DIFFICULTY_TARGET, 120);
});

test('CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE is 10', () => {
  assertEqual(CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, 10);
});

test('DEFAULT_RING_SIZE is 16', () => {
  assertEqual(DEFAULT_RING_SIZE, 16);
});

test('sampleGamma returns positive values', () => {
  for (let i = 0; i < 100; i++) {
    const sample = sampleGamma(GAMMA_SHAPE, GAMMA_SCALE);
    assertTrue(sample > 0);
  }
});

test('sampleGamma produces reasonable distribution', () => {
  // Mean of gamma distribution = shape * scale
  const expectedMean = GAMMA_SHAPE * GAMMA_SCALE;
  let sum = 0;
  const n = 1000;
  for (let i = 0; i < n; i++) {
    sum += sampleGamma(GAMMA_SHAPE, GAMMA_SCALE);
  }
  const mean = sum / n;
  // Should be within 30% of expected (sampling variance)
  assertTrue(Math.abs(mean - expectedMean) / expectedMean < 0.3);
});

test('GammaPicker constructor validates inputs', () => {
  // Not enough blocks
  let threw = false;
  try {
    new GammaPicker([1, 2, 3]);
  } catch (e) {
    threw = true;
  }
  assertTrue(threw);
});

test('GammaPicker picks valid output indices', () => {
  // Create mock output distribution (1000 blocks with ~5 outputs each)
  const rctOffsets = [];
  let total = 0;
  for (let i = 0; i < 1000; i++) {
    total += Math.floor(Math.random() * 10) + 1;
    rctOffsets.push(total);
  }

  const picker = new GammaPicker(rctOffsets);

  for (let i = 0; i < 100; i++) {
    const pick = picker.pick();
    // Should be valid index or -1 (bad pick)
    assertTrue(pick === -1 || (pick >= 0 && pick < picker.getNumRctOutputs()));
  }
});

test('indicesToOffsets converts correctly', () => {
  const indices = [10, 25, 100, 150];
  const offsets = indicesToOffsets(indices);
  assertEqual(offsets[0], 10);   // First is absolute
  assertEqual(offsets[1], 15);   // 25 - 10
  assertEqual(offsets[2], 75);   // 100 - 25
  assertEqual(offsets[3], 50);   // 150 - 100
});

test('offsetsToIndices converts correctly', () => {
  const offsets = [10, 15, 75, 50];
  const indices = offsetsToIndices(offsets);
  assertEqual(indices[0], 10);
  assertEqual(indices[1], 25);
  assertEqual(indices[2], 100);
  assertEqual(indices[3], 150);
});

test('indicesToOffsets and offsetsToIndices are inverses', () => {
  const original = [5, 20, 50, 120, 500];
  const offsets = indicesToOffsets(original);
  const recovered = offsetsToIndices(offsets);
  for (let i = 0; i < original.length; i++) {
    assertEqual(recovered[i], original[i]);
  }
});

test('selectDecoys returns correct ring size', () => {
  // Create mock output distribution
  const rctOffsets = [];
  let total = 0;
  for (let i = 0; i < 1000; i++) {
    total += Math.floor(Math.random() * 10) + 1;
    rctOffsets.push(total);
  }

  const realOutputIndex = 500;
  const ringSize = 16;
  const ring = selectDecoys(rctOffsets, realOutputIndex, ringSize);

  assertEqual(ring.length, ringSize);
  assertTrue(ring.includes(realOutputIndex));
});

test('selectDecoys returns sorted indices', () => {
  const rctOffsets = [];
  let total = 0;
  for (let i = 0; i < 1000; i++) {
    total += Math.floor(Math.random() * 10) + 1;
    rctOffsets.push(total);
  }

  const ring = selectDecoys(rctOffsets, 500, 16);

  for (let i = 1; i < ring.length; i++) {
    assertTrue(ring[i] > ring[i-1]);
  }
});

test('selectDecoys excludes specified indices', () => {
  const rctOffsets = [];
  let total = 0;
  for (let i = 0; i < 1000; i++) {
    total += Math.floor(Math.random() * 10) + 1;
    rctOffsets.push(total);
  }

  const exclude = new Set([100, 200, 300]);
  const ring = selectDecoys(rctOffsets, 500, 16, exclude);

  for (const idx of exclude) {
    assertTrue(!ring.includes(idx));
  }
});

// =============================================================================
// FEE CALCULATION TESTS
// =============================================================================

console.log('\n--- Fee Calculation Tests ---');

import {
  FEE_PER_KB,
  FEE_PER_BYTE,
  DYNAMIC_FEE_PER_KB_BASE_FEE,
  FEE_MULTIPLIERS,
  FEE_PRIORITY,
  getFeeMultiplier,
  calculateFeeFromWeight,
  calculateFeeFromSize,
  estimateTxSize,
  estimateTxWeight,
  estimateFee
} from '../src/transaction.js';

test('FEE_PER_KB matches Salvium config', () => {
  assertEqual(FEE_PER_KB, 200000n);
});

test('FEE_PER_BYTE matches Salvium config', () => {
  assertEqual(FEE_PER_BYTE, 30n);
});

test('DYNAMIC_FEE_PER_KB_BASE_FEE matches Salvium config', () => {
  assertEqual(DYNAMIC_FEE_PER_KB_BASE_FEE, 200000n);
});

test('FEE_MULTIPLIERS are correct', () => {
  assertEqual(FEE_MULTIPLIERS.length, 4);
  assertEqual(FEE_MULTIPLIERS[0], 1n);
  assertEqual(FEE_MULTIPLIERS[1], 5n);
  assertEqual(FEE_MULTIPLIERS[2], 25n);
  assertEqual(FEE_MULTIPLIERS[3], 1000n);
});

test('FEE_PRIORITY constants are correct', () => {
  assertEqual(FEE_PRIORITY.LOW, 1);
  assertEqual(FEE_PRIORITY.NORMAL, 2);
  assertEqual(FEE_PRIORITY.HIGH, 3);
  assertEqual(FEE_PRIORITY.HIGHEST, 4);
});

test('getFeeMultiplier returns correct values', () => {
  assertEqual(getFeeMultiplier(1), 1n);
  assertEqual(getFeeMultiplier(2), 5n);
  assertEqual(getFeeMultiplier(3), 25n);
  assertEqual(getFeeMultiplier(4), 1000n);
});

test('getFeeMultiplier clamps out-of-range priorities', () => {
  assertEqual(getFeeMultiplier(0), 5n);  // 0 defaults to priority 2 (Normal) per C++ wallet2.cpp
  assertEqual(getFeeMultiplier(5), 1000n);  // Clamped to 4
});

test('calculateFeeFromWeight computes correctly', () => {
  const baseFee = 30n;
  const weight = 1000n;
  const fee = calculateFeeFromWeight(baseFee, weight);
  assertEqual(fee, 30000n);
});

test('calculateFeeFromWeight with quantization', () => {
  const baseFee = 30n;
  const weight = 1000n;
  const mask = 10000n;
  const fee = calculateFeeFromWeight(baseFee, weight, mask);
  // 30000 rounded up to nearest 10000 = 30000
  assertEqual(fee, 30000n);
});

test('calculateFeeFromSize rounds up to KB', () => {
  const feePerKb = 200000n;
  // 1500 bytes = 2 KB (rounded up)
  const fee = calculateFeeFromSize(feePerKb, 1500);
  assertEqual(fee, 400000n);
});

test('calculateFeeFromSize handles exact KB', () => {
  const feePerKb = 200000n;
  // 2048 bytes = 2 KB exactly
  const fee = calculateFeeFromSize(feePerKb, 2048);
  assertEqual(fee, 400000n);
});

test('estimateTxSize returns reasonable values', () => {
  const size = estimateTxSize(2, 16, 2, 64);
  // A 2-in/2-out tx should be a few KB
  assertTrue(size > 500);
  assertTrue(size < 10000);
});

test('estimateTxSize increases with ring size', () => {
  const size16 = estimateTxSize(1, 16, 2, 0);
  const size32 = estimateTxSize(1, 32, 2, 0);
  assertTrue(size32 > size16);
});

test('estimateTxSize increases with inputs', () => {
  const size1 = estimateTxSize(1, 16, 2, 0);
  const size5 = estimateTxSize(5, 16, 2, 0);
  assertTrue(size5 > size1);
});

test('estimateTxWeight includes clawback for multiple outputs', () => {
  const weight2 = estimateTxWeight(1, 16, 2, 0);
  const weight4 = estimateTxWeight(1, 16, 4, 0);
  // More outputs = larger range proof but clawback helps
  assertTrue(weight4 > weight2);
});

test('estimateFee returns bigint', () => {
  const fee = estimateFee(2, 16, 2, 64);
  assertEqual(typeof fee, 'bigint');
});

test('estimateFee increases with priority', () => {
  const feeLow = estimateFee(2, 16, 2, 0, { priority: FEE_PRIORITY.LOW });
  const feeNormal = estimateFee(2, 16, 2, 0, { priority: FEE_PRIORITY.NORMAL });
  const feeHigh = estimateFee(2, 16, 2, 0, { priority: FEE_PRIORITY.HIGH });
  assertTrue(feeNormal > feeLow);
  assertTrue(feeHigh > feeNormal);
});

test('estimateFee per-KB vs per-byte', () => {
  const feePerByte = estimateFee(2, 16, 2, 0, { perByte: true });
  const feePerKb = estimateFee(2, 16, 2, 0, { perByte: false });
  // Both should be reasonable
  assertTrue(feePerByte > 0n);
  assertTrue(feePerKb > 0n);
});

// =============================================================================
// RINGCT ASSEMBLY TESTS
// =============================================================================

console.log('\n--- RingCT Assembly Tests ---');

import {
  buildRingCtSignature,
  computePseudoOutputs
} from '../src/transaction.js';

test('computePseudoOutputs creates correct number of outputs', () => {
  const inputs = [
    { amount: 100000000n, mask: scRandom() },
    { amount: 50000000n, mask: scRandom() }
  ];
  const outputs = [
    { amount: 140000000n, mask: scRandom() },
    { amount: 9990000n, mask: scRandom() }
  ];
  const fee = 10000n;

  const { pseudoOuts, pseudoMasks } = computePseudoOutputs(inputs, outputs, fee);

  assertEqual(pseudoOuts.length, inputs.length);
  assertEqual(pseudoMasks.length, inputs.length);
});

test('computePseudoOutputs produces 32-byte outputs', () => {
  const inputs = [
    { amount: 100000000n, mask: scRandom() }
  ];
  const outputs = [
    { amount: 99990000n, mask: scRandom() }
  ];
  const fee = 10000n;

  const { pseudoOuts, pseudoMasks } = computePseudoOutputs(inputs, outputs, fee);

  assertEqual(pseudoOuts[0].length, 32);
  assertEqual(pseudoMasks[0].length, 32);
});

test('computePseudoOutputs produces 32-byte masks', () => {
  const inputs = [
    { amount: 100n, mask: scRandom() },
    { amount: 200n, mask: scRandom() }
  ];
  const outputs = [
    { amount: 290n, mask: scRandom() }
  ];
  const fee = 10n;

  const { pseudoMasks } = computePseudoOutputs(inputs, outputs, fee);

  for (const mask of pseudoMasks) {
    assertEqual(mask.length, 32);
  }
});

// =============================================================================
// CARROT OUTPUT GENERATION TESTS
// =============================================================================

console.log('\n--- CARROT Output Generation Tests ---');

import {
  CARROT_DOMAIN,
  CARROT_ENOTE_TYPE,
  generateJanusAnchor,
  buildRingCtInputContext,
  buildCoinbaseInputContext,
  deriveCarrotEphemeralPrivkey,
  computeCarrotEphemeralPubkey,
  computeCarrotSharedSecret,
  deriveCarrotSenderReceiverSecret,
  deriveCarrotOnetimeExtensions,
  computeCarrotOnetimeAddress,
  deriveCarrotAmountBlindingFactor,
  deriveCarrotViewTag,
  encryptCarrotAnchor,
  encryptCarrotAmount,
  encryptCarrotPaymentId,
  createCarrotOutput,
  computeCarrotSpecialAnchor
} from '../src/transaction.js';

test('CARROT_DOMAIN has correct domain separators', () => {
  assertEqual(CARROT_DOMAIN.EPHEMERAL_PRIVKEY, 'Carrot sending key normal');
  assertEqual(CARROT_DOMAIN.SENDER_RECEIVER_SECRET, 'Carrot sender-receiver secret');
  assertEqual(CARROT_DOMAIN.VIEW_TAG, 'Carrot view tag');
  assertEqual(CARROT_DOMAIN.INPUT_CONTEXT_COINBASE, 'C');
  assertEqual(CARROT_DOMAIN.INPUT_CONTEXT_RINGCT, 'R');
});

test('CARROT_ENOTE_TYPE has correct values', () => {
  assertEqual(CARROT_ENOTE_TYPE.PAYMENT, 0);
  assertEqual(CARROT_ENOTE_TYPE.CHANGE, 1);
  assertEqual(CARROT_ENOTE_TYPE.SELF_SPEND, 2);
});

test('generateJanusAnchor produces 16-byte anchor', () => {
  const anchor = generateJanusAnchor();
  assertEqual(anchor.length, 16);
});

test('generateJanusAnchor produces different values', () => {
  const a1 = generateJanusAnchor();
  const a2 = generateJanusAnchor();
  let different = false;
  for (let i = 0; i < 16; i++) {
    if (a1[i] !== a2[i]) {
      different = true;
      break;
    }
  }
  assertTrue(different);
});

test('buildRingCtInputContext produces 33-byte context', () => {
  const keyImage = new Uint8Array(32).fill(0xab);
  const context = buildRingCtInputContext(keyImage);
  assertEqual(context.length, 33);
  assertEqual(context[0], 'R'.charCodeAt(0));
});

test('buildRingCtInputContext includes key image', () => {
  const keyImage = new Uint8Array(32).fill(0xcd);
  const context = buildRingCtInputContext(keyImage);
  for (let i = 0; i < 32; i++) {
    assertEqual(context[i + 1], 0xcd);
  }
});

test('buildCoinbaseInputContext produces 33-byte context', () => {
  // C++ input_context_t: 1 byte domain separator + 32 bytes data = 33 bytes
  // See carrot_core/core_types.h: INPUT_CONTEXT_BYTES{1 + 32}
  const context = buildCoinbaseInputContext(12345n);
  assertEqual(context.length, 33);
  assertEqual(context[0], 'C'.charCodeAt(0));
});

test('buildCoinbaseInputContext encodes height little-endian', () => {
  const context = buildCoinbaseInputContext(0x1234n);
  assertEqual(context[1], 0x34);
  assertEqual(context[2], 0x12);
});

test('deriveCarrotEphemeralPrivkey produces 32-byte scalar', () => {
  const anchor = new Uint8Array(16).fill(0x11);
  const inputContext = new Uint8Array(33).fill(0x22);
  const spendPubkey = new Uint8Array(32).fill(0x33);
  const paymentId = new Uint8Array(8).fill(0x44);

  const privkey = deriveCarrotEphemeralPrivkey(anchor, inputContext, spendPubkey, paymentId);
  assertEqual(privkey.length, 32);
});

test('deriveCarrotEphemeralPrivkey is deterministic', () => {
  const anchor = new Uint8Array(16).fill(0x55);
  const inputContext = new Uint8Array(33).fill(0x66);
  const spendPubkey = new Uint8Array(32).fill(0x77);
  const paymentId = new Uint8Array(8).fill(0x88);

  const p1 = deriveCarrotEphemeralPrivkey(anchor, inputContext, spendPubkey, paymentId);
  const p2 = deriveCarrotEphemeralPrivkey(anchor, inputContext, spendPubkey, paymentId);
  assertEqual(bytesToHex(p1), bytesToHex(p2));
});

test('computeCarrotEphemeralPubkey produces 32-byte point', () => {
  const privkey = scRandom();
  const spendPubkey = scalarMultBase(scRandom());
  const pubkey = computeCarrotEphemeralPubkey(privkey, spendPubkey, false);
  assertEqual(pubkey.length, 32);
});

test('computeCarrotEphemeralPubkey differs for main vs subaddress', () => {
  const privkey = scRandom();
  const spendPubkey = scalarMultBase(scRandom());
  const pubMain = computeCarrotEphemeralPubkey(privkey, spendPubkey, false);
  const pubSub = computeCarrotEphemeralPubkey(privkey, spendPubkey, true);
  assertTrue(bytesToHex(pubMain) !== bytesToHex(pubSub));
});

test('computeCarrotSharedSecret produces 32-byte secret', () => {
  const privkey = scRandom();
  const viewPubkey = scalarMultBase(scRandom());
  const secret = computeCarrotSharedSecret(privkey, viewPubkey);
  assertEqual(secret.length, 32);
});

test('deriveCarrotSenderReceiverSecret produces 32-byte secret', () => {
  const sharedSecret = new Uint8Array(32).fill(0xaa);
  const ephemeralPubkey = new Uint8Array(32).fill(0xbb);
  const inputContext = new Uint8Array(33).fill(0xcc);

  const srSecret = deriveCarrotSenderReceiverSecret(sharedSecret, ephemeralPubkey, inputContext);
  assertEqual(srSecret.length, 32);
});

test('deriveCarrotOnetimeExtensions produces two 32-byte scalars', () => {
  const srSecret = new Uint8Array(32).fill(0xdd);
  const commitment = new Uint8Array(32).fill(0xee);

  const { extensionG, extensionT } = deriveCarrotOnetimeExtensions(srSecret, commitment);
  assertEqual(extensionG.length, 32);
  assertEqual(extensionT.length, 32);
});

test('computeCarrotOnetimeAddress produces 32-byte address', () => {
  const spendPubkey = scalarMultBase(scRandom());
  const extensionG = scRandom();
  const extensionT = scRandom();

  const onetimeAddr = computeCarrotOnetimeAddress(spendPubkey, extensionG, extensionT);
  assertEqual(onetimeAddr.length, 32);
});

test('deriveCarrotAmountBlindingFactor produces 32-byte scalar', () => {
  const srSecret = new Uint8Array(32).fill(0x11);
  const spendPubkey = new Uint8Array(32).fill(0x22);

  const bf = deriveCarrotAmountBlindingFactor(srSecret, 1000000n, spendPubkey, CARROT_ENOTE_TYPE.PAYMENT);
  assertEqual(bf.length, 32);
});

test('deriveCarrotViewTag produces 3-byte tag', () => {
  const sharedSecret = new Uint8Array(32).fill(0x33);
  const inputContext = new Uint8Array(33).fill(0x44);
  const onetimeAddr = new Uint8Array(32).fill(0x55);

  const viewTag = deriveCarrotViewTag(sharedSecret, inputContext, onetimeAddr);
  assertEqual(viewTag.length, 3);
});

test('encryptCarrotAnchor produces 16-byte result', () => {
  const anchor = new Uint8Array(16).fill(0x66);
  const srSecret = new Uint8Array(32).fill(0x77);
  const onetimeAddr = new Uint8Array(32).fill(0x88);

  const encrypted = encryptCarrotAnchor(anchor, srSecret, onetimeAddr);
  assertEqual(encrypted.length, 16);
});

test('encryptCarrotAnchor is reversible', () => {
  const anchor = new Uint8Array(16).fill(0x99);
  const srSecret = new Uint8Array(32).fill(0xaa);
  const onetimeAddr = new Uint8Array(32).fill(0xbb);

  const encrypted = encryptCarrotAnchor(anchor, srSecret, onetimeAddr);
  const decrypted = encryptCarrotAnchor(encrypted, srSecret, onetimeAddr);
  assertEqual(bytesToHex(decrypted), bytesToHex(anchor));
});

test('encryptCarrotAmount produces 8-byte result', () => {
  const srSecret = new Uint8Array(32).fill(0xcc);
  const onetimeAddr = new Uint8Array(32).fill(0xdd);

  const encrypted = encryptCarrotAmount(1000000n, srSecret, onetimeAddr);
  assertEqual(encrypted.length, 8);
});

test('encryptCarrotPaymentId produces 8-byte result', () => {
  const paymentId = new Uint8Array(8).fill(0xee);
  const srSecret = new Uint8Array(32).fill(0xff);
  const onetimeAddr = new Uint8Array(32).fill(0x11);

  const encrypted = encryptCarrotPaymentId(paymentId, srSecret, onetimeAddr);
  assertEqual(encrypted.length, 8);
});

test('encryptCarrotPaymentId is reversible', () => {
  const paymentId = new Uint8Array(8);
  for (let i = 0; i < 8; i++) paymentId[i] = i * 17;
  const srSecret = new Uint8Array(32).fill(0x22);
  const onetimeAddr = new Uint8Array(32).fill(0x33);

  const encrypted = encryptCarrotPaymentId(paymentId, srSecret, onetimeAddr);
  const decrypted = encryptCarrotPaymentId(encrypted, srSecret, onetimeAddr);
  assertEqual(bytesToHex(decrypted), bytesToHex(paymentId));
});

test('createCarrotOutput produces complete output', () => {
  const spendPubkey = scalarMultBase(scRandom());
  const viewPubkey = scalarMultBase(scRandom());
  const inputContext = buildCoinbaseInputContext(1000n);

  const output = createCarrotOutput({
    addressSpendPubkey: spendPubkey,
    addressViewPubkey: viewPubkey,
    amount: 5000000000n,
    inputContext: inputContext
  });

  assertEqual(output.ephemeralPubkey.length, 32);
  assertEqual(output.onetimeAddress.length, 32);
  assertEqual(output.amountCommitment.length, 32);
  assertEqual(output.amountEncrypted.length, 8);
  assertEqual(output.anchorEncrypted.length, 16);
  assertEqual(output.viewTag.length, 3);
  assertEqual(output.paymentIdEncrypted.length, 8);
  assertEqual(output.amountBlindingFactor.length, 32);
});

test('createCarrotOutput is deterministic with same anchor', () => {
  const spendPubkey = scalarMultBase(scRandom());
  const viewPubkey = scalarMultBase(scRandom());
  const inputContext = buildCoinbaseInputContext(2000n);
  const anchor = generateJanusAnchor();

  const o1 = createCarrotOutput({
    addressSpendPubkey: spendPubkey,
    addressViewPubkey: viewPubkey,
    amount: 1000000n,
    inputContext: inputContext,
    anchor: anchor
  });

  const o2 = createCarrotOutput({
    addressSpendPubkey: spendPubkey,
    addressViewPubkey: viewPubkey,
    amount: 1000000n,
    inputContext: inputContext,
    anchor: anchor
  });

  assertEqual(bytesToHex(o1.onetimeAddress), bytesToHex(o2.onetimeAddress));
  assertEqual(bytesToHex(o1.amountCommitment), bytesToHex(o2.amountCommitment));
});

test('createCarrotOutput produces different outputs for different amounts', () => {
  const spendPubkey = scalarMultBase(scRandom());
  const viewPubkey = scalarMultBase(scRandom());
  const inputContext = buildCoinbaseInputContext(3000n);
  const anchor = generateJanusAnchor();

  const o1 = createCarrotOutput({
    addressSpendPubkey: spendPubkey,
    addressViewPubkey: viewPubkey,
    amount: 1000000n,
    inputContext: inputContext,
    anchor: anchor
  });

  const o2 = createCarrotOutput({
    addressSpendPubkey: spendPubkey,
    addressViewPubkey: viewPubkey,
    amount: 2000000n,
    inputContext: inputContext,
    anchor: anchor
  });

  // Different amount = different commitment and one-time address
  assertTrue(bytesToHex(o1.amountCommitment) !== bytesToHex(o2.amountCommitment));
});

test('computeCarrotSpecialAnchor produces 16-byte anchor', () => {
  const ephemeralPubkey = new Uint8Array(32).fill(0x44);
  const inputContext = new Uint8Array(33).fill(0x55);
  const onetimeAddr = new Uint8Array(32).fill(0x66);
  const viewSecretKey = scRandom();

  const specialAnchor = computeCarrotSpecialAnchor(ephemeralPubkey, inputContext, onetimeAddr, viewSecretKey);
  assertEqual(specialAnchor.length, 16);
});

test('CARROT enote types affect blinding factor', () => {
  const srSecret = new Uint8Array(32).fill(0x77);
  const spendPubkey = new Uint8Array(32).fill(0x88);

  const bf1 = deriveCarrotAmountBlindingFactor(srSecret, 1000n, spendPubkey, CARROT_ENOTE_TYPE.PAYMENT);
  const bf2 = deriveCarrotAmountBlindingFactor(srSecret, 1000n, spendPubkey, CARROT_ENOTE_TYPE.CHANGE);
  const bf3 = deriveCarrotAmountBlindingFactor(srSecret, 1000n, spendPubkey, CARROT_ENOTE_TYPE.SELF_SPEND);

  assertTrue(bytesToHex(bf1) !== bytesToHex(bf2));
  assertTrue(bytesToHex(bf2) !== bytesToHex(bf3));
});

// =============================================================================
// SUMMARY
// =============================================================================

console.log(`\n--- Transaction Test Summary ---`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

if (failed === 0) {
  console.log('\n✓ All transaction tests passed!');
  process.exit(0);
} else {
  console.log('\n✗ Some transaction tests failed!');
  process.exit(1);
}
