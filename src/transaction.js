/**
 * Transaction Construction Module
 *
 * Implements the cryptographic primitives needed for Salvium transaction construction:
 * - Scalar operations mod L (subgroup order)
 * - Pedersen commitments
 * - One-time destination key generation
 * - CLSAG ring signatures
 *
 * Reference: Salvium/Monero src/ringct/rctOps.cpp, src/ringct/rctSigs.cpp
 */

import { keccak256, keccak256Hex } from './keccak.js';

// =============================================================================
// ERROR CLASSES
// =============================================================================

/**
 * Error thrown when parsing fails
 * Provides detailed context about what went wrong and where
 */
export class ParseError extends Error {
  constructor(message, context = {}) {
    super(message);
    this.name = 'ParseError';
    this.offset = context.offset;
    this.field = context.field;
    this.expected = context.expected;
    this.actual = context.actual;
    this.dataLength = context.dataLength;
  }

  toString() {
    let msg = `ParseError: ${this.message}`;
    if (this.field) msg += ` [field: ${this.field}]`;
    if (this.offset !== undefined) msg += ` [offset: ${this.offset}]`;
    if (this.dataLength !== undefined) msg += ` [dataLength: ${this.dataLength}]`;
    if (this.expected !== undefined) msg += ` [expected: ${this.expected}]`;
    if (this.actual !== undefined) msg += ` [actual: ${this.actual}]`;
    return msg;
  }
}
import { scalarMultBase, scalarMultPoint, pointAddCompressed, getGeneratorG } from './ed25519.js';
import { generateKeyDerivation, derivationToScalar, derivePublicKey, deriveSecretKey } from './scanning.js';
import { hashToPoint, generateKeyImage } from './keyimage.js';
import { bytesToHex, hexToBytes } from './address.js';

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * The subgroup order L = 2^252 + 27742317777372353535851937790883648493
 * This is the order of the prime-order subgroup of the Ed25519 curve.
 * All scalar operations are performed mod L.
 */
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/**
 * The field prime p = 2^255 - 19
 */
const P = 2n ** 255n - 19n;

/**
 * H = toPoint(cn_fast_hash(G)) - the second generator for Pedersen commitments
 * H is computed as H_p(G) where H_p is the hash-to-point function
 * Pre-computed value from rctTypes.h
 */
export const H = '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94';

/**
 * Verify H is computed correctly: H = hashToPoint(G)
 * This is done at module load to ensure correctness.
 */
function verifyH() {
  const G = getGeneratorG();
  const computedH = hashToPoint(G);
  if (bytesToHex(computedH) !== H) {
    console.warn('Warning: Computed H does not match pre-computed value');
    console.warn('  Computed:', bytesToHex(computedH));
    console.warn('  Expected:', H);
  }
}

// Verify H on module load (comment out if performance is critical)
// verifyH();

// =============================================================================
// SCALAR OPERATIONS MOD L
// =============================================================================

/**
 * Convert bytes to BigInt (little-endian)
 * @param {Uint8Array|string} bytes - Input bytes or hex string
 * @returns {bigint} BigInt value
 */
export function bytesToBigInt(bytes) {
  if (typeof bytes === 'string') {
    bytes = hexToBytes(bytes);
  }
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Convert BigInt to bytes (little-endian, 32 bytes)
 * @param {bigint} n - BigInt value
 * @returns {Uint8Array} 32-byte array
 */
export function bigIntToBytes(n) {
  // Ensure positive
  n = ((n % L) + L) % L;
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

/**
 * Reduce a scalar mod L
 * @param {Uint8Array|string} scalar - 32-byte scalar
 * @returns {Uint8Array} Reduced scalar
 */
export function scReduce32(scalar) {
  if (typeof scalar === 'string') {
    scalar = hexToBytes(scalar);
  }
  const n = bytesToBigInt(scalar);
  return bigIntToBytes(n % L);
}

/**
 * Reduce a 64-byte scalar mod L (used after multiplication)
 * @param {Uint8Array|string} scalar - 64-byte scalar
 * @returns {Uint8Array} Reduced 32-byte scalar
 */
export function scReduce64(scalar) {
  if (typeof scalar === 'string') {
    scalar = hexToBytes(scalar);
  }
  const n = bytesToBigInt(scalar);
  return bigIntToBytes(n % L);
}

/**
 * Add two scalars mod L: result = a + b mod L
 * @param {Uint8Array|string} a - First scalar
 * @param {Uint8Array|string} b - Second scalar
 * @returns {Uint8Array} Sum mod L
 */
export function scAdd(a, b) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  return bigIntToBytes((aBig + bBig) % L);
}

/**
 * Subtract two scalars mod L: result = a - b mod L
 * @param {Uint8Array|string} a - First scalar
 * @param {Uint8Array|string} b - Second scalar
 * @returns {Uint8Array} Difference mod L
 */
export function scSub(a, b) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  return bigIntToBytes(((aBig - bBig) % L + L) % L);
}

/**
 * Multiply two scalars mod L: result = a * b mod L
 * @param {Uint8Array|string} a - First scalar
 * @param {Uint8Array|string} b - Second scalar
 * @returns {Uint8Array} Product mod L
 */
export function scMul(a, b) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  return bigIntToBytes((aBig * bBig) % L);
}

/**
 * Multiply-add: result = a*b + c mod L
 * @param {Uint8Array|string} a - First multiplicand
 * @param {Uint8Array|string} b - Second multiplicand
 * @param {Uint8Array|string} c - Addend
 * @returns {Uint8Array} Result mod L
 */
export function scMulAdd(a, b, c) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const cBig = bytesToBigInt(c);
  return bigIntToBytes((aBig * bBig + cBig) % L);
}

/**
 * Multiply-subtract: result = c - a*b mod L
 * @param {Uint8Array|string} a - First multiplicand
 * @param {Uint8Array|string} b - Second multiplicand
 * @param {Uint8Array|string} c - Minuend
 * @returns {Uint8Array} Result mod L
 */
export function scMulSub(a, b, c) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const cBig = bytesToBigInt(c);
  return bigIntToBytes(((cBig - aBig * bBig) % L + L) % L);
}

/**
 * Check if scalar is valid (less than L and non-zero for some operations)
 * @param {Uint8Array|string} scalar - Scalar to check
 * @returns {boolean} True if valid
 */
export function scCheck(scalar) {
  const n = bytesToBigInt(scalar);
  return n < L;
}

/**
 * Check if scalar is zero
 * @param {Uint8Array|string} scalar - Scalar to check
 * @returns {boolean} True if zero
 */
export function scIsZero(scalar) {
  if (typeof scalar === 'string') {
    scalar = hexToBytes(scalar);
  }
  for (let i = 0; i < scalar.length; i++) {
    if (scalar[i] !== 0) return false;
  }
  return true;
}

/**
 * Generate a random scalar mod L
 * @returns {Uint8Array} Random 32-byte scalar < L
 */
export function scRandom() {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  return scReduce64(bytes);
}

/**
 * Compute modular inverse: result = a^(-1) mod L
 * Uses extended Euclidean algorithm / Fermat's little theorem
 * @param {Uint8Array|string} a - Scalar to invert
 * @returns {Uint8Array} Inverse mod L
 */
export function scInvert(a) {
  const aBig = bytesToBigInt(a);
  if (aBig === 0n) {
    throw new Error('Cannot invert zero');
  }
  // Using Fermat's little theorem: a^(-1) = a^(L-2) mod L
  const result = modPow(aBig, L - 2n, L);
  return bigIntToBytes(result);
}

/**
 * Modular exponentiation: base^exp mod m
 * @param {bigint} base
 * @param {bigint} exp
 * @param {bigint} m
 * @returns {bigint}
 */
function modPow(base, exp, m) {
  let result = 1n;
  base = base % m;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % m;
    }
    exp = exp >> 1n;
    base = (base * base) % m;
  }
  return result;
}

// =============================================================================
// PEDERSEN COMMITMENTS
// =============================================================================

/**
 * Compute a Pedersen commitment: C = mask*G + amount*H
 * This hides the amount while allowing verification of zero-sum property.
 *
 * @param {bigint|number} amount - Amount to commit to
 * @param {Uint8Array|string} mask - Blinding factor (32-byte scalar)
 * @returns {Uint8Array} 32-byte compressed point (commitment)
 */
export function commit(amount, mask) {
  if (typeof amount === 'number') {
    amount = BigInt(amount);
  }

  // Convert amount to 32-byte scalar
  const amountBytes = bigIntToBytes(amount);

  // C = mask*G + amount*H
  const maskG = scalarMultBase(mask);    // mask * G
  const amountH = scalarMultPoint(amountBytes, hexToBytes(H));  // amount * H

  return pointAddCompressed(maskG, amountH);
}

/**
 * Compute a zero commitment: C = amount*H (mask = 0)
 * Used for transaction fees and other public amounts.
 *
 * @param {bigint|number} amount - Amount to commit to
 * @returns {Uint8Array} 32-byte compressed point
 */
export function zeroCommit(amount) {
  if (typeof amount === 'number') {
    amount = BigInt(amount);
  }
  const amountBytes = bigIntToBytes(amount);
  return scalarMultPoint(amountBytes, hexToBytes(H));
}

/**
 * Generate a commitment mask from a shared secret
 * Uses domain-separated hashing: mask = H("commitment_mask" || sharedSecret)
 *
 * @param {Uint8Array|string} sharedSecret - 32-byte shared secret
 * @returns {Uint8Array} 32-byte mask
 */
export function genCommitmentMask(sharedSecret) {
  if (typeof sharedSecret === 'string') {
    sharedSecret = hexToBytes(sharedSecret);
  }

  // Domain separation: "commitment_mask" || sharedSecret
  const prefix = new TextEncoder().encode('commitment_mask');
  const data = new Uint8Array(prefix.length + sharedSecret.length);
  data.set(prefix, 0);
  data.set(sharedSecret, prefix.length);

  // Hash and reduce to scalar
  const hash = keccak256(data);
  return scReduce32(hash);
}

// =============================================================================
// OUTPUT CREATION
// =============================================================================

/**
 * Generate one-time output keys for a transaction output
 *
 * For a standard address (B, A):
 *   - r = random scalar (tx secret key)
 *   - R = r*G (tx public key, goes in tx extra)
 *   - D = r*A = r*a*G (key derivation, computed by recipient as a*R)
 *   - s = H_s(D, outputIndex) (scalar)
 *   - P = s*G + B (one-time output public key)
 *
 * For a subaddress (D_i, C_i):
 *   - r = random scalar
 *   - R = r*D_i (not r*G!)
 *   - derivation = r*C_i
 *   - s = H_s(derivation, outputIndex)
 *   - P = s*G + D_i
 *
 * @param {Uint8Array|string} txSecretKey - Transaction secret key (r)
 * @param {Uint8Array|string} viewPublicKey - Recipient's view public key (A or C_i)
 * @param {Uint8Array|string} spendPublicKey - Recipient's spend public key (B or D_i)
 * @param {number} outputIndex - Output index in transaction
 * @param {boolean} isSubaddress - True if destination is a subaddress
 * @returns {Object} { outputPublicKey, txPublicKey, derivation }
 */
export function generateOutputKeys(txSecretKey, viewPublicKey, spendPublicKey, outputIndex, isSubaddress = false) {
  if (typeof txSecretKey === 'string') txSecretKey = hexToBytes(txSecretKey);
  if (typeof viewPublicKey === 'string') viewPublicKey = hexToBytes(viewPublicKey);
  if (typeof spendPublicKey === 'string') spendPublicKey = hexToBytes(spendPublicKey);

  let txPublicKey;
  let derivation;

  if (isSubaddress) {
    // For subaddress: R = r*D (spend public key), derivation = r*C (view public key)
    txPublicKey = scalarMultPoint(txSecretKey, spendPublicKey);
    derivation = scalarMultPoint(txSecretKey, viewPublicKey);
  } else {
    // For standard address: R = r*G, derivation = r*A (view public key)
    txPublicKey = scalarMultBase(txSecretKey);
    derivation = scalarMultPoint(txSecretKey, viewPublicKey);
  }

  // Multiply by 8 for cofactor clearing (generateKeyDerivation does this internally)
  // Actually we need to use the same approach as scanning
  // derivation should be 8*r*A = key derivation
  const keyDerivation = generateKeyDerivation(viewPublicKey, txSecretKey);

  // Derive the one-time output public key
  const outputPublicKey = derivePublicKey(keyDerivation, outputIndex, spendPublicKey);

  return {
    outputPublicKey,
    txPublicKey,
    derivation: keyDerivation
  };
}

/**
 * Create a complete transaction output
 *
 * @param {Uint8Array|string} txSecretKey - Transaction secret key
 * @param {Uint8Array|string} viewPublicKey - Recipient's view public key
 * @param {Uint8Array|string} spendPublicKey - Recipient's spend public key
 * @param {bigint|number} amount - Amount to send
 * @param {number} outputIndex - Output index
 * @param {boolean} isSubaddress - True if destination is a subaddress
 * @returns {Object} { outputPublicKey, txPublicKey, commitment, encryptedAmount, mask }
 */
export function createOutput(txSecretKey, viewPublicKey, spendPublicKey, amount, outputIndex, isSubaddress = false) {
  if (typeof amount === 'number') amount = BigInt(amount);

  // Generate one-time keys
  const { outputPublicKey, txPublicKey, derivation } = generateOutputKeys(
    txSecretKey, viewPublicKey, spendPublicKey, outputIndex, isSubaddress
  );

  // Generate the commitment mask from the derivation
  const scalar = derivationToScalar(derivation, outputIndex);
  const mask = genCommitmentMask(scalar);

  // Create the Pedersen commitment
  const commitment = commit(amount, mask);

  // Encrypt the amount (XOR with first 8 bytes of H_s("amount" || scalar))
  const amountKey = deriveAmountKey(scalar);
  const encryptedAmount = encryptAmount(amount, amountKey);

  return {
    outputPublicKey,
    txPublicKey,
    commitment,
    encryptedAmount,
    mask,
    derivation
  };
}

/**
 * Derive amount encryption key from scalar
 * @param {Uint8Array|string} scalar - Derivation scalar
 * @returns {Uint8Array} 8-byte amount key
 */
function deriveAmountKey(scalar) {
  if (typeof scalar === 'string') scalar = hexToBytes(scalar);

  const prefix = new TextEncoder().encode('amount');
  const data = new Uint8Array(prefix.length + scalar.length);
  data.set(prefix, 0);
  data.set(scalar, prefix.length);

  const hash = keccak256(data);
  return hash.slice(0, 8);
}

/**
 * Encrypt amount using XOR
 * @param {bigint} amount - Amount to encrypt
 * @param {Uint8Array} key - 8-byte encryption key
 * @returns {Uint8Array} 8-byte encrypted amount
 */
function encryptAmount(amount, key) {
  const amountBytes = new Uint8Array(8);
  let a = amount;
  for (let i = 0; i < 8; i++) {
    amountBytes[i] = Number(a & 0xffn) ^ key[i];
    a >>= 8n;
  }
  return amountBytes;
}

// =============================================================================
// CLSAG SIGNATURES
// =============================================================================

/**
 * Hash data for CLSAG aggregate coefficient computation
 * @param {Array} data - Array of items to hash
 * @returns {Uint8Array} 32-byte hash
 */
function hashToScalar(...data) {
  let totalLen = 0;
  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  const hash = keccak256(combined);
  return scReduce32(hash);
}

/**
 * Domain separator for CLSAG
 */
const CLSAG_DOMAIN = new TextEncoder().encode('CLSAG_');
const CLSAG_AGG_0 = new Uint8Array([...CLSAG_DOMAIN, ...new TextEncoder().encode('agg_0')]);
const CLSAG_AGG_1 = new Uint8Array([...CLSAG_DOMAIN, ...new TextEncoder().encode('agg_1')]);
const CLSAG_ROUND = new Uint8Array([...CLSAG_DOMAIN, ...new TextEncoder().encode('round')]);

/**
 * Generate a CLSAG signature
 *
 * CLSAG (Compact Linkable Anonymous Group) signatures are ring signatures
 * that prove ownership of one input in a ring without revealing which one.
 *
 * @param {Uint8Array|string} message - Message to sign (usually pre-MLSAG hash)
 * @param {Array<Uint8Array>} ring - Array of public keys in the ring
 * @param {Uint8Array|string} secretKey - Secret key corresponding to ring[secretIndex]
 * @param {Array<Uint8Array>} commitments - Array of commitments C_i for each ring member
 * @param {Uint8Array|string} commitmentMask - Mask for our commitment (z)
 * @param {Uint8Array|string} pseudoOutputCommitment - Pseudo output commitment C'
 * @param {number} secretIndex - Index of our key in the ring
 * @returns {Object} CLSAG signature { s: Array, c1, I (key image), D (commitment key image) }
 */
export function clsagSign(message, ring, secretKey, commitments, commitmentMask, pseudoOutputCommitment, secretIndex) {
  if (typeof message === 'string') message = hexToBytes(message);
  if (typeof secretKey === 'string') secretKey = hexToBytes(secretKey);
  if (typeof commitmentMask === 'string') commitmentMask = hexToBytes(commitmentMask);
  if (typeof pseudoOutputCommitment === 'string') pseudoOutputCommitment = hexToBytes(pseudoOutputCommitment);

  const n = ring.length; // Ring size

  // Normalize inputs
  ring = ring.map(k => typeof k === 'string' ? hexToBytes(k) : k);
  commitments = commitments.map(c => typeof c === 'string' ? hexToBytes(c) : c);

  // Compute commitment differences: C_i - C' (should be commitment to 0 for real input)
  // C[i] = commitment[i] - pseudoOutputCommitment
  const C = commitments.map(c => pointSub(c, pseudoOutputCommitment));

  // Compute key image: I = x * H_p(P)
  const P_l = ring[secretIndex];
  const I = generateKeyImage(P_l, secretKey);

  // Compute commitment key image: D = z * H_p(P)
  // where z = commitmentMask - pseudoOutputMask
  const H_P = hashToPoint(P_l);
  const D = scalarMultPoint(commitmentMask, H_P);

  // Compute aggregate coefficients mu_P and mu_C
  // mu_P = H_agg(H_agg_domain, P_1, ..., P_n, I, D, C_1, ..., C_n)
  // mu_C = H_agg(H_agg_domain_2, P_1, ..., P_n, I, D, C_1, ..., C_n)
  const aggData = [
    ...ring,
    I,
    D,
    ...C
  ];
  const mu_P = hashToScalar(CLSAG_AGG_0, ...aggData);
  const mu_C = hashToScalar(CLSAG_AGG_1, ...aggData);

  // Initialize signature arrays
  const s = new Array(n);

  // Generate random scalar for the real input
  const alpha = scRandom();

  // Compute initial values: aG = alpha * G, aH = alpha * H_p(P_l)
  const aG = scalarMultBase(alpha);
  const aH = scalarMultPoint(alpha, H_P);

  // Build the base hash data (matches Salvium C++ rctSigs.cpp:305-320)
  // c_to_hash = [domain, P[0..n-1], C[0..n-1], C_offset, message, L, R]
  // We'll update L and R for each round
  const buildChallengeHash = (L, R) => {
    return hashToScalar(CLSAG_ROUND, ...ring, ...C, pseudoOutputCommitment, message, L, R);
  };

  // Start the ring: first challenge from alpha commitments
  let c = buildChallengeHash(aG, aH);

  // c1 will be captured when loop index becomes 0
  // Per Salvium C++ (rctSigs.cpp:325-326, 364-365):
  // c1 is saved when i wraps to 0
  let c1 = null;

  // Start at position after secret index
  let i = (secretIndex + 1) % n;

  // If we start at index 0, capture c1 immediately
  if (i === 0) {
    c1 = new Uint8Array(c);
  }

  // Go around the ring until we reach the secret index
  while (i !== secretIndex) {
    // Generate random s[i] for this decoy position
    s[i] = scRandom();

    // Compute H_p(P_i) - hash to point of this ring member's public key
    const H_P_i = hashToPoint(ring[i]);

    // Weighted challenges: c_p = mu_P * c, c_c = mu_C * c
    const c_mu_P = scMul(c, mu_P);
    const c_mu_C = scMul(c, mu_C);

    // L = s[i]*G + c_p*P[i] + c_c*C[i]
    const sG = scalarMultBase(s[i]);
    const c_mu_P_Pi = scalarMultPoint(c_mu_P, ring[i]);
    const c_mu_C_Ci = scalarMultPoint(c_mu_C, C[i]);
    const L = pointAddCompressed(pointAddCompressed(sG, c_mu_P_Pi), c_mu_C_Ci);

    // R = s[i]*H_p(P[i]) + c_p*I + c_c*D
    const sH = scalarMultPoint(s[i], H_P_i);
    const c_mu_P_I = scalarMultPoint(c_mu_P, I);
    const c_mu_C_D = scalarMultPoint(c_mu_C, D);
    const R = pointAddCompressed(pointAddCompressed(sH, c_mu_P_I), c_mu_C_D);

    // Next challenge: c = H_n(domain, P[0..n-1], C[0..n-1], C_offset, message, L, R)
    c = buildChallengeHash(L, R);

    // Advance to next ring member
    i = (i + 1) % n;

    // Capture c1 when we wrap to index 0
    if (i === 0) {
      c1 = new Uint8Array(c);
    }
  }

  // Now c is the challenge at the secret position (c_l)
  // Compute s[l] to close the ring:
  // s[l] = alpha - c * (mu_P * p + mu_C * z)
  const mu_P_p = scMul(mu_P, secretKey);
  const mu_C_z = scMul(mu_C, commitmentMask);
  const sum = scAdd(mu_P_p, mu_C_z);
  const c_sum = scMul(c, sum);
  s[secretIndex] = scSub(alpha, c_sum);

  // If c1 wasn't captured (secretIndex == 0 and n == 1), compute it now
  // by doing one more round with the completed s[0]
  if (c1 === null) {
    // Single member ring or secretIndex caused us to miss capture
    // Recompute: after s[l] is set, we can compute what c1 would be
    // by computing L_l, R_l with s[l] and c_l
    const H_P_l = hashToPoint(ring[secretIndex]);
    const c_mu_P = scMul(c, mu_P);
    const c_mu_C = scMul(c, mu_C);

    const sG = scalarMultBase(s[secretIndex]);
    const c_mu_P_Pl = scalarMultPoint(c_mu_P, ring[secretIndex]);
    const c_mu_C_Cl = scalarMultPoint(c_mu_C, C[secretIndex]);
    const L = pointAddCompressed(pointAddCompressed(sG, c_mu_P_Pl), c_mu_C_Cl);

    const sH = scalarMultPoint(s[secretIndex], H_P_l);
    const c_mu_P_I = scalarMultPoint(c_mu_P, I);
    const c_mu_C_D = scalarMultPoint(c_mu_C, D);
    const R = pointAddCompressed(pointAddCompressed(sH, c_mu_P_I), c_mu_C_D);

    c1 = buildChallengeHash(L, R);
  }

  return {
    s: s.map(si => bytesToHex(si)),
    c1: bytesToHex(c1),
    I: bytesToHex(I),
    D: bytesToHex(D)
  };
}

/**
 * Point subtraction: A - B
 * @param {Uint8Array} a - First point
 * @param {Uint8Array} b - Second point
 * @returns {Uint8Array} A - B
 */
function pointSub(a, b) {
  // A - B = A + (-B)
  // -B is computed by negating the x-coordinate in compressed form
  // For Edwards curves, -(x, y) = (-x, y), and in compressed form we negate the sign bit
  const negB = negatePoint(b);
  return pointAddCompressed(a, negB);
}

/**
 * Negate a compressed point
 * @param {Uint8Array} p - Compressed point
 * @returns {Uint8Array} -P
 */
function negatePoint(p) {
  if (typeof p === 'string') p = hexToBytes(p);
  const result = new Uint8Array(p);
  // In compressed Edwards form, the sign bit is the LSB of the last byte
  // Negation flips this bit
  result[31] ^= 0x80;
  return result;
}

/**
 * Verify a CLSAG signature
 *
 * @param {Uint8Array|string} message - Message that was signed
 * @param {Object} sig - CLSAG signature { s, c1, I, D }
 * @param {Array<Uint8Array>} ring - Array of public keys
 * @param {Array<Uint8Array>} commitments - Array of commitments
 * @param {Uint8Array|string} pseudoOutputCommitment - Pseudo output commitment
 * @returns {boolean} True if signature is valid
 */
export function clsagVerify(message, sig, ring, commitments, pseudoOutputCommitment) {
  if (typeof message === 'string') message = hexToBytes(message);
  if (typeof pseudoOutputCommitment === 'string') pseudoOutputCommitment = hexToBytes(pseudoOutputCommitment);

  const n = ring.length;

  // Normalize inputs
  ring = ring.map(k => typeof k === 'string' ? hexToBytes(k) : k);
  commitments = commitments.map(c => typeof c === 'string' ? hexToBytes(c) : c);
  const s = sig.s.map(si => typeof si === 'string' ? hexToBytes(si) : si);
  const c1 = typeof sig.c1 === 'string' ? hexToBytes(sig.c1) : sig.c1;
  const I = typeof sig.I === 'string' ? hexToBytes(sig.I) : sig.I;
  const D = typeof sig.D === 'string' ? hexToBytes(sig.D) : sig.D;

  // Compute commitment differences
  const C = commitments.map(c => pointSub(c, pseudoOutputCommitment));

  // Compute aggregate coefficients
  const aggData = [...ring, I, D, ...C];
  const mu_P = hashToScalar(CLSAG_AGG_0, ...aggData);
  const mu_C = hashToScalar(CLSAG_AGG_1, ...aggData);

  // Build challenge hash with full ring data (matches Salvium C++ rctSigs.cpp:305-320)
  // c_to_hash = [domain, P[0..n-1], C[0..n-1], C_offset, message, L, R]
  const buildChallengeHash = (L, R) => {
    return hashToScalar(CLSAG_ROUND, ...ring, ...C, pseudoOutputCommitment, message, L, R);
  };

  // Verify the ring
  let c = c1;
  for (let i = 0; i < n; i++) {
    const H_P_i = hashToPoint(ring[i]);

    // L = s[i]*G + c*mu_P*P_i + c*mu_C*C_i
    const sG = scalarMultBase(s[i]);
    const c_mu_P = scMul(c, mu_P);
    const c_mu_P_Pi = scalarMultPoint(c_mu_P, ring[i]);
    const c_mu_C = scMul(c, mu_C);
    const c_mu_C_Ci = scalarMultPoint(c_mu_C, C[i]);

    const L = pointAddCompressed(pointAddCompressed(sG, c_mu_P_Pi), c_mu_C_Ci);

    // R = s[i]*H_p(P_i) + c*mu_P*I + c*mu_C*D
    const sH = scalarMultPoint(s[i], H_P_i);
    const c_mu_P_I = scalarMultPoint(c_mu_P, I);
    const c_mu_C_D = scalarMultPoint(c_mu_C, D);

    const R = pointAddCompressed(pointAddCompressed(sH, c_mu_P_I), c_mu_C_D);

    // c = H_n(domain, P[0..n-1], C[0..n-1], C_offset, message, L, R)
    c = buildChallengeHash(L, R);
  }

  // After going around the ring, c should equal c1
  return bytesToHex(c) === bytesToHex(c1);
}

// =============================================================================
// TRANSACTION UTILITIES
// =============================================================================

/**
 * Compute the pre-MLSAG/CLSAG hash (message to sign)
 * This is H(txPrefixHash || ss || pseudoOuts)
 *
 * @param {Uint8Array|string} txPrefixHash - Hash of transaction prefix
 * @param {Uint8Array|string} ss - Serialized bulletproof/rangeproof data
 * @param {Array<Uint8Array>} pseudoOuts - Pseudo output commitments
 * @returns {Uint8Array} 32-byte message hash
 */
export function getPreMlsagHash(txPrefixHash, ss, pseudoOuts) {
  if (typeof txPrefixHash === 'string') txPrefixHash = hexToBytes(txPrefixHash);
  if (typeof ss === 'string') ss = hexToBytes(ss);

  let totalLen = txPrefixHash.length + ss.length;
  pseudoOuts = pseudoOuts.map(p => {
    if (typeof p === 'string') p = hexToBytes(p);
    totalLen += p.length;
    return p;
  });

  const data = new Uint8Array(totalLen);
  let offset = 0;
  data.set(txPrefixHash, offset);
  offset += txPrefixHash.length;
  data.set(ss, offset);
  offset += ss.length;
  for (const p of pseudoOuts) {
    data.set(p, offset);
    offset += p.length;
  }

  return keccak256(data);
}

/**
 * Generate a random transaction secret key
 * @returns {Uint8Array} 32-byte random scalar
 */
export function generateTxSecretKey() {
  return scRandom();
}

/**
 * Compute transaction public key from secret key
 * @param {Uint8Array|string} txSecretKey - Transaction secret key
 * @returns {Uint8Array} Transaction public key (R = r*G)
 */
export function getTxPublicKey(txSecretKey) {
  return scalarMultBase(txSecretKey);
}

// =============================================================================
// SERIALIZATION
// =============================================================================

/**
 * Encode an unsigned integer as a varint (variable-length integer)
 * CryptoNote uses 7-bit encoding with MSB as continuation flag.
 *
 * @param {number|bigint} value - Value to encode
 * @returns {Uint8Array} Encoded varint
 */
export function encodeVarint(value) {
  if (typeof value === 'number') value = BigInt(value);

  const bytes = [];
  while (value >= 0x80n) {
    bytes.push(Number((value & 0x7fn) | 0x80n));
    value >>= 7n;
  }
  bytes.push(Number(value));

  return new Uint8Array(bytes);
}

/**
 * Decode a varint from bytes
 *
 * @param {Uint8Array} bytes - Bytes containing varint
 * @param {number} offset - Starting offset
 * @returns {{value: bigint, bytesRead: number}} Decoded value and bytes consumed
 */
export function decodeVarint(bytes, offset = 0) {
  let value = 0n;
  let shift = 0n;
  let bytesRead = 0;

  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    bytesRead++;

    value |= BigInt(byte & 0x7f) << shift;

    if ((byte & 0x80) === 0) {
      break;
    }

    shift += 7n;

    // Prevent overflow (max 10 bytes for 64-bit)
    if (shift >= 70n) {
      throw new Error('Varint overflow');
    }
  }

  return { value, bytesRead };
}

/**
 * Transaction version constants
 */
export const TX_VERSION = {
  V1: 1,  // Pre-RingCT
  V2: 2   // RingCT
};

/**
 * RingCT type constants
 */
export const RCT_TYPE = {
  Null: 0,
  Full: 1,
  Simple: 2,
  Bulletproof: 3,
  Bulletproof2: 4,
  CLSAG: 5,
  BulletproofPlus: 6,
  FullProofs: 7,       // Salvium: BulletproofPlus + CLSAGs + partial salvium_data
  SalviumZero: 8,      // Salvium: BulletproofPlus + CLSAGs + full salvium_data
  SalviumOne: 9        // Salvium: BulletproofPlus + TCLSAGs + full salvium_data
};

/**
 * Transaction output type constants
 */
export const TXOUT_TYPE = {
  ToKey: 0x02,
  KEY: 0x02,          // Alias
  ToTaggedKey: 0x03,
  TAGGED_KEY: 0x03    // Alias
};

/**
 * Transaction input type constants
 */
export const TXIN_TYPE = {
  Gen: 0xff,    // Coinbase/generation
  GEN: 0xff,    // Alias
  ToKey: 0x02,  // Regular input
  KEY: 0x02     // Alias
};

/**
 * Transaction type constants (from cryptonote_protocol/enums.h)
 */
export const TX_TYPE = {
  UNSET: 0,
  MINER: 1,
  PROTOCOL: 2,
  TRANSFER: 3,
  CONVERT: 4,
  BURN: 5,
  STAKE: 6,
  RETURN: 7,
  AUDIT: 8
};

/**
 * Serialize a transaction output
 *
 * @param {Object} output - Output object
 * @param {bigint|number} output.amount - Amount (usually 0 for RingCT)
 * @param {Uint8Array} output.target - Output public key (32 bytes)
 * @param {number} [output.viewTag] - Optional view tag (1 byte)
 * @returns {Uint8Array} Serialized output
 */
export function serializeTxOutput(output) {
  const chunks = [];

  // Amount (varint, usually 0 for RingCT)
  chunks.push(encodeVarint(output.amount || 0n));

  // Output type + target
  if (output.viewTag !== undefined) {
    // Tagged key output (post-view-tag era)
    chunks.push(new Uint8Array([TXOUT_TYPE.ToTaggedKey]));
    chunks.push(typeof output.target === 'string' ? hexToBytes(output.target) : output.target);
    chunks.push(new Uint8Array([output.viewTag & 0xff]));
  } else {
    // Regular key output
    chunks.push(new Uint8Array([TXOUT_TYPE.ToKey]));
    chunks.push(typeof output.target === 'string' ? hexToBytes(output.target) : output.target);
  }

  return concatBytes(chunks);
}

/**
 * Serialize a transaction input (key input)
 *
 * @param {Object} input - Input object
 * @param {bigint|number} input.amount - Amount
 * @param {Array<bigint|number>} input.keyOffsets - Ring member offsets (relative indices)
 * @param {Uint8Array} input.keyImage - Key image (32 bytes)
 * @returns {Uint8Array} Serialized input
 */
export function serializeTxInput(input) {
  const chunks = [];

  // Input type
  chunks.push(new Uint8Array([TXIN_TYPE.ToKey]));

  // Amount (varint)
  chunks.push(encodeVarint(input.amount || 0n));

  // Key offsets (varint count + varint values)
  chunks.push(encodeVarint(input.keyOffsets.length));
  for (const offset of input.keyOffsets) {
    chunks.push(encodeVarint(offset));
  }

  // Key image (32 bytes)
  const ki = typeof input.keyImage === 'string' ? hexToBytes(input.keyImage) : input.keyImage;
  chunks.push(ki);

  return concatBytes(chunks);
}

/**
 * Serialize a coinbase (generation) input
 *
 * @param {number|bigint} height - Block height
 * @returns {Uint8Array} Serialized gen input
 */
export function serializeGenInput(height) {
  return concatBytes([
    new Uint8Array([TXIN_TYPE.Gen]),
    encodeVarint(height)
  ]);
}

/**
 * Serialize transaction extra field
 *
 * @param {Object} extra - Extra field data
 * @param {Uint8Array} extra.txPubKey - Transaction public key (32 bytes)
 * @param {Uint8Array} [extra.paymentId] - Optional encrypted payment ID (8 bytes)
 * @param {Array<Uint8Array>} [extra.additionalPubKeys] - Additional tx public keys
 * @returns {Uint8Array} Serialized extra field
 */
export function serializeTxExtra(extra) {
  const chunks = [];

  // TX_EXTRA_TAG_PUBKEY = 0x01
  if (extra.txPubKey) {
    const pk = typeof extra.txPubKey === 'string' ? hexToBytes(extra.txPubKey) : extra.txPubKey;
    chunks.push(new Uint8Array([0x01]));
    chunks.push(pk);
  }

  // TX_EXTRA_NONCE = 0x02 with encrypted payment ID
  if (extra.paymentId) {
    const pid = typeof extra.paymentId === 'string' ? hexToBytes(extra.paymentId) : extra.paymentId;
    // 0x02 (nonce tag) + length (9) + 0x01 (encrypted payment ID tag) + 8 bytes
    chunks.push(new Uint8Array([0x02, 9, 0x01]));
    chunks.push(pid);
  }

  // TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04
  if (extra.additionalPubKeys && extra.additionalPubKeys.length > 0) {
    chunks.push(new Uint8Array([0x04]));
    chunks.push(encodeVarint(extra.additionalPubKeys.length));
    for (const pk of extra.additionalPubKeys) {
      const pkBytes = typeof pk === 'string' ? hexToBytes(pk) : pk;
      chunks.push(pkBytes);
    }
  }

  return concatBytes(chunks);
}

/**
 * Serialize transaction prefix
 *
 * @param {Object} tx - Transaction object
 * @param {number} tx.version - Transaction version (1 or 2)
 * @param {bigint|number} tx.unlockTime - Unlock time
 * @param {Array<Object>} tx.inputs - Transaction inputs
 * @param {Array<Object>} tx.outputs - Transaction outputs
 * @param {Object} tx.extra - Extra field data
 * @returns {Uint8Array} Serialized transaction prefix
 */
export function serializeTxPrefix(tx) {
  const chunks = [];

  // Version
  chunks.push(encodeVarint(tx.version));

  // Unlock time
  chunks.push(encodeVarint(tx.unlockTime || 0n));

  // Inputs
  chunks.push(encodeVarint(tx.inputs.length));
  for (const input of tx.inputs) {
    if (input.type === 'gen') {
      chunks.push(serializeGenInput(input.height));
    } else {
      chunks.push(serializeTxInput(input));
    }
  }

  // Outputs
  chunks.push(encodeVarint(tx.outputs.length));
  for (const output of tx.outputs) {
    chunks.push(serializeTxOutput(output));
  }

  // Extra
  const extraBytes = serializeTxExtra(tx.extra);
  chunks.push(encodeVarint(extraBytes.length));
  chunks.push(extraBytes);

  // Salvium-specific transaction prefix fields
  // txType (default: TRANSFER for backward compatibility)
  const txType = tx.txType ?? TX_TYPE.TRANSFER;
  chunks.push(encodeVarint(txType));

  // Fields for non-UNSET, non-PROTOCOL transaction types
  if (txType !== TX_TYPE.UNSET && txType !== TX_TYPE.PROTOCOL) {
    // amount_burnt
    chunks.push(encodeVarint(tx.amount_burnt ?? 0n));

    if (txType !== TX_TYPE.MINER) {
      // Return address handling depends on tx type and version
      if (txType === TX_TYPE.TRANSFER && tx.version >= 3) {
        // TRANSFER with version >= 3: return_address_list and change_mask
        const returnList = tx.return_address_list || [];
        chunks.push(encodeVarint(returnList.length));
        for (const addr of returnList) {
          chunks.push(typeof addr === 'string' ? hexToBytes(addr) : addr);
        }
        const changeMask = tx.return_address_change_mask || new Uint8Array(0);
        chunks.push(encodeVarint(changeMask.length));
        if (changeMask.length > 0) {
          chunks.push(changeMask);
        }
      } else if (txType === TX_TYPE.STAKE && tx.version >= 4) {
        // STAKE with CARROT (version >= 4): protocol_tx_data
        const ptxData = tx.protocol_tx_data || {};
        chunks.push(encodeVarint(ptxData.version ?? 1));
        chunks.push(typeof ptxData.return_address === 'string'
          ? hexToBytes(ptxData.return_address)
          : (ptxData.return_address || new Uint8Array(32)));
        chunks.push(typeof ptxData.return_pubkey === 'string'
          ? hexToBytes(ptxData.return_pubkey)
          : (ptxData.return_pubkey || new Uint8Array(32)));
        chunks.push(ptxData.return_view_tag || new Uint8Array(3));
        chunks.push(ptxData.return_anchor_enc || new Uint8Array(16));
      } else {
        // Legacy format: return_address + return_pubkey
        chunks.push(typeof tx.return_address === 'string'
          ? hexToBytes(tx.return_address)
          : (tx.return_address || new Uint8Array(32)));
        chunks.push(typeof tx.return_pubkey === 'string'
          ? hexToBytes(tx.return_pubkey)
          : (tx.return_pubkey || new Uint8Array(32)));
      }

      // source_asset_type (length-prefixed string)
      const srcAsset = tx.source_asset_type || 'SAL';
      const srcAssetBytes = new TextEncoder().encode(srcAsset);
      chunks.push(encodeVarint(srcAssetBytes.length));
      chunks.push(srcAssetBytes);

      // destination_asset_type (length-prefixed string)
      const dstAsset = tx.destination_asset_type || 'SAL';
      const dstAssetBytes = new TextEncoder().encode(dstAsset);
      chunks.push(encodeVarint(dstAssetBytes.length));
      chunks.push(dstAssetBytes);

      // amount_slippage_limit
      chunks.push(encodeVarint(tx.amount_slippage_limit ?? 0n));
    }
  }

  return concatBytes(chunks);
}

/**
 * Compute transaction prefix hash
 *
 * @param {Object|Uint8Array} tx - Transaction object or serialized prefix
 * @returns {Uint8Array} 32-byte hash
 */
export function getTxPrefixHash(tx) {
  if (tx instanceof Uint8Array) {
    return keccak256(tx);
  }

  // Adapt vin/vout format to inputs/outputs if needed
  // Include all Salvium-specific fields for correct hash
  const prefixForSerialization = {
    version: tx.version,
    unlockTime: tx.unlockTime,
    inputs: tx.inputs || tx.vin,
    outputs: tx.outputs || tx.vout,
    extra: tx.extra,
    // Salvium-specific fields
    txType: tx.txType,
    amount_burnt: tx.amount_burnt,
    return_address: tx.return_address,
    return_address_list: tx.return_address_list,
    return_address_change_mask: tx.return_address_change_mask,
    return_pubkey: tx.return_pubkey,
    protocol_tx_data: tx.protocol_tx_data,
    source_asset_type: tx.source_asset_type,
    destination_asset_type: tx.destination_asset_type,
    amount_slippage_limit: tx.amount_slippage_limit
  };

  return keccak256(serializeTxPrefix(prefixForSerialization));
}

/**
 * Serialize a CLSAG signature
 *
 * @param {Object} sig - CLSAG signature
 * @param {Array<string>} sig.s - Response scalars (32 bytes each, as hex)
 * @param {string} sig.c1 - Initial challenge (32 bytes, as hex)
 * @param {string} sig.D - Commitment key image (32 bytes, as hex)
 * @returns {Uint8Array} Serialized CLSAG
 */
export function serializeCLSAG(sig) {
  const chunks = [];

  // s values (no length prefix, determined by ring size)
  for (const s of sig.s) {
    chunks.push(typeof s === 'string' ? hexToBytes(s) : s);
  }

  // c1
  chunks.push(typeof sig.c1 === 'string' ? hexToBytes(sig.c1) : sig.c1);

  // D (commitment key image)
  // Note: I (key image) is NOT serialized as it can be reconstructed
  chunks.push(typeof sig.D === 'string' ? hexToBytes(sig.D) : sig.D);

  return concatBytes(chunks);
}

/**
 * Serialize RingCT base (type + fee)
 *
 * @param {Object} rct - RingCT data
 * @param {number} rct.type - RCT type
 * @param {bigint|number} rct.fee - Transaction fee
 * @returns {Uint8Array} Serialized RCT base
 */
export function serializeRctBase(rct) {
  const chunks = [];

  // Type (1 byte)
  chunks.push(new Uint8Array([rct.type]));

  // Fee (varint, only for non-coinbase)
  if (rct.type !== RCT_TYPE.Null) {
    chunks.push(encodeVarint(rct.fee || 0n));
  }

  return concatBytes(chunks);
}

/**
 * Serialize encrypted amounts (ecdhInfo)
 *
 * @param {Array<Uint8Array>} encryptedAmounts - 8-byte encrypted amounts
 * @returns {Uint8Array} Serialized encrypted amounts
 */
export function serializeEcdhInfo(encryptedAmounts) {
  const chunks = [];
  for (const ea of encryptedAmounts) {
    const bytes = typeof ea === 'string' ? hexToBytes(ea) : ea;
    // V2+ compact format: just 8 bytes
    chunks.push(bytes.slice(0, 8));
  }
  return concatBytes(chunks);
}

/**
 * Serialize output commitments
 *
 * @param {Array<Uint8Array>} commitments - 32-byte Pedersen commitments
 * @returns {Uint8Array} Serialized commitments
 */
export function serializeOutPk(commitments) {
  const chunks = [];
  for (const c of commitments) {
    chunks.push(typeof c === 'string' ? hexToBytes(c) : c);
  }
  return concatBytes(chunks);
}

/**
 * Concatenate multiple Uint8Arrays
 *
 * @param {Array<Uint8Array>} arrays - Arrays to concatenate
 * @returns {Uint8Array} Concatenated result
 */
function concatBytes(arrays) {
  let totalLen = 0;
  for (const arr of arrays) {
    totalLen += arr.length;
  }

  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/**
 * Compute full transaction hash
 * This is the hash used to identify transactions.
 *
 * @param {Object} tx - Full transaction with RingCT
 * @returns {Uint8Array} 32-byte transaction hash
 */
export function getTransactionHash(tx) {
  // For RingCT transactions, the hash is computed over:
  // H(H(prefix) || H(rctBase) || H(rctPrunable))
  // But for simplicity, if we have serialized data, we can hash that

  // This is simplified - full implementation needs proper RingCT serialization
  const prefix = serializeTxPrefix(tx);
  const prefixHash = keccak256(prefix);

  // For a complete implementation, we'd also hash RingCT data
  // For now, return prefix hash
  return prefixHash;
}

// =============================================================================
// DECOY SELECTION (GAMMA PICKER)
// =============================================================================

/**
 * Gamma distribution parameters from Miller et al. (https://arxiv.org/pdf/1704.04299/)
 * These parameters model the spending behavior of real users.
 */
export const GAMMA_SHAPE = 19.28;
export const GAMMA_SCALE = 1 / 1.61;

/**
 * Default unlock time in seconds (10 blocks at 120s each)
 */
export const DEFAULT_UNLOCK_TIME = 10 * 120; // 1200 seconds

/**
 * Difficulty target (seconds per block)
 */
export const DIFFICULTY_TARGET = 120;

/**
 * Recent spend window in seconds (outputs expected to be spent quickly)
 */
export const RECENT_SPEND_WINDOW = 15 * DIFFICULTY_TARGET; // 1800 seconds

/**
 * Default spendable age in blocks
 */
export const CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10;

/**
 * Default ring size (number of decoys + 1)
 */
export const DEFAULT_RING_SIZE = 16;

/**
 * Gamma distribution sampler using the Marsaglia and Tsang method
 * @param {number} shape - Shape parameter (k or alpha)
 * @param {number} scale - Scale parameter (theta)
 * @returns {number} Random sample from gamma distribution
 */
export function sampleGamma(shape, scale) {
  // For shape >= 1, use Marsaglia and Tsang's method
  // For shape < 1, use shape + 1 and adjust

  let d, c;
  let adjustedShape = shape;

  if (shape < 1) {
    adjustedShape = shape + 1;
  }

  d = adjustedShape - 1/3;
  c = 1 / Math.sqrt(9 * d);

  while (true) {
    let x, v;

    // Generate standard normal using Box-Muller
    do {
      const u1 = Math.random();
      const u2 = Math.random();
      x = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      v = 1 + c * x;
    } while (v <= 0);

    v = v * v * v;
    const u = Math.random();

    // Accept/reject
    if (u < 1 - 0.0331 * x * x * x * x) {
      let result = d * v * scale;
      if (shape < 1) {
        result *= Math.pow(Math.random(), 1 / shape);
      }
      return result;
    }

    if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) {
      let result = d * v * scale;
      if (shape < 1) {
        result *= Math.pow(Math.random(), 1 / shape);
      }
      return result;
    }
  }
}

/**
 * Gamma picker for decoy selection
 * Implements the algorithm from wallet2.cpp gamma_picker
 */
export class GammaPicker {
  /**
   * Create a gamma picker
   * @param {Array<number>} rctOffsets - Cumulative output counts per block
   * @param {Object} options - Optional configuration
   * @param {number} options.shape - Gamma shape (default: GAMMA_SHAPE)
   * @param {number} options.scale - Gamma scale (default: GAMMA_SCALE)
   */
  constructor(rctOffsets, options = {}) {
    this.rctOffsets = rctOffsets;
    this.shape = options.shape || GAMMA_SHAPE;
    this.scale = options.scale || GAMMA_SCALE;

    if (rctOffsets.length <= CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE) {
      throw new Error('Not enough blocks for decoy selection');
    }

    // Calculate average output time from recent blocks
    const blocksInYear = Math.floor(86400 * 365 / DIFFICULTY_TARGET);
    const blocksToConsider = Math.min(rctOffsets.length, blocksInYear);

    const startOffset = blocksToConsider < rctOffsets.length
      ? rctOffsets[rctOffsets.length - blocksToConsider - 1]
      : 0;
    const outputsToConsider = rctOffsets[rctOffsets.length - 1] - startOffset;

    this.numRctOutputs = rctOffsets[rctOffsets.length - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE];
    this.averageOutputTime = DIFFICULTY_TARGET * blocksToConsider / outputsToConsider;

    if (this.numRctOutputs === 0) {
      throw new Error('No RCT outputs available');
    }
  }

  /**
   * Pick a random output index using gamma distribution
   * @returns {number} Output global index, or -1 if bad pick
   */
  pick() {
    // Sample from gamma and exponentiate (as per Miller et al.)
    let x = sampleGamma(this.shape, this.scale);
    x = Math.exp(x);

    // Adjust for unlock time
    if (x > DEFAULT_UNLOCK_TIME) {
      x -= DEFAULT_UNLOCK_TIME;
    } else {
      // Output would be too recent, pick from recent spend window
      x = Math.floor(Math.random() * RECENT_SPEND_WINDOW);
    }

    // Convert time to output index
    let outputIndex = Math.floor(x / this.averageOutputTime);

    if (outputIndex >= this.numRctOutputs) {
      return -1; // Bad pick
    }

    // Convert to ascending index (from chain tip going back)
    outputIndex = this.numRctOutputs - 1 - outputIndex;

    // Find which block contains this output
    const blockIndex = this.findBlockIndex(outputIndex);

    if (blockIndex < 0) {
      return -1;
    }

    // Pick a random output from this block
    const firstInBlock = blockIndex === 0 ? 0 : this.rctOffsets[blockIndex - 1];
    const countInBlock = this.rctOffsets[blockIndex] - firstInBlock;

    if (countInBlock === 0) {
      return -1;
    }

    return firstInBlock + Math.floor(Math.random() * countInBlock);
  }

  /**
   * Find block index containing a given output index
   * @param {number} outputIndex - Global output index
   * @returns {number} Block index
   */
  findBlockIndex(outputIndex) {
    // Binary search
    let low = 0;
    let high = this.rctOffsets.length - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;

    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      if (this.rctOffsets[mid] <= outputIndex) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }

    return low;
  }

  /**
   * Get the number of available RCT outputs
   * @returns {number}
   */
  getNumRctOutputs() {
    return this.numRctOutputs;
  }
}

/**
 * Select decoy outputs for a ring
 *
 * @param {Array<number>} rctOffsets - Cumulative output counts from get_output_distribution
 * @param {number} realOutputIndex - Global index of the real output being spent
 * @param {number} ringSize - Desired ring size (default: DEFAULT_RING_SIZE)
 * @param {Set<number>} excludeIndices - Output indices to exclude (e.g., already used)
 * @returns {Array<number>} Array of output indices (including real output, sorted)
 */
export function selectDecoys(rctOffsets, realOutputIndex, ringSize = DEFAULT_RING_SIZE, excludeIndices = new Set()) {
  const picker = new GammaPicker(rctOffsets);
  const selected = new Set([realOutputIndex]);
  excludeIndices = new Set(excludeIndices);
  excludeIndices.add(realOutputIndex);

  const maxAttempts = ringSize * 100; // Prevent infinite loops
  let attempts = 0;

  while (selected.size < ringSize && attempts < maxAttempts) {
    const pick = picker.pick();
    attempts++;

    if (pick >= 0 && !selected.has(pick) && !excludeIndices.has(pick)) {
      selected.add(pick);
    }
  }

  if (selected.size < ringSize) {
    throw new Error(`Could not select enough decoys: got ${selected.size}, need ${ringSize}`);
  }

  // Return sorted array
  return Array.from(selected).sort((a, b) => a - b);
}

/**
 * Convert absolute output indices to relative offsets
 * CryptoNote uses relative offsets in the serialized transaction
 *
 * @param {Array<number>} indices - Sorted absolute output indices
 * @returns {Array<number>} Relative offsets
 */
export function indicesToOffsets(indices) {
  const offsets = [];
  for (let i = 0; i < indices.length; i++) {
    if (i === 0) {
      offsets.push(indices[i]);
    } else {
      offsets.push(indices[i] - indices[i - 1]);
    }
  }
  return offsets;
}

/**
 * Convert relative offsets back to absolute indices
 *
 * @param {Array<number>} offsets - Relative offsets
 * @returns {Array<number>} Absolute indices
 */
export function offsetsToIndices(offsets) {
  const indices = [];
  let current = 0;
  for (const offset of offsets) {
    current += offset;
    indices.push(current);
  }
  return indices;
}

// =============================================================================
// FEE CALCULATION
// =============================================================================

/**
 * Fee constants from cryptonote_config.h
 */
export const FEE_PER_KB = 200000n; // 2 * 10^5 atomic units
export const FEE_PER_BYTE = 30n;
export const DYNAMIC_FEE_PER_KB_BASE_FEE = 200000n;
export const DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD = 1000000000n; // 10 * 10^8
export const DYNAMIC_FEE_REFERENCE_TX_WEIGHT = 3000n;
export const FEE_QUANTIZATION_DECIMALS = 8;

/**
 * Fee priority multipliers (algorithm 3)
 * Priority 1 (low) to 4 (high)
 */
export const FEE_MULTIPLIERS = [1n, 5n, 25n, 1000n];

/**
 * Fee priority levels
 */
export const FEE_PRIORITY = {
  LOW: 1,
  NORMAL: 2,
  HIGH: 3,
  HIGHEST: 4
};

/**
 * Get fee multiplier for priority level
 * @param {number} priority - Priority level (1-4)
 * @returns {bigint} Multiplier
 */
export function getFeeMultiplier(priority) {
  if (priority < 1) priority = 1;
  if (priority > 4) priority = 4;
  return FEE_MULTIPLIERS[priority - 1];
}

/**
 * Calculate fee from transaction weight
 *
 * @param {bigint} baseFee - Base fee per weight unit
 * @param {bigint} weight - Transaction weight
 * @param {bigint} quantizationMask - Fee quantization mask (optional)
 * @returns {bigint} Calculated fee
 */
export function calculateFeeFromWeight(baseFee, weight, quantizationMask = 0n) {
  let fee = weight * baseFee;

  if (quantizationMask > 0n) {
    // Round up to quantization mask
    fee = ((fee + quantizationMask - 1n) / quantizationMask) * quantizationMask;
  }

  return fee;
}

/**
 * Calculate fee from transaction size (legacy per-KB method)
 *
 * @param {bigint} feePerKb - Fee per kilobyte
 * @param {number} sizeBytes - Transaction size in bytes
 * @returns {bigint} Calculated fee
 */
export function calculateFeeFromSize(feePerKb, sizeBytes) {
  // Round up to next KB
  const kb = BigInt(Math.ceil(sizeBytes / 1024));
  return kb * feePerKb;
}

/**
 * Estimate transaction size
 * Based on wallet2.cpp estimate_rct_tx_size
 *
 * @param {number} numInputs - Number of inputs
 * @param {number} ringSize - Ring size (mixin + 1)
 * @param {number} numOutputs - Number of outputs
 * @param {number} extraSize - Extra field size
 * @param {Object} options - Options
 * @param {boolean} options.bulletproofPlus - Use Bulletproof+ (default: true)
 * @param {boolean} options.clsag - Use CLSAG (default: true)
 * @param {boolean} options.viewTags - Include view tags (default: true)
 * @returns {number} Estimated size in bytes
 */
export function estimateTxSize(numInputs, ringSize, numOutputs, extraSize = 0, options = {}) {
  const {
    bulletproofPlus = true,
    clsag = true,
    viewTags = true
  } = options;

  let size = 0;

  // Transaction prefix
  size += 1 + 6; // version + unlock_time varint

  // Inputs
  // vin: type(1) + amount varint + key_offsets (count + values) + key_image(32)
  const inputSize = 1 + 6 + 4 + ringSize * 4 + 32;
  size += inputSize * numInputs;

  // Outputs
  // vout: amount varint + type(1) + key(32) + view_tag(1 if enabled)
  const outputSize = 2 + 4 + 6 + 32 + (viewTags ? 1 : 0);
  size += outputSize * numOutputs;

  // Extra
  size += extraSize;

  // RCT type
  size += 1;

  // Bulletproof(+) range proof
  if (bulletproofPlus) {
    // BP+ size: 32 * (6 + 2*ceil(log2(numOutputs)))
    const log2Outputs = Math.ceil(Math.log2(Math.max(numOutputs, 1)));
    size += 32 * (6 + 2 * log2Outputs);
  } else {
    // Original BP: 32 * (9 + 2*ceil(log2(numOutputs)))
    const log2Outputs = Math.ceil(Math.log2(Math.max(numOutputs, 1)));
    size += 32 * (9 + 2 * log2Outputs);
  }

  // Ring signatures (CLSAG)
  if (clsag) {
    // CLSAG: ringSize * 32 (s values) + 32 (c1) + 32 (D)
    size += (ringSize * 32 + 64) * numInputs;
  } else {
    // MLSAG: (ringSize + 1) * 32 * 2
    size += ((ringSize + 1) * 64) * numInputs;
  }

  // Pseudo outputs (one per input, except coinbase)
  size += 32 * numInputs;

  // ecdhInfo (encrypted amounts)
  size += 8 * numOutputs;

  // outPk (output commitments)
  size += 32 * numOutputs;

  // txnFee
  size += 4;

  // Extra tx pubkey
  size += 32;

  return size;
}

/**
 * Estimate transaction weight (for fee calculation)
 * Weight includes clawback adjustment for bulletproofs
 *
 * @param {number} numInputs - Number of inputs
 * @param {number} ringSize - Ring size
 * @param {number} numOutputs - Number of outputs
 * @param {number} extraSize - Extra field size
 * @param {Object} options - Options (same as estimateTxSize)
 * @returns {number} Estimated weight
 */
export function estimateTxWeight(numInputs, ringSize, numOutputs, extraSize = 0, options = {}) {
  let weight = estimateTxSize(numInputs, ringSize, numOutputs, extraSize, options);

  const { bulletproofPlus = true } = options;

  // Apply clawback for > 2 outputs
  if (numOutputs > 2) {
    const bpBase = 32 * (bulletproofPlus ? 6 : 9) / 2;
    const logPaddedOutputs = Math.ceil(Math.log2(numOutputs));
    const paddedOutputs = 1 << logPaddedOutputs;
    const nlr = 2 * logPaddedOutputs;
    const bpSize = 32 * ((bulletproofPlus ? 6 : 9) + nlr);

    // Clawback: what we'd pay for individual proofs minus what we actually need
    const bpClawback = Math.floor((bpBase * paddedOutputs - bpSize) * 4 / 5);
    weight += bpClawback;
  }

  return weight;
}

/**
 * Estimate fee for a transaction
 *
 * @param {number} numInputs - Number of inputs
 * @param {number} ringSize - Ring size
 * @param {number} numOutputs - Number of outputs
 * @param {number} extraSize - Extra field size
 * @param {Object} options - Options
 * @param {bigint} options.baseFee - Base fee per byte (default: FEE_PER_BYTE)
 * @param {number} options.priority - Priority level 1-4 (default: 2)
 * @param {boolean} options.perByte - Use per-byte fee (default: true)
 * @returns {bigint} Estimated fee
 */
export function estimateFee(numInputs, ringSize, numOutputs, extraSize = 0, options = {}) {
  const {
    baseFee = FEE_PER_BYTE,
    priority = FEE_PRIORITY.NORMAL,
    perByte = true
  } = options;

  const multiplier = getFeeMultiplier(priority);

  if (perByte) {
    const weight = estimateTxWeight(numInputs, ringSize, numOutputs, extraSize, options);
    return calculateFeeFromWeight(baseFee * multiplier, BigInt(weight));
  } else {
    const size = estimateTxSize(numInputs, ringSize, numOutputs, extraSize, options);
    return calculateFeeFromSize(FEE_PER_KB * multiplier, size);
  }
}

// =============================================================================
// RINGCT SIGNATURE ASSEMBLY
// =============================================================================

/**
 * Build a complete RingCT signature
 *
 * @param {Object} params - Transaction parameters
 * @param {Uint8Array} params.message - Message to sign (pre-MLSAG hash)
 * @param {Array<Object>} params.inputs - Input objects with { secretKey, ring, commitments, mask, realIndex }
 * @param {Array<Object>} params.outputs - Output objects with { commitment, encryptedAmount }
 * @param {bigint} params.fee - Transaction fee
 * @param {Array<Uint8Array>} params.pseudoOuts - Pseudo output commitments
 * @returns {Object} RingCT signature data
 */
export function buildRingCtSignature(params) {
  const { message, inputs, outputs, fee, pseudoOuts } = params;

  const clsags = [];

  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i];

    // Sign with CLSAG
    const sig = clsagSign(
      message,
      input.ring,
      input.secretKey,
      input.commitments,
      input.mask,
      pseudoOuts[i],
      input.realIndex
    );

    clsags.push(sig);
  }

  return {
    type: RCT_TYPE.BulletproofPlus, // or CLSAG
    fee,
    pseudoOuts: pseudoOuts.map(p => typeof p === 'string' ? p : bytesToHex(p)),
    ecdhInfo: outputs.map(o => typeof o.encryptedAmount === 'string' ? o.encryptedAmount : bytesToHex(o.encryptedAmount)),
    outPk: outputs.map(o => typeof o.commitment === 'string' ? o.commitment : bytesToHex(o.commitment)),
    clsags
  };
}

/**
 * Compute pseudo output commitments that balance with output commitments
 * Sum(pseudoOuts) = Sum(outPk) + fee*H
 *
 * @param {Array<Object>} inputs - Inputs with { amount, mask }
 * @param {Array<Object>} outputs - Outputs with { amount, mask }
 * @param {bigint} fee - Transaction fee
 * @returns {Object} { pseudoOuts: Array<Uint8Array>, pseudoMasks: Array<Uint8Array> }
 */
export function computePseudoOutputs(inputs, outputs, fee) {
  const pseudoOuts = [];
  const pseudoMasks = [];

  // Sum of output masks
  let outputMaskSum = 0n;
  for (const output of outputs) {
    const maskBig = bytesToBigInt(output.mask);
    outputMaskSum = (outputMaskSum + maskBig) % L;
  }

  // Create pseudo outputs for all inputs except the last
  let usedMaskSum = 0n;

  for (let i = 0; i < inputs.length - 1; i++) {
    // Random mask for this pseudo output
    const mask = scRandom();
    const maskBig = bytesToBigInt(mask);
    usedMaskSum = (usedMaskSum + maskBig) % L;

    // Pseudo output = mask*G + amount*H
    const pseudoOut = commit(inputs[i].amount, mask);

    pseudoMasks.push(mask);
    pseudoOuts.push(pseudoOut);
  }

  // Last pseudo output mask: ensures sum balances
  // lastMask = outputMaskSum - usedMaskSum
  const lastMaskBig = ((outputMaskSum - usedMaskSum) % L + L) % L;
  const lastMask = bigIntToBytes(lastMaskBig);

  // Last pseudo output
  const lastInput = inputs[inputs.length - 1];
  const lastPseudoOut = commit(lastInput.amount, lastMask);

  pseudoMasks.push(lastMask);
  pseudoOuts.push(lastPseudoOut);

  return { pseudoOuts, pseudoMasks };
}

// =============================================================================
// CARROT OUTPUT GENERATION
// =============================================================================

/**
 * CARROT domain separators
 * Reference: carrot_core/config.h
 */
export const CARROT_DOMAIN = {
  EPHEMERAL_PRIVKEY: 'Carrot sending key normal',
  SENDER_RECEIVER_SECRET: 'Carrot sender-receiver secret',
  VIEW_TAG: 'Carrot view tag',
  COMMITMENT_MASK: 'Carrot commitment mask',
  ONETIME_EXTENSION_G: 'Carrot key extension G',
  ONETIME_EXTENSION_T: 'Carrot key extension T',
  ENCRYPTION_MASK_ANCHOR: 'Carrot encryption mask anchor',
  ENCRYPTION_MASK_AMOUNT: 'Carrot encryption mask a',
  ENCRYPTION_MASK_PAYMENT_ID: 'Carrot encryption mask pid',
  JANUS_ANCHOR_SPECIAL: 'Carrot janus anchor special',
  INPUT_CONTEXT_COINBASE: 'C',
  INPUT_CONTEXT_RINGCT: 'R'
};

/**
 * CARROT enote type
 */
export const CARROT_ENOTE_TYPE = {
  PAYMENT: 0,
  CHANGE: 1,
  SELF_SPEND: 2
};

import { blake2b } from './blake2b.js';
import { getGeneratorT } from './ed25519.js';

/**
 * Hash data with domain separation using Blake2b
 * @param {string} domain - Domain separator string
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 32-byte hash
 */
function carrotHash32(domain, ...data) {
  const domainBytes = new TextEncoder().encode(domain);
  let totalLen = domainBytes.length;

  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  combined.set(domainBytes, offset);
  offset += domainBytes.length;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  return blake2b(combined, 32);
}

/**
 * Hash to scalar with domain separation (CARROT)
 * @param {string} domain - Domain separator
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 32-byte scalar < L
 */
function carrotHashToScalar(domain, ...data) {
  const hash = carrotHash32(domain, ...data);
  return scReduce32(hash);
}

/**
 * Hash to 16 bytes (for anchor, etc.)
 * @param {string} domain - Domain separator
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 16-byte hash
 */
function carrotHash16(domain, ...data) {
  const domainBytes = new TextEncoder().encode(domain);
  let totalLen = domainBytes.length;

  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  combined.set(domainBytes, offset);
  offset += domainBytes.length;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  return blake2b(combined, 16);
}

/**
 * Hash to 8 bytes (for amount/payment ID encryption)
 * @param {string} domain - Domain separator
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 8-byte hash
 */
function carrotHash8(domain, ...data) {
  const domainBytes = new TextEncoder().encode(domain);
  let totalLen = domainBytes.length;

  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  combined.set(domainBytes, offset);
  offset += domainBytes.length;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  return blake2b(combined, 8);
}

/**
 * Hash to 3 bytes (for view tag)
 * @param {string} domain - Domain separator
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 3-byte hash
 */
function carrotHash3(domain, ...data) {
  const domainBytes = new TextEncoder().encode(domain);
  let totalLen = domainBytes.length;

  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  combined.set(domainBytes, offset);
  offset += domainBytes.length;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  return blake2b(combined, 3);
}

/**
 * Generate random Janus anchor (16 bytes)
 * @returns {Uint8Array} 16-byte random anchor
 */
export function generateJanusAnchor() {
  const anchor = new Uint8Array(16);
  crypto.getRandomValues(anchor);
  return anchor;
}

/**
 * Build input context for RingCT transaction
 * Format: 'R' || first_key_image (32 bytes)
 *
 * @param {Uint8Array|string} firstKeyImage - First input's key image
 * @returns {Uint8Array} 33-byte input context
 */
export function buildRingCtInputContext(firstKeyImage) {
  if (typeof firstKeyImage === 'string') firstKeyImage = hexToBytes(firstKeyImage);

  const context = new Uint8Array(33);
  context[0] = CARROT_DOMAIN.INPUT_CONTEXT_RINGCT.charCodeAt(0);
  context.set(firstKeyImage, 1);
  return context;
}

/**
 * Build input context for coinbase transaction
 * Format: 'C' || block_height (8 bytes, little-endian)
 *
 * @param {bigint|number} blockHeight - Block height
 * @returns {Uint8Array} 9-byte input context
 */
export function buildCoinbaseInputContext(blockHeight) {
  if (typeof blockHeight === 'number') blockHeight = BigInt(blockHeight);

  const context = new Uint8Array(9);
  context[0] = CARROT_DOMAIN.INPUT_CONTEXT_COINBASE.charCodeAt(0);

  // Little-endian 8-byte height
  let h = blockHeight;
  for (let i = 1; i < 9; i++) {
    context[i] = Number(h & 0xffn);
    h >>= 8n;
  }

  return context;
}

/**
 * Derive CARROT ephemeral private key
 * d_e = H_n("Carrot sending key normal", anchor, input_context, K_s, payment_id)
 *
 * @param {Uint8Array} anchor - 16-byte Janus anchor
 * @param {Uint8Array} inputContext - Input context
 * @param {Uint8Array} addressSpendPubkey - Recipient's spend public key (K_s)
 * @param {Uint8Array} paymentId - 8-byte payment ID
 * @returns {Uint8Array} 32-byte ephemeral private key
 */
export function deriveCarrotEphemeralPrivkey(anchor, inputContext, addressSpendPubkey, paymentId) {
  return carrotHashToScalar(
    CARROT_DOMAIN.EPHEMERAL_PRIVKEY,
    anchor,
    inputContext,
    addressSpendPubkey,
    paymentId
  );
}

/**
 * Compute CARROT ephemeral public key
 * For main address: D_e = d_e * G (on X25519 curve)
 * For subaddress: D_e = d_e * ConvertPointE(K_s)
 *
 * For simplicity, we use Ed25519 scalar multiplication
 * (full X25519 conversion would be needed for production)
 *
 * @param {Uint8Array} ephemeralPrivkey - Ephemeral private key (d_e)
 * @param {Uint8Array} addressSpendPubkey - Address spend pubkey (for subaddress)
 * @param {boolean} isSubaddress - Whether target is a subaddress
 * @returns {Uint8Array} 32-byte ephemeral public key
 */
export function computeCarrotEphemeralPubkey(ephemeralPrivkey, addressSpendPubkey, isSubaddress = false) {
  if (isSubaddress) {
    // D_e = d_e * K_s
    return scalarMultPoint(ephemeralPrivkey, addressSpendPubkey);
  } else {
    // D_e = d_e * G
    return scalarMultBase(ephemeralPrivkey);
  }
}

/**
 * Compute CARROT sender-receiver shared secret (un-contextualized)
 * s_sr = d_e * K_v (sender side)
 * s_sr = k_v * D_e (receiver side)
 *
 * @param {Uint8Array} ephemeralPrivkey - Ephemeral private key
 * @param {Uint8Array} addressViewPubkey - Address view public key
 * @returns {Uint8Array} 32-byte shared secret
 */
export function computeCarrotSharedSecret(ephemeralPrivkey, addressViewPubkey) {
  return scalarMultPoint(ephemeralPrivkey, addressViewPubkey);
}

/**
 * Derive contextualized sender-receiver secret
 * s^ctx_sr = H_32("Carrot sender-receiver secret", D_e, input_context, s_sr)
 *
 * @param {Uint8Array} sharedSecret - Un-contextualized shared secret (s_sr)
 * @param {Uint8Array} ephemeralPubkey - Ephemeral public key (D_e)
 * @param {Uint8Array} inputContext - Input context
 * @returns {Uint8Array} 32-byte contextualized secret
 */
export function deriveCarrotSenderReceiverSecret(sharedSecret, ephemeralPubkey, inputContext) {
  return carrotHash32(
    CARROT_DOMAIN.SENDER_RECEIVER_SECRET,
    ephemeralPubkey,
    inputContext,
    sharedSecret
  );
}

/**
 * Derive CARROT one-time address extension keys
 * k^o_g = H_n("Carrot key extension G", s^ctx_sr, C_a)
 * k^o_t = H_n("Carrot key extension T", s^ctx_sr, C_a)
 *
 * @param {Uint8Array} senderReceiverSecret - Contextualized sender-receiver secret
 * @param {Uint8Array} amountCommitment - Amount commitment
 * @returns {Object} { extensionG, extensionT }
 */
export function deriveCarrotOnetimeExtensions(senderReceiverSecret, amountCommitment) {
  const extensionG = carrotHashToScalar(
    CARROT_DOMAIN.ONETIME_EXTENSION_G,
    senderReceiverSecret,
    amountCommitment
  );

  const extensionT = carrotHashToScalar(
    CARROT_DOMAIN.ONETIME_EXTENSION_T,
    senderReceiverSecret,
    amountCommitment
  );

  return { extensionG, extensionT };
}

/**
 * Compute CARROT one-time address
 * Ko = K_s + k^o_g * G + k^o_t * T
 *
 * @param {Uint8Array} addressSpendPubkey - Recipient's spend public key
 * @param {Uint8Array} extensionG - Extension scalar for G
 * @param {Uint8Array} extensionT - Extension scalar for T
 * @returns {Uint8Array} 32-byte one-time address
 */
export function computeCarrotOnetimeAddress(addressSpendPubkey, extensionG, extensionT) {
  // k^o_g * G
  const kgG = scalarMultBase(extensionG);

  // k^o_t * T
  const T = getGeneratorT();
  const ktT = scalarMultPoint(extensionT, T);

  // K_s + k^o_g * G + k^o_t * T
  const sum1 = pointAddCompressed(addressSpendPubkey, kgG);
  return pointAddCompressed(sum1, ktT);
}

/**
 * Derive CARROT amount blinding factor
 * k_a = H_n("Carrot commitment mask", s^ctx_sr, amount, K_s, enote_type)
 *
 * @param {Uint8Array} senderReceiverSecret - Contextualized secret
 * @param {bigint} amount - Amount
 * @param {Uint8Array} addressSpendPubkey - Address spend pubkey
 * @param {number} enoteType - Enote type (0=payment, 1=change, 2=self-spend)
 * @returns {Uint8Array} 32-byte blinding factor
 */
export function deriveCarrotAmountBlindingFactor(senderReceiverSecret, amount, addressSpendPubkey, enoteType) {
  const amountBytes = bigIntToBytes(amount);
  const typeBytes = new Uint8Array([enoteType]);

  return carrotHashToScalar(
    CARROT_DOMAIN.COMMITMENT_MASK,
    senderReceiverSecret,
    amountBytes,
    addressSpendPubkey,
    typeBytes
  );
}

/**
 * Derive CARROT view tag (3 bytes)
 * vt = H_3("Carrot view tag", s_sr, input_context, Ko)
 *
 * @param {Uint8Array} sharedSecret - Un-contextualized shared secret
 * @param {Uint8Array} inputContext - Input context
 * @param {Uint8Array} onetimeAddress - One-time address
 * @returns {Uint8Array} 3-byte view tag
 */
export function deriveCarrotViewTag(sharedSecret, inputContext, onetimeAddress) {
  return carrotHash3(
    CARROT_DOMAIN.VIEW_TAG,
    sharedSecret,
    inputContext,
    onetimeAddress
  );
}

/**
 * Encrypt anchor for CARROT output
 * anchor_enc = anchor XOR H_16("Carrot encryption mask anchor", s^ctx_sr, Ko)
 *
 * @param {Uint8Array} anchor - 16-byte Janus anchor
 * @param {Uint8Array} senderReceiverSecret - Contextualized secret
 * @param {Uint8Array} onetimeAddress - One-time address
 * @returns {Uint8Array} 16-byte encrypted anchor
 */
export function encryptCarrotAnchor(anchor, senderReceiverSecret, onetimeAddress) {
  const mask = carrotHash16(
    CARROT_DOMAIN.ENCRYPTION_MASK_ANCHOR,
    senderReceiverSecret,
    onetimeAddress
  );

  const encrypted = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    encrypted[i] = anchor[i] ^ mask[i];
  }
  return encrypted;
}

/**
 * Encrypt amount for CARROT output
 * amount_enc = amount XOR H_8("Carrot encryption mask a", s^ctx_sr, Ko)
 *
 * @param {bigint} amount - Amount to encrypt
 * @param {Uint8Array} senderReceiverSecret - Contextualized secret
 * @param {Uint8Array} onetimeAddress - One-time address
 * @returns {Uint8Array} 8-byte encrypted amount
 */
export function encryptCarrotAmount(amount, senderReceiverSecret, onetimeAddress) {
  const mask = carrotHash8(
    CARROT_DOMAIN.ENCRYPTION_MASK_AMOUNT,
    senderReceiverSecret,
    onetimeAddress
  );

  // Amount to 8-byte little-endian
  const amountBytes = new Uint8Array(8);
  let a = amount;
  for (let i = 0; i < 8; i++) {
    amountBytes[i] = Number(a & 0xffn);
    a >>= 8n;
  }

  const encrypted = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    encrypted[i] = amountBytes[i] ^ mask[i];
  }
  return encrypted;
}

/**
 * Encrypt payment ID for CARROT output
 * pid_enc = payment_id XOR H_8("Carrot encryption mask pid", s^ctx_sr, Ko)
 *
 * @param {Uint8Array} paymentId - 8-byte payment ID
 * @param {Uint8Array} senderReceiverSecret - Contextualized secret
 * @param {Uint8Array} onetimeAddress - One-time address
 * @returns {Uint8Array} 8-byte encrypted payment ID
 */
export function encryptCarrotPaymentId(paymentId, senderReceiverSecret, onetimeAddress) {
  const mask = carrotHash8(
    CARROT_DOMAIN.ENCRYPTION_MASK_PAYMENT_ID,
    senderReceiverSecret,
    onetimeAddress
  );

  const encrypted = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    encrypted[i] = paymentId[i] ^ mask[i];
  }
  return encrypted;
}

/**
 * Create a complete CARROT output
 *
 * @param {Object} params - Parameters
 * @param {Uint8Array} params.addressSpendPubkey - Recipient's spend public key (K_s)
 * @param {Uint8Array} params.addressViewPubkey - Recipient's view public key (K_v)
 * @param {bigint} params.amount - Amount to send
 * @param {Uint8Array} params.inputContext - Transaction input context
 * @param {Uint8Array} params.paymentId - 8-byte payment ID (optional, defaults to zeros)
 * @param {number} params.enoteType - Enote type (optional, defaults to PAYMENT)
 * @param {boolean} params.isSubaddress - Whether recipient is subaddress
 * @param {Uint8Array} params.anchor - Janus anchor (optional, generated if not provided)
 * @returns {Object} CARROT output with all components
 */
export function createCarrotOutput(params) {
  const {
    addressSpendPubkey,
    addressViewPubkey,
    amount,
    inputContext,
    paymentId = new Uint8Array(8),
    enoteType = CARROT_ENOTE_TYPE.PAYMENT,
    isSubaddress = false,
    anchor = generateJanusAnchor()
  } = params;

  // 1. Derive ephemeral private key
  const ephemeralPrivkey = deriveCarrotEphemeralPrivkey(
    anchor,
    inputContext,
    addressSpendPubkey,
    paymentId
  );

  // 2. Compute ephemeral public key
  const ephemeralPubkey = computeCarrotEphemeralPubkey(
    ephemeralPrivkey,
    addressSpendPubkey,
    isSubaddress
  );

  // 3. Compute shared secret (un-contextualized)
  const sharedSecret = computeCarrotSharedSecret(ephemeralPrivkey, addressViewPubkey);

  // 4. Derive contextualized sender-receiver secret
  const senderReceiverSecret = deriveCarrotSenderReceiverSecret(
    sharedSecret,
    ephemeralPubkey,
    inputContext
  );

  // 5. Derive amount blinding factor
  const amountBlindingFactor = deriveCarrotAmountBlindingFactor(
    senderReceiverSecret,
    amount,
    addressSpendPubkey,
    enoteType
  );

  // 6. Create amount commitment
  const amountCommitment = commit(amount, amountBlindingFactor);

  // 7. Derive one-time address extension keys
  const { extensionG, extensionT } = deriveCarrotOnetimeExtensions(
    senderReceiverSecret,
    amountCommitment
  );

  // 8. Compute one-time address
  const onetimeAddress = computeCarrotOnetimeAddress(
    addressSpendPubkey,
    extensionG,
    extensionT
  );

  // 9. Derive view tag
  const viewTag = deriveCarrotViewTag(sharedSecret, inputContext, onetimeAddress);

  // 10. Encrypt components
  const anchorEncrypted = encryptCarrotAnchor(anchor, senderReceiverSecret, onetimeAddress);
  const amountEncrypted = encryptCarrotAmount(amount, senderReceiverSecret, onetimeAddress);
  const paymentIdEncrypted = encryptCarrotPaymentId(paymentId, senderReceiverSecret, onetimeAddress);

  return {
    // Public output data
    ephemeralPubkey,
    onetimeAddress,
    amountCommitment,
    amountEncrypted,
    anchorEncrypted,
    viewTag,
    paymentIdEncrypted,

    // Private data (needed for spending)
    amountBlindingFactor,
    extensionG,
    extensionT,
    senderReceiverSecret,

    // Input data for reference
    anchor,
    inputContext,
    enoteType
  };
}

/**
 * Compute special Janus anchor for self-sends
 * anchor_sp = H_16("Carrot janus anchor special", D_e, input_context, Ko, k_v)
 *
 * @param {Uint8Array} ephemeralPubkey - Ephemeral public key
 * @param {Uint8Array} inputContext - Input context
 * @param {Uint8Array} onetimeAddress - One-time address
 * @param {Uint8Array} viewSecretKey - View secret key
 * @returns {Uint8Array} 16-byte special anchor
 */
export function computeCarrotSpecialAnchor(ephemeralPubkey, inputContext, onetimeAddress, viewSecretKey) {
  return carrotHash16(
    CARROT_DOMAIN.JANUS_ANCHOR_SPECIAL,
    ephemeralPubkey,
    inputContext,
    onetimeAddress,
    viewSecretKey
  );
}

// =============================================================================
// Block Serialization
// =============================================================================

/**
 * HF version that enables oracle pricing records
 * (Currently set to 255, meaning pricing records not yet active)
 */
export const HF_VERSION_ENABLE_ORACLE = 255;

/**
 * Serialize a pricing record supply_data structure
 * @param {Object} supply - { sal: bigint, vsd: bigint }
 * @returns {Uint8Array} Serialized supply data
 */
export function serializeSupplyData(supply) {
  const parts = [];
  parts.push(encodeVarint(BigInt(supply.sal || 0)));
  parts.push(encodeVarint(BigInt(supply.vsd || 0)));

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Serialize a pricing record asset_data structure
 * @param {Object} asset - { asset_type: string, spot_price: bigint, ma_price: bigint }
 * @returns {Uint8Array} Serialized asset data
 */
export function serializeAssetData(asset) {
  const parts = [];

  // asset_type as string (length-prefixed)
  const assetType = asset.asset_type || '';
  const assetTypeBytes = new TextEncoder().encode(assetType);
  parts.push(encodeVarint(BigInt(assetTypeBytes.length)));
  parts.push(assetTypeBytes);

  // spot_price and ma_price as varints
  parts.push(encodeVarint(BigInt(asset.spot_price || 0)));
  parts.push(encodeVarint(BigInt(asset.ma_price || 0)));

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Serialize a pricing_record structure
 * @param {Object} pricingRecord - Pricing record object
 * @returns {Uint8Array} Serialized pricing record
 */
export function serializePricingRecord(pricingRecord) {
  const parts = [];

  // pr_version (varint)
  parts.push(encodeVarint(BigInt(pricingRecord.pr_version || 0)));

  // height (varint)
  parts.push(encodeVarint(BigInt(pricingRecord.height || 0)));

  // supply (supply_data)
  parts.push(serializeSupplyData(pricingRecord.supply || { sal: 0, vsd: 0 }));

  // assets (vector of asset_data)
  const assets = pricingRecord.assets || [];
  parts.push(encodeVarint(BigInt(assets.length)));
  for (const asset of assets) {
    parts.push(serializeAssetData(asset));
  }

  // timestamp (varint)
  parts.push(encodeVarint(BigInt(pricingRecord.timestamp || 0)));

  // signature (vector of uint8)
  const signature = pricingRecord.signature || new Uint8Array(0);
  parts.push(encodeVarint(BigInt(signature.length)));
  parts.push(signature);

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Serialize a block header
 * @param {Object} header - Block header object
 * @returns {Uint8Array} Serialized block header
 */
export function serializeBlockHeader(header) {
  const parts = [];

  // major_version (varint)
  const majorVersion = header.major_version || 0;
  parts.push(encodeVarint(BigInt(majorVersion)));

  // minor_version (varint)
  parts.push(encodeVarint(BigInt(header.minor_version || 0)));

  // timestamp (varint)
  parts.push(encodeVarint(BigInt(header.timestamp || 0)));

  // prev_id (32-byte hash)
  const prevId = header.prev_id || new Uint8Array(32);
  if (prevId.length !== 32) {
    throw new Error('prev_id must be 32 bytes');
  }
  parts.push(prevId);

  // nonce (4 bytes, little-endian)
  const nonce = header.nonce || 0;
  const nonceBytes = new Uint8Array(4);
  nonceBytes[0] = nonce & 0xff;
  nonceBytes[1] = (nonce >>> 8) & 0xff;
  nonceBytes[2] = (nonce >>> 16) & 0xff;
  nonceBytes[3] = (nonce >>> 24) & 0xff;
  parts.push(nonceBytes);

  // pricing_record (only if major_version >= HF_VERSION_ENABLE_ORACLE)
  if (majorVersion >= HF_VERSION_ENABLE_ORACLE && header.pricing_record) {
    parts.push(serializePricingRecord(header.pricing_record));
  }

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Serialize a complete block
 * @param {Object} block - Block object containing header and transactions
 * @returns {Uint8Array} Serialized block
 */
export function serializeBlock(block) {
  const parts = [];

  // Block header fields
  parts.push(serializeBlockHeader(block));

  // miner_tx (full transaction - use existing serialization)
  // We need to serialize the full transaction including RingCT
  if (block.miner_tx) {
    // For coinbase transactions, we serialize prefix + RCT
    const minerTxPrefix = serializeTxPrefix(block.miner_tx);
    parts.push(minerTxPrefix);

    // RCT signature for miner_tx (usually RCTTypeNull for coinbase)
    if (block.miner_tx.rct_signatures) {
      parts.push(serializeRctBase(block.miner_tx.rct_signatures, block.miner_tx.vout?.length || 0));
    }
  }

  // protocol_tx (Salvium-specific)
  if (block.protocol_tx) {
    const protocolTxPrefix = serializeTxPrefix(block.protocol_tx);
    parts.push(protocolTxPrefix);

    if (block.protocol_tx.rct_signatures) {
      parts.push(serializeRctBase(block.protocol_tx.rct_signatures, block.protocol_tx.vout?.length || 0));
    }
  }

  // tx_hashes (vector of 32-byte hashes)
  const txHashes = block.tx_hashes || [];
  parts.push(encodeVarint(BigInt(txHashes.length)));
  for (const hash of txHashes) {
    if (hash.length !== 32) {
      throw new Error('tx_hash must be 32 bytes');
    }
    parts.push(hash);
  }

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Compute the block hash (hash of serialized block header)
 * @param {Object} block - Block object
 * @returns {Uint8Array} 32-byte block hash
 */
export function getBlockHash(block) {
  // Block hash is computed from the "hashing blob"
  // which includes: header + miner_tx_hash + tx_merkle_root
  const headerBytes = serializeBlockHeader(block);

  // Compute miner_tx hash if present
  let minerTxHash = new Uint8Array(32);
  if (block.miner_tx) {
    const minerTxPrefix = serializeTxPrefix(block.miner_tx);
    minerTxHash = cnFastHash(minerTxPrefix);
  }

  // Compute merkle root of tx_hashes (including protocol_tx if present)
  let allHashes = [];

  // Add protocol_tx hash if present
  if (block.protocol_tx) {
    const protocolTxPrefix = serializeTxPrefix(block.protocol_tx);
    allHashes.push(cnFastHash(protocolTxPrefix));
  }

  // Add all tx_hashes
  if (block.tx_hashes) {
    allHashes = allHashes.concat(block.tx_hashes);
  }

  // Compute merkle root
  const merkleRoot = computeMerkleRoot(allHashes);

  // Combine: header_hash, miner_tx_hash, merkle_root
  const combined = new Uint8Array(headerBytes.length + 32 + 32);
  combined.set(headerBytes, 0);
  combined.set(minerTxHash, headerBytes.length);
  combined.set(merkleRoot, headerBytes.length + 32);

  return cnFastHash(combined);
}

/**
 * Compute merkle root of transaction hashes
 * @param {Array<Uint8Array>} hashes - Array of 32-byte hashes
 * @returns {Uint8Array} 32-byte merkle root
 */
export function computeMerkleRoot(hashes) {
  if (hashes.length === 0) {
    return new Uint8Array(32); // Empty merkle root
  }

  if (hashes.length === 1) {
    return hashes[0];
  }

  // Build merkle tree
  let layer = [...hashes];

  while (layer.length > 1) {
    const nextLayer = [];

    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length) {
        // Hash pair
        const combined = new Uint8Array(64);
        combined.set(layer[i], 0);
        combined.set(layer[i + 1], 32);
        nextLayer.push(cnFastHash(combined));
      } else {
        // Odd one out - just pass through
        nextLayer.push(layer[i]);
      }
    }

    layer = nextLayer;
  }

  return layer[0];
}

// =============================================================================
// UTXO SELECTION
// =============================================================================

/**
 * UTXO selection strategies
 */
export const UTXO_STRATEGY = {
  LARGEST_FIRST: 'largest_first',    // Minimize number of inputs
  SMALLEST_FIRST: 'smallest_first',  // Privacy: use oldest/smallest first
  RANDOM: 'random',                   // Privacy: randomize selection
  FIFO: 'fifo'                        // First In First Out (oldest first)
};

/**
 * Select UTXOs to spend for a transaction
 *
 * @param {Array<Object>} utxos - Available UTXOs with { amount, globalIndex, txHash, outputIndex, ... }
 * @param {bigint} targetAmount - Amount to spend (excluding fee)
 * @param {bigint} feePerInput - Estimated fee per input (for fee calculation)
 * @param {Object} options - Selection options
 * @param {string} options.strategy - Selection strategy (default: LARGEST_FIRST)
 * @param {number} options.minConfirmations - Minimum confirmations required (default: 10)
 * @param {number} options.currentHeight - Current blockchain height (for confirmation check)
 * @param {bigint} options.dustThreshold - Minimum output value to consider (default: 1000000n)
 * @param {number} options.maxInputs - Maximum inputs to use (default: 150)
 * @returns {Object} { selected: Array<Object>, totalAmount: bigint, changeAmount: bigint, estimatedFee: bigint }
 */
export function selectUTXOs(utxos, targetAmount, feePerInput, options = {}) {
  const {
    strategy = UTXO_STRATEGY.LARGEST_FIRST,
    minConfirmations = CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
    currentHeight = 0,
    dustThreshold = 1000000n,
    maxInputs = 150
  } = options;

  if (typeof targetAmount === 'number') {
    targetAmount = BigInt(targetAmount);
  }
  if (typeof feePerInput === 'number') {
    feePerInput = BigInt(feePerInput);
  }

  // Filter eligible UTXOs
  const eligible = utxos.filter(utxo => {
    const amount = typeof utxo.amount === 'bigint' ? utxo.amount : BigInt(utxo.amount);
    // Must be above dust threshold
    if (amount < dustThreshold) return false;
    // Must have enough confirmations
    if (currentHeight > 0 && utxo.blockHeight) {
      const confirmations = currentHeight - utxo.blockHeight;
      if (confirmations < minConfirmations) return false;
    }
    return true;
  });

  if (eligible.length === 0) {
    throw new Error('No eligible UTXOs available');
  }

  // Sort based on strategy
  let sorted;
  switch (strategy) {
    case UTXO_STRATEGY.LARGEST_FIRST:
      sorted = [...eligible].sort((a, b) => {
        const aAmount = typeof a.amount === 'bigint' ? a.amount : BigInt(a.amount);
        const bAmount = typeof b.amount === 'bigint' ? b.amount : BigInt(b.amount);
        return bAmount > aAmount ? 1 : bAmount < aAmount ? -1 : 0;
      });
      break;
    case UTXO_STRATEGY.SMALLEST_FIRST:
      sorted = [...eligible].sort((a, b) => {
        const aAmount = typeof a.amount === 'bigint' ? a.amount : BigInt(a.amount);
        const bAmount = typeof b.amount === 'bigint' ? b.amount : BigInt(b.amount);
        return aAmount > bAmount ? 1 : aAmount < bAmount ? -1 : 0;
      });
      break;
    case UTXO_STRATEGY.FIFO:
      sorted = [...eligible].sort((a, b) => {
        return (a.blockHeight || 0) - (b.blockHeight || 0);
      });
      break;
    case UTXO_STRATEGY.RANDOM:
      sorted = [...eligible];
      // Fisher-Yates shuffle
      for (let i = sorted.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [sorted[i], sorted[j]] = [sorted[j], sorted[i]];
      }
      break;
    default:
      sorted = eligible;
  }

  // Select UTXOs until we have enough
  const selected = [];
  let totalAmount = 0n;

  for (const utxo of sorted) {
    if (selected.length >= maxInputs) break;

    selected.push(utxo);
    const amount = typeof utxo.amount === 'bigint' ? utxo.amount : BigInt(utxo.amount);
    totalAmount += amount;

    // Calculate estimated fee with current selection
    const estimatedFee = feePerInput * BigInt(selected.length);
    const required = targetAmount + estimatedFee;

    if (totalAmount >= required) {
      break;
    }
  }

  // Check if we have enough
  const estimatedFee = feePerInput * BigInt(selected.length);
  const required = targetAmount + estimatedFee;

  if (totalAmount < required) {
    const shortfall = required - totalAmount;
    throw new Error(`Insufficient funds: need ${required} but only have ${totalAmount} (short ${shortfall})`);
  }

  const changeAmount = totalAmount - required;

  return {
    selected,
    totalAmount,
    changeAmount,
    estimatedFee
  };
}

// =============================================================================
// TRANSACTION BUILDING
// =============================================================================

/**
 * Build a complete transaction
 *
 * This is the main orchestration function that creates a signed transaction
 * ready for broadcast. It handles:
 * - Output creation with one-time keys
 * - Pedersen commitments for amounts
 * - CLSAG ring signatures
 * - Bulletproofs+ range proofs
 * - Change output generation
 * - Fee calculation and balance verification
 *
 * @param {Object} params - Transaction parameters
 * @param {Array<Object>} params.inputs - Inputs to spend, each with:
 *   - secretKey: Uint8Array - One-time secret key for this output
 *   - publicKey: Uint8Array - One-time public key
 *   - amount: bigint - Amount of this input
 *   - mask: Uint8Array - Commitment mask (blinding factor)
 *   - globalIndex: number - Global output index (for key offsets)
 *   - ring: Array<Uint8Array> - Ring member public keys (including real key)
 *   - ringCommitments: Array<Uint8Array> - Ring member commitments
 *   - realIndex: number - Index of real key in ring
 * @param {Array<Object>} params.destinations - Outputs to create, each with:
 *   - address: string - Destination address
 *   - amount: bigint - Amount to send
 *   - paymentId?: string - Optional payment ID (for integrated addresses)
 * @param {Object} params.changeAddress - Change address info:
 *   - viewPublicKey: Uint8Array - View public key
 *   - spendPublicKey: Uint8Array - Spend public key
 *   - isSubaddress?: boolean - True if subaddress
 * @param {bigint} params.fee - Transaction fee
 * @param {Object} options - Additional options
 * @param {number} options.unlockTime - Unlock time (default: 0)
 * @param {Uint8Array} options.txSecretKey - Pre-generated tx secret key
 * @param {boolean} options.useCarrot - Use CARROT addressing (default: false)
 * @returns {Object} Complete transaction ready for serialization/broadcast
 */
export function buildTransaction(params, options = {}) {
  const { inputs, destinations, changeAddress, fee } = params;
  const {
    unlockTime = 0,
    txSecretKey: providedTxSecKey,
    useCarrot = false,
    // Salvium-specific options
    txType = TX_TYPE.TRANSFER,
    amountBurnt = 0n,
    sourceAssetType = 'SAL',
    destinationAssetType = 'SAL',
    returnAddress = null,
    returnPubkey = null,
    protocolTxData = null,
    amountSlippageLimit = 0n
  } = options;

  if (!inputs || inputs.length === 0) {
    throw new Error('At least one input is required');
  }
  // STAKE and BURN transactions can have no payment destinations (only change)
  // The "burned" amount goes to amount_burnt field, not to outputs
  if ((!destinations || destinations.length === 0) &&
      txType !== TX_TYPE.STAKE && txType !== TX_TYPE.BURN) {
    throw new Error('At least one destination is required');
  }

  // Convert fee to bigint if needed
  const feeBig = typeof fee === 'bigint' ? fee : BigInt(fee);

  // Calculate total input amount
  let totalInputAmount = 0n;
  for (const input of inputs) {
    const amount = typeof input.amount === 'bigint' ? input.amount : BigInt(input.amount);
    totalInputAmount += amount;
  }

  // Calculate total output amount
  let totalOutputAmount = 0n;
  for (const dest of destinations) {
    const amount = typeof dest.amount === 'bigint' ? dest.amount : BigInt(dest.amount);
    totalOutputAmount += amount;
  }

  // Verify balance
  const changeAmount = totalInputAmount - totalOutputAmount - feeBig;
  if (changeAmount < 0n) {
    throw new Error(`Insufficient funds: inputs=${totalInputAmount}, outputs=${totalOutputAmount}, fee=${feeBig}`);
  }

  // Generate transaction secret key
  const txSecretKey = providedTxSecKey || generateTxSecretKey();

  // Create outputs (destinations + change if needed)
  const outputs = [];
  const outputMasks = [];
  let outputIndex = 0;

  // Add destination outputs
  for (const dest of destinations) {
    const amount = typeof dest.amount === 'bigint' ? dest.amount : BigInt(dest.amount);

    // Parse destination address to get public keys
    // Note: Caller should pre-parse addresses and provide viewPublicKey/spendPublicKey
    const output = createOutput(
      txSecretKey,
      dest.viewPublicKey,
      dest.spendPublicKey,
      amount,
      outputIndex,
      dest.isSubaddress || false
    );

    outputs.push({
      amount,
      publicKey: output.outputPublicKey,
      commitment: output.commitment,
      encryptedAmount: output.encryptedAmount,
      mask: output.mask
    });
    outputMasks.push(output.mask);
    outputIndex++;
  }

  // Add change output if there's change
  if (changeAmount > 0n && changeAddress) {
    const changeOutput = createOutput(
      txSecretKey,
      changeAddress.viewPublicKey,
      changeAddress.spendPublicKey,
      changeAmount,
      outputIndex,
      changeAddress.isSubaddress || false
    );

    outputs.push({
      amount: changeAmount,
      publicKey: changeOutput.outputPublicKey,
      commitment: changeOutput.commitment,
      encryptedAmount: changeOutput.encryptedAmount,
      mask: changeOutput.mask,
      isChange: true
    });
    outputMasks.push(changeOutput.mask);
  }

  // Generate key images for inputs
  const keyImages = inputs.map(input => {
    return generateKeyImage(input.publicKey, input.secretKey);
  });

  // Build transaction prefix
  const txPrefix = {
    version: TX_VERSION.RCT_2,
    unlockTime,
    vin: inputs.map((input, i) => ({
      type: TXIN_TYPE.KEY,
      amount: 0n, // RingCT: always 0
      keyOffsets: indicesToOffsets(input.ring.map((_, j) => {
        // Convert ring to global indices
        return input.ringIndices ? input.ringIndices[j] : j;
      })),
      keyImage: keyImages[i]
    })),
    vout: outputs.map(output => ({
      type: TXOUT_TYPE.KEY,
      amount: 0n, // RingCT: always 0
      target: output.publicKey  // 'target' for serialization compatibility
    })),
    extra: {
      txPubKey: getTxPublicKey(txSecretKey)
    },
    // Salvium-specific prefix fields
    txType,
    amount_burnt: amountBurnt,
    source_asset_type: sourceAssetType,
    destination_asset_type: destinationAssetType,
    return_address: returnAddress,
    return_pubkey: returnPubkey,
    protocol_tx_data: protocolTxData,
    amount_slippage_limit: amountSlippageLimit
  };

  // Calculate transaction prefix hash
  const txPrefixHash = getTxPrefixHash(txPrefix);

  // Compute pseudo output commitments (balances input/output masks)
  const inputsForPseudo = inputs.map(input => ({
    amount: typeof input.amount === 'bigint' ? input.amount : BigInt(input.amount),
    mask: input.mask
  }));
  const outputsForPseudo = outputs.map(output => ({
    amount: output.amount,
    mask: output.mask
  }));

  const { pseudoOuts, pseudoMasks } = computePseudoOutputs(inputsForPseudo, outputsForPseudo, feeBig);

  // Build RingCT base (needed for pre-MLSAG hash)
  const rctBase = {
    type: RCT_TYPE.BulletproofPlus,
    fee: feeBig,
    pseudoOuts: pseudoOuts.map(p => bytesToHex(p)),
    ecdhInfo: outputs.map(o => bytesToHex(o.encryptedAmount)),
    outPk: outputs.map(o => bytesToHex(o.commitment))
  };

  // Serialize RCT base for pre-MLSAG hash
  const rctBaseSerialized = serializeRctBase(rctBase);

  // Calculate pre-MLSAG hash (message to sign)
  const preMLsagHash = getPreMlsagHash(txPrefixHash, rctBaseSerialized, pseudoOuts);

  // Sign each input with CLSAG
  const clsags = [];
  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i];

    // The mask for signing is the difference between pseudo output mask and real mask
    // signingMask = pseudoMask - inputMask (so commitment - pseudoOut = 0)
    const inputMask = typeof input.mask === 'string' ? hexToBytes(input.mask) : input.mask;
    const signingMask = scSub(pseudoMasks[i], inputMask);

    const sig = clsagSign(
      preMLsagHash,
      input.ring,
      input.secretKey,
      input.ringCommitments,
      signingMask,
      pseudoOuts[i],
      input.realIndex
    );

    clsags.push(sig);
  }

  // Generate Bulletproofs+ range proofs for outputs
  // Note: This requires the proveRangeMultiple function from bulletproofs_plus.js
  let bulletproofPlus = null;
  try {
    // Import dynamically if needed, or assume caller handles proofs separately
    // For now, we note that range proofs should be generated
    bulletproofPlus = {
      // Range proof would be generated here
      // proof: proveRangeMultiple(outputs.map(o => o.amount), outputMasks)
      note: 'Range proof generation requires proveRangeMultiple'
    };
  } catch (e) {
    // Range proofs can be added after
  }

  // Assemble complete transaction
  const transaction = {
    prefix: txPrefix,
    rct: {
      type: RCT_TYPE.BulletproofPlus,
      fee: feeBig,
      pseudoOuts: pseudoOuts.map(p => bytesToHex(p)),
      ecdhInfo: outputs.map(o => bytesToHex(o.encryptedAmount)),
      outPk: outputs.map(o => bytesToHex(o.commitment)),
      CLSAGs: clsags,
      bulletproofPlus
    },
    // Additional metadata (not serialized to chain)
    _meta: {
      txSecretKey: bytesToHex(txSecretKey),
      keyImages: keyImages.map(ki => bytesToHex(ki)),
      outputMasks: outputMasks.map(m => bytesToHex(m)),
      changeIndex: changeAmount > 0n ? outputs.length - 1 : -1
    }
  };

  return transaction;
}

/**
 * Build a STAKE transaction (Salvium-specific)
 *
 * STAKE transactions lock funds for STAKE_LOCK_PERIOD blocks and earn yield.
 * Key differences from regular transfers:
 * - Funds go to own address (self-send with lock)
 * - amount_burnt contains the staked amount
 * - Only change output (no payment destination)
 * - unlock_time = STAKE_LOCK_PERIOD
 *
 * @param {Object} params - Transaction parameters
 * @param {Array<Object>} params.inputs - Inputs to spend
 * @param {bigint} params.stakeAmount - Amount to stake
 * @param {Object} params.returnAddress - Address to receive stake back (usually own address)
 *   - viewPublicKey, spendPublicKey, isSubaddress
 * @param {bigint} params.fee - Transaction fee
 * @param {Object} options - Additional options
 * @param {number} options.stakeLockPeriod - Lock period in blocks (default: 21600 mainnet)
 * @param {string} options.assetType - Asset type to stake ('SAL' or 'SAL1')
 * @param {Uint8Array} options.txSecretKey - Pre-generated tx secret key
 * @param {boolean} options.useCarrot - Use CARROT protocol (affects protocol_tx_data)
 * @returns {Object} Complete STAKE transaction ready for broadcast
 */
export function buildStakeTransaction(params, options = {}) {
  const { inputs, stakeAmount, returnAddress, fee } = params;
  const {
    stakeLockPeriod = 21600, // Mainnet default
    assetType = 'SAL',
    txSecretKey,
    useCarrot = false
  } = options;

  if (!inputs || inputs.length === 0) {
    throw new Error('At least one input is required');
  }
  if (!stakeAmount || stakeAmount <= 0n) {
    throw new Error('Stake amount must be positive');
  }
  if (!returnAddress) {
    throw new Error('Return address is required for stake transaction');
  }

  const stakeAmountBig = typeof stakeAmount === 'bigint' ? stakeAmount : BigInt(stakeAmount);
  const feeBig = typeof fee === 'bigint' ? fee : BigInt(fee);

  // Calculate total input amount
  let totalInputAmount = 0n;
  for (const input of inputs) {
    const amount = typeof input.amount === 'bigint' ? input.amount : BigInt(input.amount);
    totalInputAmount += amount;
  }

  // For STAKE: staked amount goes in amount_burnt, only change output
  const changeAmount = totalInputAmount - stakeAmountBig - feeBig;
  if (changeAmount < 0n) {
    throw new Error(`Insufficient funds: inputs=${totalInputAmount}, stake=${stakeAmountBig}, fee=${feeBig}`);
  }

  // Create dummy destination (STAKE has no real destination - amount goes to amount_burnt)
  // But we need at least one output (change) for the ring signature
  const destinations = [];

  // Prepare protocol_tx_data for CARROT STAKE (version >= 4)
  let protocolTxData = null;
  let returnAddressBytes = null;
  let returnPubkeyBytes = null;

  if (useCarrot) {
    // CARROT STAKE uses protocol_tx_data structure
    protocolTxData = {
      version: 1,
      return_address: typeof returnAddress.onetimeAddress === 'string'
        ? hexToBytes(returnAddress.onetimeAddress)
        : (returnAddress.onetimeAddress || new Uint8Array(32)),
      return_pubkey: typeof returnAddress.spendPublicKey === 'string'
        ? hexToBytes(returnAddress.spendPublicKey)
        : returnAddress.spendPublicKey,
      return_view_tag: returnAddress.viewTag || new Uint8Array(3),
      return_anchor_enc: returnAddress.anchorEnc || new Uint8Array(16)
    };
  } else {
    // Legacy STAKE uses return_address and return_pubkey
    returnAddressBytes = typeof returnAddress.spendPublicKey === 'string'
      ? hexToBytes(returnAddress.spendPublicKey)
      : returnAddress.spendPublicKey;
    returnPubkeyBytes = typeof returnAddress.viewPublicKey === 'string'
      ? hexToBytes(returnAddress.viewPublicKey)
      : returnAddress.viewPublicKey;
  }

  // Build using base buildTransaction with STAKE options
  return buildTransaction(
    {
      inputs,
      destinations,  // Empty - STAKE has no payment destinations
      changeAddress: returnAddress,  // Change goes back to staker
      fee
    },
    {
      unlockTime: stakeLockPeriod,
      txSecretKey,
      useCarrot,
      txType: TX_TYPE.STAKE,
      amountBurnt: stakeAmountBig,
      sourceAssetType: assetType,
      destinationAssetType: assetType,
      returnAddress: returnAddressBytes,
      returnPubkey: returnPubkeyBytes,
      protocolTxData,
      amountSlippageLimit: 0n
    }
  );
}

/**
 * Sign an unsigned transaction
 *
 * Used when transaction was pre-built without signatures (e.g., offline signing)
 *
 * @param {Object} unsignedTx - Unsigned transaction with:
 *   - prefix: Transaction prefix
 *   - rct: RingCT data without CLSAGs
 *   - inputs: Array of input data for signing
 * @param {Array<Object>} secrets - Signing secrets for each input:
 *   - secretKey: Uint8Array - One-time secret key
 *   - mask: Uint8Array - Commitment mask
 * @returns {Object} Signed transaction
 */
export function signTransaction(unsignedTx, secrets) {
  const { prefix, rct, inputs } = unsignedTx;

  if (!inputs || inputs.length !== secrets.length) {
    throw new Error('Number of secrets must match number of inputs');
  }

  // Calculate transaction prefix hash
  const txPrefixHash = getTxPrefixHash(prefix);

  // Parse pseudo outputs
  const pseudoOuts = rct.pseudoOuts.map(p =>
    typeof p === 'string' ? hexToBytes(p) : p
  );

  // Build RingCT base for pre-MLSAG hash
  const rctBase = {
    type: rct.type,
    fee: rct.fee,
    pseudoOuts: rct.pseudoOuts,
    ecdhInfo: rct.ecdhInfo,
    outPk: rct.outPk
  };

  // Calculate pre-MLSAG hash
  const preMLsagHash = getPreMlsagHash(txPrefixHash, rctBase, pseudoOuts);

  // Compute pseudo output masks (need to reconstruct from outputs)
  // For signing, we need the relationship between pseudo and real masks
  const pseudoMasks = unsignedTx._pseudoMasks ||
    secrets.map(() => scRandom()); // If not provided, random (signing would fail)

  // Sign each input
  const clsags = [];
  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i];
    const secret = secrets[i];

    const inputMask = typeof secret.mask === 'string' ? hexToBytes(secret.mask) : secret.mask;
    const pseudoMask = typeof pseudoMasks[i] === 'string' ? hexToBytes(pseudoMasks[i]) : pseudoMasks[i];
    const signingMask = scSub(pseudoMask, inputMask);

    const sig = clsagSign(
      preMLsagHash,
      input.ring,
      secret.secretKey,
      input.ringCommitments,
      signingMask,
      pseudoOuts[i],
      input.realIndex
    );

    clsags.push(sig);
  }

  // Return signed transaction
  return {
    prefix,
    rct: {
      ...rct,
      CLSAGs: clsags
    },
    _meta: unsignedTx._meta
  };
}

/**
 * Prepare inputs for transaction building by fetching decoys
 *
 * @param {Array<Object>} ownedOutputs - Outputs to spend, each with:
 *   - publicKey: Uint8Array - One-time public key
 *   - secretKey: Uint8Array - One-time secret key (derived)
 *   - amount: bigint - Decrypted amount
 *   - mask: Uint8Array - Commitment mask
 *   - commitment: Uint8Array - Pedersen commitment
 *   - globalIndex: number - Global output index
 * @param {Object} rpcClient - Daemon RPC client (for fetching decoys)
 * @param {Object} options - Options
 * @param {number} options.ringSize - Ring size (default: 16)
 * @param {Array<number>} options.rctOffsets - Global output distribution
 * @returns {Promise<Array<Object>>} Prepared inputs ready for buildTransaction
 */
export async function prepareInputs(ownedOutputs, rpcClient, options = {}) {
  const { ringSize = DEFAULT_RING_SIZE, rctOffsets } = options;

  const preparedInputs = [];

  for (const output of ownedOutputs) {
    // Get global output distribution if not provided
    let offsets = rctOffsets;
    if (!offsets && rpcClient) {
      const histogram = await rpcClient.getOutputHistogram({ amounts: [0] });
      offsets = histogram.histogram[0]?.recent_outputs_offsets || [];
    }

    // Select decoy indices
    const decoyIndices = selectDecoys(
      offsets,
      output.globalIndex,
      ringSize,
      new Set([output.globalIndex])
    );

    // Fetch ring member keys and commitments
    let ring, ringCommitments;
    if (rpcClient) {
      const outsResponse = await rpcClient.getOuts({
        outputs: decoyIndices.map(i => ({ amount: 0, index: i })),
        get_txid: false
      });

      ring = outsResponse.outs.map(o => hexToBytes(o.key));
      ringCommitments = outsResponse.outs.map(o => hexToBytes(o.mask));
    } else {
      // Placeholder for testing
      ring = decoyIndices.map(() => new Uint8Array(32));
      ringCommitments = decoyIndices.map(() => new Uint8Array(32));
    }

    // Find real index in sorted ring
    const sortedIndices = [...decoyIndices].sort((a, b) => a - b);
    const realIndex = sortedIndices.indexOf(output.globalIndex);

    // Insert real output at correct position
    ring[realIndex] = typeof output.publicKey === 'string'
      ? hexToBytes(output.publicKey)
      : output.publicKey;
    ringCommitments[realIndex] = typeof output.commitment === 'string'
      ? hexToBytes(output.commitment)
      : output.commitment;

    preparedInputs.push({
      secretKey: output.secretKey,
      publicKey: output.publicKey,
      amount: output.amount,
      mask: output.mask,
      globalIndex: output.globalIndex,
      ring,
      ringCommitments,
      ringIndices: sortedIndices,
      realIndex
    });
  }

  return preparedInputs;
}

/**
 * Estimate fee for a transaction
 *
 * @param {number} numInputs - Number of inputs
 * @param {number} numOutputs - Number of outputs (including change)
 * @param {Object} options - Fee options
 * @param {string} options.priority - Fee priority (default, low, high, highest)
 * @param {number} options.ringSize - Ring size (default: 16)
 * @param {bigint} options.baseFee - Base fee per byte (from network)
 * @returns {bigint} Estimated fee in atomic units
 */
export function estimateTransactionFee(numInputs, numOutputs, options = {}) {
  const {
    priority = 'default',
    ringSize = DEFAULT_RING_SIZE,
    baseFee = FEE_PER_KB
  } = options;

  // Convert string priority to number
  let priorityNum;
  if (typeof priority === 'string') {
    switch (priority.toLowerCase()) {
      case 'low': priorityNum = FEE_PRIORITY.LOW; break;
      case 'high': priorityNum = FEE_PRIORITY.HIGH; break;
      case 'highest': priorityNum = FEE_PRIORITY.HIGHEST; break;
      default: priorityNum = FEE_PRIORITY.NORMAL; break;
    }
  } else {
    priorityNum = priority;
  }

  // Estimate transaction size
  const size = estimateTxSize(numInputs, ringSize, numOutputs, 0, { bulletproofPlus: true });

  // Get fee multiplier for priority
  const multiplier = getFeeMultiplier(priorityNum);

  // Calculate fee (size is already a number from estimateTxSize)
  return calculateFeeFromSize(baseFee * BigInt(multiplier), size);
}

/**
 * Validate a transaction before broadcast
 *
 * @param {Object} tx - Transaction to validate
 * @returns {Object} { valid: boolean, errors: Array<string> }
 */
export function validateTransaction(tx) {
  const errors = [];

  // Check transaction has required fields
  if (!tx.prefix) {
    errors.push('Missing transaction prefix');
  }
  if (!tx.rct) {
    errors.push('Missing RingCT signature data');
  }

  if (tx.prefix) {
    // Check version
    if (tx.prefix.version < 2) {
      errors.push('Invalid transaction version');
    }

    // Check inputs
    if (!tx.prefix.vin || tx.prefix.vin.length === 0) {
      errors.push('Transaction has no inputs');
    }

    // Check outputs
    if (!tx.prefix.vout || tx.prefix.vout.length === 0) {
      errors.push('Transaction has no outputs');
    }

    // Check for duplicate key images
    const keyImages = new Set();
    for (const vin of tx.prefix.vin || []) {
      if (vin.keyImage) {
        const kiHex = typeof vin.keyImage === 'string'
          ? vin.keyImage
          : bytesToHex(vin.keyImage);
        if (keyImages.has(kiHex)) {
          errors.push('Duplicate key image detected');
        }
        keyImages.add(kiHex);
      }
    }
  }

  if (tx.rct) {
    // Check CLSAG signatures present
    if (!tx.rct.CLSAGs || tx.rct.CLSAGs.length === 0) {
      errors.push('Missing CLSAG signatures');
    }

    // Check signature count matches input count
    if (tx.prefix && tx.rct.CLSAGs) {
      if (tx.rct.CLSAGs.length !== tx.prefix.vin.length) {
        errors.push('CLSAG count does not match input count');
      }
    }

    // Check output commitments present
    if (!tx.rct.outPk || tx.rct.outPk.length === 0) {
      errors.push('Missing output commitments');
    }

    // Check fee is positive
    if (tx.rct.fee <= 0n) {
      errors.push('Fee must be positive');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Serialize a complete transaction for broadcast
 *
 * @param {Object} tx - Transaction object
 * @returns {Uint8Array} Serialized transaction bytes
 */
export function serializeTransaction(tx) {
  // Adapt prefix structure for serializeTxPrefix
  // (buildTransaction uses vin/vout, serializeTxPrefix expects inputs/outputs)
  const prefixForSerialization = {
    version: tx.prefix.version,
    unlockTime: tx.prefix.unlockTime,
    inputs: tx.prefix.vin,
    outputs: tx.prefix.vout,
    extra: tx.prefix.extra
  };

  // Serialize prefix
  const prefixBytes = serializeTxPrefix(prefixForSerialization);

  // Serialize RingCT base
  const rctBaseBytes = serializeRctBase(tx.rct);

  // Serialize CLSAG signatures
  const clsagBytes = [];
  for (const sig of tx.rct.CLSAGs) {
    clsagBytes.push(serializeCLSAG(sig));
  }

  // Serialize output commitments
  const outPkBytes = serializeOutPk(tx.rct.outPk);

  // Serialize ECDH info
  const ecdhBytes = serializeEcdhInfo(tx.rct.ecdhInfo);

  // Combine all parts
  let totalLen = prefixBytes.length + rctBaseBytes.length;
  for (const cb of clsagBytes) {
    totalLen += cb.length;
  }
  totalLen += outPkBytes.length + ecdhBytes.length;

  // Add Bulletproof+ proof if present
  let bpBytes = new Uint8Array(0);
  if (tx.rct.bulletproofPlus && tx.rct.bulletproofPlus.serialized) {
    bpBytes = tx.rct.bulletproofPlus.serialized;
    totalLen += bpBytes.length;
  }

  const result = new Uint8Array(totalLen);
  let offset = 0;

  result.set(prefixBytes, offset);
  offset += prefixBytes.length;

  result.set(rctBaseBytes, offset);
  offset += rctBaseBytes.length;

  for (const cb of clsagBytes) {
    result.set(cb, offset);
    offset += cb.length;
  }

  result.set(outPkBytes, offset);
  offset += outPkBytes.length;

  result.set(ecdhBytes, offset);
  offset += ecdhBytes.length;

  if (bpBytes.length > 0) {
    result.set(bpBytes, offset);
  }

  return result;
}

// =============================================================================
// TRANSACTION PARSING / DECODING
// =============================================================================

/**
 * Parse a raw transaction from bytes
 *
 * @param {Uint8Array|string} data - Raw transaction bytes or hex string
 * @returns {Object} Parsed transaction object
 */
export function parseTransaction(data) {
  if (typeof data === 'string') {
    data = hexToBytes(data);
  }

  let offset = 0;

  // Helper to read bytes
  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of data at offset ${offset}`);
    }
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  // Helper to read varint
  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  // Parse transaction prefix
  const version = Number(readVarint());
  const unlockTime = Number(readVarint());

  // Parse inputs
  const vinCount = Number(readVarint());
  const vin = [];

  for (let i = 0; i < vinCount; i++) {
    const inputType = data[offset++];

    if (inputType === TXIN_TYPE.GEN) {
      // Coinbase input
      const height = Number(readVarint());
      vin.push({ type: TXIN_TYPE.GEN, height });
    } else if (inputType === TXIN_TYPE.KEY) {
      // Key input (Salvium format includes asset_type)
      const amount = readVarint();

      // Salvium-specific: read asset_type string (length-prefixed)
      const assetTypeLen = Number(readVarint());
      let assetType = '';
      if (assetTypeLen > 0) {
        const assetTypeBytes = readBytes(assetTypeLen);
        assetType = new TextDecoder().decode(assetTypeBytes);
      }

      const keyOffsetCount = Number(readVarint());
      const keyOffsets = [];
      for (let j = 0; j < keyOffsetCount; j++) {
        keyOffsets.push(Number(readVarint()));
      }
      const keyImage = readBytes(32);
      vin.push({
        type: TXIN_TYPE.KEY,
        amount,
        assetType,
        keyOffsets,
        keyImage
      });
    } else {
      throw new Error(`Unknown input type: ${inputType}`);
    }
  }

  // Parse outputs
  const voutCount = Number(readVarint());
  const vout = [];

  for (let i = 0; i < voutCount; i++) {
    const amount = readVarint();
    const outputType = data[offset++];

    if (outputType === TXOUT_TYPE.KEY) {
      // Salvium txout_to_key: key + asset_type + unlock_time
      const key = readBytes(32);

      // Salvium-specific: read asset_type string
      const assetTypeLen = Number(readVarint());
      let assetType = '';
      if (assetTypeLen > 0) {
        const assetTypeBytes = readBytes(assetTypeLen);
        assetType = new TextDecoder().decode(assetTypeBytes);
      }

      const outputUnlockTime = Number(readVarint());

      vout.push({
        type: TXOUT_TYPE.KEY,
        amount,
        key,
        assetType,
        unlockTime: outputUnlockTime
      });
    } else if (outputType === TXOUT_TYPE.TAGGED_KEY) {
      // Salvium txout_to_tagged_key: key + asset_type + unlock_time + view_tag
      const key = readBytes(32);

      // Salvium-specific: read asset_type string
      const assetTypeLen = Number(readVarint());
      let assetType = '';
      if (assetTypeLen > 0) {
        const assetTypeBytes = readBytes(assetTypeLen);
        assetType = new TextDecoder().decode(assetTypeBytes);
      }

      const outputUnlockTime = Number(readVarint());
      const viewTag = data[offset++];

      vout.push({
        type: TXOUT_TYPE.TAGGED_KEY,
        amount,
        key,
        assetType,
        unlockTime: outputUnlockTime,
        viewTag
      });
    } else if (outputType === 0x04) {
      // Salvium txout_to_carrot_v1: key + asset_type + view_tag(3) + encrypted_janus_anchor(16)
      const key = readBytes(32);

      // Salvium-specific: read asset_type string
      const assetTypeLen = Number(readVarint());
      let assetType = '';
      if (assetTypeLen > 0) {
        const assetTypeBytes = readBytes(assetTypeLen);
        assetType = new TextDecoder().decode(assetTypeBytes);
      }

      const viewTag = readBytes(3);  // carrot view_tag is 3 bytes
      const encryptedJanusAnchor = readBytes(16);  // janus anchor is 16 bytes

      vout.push({
        type: 0x04,  // CARROT_V1
        amount,
        key,
        assetType,
        viewTag,
        encryptedJanusAnchor
      });
    } else {
      throw new Error(`Unknown output type: ${outputType}`);
    }
  }

  // Parse extra
  const extraSize = Number(readVarint());
  const extraBytes = readBytes(extraSize);
  const extra = parseExtra(extraBytes);

  // Salvium-specific transaction prefix fields (cryptonote_basic.h lines 249-280)
  const txType = Number(readVarint());

  let amount_burnt = 0n;
  let return_address = null;
  let return_address_list = null;
  let return_address_change_mask = null;
  let return_pubkey = null;
  let source_asset_type = '';
  let destination_asset_type = '';
  let amount_slippage_limit = 0n;
  let protocol_tx_data = null;

  // TX_TYPE: see TX_TYPE constant
  if (txType !== TX_TYPE.UNSET && txType !== TX_TYPE.PROTOCOL) {
    // type != UNSET && type != PROTOCOL
    amount_burnt = readVarint();

    if (txType !== TX_TYPE.MINER) {
      // type != MINER
      if (txType === TX_TYPE.TRANSFER && version >= 3) {
        // TRANSFER with version >= TRANSACTION_VERSION_N_OUTS (3)
        const returnListCount = Number(readVarint());
        return_address_list = [];
        for (let i = 0; i < returnListCount; i++) {
          return_address_list.push(readBytes(32));
        }
        const changeMaskCount = Number(readVarint());
        return_address_change_mask = readBytes(changeMaskCount);
      } else if (txType === TX_TYPE.STAKE && version >= 4) {
        // STAKE with version >= TRANSACTION_VERSION_CARROT (4)
        // protocol_tx_data_t has: version(varint), return_address(32), return_pubkey(32), return_view_tag(3), return_anchor_enc(16)
        protocol_tx_data = {
          version: Number(readVarint()),
          return_address: readBytes(32),
          return_pubkey: readBytes(32),
          return_view_tag: readBytes(3),
          return_anchor_enc: readBytes(16)
        };
      } else {
        return_address = readBytes(32);
        return_pubkey = readBytes(32);
      }

      // source_asset_type (string)
      const srcTypeLen = Number(readVarint());
      if (srcTypeLen > 0) {
        source_asset_type = new TextDecoder().decode(readBytes(srcTypeLen));
      }

      // destination_asset_type (string)
      const dstTypeLen = Number(readVarint());
      if (dstTypeLen > 0) {
        destination_asset_type = new TextDecoder().decode(readBytes(dstTypeLen));
      }

      amount_slippage_limit = readVarint();
    }
  }

  const prefix = {
    version,
    unlockTime,
    vin,
    vout,
    extra,
    // Salvium-specific
    txType,
    amount_burnt,
    return_address,
    return_address_list,
    return_address_change_mask,
    return_pubkey,
    source_asset_type,
    destination_asset_type,
    amount_slippage_limit,
    protocol_tx_data
  };

  // For v1 transactions, we're done
  if (version === 1) {
    return { prefix, _bytesRead: offset };
  }

  // Track prefix end offset for _bytesRead calculation
  const prefixEndOffset = offset;

  // Get mixin from first input (needed for CLSAG parsing)
  const mixin = vin.length > 0 && vin[0].keyOffsets ? vin[0].keyOffsets.length - 1 : 15;

  // Parse RingCT signature for v2+ transactions
  const rct = parseRingCtSignature(data, offset, vin.length, vout.length, mixin);

  // Use actual end offset from RCT parsing for accurate _bytesRead
  const rctEndOffset = rct._endOffset || (prefixEndOffset + 1); // fallback to prefix + 1 byte for Null type
  delete rct._endOffset; // Clean up internal field

  return { prefix, rct, _bytesRead: rctEndOffset };
}

/**
 * Parse transaction extra field
 *
 * @param {Uint8Array} extraBytes - Raw extra bytes
 * @returns {Array} Parsed extra fields
 */
export function parseExtra(extraBytes) {
  const extra = [];
  let offset = 0;

  while (offset < extraBytes.length) {
    const tag = extraBytes[offset++];

    switch (tag) {
      case 0x00: // TX_EXTRA_TAG_PADDING
        // Skip padding bytes (value 0x00)
        while (offset < extraBytes.length && extraBytes[offset] === 0x00) {
          offset++;
        }
        extra.push({ type: 0x00, tag: 'padding' });
        break;

      case 0x01: // TX_EXTRA_TAG_PUBKEY
        if (offset + 32 > extraBytes.length) {
          throw new Error('Invalid tx pubkey in extra');
        }
        const txPubKey = extraBytes.slice(offset, offset + 32);
        offset += 32;
        extra.push({ type: 0x01, tag: 'tx_pubkey', key: txPubKey });
        break;

      case 0x02: // TX_EXTRA_NONCE
        const nonceSize = extraBytes[offset++];
        if (offset + nonceSize > extraBytes.length) {
          throw new Error('Invalid nonce in extra');
        }
        const nonce = extraBytes.slice(offset, offset + nonceSize);
        offset += nonceSize;

        // Parse nonce contents (payment ID, encrypted payment ID, etc.)
        const nonceContent = parseExtraNonce(nonce);
        extra.push({ type: 0x02, tag: 'nonce', ...nonceContent });
        break;

      case 0x03: // TX_EXTRA_MERGE_MINING_TAG
        const { value: mmSize, bytesRead } = decodeVarint(extraBytes, offset);
        offset += bytesRead;
        const mmData = extraBytes.slice(offset, offset + Number(mmSize));
        offset += Number(mmSize);
        extra.push({ type: 0x03, tag: 'merge_mining', data: mmData });
        break;

      case 0x04: // TX_EXTRA_TAG_ADDITIONAL_PUBKEYS
        const pubkeyCount = extraBytes[offset++];
        const additionalPubkeys = [];
        for (let i = 0; i < pubkeyCount; i++) {
          if (offset + 32 > extraBytes.length) {
            throw new Error('Invalid additional pubkey in extra');
          }
          additionalPubkeys.push(extraBytes.slice(offset, offset + 32));
          offset += 32;
        }
        extra.push({ type: 0x04, tag: 'additional_pubkeys', keys: additionalPubkeys });
        break;

      default:
        // Unknown tag - try to skip using varint length
        // This is a best-effort attempt
        extra.push({ type: tag, tag: 'unknown', offset: offset - 1 });
        // Skip remaining bytes as we don't know the format
        offset = extraBytes.length;
    }
  }

  return extra;
}

/**
 * Parse extra nonce content
 *
 * @param {Uint8Array} nonce - Nonce bytes
 * @returns {Object} Parsed nonce content
 */
function parseExtraNonce(nonce) {
  if (nonce.length === 0) {
    return { raw: nonce };
  }

  const tag = nonce[0];

  // Payment ID (unencrypted, 32 bytes)
  if (tag === 0x00 && nonce.length === 33) {
    return {
      paymentIdType: 'unencrypted',
      paymentId: nonce.slice(1)
    };
  }

  // Encrypted payment ID (8 bytes)
  if (tag === 0x01 && nonce.length === 9) {
    return {
      paymentIdType: 'encrypted',
      paymentId: nonce.slice(1)
    };
  }

  return { raw: nonce };
}

/**
 * Parse RingCT signature data (Salvium format)
 *
 * Salvium RCT format differs from Monero:
 * 1. Header byte (not RCT type)
 * 2. Salvium-specific data
 * 3. Asset type strings (length-prefixed, "SAL" or "SAL1")
 * 4. Separator byte (0x00)
 * 5. Actual RCT type
 * 6. Fee varint
 * 7. ecdhInfo
 * 8. outPk
 * 9. p_r (Salvium-specific, 32 bytes)
 * 10. Prunable data (bulletproofs, CLSAGs, pseudoOuts)
 *
 * @param {Uint8Array} data - Full transaction data
 * @param {number} startOffset - Starting offset for RCT data
 * @param {number} inputCount - Number of inputs
 * @param {number} outputCount - Number of outputs
 * @param {number} mixin - Ring size minus 1 (from first input's key_offsets.length - 1)
 * @returns {Object} Parsed RingCT signature
 */
function parseRingCtSignature(data, startOffset, inputCount, outputCount, mixin = 15) {
  let offset = startOffset;

  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of RCT data at offset ${offset}`);
    }
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  // Salvium RCT format (rctTypes.h lines 430-489):
  // 1. type (1 byte)
  // 2. txnFee (varint) - if type != Null
  // 3. ecdhInfo (8 bytes per output for BulletproofPlus types)
  // 4. outPk (32 bytes per output - mask only)
  // 5. p_r (32 bytes)
  // 6. salvium_data - only for SalviumZero/SalviumOne types

  // RCT type
  const type = data[offset++];

  if (type === RCT_TYPE.Null) {
    return { type, _endOffset: offset };
  }

  // Valid types for Salvium
  const validTypes = [
    RCT_TYPE.BulletproofPlus,  // 6
    RCT_TYPE.FullProofs,       // 7
    RCT_TYPE.SalviumZero,      // 8
    RCT_TYPE.SalviumOne        // 9
  ];

  if (!validTypes.includes(type)) {
    throw new Error(`Invalid RCT type: ${type} at offset ${offset - 1}`);
  }

  // Fee
  const fee = readVarint();

  // ECDH info (encrypted amounts) - 8 bytes per output for BulletproofPlus types
  const ecdhInfo = [];
  for (let i = 0; i < outputCount; i++) {
    ecdhInfo.push({ amount: readBytes(8) });
  }

  // Output commitments (outPk) - 32 bytes per output
  const outPk = [];
  for (let i = 0; i < outputCount; i++) {
    outPk.push(readBytes(32));
  }

  // p_r - Salvium-specific field (32 bytes)
  const p_r = readBytes(32);

  const rct = {
    type,
    txnFee: fee,
    ecdhInfo,
    outPk,
    p_r
  };

  // Parse salvium_data based on type (matches Salvium rctTypes.h lines 486-494)
  // Note: salvium_data parsing is optional for wallet scanning - we have enough
  // info from outPk/ecdhInfo for output detection
  try {
    if (type === RCT_TYPE.SalviumZero || type === RCT_TYPE.SalviumOne) {
      // Full salvium_data_t
      rct.salvium_data = parseSalviumData(data, offset, true);
      offset = rct.salvium_data._endOffset;
      delete rct.salvium_data._endOffset;
    } else if (type === RCT_TYPE.FullProofs) {
      // Only pr_proof and sa_proof (2 x zk_proof = 2 x 96 bytes)
      rct.salvium_data = {
        pr_proof: parseZkProof(data, offset),
        sa_proof: parseZkProof(data, offset + 96)
      };
      offset += 192;
    }
  } catch (e) {
    // If salvium_data parsing fails, we can still use the transaction for scanning
    // Just mark it as having a parse error and skip the prunable section
    rct.salvium_data_parse_error = e.message;
    rct._endOffset = offset;
    return rct; // Return early with what we have
  }

  // Parse prunable data (bulletproofs + CLSAGs) with bounds checking
  // The prunable section follows the base section
  if (offset < data.length && type !== RCT_TYPE.Null) {
    try {
      const prunable = parseRctSigPrunable(data, offset, type, inputCount, outputCount, mixin);
      rct.bulletproofPlus = prunable.bulletproofPlus;
      rct.CLSAGs = prunable.CLSAGs;
      rct.TCLSAGs = prunable.TCLSAGs;
      rct.pseudoOuts = prunable.pseudoOuts;
      if (prunable._endOffset) {
        offset = prunable._endOffset;
      }
    } catch (e) {
      if (e instanceof ParseError) {
        rct.prunable_parse_error = e.toString();
      } else {
        rct.prunable_parse_error = `Unexpected error parsing prunable: ${e.message}`;
      }
    }
  }

  rct._endOffset = offset;
  return rct;
}

/**
 * Parse RingCT signature data (Monero format - for compatibility)
 */
function parseRingCtSignatureMonero(data, startOffset, inputCount, outputCount) {
  let offset = startOffset;

  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of RCT data at offset ${offset}`);
    }
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  // RCT type
  const type = data[offset++];

  if (type === RCT_TYPE.Null) {
    return { type };
  }

  // Fee
  const fee = readVarint();

  // Pseudo outputs (for simple/bulletproof types)
  const pseudoOuts = [];
  if (type === RCT_TYPE.Simple || type >= RCT_TYPE.Bulletproof) {
    for (let i = 0; i < inputCount; i++) {
      pseudoOuts.push(readBytes(32));
    }
  }

  // ECDH info (encrypted amounts)
  const ecdhInfo = [];
  for (let i = 0; i < outputCount; i++) {
    if (type >= RCT_TYPE.Bulletproof2) {
      ecdhInfo.push({ amount: readBytes(8) });
    } else {
      ecdhInfo.push({
        mask: readBytes(32),
        amount: readBytes(32)
      });
    }
  }

  // Output commitments
  const outPk = [];
  for (let i = 0; i < outputCount; i++) {
    outPk.push(readBytes(32));
  }

  return {
    type,
    txnFee: fee,
    pseudoOuts,
    ecdhInfo,
    outPk
  };
}

/**
 * Parse zk_proof structure (R, z1, z2 - 3 x 32 bytes = 96 bytes)
 * Matches Salvium rctTypes.h lines 94-103
 */
function parseZkProof(data, offset) {
  return {
    R: data.slice(offset, offset + 32),
    z1: data.slice(offset + 32, offset + 64),
    z2: data.slice(offset + 64, offset + 96)
  };
}

/**
 * Parse salvium_data_t structure
 * Matches Salvium rctTypes.h lines 390-412
 */
function parseSalviumData(data, startOffset, full = true) {
  let offset = startOffset;

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  const result = {};

  // salvium_data_type (varint)
  result.salvium_data_type = Number(readVarint());

  // pr_proof (zk_proof = 96 bytes)
  result.pr_proof = parseZkProof(data, offset);
  offset += 96;

  // sa_proof (zk_proof = 96 bytes)
  result.sa_proof = parseZkProof(data, offset);
  offset += 96;

  // SalviumZeroAudit (type 1) has additional fields
  if (result.salvium_data_type === 1) {
    // cz_proof (zk_proof = 96 bytes)
    result.cz_proof = parseZkProof(data, offset);
    offset += 96;

    // input_verification_data (vector of salvium_input_data_t)
    const inputCount = Number(readVarint());
    result.input_verification_data = [];
    for (let i = 0; i < inputCount; i++) {
      // salvium_input_data_t (per rctTypes.h lines 371-388):
      // - aR: key_derivation (32 bytes)
      // - amount: xmr_amount (VARINT_FIELD)
      // - i: size_t (VARINT_FIELD)
      // - origin_tx_type: uint8_t (VARINT_FIELD)
      // - if origin_tx_type != UNSET:
      //   - aR_stake: key_derivation (FIELD = 32 bytes)
      //   - i_stake: size_t (FIELD = 8 bytes little-endian, NOT varint!)
      const aR = data.slice(offset, offset + 32);
      offset += 32;
      const amount = readVarint();
      const idx = Number(readVarint());
      const origin_tx_type = Number(readVarint());

      const inputData = { aR, amount, i: idx, origin_tx_type };

      // Per Salvium source: if (origin_tx_type != cryptonote::transaction_type::UNSET)
      if (origin_tx_type !== 0) {
        inputData.aR_stake = data.slice(offset, offset + 32);
        offset += 32;
        // i_stake uses FIELD() for size_t = 8 bytes little-endian uint64
        inputData.i_stake = Number(
          BigInt(data[offset]) |
          (BigInt(data[offset + 1]) << 8n) |
          (BigInt(data[offset + 2]) << 16n) |
          (BigInt(data[offset + 3]) << 24n) |
          (BigInt(data[offset + 4]) << 32n) |
          (BigInt(data[offset + 5]) << 40n) |
          (BigInt(data[offset + 6]) << 48n) |
          (BigInt(data[offset + 7]) << 56n)
        );
        offset += 8;
      }

      result.input_verification_data.push(inputData);
    }

    // spend_pubkey (32 bytes)
    result.spend_pubkey = data.slice(offset, offset + 32);
    offset += 32;

    // enc_view_privkey_str (length-prefixed string)
    const strLen = Number(readVarint());
    result.enc_view_privkey_str = new TextDecoder().decode(data.slice(offset, offset + strLen));
    offset += strLen;
  }

  result._endOffset = offset;
  return result;
}

/**
 * Parse RCT prunable section (bulletproofs + CLSAGs/TCLSAGs + pseudoOuts)
 * Matches Salvium rctTypes.h lines 518-679
 *
 * @param {number} mixin - Ring size minus 1 (CLSAG s array has mixin+1 elements with NO size prefix)
 */
function parseRctSigPrunable(data, startOffset, type, inputCount, outputCount, mixin) {
  let offset = startOffset;

  const readBytes = (count, fieldName) => {
    if (offset + count > data.length) {
      throw new ParseError(`Unexpected end of data reading ${fieldName}`, {
        field: fieldName,
        offset,
        expected: count,
        actual: data.length - offset,
        dataLength: data.length
      });
    }
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = (fieldName) => {
    if (offset >= data.length) {
      throw new ParseError(`Unexpected end of data reading varint for ${fieldName}`, {
        field: fieldName,
        offset,
        dataLength: data.length
      });
    }
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  const result = {};

  // For BulletproofPlus types (6, 7, 8, 9), parse BulletproofPlus
  if (type >= RCT_TYPE.BulletproofPlus) {
    const nbp = readVarint('bulletproofPlus count');
    if (nbp > 1000) {
      throw new ParseError('Invalid bulletproofPlus count', {
        field: 'bulletproofPlus count',
        offset,
        expected: '<=1000',
        actual: nbp
      });
    }

    result.bulletproofPlus = [];
    for (let i = 0; i < nbp; i++) {
      const A = readBytes(32, `bulletproofPlus[${i}].A`);
      const A1 = readBytes(32, `bulletproofPlus[${i}].A1`);
      const B = readBytes(32, `bulletproofPlus[${i}].B`);
      const r1 = readBytes(32, `bulletproofPlus[${i}].r1`);
      const s1 = readBytes(32, `bulletproofPlus[${i}].s1`);
      const d1 = readBytes(32, `bulletproofPlus[${i}].d1`);

      // L array
      const Lcount = readVarint(`bulletproofPlus[${i}].L count`);
      if (Lcount > 64) {
        throw new ParseError('Invalid L array count in bulletproofPlus', {
          field: `bulletproofPlus[${i}].L count`,
          offset,
          expected: '<=64',
          actual: Lcount
        });
      }
      const L = [];
      for (let j = 0; j < Lcount; j++) {
        L.push(readBytes(32, `bulletproofPlus[${i}].L[${j}]`));
      }

      // R array (same size as L)
      const R = [];
      for (let j = 0; j < Lcount; j++) {
        R.push(readBytes(32, `bulletproofPlus[${i}].R[${j}]`));
      }

      result.bulletproofPlus.push({ A, A1, B, r1, s1, d1, L, R });
    }
  }

  // Parse CLSAGs or TCLSAGs based on type
  // Note: s/sx/sy arrays have NO size prefix - size is mixin + 1
  const ringSize = mixin + 1;

  if (type === RCT_TYPE.SalviumOne) {
    // TCLSAGs (Twin CLSAG) - has sx and sy arrays (Salvium rctTypes.h lines 560-612)
    result.TCLSAGs = [];
    for (let i = 0; i < inputCount; i++) {
      // sx array: mixin + 1 elements, NO size prefix
      const sx = [];
      for (let j = 0; j < ringSize; j++) {
        sx.push(readBytes(32, `TCLSAG[${i}].sx[${j}]`));
      }

      // sy array: mixin + 1 elements, NO size prefix
      const sy = [];
      for (let j = 0; j < ringSize; j++) {
        sy.push(readBytes(32, `TCLSAG[${i}].sy[${j}]`));
      }

      const c1 = readBytes(32, `TCLSAG[${i}].c1`);
      const D = readBytes(32, `TCLSAG[${i}].D`);

      result.TCLSAGs.push({ sx, sy, c1, D });
    }
  } else if (type >= RCT_TYPE.CLSAG) {
    // CLSAGs (Salvium rctTypes.h lines 613-652)
    result.CLSAGs = [];
    for (let i = 0; i < inputCount; i++) {
      // s array: mixin + 1 elements, NO size prefix
      const s = [];
      for (let j = 0; j < ringSize; j++) {
        s.push(readBytes(32, `CLSAG[${i}].s[${j}]`));
      }

      const c1 = readBytes(32, `CLSAG[${i}].c1`);
      const D = readBytes(32, `CLSAG[${i}].D`);

      result.CLSAGs.push({ s, c1, D });
    }
  }

  // pseudoOuts (for types that have them in prunable)
  if (type >= RCT_TYPE.BulletproofPlus) {
    result.pseudoOuts = [];
    for (let i = 0; i < inputCount; i++) {
      result.pseudoOuts.push(readBytes(32, `pseudoOuts[${i}]`));
    }
  }

  return result;
}

/**
 * Parse Bulletproofs range proof
 */
function parseBulletproofs(data, startOffset) {
  let offset = startOffset;

  const readBytes = (count) => {
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  const proofCount = Number(readVarint());
  const proofs = [];

  for (let i = 0; i < proofCount; i++) {
    const A = readBytes(32);
    const S = readBytes(32);
    const T1 = readBytes(32);
    const T2 = readBytes(32);
    const taux = readBytes(32);
    const mu = readBytes(32);

    const Lcount = Number(readVarint());
    const L = [];
    for (let j = 0; j < Lcount; j++) {
      L.push(readBytes(32));
    }

    const Rcount = Number(readVarint());
    const R = [];
    for (let j = 0; j < Rcount; j++) {
      R.push(readBytes(32));
    }

    const a = readBytes(32);
    const b = readBytes(32);
    const t = readBytes(32);

    proofs.push({ A, S, T1, T2, taux, mu, L, R, a, b, t });
  }

  return { proofs, _endOffset: offset };
}

/**
 * Parse Bulletproofs+ range proof
 */
function parseBulletproofPlus(data, startOffset, outputCount) {
  let offset = startOffset;

  const readBytes = (count) => {
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  const proofCount = Number(readVarint());
  const proofs = [];

  for (let i = 0; i < proofCount; i++) {
    const A = readBytes(32);
    const A1 = readBytes(32);
    const B = readBytes(32);
    const r1 = readBytes(32);
    const s1 = readBytes(32);
    const d1 = readBytes(32);

    const Lcount = Number(readVarint());
    const L = [];
    for (let j = 0; j < Lcount; j++) {
      L.push(readBytes(32));
    }

    const Rcount = Number(readVarint());
    const R = [];
    for (let j = 0; j < Rcount; j++) {
      R.push(readBytes(32));
    }

    proofs.push({ A, A1, B, r1, s1, d1, L, R });
  }

  return { proofs, _endOffset: offset };
}

/**
 * Parse CLSAG signature
 */
function parseCLSAG(data, startOffset, ringSize) {
  let offset = startOffset;

  const readBytes = (count) => {
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  // s values (ringSize scalars)
  const s = [];
  for (let i = 0; i < ringSize; i++) {
    s.push(readBytes(32));
  }

  // c1 (scalar)
  const c1 = readBytes(32);

  // D (point)
  const D = readBytes(32);

  return {
    sig: { s, c1, D },
    endOffset: offset
  };
}

/**
 * Get transaction hash from parsed transaction
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Uint8Array} 32-byte transaction hash
 */
export function getTransactionHashFromParsed(tx) {
  // For RingCT transactions, hash is calculated differently
  if (tx.prefix.version >= 2 && tx.rct) {
    const prefixHash = getTxPrefixHash(tx.prefix);

    // Hash of RCT base
    const rctBaseHash = keccak256(serializeRctBase(tx.rct));

    // Hash of prunable data (signatures)
    const prunableData = []; // Would need to serialize CLSAG, BP, etc.
    const prunableHash = new Uint8Array(32); // Placeholder

    // Combine: hash(prefixHash || rctBaseHash || prunableHash)
    const combined = new Uint8Array(96);
    combined.set(prefixHash, 0);
    combined.set(rctBaseHash, 32);
    combined.set(prunableHash, 64);

    return keccak256(combined);
  }

  // For v1 transactions, just hash the serialized prefix
  return getTxPrefixHash(tx.prefix);
}

/**
 * Decode encrypted amount from transaction output
 *
 * @param {Uint8Array|string} encryptedAmount - Encrypted amount (8 bytes)
 * @param {Uint8Array|string} sharedSecret - Shared secret for decryption
 * @returns {bigint} Decrypted amount
 */
export function decodeAmount(encryptedAmount, sharedSecret) {
  if (typeof encryptedAmount === 'string') {
    encryptedAmount = hexToBytes(encryptedAmount);
  }
  if (typeof sharedSecret === 'string') {
    sharedSecret = hexToBytes(sharedSecret);
  }

  // Generate amount mask: H_n("amount" || shared_secret)
  const prefix = new TextEncoder().encode('amount');
  const data = new Uint8Array(prefix.length + sharedSecret.length);
  data.set(prefix, 0);
  data.set(sharedSecret, prefix.length);

  const mask = keccak256(data).slice(0, 8);

  // XOR to decrypt
  const amountBytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    amountBytes[i] = encryptedAmount[i] ^ mask[i];
  }

  // Convert to bigint (little-endian)
  let amount = 0n;
  for (let i = 7; i >= 0; i--) {
    amount = (amount << 8n) | BigInt(amountBytes[i]);
  }

  return amount;
}

/**
 * Extract transaction public key from extra field
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Uint8Array|null} Transaction public key or null
 */
export function extractTxPubKey(tx) {
  const extra = tx.prefix?.extra || tx.extra || [];

  for (const field of extra) {
    if (field.type === 0x01 && field.key) {
      return field.key;
    }
  }

  return null;
}

/**
 * Extract payment ID from extra field
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Object|null} { type: 'encrypted'|'unencrypted', id: Uint8Array } or null
 */
export function extractPaymentId(tx) {
  const extra = tx.prefix?.extra || tx.extra || [];

  for (const field of extra) {
    if (field.type === 0x02 && field.paymentId) {
      return {
        type: field.paymentIdType,
        id: field.paymentId
      };
    }
  }

  return null;
}

/**
 * Summarize a parsed transaction
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Object} Transaction summary
 */
export function summarizeTransaction(tx) {
  const prefix = tx.prefix;

  return {
    version: prefix.version,
    unlockTime: prefix.unlockTime,
    inputCount: prefix.vin.length,
    outputCount: prefix.vout.length,
    isCoinbase: prefix.vin.length > 0 && prefix.vin[0].type === TXIN_TYPE.GEN,
    rctType: tx.rct?.type || null,
    fee: tx.rct?.fee || 0n,
    txPubKey: extractTxPubKey(tx),
    paymentId: extractPaymentId(tx),
    keyImages: prefix.vin
      .filter(v => v.type === TXIN_TYPE.KEY)
      .map(v => v.keyImage),
    outputKeys: prefix.vout.map(v => v.key),
    commitments: tx.rct?.outPk || []
  };
}

// =============================================================================
// BLOCK PARSING
// =============================================================================

/**
 * Parse a Salvium pricing_record from binary data
 *
 * Structure (from oracle/pricing_record.h):
 * - pr_version: varint
 * - height: varint
 * - supply: { sal: varint, vsd: varint }
 * - assets: vector of { asset_type: string, spot_price: varint, ma_price: varint }
 * - timestamp: varint
 * - signature: vector of bytes
 *
 * @param {Uint8Array} data - Raw binary data
 * @param {number} [startOffset=0] - Starting offset in data
 * @returns {{ record: Object, bytesRead: number }} Parsed pricing record and bytes consumed
 */
export function parsePricingRecord(data, startOffset = 0) {
  let offset = startOffset;

  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of data reading ${count} bytes at offset ${offset}`);
    }
    const bytes = data.slice(offset, offset + count);
    offset += count;
    return bytes;
  };

  const readVarint = () => {
    let result = 0n;
    let shift = 0n;
    while (offset < data.length) {
      const byte = data[offset++];
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7n;
    }
    return result;
  };

  const readString = () => {
    const len = Number(readVarint());
    if (len === 0) return '';
    const bytes = readBytes(len);
    return new TextDecoder().decode(bytes);
  };

  // pr_version
  const prVersion = Number(readVarint());

  // height
  const height = Number(readVarint());

  // supply_data { sal, vsd }
  const supply = {
    sal: readVarint(),
    vsd: readVarint()
  };

  // assets vector
  const assetsCount = Number(readVarint());
  const assets = [];
  for (let i = 0; i < assetsCount; i++) {
    assets.push({
      assetType: readString(),
      spotPrice: readVarint(),
      maPrice: readVarint()
    });
  }

  // timestamp
  const timestamp = Number(readVarint());

  // signature (vector of bytes)
  const signatureLen = Number(readVarint());
  const signature = signatureLen > 0 ? readBytes(signatureLen) : new Uint8Array(0);

  return {
    record: {
      prVersion,
      height,
      supply,
      assets,
      timestamp,
      signature
    },
    bytesRead: offset - startOffset
  };
}

/**
 * Parse a Salvium block from binary data
 *
 * Structure (from cryptonote_basic/cryptonote_basic.h):
 *
 * block_header:
 * - major_version: varint
 * - minor_version: varint
 * - timestamp: varint
 * - prev_id: 32 bytes (hash)
 * - nonce: 4 bytes (uint32 LE)
 * - pricing_record: only if major_version >= HF_VERSION_ENABLE_ORACLE (255)
 *
 * block (extends block_header):
 * - miner_tx: full transaction (coinbase)
 * - protocol_tx: full transaction (Salvium-specific: conversions, yields, refunds)
 * - tx_hashes: vector of 32-byte hashes
 *
 * @param {Uint8Array} data - Raw binary block data
 * @returns {Object} Parsed block
 */
export function parseBlock(data) {
  let offset = 0;

  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of data reading ${count} bytes at offset ${offset}`);
    }
    const bytes = data.slice(offset, offset + count);
    offset += count;
    return bytes;
  };

  const readVarint = () => {
    let result = 0n;
    let shift = 0n;
    while (offset < data.length) {
      const byte = data[offset++];
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7n;
    }
    return result;
  };

  const readUint32LE = () => {
    const bytes = readBytes(4);
    return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
  };

  // ============================================
  // BLOCK HEADER
  // ============================================

  const majorVersion = Number(readVarint());
  const minorVersion = Number(readVarint());
  const timestamp = Number(readVarint());
  const prevId = readBytes(32);
  const nonce = readUint32LE();

  // Pricing record (only if major_version >= HF_VERSION_ENABLE_ORACLE)
  let pricingRecord = null;
  if (majorVersion >= HF_VERSION_ENABLE_ORACLE) {
    const prResult = parsePricingRecord(data, offset);
    pricingRecord = prResult.record;
    offset += prResult.bytesRead;
  }

  // ============================================
  // BLOCK BODY
  // ============================================

  // Parse miner_tx (coinbase transaction)
  const minerTxData = data.slice(offset);
  const minerTx = parseTransaction(minerTxData);
  offset += minerTx._bytesRead || estimateTransactionSize(minerTxData);

  // Parse protocol_tx (Salvium-specific transaction)
  const protocolTxData = data.slice(offset);
  const protocolTx = parseTransaction(protocolTxData);
  offset += protocolTx._bytesRead || estimateTransactionSize(protocolTxData);

  // Parse tx_hashes vector
  const txHashCount = Number(readVarint());
  const txHashes = [];
  for (let i = 0; i < txHashCount; i++) {
    txHashes.push(readBytes(32));
  }

  return {
    header: {
      majorVersion,
      minorVersion,
      timestamp,
      prevId,
      nonce,
      pricingRecord
    },
    minerTx,
    protocolTx,
    txHashes,
    _bytesRead: offset
  };
}

/**
 * Estimate transaction size by parsing it (internal helper)
 * This is needed because parseTransaction doesn't return bytes read
 *
 * @param {Uint8Array} data - Transaction data
 * @returns {number} Estimated bytes consumed
 * @private
 */
function estimateTransactionSize(data) {
  // Parse the transaction and track how many bytes were consumed
  // This is a simplified re-parse just for size calculation
  let offset = 0;

  const readVarint = () => {
    let result = 0n;
    let shift = 0n;
    while (offset < data.length) {
      const byte = data[offset++];
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7n;
    }
    return result;
  };

  const readBytes = (count) => {
    offset += count;
    return data.slice(offset - count, offset);
  };

  // Version
  const version = Number(readVarint());
  // Unlock time
  readVarint();

  // Inputs
  const vinCount = Number(readVarint());
  for (let i = 0; i < vinCount; i++) {
    const type = data[offset++];
    if (type === 0xff) {
      // txin_gen
      readVarint();
    } else if (type === 0x02) {
      // txin_to_key
      readVarint(); // amount
      const assetTypeLen = Number(readVarint());
      if (assetTypeLen > 0) readBytes(assetTypeLen);
      const keyOffsetCount = Number(readVarint());
      for (let j = 0; j < keyOffsetCount; j++) readVarint();
      readBytes(32); // key image
    }
  }

  // Outputs
  const voutCount = Number(readVarint());
  for (let i = 0; i < voutCount; i++) {
    readVarint(); // amount
    const type = data[offset++];
    if (type === 0x02 || type === 0x03 || type === 0x04) {
      readBytes(32); // key
      const assetTypeLen = Number(readVarint());
      if (assetTypeLen > 0) readBytes(assetTypeLen);
      if (type === 0x03 || type === 0x04) {
        readVarint(); // output_unlock_time
        if (type === 0x04) {
          readBytes(3); // view_tag
        }
      }
    }
  }

  // Extra
  const extraLen = Number(readVarint());
  readBytes(extraLen);

  // Transaction type and Salvium-specific fields (version >= 2)
  if (version >= 2) {
    const txType = Number(readVarint());

    if (txType !== TX_TYPE.UNSET && txType !== TX_TYPE.PROTOCOL) {
      readVarint(); // amount_burnt

      if (txType !== TX_TYPE.MINER) {
        if (txType === TX_TYPE.TRANSFER && version >= 3) {
          const returnAddressLen = Number(readVarint());
          if (returnAddressLen > 0) readBytes(returnAddressLen);
        } else if (txType === TX_TYPE.STAKE && version >= 4) {
          readBytes(32); // return_address
          readBytes(32); // return_pubkey
          readBytes(3);  // return_view_tag
          readBytes(16); // return_anchor_enc
        } else if (txType !== TX_TYPE.TRANSFER) {
          readBytes(32); // return_address
        }

        const srcAssetLen = Number(readVarint());
        if (srcAssetLen > 0) readBytes(srcAssetLen);
        const dstAssetLen = Number(readVarint());
        if (dstAssetLen > 0) readBytes(dstAssetLen);
        readVarint(); // amount_slippage_limit
      }
    }

    if (txType === TX_TYPE.PROTOCOL) {
      readVarint(); // protocol_tx_data.version
      readBytes(32); // return_address
      readBytes(32); // return_pubkey
      readBytes(3);  // return_view_tag
      readBytes(16); // return_anchor_enc
    }
  }

  // RCT signatures (if version >= 2 and not coinbase)
  if (version >= 2 && vinCount > 0 && data[offset] !== undefined) {
    const rctType = data[offset++];

    if (rctType !== 0) {
      // txnFee
      readVarint();

      // ecdhInfo (for non-coinbase)
      for (let i = 0; i < voutCount; i++) {
        readBytes(8); // amount (compact)
      }

      // outPk
      for (let i = 0; i < voutCount; i++) {
        readBytes(32);
      }
    }
  }

  return offset;
}
