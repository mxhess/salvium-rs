/**
 * Bulletproofs+ Range Proof Generation & Verification
 *
 * Delegates all cryptographic operations to the Rust backend (WASM/FFI/JSI).
 * Provides parseProof/serializeProof for binary (de)serialization.
 *
 * Reference: https://eprint.iacr.org/2020/735.pdf
 */

import { getCryptoBackend } from './crypto/index.js';

// Fixed H constant from Monero/Salvium (toPoint(cn_fast_hash(G)))
const H_BYTES = new Uint8Array([
  0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
  0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
  0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
  0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
]);

// Number of bits in range proof
const N = 64;
// Maximum aggregation (16 outputs)
const MAX_M = 16;
const MAX_N = N;

// ============================================================
// Binary Serialization / Deserialization
// ============================================================

function _decodeVarint(bytes, offset) {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;
  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    bytesRead++;
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return { value, bytesRead };
}

function _encodeVarint(value) {
  const bytes = [];
  let v = value;
  while (v >= 0x80) {
    bytes.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  bytes.push(v);
  return new Uint8Array(bytes);
}

/**
 * Parse a Bulletproof+ proof from bytes.
 * Returns raw 32-byte Uint8Arrays for all fields.
 *
 * Wire format: A(32) A1(32) B(32) r1(32) s1(32) d1(32) varint(L.len) L[](32 each) varint(R.len) R[](32 each)
 * Note: V (commitments) is NOT in the wire format — restored from outPk.
 */
export function parseProof(proofBytes) {
  if (proofBytes.length < 32 * 6) {
    throw new Error('Proof too short');
  }

  let offset = 0;

  // A, A1, B (32-byte compressed points)
  const A = proofBytes.slice(offset, offset + 32); offset += 32;
  const A1 = proofBytes.slice(offset, offset + 32); offset += 32;
  const B = proofBytes.slice(offset, offset + 32); offset += 32;

  // r1, s1, d1 (32-byte scalars)
  const r1 = proofBytes.slice(offset, offset + 32); offset += 32;
  const s1 = proofBytes.slice(offset, offset + 32); offset += 32;
  const d1 = proofBytes.slice(offset, offset + 32); offset += 32;

  // L
  const { value: lCount, bytesRead: lBytes } = _decodeVarint(proofBytes, offset);
  offset += lBytes;
  const L = [];
  for (let i = 0; i < lCount; i++) {
    L.push(proofBytes.slice(offset, offset + 32));
    offset += 32;
  }

  // R
  const { value: rCount, bytesRead: rBytes } = _decodeVarint(proofBytes, offset);
  offset += rBytes;
  const R = [];
  for (let i = 0; i < rCount; i++) {
    R.push(proofBytes.slice(offset, offset + 32));
    offset += 32;
  }

  return { A, A1, B, r1, s1, d1, L, R };
}

/**
 * Serialize a Bulletproof+ proof to bytes.
 */
export function serializeProof(proof) {
  // Short-circuit: WASM/JSI backend already provides serialized bytes
  if (proof.proofBytes) return proof.proofBytes;

  const { A, A1, B, r1, s1, d1, L, R } = proof;

  // Convert to bytes if needed (handles both raw Uint8Array and legacy Point objects)
  const toBytes = (v) => v instanceof Uint8Array ? v : v.toBytes();
  const scalarBytes = (s) => {
    if (s instanceof Uint8Array) return s;
    // BigInt to 32-byte LE
    const bytes = new Uint8Array(32);
    let val = s;
    for (let i = 0; i < 32; i++) {
      bytes[i] = Number(val & 0xffn);
      val >>= 8n;
    }
    return bytes;
  };

  const chunks = [];

  // A, A1, B (points)
  chunks.push(toBytes(A));
  chunks.push(toBytes(A1));
  chunks.push(toBytes(B));

  // r1, s1, d1 (scalars)
  chunks.push(scalarBytes(r1));
  chunks.push(scalarBytes(s1));
  chunks.push(scalarBytes(d1));

  // L
  chunks.push(_encodeVarint(L.length));
  for (const l of L) chunks.push(toBytes(l));

  // R
  chunks.push(_encodeVarint(R.length));
  for (const r of R) chunks.push(toBytes(r));

  // Concatenate
  let totalLen = 0;
  for (const c of chunks) totalLen += c.length;
  const bytes = new Uint8Array(totalLen);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.length;
  }
  return bytes;
}

// ============================================================
// Range Proof Verification (Rust backend)
// ============================================================

/**
 * Verify a range proof from raw bytes.
 * Delegates to Rust backend (WASM/FFI/JSI).
 *
 * @param {Uint8Array[]} commitmentBytes - Array of 32-byte commitment encodings
 * @param {Uint8Array} proofBytes - Serialized proof
 * @returns {boolean} True if proof is valid
 */
export function verifyRangeProof(commitmentBytes, proofBytes) {
  return getCryptoBackend().bulletproofPlusVerify(commitmentBytes, proofBytes);
}

/**
 * Verify a single Bulletproof+ range proof (convenience wrapper).
 *
 * @param {Uint8Array[]} V - Commitment byte arrays (32 bytes each)
 * @param {Object} proof - Parsed proof object
 * @returns {boolean} True if proof is valid
 */
export function verifyBulletproofPlus(V, proof) {
  const commitmentBytes = V.map(v => v instanceof Uint8Array ? v : v.toBytes());
  const proofBytes = serializeProof(proof);
  return verifyRangeProof(commitmentBytes, proofBytes);
}

// ============================================================
// Range Proof Generation (Rust backend)
// ============================================================

/**
 * Generate a Bulletproof+ range proof.
 * Delegates to Rust backend (WASM/FFI/JSI).
 *
 * @param {BigInt[]} amounts - Array of amounts to prove (each < 2^64)
 * @param {BigInt[]|Uint8Array[]} masks - Array of blinding factors
 * @returns {Object} Proof object { V, proofBytes, A, A1, B, r1, s1, d1, L, R }
 */
export function bulletproofPlusProve(amounts, masks) {
  if (amounts.length === 0 || amounts.length !== masks.length) {
    throw new Error('Invalid input: amounts and masks must have equal non-zero length');
  }

  if (amounts.length > MAX_M) {
    throw new Error(`Too many amounts: ${amounts.length} > ${MAX_M}`);
  }

  const result = getCryptoBackend().bulletproofPlusProve(amounts, masks);

  // Expand proofBytes into individual fields for consumers that need them
  if (result.proofBytes && !result.A) {
    const parsed = parseProof(result.proofBytes);
    return { V: result.V, ...parsed, proofBytes: result.proofBytes };
  }
  return result;
}

/**
 * Create a range proof for a single amount.
 */
export function proveRange(amount, mask) {
  return bulletproofPlusProve([amount], [mask]);
}

/**
 * Create a range proof for multiple amounts (aggregated).
 */
export function proveRangeMultiple(amounts, masks) {
  return bulletproofPlusProve(amounts, masks);
}

export { H_BYTES, N, MAX_M, MAX_N };
