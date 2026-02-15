/**
 * Transaction Scanning Module
 *
 * Implements output detection and amount decryption for Salvium transactions.
 * Supports both CryptoNote (legacy) and CARROT protocols.
 *
 * Key functions:
 * - generateKeyDerivation: compute shared secret D = 8 * viewSecret * txPubKey
 * - derivationToScalar: H_s(D || varint(output_index))
 * - derivePublicKey: compute expected output pubkey P' = B + scalar*G
 * - deriveSecretKey: compute output secret s' = b + scalar
 * - deriveSubaddressPublicKey: for subaddress detection P' = Ko - scalar*G
 * - deriveViewTag: 1-byte filter for fast scanning
 * - ecdhDecode: decrypt RingCT amount
 */

import { keccak256 } from './keccak.js';
import { hexToBytes, bytesToHex } from './address.js';
import {
  scalarMultBase,
  scalarMultPoint,
  pointAddCompressed,
  scReduce32, scAdd as scalarAddBackend,
  generateKeyDerivation as _generateKeyDerivation
} from './crypto/index.js';

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Encode a number as varint (variable-length integer)
 * Used in CryptoNote for output indices
 * @param {number} n - Number to encode
 * @returns {Uint8Array} Varint bytes
 */
function encodeVarint(n) {
  const bytes = [];
  while (n >= 0x80) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n);
  return new Uint8Array(bytes);
}

// scReduce32 and scalarAdd delegated to Rust backend via crypto/index.js
function scalarAdd(a, b) { return scalarAddBackend(a, b); }

/**
 * XOR two byte arrays of equal length
 * @param {Uint8Array} a - First array
 * @param {Uint8Array} b - Second array
 * @returns {Uint8Array} XOR result
 */
function xorBytes(a, b) {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

// ============================================================================
// Key Derivation (CryptoNote)
// ============================================================================

/**
 * Generate key derivation (shared secret)
 * D = 8 * viewSecretKey * txPubKey (cofactor multiplication)
 *
 * This is the first step in output detection. The sender computes
 * D using their random tx secret key (r) and recipient's view public key.
 * The recipient can compute the same D using their view secret key
 * and the tx public key (R = r*G).
 *
 * @param {Uint8Array|string} txPubKey - 32-byte transaction public key
 * @param {Uint8Array|string} viewSecretKey - 32-byte view secret key
 * @returns {Uint8Array|null} 32-byte key derivation, or null if invalid
 */
export function generateKeyDerivation(txPubKey, viewSecretKey) {
  if (typeof txPubKey === 'string') txPubKey = hexToBytes(txPubKey);
  if (typeof viewSecretKey === 'string') viewSecretKey = hexToBytes(viewSecretKey);

  // Delegate to Rust backend: computes 8 * viewSecretKey * txPubKey in a single call
  return _generateKeyDerivation(txPubKey, viewSecretKey);
}

/**
 * Convert key derivation + output index to scalar
 * scalar = H_s(derivation || varint(output_index))
 *
 * This produces the per-output blinding factor used to derive
 * the one-time stealth address.
 *
 * @param {Uint8Array|string} derivation - 32-byte key derivation
 * @param {number} outputIndex - Output index in the transaction
 * @returns {Uint8Array} 32-byte scalar
 */
export function derivationToScalar(derivation, outputIndex) {
  if (typeof derivation === 'string') {
    derivation = hexToBytes(derivation);
  }

  // Concatenate derivation + varint(output_index)
  const indexBytes = encodeVarint(outputIndex);
  const input = new Uint8Array(derivation.length + indexBytes.length);
  input.set(derivation);
  input.set(indexBytes, derivation.length);

  // Hash with Keccak256 and reduce to scalar
  const hash = keccak256(input);
  return scReduce32(hash);
}

/**
 * Derive output public key (stealth address)
 * P' = base + H_s(derivation, output_index) * G
 *
 * The recipient computes this using their spend public key as base.
 * If P' matches the actual output key in the transaction, the output
 * belongs to them.
 *
 * @param {Uint8Array|string} derivation - 32-byte key derivation
 * @param {number} outputIndex - Output index
 * @param {Uint8Array|string} baseSpendPubKey - 32-byte spend public key
 * @returns {Uint8Array|null} 32-byte derived public key, or null if invalid
 */
export function derivePublicKey(derivation, outputIndex, baseSpendPubKey) {
  if (typeof derivation === 'string') {
    derivation = hexToBytes(derivation);
  }
  if (typeof baseSpendPubKey === 'string') {
    baseSpendPubKey = hexToBytes(baseSpendPubKey);
  }

  // scalar = H_s(derivation || output_index)
  const scalar = derivationToScalar(derivation, outputIndex);

  // scalar * G
  const scalarG = scalarMultBase(scalar);

  // P' = base + scalar*G
  const result = pointAddCompressed(baseSpendPubKey, scalarG);
  return result;
}

/**
 * Derive output secret key (for spending)
 * s' = base + H_s(derivation, output_index)
 *
 * Used by the wallet owner to derive the private key for an owned output,
 * which is needed to spend it (generate key image, create signature).
 *
 * @param {Uint8Array|string} derivation - 32-byte key derivation
 * @param {number} outputIndex - Output index
 * @param {Uint8Array|string} baseSpendSecKey - 32-byte spend secret key
 * @returns {Uint8Array} 32-byte derived secret key
 */
export function deriveSecretKey(derivation, outputIndex, baseSpendSecKey) {
  if (typeof derivation === 'string') {
    derivation = hexToBytes(derivation);
  }
  if (typeof baseSpendSecKey === 'string') {
    baseSpendSecKey = hexToBytes(baseSpendSecKey);
  }

  // scalar = H_s(derivation || output_index)
  const scalar = derivationToScalar(derivation, outputIndex);

  // s' = base + scalar
  return scalarAdd(baseSpendSecKey, scalar);
}

/**
 * Derive subaddress public key (for subaddress detection)
 * P' = outputKey - H_s(derivation, output_index) * G
 *
 * Used when scanning for outputs to subaddresses. The result is compared
 * against all known subaddress spend public keys to detect ownership.
 *
 * @param {Uint8Array|string} outputKey - 32-byte output public key from transaction
 * @param {Uint8Array|string} derivation - 32-byte key derivation
 * @param {number} outputIndex - Output index
 * @returns {Uint8Array|null} 32-byte derived public key, or null if invalid
 */
export function deriveSubaddressPublicKey(outputKey, derivation, outputIndex) {
  if (typeof outputKey === 'string') {
    outputKey = hexToBytes(outputKey);
  }
  if (typeof derivation === 'string') {
    derivation = hexToBytes(derivation);
  }

  // Validate inputs
  if (!outputKey || !(outputKey instanceof Uint8Array)) {
    throw new Error('deriveSubaddressPublicKey: outputKey must be a Uint8Array');
  }
  if (outputKey.length !== 32) {
    throw new Error(`deriveSubaddressPublicKey: outputKey must be 32 bytes, got ${outputKey.length}`);
  }
  if (!derivation || !(derivation instanceof Uint8Array)) {
    throw new Error('deriveSubaddressPublicKey: derivation must be a Uint8Array');
  }
  if (derivation.length !== 32) {
    throw new Error(`deriveSubaddressPublicKey: derivation must be 32 bytes, got ${derivation.length}`);
  }

  // scalar = H_s(derivation || output_index)
  const scalar = derivationToScalar(derivation, outputIndex);
  if (!scalar) {
    throw new Error('deriveSubaddressPublicKey: derivationToScalar failed');
  }

  // scalar * G
  const scalarG = scalarMultBase(scalar);
  if (!scalarG || scalarG.length !== 32) {
    throw new Error('deriveSubaddressPublicKey: scalarMultBase failed');
  }

  // Negate the point (subtract instead of add)
  // In Ed25519, negating a point means negating the x-coordinate
  // For compressed points, flip the sign bit (bit 255)
  const scalarGNeg = new Uint8Array(scalarG);
  scalarGNeg[31] ^= 0x80; // Flip sign bit

  // P' = outputKey - scalar*G = outputKey + (-scalar*G)
  const result = pointAddCompressed(outputKey, scalarGNeg);
  return result;
}

// ============================================================================
// View Tag (Optimization)
// ============================================================================

/**
 * Derive view tag for fast output filtering
 * view_tag = first byte of H("view_tag" || derivation || varint(output_index))
 *
 * View tags allow wallets to quickly filter out non-owned outputs
 * without performing the full stealth address derivation.
 *
 * Matches Salvium C++ crypto_ops::derive_view_tag in crypto.cpp
 *
 * @param {Uint8Array|string} derivation - 32-byte key derivation
 * @param {number} outputIndex - Output index
 * @returns {number} Single byte view tag (0-255)
 */
export function deriveViewTag(derivation, outputIndex) {
  if (typeof derivation === 'string') {
    derivation = hexToBytes(derivation);
  }

  // Salvium uses "view_tag" (8 bytes) as salt prefix
  const salt = new TextEncoder().encode('view_tag'); // 8 bytes
  const indexBytes = encodeVarint(outputIndex);

  // Build: salt || derivation || varint(output_index)
  const input = new Uint8Array(salt.length + derivation.length + indexBytes.length);
  input.set(salt);
  input.set(derivation, salt.length);
  input.set(indexBytes, salt.length + derivation.length);

  const hash = keccak256(input);

  // View tag is the first byte
  return hash[0];
}

// ============================================================================
// Amount Decryption (RingCT)
// ============================================================================

/**
 * Generate amount encoding factor
 * H("amount" || shared_secret)
 *
 * Used for encrypting/decrypting the amount in RingCT transactions.
 *
 * @param {Uint8Array} sharedSecret - 32-byte shared secret (derivation)
 * @returns {Uint8Array} 32-byte encoding factor (first 8 bytes used for amount)
 */
function genAmountEncodingFactor(sharedSecret) {
  // "amount" prefix (6 bytes) + shared secret (32 bytes)
  const prefix = new TextEncoder().encode('amount');
  const input = new Uint8Array(prefix.length + sharedSecret.length);
  input.set(prefix);
  input.set(sharedSecret, prefix.length);

  return keccak256(input);
}

/**
 * Generate commitment mask
 * H("commitment_mask" || shared_secret)
 *
 * Used to blind the Pedersen commitment to the amount.
 *
 * @param {Uint8Array} sharedSecret - 32-byte shared secret
 * @returns {Uint8Array} 32-byte commitment mask (reduced to scalar)
 */
function genCommitmentMask(sharedSecret) {
  const prefix = new TextEncoder().encode('commitment_mask');
  const input = new Uint8Array(prefix.length + sharedSecret.length);
  input.set(prefix);
  input.set(sharedSecret, prefix.length);

  const hash = keccak256(input);
  return scReduce32(hash);
}

/**
 * Compute shared secret for output (used for ECDH amount encoding/decoding)
 *
 * This is equivalent to Salvium's derivation_to_scalar, which computes:
 * hash_to_scalar(derivation || varint(output_index))
 *
 * Matches Salvium C++ crypto_ops::derivation_to_scalar in crypto.cpp
 *
 * @param {Uint8Array|string} derivation - 32-byte key derivation
 * @param {number} outputIndex - Output index
 * @returns {Uint8Array} 32-byte scalar (reduced mod L)
 */
export function computeSharedSecret(derivation, outputIndex) {
  // Salvium uses derivation_to_scalar which calls hash_to_scalar
  // This hashes and then reduces mod L (curve order)
  return derivationToScalar(derivation, outputIndex);
}

/**
 * Decode encrypted amount (ECDH decode for RingCT v2/Bulletproof+)
 *
 * In RingCT v2 and later (Bulletproofs), amounts are encrypted as:
 * encrypted_amount = amount XOR H("amount" || shared_secret)[0:8]
 *
 * @param {Uint8Array} encryptedAmount - 8-byte encrypted amount
 * @param {Uint8Array|string} sharedSecret - 32-byte shared secret
 * @returns {bigint} Decrypted amount in atomic units
 */
export function ecdhDecode(encryptedAmount, sharedSecret) {
  if (typeof sharedSecret === 'string') {
    sharedSecret = hexToBytes(sharedSecret);
  }

  // Generate amount encoding factor
  const encodingFactor = genAmountEncodingFactor(sharedSecret);

  // XOR first 8 bytes to decrypt
  const decrypted = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    decrypted[i] = encryptedAmount[i] ^ encodingFactor[i];
  }

  // Convert little-endian bytes to amount (bigint)
  let amount = 0n;
  for (let i = 7; i >= 0; i--) {
    amount = (amount << 8n) | BigInt(decrypted[i]);
  }

  return amount;
}

/**
 * Full ECDH decode for RingCT (returns both amount and mask)
 *
 * @param {Uint8Array} encryptedAmount - 8-byte encrypted amount
 * @param {Uint8Array|string} sharedSecret - 32-byte shared secret
 * @returns {Object} { amount: bigint, mask: Uint8Array }
 */
export function ecdhDecodeFull(encryptedAmount, sharedSecret) {
  if (typeof sharedSecret === 'string') {
    sharedSecret = hexToBytes(sharedSecret);
  }

  const amount = ecdhDecode(encryptedAmount, sharedSecret);
  const mask = genCommitmentMask(sharedSecret);

  return { amount, mask };
}

/**
 * Encode amount for transmission (ECDH encode)
 *
 * @param {bigint} amount - Amount in atomic units
 * @param {Uint8Array|string} sharedSecret - 32-byte shared secret
 * @returns {Uint8Array} 8-byte encrypted amount
 */
export function ecdhEncode(amount, sharedSecret) {
  if (typeof sharedSecret === 'string') {
    sharedSecret = hexToBytes(sharedSecret);
  }

  // Convert amount to little-endian bytes
  const amountBytes = new Uint8Array(8);
  let a = amount;
  for (let i = 0; i < 8; i++) {
    amountBytes[i] = Number(a & 0xffn);
    a = a >> 8n;
  }

  // Generate amount encoding factor
  const encodingFactor = genAmountEncodingFactor(sharedSecret);

  // XOR first 8 bytes to encrypt
  const encrypted = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    encrypted[i] = amountBytes[i] ^ encodingFactor[i];
  }

  return encrypted;
}

// ============================================================================
// Output Ownership Check
// ============================================================================

/**
 * Check if an output belongs to a wallet
 *
 * @param {Uint8Array|string} outputPubKey - Output public key from transaction
 * @param {Uint8Array|string} txPubKey - Transaction public key
 * @param {Uint8Array|string} viewSecretKey - Wallet's view secret key
 * @param {Uint8Array|string} spendPubKey - Wallet's spend public key
 * @param {number} outputIndex - Output index in transaction
 * @returns {boolean} True if output belongs to this wallet
 */
export function checkOutputOwnership(outputPubKey, txPubKey, viewSecretKey, spendPubKey, outputIndex) {
  if (typeof outputPubKey === 'string') {
    outputPubKey = hexToBytes(outputPubKey);
  }
  if (typeof spendPubKey === 'string') {
    spendPubKey = hexToBytes(spendPubKey);
  }

  // Compute key derivation
  const derivation = generateKeyDerivation(txPubKey, viewSecretKey);
  if (!derivation) return false;

  // Derive expected output public key
  const expectedPubKey = derivePublicKey(derivation, outputIndex, spendPubKey);
  if (!expectedPubKey) return false;

  // Compare with actual output key
  return bytesToHex(outputPubKey) === bytesToHex(expectedPubKey);
}

/**
 * Check if output belongs to a subaddress
 *
 * @param {Uint8Array|string} outputPubKey - Output public key from transaction
 * @param {Uint8Array|string} txPubKey - Transaction public key
 * @param {Uint8Array|string} viewSecretKey - Wallet's view secret key
 * @param {Map} subaddressSpendKeys - Map of spend public key hex -> {major, minor}
 * @param {number} outputIndex - Output index in transaction
 * @returns {Object|null} { major, minor, derivation } if found, null otherwise
 */
export function checkSubaddressOwnership(outputPubKey, txPubKey, viewSecretKey, subaddressSpendKeys, outputIndex) {
  if (typeof outputPubKey === 'string') {
    outputPubKey = hexToBytes(outputPubKey);
  }

  try {
    // Compute key derivation
    const derivation = generateKeyDerivation(txPubKey, viewSecretKey);

    // For subaddress, we compute: derived = outputKey - scalar*G
    // Then check if derived matches any known subaddress spend key
    const derivedSpendKey = deriveSubaddressPublicKey(outputPubKey, derivation, outputIndex);

    const derivedHex = bytesToHex(derivedSpendKey);
    const subaddressInfo = subaddressSpendKeys.get(derivedHex);

    if (subaddressInfo) {
      return {
        major: subaddressInfo.major,
        minor: subaddressInfo.minor,
        derivation
      };
    }

    return null; // Not our subaddress
  } catch (e) {
    // Crypto operation failed - this output isn't valid for our keys
    return null;
  }
}

// ============================================================================
// Transaction Scanning Utilities
// ============================================================================

/**
 * Scan a single output for ownership (main address)
 *
 * @param {Object} output - Output object with key, amount, etc.
 * @param {Uint8Array|string} txPubKey - Transaction public key
 * @param {Uint8Array|string} viewSecretKey - View secret key
 * @param {Uint8Array|string} spendPubKey - Spend public key
 * @param {number} outputIndex - Output index
 * @returns {Object|null} Scan result with derivation, amount, etc.
 */
export function scanOutput(output, txPubKey, viewSecretKey, spendPubKey, outputIndex) {
  let derivation;
  try {
    // Compute key derivation
    derivation = generateKeyDerivation(txPubKey, viewSecretKey);
  } catch (e) {
    // Key derivation failed - cannot be our output
    return null;
  }

  // Check view tag first (if available) for optimization
  if (output.view_tag !== undefined) {
    const expectedViewTag = deriveViewTag(derivation, outputIndex);
    if (output.view_tag !== expectedViewTag) {
      return null; // View tag mismatch, not our output
    }
  }

  // Derive expected output public key
  let expectedPubKey;
  try {
    expectedPubKey = derivePublicKey(derivation, outputIndex, spendPubKey);
  } catch (e) {
    // Key derivation failed - cannot be our output
    return null;
  }
  if (!expectedPubKey) return null;

  // Compare with actual output key
  const outputKey = typeof output.key === 'string' ? hexToBytes(output.key) : output.key;
  if (bytesToHex(outputKey) !== bytesToHex(expectedPubKey)) {
    return null; // Not our output
  }

  // Output is ours! Decrypt amount if encrypted
  let amount = output.amount;
  let mask = null;

  if (output.encrypted_amount) {
    const sharedSecret = computeSharedSecret(derivation, outputIndex);
    const decoded = ecdhDecodeFull(
      typeof output.encrypted_amount === 'string'
        ? hexToBytes(output.encrypted_amount)
        : output.encrypted_amount,
      sharedSecret
    );
    amount = decoded.amount;
    mask = decoded.mask;
  }

  return {
    owned: true,
    outputIndex,
    derivation,
    amount,
    mask,
    outputKey: bytesToHex(outputKey)
  };
}

/**
 * Scan a transaction for owned outputs
 *
 * @param {Object} tx - Transaction object
 * @param {Uint8Array|string} viewSecretKey - View secret key
 * @param {Uint8Array|string} spendPubKey - Spend public key
 * @returns {Array} Array of owned outputs
 */
export function scanTransaction(tx, viewSecretKey, spendPubKey) {
  const ownedOutputs = [];

  // Get transaction public key
  const txPubKey = tx.tx_pub_key || tx.extra?.tx_pub_key;
  if (!txPubKey) return ownedOutputs;

  // Scan each output
  const outputs = tx.vout || tx.outputs || [];
  for (let i = 0; i < outputs.length; i++) {
    const result = scanOutput(outputs[i], txPubKey, viewSecretKey, spendPubKey, i);
    if (result) {
      ownedOutputs.push(result);
    }
  }

  return ownedOutputs;
}

// ============================================================================
// Exports
// ============================================================================

// Named export for scalarAdd
export { scalarAdd };

export default {
  // Key derivation
  generateKeyDerivation,
  derivationToScalar,
  derivePublicKey,
  deriveSecretKey,
  deriveSubaddressPublicKey,
  deriveViewTag,

  // Amount encryption/decryption
  computeSharedSecret,
  ecdhDecode,
  ecdhDecodeFull,
  ecdhEncode,

  // Ownership checks
  checkOutputOwnership,
  checkSubaddressOwnership,

  // Transaction scanning
  scanOutput,
  scanTransaction,

  // Utilities
  encodeVarint: encodeVarint,
  scalarAdd
};
