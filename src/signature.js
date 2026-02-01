/**
 * Salvium Message Signature Verification
 *
 * Supports both V1 (legacy) and V2 (domain-separated) signatures.
 *
 * Signature format: "SigV1" or "SigV2" + Base58(signature_bytes)
 * where signature_bytes = c (32 bytes) + r (32 bytes) + sign_mask (1 byte) = 65 bytes
 *
 * V1: hash = Keccak256(message)
 * V2: hash = Keccak256(domain_separator + spend_key + view_key + mode + varint(len) + message)
 */

import { keccak256, scCheck, scIsZero, scSub, scReduce32, doubleScalarMultBase, isIdentity } from './crypto/index.js';
import { decode } from './base58.js';
import { parseAddress } from './address.js';

// Domain separator for V2 signatures (includes null terminator)
const HASH_KEY_MESSAGE_SIGNING = new TextEncoder().encode('MoneroMessageSignature\0');

/**
 * Encode a number as a varint (variable-length integer)
 * @param {number} n - Number to encode
 * @returns {Uint8Array} Varint bytes
 */
function encodeVarint(n) {
  const bytes = [];
  while (n >= 0x80) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n & 0x7f);
  return new Uint8Array(bytes);
}

/**
 * Compute V1 message hash (simple Keccak256)
 * @param {string} message - The message
 * @returns {Uint8Array} 32-byte hash
 */
function getMessageHashV1(message) {
  const messageBytes = new TextEncoder().encode(message);
  return keccak256(messageBytes);
}

/**
 * Compute V2 message hash with domain separation
 * @param {string} message - The message
 * @param {Uint8Array} spendKey - 32-byte spend public key
 * @param {Uint8Array} viewKey - 32-byte view public key
 * @param {number} mode - 0 for spend key, 1 for view key
 * @returns {Uint8Array} 32-byte hash
 */
function getMessageHashV2(message, spendKey, viewKey, mode) {
  const messageBytes = new TextEncoder().encode(message);
  const lenVarint = encodeVarint(messageBytes.length);

  // Concatenate: domain_separator + spend_key + view_key + mode + len + message
  const totalLen = HASH_KEY_MESSAGE_SIGNING.length + 32 + 32 + 1 + lenVarint.length + messageBytes.length;
  const data = new Uint8Array(totalLen);

  let offset = 0;
  data.set(HASH_KEY_MESSAGE_SIGNING, offset);
  offset += HASH_KEY_MESSAGE_SIGNING.length;

  data.set(spendKey, offset);
  offset += 32;

  data.set(viewKey, offset);
  offset += 32;

  data[offset++] = mode;

  data.set(lenVarint, offset);
  offset += lenVarint.length;

  data.set(messageBytes, offset);

  return keccak256(data);
}

/**
 * Perform Schnorr signature verification
 *
 * Verifies: R' = r*G + c*P, then checks hash(prefix || key || R') == c
 *
 * @param {Uint8Array} hash - 32-byte message hash
 * @param {Uint8Array} publicKey - 32-byte public key
 * @param {Uint8Array} sigC - 32-byte signature c component
 * @param {Uint8Array} sigR - 32-byte signature r component
 * @returns {boolean} true if signature is valid
 */
function checkSignature(hash, publicKey, sigC, sigR) {
  // Validate scalars
  if (!scCheck(sigC) || !scCheck(sigR) || scIsZero(sigC)) {
    return false;
  }

  // Compute R' = c*P + r*G using double scalar multiplication
  // doubleScalarMultBase takes compressed bytes; returns null if publicKey is invalid
  const RBytes = doubleScalarMultBase(sigC, publicKey, sigR);
  if (!RBytes || isIdentity(RBytes)) {
    return false;
  }

  // Recompute challenge: c' = H(hash || publicKey || R')
  const buf = new Uint8Array(32 + 32 + 32);
  buf.set(hash, 0);
  buf.set(publicKey, 32);
  buf.set(RBytes, 64);

  const cPrimeReduced = scReduce32(keccak256(buf));

  // Check c' == c
  const diff = scSub(cPrimeReduced, sigC);
  return scIsZero(diff);
}

/**
 * Verify a Salvium message signature
 *
 * @param {string} message - The original message that was signed
 * @param {string} address - Salvium address (to extract public keys)
 * @param {string} signature - The signature string (SigV1... or SigV2...)
 * @returns {Object} Result object with:
 *   - valid: boolean - whether signature is valid
 *   - version: number - signature version (1 or 2)
 *   - keyType: string - 'spend' or 'view' (which key was used to sign)
 *   - error: string|null - error message if invalid
 */
export function verifySignature(message, address, signature) {
  // Parse signature header
  const isV1 = signature.startsWith('SigV1');
  const isV2 = signature.startsWith('SigV2');

  if (!isV1 && !isV2) {
    return { valid: false, version: 0, keyType: null, error: 'Invalid signature header (expected SigV1 or SigV2)' };
  }

  const version = isV1 ? 1 : 2;
  const headerLen = 5; // "SigV1" or "SigV2"

  // Decode signature from Base58
  let sigBytes;
  try {
    sigBytes = decode(signature.substring(headerLen));
  } catch (e) {
    return { valid: false, version, keyType: null, error: 'Failed to decode signature Base58' };
  }

  // Signature should be 65 bytes (c: 32, r: 32, sign_mask: 1)
  if (sigBytes.length !== 65) {
    return { valid: false, version, keyType: null, error: `Invalid signature length: expected 65, got ${sigBytes.length}` };
  }

  const sigC = sigBytes.slice(0, 32);
  const sigR = sigBytes.slice(32, 64);
  // sign_mask (byte 64) is not used for standard message verification

  // Parse address to get public keys
  const addrInfo = parseAddress(address);
  if (!addrInfo.valid) {
    return { valid: false, version, keyType: null, error: `Invalid address: ${addrInfo.error}` };
  }

  const spendKey = addrInfo.spendPublicKey;
  const viewKey = addrInfo.viewPublicKey;

  // Try verification with spend key (mode 0)
  let hash;
  if (isV1) {
    hash = getMessageHashV1(message);
  } else {
    hash = getMessageHashV2(message, spendKey, viewKey, 0);
  }

  if (checkSignature(hash, spendKey, sigC, sigR)) {
    return { valid: true, version, keyType: 'spend', error: null };
  }

  // Try verification with view key (mode 1)
  if (isV2) {
    hash = getMessageHashV2(message, spendKey, viewKey, 1);
  }
  // For V1, the hash is just the message hash, same for both keys

  if (checkSignature(hash, viewKey, sigC, sigR)) {
    return { valid: true, version, keyType: 'view', error: null };
  }

  return { valid: false, version, keyType: null, error: 'Signature verification failed' };
}

/**
 * Parse a signature string and extract its components
 *
 * @param {string} signature - The signature string
 * @returns {Object} Parsed signature with version, c, r, signMask
 */
export function parseSignature(signature) {
  const isV1 = signature.startsWith('SigV1');
  const isV2 = signature.startsWith('SigV2');

  if (!isV1 && !isV2) {
    return { valid: false, error: 'Invalid signature header' };
  }

  const version = isV1 ? 1 : 2;

  try {
    const sigBytes = decode(signature.substring(5));
    if (sigBytes.length !== 65) {
      return { valid: false, error: 'Invalid signature length' };
    }

    return {
      valid: true,
      version,
      c: sigBytes.slice(0, 32),
      r: sigBytes.slice(32, 64),
      signMask: sigBytes[64]
    };
  } catch (e) {
    return { valid: false, error: 'Failed to decode signature' };
  }
}

export default {
  verifySignature,
  parseSignature,
  getMessageHashV1,
  getMessageHashV2
};
