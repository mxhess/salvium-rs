/**
 * JavaScript Crypto Backend (Minimal Fallback)
 *
 * Provides only hashing primitives (keccak256, blake2b, sha256) and
 * signature verification as pure JS. All scalar, point, commitment,
 * and key derivation operations require a Rust-backed backend (WASM,
 * FFI, or JSI). Call initCrypto() or setCryptoBackend() at startup.
 *
 * @module crypto/backend-js
 * @deprecated Scalar/point operations removed. Use WASM/FFI/JSI backend.
 */

import { keccak256 as jsKeccak } from '../keccak.js';
import { blake2b as jsBlake2b } from '../blake2b.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';

const RUST_REQUIRED = 'Rust crypto backend required. Call initCrypto() or setCryptoBackend("wasm"/"ffi"/"jsi") before using crypto operations.';

export class JsCryptoBackend {
  constructor() {
    this.name = 'js';
  }

  async init() {
    // No initialization needed for JS backend
  }

  keccak256(data) {
    return jsKeccak(data);
  }

  blake2b(data, outLen, key) {
    return jsBlake2b(data, outLen, key);
  }

  // Scalar ops — require Rust backend
  scAdd() { throw new Error(RUST_REQUIRED); }
  scSub() { throw new Error(RUST_REQUIRED); }
  scMul() { throw new Error(RUST_REQUIRED); }
  scMulAdd() { throw new Error(RUST_REQUIRED); }
  scMulSub() { throw new Error(RUST_REQUIRED); }
  scReduce32() { throw new Error(RUST_REQUIRED); }
  scReduce64() { throw new Error(RUST_REQUIRED); }
  scInvert() { throw new Error(RUST_REQUIRED); }
  scCheck() { throw new Error(RUST_REQUIRED); }
  scIsZero() { throw new Error(RUST_REQUIRED); }

  // X25519 — requires Rust backend
  x25519ScalarMult() { throw new Error(RUST_REQUIRED); }
  edwardsToMontgomeryU() { throw new Error(RUST_REQUIRED); }

  // Point ops — require Rust backend
  scalarMultBase() { throw new Error(RUST_REQUIRED); }
  scalarMultPoint() { throw new Error(RUST_REQUIRED); }
  pointAddCompressed() { throw new Error(RUST_REQUIRED); }
  pointSubCompressed() { throw new Error(RUST_REQUIRED); }
  pointNegate() { throw new Error(RUST_REQUIRED); }
  doubleScalarMultBase() { throw new Error(RUST_REQUIRED); }

  // Hash-to-point & key derivation — require Rust backend
  hashToPoint() { throw new Error(RUST_REQUIRED); }
  generateKeyImage() { throw new Error(RUST_REQUIRED); }
  generateKeyDerivation() { throw new Error(RUST_REQUIRED); }
  derivePublicKey() { throw new Error(RUST_REQUIRED); }
  deriveSecretKey() { throw new Error(RUST_REQUIRED); }

  // Pedersen commitments — require Rust backend
  commit() { throw new Error(RUST_REQUIRED); }
  zeroCommit() { throw new Error(RUST_REQUIRED); }
  genCommitmentMask() { throw new Error(RUST_REQUIRED); }

  // RCT batch verification — returns null (JS fallback handled in validation.js)
  verifyRctSignatures() { return null; }

  // Full TX parsing/serialization — returns null (signals JS fallback)
  parseTransaction() { return null; }
  serializeTransaction() { return null; }
  parseBlock() { return null; }

  // CLSAG/TCLSAG/BP+ — require Rust backend
  clsagSign() { throw new Error(RUST_REQUIRED); }
  clsagVerify() { throw new Error(RUST_REQUIRED); }
  tclsagSign() { throw new Error(RUST_REQUIRED); }
  tclsagVerify() { throw new Error(RUST_REQUIRED); }
  bulletproofPlusProve() { throw new Error(RUST_REQUIRED); }
  bulletproofPlusVerify() { throw new Error(RUST_REQUIRED); }

  // Oracle signature verification — JS fallback (WebCrypto / Node.js crypto)
  sha256(data) { return nobleSha256(data); }

  // Argon2id key derivation (JS fallback via Noble — slow, use WASM/JSI when possible)
  argon2id(password, salt, opts) {
    console.warn('[salvium-js] suboptimal crypto path: js->argon2id (call initCrypto() for WASM acceleration)');
    return nobleArgon2id(password, salt, opts);
  }

  /**
   * Verify signature using WebCrypto (browser/Node.js 15+) or Node.js crypto.
   * @param {Uint8Array} message - Message bytes (will be SHA-256 hashed)
   * @param {Uint8Array} signature - DER-encoded signature
   * @param {Uint8Array} pubkeyDer - DER-encoded SPKI public key
   * @returns {Promise<boolean>} True if valid
   */
  async verifySignature(message, signature, pubkeyDer) {
    // Try WebCrypto first (works in browsers and modern Node.js)
    if (typeof globalThis.crypto?.subtle?.verify === 'function') {
      return verifyWithWebCrypto(message, signature, pubkeyDer);
    }
    // Fall back to Node.js crypto module
    return verifyWithNodeCrypto(message, signature, pubkeyDer);
  }
}

/**
 * Verify using WebCrypto API.
 * Detects ECDSA P-256 vs DSA from the SPKI OID.
 */
async function verifyWithWebCrypto(message, signature, pubkeyDer) {
  try {
    // Detect algorithm from SPKI OID bytes
    // ECDSA P-256 OID: 06 07 2a 86 48 ce 3d 02 01 (1.2.840.10045.2.1)
    // DSA OID: 06 07 2a 86 48 ce 38 04 01 (1.2.840.10040.4.1)
    const isEcdsa = containsBytes(pubkeyDer, [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);

    if (isEcdsa) {
      // Convert DER signature to raw r||s format for WebCrypto
      const rawSig = derSignatureToRaw(signature, 32);
      const key = await globalThis.crypto.subtle.importKey(
        'spki', pubkeyDer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, ['verify']
      );
      return await globalThis.crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key, rawSig, message
      );
    }
    // WebCrypto doesn't support DSA — fall back to Node.js crypto
    return verifyWithNodeCrypto(message, signature, pubkeyDer);
  } catch (_e) {
    return false;
  }
}

/**
 * Verify using Node.js crypto module (createVerify).
 * Works for both ECDSA and DSA.
 */
async function verifyWithNodeCrypto(message, signature, pubkeyDer) {
  try {
    const { createVerify } = await import('crypto');
    // Wrap DER key in PEM
    const b64 = typeof Buffer !== 'undefined'
      ? Buffer.from(pubkeyDer).toString('base64')
      : btoa(String.fromCharCode(...pubkeyDer));
    const pem = `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
    const verifier = createVerify('SHA256');
    verifier.update(message);
    return verifier.verify(pem, Buffer.from(signature));
  } catch (_e) {
    return false;
  }
}

/**
 * Convert DER-encoded ECDSA signature to raw r||s format.
 * WebCrypto expects raw format, not DER.
 */
function derSignatureToRaw(der, componentLen) {
  // DER: 30 <len> 02 <rlen> <r> 02 <slen> <s>
  let offset = 2; // skip SEQUENCE tag + length
  if (der[0] !== 0x30) return der; // not DER, return as-is

  // Parse r
  if (der[offset] !== 0x02) return der;
  const rLen = der[offset + 1];
  const rStart = offset + 2;
  offset = rStart + rLen;

  // Parse s
  if (der[offset] !== 0x02) return der;
  const sLen = der[offset + 1];
  const sStart = offset + 2;

  const raw = new Uint8Array(componentLen * 2);
  // Copy r (right-aligned, strip leading zeros)
  const rBytes = der.slice(rStart, rStart + rLen);
  const rTrim = rBytes[0] === 0 ? rBytes.slice(1) : rBytes;
  raw.set(rTrim, componentLen - rTrim.length);
  // Copy s (right-aligned, strip leading zeros)
  const sBytes = der.slice(sStart, sStart + sLen);
  const sTrim = sBytes[0] === 0 ? sBytes.slice(1) : sBytes;
  raw.set(sTrim, componentLen * 2 - sTrim.length);
  return raw;
}

/** Check if haystack contains needle bytes at any offset */
function containsBytes(haystack, needle) {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
