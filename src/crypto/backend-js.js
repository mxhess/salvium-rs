/**
 * JavaScript Crypto Backend
 *
 * Wraps existing pure-JS implementations behind the unified backend interface.
 * All existing code remains untouched — this is just a thin adapter.
 *
 * @module crypto/backend-js
 */

import { keccak256 as jsKeccak } from '../keccak.js';
import { blake2b as jsBlake2b } from '../blake2b.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import {
  scAdd, scSub, scMul, scMulAdd, scMulSub,
  scReduce32, scReduce64, scInvert, scCheck, scIsZero
} from '../transaction/serialization.js';
import {
  scalarMultBase, scalarMultPoint, pointAddCompressed,
  pointSubCompressed, pointNegate, doubleScalarMultBase
} from '../ed25519.js';
import { hashToPoint, generateKeyImage } from '../keyimage.js';
import { generateKeyDerivation, derivePublicKey, deriveSecretKey } from '../scanning.js';
import { commit, zeroCommit, genCommitmentMask } from '../transaction/serialization.js';

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

  // Scalar ops
  scAdd(a, b) { return scAdd(a, b); }
  scSub(a, b) { return scSub(a, b); }
  scMul(a, b) { return scMul(a, b); }
  scMulAdd(a, b, c) { return scMulAdd(a, b, c); }
  scMulSub(a, b, c) { return scMulSub(a, b, c); }
  scReduce32(s) { return scReduce32(s); }
  scReduce64(s) { return scReduce64(s); }
  scInvert(a) { return scInvert(a); }
  scCheck(s) { return scCheck(s); }
  scIsZero(s) { return scIsZero(s); }

  // Point ops
  scalarMultBase(s) { return scalarMultBase(s); }
  scalarMultPoint(s, p) { return scalarMultPoint(s, p); }
  pointAddCompressed(p, q) { return pointAddCompressed(p, q); }
  pointSubCompressed(p, q) { return pointSubCompressed(p, q); }
  pointNegate(p) { return pointNegate(p); }
  doubleScalarMultBase(a, p, b) {
    // JS doubleScalarMultBase expects decompressed point object, not bytes.
    // Compose from primitives instead: a*P + b*G
    const aP = scalarMultPoint(a, p);
    const bG = scalarMultBase(b);
    return pointAddCompressed(aP, bG);
  }

  // Hash-to-point & key derivation
  hashToPoint(data) { return hashToPoint(data); }
  generateKeyImage(pubKey, secKey) { return generateKeyImage(pubKey, secKey); }
  generateKeyDerivation(pubKey, secKey) { return generateKeyDerivation(pubKey, secKey); }
  derivePublicKey(derivation, outputIndex, basePub) { return derivePublicKey(derivation, outputIndex, basePub); }
  deriveSecretKey(derivation, outputIndex, baseSec) { return deriveSecretKey(derivation, outputIndex, baseSec); }

  // Pedersen commitments
  commit(amount, mask) { return commit(amount, mask); }
  zeroCommit(amount) { return zeroCommit(amount); }
  genCommitmentMask(sharedSecret) { return genCommitmentMask(sharedSecret); }

  // ─── CLSAG/TCLSAG/BP+ — no native implementation, return null ──────────
  // The JS fallback for these lives in transaction.js and bulletproofs_plus.js.
  // The backend returning null signals callers to use the JS fallback path.
  clsagSign() { return null; }
  clsagVerify() { return null; }
  tclsagSign() { return null; }
  tclsagVerify() { return null; }
  bulletproofPlusProve() { return null; }
  bulletproofPlusVerify() { return null; }

  // Oracle signature verification
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
