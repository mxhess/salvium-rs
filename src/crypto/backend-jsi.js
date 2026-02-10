/**
 * JSI Crypto Backend
 *
 * Calls native Rust crypto via React Native JSI (C++ bridge).
 * The native module installs `global.__SalviumCrypto` at app startup.
 * This backend provides the same interface as JS and WASM backends.
 *
 * @module crypto/backend-jsi
 */

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function ensureBytes(v) {
  if (typeof v === 'string') return hexToBytes(v);
  return v;
}

export class JsiCryptoBackend {
  constructor() {
    this.name = 'jsi';
    this.native = null;
  }

  async init() {
    if (!global.__SalviumCrypto) {
      throw new Error(
        'JSI backend not available: global.__SalviumCrypto is not installed. ' +
        'Ensure the native SalviumCrypto module is linked and initialized.'
      );
    }
    this.native = global.__SalviumCrypto;
  }

  // ─── Hashing ────────────────────────────────────────────────────────────

  keccak256(data) {
    return this.native.keccak256(data);
  }

  blake2b(data, outLen, key) {
    if (key) {
      return this.native.blake2bKeyed(data, outLen, key);
    }
    return this.native.blake2b(data, outLen);
  }

  // ─── Scalar Operations ──────────────────────────────────────────────────

  scAdd(a, b) { return this.native.scAdd(a, b); }
  scSub(a, b) { return this.native.scSub(a, b); }
  scMul(a, b) { return this.native.scMul(a, b); }
  scMulAdd(a, b, c) { return this.native.scMulAdd(a, b, c); }
  scMulSub(a, b, c) { return this.native.scMulSub(a, b, c); }
  scReduce32(s) { return this.native.scReduce32(s); }
  scReduce64(s) { return this.native.scReduce64(s); }
  scInvert(a) { return this.native.scInvert(a); }
  scCheck(s) { return this.native.scCheck(s); }
  scIsZero(s) { return this.native.scIsZero(s); }

  // ─── Point Operations ───────────────────────────────────────────────────

  scalarMultBase(s) { return this.native.scalarMultBase(s); }
  scalarMultPoint(s, p) { return this.native.scalarMultPoint(s, p); }
  pointAddCompressed(p, q) { return this.native.pointAdd(p, q); }
  pointSubCompressed(p, q) { return this.native.pointSub(p, q); }
  pointNegate(p) { return this.native.pointNegate(p); }
  doubleScalarMultBase(a, p, b) { return this.native.doubleScalarMultBase(a, p, b); }

  // ─── Hash-to-Point & Key Derivation ─────────────────────────────────────

  hashToPoint(data) { return this.native.hashToPoint(data); }

  generateKeyImage(pubKey, secKey) {
    pubKey = ensureBytes(pubKey);
    secKey = ensureBytes(secKey);
    return this.native.generateKeyImage(pubKey, secKey);
  }

  generateKeyDerivation(pubKey, secKey) {
    pubKey = ensureBytes(pubKey);
    secKey = ensureBytes(secKey);
    return this.native.generateKeyDerivation(pubKey, secKey);
  }

  derivePublicKey(derivation, outputIndex, basePub) {
    return this.native.derivePublicKey(derivation, outputIndex, basePub);
  }

  deriveSecretKey(derivation, outputIndex, baseSec) {
    return this.native.deriveSecretKey(derivation, outputIndex, baseSec);
  }

  // ─── Pedersen Commitments ───────────────────────────────────────────────

  commit(amount, mask) {
    // Convert amount (BigInt/number) to 32-byte LE scalar
    let amountBytes = amount;
    if (typeof amount === 'bigint' || typeof amount === 'number') {
      let n = BigInt(amount);
      amountBytes = new Uint8Array(32);
      for (let i = 0; i < 32 && n > 0n; i++) {
        amountBytes[i] = Number(n & 0xffn);
        n >>= 8n;
      }
    }
    mask = ensureBytes(mask);
    return this.native.pedersenCommit(amountBytes, mask);
  }

  zeroCommit(amount) {
    // Salvium rct::zeroCommit uses blinding factor = 1 (not 0).
    const scalarOne = new Uint8Array(32);
    scalarOne[0] = 1;
    return this.commit(amount, scalarOne);
  }

  genCommitmentMask(sharedSecret) {
    sharedSecret = ensureBytes(sharedSecret);
    return this.native.genCommitmentMask(sharedSecret);
  }

  // ─── Oracle Signature Verification ──────────────────────────────────────

  sha256(data) {
    return this.native.sha256(data);
  }

  async verifySignature(message, signature, pubkeyDer) {
    // Native module returns 1 for valid, 0 for invalid
    return this.native.verifySignature(message, signature, pubkeyDer) === 1;
  }
}
