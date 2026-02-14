/**
 * JSI Crypto Backend
 *
 * Calls native Rust crypto via React Native JSI (C++ bridge).
 * The native module installs `globalThis.__SalviumCrypto` at app startup.
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
    if (!globalThis.__SalviumCrypto) {
      throw new Error(
        'JSI backend not available: globalThis.__SalviumCrypto is not installed. ' +
        'Ensure the native SalviumCrypto module is linked and initialized.'
      );
    }
    this.native = globalThis.__SalviumCrypto;
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

  // ─── X25519 ────────────────────────────────────────────────────────────

  x25519ScalarMult(scalar, uCoord) { return this.native.x25519ScalarMult(scalar, uCoord); }

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

  // ─── Batch Subaddress Map Generation ────────────────────────────────────

  cnSubaddressMapBatch(spendPubkey, viewSecretKey, majorCount, minorCount) {
    const buf = this.native.cnSubaddressMapBatch(spendPubkey, viewSecretKey, majorCount, minorCount);
    return _parseSubaddressMapBufferJsi(buf);
  }

  carrotSubaddressMapBatch(accountSpendPubkey, accountViewPubkey, generateAddressSecret, majorCount, minorCount) {
    const buf = this.native.carrotSubaddressMapBatch(accountSpendPubkey, accountViewPubkey, generateAddressSecret, majorCount, minorCount);
    return _parseSubaddressMapBufferJsi(buf);
  }

  // ─── CARROT Key Derivation (Batch) ────────────────────────────────────

  deriveCarrotKeysBatch(masterSecret) {
    return this.native.deriveCarrotKeysBatch(masterSecret);
  }

  deriveCarrotViewOnlyKeysBatch(viewBalanceSecret, accountSpendPubkey) {
    return this.native.deriveCarrotViewOnlyKeysBatch(viewBalanceSecret, accountSpendPubkey);
  }

  // ─── CARROT Helpers ────────────────────────────────────────────────────

  computeCarrotViewTag(sSrUnctx, inputContext, ko) {
    return this.native.computeCarrotViewTag(sSrUnctx, inputContext, ko);
  }
  decryptCarrotAmount(encAmount, sSrCtx, ko) {
    return this.native.decryptCarrotAmount(encAmount, sSrCtx, ko);
  }
  deriveCarrotCommitmentMask(sSrCtx, amount, addressSpendPubkey, enoteType) {
    return this.native.deriveCarrotCommitmentMask(sSrCtx, amount, addressSpendPubkey, enoteType);
  }
  recoverCarrotAddressSpendPubkey(ko, sSrCtx, commitment) {
    return this.native.recoverCarrotAddressSpendPubkey(ko, sSrCtx, commitment);
  }
  makeInputContextRct(firstKeyImage) {
    return this.native.makeInputContextRct(firstKeyImage);
  }
  makeInputContextCoinbase(blockHeight) {
    return this.native.makeInputContextCoinbase(blockHeight);
  }

  // ─── CryptoNote Output Scanning ──────────────────────────────────────────

  scanCnOutput(outputPubkey, derivation, outputIndex, viewTag,
      rctType, clearTextAmount, ecdhEncAmount,
      spendSecretKey, viewSecretKey, subaddressMap) {
    return this.native.cnScanOutput(
      outputPubkey, derivation, outputIndex, viewTag,
      rctType, clearTextAmount, ecdhEncAmount,
      spendSecretKey, viewSecretKey, subaddressMap
    );
  }

  // ─── Transaction Extra Parsing & Serialization ────────────────────────────

  parseExtra(extraBytes) {
    return this.native.parseExtra(extraBytes);
  }
  serializeTxExtra(jsonStr) {
    return this.native.serializeTxExtra(jsonStr);
  }
  computeTxPrefixHash(data) {
    return this.native.computeTxPrefixHash(data);
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

  // ─── RCT Batch Signature Verification ──────────────────────────────────

  verifyRctSignatures(rctType, inputCount, ringSize, txPrefixHash,
      rctBaseBytes, bpComponents, keyImagesFlat, pseudoOutsFlat,
      sigsFlat, ringPubkeysFlat, ringCommitmentsFlat) {
    const result = this.native.verifyRctSignatures(
      rctType, inputCount, ringSize,
      txPrefixHash, rctBaseBytes, bpComponents,
      keyImagesFlat, pseudoOutsFlat, sigsFlat,
      ringPubkeysFlat, ringCommitmentsFlat
    );
    return result;
  }

  // ─── CLSAG Ring Signatures ──────────────────────────────────────────────

  clsagSign(message, ring, secretKey, commitments, commitmentMask, pseudoOutput, secretIndex) {
    const ringFlat = flattenRing(ring);
    const commFlat = flattenRing(commitments);
    return deserializeClsagNative(
      this.native.clsagSign(message, ringFlat, ring.length, secretKey, commFlat, commitmentMask, pseudoOutput, secretIndex),
      ring.length
    );
  }

  clsagVerify(message, sig, ring, commitments, pseudoOutput) {
    const sigBuf = serializeClsagNative(sig);
    const ringFlat = flattenRing(ring);
    const commFlat = flattenRing(commitments);
    return this.native.clsagVerify(message, sigBuf, sigBuf.length, ringFlat, ring.length, commFlat, pseudoOutput) === 1;
  }

  // ─── TCLSAG Ring Signatures ────────────────────────────────────────────

  tclsagSign(message, ring, secretKeyX, secretKeyY, commitments, commitmentMask, pseudoOutput, secretIndex) {
    const ringFlat = flattenRing(ring);
    const commFlat = flattenRing(commitments);
    return deserializeTclsagNative(
      this.native.tclsagSign(message, ringFlat, ring.length, secretKeyX, secretKeyY, commFlat, commitmentMask, pseudoOutput, secretIndex),
      ring.length
    );
  }

  tclsagVerify(message, sig, ring, commitments, pseudoOutput) {
    const sigBuf = serializeTclsagNative(sig);
    const ringFlat = flattenRing(ring);
    const commFlat = flattenRing(commitments);
    return this.native.tclsagVerify(message, sigBuf, sigBuf.length, ringFlat, ring.length, commFlat, pseudoOutput) === 1;
  }

  // ─── Bulletproofs+ Range Proofs ────────────────────────────────────────

  bulletproofPlusProve(amounts, masks) {
    const amountBytes = serializeAmountsJsi(amounts);
    const masksFlat = flattenRing(masks);
    const result = this.native.bulletproofPlusProve(amountBytes, masksFlat, amounts.length);
    return deserializeBpProveJsi(result);
  }

  bulletproofPlusVerify(commitmentBytes, proofBytes) {
    const commFlat = flattenRing(commitmentBytes);
    return this.native.bulletproofPlusVerify(proofBytes, proofBytes.length, commFlat, commitmentBytes.length) === 1;
  }

  // ─── Key Derivation ─────────────────────────────────────────────────────

  argon2id(password, salt, opts) {
    return this.native.argon2id(password, salt, opts.t, opts.m, opts.p, opts.dkLen);
  }
}

// ─── Serialization helpers ──────────────────────────────────────────────────

function flattenRing(arr) {
  const flat = new Uint8Array(arr.length * 32);
  for (let i = 0; i < arr.length; i++) {
    const item = ensureBytes(arr[i]);
    flat.set(item, i * 32);
  }
  return flat;
}

function bytesToHexJsi(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function serializeAmountsJsi(amounts) {
  const buf = new Uint8Array(amounts.length * 8);
  for (let i = 0; i < amounts.length; i++) {
    let n = BigInt(amounts[i]);
    for (let j = 0; j < 8; j++) {
      buf[i * 8 + j] = Number(n & 0xffn);
      n >>= 8n;
    }
  }
  return buf;
}

function deserializeClsagNative(bytes, n) {
  let offset = 0;
  const s = [];
  for (let i = 0; i < n; i++) { s.push(bytesToHexJsi(bytes.slice(offset, offset + 32))); offset += 32; }
  const c1 = bytesToHexJsi(bytes.slice(offset, offset + 32)); offset += 32;
  const I = bytesToHexJsi(bytes.slice(offset, offset + 32)); offset += 32;
  const D = bytesToHexJsi(bytes.slice(offset, offset + 32));
  return { s, c1, I, D };
}

function serializeClsagNative(sig) {
  const s = sig.s.map(ensureBytes);
  const n = s.length;
  const buf = new Uint8Array(n * 32 + 96);
  let offset = 0;
  for (const si of s) { buf.set(si, offset); offset += 32; }
  buf.set(ensureBytes(sig.c1), offset); offset += 32;
  buf.set(ensureBytes(sig.I), offset); offset += 32;
  buf.set(ensureBytes(sig.D), offset);
  return buf;
}

function deserializeTclsagNative(bytes, n) {
  let offset = 0;
  const sx = [];
  for (let i = 0; i < n; i++) { sx.push(bytesToHexJsi(bytes.slice(offset, offset + 32))); offset += 32; }
  const sy = [];
  for (let i = 0; i < n; i++) { sy.push(bytesToHexJsi(bytes.slice(offset, offset + 32))); offset += 32; }
  const c1 = bytesToHexJsi(bytes.slice(offset, offset + 32)); offset += 32;
  const I = bytesToHexJsi(bytes.slice(offset, offset + 32)); offset += 32;
  const D = bytesToHexJsi(bytes.slice(offset, offset + 32));
  return { sx, sy, c1, I, D };
}

function serializeTclsagNative(sig) {
  const sx = sig.sx.map(ensureBytes);
  const sy = sig.sy.map(ensureBytes);
  const n = sx.length;
  const buf = new Uint8Array(2 * n * 32 + 96);
  let offset = 0;
  for (const s of sx) { buf.set(s, offset); offset += 32; }
  for (const s of sy) { buf.set(s, offset); offset += 32; }
  buf.set(ensureBytes(sig.c1), offset); offset += 32;
  buf.set(ensureBytes(sig.I), offset); offset += 32;
  buf.set(ensureBytes(sig.D), offset);
  return buf;
}

function _parseSubaddressMapBufferJsi(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const count = dv.getUint32(0, true);
  const map = new Map();
  let offset = 4;
  for (let i = 0; i < count; i++) {
    const key = buf.slice(offset, offset + 32);
    offset += 32;
    const major = dv.getUint32(offset, true);
    offset += 4;
    const minor = dv.getUint32(offset, true);
    offset += 4;
    map.set(bytesToHexJsi(key), { major, minor });
  }
  return map;
}

function deserializeBpProveJsi(bytes) {
  const vCount = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  let offset = 4;
  const V = [];
  for (let i = 0; i < vCount; i++) { V.push(bytes.slice(offset, offset + 32)); offset += 32; }
  const proofBytes = bytes.slice(offset);
  return { V, proofBytes };
}
