/**
 * WASM Crypto Backend
 *
 * Loads Rust-compiled WASM module and wraps it behind the unified backend interface.
 * Supports both Node/Bun (fs.readFile) and browser (fetch) environments.
 *
 * @module crypto/backend-wasm
 */

import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

let wasmExports = null;

/** Convert empty Uint8Array (Rust returned Vec::new() for invalid point) to null */
function nullIfEmpty(result) {
  return (result && result.length > 0) ? result : null;
}

/**
 * Detect if running in a browser environment
 */
function isBrowser() {
  return typeof window !== 'undefined' || (typeof globalThis !== 'undefined' && typeof globalThis.document !== 'undefined');
}

/**
 * Load WASM bytes from disk (Node/Bun)
 */
async function loadWasmNode() {
  const { readFile } = await import('fs/promises');
  const { fileURLToPath } = await import('url');
  const { dirname, join } = await import('path');

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const wasmPath = join(__dirname, 'wasm', 'salvium_crypto_bg.wasm');
  return readFile(wasmPath);
}

/**
 * Load WASM bytes via fetch (browser)
 */
async function loadWasmBrowser() {
  // Resolve relative to this module's URL
  const wasmUrl = new URL('./wasm/salvium_crypto_bg.wasm', import.meta.url);
  const response = await fetch(wasmUrl);
  if (!response.ok) throw new Error(`Failed to fetch WASM: ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Load and instantiate the WASM module
 */
async function loadWasm() {
  if (wasmExports) return wasmExports;

  const wasmBytes = isBrowser() ? await loadWasmBrowser() : await loadWasmNode();

  // Import the JS glue to get the import object and init function
  const glue = await import('./wasm/salvium_crypto.js');

  // Use initSync with the raw WASM bytes
  glue.initSync({ module: wasmBytes });
  wasmExports = glue;
  return wasmExports;
}

export class WasmCryptoBackend {
  constructor() {
    this.name = 'wasm';
    this.wasm = null;
  }

  async init() {
    this.wasm = await loadWasm();
  }

  keccak256(data) {
    if (!this.wasm) throw new Error('WASM backend not initialized. Call init() first.');
    return this.wasm.keccak256(data);
  }

  blake2b(data, outLen, key) {
    if (!this.wasm) throw new Error('WASM backend not initialized. Call init() first.');
    if (key) {
      return this.wasm.blake2b_keyed(data, outLen, key);
    }
    return this.wasm.blake2b_hash(data, outLen);
  }

  // Scalar ops
  scAdd(a, b) { return this.wasm.sc_add(a, b); }
  scSub(a, b) { return this.wasm.sc_sub(a, b); }
  scMul(a, b) { return this.wasm.sc_mul(a, b); }
  scMulAdd(a, b, c) { return this.wasm.sc_mul_add(a, b, c); }
  scMulSub(a, b, c) { return this.wasm.sc_mul_sub(a, b, c); }
  scReduce32(s) { return this.wasm.sc_reduce32(s); }
  scReduce64(s) { return this.wasm.sc_reduce64(s); }
  scInvert(a) { return this.wasm.sc_invert(a); }
  scCheck(s) { return this.wasm.sc_check(s); }
  scIsZero(s) { return this.wasm.sc_is_zero(s); }

  // Point ops — return null on invalid points (empty vec from Rust)
  scalarMultBase(s) { return this.wasm.scalar_mult_base(s); }
  scalarMultPoint(s, p) { return nullIfEmpty(this.wasm.scalar_mult_point(s, p)); }
  pointAddCompressed(p, q) { return nullIfEmpty(this.wasm.point_add_compressed(p, q)); }
  pointSubCompressed(p, q) { return nullIfEmpty(this.wasm.point_sub_compressed(p, q)); }
  pointNegate(p) { return nullIfEmpty(this.wasm.point_negate(p)); }
  doubleScalarMultBase(a, p, b) { return nullIfEmpty(this.wasm.double_scalar_mult_base(a, p, b)); }

  // Batch subaddress map generation
  cnSubaddressMapBatch(spendPubkey, viewSecretKey, majorCount, minorCount) {
    const buf = this.wasm.cn_subaddress_map_batch(spendPubkey, viewSecretKey, majorCount, minorCount);
    return _parseSubaddressMapBuffer(buf);
  }

  carrotSubaddressMapBatch(accountSpendPubkey, accountViewPubkey, generateAddressSecret, majorCount, minorCount) {
    const buf = this.wasm.carrot_subaddress_map_batch(accountSpendPubkey, accountViewPubkey, generateAddressSecret, majorCount, minorCount);
    return _parseSubaddressMapBuffer(buf);
  }

  // CARROT key derivation (batch)
  deriveCarrotKeysBatch(masterSecret) { return this.wasm.derive_carrot_keys_batch(masterSecret); }
  deriveCarrotViewOnlyKeysBatch(viewBalanceSecret, accountSpendPubkey) {
    return this.wasm.derive_carrot_view_only_keys_batch(viewBalanceSecret, accountSpendPubkey);
  }

  // CARROT helpers
  computeCarrotViewTag(sSrUnctx, inputContext, ko) {
    return this.wasm.compute_carrot_view_tag(sSrUnctx, inputContext, ko);
  }
  decryptCarrotAmount(encAmount, sSrCtx, ko) {
    return this.wasm.decrypt_carrot_amount(encAmount, sSrCtx, ko);
  }
  deriveCarrotCommitmentMask(sSrCtx, amount, addressSpendPubkey, enoteType) {
    return this.wasm.derive_carrot_commitment_mask(sSrCtx, BigInt(amount), addressSpendPubkey, enoteType);
  }
  recoverCarrotAddressSpendPubkey(ko, sSrCtx, commitment) {
    const result = this.wasm.recover_carrot_address_spend_pubkey(ko, sSrCtx, commitment);
    return (result && result.length > 0) ? result : null;
  }
  makeInputContextRct(firstKeyImage) {
    return this.wasm.make_input_context_rct(firstKeyImage);
  }
  makeInputContextCoinbase(blockHeight) {
    return this.wasm.make_input_context_coinbase(BigInt(blockHeight));
  }

  // Transaction extra parsing & serialization
  parseExtra(extraBytes) {
    return this.wasm.parse_extra(extraBytes);
  }
  serializeTxExtra(jsonStr) {
    const result = this.wasm.serialize_tx_extra(jsonStr);
    return (result && result.length > 0) ? result : null;
  }
  computeTxPrefixHash(data) {
    return this.wasm.compute_tx_prefix_hash(data);
  }

  // X25519
  x25519ScalarMult(scalar, uCoord) { return this.wasm.x25519_scalar_mult(scalar, uCoord); }

  // Hash-to-point & key derivation
  hashToPoint(data) { return this.wasm.hash_to_point(data); }
  generateKeyImage(pubKey, secKey) {
    // Normalize inputs: convert hex strings to Uint8Array
    if (typeof pubKey === 'string') {
      pubKey = new Uint8Array(pubKey.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    }
    if (typeof secKey === 'string') {
      secKey = new Uint8Array(secKey.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    }
    return this.wasm.generate_key_image(pubKey, secKey);
  }
  generateKeyDerivation(pubKey, secKey) {
    // Normalize inputs: convert hex strings to Uint8Array
    if (typeof pubKey === 'string') {
      pubKey = new Uint8Array(pubKey.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    }
    if (typeof secKey === 'string') {
      secKey = new Uint8Array(secKey.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    }
    return nullIfEmpty(this.wasm.generate_key_derivation(pubKey, secKey));
  }
  derivePublicKey(derivation, outputIndex, basePub) { return nullIfEmpty(this.wasm.derive_public_key(derivation, outputIndex, basePub)); }
  deriveSecretKey(derivation, outputIndex, baseSec) { return this.wasm.derive_secret_key(derivation, outputIndex, baseSec); }

  // Pedersen commitments
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
    // Convert mask if hex string
    if (typeof mask === 'string') {
      const hex = mask;
      mask = new Uint8Array(hex.length / 2);
      for (let i = 0; i < mask.length; i++) mask[i] = parseInt(hex.substr(i*2, 2), 16);
    }
    return this.wasm.pedersen_commit(amountBytes, mask);
  }
  zeroCommit(amount) {
    // Salvium rct::zeroCommit uses blinding factor = 1 (not 0).
    // The native WASM zero_commit uses mask=0 (Monero behavior), so we
    // use pedersen_commit with scalarOne to match C++ rct::zeroCommit.
    const scalarOne = new Uint8Array(32);
    scalarOne[0] = 1;
    return this.commit(amount, scalarOne);
  }
  genCommitmentMask(sharedSecret) {
    if (typeof sharedSecret === 'string') {
      const hex = sharedSecret;
      sharedSecret = new Uint8Array(hex.length / 2);
      for (let i = 0; i < sharedSecret.length; i++) sharedSecret[i] = parseInt(hex.substr(i*2, 2), 16);
    }
    return this.wasm.gen_commitment_mask(sharedSecret);
  }

  // ─── CLSAG Ring Signatures ──────────────────────────────────────────────

  clsagSign(message, ring, secretKey, commitments, commitmentMask, pseudoOutput, secretIndex) {
    const ringFlat = flattenArrayOf32(ring);
    const commFlat = flattenArrayOf32(commitments);
    const resultBytes = this.wasm.clsag_sign_wasm(
      message, ringFlat, secretKey, commFlat, commitmentMask, pseudoOutput, secretIndex
    );
    return deserializeClsagSig(resultBytes, ring.length);
  }

  clsagVerify(message, sig, ring, commitments, pseudoOutput) {
    const sigBytes = serializeClsagSig(sig);
    const ringFlat = flattenArrayOf32(ring);
    const commFlat = flattenArrayOf32(commitments);
    return this.wasm.clsag_verify_wasm(
      message, sigBytes, ringFlat, commFlat, pseudoOutput
    );
  }

  // ─── TCLSAG Ring Signatures ────────────────────────────────────────────

  tclsagSign(message, ring, secretKeyX, secretKeyY, commitments, commitmentMask, pseudoOutput, secretIndex) {
    const ringFlat = flattenArrayOf32(ring);
    const commFlat = flattenArrayOf32(commitments);
    const resultBytes = this.wasm.tclsag_sign_wasm(
      message, ringFlat, secretKeyX, secretKeyY, commFlat, commitmentMask, pseudoOutput, secretIndex
    );
    return deserializeTclsagSig(resultBytes, ring.length);
  }

  tclsagVerify(message, sig, ring, commitments, pseudoOutput) {
    const sigBytes = serializeTclsagSig(sig);
    const ringFlat = flattenArrayOf32(ring);
    const commFlat = flattenArrayOf32(commitments);
    return this.wasm.tclsag_verify_wasm(
      message, sigBytes, ringFlat, commFlat, pseudoOutput
    );
  }

  // ─── RCT Batch Signature Verification ──────────────────────────────────

  verifyRctSignatures(rctType, inputCount, ringSize, txPrefixHash,
      rctBaseBytes, bpComponents, keyImagesFlat, pseudoOutsFlat,
      sigsFlat, ringPubkeysFlat, ringCommitmentsFlat) {
    const result = this.wasm.verify_rct_signatures_wasm(
      rctType, inputCount, ringSize,
      txPrefixHash, rctBaseBytes, bpComponents,
      keyImagesFlat, pseudoOutsFlat, sigsFlat,
      ringPubkeysFlat, ringCommitmentsFlat
    );
    return new Uint8Array(result);
  }

  // ─── Bulletproofs+ Range Proofs ────────────────────────────────────────

  bulletproofPlusProve(amounts, masks) {
    const amountBytes = serializeAmounts(amounts);
    const masksFlat = flattenArrayOf32(masks);
    const resultBytes = this.wasm.bulletproof_plus_prove_wasm(amountBytes, masksFlat);
    return deserializeBpProveResult(resultBytes);
  }

  bulletproofPlusVerify(commitmentBytes, proofBytes) {
    const commFlat = flattenArrayOf32(commitmentBytes);
    return this.wasm.bulletproof_plus_verify_wasm(proofBytes, commFlat);
  }

  // Oracle signature verification
  sha256(data) { return nobleSha256(data); }

  // Argon2id key derivation via Rust/WASM
  argon2id(password, salt, opts) {
    const result = this.wasm.argon2id_hash(password, salt, opts.t, opts.m, opts.p, opts.dkLen);
    if (result.length === 0) throw new Error('Argon2id failed');
    return result;
  }

  async verifySignature(message, signature, pubkeyDer) {
    // WASM can't do ECDSA/DSA verification (native-only crates).
    // Use WebCrypto (browser/Node 15+) or Node.js crypto as fallback.
    if (typeof globalThis.crypto?.subtle?.verify === 'function') {
      return wasmVerifyWebCrypto(message, signature, pubkeyDer);
    }
    return wasmVerifyNodeCrypto(message, signature, pubkeyDer);
  }
}

// ─── WASM backend verify helpers (same logic as JS backend) ───────────────

async function wasmVerifyWebCrypto(message, signature, pubkeyDer) {
  try {
    const isEcdsa = containsBytesWasm(pubkeyDer, [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    if (isEcdsa) {
      const rawSig = derToRawWasm(signature, 32);
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
    return wasmVerifyNodeCrypto(message, signature, pubkeyDer);
  } catch (_e) {
    return false;
  }
}

async function wasmVerifyNodeCrypto(message, signature, pubkeyDer) {
  try {
    const { createVerify } = await import('crypto');
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

function derToRawWasm(der, componentLen) {
  let offset = 2;
  if (der[0] !== 0x30) return der;
  if (der[offset] !== 0x02) return der;
  const rLen = der[offset + 1];
  const rStart = offset + 2;
  offset = rStart + rLen;
  if (der[offset] !== 0x02) return der;
  const sLen = der[offset + 1];
  const sStart = offset + 2;
  const raw = new Uint8Array(componentLen * 2);
  const rBytes = der.slice(rStart, rStart + rLen);
  const rTrim = rBytes[0] === 0 ? rBytes.slice(1) : rBytes;
  raw.set(rTrim, componentLen - rTrim.length);
  const sBytes = der.slice(sStart, sStart + sLen);
  const sTrim = sBytes[0] === 0 ? sBytes.slice(1) : sBytes;
  raw.set(sTrim, componentLen * 2 - sTrim.length);
  return raw;
}

// ─── Serialization helpers for ring signatures ────────────────────────────

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

const _hexLUT = new Array(256);
for (let i = 0; i < 256; i++) _hexLUT[i] = i.toString(16).padStart(2, '0');
function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += _hexLUT[bytes[i]];
  return hex;
}

function ensureBytes(v) {
  if (typeof v === 'string') return hexToBytes(v);
  if (typeof v === 'bigint') {
    const bytes = new Uint8Array(32);
    let n = v;
    for (let i = 0; i < 32; i++) {
      bytes[i] = Number(n & 0xffn);
      n >>= 8n;
    }
    return bytes;
  }
  return v;
}

function flattenArrayOf32(arr) {
  const flat = new Uint8Array(arr.length * 32);
  for (let i = 0; i < arr.length; i++) {
    const item = ensureBytes(arr[i]);
    flat.set(item, i * 32);
  }
  return flat;
}

function serializeAmounts(amounts) {
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

/**
 * Deserialize CLSAG signature from WASM output.
 * Format: [n as u32 LE][s_0..s_n (32 each)][c1 (32)][I (32)][D (32)]
 */
function deserializeClsagSig(bytes, ringSize) {
  const n = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  let offset = 4;
  const s = [];
  for (let i = 0; i < n; i++) {
    s.push(bytesToHex(bytes.slice(offset, offset + 32)));
    offset += 32;
  }
  const c1 = bytesToHex(bytes.slice(offset, offset + 32)); offset += 32;
  const I = bytesToHex(bytes.slice(offset, offset + 32)); offset += 32;
  const D = bytesToHex(bytes.slice(offset, offset + 32));
  return { s, c1, I, D };
}

/**
 * Serialize CLSAG signature for WASM verification.
 * Format: [n as u32 LE][s_0..s_n][c1][I][D]
 */
function serializeClsagSig(sig) {
  const s = sig.s.map(ensureBytes);
  const n = s.length;
  const buf = new Uint8Array(4 + n * 32 + 96);
  new DataView(buf.buffer).setUint32(0, n, true);
  let offset = 4;
  for (const si of s) { buf.set(si, offset); offset += 32; }
  buf.set(ensureBytes(sig.c1), offset); offset += 32;
  buf.set(ensureBytes(sig.I), offset); offset += 32;
  buf.set(ensureBytes(sig.D), offset);
  return buf;
}

/**
 * Deserialize TCLSAG signature from WASM output.
 * Format: [n as u32 LE][sx_0..sx_n][sy_0..sy_n][c1][I][D]
 */
function deserializeTclsagSig(bytes, ringSize) {
  const n = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  let offset = 4;
  const sx = [];
  for (let i = 0; i < n; i++) { sx.push(bytesToHex(bytes.slice(offset, offset + 32))); offset += 32; }
  const sy = [];
  for (let i = 0; i < n; i++) { sy.push(bytesToHex(bytes.slice(offset, offset + 32))); offset += 32; }
  const c1 = bytesToHex(bytes.slice(offset, offset + 32)); offset += 32;
  const I = bytesToHex(bytes.slice(offset, offset + 32)); offset += 32;
  const D = bytesToHex(bytes.slice(offset, offset + 32));
  return { sx, sy, c1, I, D };
}

/**
 * Serialize TCLSAG signature for WASM verification.
 */
function serializeTclsagSig(sig) {
  const sx = sig.sx.map(ensureBytes);
  const sy = sig.sy.map(ensureBytes);
  const n = sx.length;
  const buf = new Uint8Array(4 + 2 * n * 32 + 96);
  new DataView(buf.buffer).setUint32(0, n, true);
  let offset = 4;
  for (const s of sx) { buf.set(s, offset); offset += 32; }
  for (const s of sy) { buf.set(s, offset); offset += 32; }
  buf.set(ensureBytes(sig.c1), offset); offset += 32;
  buf.set(ensureBytes(sig.I), offset); offset += 32;
  buf.set(ensureBytes(sig.D), offset);
  return buf;
}

/**
 * Deserialize BP+ prove result from WASM output.
 * Format: [v_count u32 LE][V_0..V_n 32B each][proof_bytes]
 */
function deserializeBpProveResult(bytes) {
  const vCount = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  let offset = 4;
  const V = [];
  for (let i = 0; i < vCount; i++) {
    V.push(bytes.slice(offset, offset + 32));
    offset += 32;
  }
  const proofBytes = bytes.slice(offset);
  return { V, proofBytes };
}

/**
 * Parse flat subaddress map buffer into Map<hex → {major, minor}>
 * Format: [count:u32 LE][spend_pub(32)|major(u32 LE)|minor(u32 LE)]...
 */
function _parseSubaddressMapBuffer(buf) {
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
    map.set(bytesToHex(key), { major, minor });
  }
  return map;
}

function containsBytesWasm(haystack, needle) {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
