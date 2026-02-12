/**
 * Bun FFI Crypto Backend
 *
 * Loads the native Rust shared library (libsalvium_crypto.so) via Bun's
 * built-in FFI and wraps all C functions behind the unified backend interface.
 *
 * Requires: Bun runtime with bun:ffi support.
 *
 * Library resolution order:
 *   1. SALVIUM_CRYPTO_LIB env var (absolute path)
 *   2. crates/salvium-crypto/target/release/libsalvium_crypto.so (relative to project root)
 *
 * @module crypto/backend-ffi
 */

import { dlopen, FFIType, CString } from 'bun:ffi';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

const { ptr, i32, u32, usize } = FFIType;

// ─── Helpers ────────────────────────────────────────────────────────────────

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

function ensureBuffer(v) {
  if (typeof v === 'string') return Buffer.from(hexToBytes(v));
  if (v instanceof Buffer) return v;
  return Buffer.from(v);
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

// ─── Library path resolution ────────────────────────────────────────────────

function resolveLibPath() {
  if (process.env.SALVIUM_CRYPTO_LIB) {
    return process.env.SALVIUM_CRYPTO_LIB;
  }

  const { fileURLToPath } = require('url');
  const { dirname, join } = require('path');

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  // Navigate from src/crypto/ up to project root
  const projectRoot = join(__dirname, '..', '..');
  return join(projectRoot, 'crates', 'salvium-crypto', 'target', 'release', 'libsalvium_crypto.so');
}

// ─── FFI symbol definitions ─────────────────────────────────────────────────

const FFI_SYMBOLS = {
  // Hashing
  salvium_keccak256:       { args: [ptr, usize, ptr], returns: i32 },
  salvium_blake2b:         { args: [ptr, usize, usize, ptr], returns: i32 },
  salvium_blake2b_keyed:   { args: [ptr, usize, usize, ptr, usize, ptr], returns: i32 },
  salvium_sha256:          { args: [ptr, usize, ptr], returns: i32 },

  // Scalars
  salvium_sc_add:       { args: [ptr, ptr, ptr], returns: i32 },
  salvium_sc_sub:       { args: [ptr, ptr, ptr], returns: i32 },
  salvium_sc_mul:       { args: [ptr, ptr, ptr], returns: i32 },
  salvium_sc_mul_add:   { args: [ptr, ptr, ptr, ptr], returns: i32 },
  salvium_sc_mul_sub:   { args: [ptr, ptr, ptr, ptr], returns: i32 },
  salvium_sc_reduce32:  { args: [ptr, ptr], returns: i32 },
  salvium_sc_reduce64:  { args: [ptr, ptr], returns: i32 },
  salvium_sc_invert:    { args: [ptr, ptr], returns: i32 },
  salvium_sc_check:     { args: [ptr], returns: i32 },
  salvium_sc_is_zero:   { args: [ptr], returns: i32 },

  // Points
  salvium_scalar_mult_base:        { args: [ptr, ptr], returns: i32 },
  salvium_scalar_mult_point:       { args: [ptr, ptr, ptr], returns: i32 },
  salvium_point_add:               { args: [ptr, ptr, ptr], returns: i32 },
  salvium_point_sub:               { args: [ptr, ptr, ptr], returns: i32 },
  salvium_point_negate:            { args: [ptr, ptr], returns: i32 },
  salvium_double_scalar_mult_base: { args: [ptr, ptr, ptr, ptr], returns: i32 },

  // X25519
  salvium_x25519_scalar_mult: { args: [ptr, ptr, ptr], returns: i32 },

  // Hash-to-point & key derivation
  salvium_hash_to_point:           { args: [ptr, usize, ptr], returns: i32 },
  salvium_generate_key_derivation: { args: [ptr, ptr, ptr], returns: i32 },
  salvium_generate_key_image:      { args: [ptr, ptr, ptr], returns: i32 },
  salvium_derive_public_key:       { args: [ptr, u32, ptr, ptr], returns: i32 },
  salvium_derive_secret_key:       { args: [ptr, u32, ptr, ptr], returns: i32 },

  // Pedersen commitments
  salvium_pedersen_commit:     { args: [ptr, ptr, ptr], returns: i32 },
  salvium_zero_commit:         { args: [ptr, ptr], returns: i32 },
  salvium_gen_commitment_mask: { args: [ptr, ptr], returns: i32 },

  // Oracle signature verification
  salvium_verify_signature: { args: [ptr, usize, ptr, usize, ptr, usize], returns: i32 },

  // Key derivation
  salvium_argon2id: { args: [ptr, usize, ptr, usize, u32, u32, u32, usize, ptr], returns: i32 },

  // CLSAG
  salvium_clsag_sign:   { args: [ptr, ptr, u32, ptr, ptr, ptr, ptr, u32, ptr], returns: i32 },
  salvium_clsag_verify: { args: [ptr, ptr, usize, ptr, u32, ptr, ptr], returns: i32 },

  // TCLSAG
  salvium_tclsag_sign:   { args: [ptr, ptr, u32, ptr, ptr, ptr, ptr, ptr, u32, ptr], returns: i32 },
  salvium_tclsag_verify: { args: [ptr, ptr, usize, ptr, u32, ptr, ptr], returns: i32 },

  // BP+
  salvium_bulletproof_plus_prove:  { args: [ptr, ptr, u32, ptr, usize, ptr], returns: i32 },
  salvium_bulletproof_plus_verify: { args: [ptr, usize, ptr, u32], returns: i32 },

  // AES-256-GCM
  salvium_aes256gcm_encrypt: { args: [ptr, ptr, usize, ptr, ptr], returns: i32 },
  salvium_aes256gcm_decrypt: { args: [ptr, ptr, usize, ptr, ptr], returns: i32 },

  // CARROT scanning
  salvium_carrot_scan_output:   { args: [ptr, ptr, ptr, ptr, ptr, ptr, ptr, ptr, usize, FFIType.u64, ptr, u32, ptr, ptr], returns: i32 },
  salvium_carrot_scan_internal: { args: [ptr, ptr, ptr, ptr, ptr, ptr, ptr, ptr, usize, FFIType.u64, ptr, u32, ptr, ptr], returns: i32 },

  // Buffer management
  salvium_storage_free_buf: { args: [ptr, usize], returns: FFIType.void },
};

// ─── Backend class ──────────────────────────────────────────────────────────

export class FfiCryptoBackend {
  constructor() {
    this.name = 'ffi';
    this.lib = null;
  }

  async init() {
    const libPath = resolveLibPath();
    this.lib = dlopen(libPath, FFI_SYMBOLS);
  }

  // ─── Hashing ──────────────────────────────────────────────────────────

  keccak256(data) {
    const input = ensureBuffer(data);
    const out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_keccak256(input, input.length, out);
    if (rc !== 0) throw new Error('keccak256 failed');
    return new Uint8Array(out);
  }

  blake2b(data, outLen, key) {
    const input = ensureBuffer(data);
    const out = Buffer.alloc(outLen);
    let rc;
    if (key) {
      const keyBuf = ensureBuffer(key);
      rc = this.lib.symbols.salvium_blake2b_keyed(input, input.length, outLen, keyBuf, keyBuf.length, out);
    } else {
      rc = this.lib.symbols.salvium_blake2b(input, input.length, outLen, out);
    }
    if (rc !== 0) throw new Error('blake2b failed');
    return new Uint8Array(out);
  }

  sha256(data) {
    return nobleSha256(data);
  }

  // ─── Scalar operations ────────────────────────────────────────────────

  scAdd(a, b) {
    const ba = ensureBuffer(a), bb = ensureBuffer(b), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_sc_add(ba, bb, out);
    if (rc !== 0) throw new Error('sc_add failed');
    return new Uint8Array(out);
  }

  scSub(a, b) {
    const ba = ensureBuffer(a), bb = ensureBuffer(b), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_sc_sub(ba, bb, out);
    if (rc !== 0) throw new Error('sc_sub failed');
    return new Uint8Array(out);
  }

  scMul(a, b) {
    const ba = ensureBuffer(a), bb = ensureBuffer(b), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_sc_mul(ba, bb, out);
    if (rc !== 0) throw new Error('sc_mul failed');
    return new Uint8Array(out);
  }

  scMulAdd(a, b, c) {
    const ba = ensureBuffer(a), bb = ensureBuffer(b), bc = ensureBuffer(c), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_sc_mul_add(ba, bb, bc, out);
    if (rc !== 0) throw new Error('sc_mul_add failed');
    return new Uint8Array(out);
  }

  scMulSub(a, b, c) {
    const ba = ensureBuffer(a), bb = ensureBuffer(b), bc = ensureBuffer(c), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_sc_mul_sub(ba, bb, bc, out);
    if (rc !== 0) throw new Error('sc_mul_sub failed');
    return new Uint8Array(out);
  }

  scReduce32(s) {
    const bs = ensureBuffer(s), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_sc_reduce32(bs, out);
    if (rc !== 0) throw new Error('sc_reduce32 failed');
    return new Uint8Array(out);
  }

  scReduce64(s) {
    const bs = ensureBuffer(s), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_sc_reduce64(bs, out);
    if (rc !== 0) throw new Error('sc_reduce64 failed');
    return new Uint8Array(out);
  }

  scInvert(a) {
    const ba = ensureBuffer(a), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_sc_invert(ba, out);
    if (rc !== 0) throw new Error('sc_invert failed');
    return new Uint8Array(out);
  }

  scCheck(s) {
    const bs = ensureBuffer(s);
    return this.lib.symbols.salvium_sc_check(bs) === 1;
  }

  scIsZero(s) {
    const bs = ensureBuffer(s);
    return this.lib.symbols.salvium_sc_is_zero(bs) === 1;
  }

  // ─── Point operations ─────────────────────────────────────────────────

  scalarMultBase(s) {
    const bs = ensureBuffer(s), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_scalar_mult_base(bs, out);
    if (rc !== 0) throw new Error('scalar_mult_base failed');
    return new Uint8Array(out);
  }

  scalarMultPoint(s, p) {
    const bs = ensureBuffer(s), bp = ensureBuffer(p), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_scalar_mult_point(bs, bp, out);
    if (rc !== 0) return null; // invalid point
    return new Uint8Array(out);
  }

  pointAddCompressed(p, q) {
    const bp = ensureBuffer(p), bq = ensureBuffer(q), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_point_add(bp, bq, out);
    if (rc !== 0) return null; // invalid point
    return new Uint8Array(out);
  }

  pointSubCompressed(p, q) {
    const bp = ensureBuffer(p), bq = ensureBuffer(q), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_point_sub(bp, bq, out);
    if (rc !== 0) return null; // invalid point
    return new Uint8Array(out);
  }

  pointNegate(p) {
    const bp = ensureBuffer(p), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_point_negate(bp, out);
    if (rc !== 0) return null; // invalid point
    return new Uint8Array(out);
  }

  doubleScalarMultBase(a, p, b) {
    const ba = ensureBuffer(a), bp = ensureBuffer(p), bb = ensureBuffer(b), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_double_scalar_mult_base(ba, bp, bb, out);
    if (rc !== 0) return null; // invalid point
    return new Uint8Array(out);
  }

  // ─── X25519 ───────────────────────────────────────────────────────────

  x25519ScalarMult(scalar, uCoord) {
    const bs = ensureBuffer(scalar), bu = ensureBuffer(uCoord), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_x25519_scalar_mult(bs, bu, out);
    if (rc !== 0) throw new Error('x25519_scalar_mult failed');
    return new Uint8Array(out);
  }

  // ─── Hash-to-point & key derivation ───────────────────────────────────

  hashToPoint(data) {
    const input = ensureBuffer(data);
    const out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_hash_to_point(input, input.length, out);
    if (rc !== 0) throw new Error('hash_to_point failed');
    return new Uint8Array(out);
  }

  generateKeyDerivation(pubKey, secKey) {
    if (typeof pubKey === 'string') pubKey = hexToBytes(pubKey);
    if (typeof secKey === 'string') secKey = hexToBytes(secKey);
    const bPub = ensureBuffer(pubKey), bSec = ensureBuffer(secKey), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_generate_key_derivation(bPub, bSec, out);
    if (rc !== 0) return null; // invalid pub key
    return new Uint8Array(out);
  }

  generateKeyImage(pubKey, secKey) {
    if (typeof pubKey === 'string') pubKey = hexToBytes(pubKey);
    if (typeof secKey === 'string') secKey = hexToBytes(secKey);
    const bPub = ensureBuffer(pubKey), bSec = ensureBuffer(secKey), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_generate_key_image(bPub, bSec, out);
    if (rc !== 0) throw new Error('generate_key_image failed');
    return new Uint8Array(out);
  }

  derivePublicKey(derivation, outputIndex, basePub) {
    const bDeriv = ensureBuffer(derivation), bBase = ensureBuffer(basePub), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_derive_public_key(bDeriv, outputIndex, bBase, out);
    if (rc !== 0) return null; // invalid base pub key
    return new Uint8Array(out);
  }

  deriveSecretKey(derivation, outputIndex, baseSec) {
    const bDeriv = ensureBuffer(derivation), bBase = ensureBuffer(baseSec), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_derive_secret_key(bDeriv, outputIndex, bBase, out);
    if (rc !== 0) throw new Error('derive_secret_key failed');
    return new Uint8Array(out);
  }

  // ─── Pedersen commitments ─────────────────────────────────────────────

  commit(amount, mask) {
    let amountBytes = amount;
    if (typeof amount === 'bigint' || typeof amount === 'number') {
      let n = BigInt(amount);
      amountBytes = new Uint8Array(32);
      for (let i = 0; i < 32 && n > 0n; i++) {
        amountBytes[i] = Number(n & 0xffn);
        n >>= 8n;
      }
    }
    if (typeof mask === 'string') {
      mask = hexToBytes(mask);
    }
    const bAmt = ensureBuffer(amountBytes), bMask = ensureBuffer(mask), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_pedersen_commit(bAmt, bMask, out);
    if (rc !== 0) throw new Error('pedersen_commit failed');
    return new Uint8Array(out);
  }

  zeroCommit(amount) {
    // Salvium rct::zeroCommit uses blinding factor = 1 (not 0).
    // Match the WASM backend behavior.
    const scalarOne = new Uint8Array(32);
    scalarOne[0] = 1;
    return this.commit(amount, scalarOne);
  }

  genCommitmentMask(sharedSecret) {
    if (typeof sharedSecret === 'string') {
      sharedSecret = hexToBytes(sharedSecret);
    }
    const bSecret = ensureBuffer(sharedSecret), out = Buffer.alloc(32);
    const rc = this.lib.symbols.salvium_gen_commitment_mask(bSecret, out);
    if (rc !== 0) throw new Error('gen_commitment_mask failed');
    return new Uint8Array(out);
  }

  // ─── Oracle signature verification ────────────────────────────────────

  async verifySignature(message, signature, pubkeyDer) {
    const bMsg = ensureBuffer(message);
    const bSig = ensureBuffer(signature);
    const bKey = ensureBuffer(pubkeyDer);
    const rc = this.lib.symbols.salvium_verify_signature(
      bMsg, bMsg.length, bSig, bSig.length, bKey, bKey.length
    );
    return rc === 1;
  }

  // ─── Key derivation ───────────────────────────────────────────────────

  argon2id(password, salt, opts) {
    const bPass = ensureBuffer(password);
    const bSalt = ensureBuffer(salt);
    const outLen = opts.dkLen || 32;
    const out = Buffer.alloc(outLen);
    const rc = this.lib.symbols.salvium_argon2id(
      bPass, bPass.length,
      bSalt, bSalt.length,
      opts.t, opts.m, opts.p,
      outLen, out
    );
    if (rc !== 0) throw new Error('argon2id failed');
    return new Uint8Array(out);
  }

  // ─── CLSAG Ring Signatures ────────────────────────────────────────────

  clsagSign(message, ring, secretKey, commitments, commitmentMask, pseudoOutput, secretIndex) {
    const bMsg = ensureBuffer(message);
    const ringFlat = ensureBuffer(flattenArrayOf32(ring));
    const bSk = ensureBuffer(secretKey);
    const commFlat = ensureBuffer(flattenArrayOf32(commitments));
    const bCm = ensureBuffer(commitmentMask);
    const bPo = ensureBuffer(pseudoOutput);
    const n = ring.length;
    const outSize = n * 32 + 96;
    const out = Buffer.alloc(outSize);

    const rc = this.lib.symbols.salvium_clsag_sign(
      bMsg, ringFlat, n, bSk, commFlat, bCm, bPo, secretIndex, out
    );
    if (rc !== 0) throw new Error('clsag_sign failed');

    // Parse: s[0..n], c1, I, D
    let offset = 0;
    const s = [];
    for (let i = 0; i < n; i++) {
      s.push(bytesToHex(out.slice(offset, offset + 32)));
      offset += 32;
    }
    const c1 = bytesToHex(out.slice(offset, offset + 32)); offset += 32;
    const I = bytesToHex(out.slice(offset, offset + 32)); offset += 32;
    const D = bytesToHex(out.slice(offset, offset + 32));
    return { s, c1, I, D };
  }

  clsagVerify(message, sig, ring, commitments, pseudoOutput) {
    const bMsg = ensureBuffer(message);
    const n = ring.length;
    const ringFlat = ensureBuffer(flattenArrayOf32(ring));
    const commFlat = ensureBuffer(flattenArrayOf32(commitments));
    const bPo = ensureBuffer(pseudoOutput);

    // Serialize sig: s[0..n], c1, I, D (no length prefix for FFI)
    const sigSize = n * 32 + 96;
    const sigBuf = Buffer.alloc(sigSize);
    let offset = 0;
    for (const si of sig.s) {
      sigBuf.set(ensureBytes(si), offset);
      offset += 32;
    }
    sigBuf.set(ensureBytes(sig.c1), offset); offset += 32;
    sigBuf.set(ensureBytes(sig.I), offset); offset += 32;
    sigBuf.set(ensureBytes(sig.D), offset);

    const rc = this.lib.symbols.salvium_clsag_verify(
      bMsg, sigBuf, sigSize, ringFlat, n, commFlat, bPo
    );
    return rc === 1;
  }

  // ─── TCLSAG Ring Signatures ───────────────────────────────────────────

  tclsagSign(message, ring, secretKeyX, secretKeyY, commitments, commitmentMask, pseudoOutput, secretIndex) {
    const bMsg = ensureBuffer(message);
    const ringFlat = ensureBuffer(flattenArrayOf32(ring));
    const bSkx = ensureBuffer(secretKeyX);
    const bSky = ensureBuffer(secretKeyY);
    const commFlat = ensureBuffer(flattenArrayOf32(commitments));
    const bCm = ensureBuffer(commitmentMask);
    const bPo = ensureBuffer(pseudoOutput);
    const n = ring.length;
    const outSize = 2 * n * 32 + 96;
    const out = Buffer.alloc(outSize);

    const rc = this.lib.symbols.salvium_tclsag_sign(
      bMsg, ringFlat, n, bSkx, bSky, commFlat, bCm, bPo, secretIndex, out
    );
    if (rc !== 0) throw new Error('tclsag_sign failed');

    // Parse: sx[0..n], sy[0..n], c1, I, D
    let offset = 0;
    const sx = [];
    for (let i = 0; i < n; i++) { sx.push(bytesToHex(out.slice(offset, offset + 32))); offset += 32; }
    const sy = [];
    for (let i = 0; i < n; i++) { sy.push(bytesToHex(out.slice(offset, offset + 32))); offset += 32; }
    const c1 = bytesToHex(out.slice(offset, offset + 32)); offset += 32;
    const I = bytesToHex(out.slice(offset, offset + 32)); offset += 32;
    const D = bytesToHex(out.slice(offset, offset + 32));
    return { sx, sy, c1, I, D };
  }

  tclsagVerify(message, sig, ring, commitments, pseudoOutput) {
    const bMsg = ensureBuffer(message);
    const n = ring.length;
    const ringFlat = ensureBuffer(flattenArrayOf32(ring));
    const commFlat = ensureBuffer(flattenArrayOf32(commitments));
    const bPo = ensureBuffer(pseudoOutput);

    // Serialize sig: sx[0..n], sy[0..n], c1, I, D
    const sigSize = 2 * n * 32 + 96;
    const sigBuf = Buffer.alloc(sigSize);
    let offset = 0;
    for (const s of sig.sx) { sigBuf.set(ensureBytes(s), offset); offset += 32; }
    for (const s of sig.sy) { sigBuf.set(ensureBytes(s), offset); offset += 32; }
    sigBuf.set(ensureBytes(sig.c1), offset); offset += 32;
    sigBuf.set(ensureBytes(sig.I), offset); offset += 32;
    sigBuf.set(ensureBytes(sig.D), offset);

    const rc = this.lib.symbols.salvium_tclsag_verify(
      bMsg, sigBuf, sigSize, ringFlat, n, commFlat, bPo
    );
    return rc === 1;
  }

  // ─── Bulletproofs+ Range Proofs ───────────────────────────────────────

  bulletproofPlusProve(amounts, masks) {
    const amountBytes = ensureBuffer(serializeAmounts(amounts));
    const masksFlat = ensureBuffer(flattenArrayOf32(masks));
    const count = amounts.length;
    const outMax = 8192; // generous upper bound
    const out = Buffer.alloc(outMax);
    const outLenBuf = Buffer.alloc(8); // size_t = 8 bytes on 64-bit

    const rc = this.lib.symbols.salvium_bulletproof_plus_prove(
      amountBytes, masksFlat, count, out, outMax, outLenBuf
    );
    if (rc !== 0) throw new Error('bulletproof_plus_prove failed');

    // Read actual output length (native size_t, 8 bytes LE on 64-bit)
    const actualLen = Number(outLenBuf.readBigUInt64LE(0));
    const result = new Uint8Array(out.slice(0, actualLen));

    // Parse: [v_count u32 LE][V_0..V_n 32B each][proof_bytes]
    const vCount = result[0] | (result[1] << 8) | (result[2] << 16) | (result[3] << 24);
    let off = 4;
    const V = [];
    for (let i = 0; i < vCount; i++) {
      V.push(result.slice(off, off + 32));
      off += 32;
    }
    const proofBytes = result.slice(off);
    return { V, proofBytes };
  }

  bulletproofPlusVerify(commitmentBytes, proofBytes) {
    const commFlat = ensureBuffer(flattenArrayOf32(commitmentBytes));
    const bProof = ensureBuffer(proofBytes);
    const rc = this.lib.symbols.salvium_bulletproof_plus_verify(
      bProof, bProof.length, commFlat, commitmentBytes.length
    );
    return rc === 1;
  }

  // ─── AES-256-GCM Encryption ─────────────────────────────────────────────

  aes256gcmEncrypt(key, plaintext) {
    const bKey = ensureBuffer(key);
    const bPlain = ensureBuffer(plaintext);
    const outSize = bPlain.length + 28; // nonce(12) + ciphertext + tag(16)
    const out = Buffer.alloc(outSize);
    const outLenBuf = Buffer.alloc(8); // size_t = 8 bytes on 64-bit
    const rc = this.lib.symbols.salvium_aes256gcm_encrypt(
      bKey, bPlain, bPlain.length, out, outLenBuf
    );
    if (rc !== 0) throw new Error('aes256gcm_encrypt failed');
    const actualLen = Number(outLenBuf.readBigUInt64LE(0));
    return new Uint8Array(out.slice(0, actualLen));
  }

  aes256gcmDecrypt(key, ciphertext) {
    const bKey = ensureBuffer(key);
    const bCipher = ensureBuffer(ciphertext);
    if (bCipher.length < 28) throw new Error('ciphertext too short');
    const outSize = bCipher.length - 28;
    const out = Buffer.alloc(outSize);
    const outLenBuf = Buffer.alloc(8);
    const rc = this.lib.symbols.salvium_aes256gcm_decrypt(
      bKey, bCipher, bCipher.length, out, outLenBuf
    );
    if (rc !== 0) throw new Error('aes256gcm_decrypt failed (authentication or key error)');
    const actualLen = Number(outLenBuf.readBigUInt64LE(0));
    return new Uint8Array(out.slice(0, actualLen));
  }

  // ─── CARROT Output Scanning ──────────────────────────────────────────────

  /**
   * Scan a CARROT output using the native Rust pipeline (single FFI call).
   * Returns scan result object or null if not owned.
   */
  scanCarrotOutput(ko, viewTag, dE, encAmount, commitment, kVi, accountSpendPubkey, inputContext, subaddressMap, clearTextAmount) {
    return this._carrotScan(
      'salvium_carrot_scan_output',
      ko, viewTag, dE, encAmount, commitment,
      kVi, accountSpendPubkey, inputContext,
      subaddressMap, clearTextAmount
    );
  }

  /**
   * Scan a CARROT output using the self-send (internal) path.
   * viewBalanceSecret is used directly as s_sr_unctx (no X25519 ECDH).
   */
  scanCarrotInternalOutput(ko, viewTag, dE, encAmount, commitment, viewBalanceSecret, accountSpendPubkey, inputContext, subaddressMap, clearTextAmount) {
    return this._carrotScan(
      'salvium_carrot_scan_internal',
      ko, viewTag, dE, encAmount, commitment,
      viewBalanceSecret, accountSpendPubkey, inputContext,
      subaddressMap, clearTextAmount
    );
  }

  /** @private Shared implementation for both scan paths. */
  _carrotScan(symbolName, ko, viewTag, dE, encAmount, commitment, secretKey, accountSpendPubkey, inputContext, subaddressMap, clearTextAmount) {
    const bKo = ensureBuffer(ko);
    const bVt = ensureBuffer(viewTag);
    const bDe = ensureBuffer(dE);
    const bEnc = ensureBuffer(encAmount || new Uint8Array(8));
    const bCommit = commitment ? ensureBuffer(commitment) : null;
    const bSk = ensureBuffer(secretKey);
    const bKs = ensureBuffer(accountSpendPubkey);
    const bIc = ensureBuffer(inputContext);

    // Encode clear text amount: u64::MAX (0xFFFFFFFFFFFFFFFF) means "not provided"
    const ctAmount = (clearTextAmount !== undefined && clearTextAmount !== null)
      ? BigInt(clearTextAmount)
      : 0xFFFFFFFFFFFFFFFFn;

    // Marshal subaddress map: each entry = 32-byte key + 4-byte major LE + 4-byte minor LE
    let subBuf, nSub;
    if (subaddressMap && subaddressMap.size > 0) {
      nSub = subaddressMap.size;
      subBuf = Buffer.alloc(nSub * 40);
      let offset = 0;
      for (const [hexKey, { major, minor }] of subaddressMap) {
        const keyBytes = hexToBytes(hexKey);
        subBuf.set(keyBytes, offset); offset += 32;
        subBuf.writeUInt32LE(major, offset); offset += 4;
        subBuf.writeUInt32LE(minor, offset); offset += 4;
      }
    } else {
      nSub = 0;
      subBuf = Buffer.alloc(0);
    }

    // Rust-allocated output pointers
    const outPtrBuf = Buffer.alloc(8); // *mut u8
    const outLenBuf = Buffer.alloc(8); // usize

    const rc = this.lib.symbols[symbolName](
      bKo, bVt, bDe, bEnc,
      bCommit,         // nullable
      bSk, bKs, bIc, bIc.length,
      ctAmount,
      subBuf, nSub,
      outPtrBuf, outLenBuf
    );

    if (rc === 0) return null;  // Not owned
    if (rc < 0) throw new Error(`${symbolName} failed`);

    // Read JSON from Rust-allocated buffer using CString (safe before free)
    const resultPtr = Number(outPtrBuf.readBigUInt64LE(0));
    const resultLen = Number(outLenBuf.readBigUInt64LE(0));
    const jsonStr = new CString(resultPtr, 0, resultLen).toString();

    // Free Rust-allocated buffer
    this.lib.symbols.salvium_storage_free_buf(resultPtr, resultLen);

    const result = JSON.parse(jsonStr);

    return {
      owned: true,
      onetimeAddress: bytesToHex(ko),
      addressSpendPubkey: result.address_spend_pubkey,
      sharedSecret: result.shared_secret,
      amount: BigInt(result.amount),
      mask: hexToBytes(result.mask),
      enoteType: result.enote_type,
      subaddressIndex: { major: result.subaddress_major, minor: result.subaddress_minor },
      isMainAddress: result.is_main_address,
      isCarrot: true,
    };
  }
}
