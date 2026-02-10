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

  // Point ops
  scalarMultBase(s) { return this.wasm.scalar_mult_base(s); }
  scalarMultPoint(s, p) { return this.wasm.scalar_mult_point(s, p); }
  pointAddCompressed(p, q) { return this.wasm.point_add_compressed(p, q); }
  pointSubCompressed(p, q) { return this.wasm.point_sub_compressed(p, q); }
  pointNegate(p) { return this.wasm.point_negate(p); }
  doubleScalarMultBase(a, p, b) { return this.wasm.double_scalar_mult_base(a, p, b); }

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
    return this.wasm.generate_key_derivation(pubKey, secKey);
  }
  derivePublicKey(derivation, outputIndex, basePub) { return this.wasm.derive_public_key(derivation, outputIndex, basePub); }
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

  // Oracle signature verification
  sha256(data) { return nobleSha256(data); }

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

function containsBytesWasm(haystack, needle) {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
