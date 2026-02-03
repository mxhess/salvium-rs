/**
 * WASM Crypto Backend
 *
 * Loads Rust-compiled WASM module and wraps it behind the unified backend interface.
 * Supports both Node/Bun (fs.readFile) and browser (fetch) environments.
 *
 * @module crypto/backend-wasm
 */

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
    let amountBytes = amount;
    if (typeof amount === 'bigint' || typeof amount === 'number') {
      let n = BigInt(amount);
      amountBytes = new Uint8Array(32);
      for (let i = 0; i < 32 && n > 0n; i++) {
        amountBytes[i] = Number(n & 0xffn);
        n >>= 8n;
      }
    }
    return this.wasm.zero_commit(amountBytes);
  }
  genCommitmentMask(sharedSecret) {
    if (typeof sharedSecret === 'string') {
      const hex = sharedSecret;
      sharedSecret = new Uint8Array(hex.length / 2);
      for (let i = 0; i < sharedSecret.length; i++) sharedSecret[i] = parseInt(hex.substr(i*2, 2), 16);
    }
    return this.wasm.gen_commitment_mask(sharedSecret);
  }
}
