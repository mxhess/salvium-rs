/**
 * WASM Crypto Backend
 *
 * Loads Rust-compiled WASM module and wraps it behind the unified backend interface.
 * Falls back gracefully if WASM cannot be loaded.
 *
 * @module crypto/backend-wasm
 */

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let wasmExports = null;

/**
 * Load and instantiate the WASM module from disk
 */
async function loadWasm() {
  if (wasmExports) return wasmExports;

  const wasmPath = join(__dirname, 'wasm', 'salvium_crypto_bg.wasm');
  const wasmBytes = await readFile(wasmPath);

  // Import the JS glue to get the import object and init function
  const glue = await import('./wasm/salvium_crypto.js');

  // Use initSync with the raw WASM bytes (works in Bun/Node, no fetch needed)
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
}
