/**
 * Crypto Provider — Switchable Backend
 *
 * Enables runtime switching between JS and WASM crypto implementations.
 * Default: JS (no async init needed). Switch to WASM for performance.
 *
 * Usage:
 *   import { setCryptoBackend, keccak256, blake2b } from './crypto/provider.js';
 *   await setCryptoBackend('wasm');  // Switch to WASM
 *   const hash = keccak256(data);    // Uses WASM backend
 *   await setCryptoBackend('js');    // Switch back to JS
 *
 * @module crypto/provider
 */

import { JsCryptoBackend } from './backend-js.js';

let currentBackend = null;
let backendType = 'js';

/**
 * Set the active crypto backend
 * @param {'js'|'wasm'} type - Backend type
 */
export async function setCryptoBackend(type) {
  if (type === 'js') {
    currentBackend = new JsCryptoBackend();
    await currentBackend.init();
  } else if (type === 'wasm') {
    // Dynamic import to avoid loading WASM unless requested
    const { WasmCryptoBackend } = await import('./backend-wasm.js');
    currentBackend = new WasmCryptoBackend();
    await currentBackend.init();
  } else {
    throw new Error(`Unknown crypto backend: ${type}. Use 'js' or 'wasm'.`);
  }
  backendType = type;
}

/**
 * Get the current crypto backend instance
 * @returns {Object} Backend with keccak256, blake2b, etc.
 */
export function getCryptoBackend() {
  if (!currentBackend) {
    // Lazy-init JS backend (sync, no await needed)
    currentBackend = new JsCryptoBackend();
  }
  return currentBackend;
}

/**
 * Get the name of the current backend
 * @returns {'js'|'wasm'}
 */
export function getCurrentBackendType() {
  return backendType;
}

// =============================================================================
// Delegating functions — use active backend transparently
// =============================================================================

export function keccak256(data) {
  return getCryptoBackend().keccak256(data);
}

export function blake2b(data, outLen, key) {
  return getCryptoBackend().blake2b(data, outLen, key);
}

// Scalar ops
export function scAdd(a, b) { return getCryptoBackend().scAdd(a, b); }
export function scSub(a, b) { return getCryptoBackend().scSub(a, b); }
export function scMul(a, b) { return getCryptoBackend().scMul(a, b); }
export function scMulAdd(a, b, c) { return getCryptoBackend().scMulAdd(a, b, c); }
export function scMulSub(a, b, c) { return getCryptoBackend().scMulSub(a, b, c); }
export function scReduce32(s) { return getCryptoBackend().scReduce32(s); }
export function scReduce64(s) { return getCryptoBackend().scReduce64(s); }
export function scInvert(a) { return getCryptoBackend().scInvert(a); }
export function scCheck(s) { return getCryptoBackend().scCheck(s); }
export function scIsZero(s) { return getCryptoBackend().scIsZero(s); }

// Point ops
export function scalarMultBase(s) { return getCryptoBackend().scalarMultBase(s); }
export function scalarMultPoint(s, p) { return getCryptoBackend().scalarMultPoint(s, p); }
export function pointAddCompressed(p, q) { return getCryptoBackend().pointAddCompressed(p, q); }
export function pointSubCompressed(p, q) { return getCryptoBackend().pointSubCompressed(p, q); }
export function pointNegate(p) { return getCryptoBackend().pointNegate(p); }
export function doubleScalarMultBase(a, p, b) { return getCryptoBackend().doubleScalarMultBase(a, p, b); }
