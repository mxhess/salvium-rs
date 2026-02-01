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
import { hexToBytes } from '../address.js';

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

// Hash-to-point & key derivation
export function hashToPoint(data) { return getCryptoBackend().hashToPoint(data); }
export function generateKeyImage(pubKey, secKey) { return getCryptoBackend().generateKeyImage(pubKey, secKey); }
export function generateKeyDerivation(pubKey, secKey) { return getCryptoBackend().generateKeyDerivation(pubKey, secKey); }
export function derivePublicKey(derivation, outputIndex, basePub) { return getCryptoBackend().derivePublicKey(derivation, outputIndex, basePub); }
export function deriveSecretKey(derivation, outputIndex, baseSec) { return getCryptoBackend().deriveSecretKey(derivation, outputIndex, baseSec); }

// Pedersen commitments
export function commit(amount, mask) { return getCryptoBackend().commit(amount, mask); }
export function zeroCommit(amount) { return getCryptoBackend().zeroCommit(amount); }
export function genCommitmentMask(sharedSecret) { return getCryptoBackend().genCommitmentMask(sharedSecret); }

// =============================================================================
// Composite functions — built on top of backend primitives
// =============================================================================

// Aliases
export const cnFastHash = keccak256;

export function keccak256Hex(input) {
  const hash = keccak256(input);
  return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Constants
const G_BYTES = new Uint8Array([
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
]);

const T_BYTES = new Uint8Array([
  0x96, 0x6f, 0xc6, 0x6b, 0x82, 0xcd, 0x56, 0xcf,
  0x85, 0xea, 0xec, 0x80, 0x1c, 0x42, 0x84, 0x5f,
  0x5f, 0x40, 0x88, 0x78, 0xd1, 0x56, 0x1e, 0x00,
  0xd3, 0xd7, 0xde, 0xd2, 0x79, 0x4d, 0x09, 0x4f,
]);

export function getGeneratorG() { return new Uint8Array(G_BYTES); }
export function getGeneratorT() { return new Uint8Array(T_BYTES); }

export function isIdentity(p) {
  if (p[0] !== 1) return false;
  for (let i = 1; i < 32; i++) {
    if (p[i] !== 0) return false;
  }
  return true;
}

// Random scalar: generate 64 random bytes, reduce mod L
export function randomScalar() {
  let bytes64;
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    bytes64 = new Uint8Array(64);
    globalThis.crypto.getRandomValues(bytes64);
  } else {
    const { randomBytes } = require('crypto');
    bytes64 = new Uint8Array(randomBytes(64));
  }
  return scReduce64(bytes64);
}

// Varint encoding (internal helper)
function encodeVarint(n) {
  const bytes = [];
  while (n >= 0x80) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n);
  return new Uint8Array(bytes);
}

// Key derivation composites
export function derivationToScalar(derivation, outputIndex) {
  if (typeof derivation === 'string') {
    derivation = hexToBytes(derivation);
  }
  const indexBytes = encodeVarint(outputIndex);
  const input = new Uint8Array(derivation.length + indexBytes.length);
  input.set(derivation);
  input.set(indexBytes, derivation.length);
  return scReduce32(keccak256(input));
}

export function computeSharedSecret(derivation, outputIndex) {
  return derivationToScalar(derivation, outputIndex);
}

export function deriveViewTag(derivation, outputIndex) {
  if (typeof derivation === 'string') {
    derivation = hexToBytes(derivation);
  }
  const salt = new TextEncoder().encode('view_tag');
  const indexBytes = encodeVarint(outputIndex);
  const input = new Uint8Array(salt.length + derivation.length + indexBytes.length);
  input.set(salt);
  input.set(derivation, salt.length);
  input.set(indexBytes, salt.length + derivation.length);
  return keccak256(input)[0];
}

export function deriveSubaddressPublicKey(outputKey, derivation, outputIndex) {
  if (typeof outputKey === 'string') outputKey = hexToBytes(outputKey);
  if (typeof derivation === 'string') derivation = hexToBytes(derivation);
  const scalar = derivationToScalar(derivation, outputIndex);
  const scalarG = scalarMultBase(scalar);
  const scalarGNeg = new Uint8Array(scalarG);
  scalarGNeg[31] ^= 0x80;
  return pointAddCompressed(outputKey, scalarGNeg);
}

// Amount decryption
function genAmountEncodingFactor(sharedSecret) {
  const prefix = new TextEncoder().encode('amount');
  const input = new Uint8Array(prefix.length + sharedSecret.length);
  input.set(prefix);
  input.set(sharedSecret, prefix.length);
  return keccak256(input);
}

export function ecdhDecode(encryptedAmount, sharedSecret) {
  if (typeof sharedSecret === 'string') sharedSecret = hexToBytes(sharedSecret);
  const encodingFactor = genAmountEncodingFactor(sharedSecret);
  const decrypted = new Uint8Array(8);
  for (let i = 0; i < 8; i++) decrypted[i] = encryptedAmount[i] ^ encodingFactor[i];
  let amount = 0n;
  for (let i = 7; i >= 0; i--) amount = (amount << 8n) | BigInt(decrypted[i]);
  return amount;
}

export function ecdhDecodeFull(encryptedAmount, sharedSecret) {
  if (typeof sharedSecret === 'string') sharedSecret = hexToBytes(sharedSecret);
  const amount = ecdhDecode(encryptedAmount, sharedSecret);
  const mask = genCommitmentMask(sharedSecret);
  return { amount, mask };
}

export function ecdhEncode(amount, sharedSecret) {
  if (typeof sharedSecret === 'string') sharedSecret = hexToBytes(sharedSecret);
  const encodingFactor = genAmountEncodingFactor(sharedSecret);
  const amountBytes = new Uint8Array(8);
  let n = BigInt(amount);
  for (let i = 0; i < 8; i++) { amountBytes[i] = Number(n & 0xffn); n >>= 8n; }
  const encrypted = new Uint8Array(8);
  for (let i = 0; i < 8; i++) encrypted[i] = amountBytes[i] ^ encodingFactor[i];
  return encrypted;
}

// CARROT key composites
export function computeCarrotSpendPubkey(k_gi, k_ps) {
  const giG = scalarMultBase(k_gi);
  const psT = scalarMultPoint(k_ps, T_BYTES);
  return pointAddCompressed(giG, psT);
}

export function computeCarrotAccountViewPubkey(k_vi, K_s) {
  return scalarMultPoint(k_vi, K_s);
}

export function computeCarrotMainAddressViewPubkey(k_vi) {
  return scalarMultBase(k_vi);
}

// Scalar add (simple wrapper around scAdd)
export function scalarAdd(a, b) { return scAdd(a, b); }
