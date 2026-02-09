/**
 * CARROT and CryptoNote Key Derivation Functions
 * Implements key derivation as per Salvium specification
 */

import { hexToBytes, bytesToHex } from './address.js';
import {
  blake2b, keccak256, scalarMultBase,
  computeCarrotSpendPubkey, computeCarrotMainAddressViewPubkey, computeCarrotAccountViewPubkey,
} from './crypto/index.js';

// Group order L for scalar reduction
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

// Create length-prefixed domain separator (matches Salvium SpFixedTranscript format)
function makeDomainSep(str) {
  const strBytes = new TextEncoder().encode(str);
  const result = new Uint8Array(1 + strBytes.length);
  result[0] = strBytes.length;  // Length prefix
  result.set(strBytes, 1);
  return result;
}

// Domain separators (from Salvium carrot_core/config.h)
// Each is length-prefixed as per SpFixedTranscript format
const DOMAIN_SEP = {
  PROVE_SPEND_KEY: makeDomainSep("Carrot prove-spend key"),
  VIEW_BALANCE_SECRET: makeDomainSep("Carrot view-balance secret"),
  GENERATE_IMAGE_KEY: makeDomainSep("Carrot generate-image key"),
  INCOMING_VIEW_KEY: makeDomainSep("Carrot incoming view key"),
  GENERATE_ADDRESS_SECRET: makeDomainSep("Carrot generate-address secret")
};

/**
 * Reduce a 64-byte value modulo L (curve order)
 * This is sc_reduce from ref10
 * @param {Uint8Array} bytes - 64 bytes to reduce
 * @returns {Uint8Array} 32-byte scalar
 */
function scReduce(bytes) {
  // Convert 64 bytes to BigInt (little-endian)
  let n = 0n;
  for (let i = 63; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }

  // Reduce mod L
  n = n % L;

  // Convert back to 32 bytes (little-endian)
  const result = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    result[i] = Number(n & 0xffn);
    n = n >> 8n;
  }

  return result;
}

/**
 * Reduce a 32-byte value modulo L (curve order)
 * This is sc_reduce32 from ref10
 * @param {Uint8Array} bytes - 32 bytes to reduce
 * @returns {Uint8Array} 32-byte scalar
 */
function scReduce32(bytes) {
  // Convert 32 bytes to BigInt (little-endian)
  let n = 0n;
  for (let i = 31; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }

  // Reduce mod L
  n = n % L;

  // Convert back to 32 bytes (little-endian)
  const result = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    result[i] = Number(n & 0xffn);
    n = n >> 8n;
  }

  return result;
}

// ============================================================================
// Seed Generation
// ============================================================================

/**
 * Generate a cryptographically secure random seed
 * @returns {Uint8Array} 32-byte random seed
 */
export function generateSeed() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return seed;
}

// ============================================================================
// CryptoNote (Legacy) Key Derivation
// ============================================================================

/**
 * Derive CryptoNote wallet keys from seed
 *
 * From account.cpp:
 * - spend_secret_key = seed (reduced to scalar)
 * - spend_public_key = spend_secret_key * G
 * - view_secret_key = keccak256(spend_secret_key), reduced to scalar
 * - view_public_key = view_secret_key * G
 *
 * @param {Uint8Array|string} seed - 32-byte seed or hex string
 * @returns {Object} { spendSecretKey, spendPublicKey, viewSecretKey, viewPublicKey }
 */
export function deriveKeys(seed) {
  // Convert hex string to bytes if needed
  if (typeof seed === 'string') {
    seed = hexToBytes(seed);
  }

  if (seed.length !== 32) {
    throw new Error('Seed must be 32 bytes');
  }

  // Spend secret key = seed, reduced to scalar mod L
  const spendSecretKey = scReduce32(seed);

  // Spend public key = spend_secret_key * G
  const spendPublicKey = scalarMultBase(spendSecretKey);

  // View secret key = H(spend_secret_key), reduced to scalar
  const viewSecretHash = keccak256(spendSecretKey);
  const viewSecretKey = scReduce32(viewSecretHash);

  // View public key = view_secret_key * G
  const viewPublicKey = scalarMultBase(viewSecretKey);

  return {
    spendSecretKey,
    spendPublicKey,
    viewSecretKey,
    viewPublicKey
  };
}

// ============================================================================
// CARROT Key Derivation
// ============================================================================

/**
 * H_32: 32-byte keyed hash
 * @param {Uint8Array} domainSep - Domain separator
 * @param {Uint8Array} key - 32-byte key
 * @returns {Uint8Array} 32-byte hash
 */
function deriveBytes32(domainSep, key) {
  return blake2b(domainSep, 32, key);
}

/**
 * H_n: Scalar derivation (hash to 64 bytes, then reduce mod L)
 * @param {Uint8Array} domainSep - Domain separator
 * @param {Uint8Array} key - 32-byte key
 * @returns {Uint8Array} 32-byte scalar
 */
function deriveScalar(domainSep, key) {
  const hash64 = blake2b(domainSep, 64, key);
  return scReduce(hash64);
}

/**
 * Derive view-balance secret from master secret
 * s_vb = H_32("Carrot view-balance secret", s_master)
 * @param {Uint8Array} masterSecret - 32-byte master secret (spend key)
 * @returns {Uint8Array} 32-byte view-balance secret
 */
export function makeViewBalanceSecret(masterSecret) {
  return deriveBytes32(DOMAIN_SEP.VIEW_BALANCE_SECRET, masterSecret);
}

/**
 * Derive view-incoming key from view-balance secret
 * k_vi = H_n("Carrot incoming view key", s_vb)
 * @param {Uint8Array} viewBalanceSecret - 32-byte view-balance secret
 * @returns {Uint8Array} 32-byte view-incoming key
 */
export function makeViewIncomingKey(viewBalanceSecret) {
  return deriveScalar(DOMAIN_SEP.INCOMING_VIEW_KEY, viewBalanceSecret);
}

/**
 * Derive prove-spend key from master secret
 * k_ps = H_n("Carrot prove-spend key", s_master)
 * @param {Uint8Array} masterSecret - 32-byte master secret
 * @returns {Uint8Array} 32-byte prove-spend key
 */
export function makeProveSpendKey(masterSecret) {
  return deriveScalar(DOMAIN_SEP.PROVE_SPEND_KEY, masterSecret);
}

/**
 * Derive generate-image key from view-balance secret
 * k_gi = H_n("Carrot generate-image key", s_vb)
 * @param {Uint8Array} viewBalanceSecret - 32-byte view-balance secret
 * @returns {Uint8Array} 32-byte generate-image key
 */
export function makeGenerateImageKey(viewBalanceSecret) {
  return deriveScalar(DOMAIN_SEP.GENERATE_IMAGE_KEY, viewBalanceSecret);
}

/**
 * Derive generate-address secret from view-balance secret
 * s_ga = H_32("Carrot generate-address secret", s_vb)
 * @param {Uint8Array} viewBalanceSecret - 32-byte view-balance secret
 * @returns {Uint8Array} 32-byte generate-address secret
 */
export function makeGenerateAddressSecret(viewBalanceSecret) {
  return deriveBytes32(DOMAIN_SEP.GENERATE_ADDRESS_SECRET, viewBalanceSecret);
}

/**
 * Derive all CARROT keys from master secret
 * @param {Uint8Array|string} masterSecret - 32-byte master secret or hex string
 * @returns {Object} All derived keys as hex strings
 */
export function deriveCarrotKeys(masterSecret) {
  // Convert hex string to bytes if needed
  if (typeof masterSecret === 'string') {
    masterSecret = hexToBytes(masterSecret);
  }

  // Derive account secrets
  const viewBalanceSecret = makeViewBalanceSecret(masterSecret);
  const proveSpendKey = makeProveSpendKey(masterSecret);
  const viewIncomingKey = makeViewIncomingKey(viewBalanceSecret);
  const generateImageKey = makeGenerateImageKey(viewBalanceSecret);
  const generateAddressSecret = makeGenerateAddressSecret(viewBalanceSecret);

  // Compute account pubkeys
  // K_s = k_gi * G + k_ps * T
  const accountSpendPubkey = computeCarrotSpendPubkey(generateImageKey, proveSpendKey);
  // K^0_v = k_vi * G (primary address view pubkey - for main address)
  const primaryAddressViewPubkey = computeCarrotMainAddressViewPubkey(viewIncomingKey);
  // K_v = k_vi * K_s (account view pubkey - for subaddress derivation)
  const accountViewPubkey = computeCarrotAccountViewPubkey(viewIncomingKey, accountSpendPubkey);

  return {
    // Account secrets
    masterSecret: bytesToHex(masterSecret),
    proveSpendKey: bytesToHex(proveSpendKey),
    viewBalanceSecret: bytesToHex(viewBalanceSecret),
    generateImageKey: bytesToHex(generateImageKey),
    viewIncomingKey: bytesToHex(viewIncomingKey),
    generateAddressSecret: bytesToHex(generateAddressSecret),
    // Account pubkeys (for address generation)
    accountSpendPubkey: bytesToHex(accountSpendPubkey),
    primaryAddressViewPubkey: bytesToHex(primaryAddressViewPubkey),
    accountViewPubkey: bytesToHex(accountViewPubkey)
  };
}

/**
 * Derive CARROT keys for view-only wallet from view-balance secret
 * Requires account spend pubkey to be provided (can't be derived from s_vb)
 * @param {Uint8Array|string} viewBalanceSecret - 32-byte view-balance secret or hex string
 * @param {Uint8Array|string} accountSpendPubkey - 32-byte account spend pubkey or hex string
 * @returns {Object} Derived keys for view-only scanning
 */
export function deriveCarrotViewOnlyKeys(viewBalanceSecret, accountSpendPubkey) {
  // Convert hex string to bytes if needed
  if (typeof viewBalanceSecret === 'string') {
    viewBalanceSecret = hexToBytes(viewBalanceSecret);
  }
  if (typeof accountSpendPubkey === 'string') {
    accountSpendPubkey = hexToBytes(accountSpendPubkey);
  }

  // Derive keys from view-balance secret
  const viewIncomingKey = makeViewIncomingKey(viewBalanceSecret);
  const generateImageKey = makeGenerateImageKey(viewBalanceSecret);
  const generateAddressSecret = makeGenerateAddressSecret(viewBalanceSecret);

  // Compute account view pubkey: K_v = k_vi * K_s
  const accountViewPubkey = computeCarrotAccountViewPubkey(viewIncomingKey, accountSpendPubkey);
  // Primary address view pubkey: K^0_v = k_vi * G
  const primaryAddressViewPubkey = computeCarrotMainAddressViewPubkey(viewIncomingKey);

  return {
    // Secrets (view-only subset)
    viewBalanceSecret: bytesToHex(viewBalanceSecret),
    viewIncomingKey: bytesToHex(viewIncomingKey),
    generateImageKey: bytesToHex(generateImageKey),
    generateAddressSecret: bytesToHex(generateAddressSecret),
    // Pubkeys
    accountSpendPubkey: bytesToHex(accountSpendPubkey),
    primaryAddressViewPubkey: bytesToHex(primaryAddressViewPubkey),
    accountViewPubkey: bytesToHex(accountViewPubkey),
    // Flag
    isViewOnly: true
  };
}

export default {
  generateSeed,
  deriveKeys,
  makeViewBalanceSecret,
  makeViewIncomingKey,
  makeProveSpendKey,
  makeGenerateImageKey,
  makeGenerateAddressSecret,
  deriveCarrotKeys,
  deriveCarrotViewOnlyKeys
};
