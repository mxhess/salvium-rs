/**
 * CARROT and CryptoNote Key Derivation Functions
 * Implements key derivation as per Salvium specification
 */

import { hexToBytes, bytesToHex } from './address.js';
import {
  blake2b, keccak256, scalarMultBase, scReduce32, scReduce64,
  computeCarrotSpendPubkey, computeCarrotMainAddressViewPubkey, computeCarrotAccountViewPubkey,
  deriveCarrotKeysBatch as _deriveKeysBatch,
  deriveCarrotViewOnlyKeysBatch as _deriveViewOnlyBatch,
} from './crypto/index.js';

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

// sc_reduce delegated to Rust backend (scReduce64 for 64-byte inputs)
function scReduce(bytes) { return scReduce64(bytes); }

// scReduce32 delegated to Rust backend via crypto/index.js

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

  // Try single-call Rust batch derivation (eliminates 10+ FFI round-trips)
  try {
    const buf = _deriveKeysBatch(masterSecret);
    if (buf && buf.length === 288) {
      return {
        masterSecret:             bytesToHex(buf.slice(0, 32)),
        proveSpendKey:            bytesToHex(buf.slice(32, 64)),
        viewBalanceSecret:        bytesToHex(buf.slice(64, 96)),
        generateImageKey:         bytesToHex(buf.slice(96, 128)),
        viewIncomingKey:          bytesToHex(buf.slice(128, 160)),
        generateAddressSecret:    bytesToHex(buf.slice(160, 192)),
        accountSpendPubkey:       bytesToHex(buf.slice(192, 224)),
        primaryAddressViewPubkey: bytesToHex(buf.slice(224, 256)),
        accountViewPubkey:        bytesToHex(buf.slice(256, 288)),
      };
    }
  } catch (_e) {
    // Fall back to JS derivation
  }

  // JS fallback — individual crypto calls
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

  // Try single-call Rust batch derivation
  try {
    const buf = _deriveViewOnlyBatch(viewBalanceSecret, accountSpendPubkey);
    if (buf && buf.length === 224) {
      return {
        viewBalanceSecret:        bytesToHex(buf.slice(0, 32)),
        viewIncomingKey:          bytesToHex(buf.slice(32, 64)),
        generateImageKey:         bytesToHex(buf.slice(64, 96)),
        generateAddressSecret:    bytesToHex(buf.slice(96, 128)),
        accountSpendPubkey:       bytesToHex(buf.slice(128, 160)),
        primaryAddressViewPubkey: bytesToHex(buf.slice(160, 192)),
        accountViewPubkey:        bytesToHex(buf.slice(192, 224)),
        isViewOnly: true,
      };
    }
  } catch (_e) {
    // Fall back to JS derivation
  }

  // JS fallback
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
