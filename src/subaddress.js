/**
 * Subaddress and Integrated Address Generation
 *
 * Implements both CryptoNote (legacy) and CARROT subaddress derivation,
 * plus integrated address creation.
 */

import {
  keccak256, blake2b,
  scalarMultBase, scalarMultPoint, pointAddCompressed,
  cnSubaddressMapBatch as _cnBatch,
  carrotSubaddressMapBatch as _carrotBatch,
} from './crypto/index.js';

// Group order L for scalar reduction
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

/**
 * Reduce a 32-byte hash to a scalar mod L
 * @param {Uint8Array} bytes - 32 bytes
 * @returns {Uint8Array} 32-byte scalar
 */
function scReduce32(bytes) {
  // Convert to BigInt (little-endian)
  let n = 0n;
  for (let i = 31; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }

  // Reduce mod L
  n = n % L;

  // Convert back to bytes (little-endian)
  const result = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    result[i] = Number(n & 0xffn);
    n = n >> 8n;
  }

  return result;
}

/**
 * Hash to scalar using Keccak256
 * H_s(data) = Keccak256(data) mod L
 * @param {Uint8Array} data - Input data
 * @returns {Uint8Array} 32-byte scalar
 */
function hashToScalar(data) {
  const hash = keccak256(data);
  return scReduce32(hash);
}

/**
 * Write uint32 as little-endian bytes
 * @param {number} value - 32-bit unsigned integer
 * @returns {Uint8Array} 4 bytes
 */
function uint32ToLE(value) {
  const result = new Uint8Array(4);
  result[0] = value & 0xff;
  result[1] = (value >> 8) & 0xff;
  result[2] = (value >> 16) & 0xff;
  result[3] = (value >> 24) & 0xff;
  return result;
}

// ============================================================================
// CryptoNote (Legacy) Subaddress Derivation
// ============================================================================

/**
 * Derive CryptoNote subaddress secret key
 * m = H_s("SubAddr" || k_view || major || minor)
 *
 * @param {Uint8Array} viewSecretKey - 32-byte view secret key
 * @param {number} major - Major index (account)
 * @param {number} minor - Minor index (address within account)
 * @returns {Uint8Array} 32-byte subaddress secret key
 */
export function cnSubaddressSecretKey(viewSecretKey, major, minor) {
  // Domain separator: "SubAddr\0" (8 bytes, INCLUDING null terminator)
  // Salvium uses sizeof(HASH_KEY_SUBADDRESS) which includes the null byte
  const domainSep = new Uint8Array([0x53, 0x75, 0x62, 0x41, 0x64, 0x64, 0x72, 0x00]); // "SubAddr\0"

  // Build data: "SubAddr\0" || k_view || major_LE || minor_LE
  const data = new Uint8Array(8 + 32 + 4 + 4);
  data.set(domainSep, 0);
  data.set(viewSecretKey, 8);
  data.set(uint32ToLE(major), 8 + 32);
  data.set(uint32ToLE(minor), 8 + 32 + 4);

  return hashToScalar(data);
}

/**
 * Generate CryptoNote subaddress spend public key
 * D = K_spend + m*G
 *
 * @param {Uint8Array} spendPublicKey - 32-byte main spend public key
 * @param {Uint8Array} viewSecretKey - 32-byte view secret key
 * @param {number} major - Major index
 * @param {number} minor - Minor index
 * @returns {Uint8Array} 32-byte subaddress spend public key
 */
export function cnSubaddressSpendPublicKey(spendPublicKey, viewSecretKey, major, minor) {
  // Main address (0,0) returns the original spend key
  if (major === 0 && minor === 0) {
    return new Uint8Array(spendPublicKey);
  }

  // m = H_s("SubAddr" || k_view || major || minor)
  const m = cnSubaddressSecretKey(viewSecretKey, major, minor);

  // M = m * G
  const M = scalarMultBase(m);

  // D = K_spend + M
  const D = pointAddCompressed(spendPublicKey, M);
  return D;
}

/**
 * Generate CryptoNote subaddress (both spend and view public keys)
 *
 * @param {Uint8Array} spendPublicKey - 32-byte main spend public key
 * @param {Uint8Array} viewSecretKey - 32-byte view secret key
 * @param {number} major - Major index
 * @param {number} minor - Minor index
 * @returns {Object} { spendPublicKey, viewPublicKey }
 */
export function cnSubaddress(spendPublicKey, viewSecretKey, major, minor) {
  // Main address (0,0)
  if (major === 0 && minor === 0) {
    const viewPublicKey = scalarMultBase(viewSecretKey);
    return {
      spendPublicKey: new Uint8Array(spendPublicKey),
      viewPublicKey
    };
  }

  // D = subaddress spend public key
  const D = cnSubaddressSpendPublicKey(spendPublicKey, viewSecretKey, major, minor);

  // C = k_view * D
  const C = scalarMultPoint(viewSecretKey, D);

  return {
    spendPublicKey: D,
    viewPublicKey: C
  };
}

// ============================================================================
// CARROT Subaddress Derivation
// ============================================================================

// Domain separators (length-prefixed as per SpFixedTranscript)
function makeDomainSep(str) {
  const strBytes = new TextEncoder().encode(str);
  const result = new Uint8Array(1 + strBytes.length);
  result[0] = strBytes.length;
  result.set(strBytes, 1);
  return result;
}

const CARROT_DOMAIN_SEP = {
  ADDRESS_INDEX_GEN: makeDomainSep("Carrot address index generator"),
  SUBADDRESS_SCALAR: makeDomainSep("Carrot subaddress scalar")
};

/**
 * Derive bytes using Blake2b with key
 * @param {Uint8Array} domainSep - Domain separator
 * @param {Uint8Array} key - 32-byte key
 * @returns {Uint8Array} 32-byte output
 */
function deriveBytes32(domainSep, key) {
  return blake2b(domainSep, 32, key);
}

/**
 * Derive scalar using Blake2b (hash to 64 bytes, then reduce)
 * @param {Uint8Array} domainSep - Domain separator
 * @param {Uint8Array} key - 32-byte key
 * @returns {Uint8Array} 32-byte scalar
 */
function deriveScalar(domainSep, key) {
  const hash64 = blake2b(domainSep, 64, key);
  // Reduce 64 bytes mod L
  let n = 0n;
  for (let i = 63; i >= 0; i--) {
    n = (n << 8n) | BigInt(hash64[i]);
  }
  n = n % L;

  const result = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    result[i] = Number(n & 0xffn);
    n = n >> 8n;
  }
  return result;
}

/**
 * Generate CARROT address index extension generator
 * s^j_gen = H_32[s_ga](j_major, j_minor)
 *
 * @param {Uint8Array} generateAddressSecret - s_ga (32 bytes)
 * @param {number} major - Major index
 * @param {number} minor - Minor index
 * @returns {Uint8Array} 32-byte index generator
 */
export function carrotIndexExtensionGenerator(generateAddressSecret, major, minor) {
  // Build transcript: domain_sep || major_LE || minor_LE
  const transcript = new Uint8Array(CARROT_DOMAIN_SEP.ADDRESS_INDEX_GEN.length + 8);
  transcript.set(CARROT_DOMAIN_SEP.ADDRESS_INDEX_GEN, 0);
  transcript.set(uint32ToLE(major), CARROT_DOMAIN_SEP.ADDRESS_INDEX_GEN.length);
  transcript.set(uint32ToLE(minor), CARROT_DOMAIN_SEP.ADDRESS_INDEX_GEN.length + 4);

  return deriveBytes32(transcript, generateAddressSecret);
}

/**
 * Generate CARROT subaddress scalar
 * k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
 *
 * @param {Uint8Array} accountSpendPubkey - K_s (32 bytes)
 * @param {Uint8Array} addressIndexGenerator - s^j_gen (32 bytes)
 * @param {number} major - Major index
 * @param {number} minor - Minor index
 * @returns {Uint8Array} 32-byte subaddress scalar
 */
export function carrotSubaddressScalar(accountSpendPubkey, addressIndexGenerator, major, minor) {
  // Build transcript: domain_sep || K_s || major_LE || minor_LE
  const transcript = new Uint8Array(CARROT_DOMAIN_SEP.SUBADDRESS_SCALAR.length + 32 + 8);
  transcript.set(CARROT_DOMAIN_SEP.SUBADDRESS_SCALAR, 0);
  let offset = CARROT_DOMAIN_SEP.SUBADDRESS_SCALAR.length;
  transcript.set(accountSpendPubkey, offset);
  offset += 32;
  transcript.set(uint32ToLE(major), offset);
  offset += 4;
  transcript.set(uint32ToLE(minor), offset);

  return deriveScalar(transcript, addressIndexGenerator);
}

/**
 * Generate CARROT subaddress public keys
 *
 * For main address (0,0):
 *   K^0_s = K_s
 *   K^0_v = k_vi * G
 *
 * For subaddress (j > 0):
 *   k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
 *   K^j_s = k^j_subscal * K_s
 *   K^j_v = k^j_subscal * K_v (where K_v = k_vi * K_s)
 *
 * @param {Uint8Array} accountSpendPubkey - K_s (32 bytes)
 * @param {Uint8Array} accountViewPubkey - K_v = k_vi * K_s (32 bytes)
 * @param {Uint8Array} generateAddressSecret - s_ga (32 bytes)
 * @param {number} major - Major index
 * @param {number} minor - Minor index
 * @returns {Object} { spendPublicKey, viewPublicKey }
 */
export function carrotSubaddress(accountSpendPubkey, accountViewPubkey, generateAddressSecret, major, minor) {
  // Main address (0,0) - note: view key in address is k_vi*G, not k_vi*K_s
  // But for subaddress derivation we use the account view pubkey (k_vi*K_s)
  if (major === 0 && minor === 0) {
    return {
      spendPublicKey: new Uint8Array(accountSpendPubkey),
      viewPublicKey: new Uint8Array(accountViewPubkey),
      isMainAddress: true
    };
  }

  // s^j_gen = H_32[s_ga](j_major, j_minor)
  const addressIndexGenerator = carrotIndexExtensionGenerator(generateAddressSecret, major, minor);

  // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
  const subaddressScalar = carrotSubaddressScalar(accountSpendPubkey, addressIndexGenerator, major, minor);

  // K^j_s = k^j_subscal * K_s
  const subSpendPubkey = scalarMultPoint(subaddressScalar, accountSpendPubkey);

  // K^j_v = k^j_subscal * K_v
  const subViewPubkey = scalarMultPoint(subaddressScalar, accountViewPubkey);

  return {
    spendPublicKey: subSpendPubkey,
    viewPublicKey: subViewPubkey,
    isMainAddress: false
  };
}

// ============================================================================
// Integrated Address Utilities
// ============================================================================

/**
 * Generate a random payment ID (8 bytes)
 * @returns {Uint8Array} 8-byte payment ID
 */
export function generatePaymentId() {
  const paymentId = new Uint8Array(8);
  crypto.getRandomValues(paymentId);
  return paymentId;
}

/**
 * Check if a payment ID is valid (8 bytes, not all zeros)
 * @param {Uint8Array} paymentId - Payment ID to check
 * @returns {boolean} True if valid
 */
export function isValidPaymentId(paymentId) {
  if (!paymentId || paymentId.length !== 8) return false;

  // Check if all zeros (null payment ID)
  let allZeros = true;
  for (let i = 0; i < 8; i++) {
    if (paymentId[i] !== 0) {
      allZeros = false;
      break;
    }
  }

  return !allZeros;
}

// ============================================================================
// Subaddress Map Generation (matches C++ wallet lookahead behavior)
// ============================================================================

/**
 * Default lookahead values from Salvium C++ wallet
 */
export const SUBADDRESS_LOOKAHEAD_MAJOR = 50;
export const SUBADDRESS_LOOKAHEAD_MINOR = 200;

// Pre-computed hex lookup table — avoids Array.from().map().join() per call
const _hexLUT = new Array(256);
for (let i = 0; i < 256; i++) _hexLUT[i] = i.toString(16).padStart(2, '0');

/**
 * Convert bytes to hex string (fast path using lookup table)
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += _hexLUT[bytes[i]];
  return hex;
}

/**
 * Generate CryptoNote subaddress lookup map
 * Maps: spendPublicKey (hex) → {major, minor}
 *
 * @param {Uint8Array} spendPublicKey - Main spend public key
 * @param {Uint8Array} viewSecretKey - View secret key
 * @param {number} [majorLookahead=50] - Number of major indices
 * @param {number} [minorLookahead=200] - Number of minor indices per major
 * @returns {Map<string, {major: number, minor: number}>}
 */
export function generateCNSubaddressMap(spendPublicKey, viewSecretKey, majorLookahead = SUBADDRESS_LOOKAHEAD_MAJOR, minorLookahead = SUBADDRESS_LOOKAHEAD_MINOR) {
  // Try batch Rust call (single FFI round-trip for all entries)
  try {
    return _cnBatch(spendPublicKey, viewSecretKey, majorLookahead, minorLookahead);
  } catch (e) {
    console.warn('CN subaddress batch failed, using chunked JS fallback:', e.message);
  }

  // Chunked JS fallback — process one major index at a time to limit memory pressure
  const map = new Map();
  for (let major = 0; major <= majorLookahead; major++) {
    for (let minor = 0; minor <= minorLookahead; minor++) {
      const subaddr = cnSubaddress(spendPublicKey, viewSecretKey, major, minor);
      map.set(bytesToHex(subaddr.spendPublicKey), { major, minor });
    }
  }
  return map;
}

/**
 * Generate CARROT subaddress lookup map
 * Maps: spendPublicKey (hex) → {major, minor}
 *
 * @param {Uint8Array} accountSpendPubkey - K_s (account spend pubkey)
 * @param {Uint8Array} accountViewPubkey - K_v = k_vi * K_s
 * @param {Uint8Array} generateAddressSecret - s_ga
 * @param {number} [majorLookahead=50] - Number of major indices
 * @param {number} [minorLookahead=200] - Number of minor indices per major
 * @returns {Map<string, {major: number, minor: number}>}
 */
export function generateCarrotSubaddressMap(accountSpendPubkey, accountViewPubkey, generateAddressSecret, majorLookahead = SUBADDRESS_LOOKAHEAD_MAJOR, minorLookahead = SUBADDRESS_LOOKAHEAD_MINOR) {
  // Try batch Rust call (single FFI round-trip for all entries)
  try {
    return _carrotBatch(accountSpendPubkey, accountViewPubkey, generateAddressSecret, majorLookahead, minorLookahead);
  } catch (e) {
    console.warn('CARROT subaddress batch failed, using JS fallback:', e.message);
  }

  // JS fallback — process per-major to limit memory pressure
  const map = new Map();
  for (let major = 0; major <= majorLookahead; major++) {
    for (let minor = 0; minor <= minorLookahead; minor++) {
      const subaddr = carrotSubaddress(accountSpendPubkey, accountViewPubkey, generateAddressSecret, major, minor);
      map.set(bytesToHex(subaddr.spendPublicKey), { major, minor });
    }
  }
  return map;
}

/**
 * Generate both CN and CARROT subaddress maps
 * This matches the C++ wallet behavior of generating both derivation types
 *
 * @param {Object} keys - Wallet keys
 * @param {Uint8Array} keys.spendPublicKey - CN main spend public key
 * @param {Uint8Array} keys.viewSecretKey - CN view secret key
 * @param {Uint8Array} keys.accountSpendPubkey - CARROT K_s
 * @param {Uint8Array} keys.accountViewPubkey - CARROT K_v
 * @param {Uint8Array} keys.generateAddressSecret - CARROT s_ga
 * @param {number} [majorLookahead=50] - Number of major indices
 * @param {number} [minorLookahead=200] - Number of minor indices per major
 * @returns {Object} { cnSubaddresses: Map, carrotSubaddresses: Map }
 */
export function generateSubaddressMaps(keys, majorLookahead = SUBADDRESS_LOOKAHEAD_MAJOR, minorLookahead = SUBADDRESS_LOOKAHEAD_MINOR) {
  const cnSubaddresses = generateCNSubaddressMap(
    keys.spendPublicKey,
    keys.viewSecretKey,
    majorLookahead,
    minorLookahead
  );

  const carrotSubaddresses = generateCarrotSubaddressMap(
    keys.accountSpendPubkey,
    keys.accountViewPubkey,
    keys.generateAddressSecret,
    majorLookahead,
    minorLookahead
  );

  return { cnSubaddresses, carrotSubaddresses };
}

export default {
  // CryptoNote
  cnSubaddressSecretKey,
  cnSubaddressSpendPublicKey,
  cnSubaddress,

  // CARROT
  carrotIndexExtensionGenerator,
  carrotSubaddressScalar,
  carrotSubaddress,

  // Subaddress map generation
  generateCNSubaddressMap,
  generateCarrotSubaddressMap,
  generateSubaddressMaps,
  SUBADDRESS_LOOKAHEAD_MAJOR,
  SUBADDRESS_LOOKAHEAD_MINOR,

  // Integrated address utilities
  generatePaymentId,
  isValidPaymentId,

  // Scalar utilities
  hashToScalar,
  scReduce32
};
