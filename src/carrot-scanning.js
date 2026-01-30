/**
 * CARROT Output Scanning Module
 *
 * Implements CARROT-specific output detection for Salvium.
 * CARROT uses X25519 ECDH (Montgomery curve) instead of ed25519.
 *
 * Key differences from CryptoNote scanning:
 * - Uses X25519 for key exchange (view_key_scalar_mult_x25519)
 * - 3-byte view tag (vs 1-byte in CryptoNote)
 * - Encrypted janus anchor for additional verification
 * - Different address spend pubkey recovery
 *
 * References:
 * - Salvium carrot_core/scan.cpp
 * - Salvium carrot_core/enote_utils.cpp
 */

import { blake2b } from './blake2b.js';
import { keccak256 } from './keccak.js';
import { hexToBytes, bytesToHex } from './address.js';
import { scalarMultPoint, pointFromBytes, pointToBytes } from './ed25519.js';

// Group order L for scalar reduction
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

// ============================================================================
// X25519 Implementation (Montgomery Curve)
// ============================================================================

/**
 * Convert ed25519 point (compressed) to X25519 (Montgomery u-coordinate)
 * The Montgomery u-coordinate is: u = (1 + y) / (1 - y) mod p
 * where y is the ed25519 y-coordinate
 *
 * @param {Uint8Array} edPoint - 32-byte ed25519 compressed point
 * @returns {Uint8Array} 32-byte X25519 u-coordinate
 */
export function edwardsToMontgomeryU(edPoint) {
  // Ed25519 compressed format: sign bit in MSB of last byte, y-coordinate in rest
  // Extract y-coordinate
  const p = 2n ** 255n - 19n;

  let y = 0n;
  for (let i = 0; i < 32; i++) {
    y |= BigInt(edPoint[i]) << (8n * BigInt(i));
  }
  // Clear the sign bit
  y &= (1n << 255n) - 1n;

  // u = (1 + y) / (1 - y) mod p
  const one = 1n;
  const numerator = (one + y) % p;
  const denominator = (p + one - y) % p;

  // Compute modular inverse of denominator using Fermat's little theorem
  // p is prime, so denominator^(p-2) = denominator^(-1) mod p
  const invDenom = modPow(denominator, p - 2n, p);
  const u = (numerator * invDenom) % p;

  // Convert to bytes (little-endian)
  const result = new Uint8Array(32);
  let val = u;
  for (let i = 0; i < 32; i++) {
    result[i] = Number(val & 0xffn);
    val >>= 8n;
  }

  return result;
}

/**
 * Modular exponentiation: base^exp mod mod
 */
function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

/**
 * X25519 scalar multiplication on Montgomery curve
 * Computes scalar * u where u is a Montgomery u-coordinate
 *
 * This implements Salvium's mx25519, which differs from RFC 7748:
 * - Does NOT clear bits 0-2 of scalar (caller must do this if needed)
 * - Only clears bit 255
 * - Does NOT set bit 254
 * - Uses formula z2 = E * (BB + a24 * E) with a24 = 121666
 *
 * @param {Uint8Array} scalar - 32-byte scalar
 * @param {Uint8Array} u - 32-byte Montgomery u-coordinate
 * @returns {Uint8Array} 32-byte result u-coordinate
 */
export function x25519ScalarMult(scalar, u) {
  const p = 2n ** 255n - 19n;
  const a24 = 121666n; // Salvium uses 121666, not 121665

  // Clamp the scalar as per Salvium's mx25519:
  // - Do NOT clear bits 0-2 (unlike standard X25519)
  // - Clear bit 255
  // - Do NOT set bit 254 (unlike standard X25519)
  const k = new Uint8Array(scalar);
  // k[0] &= 248;  // Salvium does NOT clear bits 0-2
  k[31] &= 127;    // Only clear bit 255

  // Convert inputs to BigInt
  let kVal = 0n;
  let uVal = 0n;
  for (let i = 0; i < 32; i++) {
    kVal |= BigInt(k[i]) << (8n * BigInt(i));
    uVal |= BigInt(u[i]) << (8n * BigInt(i));
  }
  uVal &= (1n << 255n) - 1n; // Clear top bit

  // Montgomery ladder
  let x1 = uVal;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = uVal;
  let z3 = 1n;
  let swap = 0n;

  // Process bits from 254 down to 0
  for (let t = 254; t >= 0; t--) {
    const kt = (kVal >> BigInt(t)) & 1n;
    swap ^= kt;

    // Conditional swap
    if (swap) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = kt;

    // Montgomery ladder step (matching Salvium's mx25519 portable implementation)
    const D = (p + x3 - z3) % p;     // tmp0 = x3 - z3
    const B = (p + x2 - z2) % p;     // tmp1 = x2 - z2
    const A = (x2 + z2) % p;         // x2 = x2 + z2 (reusing as A)
    const C = (x3 + z3) % p;         // z2 = x3 + z3 (reusing as C)
    const DA = (D * A) % p;          // z3 = D * A
    const CB = (C * B) % p;          // z2 = C * B
    const BB = (B * B) % p;          // tmp0 = B^2
    const AA = (A * A) % p;          // tmp1 = A^2
    const x3_new = ((DA + CB) % p) ** 2n % p;  // x3 = (DA + CB)^2
    const diff = (p + DA - CB) % p;
    const z2_diff = (diff * diff) % p;         // z2 = (DA - CB)^2
    const x2_new = (AA * BB) % p;              // x2 = AA * BB
    const E = (p + AA - BB) % p;               // tmp1 = AA - BB = E
    const z3_new = (x1 * z2_diff) % p;         // z3 = x1 * (DA - CB)^2
    const a24E = (a24 * E) % p;                // z3 = a24 * E
    const z2_new = (E * ((BB + a24E) % p)) % p; // z2 = E * (BB + a24 * E)

    x2 = x2_new;
    z2 = z2_new;
    x3 = x3_new;
    z3 = z3_new;
  }

  // Final conditional swap
  if (swap) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }

  // Compute result = x2 / z2
  const z2Inv = modPow(z2, p - 2n, p);
  const result = (x2 * z2Inv) % p;

  // Convert to bytes
  const out = new Uint8Array(32);
  let val = result;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(val & 0xffn);
    val >>= 8n;
  }

  return out;
}

/**
 * Perform X25519 ECDH key exchange for CARROT scanning
 * s_sr = k_vi * D_e (where D_e is the enote ephemeral pubkey)
 *
 * @param {Uint8Array} viewIncomingKey - 32-byte view-incoming key (k_vi)
 * @param {Uint8Array} enoteEphemeralPubkey - 32-byte enote ephemeral pubkey (D_e)
 * @returns {Uint8Array} 32-byte shared secret (s_sender_receiver_unctx)
 */
export function carrotEcdhKeyExchange(viewIncomingKey, enoteEphemeralPubkey) {
  // enoteEphemeralPubkey (D_e / p_r) is ALREADY in X25519 format (Montgomery u-coordinate)
  // No conversion needed - just perform X25519 scalar multiplication directly
  // s_sr = k_vi * D_e
  const sharedSecret = x25519ScalarMult(viewIncomingKey, enoteEphemeralPubkey);

  return sharedSecret;
}

// ============================================================================
// CARROT View Tag
// ============================================================================

/**
 * Compute CARROT view tag (3 bytes)
 * vt = H_3[s_sr_unctx]("Carrot view tag", input_context, Ko)
 *
 * Uses blake2b keyed hash: transcript is domain || input_context || Ko
 * Key is s_sr_unctx (32 bytes)
 *
 * @param {Uint8Array} senderReceiverUnctx - 32-byte uncontextualized shared secret
 * @param {Uint8Array} inputContext - Input context bytes
 * @param {Uint8Array} onetimeAddress - 32-byte onetime address (Ko)
 * @returns {Uint8Array} 3-byte view tag
 */
export function computeCarrotViewTag(senderReceiverUnctx, inputContext, onetimeAddress) {
  // Build transcript: [length_byte] || domain_sep || input_context || Ko
  // SpFixedTranscript format: domain separator is length-prefixed with a single byte
  const domainSep = new TextEncoder().encode('Carrot view tag');
  const data = new Uint8Array(1 + domainSep.length + inputContext.length + 32);
  let offset = 0;
  data[offset++] = domainSep.length; // Length prefix byte
  data.set(domainSep, offset); offset += domainSep.length;
  data.set(inputContext, offset); offset += inputContext.length;
  data.set(onetimeAddress, offset);

  // Blake2b with s_sr_unctx as key, output 3 bytes
  return blake2b(data, 3, senderReceiverUnctx);
}

/**
 * Test CARROT view tag
 *
 * @param {Uint8Array} senderReceiverUnctx - 32-byte uncontextualized shared secret
 * @param {Uint8Array} inputContext - Input context bytes
 * @param {Uint8Array} onetimeAddress - 32-byte onetime address
 * @param {Uint8Array} viewTag - 3-byte view tag from the enote
 * @returns {boolean} True if view tag matches
 */
export function testCarrotViewTag(senderReceiverUnctx, inputContext, onetimeAddress, viewTag) {
  const expected = computeCarrotViewTag(senderReceiverUnctx, inputContext, onetimeAddress);
  return expected[0] === viewTag[0] &&
         expected[1] === viewTag[1] &&
         expected[2] === viewTag[2];
}

// ============================================================================
// CARROT Input Context
// ============================================================================

/**
 * Make input context for a regular (RingCT) transaction
 * input_context = "R" || first_key_image (33 bytes total)
 *
 * @param {Uint8Array|string} firstKeyImage - First key image from transaction inputs (32 bytes)
 * @returns {Uint8Array} Input context (33 bytes)
 */
export function makeInputContext(firstKeyImage) {
  if (typeof firstKeyImage === 'string') {
    firstKeyImage = hexToBytes(firstKeyImage);
  }

  // input_context_t is always 33 bytes: 1 byte type + 32 bytes data
  const result = new Uint8Array(33);
  result[0] = 0x52; // 'R' for RingCT
  result.set(firstKeyImage, 1);
  return result;
}

/**
 * Make input context for coinbase transaction
 * input_context = "C" || block_height_LE_8bytes || zeros_24bytes (33 bytes total)
 *
 * @param {number} blockHeight - Block height
 * @returns {Uint8Array} Input context (33 bytes)
 */
export function makeInputContextCoinbase(blockHeight) {
  // input_context_t is always 33 bytes: 1 byte type + 32 bytes data
  const result = new Uint8Array(33);
  result[0] = 0x43; // 'C' for Coinbase

  // Block height as 8-byte little-endian at bytes 1-8
  let h = BigInt(blockHeight);
  for (let i = 0; i < 8; i++) {
    result[1 + i] = Number(h & 0xffn);
    h >>= 8n;
  }
  // Bytes 9-32 are already zero (padding)
  return result;
}

// ============================================================================
// CARROT Domain Separators (matching config.h)
// ============================================================================

const CARROT_DOMAIN = {
  SENDER_RECEIVER_SECRET: 'Carrot sender-receiver secret',
  VIEW_TAG: 'Carrot view tag',
  COMMITMENT_MASK: 'Carrot commitment mask',
  ONETIME_EXTENSION_G: 'Carrot key extension G',
  ONETIME_EXTENSION_T: 'Carrot key extension T',
  ENCRYPTION_MASK_AMOUNT: 'Carrot encryption mask a',
  ENCRYPTION_MASK_PAYMENT_ID: 'Carrot encryption mask pid'
};

// ============================================================================
// CARROT Sender-Receiver Secret
// ============================================================================

/**
 * Compute contextualized sender-receiver secret
 * s^ctx_sr = H_32[s_sr_unctx]("Carrot sender-receiver secret", D_e, input_context)
 * Key = s_sender_receiver_unctx, transcript = D_e + input_context
 *
 * @param {Uint8Array} senderReceiverUnctx - 32-byte uncontextualized shared secret (KEY)
 * @param {Uint8Array} enoteEphemeralPubkey - 32-byte enote ephemeral pubkey (D_e)
 * @param {Uint8Array} inputContext - Input context (33 bytes)
 * @returns {Uint8Array} 32-byte contextualized shared secret
 */
export function makeCarrotSenderReceiverSecret(senderReceiverUnctx, enoteEphemeralPubkey, inputContext) {
  // Key is s_sender_receiver_unctx, transcript is D_e + input_context
  // We need to build: [len] + "Carrot sender-receiver secret" + D_e + input_context
  // Then use blake2b with s_sender_receiver_unctx as key
  const domainBytes = new TextEncoder().encode(CARROT_DOMAIN.SENDER_RECEIVER_SECRET);
  const domainLen = domainBytes.length;

  // Transcript: [len] + domain + D_e + input_context
  const transcript = new Uint8Array(1 + domainLen + 32 + inputContext.length);
  let offset = 0;
  transcript[offset++] = domainLen;
  transcript.set(domainBytes, offset); offset += domainLen;
  transcript.set(enoteEphemeralPubkey, offset); offset += 32;
  transcript.set(inputContext, offset);

  // blake2b with s_sender_receiver_unctx as key, 32-byte output
  return blake2b(transcript, 32, senderReceiverUnctx);
}

// ============================================================================
// CARROT Hash Functions (matching Salvium's derive_* functions)
// ============================================================================

/**
 * Build SpFixedTranscript: [len_byte] + domain_sep + args...
 * @param {string} domain - Domain separator string
 * @param {Array<Uint8Array>} args - Data arguments
 * @returns {Uint8Array} Transcript bytes
 */
function makeTranscript(domain, ...args) {
  const domainBytes = new TextEncoder().encode(domain);
  const domainLen = domainBytes.length;

  // Calculate total size: 1 (len) + domain + all args
  let totalLen = 1 + domainLen;
  const processed = args.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const transcript = new Uint8Array(totalLen);
  let offset = 0;

  // Length prefix byte
  transcript[offset++] = domainLen;

  // Domain separator
  transcript.set(domainBytes, offset);
  offset += domainLen;

  // Arguments
  for (const item of processed) {
    transcript.set(item, offset);
    offset += item.length;
  }

  return transcript;
}

/**
 * sc_reduce: reduce a 64-byte value modulo L to 32 bytes
 * This matches crypto-ops.c sc_reduce
 * @param {Uint8Array} input - 64-byte input
 * @returns {Uint8Array} 32-byte reduced scalar
 */
function scReduce(input) {
  // Read 64-byte input as little-endian BigInt
  let n = 0n;
  for (let i = 63; i >= 0; i--) {
    n = (n << 8n) | BigInt(input[i]);
  }

  // Reduce mod L
  n = n % L;

  // Convert back to 32-byte little-endian
  const result = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    result[i] = Number(n & 0xffn);
    n = n >> 8n;
  }
  return result;
}

/**
 * derive_scalar: H_n with 64-byte hash then sc_reduce
 * Matches Salvium's derive_scalar: blake2b(data, 64, key) then sc_reduce
 *
 * @param {Uint8Array} key - 32-byte key (e.g., s_sender_receiver)
 * @param {string} domain - Domain separator
 * @param {...Uint8Array} args - Data to include in transcript
 * @returns {Uint8Array} 32-byte reduced scalar
 */
function deriveScalar(key, domain, ...args) {
  // Build transcript: [len] + domain + args
  const transcript = makeTranscript(domain, ...args);

  // blake2b with key, 64-byte output
  const hash64 = blake2b(transcript, 64, key);

  // Reduce mod L
  return scReduce(hash64);
}

/**
 * derive_bytes_32: H_32 (32-byte output, keyed)
 * @param {Uint8Array} key - 32-byte key
 * @param {string} domain - Domain separator
 * @param {...Uint8Array} args - Data arguments
 * @returns {Uint8Array} 32-byte output
 */
function deriveBytes32(key, domain, ...args) {
  const transcript = makeTranscript(domain, ...args);
  return blake2b(transcript, 32, key);
}

/**
 * derive_bytes_8: H_8 (8-byte output, keyed)
 * @param {Uint8Array} key - 32-byte key
 * @param {string} domain - Domain separator
 * @param {...Uint8Array} args - Data arguments
 * @returns {Uint8Array} 8-byte output
 */
function deriveBytes8(key, domain, ...args) {
  const transcript = makeTranscript(domain, ...args);
  return blake2b(transcript, 8, key);
}

// Legacy functions (for non-keyed hashing)
function carrotHash32(domain, ...data) {
  const transcript = makeTranscript(domain, ...data);
  return blake2b(transcript, 32);
}

function carrotHashToScalar(domain, ...data) {
  const transcript = makeTranscript(domain, ...data);
  const hash64 = blake2b(transcript, 64);
  return scReduce(hash64);
}

function carrotHash8(domain, ...data) {
  const transcript = makeTranscript(domain, ...data);
  return blake2b(transcript, 8);
}

// ============================================================================
// CARROT One-time Address Recovery
// ============================================================================

// Import generator T from ed25519 or define it here
const T_BYTES = new Uint8Array([
  0x96, 0x6f, 0xc6, 0x6b, 0x82, 0xcd, 0x56, 0xcf,
  0x85, 0xea, 0xec, 0x80, 0x1c, 0x42, 0x84, 0x5f,
  0x5f, 0x40, 0x88, 0x78, 0xd1, 0x56, 0x1e, 0x00,
  0xd3, 0xd7, 0xde, 0xd2, 0x79, 0x4d, 0x09, 0x4f
]);

/**
 * Derive one-time address extension G scalar
 * k^o_g = H_n[s^ctx_sr]("Carrot key extension G", C_a)
 * Key = s_sender_receiver, data = C_a
 */
function deriveOnetimeExtensionG(senderReceiverCtx, amountCommitment) {
  // Key is s_sender_receiver, transcript is just C_a
  return deriveScalar(senderReceiverCtx, CARROT_DOMAIN.ONETIME_EXTENSION_G, amountCommitment);
}

/**
 * Derive one-time address extension T scalar
 * k^o_t = H_n[s^ctx_sr]("Carrot key extension T", C_a)
 * Key = s_sender_receiver, data = C_a
 */
function deriveOnetimeExtensionT(senderReceiverCtx, amountCommitment) {
  // Key is s_sender_receiver, transcript is just C_a
  return deriveScalar(senderReceiverCtx, CARROT_DOMAIN.ONETIME_EXTENSION_T, amountCommitment);
}

/**
 * Compute one-time address extension pubkey
 * K^o_ext = k^o_g * G + k^o_t * T
 */
function computeOnetimeExtensionPubkey(senderReceiverCtx, amountCommitment) {
  const k_g = deriveOnetimeExtensionG(senderReceiverCtx, amountCommitment);
  const k_t = deriveOnetimeExtensionT(senderReceiverCtx, amountCommitment);

  // k^o_g * G
  const kgG = scalarMultBase(k_g);

  // k^o_t * T
  const ktT = scalarMultPoint(k_t, T_BYTES);

  // K^o_ext = k^o_g * G + k^o_t * T
  return pointAddCompressed(kgG, ktT);
}

/**
 * Recover address spend pubkey from one-time address
 * K^j_s = Ko - K^o_ext
 */
export function recoverAddressSpendPubkey(onetimeAddress, senderReceiverCtx, amountCommitment) {
  // Compute extension pubkey
  const extensionPubkey = computeOnetimeExtensionPubkey(senderReceiverCtx, amountCommitment);

  // Negate the extension pubkey (flip sign bit)
  const negExtension = new Uint8Array(extensionPubkey);
  negExtension[31] ^= 0x80;

  // K^j_s = Ko + (-K^o_ext) = Ko - K^o_ext
  return pointAddCompressed(onetimeAddress, negExtension);
}

// ============================================================================
// CARROT Amount Decryption
// ============================================================================

/**
 * Decrypt CARROT amount
 * amount = amount_enc XOR H_8[s^ctx_sr]("Carrot encryption mask a", Ko)
 * Key = s_sender_receiver, transcript = Ko
 */
export function decryptCarrotAmount(encryptedAmount, senderReceiverCtx, onetimeAddress) {
  // Key is s_sender_receiver, transcript is just Ko
  const mask = deriveBytes8(senderReceiverCtx, CARROT_DOMAIN.ENCRYPTION_MASK_AMOUNT, onetimeAddress);

  const decrypted = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    decrypted[i] = encryptedAmount[i] ^ mask[i];
  }

  // Convert little-endian bytes to amount
  let amount = 0n;
  for (let i = 7; i >= 0; i--) {
    amount = (amount << 8n) | BigInt(decrypted[i]);
  }

  return amount;
}

/**
 * Derive CARROT commitment mask (amount blinding factor)
 * k_a = H_n[s^ctx_sr]("Carrot commitment mask", amount, K_s, enote_type)
 * Key = s_sender_receiver, transcript = amount + K_s + enote_type
 */
export function deriveCarrotCommitmentMask(senderReceiverCtx, amount, addressSpendPubkey, enoteType = 0) {
  const amountBytes = new Uint8Array(8);
  let a = typeof amount === 'bigint' ? amount : BigInt(amount);
  for (let i = 0; i < 8; i++) {
    amountBytes[i] = Number(a & 0xffn);
    a = a >> 8n;
  }
  const typeBytes = new Uint8Array([enoteType]);
  // Key is s_sender_receiver, transcript is amount + K_s + enote_type
  return deriveScalar(senderReceiverCtx, CARROT_DOMAIN.COMMITMENT_MASK, amountBytes, addressSpendPubkey, typeBytes);
}

// ============================================================================
// CARROT Output Scanning
// ============================================================================

/**
 * Scan a CARROT output for ownership
 *
 * Algorithm:
 * 1. Compute uncontextualized shared secret: s_sr = k_vi * D_e (X25519)
 * 2. Test view tag: vt' = H_3(s_sr, input_context, Ko) - fast filter
 * 3. Compute contextualized shared secret: s^ctx_sr = H_32(s_sr, D_e, input_context)
 * 4. Recover address spend pubkey: K^j_s = Ko - (k^o_g G + k^o_t T)
 * 5. Check if K^j_s matches any known address
 * 6. Decrypt amount
 *
 * @param {Object} output - Output from parsed transaction
 * @param {Uint8Array} viewIncomingKey - View-incoming key (k_vi)
 * @param {Uint8Array} accountSpendPubkey - Account spend public key (K_s)
 * @param {Uint8Array} inputContext - Input context
 * @param {Map} subaddressMap - Map of address spend pubkeys (hex) to {major, minor}
 * @param {Uint8Array} amountCommitment - Amount commitment (C_a) from RingCT
 * @returns {Object|null} Scan result or null if not owned
 */
export function scanCarrotOutput(output, viewIncomingKey, accountSpendPubkey, inputContext, subaddressMap, amountCommitment) {
  // Convert keys if passed as hex strings
  if (typeof viewIncomingKey === 'string') viewIncomingKey = hexToBytes(viewIncomingKey);
  if (typeof accountSpendPubkey === 'string') accountSpendPubkey = hexToBytes(accountSpendPubkey);
  if (typeof inputContext === 'string') inputContext = hexToBytes(inputContext);
  if (typeof amountCommitment === 'string') amountCommitment = hexToBytes(amountCommitment);

  // Extract CARROT-specific fields
  const onetimeAddress = typeof output.key === 'string' ? hexToBytes(output.key) : output.key;
  const viewTag = output.viewTag;
  const enoteEphemeralPubkey = typeof output.enoteEphemeralPubkey === 'string'
    ? hexToBytes(output.enoteEphemeralPubkey)
    : output.enoteEphemeralPubkey;
  const encryptedAmount = output.encryptedAmount;

  if (!onetimeAddress) {
    throw new Error('scanCarrotOutput: onetimeAddress is required');
  }
  if (!viewTag) {
    throw new Error('scanCarrotOutput: viewTag is required');
  }
  if (!enoteEphemeralPubkey) {
    throw new Error('scanCarrotOutput: enoteEphemeralPubkey is required');
  }

  // 1. Compute uncontextualized shared secret using X25519
  const senderReceiverUnctx = carrotEcdhKeyExchange(viewIncomingKey, enoteEphemeralPubkey);

  // 2. Test view tag (fast filter - 3 bytes)
  const expectedViewTag = computeCarrotViewTag(senderReceiverUnctx, inputContext, onetimeAddress);
  const viewTagMatch = expectedViewTag[0] === viewTag[0] &&
                       expectedViewTag[1] === viewTag[1] &&
                       expectedViewTag[2] === viewTag[2];

  if (!viewTagMatch) {
    return null; // View tag mismatch - not our output
  }

  // 3. Compute contextualized shared secret
  const senderReceiverCtx = makeCarrotSenderReceiverSecret(
    senderReceiverUnctx,
    enoteEphemeralPubkey,
    inputContext
  );

  // 4. Recover address spend pubkey
  // Need amount commitment for this - if not provided, use zero commitment
  const commitment = amountCommitment || new Uint8Array(32);
  const recoveredSpendPubkey = recoverAddressSpendPubkey(onetimeAddress, senderReceiverCtx, commitment);
  const recoveredSpendPubkeyHex = bytesToHex(recoveredSpendPubkey);

  // 5. Check if this matches our account or any subaddress
  let subaddressIndex = null;
  let isMainAddress = false;

  // Check main address (account spend pubkey)
  if (bytesToHex(accountSpendPubkey) === recoveredSpendPubkeyHex) {
    isMainAddress = true;
    subaddressIndex = { major: 0, minor: 0 };
  } else if (subaddressMap && subaddressMap.has(recoveredSpendPubkeyHex)) {
    // Check subaddresses
    subaddressIndex = subaddressMap.get(recoveredSpendPubkeyHex);
  }

  if (!subaddressIndex) {
    return null; // Not our output
  }

  // 6. Decrypt amount (if encrypted)
  let amount = 0n;
  if (encryptedAmount) {
    const encAmountBytes = typeof encryptedAmount === 'string'
      ? hexToBytes(encryptedAmount)
      : encryptedAmount;
    amount = decryptCarrotAmount(encAmountBytes, senderReceiverCtx, onetimeAddress);
  }

  // 7. Derive commitment mask for verification
  const mask = deriveCarrotCommitmentMask(senderReceiverCtx, amount, recoveredSpendPubkey, 0);

  return {
    owned: true,
    onetimeAddress: bytesToHex(onetimeAddress),
    addressSpendPubkey: recoveredSpendPubkeyHex,
    sharedSecret: bytesToHex(senderReceiverCtx),
    viewTag: bytesToHex(viewTag),
    amount,
    mask,
    subaddressIndex,
    isMainAddress,
    isCarrot: true
  };
}

// ============================================================================
// Import additional ed25519 functions
// ============================================================================

import { scalarMultBase, pointAddCompressed } from './ed25519.js';
import { hashToPoint } from './keyimage.js';

// Group order L for scalar reduction (also defined at top for clarity)
const L_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;

/**
 * Scalar addition: a + b mod L
 * @param {Uint8Array} a - 32-byte scalar
 * @param {Uint8Array} b - 32-byte scalar
 * @returns {Uint8Array} 32-byte result
 */
function scalarAdd(a, b) {
  let aVal = 0n;
  let bVal = 0n;
  for (let i = 0; i < 32; i++) {
    aVal |= BigInt(a[i]) << (8n * BigInt(i));
    bVal |= BigInt(b[i]) << (8n * BigInt(i));
  }
  let result = (aVal + bVal) % L_ORDER;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(result & 0xffn);
    result = result >> 8n;
  }
  return out;
}

/**
 * Scalar multiplication: a * b mod L
 * @param {Uint8Array} a - 32-byte scalar
 * @param {Uint8Array} b - 32-byte scalar
 * @returns {Uint8Array} 32-byte result
 */
function scalarMul(a, b) {
  let aVal = 0n;
  let bVal = 0n;
  for (let i = 0; i < 32; i++) {
    aVal |= BigInt(a[i]) << (8n * BigInt(i));
    bVal |= BigInt(b[i]) << (8n * BigInt(i));
  }
  let result = (aVal * bVal) % L_ORDER;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(result & 0xffn);
    result = result >> 8n;
  }
  return out;
}

/**
 * Generate CARROT key image
 *
 * CARROT key image formula:
 *   sender_extension_g = H_n("Carrot key extension G", s_sender_receiver_ctx, C_a)
 *   x = k_gi * k_subscal + sender_extension_g
 *   KI = x * H_p(Ko)
 *
 * For main address (j=0,0), k_subscal = 1, so x = k_gi + sender_extension_g
 *
 * @param {Uint8Array|string} onetimeAddress - One-time address Ko (32 bytes)
 * @param {Uint8Array|string} senderReceiverCtx - Contextualized shared secret (32 bytes)
 * @param {Uint8Array|string} amountCommitment - Amount commitment C_a (32 bytes)
 * @param {Uint8Array|string} generateImageKey - k_gi from CARROT keys (32 bytes)
 * @param {Uint8Array|string} [subaddressScalar] - k_subscal (32 bytes), defaults to 1 for main address
 * @returns {Uint8Array} Key image (32 bytes)
 */
export function generateCarrotKeyImage(
  onetimeAddress,
  senderReceiverCtx,
  amountCommitment,
  generateImageKey,
  subaddressScalar = null
) {
  // Convert string inputs to bytes
  const Ko = typeof onetimeAddress === 'string' ? hexToBytes(onetimeAddress) : onetimeAddress;
  const sSR = typeof senderReceiverCtx === 'string' ? hexToBytes(senderReceiverCtx) : senderReceiverCtx;
  const Ca = typeof amountCommitment === 'string' ? hexToBytes(amountCommitment) : amountCommitment;
  const kGi = typeof generateImageKey === 'string' ? hexToBytes(generateImageKey) : generateImageKey;

  // 1. Derive sender_extension_g = H_n("Carrot key extension G", s_sr_ctx, C_a)
  const senderExtG = deriveOnetimeExtensionG(sSR, Ca);

  // 2. Compute x = k_gi * k_subscal + sender_extension_g
  let x;
  if (subaddressScalar) {
    const kSubscal = typeof subaddressScalar === 'string' ? hexToBytes(subaddressScalar) : subaddressScalar;
    // x = k_gi * k_subscal + sender_extension_g
    const kgiScaled = scalarMul(kGi, kSubscal);
    x = scalarAdd(kgiScaled, senderExtG);
  } else {
    // Main address: k_subscal = 1, so x = k_gi + sender_extension_g
    x = scalarAdd(kGi, senderExtG);
  }

  // 3. Compute H_p(Ko) - hash to point
  const hpKo = hashToPoint(Ko);

  // 4. Compute key image: KI = x * H_p(Ko)
  const keyImage = scalarMultPoint(x, hpKo);

  return keyImage;
}

// ============================================================================
// Exports
// ============================================================================

export default {
  // X25519
  edwardsToMontgomeryU,
  x25519ScalarMult,
  carrotEcdhKeyExchange,

  // View tag
  computeCarrotViewTag,
  testCarrotViewTag,

  // Input context
  makeInputContext,
  makeInputContextCoinbase,

  // Shared secret
  makeCarrotSenderReceiverSecret,

  // Address recovery
  recoverAddressSpendPubkey,

  // Amount decryption
  decryptCarrotAmount,
  deriveCarrotCommitmentMask,

  // Key image
  generateCarrotKeyImage,

  // Scanning
  scanCarrotOutput
};
