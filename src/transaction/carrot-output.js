/**
 * CARROT Output Module
 *
 * Implements CARROT (Cryptographic Address Randomization and Recipient Output Tagging)
 * for Salvium transaction outputs:
 * - Janus anchor generation
 * - Ephemeral key derivation
 * - One-time address computation
 * - Amount encryption
 * - View tag computation
 *
 * Reference: Salvium CARROT specification
 *
 * @module transaction/carrot-output
 */

import { hexToBytes, bytesToHex } from '../address.js';
import { getGeneratorT } from '../ed25519.js';
import { edwardsToMontgomeryU, x25519ScalarMult } from '../carrot-scanning.js';
import {
  blake2b, scalarMultBase, scalarMultPoint, pointAddCompressed,
  scReduce32, commit,
} from '../crypto/index.js';

import { CARROT_DOMAIN, CARROT_ENOTE_TYPE } from './constants.js';
import { bigIntToBytes } from './serialization.js';

// =============================================================================
// CARROT HASH FUNCTIONS
//
// Matches C++ hash_base(): blake2b(out, outLen, transcript, transcriptLen, key, keyLen)
// Transcript uses SpFixedTranscript format: [domain_length_byte] || [domain_bytes] || [data...]
// The key (shared secret / sender-receiver secret) is passed as the Blake2b key.
// =============================================================================

/**
 * Build SpFixedTranscript: [domain_length_byte] || [domain_bytes] || [data...]
 * @param {string} domain - Domain separator string
 * @param {Array<Uint8Array>} dataItems - Transcript data items
 * @returns {Uint8Array} Transcript bytes
 */
function buildTranscript(domain, dataItems) {
  const domainBytes = new TextEncoder().encode(domain);
  let totalLen = 1 + domainBytes.length; // 1 for length prefix byte
  for (const item of dataItems) {
    totalLen += item.length;
  }
  const transcript = new Uint8Array(totalLen);
  let offset = 0;
  transcript[offset++] = domainBytes.length; // Length prefix byte
  transcript.set(domainBytes, offset);
  offset += domainBytes.length;
  for (const item of dataItems) {
    transcript.set(item, offset);
    offset += item.length;
  }
  return transcript;
}

/**
 * Normalize data arguments (hex strings to Uint8Array)
 */
function normalizeData(data) {
  return data.map(item => {
    if (typeof item === 'string') return hexToBytes(item);
    return item;
  });
}

/**
 * Keyed Blake2b hash with SpFixedTranscript (C++ hash_base equivalent)
 * @param {string} domain - Domain separator string
 * @param {Uint8Array|null} key - Blake2b key (32 bytes), or null for unkeyed
 * @param {number} outLen - Output length in bytes
 * @param {...(Uint8Array|string)} data - Transcript data items
 * @returns {Uint8Array} Hash output
 */
function carrotHashBase(domain, key, outLen, ...data) {
  const transcript = buildTranscript(domain, normalizeData(data));
  return blake2b(transcript, outLen, key || null);
}

/**
 * Hash to 32 bytes with optional key (keyed Blake2b + SpFixedTranscript)
 */
function carrotHash32(domain, key, ...data) {
  return carrotHashBase(domain, key, 32, ...data);
}

/**
 * Hash to scalar with optional key
 * H_n: 64-byte hash then reduce mod L
 */
function carrotHashToScalar(domain, key, ...data) {
  const transcript = buildTranscript(domain, normalizeData(data));
  const hash64 = blake2b(transcript, 64, key || null);
  return scReduce32(hash64);
}

/**
 * Hash to 16 bytes with key
 */
function carrotHash16(domain, key, ...data) {
  return carrotHashBase(domain, key, 16, ...data);
}

/**
 * Hash to 8 bytes with key
 */
function carrotHash8(domain, key, ...data) {
  return carrotHashBase(domain, key, 8, ...data);
}

/**
 * Hash to 3 bytes with key
 */
function carrotHash3(domain, key, ...data) {
  return carrotHashBase(domain, key, 3, ...data);
}

// =============================================================================
// JANUS ANCHOR
// =============================================================================

/**
 * Generate random Janus anchor (16 bytes)
 * @returns {Uint8Array} 16-byte random anchor
 */
export function generateJanusAnchor() {
  const anchor = new Uint8Array(16);
  crypto.getRandomValues(anchor);
  return anchor;
}

// =============================================================================
// INPUT CONTEXT
// =============================================================================

/**
 * Build input context for RingCT transaction
 * Format: 'R' || first_key_image (32 bytes)
 *
 * @param {Uint8Array|string} firstKeyImage - First input's key image
 * @returns {Uint8Array} 33-byte input context
 */
export function buildRingCtInputContext(firstKeyImage) {
  if (typeof firstKeyImage === 'string') firstKeyImage = hexToBytes(firstKeyImage);

  const context = new Uint8Array(33);
  context[0] = CARROT_DOMAIN.INPUT_CONTEXT_RINGCT.charCodeAt(0);
  context.set(firstKeyImage, 1);
  return context;
}

/**
 * Build input context for coinbase transaction
 * Format: 'C' || block_height (8 bytes, little-endian)
 *
 * @param {bigint|number} blockHeight - Block height
 * @returns {Uint8Array} 9-byte input context
 */
export function buildCoinbaseInputContext(blockHeight) {
  if (typeof blockHeight === 'number') blockHeight = BigInt(blockHeight);

  const context = new Uint8Array(9);
  context[0] = CARROT_DOMAIN.INPUT_CONTEXT_COINBASE.charCodeAt(0);

  // Little-endian 8-byte height
  let h = blockHeight;
  for (let i = 1; i < 9; i++) {
    context[i] = Number(h & 0xffn);
    h >>= 8n;
  }

  return context;
}

// =============================================================================
// EPHEMERAL KEY DERIVATION
// =============================================================================

/**
 * Derive CARROT ephemeral private key
 * d_e = H_n("Carrot sending key normal", anchor, input_context, K_s, payment_id)
 *
 * @param {Uint8Array} anchor - 16-byte Janus anchor
 * @param {Uint8Array} inputContext - Input context
 * @param {Uint8Array} addressSpendPubkey - Recipient's spend public key (K_s)
 * @param {Uint8Array} paymentId - 8-byte payment ID
 * @returns {Uint8Array} 32-byte ephemeral private key
 */
export function deriveCarrotEphemeralPrivkey(anchor, inputContext, addressSpendPubkey, paymentId) {
  return carrotHashToScalar(
    CARROT_DOMAIN.EPHEMERAL_PRIVKEY,
    null, // unkeyed (C++ passes nullptr)
    anchor,
    inputContext,
    addressSpendPubkey,
    paymentId
  );
}

/**
 * Compute CARROT ephemeral public key (on X25519/Montgomery curve)
 * For main address: D_e = d_e * B (X25519 base point, u=9)
 * For subaddress: D_e = d_e * ConvertPointE(K_s)
 *
 * @param {Uint8Array} ephemeralPrivkey - Ephemeral private key (d_e)
 * @param {Uint8Array} addressSpendPubkey - Address spend pubkey (for subaddress)
 * @param {boolean} isSubaddress - Whether target is a subaddress
 * @returns {Uint8Array} 32-byte ephemeral public key (X25519 u-coordinate)
 */
export function computeCarrotEphemeralPubkey(ephemeralPrivkey, addressSpendPubkey, isSubaddress = false) {
  if (isSubaddress) {
    // D_e = d_e * ConvertPointE(K_s)
    const spendPubX25519 = edwardsToMontgomeryU(addressSpendPubkey);
    return x25519ScalarMult(ephemeralPrivkey, spendPubX25519);
  } else {
    // D_e = d_e * B (X25519 base point u=9)
    const basePoint = new Uint8Array(32);
    basePoint[0] = 9;
    return x25519ScalarMult(ephemeralPrivkey, basePoint);
  }
}

// =============================================================================
// SHARED SECRET DERIVATION
// =============================================================================

/**
 * Compute CARROT sender-receiver shared secret (un-contextualized)
 * s_sr = d_e * ConvertPointE(K_v)  (sender side, on X25519)
 * s_sr = k_vi * D_e                (receiver side, on X25519)
 *
 * @param {Uint8Array} ephemeralPrivkey - Ephemeral private key
 * @param {Uint8Array} addressViewPubkey - Address view public key (Ed25519)
 * @returns {Uint8Array} 32-byte shared secret
 */
export function computeCarrotSharedSecret(ephemeralPrivkey, addressViewPubkey) {
  // Convert Ed25519 view pubkey to X25519 u-coordinate
  const viewPubX25519 = edwardsToMontgomeryU(addressViewPubkey);
  // X25519 scalar multiplication: s_sr = d_e * D^j_v
  return x25519ScalarMult(ephemeralPrivkey, viewPubX25519);
}

/**
 * Derive contextualized sender-receiver secret
 * s^ctx_sr = H_32("Carrot sender-receiver secret", D_e, input_context, s_sr)
 *
 * @param {Uint8Array} sharedSecret - Un-contextualized shared secret (s_sr)
 * @param {Uint8Array} ephemeralPubkey - Ephemeral public key (D_e)
 * @param {Uint8Array} inputContext - Input context
 * @returns {Uint8Array} 32-byte contextualized secret
 */
export function deriveCarrotSenderReceiverSecret(sharedSecret, ephemeralPubkey, inputContext) {
  return carrotHash32(
    CARROT_DOMAIN.SENDER_RECEIVER_SECRET,
    sharedSecret, // key = s_sr_unctx
    ephemeralPubkey,
    inputContext
  );
}

// =============================================================================
// ONE-TIME ADDRESS DERIVATION
// =============================================================================

/**
 * Derive CARROT one-time address extension keys
 * k^o_g = H_n("Carrot key extension G", s^ctx_sr, C_a)
 * k^o_t = H_n("Carrot key extension T", s^ctx_sr, C_a)
 *
 * @param {Uint8Array} senderReceiverSecret - Contextualized sender-receiver secret
 * @param {Uint8Array} amountCommitment - Amount commitment
 * @returns {Object} { extensionG, extensionT }
 */
export function deriveCarrotOnetimeExtensions(senderReceiverSecret, amountCommitment) {
  const extensionG = carrotHashToScalar(
    CARROT_DOMAIN.ONETIME_EXTENSION_G,
    senderReceiverSecret, // key = s^ctx_sr
    amountCommitment
  );

  const extensionT = carrotHashToScalar(
    CARROT_DOMAIN.ONETIME_EXTENSION_T,
    senderReceiverSecret, // key = s^ctx_sr
    amountCommitment
  );

  return { extensionG, extensionT };
}

/**
 * Compute CARROT one-time address
 * Ko = K_s + k^o_g * G + k^o_t * T
 *
 * @param {Uint8Array} addressSpendPubkey - Recipient's spend public key
 * @param {Uint8Array} extensionG - Extension scalar for G
 * @param {Uint8Array} extensionT - Extension scalar for T
 * @returns {Uint8Array} 32-byte one-time address
 */
export function computeCarrotOnetimeAddress(addressSpendPubkey, extensionG, extensionT) {
  // k^o_g * G
  const kgG = scalarMultBase(extensionG);

  // k^o_t * T
  const T = getGeneratorT();
  const ktT = scalarMultPoint(extensionT, T);

  // K_s + k^o_g * G + k^o_t * T
  const sum1 = pointAddCompressed(addressSpendPubkey, kgG);
  return pointAddCompressed(sum1, ktT);
}

// =============================================================================
// BLINDING FACTOR DERIVATION
// =============================================================================

/**
 * Derive CARROT amount blinding factor
 * k_a = H_n("Carrot commitment mask", s^ctx_sr, amount, K_s, enote_type)
 *
 * @param {Uint8Array} senderReceiverSecret - Contextualized secret
 * @param {bigint} amount - Amount
 * @param {Uint8Array} addressSpendPubkey - Address spend pubkey
 * @param {number} enoteType - Enote type (0=payment, 1=change, 2=self-spend)
 * @returns {Uint8Array} 32-byte blinding factor
 */
export function deriveCarrotAmountBlindingFactor(senderReceiverSecret, amount, addressSpendPubkey, enoteType) {
  const amountBytes = bigIntToBytes(amount);
  const typeBytes = new Uint8Array([enoteType]);

  return carrotHashToScalar(
    CARROT_DOMAIN.COMMITMENT_MASK,
    senderReceiverSecret, // key = s^ctx_sr
    amountBytes,
    addressSpendPubkey,
    typeBytes
  );
}

// =============================================================================
// VIEW TAG DERIVATION
// =============================================================================

/**
 * Derive CARROT view tag (3 bytes)
 * vt = H_3("Carrot view tag", s_sr, input_context, Ko)
 *
 * @param {Uint8Array} sharedSecret - Un-contextualized shared secret
 * @param {Uint8Array} inputContext - Input context
 * @param {Uint8Array} onetimeAddress - One-time address
 * @returns {Uint8Array} 3-byte view tag
 */
export function deriveCarrotViewTag(sharedSecret, inputContext, onetimeAddress) {
  return carrotHash3(
    CARROT_DOMAIN.VIEW_TAG,
    sharedSecret, // key = s_sr_unctx
    inputContext,
    onetimeAddress
  );
}

// =============================================================================
// ENCRYPTION
// =============================================================================

/**
 * Encrypt anchor for CARROT output
 * anchor_enc = anchor XOR H_16("Carrot encryption mask anchor", s^ctx_sr, Ko)
 *
 * @param {Uint8Array} anchor - 16-byte Janus anchor
 * @param {Uint8Array} senderReceiverSecret - Contextualized secret
 * @param {Uint8Array} onetimeAddress - One-time address
 * @returns {Uint8Array} 16-byte encrypted anchor
 */
export function encryptCarrotAnchor(anchor, senderReceiverSecret, onetimeAddress) {
  const mask = carrotHash16(
    CARROT_DOMAIN.ENCRYPTION_MASK_ANCHOR,
    senderReceiverSecret, // key = s^ctx_sr
    onetimeAddress
  );

  const encrypted = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    encrypted[i] = anchor[i] ^ mask[i];
  }
  return encrypted;
}

/**
 * Encrypt amount for CARROT output
 * amount_enc = amount XOR H_8("Carrot encryption mask a", s^ctx_sr, Ko)
 *
 * @param {bigint} amount - Amount to encrypt
 * @param {Uint8Array} senderReceiverSecret - Contextualized secret
 * @param {Uint8Array} onetimeAddress - One-time address
 * @returns {Uint8Array} 8-byte encrypted amount
 */
export function encryptCarrotAmount(amount, senderReceiverSecret, onetimeAddress) {
  const mask = carrotHash8(
    CARROT_DOMAIN.ENCRYPTION_MASK_AMOUNT,
    senderReceiverSecret, // key = s^ctx_sr
    onetimeAddress
  );

  // Amount to 8-byte little-endian
  const amountBytes = new Uint8Array(8);
  let a = amount;
  for (let i = 0; i < 8; i++) {
    amountBytes[i] = Number(a & 0xffn);
    a >>= 8n;
  }

  const encrypted = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    encrypted[i] = amountBytes[i] ^ mask[i];
  }
  return encrypted;
}

/**
 * Encrypt payment ID for CARROT output
 * pid_enc = payment_id XOR H_8("Carrot encryption mask pid", s^ctx_sr, Ko)
 *
 * @param {Uint8Array} paymentId - 8-byte payment ID
 * @param {Uint8Array} senderReceiverSecret - Contextualized secret
 * @param {Uint8Array} onetimeAddress - One-time address
 * @returns {Uint8Array} 8-byte encrypted payment ID
 */
export function encryptCarrotPaymentId(paymentId, senderReceiverSecret, onetimeAddress) {
  const mask = carrotHash8(
    CARROT_DOMAIN.ENCRYPTION_MASK_PAYMENT_ID,
    senderReceiverSecret, // key = s^ctx_sr
    onetimeAddress
  );

  const encrypted = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    encrypted[i] = paymentId[i] ^ mask[i];
  }
  return encrypted;
}

// =============================================================================
// COMPLETE OUTPUT CREATION
// =============================================================================

/**
 * Create a complete CARROT output
 *
 * @param {Object} params - Parameters
 * @param {Uint8Array} params.addressSpendPubkey - Recipient's spend public key (K_s)
 * @param {Uint8Array} params.addressViewPubkey - Recipient's view public key (K_v)
 * @param {bigint} params.amount - Amount to send
 * @param {Uint8Array} params.inputContext - Transaction input context
 * @param {Uint8Array} params.paymentId - 8-byte payment ID (optional, defaults to zeros)
 * @param {number} params.enoteType - Enote type (optional, defaults to PAYMENT)
 * @param {boolean} params.isSubaddress - Whether recipient is subaddress
 * @param {Uint8Array} params.anchor - Janus anchor (optional, generated if not provided)
 * @returns {Object} CARROT output with all components
 */
export function createCarrotOutput(params) {
  const {
    addressSpendPubkey,
    addressViewPubkey,
    amount,
    inputContext,
    paymentId = new Uint8Array(8),
    enoteType = CARROT_ENOTE_TYPE.PAYMENT,
    isSubaddress = false,
    anchor = generateJanusAnchor(),
    isCoinbase = false
  } = params;

  // 1. Derive ephemeral private key
  const ephemeralPrivkey = deriveCarrotEphemeralPrivkey(
    anchor,
    inputContext,
    addressSpendPubkey,
    paymentId
  );

  // 2. Compute ephemeral public key
  const ephemeralPubkey = computeCarrotEphemeralPubkey(
    ephemeralPrivkey,
    addressSpendPubkey,
    isSubaddress
  );

  // 3. Compute shared secret (un-contextualized)
  const sharedSecret = computeCarrotSharedSecret(ephemeralPrivkey, addressViewPubkey);

  // 4. Derive contextualized sender-receiver secret
  const senderReceiverSecret = deriveCarrotSenderReceiverSecret(
    sharedSecret,
    ephemeralPubkey,
    inputContext
  );

  // 5. Derive amount blinding factor
  // For coinbase: k_a = 1 (scalar 1), matching C++ sc_1()
  let amountBlindingFactor;
  if (isCoinbase) {
    amountBlindingFactor = new Uint8Array(32);
    amountBlindingFactor[0] = 1;
  } else {
    amountBlindingFactor = deriveCarrotAmountBlindingFactor(
      senderReceiverSecret,
      amount,
      addressSpendPubkey,
      enoteType
    );
  }

  // 6. Create amount commitment
  const amountCommitment = commit(amount, amountBlindingFactor);

  // 7. Derive one-time address extension keys
  const { extensionG, extensionT } = deriveCarrotOnetimeExtensions(
    senderReceiverSecret,
    amountCommitment
  );

  // 8. Compute one-time address
  const onetimeAddress = computeCarrotOnetimeAddress(
    addressSpendPubkey,
    extensionG,
    extensionT
  );

  // 9. Derive view tag
  const viewTag = deriveCarrotViewTag(sharedSecret, inputContext, onetimeAddress);

  // 10. Encrypt components
  const anchorEncrypted = encryptCarrotAnchor(anchor, senderReceiverSecret, onetimeAddress);
  const amountEncrypted = encryptCarrotAmount(amount, senderReceiverSecret, onetimeAddress);
  const paymentIdEncrypted = encryptCarrotPaymentId(paymentId, senderReceiverSecret, onetimeAddress);

  return {
    // Public output data
    ephemeralPubkey,
    onetimeAddress,
    amountCommitment,
    amountEncrypted,
    anchorEncrypted,
    viewTag,
    paymentIdEncrypted,

    // Private data (needed for spending)
    amountBlindingFactor,
    extensionG,
    extensionT,
    senderReceiverSecret,

    // Input data for reference
    anchor,
    inputContext,
    enoteType
  };
}

/**
 * Compute special Janus anchor for self-sends
 * anchor_sp = H_16("Carrot janus anchor special", D_e, input_context, Ko, k_v)
 *
 * @param {Uint8Array} ephemeralPubkey - Ephemeral public key
 * @param {Uint8Array} inputContext - Input context
 * @param {Uint8Array} onetimeAddress - One-time address
 * @param {Uint8Array} viewSecretKey - View secret key
 * @returns {Uint8Array} 16-byte special anchor
 */
export function computeCarrotSpecialAnchor(ephemeralPubkey, inputContext, onetimeAddress, viewSecretKey) {
  return carrotHash16(
    CARROT_DOMAIN.JANUS_ANCHOR_SPECIAL,
    viewSecretKey, // key = k_v
    ephemeralPubkey,
    inputContext,
    onetimeAddress
  );
}
