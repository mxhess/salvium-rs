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

import { blake2b } from '../blake2b.js';
import { hexToBytes } from '../address.js';
import { scalarMultBase, scalarMultPoint, pointAddCompressed, getGeneratorT } from '../ed25519.js';

import { CARROT_DOMAIN, CARROT_ENOTE_TYPE } from './constants.js';
import { scReduce32, bigIntToBytes, commit } from './serialization.js';

// =============================================================================
// CARROT HASH FUNCTIONS
// =============================================================================

/**
 * Hash data with domain separation using Blake2b
 * @param {string} domain - Domain separator string
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 32-byte hash
 */
function carrotHash32(domain, ...data) {
  const domainBytes = new TextEncoder().encode(domain);
  let totalLen = domainBytes.length;

  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  combined.set(domainBytes, offset);
  offset += domainBytes.length;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  return blake2b(combined, 32);
}

/**
 * Hash to scalar with domain separation (CARROT)
 * @param {string} domain - Domain separator
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 32-byte scalar < L
 */
function carrotHashToScalar(domain, ...data) {
  const hash = carrotHash32(domain, ...data);
  return scReduce32(hash);
}

/**
 * Hash to 16 bytes (for anchor, etc.)
 * @param {string} domain - Domain separator
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 16-byte hash
 */
function carrotHash16(domain, ...data) {
  const domainBytes = new TextEncoder().encode(domain);
  let totalLen = domainBytes.length;

  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  combined.set(domainBytes, offset);
  offset += domainBytes.length;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  return blake2b(combined, 16);
}

/**
 * Hash to 8 bytes (for amount/payment ID encryption)
 * @param {string} domain - Domain separator
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 8-byte hash
 */
function carrotHash8(domain, ...data) {
  const domainBytes = new TextEncoder().encode(domain);
  let totalLen = domainBytes.length;

  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  combined.set(domainBytes, offset);
  offset += domainBytes.length;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  return blake2b(combined, 8);
}

/**
 * Hash to 3 bytes (for view tag)
 * @param {string} domain - Domain separator
 * @param {...(Uint8Array|string)} data - Data to hash
 * @returns {Uint8Array} 3-byte hash
 */
function carrotHash3(domain, ...data) {
  const domainBytes = new TextEncoder().encode(domain);
  let totalLen = domainBytes.length;

  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  combined.set(domainBytes, offset);
  offset += domainBytes.length;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  return blake2b(combined, 3);
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
    anchor,
    inputContext,
    addressSpendPubkey,
    paymentId
  );
}

/**
 * Compute CARROT ephemeral public key
 * For main address: D_e = d_e * G (on X25519 curve)
 * For subaddress: D_e = d_e * ConvertPointE(K_s)
 *
 * For simplicity, we use Ed25519 scalar multiplication
 * (full X25519 conversion would be needed for production)
 *
 * @param {Uint8Array} ephemeralPrivkey - Ephemeral private key (d_e)
 * @param {Uint8Array} addressSpendPubkey - Address spend pubkey (for subaddress)
 * @param {boolean} isSubaddress - Whether target is a subaddress
 * @returns {Uint8Array} 32-byte ephemeral public key
 */
export function computeCarrotEphemeralPubkey(ephemeralPrivkey, addressSpendPubkey, isSubaddress = false) {
  if (isSubaddress) {
    // D_e = d_e * K_s
    return scalarMultPoint(ephemeralPrivkey, addressSpendPubkey);
  } else {
    // D_e = d_e * G
    return scalarMultBase(ephemeralPrivkey);
  }
}

// =============================================================================
// SHARED SECRET DERIVATION
// =============================================================================

/**
 * Compute CARROT sender-receiver shared secret (un-contextualized)
 * s_sr = d_e * K_v (sender side)
 * s_sr = k_v * D_e (receiver side)
 *
 * @param {Uint8Array} ephemeralPrivkey - Ephemeral private key
 * @param {Uint8Array} addressViewPubkey - Address view public key
 * @returns {Uint8Array} 32-byte shared secret
 */
export function computeCarrotSharedSecret(ephemeralPrivkey, addressViewPubkey) {
  return scalarMultPoint(ephemeralPrivkey, addressViewPubkey);
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
    ephemeralPubkey,
    inputContext,
    sharedSecret
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
    senderReceiverSecret,
    amountCommitment
  );

  const extensionT = carrotHashToScalar(
    CARROT_DOMAIN.ONETIME_EXTENSION_T,
    senderReceiverSecret,
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
    senderReceiverSecret,
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
    sharedSecret,
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
    senderReceiverSecret,
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
    senderReceiverSecret,
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
    senderReceiverSecret,
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
    anchor = generateJanusAnchor()
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
  const amountBlindingFactor = deriveCarrotAmountBlindingFactor(
    senderReceiverSecret,
    amount,
    addressSpendPubkey,
    enoteType
  );

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
    ephemeralPubkey,
    inputContext,
    onetimeAddress,
    viewSecretKey
  );
}
