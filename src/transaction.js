/**
 * Transaction Construction Module
 *
 * Implements the cryptographic primitives needed for Salvium transaction construction:
 * - Scalar operations mod L (subgroup order)
 * - Pedersen commitments
 * - One-time destination key generation
 * - CLSAG ring signatures
 *
 * Reference: Salvium/Monero src/ringct/rctOps.cpp, src/ringct/rctSigs.cpp
 */

import {
  keccak256, keccak256Hex, scalarMultBase, scalarMultPoint, pointAddCompressed,
  getGeneratorG, getGeneratorT,
  generateKeyDerivation, derivePublicKey, deriveSecretKey,
  derivationToScalar, deriveViewTag,
  hashToPoint, generateKeyImage,
  getCryptoBackend,
} from './crypto/index.js';
import { bytesToHex, hexToBytes } from './address.js';
import { bulletproofPlusProve, serializeProof as serializeBpPlus } from './bulletproofs_plus.js';
import { getTxVersion, getRctType, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW } from './consensus.js';
import { getDynamicFeePerByte } from './transaction/fee.js';
import { zeroCommit } from './transaction/serialization.js';

// =============================================================================
// RE-EXPORTS FROM SUBMODULES
// =============================================================================

// Constants
export {
  ParseError,
  L, P, H,
  TX_VERSION, TX_TYPE, RCT_TYPE, TXOUT_TYPE, TXIN_TYPE,
  DIFFICULTY_TARGET, RECENT_SPEND_WINDOW,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, DEFAULT_RING_SIZE,
  HF_VERSION_ENABLE_ORACLE,
  FEE_PER_KB, FEE_PER_BYTE,
  DYNAMIC_FEE_PER_KB_BASE_FEE, DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD,
  DYNAMIC_FEE_REFERENCE_TX_WEIGHT, FEE_QUANTIZATION_DECIMALS,
  FEE_MULTIPLIERS, FEE_PRIORITY, getFeeMultiplier,
  UTXO_STRATEGY,
  CARROT_DOMAIN, CARROT_ENOTE_TYPE
} from './transaction/constants.js';

// Serialization
export {
  bytesToBigInt, bigIntToBytes,
  scReduce32, scReduce64,
  scAdd, scSub, scMul, scMulAdd, scMulSub,
  scCheck, scIsZero, scRandom, scInvert,
  commit, zeroCommit, genCommitmentMask,
  encodeVarint, decodeVarint, concatBytes,
  serializeTxOutput, serializeTxInput, serializeGenInput,
  serializeTxExtra, serializeTxPrefix, getTxPrefixHash,
  serializeCLSAG, serializeRctBase, serializeEcdhInfo, serializeOutPk,
  serializeTransaction
} from './transaction/serialization.js';

// UTXO selection
export { selectUTXOs } from './transaction/utxo.js';

// Parsing
export {
  parseTransaction, parseExtra, parsePricingRecord, parseBlock
} from './transaction/parsing.js';

// Analysis
export {
  getTransactionHashFromParsed, decodeAmount,
  extractTxPubKey, extractPaymentId, extractAdditionalPubKeys,
  summarizeTransaction, getTransactionTypeName, getRctTypeName,
  analyzeTransaction
} from './transaction/analysis.js';

// Dynamic fee calculation
export {
  getBlockReward, estimateAlreadyGeneratedCoins,
  getDynamicBaseFee, getDynamicFeeEstimate2021, getDynamicFeePerByte,
  computeNeededFee, roundMoneyUp, getMinBlockWeight, getFeeQuantizationMask,
  MONEY_SUPPLY, PREMINE_AMOUNT,
  EMISSION_SPEED_FACTOR_PER_MINUTE as EMISSION_SPEED,
} from './transaction/fee.js';

// CARROT output generation
export {
  generateJanusAnchor, buildRingCtInputContext, buildCoinbaseInputContext,
  deriveCarrotEphemeralPrivkey, computeCarrotEphemeralPubkey,
  computeCarrotSharedSecret, deriveCarrotSenderReceiverSecret,
  deriveCarrotOnetimeExtensions, computeCarrotOnetimeAddress,
  deriveCarrotAmountBlindingFactor, deriveCarrotViewTag,
  encryptCarrotAnchor, encryptCarrotAmount, encryptCarrotPaymentId,
  createCarrotOutput, computeCarrotSpecialAnchor
} from './transaction/carrot-output.js';

// Block serialization
export {
  serializeSupplyData, serializeAssetData, serializePricingRecord,
  serializeBlockHeader, serializeBlock, getBlockHash, computeMerkleRoot
} from './block/serialization.js';

// =============================================================================
// IMPORTS FROM SUBMODULES (used by unique code below)
// =============================================================================

import {
  TX_VERSION as _TX_VERSION, TX_TYPE as _TX_TYPE, RCT_TYPE as _RCT_TYPE,
  TXOUT_TYPE as _TXOUT_TYPE, TXIN_TYPE as _TXIN_TYPE,
  L as _L,
  DIFFICULTY_TARGET as _DIFFICULTY_TARGET,
  RECENT_SPEND_WINDOW as _RECENT_SPEND_WINDOW,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE as _CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
  DEFAULT_RING_SIZE as _DEFAULT_RING_SIZE,
  FEE_PER_KB as _FEE_PER_KB, FEE_PER_BYTE as _FEE_PER_BYTE,
  FEE_PRIORITY as _FEE_PRIORITY,
  CARROT_ENOTE_TYPE as _CARROT_ENOTE_TYPE,
  getFeeMultiplier as _getFeeMultiplier
} from './transaction/constants.js';

import {
  bytesToBigInt as _bytesToBigInt, bigIntToBytes as _bigIntToBytes,
  scReduce32 as _scReduce32, scInvert as _scInvert,
  scAdd as _scAdd, scSub as _scSub, scMul as _scMul, scMulAdd as _scMulAdd, scRandom as _scRandom,
  commit as _commit, genCommitmentMask as _genCommitmentMask,
  serializeTxPrefix as _serializeTxPrefix, getTxPrefixHash as _getTxPrefixHash,
  serializeRctBase as _serializeRctBase,
  serializeCLSAG as _serializeCLSAG, serializeTCLSAG as _serializeTCLSAG,
  encodeVarint as _encodeVarint, concatBytes as _concatBytes
} from './transaction/serialization.js';

// Local aliases for use in this file
const TX_VERSION = _TX_VERSION;
const TX_TYPE = _TX_TYPE;
const RCT_TYPE = _RCT_TYPE;
const TXOUT_TYPE = _TXOUT_TYPE;
const TXIN_TYPE = _TXIN_TYPE;
const L = _L;
const DIFFICULTY_TARGET = _DIFFICULTY_TARGET;
const RECENT_SPEND_WINDOW = _RECENT_SPEND_WINDOW;
const CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = _CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
const DEFAULT_RING_SIZE = _DEFAULT_RING_SIZE;
const FEE_PER_KB = _FEE_PER_KB;
const FEE_PER_BYTE = _FEE_PER_BYTE;
const FEE_PRIORITY = _FEE_PRIORITY;
const getFeeMultiplier = _getFeeMultiplier;
const bytesToBigInt = _bytesToBigInt;
const bigIntToBytes = _bigIntToBytes;
const scReduce32 = _scReduce32;
const scInvert = _scInvert;
const scAdd = _scAdd;
const scSub = _scSub;
const scMul = _scMul;
const scMulAdd = _scMulAdd;
const scRandom = _scRandom;
const commit = _commit;
const genCommitmentMask = _genCommitmentMask;
const serializeTxPrefix = _serializeTxPrefix;
const getTxPrefixHash = _getTxPrefixHash;
const serializeRctBase = _serializeRctBase;
const CARROT_ENOTE_TYPE = _CARROT_ENOTE_TYPE;

// Local imports for CARROT output creation (re-exported above, need local refs)
import {
  generateJanusAnchor as _generateJanusAnchor,
  buildRingCtInputContext as _buildRingCtInputContext,
  deriveCarrotEphemeralPrivkey as _deriveCarrotEphemeralPrivkey,
  computeCarrotEphemeralPubkey as _computeCarrotEphemeralPubkey,
  computeCarrotSharedSecret as _computeCarrotSharedSecret,
  deriveCarrotSenderReceiverSecret as _deriveCarrotSenderReceiverSecret,
  deriveCarrotOnetimeExtensions as _deriveCarrotOnetimeExtensions,
  computeCarrotOnetimeAddress as _computeCarrotOnetimeAddress,
  deriveCarrotAmountBlindingFactor as _deriveCarrotAmountBlindingFactor,
  deriveCarrotViewTag as _deriveCarrotViewTag,
  encryptCarrotAnchor as _encryptCarrotAnchor,
  encryptCarrotAmount as _encryptCarrotAmount,
  computeCarrotSpecialAnchor as _computeCarrotSpecialAnchor
} from './transaction/carrot-output.js';

// =============================================================================
// OUTPUT CREATION
// =============================================================================

/**
 * Generate one-time output keys for a transaction output
 *
 * For a standard address (B, A):
 *   - r = random scalar (tx secret key)
 *   - R = r*G (tx public key, goes in tx extra)
 *   - D = r*A = r*a*G (key derivation, computed by recipient as a*R)
 *   - s = H_s(D, outputIndex) (scalar)
 *   - P = s*G + B (one-time output public key)
 *
 * For a subaddress (D_i, C_i):
 *   - r = random scalar
 *   - R = r*D_i (not r*G!)
 *   - derivation = r*C_i
 *   - s = H_s(derivation, outputIndex)
 *   - P = s*G + D_i
 *
 * @param {Uint8Array|string} txSecretKey - Transaction secret key (r)
 * @param {Uint8Array|string} viewPublicKey - Recipient's view public key (A or C_i)
 * @param {Uint8Array|string} spendPublicKey - Recipient's spend public key (B or D_i)
 * @param {number} outputIndex - Output index in transaction
 * @param {boolean} isSubaddress - True if destination is a subaddress
 * @returns {Object} { outputPublicKey, txPublicKey, derivation }
 */
export function generateOutputKeys(txSecretKey, viewPublicKey, spendPublicKey, outputIndex, isSubaddress = false) {
  if (typeof txSecretKey === 'string') txSecretKey = hexToBytes(txSecretKey);
  if (typeof viewPublicKey === 'string') viewPublicKey = hexToBytes(viewPublicKey);
  if (typeof spendPublicKey === 'string') spendPublicKey = hexToBytes(spendPublicKey);

  let txPublicKey;
  let derivation;

  if (isSubaddress) {
    // For subaddress: R = r*D (spend public key), derivation = r*C (view public key)
    txPublicKey = scalarMultPoint(txSecretKey, spendPublicKey);
    derivation = scalarMultPoint(txSecretKey, viewPublicKey);
  } else {
    // For standard address: R = r*G, derivation = r*A (view public key)
    txPublicKey = scalarMultBase(txSecretKey);
    derivation = scalarMultPoint(txSecretKey, viewPublicKey);
  }

  // Multiply by 8 for cofactor clearing (generateKeyDerivation does this internally)
  // Actually we need to use the same approach as scanning
  // derivation should be 8*r*A = key derivation
  const keyDerivation = generateKeyDerivation(viewPublicKey, txSecretKey);

  // Derive the one-time output public key
  const outputPublicKey = derivePublicKey(keyDerivation, outputIndex, spendPublicKey);

  return {
    outputPublicKey,
    txPublicKey,
    derivation: keyDerivation
  };
}

/**
 * Create a complete transaction output
 *
 * @param {Uint8Array|string} txSecretKey - Transaction secret key
 * @param {Uint8Array|string} viewPublicKey - Recipient's view public key
 * @param {Uint8Array|string} spendPublicKey - Recipient's spend public key
 * @param {bigint|number} amount - Amount to send
 * @param {number} outputIndex - Output index
 * @param {boolean} isSubaddress - True if destination is a subaddress
 * @returns {Object} { outputPublicKey, txPublicKey, commitment, encryptedAmount, mask }
 */
export function createOutput(txSecretKey, viewPublicKey, spendPublicKey, amount, outputIndex, isSubaddress = false) {
  if (typeof amount === 'number') amount = BigInt(amount);

  // Generate one-time keys
  const { outputPublicKey, txPublicKey, derivation } = generateOutputKeys(
    txSecretKey, viewPublicKey, spendPublicKey, outputIndex, isSubaddress
  );

  // Generate the commitment mask from the derivation
  const scalar = derivationToScalar(derivation, outputIndex);
  const mask = genCommitmentMask(scalar);

  // Create the Pedersen commitment
  const commitment = commit(amount, mask);

  // Encrypt the amount (XOR with first 8 bytes of H_s("amount" || scalar))
  const amountKey = deriveAmountKey(scalar);
  const encryptedAmount = encryptAmount(amount, amountKey);

  // Derive view tag for tagged key outputs
  const viewTag = deriveViewTag(derivation, outputIndex);

  return {
    outputPublicKey,
    txPublicKey,
    commitment,
    encryptedAmount,
    mask,
    derivation,
    viewTag
  };
}

/**
 * Derive amount encryption key from scalar
 * @param {Uint8Array|string} scalar - Derivation scalar
 * @returns {Uint8Array} 8-byte amount key
 */
function deriveAmountKey(scalar) {
  if (typeof scalar === 'string') scalar = hexToBytes(scalar);

  const prefix = new TextEncoder().encode('amount');
  const data = new Uint8Array(prefix.length + scalar.length);
  data.set(prefix, 0);
  data.set(scalar, prefix.length);

  const hash = keccak256(data);
  return hash.slice(0, 8);
}

/**
 * Encrypt amount using XOR
 * @param {bigint} amount - Amount to encrypt
 * @param {Uint8Array} key - 8-byte encryption key
 * @returns {Uint8Array} 8-byte encrypted amount
 */
function encryptAmount(amount, key) {
  const amountBytes = new Uint8Array(8);
  let a = amount;
  for (let i = 0; i < 8; i++) {
    amountBytes[i] = Number(a & 0xffn) ^ key[i];
    a >>= 8n;
  }
  return amountBytes;
}

// =============================================================================
// CLSAG SIGNATURES
// =============================================================================

/**
 * Hash data for CLSAG aggregate coefficient computation
 * @param {Array} data - Array of items to hash
 * @returns {Uint8Array} 32-byte hash
 */
function hashToScalar(...data) {
  let totalLen = 0;
  const processed = data.map(item => {
    if (typeof item === 'string') item = hexToBytes(item);
    totalLen += item.length;
    return item;
  });

  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const item of processed) {
    combined.set(item, offset);
    offset += item.length;
  }

  const hash = keccak256(combined);
  return scReduce32(hash);
}

// =============================================================================
// SALVIUM p_r AND pr_proof (RETURN ADDRESS PROOF)
// =============================================================================

/**
 * Compute p_r: the blinding factor remainder commitment.
 *
 * p_r = difference * G where difference = sum(pseudoOut_masks) - sum(output_masks)
 *
 * Reference: Salvium rctSigs.cpp lines 1816-1818
 *   sc_sub(difference.bytes, sumpouts.bytes, sumout.bytes);
 *   genC(rv.p_r, difference, 0);   // commitment with amount=0
 *
 * @param {Array<Uint8Array>} pseudoMasks - Pseudo output mask scalars
 * @param {Array<Uint8Array>} outputMasks - Output mask scalars
 * @returns {{ p_r: Uint8Array, difference: Uint8Array }} p_r point (32 bytes) and difference scalar
 */
export function computePR(pseudoMasks, outputMasks) {
  // Sum pseudo output masks
  let sumPseudo = new Uint8Array(32);
  for (const m of pseudoMasks) {
    const mask = typeof m === 'string' ? hexToBytes(m) : m;
    sumPseudo = scAdd(sumPseudo, mask);
  }

  // Sum output masks
  let sumOut = new Uint8Array(32);
  for (const m of outputMasks) {
    const mask = typeof m === 'string' ? hexToBytes(m) : m;
    sumOut = scAdd(sumOut, mask);
  }

  // difference = sumPseudo - sumOut
  const difference = scSub(sumPseudo, sumOut);

  // p_r = difference * G (genC with amount=0 is just scalarmultBase)
  const p_r = scalarMultBase(difference);

  return { p_r, difference };
}

/**
 * Generate a Schnorr proof of knowledge of the discrete log of p_r.
 *
 * Proves: "I know `difference` such that p_r = difference * G"
 *
 * Reference: Salvium rctSigs.cpp PRProof_Gen (lines 680-701)
 *   r = random scalar
 *   R = r * G
 *   c = H(R || p_r)
 *   z1 = r + c * difference
 *   z2 = 0
 *
 * @param {Uint8Array} difference - The scalar whose DL we're proving
 * @param {Uint8Array} p_r - The commitment point (= difference * G)
 * @returns {{ R: Uint8Array, z1: Uint8Array, z2: Uint8Array }} zk_proof
 */
export function generatePRProof(difference, p_r) {
  // Random nonce
  const r = scRandom();

  // R = r * G
  const R = scalarMultBase(r);

  // c = H(R || p_r)  — hash two points to scalar
  const c = hashToScalar(R, p_r);

  // z1 = r + c * difference
  const z1 = scMulAdd(c, difference, r);

  // z2 = 0 (unused)
  const z2 = new Uint8Array(32);

  return { R, z1, z2 };
}

/**
 * Domain separator for CLSAG
 * C++ pads these to 32 bytes (sc_0 then memcpy)
 * Reference: rctSigs.cpp lines 1242-1245, 1266-1267
 */
function padDomain(str) {
  const bytes = new Uint8Array(32);
  const encoded = new TextEncoder().encode(str);
  bytes.set(encoded.slice(0, 32)); // Copy up to 32 bytes, rest stays zero
  return bytes;
}
const CLSAG_AGG_0 = padDomain('CLSAG_agg_0');
const CLSAG_AGG_1 = padDomain('CLSAG_agg_1');
const CLSAG_ROUND = padDomain('CLSAG_round');

/**
 * Generate a CLSAG signature
 *
 * CLSAG (Compact Linkable Anonymous Group) signatures are ring signatures
 * that prove ownership of one input in a ring without revealing which one.
 *
 * @param {Uint8Array|string} message - Message to sign (usually pre-MLSAG hash)
 * @param {Array<Uint8Array>} ring - Array of public keys in the ring
 * @param {Uint8Array|string} secretKey - Secret key corresponding to ring[secretIndex]
 * @param {Array<Uint8Array>} commitments - Array of commitments C_i for each ring member
 * @param {Uint8Array|string} commitmentMask - Mask for our commitment (z)
 * @param {Uint8Array|string} pseudoOutputCommitment - Pseudo output commitment C'
 * @param {number} secretIndex - Index of our key in the ring
 * @returns {Object} CLSAG signature { s: Array, c1, I (key image), D (commitment key image) }
 */
export function clsagSign(message, ring, secretKey, commitments, commitmentMask, pseudoOutputCommitment, secretIndex) {
  if (typeof message === 'string') message = hexToBytes(message);
  if (typeof secretKey === 'string') secretKey = hexToBytes(secretKey);
  if (typeof commitmentMask === 'string') commitmentMask = hexToBytes(commitmentMask);
  if (typeof pseudoOutputCommitment === 'string') pseudoOutputCommitment = hexToBytes(pseudoOutputCommitment);

  // Normalize inputs
  ring = ring.map(k => typeof k === 'string' ? hexToBytes(k) : k);
  commitments = commitments.map(c => typeof c === 'string' ? hexToBytes(c) : c);

  // Try accelerated backend (WASM/JSI)
  const backend = getCryptoBackend();
  const nativeResult = backend.clsagSign(message, ring, secretKey, commitments, commitmentMask, pseudoOutputCommitment, secretIndex);
  if (nativeResult !== null) return nativeResult;

  const n = ring.length; // Ring size

  // Validate ring data
  for (let _i = 0; _i < ring.length; _i++) {
    if (!ring[_i] || ring[_i].length !== 32) {
      throw new Error(`clsagSign: invalid ring member at index ${_i} (${ring[_i]?.length || 'null'})`);
    }
  }
  for (let _i = 0; _i < commitments.length; _i++) {
    if (!commitments[_i] || commitments[_i].length !== 32) {
      throw new Error(`clsagSign: invalid commitment at index ${_i} (${commitments[_i]?.length || 'null'})`);
    }
  }

  // Compute commitment differences: C_i - C' (should be commitment to 0 for real input)
  // C[i] = commitment[i] - pseudoOutputCommitment
  const C = commitments.map(c => pointSub(c, pseudoOutputCommitment));

  // Compute key image: I = x * H_p(P)
  const P_l = ring[secretIndex];
  if (!P_l) throw new Error(`clsagSign: ring[${secretIndex}] (P_l) is null/undefined`);
  const I = generateKeyImage(P_l, secretKey);
  if (!I) throw new Error('clsagSign: generateKeyImage returned null');

  // Compute commitment key image: D = z * H_p(P)
  // where z = commitmentMask - pseudoOutputMask
  const H_P = hashToPoint(P_l);
  if (!H_P) throw new Error('clsagSign: hashToPoint returned null');
  const D = scalarMultPoint(commitmentMask, H_P);
  if (!D) throw new Error('clsagSign: scalarMultPoint returned null for D');

  // D_8 = D * (1/8) — stored in signature and used in aggregation hash
  // Matches C++ CLSAG_Gen line 278: scalarmultKey(sig.D, D, INV_EIGHT)
  const INV_EIGHT_SCALAR = hexToBytes('792fdce229e50661d0da1c7db39dd30700000000000000000000000000000006');
  const D_8 = scalarMultPoint(INV_EIGHT_SCALAR, D);

  // Compute aggregate coefficients mu_P and mu_C
  // C++ order: [domain, P[0..n-1], C_nonzero[0..n-1], I, D_8, C_offset]
  const aggData = [
    ...ring,
    ...commitments,  // C_nonzero (original commitments, NOT differences)
    I,
    D_8,
    pseudoOutputCommitment  // C_offset
  ];
  const mu_P = hashToScalar(CLSAG_AGG_0, ...aggData);
  const mu_C = hashToScalar(CLSAG_AGG_1, ...aggData);

  // Initialize signature arrays
  const s = new Array(n);

  // Generate random scalar for the real input
  const alpha = scRandom();

  // Compute initial values: aG = alpha * G, aH = alpha * H_p(P_l)
  const aG = scalarMultBase(alpha);
  const aH = scalarMultPoint(alpha, H_P);

  // Build the base hash data (matches Salvium C++ rctSigs.cpp:305-320)
  // c_to_hash = [domain, P[0..n-1], C_nonzero[0..n-1], C_offset, message, L, R]
  const buildChallengeHash = (L, R) => {
    return hashToScalar(CLSAG_ROUND, ...ring, ...commitments, pseudoOutputCommitment, message, L, R);
  };

  // Start the ring: first challenge from alpha commitments
  let c = buildChallengeHash(aG, aH);

  // c1 will be captured when loop index becomes 0
  // Per Salvium C++ (rctSigs.cpp:325-326, 364-365):
  // c1 is saved when i wraps to 0
  let c1 = null;

  // Start at position after secret index
  let i = (secretIndex + 1) % n;

  // If we start at index 0, capture c1 immediately
  if (i === 0) {
    c1 = new Uint8Array(c);
  }

  // Go around the ring until we reach the secret index
  while (i !== secretIndex) {
    // Generate random s[i] for this decoy position
    s[i] = scRandom();

    // Compute H_p(P_i) - hash to point of this ring member's public key
    const H_P_i = hashToPoint(ring[i]);

    // Weighted challenges: c_p = mu_P * c, c_c = mu_C * c
    const c_mu_P = scMul(c, mu_P);
    const c_mu_C = scMul(c, mu_C);

    // L = s[i]*G + c_p*P[i] + c_c*C[i]
    const sG = scalarMultBase(s[i]);
    const c_mu_P_Pi = scalarMultPoint(c_mu_P, ring[i]);
    const c_mu_C_Ci = scalarMultPoint(c_mu_C, C[i]);
    const L = pointAddCompressed(pointAddCompressed(sG, c_mu_P_Pi), c_mu_C_Ci);

    // R = s[i]*H_p(P[i]) + c_p*I + c_c*D
    const sH = scalarMultPoint(s[i], H_P_i);
    const c_mu_P_I = scalarMultPoint(c_mu_P, I);
    const c_mu_C_D = scalarMultPoint(c_mu_C, D);
    const R = pointAddCompressed(pointAddCompressed(sH, c_mu_P_I), c_mu_C_D);

    // Next challenge: c = H_n(domain, P[0..n-1], C[0..n-1], C_offset, message, L, R)
    c = buildChallengeHash(L, R);

    // Advance to next ring member
    i = (i + 1) % n;

    // Capture c1 when we wrap to index 0
    if (i === 0) {
      c1 = new Uint8Array(c);
    }
  }

  // Now c is the challenge at the secret position (c_l)
  // Compute s[l] to close the ring:
  // s[l] = alpha - c * (mu_P * p + mu_C * z)
  const mu_P_p = scMul(mu_P, secretKey);
  const mu_C_z = scMul(mu_C, commitmentMask);
  const sum = scAdd(mu_P_p, mu_C_z);
  const c_sum = scMul(c, sum);
  s[secretIndex] = scSub(alpha, c_sum);

  // If c1 wasn't captured (secretIndex == 0 and n == 1), compute it now
  // by doing one more round with the completed s[0]
  if (c1 === null) {
    // Single member ring or secretIndex caused us to miss capture
    // Recompute: after s[l] is set, we can compute what c1 would be
    // by computing L_l, R_l with s[l] and c_l
    const H_P_l = hashToPoint(ring[secretIndex]);
    const c_mu_P = scMul(c, mu_P);
    const c_mu_C = scMul(c, mu_C);

    const sG = scalarMultBase(s[secretIndex]);
    const c_mu_P_Pl = scalarMultPoint(c_mu_P, ring[secretIndex]);
    const c_mu_C_Cl = scalarMultPoint(c_mu_C, C[secretIndex]);
    const L = pointAddCompressed(pointAddCompressed(sG, c_mu_P_Pl), c_mu_C_Cl);

    const sH = scalarMultPoint(s[secretIndex], H_P_l);
    const c_mu_P_I = scalarMultPoint(c_mu_P, I);
    const c_mu_C_D = scalarMultPoint(c_mu_C, D);
    const R = pointAddCompressed(pointAddCompressed(sH, c_mu_P_I), c_mu_C_D);

    c1 = buildChallengeHash(L, R);
  }

  return {
    s: s.map(si => bytesToHex(si)),
    c1: bytesToHex(c1),
    I: bytesToHex(I),
    D: bytesToHex(D_8)  // Store D*INV_EIGHT as per C++ CLSAG_Gen
  };
}

/**
 * Generate a TCLSAG (Twin CLSAG) signature
 *
 * TCLSAG uses dual secret keys (x, y) and two generators (G, T) for enhanced
 * security. Used in RCTTypeSalviumOne transactions.
 *
 * Key differences from CLSAG:
 * - Two secret keys: x (spend component) and y (auxiliary component)
 * - Two random scalars: a and b
 * - Initial L = a*G + b*T, R = a*H(P)
 * - Two response arrays: sx[] and sy[]
 * - Final: sx[l] = a - c*(mu_P*x + mu_C*z), sy[l] = b - c*mu_P*y
 *
 * Reference: Salvium rctSigs.cpp TCLSAG_Gen (lines 375-520)
 *
 * @param {Uint8Array|string} message - Message to sign (usually pre-MLSAG hash)
 * @param {Array<Uint8Array>} ring - Array of public keys in the ring
 * @param {Uint8Array|string} secretKeyX - X component of secret key (spend key)
 * @param {Uint8Array|string} secretKeyY - Y component of secret key (auxiliary)
 * @param {Array<Uint8Array>} commitments - Array of non-zero commitments for each ring member
 * @param {Uint8Array|string} commitmentMask - Mask for our commitment (z)
 * @param {Uint8Array|string} pseudoOutputCommitment - Pseudo output commitment C'
 * @param {number} secretIndex - Index of our key in the ring
 * @returns {Object} TCLSAG signature { sx: Array, sy: Array, c1, I (key image), D (commitment key image) }
 */
export function tclsagSign(message, ring, secretKeyX, secretKeyY, commitments, commitmentMask, pseudoOutputCommitment, secretIndex) {
  if (typeof message === 'string') message = hexToBytes(message);
  if (typeof secretKeyX === 'string') secretKeyX = hexToBytes(secretKeyX);
  if (typeof secretKeyY === 'string') secretKeyY = hexToBytes(secretKeyY);
  if (typeof commitmentMask === 'string') commitmentMask = hexToBytes(commitmentMask);
  if (typeof pseudoOutputCommitment === 'string') pseudoOutputCommitment = hexToBytes(pseudoOutputCommitment);

  // Normalize inputs
  ring = ring.map(k => typeof k === 'string' ? hexToBytes(k) : k);
  commitments = commitments.map(c => typeof c === 'string' ? hexToBytes(c) : c);

  // Try accelerated backend (WASM/JSI)
  const backend = getCryptoBackend();
  const nativeResult = backend.tclsagSign(message, ring, secretKeyX, secretKeyY, commitments, commitmentMask, pseudoOutputCommitment, secretIndex);
  if (nativeResult !== null) return nativeResult;

  const n = ring.length; // Ring size

  // Get generator T (second basis point)
  const T = getGeneratorT();

  // Compute commitment differences: C[i] = commitment[i] - pseudoOutputCommitment
  const C = commitments.map(c => pointSub(c, pseudoOutputCommitment));

  // Compute key image: I = x * H_p(P)
  const P_l = ring[secretIndex];
  const I = generateKeyImage(P_l, secretKeyX);

  // Compute commitment key image: D = z * H_p(P)
  const H_P = hashToPoint(P_l);
  const D = scalarMultPoint(commitmentMask, H_P);

  // D_8 = D * (1/8) — stored in signature and used in aggregation hash
  // Matches C++ TCLSAG_Gen line 416: scalarmultKey(sig.D, D, INV_EIGHT)
  const INV_EIGHT_SCALAR = hexToBytes('792fdce229e50661d0da1c7db39dd30700000000000000000000000000000006');
  const D_8 = scalarMultPoint(INV_EIGHT_SCALAR, D);

  // Compute aggregate coefficients mu_P and mu_C
  // For TCLSAG, aggregation uses C_nonzero (not C differences) plus I, D_8, C_offset
  const aggData = [...ring, ...commitments, I, D_8, pseudoOutputCommitment];
  const mu_P = hashToScalar(CLSAG_AGG_0, ...aggData);
  const mu_C = hashToScalar(CLSAG_AGG_1, ...aggData);

  // Initialize signature arrays
  const sx = new Array(n);
  const sy = new Array(n);

  // Generate random scalars for the real input
  const a = scRandom(); // For x component
  const b = scRandom(); // For y component

  // Compute initial values:
  // L = a*G + b*T
  // R = a*H_p(P_l)
  const aG = scalarMultBase(a);
  const bT = scalarMultPoint(b, T);
  const L_init = pointAddCompressed(aG, bT);
  const aH = scalarMultPoint(a, H_P);

  // Build challenge hash (matches Salvium C++ - uses C_nonzero, not C differences)
  const buildChallengeHash = (L, R) => {
    return hashToScalar(CLSAG_ROUND, ...ring, ...commitments, pseudoOutputCommitment, message, L, R);
  };

  // Start the ring: first challenge from (a,b) commitments
  let c = buildChallengeHash(L_init, aH);

  // c1 will be captured when loop index becomes 0
  let c1 = null;

  // Start at position after secret index
  let i = (secretIndex + 1) % n;

  // If we start at index 0, capture c1 immediately
  if (i === 0) {
    c1 = new Uint8Array(c);
  }

  // Go around the ring until we reach the secret index
  while (i !== secretIndex) {
    // Generate random sx[i] and sy[i] for this decoy position
    sx[i] = scRandom();
    sy[i] = scRandom();

    // Compute H_p(P_i)
    const H_P_i = hashToPoint(ring[i]);

    // Weighted challenges
    const c_mu_P = scMul(c, mu_P);
    const c_mu_C = scMul(c, mu_C);

    // L = sx[i]*G + sy[i]*T + c*mu_P*P[i] + c*mu_C*C[i]
    const sxG = scalarMultBase(sx[i]);
    const syT = scalarMultPoint(sy[i], T);
    const c_mu_P_Pi = scalarMultPoint(c_mu_P, ring[i]);
    const c_mu_C_Ci = scalarMultPoint(c_mu_C, C[i]);

    let L = pointAddCompressed(sxG, syT);
    L = pointAddCompressed(L, c_mu_P_Pi);
    L = pointAddCompressed(L, c_mu_C_Ci);

    // R = sx[i]*H_p(P[i]) + c*mu_P*I + c*mu_C*D
    const sxH = scalarMultPoint(sx[i], H_P_i);
    const c_mu_P_I = scalarMultPoint(c_mu_P, I);
    const c_mu_C_D = scalarMultPoint(c_mu_C, D);

    let R = pointAddCompressed(sxH, c_mu_P_I);
    R = pointAddCompressed(R, c_mu_C_D);

    // Next challenge
    c = buildChallengeHash(L, R);

    // Advance to next ring member
    i = (i + 1) % n;

    // Capture c1 when we wrap to index 0
    if (i === 0) {
      c1 = new Uint8Array(c);
    }
  }

  // Now c is the challenge at the secret position (c_l)
  // Compute sx[l] and sy[l] to close the ring:
  // sx[l] = a - c * (mu_P * x + mu_C * z)
  // sy[l] = b (T component closes without secret key contribution when P = x*G)
  const mu_P_x = scMul(mu_P, secretKeyX);
  const mu_C_z = scMul(mu_C, commitmentMask);
  const sum_x = scAdd(mu_P_x, mu_C_z);
  const c_sum_x = scMul(c, sum_x);
  sx[secretIndex] = scSub(a, c_sum_x);

  // sy[l] = b - c * (mu_P * y) — matches C++ clsag_sign_y
  // For non-CARROT inputs, y=0, so this simplifies to sy = b
  const mu_P_y = scMul(mu_P, secretKeyY);
  const c_mu_P_y = scMul(c, mu_P_y);
  sy[secretIndex] = scSub(b, c_mu_P_y);

  // If c1 wasn't captured, compute it now
  if (c1 === null) {
    const H_P_l = hashToPoint(ring[secretIndex]);
    const c_mu_P = scMul(c, mu_P);
    const c_mu_C = scMul(c, mu_C);

    const sxG = scalarMultBase(sx[secretIndex]);
    const syT = scalarMultPoint(sy[secretIndex], T);
    const c_mu_P_Pl = scalarMultPoint(c_mu_P, ring[secretIndex]);
    const c_mu_C_Cl = scalarMultPoint(c_mu_C, C[secretIndex]);

    let L = pointAddCompressed(sxG, syT);
    L = pointAddCompressed(L, c_mu_P_Pl);
    L = pointAddCompressed(L, c_mu_C_Cl);

    const sxH = scalarMultPoint(sx[secretIndex], H_P_l);
    const c_mu_P_I = scalarMultPoint(c_mu_P, I);
    const c_mu_C_D_c1 = scalarMultPoint(c_mu_C, D);

    let R = pointAddCompressed(sxH, c_mu_P_I);
    R = pointAddCompressed(R, c_mu_C_D_c1);

    c1 = buildChallengeHash(L, R);
  }

  return {
    sx: sx.map(si => bytesToHex(si)),
    sy: sy.map(si => bytesToHex(si)),
    c1: bytesToHex(c1),
    I: bytesToHex(I),
    D: bytesToHex(D_8)  // Store D*INV_EIGHT as per C++ TCLSAG_Gen
  };
}

/**
 * Point subtraction: A - B
 * @param {Uint8Array} a - First point
 * @param {Uint8Array} b - Second point
 * @returns {Uint8Array} A - B
 */
function pointSub(a, b) {
  // A - B = A + (-B)
  // -B is computed by negating the x-coordinate in compressed form
  // For Edwards curves, -(x, y) = (-x, y), and in compressed form we negate the sign bit
  const negB = negatePoint(b);
  return pointAddCompressed(a, negB);
}

/**
 * Negate a compressed point
 * @param {Uint8Array} p - Compressed point
 * @returns {Uint8Array} -P
 */
function negatePoint(p) {
  if (typeof p === 'string') p = hexToBytes(p);
  const result = new Uint8Array(p);
  // In compressed Edwards form, the sign bit is the LSB of the last byte
  // Negation flips this bit
  result[31] ^= 0x80;
  return result;
}

/**
 * Verify a CLSAG signature
 *
 * @param {Uint8Array|string} message - Message that was signed
 * @param {Object} sig - CLSAG signature { s, c1, I, D }
 * @param {Array<Uint8Array>} ring - Array of public keys
 * @param {Array<Uint8Array>} commitments - Array of commitments
 * @param {Uint8Array|string} pseudoOutputCommitment - Pseudo output commitment
 * @returns {boolean} True if signature is valid
 */
export function clsagVerify(message, sig, ring, commitments, pseudoOutputCommitment) {
  if (typeof message === 'string') message = hexToBytes(message);
  if (typeof pseudoOutputCommitment === 'string') pseudoOutputCommitment = hexToBytes(pseudoOutputCommitment);

  // Normalize inputs
  ring = ring.map(k => typeof k === 'string' ? hexToBytes(k) : k);
  commitments = commitments.map(c => typeof c === 'string' ? hexToBytes(c) : c);

  // Try accelerated backend (WASM/JSI)
  const backend = getCryptoBackend();
  const nativeResult = backend.clsagVerify(message, sig, ring, commitments, pseudoOutputCommitment);
  if (nativeResult !== null) return nativeResult;

  const n = ring.length;

  const s = sig.s.map(si => typeof si === 'string' ? hexToBytes(si) : si);
  const c1 = typeof sig.c1 === 'string' ? hexToBytes(sig.c1) : sig.c1;
  const I = typeof sig.I === 'string' ? hexToBytes(sig.I) : sig.I;
  const D = typeof sig.D === 'string' ? hexToBytes(sig.D) : sig.D;

  // Compute commitment differences: C[i] = C_nonzero[i] - C_offset
  const C = commitments.map(c => pointSub(c, pseudoOutputCommitment));

  // D from signature is D_8 (D * INV_EIGHT). For R computation we need full D.
  // D_full = D_8 * 8 (3 doublings)
  let D_full = pointAddCompressed(D, D);         // 2D
  D_full = pointAddCompressed(D_full, D_full);   // 4D
  D_full = pointAddCompressed(D_full, D_full);   // 8D

  // Aggregation hash uses D_8 (sig.D) and C_nonzero (original commitments)
  // Matches C++ CLSAG: [domain, P[], C_nonzero[], I, D_8, C_offset]
  const aggData = [...ring, ...commitments, I, D, pseudoOutputCommitment];
  const mu_P = hashToScalar(CLSAG_AGG_0, ...aggData);
  const mu_C = hashToScalar(CLSAG_AGG_1, ...aggData);

  // Challenge hash uses C_nonzero (original commitments), matching sign
  // c = H_n(domain, P[], C_nonzero[], C_offset, message, L, R)
  const buildChallengeHash = (L, R) => {
    return hashToScalar(CLSAG_ROUND, ...ring, ...commitments, pseudoOutputCommitment, message, L, R);
  };

  // Verify the ring
  let c = c1;
  for (let i = 0; i < n; i++) {
    const H_P_i = hashToPoint(ring[i]);

    // Weighted challenges
    const c_mu_P = scMul(c, mu_P);
    const c_mu_C = scMul(c, mu_C);

    // L = s[i]*G + c*mu_P*P[i] + c*mu_C*C[i]
    const sG = scalarMultBase(s[i]);
    const c_mu_P_Pi = scalarMultPoint(c_mu_P, ring[i]);
    const c_mu_C_Ci = scalarMultPoint(c_mu_C, C[i]);

    const L = pointAddCompressed(pointAddCompressed(sG, c_mu_P_Pi), c_mu_C_Ci);

    // R = s[i]*H_p(P[i]) + c*mu_P*I + c*mu_C*D_full
    const sH = scalarMultPoint(s[i], H_P_i);
    const c_mu_P_I = scalarMultPoint(c_mu_P, I);
    const c_mu_C_D = scalarMultPoint(c_mu_C, D_full);

    const R = pointAddCompressed(pointAddCompressed(sH, c_mu_P_I), c_mu_C_D);

    // Next challenge
    c = buildChallengeHash(L, R);
  }

  // After going around the ring, c should equal c1
  return bytesToHex(c) === bytesToHex(c1);
}

/**
 * Verify a TCLSAG (Twin CLSAG) signature
 *
 * TCLSAG uses two scalar arrays (sx, sy) for dual-component signing with generators G and T.
 * This is used in RCTTypeSalviumOne transactions.
 *
 * Verification equation for each ring member i:
 *   L = sx[i]*G + sy[i]*T + c*mu_P*P[i] + c*mu_C*(C[i] - C_offset)
 *   R = sx[i]*H(P[i]) + c*mu_P*I + c*mu_C*D
 *
 * Reference: Salvium rctSigs.cpp lines 1207-1326
 *
 * @param {Uint8Array|string} message - Message that was signed
 * @param {Object} sig - TCLSAG signature { sx, sy, c1, I, D }
 * @param {Array<Uint8Array>} ring - Array of public keys
 * @param {Array<Uint8Array>} commitments - Array of non-zero commitments (C_nonzero)
 * @param {Uint8Array|string} pseudoOutputCommitment - Pseudo output commitment (C_offset)
 * @returns {boolean} True if signature is valid
 */
export function tclsagVerify(message, sig, ring, commitments, pseudoOutputCommitment) {
  if (typeof message === 'string') message = hexToBytes(message);
  if (typeof pseudoOutputCommitment === 'string') pseudoOutputCommitment = hexToBytes(pseudoOutputCommitment);

  // Normalize inputs
  ring = ring.map(k => typeof k === 'string' ? hexToBytes(k) : k);
  commitments = commitments.map(c => typeof c === 'string' ? hexToBytes(c) : c);

  // Try accelerated backend (WASM/JSI)
  const backend = getCryptoBackend();
  const nativeResult = backend.tclsagVerify(message, sig, ring, commitments, pseudoOutputCommitment);
  if (nativeResult !== null) return nativeResult;

  const n = ring.length;

  const sx = sig.sx.map(si => typeof si === 'string' ? hexToBytes(si) : si);
  const sy = sig.sy.map(si => typeof si === 'string' ? hexToBytes(si) : si);
  const c1 = typeof sig.c1 === 'string' ? hexToBytes(sig.c1) : sig.c1;
  const I = typeof sig.I === 'string' ? hexToBytes(sig.I) : sig.I;
  const D = typeof sig.D === 'string' ? hexToBytes(sig.D) : sig.D;

  // Get generator T (second basis point for twin commitments)
  const T = getGeneratorT();

  // Compute commitment differences: C[i] = C_nonzero[i] - C_offset
  const C = commitments.map(c => pointSub(c, pseudoOutputCommitment));

  // D from signature is D_8 (D * INV_EIGHT). For R computation we need full D.
  // D_full = D_8 * 8 = sig.D * 8
  // Use doubling 3 times to match C++ scalarmult8
  let D_full = pointAddCompressed(D, D);         // 2D
  D_full = pointAddCompressed(D_full, D_full);   // 4D
  D_full = pointAddCompressed(D_full, D_full);   // 8D

  // Aggregation hash uses D_8 (sig.D), matching C++ verification
  // mu_P = H_n("CLSAG_agg_0", P[0..n-1], C_nonzero[0..n-1], I, D_8, C_offset)
  // mu_C = H_n("CLSAG_agg_1", P[0..n-1], C_nonzero[0..n-1], I, D_8, C_offset)
  const aggData = [...ring, ...commitments, I, D, pseudoOutputCommitment];
  const mu_P = hashToScalar(CLSAG_AGG_0, ...aggData);
  const mu_C = hashToScalar(CLSAG_AGG_1, ...aggData);

  // Build challenge hash
  // c = H_n("CLSAG_round", P[0..n-1], C_nonzero[0..n-1], C_offset, message, L, R)
  const buildChallengeHash = (L, R) => {
    return hashToScalar(CLSAG_ROUND, ...ring, ...commitments, pseudoOutputCommitment, message, L, R);
  };

  // Verify the ring
  let c = c1;
  for (let i = 0; i < n; i++) {
    const H_P_i = hashToPoint(ring[i]);

    // Compute scaled challenges
    const c_mu_P = scMul(c, mu_P);
    const c_mu_C = scMul(c, mu_C);

    // L = sx[i]*G + sy[i]*T + c*mu_P*P[i] + c*mu_C*C[i]
    // Where C[i] = C_nonzero[i] - C_offset (already computed above)
    const sxG = scalarMultBase(sx[i]);
    const syT = scalarMultPoint(sy[i], T);
    const c_mu_P_Pi = scalarMultPoint(c_mu_P, ring[i]);
    const c_mu_C_Ci = scalarMultPoint(c_mu_C, C[i]);

    let L = pointAddCompressed(sxG, syT);
    L = pointAddCompressed(L, c_mu_P_Pi);
    L = pointAddCompressed(L, c_mu_C_Ci);

    // R = sx[i]*H(P[i]) + c*mu_P*I + c*mu_C*D_full
    // Note: We use D_full (sig.D * 8) here, matching C++ verification
    const sxH = scalarMultPoint(sx[i], H_P_i);
    const c_mu_P_I = scalarMultPoint(c_mu_P, I);
    const c_mu_C_D = scalarMultPoint(c_mu_C, D_full);

    let R = pointAddCompressed(sxH, c_mu_P_I);
    R = pointAddCompressed(R, c_mu_C_D);

    // Next challenge
    c = buildChallengeHash(L, R);
  }

  // After going around the ring, c should equal c1
  const cHex = bytesToHex(c);
  const c1Hex = bytesToHex(c1);
  return cHex === c1Hex;
}

// =============================================================================
// TRANSACTION UTILITIES
// =============================================================================

/**
 * Expand a parsed transaction by copying key images from prefix inputs
 * into the ring signature structs (TCLSAG/CLSAG).
 *
 * In C++ (blockchain.cpp:3894 expand_transaction_2), key images from
 * vin[n].k_image are copied into the sig structs before verification.
 * The key image is NOT serialized in the signature itself.
 *
 * @param {Object} tx - Parsed transaction with prefix and rct
 * @returns {Object} The same tx object, mutated with I fields populated
 */
export function expandTransaction(tx) {
  const { prefix, rct } = tx;
  if (!prefix?.vin || !rct) return tx;
  if (rct.TCLSAGs) {
    for (let i = 0; i < rct.TCLSAGs.length && i < prefix.vin.length; i++) {
      if (prefix.vin[i].keyImage) rct.TCLSAGs[i].I = prefix.vin[i].keyImage;
    }
  }
  if (rct.CLSAGs) {
    for (let i = 0; i < rct.CLSAGs.length && i < prefix.vin.length; i++) {
      if (prefix.vin[i].keyImage) rct.CLSAGs[i].I = prefix.vin[i].keyImage;
    }
  }
  return tx;
}

/**
 * Compute the pre-MLSAG/CLSAG hash (message to sign)
 * Matches C++ get_pre_mlsag_hash: H(message || H(rctSigBase) || H(bp_components))
 *
 * @param {Uint8Array|string} txPrefixHash - Hash of transaction prefix (hashes[0])
 * @param {Uint8Array|string} rctBaseSerialized - Full serialized rctSigBase (hashed to get hashes[1])
 * @param {Object} bpProof - Bulletproof+ proof object with A, A1, B, r1, s1, d1, L, R fields
 * @returns {Uint8Array} 32-byte message hash
 */
export function getPreMlsagHash(txPrefixHash, rctBaseSerialized, bpProof) {
  if (typeof txPrefixHash === 'string') txPrefixHash = hexToBytes(txPrefixHash);
  if (typeof rctBaseSerialized === 'string') rctBaseSerialized = hexToBytes(rctBaseSerialized);

  // hashes[0] = message (tx prefix hash)
  const hash0 = txPrefixHash;

  // hashes[1] = H(serialized rctSigBase)
  const hash1 = keccak256(rctBaseSerialized);

  // hashes[2] = H(bp+ components: A, A1, B, r1, s1, d1, L[], R[])
  // Each component is a 32-byte key, concatenated then hashed
  const bpChunks = [];
  if (bpProof) {
    const toBytes = (v) => {
      if (typeof v === 'string') return hexToBytes(v);
      if (v && typeof v.toBytes === 'function') return v.toBytes();
      if (typeof v === 'bigint') {
        // Scalar: convert to 32-byte little-endian
        const bytes = new Uint8Array(32);
        let n = v;
        for (let i = 0; i < 32; i++) { bytes[i] = Number(n & 0xFFn); n >>= 8n; }
        return bytes;
      }
      if (v instanceof Uint8Array) return v;
      return v;
    };
    bpChunks.push(toBytes(bpProof.A));
    bpChunks.push(toBytes(bpProof.A1));
    bpChunks.push(toBytes(bpProof.B));
    bpChunks.push(toBytes(bpProof.r1));
    bpChunks.push(toBytes(bpProof.s1));
    bpChunks.push(toBytes(bpProof.d1));
    for (const l of bpProof.L) bpChunks.push(toBytes(l));
    for (const r of bpProof.R) bpChunks.push(toBytes(r));
  }
  let bpDataLen = 0;
  for (const c of bpChunks) bpDataLen += c.length;
  const bpData = new Uint8Array(bpDataLen);
  let off = 0;
  for (const c of bpChunks) { bpData.set(c, off); off += c.length; }
  const hash2 = keccak256(bpData);

  // prehash = H(hashes[0] || hashes[1] || hashes[2])
  const combined = new Uint8Array(96);
  combined.set(hash0, 0);
  combined.set(hash1, 32);
  combined.set(hash2, 64);
  return keccak256(combined);
}

/**
 * Generate a random transaction secret key
 * @returns {Uint8Array} 32-byte random scalar
 */
export function generateTxSecretKey() {
  return scRandom();
}

/**
 * Compute transaction public key from secret key
 * @param {Uint8Array|string} txSecretKey - Transaction secret key
 * @returns {Uint8Array} Transaction public key (R = r*G)
 */
export function getTxPublicKey(txSecretKey) {
  return scalarMultBase(txSecretKey);
}

// =============================================================================
// TRANSACTION HASH
// =============================================================================

/**
 * Compute full transaction hash
 * This is the hash used to identify transactions.
 *
 * @param {Object} tx - Full transaction with RingCT
 * @returns {Uint8Array} 32-byte transaction hash
 */
export function getTransactionHash(tx) {
  // CryptoNote v2+ transaction hash: H(H(prefix) || H(rctBase) || H(rctPrunable))
  const prefixBytes = serializeTxPrefix(tx);
  const prefixHash = keccak256(prefixBytes);

  // If no RCT data, just return prefix hash (e.g. coinbase with RCT type 0)
  if (!tx.rct || !tx.rct.type) {
    return prefixHash;
  }

  // Hash the RCT base (type, fee, ecdhInfo, outPk, etc.)
  const rctBaseBytes = serializeRctBase(tx.rct);
  const rctBaseHash = keccak256(rctBaseBytes);

  // Hash the RCT prunable section (BP+ proofs, ring signatures, pseudoOuts)
  const prunableChunks = [];

  // BP+ proofs
  if (tx.rct.bulletproofPlus && tx.rct.bulletproofPlus.serialized) {
    prunableChunks.push(_encodeVarint(1));
    prunableChunks.push(tx.rct.bulletproofPlus.serialized);
  }

  // Ring signatures
  if (tx.rct.type === 9 && tx.rct.TCLSAGs) {
    for (const sig of tx.rct.TCLSAGs) {
      prunableChunks.push(_serializeTCLSAG(sig));
    }
  } else if (tx.rct.CLSAGs) {
    for (const sig of tx.rct.CLSAGs) {
      prunableChunks.push(_serializeCLSAG(sig));
    }
  }

  // pseudoOuts
  if (tx.rct.pseudoOuts) {
    for (const po of tx.rct.pseudoOuts) {
      prunableChunks.push(typeof po === 'string' ? hexToBytes(po) : po);
    }
  }

  let rctPrunableHash;
  if (prunableChunks.length > 0) {
    rctPrunableHash = keccak256(_concatBytes(prunableChunks));
  } else {
    rctPrunableHash = new Uint8Array(32); // zeros if no prunable data
  }

  // Final hash: H(prefixHash || rctBaseHash || rctPrunableHash)
  const combined = new Uint8Array(96);
  combined.set(prefixHash, 0);
  combined.set(rctBaseHash, 32);
  combined.set(rctPrunableHash, 64);
  return keccak256(combined);
}

// =============================================================================
// DECOY SELECTION (GAMMA PICKER)
// =============================================================================

/**
 * Gamma distribution parameters from Miller et al. (https://arxiv.org/pdf/1704.04299/)
 * These parameters model the spending behavior of real users.
 */
export const GAMMA_SHAPE = 19.28;
export const GAMMA_SCALE = 1 / 1.61;

/**
 * Default unlock time in seconds (10 blocks at 120s each)
 */
export const DEFAULT_UNLOCK_TIME = 10 * 120; // 1200 seconds

/**
 * Generate a cryptographically secure random float in [0, 1).
 * Uses crypto.getRandomValues instead of Math.random() to prevent
 * statistical leakage of the real spend in ring signatures.
 * @returns {number} Random float in [0, 1)
 */
function secureRandomFloat() {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] / 0x100000000;
}

/**
 * Gamma distribution sampler using the Marsaglia and Tsang method
 * Uses CSPRNG (crypto.getRandomValues) for privacy-critical decoy selection.
 * @param {number} shape - Shape parameter (k or alpha)
 * @param {number} scale - Scale parameter (theta)
 * @returns {number} Random sample from gamma distribution
 */
export function sampleGamma(shape, scale) {
  // For shape >= 1, use Marsaglia and Tsang's method
  // For shape < 1, use shape + 1 and adjust

  let d, c;
  let adjustedShape = shape;

  if (shape < 1) {
    adjustedShape = shape + 1;
  }

  d = adjustedShape - 1/3;
  c = 1 / Math.sqrt(9 * d);

  while (true) {
    let x, v;

    // Generate standard normal using Box-Muller (CSPRNG)
    do {
      const u1 = secureRandomFloat();
      const u2 = secureRandomFloat();
      x = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      v = 1 + c * x;
    } while (v <= 0);

    v = v * v * v;
    const u = secureRandomFloat();

    // Accept/reject
    if (u < 1 - 0.0331 * x * x * x * x) {
      let result = d * v * scale;
      if (shape < 1) {
        result *= Math.pow(secureRandomFloat(), 1 / shape);
      }
      return result;
    }

    if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) {
      let result = d * v * scale;
      if (shape < 1) {
        result *= Math.pow(secureRandomFloat(), 1 / shape);
      }
      return result;
    }
  }
}

/**
 * Gamma picker for decoy selection
 * Implements the algorithm from wallet2.cpp gamma_picker
 */
export class GammaPicker {
  /**
   * Create a gamma picker
   * @param {Array<number>} rctOffsets - Cumulative output counts per block
   * @param {Object} options - Optional configuration
   * @param {number} options.shape - Gamma shape (default: GAMMA_SHAPE)
   * @param {number} options.scale - Gamma scale (default: GAMMA_SCALE)
   */
  constructor(rctOffsets, options = {}) {
    this.rctOffsets = rctOffsets;
    this.shape = options.shape || GAMMA_SHAPE;
    this.scale = options.scale || GAMMA_SCALE;

    // Match C++ gamma_picker: use DEFAULT_TX_SPENDABLE_AGE (10) as the
    // exclusion zone, not MINED_MONEY_UNLOCK_WINDOW (60). Locked coinbase
    // outputs still have valid public keys and are fine as ring decoys.
    // The C++ wallet over-requests outputs to compensate for locked picks.
    const unlockExclusion = CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;

    if (rctOffsets.length <= unlockExclusion) {
      throw new Error('Not enough blocks for decoy selection');
    }

    // Calculate average output time from recent blocks
    const blocksInYear = Math.floor(86400 * 365 / DIFFICULTY_TARGET);
    const blocksToConsider = Math.min(rctOffsets.length, blocksInYear);

    const startOffset = blocksToConsider < rctOffsets.length
      ? rctOffsets[rctOffsets.length - blocksToConsider - 1]
      : 0;
    const outputsToConsider = rctOffsets[rctOffsets.length - 1] - startOffset;

    this.numRctOutputs = rctOffsets[rctOffsets.length - unlockExclusion];
    this.averageOutputTime = DIFFICULTY_TARGET * blocksToConsider / outputsToConsider;

    if (this.numRctOutputs === 0) {
      throw new Error('No RCT outputs available');
    }
  }

  /**
   * Pick a random output index using gamma distribution
   * @returns {number} Output global index, or -1 if bad pick
   */
  pick() {
    // Sample from gamma and exponentiate (as per Miller et al.)
    let x = sampleGamma(this.shape, this.scale);
    x = Math.exp(x);

    // Adjust for unlock time
    if (x > DEFAULT_UNLOCK_TIME) {
      x -= DEFAULT_UNLOCK_TIME;
    } else {
      // Output would be too recent, pick from recent spend window
      x = Math.floor(secureRandomFloat() * RECENT_SPEND_WINDOW);
    }

    // Convert time to output index
    let outputIndex = Math.floor(x / this.averageOutputTime);

    if (outputIndex >= this.numRctOutputs) {
      return -1; // Bad pick
    }

    // Convert to ascending index (from chain tip going back)
    outputIndex = this.numRctOutputs - 1 - outputIndex;

    // Find which block contains this output
    const blockIndex = this.findBlockIndex(outputIndex);

    if (blockIndex < 0) {
      return -1;
    }

    // Pick a random output from this block
    const firstInBlock = blockIndex === 0 ? 0 : this.rctOffsets[blockIndex - 1];
    const countInBlock = this.rctOffsets[blockIndex] - firstInBlock;

    if (countInBlock === 0) {
      return -1;
    }

    return firstInBlock + Math.floor(secureRandomFloat() * countInBlock);
  }

  /**
   * Find block index containing a given output index
   * @param {number} outputIndex - Global output index
   * @returns {number} Block index
   */
  findBlockIndex(outputIndex) {
    // Binary search
    let low = 0;
    let high = this.rctOffsets.length - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;

    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      if (this.rctOffsets[mid] <= outputIndex) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }

    return low;
  }

  /**
   * Get the number of available RCT outputs
   * @returns {number}
   */
  getNumRctOutputs() {
    return this.numRctOutputs;
  }
}

/**
 * Select decoy outputs for a ring
 *
 * @param {Array<number>} rctOffsets - Cumulative output counts from get_output_distribution
 * @param {number} realOutputIndex - Global index of the real output being spent
 * @param {number} ringSize - Desired ring size (default: DEFAULT_RING_SIZE)
 * @param {Set<number>} excludeIndices - Output indices to exclude (e.g., already used)
 * @returns {Array<number>} Array of output indices (including real output, sorted)
 */
export function selectDecoys(rctOffsets, realOutputIndex, ringSize = DEFAULT_RING_SIZE, excludeIndices = new Set()) {
  const picker = new GammaPicker(rctOffsets);
  const selected = new Set([realOutputIndex]);
  excludeIndices = new Set(excludeIndices);
  excludeIndices.add(realOutputIndex);

  const maxAttempts = ringSize * 100; // Prevent infinite loops
  let attempts = 0;

  while (selected.size < ringSize && attempts < maxAttempts) {
    const pick = picker.pick();
    attempts++;

    if (pick >= 0 && !selected.has(pick) && !excludeIndices.has(pick)) {
      selected.add(pick);
    }
  }

  if (selected.size < ringSize) {
    throw new Error(`Could not select enough decoys: got ${selected.size}, need ${ringSize}`);
  }

  // Return sorted array
  return Array.from(selected).sort((a, b) => a - b);
}

/**
 * Convert absolute output indices to relative offsets
 * CryptoNote uses relative offsets in the serialized transaction
 *
 * @param {Array<number>} indices - Sorted absolute output indices
 * @returns {Array<number>} Relative offsets
 */
export function indicesToOffsets(indices) {
  const offsets = [];
  for (let i = 0; i < indices.length; i++) {
    if (i === 0) {
      offsets.push(indices[i]);
    } else {
      offsets.push(indices[i] - indices[i - 1]);
    }
  }
  return offsets;
}

/**
 * Convert relative offsets back to absolute indices
 *
 * @param {Array<number>} offsets - Relative offsets
 * @returns {Array<number>} Absolute indices
 */
export function offsetsToIndices(offsets) {
  const indices = [];
  let current = 0;
  for (const offset of offsets) {
    current += offset;
    indices.push(current);
  }
  return indices;
}

// =============================================================================
// FEE CALCULATION
// =============================================================================

/**
 * Calculate fee from transaction weight
 *
 * @param {bigint} baseFee - Base fee per weight unit
 * @param {bigint} weight - Transaction weight
 * @param {bigint} quantizationMask - Fee quantization mask (optional)
 * @returns {bigint} Calculated fee
 */
export function calculateFeeFromWeight(baseFee, weight, quantizationMask = 0n) {
  let fee = weight * baseFee;

  if (quantizationMask > 0n) {
    // Round up to quantization mask
    fee = ((fee + quantizationMask - 1n) / quantizationMask) * quantizationMask;
  }

  return fee;
}

/**
 * Calculate fee from transaction size (legacy per-KB method)
 *
 * @param {bigint} feePerKb - Fee per kilobyte
 * @param {number} sizeBytes - Transaction size in bytes
 * @returns {bigint} Calculated fee
 */
export function calculateFeeFromSize(feePerKb, sizeBytes) {
  // Round up to next KB
  const kb = BigInt(Math.ceil(sizeBytes / 1024));
  return kb * feePerKb;
}

/**
 * Estimate transaction size
 * Based on wallet2.cpp estimate_rct_tx_size
 *
 * @param {number} numInputs - Number of inputs
 * @param {number} ringSize - Ring size (mixin + 1)
 * @param {number} numOutputs - Number of outputs
 * @param {number} extraSize - Extra field size
 * @param {Object} options - Options
 * @param {boolean} options.bulletproofPlus - Use Bulletproof+ (default: true)
 * @param {boolean} options.clsag - Use CLSAG (default: true)
 * @param {boolean} options.viewTags - Include view tags (default: true)
 * @returns {number} Estimated size in bytes
 */
export function estimateTxSize(numInputs, ringSize, numOutputs, extraSize = 0, options = {}) {
  const {
    bulletproofPlus = true,
    clsag = true,
    viewTags = true,
    txType = 0,           // Salvium TX type (0=none, 3=TRANSFER, 5=BURN, 6=STAKE, etc.)
    numReturnAddresses = 0 // Number of return addresses in return_address_list
  } = options;

  let size = 0;

  // Transaction prefix
  size += 1 + 6; // version + unlock_time varint

  // Salvium-specific prefix fields (HF3+)
  if (txType > 0) {
    size += 1;  // txType varint
    size += 6;  // amount_burnt varint
    // return_address_list: varint count + addresses (each ~70 bytes encoded)
    size += 4 + numReturnAddresses * 70;
    size += 32; // change_mask (32 bytes)
  }

  // Inputs
  // vin: type(1) + amount varint(6) + key_offsets count(4) + key_offsets values(ringSize*2) + key_image(32)
  // C++ wallet2.cpp: n_inputs * (1+6+4+(mixin+1)*2+32) where mixin+1 = ringSize
  const inputSize = 1 + 6 + 4 + ringSize * 2 + 32;
  size += inputSize * numInputs;

  // Outputs
  // vout: amount varint + type(1) + key(32) + view_tag(1 if enabled)
  const outputSize = 2 + 4 + 6 + 32 + (viewTags ? 1 : 0);
  size += outputSize * numOutputs;

  // Extra
  size += extraSize;

  // RCT type
  size += 1;

  // Bulletproof(+) range proof
  // C++ wallet2.cpp: (2 * (6 + log_padded_outputs) + (bp_plus ? 6 : (4+5))) * 32 + 3
  if (bulletproofPlus) {
    let log2Outputs = 0;
    while ((1 << log2Outputs) < numOutputs) log2Outputs++;
    size += (2 * (6 + log2Outputs) + 6) * 32 + 3;
  } else {
    let log2Outputs = 0;
    while ((1 << log2Outputs) < numOutputs) log2Outputs++;
    size += (2 * (6 + log2Outputs) + 9) * 32 + 3;
  }

  // Ring signatures (CLSAG)
  if (clsag) {
    // CLSAG: ringSize * 32 (s values) + 32 (c1) + 32 (D)
    size += (ringSize * 32 + 64) * numInputs;
  } else {
    // MLSAG: (ringSize + 1) * 32 * 2
    size += ((ringSize + 1) * 64) * numInputs;
  }

  // Pseudo outputs (one per input, except coinbase)
  size += 32 * numInputs;

  // ecdhInfo (encrypted amounts)
  size += 8 * numOutputs;

  // outPk (output commitments)
  size += 32 * numOutputs;

  // txnFee
  size += 4;

  // Extra tx pubkey
  size += 32;

  return size;
}

/**
 * Estimate transaction weight (for fee calculation)
 * Weight includes clawback adjustment for bulletproofs
 *
 * @param {number} numInputs - Number of inputs
 * @param {number} ringSize - Ring size
 * @param {number} numOutputs - Number of outputs
 * @param {number} extraSize - Extra field size
 * @param {Object} options - Options (same as estimateTxSize)
 * @returns {number} Estimated weight
 */
export function estimateTxWeight(numInputs, ringSize, numOutputs, extraSize = 0, options = {}) {
  let weight = estimateTxSize(numInputs, ringSize, numOutputs, extraSize, options);

  const { bulletproofPlus = true } = options;

  // Apply clawback for > 2 outputs
  // C++ wallet2.cpp: bp_base = (32 * ((plus ? 6 : 9) + 7 * 2)) / 2
  if (numOutputs > 2) {
    const bpBase = (32 * ((bulletproofPlus ? 6 : 9) + 7 * 2)) / 2;
    let logPaddedOutputs = 2;
    while ((1 << logPaddedOutputs) < numOutputs) logPaddedOutputs++;
    const paddedOutputs = 1 << logPaddedOutputs;
    const nlr = 2 * (6 + logPaddedOutputs);
    const bpSize = 32 * ((bulletproofPlus ? 6 : 9) + nlr);

    const bpClawback = Math.floor((bpBase * paddedOutputs - bpSize) * 4 / 5);
    weight += bpClawback;
  }

  return weight;
}

/**
 * Estimate fee for a transaction
 *
 * @param {number} numInputs - Number of inputs
 * @param {number} ringSize - Ring size
 * @param {number} numOutputs - Number of outputs
 * @param {number} extraSize - Extra field size
 * @param {Object} options - Options
 * @param {bigint} options.baseFee - Base fee per byte (default: FEE_PER_BYTE)
 * @param {number} options.priority - Priority level 1-4 (default: 2)
 * @param {boolean} options.perByte - Use per-byte fee (default: true)
 * @returns {bigint} Estimated fee
 */
export function estimateFee(numInputs, ringSize, numOutputs, extraSize = 0, options = {}) {
  const {
    baseFee = FEE_PER_BYTE,
    priority = FEE_PRIORITY.NORMAL,
    perByte = true
  } = options;

  const multiplier = getFeeMultiplier(priority);

  if (perByte) {
    const weight = estimateTxWeight(numInputs, ringSize, numOutputs, extraSize, options);
    return calculateFeeFromWeight(baseFee * multiplier, BigInt(weight));
  } else {
    const size = estimateTxSize(numInputs, ringSize, numOutputs, extraSize, options);
    return calculateFeeFromSize(FEE_PER_KB * multiplier, size);
  }
}

// =============================================================================
// RINGCT SIGNATURE ASSEMBLY
// =============================================================================

/**
 * Build a complete RingCT signature
 *
 * @param {Object} params - Transaction parameters
 * @param {Uint8Array} params.message - Message to sign (pre-MLSAG hash)
 * @param {Array<Object>} params.inputs - Input objects with { secretKey, ring, commitments, mask, realIndex }
 * @param {Array<Object>} params.outputs - Output objects with { commitment, encryptedAmount }
 * @param {bigint} params.fee - Transaction fee
 * @param {Array<Uint8Array>} params.pseudoOuts - Pseudo output commitments
 * @returns {Object} RingCT signature data
 */
export function buildRingCtSignature(params) {
  const { message, inputs, outputs, fee, pseudoOuts } = params;

  const clsags = [];

  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i];

    // Sign with CLSAG
    const sig = clsagSign(
      message,
      input.ring,
      input.secretKey,
      input.commitments,
      input.mask,
      pseudoOuts[i],
      input.realIndex
    );

    clsags.push(sig);
  }

  return {
    type: RCT_TYPE.BulletproofPlus, // or CLSAG
    fee,
    pseudoOuts: pseudoOuts.map(p => typeof p === 'string' ? p : bytesToHex(p)),
    ecdhInfo: outputs.map(o => typeof o.encryptedAmount === 'string' ? o.encryptedAmount : bytesToHex(o.encryptedAmount)),
    outPk: outputs.map(o => typeof o.commitment === 'string' ? o.commitment : bytesToHex(o.commitment)),
    clsags
  };
}

/**
 * Compute pseudo output commitments that balance with output commitments
 * Sum(pseudoOuts) = Sum(outPk) + fee*H
 *
 * @param {Array<Object>} inputs - Inputs with { amount, mask }
 * @param {Array<Object>} outputs - Outputs with { amount, mask }
 * @param {bigint} fee - Transaction fee
 * @returns {Object} { pseudoOuts: Array<Uint8Array>, pseudoMasks: Array<Uint8Array> }
 */
export function computePseudoOutputs(inputs, outputs, fee) {
  const pseudoOuts = [];
  const pseudoMasks = [];

  // Sum of output masks
  let outputMaskSum = 0n;
  for (const output of outputs) {
    const maskBig = bytesToBigInt(output.mask);
    outputMaskSum = (outputMaskSum + maskBig) % L;
  }

  // Create pseudo outputs for all inputs except the last
  let usedMaskSum = 0n;

  for (let i = 0; i < inputs.length - 1; i++) {
    // Random mask for this pseudo output
    const mask = scRandom();
    const maskBig = bytesToBigInt(mask);
    usedMaskSum = (usedMaskSum + maskBig) % L;

    // Pseudo output = mask*G + amount*H
    const pseudoOut = commit(inputs[i].amount, mask);

    pseudoMasks.push(mask);
    pseudoOuts.push(pseudoOut);
  }

  // Last pseudo output mask: ensures sum balances
  // lastMask = outputMaskSum - usedMaskSum
  const lastMaskBig = ((outputMaskSum - usedMaskSum) % L + L) % L;
  const lastMask = bigIntToBytes(lastMaskBig);

  // Last pseudo output
  const lastInput = inputs[inputs.length - 1];
  const lastPseudoOut = commit(lastInput.amount, lastMask);

  pseudoMasks.push(lastMask);
  pseudoOuts.push(lastPseudoOut);

  return { pseudoOuts, pseudoMasks };
}

// =============================================================================
// TRANSACTION BUILDING
// =============================================================================

/**
 * Build a complete transaction
 *
 * This is the main orchestration function that creates a signed transaction
 * ready for broadcast. It handles:
 * - Output creation with one-time keys
 * - Pedersen commitments for amounts
 * - CLSAG ring signatures
 * - Bulletproofs+ range proofs
 * - Change output generation
 * - Fee calculation and balance verification
 *
 * @param {Object} params - Transaction parameters
 * @param {Array<Object>} params.inputs - Inputs to spend, each with:
 *   - secretKey: Uint8Array - One-time secret key for this output
 *   - publicKey: Uint8Array - One-time public key
 *   - amount: bigint - Amount of this input
 *   - mask: Uint8Array - Commitment mask (blinding factor)
 *   - globalIndex: number - Global output index (for key offsets)
 *   - ring: Array<Uint8Array> - Ring member public keys (including real key)
 *   - ringCommitments: Array<Uint8Array> - Ring member commitments
 *   - realIndex: number - Index of real key in ring
 * @param {Array<Object>} params.destinations - Outputs to create, each with:
 *   - address: string - Destination address
 *   - amount: bigint - Amount to send
 *   - paymentId?: string - Optional payment ID (for integrated addresses)
 * @param {Object} params.changeAddress - Change address info:
 *   - viewPublicKey: Uint8Array - View public key
 *   - spendPublicKey: Uint8Array - Spend public key
 *   - isSubaddress?: boolean - True if subaddress
 * @param {bigint} params.fee - Transaction fee
 * @param {Object} options - Additional options
 * @param {number} options.unlockTime - Unlock time (default: 0)
 * @param {Uint8Array} options.txSecretKey - Pre-generated tx secret key
 * @param {boolean} options.useCarrot - Use CARROT addressing (default: false)
 * @returns {Object} Complete transaction ready for serialization/broadcast
 */
export function buildTransaction(params, options = {}) {
  const { inputs, destinations, changeAddress, fee } = params;
  const {
    unlockTime = 0,
    txSecretKey: providedTxSecKey,
    useCarrot = false,
    // Salvium-specific options
    txType = TX_TYPE.TRANSFER,
    amountBurnt = 0n,
    sourceAssetType = 'SAL',
    destinationAssetType = 'SAL',
    returnAddress = null,
    returnPubkey = null,
    protocolTxData = null,
    amountSlippageLimit = 0n,
    // HF-aware options
    height = 0,
    network = 0,
    // CARROT view incoming key (k_vi) — for anchor computation in CARROT outputs
    viewSecretKey = null,
    // Sender's CryptoNote view secret key — for F-point computation in v3+ return addresses
    senderViewSecretKey = null
  } = options;

  if (!inputs || inputs.length === 0) {
    throw new Error('At least one input is required');
  }
  // STAKE, BURN, CONVERT, and AUDIT transactions can have no payment destinations
  // - STAKE/BURN: The "burned" amount goes to amount_burnt field, not to outputs
  // - CONVERT: The converted output is created by the protocol_tx at block mining time
  // - AUDIT: All coins locked (change-is-zero), returned via protocol_tx after maturity
  if ((!destinations || destinations.length === 0) &&
      txType !== TX_TYPE.STAKE && txType !== TX_TYPE.BURN && txType !== TX_TYPE.CONVERT && txType !== TX_TYPE.AUDIT) {
    throw new Error('At least one destination is required');
  }

  // Convert fee to bigint if needed
  const feeBig = typeof fee === 'bigint' ? fee : BigInt(fee);

  // Calculate total input amount
  let totalInputAmount = 0n;
  for (const input of inputs) {
    const amount = typeof input.amount === 'bigint' ? input.amount : BigInt(input.amount);
    totalInputAmount += amount;
  }

  // Calculate total output amount
  let totalOutputAmount = 0n;
  for (const dest of destinations) {
    const amount = typeof dest.amount === 'bigint' ? dest.amount : BigInt(dest.amount);
    totalOutputAmount += amount;
  }

  // Verify balance (amountBurnt covers STAKE/BURN/CONVERT amounts)
  const changeAmount = totalInputAmount - totalOutputAmount - feeBig - amountBurnt;
  if (changeAmount < 0n) {
    throw new Error(`Insufficient funds: inputs=${totalInputAmount}, outputs=${totalOutputAmount}, fee=${feeBig}, burnt=${amountBurnt}`);
  }

  // Generate transaction secret key
  const txSecretKey = providedTxSecKey || generateTxSecretKey();

  // Generate key images for inputs FIRST (needed for CARROT input context)
  const keyImages = inputs.map(input => {
    return generateKeyImage(input.publicKey, input.secretKey);
  });

  // Determine TX version and RCT type based on hard fork BEFORE output creation
  const txVersion = height > 0 ? getTxVersion(txType, height, network) : TX_VERSION.V2;
  const rctType = height > 0 ? getRctType(height, network) : RCT_TYPE.BulletproofPlus;

  // Create outputs (destinations + change if needed)
  const outputs = [];
  const outputMasks = [];
  const amountKeys = []; // derivation scalars for F-point computation (v3+ return addresses)
  let outputIndex = 0;

  // CARROT ephemeral key (D_e) — used as txPubKey for CARROT outputs
  let carrotEphemeralPubkey = null;

  if (rctType >= 9) {
    // =========================================================================
    // CARROT OUTPUT CREATION (SalviumOne / HF10+)
    //
    // Uses X25519 ECDH with CARROT key derivation:
    //   1. Generate ephemeral private key d_e from anchor + input context
    //   2. D_e = d_e * B (X25519 basepoint) — stored as txPubKey
    //   3. For each output: s_sr = d_e * ConvertPointE(K_v), derive Ko, viewTag, etc.
    //
    // The destination's viewPublicKey and spendPublicKey must be CARROT keys
    // (K^0_v and K_s from a CARROT address), not legacy CN keys.
    // =========================================================================

    // Build input context: 'R' || first_key_image
    const inputContext = _buildRingCtInputContext(keyImages[0]);

    // Use first destination's spend pubkey for d_e derivation
    const allDests = [...destinations];
    if (changeAddress) {
      allDests.push({ ...changeAddress, amount: changeAmount, isChange: true });
    }

    const firstDest = allDests[0];
    const firstSpendPub = typeof firstDest.spendPublicKey === 'string'
      ? hexToBytes(firstDest.spendPublicKey) : firstDest.spendPublicKey;
    const paymentId = new Uint8Array(8); // default zero payment ID

    // Generate anchor and derive ephemeral private key
    const firstAnchor = _generateJanusAnchor();
    const d_e = _deriveCarrotEphemeralPrivkey(firstAnchor, inputContext, firstSpendPub, paymentId);

    // D_e = d_e * B (X25519 basepoint)
    carrotEphemeralPubkey = _computeCarrotEphemeralPubkey(d_e, firstSpendPub, firstDest.isSubaddress || false);

    // Create CARROT outputs for each destination
    for (const dest of destinations) {
      const amount = typeof dest.amount === 'bigint' ? dest.amount : BigInt(dest.amount);
      const destViewPub = typeof dest.viewPublicKey === 'string'
        ? hexToBytes(dest.viewPublicKey) : dest.viewPublicKey;
      const destSpendPub = typeof dest.spendPublicKey === 'string'
        ? hexToBytes(dest.spendPublicKey) : dest.spendPublicKey;

      // Compute shared secret: s_sr = d_e * ConvertPointE(K_v)
      const s_sr = _computeCarrotSharedSecret(d_e, destViewPub);

      // Contextualized secret: s^ctx_sr
      const s_ctx = _deriveCarrotSenderReceiverSecret(s_sr, carrotEphemeralPubkey, inputContext);

      // Amount blinding factor
      const enoteType = CARROT_ENOTE_TYPE.PAYMENT;
      const mask = _deriveCarrotAmountBlindingFactor(s_ctx, amount, destSpendPub, enoteType);

      // Commitment: C_a = mask*G + amount*H
      const commitment = commit(amount, mask);

      // One-time address extensions
      const { extensionG, extensionT } = _deriveCarrotOnetimeExtensions(s_ctx, commitment);

      // One-time address: Ko = K_s + k^o_g * G + k^o_t * T
      const Ko = _computeCarrotOnetimeAddress(destSpendPub, extensionG, extensionT);

      // 3-byte view tag (uses UN-contextualized secret)
      const viewTag = _deriveCarrotViewTag(s_sr, inputContext, Ko);

      // Encrypted components
      const anchor = _generateJanusAnchor(); // each output gets its own anchor for encryption
      const anchorEnc = _encryptCarrotAnchor(anchor, s_ctx, Ko);
      const amountEnc = _encryptCarrotAmount(amount, s_ctx, Ko);

      outputs.push({
        amount,
        publicKey: Ko,
        commitment,
        encryptedAmount: amountEnc,
        mask,
        carrotViewTag: viewTag,
        encryptedJanusAnchor: anchorEnc,
        viewTag: null // no CN view tag for CARROT
      });
      outputMasks.push(mask);
      // Standard Ed25519 ECDH derivation scalar for F-point computation
      const derivation_fp = generateKeyDerivation(destViewPub, txSecretKey);
      amountKeys.push(derivationToScalar(derivation_fp, outputIndex));
      outputIndex++;
    }

    // Add CARROT change output (always when changeAddress provided, even for 0 amount)
    if (changeAddress) {
      const chgViewPub = typeof changeAddress.viewPublicKey === 'string'
        ? hexToBytes(changeAddress.viewPublicKey) : changeAddress.viewPublicKey;
      const chgSpendPub = typeof changeAddress.spendPublicKey === 'string'
        ? hexToBytes(changeAddress.spendPublicKey) : changeAddress.spendPublicKey;

      // Shared secret for change output
      const s_sr_chg = _computeCarrotSharedSecret(d_e, chgViewPub);
      const s_ctx_chg = _deriveCarrotSenderReceiverSecret(s_sr_chg, carrotEphemeralPubkey, inputContext);

      // CHANGE enote type for amount blinding factor
      const mask_chg = _deriveCarrotAmountBlindingFactor(s_ctx_chg, changeAmount, chgSpendPub, CARROT_ENOTE_TYPE.CHANGE);
      const commitment_chg = commit(changeAmount, mask_chg);
      const { extensionG: extG_chg, extensionT: extT_chg } = _deriveCarrotOnetimeExtensions(s_ctx_chg, commitment_chg);
      const Ko_chg = _computeCarrotOnetimeAddress(chgSpendPub, extG_chg, extT_chg);
      const viewTag_chg = _deriveCarrotViewTag(s_sr_chg, inputContext, Ko_chg);

      // For self-send (change), compute special anchor
      let anchor_chg;
      if (viewSecretKey) {
        const vsk = typeof viewSecretKey === 'string' ? hexToBytes(viewSecretKey) : viewSecretKey;
        anchor_chg = _computeCarrotSpecialAnchor(carrotEphemeralPubkey, inputContext, Ko_chg, vsk);
      } else {
        anchor_chg = _generateJanusAnchor();
      }
      const anchorEnc_chg = _encryptCarrotAnchor(anchor_chg, s_ctx_chg, Ko_chg);
      const amountEnc_chg = _encryptCarrotAmount(changeAmount, s_ctx_chg, Ko_chg);

      outputs.push({
        amount: changeAmount,
        publicKey: Ko_chg,
        commitment: commitment_chg,
        encryptedAmount: amountEnc_chg,
        mask: mask_chg,
        carrotViewTag: viewTag_chg,
        encryptedJanusAnchor: anchorEnc_chg,
        viewTag: null,
        isChange: true
      });
      outputMasks.push(mask_chg);
      // Standard Ed25519 ECDH derivation scalar for F-point computation
      const derivation_fp_chg = generateKeyDerivation(chgViewPub, txSecretKey);
      amountKeys.push(derivationToScalar(derivation_fp_chg, outputIndex));
    }
  } else {
    // =========================================================================
    // CRYPTONOTE OUTPUT CREATION (pre-CARROT: rctType 6, 7, 8)
    // =========================================================================

    // Add destination outputs
    for (const dest of destinations) {
      const amount = typeof dest.amount === 'bigint' ? dest.amount : BigInt(dest.amount);

      const output = createOutput(
        txSecretKey,
        dest.viewPublicKey,
        dest.spendPublicKey,
        amount,
        outputIndex,
        dest.isSubaddress || false
      );

      outputs.push({
        amount,
        publicKey: output.outputPublicKey,
        commitment: output.commitment,
        encryptedAmount: output.encryptedAmount,
        mask: output.mask,
        viewTag: output.viewTag
      });
      outputMasks.push(output.mask);
      // Derivation scalar for F-point computation (createOutput already computed it)
      amountKeys.push(derivationToScalar(output.derivation, outputIndex));
      outputIndex++;
    }

    // Add change output (always when changeAddress provided, even for 0 amount)
    if (changeAddress) {
      const changeOutput = createOutput(
        txSecretKey,
        changeAddress.viewPublicKey,
        changeAddress.spendPublicKey,
        changeAmount,
        outputIndex,
        changeAddress.isSubaddress || false
      );

      outputs.push({
        amount: changeAmount,
        publicKey: changeOutput.outputPublicKey,
        commitment: changeOutput.commitment,
        encryptedAmount: changeOutput.encryptedAmount,
        mask: changeOutput.mask,
        viewTag: changeOutput.viewTag,
        isChange: true
      });
      outputMasks.push(changeOutput.mask);
      amountKeys.push(derivationToScalar(changeOutput.derivation, outputIndex));
    }
  }

  // Sort outputs by public key (lexicographic) for CARROT (HF10+)
  // C++ sorts enotes by K_o: output_set_finalization.cpp:311-314
  if (rctType >= 9) {
    // Build sort permutation
    const indices = outputs.map((_, i) => i);
    indices.sort((a, b) => {
      const ka = typeof outputs[a].publicKey === 'string' ? outputs[a].publicKey : bytesToHex(outputs[a].publicKey);
      const kb = typeof outputs[b].publicKey === 'string' ? outputs[b].publicKey : bytesToHex(outputs[b].publicKey);
      // memcmp comparison (byte-by-byte, big endian in hex)
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    const sortedOutputs = indices.map(i => outputs[i]);
    const sortedMasks = indices.map(i => outputMasks[i]);
    const sortedAmountKeys = indices.map(i => amountKeys[i]);
    outputs.length = 0;
    outputMasks.length = 0;
    amountKeys.length = 0;
    for (let i = 0; i < sortedOutputs.length; i++) {
      outputs.push(sortedOutputs[i]);
      outputMasks.push(sortedMasks[i]);
      amountKeys.push(sortedAmountKeys[i]);
    }
  }

  // Sort inputs by key image (descending memcmp) — C++ cryptonote_tx_utils.cpp:937-946
  {
    const insOrder = inputs.map((_, i) => i);
    insOrder.sort((a, b) => {
      const ka = bytesToHex(keyImages[a]);
      const kb = bytesToHex(keyImages[b]);
      // descending: memcmp > 0 means a comes first
      return ka > kb ? -1 : ka < kb ? 1 : 0;
    });
    const sortedInputs = insOrder.map(i => inputs[i]);
    const sortedKeyImages = insOrder.map(i => keyImages[i]);
    inputs.length = 0;
    keyImages.length = 0;
    for (let i = 0; i < sortedInputs.length; i++) {
      inputs.push(sortedInputs[i]);
      keyImages.push(sortedKeyImages[i]);
    }
  }

  // Build transaction prefix
  const txPrefix = {
    version: txVersion,
    unlockTime,
    vin: inputs.map((input, i) => ({
      type: TXIN_TYPE.KEY,
      amount: 0n, // RingCT: always 0
      assetType: sourceAssetType,
      keyOffsets: indicesToOffsets(input.ringIndices
        ? input.ringIndices.slice(0, input.ring.length)
        : input.ring.map((_, j) => j)),
      keyImage: keyImages[i]
    })),
    vout: outputs.map(output => {
      // For BURN/CONVERT TXs, change outputs keep the source asset type
      const outputAssetType = (output.isChange && txType === TX_TYPE.BURN)
        ? sourceAssetType : destinationAssetType;
      if (rctType === 9) {
        // CARROT v1 output for SalviumOne (HF10+)
        return {
          type: TXOUT_TYPE.CARROT_V1,
          amount: 0n,
          target: output.publicKey,
          assetType: outputAssetType,
          carrotViewTag: output.carrotViewTag || new Uint8Array(3),
          encryptedJanusAnchor: output.encryptedJanusAnchor || new Uint8Array(16)
        };
      }
      return {
        type: TXOUT_TYPE.TAGGED_KEY,
        amount: 0n,
        target: output.publicKey,
        assetType: outputAssetType,
        unlockTime: 0n,
        viewTag: output.viewTag
      };
    }),
    extra: {
      // For CARROT (rctType >= 9): txPubKey = D_e (CARROT ephemeral pubkey, X25519)
      // For pre-CARROT: txPubKey = r*G (standard Ed25519 tx public key)
      txPubKey: carrotEphemeralPubkey || getTxPublicKey(txSecretKey)
    },
    // Salvium-specific prefix fields
    txType,
    amount_burnt: amountBurnt,
    source_asset_type: sourceAssetType,
    destination_asset_type: destinationAssetType,
    amount_slippage_limit: amountSlippageLimit
  };

  // Set return address fields based on TX version
  if (txVersion >= 3 && txType === TX_TYPE.TRANSFER) {
    // v3+: return_address_list (F-points) + return_address_change_mask
    // F = (y^-1) * a * P_change  (C++ cryptonote_tx_utils.cpp:148-263)
    // change_mask[i] = change_index XOR H("CHG_IDX\0" || amount_key[i])[0]
    const changeIdx = outputs.findIndex(o => o.isChange);
    const P_change = changeIdx >= 0
      ? (typeof outputs[changeIdx].publicKey === 'string'
          ? hexToBytes(outputs[changeIdx].publicKey) : outputs[changeIdx].publicKey)
      : null;

    // Precompute a * P_change (view secret key * change output pubkey)
    let aP_change = null;
    if (P_change && senderViewSecretKey) {
      const vsk = typeof senderViewSecretKey === 'string'
        ? hexToBytes(senderViewSecretKey) : senderViewSecretKey;
      aP_change = scalarMultPoint(vsk, P_change);
    }

    const fPoints = [];
    const changeMaskBytes = [];

    for (let i = 0; i < outputs.length; i++) {
      const ak = amountKeys[i];
      const akBytes = typeof ak === 'string' ? hexToBytes(ak) : ak;

      // y = H_s("RETURN\0\0" || amount_key) — 8-byte domain + 32-byte key
      const domainReturn = new Uint8Array(40);
      domainReturn.set(new TextEncoder().encode('RETURN'), 0); // bytes 6-7 stay 0
      domainReturn.set(akBytes, 8);
      const y = scReduce32(keccak256(domainReturn));

      // F = y^-1 * (a * P_change)
      if (aP_change) {
        const yInv = scInvert(y);
        fPoints.push(scalarMultPoint(yInv, aP_change));
      } else {
        fPoints.push(new Uint8Array(32));
      }

      // change_mask[i] = change_index XOR H("CHG_IDX\0" || amount_key)[0]
      const domainChg = new Uint8Array(40);
      domainChg.set(new TextEncoder().encode('CHG_IDX'), 0); // byte 7 stays 0
      domainChg.set(akBytes, 8);
      const eciHash = keccak256(domainChg);
      changeMaskBytes.push((changeIdx >= 0 ? changeIdx : 0) ^ eciHash[0]);
    }

    txPrefix.return_address_list = fPoints;
    txPrefix.return_address_change_mask = new Uint8Array(changeMaskBytes);
  } else if (txVersion >= 4 && txType === TX_TYPE.STAKE) {
    txPrefix.protocol_tx_data = protocolTxData;
  } else if (txType !== TX_TYPE.MINER && txType !== TX_TYPE.UNSET && txType !== TX_TYPE.PROTOCOL) {
    txPrefix.return_address = returnAddress;
    txPrefix.return_pubkey = returnPubkey;
  }

  // Calculate transaction prefix hash
  const txPrefixHash = getTxPrefixHash(txPrefix);

  // Compute pseudo output commitments (balances input/output masks)
  const inputsForPseudo = inputs.map(input => ({
    amount: typeof input.amount === 'bigint' ? input.amount : BigInt(input.amount),
    mask: input.mask
  }));
  const outputsForPseudo = outputs.map(output => ({
    amount: output.amount,
    mask: output.mask
  }));

  const { pseudoOuts, pseudoMasks } = computePseudoOutputs(inputsForPseudo, outputsForPseudo, feeBig);

  // Compute p_r for ALL RCT types — Salvium always includes p_r in the sum check.
  // Reference: rctSigs.cpp genRctSimple always calls genC(rv.p_r, difference, 0)
  // and verRctSemanticsSimple always does addKeys(sumOutpks, rv.p_r, sumOutpks)
  const { p_r, difference: prDifference } = computePR(pseudoMasks, outputMasks);

  // Generate pr_proof and salvium_data for FullProofs/SalviumZero/SalviumOne (types 7-9)
  let salvium_data = null;
  if (rctType >= 7) {
    const prProof = generatePRProof(prDifference, p_r);

    if (rctType === 8 || rctType === 9) {
      // Full salvium_data_t for SalviumZero/SalviumOne
      salvium_data = {
        salvium_data_type: 0, // SalviumZero
        pr_proof: prProof,
        sa_proof: { R: new Uint8Array(32), z1: new Uint8Array(32), z2: new Uint8Array(32) } // zeros for SalviumZero
      };
    } else {
      // FullProofs (7): just the two proofs, no type wrapper
      salvium_data = {
        pr_proof: prProof,
        sa_proof: { R: new Uint8Array(32), z1: new Uint8Array(32), z2: new Uint8Array(32) }
      };
    }
  }

  // Generate Bulletproofs+ range proofs BEFORE pre-MLSAG hash
  // (C++ genRctSimple generates BP+ first, then hashes components for CLSAG message)
  // Skip for transactions with no outputs (e.g. AUDIT — all coins locked, no change)
  let bpProof = null;
  let bulletproofPlus = null;
  if (outputs.length > 0) {
    const bpAmounts = outputs.map(o => o.amount);
    const bpMasks = outputMasks.map(m => {
      const bytes = typeof m === 'string' ? hexToBytes(m) : m;
      return _bytesToBigInt(bytes);
    });
    bpProof = bulletproofPlusProve(bpAmounts, bpMasks);
    bulletproofPlus = {
      ...bpProof,
      serialized: serializeBpPlus(bpProof)
    };
  }

  // Build RingCT base (needed for pre-MLSAG hash)
  // Must include ecdhInfo, outPk, p_r, and salvium_data — matches C++ serialize_rctsig_base
  const rctBase = {
    type: rctType,
    fee: feeBig,
    ecdhInfo: outputs.map(o => bytesToHex(o.encryptedAmount)),
    outPk: outputs.map(o => bytesToHex(o.commitment)),
    p_r: p_r,
    salvium_data: salvium_data
  };

  const rctBaseSerialized = serializeRctBase(rctBase);

  // Calculate pre-MLSAG hash: H(prefixHash || H(rctSigBase) || H(bp+ components))
  const preMLsagHash = getPreMlsagHash(txPrefixHash, rctBaseSerialized, bpProof);

  // Sign each input: CLSAG for types 6-8, TCLSAG for type 9
  const clsags = [];
  const tclsags = [];

  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i];
    const inputMask = typeof input.mask === 'string' ? hexToBytes(input.mask) : input.mask;
    // z = inputMask - pseudoMask, so that C[l] = z*G (commitment difference = z*G)
    const signingMask = scSub(inputMask, pseudoMasks[i]);

    if (rctType === 9) {
      // TCLSAG for SalviumOne — y=zero for non-carrot inputs (see tx_builder.cpp:1145)
      const secretKeyY = input.secretKeyY || new Uint8Array(32);

      const sig = tclsagSign(
        preMLsagHash,
        input.ring,
        input.secretKey,
        secretKeyY,
        input.ringCommitments,
        signingMask,
        pseudoOuts[i],
        input.realIndex
      );

      tclsags.push(sig);
    } else {
      // CLSAG for all other types
      const sig = clsagSign(
        preMLsagHash,
        input.ring,
        input.secretKey,
        input.ringCommitments,
        signingMask,
        pseudoOuts[i],
        input.realIndex
      );
      clsags.push(sig);
    }
  }

  // Assemble complete transaction
  const rctObj = {
    type: rctType,
    fee: feeBig,
    pseudoOuts: pseudoOuts.map(p => bytesToHex(p)),
    ecdhInfo: outputs.map(o => bytesToHex(o.encryptedAmount)),
    outPk: outputs.map(o => bytesToHex(o.commitment)),
    bulletproofPlus
  };

  // p_r is always set (computed for all RCT types)
  rctObj.p_r = p_r;
  if (salvium_data) rctObj.salvium_data = salvium_data;

  // Add signatures
  if (rctType === 9) {
    rctObj.TCLSAGs = tclsags;
  } else {
    rctObj.CLSAGs = clsags;
  }

  const transaction = {
    prefix: txPrefix,
    rct: rctObj,
    // Additional metadata (not serialized to chain)
    _meta: {
      txSecretKey: bytesToHex(txSecretKey),
      keyImages: keyImages.map(ki => bytesToHex(ki)),
      outputMasks: outputMasks.map(m => bytesToHex(m)),
      changeIndex: changeAmount > 0n ? outputs.length - 1 : -1,
      // Ring data for debugging/verification (not serialized)
      ringData: inputs.map(input => ({
        ring: input.ring.map(k => typeof k === 'string' ? k : bytesToHex(k)),
        ringCommitments: input.ringCommitments.map(c => typeof c === 'string' ? c : bytesToHex(c)),
        realIndex: input.realIndex
      }))
    }
  };

  return transaction;
}

/**
 * Build a STAKE transaction (Salvium-specific)
 *
 * STAKE transactions lock funds for STAKE_LOCK_PERIOD blocks and earn yield.
 * Key differences from regular transfers:
 * - Funds go to own address (self-send with lock)
 * - amount_burnt contains the staked amount
 * - Only change output (no payment destination)
 * - unlock_time = STAKE_LOCK_PERIOD
 *
 * @param {Object} params - Transaction parameters
 * @param {Array<Object>} params.inputs - Inputs to spend
 * @param {bigint} params.stakeAmount - Amount to stake
 * @param {Object} params.returnAddress - Address to receive stake back (usually own address)
 *   - viewPublicKey, spendPublicKey, isSubaddress
 * @param {bigint} params.fee - Transaction fee
 * @param {Object} options - Additional options
 * @param {number} options.stakeLockPeriod - Lock period in blocks (default: 21600 mainnet)
 * @param {string} options.assetType - Asset type to stake ('SAL' or 'SAL1')
 * @param {Uint8Array} options.txSecretKey - Pre-generated tx secret key
 * @param {boolean} options.useCarrot - Use CARROT protocol (affects protocol_tx_data)
 * @returns {Object} Complete STAKE transaction ready for broadcast
 */
export function buildStakeTransaction(params, options = {}) {
  const { inputs, stakeAmount, returnAddress, fee } = params;
  const {
    stakeLockPeriod = 21600, // Mainnet default
    assetType = 'SAL',
    txSecretKey,
    useCarrot = false,
    height = 0,
    network = 0,
    viewSecretKey = null
  } = options;

  if (!inputs || inputs.length === 0) {
    throw new Error('At least one input is required');
  }
  if (!stakeAmount || stakeAmount <= 0n) {
    throw new Error('Stake amount must be positive');
  }
  if (!returnAddress) {
    throw new Error('Return address is required for stake transaction');
  }

  const stakeAmountBig = typeof stakeAmount === 'bigint' ? stakeAmount : BigInt(stakeAmount);
  const feeBig = typeof fee === 'bigint' ? fee : BigInt(fee);

  // Calculate total input amount
  let totalInputAmount = 0n;
  for (const input of inputs) {
    const amount = typeof input.amount === 'bigint' ? input.amount : BigInt(input.amount);
    totalInputAmount += amount;
  }

  // For STAKE: staked amount goes in amount_burnt, only change output
  const changeAmount = totalInputAmount - stakeAmountBig - feeBig;
  if (changeAmount < 0n) {
    throw new Error(`Insufficient funds: inputs=${totalInputAmount}, stake=${stakeAmountBig}, fee=${feeBig}`);
  }

  // Create dummy destination (STAKE has no real destination - amount goes to amount_burnt)
  // But we need at least one output (change) for the ring signature
  const destinations = [];

  // Prepare protocol_tx_data for CARROT STAKE (version >= 4)
  let protocolTxData = null;
  let returnAddressBytes = null;
  let returnPubkeyBytes = null;

  if (useCarrot) {
    // CARROT STAKE uses protocol_tx_data structure
    // return_address = spend pubkey (K_s), return_pubkey = view pubkey (K^0_v)
    protocolTxData = {
      version: 1,
      return_address: typeof returnAddress.spendPublicKey === 'string'
        ? hexToBytes(returnAddress.spendPublicKey)
        : returnAddress.spendPublicKey,
      return_pubkey: typeof returnAddress.viewPublicKey === 'string'
        ? hexToBytes(returnAddress.viewPublicKey)
        : returnAddress.viewPublicKey,
      return_view_tag: returnAddress.viewTag || new Uint8Array(3),
      return_anchor_enc: returnAddress.anchorEnc || new Uint8Array(16)
    };
  } else {
    // Legacy STAKE uses return_address and return_pubkey
    returnAddressBytes = typeof returnAddress.spendPublicKey === 'string'
      ? hexToBytes(returnAddress.spendPublicKey)
      : returnAddress.spendPublicKey;
    returnPubkeyBytes = typeof returnAddress.viewPublicKey === 'string'
      ? hexToBytes(returnAddress.viewPublicKey)
      : returnAddress.viewPublicKey;
  }

  // Build using base buildTransaction with STAKE options
  return buildTransaction(
    {
      inputs,
      destinations,  // Empty - STAKE has no payment destinations
      changeAddress: returnAddress,  // Change goes back to staker
      fee
    },
    {
      unlockTime: stakeLockPeriod,
      txSecretKey,
      useCarrot,
      txType: TX_TYPE.STAKE,
      amountBurnt: stakeAmountBig,
      sourceAssetType: assetType,
      destinationAssetType: assetType,
      returnAddress: returnAddressBytes,
      returnPubkey: returnPubkeyBytes,
      protocolTxData,
      amountSlippageLimit: 0n,
      height,
      network,
      viewSecretKey
    }
  );
}

/**
 * Build a BURN transaction
 *
 * BURN transactions permanently destroy coins. The burned amount goes into
 * amount_burnt field with destination_asset_type = "BURN".
 *
 * Structure:
 * - txType: BURN (5)
 * - source_asset_type: "SAL" or "SAL1"
 * - destination_asset_type: "BURN"
 * - amount_burnt: burned amount
 * - unlock_time: 0 (no lock)
 * - outputs: only change back to sender
 *
 * @param {Object} params - Transaction parameters:
 * @param {Array} params.inputs - Array of input objects with ring data
 * @param {BigInt|number} params.burnAmount - Amount to burn
 * @param {Object} params.changeAddress - Address for change output
 * @param {BigInt|number} params.fee - Transaction fee
 * @param {Object} options - Additional options:
 * @param {string} options.assetType - Asset type to burn ('SAL' or 'SAL1', default 'SAL')
 * @param {Uint8Array} options.txSecretKey - Optional pre-generated tx secret key
 * @param {boolean} options.useCarrot - Use CARROT protocol
 * @returns {Object} Complete BURN transaction ready for broadcast
 */
export function buildBurnTransaction(params, options = {}) {
  const { inputs, burnAmount, changeAddress, fee } = params;
  const {
    assetType = 'SAL',
    txSecretKey,
    useCarrot = false,
    height = 0,
    network = 0,
    viewSecretKey = null
  } = options;

  if (!inputs || inputs.length === 0) {
    throw new Error('At least one input is required');
  }
  if (!burnAmount || burnAmount <= 0n) {
    throw new Error('Burn amount must be positive');
  }
  if (!changeAddress) {
    throw new Error('Change address is required for burn transaction');
  }

  const burnAmountBig = typeof burnAmount === 'bigint' ? burnAmount : BigInt(burnAmount);
  const feeBig = typeof fee === 'bigint' ? fee : BigInt(fee);

  // Calculate total input amount
  let totalInputAmount = 0n;
  for (const input of inputs) {
    const amount = typeof input.amount === 'bigint' ? input.amount : BigInt(input.amount);
    totalInputAmount += amount;
  }

  // For BURN: burned amount goes in amount_burnt, only change output
  const changeAmount = totalInputAmount - burnAmountBig - feeBig;
  if (changeAmount < 0n) {
    throw new Error(`Insufficient funds: inputs=${totalInputAmount}, burn=${burnAmountBig}, fee=${feeBig}`);
  }

  // BURN has no destinations - only change output
  const destinations = [];

  // Build using base buildTransaction with BURN options
  return buildTransaction(
    {
      inputs,
      destinations,  // Empty - BURN has no payment destinations
      changeAddress,
      fee
    },
    {
      unlockTime: 0,  // BURN has no lock period
      txSecretKey,
      useCarrot,
      txType: TX_TYPE.BURN,
      amountBurnt: burnAmountBig,
      sourceAssetType: assetType,
      destinationAssetType: 'BURN',  // Special marker for BURN transactions
      returnAddress: null,
      returnPubkey: null,
      protocolTxData: null,
      amountSlippageLimit: 0n,
      height,
      network,
      viewSecretKey
    }
  );
}

/**
 * Build a CONVERT transaction
 *
 * CONVERT transactions convert between asset types (SAL <-> VSD) using oracle pricing.
 * The actual conversion happens at the protocol layer when the block is mined.
 *
 * NOTE: CONVERT transactions are currently gated behind hard fork version 255
 * and are not yet enabled on mainnet.
 *
 * @param {Object} params - Transaction parameters:
 *   - inputs: Array of inputs to spend
 *   - convertAmount: Amount to convert (in source asset)
 *   - sourceAsset: Asset type to convert FROM ('SAL' or 'VSD')
 *   - destAsset: Asset type to convert TO ('VSD' or 'SAL')
 *   - slippageLimit: Maximum acceptable slippage (default: 3.125% = amount/32)
 *   - changeAddress: Address object for change output
 *   - returnAddress: Public key for receiving converted amount (derived from wallet keys)
 *   - returnPubkey: TX public key for ECDH (derived from wallet keys)
 *   - fee: Transaction fee
 * @param {Object} options - Optional settings:
 *   - txSecretKey: Pre-set transaction secret key
 *   - useCarrot: Use CARROT output format
 * @returns {Object} Built transaction ready for broadcast
 */
export function buildConvertTransaction(params, options = {}) {
  const {
    inputs,
    convertAmount,
    sourceAsset,
    destAsset,
    slippageLimit,
    changeAddress,
    returnAddress,
    returnPubkey,
    fee
  } = params;

  const {
    txSecretKey,
    useCarrot = false,
    height = 0,
    network = 0,
    viewSecretKey = null
  } = options;

  // Validate inputs
  if (!inputs || inputs.length === 0) {
    throw new Error('At least one input is required');
  }
  if (!convertAmount || convertAmount <= 0n) {
    throw new Error('Convert amount must be positive');
  }
  if (!sourceAsset) {
    throw new Error('Source asset type is required');
  }
  if (!destAsset) {
    throw new Error('Destination asset type is required');
  }
  if (sourceAsset === destAsset) {
    throw new Error('Source and destination asset types must be different');
  }

  // Only SAL <-> VSD conversions are valid
  const validPairs = [
    ['SAL', 'VSD'],
    ['VSD', 'SAL']
  ];
  const isValidPair = validPairs.some(
    ([from, to]) => from === sourceAsset && to === destAsset
  );
  if (!isValidPair) {
    throw new Error(`Invalid conversion pair: ${sourceAsset} -> ${destAsset}. Only SAL <-> VSD conversions are allowed`);
  }

  if (!changeAddress) {
    throw new Error('Change address is required for convert transaction');
  }
  if (!returnAddress) {
    throw new Error('Return address is required for convert transaction');
  }
  if (!returnPubkey) {
    throw new Error('Return pubkey is required for convert transaction');
  }

  const convertAmountBig = typeof convertAmount === 'bigint' ? convertAmount : BigInt(convertAmount);
  const feeBig = typeof fee === 'bigint' ? fee : BigInt(fee);

  // Calculate slippage limit - default is 1/32 (3.125%) of convert amount
  // User can specify lower but not lower than protocol minimum
  const defaultSlippage = convertAmountBig >> 5n; // amount / 32
  let slippageLimitBig;
  if (slippageLimit !== undefined && slippageLimit !== null) {
    slippageLimitBig = typeof slippageLimit === 'bigint' ? slippageLimit : BigInt(slippageLimit);
    // Slippage limit must be >= protocol slippage (1/32) for conversion to succeed
    if (slippageLimitBig < defaultSlippage) {
      throw new Error(`Slippage limit ${slippageLimitBig} is below protocol minimum ${defaultSlippage} (3.125%)`);
    }
  } else {
    slippageLimitBig = defaultSlippage;
  }

  // Calculate total input amount
  let totalInputAmount = 0n;
  for (const input of inputs) {
    const amount = typeof input.amount === 'bigint' ? input.amount : BigInt(input.amount);
    totalInputAmount += amount;
  }

  // For CONVERT: converted amount goes in amount_burnt, only change output in this tx
  // The converted output is created by the protocol_tx at block mining time
  const changeAmount = totalInputAmount - convertAmountBig - feeBig;
  if (changeAmount < 0n) {
    throw new Error(`Insufficient funds: inputs=${totalInputAmount}, convert=${convertAmountBig}, fee=${feeBig}`);
  }

  // CONVERT has no direct destinations - converted output comes from protocol_tx
  // Only change output is included in this transaction
  const destinations = [];

  // Build using base buildTransaction with CONVERT options
  return buildTransaction(
    {
      inputs,
      destinations,  // Empty - converted output created by protocol_tx
      changeAddress,
      fee
    },
    {
      unlockTime: 0,  // CONVERT has no lock period
      txSecretKey,
      useCarrot,
      txType: TX_TYPE.CONVERT,
      amountBurnt: convertAmountBig,  // Amount being converted
      sourceAssetType: sourceAsset,
      destinationAssetType: destAsset,
      returnAddress,
      returnPubkey,
      protocolTxData: null,
      amountSlippageLimit: slippageLimitBig,
      height,
      network,
      viewSecretKey
    }
  );
}

/**
 * Build an AUDIT transaction
 *
 * AUDIT transactions enable users to participate in periodic compliance/transparency
 * audits during designated AUDIT hard fork periods. Users voluntarily lock their
 * holdings for a defined period, providing cryptographic proofs of ownership.
 *
 * NOTE: AUDIT transactions are only valid during specific AUDIT hard fork periods
 * (HF v6, v8). Transactions submitted outside these windows will be rejected.
 *
 * @param {Object} params - Transaction parameters:
 *   - inputs: Array of inputs to spend (all coins from the wallet/subaddress)
 *   - auditAmount: Total amount being audited (locked)
 *   - sourceAsset: Asset type being audited ('SAL' or 'SAL1' depending on HF)
 *   - destAsset: Asset type received after maturity ('SAL1')
 *   - unlockHeight: Block height when coins unlock (current_height + lock_period)
 *   - returnAddress: Public key for receiving coins after maturity
 *   - returnPubkey: TX public key for ECDH
 *   - fee: Transaction fee
 * @param {Object} options - Optional settings:
 *   - txSecretKey: Pre-set transaction secret key
 *   - useCarrot: Use CARROT output format
 *   - viewSecretKey: View secret key for audit disclosure (encrypted in tx)
 *   - spendPublicKey: Spend public key for audit verification
 * @returns {Object} Built transaction ready for broadcast
 */
export function buildAuditTransaction(params, options = {}) {
  const {
    inputs,
    auditAmount,
    sourceAsset,
    destAsset,
    unlockHeight,
    returnAddress,
    returnPubkey,
    fee
  } = params;

  const {
    txSecretKey,
    useCarrot = false,
    viewSecretKey = null,
    spendPublicKey = null
  } = options;

  // Validate inputs
  if (!inputs || inputs.length === 0) {
    throw new Error('At least one input is required');
  }
  if (!auditAmount || auditAmount <= 0n) {
    throw new Error('Audit amount must be positive');
  }
  if (!sourceAsset) {
    throw new Error('Source asset type is required');
  }
  if (!destAsset) {
    throw new Error('Destination asset type is required');
  }

  // AUDIT transactions convert SAL -> SAL1 or audit SAL1 -> SAL1
  const validPairs = [
    ['SAL', 'SAL1'],
    ['SAL1', 'SAL1']
  ];
  const isValidPair = validPairs.some(
    ([from, to]) => from === sourceAsset && to === destAsset
  );
  if (!isValidPair) {
    throw new Error(`Invalid audit asset pair: ${sourceAsset} -> ${destAsset}. AUDIT uses SAL->SAL1 or SAL1->SAL1`);
  }

  if (!returnAddress) {
    throw new Error('Return address is required for audit transaction');
  }
  if (!returnPubkey) {
    throw new Error('Return pubkey is required for audit transaction');
  }
  if (!unlockHeight || unlockHeight <= 0) {
    throw new Error('Unlock height must be positive');
  }

  const auditAmountBig = typeof auditAmount === 'bigint' ? auditAmount : BigInt(auditAmount);
  const feeBig = typeof fee === 'bigint' ? fee : BigInt(fee);

  // Calculate total input amount
  let totalInputAmount = 0n;
  for (const input of inputs) {
    const amount = typeof input.amount === 'bigint' ? input.amount : BigInt(input.amount);
    totalInputAmount += amount;
  }

  // For AUDIT: all coins are locked (minus fee), no change output
  // The change-is-zero proof requires that change = 0
  const expectedAudit = totalInputAmount - feeBig;
  if (auditAmountBig !== expectedAudit) {
    throw new Error(
      `AUDIT requires all inputs minus fee. Expected audit amount: ${expectedAudit}, got: ${auditAmountBig}. ` +
      `AUDIT transactions must lock all coins (no change allowed).`
    );
  }

  // AUDIT has no change output - change-is-zero is a requirement
  // The locked coins return via protocol_tx after maturity
  const destinations = [];

  // Build using base buildTransaction with AUDIT options
  return buildTransaction(
    {
      inputs,
      destinations,  // Empty - AUDIT has no payment destinations, no change
      changeAddress: null,  // No change for AUDIT
      fee
    },
    {
      unlockTime: unlockHeight,  // Unlock after the audit period
      txSecretKey,
      useCarrot,
      txType: TX_TYPE.AUDIT,
      amountBurnt: auditAmountBig,  // Amount being locked for audit
      sourceAssetType: sourceAsset,
      destinationAssetType: destAsset,
      returnAddress,
      returnPubkey,
      protocolTxData: null,
      amountSlippageLimit: 0n,  // Not used for AUDIT
      // AUDIT-specific options for the special proofs
      auditData: {
        viewSecretKey,  // For encrypted view key disclosure
        spendPublicKey  // For spend authority verification
      }
    }
  );
}

/**
 * Sign an unsigned transaction
 *
 * Used when transaction was pre-built without signatures (e.g., offline signing)
 *
 * @param {Object} unsignedTx - Unsigned transaction with:
 *   - prefix: Transaction prefix
 *   - rct: RingCT data without CLSAGs
 *   - inputs: Array of input data for signing
 * @param {Array<Object>} secrets - Signing secrets for each input:
 *   - secretKey: Uint8Array - One-time secret key
 *   - mask: Uint8Array - Commitment mask
 * @returns {Object} Signed transaction
 */
export function signTransaction(unsignedTx, secrets) {
  const { prefix, rct, inputs } = unsignedTx;

  if (!inputs || inputs.length !== secrets.length) {
    throw new Error('Number of secrets must match number of inputs');
  }

  // Calculate transaction prefix hash
  const txPrefixHash = getTxPrefixHash(prefix);

  // Parse pseudo outputs
  const pseudoOuts = rct.pseudoOuts.map(p =>
    typeof p === 'string' ? hexToBytes(p) : p
  );

  // Build RingCT base for pre-MLSAG hash
  const rctBase = {
    type: rct.type,
    fee: rct.fee,
    pseudoOuts: rct.pseudoOuts,
    ecdhInfo: rct.ecdhInfo,
    outPk: rct.outPk
  };

  // Calculate pre-MLSAG hash
  const preMLsagHash = getPreMlsagHash(txPrefixHash, rctBase, pseudoOuts);

  // Compute pseudo output masks (need to reconstruct from outputs)
  // For signing, we need the relationship between pseudo and real masks
  const pseudoMasks = unsignedTx._pseudoMasks ||
    secrets.map(() => scRandom()); // If not provided, random (signing would fail)

  // Sign each input
  const clsags = [];
  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i];
    const secret = secrets[i];

    const inputMask = typeof secret.mask === 'string' ? hexToBytes(secret.mask) : secret.mask;
    const pseudoMask = typeof pseudoMasks[i] === 'string' ? hexToBytes(pseudoMasks[i]) : pseudoMasks[i];
    // z = inputMask - pseudoMask, so that C[l] = z*G (commitment difference = z*G)
    const signingMask = scSub(inputMask, pseudoMask);

    const sig = clsagSign(
      preMLsagHash,
      input.ring,
      secret.secretKey,
      input.ringCommitments,
      signingMask,
      pseudoOuts[i],
      input.realIndex
    );

    clsags.push(sig);
  }

  // Return signed transaction
  return {
    prefix,
    rct: {
      ...rct,
      CLSAGs: clsags
    },
    _meta: unsignedTx._meta
  };
}

/**
 * Prepare inputs for transaction building by fetching decoys
 *
 * @param {Array<Object>} ownedOutputs - Outputs to spend, each with:
 *   - publicKey: Uint8Array - One-time public key
 *   - secretKey: Uint8Array - One-time secret key (derived)
 *   - amount: bigint - Decrypted amount
 *   - mask: Uint8Array - Commitment mask
 *   - commitment: Uint8Array - Pedersen commitment
 *   - globalIndex: number - Global output index
 * @param {Object} rpcClient - Daemon RPC client (for fetching decoys)
 * @param {Object} options - Options
 * @param {number} options.ringSize - Ring size (default: 16)
 * @param {Array<number>} options.rctOffsets - Global output distribution
 * @returns {Promise<Array<Object>>} Prepared inputs ready for buildTransaction
 */
export async function prepareInputs(ownedOutputs, rpcClient, options = {}) {
  const { ringSize = DEFAULT_RING_SIZE, rctOffsets, assetType = 'SAL' } = options;

  // When asset_type is provided, use asset-type-local indices for decoy selection
  // and getOuts calls (matching C++ wallet2::get_outs behavior).
  // The output distribution and getOuts both work in asset-type-local index space.

  // Fetch output distribution once (not per-input)
  let offsets = rctOffsets;
  if (!offsets && rpcClient) {
    const distResp = await rpcClient.getOutputDistribution([0], { cumulative: true, rct_asset_type: assetType });
    const dist = distResp.result?.distributions?.[0] || distResp.distributions?.[0];
    offsets = dist?.distribution || [];
  }

  const preparedInputs = [];

  for (const output of ownedOutputs) {

    // Use asset-type-local index for decoy selection when available
    // (C++ wallet2 uses m_asset_type_output_index, not m_global_output_index)
    const outputIndex = output.assetTypeIndex != null ? output.assetTypeIndex : output.globalIndex;

    // Select decoy indices (in asset-type-local index space)
    const decoyIndices = selectDecoys(
      offsets,
      outputIndex,
      ringSize,
      new Set([outputIndex])
    );

    // Fetch ring member keys and commitments
    let ring, ringCommitments;
    if (rpcClient) {
      const outsResponse = await rpcClient.getOuts(
        decoyIndices.map(i => ({ amount: 0, index: i })),
        { asset_type: assetType }
      );

      const outs = outsResponse.result?.outs || outsResponse.outs || [];
      ring = outs.map(o => hexToBytes(o.key));
      ringCommitments = outs.map(o => hexToBytes(o.mask));
    } else {
      // Placeholder for testing
      ring = decoyIndices.map(() => new Uint8Array(32));
      ringCommitments = decoyIndices.map(() => new Uint8Array(32));
    }

    // Find real index in sorted ring
    const sortedIndices = [...decoyIndices].sort((a, b) => a - b);
    const realIndex = sortedIndices.indexOf(outputIndex);

    // Insert real output at correct position
    ring[realIndex] = typeof output.publicKey === 'string'
      ? hexToBytes(output.publicKey)
      : output.publicKey;
    ringCommitments[realIndex] = typeof output.commitment === 'string'
      ? hexToBytes(output.commitment)
      : output.commitment;

    preparedInputs.push({
      secretKey: output.secretKey,
      secretKeyY: output.secretKeyY || null,  // T-component for CARROT TCLSAG
      publicKey: output.publicKey,
      amount: output.amount,
      mask: output.mask,
      globalIndex: output.globalIndex,
      assetTypeIndex: outputIndex,
      ring,
      ringCommitments,
      ringIndices: sortedIndices,
      realIndex
    });
  }

  return preparedInputs;
}

/**
 * Estimate fee for a transaction
 *
 * Uses the 2021 scaling dynamic fee algorithm matching C++ wallet2.
 * When blockchainState is provided, computes the fee identically to the daemon.
 * Without blockchainState, falls back to static FEE_PER_BYTE (likely too low
 * for broadcast — only suitable for offline estimation).
 *
 * @param {number} numInputs - Number of inputs
 * @param {number} numOutputs - Number of outputs (including change)
 * @param {Object} options - Fee options
 * @param {string} options.priority - Fee priority (default, low, high, highest)
 * @param {number} options.ringSize - Ring size (default: 16)
 * @param {bigint} options.feePerByte - Pre-computed per-byte fee (overrides all calculation)
 * @param {Object} options.blockchainState - Blockchain parameters for dynamic fee
 * @param {number} options.blockchainState.height - Current height
 * @param {number} options.blockchainState.blockWeightMedian - Median block weight
 * @param {bigint} [options.blockchainState.alreadyGeneratedCoins] - Exact coins if known
 * @returns {bigint} Estimated fee in atomic units
 */
export function estimateTransactionFee(numInputs, numOutputs, options = {}) {
  const {
    priority = 'default',
    ringSize = DEFAULT_RING_SIZE,
    feePerByte: explicitFeePerByte,
    blockchainState,
  } = options;

  // Convert string priority to number
  // C++ wallet2.cpp: priority 0 maps to priority 2 (Normal) for fee algorithm >= 2
  let priorityNum;
  if (typeof priority === 'string') {
    switch (priority.toLowerCase()) {
      case 'low': priorityNum = FEE_PRIORITY.LOW; break;
      case 'high': priorityNum = FEE_PRIORITY.HIGH; break;
      case 'highest': priorityNum = FEE_PRIORITY.HIGHEST; break;
      default: priorityNum = FEE_PRIORITY.NORMAL; break;
    }
  } else {
    priorityNum = priority === 0 ? FEE_PRIORITY.NORMAL : priority;
  }

  // Estimate TX weight
  const weight = estimateTxWeight(numInputs, ringSize, numOutputs, 0, { bulletproofPlus: true });

  // Determine per-byte fee rate
  let feeRate;
  if (explicitFeePerByte != null) {
    // Caller provided a pre-computed per-byte rate (already includes priority)
    feeRate = BigInt(explicitFeePerByte);
  } else if (blockchainState) {
    // Compute dynamic fee from blockchain state (2021 scaling)
    // getDynamicFeePerByte returns the rate for the given priority — no multiplier needed
    feeRate = getDynamicFeePerByte(blockchainState, priorityNum);
  } else {
    // Fallback: static fee with priority multiplier (legacy, likely too low for broadcast)
    feeRate = FEE_PER_BYTE * getFeeMultiplier(priorityNum);
  }

  return calculateFeeFromWeight(feeRate, BigInt(weight));
}

/**
 * Validate a transaction before broadcast
 *
 * @param {Object} tx - Transaction to validate
 * @returns {Object} { valid: boolean, errors: Array<string> }
 */
export function validateTransaction(tx) {
  const errors = [];

  // Check transaction has required fields
  if (!tx.prefix) {
    errors.push('Missing transaction prefix');
  }
  if (!tx.rct) {
    errors.push('Missing RingCT signature data');
  }

  if (tx.prefix) {
    // Check version
    if (tx.prefix.version < 2) {
      errors.push('Invalid transaction version');
    }

    // Check inputs
    if (!tx.prefix.vin || tx.prefix.vin.length === 0) {
      errors.push('Transaction has no inputs');
    }

    // Check outputs
    if (!tx.prefix.vout || tx.prefix.vout.length === 0) {
      errors.push('Transaction has no outputs');
    }

    // Check for duplicate key images
    const keyImages = new Set();
    for (const vin of tx.prefix.vin || []) {
      if (vin.keyImage) {
        const kiHex = typeof vin.keyImage === 'string'
          ? vin.keyImage
          : bytesToHex(vin.keyImage);
        if (keyImages.has(kiHex)) {
          errors.push('Duplicate key image detected');
        }
        keyImages.add(kiHex);
      }
    }
  }

  if (tx.rct) {
    // Check CLSAG signatures present
    if (!tx.rct.CLSAGs || tx.rct.CLSAGs.length === 0) {
      errors.push('Missing CLSAG signatures');
    }

    // Check signature count matches input count
    if (tx.prefix && tx.rct.CLSAGs) {
      if (tx.rct.CLSAGs.length !== tx.prefix.vin.length) {
        errors.push('CLSAG count does not match input count');
      }
    }

    // Check output commitments present
    if (!tx.rct.outPk || tx.rct.outPk.length === 0) {
      errors.push('Missing output commitments');
    }

    // Check fee is positive
    if (tx.rct.fee <= 0n) {
      errors.push('Fee must be positive');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
