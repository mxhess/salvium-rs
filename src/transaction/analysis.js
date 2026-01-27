/**
 * Transaction Analysis Module
 *
 * Provides utilities for analyzing and extracting information from parsed transactions:
 * - Transaction hash calculation
 * - Amount decryption
 * - Public key extraction
 * - Payment ID extraction
 * - Transaction summarization
 *
 * @module transaction/analysis
 */

import { keccak256 } from '../keccak.js';
import { hexToBytes } from '../address.js';

import { TXIN_TYPE } from './constants.js';
import { getTxPrefixHash, serializeRctBase } from './serialization.js';

// =============================================================================
// TRANSACTION HASH CALCULATION
// =============================================================================

/**
 * Get transaction hash from parsed transaction
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Uint8Array} 32-byte transaction hash
 */
export function getTransactionHashFromParsed(tx) {
  // For RingCT transactions, hash is calculated differently
  if (tx.prefix.version >= 2 && tx.rct) {
    const prefixHash = getTxPrefixHash(tx.prefix);

    // Hash of RCT base
    const rctBaseHash = keccak256(serializeRctBase(tx.rct));

    // Hash of prunable data (signatures)
    const prunableData = []; // Would need to serialize CLSAG, BP, etc.
    const prunableHash = new Uint8Array(32); // Placeholder

    // Combine: hash(prefixHash || rctBaseHash || prunableHash)
    const combined = new Uint8Array(96);
    combined.set(prefixHash, 0);
    combined.set(rctBaseHash, 32);
    combined.set(prunableHash, 64);

    return keccak256(combined);
  }

  // For v1 transactions, just hash the serialized prefix
  return getTxPrefixHash(tx.prefix);
}

// =============================================================================
// AMOUNT DECRYPTION
// =============================================================================

/**
 * Decode encrypted amount from transaction output
 *
 * @param {Uint8Array|string} encryptedAmount - Encrypted amount (8 bytes)
 * @param {Uint8Array|string} sharedSecret - Shared secret for decryption
 * @returns {bigint} Decrypted amount
 */
export function decodeAmount(encryptedAmount, sharedSecret) {
  if (typeof encryptedAmount === 'string') {
    encryptedAmount = hexToBytes(encryptedAmount);
  }
  if (typeof sharedSecret === 'string') {
    sharedSecret = hexToBytes(sharedSecret);
  }

  // Generate amount mask: H_n("amount" || shared_secret)
  const prefix = new TextEncoder().encode('amount');
  const data = new Uint8Array(prefix.length + sharedSecret.length);
  data.set(prefix, 0);
  data.set(sharedSecret, prefix.length);

  const mask = keccak256(data).slice(0, 8);

  // XOR to decrypt
  const amountBytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    amountBytes[i] = encryptedAmount[i] ^ mask[i];
  }

  // Convert to bigint (little-endian)
  let amount = 0n;
  for (let i = 7; i >= 0; i--) {
    amount = (amount << 8n) | BigInt(amountBytes[i]);
  }

  return amount;
}

// =============================================================================
// FIELD EXTRACTION
// =============================================================================

/**
 * Extract transaction public key from extra field
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Uint8Array|null} Transaction public key or null
 */
export function extractTxPubKey(tx) {
  const extra = tx.prefix?.extra || tx.extra || [];

  for (const field of extra) {
    if (field.type === 0x01 && field.key) {
      return field.key;
    }
  }

  return null;
}

/**
 * Extract payment ID from extra field
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Object|null} { type: 'encrypted'|'unencrypted', id: Uint8Array } or null
 */
export function extractPaymentId(tx) {
  const extra = tx.prefix?.extra || tx.extra || [];

  for (const field of extra) {
    if (field.type === 0x02 && field.paymentId) {
      return {
        type: field.paymentIdType,
        id: field.paymentId
      };
    }
  }

  return null;
}

/**
 * Extract additional public keys from extra field (for subaddress outputs)
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Array<Uint8Array>} Array of additional public keys
 */
export function extractAdditionalPubKeys(tx) {
  const extra = tx.prefix?.extra || tx.extra || [];

  for (const field of extra) {
    if (field.type === 0x04 && field.keys) {
      return field.keys;
    }
  }

  return [];
}

// =============================================================================
// TRANSACTION SUMMARIZATION
// =============================================================================

/**
 * Summarize a parsed transaction
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Object} Transaction summary
 */
export function summarizeTransaction(tx) {
  const prefix = tx.prefix;

  return {
    version: prefix.version,
    unlockTime: prefix.unlockTime,
    inputCount: prefix.vin.length,
    outputCount: prefix.vout.length,
    isCoinbase: prefix.vin.length > 0 && prefix.vin[0].type === TXIN_TYPE.GEN,
    rctType: tx.rct?.type || null,
    fee: tx.rct?.txnFee || 0n,
    txPubKey: extractTxPubKey(tx),
    paymentId: extractPaymentId(tx),
    keyImages: prefix.vin
      .filter(v => v.type === TXIN_TYPE.KEY)
      .map(v => v.keyImage),
    outputKeys: prefix.vout.map(v => v.key),
    commitments: tx.rct?.outPk || []
  };
}

/**
 * Get transaction type name from type code
 *
 * @param {number} txType - Transaction type code
 * @returns {string} Human-readable type name
 */
export function getTransactionTypeName(txType) {
  const names = {
    0: 'UNSET',
    1: 'MINER',
    2: 'PROTOCOL',
    3: 'TRANSFER',
    4: 'CONVERT',
    5: 'BURN',
    6: 'STAKE',
    7: 'RETURN',
    8: 'AUDIT'
  };
  return names[txType] || `UNKNOWN(${txType})`;
}

/**
 * Get RCT type name from type code
 *
 * @param {number} rctType - RCT type code
 * @returns {string} Human-readable type name
 */
export function getRctTypeName(rctType) {
  const names = {
    0: 'Null',
    1: 'Full',
    2: 'Simple',
    3: 'Bulletproof',
    4: 'Bulletproof2',
    5: 'CLSAG',
    6: 'BulletproofPlus',
    7: 'FullProofs',
    8: 'SalviumZero',
    9: 'SalviumOne'
  };
  return names[rctType] || `UNKNOWN(${rctType})`;
}

/**
 * Analyze transaction for debugging purposes
 *
 * @param {Object} tx - Parsed transaction
 * @returns {Object} Detailed analysis
 */
export function analyzeTransaction(tx) {
  const prefix = tx.prefix;
  const summary = summarizeTransaction(tx);

  return {
    ...summary,
    txTypeName: getTransactionTypeName(prefix.txType),
    rctTypeName: tx.rct ? getRctTypeName(tx.rct.type) : null,
    hasAmountBurnt: prefix.amount_burnt > 0n,
    hasReturnAddress: !!prefix.return_address,
    hasProtocolTxData: !!prefix.protocol_tx_data,
    sourceAsset: prefix.source_asset_type || 'SAL',
    destinationAsset: prefix.destination_asset_type || 'SAL',
    slippageLimit: prefix.amount_slippage_limit,
    inputs: prefix.vin.map((v, i) => ({
      index: i,
      type: v.type === TXIN_TYPE.GEN ? 'coinbase' : 'key',
      height: v.height,
      amount: v.amount,
      assetType: v.assetType,
      ringSize: v.keyOffsets?.length || 0
    })),
    outputs: prefix.vout.map((v, i) => ({
      index: i,
      type: v.type,
      amount: v.amount,
      assetType: v.assetType,
      unlockTime: v.unlockTime,
      hasViewTag: v.viewTag !== undefined
    }))
  };
}
