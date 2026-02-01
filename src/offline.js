/**
 * Offline Transaction Signing
 *
 * Provides a workflow for cold wallet / air-gapped transaction signing:
 * 1. Online (view-only) wallet creates unsigned transaction
 * 2. Export unsigned transaction to portable format
 * 3. Offline (full) wallet imports and signs
 * 4. Export signed transaction
 * 5. Online wallet imports and broadcasts
 *
 * @module offline
 */

import { bytesToHex, hexToBytes } from './address.js';
import { keccak256 } from './crypto/index.js';
import {
  signTransaction,
  serializeTransaction,
  validateTransaction
} from './transaction.js';

// ============================================================================
// UNSIGNED TRANSACTION FORMAT
// ============================================================================

/**
 * Version for unsigned transaction format
 */
export const UNSIGNED_TX_VERSION = 1;

/**
 * Create an unsigned transaction structure
 * @param {Object} txData - Transaction data
 * @returns {Object} Unsigned transaction
 */
export function createUnsignedTx(txData) {
  return {
    version: UNSIGNED_TX_VERSION,
    created: Date.now(),
    tx: {
      version: txData.version || 2,
      unlockTime: txData.unlockTime || 0n,
      inputs: txData.inputs.map(input => ({
        // Include all data needed for signing
        amount: input.amount.toString(),
        keyImage: null,  // Will be computed during signing
        outputIndex: input.outputIndex,
        txHash: input.txHash,
        publicKey: bytesToHex(input.publicKey),
        // Ring member data
        ring: input.ring.map(member => ({
          publicKey: bytesToHex(member.publicKey),
          commitment: member.commitment ? bytesToHex(member.commitment) : null,
          globalIndex: member.globalIndex.toString()
        })),
        realOutputIndex: input.realOutputIndex,
        // Commitment data
        commitment: input.commitment ? bytesToHex(input.commitment) : null,
        mask: input.mask ? bytesToHex(input.mask) : null
      })),
      outputs: txData.outputs.map(output => ({
        amount: output.amount.toString(),
        publicKey: bytesToHex(output.publicKey),
        viewTag: output.viewTag,
        // CARROT encrypted data
        encryptedAmount: output.encryptedAmount ? bytesToHex(output.encryptedAmount) : null,
        commitment: output.commitment ? bytesToHex(output.commitment) : null,
        // Destination info (for verification)
        destinationAddress: output.destinationAddress || null
      })),
      extra: txData.extra ? bytesToHex(txData.extra) : '',
      fee: txData.fee.toString(),
      // Additional metadata for signing
      txSecretKey: txData.txSecretKey ? bytesToHex(txData.txSecretKey) : null,
      changeIndex: txData.changeIndex ?? null
    },
    // Metadata
    metadata: {
      networkType: txData.networkType || 'mainnet',
      description: txData.description || '',
      priority: txData.priority || 'default'
    }
  };
}

/**
 * Parse an unsigned transaction from JSON
 * @param {Object|string} data - Unsigned transaction data
 * @returns {Object} Parsed unsigned transaction
 */
export function parseUnsignedTx(data) {
  const parsed = typeof data === 'string' ? JSON.parse(data) : data;

  if (parsed.version !== UNSIGNED_TX_VERSION) {
    throw new Error(`Unsupported unsigned tx version: ${parsed.version}`);
  }

  return {
    version: parsed.version,
    created: parsed.created,
    tx: {
      version: parsed.tx.version,
      unlockTime: BigInt(parsed.tx.unlockTime),
      inputs: parsed.tx.inputs.map(input => ({
        amount: BigInt(input.amount),
        keyImage: null,
        outputIndex: input.outputIndex,
        txHash: input.txHash,
        publicKey: hexToBytes(input.publicKey),
        ring: input.ring.map(member => ({
          publicKey: hexToBytes(member.publicKey),
          commitment: member.commitment ? hexToBytes(member.commitment) : null,
          globalIndex: BigInt(member.globalIndex)
        })),
        realOutputIndex: input.realOutputIndex,
        commitment: input.commitment ? hexToBytes(input.commitment) : null,
        mask: input.mask ? hexToBytes(input.mask) : null
      })),
      outputs: parsed.tx.outputs.map(output => ({
        amount: BigInt(output.amount),
        publicKey: hexToBytes(output.publicKey),
        viewTag: output.viewTag,
        encryptedAmount: output.encryptedAmount ? hexToBytes(output.encryptedAmount) : null,
        commitment: output.commitment ? hexToBytes(output.commitment) : null,
        destinationAddress: output.destinationAddress
      })),
      extra: parsed.tx.extra ? hexToBytes(parsed.tx.extra) : new Uint8Array(0),
      fee: BigInt(parsed.tx.fee),
      txSecretKey: parsed.tx.txSecretKey ? hexToBytes(parsed.tx.txSecretKey) : null,
      changeIndex: parsed.tx.changeIndex
    },
    metadata: parsed.metadata
  };
}

// ============================================================================
// SIGNED TRANSACTION FORMAT
// ============================================================================

/**
 * Version for signed transaction format
 */
export const SIGNED_TX_VERSION = 1;

/**
 * Create a signed transaction structure
 * @param {Object} signedTx - Signed transaction
 * @param {Object} metadata - Transaction metadata
 * @returns {Object} Signed transaction export
 */
export function createSignedTx(signedTx, metadata = {}) {
  const serialized = serializeTransaction(signedTx);
  const txHash = bytesToHex(keccak256(serialized));

  return {
    version: SIGNED_TX_VERSION,
    created: Date.now(),
    txHash,
    txBlob: bytesToHex(serialized),
    // Include original metadata
    metadata: {
      ...metadata,
      fee: signedTx.fee?.toString() || '0',
      inputCount: signedTx.inputs?.length || 0,
      outputCount: signedTx.outputs?.length || 0
    }
  };
}

/**
 * Parse a signed transaction from JSON
 * @param {Object|string} data - Signed transaction data
 * @returns {Object} Parsed signed transaction
 */
export function parseSignedTx(data) {
  const parsed = typeof data === 'string' ? JSON.parse(data) : data;

  if (parsed.version !== SIGNED_TX_VERSION) {
    throw new Error(`Unsupported signed tx version: ${parsed.version}`);
  }

  return {
    version: parsed.version,
    created: parsed.created,
    txHash: parsed.txHash,
    txBlob: hexToBytes(parsed.txBlob),
    metadata: parsed.metadata
  };
}

// ============================================================================
// OFFLINE SIGNING WORKFLOW
// ============================================================================

/**
 * Export an unsigned transaction for offline signing
 * @param {Object} txData - Transaction data from wallet
 * @param {Object} options - Export options
 * @returns {string} JSON string for transfer to offline device
 */
export function exportUnsignedTx(txData, options = {}) {
  const unsigned = createUnsignedTx(txData);

  if (options.compact) {
    return JSON.stringify(unsigned);
  }
  return JSON.stringify(unsigned, null, 2);
}

/**
 * Import an unsigned transaction on the offline device
 * @param {string} exportedTx - JSON string from online wallet
 * @returns {Object} Unsigned transaction ready for signing
 */
export function importUnsignedTx(exportedTx) {
  return parseUnsignedTx(exportedTx);
}

/**
 * Sign an imported unsigned transaction
 * @param {Object} unsignedTx - Imported unsigned transaction
 * @param {Uint8Array} spendSecretKey - Spend secret key
 * @param {Object} options - Signing options
 * @returns {Object} Signed transaction export
 */
export function signOffline(unsignedTx, spendSecretKey, options = {}) {
  // Validate the unsigned transaction
  if (!unsignedTx.tx) {
    throw new Error('Invalid unsigned transaction: missing tx data');
  }

  // Sign the transaction
  const signedTx = signTransaction(unsignedTx.tx, spendSecretKey);

  // Validate the signed transaction
  const validation = validateTransaction(signedTx);
  if (!validation.valid && !options.skipValidation) {
    throw new Error(`Transaction validation failed: ${validation.errors.join(', ')}`);
  }

  // Create export format
  return createSignedTx(signedTx, unsignedTx.metadata);
}

/**
 * Export a signed transaction for broadcast
 * @param {Object} signedTx - Signed transaction from signOffline
 * @param {Object} options - Export options
 * @returns {string} JSON string for transfer to online device
 */
export function exportSignedTx(signedTx, options = {}) {
  if (options.compact) {
    return JSON.stringify(signedTx);
  }
  return JSON.stringify(signedTx, null, 2);
}

/**
 * Import a signed transaction on the online device
 * @param {string} exportedTx - JSON string from offline device
 * @returns {Object} Signed transaction ready for broadcast
 */
export function importSignedTx(exportedTx) {
  return parseSignedTx(exportedTx);
}

/**
 * Get transaction blob for broadcast
 * @param {Object} signedTx - Imported signed transaction
 * @returns {string} Hex-encoded transaction blob
 */
export function getTxBlobHex(signedTx) {
  if (typeof signedTx.txBlob === 'string') {
    return signedTx.txBlob;
  }
  return bytesToHex(signedTx.txBlob);
}

// ============================================================================
// KEY IMAGE EXPORT/IMPORT
// ============================================================================

/**
 * Export key images for a view-only wallet to detect spent outputs
 * @param {Array<Object>} outputs - Outputs with key images
 * @returns {Object} Key image export data
 */
export function exportKeyImages(outputs) {
  return {
    version: 1,
    created: Date.now(),
    keyImages: outputs.map(output => ({
      keyImage: bytesToHex(output.keyImage),
      txHash: output.txHash,
      outputIndex: output.outputIndex,
      amount: output.amount.toString()
    }))
  };
}

/**
 * Import key images into a view-only wallet
 * @param {Object|string} data - Key image export data
 * @returns {Array<Object>} Key image records
 */
export function importKeyImages(data) {
  const parsed = typeof data === 'string' ? JSON.parse(data) : data;

  return parsed.keyImages.map(ki => ({
    keyImage: hexToBytes(ki.keyImage),
    txHash: ki.txHash,
    outputIndex: ki.outputIndex,
    amount: BigInt(ki.amount)
  }));
}

// ============================================================================
// OUTPUTS EXPORT/IMPORT
// ============================================================================

/**
 * Export outputs from full wallet for view-only wallet
 * @param {Array<Object>} outputs - Wallet outputs
 * @returns {Object} Outputs export data
 */
export function exportOutputs(outputs) {
  return {
    version: 1,
    created: Date.now(),
    outputs: outputs.map(output => ({
      txHash: output.txHash,
      outputIndex: output.outputIndex,
      globalIndex: output.globalIndex?.toString(),
      amount: output.amount.toString(),
      publicKey: bytesToHex(output.publicKey),
      keyImage: output.keyImage ? bytesToHex(output.keyImage) : null,
      commitment: output.commitment ? bytesToHex(output.commitment) : null,
      mask: output.mask ? bytesToHex(output.mask) : null,
      blockHeight: output.blockHeight,
      assetType: output.assetType || 'SAL',
      subaddressIndex: output.subaddressIndex
    }))
  };
}

/**
 * Import outputs into a wallet
 * @param {Object|string} data - Outputs export data
 * @returns {Array<Object>} Output records
 */
export function importOutputs(data) {
  const parsed = typeof data === 'string' ? JSON.parse(data) : data;

  return parsed.outputs.map(output => ({
    txHash: output.txHash,
    outputIndex: output.outputIndex,
    globalIndex: output.globalIndex ? BigInt(output.globalIndex) : null,
    amount: BigInt(output.amount),
    publicKey: hexToBytes(output.publicKey),
    keyImage: output.keyImage ? hexToBytes(output.keyImage) : null,
    commitment: output.commitment ? hexToBytes(output.commitment) : null,
    mask: output.mask ? hexToBytes(output.mask) : null,
    blockHeight: output.blockHeight,
    assetType: output.assetType,
    subaddressIndex: output.subaddressIndex
  }));
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Verify unsigned transaction integrity
 * @param {Object} unsignedTx - Unsigned transaction
 * @returns {Object} { valid: boolean, errors: string[] }
 */
export function verifyUnsignedTx(unsignedTx) {
  const errors = [];

  if (!unsignedTx.tx) {
    errors.push('Missing transaction data');
    return { valid: false, errors };
  }

  const tx = unsignedTx.tx;

  // Check inputs
  if (!tx.inputs || tx.inputs.length === 0) {
    errors.push('Transaction has no inputs');
  } else {
    for (let i = 0; i < tx.inputs.length; i++) {
      const input = tx.inputs[i];
      if (!input.ring || input.ring.length === 0) {
        errors.push(`Input ${i} has no ring members`);
      }
      if (input.realOutputIndex === undefined) {
        errors.push(`Input ${i} missing real output index`);
      }
    }
  }

  // Check outputs
  if (!tx.outputs || tx.outputs.length === 0) {
    errors.push('Transaction has no outputs');
  }

  // Check fee
  if (tx.fee === undefined || tx.fee <= 0n) {
    errors.push('Invalid fee');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Get summary of unsigned transaction
 * @param {Object} unsignedTx - Unsigned transaction
 * @returns {Object} Transaction summary
 */
export function summarizeUnsignedTx(unsignedTx) {
  const tx = unsignedTx.tx;
  const totalIn = tx.inputs.reduce((sum, i) => sum + i.amount, 0n);
  const totalOut = tx.outputs.reduce((sum, o) => sum + o.amount, 0n);

  return {
    inputCount: tx.inputs.length,
    outputCount: tx.outputs.length,
    totalIn,
    totalOut,
    fee: tx.fee,
    ringSize: tx.inputs[0]?.ring?.length || 0,
    created: new Date(unsignedTx.created).toISOString(),
    network: unsignedTx.metadata?.networkType || 'unknown',
    description: unsignedTx.metadata?.description || ''
  };
}

export default {
  // Unsigned tx
  UNSIGNED_TX_VERSION,
  createUnsignedTx,
  parseUnsignedTx,
  exportUnsignedTx,
  importUnsignedTx,
  verifyUnsignedTx,
  summarizeUnsignedTx,
  // Signed tx
  SIGNED_TX_VERSION,
  createSignedTx,
  parseSignedTx,
  exportSignedTx,
  importSignedTx,
  getTxBlobHex,
  // Signing
  signOffline,
  // Key images
  exportKeyImages,
  importKeyImages,
  // Outputs
  exportOutputs,
  importOutputs
};
