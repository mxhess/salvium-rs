/**
 * Transaction and Output Query Filters
 *
 * Provides flexible filtering for transactions and outputs,
 * similar to monero-ts but adapted for Salvium's transaction types.
 *
 * @module query
 */

import { TX_TYPE } from './wallet.js';

// ============================================================================
// OUTPUT QUERY
// ============================================================================

/**
 * Query filter for wallet outputs (UTXOs)
 */
export class OutputQuery {
  constructor(config = {}) {
    // Amount filters
    this.minAmount = config.minAmount ?? null;
    this.maxAmount = config.maxAmount ?? null;
    this.amount = config.amount ?? null;  // Exact match

    // Status filters
    this.isSpent = config.isSpent ?? null;
    this.isLocked = config.isLocked ?? null;
    this.isFrozen = config.isFrozen ?? null;

    // Location filters
    this.accountIndex = config.accountIndex ?? null;
    this.subaddressIndex = config.subaddressIndex ?? null;
    this.subaddressIndices = config.subaddressIndices ?? null;  // Array of { major, minor }

    // Block filters
    this.minHeight = config.minHeight ?? null;
    this.maxHeight = config.maxHeight ?? null;

    // Key image filter
    this.keyImage = config.keyImage ?? null;
    this.keyImages = config.keyImages ?? null;  // Array

    // Asset type filter (Salvium-specific)
    this.assetType = config.assetType ?? null;

    // Transaction type filter (Salvium-specific)
    this.txType = config.txType ?? null;
    this.txTypes = config.txTypes ?? null;  // Array of TX_TYPE values

    // Transaction hash filter
    this.txHash = config.txHash ?? null;
    this.txHashes = config.txHashes ?? null;  // Array
  }

  /**
   * Test if an output matches this query
   * @param {Object} output - Output to test
   * @param {number} currentHeight - Current blockchain height (for lock status)
   * @param {number} unlockBlocks - Blocks required for unlock (default: 10)
   * @returns {boolean}
   */
  matches(output, currentHeight = 0, unlockBlocks = 10) {
    // Amount filters
    if (this.amount !== null && BigInt(output.amount) !== BigInt(this.amount)) {
      return false;
    }
    if (this.minAmount !== null && BigInt(output.amount) < BigInt(this.minAmount)) {
      return false;
    }
    if (this.maxAmount !== null && BigInt(output.amount) > BigInt(this.maxAmount)) {
      return false;
    }

    // Spent status
    if (this.isSpent !== null && output.isSpent !== this.isSpent) {
      return false;
    }

    // Locked status (computed)
    if (this.isLocked !== null) {
      const isLocked = output.blockHeight &&
        (currentHeight - output.blockHeight) < unlockBlocks;
      if (isLocked !== this.isLocked) {
        return false;
      }
    }

    // Frozen status
    if (this.isFrozen !== null && output.isFrozen !== this.isFrozen) {
      return false;
    }

    // Account filter
    if (this.accountIndex !== null) {
      const major = output.subaddressIndex?.major ?? 0;
      if (major !== this.accountIndex) {
        return false;
      }
    }

    // Subaddress filter
    if (this.subaddressIndex !== null) {
      const minor = output.subaddressIndex?.minor ?? 0;
      if (minor !== this.subaddressIndex) {
        return false;
      }
    }

    // Multiple subaddress filter
    if (this.subaddressIndices !== null) {
      const major = output.subaddressIndex?.major ?? 0;
      const minor = output.subaddressIndex?.minor ?? 0;
      const found = this.subaddressIndices.some(
        idx => idx.major === major && idx.minor === minor
      );
      if (!found) return false;
    }

    // Block height filters
    if (this.minHeight !== null && output.blockHeight < this.minHeight) {
      return false;
    }
    if (this.maxHeight !== null && output.blockHeight > this.maxHeight) {
      return false;
    }

    // Key image filter
    if (this.keyImage !== null) {
      const kiHex = typeof output.keyImage === 'string'
        ? output.keyImage
        : (output.keyImage ? Array.from(output.keyImage).map(b => b.toString(16).padStart(2, '0')).join('') : null);
      if (kiHex !== this.keyImage) {
        return false;
      }
    }

    // Multiple key images filter
    if (this.keyImages !== null) {
      const kiHex = typeof output.keyImage === 'string'
        ? output.keyImage
        : (output.keyImage ? Array.from(output.keyImage).map(b => b.toString(16).padStart(2, '0')).join('') : null);
      if (!kiHex || !this.keyImages.includes(kiHex)) {
        return false;
      }
    }

    // Asset type filter (Salvium)
    if (this.assetType !== null && output.assetType !== this.assetType) {
      return false;
    }

    // Transaction type filter (Salvium)
    if (this.txType !== null && output.txType !== this.txType) {
      return false;
    }
    if (this.txTypes !== null && !this.txTypes.includes(output.txType)) {
      return false;
    }

    // Transaction hash filter
    if (this.txHash !== null && output.txHash !== this.txHash) {
      return false;
    }
    if (this.txHashes !== null && !this.txHashes.includes(output.txHash)) {
      return false;
    }

    return true;
  }

  /**
   * Filter an array of outputs
   * @param {Array<Object>} outputs - Outputs to filter
   * @param {number} currentHeight - Current blockchain height
   * @returns {Array<Object>} Matching outputs
   */
  filter(outputs, currentHeight = 0) {
    return outputs.filter(o => this.matches(o, currentHeight));
  }

  /**
   * Create a copy with additional filters
   * @param {Object} config - Additional filters
   * @returns {OutputQuery}
   */
  with(config) {
    return new OutputQuery({ ...this, ...config });
  }
}

// ============================================================================
// TRANSACTION QUERY
// ============================================================================

/**
 * Query filter for wallet transactions
 */
export class TxQuery {
  constructor(config = {}) {
    // Direction filters
    this.isIncoming = config.isIncoming ?? null;
    this.isOutgoing = config.isOutgoing ?? null;

    // Status filters
    this.isConfirmed = config.isConfirmed ?? null;
    this.inTxPool = config.inTxPool ?? null;
    this.isFailed = config.isFailed ?? null;
    this.isLocked = config.isLocked ?? null;

    // Hash filters
    this.hash = config.hash ?? null;
    this.hashes = config.hashes ?? null;  // Array

    // Block filters
    this.minHeight = config.minHeight ?? null;
    this.maxHeight = config.maxHeight ?? null;
    this.height = config.height ?? null;  // Exact match

    // Amount filters
    this.minAmount = config.minAmount ?? null;
    this.maxAmount = config.maxAmount ?? null;

    // Account filters
    this.accountIndex = config.accountIndex ?? null;
    this.subaddressIndex = config.subaddressIndex ?? null;
    this.subaddressIndices = config.subaddressIndices ?? null;

    // Payment ID filter
    this.hasPaymentId = config.hasPaymentId ?? null;
    this.paymentId = config.paymentId ?? null;
    this.paymentIds = config.paymentIds ?? null;

    // Transaction type filter (Salvium-specific)
    this.txType = config.txType ?? null;
    this.txTypes = config.txTypes ?? null;

    // Asset type filter (Salvium-specific)
    this.assetType = config.assetType ?? null;

    // Include outputs in result
    this.includeOutputs = config.includeOutputs ?? false;
  }

  /**
   * Test if a transaction matches this query
   * @param {Object} tx - Transaction to test
   * @param {number} currentHeight - Current blockchain height
   * @returns {boolean}
   */
  matches(tx, currentHeight = 0) {
    // Direction filters
    if (this.isIncoming !== null && tx.isIncoming !== this.isIncoming) {
      return false;
    }
    if (this.isOutgoing !== null && tx.isOutgoing !== this.isOutgoing) {
      return false;
    }

    // Confirmed status
    if (this.isConfirmed !== null) {
      const isConfirmed = tx.blockHeight !== null && tx.blockHeight !== undefined;
      if (isConfirmed !== this.isConfirmed) {
        return false;
      }
    }

    // In mempool
    if (this.inTxPool !== null && tx.inTxPool !== this.inTxPool) {
      return false;
    }

    // Failed status
    if (this.isFailed !== null && tx.isFailed !== this.isFailed) {
      return false;
    }

    // Locked status
    if (this.isLocked !== null) {
      const unlockBlocks = 10;
      const isLocked = tx.blockHeight &&
        (currentHeight - tx.blockHeight) < unlockBlocks;
      if (isLocked !== this.isLocked) {
        return false;
      }
    }

    // Hash filters
    if (this.hash !== null && tx.hash !== this.hash && tx.txHash !== this.hash) {
      return false;
    }
    if (this.hashes !== null) {
      const txHash = tx.hash || tx.txHash;
      if (!this.hashes.includes(txHash)) {
        return false;
      }
    }

    // Height filters
    if (this.height !== null && tx.blockHeight !== this.height) {
      return false;
    }
    if (this.minHeight !== null && (tx.blockHeight === null || tx.blockHeight < this.minHeight)) {
      return false;
    }
    if (this.maxHeight !== null && (tx.blockHeight === null || tx.blockHeight > this.maxHeight)) {
      return false;
    }

    // Amount filters (total amount)
    const amount = tx.amount ?? tx.totalAmount ?? 0n;
    if (this.minAmount !== null && BigInt(amount) < BigInt(this.minAmount)) {
      return false;
    }
    if (this.maxAmount !== null && BigInt(amount) > BigInt(this.maxAmount)) {
      return false;
    }

    // Account filter
    if (this.accountIndex !== null) {
      // Check if any transfer involves this account
      const hasAccount = (tx.transfers || []).some(t =>
        t.accountIndex === this.accountIndex
      ) || (tx.outputs || []).some(o =>
        o.subaddressIndex?.major === this.accountIndex
      );
      if (!hasAccount) return false;
    }

    // Payment ID filters
    if (this.hasPaymentId !== null) {
      const hasId = tx.paymentId !== null && tx.paymentId !== undefined;
      if (hasId !== this.hasPaymentId) {
        return false;
      }
    }
    if (this.paymentId !== null && tx.paymentId !== this.paymentId) {
      return false;
    }
    if (this.paymentIds !== null && !this.paymentIds.includes(tx.paymentId)) {
      return false;
    }

    // Transaction type filter (Salvium)
    if (this.txType !== null && tx.txType !== this.txType) {
      return false;
    }
    if (this.txTypes !== null && !this.txTypes.includes(tx.txType)) {
      return false;
    }

    // Asset type filter (Salvium)
    if (this.assetType !== null) {
      const hasAsset = (tx.assetType === this.assetType) ||
        (tx.outputs || []).some(o => o.assetType === this.assetType);
      if (!hasAsset) return false;
    }

    return true;
  }

  /**
   * Filter an array of transactions
   * @param {Array<Object>} txs - Transactions to filter
   * @param {number} currentHeight - Current blockchain height
   * @returns {Array<Object>} Matching transactions
   */
  filter(txs, currentHeight = 0) {
    return txs.filter(tx => this.matches(tx, currentHeight));
  }

  /**
   * Create a copy with additional filters
   * @param {Object} config - Additional filters
   * @returns {TxQuery}
   */
  with(config) {
    return new TxQuery({ ...this, ...config });
  }
}

// ============================================================================
// TRANSFER QUERY
// ============================================================================

/**
 * Query filter for transfers (individual movements of funds)
 */
export class TransferQuery {
  constructor(config = {}) {
    // Direction
    this.isIncoming = config.isIncoming ?? null;
    this.isOutgoing = config.isOutgoing ?? null;

    // Amount filters
    this.minAmount = config.minAmount ?? null;
    this.maxAmount = config.maxAmount ?? null;
    this.amount = config.amount ?? null;

    // Address filters
    this.address = config.address ?? null;
    this.addresses = config.addresses ?? null;

    // Account filters
    this.accountIndex = config.accountIndex ?? null;
    this.subaddressIndex = config.subaddressIndex ?? null;
    this.subaddressIndices = config.subaddressIndices ?? null;

    // Asset type (Salvium)
    this.assetType = config.assetType ?? null;

    // Transaction type (Salvium)
    this.txType = config.txType ?? null;
    this.txTypes = config.txTypes ?? null;
  }

  /**
   * Test if a transfer matches this query
   * @param {Object} transfer - Transfer to test
   * @returns {boolean}
   */
  matches(transfer) {
    // Direction
    if (this.isIncoming !== null && transfer.isIncoming !== this.isIncoming) {
      return false;
    }
    if (this.isOutgoing !== null && transfer.isOutgoing !== this.isOutgoing) {
      return false;
    }

    // Amount filters
    if (this.amount !== null && BigInt(transfer.amount) !== BigInt(this.amount)) {
      return false;
    }
    if (this.minAmount !== null && BigInt(transfer.amount) < BigInt(this.minAmount)) {
      return false;
    }
    if (this.maxAmount !== null && BigInt(transfer.amount) > BigInt(this.maxAmount)) {
      return false;
    }

    // Address filters
    if (this.address !== null && transfer.address !== this.address) {
      return false;
    }
    if (this.addresses !== null && !this.addresses.includes(transfer.address)) {
      return false;
    }

    // Account filter
    if (this.accountIndex !== null && transfer.accountIndex !== this.accountIndex) {
      return false;
    }

    // Subaddress filter
    if (this.subaddressIndex !== null && transfer.subaddressIndex !== this.subaddressIndex) {
      return false;
    }

    // Asset type (Salvium)
    if (this.assetType !== null && transfer.assetType !== this.assetType) {
      return false;
    }

    // Transaction type (Salvium)
    if (this.txType !== null && transfer.txType !== this.txType) {
      return false;
    }
    if (this.txTypes !== null && !this.txTypes.includes(transfer.txType)) {
      return false;
    }

    return true;
  }

  /**
   * Filter an array of transfers
   * @param {Array<Object>} transfers - Transfers to filter
   * @returns {Array<Object>} Matching transfers
   */
  filter(transfers) {
    return transfers.filter(t => this.matches(t));
  }
}

// ============================================================================
// CONVENIENCE CONSTRUCTORS
// ============================================================================

/**
 * Create an OutputQuery with given config
 * @param {Object} config - Query config
 * @returns {OutputQuery}
 */
export function createOutputQuery(config = {}) {
  return new OutputQuery(config);
}

/**
 * Create a TxQuery with given config
 * @param {Object} config - Query config
 * @returns {TxQuery}
 */
export function createTxQuery(config = {}) {
  return new TxQuery(config);
}

/**
 * Create a TransferQuery with given config
 * @param {Object} config - Query config
 * @returns {TransferQuery}
 */
export function createTransferQuery(config = {}) {
  return new TransferQuery(config);
}

/**
 * Create an output query for unspent outputs
 * @param {Object} config - Additional config
 * @returns {OutputQuery}
 */
export function unspentOutputs(config = {}) {
  return new OutputQuery({ ...config, isSpent: false });
}

/**
 * Create an output query for spent outputs
 * @param {Object} config - Additional config
 * @returns {OutputQuery}
 */
export function spentOutputs(config = {}) {
  return new OutputQuery({ ...config, isSpent: true });
}

/**
 * Create an output query for locked outputs
 * @param {Object} config - Additional config
 * @returns {OutputQuery}
 */
export function lockedOutputs(config = {}) {
  return new OutputQuery({ ...config, isLocked: true, isSpent: false });
}

/**
 * Create an output query for unlocked outputs
 * @param {Object} config - Additional config
 * @returns {OutputQuery}
 */
export function unlockedOutputs(config = {}) {
  return new OutputQuery({ ...config, isLocked: false, isSpent: false });
}

/**
 * Create an output query for staking outputs (Salvium)
 * @param {Object} config - Additional config
 * @returns {OutputQuery}
 */
export function stakingOutputs(config = {}) {
  return new OutputQuery({
    ...config,
    txType: TX_TYPE.STAKE,
    isSpent: false
  });
}

/**
 * Create an output query for yield payouts (Salvium)
 * @param {Object} config - Additional config
 * @returns {OutputQuery}
 */
export function yieldOutputs(config = {}) {
  return new OutputQuery({
    ...config,
    txType: TX_TYPE.PROTOCOL,
    isSpent: false
  });
}

/**
 * Create a transaction query for incoming transactions
 * @param {Object} config - Additional config
 * @returns {TxQuery}
 */
export function incomingTxs(config = {}) {
  return new TxQuery({ ...config, isIncoming: true });
}

/**
 * Create a transaction query for outgoing transactions
 * @param {Object} config - Additional config
 * @returns {TxQuery}
 */
export function outgoingTxs(config = {}) {
  return new TxQuery({ ...config, isOutgoing: true });
}

/**
 * Create a transaction query for pending (unconfirmed) transactions
 * @param {Object} config - Additional config
 * @returns {TxQuery}
 */
export function pendingTxs(config = {}) {
  return new TxQuery({ ...config, isConfirmed: false, inTxPool: true });
}

/**
 * Create a transaction query for confirmed transactions
 * @param {Object} config - Additional config
 * @returns {TxQuery}
 */
export function confirmedTxs(config = {}) {
  return new TxQuery({ ...config, isConfirmed: true });
}

/**
 * Create a transaction query for staking transactions (Salvium)
 * @param {Object} config - Additional config
 * @returns {TxQuery}
 */
export function stakingTxs(config = {}) {
  return new TxQuery({ ...config, txType: TX_TYPE.STAKE });
}

/**
 * Create a transaction query for yield/protocol transactions (Salvium)
 * @param {Object} config - Additional config
 * @returns {TxQuery}
 */
export function yieldTxs(config = {}) {
  return new TxQuery({ ...config, txType: TX_TYPE.PROTOCOL });
}

export default {
  OutputQuery,
  TxQuery,
  TransferQuery,
  createOutputQuery,
  createTxQuery,
  createTransferQuery,
  unspentOutputs,
  spentOutputs,
  lockedOutputs,
  unlockedOutputs,
  stakingOutputs,
  yieldOutputs,
  incomingTxs,
  outgoingTxs,
  pendingTxs,
  confirmedTxs,
  stakingTxs,
  yieldTxs
};
