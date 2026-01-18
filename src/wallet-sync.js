/**
 * Wallet Sync Engine
 *
 * Synchronizes wallet with blockchain via daemon RPC:
 * - Fetches blocks in batches
 * - Scans transactions for owned outputs
 * - Tracks spent outputs via key images
 * - Emits progress events
 *
 * @module wallet-sync
 */

import { WalletOutput, WalletTransaction } from './wallet-store.js';
import { scanTransaction } from './scanning.js';
import { generateKeyImage } from './keyimage.js';
import { parseTransaction, extractTxPubKey, extractPaymentId } from './transaction.js';
import { bytesToHex, hexToBytes } from './address.js';
import { TX_TYPE } from './wallet.js';

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Default number of blocks to fetch per batch
 */
export const DEFAULT_BATCH_SIZE = 100;

/**
 * Default confirmations required for unlock
 */
export const SYNC_UNLOCK_BLOCKS = 10;

/**
 * Sync status
 */
export const SYNC_STATUS = {
  IDLE: 'idle',
  SYNCING: 'syncing',
  COMPLETE: 'complete',
  ERROR: 'error'
};

// ============================================================================
// SYNC ENGINE
// ============================================================================

/**
 * Wallet synchronization engine
 */
export class WalletSync {
  /**
   * Create sync engine
   * @param {Object} options - Configuration
   * @param {Object} options.storage - WalletStorage instance
   * @param {Object} options.daemon - DaemonRPC instance
   * @param {Object} options.keys - Wallet keys { viewSecretKey, spendSecretKey, spendPublicKey }
   * @param {Object} options.subaddresses - Map of subaddress public keys to indices
   * @param {number} options.batchSize - Blocks per batch (default: 100)
   */
  constructor(options = {}) {
    this.storage = options.storage;
    this.daemon = options.daemon;
    this.keys = options.keys;
    this.subaddresses = options.subaddresses || new Map();
    this.batchSize = options.batchSize || DEFAULT_BATCH_SIZE;

    // State
    this.status = SYNC_STATUS.IDLE;
    this.currentHeight = 0;
    this.targetHeight = 0;
    this.startHeight = 0;
    this.error = null;

    // Control
    this._stopRequested = false;
    this._listeners = [];
  }

  // ===========================================================================
  // EVENT SYSTEM
  // ===========================================================================

  /**
   * Add event listener
   * @param {string} event - Event name
   * @param {Function} callback - Callback function
   */
  on(event, callback) {
    this._listeners.push({ event, callback });
  }

  /**
   * Remove event listener
   * @param {string} event - Event name
   * @param {Function} callback - Callback function
   */
  off(event, callback) {
    this._listeners = this._listeners.filter(
      l => l.event !== event || l.callback !== callback
    );
  }

  /**
   * Emit event
   * @private
   */
  _emit(event, ...args) {
    for (const listener of this._listeners) {
      if (listener.event === event) {
        try {
          listener.callback(...args);
        } catch (e) {
          console.error(`Sync listener error:`, e);
        }
      }
    }
  }

  // ===========================================================================
  // SYNC CONTROL
  // ===========================================================================

  /**
   * Start synchronization
   * @param {number} startHeight - Start height (default: stored sync height)
   * @returns {Promise<void>}
   */
  async start(startHeight = null) {
    if (this.status === SYNC_STATUS.SYNCING) {
      throw new Error('Already syncing');
    }

    this._stopRequested = false;
    this.status = SYNC_STATUS.SYNCING;
    this.error = null;

    try {
      // Get start height
      if (startHeight !== null) {
        this.startHeight = startHeight;
      } else {
        this.startHeight = await this.storage.getSyncHeight();
      }
      this.currentHeight = this.startHeight;

      // Get target height from daemon
      const infoResponse = await this.daemon.getInfo();
      if (!infoResponse.success) {
        throw new Error('Failed to get daemon info');
      }
      this.targetHeight = infoResponse.result.height;

      this._emit('syncStart', {
        startHeight: this.startHeight,
        targetHeight: this.targetHeight
      });

      // Sync loop
      while (this.currentHeight < this.targetHeight && !this._stopRequested) {
        await this._syncBatch();

        // Update target height periodically
        if (this.currentHeight >= this.targetHeight) {
          const info = await this.daemon.getInfo();
          if (info.success) {
            this.targetHeight = info.result.height;
          }
        }
      }

      if (this._stopRequested) {
        this.status = SYNC_STATUS.IDLE;
        this._emit('syncStopped', { height: this.currentHeight });
      } else {
        this.status = SYNC_STATUS.COMPLETE;
        this._emit('syncComplete', { height: this.currentHeight });
      }
    } catch (error) {
      this.status = SYNC_STATUS.ERROR;
      this.error = error;
      this._emit('syncError', error);
      throw error;
    }
  }

  /**
   * Stop synchronization
   */
  stop() {
    this._stopRequested = true;
  }

  /**
   * Get sync progress
   * @returns {Object} Progress info
   */
  getProgress() {
    const total = this.targetHeight - this.startHeight;
    const done = this.currentHeight - this.startHeight;
    const percent = total > 0 ? (done / total) * 100 : 0;

    return {
      status: this.status,
      currentHeight: this.currentHeight,
      targetHeight: this.targetHeight,
      startHeight: this.startHeight,
      blocksProcessed: done,
      blocksRemaining: this.targetHeight - this.currentHeight,
      percentComplete: Math.min(100, percent)
    };
  }

  // ===========================================================================
  // BATCH PROCESSING
  // ===========================================================================

  /**
   * Sync a batch of blocks
   * @private
   */
  async _syncBatch() {
    const endHeight = Math.min(
      this.currentHeight + this.batchSize,
      this.targetHeight
    );

    // Fetch block headers for the range
    const headersResponse = await this.daemon.getBlockHeadersRange(
      this.currentHeight,
      endHeight - 1
    );

    if (!headersResponse.success) {
      throw new Error(`Failed to get block headers: ${headersResponse.error?.message}`);
    }

    const headers = headersResponse.result.headers || [];

    // Process each block
    for (const header of headers) {
      if (this._stopRequested) break;

      await this._processBlock(header);
      this.currentHeight = header.height + 1;

      // Emit progress
      this._emit('syncProgress', this.getProgress());
    }

    // Save sync height
    await this.storage.setSyncHeight(this.currentHeight);
  }

  /**
   * Process a single block
   * @private
   * @param {Object} header - Block header
   */
  async _processBlock(header) {
    // Get full block data
    const blockResponse = await this.daemon.getBlock({ height: header.height });
    if (!blockResponse.success) {
      throw new Error(`Failed to get block ${header.height}`);
    }

    const block = blockResponse.result;
    const txHashes = block.tx_hashes || [];

    // Process miner transaction
    if (block.miner_tx_hash) {
      await this._processMinedTx(block, header);
    }

    // Process regular transactions
    if (txHashes.length > 0) {
      const txsResponse = await this.daemon.getTransactions(txHashes, {
        decode_as_json: true
      });

      if (txsResponse.success && txsResponse.result.txs) {
        for (const txData of txsResponse.result.txs) {
          await this._processTransaction(txData, header);
        }
      }
    }

    // Emit new block event
    this._emit('newBlock', {
      height: header.height,
      hash: header.hash,
      timestamp: header.timestamp,
      txCount: txHashes.length
    });
  }

  /**
   * Process miner/coinbase transaction
   * @private
   */
  async _processMinedTx(block, header) {
    // Coinbase outputs don't need scanning for regular wallets
    // They're only relevant if we're the miner
    // Skip for now - can be enabled if needed
  }

  /**
   * Process a single transaction
   * @private
   * @param {Object} txData - Transaction data from RPC
   * @param {Object} header - Block header
   */
  async _processTransaction(txData, header) {
    const txHash = txData.tx_hash;
    const txBlob = txData.as_hex;

    // Check if we already have this transaction
    const existing = await this.storage.getTransaction(txHash);
    if (existing && existing.isConfirmed) {
      return; // Already processed
    }

    try {
      // Parse transaction
      const tx = parseTransaction(hexToBytes(txBlob));
      const txPubKey = extractTxPubKey(tx);
      const paymentId = extractPaymentId(tx);

      // Determine transaction type (Salvium-specific)
      const txType = this._getTxType(tx);

      // Scan outputs for owned ones
      const ownedOutputs = await this._scanOutputs(tx, txHash, txPubKey, header, txType);

      // Check inputs for spent outputs
      const spentOutputs = await this._checkSpentOutputs(tx, txHash, header);

      // Determine if this transaction is relevant to us
      if (ownedOutputs.length === 0 && spentOutputs.length === 0) {
        return; // Not our transaction
      }

      // Calculate amounts
      let incomingAmount = 0n;
      let outgoingAmount = 0n;

      for (const output of ownedOutputs) {
        incomingAmount += output.amount;
      }

      for (const spent of spentOutputs) {
        outgoingAmount += spent.amount;
      }

      // Create transaction record
      const walletTx = new WalletTransaction({
        txHash,
        txPubKey: txPubKey ? bytesToHex(txPubKey) : null,
        blockHeight: header.height,
        blockTimestamp: header.timestamp,
        isConfirmed: true,
        inPool: false,
        isIncoming: incomingAmount > 0n,
        isOutgoing: outgoingAmount > 0n,
        incomingAmount,
        outgoingAmount,
        fee: tx.rctSig?.txnFee ? BigInt(tx.rctSig.txnFee) : 0n,
        paymentId,
        unlockTime: tx.unlockTime || 0n,
        txType,
        transfers: [
          ...ownedOutputs.map(o => ({
            type: 'incoming',
            amount: o.amount.toString(),
            subaddressIndex: o.subaddressIndex
          })),
          ...spentOutputs.map(o => ({
            type: 'outgoing',
            amount: o.amount.toString()
          }))
        ]
      });

      await this.storage.putTransaction(walletTx);

      // Emit events
      if (ownedOutputs.length > 0) {
        this._emit('outputReceived', {
          txHash,
          outputs: ownedOutputs,
          blockHeight: header.height
        });
      }

      if (spentOutputs.length > 0) {
        this._emit('outputSpent', {
          txHash,
          outputs: spentOutputs,
          blockHeight: header.height
        });
      }

    } catch (error) {
      console.error(`Error processing tx ${txHash}:`, error);
      // Don't throw - continue with other transactions
    }
  }

  /**
   * Scan transaction outputs for owned ones
   * @private
   */
  async _scanOutputs(tx, txHash, txPubKey, header, txType) {
    if (!txPubKey || !this.keys.viewSecretKey) {
      return [];
    }

    const ownedOutputs = [];
    const outputs = tx.vout || tx.outputs || [];

    for (let i = 0; i < outputs.length; i++) {
      const output = outputs[i];
      const outputPubKey = this._extractOutputPubKey(output);

      if (!outputPubKey) continue;

      // Try to scan this output
      const scanResult = scanTransaction(
        txPubKey,
        this.keys.viewSecretKey,
        this.keys.spendPublicKey,
        [{ publicKey: outputPubKey, index: i }],
        tx.rctSig?.ecdhInfo?.[i],
        tx.rctSig?.outPk?.[i]
      );

      if (scanResult.ours.length > 0) {
        const ownedOutput = scanResult.ours[0];

        // Generate key image if we have spend key
        let keyImage = null;
        if (this.keys.spendSecretKey) {
          try {
            keyImage = generateKeyImage(
              outputPubKey,
              this.keys.viewSecretKey,
              this.keys.spendSecretKey,
              txPubKey,
              i
            );
          } catch (e) {
            console.error('Failed to generate key image:', e);
          }
        }

        // Check for subaddress match
        let subaddressIndex = { major: 0, minor: 0 };
        if (ownedOutput.subaddressSpendPublicKey) {
          const subPubKeyHex = bytesToHex(ownedOutput.subaddressSpendPublicKey);
          if (this.subaddresses.has(subPubKeyHex)) {
            subaddressIndex = this.subaddresses.get(subPubKeyHex);
          }
        }

        // Create output record
        const walletOutput = new WalletOutput({
          keyImage: keyImage ? bytesToHex(keyImage) : null,
          publicKey: bytesToHex(outputPubKey),
          txHash,
          outputIndex: i,
          globalIndex: null, // Would need separate RPC call
          blockHeight: header.height,
          blockTimestamp: header.timestamp,
          amount: ownedOutput.amount,
          commitment: tx.rctSig?.outPk?.[i] ? bytesToHex(tx.rctSig.outPk[i]) : null,
          mask: ownedOutput.mask ? bytesToHex(ownedOutput.mask) : null,
          subaddressIndex,
          unlockTime: tx.unlockTime || 0n,
          txType
        });

        await this.storage.putOutput(walletOutput);
        ownedOutputs.push(walletOutput);
      }
    }

    return ownedOutputs;
  }

  /**
   * Check if any inputs spend our outputs
   * @private
   */
  async _checkSpentOutputs(tx, txHash, header) {
    const spentOutputs = [];
    const inputs = tx.vin || tx.inputs || [];

    for (const input of inputs) {
      if (!input.key || !input.key.k_image) continue;

      const keyImage = typeof input.key.k_image === 'string'
        ? input.key.k_image
        : bytesToHex(input.key.k_image);

      // Check if this key image belongs to one of our outputs
      const output = await this.storage.getOutput(keyImage);
      if (output && !output.isSpent) {
        await this.storage.markOutputSpent(keyImage, txHash, header.height);
        spentOutputs.push(output);
      }
    }

    return spentOutputs;
  }

  /**
   * Extract output public key from output data
   * @private
   */
  _extractOutputPubKey(output) {
    if (output.target?.key) {
      return typeof output.target.key === 'string'
        ? hexToBytes(output.target.key)
        : output.target.key;
    }
    if (output.target?.tagged_key?.key) {
      return typeof output.target.tagged_key.key === 'string'
        ? hexToBytes(output.target.tagged_key.key)
        : output.target.tagged_key.key;
    }
    if (output.publicKey) {
      return typeof output.publicKey === 'string'
        ? hexToBytes(output.publicKey)
        : output.publicKey;
    }
    return null;
  }

  /**
   * Determine Salvium transaction type
   * @private
   */
  _getTxType(tx) {
    // Check extra field for transaction type marker
    // This is Salvium-specific
    if (tx.extra) {
      // Look for type marker in extra
      // Format depends on Salvium implementation
    }

    // Default to TRANSFER
    return TX_TYPE.TRANSFER;
  }

  // ===========================================================================
  // MEMPOOL SCANNING
  // ===========================================================================

  /**
   * Scan mempool for pending transactions
   * @returns {Promise<Array>} Pending transactions relevant to wallet
   */
  async scanMempool() {
    const poolResponse = await this.daemon.getTransactionPool();
    if (!poolResponse.success) {
      return [];
    }

    const pendingTxs = [];
    const transactions = poolResponse.result.transactions || [];

    for (const txData of transactions) {
      try {
        const tx = parseTransaction(hexToBytes(txData.tx_blob));
        const txPubKey = extractTxPubKey(tx);

        // Quick check - scan outputs
        const outputs = tx.vout || tx.outputs || [];
        let isOurs = false;

        for (let i = 0; i < outputs.length && !isOurs; i++) {
          const outputPubKey = this._extractOutputPubKey(outputs[i]);
          if (!outputPubKey || !txPubKey) continue;

          const scanResult = scanTransaction(
            txPubKey,
            this.keys.viewSecretKey,
            this.keys.spendPublicKey,
            [{ publicKey: outputPubKey, index: i }]
          );

          if (scanResult.ours.length > 0) {
            isOurs = true;
          }
        }

        if (isOurs) {
          pendingTxs.push({
            txHash: txData.id_hash,
            inPool: true,
            receivedTime: txData.receive_time
          });
        }
      } catch (e) {
        // Skip malformed transactions
      }
    }

    return pendingTxs;
  }

  // ===========================================================================
  // RESCAN
  // ===========================================================================

  /**
   * Rescan blockchain from a specific height
   * @param {number} fromHeight - Height to start rescan
   * @returns {Promise<void>}
   */
  async rescan(fromHeight = 0) {
    // Clear outputs and transactions from storage
    await this.storage.clear();
    await this.storage.setSyncHeight(fromHeight);

    // Start fresh sync
    return this.start(fromHeight);
  }
}

// ============================================================================
// FACTORY
// ============================================================================

/**
 * Create a wallet sync engine
 * @param {Object} options - Configuration
 * @returns {WalletSync}
 */
export function createWalletSync(options) {
  return new WalletSync(options);
}

// ============================================================================
// DEFAULT EXPORT
// ============================================================================

export default {
  WalletSync,
  createWalletSync,
  SYNC_STATUS,
  DEFAULT_BATCH_SIZE,
  SYNC_UNLOCK_BLOCKS
};
