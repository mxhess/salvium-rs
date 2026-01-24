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
import {
  generateKeyDerivation,
  derivePublicKey,
  deriveSecretKey,
  deriveViewTag,
  computeSharedSecret,
  ecdhDecodeFull,
  deriveSubaddressPublicKey,
  scalarAdd
} from './scanning.js';
import { cnSubaddressSecretKey, carrotIndexExtensionGenerator, carrotSubaddressScalar } from './subaddress.js';
import { scanCarrotOutput, makeInputContext, makeInputContextCoinbase, generateCarrotKeyImage } from './carrot-scanning.js';
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
 * Minimum batch size (floor)
 */
export const MIN_BATCH_SIZE = 5;

/**
 * Maximum batch size (ceiling) - prevent memory/timeout issues
 */
export const MAX_BATCH_SIZE = 400;

/**
 * Target time per batch cycle in milliseconds (~2 seconds)
 */
export const TARGET_BATCH_TIME = 2000;

/**
 * Batch adjustment factor (20% per cycle)
 */
export const BATCH_ADJUST_FACTOR = 0.2;

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
   * @param {Object} options.carrotKeys - CARROT keys { viewIncomingKey, accountSpendPubkey }
   * @param {Object} options.subaddresses - Map of CN subaddress public keys to indices
   * @param {Object} options.carrotSubaddresses - Map of CARROT address spend pubkeys to indices
   * @param {number} options.batchSize - Blocks per batch (default: 100)
   */
  constructor(options = {}) {
    this.storage = options.storage;
    this.daemon = options.daemon;
    this.keys = options.keys;
    this.carrotKeys = options.carrotKeys || null;
    this.subaddresses = options.subaddresses || new Map();
    this.carrotSubaddresses = options.carrotSubaddresses || new Map();
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
    const batchStartTime = Date.now();

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

    // Process blocks in batches using batch RPC for better performance
    const BLOCK_BATCH_SIZE = 100; // Fetch 100 blocks per RPC call

    // Debug: log first syncBatch call
    if (this._syncBatchCount === undefined) this._syncBatchCount = 0;
    this._syncBatchCount++;
    if (this._syncBatchCount === 1) {
      console.log(`[DEBUG] First _syncBatch call, headers count=${headers.length}`);
    }

    for (let i = 0; i < headers.length; i += BLOCK_BATCH_SIZE) {
      if (this._stopRequested) break;

      const batch = headers.slice(i, i + BLOCK_BATCH_SIZE);
      const heights = batch.map(h => h.height);

      // Batch fetch all blocks at once
      const blocksResponse = await this.daemon.getBlocksByHeight(heights);

      // Debug: log batch response status
      if (this._syncBatchCount === 1 && i === 0) {
        console.log(`[DEBUG] Batch fetch response: success=${blocksResponse.success}, has blocks=${!!blocksResponse.result?.blocks}, blocks count=${blocksResponse.result?.blocks?.length || 0}`);
      }

      if (!blocksResponse.success || !blocksResponse.result?.blocks) {
        // Fallback to individual fetches if batch fails
        for (const header of batch) {
          if (this._stopRequested) break;
          await this._processBlock(header);
          this.currentHeight = header.height + 1;
          this._emit('syncProgress', this.getProgress());
        }
        continue;
      }

      // Process each block from batch response
      const blocks = blocksResponse.result.blocks;
      for (let j = 0; j < blocks.length; j++) {
        if (this._stopRequested) break;

        const header = batch[j];
        const blockData = blocks[j];

        await this._processBlockFromBatch(header, blockData);
        this.currentHeight = header.height + 1;
        this._emit('syncProgress', this.getProgress());
      }
    }

    // Save sync height
    await this.storage.setSyncHeight(this.currentHeight);

    // Adaptive batch sizing: adjust based on elapsed time
    this._adjustBatchSize(batchStartTime);
  }

  /**
   * Adjust batch size based on elapsed time for last batch
   * @private
   * @param {number} batchStartTime - Start time of the batch (from Date.now())
   */
  _adjustBatchSize(batchStartTime) {
    const elapsed = Date.now() - batchStartTime;

    // Too fast (< 60% of target) → increase by 20%
    if (elapsed < TARGET_BATCH_TIME * 0.6) {
      this.batchSize = Math.min(
        Math.round(this.batchSize * (1 + BATCH_ADJUST_FACTOR)),
        MAX_BATCH_SIZE
      );
    }
    // Too slow (> 150% of target) → decrease by 20%
    else if (elapsed > TARGET_BATCH_TIME * 1.5) {
      this.batchSize = Math.max(
        Math.round(this.batchSize * (1 - BATCH_ADJUST_FACTOR)),
        MIN_BATCH_SIZE
      );
    }
    // else: in the sweet spot, keep same

    // Emit batch timing info for debugging/monitoring
    this._emit('batchComplete', {
      elapsed,
      batchSize: this.batchSize,
      blocksPerSec: this.batchSize / (elapsed / 1000)
    });
  }

  /**
   * Process a block from batch response
   * @private
   */
  async _processBlockFromBatch(header, blockData) {
    // blockData from get_blocks_by_height.bin contains block blob
    // We need to parse it or use the included transactions

    // Debug: log batch processing status
    if (this._batchDebugCount === undefined) this._batchDebugCount = 0;
    this._batchDebugCount++;
    if (this._batchDebugCount <= 3) {
      console.log(`[DEBUG] _processBlockFromBatch at height ${header.height}`);
      console.log(`[DEBUG] blockData keys: ${blockData ? Object.keys(blockData).join(', ') : 'null'}`);
    }

    // If blockData has the structure we need, use it directly
    // Otherwise fall back to individual fetch
    if (!blockData || !blockData.block) {
      if (this._batchDebugCount <= 3) {
        console.log(`[DEBUG] Falling back to individual fetch for height ${header.height}`);
      }
      return this._processBlock(header);
    }

    try {
      // Parse block blob to get miner_tx and protocol_tx
      // The block field contains the hex-encoded block
      const blockBlob = blockData.block;

      // For now, decode the block JSON if available, otherwise parse binary
      // Most daemon responses include txs array with the transactions
      const txs = blockData.txs || [];

      // Process miner_tx from block header data if available
      if (blockData.miner_tx_hash) {
        // Find miner_tx in txs array or parse from block
        const minerTx = txs.find(tx => tx.tx_hash === blockData.miner_tx_hash);
        if (minerTx && minerTx.as_json) {
          await this._processEmbeddedTransaction(
            JSON.parse(minerTx.as_json),
            blockData.miner_tx_hash,
            header,
            { isMinerTx: true, isProtocolTx: false }
          );
        }
      }

      // Process protocol_tx if available
      if (blockData.protocol_tx_hash) {
        const protocolTx = txs.find(tx => tx.tx_hash === blockData.protocol_tx_hash);
        if (protocolTx && protocolTx.as_json) {
          await this._processEmbeddedTransaction(
            JSON.parse(protocolTx.as_json),
            blockData.protocol_tx_hash,
            header,
            { isMinerTx: false, isProtocolTx: true }
          );
        }
      }

      // Process regular transactions
      for (const tx of txs) {
        if (tx.tx_hash === blockData.miner_tx_hash || tx.tx_hash === blockData.protocol_tx_hash) {
          continue; // Already processed
        }
        if (tx.as_hex) {
          await this._processTransaction(tx, header, { isMinerTx: false, isProtocolTx: false });
        }
      }

      // Emit new block event
      this._emit('newBlock', {
        height: header.height,
        hash: header.hash,
        timestamp: header.timestamp,
        txCount: txs.length,
        hasMinerTx: !!blockData.miner_tx_hash,
        hasProtocolTx: !!blockData.protocol_tx_hash
      });

    } catch (error) {
      // Fallback to individual block processing
      console.error(`Batch processing failed for block ${header.height}, falling back:`, error.message);
      await this._processBlock(header);
    }
  }

  /**
   * Process a single block
   * @private
   * @param {Object} header - Block header
   */
  async _processBlock(header) {
    // Debug: count blocks processed via individual fetch
    if (this._individualBlockCount === undefined) this._individualBlockCount = 0;
    this._individualBlockCount++;

    // Get full block data - includes miner_tx and protocol_tx in JSON
    const blockResponse = await this.daemon.getBlock({ height: header.height });
    if (!blockResponse.success) {
      throw new Error(`Failed to get block ${header.height}`);
    }

    const block = blockResponse.result;

    // Parse block JSON to get miner_tx and protocol_tx directly
    // (they can't be fetched via getTransactions - that returns empty as_hex)
    let blockJson = null;
    if (block.json) {
      try {
        blockJson = JSON.parse(block.json);
      } catch (e) {
        console.error(`Failed to parse block JSON at height ${header.height}:`, e.message);
      }
    }

    // Debug: log first few blocks' miner_tx structure
    if (this._individualBlockCount <= 3 && blockJson?.miner_tx) {
      console.log(`[DEBUG] Block ${header.height} miner_tx keys: ${Object.keys(blockJson.miner_tx).join(', ')}`);
      console.log(`[DEBUG] miner_tx.vout count: ${(blockJson.miner_tx.vout || []).length}`);
      if (blockJson.miner_tx.vout?.[0]?.target) {
        console.log(`[DEBUG] First vout target keys: ${Object.keys(blockJson.miner_tx.vout[0].target).join(', ')}`);
      }
    }

    // Process miner_tx (coinbase - block reward)
    if (blockJson?.miner_tx && block.miner_tx_hash) {
      await this._processEmbeddedTransaction(
        blockJson.miner_tx,
        block.miner_tx_hash,
        header,
        { isMinerTx: true, isProtocolTx: false }
      );
    }

    // Process protocol_tx (Salvium-specific: conversions, yields, refunds)
    if (blockJson?.protocol_tx && block.protocol_tx_hash) {
      await this._processEmbeddedTransaction(
        blockJson.protocol_tx,
        block.protocol_tx_hash,
        header,
        { isMinerTx: false, isProtocolTx: true }
      );
    }

    // Fetch and process regular transactions
    const txHashes = blockJson?.tx_hashes || [];
    if (txHashes.length > 0) {
      const txsResponse = await this.daemon.getTransactions(txHashes, {
        decode_as_json: true
      });

      if (txsResponse.success && txsResponse.result.txs) {
        for (const txData of txsResponse.result.txs) {
          await this._processTransaction(txData, header, { isMinerTx: false, isProtocolTx: false });
        }
      }
    }

    // Emit new block event
    this._emit('newBlock', {
      height: header.height,
      hash: header.hash,
      timestamp: header.timestamp,
      txCount: txHashes.length,
      hasMinerTx: !!block.miner_tx_hash,
      hasProtocolTx: !!block.protocol_tx_hash
    });
  }

  /**
   * Process an embedded transaction (miner_tx or protocol_tx from block JSON)
   * @private
   * @param {Object} txJson - Transaction JSON from block.json
   * @param {string} txHash - Transaction hash
   * @param {Object} header - Block header
   * @param {Object} options - { isMinerTx, isProtocolTx }
   */
  async _processEmbeddedTransaction(txJson, txHash, header, options = {}) {
    const { isMinerTx = false, isProtocolTx = false } = options;

    // Debug: count embedded txs processed
    if (this._embeddedTxCount === undefined) this._embeddedTxCount = 0;
    this._embeddedTxCount++;
    if (this._embeddedTxCount <= 3) {
      console.log(`[DEBUG] Processing embedded tx at height ${header.height}, isMinerTx=${isMinerTx}, vout count=${(txJson.vout || []).length}`);
      if (txJson.extra) {
        console.log(`[DEBUG] extra field type: ${Array.isArray(txJson.extra) ? 'array' : typeof txJson.extra}, length=${txJson.extra.length || 0}`);
      }
    }

    // Check if we already have this transaction
    const existing = await this.storage.getTransaction(txHash);
    if (existing && existing.isConfirmed) {
      return; // Already processed
    }

    try {
      // Convert JSON structure to match our parsed transaction format
      const tx = this._convertJsonToTx(txJson);
      const txPubKey = extractTxPubKey(tx);
      const paymentId = extractPaymentId(tx);

      // Debug: log txPubKey extraction
      if (this._embeddedTxCount <= 3) {
        console.log(`[DEBUG] txPubKey extracted: ${txPubKey ? bytesToHex(txPubKey) : 'null'}`);
        console.log(`[DEBUG] converted vout count: ${(tx.prefix?.vout || []).length}`);
      }

      // Determine transaction type
      const txType = isMinerTx ? 'miner' : (isProtocolTx ? 'protocol' : this._getTxType(tx));

      // Scan outputs for owned ones
      const ownedOutputs = await this._scanOutputs(tx, txHash, txPubKey, header, txType);

      // Coinbase txs don't spend outputs, but check anyway for protocol_tx
      const spentOutputs = isProtocolTx ? await this._checkSpentOutputs(tx, txHash, header) : [];

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
        fee: 0n, // Coinbase/protocol txs have no fee
        paymentId,
        unlockTime: this._safeBigInt(txJson.unlock_time),
        txType,
        isMinerTx,
        isProtocolTx,
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
      console.error(`Error processing embedded tx ${txHash}:`, error.message);
      console.error(`  Stack:`, error.stack?.split('\n').slice(0, 5).join('\n'));
    }
  }

  /**
   * Safely convert a value to BigInt
   * @private
   */
  _safeBigInt(value) {
    if (value === undefined || value === null) return 0n;
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') return BigInt(Math.floor(value));
    if (typeof value === 'string') {
      // Handle empty string
      if (value === '') return 0n;
      // Handle hex strings
      if (value.startsWith('0x')) return BigInt(value);
      return BigInt(value);
    }
    // For anything else (objects, arrays, etc.), return 0
    return 0n;
  }

  /**
   * Convert daemon JSON transaction format to our parsed transaction format
   * @private
   * @param {Object} txJson - Transaction JSON from daemon
   * @returns {Object} Transaction in our parsed format
   */
  _convertJsonToTx(txJson) {
    // Convert vout (outputs)
    const vout = (txJson.vout || []).map(out => {
      const target = out.target;
      // Handle different output types
      if (target?.carrot_v1) {
        // CARROT v1 output (post-hardfork)
        // view_tag is 3 bytes hex (6 chars), e.g., "d3246a"
        let viewTag = undefined;
        if (target.carrot_v1.view_tag) {
          // Convert 3-byte hex to Uint8Array
          viewTag = hexToBytes(target.carrot_v1.view_tag);
        }
        return {
          amount: this._safeBigInt(out.amount),
          type: 0x04, // TXOUT_TYPE.CARROT_V1
          key: hexToBytes(target.carrot_v1.key),
          assetType: target.carrot_v1.asset_type || 'SAL1',
          viewTag,
          encryptedJanusAnchor: target.carrot_v1.encrypted_janus_anchor
            ? hexToBytes(target.carrot_v1.encrypted_janus_anchor)
            : null
        };
      } else if (target?.tagged_key) {
        // CN tagged key output (pre-hardfork with view tag)
        // View tag in JSON is hex string like "ab" (1 byte = 2 hex chars)
        // We need to convert to a number for comparison with deriveViewTag()
        let viewTag = undefined;
        if (target.tagged_key.view_tag !== undefined) {
          if (typeof target.tagged_key.view_tag === 'string') {
            // Hex string - parse first byte
            viewTag = parseInt(target.tagged_key.view_tag.slice(0, 2), 16);
          } else if (typeof target.tagged_key.view_tag === 'number') {
            viewTag = target.tagged_key.view_tag;
          }
        }
        return {
          amount: this._safeBigInt(out.amount),
          type: 0x03, // TXOUT_TYPE.TAGGED_KEY
          key: hexToBytes(target.tagged_key.key),
          assetType: target.tagged_key.asset_type || 'SAL',
          unlockTime: target.tagged_key.unlock_time || 0,
          viewTag
        };
      } else if (target?.key) {
        return {
          amount: this._safeBigInt(out.amount),
          type: 0x02, // TXOUT_TYPE.KEY
          key: hexToBytes(target.key)
        };
      }
      return { amount: this._safeBigInt(out.amount), type: 0 };
    });

    // Convert vin (inputs)
    const vin = (txJson.vin || []).map(inp => {
      if (inp.gen) {
        return { type: 0xff, height: inp.gen.height }; // TXIN_TYPE.GEN
      } else if (inp.key) {
        return {
          type: 0x02, // TXIN_TYPE.KEY
          amount: this._safeBigInt(inp.key.amount),
          keyOffsets: inp.key.key_offsets || [],
          keyImage: inp.key.k_image ? hexToBytes(inp.key.k_image) : null
        };
      }
      return { type: 0 };
    });

    // Convert extra
    const extra = this._convertExtraJson(txJson.extra || []);

    // Build prefix
    const prefix = {
      version: txJson.version || 2,
      unlockTime: this._safeBigInt(txJson.unlock_time),
      vin,
      vout,
      extra,
      type: txJson.type || 0
    };

    // RCT signatures (minimal for coinbase)
    const rct = {
      type: txJson.rct_signatures?.type || 0,
      txnFee: this._safeBigInt(txJson.rct_signatures?.txnFee),
      // p_r is the ephemeral pubkey used for CARROT output scanning
      p_r: txJson.rct_signatures?.p_r ? hexToBytes(txJson.rct_signatures.p_r) : null,
      outPk: (txJson.rct_signatures?.outPk || []).map(pk => {
        if (typeof pk === 'string') return hexToBytes(pk);
        if (pk?.mask) return hexToBytes(pk.mask);
        if (typeof pk === 'object' && pk) return hexToBytes(Object.values(pk)[0] || '');
        return new Uint8Array(32);
      }),
      ecdhInfo: (txJson.rct_signatures?.ecdhInfo || []).map(info => ({
        amount: info?.amount ? hexToBytes(info.amount) : new Uint8Array(8)
      }))
    };

    return { prefix, rct };
  }

  /**
   * Convert extra field from JSON array format
   * @private
   */
  _convertExtraJson(extraArray) {
    // Extra in JSON is just an array of bytes
    if (!Array.isArray(extraArray) || extraArray.length === 0) {
      // Debug: log if extra is empty or wrong format
      if (this._extraDebugCount === undefined) this._extraDebugCount = 0;
      this._extraDebugCount++;
      if (this._extraDebugCount <= 3) {
        console.log(`[DEBUG] _convertExtraJson: extraArray is ${Array.isArray(extraArray) ? 'array of length ' + extraArray.length : typeof extraArray}`);
      }
      return [];
    }

    // Parse the extra bytes to extract fields
    const extraBytes = new Uint8Array(extraArray);
    const parsed = [];

    // Debug: log first few bytes
    if (this._extraDebugCount === undefined) this._extraDebugCount = 0;
    this._extraDebugCount++;
    if (this._extraDebugCount <= 3) {
      console.log(`[DEBUG] _convertExtraJson: extraBytes length=${extraBytes.length}, first bytes: ${Array.from(extraBytes.slice(0, 5)).map(b => b.toString(16)).join(' ')}`);
    }
    let offset = 0;

    while (offset < extraBytes.length) {
      const tag = extraBytes[offset++];

      if (tag === 0x01 && offset + 32 <= extraBytes.length) {
        // TX_EXTRA_TAG_PUBKEY
        parsed.push({
          type: 0x01,
          key: extraBytes.slice(offset, offset + 32)
        });
        offset += 32;
      } else if (tag === 0x02) {
        // TX_EXTRA_NONCE
        if (offset >= extraBytes.length) break;
        const len = extraBytes[offset++];
        if (offset + len > extraBytes.length) break;
        const nonce = extraBytes.slice(offset, offset + len);
        offset += len;

        // Check for payment ID inside nonce
        if (len >= 1) {
          const nonceType = nonce[0];
          if (nonceType === 0x00 && len === 33) {
            // Unencrypted payment ID (32 bytes)
            parsed.push({
              type: 0x02,
              paymentIdType: 'unencrypted',
              paymentId: nonce.slice(1, 33)
            });
          } else if (nonceType === 0x01 && len === 9) {
            // Encrypted payment ID (8 bytes)
            parsed.push({
              type: 0x02,
              paymentIdType: 'encrypted',
              paymentId: nonce.slice(1, 9)
            });
          }
        }
      } else if (tag === 0x04) {
        // TX_EXTRA_ADDITIONAL_PUBKEYS
        if (offset >= extraBytes.length) break;
        const count = extraBytes[offset++];
        const keys = [];
        for (let i = 0; i < count && offset + 32 <= extraBytes.length; i++) {
          keys.push(extraBytes.slice(offset, offset + 32));
          offset += 32;
        }
        parsed.push({ type: 0x04, keys });
      } else {
        // Unknown tag, try to skip
        break;
      }
    }

    return parsed;
  }

  /**
   * Process a single transaction
   * @private
   * @param {Object} txData - Transaction data from RPC
   * @param {Object} header - Block header
   * @param {Object} [options] - Additional options
   * @param {boolean} [options.isMinerTx] - Whether this is a miner (coinbase) transaction
   * @param {boolean} [options.isProtocolTx] - Whether this is a Salvium protocol transaction
   */
  async _processTransaction(txData, header, options = {}) {
    const { isMinerTx = false, isProtocolTx = false } = options;
    const txHash = txData.tx_hash;
    const txBlob = txData.as_hex;

    // Debug: count regular txs processed
    if (this._regularTxCount === undefined) this._regularTxCount = 0;
    this._regularTxCount++;
    if (this._regularTxCount <= 3) {
      console.log(`[DEBUG] _processTransaction at height ${header.height}, tx ${txHash.slice(0, 16)}...`);
    }

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

      // Debug: log tx structure
      if (this._regularTxCount <= 3) {
        console.log(`[DEBUG] Regular tx: txPubKey=${txPubKey ? bytesToHex(txPubKey).slice(0, 16) + '...' : 'null'}, vout count=${(tx.prefix?.vout || []).length}`);
      }

      // Determine transaction type (Salvium-specific)
      // For miner_tx and protocol_tx, use the type from the prefix
      // Otherwise use our helper method
      const txType = isMinerTx ? 'miner' : (isProtocolTx ? 'protocol' : this._getTxType(tx));

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
        fee: this._safeBigInt(tx.rct?.txnFee),
        paymentId,
        unlockTime: tx.prefix?.unlockTime || 0n,
        txType,
        isMinerTx,
        isProtocolTx,
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
      // Log parse errors but don't throw - continue with other transactions
      // Some transactions may have formats we don't fully support yet
      if (this._parseErrorCount === undefined) this._parseErrorCount = 0;
      this._parseErrorCount++;
      if (this._parseErrorCount <= 5) {
        console.error(`Error processing tx ${txHash}: ${error.message}`);
      } else if (this._parseErrorCount === 6) {
        console.error(`(suppressing further parse errors...)`);
      }
    }
  }

  /**
   * Scan transaction outputs for owned ones
   * Handles both CryptoNote (legacy) and CARROT outputs
   * @private
   */
  async _scanOutputs(tx, txHash, txPubKey, header, txType) {
    const ownedOutputs = [];
    const outputs = tx.prefix?.vout || tx.outputs || [];

    // Debug: log first 3 calls unconditionally
    if (this._scanOutputsCount === undefined) this._scanOutputsCount = 0;
    this._scanOutputsCount++;
    if (this._scanOutputsCount <= 3) {
      console.log(`\n=== _scanOutputs call #${this._scanOutputsCount} at height ${header.height} ===`);
      console.log(`txHash: ${txHash}`);
      console.log(`txPubKey: ${txPubKey ? bytesToHex(txPubKey) : 'NULL'}`);
      console.log(`outputs count: ${outputs.length}`);
      console.log(`txType: ${txType}`);
      if (outputs.length > 0) {
        const firstOutput = outputs[0];
        console.log(`first output type: ${firstOutput.type}`);
        console.log(`first output keys: ${Object.keys(firstOutput).join(', ')}`);
        const firstKey = this._extractOutputPubKey(firstOutput);
        console.log(`first output pubkey: ${firstKey ? bytesToHex(firstKey).slice(0, 32) + '...' : 'NULL'}`);
      }
      console.log(`===\n`);
    }

    for (let i = 0; i < outputs.length; i++) {
      const output = outputs[i];
      const outputPubKey = this._extractOutputPubKey(output);

      if (!outputPubKey) continue;

      let scanResult = null;

      // Detect CARROT vs CryptoNote output
      // CARROT outputs have: 3-byte view tag, enote ephemeral pubkey
      const isCarrotOutput = this._isCarrotOutput(output);

      // Debug: log CARROT detection after hardfork
      if (header.height >= 334750 && header.height <= 334760) {
        console.log(`[DEBUG CARROT] height=${header.height} output=${i} isCarrot=${isCarrotOutput} viewTag=${output.viewTag} type=${output.type} target.type=${output.target?.type}`);
      }

      if (isCarrotOutput && this.carrotKeys) {
        // CARROT scanning - pass txPubKey (D_e) from tx_extra
        scanResult = await this._scanCarrotOutput(output, i, tx, txHash, txPubKey, header);
      } else if (txPubKey && this.keys.viewSecretKey) {
        // CryptoNote (legacy) scanning
        scanResult = await this._scanCNOutput(output, i, tx, txHash, txPubKey, header);
      }

      if (scanResult) {
        // Create output record
        const walletOutput = new WalletOutput({
          keyImage: scanResult.keyImage,
          publicKey: bytesToHex(outputPubKey),
          txHash,
          outputIndex: i,
          globalIndex: null,
          blockHeight: header.height,
          blockTimestamp: header.timestamp,
          amount: scanResult.amount,
          commitment: tx.rct?.outPk?.[i] ? bytesToHex(tx.rct.outPk[i]) : null,
          mask: scanResult.mask ? bytesToHex(scanResult.mask) : null,
          subaddressIndex: scanResult.subaddressIndex,
          unlockTime: tx.prefix?.unlockTime || 0n,
          txType,
          isCarrot: scanResult.isCarrot || false
        });

        // Debug: log key image for found outputs
        console.log(`[OUTPUT] Found at height ${header.height}: keyImage=${walletOutput.keyImage ? walletOutput.keyImage.slice(0,16) + '...' : 'NULL'} amount=${walletOutput.amount}`);

        await this.storage.putOutput(walletOutput);
        ownedOutputs.push(walletOutput);

        // Emit output found event
        this._emit('outputFound', {
          amount: scanResult.amount,
          blockHeight: header.height,
          subaddressIndex: scanResult.subaddressIndex,
          isCarrot: scanResult.isCarrot || false
        });
      }
    }

    return ownedOutputs;
  }

  /**
   * Check if output is CARROT format
   * @private
   */
  _isCarrotOutput(output) {
    // CARROT outputs have 3-byte view tag (as Uint8Array)
    // From parseTransaction: viewTag is 3-byte Uint8Array
    // From _convertJsonToTx: viewTag for CARROT would need special handling
    if (output.viewTag instanceof Uint8Array && output.viewTag.length === 3) {
      return true;
    }
    // Check output type directly
    // 0x04 = CARROT_V1 (from parseTransaction)
    // output.type from _convertJsonToTx
    if (output.type === 0x04) {
      return true;
    }
    if (output.target?.type === 0x04) {
      return true;
    }
    return false;
  }

  /**
   * Scan a CARROT output for ownership
   * @private
   * @param {Object} output - The output to scan
   * @param {number} outputIndex - Index of the output in the transaction
   * @param {Object} tx - The parsed transaction
   * @param {string} txHash - Transaction hash
   * @param {Uint8Array|null} txPubKey - The enote ephemeral pubkey (D_e) from tx_extra
   * @param {Object} header - Block header with height and timestamp
   */
  async _scanCarrotOutput(output, outputIndex, tx, txHash, txPubKey, header) {
    if (!this.carrotKeys?.viewIncomingKey || !this.carrotKeys?.accountSpendPubkey) {
      return null;
    }

    // Build input context
    // For regular tx: 'R' || first_key_image (33 bytes)
    // For coinbase: 'C' || block_height (33 bytes)
    let inputContext;
    const inputs = tx.prefix?.vin || tx.inputs || [];
    const firstKi = inputs.length > 0 ? (inputs[0].keyImage || inputs[0].key?.k_image) : null;
    if (firstKi) {
      // RingCT transaction: input_context = 'R' || first_key_image
      const firstKeyImage = typeof firstKi === 'string'
        ? hexToBytes(firstKi)
        : firstKi;
      inputContext = makeInputContext(firstKeyImage);
      // Debug: show first key image
      if (header.height >= 405588 && header.height <= 405590 && this._inputContextDebug === undefined) {
        this._inputContextDebug = true;
        console.log(`[INPUT CONTEXT DEBUG] height=${header.height} txHash=${txHash.slice(0,16)}...`);
        console.log(`  firstKeyImage: ${bytesToHex(firstKeyImage)}`);
        console.log(`  inputContext: ${bytesToHex(inputContext)}`);
      }
    } else {
      // Coinbase transaction: input_context = 'C' || block_height
      inputContext = makeInputContextCoinbase(header.height);
    }

    // Get amount commitment from RingCT
    const amountCommitment = tx.rct?.outPk?.[outputIndex]
      ? (typeof tx.rct.outPk[outputIndex] === 'string'
          ? hexToBytes(tx.rct.outPk[outputIndex])
          : tx.rct.outPk[outputIndex])
      : null;

    // Use the passed txPubKey (D_e) as the enote ephemeral pubkey
    // It was extracted from tx_extra by the caller
    // For per-output ephemeral pubkeys, check additionalPubKeys
    let enoteEphemeralPubkey = txPubKey;
    if (!enoteEphemeralPubkey && tx.prefix?.extra?.additionalPubKeys?.[outputIndex]) {
      // Per-output ephemeral pubkeys
      const pubKey = tx.prefix.extra.additionalPubKeys[outputIndex];
      enoteEphemeralPubkey = typeof pubKey === 'string' ? hexToBytes(pubKey) : pubKey;
    }

    const outputForScan = {
      key: this._extractOutputPubKey(output),
      viewTag: output.viewTag,
      enoteEphemeralPubkey,
      encryptedAmount: tx.rct?.ecdhInfo?.[outputIndex]?.amount
    };

    // Debug CARROT scanning inputs
    if (header.height >= 405585 && header.height <= 405595) {
      console.log(`[DEBUG CARROT SCAN] height=${header.height} outputIndex=${outputIndex}`);
      console.log(`  key: ${outputForScan.key ? bytesToHex(outputForScan.key).slice(0,16) + '...' : 'NULL'}`);
      console.log(`  viewTag: ${outputForScan.viewTag}`);
      console.log(`  enoteEphemeralPubkey: ${outputForScan.enoteEphemeralPubkey ? (typeof outputForScan.enoteEphemeralPubkey === 'string' ? outputForScan.enoteEphemeralPubkey.slice(0,16) : bytesToHex(outputForScan.enoteEphemeralPubkey).slice(0,16)) + '...' : 'NULL'}`);
      console.log(`  amountCommitment: ${amountCommitment ? bytesToHex(amountCommitment).slice(0,16) + '...' : 'NULL'}`);
      console.log(`  carrotKeys: viewIncomingKey=${this.carrotKeys?.viewIncomingKey ? 'SET' : 'NULL'}, accountSpendPubkey=${this.carrotKeys?.accountSpendPubkey ? 'SET' : 'NULL'}`);
    }

    // Scan with CARROT algorithm
    let result;
    try {
      result = scanCarrotOutput(
        outputForScan,
        this.carrotKeys.viewIncomingKey,
        this.carrotKeys.accountSpendPubkey,
        inputContext,
        this.carrotSubaddresses,
        amountCommitment
      );
    } catch (e) {
      // Missing required fields in CARROT output - skip this output
      return null;
    }

    if (!result) {
      return null;
    }

    // Generate CARROT key image if we have the generateImageKey
    let keyImage = null;
    if (this.carrotKeys.generateImageKey && amountCommitment) {
      try {
        // Compute subaddress scalar for subaddresses
        // For main address (0,0): k_subscal = 1 (pass null)
        // For subaddresses: k_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
        let subaddressScalar = null;
        if (result.subaddressIndex.major !== 0 || result.subaddressIndex.minor !== 0) {
          // Need generateAddressSecret (s_ga) and accountSpendPubkey (K_s)
          if (this.carrotKeys.generateAddressSecret && this.carrotKeys.accountSpendPubkey) {
            const sGa = typeof this.carrotKeys.generateAddressSecret === 'string'
              ? hexToBytes(this.carrotKeys.generateAddressSecret)
              : this.carrotKeys.generateAddressSecret;
            const Ks = typeof this.carrotKeys.accountSpendPubkey === 'string'
              ? hexToBytes(this.carrotKeys.accountSpendPubkey)
              : this.carrotKeys.accountSpendPubkey;

            // s^j_gen = H_32[s_ga](j_major, j_minor)
            const indexGenerator = carrotIndexExtensionGenerator(
              sGa,
              result.subaddressIndex.major,
              result.subaddressIndex.minor
            );

            // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
            subaddressScalar = carrotSubaddressScalar(
              Ks,
              indexGenerator,
              result.subaddressIndex.major,
              result.subaddressIndex.minor
            );
          }
        }

        const kiBytes = generateCarrotKeyImage(
          result.onetimeAddress,
          result.sharedSecret,
          amountCommitment,
          this.carrotKeys.generateImageKey,
          subaddressScalar
        );
        keyImage = bytesToHex(kiBytes);
      } catch (e) {
        console.error('Failed to generate CARROT key image:', e.message);
      }
    }

    return {
      amount: result.amount,
      mask: result.mask,
      subaddressIndex: result.subaddressIndex,
      keyImage,
      isCarrot: true
    };
  }

  /**
   * Scan a CryptoNote (legacy) output for ownership
   * Uses subaddress map lookup (matches C++ wallet behavior)
   * @private
   */
  async _scanCNOutput(output, outputIndex, tx, txHash, txPubKey, header) {
    // Debug: count CN scan attempts
    if (this._cnScanCount === undefined) this._cnScanCount = 0;
    this._cnScanCount++;

    const outputPubKey = this._extractOutputPubKey(output);
    if (!outputPubKey) {
      if (this._cnScanCount <= 3) {
        console.log(`[DEBUG] _scanCNOutput: no outputPubKey for output ${outputIndex}`);
      }
      return null;
    }

    // Compute key derivation: D = 8 * viewSecretKey * txPubKey
    const derivation = generateKeyDerivation(txPubKey, this.keys.viewSecretKey);
    if (!derivation) {
      if (this._cnScanCount <= 3) {
        console.log(`[DEBUG] _scanCNOutput: derivation failed`);
      }
      return null;
    }

    // Check view tag FIRST (if available) for fast rejection
    if (output.viewTag !== undefined) {
      const expectedViewTag = deriveViewTag(derivation, outputIndex);
      if (this._cnScanCount <= 3) {
        console.log(`[DEBUG] _scanCNOutput: viewTag check - output.viewTag=${output.viewTag}, expected=${expectedViewTag}`);
      }
      if (output.viewTag !== expectedViewTag) {
        return null; // Not our output - skip expensive operations
      }
    }

    // Derive the spend public key from the output (reverse derivation)
    // P' = outputKey - H_s(D || index) * G
    // This gives us the spend pubkey that was used to create this output
    const derivedSpendPubKey = deriveSubaddressPublicKey(outputPubKey, derivation, outputIndex);
    if (!derivedSpendPubKey) {
      if (this._cnScanCount <= 3) {
        console.log(`[DEBUG] _scanCNOutput: deriveSubaddressPublicKey failed`);
      }
      return null;
    }

    const derivedSpendPubKeyHex = bytesToHex(derivedSpendPubKey);

    // Look up in subaddress map
    let subaddressIndex = null;
    if (this.subaddresses && this.subaddresses.has(derivedSpendPubKeyHex)) {
      subaddressIndex = this.subaddresses.get(derivedSpendPubKeyHex);
    }

    // Debug: log first few lookups
    if (this._cnScanCount <= 3) {
      console.log(`[DEBUG] _scanCNOutput: derived spend key=${derivedSpendPubKeyHex.slice(0, 16)}...`);
      console.log(`[DEBUG] _scanCNOutput: subaddress map size=${this.subaddresses?.size || 0}`);
      console.log(`[DEBUG] _scanCNOutput: found in map=${!!subaddressIndex}`);
    }

    if (!subaddressIndex) {
      return null; // Not our output
    }

    // Output is ours! Decrypt amount
    let amount = 0n;
    let mask = null;

    const ecdhInfo = tx.rct?.ecdhInfo?.[outputIndex];
    if (ecdhInfo?.amount) {
      const sharedSecret = computeSharedSecret(derivation, outputIndex);
      const encryptedAmount = typeof ecdhInfo.amount === 'string'
        ? hexToBytes(ecdhInfo.amount)
        : ecdhInfo.amount;
      const decoded = ecdhDecodeFull(encryptedAmount, sharedSecret);
      amount = decoded.amount;
      mask = decoded.mask;
    }

    // Generate key image if we have spend key
    // For subaddresses, need to derive the subaddress secret key first:
    // subaddr_secret_key = spend_secret_key + H_s("SubAddr\0" || view_secret_key || major || minor)
    let keyImage = null;
    if (this.keys.spendSecretKey && this.keys.viewSecretKey) {
      try {
        // For subaddresses (not main address), compute the subaddress secret key
        let baseSpendSecretKey = this.keys.spendSecretKey;
        if (subaddressIndex.major !== 0 || subaddressIndex.minor !== 0) {
          // m = H_s("SubAddr\0" || k_view || major || minor)
          const subaddrScalar = cnSubaddressSecretKey(
            typeof this.keys.viewSecretKey === 'string'
              ? hexToBytes(this.keys.viewSecretKey)
              : this.keys.viewSecretKey,
            subaddressIndex.major,
            subaddressIndex.minor
          );
          // subaddress_secret_key = spend_secret_key + m
          const spendKey = typeof this.keys.spendSecretKey === 'string'
            ? hexToBytes(this.keys.spendSecretKey)
            : this.keys.spendSecretKey;
          baseSpendSecretKey = scalarAdd(spendKey, subaddrScalar);
        }
        const outputSecretKey = deriveSecretKey(derivation, outputIndex, baseSpendSecretKey);
        keyImage = bytesToHex(generateKeyImage(outputPubKey, outputSecretKey));
      } catch (e) {
        console.error('Failed to generate key image:', e);
      }
    }

    return {
      amount,
      mask,
      subaddressIndex,
      keyImage,
      isCarrot: false
    };
  }

  /**
   * Check if any inputs spend our outputs
   * @private
   */
  async _checkSpentOutputs(tx, txHash, header) {
    const spentOutputs = [];
    const inputs = tx.prefix?.vin || tx.inputs || [];

    // Debug: log first few checks
    if (this._spentCheckCount === undefined) this._spentCheckCount = 0;
    this._spentCheckCount++;

    for (const input of inputs) {
      // Parsed transactions use input.keyImage directly
      // JSON-converted transactions might use input.key.k_image
      const ki = input.keyImage || input.key?.k_image;
      if (!ki) continue;

      const keyImage = typeof ki === 'string'
        ? ki
        : bytesToHex(ki);

      // Check if this key image belongs to one of our outputs
      const output = await this.storage.getOutput(keyImage);

      // Debug: log when we find a potential match or at specific heights
      if (output || (header.height >= 270510 && header.height <= 270530)) {
        console.log(`[DEBUG] _checkSpentOutputs height=${header.height} keyImage=${keyImage.slice(0,16)}... found=${!!output}`);
      }

      if (output && !output.isSpent) {
        console.log(`[SPENT] Output spent at height ${header.height}: keyImage=${keyImage.slice(0,16)}... amount=${output.amount}`);
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
    // From _convertJsonToTx: key is directly on output
    if (output.key) {
      return typeof output.key === 'string'
        ? hexToBytes(output.key)
        : output.key;
    }
    // From parseTransaction: output.target.key
    if (output.target?.key) {
      return typeof output.target.key === 'string'
        ? hexToBytes(output.target.key)
        : output.target.key;
    }
    // From parseTransaction: output.target.tagged_key.key
    if (output.target?.tagged_key?.key) {
      return typeof output.target.tagged_key.key === 'string'
        ? hexToBytes(output.target.tagged_key.key)
        : output.target.tagged_key.key;
    }
    // Legacy: output.publicKey
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
    // Salvium transaction type is in prefix.type
    // Maps to TX_TYPE enum values
    const prefixType = tx.prefix?.type;
    if (prefixType !== undefined && prefixType !== null) {
      // Direct mapping from Salvium transaction_type enum
      switch (prefixType) {
        case 1: return TX_TYPE.MINER;
        case 2: return TX_TYPE.PROTOCOL;
        case 3: return TX_TYPE.TRANSFER;
        case 4: return TX_TYPE.CONVERT;
        case 5: return TX_TYPE.BURN;
        case 6: return TX_TYPE.STAKE;
        case 7: return TX_TYPE.RETURN;
        case 8: return TX_TYPE.AUDIT;
        default: return TX_TYPE.TRANSFER;
      }
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
        if (!txPubKey) continue;

        // Compute key derivation once per transaction
        const derivation = generateKeyDerivation(txPubKey, this.keys.viewSecretKey);
        if (!derivation) continue;

        // Scan outputs
        const outputs = tx.prefix?.vout || tx.outputs || [];
        let isOurs = false;

        for (let i = 0; i < outputs.length && !isOurs; i++) {
          const outputPubKey = this._extractOutputPubKey(outputs[i]);
          if (!outputPubKey) continue;

          // Check view tag if available
          if (outputs[i].viewTag !== undefined) {
            const expectedViewTag = deriveViewTag(derivation, i);
            if (outputs[i].viewTag !== expectedViewTag) {
              continue;
            }
          }

          // Derive expected output public key
          const expectedPubKey = derivePublicKey(derivation, i, this.keys.spendPublicKey);
          if (!expectedPubKey) continue;

          // Compare with actual output key
          if (bytesToHex(outputPubKey) === bytesToHex(expectedPubKey)) {
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
