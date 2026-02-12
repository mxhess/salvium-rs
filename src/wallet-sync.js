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
import { cnSubaddressSecretKey, carrotIndexExtensionGenerator, carrotSubaddressScalar } from './subaddress.js';
import { scanCarrotOutput, scanCarrotInternalOutput, computeReturnAddress, makeInputContext, makeInputContextCoinbase, generateCarrotKeyImage } from './carrot-scanning.js';
import { parseTransaction, parseBlock, extractTxPubKey, extractPaymentId, extractAdditionalPubKeys, serializeTxPrefix } from './transaction.js';
import { bytesToHex, hexToBytes } from './address.js';
import { TX_TYPE } from './wallet.js';
import {
  getCryptoBackend,
  generateKeyDerivation, derivePublicKey, deriveSecretKey,
  generateKeyImage, commit as pedersonCommit,
  deriveViewTag, computeSharedSecret, ecdhDecodeFull,
  deriveSubaddressPublicKey, scalarAdd,
  cnFastHash,
} from './crypto/index.js';

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
export const MIN_BATCH_SIZE = 2;

/**
 * Maximum batch size (ceiling) - prevent memory/timeout issues
 */
export const MAX_BATCH_SIZE = 500;

/**
 * Maximum concurrent RPC calls for parallel block fetching
 */
export const FETCH_CONCURRENCY = 20;

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
// HELPERS
// ============================================================================

/**
 * Normalize a key value to a hex string.
 * Accepts: hex string (passthrough), Uint8Array, or indexed-object
 * (e.g. {"0": 175, "1": 212, ...} from JSON.stringify(Uint8Array)).
 */
function _toHex(val) {
  if (typeof val === 'string') return val;
  if (val instanceof Uint8Array) return bytesToHex(val);
  if (val && typeof val === 'object' && '0' in val) {
    const len = Object.keys(val).length;
    const arr = new Uint8Array(len);
    for (let i = 0; i < len; i++) arr[i] = val[i];
    return bytesToHex(arr);
  }
  return val;
}

/**
 * Normalize wallet keys object so all key fields are hex strings.
 * This prevents issues where Uint8Arrays or JSON-deserialized indexed objects
 * are passed as keys (Map lookups and crypto functions expect consistent types).
 */
function _normalizeKeys(keys) {
  if (!keys) return keys;
  const result = { ...keys };
  for (const field of ['viewSecretKey', 'spendSecretKey', 'viewPublicKey', 'spendPublicKey']) {
    if (result[field] && typeof result[field] !== 'string') {
      result[field] = _toHex(result[field]);
    }
  }
  return result;
}

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
    // Normalize keys to hex strings (handles Uint8Array and indexed-object formats)
    this.keys = options.keys ? _normalizeKeys(options.keys) : options.keys;
    this.carrotKeys = options.carrotKeys || null;
    this.subaddresses = options.subaddresses || new Map();
    // Always include the primary address in subaddress map (as hex string for consistent lookup)
    if (this.keys?.spendPublicKey) {
      const spendPubHex = this.keys.spendPublicKey instanceof Uint8Array
        ? bytesToHex(this.keys.spendPublicKey)
        : this.keys.spendPublicKey;
      if (!this.subaddresses.has(spendPubHex)) {
        this.subaddresses.set(spendPubHex, { major: 0, minor: 0 });
      }
    }
    this.carrotSubaddresses = options.carrotSubaddresses || new Map();
    this.batchSize = options.batchSize || DEFAULT_BATCH_SIZE;

    // Cache main spend pubkey as Uint8Array for fast binary comparison in scanning
    // (avoids hex conversion for the 99%+ of outputs that aren't ours)
    this._mainSpendPubKeyBytes = this.keys?.spendPublicKey
      ? (this.keys.spendPublicKey instanceof Uint8Array
          ? this.keys.spendPublicKey
          : hexToBytes(this.keys.spendPublicKey))
      : null;

    // Return output map: maps expected return address (Ko hex) to origin data.
    // Built when we detect self-send outputs in transactions (internal CARROT path).
    // Used to detect staking return outputs in protocol_tx.
    // Key: returnAddressHex (K_r = k_return*G + Ko_selfsend)
    // Value: { inputContext, originalKo, kReturn }
    this._returnOutputMap = new Map();

    // State
    this.status = SYNC_STATUS.IDLE;
    this.currentHeight = 0;
    this.targetHeight = 0;
    this.startHeight = 0;
    this.error = null;

    // Adaptive batch sizing state
    this._lastMsPerBlock = 0;   // ms per block from previous batch
    this._lastBatchBlocks = 0;  // blocks processed in previous batch

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
    // Prevent duplicate listeners (e.g., from sync restart after node switch)
    const exists = this._listeners.some(
      l => l.event === event && l.callback === callback
    );
    if (!exists) {
      this._listeners.push({ event, callback });
    }
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

      // Detect chain reorganization before syncing
      await this._detectReorg();

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
  // REORG DETECTION
  // ===========================================================================

  /**
   * Detect and handle chain reorganization.
   * Compares stored block hashes with daemon's chain to find divergence.
   *
   * Reference: Salvium wallet2.cpp pull_blocks() reorg detection
   * @private
   */
  async _detectReorg() {
    if (this.startHeight === 0) return;

    // Check if our stored tip hash matches the daemon's hash at that height
    const checkHeight = this.startHeight - 1;
    const storedHash = await this.storage.getBlockHash(checkHeight);

    if (!storedHash) return; // No stored hash = first sync, no reorg possible

    try {
      const response = await this.daemon.getBlockHeaderByHeight(checkHeight);
      if (!response.success) return;

      const daemonHash = response.result.block_header?.hash;
      if (!daemonHash || storedHash === daemonHash) return; // No reorg

      // Hashes differ - find common ancestor
      const commonHeight = await this._findCommonAncestor(checkHeight);
      await this._handleWalletReorg(commonHeight, checkHeight);
    } catch (e) {
      // If we can't detect, proceed with normal sync
      console.error('Reorg detection failed:', e.message);
    }
  }

  /**
   * Find the common ancestor height by walking backward.
   * @private
   * @param {number} fromHeight - Start searching from this height
   * @returns {Promise<number>} Highest height where hashes match
   */
  async _findCommonAncestor(fromHeight) {
    for (let h = fromHeight; h >= 0; h--) {
      const storedHash = await this.storage.getBlockHash(h);
      if (!storedHash) return h; // No stored hash below this = safe starting point

      try {
        const response = await this.daemon.getBlockHeaderByHeight(h);
        if (!response.success) continue;

        const daemonHash = response.result.block_header?.hash;
        if (storedHash === daemonHash) return h;
      } catch (e) {
        continue;
      }
    }
    return 0;
  }

  /**
   * Handle wallet-level reorg: invalidate orphaned data and rescan.
   * @private
   * @param {number} commonHeight - Last valid block height
   * @param {number} oldTipHeight - Previous sync tip height
   */
  async _handleWalletReorg(commonHeight, oldTipHeight) {
    const blocksRolledBack = oldTipHeight - commonHeight;

    this._emit('reorg', {
      commonHeight,
      oldTipHeight,
      blocksRolledBack
    });

    // Invalidate all wallet data above the common ancestor
    await this.storage.deleteOutputsAbove(commonHeight);
    await this.storage.deleteTransactionsAbove(commonHeight);
    await this.storage.unspendOutputsAbove(commonHeight);
    await this.storage.deleteBlockHashesAbove(commonHeight);

    // Reset sync height to rescan from common ancestor
    this.startHeight = commonHeight + 1;
    this.currentHeight = commonHeight + 1;
    await this.storage.setSyncHeight(this.startHeight);
  }

  // ===========================================================================
  // BATCH PROCESSING
  // ===========================================================================

  /**
   * Sync a batch of blocks.
   *
   * Uses binary bulk fetch (2 RPCs total per batch):
   *   1. getBlockHeadersRange — headers in bulk
   *   2. getBlocksByHeight   — all block blobs + embedded tx blobs
   *
   * Falls back to parallel JSON fetch if binary endpoint unavailable.
   * @private
   */
  async _syncBatch() {
    const batchStartTime = Date.now();

    const endHeight = Math.min(
      this.currentHeight + this.batchSize,
      this.targetHeight
    );

    // ── Phase 1: Fetch block headers in bulk (1 RPC) ──────────────────────
    const headersResponse = await this.daemon.getBlockHeadersRange(
      this.currentHeight,
      endHeight - 1
    );

    if (!headersResponse.success) {
      throw new Error(`Failed to get block headers: ${headersResponse.error?.message}`);
    }

    const headers = headersResponse.result.headers || [];
    if (headers.length === 0) return;

    // ── Phase 2: Try binary bulk fetch (1 RPC for all blocks) ─────────────
    const heights = headers.map(h => h.height);
    let usedBinaryPath = false;

    if (this.daemon.getBlocksByHeight) {
      try {
        const binResp = await this.daemon.getBlocksByHeight(heights);
        if (binResp.success && binResp.result.blocks?.length === headers.length) {
          await this._processBinaryBatch(headers, binResp.result.blocks);
          usedBinaryPath = true;
        }
      } catch (e) {
        // Binary endpoint failed — fall through to JSON path
      }
    }

    // ── Phase 2b: Fallback — parallel JSON fetch ──────────────────────────
    if (!usedBinaryPath) {
      await this._syncBatchJsonFallback(headers);
    }

    // Save sync height
    await this.storage.setSyncHeight(this.currentHeight);

    // Adaptive batch sizing based on throughput trend
    this._adjustBatchSize(batchStartTime, headers.length);
  }

  /**
   * Process a batch of blocks from binary bulk fetch.
   * Block blobs contain miner_tx, protocol_tx, and tx_hashes inline.
   * Regular tx blobs are included in the response.
   *
   * Total RPCs for this path: 0 (all data already fetched).
   * @private
   */
  async _processBinaryBatch(headers, binaryBlocks) {
    for (let idx = 0; idx < headers.length; idx++) {
      if (this._stopRequested) break;
      const header = headers[idx];
      const binBlock = binaryBlocks[idx];

      try {
        // Parse the block blob → { minerTx, protocolTx, txHashes, header: {...} }
        const blockBlob = binBlock.block instanceof Uint8Array
          ? binBlock.block
          : new Uint8Array(binBlock.block);
        const parsed = parseBlock(blockBlob);

        // Use tx hashes from block header (reliable) instead of computing from blob
        // (Salvium v3 tx hashing differs from Monero v2 — blob-based hash is wrong)
        const minerTxHash = header.miner_tx_hash
          || this._computeTxHashFromBlob(blockBlob, parsed.minerTx);
        const protocolTxHash = header.protocol_tx_hash
          || this._computeTxHashFromBlob(blockBlob, parsed.protocolTx);

        // Process miner_tx (coinbase)
        if (parsed.minerTx && minerTxHash) {
          await this._processParsedTransaction(
            parsed.minerTx, minerTxHash, header,
            { isMinerTx: true, isProtocolTx: false }
          );
        }

        // Process protocol_tx
        if (parsed.protocolTx && protocolTxHash) {
          await this._processParsedTransaction(
            parsed.protocolTx, protocolTxHash, header,
            { isMinerTx: false, isProtocolTx: true }
          );
        }

        // Process regular transactions (blobs included in binary response)
        const txBlobs = binBlock.txs || [];
        for (let ti = 0; ti < txBlobs.length; ti++) {
          const txBlobBytes = txBlobs[ti] instanceof Uint8Array
            ? txBlobs[ti]
            : new Uint8Array(txBlobs[ti]);
          const tx = parseTransaction(txBlobBytes);
          // tx_hashes from the block tell us the hash for each regular tx
          const txHashBytes = parsed.txHashes[ti];
          const txHash = txHashBytes ? bytesToHex(txHashBytes) : null;
          if (tx && txHash) {
            await this._processParsedTransaction(
              tx, txHash, header,
              { isMinerTx: false, isProtocolTx: false }
            );
          }
        }

        // Emit new block event
        this._emit('newBlock', {
          height: header.height,
          hash: header.hash,
          timestamp: header.timestamp,
          txCount: txBlobs.length,
          hasMinerTx: !!parsed.minerTx,
          hasProtocolTx: !!parsed.protocolTx
        });

      } catch (e) {
        // If binary parsing fails for a block, log and continue
        console.error(`Binary parse failed at height ${header.height}: ${e.message}`);
      }

      await this.storage.putBlockHash(header.height, header.hash);
      this.currentHeight = header.height + 1;
      this._emit('syncProgress', this.getProgress());

      // Yield to event loop every 5 blocks to prevent UI freeze on mobile
      if (idx % 5 === 4) {
        await new Promise(r => setTimeout(r, 0));
      }
    }
  }

  /**
   * Compute transaction hash from a parsed tx that came from a binary blob.
   *
   * For v2+ RCTTypeNull (coinbase/protocol): uses the 3-hash scheme
   *   hash = keccak256(prefix_hash || rct_base_hash || prunable_hash)
   * where rct_base_hash and prunable_hash are constants for type null.
   *
   * For v1: hash = keccak256(full blob)
   * @private
   */
  _computeTxHashFromBlob(blockBlob, parsedTx) {
    if (!parsedTx?._bytesRead) return null;

    const version = parsedTx.prefix?.version ?? 1;
    const rctType = parsedTx.rct?.type ?? 0;

    // _blockOffset is set by parseBlock; for standalone tx blobs it's 0
    const txStart = parsedTx._blockOffset ?? 0;
    const prefixEnd = parsedTx._prefixEndOffset ?? parsedTx._bytesRead;

    // For v1 transactions: hash = keccak256(full tx blob)
    if (version < 2) {
      try {
        const txBytes = blockBlob.slice(txStart, txStart + parsedTx._bytesRead);
        const hash = cnFastHash(txBytes);
        return bytesToHex(hash instanceof Uint8Array ? hash : hexToBytes(hash));
      } catch (e) {
        return null;
      }
    }

    // For v2+ with RCTTypeNull (coinbase, protocol):
    // prefix_hash = keccak256(raw prefix bytes from blob)
    // rct_base_hash = keccak256([0x00])
    // prunable_hash = keccak256([])
    // tx_hash = keccak256(prefix_hash || rct_base_hash || prunable_hash)
    if (rctType === 0) {
      try {
        const prefixBytes = blockBlob.slice(txStart, txStart + prefixEnd);
        const prefixHash = cnFastHash(prefixBytes);

        const rctBaseHash = cnFastHash(new Uint8Array([0x00]));
        const prunableHash = cnFastHash(new Uint8Array(0));

        const combined = new Uint8Array(96);
        combined.set(prefixHash instanceof Uint8Array ? prefixHash : hexToBytes(prefixHash), 0);
        combined.set(rctBaseHash instanceof Uint8Array ? rctBaseHash : hexToBytes(rctBaseHash), 32);
        combined.set(prunableHash instanceof Uint8Array ? prunableHash : hexToBytes(prunableHash), 64);
        const hash = cnFastHash(combined);
        return bytesToHex(hash instanceof Uint8Array ? hash : hexToBytes(hash));
      } catch (e) {
        return null;
      }
    }

    // For non-null RCT types, we'd need to split rct_base and rct_prunable.
    // Skip — these won't appear in miner_tx/protocol_tx.
    return null;
  }

  /**
   * Fallback: parallel JSON fetch + bulk tx fetch.
   * Used when binary endpoint is unavailable.
   * @private
   */
  async _syncBatchJsonFallback(headers) {
    // Parallel-fetch all block data
    const blockDataArr = new Array(headers.length);
    for (let i = 0; i < headers.length; i += FETCH_CONCURRENCY) {
      const chunk = headers.slice(i, Math.min(i + FETCH_CONCURRENCY, headers.length));
      const results = await Promise.all(
        chunk.map(h => this.daemon.getBlock({ height: h.height }))
      );
      for (let j = 0; j < results.length; j++) {
        blockDataArr[i + j] = results[j];
      }
    }

    // Parse block JSONs, collect all regular tx hashes
    const parsedBlocks = new Array(headers.length);
    const allTxHashes = [];

    for (let idx = 0; idx < headers.length; idx++) {
      const blockResp = blockDataArr[idx];
      if (!blockResp?.success) {
        parsedBlocks[idx] = null;
        continue;
      }
      const block = blockResp.result;
      let blockJson = null;
      if (block.json) {
        try { blockJson = JSON.parse(block.json); } catch (e) { /* skip */ }
      }
      parsedBlocks[idx] = { block, blockJson };

      const txHashes = blockJson?.tx_hashes || [];
      for (const hash of txHashes) {
        allTxHashes.push(hash);
      }
    }

    // Bulk-fetch all regular transactions in one call
    const txDataMap = new Map();
    if (allTxHashes.length > 0) {
      const txsResponse = await this.daemon.getTransactions(allTxHashes, {
        decode_as_json: true
      });
      if (txsResponse.success && txsResponse.result.txs) {
        for (const txData of txsResponse.result.txs) {
          txDataMap.set(txData.tx_hash, txData);
        }
      }
    }

    // Process blocks sequentially with pre-fetched data
    for (let idx = 0; idx < headers.length; idx++) {
      if (this._stopRequested) break;
      const header = headers[idx];
      const parsed = parsedBlocks[idx];

      if (!parsed) {
        throw new Error(`Failed to get block ${header.height}`);
      }

      await this._processBlockPrefetched(header, parsed.block, parsed.blockJson, txDataMap);
      await this.storage.putBlockHash(header.height, header.hash);
      this.currentHeight = header.height + 1;
      this._emit('syncProgress', this.getProgress());

      // Yield to event loop every 5 blocks to prevent UI freeze on mobile
      if (idx % 5 === 4) {
        await new Promise(r => setTimeout(r, 0));
      }
    }
  }

  /**
   * Adjust batch size based on per-block throughput trend.
   *
   * Tracks ms/block across batches:
   * - If per-block time dropped (faster): scale up aggressively
   * - If per-block time more than doubled (slower): scale back ~30%
   * - If per-block time rose modestly: scale back gently
   * - If roughly stable: nudge up slightly
   *
   * @private
   */
  _adjustBatchSize(batchStartTime, blocksProcessed) {
    const elapsed = Date.now() - batchStartTime;
    const msPerBlock = blocksProcessed > 0 ? elapsed / blocksProcessed : elapsed;

    const prev = this._lastMsPerBlock;
    let newSize = this.batchSize;

    if (prev > 0) {
      const ratio = msPerBlock / prev;

      if (ratio > 2.0) {
        // Processing time more than doubled — scale back hard
        newSize = Math.round(this.batchSize * 0.5);
      } else if (ratio > 1.3) {
        // Slowed down moderately — scale back gently
        newSize = Math.round(this.batchSize * 0.75);
      } else if (ratio < 0.5) {
        // Processing time dropped by more than half — scale up aggressively
        newSize = Math.round(this.batchSize * 2.0);
      } else if (ratio < 0.8) {
        // Getting faster — scale up
        newSize = Math.round(this.batchSize * 1.5);
      } else {
        // Stable — nudge up 10%
        newSize = Math.round(this.batchSize * 1.1);
      }
    } else {
      // First batch — if it was fast, double; otherwise keep
      if (msPerBlock < 50) {
        newSize = Math.round(this.batchSize * 2.0);
      }
    }

    this.batchSize = Math.max(MIN_BATCH_SIZE, Math.min(MAX_BATCH_SIZE, newSize));
    this._lastMsPerBlock = msPerBlock;
    this._lastBatchBlocks = blocksProcessed;

    this._emit('batchComplete', {
      elapsed,
      batchSize: this.batchSize,
      blocksProcessed,
      msPerBlock: Math.round(msPerBlock),
      blocksPerSec: blocksProcessed / (elapsed / 1000)
    });
  }

  /**
   * Process a single block using pre-fetched data (no RPC calls).
   * @private
   * @param {Object} header - Block header
   * @param {Object} block - Pre-fetched block RPC result
   * @param {Object|null} blockJson - Pre-parsed block JSON
   * @param {Map} txDataMap - Map of txHash → txData (pre-fetched regular txs)
   */
  async _processBlockPrefetched(header, block, blockJson, txDataMap) {

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

    // Process regular transactions from pre-fetched map
    const txHashes = blockJson?.tx_hashes || [];
    for (const txHash of txHashes) {
      const txData = txDataMap.get(txHash);
      if (!txData) continue;

      if (txData.as_hex) {
        await this._processTransaction(txData, header, { isMinerTx: false, isProtocolTx: false });
      } else if (txData.as_json) {
        const txJson = typeof txData.as_json === 'string' ? JSON.parse(txData.as_json) : txData.as_json;
        await this._processEmbeddedTransaction(txJson, txData.tx_hash, header, { isMinerTx: false, isProtocolTx: false });
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
   * Process a transaction already in parsed format (from parseTransaction).
   * Used by the binary fetch path — no JSON conversion needed.
   * @private
   * @param {Object} tx - Parsed transaction (from parseTransaction or parseBlock)
   * @param {string} txHash - Transaction hash (hex)
   * @param {Object} header - Block header
   * @param {Object} options - { isMinerTx, isProtocolTx }
   */
  async _processParsedTransaction(tx, txHash, header, options = {}) {
    const { isMinerTx = false, isProtocolTx = false } = options;

    const existing = await this.storage.getTransaction(txHash);
    if (existing && existing.isConfirmed) return;

    try {
      const txPubKey = extractTxPubKey(tx);
      const paymentIdObj = extractPaymentId(tx);
      const paymentId = paymentIdObj && paymentIdObj.id ? bytesToHex(paymentIdObj.id) : null;
      const txType = isMinerTx ? TX_TYPE.MINER : (isProtocolTx ? TX_TYPE.PROTOCOL : this._getTxType(tx));

      const ownedOutputs = await this._scanOutputs(tx, txHash, txPubKey, header, txType);
      const spentOutputs = isProtocolTx ? await this._checkSpentOutputs(tx, txHash, header) :
        (!isMinerTx ? await this._checkSpentOutputs(tx, txHash, header) : []);

      if (ownedOutputs.length === 0 && spentOutputs.length === 0) return;

      let incomingAmount = 0n;
      let outgoingAmount = 0n;
      for (const output of ownedOutputs) incomingAmount += output.amount;
      for (const spent of spentOutputs) outgoingAmount += spent.amount;

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
        fee: (isMinerTx || isProtocolTx) ? 0n : this._safeBigInt(tx.rct?.txnFee),
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

      if (ownedOutputs.length > 0) {
        this._emit('outputReceived', {
          txHash, outputs: ownedOutputs, blockHeight: header.height
        });
      }
      if (spentOutputs.length > 0) {
        this._emit('outputSpent', {
          txHash, outputs: spentOutputs, blockHeight: header.height
        });
      }
    } catch (error) {
      console.error(`Error processing tx ${txHash}: ${error.message}`);
    }
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


    // Check if we already have this transaction
    const existing = await this.storage.getTransaction(txHash);
    if (existing && existing.isConfirmed) {
      return; // Already processed
    }

    try {
      // Convert JSON structure to match our parsed transaction format
      const tx = this._convertJsonToTx(txJson);
      const txPubKey = extractTxPubKey(tx);
      const paymentIdObj = extractPaymentId(tx);
      const paymentId = paymentIdObj && paymentIdObj.id ? bytesToHex(paymentIdObj.id) : null;


      // Determine transaction type
      const txType = isMinerTx ? TX_TYPE.MINER : (isProtocolTx ? TX_TYPE.PROTOCOL : this._getTxType(tx));

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
        // target.key can be a string (plain key) or object {key, asset_type, unlock_time}
        // The latter appears in genesis/pre-tagged_key blocks
        const keyVal = typeof target.key === 'object' ? target.key.key : target.key;
        const assetType = typeof target.key === 'object' ? (target.key.asset_type || 'SAL') : 'SAL';
        const unlockTime = typeof target.key === 'object' ? (target.key.unlock_time || 0) : 0;
        return {
          amount: this._safeBigInt(out.amount),
          type: 0x02, // TXOUT_TYPE.KEY
          key: hexToBytes(keyVal),
          assetType,
          unlockTime
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
      // p_r is the mask difference commitment in Salvium RCT (NOT the CARROT ephemeral pubkey D_e).
      // D_e is stored as txPubKey in tx_extra (tag 0x01).
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
      return [];
    }

    // Parse the extra bytes to extract fields
    const extraBytes = new Uint8Array(extraArray);
    const parsed = [];

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


    // Check if we already have this transaction
    const existing = await this.storage.getTransaction(txHash);
    if (existing && existing.isConfirmed) {
      return; // Already processed
    }

    try {
      // Parse transaction
      const tx = parseTransaction(hexToBytes(txBlob));
      const txPubKey = extractTxPubKey(tx);
      const paymentIdObj = extractPaymentId(tx);
      const paymentId = paymentIdObj && paymentIdObj.id ? bytesToHex(paymentIdObj.id) : null;


      // Determine transaction type (Salvium-specific)
      // For miner_tx and protocol_tx, use the type from the prefix
      // Otherwise use our helper method
      const txType = isMinerTx ? TX_TYPE.MINER : (isProtocolTx ? TX_TYPE.PROTOCOL : this._getTxType(tx));

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

    // Pre-compute key derivation once per tx (expensive Ed25519 point multiply)
    // Derivation only depends on txPubKey + viewSecretKey, not output index
    let cnDerivation = null;
    if (txPubKey && this.keys?.viewSecretKey) {
      try {
        cnDerivation = generateKeyDerivation(txPubKey, this.keys.viewSecretKey);
      } catch (e) {
        // Invalid txPubKey — skip CN scanning for this tx
      }
    }

    for (let i = 0; i < outputs.length; i++) {
      const output = outputs[i];
      const outputPubKey = this._extractOutputPubKey(output);

      if (!outputPubKey) continue;

      let scanResult = null;

      // Detect CARROT vs CryptoNote output
      // CARROT outputs have: 3-byte view tag, enote ephemeral pubkey
      const isCarrotOutput = this._isCarrotOutput(output);

      if (isCarrotOutput && this.carrotKeys) {
        // CARROT scanning - pass txPubKey (D_e) from tx_extra
        scanResult = await this._scanCarrotOutput(output, i, tx, txHash, txPubKey, header);
      } else if (cnDerivation) {
        // CryptoNote (legacy) scanning with pre-computed derivation
        // Skip if output is CARROT type but we couldn't scan it (missing carrotKeys or failed scan)
        if (output.type === 0x04) {
          continue; // CARROT output - don't try CN scanning
        }
        try {
          scanResult = await this._scanCNOutput(output, i, tx, txHash, txPubKey, header, cnDerivation);
        } catch (e) {
          // Key derivation can fail for malformed outputs - skip silently
          continue;
        }
      }

      if (scanResult) {
        // Create output record
        // Commitment: prefer scanResult.commitment (computed from mask/amount for CARROT coinbase),
        // then fall back to tx.rct.outPk[i] for standard RCT outputs
        let commitment = null;
        if (scanResult.commitment) {
          commitment = typeof scanResult.commitment === 'string'
            ? scanResult.commitment
            : bytesToHex(scanResult.commitment);
        } else if (tx.rct?.outPk?.[i]) {
          commitment = bytesToHex(tx.rct.outPk[i]);
        }

        const walletOutput = new WalletOutput({
          keyImage: scanResult.keyImage,
          publicKey: bytesToHex(outputPubKey),
          txHash,
          outputIndex: i,
          globalIndex: null,
          blockHeight: header.height,
          blockTimestamp: header.timestamp,
          amount: scanResult.amount,
          commitment,
          mask: scanResult.mask ? bytesToHex(scanResult.mask) : null,
          subaddressIndex: scanResult.subaddressIndex,
          unlockTime: tx.prefix?.unlockTime || 0n,
          txType,
          txPubKey: txPubKey ? bytesToHex(txPubKey) : null,
          isCarrot: scanResult.isCarrot || false,
          carrotEphemeralPubkey: scanResult.carrotEphemeralPubkey || null,
          carrotSharedSecret: scanResult.carrotSharedSecret || null,
          carrotEnoteType: scanResult.enoteType ?? null,
          assetType: output.assetType || 'SAL'
        });

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
    } else {
      // Coinbase transaction: input_context = 'C' || block_height
      inputContext = makeInputContextCoinbase(header.height);
    }

    // Get amount commitment from RingCT
    let amountCommitment = tx.rct?.outPk?.[outputIndex]
      ? (typeof tx.rct.outPk[outputIndex] === 'string'
          ? hexToBytes(tx.rct.outPk[outputIndex])
          : tx.rct.outPk[outputIndex])
      : null;

    // For coinbase (RCTTypeNull), compute commitment = 1*G + amount*H
    // This matches C++ rct::zeroCommit() used during coinbase scanning.
    // Both CryptoNote and CARROT coinbase outputs need this commitment —
    // CARROT uses it for recoverAddressSpendPubkey (spend pubkey recovery).
    const rctType = tx.rct?.type ?? 0;
    const isCarrotOutput = output.type === 0x04 || output.target?.type === 0x04;
    if (!amountCommitment && rctType === 0 && output.amount !== undefined) {
      const clearAmount = typeof output.amount === 'bigint'
        ? output.amount
        : BigInt(output.amount || 0);
      // Blinding factor = 1 (scalar 1 in LE)
      const scalarOne = new Uint8Array(32);
      scalarOne[0] = 1;
      amountCommitment = pedersonCommit(clearAmount, scalarOne);
    }

    // For CARROT outputs, the enote ephemeral pubkey (D_e) comes from:
    // 1. For SalviumOne (RCT type 9): txPubKey in tx_extra (D_e = d_e * B, X25519)
    // 2. For SalviumZero (RCT type 8): txPubKey in tx_extra
    //    NOTE: p_r is the mask difference commitment (for RCT balance equation),
    //    NOT the CARROT ephemeral pubkey. D_e is always stored as txPubKey.
    // 3. For older types: additional_pubkeys in tx_extra (per-output) or main txPubKey
    // Note: rctType already defined above
    let enoteEphemeralPubkey = null;

    if (rctType >= 8 && txPubKey) {
      // CARROT (SalviumZero=8 or SalviumOne=9): D_e is txPubKey from tx_extra
      enoteEphemeralPubkey = typeof txPubKey === 'string'
        ? hexToBytes(txPubKey)
        : txPubKey;
    } else {
      // Fallback: check additional_pubkeys or main tx pubkey
      const additionalPubKeys = extractAdditionalPubKeys(tx);
      enoteEphemeralPubkey = additionalPubKeys[outputIndex];
      if (enoteEphemeralPubkey) {
        enoteEphemeralPubkey = typeof enoteEphemeralPubkey === 'string'
          ? hexToBytes(enoteEphemeralPubkey)
          : enoteEphemeralPubkey;
      } else {
        // Fallback to main tx pubkey (for coinbase/legacy)
        enoteEphemeralPubkey = txPubKey;
      }
    }

    const outputForScan = {
      key: this._extractOutputPubKey(output),
      viewTag: output.viewTag,
      enoteEphemeralPubkey,
      encryptedAmount: tx.rct?.ecdhInfo?.[outputIndex]?.amount
    };

    // For coinbase (rctType=0), pass clear-text amount so mask derivation uses the real amount
    // (coinbase has no ecdhInfo, so encrypted amount decryption would return 0)
    const scanOptions = {};
    if (rctType === 0 && output.amount !== undefined) {
      scanOptions.clearTextAmount = typeof output.amount === 'bigint'
        ? output.amount
        : BigInt(output.amount || 0);
    }

    // Scan with CARROT algorithm — prefer native Rust scanner (single FFI call)
    // over JS scanner (many individual crypto ops).
    const backend = getCryptoBackend();
    const hasNativeScanner = typeof backend.scanCarrotOutput === 'function';
    let result;
    let isReturnOutput = false;
    try {
      if (hasNativeScanner) {
        // Native Rust scanner: extract raw fields and pass directly
        const Ko = typeof outputForScan.key === 'string' ? hexToBytes(outputForScan.key) : outputForScan.key;
        const vtBytes = typeof outputForScan.viewTag === 'string' ? hexToBytes(outputForScan.viewTag) : outputForScan.viewTag;
        const De = typeof outputForScan.enoteEphemeralPubkey === 'string'
          ? hexToBytes(outputForScan.enoteEphemeralPubkey) : outputForScan.enoteEphemeralPubkey;
        const encAmt = outputForScan.encryptedAmount
          ? (typeof outputForScan.encryptedAmount === 'string'
              ? hexToBytes(outputForScan.encryptedAmount) : outputForScan.encryptedAmount)
          : null;
        result = backend.scanCarrotOutput(
          Ko, vtBytes, De, encAmt,
          amountCommitment,
          this.carrotKeys.viewIncomingKey,
          this.carrotKeys.accountSpendPubkey,
          inputContext,
          this.carrotSubaddresses,
          scanOptions.clearTextAmount
        );
      } else {
        // JS fallback scanner
        result = scanCarrotOutput(
          outputForScan,
          this.carrotKeys.viewIncomingKey,
          this.carrotKeys.accountSpendPubkey,
          inputContext,
          this.carrotSubaddresses,
          amountCommitment,
          scanOptions
        );
      }
    } catch (e) {
      // Missing required fields in CARROT output - skip this output
      return null;
    }

    // If standard scan fails, try internal (self-send) path using s_view_balance.
    // This detects change outputs from our own STAKE/send transactions.
    // Only for regular transactions with key images (not coinbase/protocol_tx).
    if (!result && this.carrotKeys.viewBalanceSecret && firstKi) {
      try {
        if (hasNativeScanner) {
          const Ko = typeof outputForScan.key === 'string' ? hexToBytes(outputForScan.key) : outputForScan.key;
          const vtBytes = typeof outputForScan.viewTag === 'string' ? hexToBytes(outputForScan.viewTag) : outputForScan.viewTag;
          const De = typeof outputForScan.enoteEphemeralPubkey === 'string'
            ? hexToBytes(outputForScan.enoteEphemeralPubkey) : outputForScan.enoteEphemeralPubkey;
          const encAmt = outputForScan.encryptedAmount
            ? (typeof outputForScan.encryptedAmount === 'string'
                ? hexToBytes(outputForScan.encryptedAmount) : outputForScan.encryptedAmount)
            : null;
          result = backend.scanCarrotInternalOutput(
            Ko, vtBytes, De, encAmt,
            amountCommitment,
            this.carrotKeys.viewBalanceSecret,
            this.carrotKeys.accountSpendPubkey,
            inputContext,
            this.carrotSubaddresses,
            scanOptions.clearTextAmount
          );
        } else {
          result = scanCarrotInternalOutput(
            outputForScan,
            this.carrotKeys.viewBalanceSecret,
            this.carrotKeys.accountSpendPubkey,
            inputContext,
            this.carrotSubaddresses,
            amountCommitment,
            scanOptions
          );
        }

        // If we detected a self-send, compute the expected return address.
        // When this wallet's STAKE tx unlocks, the return output will appear
        // in a protocol_tx with Ko = K_r = k_return*G + Ko_selfsend.
        if (result && this.carrotKeys.viewBalanceSecret) {
          const Ko = typeof outputForScan.key === 'string'
            ? hexToBytes(outputForScan.key) : outputForScan.key;
          try {
            const ret = computeReturnAddress(
              this.carrotKeys.viewBalanceSecret,
              inputContext,
              Ko
            );
            this._returnOutputMap.set(ret.returnAddressHex, {
              inputContext,
              originalKo: Ko,
              kReturn: ret.kReturn
            });
          } catch (_e) {
            // Non-fatal: return address computation failed
          }
        }
      } catch (_e) {
        // Internal scan failed - continue
      }
    }

    // If both standard and internal scans fail, check the return output map.
    // Protocol_tx return outputs have Ko = K_r which we pre-computed from self-send detection.
    if (!result && !firstKi) {
      const outputKey = this._extractOutputPubKey(output);
      if (outputKey) {
        const koHex = bytesToHex(outputKey);
        if (this._returnOutputMap.has(koHex)) {
          isReturnOutput = true;
          // Protocol_tx has cleartext amounts (rctType=0) — use it directly
          const amount = typeof output.amount === 'bigint'
            ? output.amount
            : BigInt(output.amount || 0);

          // Blinding factor = 1 for coinbase-like outputs
          const SCALAR_ONE = hexToBytes('0100000000000000000000000000000000000000000000000000000000000000');

          result = {
            owned: true,
            onetimeAddress: koHex,
            addressSpendPubkey: bytesToHex(
              typeof this.carrotKeys.accountSpendPubkey === 'string'
                ? hexToBytes(this.carrotKeys.accountSpendPubkey)
                : this.carrotKeys.accountSpendPubkey
            ),
            sharedSecret: null,
            viewTag: null,
            amount,
            mask: SCALAR_ONE,
            enoteType: 0,
            subaddressIndex: { major: 0, minor: 0 },
            isMainAddress: true,
            isCarrot: true,
            isReturn: true
          };
        }
      }
    }

    if (!result) {
      return null;
    }

    // For coinbase (rctType=0): the on-chain commitment is 1*G + amount*H (same as CryptoNote).
    // The CARROT scan derives a CARROT mask, but for coinbase the actual blinding factor is 1.
    // Override mask to scalar 1 so the ring signature uses the correct blinding factor.
    // For non-coinbase: the scan's CARROT mask matches the outPk commitment, so no override needed.
    if (rctType === 0 && result.mask) {
      const SCALAR_ONE = '0100000000000000000000000000000000000000000000000000000000000000';
      result.mask = hexToBytes(SCALAR_ONE);
      // amountCommitment is already pedersenCommit(amount, scalar_1) from line 1132
    } else if (!amountCommitment && result.mask && result.amount !== undefined) {
      // Non-coinbase without outPk: compute commitment from CARROT mask
      const maskBytes = typeof result.mask === 'string' ? hexToBytes(result.mask) : result.mask;
      amountCommitment = pedersonCommit(BigInt(result.amount), maskBytes);
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

    // For coinbase (RCTTypeNull), amount is clear-text on the output, not encrypted
    let amount = result.amount;
    if (amount === 0n && rctType === 0 && output.amount !== undefined) {
      amount = typeof output.amount === 'bigint'
        ? output.amount
        : BigInt(output.amount || 0);
    }

    return {
      amount,
      mask: result.mask,
      enoteType: result.enoteType,  // 0=PAYMENT, 1=CHANGE (from try-both logic)
      commitment: amountCommitment,  // Computed commitment for spending
      subaddressIndex: result.subaddressIndex,
      keyImage,
      isCarrot: true,
      // CARROT-specific data needed for spending
      carrotEphemeralPubkey: enoteEphemeralPubkey ? bytesToHex(enoteEphemeralPubkey) : null,
      carrotSharedSecret: result.sharedSecret  // Already hex from scanCarrotOutput
    };
  }

  /**
   * Scan a CryptoNote (legacy) output for ownership
   * Uses subaddress map lookup (matches C++ wallet behavior)
   * @private
   */
  async _scanCNOutput(output, outputIndex, tx, txHash, txPubKey, header, precomputedDerivation) {

    const outputPubKey = this._extractOutputPubKey(output);
    if (!outputPubKey) {
      return null;
    }

    // Use pre-computed derivation if available, otherwise compute per-output
    const derivation = precomputedDerivation || generateKeyDerivation(txPubKey, this.keys.viewSecretKey);
    if (!derivation) {
      return null;
    }

    // Check view tag FIRST (if available) for fast rejection
    if (output.viewTag !== undefined) {
      const expectedViewTag = deriveViewTag(derivation, outputIndex);
      if (output.viewTag !== expectedViewTag) {
        return null; // Not our output - skip expensive operations
      }
    }

    // Derive the spend public key from the output (reverse derivation)
    // P' = outputKey - H_s(D || index) * G
    // This gives us the spend pubkey that was used to create this output
    const derivedSpendPubKey = deriveSubaddressPublicKey(outputPubKey, derivation, outputIndex);
    if (!derivedSpendPubKey) {
      return null;
    }

    // Check main address first with binary comparison (avoids hex allocation for 99%+ of outputs)
    let subaddressIndex = null;
    if (this._mainSpendPubKeyBytes &&
        derivedSpendPubKey.length === this._mainSpendPubKeyBytes.length &&
        derivedSpendPubKey.every((b, i) => b === this._mainSpendPubKeyBytes[i])) {
      subaddressIndex = { major: 0, minor: 0 };
    } else if (this.subaddresses) {
      // Fall back to hex map lookup only for non-main-address outputs
      const derivedSpendPubKeyHex = bytesToHex(derivedSpendPubKey);
      if (this.subaddresses.has(derivedSpendPubKeyHex)) {
        subaddressIndex = this.subaddresses.get(derivedSpendPubKeyHex);
      }
    }

    if (!subaddressIndex) {
      return null; // Not our output
    }

    // Output is ours! Decrypt amount
    let amount = 0n;
    let mask = null;

    const rctType = tx.rct?.type ?? 0;
    if (rctType === 0) {
      // RCTTypeNull (coinbase): amount is in clear text on the output
      amount = typeof output.amount === 'bigint' ? output.amount : BigInt(output.amount || 0);
    } else {
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
    }

    // Generate key image if we have spend key
    // For subaddresses, need to derive the subaddress secret key first:
    // subaddr_secret_key = spend_secret_key + H_s("SubAddr\0" || view_secret_key || major || minor)
    let keyImage = null;
    if (this.keys.spendSecretKey && this.keys.viewSecretKey) {
      try {
        // For subaddresses (not main address), compute the subaddress secret key
        // Always convert to bytes for deriveSecretKey
        let baseSpendSecretKey = typeof this.keys.spendSecretKey === 'string'
          ? hexToBytes(this.keys.spendSecretKey)
          : this.keys.spendSecretKey;
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
    this._emit('storageCleared', { height: fromHeight });

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
