/**
 * Wallet Storage Layer
 *
 * Provides persistent storage for wallet data:
 * - Outputs (UTXOs) with spending status
 * - Transaction history
 * - Key images (spent tracking)
 * - Sync state
 *
 * Supports multiple backends:
 * - Memory (default, for testing)
 * - IndexedDB (browser)
 * - Custom (bring your own storage)
 *
 * @module wallet-store
 */

import { bytesToHex, hexToBytes } from './address.js';
import { areAssetTypesEquivalent } from './consensus.js';

// ============================================================================
// STORAGE INTERFACE
// ============================================================================

/**
 * Abstract storage interface
 * Implement this for custom storage backends
 */
export class WalletStorage {
  /**
   * Initialize storage
   * @returns {Promise<void>}
   */
  async open() {
    throw new Error('Not implemented');
  }

  /**
   * Close storage
   * @returns {Promise<void>}
   */
  async close() {
    throw new Error('Not implemented');
  }

  /**
   * Clear all data
   * @returns {Promise<void>}
   */
  async clear() {
    throw new Error('Not implemented');
  }

  // Output operations
  async putOutput(output) { throw new Error('Not implemented'); }
  async getOutput(keyImage) { throw new Error('Not implemented'); }
  async getOutputs(query) { throw new Error('Not implemented'); }
  async markOutputSpent(keyImage, spendingTxHash) { throw new Error('Not implemented'); }

  // Transaction operations
  async putTransaction(tx) { throw new Error('Not implemented'); }
  async getTransaction(txHash) { throw new Error('Not implemented'); }
  async getTransactions(query) { throw new Error('Not implemented'); }

  // Key image operations
  async putKeyImage(keyImage, outputRef) { throw new Error('Not implemented'); }
  async isKeyImageSpent(keyImage) { throw new Error('Not implemented'); }
  async getSpentKeyImages() { throw new Error('Not implemented'); }

  // Sync state
  async getSyncHeight() { throw new Error('Not implemented'); }
  async setSyncHeight(height) { throw new Error('Not implemented'); }
  async getState(key) { throw new Error('Not implemented'); }
  async setState(key, value) { throw new Error('Not implemented'); }

  // Block hash tracking (for reorg detection)
  async putBlockHash(height, hash) { throw new Error('Not implemented'); }
  async getBlockHash(height) { throw new Error('Not implemented'); }
  async deleteBlockHashesAbove(height) { throw new Error('Not implemented'); }

  // Reorg rollback operations
  async deleteOutputsAbove(height) { throw new Error('Not implemented'); }
  async deleteTransactionsAbove(height) { throw new Error('Not implemented'); }
  async unspendOutputsAbove(height) { throw new Error('Not implemented'); }
}

// ============================================================================
// OUTPUT MODEL
// ============================================================================

/**
 * Represents a wallet output (UTXO)
 */
export class WalletOutput {
  constructor(data = {}) {
    // Identity
    this.keyImage = data.keyImage || null;          // Key image (hex)
    this.publicKey = data.publicKey || null;        // Output public key (hex)

    // Source transaction
    this.txHash = data.txHash || null;              // Transaction hash
    this.outputIndex = data.outputIndex || 0;       // Output index in transaction
    this.globalIndex = data.globalIndex || null;    // Global output index
    this.assetTypeIndex = data.assetTypeIndex ?? null; // Asset-type-local output index

    // Block info
    this.blockHeight = data.blockHeight || null;    // Block height
    this.blockTimestamp = data.blockTimestamp || null;

    // Amount (for RingCT, this is decrypted amount)
    this.amount = data.amount !== undefined ? BigInt(data.amount) : 0n;
    this.assetType = data.assetType || 'SAL';       // Salvium multi-asset

    // RingCT data
    this.commitment = data.commitment || null;      // Pedersen commitment (hex)
    this.mask = data.mask || null;                  // Commitment mask (hex)

    // Subaddress
    this.subaddressIndex = data.subaddressIndex || { major: 0, minor: 0 };

    // CARROT flag and data
    this.isCarrot = data.isCarrot || false;
    this.carrotEphemeralPubkey = data.carrotEphemeralPubkey || null;  // D_e for CARROT spending
    this.carrotSharedSecret = data.carrotSharedSecret || null;        // s_sr_ctx for CARROT spending
    this.carrotEnoteType = data.carrotEnoteType ?? null;             // 0=PAYMENT, 1=CHANGE (for mask derivation)

    // Spending status
    this.isSpent = data.isSpent || false;
    this.spentHeight = data.spentHeight || null;
    this.spentTxHash = data.spentTxHash || null;

    // Locking
    this.unlockTime = data.unlockTime !== undefined ? BigInt(data.unlockTime) : 0n;

    // Salvium-specific
    this.txType = data.txType || 3;                 // TX_TYPE (default: TRANSFER)

    // TX public key (needed to derive output secret key for spending)
    this.txPubKey = data.txPubKey || null;

    // Frozen (user-controlled)
    this.isFrozen = data.isFrozen || false;

    // Timestamps
    this.createdAt = data.createdAt || Date.now();
    this.updatedAt = data.updatedAt || Date.now();
  }

  /**
   * Check if output is unlocked at given height
   * @param {number} currentHeight - Current blockchain height
   * @param {number} unlockBlocks - Blocks required for unlock (default: 10)
   * @returns {boolean}
   */
  isUnlocked(currentHeight, unlockBlocks = 10) {
    // Coinbase outputs (miner/protocol) set unlock_time to the bare constant
    // CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW (60), NOT height+60.
    // They always require 60 confirmations regardless of the unlock_time value.
    const isCoinbase = this.txType === 'miner' || this.txType === 'protocol'
      || this.txType === 1 || this.txType === 2;
    if (isCoinbase) {
      const MINED_MONEY_UNLOCK_WINDOW = 60;
      return this.blockHeight !== null &&
        (currentHeight - this.blockHeight) >= MINED_MONEY_UNLOCK_WINDOW;
    }

    if (this.unlockTime === 0n) {
      // Standard unlock by confirmations
      return this.blockHeight !== null &&
        (currentHeight - this.blockHeight) >= unlockBlocks;
    }

    if (this.unlockTime < 500000000n) {
      // Unlock time is a block height
      return currentHeight >= Number(this.unlockTime);
    }

    // Unlock time is a Unix timestamp
    return Date.now() / 1000 >= Number(this.unlockTime);
  }

  /**
   * Check if output is spendable
   * @param {number} currentHeight - Current blockchain height
   * @returns {boolean}
   */
  isSpendable(currentHeight) {
    return !this.isSpent &&
           !this.isFrozen &&
           this.isUnlocked(currentHeight) &&
           this.keyImage !== null;
  }

  /**
   * Convert to plain object for storage
   * @returns {Object}
   */
  toJSON() {
    return {
      keyImage: this.keyImage,
      publicKey: this.publicKey,
      txHash: this.txHash,
      outputIndex: this.outputIndex,
      globalIndex: this.globalIndex,
      assetTypeIndex: this.assetTypeIndex,
      blockHeight: this.blockHeight,
      blockTimestamp: this.blockTimestamp,
      amount: this.amount.toString(),
      assetType: this.assetType,
      commitment: this.commitment,
      mask: this.mask,
      subaddressIndex: this.subaddressIndex,
      isSpent: this.isSpent,
      spentHeight: this.spentHeight,
      spentTxHash: this.spentTxHash,
      unlockTime: this.unlockTime.toString(),
      txType: this.txType,
      txPubKey: this.txPubKey,
      isCarrot: this.isCarrot,
      carrotEphemeralPubkey: this.carrotEphemeralPubkey,
      carrotSharedSecret: this.carrotSharedSecret,
      carrotEnoteType: this.carrotEnoteType,
      isFrozen: this.isFrozen,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt
    };
  }

  /**
   * Create from plain object
   * @param {Object} data
   * @returns {WalletOutput}
   */
  static fromJSON(data) {
    return new WalletOutput({
      ...data,
      amount: BigInt(data.amount || 0),
      unlockTime: BigInt(data.unlockTime || 0)
    });
  }
}

// ============================================================================
// TRANSACTION MODEL
// ============================================================================

/**
 * Represents a wallet transaction
 */
export class WalletTransaction {
  constructor(data = {}) {
    // Identity
    this.txHash = data.txHash || null;
    this.txPubKey = data.txPubKey || null;

    // Block info
    this.blockHeight = data.blockHeight || null;
    this.blockTimestamp = data.blockTimestamp || null;
    this.confirmations = data.confirmations || 0;

    // Status
    this.inPool = data.inPool || false;              // In mempool
    this.isFailed = data.isFailed || false;
    this.isConfirmed = data.blockHeight !== null;

    // Direction
    this.isIncoming = data.isIncoming || false;
    this.isOutgoing = data.isOutgoing || false;

    // Amounts (calculated from transfers)
    this.incomingAmount = data.incomingAmount !== undefined ? BigInt(data.incomingAmount) : 0n;
    this.outgoingAmount = data.outgoingAmount !== undefined ? BigInt(data.outgoingAmount) : 0n;
    this.fee = data.fee !== undefined ? BigInt(data.fee) : 0n;

    // Change
    this.changeAmount = data.changeAmount !== undefined ? BigInt(data.changeAmount) : 0n;

    // Transfers (individual movements)
    this.transfers = data.transfers || [];

    // Payment ID
    this.paymentId = data.paymentId || null;

    // Unlock time
    this.unlockTime = data.unlockTime !== undefined ? BigInt(data.unlockTime) : 0n;

    // Salvium-specific
    this.txType = data.txType || 3;                  // TX_TYPE
    this.assetType = data.assetType || 'SAL';
    this.isMinerTx = data.isMinerTx || false;        // Coinbase (block reward)
    this.isProtocolTx = data.isProtocolTx || false;  // Protocol tx (yields, conversions, refunds)

    // Note (user-defined)
    this.note = data.note || '';

    // Timestamps
    this.createdAt = data.createdAt || Date.now();
    this.updatedAt = data.updatedAt || Date.now();
  }

  /**
   * Get net amount (incoming - outgoing - fee)
   * @returns {bigint}
   */
  getNetAmount() {
    return this.incomingAmount - this.outgoingAmount - this.fee;
  }

  /**
   * Convert to plain object for storage
   * @returns {Object}
   */
  toJSON() {
    return {
      txHash: this.txHash,
      txPubKey: this.txPubKey,
      blockHeight: this.blockHeight,
      blockTimestamp: this.blockTimestamp,
      confirmations: this.confirmations,
      inPool: this.inPool,
      isFailed: this.isFailed,
      isConfirmed: this.isConfirmed,
      isIncoming: this.isIncoming,
      isOutgoing: this.isOutgoing,
      incomingAmount: this.incomingAmount.toString(),
      outgoingAmount: this.outgoingAmount.toString(),
      fee: this.fee.toString(),
      changeAmount: this.changeAmount.toString(),
      transfers: this.transfers,
      paymentId: this.paymentId,
      unlockTime: this.unlockTime.toString(),
      txType: this.txType,
      assetType: this.assetType,
      note: this.note,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt
    };
  }

  /**
   * Create from plain object
   * @param {Object} data
   * @returns {WalletTransaction}
   */
  static fromJSON(data) {
    return new WalletTransaction({
      ...data,
      incomingAmount: BigInt(data.incomingAmount || 0),
      outgoingAmount: BigInt(data.outgoingAmount || 0),
      fee: BigInt(data.fee || 0),
      changeAmount: BigInt(data.changeAmount || 0),
      unlockTime: BigInt(data.unlockTime || 0)
    });
  }
}

// ============================================================================
// MEMORY STORAGE (Default)
// ============================================================================

/**
 * In-memory storage implementation
 * Good for testing and short-lived sessions
 */
export class MemoryStorage extends WalletStorage {
  constructor() {
    super();
    this._outputs = new Map();        // keyImage -> WalletOutput
    this._transactions = new Map();   // txHash -> WalletTransaction
    this._keyImages = new Map();      // keyImage -> { txHash, outputIndex }
    this._spentKeyImages = new Set(); // Set of spent key images
    this._state = new Map();          // Generic key-value state
    this._blockHashes = new Map();    // height -> blockHash
    this._blockHashRetention = 200;   // Only keep last N block hashes (for reorg detection)
    this._syncHeight = 0;
    this._isOpen = false;
  }

  async open() {
    this._isOpen = true;
  }

  async close() {
    this._isOpen = false;
  }

  async clear() {
    this._outputs.clear();
    this._transactions.clear();
    this._keyImages.clear();
    this._spentKeyImages.clear();
    this._state.clear();
    this._blockHashes.clear();
    this._syncHeight = 0;
  }

  // Output operations
  async putOutput(output) {
    const wo = output instanceof WalletOutput ? output : new WalletOutput(output);
    wo.updatedAt = Date.now();
    this._outputs.set(wo.keyImage, wo);

    // Track key image
    if (wo.keyImage) {
      this._keyImages.set(wo.keyImage, {
        txHash: wo.txHash,
        outputIndex: wo.outputIndex
      });
    }

    return wo;
  }

  async getOutput(keyImage) {
    const output = this._outputs.get(keyImage);
    return output ? WalletOutput.fromJSON(output.toJSON()) : null;
  }

  async getOutputs(query = {}) {
    const results = [];
    for (const output of this._outputs.values()) {
      if (this._matchesQuery(output, query)) {
        results.push(WalletOutput.fromJSON(output.toJSON()));
      }
    }
    return results;
  }

  async markOutputSpent(keyImage, spendingTxHash, spentHeight = null) {
    const output = this._outputs.get(keyImage);
    if (output) {
      output.isSpent = true;
      output.spentTxHash = spendingTxHash;
      output.spentHeight = spentHeight;
      output.updatedAt = Date.now();
      this._spentKeyImages.add(keyImage);
    }
  }

  // Transaction operations
  async putTransaction(tx) {
    const wt = tx instanceof WalletTransaction ? tx : new WalletTransaction(tx);
    wt.updatedAt = Date.now();
    this._transactions.set(wt.txHash, wt);
    return wt;
  }

  async getTransaction(txHash) {
    const tx = this._transactions.get(txHash);
    return tx ? WalletTransaction.fromJSON(tx.toJSON()) : null;
  }

  async getTransactions(query = {}) {
    const results = [];
    for (const tx of this._transactions.values()) {
      if (this._matchesTxQuery(tx, query)) {
        results.push(WalletTransaction.fromJSON(tx.toJSON()));
      }
    }
    // Sort by block height descending (newest first)
    results.sort((a, b) => (b.blockHeight || 0) - (a.blockHeight || 0));
    return results;
  }

  // Key image operations
  async putKeyImage(keyImage, outputRef) {
    this._keyImages.set(keyImage, outputRef);
  }

  async isKeyImageSpent(keyImage) {
    return this._spentKeyImages.has(keyImage);
  }

  async getSpentKeyImages() {
    return Array.from(this._spentKeyImages);
  }

  // Sync state
  async getSyncHeight() {
    return this._syncHeight;
  }

  async setSyncHeight(height) {
    this._syncHeight = height;
  }

  async getState(key) {
    return this._state.get(key);
  }

  async setState(key, value) {
    this._state.set(key, value);
  }

  // Block hash tracking
  async putBlockHash(height, hash) {
    this._blockHashes.set(height, hash);
    // Prune old block hashes to limit memory usage.
    // Only keep the most recent N hashes (sufficient for reorg detection).
    const cutoff = height - this._blockHashRetention;
    if (cutoff > 0 && this._blockHashes.size > this._blockHashRetention * 1.5) {
      for (const h of this._blockHashes.keys()) {
        if (h < cutoff) this._blockHashes.delete(h);
      }
    }
  }

  async getBlockHash(height) {
    return this._blockHashes.get(height) || null;
  }

  async deleteBlockHashesAbove(height) {
    for (const h of this._blockHashes.keys()) {
      if (h > height) this._blockHashes.delete(h);
    }
  }

  // Reorg rollback operations
  async deleteOutputsAbove(height) {
    for (const [key, output] of this._outputs) {
      if (output.blockHeight !== null && output.blockHeight > height) {
        this._outputs.delete(key);
        this._keyImages.delete(key);
        this._spentKeyImages.delete(key);
      }
    }
  }

  async deleteTransactionsAbove(height) {
    for (const [key, tx] of this._transactions) {
      if (tx.blockHeight !== null && tx.blockHeight > height) {
        this._transactions.delete(key);
      }
    }
  }

  async unspendOutputsAbove(height) {
    for (const output of this._outputs.values()) {
      if (output.isSpent && output.spentHeight !== null && output.spentHeight > height) {
        output.isSpent = false;
        output.spentTxHash = null;
        output.spentHeight = null;
        output.updatedAt = Date.now();
        this._spentKeyImages.delete(output.keyImage);
      }
    }
  }

  // Query helpers
  _matchesQuery(output, query) {
    if (query.isSpent !== undefined && output.isSpent !== query.isSpent) return false;
    if (query.isFrozen !== undefined && output.isFrozen !== query.isFrozen) return false;
    if (query.assetType && !areAssetTypesEquivalent(output.assetType, query.assetType)) return false;
    if (query.txType !== undefined && output.txType !== query.txType) return false;
    if (query.minAmount !== undefined && output.amount < BigInt(query.minAmount)) return false;
    if (query.maxAmount !== undefined && output.amount > BigInt(query.maxAmount)) return false;
    if (query.accountIndex !== undefined && output.subaddressIndex?.major !== query.accountIndex) return false;
    if (query.subaddressIndex !== undefined && output.subaddressIndex?.minor !== query.subaddressIndex) return false;
    return true;
  }

  _matchesTxQuery(tx, query) {
    if (query.isIncoming !== undefined && tx.isIncoming !== query.isIncoming) return false;
    if (query.isOutgoing !== undefined && tx.isOutgoing !== query.isOutgoing) return false;
    if (query.isConfirmed !== undefined && tx.isConfirmed !== query.isConfirmed) return false;
    if (query.inPool !== undefined && tx.inPool !== query.inPool) return false;
    if (query.txType !== undefined && tx.txType !== query.txType) return false;
    if (query.minHeight !== undefined && (tx.blockHeight === null || tx.blockHeight < query.minHeight)) return false;
    if (query.maxHeight !== undefined && (tx.blockHeight === null || tx.blockHeight > query.maxHeight)) return false;
    if (query.txHash && tx.txHash !== query.txHash) return false;
    return true;
  }

  /**
   * Dump all storage state to a plain JSON-serializable object.
   * Useful for persisting MemoryStorage to a file or any key-value store.
   * @returns {Object} Serializable snapshot of all storage data
   */
  dump() {
    return {
      version: 1,
      syncHeight: this._syncHeight,
      outputs: Array.from(this._outputs.values()).map(o => o.toJSON()),
      transactions: Array.from(this._transactions.values()).map(t => t.toJSON()),
      spentKeyImages: Array.from(this._spentKeyImages),
      blockHashes: Object.fromEntries(this._blockHashes),
      state: Object.fromEntries(this._state)
    };
  }

  /**
   * Dump storage state as a JSON string with reduced peak memory.
   * Writes each section separately to avoid building one huge intermediate object.
   * @returns {string} JSON string of all storage data
   */
  dumpJSON() {
    const parts = [];
    parts.push('{"version":1');
    parts.push(`,"syncHeight":${this._syncHeight}`);

    // Outputs - stringify one at a time
    parts.push(',"outputs":[');
    let first = true;
    for (const o of this._outputs.values()) {
      if (!first) parts.push(',');
      parts.push(JSON.stringify(o.toJSON()));
      first = false;
    }
    parts.push(']');

    // Transactions - stringify one at a time
    parts.push(',"transactions":[');
    first = true;
    for (const t of this._transactions.values()) {
      if (!first) parts.push(',');
      parts.push(JSON.stringify(t.toJSON()));
      first = false;
    }
    parts.push(']');

    // Spent key images
    parts.push(',"spentKeyImages":');
    parts.push(JSON.stringify(Array.from(this._spentKeyImages)));

    // Block hashes (already pruned)
    parts.push(',"blockHashes":');
    parts.push(JSON.stringify(Object.fromEntries(this._blockHashes)));

    // State
    parts.push(',"state":');
    parts.push(JSON.stringify(Object.fromEntries(this._state)));

    parts.push('}');
    return parts.join('');
  }

  /**
   * Restore storage state from a dump() snapshot.
   * @param {Object} data - Previously dumped state
   */
  load(data) {
    if (!data || data.version !== 1) return;

    this._syncHeight = data.syncHeight || 0;

    if (data.outputs) {
      for (const o of data.outputs) {
        const wo = WalletOutput.fromJSON(o);
        this._outputs.set(wo.keyImage, wo);
        if (wo.keyImage) {
          this._keyImages.set(wo.keyImage, { txHash: wo.txHash, outputIndex: wo.outputIndex });
        }
      }
    }

    if (data.transactions) {
      for (const t of data.transactions) {
        const wt = WalletTransaction.fromJSON(t);
        this._transactions.set(wt.txHash, wt);
      }
    }

    if (data.spentKeyImages) {
      for (const ki of data.spentKeyImages) this._spentKeyImages.add(ki);
    }

    // Reconcile: ensure outputs whose key images are in _spentKeyImages
    // have isSpent=true. This fixes stale caches where sweep() marked KIs
    // as spent but output objects weren't updated before serialization.
    for (const ki of this._spentKeyImages) {
      const output = this._outputs.get(ki);
      if (output && !output.isSpent) {
        output.isSpent = true;
      }
    }

    if (data.blockHashes) {
      // Only load the most recent block hashes (prune old ones on load)
      const entries = Object.entries(data.blockHashes).map(([h, hash]) => [parseInt(h), hash]);
      entries.sort((a, b) => b[0] - a[0]); // Sort descending by height
      const toLoad = entries.slice(0, this._blockHashRetention);
      for (const [h, hash] of toLoad) {
        this._blockHashes.set(h, hash);
      }
    }

    if (data.state) {
      for (const [k, v] of Object.entries(data.state)) this._state.set(k, v);
    }
  }
}

// ============================================================================
// INDEXEDDB STORAGE (Browser)
// ============================================================================

/**
 * IndexedDB storage implementation for browsers
 */
export class IndexedDBStorage extends WalletStorage {
  constructor(options = {}) {
    super();
    this._dbName = options.dbName || 'salvium-wallet';
    this._version = options.version || 1;
    this._db = null;
  }

  async open() {
    if (typeof indexedDB === 'undefined') {
      throw new Error('IndexedDB not available');
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this._dbName, this._version);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this._db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;

        // Outputs store
        if (!db.objectStoreNames.contains('outputs')) {
          const outputStore = db.createObjectStore('outputs', { keyPath: 'keyImage' });
          outputStore.createIndex('txHash', 'txHash', { unique: false });
          outputStore.createIndex('isSpent', 'isSpent', { unique: false });
          outputStore.createIndex('assetType', 'assetType', { unique: false });
          outputStore.createIndex('blockHeight', 'blockHeight', { unique: false });
        }

        // Transactions store
        if (!db.objectStoreNames.contains('transactions')) {
          const txStore = db.createObjectStore('transactions', { keyPath: 'txHash' });
          txStore.createIndex('blockHeight', 'blockHeight', { unique: false });
          txStore.createIndex('isIncoming', 'isIncoming', { unique: false });
          txStore.createIndex('isOutgoing', 'isOutgoing', { unique: false });
        }

        // Key images store
        if (!db.objectStoreNames.contains('keyImages')) {
          db.createObjectStore('keyImages', { keyPath: 'keyImage' });
        }

        // State store
        if (!db.objectStoreNames.contains('state')) {
          db.createObjectStore('state', { keyPath: 'key' });
        }

        // Block hashes store (for reorg detection)
        if (!db.objectStoreNames.contains('blockHashes')) {
          db.createObjectStore('blockHashes', { keyPath: 'height' });
        }
      };
    });
  }

  async close() {
    if (this._db) {
      this._db.close();
      this._db = null;
    }
  }

  async clear() {
    const stores = ['outputs', 'transactions', 'keyImages', 'state'];
    if (this._db.objectStoreNames.contains('blockHashes')) stores.push('blockHashes');
    const tx = this._db.transaction(stores, 'readwrite');
    for (const name of stores) tx.objectStore(name).clear();
    return new Promise((resolve, reject) => {
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }

  // Output operations
  async putOutput(output) {
    const wo = output instanceof WalletOutput ? output : new WalletOutput(output);
    wo.updatedAt = Date.now();
    const data = wo.toJSON();

    return new Promise((resolve, reject) => {
      const tx = this._db.transaction(['outputs', 'keyImages'], 'readwrite');
      tx.objectStore('outputs').put(data);
      if (wo.keyImage) {
        tx.objectStore('keyImages').put({
          keyImage: wo.keyImage,
          txHash: wo.txHash,
          outputIndex: wo.outputIndex,
          isSpent: wo.isSpent
        });
      }
      tx.oncomplete = () => resolve(wo);
      tx.onerror = () => reject(tx.error);
    });
  }

  async getOutput(keyImage) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('outputs', 'readonly');
      const request = tx.objectStore('outputs').get(keyImage);
      request.onsuccess = () => {
        resolve(request.result ? WalletOutput.fromJSON(request.result) : null);
      };
      request.onerror = () => reject(request.error);
    });
  }

  async getOutputs(query = {}) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('outputs', 'readonly');
      const store = tx.objectStore('outputs');
      const results = [];

      const request = store.openCursor();
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          const output = WalletOutput.fromJSON(cursor.value);
          if (this._matchesOutputQuery(output, query)) {
            results.push(output);
          }
          cursor.continue();
        } else {
          resolve(results);
        }
      };
      request.onerror = () => reject(request.error);
    });
  }

  async markOutputSpent(keyImage, spendingTxHash, spentHeight = null) {
    const output = await this.getOutput(keyImage);
    if (output) {
      output.isSpent = true;
      output.spentTxHash = spendingTxHash;
      output.spentHeight = spentHeight;
      await this.putOutput(output);
    }
  }

  // Transaction operations
  async putTransaction(tx) {
    const wt = tx instanceof WalletTransaction ? tx : new WalletTransaction(tx);
    wt.updatedAt = Date.now();
    const data = wt.toJSON();

    return new Promise((resolve, reject) => {
      const dbTx = this._db.transaction('transactions', 'readwrite');
      dbTx.objectStore('transactions').put(data);
      dbTx.oncomplete = () => resolve(wt);
      dbTx.onerror = () => reject(dbTx.error);
    });
  }

  async getTransaction(txHash) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('transactions', 'readonly');
      const request = tx.objectStore('transactions').get(txHash);
      request.onsuccess = () => {
        resolve(request.result ? WalletTransaction.fromJSON(request.result) : null);
      };
      request.onerror = () => reject(request.error);
    });
  }

  async getTransactions(query = {}) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('transactions', 'readonly');
      const store = tx.objectStore('transactions');
      const results = [];

      const request = store.openCursor();
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          const wtx = WalletTransaction.fromJSON(cursor.value);
          if (this._matchesTxQuery(wtx, query)) {
            results.push(wtx);
          }
          cursor.continue();
        } else {
          // Sort by block height descending
          results.sort((a, b) => (b.blockHeight || 0) - (a.blockHeight || 0));
          resolve(results);
        }
      };
      request.onerror = () => reject(request.error);
    });
  }

  // Key image operations
  async putKeyImage(keyImage, outputRef) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('keyImages', 'readwrite');
      tx.objectStore('keyImages').put({ keyImage, ...outputRef });
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }

  async isKeyImageSpent(keyImage) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('keyImages', 'readonly');
      const request = tx.objectStore('keyImages').get(keyImage);
      request.onsuccess = () => {
        resolve(request.result?.isSpent === true);
      };
      request.onerror = () => reject(request.error);
    });
  }

  async getSpentKeyImages() {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('keyImages', 'readonly');
      const results = [];
      const request = tx.objectStore('keyImages').openCursor();
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          if (cursor.value.isSpent) {
            results.push(cursor.value.keyImage);
          }
          cursor.continue();
        } else {
          resolve(results);
        }
      };
      request.onerror = () => reject(request.error);
    });
  }

  // Sync state
  async getSyncHeight() {
    const state = await this.getState('syncHeight');
    return state || 0;
  }

  async setSyncHeight(height) {
    return this.setState('syncHeight', height);
  }

  async getState(key) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('state', 'readonly');
      const request = tx.objectStore('state').get(key);
      request.onsuccess = () => {
        resolve(request.result?.value);
      };
      request.onerror = () => reject(request.error);
    });
  }

  async setState(key, value) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('state', 'readwrite');
      tx.objectStore('state').put({ key, value });
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }

  // Block hash tracking
  async putBlockHash(height, hash) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('blockHashes', 'readwrite');
      tx.objectStore('blockHashes').put({ height, hash });
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }

  async getBlockHash(height) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('blockHashes', 'readonly');
      const request = tx.objectStore('blockHashes').get(height);
      request.onsuccess = () => resolve(request.result?.hash || null);
      request.onerror = () => reject(request.error);
    });
  }

  async deleteBlockHashesAbove(height) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('blockHashes', 'readwrite');
      const store = tx.objectStore('blockHashes');
      const range = IDBKeyRange.lowerBound(height, true);
      const request = store.openCursor(range);
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        }
      };
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }

  // Reorg rollback operations
  async deleteOutputsAbove(height) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction(['outputs', 'keyImages'], 'readwrite');
      const outputStore = tx.objectStore('outputs');
      const kiStore = tx.objectStore('keyImages');
      const index = outputStore.index('blockHeight');
      const range = IDBKeyRange.lowerBound(height, true);
      const request = index.openCursor(range);
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          const keyImage = cursor.value.keyImage;
          cursor.delete();
          if (keyImage) kiStore.delete(keyImage);
          cursor.continue();
        }
      };
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }

  async deleteTransactionsAbove(height) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('transactions', 'readwrite');
      const store = tx.objectStore('transactions');
      const index = store.index('blockHeight');
      const range = IDBKeyRange.lowerBound(height, true);
      const request = index.openCursor(range);
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        }
      };
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }

  async unspendOutputsAbove(height) {
    return new Promise((resolve, reject) => {
      const tx = this._db.transaction('outputs', 'readwrite');
      const store = tx.objectStore('outputs');
      const request = store.openCursor();
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          const data = cursor.value;
          if (data.isSpent && data.spentHeight !== null && data.spentHeight > height) {
            data.isSpent = false;
            data.spentTxHash = null;
            data.spentHeight = null;
            data.updatedAt = Date.now();
            cursor.update(data);
          }
          cursor.continue();
        }
      };
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  }

  // Query helpers
  _matchesOutputQuery(output, query) {
    if (query.isSpent !== undefined && output.isSpent !== query.isSpent) return false;
    if (query.isFrozen !== undefined && output.isFrozen !== query.isFrozen) return false;
    if (query.assetType && !areAssetTypesEquivalent(output.assetType, query.assetType)) return false;
    if (query.txType !== undefined && output.txType !== query.txType) return false;
    if (query.minAmount !== undefined && output.amount < BigInt(query.minAmount)) return false;
    if (query.maxAmount !== undefined && output.amount > BigInt(query.maxAmount)) return false;
    if (query.accountIndex !== undefined && output.subaddressIndex?.major !== query.accountIndex) return false;
    return true;
  }

  _matchesTxQuery(tx, query) {
    if (query.isIncoming !== undefined && tx.isIncoming !== query.isIncoming) return false;
    if (query.isOutgoing !== undefined && tx.isOutgoing !== query.isOutgoing) return false;
    if (query.isConfirmed !== undefined && tx.isConfirmed !== query.isConfirmed) return false;
    if (query.inPool !== undefined && tx.inPool !== query.inPool) return false;
    if (query.txType !== undefined && tx.txType !== query.txType) return false;
    if (query.minHeight !== undefined && (tx.blockHeight === null || tx.blockHeight < query.minHeight)) return false;
    if (query.maxHeight !== undefined && (tx.blockHeight === null || tx.blockHeight > query.maxHeight)) return false;
    return true;
  }
}

// ============================================================================
// FACTORY FUNCTIONS
// ============================================================================

/**
 * Create storage backend based on environment
 * @param {Object} options - Storage options
 * @param {string} options.type - Storage type: 'memory', 'indexeddb', or 'auto'
 * @param {string} options.dbName - Database name for IndexedDB
 * @returns {WalletStorage}
 */
export function createStorage(options = {}) {
  const type = options.type || 'auto';

  if (type === 'memory') {
    return new MemoryStorage();
  }

  if (type === 'indexeddb') {
    return new IndexedDBStorage(options);
  }

  // Auto-detect
  if (typeof indexedDB !== 'undefined') {
    return new IndexedDBStorage(options);
  }

  return new MemoryStorage();
}

// ============================================================================
// DEFAULT EXPORT
// ============================================================================

export default {
  WalletStorage,
  WalletOutput,
  WalletTransaction,
  MemoryStorage,
  IndexedDBStorage,
  createStorage
};
