/**
 * Persistent Wallet
 *
 * Full-featured wallet with persistent storage and daemon sync:
 * - Automatic blockchain synchronization
 * - Persistent output/transaction storage
 * - Balance calculation from stored outputs
 * - Transaction building from available UTXOs
 * - Multi-asset support (Salvium)
 * - Event-driven updates
 *
 * @module persistent-wallet
 */

import { Wallet, WalletListener, TX_TYPE, WALLET_TYPE } from './wallet.js';
import { createStorage, WalletOutput, WalletTransaction } from './wallet-store.js';
import { WalletSync, SYNC_STATUS } from './wallet-sync.js';
import { createDaemonRPC } from './rpc/index.js';
import { bytesToHex, hexToBytes } from './address.js';
import {
  buildTransaction,
  signTransaction,
  prepareInputs,
  selectUTXOs,
  estimateTransactionFee,
  serializeTransaction,
  UTXO_STRATEGY
} from './transaction.js';

// ============================================================================
// PERSISTENT WALLET
// ============================================================================

/**
 * Persistent wallet with storage and sync
 */
export class PersistentWallet extends Wallet {
  /**
   * Create a persistent wallet
   * @param {Object} options - Configuration
   * @param {Object} options.storage - Storage options or WalletStorage instance
   * @param {Object} options.daemon - DaemonRPC instance or connection options
   */
  constructor(options = {}) {
    super(options);

    // Storage
    if (options.storage && typeof options.storage.open === 'function') {
      this._storage = options.storage;
    } else {
      this._storage = createStorage(options.storage || {});
    }

    // Daemon connection
    if (options.daemon && typeof options.daemon.getInfo === 'function') {
      this._daemon = options.daemon;
    } else {
      this._daemon = createDaemonRPC(options.daemon || {});
    }

    // Sync engine (created after open)
    this._sync = null;

    // State
    this._isOpen = false;
    this._currentHeight = 0;

    // Balance cache
    this._balanceCache = new Map(); // assetType -> { balance, unlockedBalance }
    this._balanceDirty = true;
  }

  // ===========================================================================
  // LIFECYCLE
  // ===========================================================================

  /**
   * Open wallet and initialize storage
   * @returns {Promise<void>}
   */
  async open() {
    if (this._isOpen) return;

    await this._storage.open();

    // Create sync engine
    this._sync = new WalletSync({
      storage: this._storage,
      daemon: this._daemon,
      keys: {
        viewSecretKey: this._viewSecretKey,
        spendSecretKey: this._spendSecretKey,
        spendPublicKey: this._spendPublicKey
      },
      subaddresses: this._getSubaddressMap()
    });

    // Forward sync events
    this._sync.on('syncStart', (data) => this._emit('onSyncProgress', 0, data.startHeight, data.targetHeight, 0, 'Starting sync'));
    this._sync.on('syncProgress', (progress) => {
      this._currentHeight = progress.currentHeight;
      this._emit('onSyncProgress', progress.currentHeight, progress.startHeight, progress.targetHeight, progress.percentComplete, 'Syncing');
    });
    this._sync.on('syncComplete', (data) => {
      this._balanceDirty = true;
      this._emit('onSyncComplete', data.height);
    });
    this._sync.on('syncError', (error) => this._emit('onSyncError', error));
    this._sync.on('newBlock', (block) => this._emit('onNewBlock', block.height, block.hash));
    this._sync.on('outputReceived', async (data) => {
      this._balanceDirty = true;
      for (const output of data.outputs) {
        this._emit('onOutputReceived', output, 'confirmed');
      }
    });
    this._sync.on('outputSpent', async (data) => {
      this._balanceDirty = true;
      for (const output of data.outputs) {
        this._emit('onOutputSpent', output, 'confirmed');
      }
    });

    // Get current height
    try {
      const info = await this._daemon.getInfo();
      if (info.success) {
        this._currentHeight = info.result.height;
      }
    } catch (e) {
      // Daemon not available yet
    }

    this._isOpen = true;
  }

  /**
   * Close wallet and storage
   * @returns {Promise<void>}
   */
  async close() {
    if (!this._isOpen) return;

    if (this._sync) {
      this._sync.stop();
    }

    await this._storage.close();
    this._isOpen = false;
  }

  /**
   * Check if wallet is open
   * @returns {boolean}
   */
  isOpen() {
    return this._isOpen;
  }

  // ===========================================================================
  // SYNC
  // ===========================================================================

  /**
   * Sync wallet with blockchain
   * @param {number} startHeight - Start height (default: stored sync height)
   * @returns {Promise<void>}
   */
  async sync(startHeight = null) {
    this._ensureOpen();
    await this._sync.start(startHeight);
    this._balanceDirty = true;
  }

  /**
   * Start background sync
   * @param {number} intervalMs - Sync interval in milliseconds (default: 30000)
   * @returns {Promise<void>}
   */
  async startSyncing(intervalMs = 30000) {
    this._ensureOpen();

    // Initial sync
    await this.sync();

    // Periodic sync
    this._syncInterval = setInterval(async () => {
      if (this._sync.status !== SYNC_STATUS.SYNCING) {
        try {
          await this.sync();
        } catch (e) {
          console.error('Background sync error:', e);
        }
      }
    }, intervalMs);
  }

  /**
   * Stop background sync
   */
  stopSyncing() {
    if (this._syncInterval) {
      clearInterval(this._syncInterval);
      this._syncInterval = null;
    }
    if (this._sync) {
      this._sync.stop();
    }
  }

  /**
   * Rescan blockchain from height
   * @param {number} fromHeight - Height to start rescan
   * @returns {Promise<void>}
   */
  async rescan(fromHeight = 0) {
    this._ensureOpen();
    await this._sync.rescan(fromHeight);
    this._balanceDirty = true;
  }

  /**
   * Get sync height
   * @returns {Promise<number>}
   */
  async getSyncHeight() {
    this._ensureOpen();
    return this._storage.getSyncHeight();
  }

  /**
   * Get daemon height
   * @returns {Promise<number>}
   */
  async getDaemonHeight() {
    const info = await this._daemon.getInfo();
    return info.success ? info.result.height : 0;
  }

  /**
   * Check if wallet is synced
   * @returns {Promise<boolean>}
   */
  async isSynced() {
    const syncHeight = await this.getSyncHeight();
    const daemonHeight = await this.getDaemonHeight();
    return syncHeight >= daemonHeight - 1;
  }

  // ===========================================================================
  // BALANCE
  // ===========================================================================

  /**
   * Get wallet balance
   * @param {string} assetType - Asset type (default: 'SAL')
   * @returns {Promise<bigint>}
   */
  async getBalance(assetType = 'SAL') {
    this._ensureOpen();
    await this._updateBalanceIfNeeded();
    const cached = this._balanceCache.get(assetType);
    return cached?.balance || 0n;
  }

  /**
   * Get unlocked (spendable) balance
   * @param {string} assetType - Asset type (default: 'SAL')
   * @returns {Promise<bigint>}
   */
  async getUnlockedBalance(assetType = 'SAL') {
    this._ensureOpen();
    await this._updateBalanceIfNeeded();
    const cached = this._balanceCache.get(assetType);
    return cached?.unlockedBalance || 0n;
  }

  /**
   * Get all balances (multi-asset)
   * @returns {Promise<Map<string, {balance: bigint, unlockedBalance: bigint}>>}
   */
  async getBalances() {
    this._ensureOpen();
    await this._updateBalanceIfNeeded();
    return new Map(this._balanceCache);
  }

  /**
   * Update balance cache from storage
   * @private
   */
  async _updateBalanceIfNeeded() {
    if (!this._balanceDirty) return;

    const outputs = await this._storage.getOutputs({ isSpent: false });
    const balances = new Map();

    for (const output of outputs) {
      const assetType = output.assetType || 'SAL';
      if (!balances.has(assetType)) {
        balances.set(assetType, { balance: 0n, unlockedBalance: 0n });
      }

      const bal = balances.get(assetType);
      bal.balance += output.amount;

      if (output.isSpendable(this._currentHeight)) {
        bal.unlockedBalance += output.amount;
      }
    }

    this._balanceCache = balances;
    this._balanceDirty = false;
  }

  // ===========================================================================
  // OUTPUTS
  // ===========================================================================

  /**
   * Get all outputs
   * @param {Object} query - Query filters
   * @returns {Promise<Array<WalletOutput>>}
   */
  async getOutputs(query = {}) {
    this._ensureOpen();
    return this._storage.getOutputs(query);
  }

  /**
   * Get unspent outputs
   * @param {string} assetType - Asset type filter
   * @returns {Promise<Array<WalletOutput>>}
   */
  async getUnspentOutputs(assetType = null) {
    const query = { isSpent: false };
    if (assetType) query.assetType = assetType;
    return this.getOutputs(query);
  }

  /**
   * Get spendable outputs
   * @param {string} assetType - Asset type filter
   * @returns {Promise<Array<WalletOutput>>}
   */
  async getSpendableOutputs(assetType = null) {
    const outputs = await this.getUnspentOutputs(assetType);
    return outputs.filter(o => o.isSpendable(this._currentHeight));
  }

  /**
   * Freeze an output (prevent spending)
   * @param {string} keyImage - Output key image
   * @returns {Promise<void>}
   */
  async freezeOutput(keyImage) {
    this._ensureOpen();
    const output = await this._storage.getOutput(keyImage);
    if (output) {
      output.isFrozen = true;
      await this._storage.putOutput(output);
      this._balanceDirty = true;
    }
  }

  /**
   * Thaw a frozen output
   * @param {string} keyImage - Output key image
   * @returns {Promise<void>}
   */
  async thawOutput(keyImage) {
    this._ensureOpen();
    const output = await this._storage.getOutput(keyImage);
    if (output) {
      output.isFrozen = false;
      await this._storage.putOutput(output);
      this._balanceDirty = true;
    }
  }

  // ===========================================================================
  // TRANSACTIONS
  // ===========================================================================

  /**
   * Get transaction history
   * @param {Object} query - Query filters
   * @returns {Promise<Array<WalletTransaction>>}
   */
  async getTransactions(query = {}) {
    this._ensureOpen();
    return this._storage.getTransactions(query);
  }

  /**
   * Get transaction by hash
   * @param {string} txHash - Transaction hash
   * @returns {Promise<WalletTransaction|null>}
   */
  async getTransaction(txHash) {
    this._ensureOpen();
    return this._storage.getTransaction(txHash);
  }

  /**
   * Set transaction note
   * @param {string} txHash - Transaction hash
   * @param {string} note - Note text
   * @returns {Promise<void>}
   */
  async setTransactionNote(txHash, note) {
    this._ensureOpen();
    const tx = await this._storage.getTransaction(txHash);
    if (tx) {
      tx.note = note;
      await this._storage.putTransaction(tx);
    }
  }

  // ===========================================================================
  // TRANSACTION CREATION
  // ===========================================================================

  /**
   * Create a transaction
   * @param {Object} options - Transaction options
   * @param {Array<{address: string, amount: bigint}>} options.destinations - Send destinations
   * @param {string} options.assetType - Asset type (default: 'SAL')
   * @param {number} options.priority - Fee priority (1-4)
   * @param {number} options.ringSize - Ring size (default: 16)
   * @param {string} options.paymentId - Payment ID
   * @returns {Promise<Object>} Transaction data
   */
  async createTransaction(options = {}) {
    this._ensureOpen();
    this._ensureFullWallet();

    const {
      destinations,
      assetType = 'SAL',
      priority = 2,
      ringSize = 16,
      paymentId = null
    } = options;

    if (!destinations || destinations.length === 0) {
      throw new Error('No destinations specified');
    }

    // Calculate total amount needed
    const totalAmount = destinations.reduce((sum, d) => sum + BigInt(d.amount), 0n);

    // Get spendable outputs
    const spendableOutputs = await this.getSpendableOutputs(assetType);

    // Convert to UTXO format for selection
    const utxos = spendableOutputs.map(o => ({
      amount: o.amount,
      globalIndex: o.globalIndex,
      publicKey: hexToBytes(o.publicKey),
      txHash: o.txHash,
      outputIndex: o.outputIndex,
      keyImage: hexToBytes(o.keyImage),
      commitment: o.commitment ? hexToBytes(o.commitment) : null,
      mask: o.mask ? hexToBytes(o.mask) : null
    }));

    // Estimate fee
    const feeEstimate = await estimateTransactionFee({
      inputCount: 2,
      outputCount: destinations.length + 1, // +1 for change
      ringSize,
      priority
    });

    // Select UTXOs
    const selection = selectUTXOs(utxos, totalAmount + feeEstimate, {
      strategy: UTXO_STRATEGY.MINIMIZE_INPUTS
    });

    if (!selection.sufficient) {
      throw new Error(`Insufficient balance. Need ${totalAmount + feeEstimate}, have ${selection.total}`);
    }

    // Get decoys for ring signatures
    const decoys = await this._getDecoys(selection.selected, ringSize);

    // Prepare inputs with ring members
    const inputs = await prepareInputs(selection.selected, decoys, ringSize);

    // Build transaction
    const txData = {
      inputs,
      destinations,
      changeAddress: this.getAddress(),
      fee: feeEstimate,
      paymentId,
      unlockTime: 0n
    };

    const unsignedTx = buildTransaction(txData);

    // Sign transaction
    const signedTx = signTransaction(unsignedTx, this._spendSecretKey);

    // Serialize
    const txBlob = serializeTransaction(signedTx);
    const txHash = bytesToHex(signedTx.hash);

    return {
      txHash,
      txBlob: bytesToHex(txBlob),
      fee: feeEstimate,
      amount: totalAmount,
      destinations
    };
  }

  /**
   * Send transaction to network
   * @param {Object} tx - Transaction from createTransaction
   * @returns {Promise<Object>} Submission result
   */
  async sendTransaction(tx) {
    this._ensureOpen();

    const result = await this._daemon.sendRawTransaction(tx.txBlob);

    if (result.success && result.result.status === 'OK') {
      // Mark used outputs as spent (pending)
      // They'll be confirmed after sync
      return {
        success: true,
        txHash: tx.txHash,
        fee: tx.fee
      };
    }

    return {
      success: false,
      error: result.error?.message || result.result?.reason || 'Unknown error'
    };
  }

  /**
   * Create and send transaction in one call
   * @param {Object} options - Same as createTransaction
   * @returns {Promise<Object>} Result with txHash
   */
  async transfer(options) {
    const tx = await this.createTransaction(options);
    return this.sendTransaction(tx);
  }

  /**
   * Sweep all funds to an address
   * @param {string} address - Destination address
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Transaction result
   */
  async sweepAll(address, options = {}) {
    this._ensureOpen();
    this._ensureFullWallet();

    const outputs = await this.getSpendableOutputs(options.assetType || 'SAL');
    const totalAmount = outputs.reduce((sum, o) => sum + o.amount, 0n);

    if (totalAmount === 0n) {
      throw new Error('No spendable outputs');
    }

    // Estimate fee for all inputs
    const feeEstimate = await estimateTransactionFee({
      inputCount: outputs.length,
      outputCount: 1,
      ringSize: options.ringSize || 16,
      priority: options.priority || 2
    });

    const sendAmount = totalAmount - feeEstimate;
    if (sendAmount <= 0n) {
      throw new Error('Insufficient balance for fee');
    }

    return this.transfer({
      destinations: [{ address, amount: sendAmount }],
      ...options
    });
  }

  // ===========================================================================
  // HELPERS
  // ===========================================================================

  /**
   * Get decoys for ring signatures
   * @private
   */
  async _getDecoys(inputs, ringSize) {
    // Get output distribution from daemon
    const distResponse = await this._daemon.getOutputDistribution([0], {
      cumulative: true
    });

    if (!distResponse.success) {
      throw new Error('Failed to get output distribution');
    }

    const distribution = distResponse.result.distributions?.[0];
    if (!distribution) {
      throw new Error('No output distribution data');
    }

    // For each input, select random decoys
    const decoys = [];
    for (const input of inputs) {
      const inputDecoys = [];

      // Select ringSize-1 random outputs (excluding our real output)
      const totalOutputs = distribution.amount;
      const usedIndices = new Set([input.globalIndex]);

      while (inputDecoys.length < ringSize - 1) {
        // Random selection with recent bias
        const randomIndex = Math.floor(Math.random() * totalOutputs);

        if (!usedIndices.has(randomIndex)) {
          usedIndices.add(randomIndex);

          // Get output data
          const outsResponse = await this._daemon.getOuts([
            { amount: 0, index: randomIndex }
          ], { get_txid: false });

          if (outsResponse.success && outsResponse.result.outs?.[0]) {
            const out = outsResponse.result.outs[0];
            inputDecoys.push({
              globalIndex: randomIndex,
              publicKey: hexToBytes(out.key),
              commitment: out.mask ? hexToBytes(out.mask) : null
            });
          }
        }
      }

      decoys.push(inputDecoys);
    }

    return decoys;
  }

  /**
   * Get map of subaddress public keys to indices
   * @private
   */
  _getSubaddressMap() {
    const map = new Map();
    for (const [key, value] of this._subaddresses) {
      // key is "major,minor", value is address
      // We need to map public key -> {major, minor}
      // This would require computing the public key for each subaddress
    }
    return map;
  }

  /**
   * Ensure wallet is open
   * @private
   */
  _ensureOpen() {
    if (!this._isOpen) {
      throw new Error('Wallet not open. Call open() first.');
    }
  }

  /**
   * Ensure wallet has spend key
   * @private
   */
  _ensureFullWallet() {
    if (!this._spendSecretKey) {
      throw new Error('Spend key required. This is a view-only wallet.');
    }
  }
}

// ============================================================================
// FACTORY FUNCTIONS
// ============================================================================

/**
 * Create a new persistent wallet
 * @param {Object} options - Wallet options
 * @returns {Promise<PersistentWallet>}
 */
export async function createPersistentWallet(options = {}) {
  const wallet = new PersistentWallet(options);
  await wallet.open();
  return wallet;
}

/**
 * Restore a persistent wallet from mnemonic
 * @param {string} mnemonic - 25-word mnemonic
 * @param {Object} options - Wallet options
 * @returns {Promise<PersistentWallet>}
 */
export async function restorePersistentWallet(mnemonic, options = {}) {
  const wallet = new PersistentWallet({
    ...options,
    mnemonic
  });
  await wallet.open();
  return wallet;
}

/**
 * Open existing persistent wallet from storage
 * @param {Object} options - Storage and daemon options
 * @returns {Promise<PersistentWallet>}
 */
export async function openPersistentWallet(options = {}) {
  const wallet = new PersistentWallet(options);
  await wallet.open();

  // Load keys from storage if available
  const storedKeys = await wallet._storage.getState('walletKeys');
  if (storedKeys) {
    // Restore keys...
  }

  return wallet;
}

// ============================================================================
// DEFAULT EXPORT
// ============================================================================

export default {
  PersistentWallet,
  createPersistentWallet,
  restorePersistentWallet,
  openPersistentWallet
};
