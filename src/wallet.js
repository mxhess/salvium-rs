/**
 * Unified Wallet Class for Salvium
 *
 * High-level API for Salvium wallet operations:
 * - Key management (seed, spend/view keys, CARROT keys)
 * - Address generation (main and subaddresses)
 * - Account management (up to 5 accounts, 20 subaddresses each per Salvium spec)
 * - Transaction scanning and balance tracking
 * - Transaction building and signing (all 9 Salvium TX types)
 * - View-only wallet support
 * - Event/listener system for reactive updates
 * - Background sync with daemon
 * - Multi-asset support
 * - Yield/staking tracking
 *
 * @module wallet
 */

import { generateSeed, deriveKeys, deriveCarrotKeys } from './carrot.js';
import { createAddress, parseAddress, hexToBytes, bytesToHex } from './address.js';
import { cnSubaddress } from './subaddress.js';
import { generateKeyDerivation, derivationToScalar, deriveSecretKey, scanTransaction } from './scanning.js';
import { generateKeyImage } from './keyimage.js';
import {
  buildTransaction,
  signTransaction,
  prepareInputs,
  selectUTXOs,
  estimateTransactionFee,
  validateTransaction,
  serializeTransaction,
  UTXO_STRATEGY
} from './transaction.js';
import { NETWORK, ADDRESS_FORMAT } from './constants.js';
import { seedToMnemonic, mnemonicToSeed, validateMnemonic } from './mnemonic.js';

// ============================================================================
// SALVIUM-SPECIFIC CONSTANTS
// ============================================================================

/**
 * Subaddress index limits (32-bit unsigned integers)
 * No practical limit - use as many accounts/subaddresses as needed
 */
export const MAX_SUBADDRESS_MAJOR_INDEX = 0xFFFFFFFF;
export const MAX_SUBADDRESS_MINOR_INDEX = 0xFFFFFFFF;

/**
 * Salvium transaction types (from cryptonote_protocol/enums.h)
 */
export const TX_TYPE = {
  UNSET: 0,
  MINER: 1,      // Mining reward
  PROTOCOL: 2,   // Per-block protocol tx (yield payouts, burn refunds)
  TRANSFER: 3,   // Regular transfer
  CONVERT: 4,    // Asset conversion
  BURN: 5,       // Coin burn
  STAKE: 6,      // Staking transaction
  RETURN: 7,     // Return payment
  AUDIT: 8       // Audit transaction
};

/**
 * Default unlock time in blocks
 */
export const DEFAULT_UNLOCK_BLOCKS = 10;

/**
 * Wallet types
 */
export const WALLET_TYPE = {
  FULL: 'full',           // Full wallet with spend key
  VIEW_ONLY: 'view_only', // View-only (no spend key)
  WATCH: 'watch'          // Watch-only (public keys only)
};

// ============================================================================
// EVENT LISTENER SYSTEM
// ============================================================================

/**
 * Base class for wallet event listeners
 * Extend this class and override methods to receive wallet events
 */
export class WalletListener {
  /**
   * Called when sync progress updates
   * @param {number} height - Current sync height
   * @param {number} startHeight - Sync start height
   * @param {number} endHeight - Target end height
   * @param {number} percentDone - Percentage complete (0-100)
   * @param {string} message - Optional status message
   */
  onSyncProgress(height, startHeight, endHeight, percentDone, message) {}

  /**
   * Called when a new block is processed
   * @param {number} height - Block height
   * @param {string} hash - Block hash
   */
  onNewBlock(height, hash) {}

  /**
   * Called when wallet balance changes
   * @param {bigint} newBalance - New total balance
   * @param {bigint} newUnlockedBalance - New unlocked balance
   * @param {string} assetType - Asset type (default: 'SAL')
   */
  onBalanceChanged(newBalance, newUnlockedBalance, assetType = 'SAL') {}

  /**
   * Called when an output is received (called up to 3 times per output)
   * @param {Object} output - Output details
   * @param {string} status - 'unconfirmed', 'confirmed', or 'unlocked'
   */
  onOutputReceived(output, status) {}

  /**
   * Called when an output is spent (called up to 2 times per output)
   * @param {Object} output - Output details
   * @param {string} status - 'confirmed' or 'unlocked'
   */
  onOutputSpent(output, status) {}

  /**
   * Called when a stake payout is received
   * @param {Object} payout - Payout details (amount, stakeOrigin, etc.)
   */
  onStakePayout(payout) {}

  /**
   * Called when sync completes
   * @param {number} height - Final sync height
   */
  onSyncComplete(height) {}

  /**
   * Called on sync error
   * @param {Error} error - Error that occurred
   */
  onSyncError(error) {}
}

// ============================================================================
// ACCOUNT CLASS
// ============================================================================

/**
 * Represents a wallet account (major index in subaddress system)
 */
export class Account {
  constructor(wallet, index, label = '') {
    this._wallet = wallet;
    this._index = index;
    this._label = label;
    this._subaddressLabels = new Map(); // minor index -> label
  }

  /** Get account index */
  get index() { return this._index; }

  /** Get/set account label */
  get label() { return this._label; }
  set label(value) { this._label = value; }

  /**
   * Get the primary address for this account
   * @returns {string}
   */
  getPrimaryAddress() {
    return this._wallet.getSubaddress(this._index, 0);
  }

  /**
   * Get a subaddress in this account
   * @param {number} minor - Subaddress index
   * @returns {string}
   */
  getSubaddress(minor) {
    return this._wallet.getSubaddress(this._index, minor);
  }

  /**
   * Create a new subaddress in this account
   * @param {string} label - Optional label
   * @returns {Object} { index, address }
   */
  createSubaddress(label = '') {
    const minor = this._wallet._getNextSubaddressIndex(this._index);
    const address = this._wallet.getSubaddress(this._index, minor);
    if (label) {
      this._subaddressLabels.set(minor, label);
    }
    return { index: minor, address };
  }

  /**
   * Get all subaddresses in this account
   * @returns {Array<Object>} Array of { index, address, label }
   */
  getSubaddresses() {
    const result = [];
    for (let minor = 0; minor < this._wallet._getNextSubaddressIndex(this._index); minor++) {
      result.push({
        index: minor,
        address: this._wallet.getSubaddress(this._index, minor),
        label: this._subaddressLabels.get(minor) || ''
      });
    }
    return result;
  }

  /**
   * Get balance for this account only
   * @param {string} assetType - Asset type (default: 'SAL')
   * @returns {Object} { balance, unlockedBalance, lockedBalance }
   */
  getBalance(assetType = 'SAL') {
    return this._wallet.getBalance({ accountIndex: this._index, assetType });
  }

  /**
   * Get label for a subaddress
   * @param {number} minor - Subaddress index
   * @returns {string}
   */
  getSubaddressLabel(minor) {
    return this._subaddressLabels.get(minor) || '';
  }

  /**
   * Set label for a subaddress
   * @param {number} minor - Subaddress index
   * @param {string} label - Label
   */
  setSubaddressLabel(minor, label) {
    this._subaddressLabels.set(minor, label);
  }
}

// ============================================================================
// WALLET CLASS
// ============================================================================

/**
 * Unified Wallet class for Salvium
 */
export class Wallet {
  /**
   * Create a new wallet instance
   * @param {Object} options - Wallet options
   * @param {string} options.type - Wallet type (full, view_only, watch)
   * @param {string} options.network - Network (mainnet, testnet, stagenet)
   * @param {string} options.format - Address format (legacy, carrot)
   * @private - Use static factory methods instead
   */
  constructor(options = {}) {
    this.type = options.type || WALLET_TYPE.FULL;
    this.network = options.network || NETWORK.MAINNET;
    this.format = options.format || ADDRESS_FORMAT.LEGACY;

    // Key material (set by factory methods)
    this._seed = null;
    this._spendSecretKey = null;
    this._spendPublicKey = null;
    this._viewSecretKey = null;
    this._viewPublicKey = null;

    // CARROT additional keys (if using CARROT format)
    this._carrotKeys = null;

    // Account management
    this._accounts = [new Account(this, 0, 'Primary')]; // Account 0 always exists
    this._nextSubaddressIndex = new Map(); // account index -> next minor index
    this._nextSubaddressIndex.set(0, 1); // Account 0 starts with 1 (0 is main address)

    // Cached addresses
    this._mainAddress = null;
    this._subaddresses = new Map(); // Map<'major,minor', address>

    // UTXO tracking (by asset type)
    this._utxos = new Map(); // Map<assetType, Array<UTXO>>
    this._utxos.set('SAL', []);
    this._spentKeyImages = new Set(); // Key images of spent outputs
    this._pendingTxs = [];      // Pending transactions

    // Locked coins (for staking)
    this._lockedCoins = new Map(); // Map<keyImage, { amount, stakeHeight, txHash }>

    // Yield tracking
    this._yieldPayouts = []; // Array of yield payout records

    // Sync state
    this._syncHeight = 0;
    this._lastBlockHash = null;
    this._syncing = false;
    this._syncInterval = null;

    // Event listeners
    this._listeners = [];

    // Previous balance (for change detection)
    this._previousBalance = new Map(); // Map<assetType, { balance, unlocked }>
  }

  // ===========================================================================
  // FACTORY METHODS
  // ===========================================================================

  /**
   * Create a new random wallet
   * @param {Object} options - Wallet options
   * @param {string} options.network - Network (default: mainnet)
   * @param {string} options.format - Address format (default: legacy)
   * @returns {Wallet} New wallet instance
   */
  static create(options = {}) {
    const wallet = new Wallet({
      type: WALLET_TYPE.FULL,
      network: options.network || NETWORK.MAINNET,
      format: options.format || ADDRESS_FORMAT.LEGACY
    });

    // Generate random seed
    wallet._seed = generateSeed();

    // Derive keys based on format
    if (wallet.format === ADDRESS_FORMAT.CARROT) {
      wallet._carrotKeys = deriveCarrotKeys(wallet._seed);
      wallet._spendSecretKey = wallet._carrotKeys.spendSecretKey;
      wallet._spendPublicKey = wallet._carrotKeys.spendPublicKey;
      wallet._viewSecretKey = wallet._carrotKeys.viewSecretKey;
      wallet._viewPublicKey = wallet._carrotKeys.viewPublicKey;
    } else {
      const keys = deriveKeys(wallet._seed);
      wallet._spendSecretKey = keys.spendSecretKey;
      wallet._spendPublicKey = keys.spendPublicKey;
      wallet._viewSecretKey = keys.viewSecretKey;
      wallet._viewPublicKey = keys.viewPublicKey;
    }

    return wallet;
  }

  /**
   * Restore wallet from mnemonic seed phrase
   * @param {string} mnemonic - 25-word mnemonic phrase
   * @param {Object} options - Wallet options
   * @param {string} options.network - Network (default: mainnet)
   * @param {string} options.format - Address format (default: legacy)
   * @param {string} options.language - Mnemonic language (default: english)
   * @returns {Wallet} Restored wallet instance
   */
  static fromMnemonic(mnemonic, options = {}) {
    const { language = 'english' } = options;

    // Validate mnemonic
    const validation = validateMnemonic(mnemonic, language);
    if (!validation.valid) {
      throw new Error(`Invalid mnemonic: ${validation.error}`);
    }

    // Convert to seed
    const result = mnemonicToSeed(mnemonic, { language });
    if (!result.valid) {
      throw new Error(`Invalid mnemonic: ${result.error}`);
    }

    return Wallet.fromSeed(result.seed, options);
  }

  /**
   * Restore wallet from 32-byte seed
   * @param {Uint8Array|string} seed - 32-byte seed
   * @param {Object} options - Wallet options
   * @returns {Wallet} Restored wallet instance
   */
  static fromSeed(seed, options = {}) {
    const wallet = new Wallet({
      type: WALLET_TYPE.FULL,
      network: options.network || NETWORK.MAINNET,
      format: options.format || ADDRESS_FORMAT.LEGACY
    });

    // Store seed
    wallet._seed = typeof seed === 'string' ? hexToBytes(seed) : seed;

    // Derive keys
    if (wallet.format === ADDRESS_FORMAT.CARROT) {
      wallet._carrotKeys = deriveCarrotKeys(wallet._seed);
      wallet._spendSecretKey = wallet._carrotKeys.spendSecretKey;
      wallet._spendPublicKey = wallet._carrotKeys.spendPublicKey;
      wallet._viewSecretKey = wallet._carrotKeys.viewSecretKey;
      wallet._viewPublicKey = wallet._carrotKeys.viewPublicKey;
    } else {
      const keys = deriveKeys(wallet._seed);
      wallet._spendSecretKey = keys.spendSecretKey;
      wallet._spendPublicKey = keys.spendPublicKey;
      wallet._viewSecretKey = keys.viewSecretKey;
      wallet._viewPublicKey = keys.viewPublicKey;
    }

    return wallet;
  }

  /**
   * Create view-only wallet from view key and spend public key
   * @param {Uint8Array|string} viewSecretKey - View secret key
   * @param {Uint8Array|string} spendPublicKey - Spend public key
   * @param {Object} options - Wallet options
   * @returns {Wallet} View-only wallet instance
   */
  static fromViewKey(viewSecretKey, spendPublicKey, options = {}) {
    const wallet = new Wallet({
      type: WALLET_TYPE.VIEW_ONLY,
      network: options.network || NETWORK.MAINNET,
      format: options.format || ADDRESS_FORMAT.LEGACY
    });

    wallet._viewSecretKey = typeof viewSecretKey === 'string'
      ? hexToBytes(viewSecretKey)
      : viewSecretKey;
    wallet._spendPublicKey = typeof spendPublicKey === 'string'
      ? hexToBytes(spendPublicKey)
      : spendPublicKey;

    // Derive view public key from view secret key
    const { scalarMultBase } = require('./ed25519.js');
    wallet._viewPublicKey = scalarMultBase(wallet._viewSecretKey);

    return wallet;
  }

  /**
   * Create watch-only wallet from address
   * @param {string} address - Wallet address
   * @param {Object} options - Wallet options
   * @returns {Wallet} Watch-only wallet instance
   */
  static fromAddress(address, options = {}) {
    const parsed = parseAddress(address);
    if (!parsed.valid) {
      throw new Error(`Invalid address: ${parsed.error}`);
    }

    const wallet = new Wallet({
      type: WALLET_TYPE.WATCH,
      network: parsed.network,
      format: parsed.format
    });

    wallet._spendPublicKey = parsed.spendPublicKey;
    wallet._viewPublicKey = parsed.viewPublicKey;

    return wallet;
  }

  // ===========================================================================
  // EVENT LISTENER MANAGEMENT
  // ===========================================================================

  /**
   * Add an event listener
   * @param {WalletListener} listener - Listener instance
   */
  addListener(listener) {
    if (!(listener instanceof WalletListener)) {
      throw new Error('Listener must be an instance of WalletListener');
    }
    if (!this._listeners.includes(listener)) {
      this._listeners.push(listener);
    }
  }

  /**
   * Remove an event listener
   * @param {WalletListener} listener - Listener to remove
   */
  removeListener(listener) {
    const index = this._listeners.indexOf(listener);
    if (index !== -1) {
      this._listeners.splice(index, 1);
    }
  }

  /**
   * Emit an event to all listeners
   * @private
   */
  _emit(event, ...args) {
    for (const listener of this._listeners) {
      try {
        if (typeof listener[event] === 'function') {
          listener[event](...args);
        }
      } catch (e) {
        console.error(`Listener error in ${event}:`, e);
      }
    }
  }

  // ===========================================================================
  // KEY ACCESSORS
  // ===========================================================================

  /** Get the wallet seed (if available) */
  get seed() { return this._seed; }

  /** Get spend secret key (if available) */
  get spendSecretKey() { return this._spendSecretKey; }

  /** Get spend public key */
  get spendPublicKey() { return this._spendPublicKey; }

  /** Get view secret key (if available) */
  get viewSecretKey() { return this._viewSecretKey; }

  /** Get view public key */
  get viewPublicKey() { return this._viewPublicKey; }

  /** Get CARROT keys (if available) */
  get carrotKeys() { return this._carrotKeys; }

  /**
   * Get the mnemonic phrase for the wallet seed
   * @param {string} language - Language (default: english)
   * @returns {string|null} 25-word mnemonic or null
   */
  getMnemonic(language = 'english') {
    if (!this._seed) return null;
    return seedToMnemonic(this._seed, language);
  }

  /** Check if wallet can sign transactions */
  canSign() {
    return this.type === WALLET_TYPE.FULL && this._spendSecretKey !== null;
  }

  /** Check if wallet can scan for incoming transactions */
  canScan() {
    return this._viewSecretKey !== null;
  }

  /** Check if wallet is view-only */
  isViewOnly() {
    return this.type === WALLET_TYPE.VIEW_ONLY;
  }

  // ===========================================================================
  // ACCOUNT MANAGEMENT
  // ===========================================================================

  /**
   * Get all accounts
   * @returns {Array<Account>}
   */
  getAccounts() {
    return [...this._accounts];
  }

  /**
   * Get account by index
   * @param {number} index - Account index
   * @returns {Account|null}
   */
  getAccount(index) {
    return this._accounts[index] || null;
  }

  /**
   * Create a new account
   * @param {string} label - Account label
   * @returns {Account}
   */
  createAccount(label = '') {
    const index = this._accounts.length;
    const account = new Account(this, index, label || `Account ${index}`);
    this._accounts.push(account);
    this._nextSubaddressIndex.set(index, 1);

    return account;
  }

  /**
   * Get number of accounts
   * @returns {number}
   */
  numAccounts() {
    return this._accounts.length;
  }

  /**
   * Get next subaddress index for an account
   * @private
   */
  _getNextSubaddressIndex(accountIndex) {
    return this._nextSubaddressIndex.get(accountIndex) || 1;
  }

  // ===========================================================================
  // ADDRESS GENERATION
  // ===========================================================================

  /**
   * Get the main wallet address
   * @param {boolean} carrot - Use CARROT format (default: use wallet default)
   * @returns {string} Main address
   */
  getAddress(carrot = null) {
    const format = carrot === null ? this.format :
      (carrot ? ADDRESS_FORMAT.CARROT : ADDRESS_FORMAT.LEGACY);

    if (format === this.format && this._mainAddress) {
      return this._mainAddress;
    }

    const address = createAddress({
      spendPublicKey: this._spendPublicKey,
      viewPublicKey: this._viewPublicKey,
      network: this.network,
      format: format,
      type: 'standard'
    });

    if (format === this.format) {
      this._mainAddress = address;
    }

    return address;
  }

  /**
   * Generate a subaddress
   * @param {number} major - Account index (default: 0)
   * @param {number} minor - Subaddress index (default: 0)
   * @returns {string} Subaddress
   */
  getSubaddress(major = 0, minor = 0) {
    // Main address
    if (major === 0 && minor === 0) {
      return this.getAddress();
    }

    const key = `${major},${minor}`;
    if (this._subaddresses.has(key)) {
      return this._subaddresses.get(key);
    }

    // Generate subaddress
    if (!this._viewSecretKey) {
      throw new Error('View secret key required to generate subaddresses');
    }

    const keys = cnSubaddress(
      this._spendPublicKey,
      this._viewSecretKey,
      major,
      minor
    );

    const subaddr = createAddress({
      spendPublicKey: keys.spendPublicKey,
      viewPublicKey: keys.viewPublicKey,
      network: this.network,
      format: this.format,
      type: 'subaddress'
    });

    this._subaddresses.set(key, subaddr);

    // Update next index tracker
    const currentNext = this._nextSubaddressIndex.get(major) || 1;
    if (minor >= currentNext) {
      this._nextSubaddressIndex.set(major, minor + 1);
    }

    return subaddr;
  }

  /**
   * Generate an integrated address with payment ID
   * @param {string} paymentId - 8-byte payment ID (hex)
   * @param {boolean} carrot - Use CARROT format
   * @returns {string} Integrated address
   */
  getIntegratedAddress(paymentId, carrot = null) {
    const format = carrot === null ? this.format :
      (carrot ? ADDRESS_FORMAT.CARROT : ADDRESS_FORMAT.LEGACY);

    return createAddress({
      spendPublicKey: this._spendPublicKey,
      viewPublicKey: this._viewPublicKey,
      network: this.network,
      format: format,
      type: 'integrated',
      paymentId
    });
  }

  // ===========================================================================
  // SYNC AND REFRESH
  // ===========================================================================

  /**
   * Sync wallet with blockchain (one-time)
   * @param {Object} daemon - DaemonRPC instance
   * @param {number} startHeight - Start height (default: wallet sync height)
   * @returns {Promise<Object>} { numBlocksFetched, receivedMoney }
   */
  async sync(daemon, startHeight = null) {
    if (!this.canScan()) {
      throw new Error('View secret key required to sync');
    }

    const start = startHeight !== null ? startHeight : this._syncHeight;
    const info = await daemon.getInfo();
    if (!info.success) {
      throw new Error(`Failed to get daemon info: ${info.error?.message}`);
    }

    const endHeight = info.result.height;
    let numBlocksFetched = 0;
    let receivedMoney = false;

    this._emit('onSyncProgress', start, start, endHeight, 0, 'Starting sync...');

    // Fetch blocks in batches
    const batchSize = 100;
    for (let height = start; height < endHeight; height += batchSize) {
      const batchEnd = Math.min(height + batchSize, endHeight);

      // Get block headers for this batch
      const headers = await daemon.getBlockHeadersRange(height, batchEnd - 1);
      if (!headers.success) continue;

      for (const header of headers.result.headers || []) {
        // Get full block with transactions
        const block = await daemon.getBlock({ height: header.height });
        if (!block.success) continue;

        // Process block
        const result = await this._processBlock(block.result, daemon);
        if (result.receivedMoney) receivedMoney = true;
        numBlocksFetched++;

        this._syncHeight = header.height;
        this._lastBlockHash = header.hash;

        // Emit progress
        const percent = ((header.height - start) / (endHeight - start)) * 100;
        this._emit('onSyncProgress', header.height, start, endHeight, percent, `Block ${header.height}/${endHeight}`);
        this._emit('onNewBlock', header.height, header.hash);
      }
    }

    this._emit('onSyncComplete', this._syncHeight);
    return { numBlocksFetched, receivedMoney };
  }

  /**
   * Start background syncing
   * @param {Object} daemon - DaemonRPC instance
   * @param {number} intervalMs - Poll interval (default: 30000ms)
   */
  async startSyncing(daemon, intervalMs = 30000) {
    if (this._syncing) return;
    this._syncing = true;

    // Initial sync
    try {
      await this.sync(daemon);
    } catch (e) {
      this._emit('onSyncError', e);
    }

    // Background loop
    this._syncInterval = setInterval(async () => {
      if (!this._syncing) return;
      try {
        await this.sync(daemon);
      } catch (e) {
        this._emit('onSyncError', e);
      }
    }, intervalMs);
  }

  /**
   * Stop background syncing
   */
  stopSyncing() {
    this._syncing = false;
    if (this._syncInterval) {
      clearInterval(this._syncInterval);
      this._syncInterval = null;
    }
  }

  /**
   * Check if wallet is currently syncing
   * @returns {boolean}
   */
  isSyncing() {
    return this._syncing;
  }

  /**
   * Process a single block
   * @private
   */
  async _processBlock(block, daemon) {
    let receivedMoney = false;
    const previousBalance = this.getBalance();

    // Process miner tx
    if (block.miner_tx) {
      const result = this._processTransaction(block.miner_tx, {
        blockHeight: block.block_header?.height,
        txType: TX_TYPE.MINER
      });
      if (result.owned.length > 0) receivedMoney = true;
    }

    // Process protocol tx (Salvium-specific: yield payouts, burn refunds)
    if (block.protocol_tx) {
      const result = this._processTransaction(block.protocol_tx, {
        blockHeight: block.block_header?.height,
        txType: TX_TYPE.PROTOCOL
      });
      if (result.owned.length > 0) {
        receivedMoney = true;
        // Track as yield payout if linked to stake
        for (const output of result.owned) {
          if (output.originIdx !== undefined) {
            this._yieldPayouts.push({
              amount: output.amount,
              blockHeight: block.block_header?.height,
              stakeOriginIdx: output.originIdx
            });
            this._emit('onStakePayout', {
              amount: output.amount,
              blockHeight: block.block_header?.height
            });
          }
        }
      }
    }

    // Process regular transactions
    if (block.tx_hashes && daemon) {
      const txs = await daemon.getTransactions(block.tx_hashes, { decodeAsJson: true });
      if (txs.success && txs.result.txs) {
        for (const tx of txs.result.txs) {
          const result = this._processTransaction(tx, {
            blockHeight: block.block_header?.height,
            txHash: tx.tx_hash
          });
          if (result.owned.length > 0) receivedMoney = true;
          if (result.spent.length > 0) {
            // Mark key images as spent
            this.markSpent(result.spent.map(s => s.keyImage));
          }
        }
      }
    }

    // Check for balance changes and emit events
    const newBalance = this.getBalance();
    if (newBalance.balance !== previousBalance.balance ||
        newBalance.unlockedBalance !== previousBalance.unlockedBalance) {
      this._emit('onBalanceChanged', newBalance.balance, newBalance.unlockedBalance, 'SAL');
    }

    return { receivedMoney };
  }

  /**
   * Process a single transaction
   * @private
   */
  _processTransaction(tx, info = {}) {
    const result = { owned: [], spent: [] };

    // Scan for owned outputs
    if (this.canScan()) {
      const owned = this.scanTransaction(tx);
      for (const output of owned) {
        const utxo = this.addOutput(output, {
          txHash: info.txHash || tx.tx_hash,
          blockHeight: info.blockHeight,
          txType: info.txType || TX_TYPE.TRANSFER,
          assetType: output.assetType || 'SAL'
        });
        if (utxo) {
          result.owned.push(utxo);
          this._emit('onOutputReceived', utxo,
            info.blockHeight ? 'confirmed' : 'unconfirmed');
        }
      }
    }

    // Check for spent outputs (key images in inputs)
    if (tx.vin) {
      for (const input of tx.vin) {
        if (input.key && input.key.k_image) {
          const kiHex = input.key.k_image;
          // Check if this is one of our key images
          for (const [assetType, utxos] of this._utxos) {
            const spent = utxos.find(u =>
              u.keyImage && bytesToHex(u.keyImage) === kiHex
            );
            if (spent) {
              result.spent.push(spent);
              this._emit('onOutputSpent', spent, 'confirmed');
            }
          }
        }
      }
    }

    return result;
  }

  // ===========================================================================
  // TRANSACTION SCANNING
  // ===========================================================================

  /**
   * Scan a transaction for outputs belonging to this wallet
   * @param {Object} tx - Transaction to scan
   * @returns {Array<Object>} Owned outputs with amounts
   */
  scanTransaction(tx) {
    if (!this.canScan()) {
      throw new Error('View secret key required to scan transactions');
    }

    return scanTransaction(tx, this._viewSecretKey, this._spendPublicKey);
  }

  /**
   * Process a scanned output and add to UTXOs
   * @param {Object} output - Scanned output
   * @param {Object} txInfo - Transaction info (hash, height, etc.)
   */
  addOutput(output, txInfo = {}) {
    const assetType = txInfo.assetType || output.assetType || 'SAL';

    // Derive the one-time secret key for this output (needed for spending)
    let secretKey = null;
    if (this.canSign() && output.derivation) {
      secretKey = deriveSecretKey(
        output.derivation,
        output.outputIndex,
        this._spendSecretKey
      );
    }

    // Generate key image (to detect spent outputs)
    let keyImage = null;
    if (secretKey) {
      keyImage = generateKeyImage(output.publicKey, secretKey);
    }

    const utxo = {
      ...output,
      secretKey,
      keyImage,
      txHash: txInfo.txHash,
      blockHeight: txInfo.blockHeight,
      timestamp: txInfo.timestamp,
      globalIndex: txInfo.globalIndex || output.globalIndex,
      assetType,
      txType: txInfo.txType || TX_TYPE.TRANSFER
    };

    // Check if already spent
    if (keyImage && this._spentKeyImages.has(bytesToHex(keyImage))) {
      return null;
    }

    // Add to appropriate asset type bucket
    if (!this._utxos.has(assetType)) {
      this._utxos.set(assetType, []);
    }
    this._utxos.get(assetType).push(utxo);

    return utxo;
  }

  /**
   * Mark outputs as spent by key image
   * @param {Array<string|Uint8Array>} keyImages - Key images of spent outputs
   */
  markSpent(keyImages) {
    for (const ki of keyImages) {
      const kiHex = typeof ki === 'string' ? ki : bytesToHex(ki);
      this._spentKeyImages.add(kiHex);
    }

    // Remove from UTXOs (all asset types)
    for (const [assetType, utxos] of this._utxos) {
      this._utxos.set(assetType, utxos.filter(utxo => {
        if (!utxo.keyImage) return true;
        const kiHex = typeof utxo.keyImage === 'string'
          ? utxo.keyImage
          : bytesToHex(utxo.keyImage);
        return !this._spentKeyImages.has(kiHex);
      }));
    }
  }

  // ===========================================================================
  // BALANCE TRACKING
  // ===========================================================================

  /**
   * Get the wallet balance
   * @param {Object} options - Options
   * @param {number} options.accountIndex - Filter by account (optional)
   * @param {string} options.assetType - Asset type (default: 'SAL')
   * @returns {Object} { balance, unlockedBalance, lockedBalance }
   */
  getBalance(options = {}) {
    const { accountIndex = null, assetType = 'SAL' } = options;

    const utxos = this._utxos.get(assetType) || [];
    let balance = 0n;
    let unlockedBalance = 0n;

    for (const utxo of utxos) {
      // Filter by account if specified
      if (accountIndex !== null && utxo.subaddressIndex) {
        if (utxo.subaddressIndex.major !== accountIndex) continue;
      }

      const amount = typeof utxo.amount === 'bigint' ? utxo.amount : BigInt(utxo.amount);
      balance += amount;

      // Check if unlocked
      const isUnlocked = !utxo.blockHeight ||
        (this._syncHeight - utxo.blockHeight) >= DEFAULT_UNLOCK_BLOCKS;

      if (isUnlocked) {
        unlockedBalance += amount;
      }
    }

    // Subtract locked staked coins
    for (const [ki, locked] of this._lockedCoins) {
      if (locked.assetType === assetType) {
        // Locked stakes are still in balance but not unlocked
        // (already counted above, don't double-count)
      }
    }

    return {
      balance,
      unlockedBalance,
      lockedBalance: balance - unlockedBalance
    };
  }

  /**
   * Get all unspent outputs
   * @param {Object} options - Filter options
   * @param {boolean} options.unlockedOnly - Only return unlocked outputs
   * @param {number} options.accountIndex - Filter by account
   * @param {string} options.assetType - Asset type (default: 'SAL')
   * @returns {Array<Object>} UTXOs
   */
  getUTXOs(options = {}) {
    const {
      unlockedOnly = false,
      accountIndex = null,
      assetType = 'SAL'
    } = options;

    let utxos = this._utxos.get(assetType) || [];

    // Filter by account
    if (accountIndex !== null) {
      utxos = utxos.filter(u =>
        !u.subaddressIndex || u.subaddressIndex.major === accountIndex
      );
    }

    // Filter by unlock status
    if (unlockedOnly) {
      utxos = utxos.filter(utxo => {
        const isUnlocked = !utxo.blockHeight ||
          (this._syncHeight - utxo.blockHeight) >= DEFAULT_UNLOCK_BLOCKS;
        return isUnlocked;
      });
    }

    return [...utxos];
  }

  /**
   * Get all asset types with balances
   * @returns {Array<string>} Asset types
   */
  getAssetTypes() {
    return Array.from(this._utxos.keys());
  }

  // ===========================================================================
  // TRANSACTION BUILDING
  // ===========================================================================

  /**
   * Build a transaction
   * @param {Array<Object>} destinations - Outputs to create
   * @param {Object} options - Transaction options
   * @returns {Promise<Object>} Built transaction
   */
  async createTransaction(destinations, options = {}) {
    if (!this.canSign()) {
      throw new Error('Full wallet required to create transactions');
    }

    const {
      priority = 'default',
      ringSize = 16,
      utxoStrategy = UTXO_STRATEGY.LARGEST_FIRST,
      rpcClient = null,
      assetType = 'SAL',
      accountIndex = 0
    } = options;

    // Parse destination addresses
    const parsedDestinations = destinations.map(dest => {
      const parsed = parseAddress(dest.address);
      if (!parsed.valid) {
        throw new Error(`Invalid destination address: ${dest.address}`);
      }
      return {
        ...dest,
        viewPublicKey: parsed.viewPublicKey,
        spendPublicKey: parsed.spendPublicKey,
        isSubaddress: parsed.type === 'subaddress',
        amount: typeof dest.amount === 'bigint' ? dest.amount : BigInt(dest.amount)
      };
    });

    // Calculate total amount needed
    const totalAmount = parsedDestinations.reduce(
      (sum, d) => sum + d.amount,
      0n
    );

    // Estimate fee
    const estimatedFee = estimateTransactionFee(
      1,
      parsedDestinations.length + 1,
      { priority, ringSize }
    );

    // Select UTXOs from specified account
    const availableUTXOs = this.getUTXOs({
      unlockedOnly: true,
      accountIndex,
      assetType
    });

    const { selected, changeAmount } = selectUTXOs(
      availableUTXOs,
      totalAmount,
      estimatedFee,
      {
        strategy: utxoStrategy,
        currentHeight: this._syncHeight,
        dustThreshold: 1000000n
      }
    );

    // Prepare inputs with decoys
    const preparedInputs = await prepareInputs(selected, rpcClient, { ringSize });

    // Recalculate fee with actual input count
    const actualFee = estimateTransactionFee(
      preparedInputs.length,
      parsedDestinations.length + (changeAmount > 0n ? 1 : 0),
      { priority, ringSize }
    );

    // Build change output to first subaddress in account
    const changeAddress = {
      viewPublicKey: this._viewPublicKey,
      spendPublicKey: this._spendPublicKey,
      isSubaddress: false
    };

    // Build transaction
    const tx = buildTransaction({
      inputs: preparedInputs,
      destinations: parsedDestinations,
      changeAddress,
      fee: actualFee
    });

    // Validate
    const validation = validateTransaction(tx);
    if (!validation.valid) {
      throw new Error(`Transaction validation failed: ${validation.errors.join(', ')}`);
    }

    return tx;
  }

  /**
   * Create a stake transaction (Salvium-specific)
   * @param {bigint} amount - Amount to stake
   * @param {Object} options - Options
   * @returns {Promise<Object>} Stake transaction
   */
  async createStakeTransaction(amount, options = {}) {
    // TODO: Implement stake transaction following Salvium spec
    // This creates a TX_TYPE.STAKE transaction
    throw new Error('Stake transactions not yet implemented');
  }

  /**
   * Create an audit transaction (Salvium-specific)
   * @param {Object} options - Options
   * @returns {Promise<Object>} Audit transaction
   */
  async createAuditTransaction(options = {}) {
    // TODO: Implement audit transaction following Salvium spec
    // This creates a TX_TYPE.AUDIT transaction
    throw new Error('Audit transactions not yet implemented');
  }

  /**
   * Serialize a transaction for broadcast
   * @param {Object} tx - Transaction to serialize
   * @returns {Uint8Array} Serialized transaction
   */
  serializeTransaction(tx) {
    return serializeTransaction(tx);
  }

  // ===========================================================================
  // SWEEP FUNCTIONS
  // ===========================================================================

  /**
   * Sweep all funds to an address
   * @param {string} address - Destination address
   * @param {Object} options - Options
   * @returns {Promise<Object>} Sweep transaction
   */
  async sweepAll(address, options = {}) {
    const { accountIndex = 0, assetType = 'SAL', priority = 'default' } = options;

    const utxos = this.getUTXOs({ unlockedOnly: true, accountIndex, assetType });
    if (utxos.length === 0) {
      throw new Error('No unlocked outputs to sweep');
    }

    const totalAmount = utxos.reduce((sum, u) => sum + BigInt(u.amount), 0n);

    // Estimate fee for all inputs
    const fee = estimateTransactionFee(utxos.length, 1, { priority });

    if (totalAmount <= fee) {
      throw new Error('Insufficient funds to cover fee');
    }

    return this.createTransaction(
      [{ address, amount: totalAmount - fee }],
      { ...options, accountIndex, assetType }
    );
  }

  /**
   * Sweep dust outputs
   * @param {string} address - Destination address
   * @param {bigint} dustThreshold - Threshold for dust (default: 1 SAL)
   * @param {Object} options - Options
   * @returns {Promise<Object>} Sweep transaction
   */
  async sweepDust(address, dustThreshold = 100000000n, options = {}) {
    const { accountIndex = 0, assetType = 'SAL' } = options;

    const utxos = this.getUTXOs({ unlockedOnly: true, accountIndex, assetType });
    const dustOutputs = utxos.filter(u => BigInt(u.amount) < dustThreshold);

    if (dustOutputs.length === 0) {
      throw new Error('No dust outputs to sweep');
    }

    const totalAmount = dustOutputs.reduce((sum, u) => sum + BigInt(u.amount), 0n);
    const fee = estimateTransactionFee(dustOutputs.length, 1, { priority: 'low' });

    if (totalAmount <= fee) {
      throw new Error('Dust amount insufficient to cover fee');
    }

    // Build transaction with only dust outputs
    // TODO: Implement selective UTXO transaction building
    throw new Error('Sweep dust not yet fully implemented');
  }

  // ===========================================================================
  // SYNC STATE
  // ===========================================================================

  /** Set the current sync height */
  setSyncHeight(height) { this._syncHeight = height; }

  /** Get the current sync height */
  getSyncHeight() { return this._syncHeight; }

  /** Check if synced to a given height */
  isSynced(targetHeight = null) {
    if (targetHeight === null) return true; // No target specified
    return this._syncHeight >= targetHeight;
  }

  // ===========================================================================
  // YIELD TRACKING (Salvium-specific)
  // ===========================================================================

  /**
   * Get yield payout history
   * @returns {Array<Object>} Yield payouts
   */
  getYieldPayouts() {
    return [...this._yieldPayouts];
  }

  /**
   * Get total yield earned
   * @returns {bigint} Total yield amount
   */
  getTotalYield() {
    return this._yieldPayouts.reduce((sum, p) => sum + BigInt(p.amount), 0n);
  }

  /**
   * Get locked coins (staked)
   * @returns {Array<Object>} Locked coins
   */
  getLockedCoins() {
    return Array.from(this._lockedCoins.values());
  }

  // ===========================================================================
  // SERIALIZATION
  // ===========================================================================

  /**
   * Export wallet to JSON (for storage)
   * @param {boolean} includeSecrets - Include secret keys (default: true)
   * @returns {Object} Wallet data
   */
  toJSON(includeSecrets = true) {
    const data = {
      version: 2,
      type: this.type,
      network: this.network,
      format: this.format,
      spendPublicKey: bytesToHex(this._spendPublicKey),
      viewPublicKey: bytesToHex(this._viewPublicKey),
      syncHeight: this._syncHeight,
      address: this.getAddress(),
      accounts: this._accounts.map(a => ({
        index: a.index,
        label: a.label
      })),
      nextSubaddressIndex: Object.fromEntries(this._nextSubaddressIndex)
    };

    if (includeSecrets) {
      if (this._seed) {
        data.seed = bytesToHex(this._seed);
      }
      if (this._spendSecretKey) {
        data.spendSecretKey = bytesToHex(this._spendSecretKey);
      }
      if (this._viewSecretKey) {
        data.viewSecretKey = bytesToHex(this._viewSecretKey);
      }
    }

    return data;
  }

  /**
   * Import wallet from JSON
   * @param {Object} data - Wallet data
   * @returns {Wallet} Wallet instance
   */
  static fromJSON(data) {
    let wallet;

    // Determine how to restore based on available data
    if (data.seed) {
      wallet = Wallet.fromSeed(data.seed, {
        network: data.network,
        format: data.format
      });
    } else if (data.spendSecretKey) {
      wallet = new Wallet({
        type: WALLET_TYPE.FULL,
        network: data.network,
        format: data.format
      });
      wallet._spendSecretKey = hexToBytes(data.spendSecretKey);
      wallet._spendPublicKey = hexToBytes(data.spendPublicKey);
      wallet._viewSecretKey = data.viewSecretKey ? hexToBytes(data.viewSecretKey) : null;
      wallet._viewPublicKey = hexToBytes(data.viewPublicKey);
    } else if (data.viewSecretKey) {
      wallet = Wallet.fromViewKey(
        data.viewSecretKey,
        data.spendPublicKey,
        { network: data.network, format: data.format }
      );
    } else {
      wallet = Wallet.fromAddress(data.address, {
        network: data.network,
        format: data.format
      });
    }

    // Restore sync height
    wallet._syncHeight = data.syncHeight || 0;

    // Restore accounts (v2+)
    if (data.accounts && data.version >= 2) {
      wallet._accounts = [];
      for (const acc of data.accounts) {
        wallet._accounts.push(new Account(wallet, acc.index, acc.label));
      }
    }

    // Restore subaddress indices
    if (data.nextSubaddressIndex) {
      wallet._nextSubaddressIndex = new Map(
        Object.entries(data.nextSubaddressIndex).map(([k, v]) => [parseInt(k), v])
      );
    }

    return wallet;
  }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * Create a new wallet (convenience function)
 * @param {Object} options - Wallet options
 * @returns {Wallet} New wallet
 */
export function createWallet(options = {}) {
  return Wallet.create(options);
}

/**
 * Restore wallet from mnemonic (convenience function)
 * @param {string} mnemonic - 25-word mnemonic
 * @param {Object} options - Wallet options
 * @returns {Wallet} Restored wallet
 */
export function restoreWallet(mnemonic, options = {}) {
  return Wallet.fromMnemonic(mnemonic, options);
}

/**
 * Create view-only wallet (convenience function)
 * @param {string} viewSecretKey - View secret key (hex)
 * @param {string} spendPublicKey - Spend public key (hex)
 * @param {Object} options - Wallet options
 * @returns {Wallet} View-only wallet
 */
export function createViewOnlyWallet(viewSecretKey, spendPublicKey, options = {}) {
  return Wallet.fromViewKey(viewSecretKey, spendPublicKey, options);
}

// Re-export for backwards compatibility
export { UTXO_STRATEGY };
