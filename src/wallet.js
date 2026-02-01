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
import { derivationToScalar, scanTransaction } from './scanning.js';
import { generateKeyDerivation, deriveSecretKey, generateKeyImage, scalarMultBase } from './crypto/index.js';
import {
  buildTransaction,
  buildStakeTransaction,
  buildBurnTransaction,
  buildConvertTransaction,
  buildAuditTransaction,
  signTransaction,
  prepareInputs,
  selectUTXOs,
  estimateTransactionFee,
  validateTransaction,
  serializeTransaction,
  UTXO_STRATEGY
} from './transaction.js';
import { NETWORK, ADDRESS_FORMAT } from './constants.js';
import { getNetworkConfig, HF_VERSION, getHfVersionForHeight, isCarrotActive, NETWORK_ID } from './consensus.js';
import { seedToMnemonic, mnemonicToSeed, validateMnemonic } from './mnemonic.js';

// ============================================================================
// IMPORTS FROM WALLET SUBMODULES
// ============================================================================

// Import from wallet submodules and re-export for backward compatibility
import {
  MAX_SUBADDRESS_MAJOR_INDEX as _MAX_SUBADDRESS_MAJOR_INDEX,
  MAX_SUBADDRESS_MINOR_INDEX as _MAX_SUBADDRESS_MINOR_INDEX,
  DEFAULT_UNLOCK_BLOCKS as _DEFAULT_UNLOCK_BLOCKS,
  WALLET_TYPE as _WALLET_TYPE,
  TX_TYPE as _TX_TYPE
} from './wallet/constants.js';

import {
  WalletListener as _WalletListener,
  ConsoleListener,
  CallbackListener
} from './wallet/listener.js';

import { Account as _Account } from './wallet/account.js';

// Re-export for backward compatibility
export const MAX_SUBADDRESS_MAJOR_INDEX = _MAX_SUBADDRESS_MAJOR_INDEX;
export const MAX_SUBADDRESS_MINOR_INDEX = _MAX_SUBADDRESS_MINOR_INDEX;
export const DEFAULT_UNLOCK_BLOCKS = _DEFAULT_UNLOCK_BLOCKS;
export const WALLET_TYPE = _WALLET_TYPE;
export const TX_TYPE = _TX_TYPE;
export const WalletListener = _WalletListener;
export const Account = _Account;
export { ConsoleListener, CallbackListener };


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
    this._hfVersion = HF_VERSION.CARROT; // Fallback for pre-sync state (overridden by height-based detection during sync)

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
   *
   * Stakes the specified amount for STAKE_LOCK_PERIOD blocks to earn yield.
   * The staked amount is locked and returned via PROTOCOL transaction after maturity.
   *
   * @param {bigint|number|string} amount - Amount to stake (in atomic units)
   * @param {Object} options - Options
   * @param {string} options.assetType - Asset type to stake ('SAL' or 'SAL1', default: 'SAL')
   * @param {number} options.accountIndex - Account index (default: 0)
   * @param {number} options.ringSize - Ring size for privacy (default: 16)
   * @param {string} options.priority - Fee priority ('low', 'default', 'high')
   * @param {Object} options.rpcClient - RPC client for fetching decoys
   * @returns {Promise<Object>} Stake transaction ready for broadcast
   */
  async createStakeTransaction(amount, options = {}) {
    if (!this.canSign()) {
      throw new Error('Full wallet required to create stake transactions');
    }

    const {
      assetType = 'SAL',
      accountIndex = 0,
      ringSize = 16,
      priority = 'default',
      rpcClient = null
    } = options;

    // Validate asset type
    if (assetType !== 'SAL' && assetType !== 'SAL1') {
      throw new Error('STAKE transactions must use SAL or SAL1 asset type');
    }

    // Convert amount to bigint
    const stakeAmount = typeof amount === 'bigint' ? amount :
                        typeof amount === 'string' ? BigInt(amount) : BigInt(Math.floor(amount));

    if (stakeAmount <= 0n) {
      throw new Error('Stake amount must be positive');
    }

    // Get network config for STAKE_LOCK_PERIOD
    const networkConfig = getNetworkConfig(this.network);
    const stakeLockPeriod = networkConfig.STAKE_LOCK_PERIOD;

    // Estimate fee (STAKE tx has 1 input minimum, 1 output - change only)
    const estimatedFee = estimateTransactionFee(
      1, // inputs
      1, // outputs (change only)
      { priority, ringSize }
    );

    // Select UTXOs from specified account
    const availableUTXOs = this.getUTXOs({
      unlockedOnly: true,
      accountIndex,
      assetType
    });

    if (availableUTXOs.length === 0) {
      throw new Error(`No unlocked ${assetType} outputs available for staking`);
    }

    // Select UTXOs to cover stake amount + fee
    const { selected, changeAmount } = selectUTXOs(
      availableUTXOs,
      stakeAmount,
      estimatedFee,
      {
        strategy: UTXO_STRATEGY.LARGEST_FIRST,
        currentHeight: this._syncHeight,
        dustThreshold: 1000000n
      }
    );

    if (selected.length === 0) {
      throw new Error(`Insufficient ${assetType} balance for stake of ${stakeAmount} + fee ${estimatedFee}`);
    }

    // Prepare inputs with ring members (decoys)
    const preparedInputs = await prepareInputs(selected, rpcClient, { ringSize });

    // Recalculate fee with actual input count
    const actualFee = estimateTransactionFee(
      preparedInputs.length,
      1, // Only change output
      { priority, ringSize }
    );

    // Return address is own address (stake returns to self)
    const returnAddress = {
      viewPublicKey: this._viewPublicKey,
      spendPublicKey: this._spendPublicKey,
      isSubaddress: false
    };

    // Build the stake transaction
    const tx = buildStakeTransaction(
      {
        inputs: preparedInputs,
        stakeAmount,
        returnAddress,
        fee: actualFee
      },
      {
        stakeLockPeriod,
        assetType,
        useCarrot: this.isCarrotEnabled()
      }
    );

    // Validate
    const validation = validateTransaction(tx);
    if (!validation.valid) {
      throw new Error(`Stake transaction validation failed: ${validation.errors.join(', ')}`);
    }

    // Add metadata for tracking
    tx._meta = tx._meta || {};
    tx._meta.txType = TX_TYPE.STAKE;
    tx._meta.stakeAmount = stakeAmount.toString();
    tx._meta.stakeLockPeriod = stakeLockPeriod;
    tx._meta.unlockHeight = this._syncHeight + stakeLockPeriod;
    tx._meta.assetType = assetType;

    return tx;
  }

  /**
   * Create a BURN transaction (Salvium-specific)
   *
   * Burns coins permanently - they are destroyed and cannot be recovered.
   * The burned amount is recorded in amount_burnt with destination_asset_type = "BURN".
   *
   * @param {BigInt|number|string} amount - Amount to burn
   * @param {Object} options - Transaction options:
   * @param {string} options.assetType - Asset type to burn ('SAL' or 'SAL1', default 'SAL')
   * @param {number} options.accountIndex - Account index to burn from (default 0)
   * @param {number} options.ringSize - Ring size for CLSAG (default 16)
   * @param {string} options.priority - Fee priority ('low', 'default', 'high')
   * @param {Object} options.rpcClient - RPC client for fetching decoys
   * @returns {Promise<Object>} Burn transaction ready for broadcast
   */
  async createBurnTransaction(amount, options = {}) {
    if (!this.canSign()) {
      throw new Error('Full wallet required to create burn transactions');
    }

    const {
      assetType = 'SAL',
      accountIndex = 0,
      ringSize = 16,
      priority = 'default',
      rpcClient = null
    } = options;

    // Validate asset type
    if (assetType !== 'SAL' && assetType !== 'SAL1') {
      throw new Error('BURN transactions must use SAL or SAL1 asset type');
    }

    // Convert amount to bigint
    const burnAmount = typeof amount === 'bigint' ? amount :
                       typeof amount === 'string' ? BigInt(amount) : BigInt(Math.floor(amount));

    if (burnAmount <= 0n) {
      throw new Error('Burn amount must be positive');
    }

    // Estimate fee (BURN tx has 1 input minimum, 1 output - change only)
    const estimatedFee = estimateTransactionFee(
      1, // inputs
      1, // outputs (change only)
      { priority, ringSize }
    );

    // Select UTXOs from specified account
    const availableUTXOs = this.getUTXOs({
      unlockedOnly: true,
      accountIndex,
      assetType
    });

    if (availableUTXOs.length === 0) {
      throw new Error(`No unlocked ${assetType} outputs available for burning`);
    }

    // Select UTXOs to cover burn amount + fee
    const { selected, changeAmount } = selectUTXOs(
      availableUTXOs,
      burnAmount,
      estimatedFee,
      {
        strategy: UTXO_STRATEGY.LARGEST_FIRST,
        currentHeight: this._syncHeight,
        dustThreshold: 1000000n
      }
    );

    if (selected.length === 0) {
      throw new Error(`Insufficient ${assetType} balance for burn of ${burnAmount} + fee ${estimatedFee}`);
    }

    // Prepare inputs with ring members (decoys)
    const preparedInputs = await prepareInputs(selected, rpcClient, { ringSize });

    // Recalculate fee with actual input count
    const actualFee = estimateTransactionFee(
      preparedInputs.length,
      1, // Only change output
      { priority, ringSize }
    );

    // Change address is own address
    const changeAddress = {
      viewPublicKey: this._viewPublicKey,
      spendPublicKey: this._spendPublicKey,
      isSubaddress: false
    };

    // Build the burn transaction
    const tx = buildBurnTransaction(
      {
        inputs: preparedInputs,
        burnAmount,
        changeAddress,
        fee: actualFee
      },
      {
        assetType,
        useCarrot: this.isCarrotEnabled()
      }
    );

    // Validate
    const validation = validateTransaction(tx);
    if (!validation.valid) {
      throw new Error(`Burn transaction validation failed: ${validation.errors.join(', ')}`);
    }

    // Add metadata for tracking
    tx._meta = tx._meta || {};
    tx._meta.txType = TX_TYPE.BURN;
    tx._meta.burnAmount = burnAmount.toString();
    tx._meta.assetType = assetType;

    return tx;
  }

  /**
   * Create a CONVERT transaction (Salvium-specific)
   *
   * CONVERT transactions convert between asset types (SAL <-> VSD) using oracle pricing.
   * The actual conversion happens at the protocol layer when the block is mined.
   *
   * NOTE: CONVERT transactions are currently gated behind hard fork version 255
   * and are not yet enabled on mainnet. This function will build valid transactions
   * but they will be rejected by nodes until the feature is activated.
   *
   * @param {bigint|number|string} amount - Amount to convert (in source asset atomic units)
   * @param {Object} options - Options:
   *   - sourceAsset: Asset to convert FROM ('SAL' or 'VSD'), default 'SAL'
   *   - destAsset: Asset to convert TO ('VSD' or 'SAL'), default 'VSD'
   *   - slippageLimit: Maximum acceptable slippage (default: 3.125% = amount/32)
   *   - accountIndex: Source account index (default: 0)
   *   - ringSize: Ring size for anonymity (default: 16)
   *   - priority: Fee priority ('low'|'default'|'elevated'|'priority')
   *   - rpcClient: RPC client for fetching ring members
   * @returns {Promise<Object>} Convert transaction ready for broadcast
   */
  async createConvertTransaction(amount, options = {}) {
    if (!this.canSign()) {
      throw new Error('Full wallet required to create convert transactions');
    }

    const {
      sourceAsset = 'SAL',
      destAsset = 'VSD',
      slippageLimit = null,  // null = use default (3.125%)
      accountIndex = 0,
      ringSize = 16,
      priority = 'default',
      rpcClient = null
    } = options;

    // Validate asset types
    const validAssets = ['SAL', 'VSD'];
    if (!validAssets.includes(sourceAsset)) {
      throw new Error(`Invalid source asset: ${sourceAsset}. Must be SAL or VSD`);
    }
    if (!validAssets.includes(destAsset)) {
      throw new Error(`Invalid destination asset: ${destAsset}. Must be SAL or VSD`);
    }
    if (sourceAsset === destAsset) {
      throw new Error('Source and destination assets must be different for conversion');
    }

    // Convert amount to bigint
    const convertAmount = typeof amount === 'bigint' ? amount :
                          typeof amount === 'string' ? BigInt(amount) : BigInt(Math.floor(amount));

    if (convertAmount <= 0n) {
      throw new Error('Convert amount must be positive');
    }

    // Calculate slippage limit
    const defaultSlippage = convertAmount >> 5n; // 1/32 = 3.125%
    let slippageLimitBig;
    if (slippageLimit !== null && slippageLimit !== undefined) {
      slippageLimitBig = typeof slippageLimit === 'bigint' ? slippageLimit :
                         typeof slippageLimit === 'string' ? BigInt(slippageLimit) :
                         BigInt(Math.floor(slippageLimit));
      if (slippageLimitBig < defaultSlippage) {
        throw new Error(`Slippage limit ${slippageLimitBig} is below protocol minimum ${defaultSlippage} (3.125%)`);
      }
    } else {
      slippageLimitBig = defaultSlippage;
    }

    // Estimate fee (CONVERT tx has 1 input minimum, 1 output - change only)
    // The converted output is created by the protocol_tx at block time
    const estimatedFee = estimateTransactionFee(
      1, // inputs
      1, // outputs (change only)
      { priority, ringSize }
    );

    // Select UTXOs from specified account
    const availableUTXOs = this.getUTXOs({
      unlockedOnly: true,
      accountIndex,
      assetType: sourceAsset
    });

    if (availableUTXOs.length === 0) {
      throw new Error(`No unlocked ${sourceAsset} outputs available for conversion`);
    }

    // Select UTXOs to cover convert amount + fee
    const { selected, changeAmount } = selectUTXOs(
      availableUTXOs,
      convertAmount,
      estimatedFee,
      {
        strategy: UTXO_STRATEGY.LARGEST_FIRST,
        currentHeight: this._syncHeight,
        dustThreshold: 1000000n
      }
    );

    if (selected.length === 0) {
      throw new Error(`Insufficient ${sourceAsset} balance for conversion of ${convertAmount} + fee ${estimatedFee}`);
    }

    // Prepare inputs with ring members (decoys)
    const preparedInputs = await prepareInputs(selected, rpcClient, { ringSize });

    // Recalculate fee with actual input count
    const actualFee = estimateTransactionFee(
      preparedInputs.length,
      1, // Only change output (converted amount from protocol_tx)
      { priority, ringSize }
    );

    // Change address is own address
    const changeAddress = {
      viewPublicKey: this._viewPublicKey,
      spendPublicKey: this._spendPublicKey,
      isSubaddress: false
    };

    // Return address for receiving converted amount (also own address)
    // This is where the protocol_tx will send the converted output
    const returnAddress = this._spendPublicKey;
    const returnPubkey = this._viewPublicKey;

    // Build the convert transaction
    const tx = buildConvertTransaction(
      {
        inputs: preparedInputs,
        convertAmount,
        sourceAsset,
        destAsset,
        slippageLimit: slippageLimitBig,
        changeAddress,
        returnAddress,
        returnPubkey,
        fee: actualFee
      },
      {
        useCarrot: this.isCarrotEnabled()
      }
    );

    // Validate
    const validation = validateTransaction(tx);
    if (!validation.valid) {
      throw new Error(`Convert transaction validation failed: ${validation.errors.join(', ')}`);
    }

    // Add metadata for tracking
    tx._meta = tx._meta || {};
    tx._meta.txType = 'CONVERT';
    tx._meta.convertAmount = convertAmount.toString();
    tx._meta.sourceAsset = sourceAsset;
    tx._meta.destAsset = destAsset;
    tx._meta.slippageLimit = slippageLimitBig.toString();
    tx._meta.expectedSlippage = defaultSlippage.toString();

    return tx;
  }

  /**
   * Create an AUDIT transaction (Salvium-specific)
   *
   * AUDIT transactions enable users to participate in periodic compliance/transparency
   * audits during designated AUDIT hard fork periods. Users voluntarily lock ALL their
   * holdings (or from a specific account/subaddress) for a defined period.
   *
   * NOTE: AUDIT transactions are only valid during specific AUDIT hard fork periods
   * (HF v6, v8). Transactions submitted outside these windows will be rejected.
   *
   * The change-is-zero requirement means ALL coins must be locked - no partial audits.
   * Coins are returned via protocol_tx after the lock period expires.
   *
   * @param {Object} options - Options:
   *   - sourceAsset: Asset to audit ('SAL' or 'SAL1' depending on HF), default 'SAL'
   *   - destAsset: Asset received after maturity ('SAL1'), default 'SAL1'
   *   - accountIndex: Source account index (default: 0)
   *   - subaddressIndices: Specific subaddresses to audit (default: all)
   *   - lockPeriod: Lock period in blocks (default: network-specific from AUDIT_HARD_FORKS)
   *   - ringSize: Ring size for anonymity (default: 16)
   *   - priority: Fee priority ('low'|'default'|'elevated'|'priority')
   *   - rpcClient: RPC client for fetching ring members
   * @returns {Promise<Object>} Audit transaction ready for broadcast
   */
  async createAuditTransaction(options = {}) {
    if (!this.canSign()) {
      throw new Error('Full wallet required to create audit transactions');
    }

    const {
      sourceAsset = 'SAL',
      destAsset = 'SAL1',
      accountIndex = 0,
      subaddressIndices = null,  // null = all subaddresses in account
      lockPeriod = null,  // null = use network default from AUDIT_HARD_FORKS
      ringSize = 16,
      priority = 'default',
      rpcClient = null
    } = options;

    // Validate asset types
    const validSourceAssets = ['SAL', 'SAL1'];
    if (!validSourceAssets.includes(sourceAsset)) {
      throw new Error(`Invalid source asset: ${sourceAsset}. Must be SAL or SAL1`);
    }
    if (destAsset !== 'SAL1') {
      throw new Error(`Invalid destination asset: ${destAsset}. AUDIT destination must be SAL1`);
    }

    // Get all UTXOs from the specified account/subaddresses
    const utxoOptions = {
      unlockedOnly: true,
      accountIndex,
      assetType: sourceAsset
    };
    if (subaddressIndices) {
      utxoOptions.subaddressIndices = subaddressIndices;
    }

    const availableUTXOs = this.getUTXOs(utxoOptions);

    if (availableUTXOs.length === 0) {
      throw new Error(`No unlocked ${sourceAsset} outputs available for audit`);
    }

    // Calculate total amount to audit (ALL coins - change-is-zero requirement)
    let totalAmount = 0n;
    for (const utxo of availableUTXOs) {
      totalAmount += typeof utxo.amount === 'bigint' ? utxo.amount : BigInt(utxo.amount);
    }

    // Estimate fee for all inputs, 0 outputs (AUDIT has no outputs)
    const estimatedFee = estimateTransactionFee(
      availableUTXOs.length,
      0,  // AUDIT has 0 outputs (change-is-zero)
      { priority, ringSize }
    );

    // Audit amount is total minus fee
    const auditAmount = totalAmount - estimatedFee;
    if (auditAmount <= 0n) {
      throw new Error(`Insufficient funds: total ${totalAmount} minus fee ${estimatedFee} <= 0`);
    }

    // Prepare inputs with ring members (decoys)
    const preparedInputs = await prepareInputs(availableUTXOs, rpcClient, { ringSize });

    // Recalculate fee with actual input count
    const actualFee = estimateTransactionFee(
      preparedInputs.length,
      0,  // AUDIT has 0 outputs
      { priority, ringSize }
    );

    // Recalculate audit amount with actual fee
    const actualAuditAmount = totalAmount - actualFee;
    if (actualAuditAmount <= 0n) {
      throw new Error(`Insufficient funds after fee calculation`);
    }

    // Calculate unlock height
    // Default lock periods from C++: mainnet 30*24*10 or 30*24*14, testnet 30 or 40
    const defaultLockPeriod = 30 * 24 * 10;  // ~10 days on mainnet (1 block/min)
    const lockBlocks = lockPeriod || defaultLockPeriod;
    const unlockHeight = this._syncHeight + lockBlocks;

    // Return address and pubkey for receiving coins after maturity
    const returnAddress = this._spendPublicKey;
    const returnPubkey = this._viewPublicKey;

    // Build the audit transaction
    const tx = buildAuditTransaction(
      {
        inputs: preparedInputs,
        auditAmount: actualAuditAmount,
        sourceAsset,
        destAsset,
        unlockHeight,
        returnAddress,
        returnPubkey,
        fee: actualFee
      },
      {
        useCarrot: false,
        viewSecretKey: this._viewSecretKey,  // For audit disclosure
        spendPublicKey: this._spendPublicKey  // For spend authority verification
      }
    );

    // Validate
    const validation = validateTransaction(tx);
    if (!validation.valid) {
      throw new Error(`Audit transaction validation failed: ${validation.errors.join(', ')}`);
    }

    // Add metadata for tracking
    tx._meta = tx._meta || {};
    tx._meta.txType = 'AUDIT';
    tx._meta.auditAmount = actualAuditAmount.toString();
    tx._meta.sourceAsset = sourceAsset;
    tx._meta.destAsset = destAsset;
    tx._meta.unlockHeight = unlockHeight;
    tx._meta.lockPeriod = lockBlocks;

    return tx;
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
    if (!this.canSign()) {
      throw new Error('Full wallet required to sweep dust');
    }

    const {
      accountIndex = 0,
      assetType = 'SAL',
      ringSize = 16,
      priority = 'low',
      rpcClient = null
    } = options;

    // Get all unlocked UTXOs for account
    const utxos = this.getUTXOs({ unlockedOnly: true, accountIndex, assetType });
    const dustOutputs = utxos.filter(u => BigInt(u.amount) < dustThreshold);

    if (dustOutputs.length === 0) {
      throw new Error('No dust outputs to sweep');
    }

    // Calculate total amount from dust
    const totalAmount = dustOutputs.reduce((sum, u) => sum + BigInt(u.amount), 0n);

    // Estimate fee for sweeping all dust outputs
    const estimatedFee = estimateTransactionFee(
      dustOutputs.length,
      1, // single output (sweep to destination)
      { priority, ringSize }
    );

    if (totalAmount <= estimatedFee) {
      throw new Error(`Dust amount (${totalAmount}) insufficient to cover fee (${estimatedFee})`);
    }

    // Prepare inputs with ring members (decoys)
    const preparedInputs = await prepareInputs(dustOutputs, rpcClient, { ringSize });

    // Recalculate fee with actual input count
    const actualFee = estimateTransactionFee(
      preparedInputs.length,
      1,
      { priority, ringSize }
    );

    // Amount to sweep = total - fee
    const sweepAmount = totalAmount - actualFee;

    if (sweepAmount <= 0n) {
      throw new Error(`Dust amount insufficient after fee calculation`);
    }

    // Parse destination address
    const parsedDest = parseAddress(address);
    if (!parsedDest.valid) {
      throw new Error(`Invalid destination address: ${address}`);
    }

    // Build the sweep transaction
    const tx = buildTransaction(
      {
        inputs: preparedInputs,
        destinations: [{
          address: parsedDest,
          amount: sweepAmount
        }],
        fee: actualFee,
        // No change output - we're sweeping everything
        changeAddress: null
      },
      {
        txType: TX_TYPE.TRANSFER,
        sourceAssetType: assetType,
        destinationAssetType: assetType,
        useCarrot: parsedDest.format === ADDRESS_FORMAT.CARROT
      }
    );

    // Validate
    const validation = validateTransaction(tx);
    if (!validation.valid) {
      throw new Error(`Sweep transaction validation failed: ${validation.errors.join(', ')}`);
    }

    return tx;
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

  /**
   * Map wallet network string to NETWORK_ID integer
   * @returns {number} NETWORK_ID constant
   * @private
   */
  _getNetworkId() {
    switch (this.network) {
      case 'mainnet': return NETWORK_ID.MAINNET;
      case 'testnet': return NETWORK_ID.TESTNET;
      case 'stagenet': return NETWORK_ID.STAGENET;
      default: return NETWORK_ID.MAINNET;
    }
  }

  /**
   * Set the current hard fork version (deprecated - use sync height instead)
   * This is kept for backward compatibility but the HF version is now
   * automatically determined from the sync height and network.
   * @param {number} version - Hard fork version
   * @deprecated Use sync height to determine HF version automatically
   */
  setHfVersion(version) { this._hfVersion = version; }

  /**
   * Get the current hard fork version based on sync height and network
   * @returns {number} Hard fork version
   */
  getHfVersion() {
    // Use height-based detection if we have a sync height
    if (this._syncHeight > 0) {
      return getHfVersionForHeight(this._syncHeight, this._getNetworkId());
    }
    // Fall back to stored version (for pre-sync state)
    return this._hfVersion;
  }

  /**
   * Check if CARROT outputs are enabled at the current sync height
   * CARROT is enabled at HF version 10 (mainnet: 334750, testnet: 1100)
   * @returns {boolean} True if CARROT outputs should be used
   */
  isCarrotEnabled() {
    // Use height-based detection if we have a sync height
    if (this._syncHeight > 0) {
      return isCarrotActive(this._syncHeight, this._getNetworkId());
    }
    // Fall back to stored version (for pre-sync state)
    return this._hfVersion >= HF_VERSION.CARROT;
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
