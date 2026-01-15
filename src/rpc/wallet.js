/**
 * Wallet RPC Client
 *
 * Provides access to Salvium wallet RPC endpoints.
 * Includes account management, transfers, transaction history, signing, and more.
 *
 * Conventional ports (wallet RPC has no default in source - it's user-specified):
 * - Mainnet: 19083 (daemon port + 1)
 * - Testnet: 29083 (daemon port + 1)
 * - Stagenet: 39083 (daemon port + 1)
 *
 * Note: The wallet RPC server (salvium-wallet-rpc) must be started separately.
 * The --rpc-bind-port argument is required and has no default value.
 * Start with: salvium-wallet-rpc --wallet-file <wallet> --rpc-bind-port 19083
 */

import { RPCClient } from './client.js';

/**
 * @typedef {import('./client.js').RPCClientOptions} RPCClientOptions
 * @typedef {import('./client.js').RPCResponse} RPCResponse
 */

/**
 * @typedef {Object} TransferDestination
 * @property {string} address - Recipient address
 * @property {number|string} amount - Amount in atomic units
 * @property {string} [asset_type] - Asset type (default: SAL)
 */

/**
 * @typedef {Object} SubaddressIndex
 * @property {number} major - Account index
 * @property {number} minor - Address index within account
 */

/**
 * @typedef {Object} TransferEntry
 * @property {string} txid - Transaction ID
 * @property {string} payment_id - Payment ID
 * @property {number} height - Block height
 * @property {number} timestamp - Transaction timestamp
 * @property {number} amount - Amount in atomic units
 * @property {number} fee - Transaction fee
 * @property {string} type - Transaction type (in/out/pending/failed/pool)
 * @property {boolean} locked - Is locked
 * @property {number} unlock_time - Unlock time in blocks
 * @property {number} confirmations - Number of confirmations
 * @property {SubaddressIndex} subaddr_index - Source/destination subaddress
 * @property {string} address - Address
 * @property {boolean} double_spend_seen - Double spend detected
 */

/**
 * @typedef {Object} AddressInfo
 * @property {string} address - Standard address
 * @property {string} [address_cn] - CryptoNote format address
 * @property {string} [address_carrot] - Carrot format address
 * @property {string} label - Address label
 * @property {number} address_index - Address index
 * @property {boolean} used - Has received transactions
 */

/**
 * @typedef {Object} AccountInfo
 * @property {number} account_index - Account index
 * @property {string} base_address - Primary address for account
 * @property {number} balance - Total balance (atomic units)
 * @property {number} unlocked_balance - Unlocked balance (atomic units)
 * @property {string} label - Account label
 * @property {string} tag - Account tag
 */

/**
 * Transfer priority levels
 */
export const PRIORITY = {
  DEFAULT: 0,
  UNIMPORTANT: 1,
  NORMAL: 2,
  ELEVATED: 3,
  PRIORITY: 4
};

/**
 * Transfer types
 */
export const TRANSFER_TYPE = {
  ALL: 'all',
  AVAILABLE: 'available',
  UNAVAILABLE: 'unavailable'
};

/**
 * Wallet RPC Client
 */
export class WalletRPC extends RPCClient {
  /**
   * Create a Wallet RPC client
   * @param {RPCClientOptions} options - Client configuration
   */
  constructor(options = {}) {
    // Default to mainnet wallet RPC port if no URL provided
    if (!options.url) {
      options.url = 'http://localhost:19083';
    }
    super(options);
  }

  // ============================================================
  // Wallet Management
  // ============================================================

  /**
   * Create a new wallet
   * @param {string} filename - Wallet filename
   * @param {string} [password=''] - Wallet password
   * @param {string} [language='English'] - Seed language
   * @returns {Promise<RPCResponse>} Result
   */
  async createWallet(filename, password = '', language = 'English') {
    return this.call('create_wallet', {
      filename,
      password,
      language
    });
  }

  /**
   * Open an existing wallet
   * @param {string} filename - Wallet filename
   * @param {string} [password=''] - Wallet password
   * @returns {Promise<RPCResponse>} Result
   */
  async openWallet(filename, password = '') {
    return this.call('open_wallet', {
      filename,
      password
    });
  }

  /**
   * Close the current wallet
   * @returns {Promise<RPCResponse>} Result
   */
  async closeWallet() {
    return this.call('close_wallet');
  }

  /**
   * Restore a wallet from seed phrase
   * @param {Object} options - Restore options
   * @param {string} options.filename - Wallet filename
   * @param {string} options.seed - 25-word mnemonic seed
   * @param {string} [options.password=''] - Wallet password
   * @param {string} [options.seed_offset=''] - Seed passphrase
   * @param {number} [options.restore_height=0] - Restore from height
   * @param {string} [options.language='English'] - Seed language
   * @param {boolean} [options.autosave_current=true] - Auto-save current wallet
   * @returns {Promise<RPCResponse>} Result with address and seed
   */
  async restoreDeterministicWallet(options) {
    return this.call('restore_deterministic_wallet', {
      filename: options.filename,
      seed: options.seed,
      password: options.password || '',
      seed_offset: options.seed_offset || '',
      restore_height: options.restore_height || 0,
      language: options.language || 'English',
      autosave_current: options.autosave_current !== false
    });
  }

  /**
   * Restore a wallet from keys
   * @param {Object} options - Restore options
   * @param {string} options.filename - Wallet filename
   * @param {string} options.address - Wallet address
   * @param {string} options.viewkey - Private view key
   * @param {string} [options.spendkey] - Private spend key (omit for view-only)
   * @param {string} [options.password=''] - Wallet password
   * @param {number} [options.restore_height=0] - Restore from height
   * @param {boolean} [options.autosave_current=true] - Auto-save current wallet
   * @returns {Promise<RPCResponse>} Result with address and info
   */
  async generateFromKeys(options) {
    return this.call('generate_from_keys', {
      filename: options.filename,
      address: options.address,
      viewkey: options.viewkey,
      spendkey: options.spendkey || '',
      password: options.password || '',
      restore_height: options.restore_height || 0,
      autosave_current: options.autosave_current !== false
    });
  }

  /**
   * Change wallet password
   * @param {string} [oldPassword=''] - Current password
   * @param {string} [newPassword=''] - New password
   * @returns {Promise<RPCResponse>} Result
   */
  async changeWalletPassword(oldPassword = '', newPassword = '') {
    return this.call('change_wallet_password', {
      old_password: oldPassword,
      new_password: newPassword
    });
  }

  /**
   * Check if wallet is multisig
   * @returns {Promise<RPCResponse>} Multisig status
   */
  async isMultisig() {
    return this.call('is_multisig');
  }

  /**
   * Get wallet RPC version
   * @returns {Promise<RPCResponse>} Version info
   */
  async getVersion() {
    return this.call('get_version');
  }

  // ============================================================
  // Account & Address Operations
  // ============================================================

  /**
   * Get wallet addresses
   * @param {Object} [options={}] - Options
   * @param {number} [options.account_index=0] - Account index
   * @param {number[]} [options.address_index] - Specific address indices
   * @param {boolean} [options.carrot=true] - Include Carrot format addresses
   * @param {boolean} [options.cryptonote=true] - Include CryptoNote format addresses
   * @returns {Promise<RPCResponse>} Address info
   */
  async getAddress(options = {}) {
    return this.call('get_address', {
      account_index: options.account_index || 0,
      address_index: options.address_index,
      carrot: options.carrot !== false,
      cryptonote: options.cryptonote !== false
    });
  }

  /**
   * Get address index from address
   * @param {string} address - Address to look up
   * @returns {Promise<RPCResponse>} Address index info
   */
  async getAddressIndex(address) {
    return this.call('get_address_index', { address });
  }

  /**
   * Create a new subaddress
   * @param {number} [accountIndex=0] - Account index
   * @param {string} [label=''] - Address label
   * @returns {Promise<RPCResponse>} New address info
   */
  async createAddress(accountIndex = 0, label = '') {
    return this.call('create_address', {
      account_index: accountIndex,
      label
    });
  }

  /**
   * Label an address
   * @param {SubaddressIndex} index - Address index
   * @param {string} label - New label
   * @returns {Promise<RPCResponse>} Result
   */
  async labelAddress(index, label) {
    return this.call('label_address', {
      index,
      label
    });
  }

  /**
   * Get all accounts
   * @param {string} [tag] - Filter by tag
   * @param {boolean} [strictBalances=false] - Use strict balance calculation
   * @returns {Promise<RPCResponse>} Account list
   */
  async getAccounts(tag, strictBalances = false) {
    const params = { strict_balances: strictBalances };
    if (tag) params.tag = tag;
    return this.call('get_accounts', params);
  }

  /**
   * Create a new account
   * @param {string} [label=''] - Account label
   * @returns {Promise<RPCResponse>} New account info
   */
  async createAccount(label = '') {
    return this.call('create_account', { label });
  }

  /**
   * Label an account
   * @param {number} accountIndex - Account index
   * @param {string} label - New label
   * @returns {Promise<RPCResponse>} Result
   */
  async labelAccount(accountIndex, label) {
    return this.call('label_account', {
      account_index: accountIndex,
      label
    });
  }

  /**
   * Tag accounts
   * @param {string} tag - Tag name
   * @param {number[]} accounts - Account indices to tag
   * @returns {Promise<RPCResponse>} Result
   */
  async tagAccounts(tag, accounts) {
    return this.call('tag_accounts', { tag, accounts });
  }

  /**
   * Remove tags from accounts
   * @param {number[]} accounts - Account indices to untag
   * @returns {Promise<RPCResponse>} Result
   */
  async untagAccounts(accounts) {
    return this.call('untag_accounts', { accounts });
  }

  /**
   * Get account tags
   * @returns {Promise<RPCResponse>} Account tags info
   */
  async getAccountTags() {
    return this.call('get_account_tags');
  }

  /**
   * Set account tag description
   * @param {string} tag - Tag name
   * @param {string} description - Tag description
   * @returns {Promise<RPCResponse>} Result
   */
  async setAccountTagDescription(tag, description) {
    return this.call('set_account_tag_description', { tag, description });
  }

  /**
   * Validate an address
   * @param {string} address - Address to validate
   * @param {boolean} [anyNetType=false] - Allow any network type
   * @param {boolean} [allowOpenalias=false] - Resolve OpenAlias addresses
   * @returns {Promise<RPCResponse>} Validation result
   */
  async validateAddress(address, anyNetType = false, allowOpenalias = false) {
    return this.call('validate_address', {
      address,
      any_net_type: anyNetType,
      allow_openalias: allowOpenalias
    });
  }

  /**
   * Create an integrated address
   * @param {string} [standardAddress] - Standard address (uses primary if omitted)
   * @param {string} [paymentId] - Payment ID (generated if omitted)
   * @returns {Promise<RPCResponse>} Integrated address info
   */
  async makeIntegratedAddress(standardAddress, paymentId) {
    const params = {};
    if (standardAddress) params.standard_address = standardAddress;
    if (paymentId) params.payment_id = paymentId;
    return this.call('make_integrated_address', params);
  }

  /**
   * Split an integrated address into components
   * @param {string} integratedAddress - Integrated address
   * @returns {Promise<RPCResponse>} Standard address and payment ID
   */
  async splitIntegratedAddress(integratedAddress) {
    return this.call('split_integrated_address', {
      integrated_address: integratedAddress
    });
  }

  // ============================================================
  // Balance & History
  // ============================================================

  /**
   * Get wallet balance
   * @param {Object} [options={}] - Options
   * @param {number} [options.account_index=0] - Account index
   * @param {number[]} [options.address_indices] - Specific address indices
   * @param {string} [options.asset_type] - Asset type filter
   * @param {boolean} [options.all_accounts=false] - Include all accounts
   * @param {boolean} [options.all_assets=false] - Include all asset types
   * @param {boolean} [options.strict=false] - Strict balance calculation
   * @returns {Promise<RPCResponse>} Balance info
   */
  async getBalance(options = {}) {
    return this.call('get_balance', {
      account_index: options.account_index || 0,
      address_indices: options.address_indices,
      asset_type: options.asset_type,
      all_accounts: options.all_accounts || false,
      all_assets: options.all_assets || false,
      strict: options.strict || false
    });
  }

  /**
   * Get wallet height (sync height)
   * @returns {Promise<RPCResponse>} Wallet height
   */
  async getHeight() {
    return this.call('get_height');
  }

  /**
   * Get transaction history
   * @param {Object} [options={}] - Filter options
   * @param {boolean} [options.in=true] - Include incoming
   * @param {boolean} [options.out=true] - Include outgoing
   * @param {boolean} [options.pending=true] - Include pending
   * @param {boolean} [options.failed=false] - Include failed
   * @param {boolean} [options.pool=true] - Include mempool
   * @param {boolean} [options.filter_by_height=false] - Filter by height
   * @param {number} [options.min_height] - Minimum height
   * @param {number} [options.max_height] - Maximum height
   * @param {number} [options.account_index=0] - Account index
   * @param {number[]} [options.subaddr_indices] - Subaddress indices
   * @param {boolean} [options.all_accounts=false] - Include all accounts
   * @returns {Promise<RPCResponse>} Transfer lists by type
   */
  async getTransfers(options = {}) {
    return this.call('get_transfers', {
      in: options.in !== false,
      out: options.out !== false,
      pending: options.pending !== false,
      failed: options.failed || false,
      pool: options.pool !== false,
      filter_by_height: options.filter_by_height || false,
      min_height: options.min_height,
      max_height: options.max_height,
      account_index: options.account_index || 0,
      subaddr_indices: options.subaddr_indices,
      all_accounts: options.all_accounts || false
    });
  }

  /**
   * Get a single transfer by transaction ID
   * @param {string} txid - Transaction ID
   * @param {number} [accountIndex] - Account index
   * @returns {Promise<RPCResponse>} Transfer entry
   */
  async getTransferByTxid(txid, accountIndex) {
    const params = { txid };
    if (accountIndex !== undefined) params.account_index = accountIndex;
    return this.call('get_transfer_by_txid', params);
  }

  /**
   * Get payments by payment ID
   * @param {string} paymentId - Payment ID
   * @returns {Promise<RPCResponse>} Matching payments
   */
  async getPayments(paymentId) {
    return this.call('get_payments', { payment_id: paymentId });
  }

  /**
   * Get payments for multiple payment IDs
   * @param {string[]} paymentIds - Payment IDs
   * @param {number} [minBlockHeight=0] - Minimum block height
   * @returns {Promise<RPCResponse>} Matching payments
   */
  async getBulkPayments(paymentIds, minBlockHeight = 0) {
    return this.call('get_bulk_payments', {
      payment_ids: paymentIds,
      min_block_height: minBlockHeight
    });
  }

  /**
   * Get incoming transfers (outputs)
   * @param {Object} [options={}] - Options
   * @param {string} [options.transfer_type='all'] - 'all', 'available', or 'unavailable'
   * @param {number} [options.account_index=0] - Account index
   * @param {number[]} [options.subaddr_indices] - Subaddress indices
   * @returns {Promise<RPCResponse>} Incoming transfers
   */
  async incomingTransfers(options = {}) {
    return this.call('incoming_transfers', {
      transfer_type: options.transfer_type || 'all',
      account_index: options.account_index || 0,
      subaddr_indices: options.subaddr_indices
    });
  }

  // ============================================================
  // Transfer Operations
  // ============================================================

  /**
   * Send SAL to one or more destinations
   * @param {Object} options - Transfer options
   * @param {TransferDestination[]} options.destinations - Recipient addresses and amounts
   * @param {string} [options.source_asset='SAL'] - Source asset type
   * @param {string} [options.dest_asset='SAL'] - Destination asset type
   * @param {number} [options.account_index=0] - Source account index
   * @param {number[]} [options.subaddr_indices] - Source subaddress indices
   * @param {number} [options.priority=0] - Fee priority (0-4)
   * @param {number} [options.ring_size=0] - Ring size (0 for default)
   * @param {number} [options.unlock_time=0] - Unlock time in blocks
   * @param {string} [options.payment_id] - Payment ID (deprecated, use integrated address)
   * @param {boolean} [options.get_tx_key=true] - Return transaction key
   * @param {boolean} [options.do_not_relay=false] - Don't relay to network
   * @param {boolean} [options.get_tx_hex=false] - Return transaction hex
   * @param {boolean} [options.get_tx_metadata=false] - Return transaction metadata
   * @returns {Promise<RPCResponse>} Transaction info
   */
  async transfer(options) {
    return this.call('transfer', {
      destinations: options.destinations,
      source_asset: options.source_asset || 'SAL',
      dest_asset: options.dest_asset || 'SAL',
      account_index: options.account_index || 0,
      subaddr_indices: options.subaddr_indices,
      priority: options.priority || 0,
      ring_size: options.ring_size || 0,
      unlock_time: options.unlock_time || 0,
      payment_id: options.payment_id,
      get_tx_key: options.get_tx_key !== false,
      do_not_relay: options.do_not_relay || false,
      get_tx_hex: options.get_tx_hex || false,
      get_tx_metadata: options.get_tx_metadata || false
    });
  }

  /**
   * Send SAL with automatic transaction splitting
   * @param {Object} options - Transfer options (same as transfer())
   * @returns {Promise<RPCResponse>} Transaction info (may include multiple transactions)
   */
  async transferSplit(options) {
    return this.call('transfer_split', {
      destinations: options.destinations,
      source_asset: options.source_asset || 'SAL',
      dest_asset: options.dest_asset || 'SAL',
      account_index: options.account_index || 0,
      subaddr_indices: options.subaddr_indices,
      priority: options.priority || 0,
      ring_size: options.ring_size || 0,
      unlock_time: options.unlock_time || 0,
      payment_id: options.payment_id,
      get_tx_keys: options.get_tx_key !== false,
      do_not_relay: options.do_not_relay || false,
      get_tx_hex: options.get_tx_hex || false,
      get_tx_metadata: options.get_tx_metadata || false
    });
  }

  /**
   * Sweep all funds to an address
   * @param {Object} options - Sweep options
   * @param {string} options.address - Destination address
   * @param {number} [options.account_index=0] - Source account index
   * @param {number[]} [options.subaddr_indices] - Source subaddress indices
   * @param {boolean} [options.subaddr_indices_all=false] - Sweep all subaddresses
   * @param {number} [options.priority=0] - Fee priority (0-4)
   * @param {number} [options.ring_size=0] - Ring size (0 for default)
   * @param {number} [options.outputs=1] - Number of outputs to create
   * @param {number} [options.unlock_time=0] - Unlock time in blocks
   * @param {string} [options.payment_id] - Payment ID
   * @param {boolean} [options.get_tx_keys=true] - Return transaction keys
   * @param {number} [options.below_amount] - Only sweep outputs below this amount
   * @param {boolean} [options.do_not_relay=false] - Don't relay to network
   * @param {boolean} [options.get_tx_hex=false] - Return transaction hex
   * @param {boolean} [options.get_tx_metadata=false] - Return transaction metadata
   * @returns {Promise<RPCResponse>} Transaction info
   */
  async sweepAll(options) {
    return this.call('sweep_all', {
      address: options.address,
      account_index: options.account_index || 0,
      subaddr_indices: options.subaddr_indices,
      subaddr_indices_all: options.subaddr_indices_all || false,
      priority: options.priority || 0,
      ring_size: options.ring_size || 0,
      outputs: options.outputs || 1,
      unlock_time: options.unlock_time || 0,
      payment_id: options.payment_id,
      get_tx_keys: options.get_tx_keys !== false,
      below_amount: options.below_amount,
      do_not_relay: options.do_not_relay || false,
      get_tx_hex: options.get_tx_hex || false,
      get_tx_metadata: options.get_tx_metadata || false
    });
  }

  /**
   * Sweep a single output
   * @param {Object} options - Sweep options
   * @param {string} options.address - Destination address
   * @param {string} options.key_image - Key image of the output to sweep
   * @param {number} [options.priority=0] - Fee priority (0-4)
   * @param {number} [options.ring_size=0] - Ring size (0 for default)
   * @param {number} [options.outputs=1] - Number of outputs to create
   * @param {number} [options.unlock_time=0] - Unlock time in blocks
   * @param {string} [options.payment_id] - Payment ID
   * @param {boolean} [options.get_tx_key=true] - Return transaction key
   * @param {boolean} [options.do_not_relay=false] - Don't relay to network
   * @param {boolean} [options.get_tx_hex=false] - Return transaction hex
   * @param {boolean} [options.get_tx_metadata=false] - Return transaction metadata
   * @returns {Promise<RPCResponse>} Transaction info
   */
  async sweepSingle(options) {
    return this.call('sweep_single', {
      address: options.address,
      key_image: options.key_image,
      priority: options.priority || 0,
      ring_size: options.ring_size || 0,
      outputs: options.outputs || 1,
      unlock_time: options.unlock_time || 0,
      payment_id: options.payment_id,
      get_tx_key: options.get_tx_key !== false,
      do_not_relay: options.do_not_relay || false,
      get_tx_hex: options.get_tx_hex || false,
      get_tx_metadata: options.get_tx_metadata || false
    });
  }

  /**
   * Sweep unmixable (dust) outputs
   * @param {Object} [options={}] - Sweep options
   * @param {boolean} [options.get_tx_keys=true] - Return transaction keys
   * @param {boolean} [options.do_not_relay=false] - Don't relay to network
   * @param {boolean} [options.get_tx_hex=false] - Return transaction hex
   * @param {boolean} [options.get_tx_metadata=false] - Return transaction metadata
   * @returns {Promise<RPCResponse>} Transaction info
   */
  async sweepDust(options = {}) {
    return this.call('sweep_dust', {
      get_tx_keys: options.get_tx_keys !== false,
      do_not_relay: options.do_not_relay || false,
      get_tx_hex: options.get_tx_hex || false,
      get_tx_metadata: options.get_tx_metadata || false
    });
  }

  /**
   * Relay a previously created transaction
   * @param {string} hex - Transaction hex
   * @returns {Promise<RPCResponse>} Transaction hash
   */
  async relayTx(hex) {
    return this.call('relay_tx', { hex });
  }

  /**
   * Describe an unsigned transaction
   * @param {string} unsignedTxset - Unsigned transaction set
   * @param {string} [multisigTxset] - Multisig transaction set
   * @returns {Promise<RPCResponse>} Transaction description
   */
  async describeTransfer(unsignedTxset, multisigTxset) {
    const params = { unsigned_txset: unsignedTxset };
    if (multisigTxset) params.multisig_txset = multisigTxset;
    return this.call('describe_transfer', params);
  }

  /**
   * Sign an unsigned transaction
   * @param {string} unsignedTxset - Unsigned transaction set
   * @param {boolean} [exportRaw=false] - Export as raw hex
   * @param {boolean} [getTxKeys=false] - Return transaction keys
   * @returns {Promise<RPCResponse>} Signed transaction set
   */
  async signTransfer(unsignedTxset, exportRaw = false, getTxKeys = false) {
    return this.call('sign_transfer', {
      unsigned_txset: unsignedTxset,
      export_raw: exportRaw,
      get_tx_keys: getTxKeys
    });
  }

  /**
   * Submit a signed transaction
   * @param {string} txDataHex - Signed transaction data
   * @returns {Promise<RPCResponse>} Transaction hashes
   */
  async submitTransfer(txDataHex) {
    return this.call('submit_transfer', { tx_data_hex: txDataHex });
  }

  /**
   * Estimate transaction size and weight
   * @param {Object} options - Estimate options
   * @param {number} options.n_inputs - Number of inputs
   * @param {number} options.n_outputs - Number of outputs
   * @param {number} [options.ring_size=0] - Ring size
   * @param {boolean} [options.rct=true] - RingCT transaction
   * @returns {Promise<RPCResponse>} Size and weight estimates
   */
  async estimateTxSizeAndWeight(options) {
    return this.call('estimate_tx_size_and_weight', {
      n_inputs: options.n_inputs,
      n_outputs: options.n_outputs,
      ring_size: options.ring_size || 0,
      rct: options.rct !== false
    });
  }

  // ============================================================
  // Transaction Management
  // ============================================================

  /**
   * Get transaction secret key
   * @param {string} txid - Transaction ID
   * @returns {Promise<RPCResponse>} Transaction key
   */
  async getTxKey(txid) {
    return this.call('get_tx_key', { txid });
  }

  /**
   * Verify payment with transaction key
   * @param {string} txid - Transaction ID
   * @param {string} txKey - Transaction secret key
   * @param {string} address - Destination address
   * @returns {Promise<RPCResponse>} Verification result with amount
   */
  async checkTxKey(txid, txKey, address) {
    return this.call('check_tx_key', {
      txid,
      tx_key: txKey,
      address
    });
  }

  /**
   * Generate a payment proof
   * @param {string} txid - Transaction ID
   * @param {string} address - Destination address
   * @param {string} [message] - Optional message to include
   * @returns {Promise<RPCResponse>} Payment proof signature
   */
  async getTxProof(txid, address, message) {
    const params = { txid, address };
    if (message) params.message = message;
    return this.call('get_tx_proof', params);
  }

  /**
   * Verify a payment proof
   * @param {string} txid - Transaction ID
   * @param {string} address - Destination address
   * @param {string} signature - Proof signature
   * @param {string} [message] - Optional message
   * @returns {Promise<RPCResponse>} Verification result
   */
  async checkTxProof(txid, address, signature, message) {
    const params = { txid, address, signature };
    if (message) params.message = message;
    return this.call('check_tx_proof', params);
  }

  /**
   * Generate a spend proof
   * @param {string} txid - Transaction ID
   * @param {string} [message] - Optional message to include
   * @returns {Promise<RPCResponse>} Spend proof signature
   */
  async getSpendProof(txid, message) {
    const params = { txid };
    if (message) params.message = message;
    return this.call('get_spend_proof', params);
  }

  /**
   * Verify a spend proof
   * @param {string} txid - Transaction ID
   * @param {string} signature - Proof signature
   * @param {string} [message] - Optional message
   * @returns {Promise<RPCResponse>} Verification result
   */
  async checkSpendProof(txid, signature, message) {
    const params = { txid, signature };
    if (message) params.message = message;
    return this.call('check_spend_proof', params);
  }

  /**
   * Generate a reserve proof
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.all=true] - Prove all funds
   * @param {number} [options.account_index=0] - Account index
   * @param {number} [options.amount] - Amount to prove (if not all)
   * @param {string} [options.message] - Optional message
   * @returns {Promise<RPCResponse>} Reserve proof signature
   */
  async getReserveProof(options = {}) {
    return this.call('get_reserve_proof', {
      all: options.all !== false,
      account_index: options.account_index || 0,
      amount: options.amount,
      message: options.message
    });
  }

  /**
   * Verify a reserve proof
   * @param {string} address - Wallet address
   * @param {string} signature - Proof signature
   * @param {string} [message] - Optional message
   * @returns {Promise<RPCResponse>} Verification result with amounts
   */
  async checkReserveProof(address, signature, message) {
    const params = { address, signature };
    if (message) params.message = message;
    return this.call('check_reserve_proof', params);
  }

  /**
   * Get transaction notes
   * @param {string[]} txids - Transaction IDs
   * @returns {Promise<RPCResponse>} Transaction notes
   */
  async getTxNotes(txids) {
    return this.call('get_tx_notes', { txids });
  }

  /**
   * Set transaction notes
   * @param {string[]} txids - Transaction IDs
   * @param {string[]} notes - Notes for each transaction
   * @returns {Promise<RPCResponse>} Result
   */
  async setTxNotes(txids, notes) {
    return this.call('set_tx_notes', { txids, notes });
  }

  // ============================================================
  // Key Management
  // ============================================================

  /**
   * Query a wallet key
   * @param {string} keyType - Key type: 'mnemonic', 'view_key', or 'spend_key'
   * @returns {Promise<RPCResponse>} Requested key
   */
  async queryKey(keyType) {
    return this.call('query_key', { key_type: keyType });
  }

  /**
   * Get mnemonic seed
   * @returns {Promise<RPCResponse>} Mnemonic seed phrase
   */
  async getMnemonic() {
    return this.queryKey('mnemonic');
  }

  /**
   * Get private view key
   * @returns {Promise<RPCResponse>} Private view key
   */
  async getViewKey() {
    return this.queryKey('view_key');
  }

  /**
   * Get private spend key
   * @returns {Promise<RPCResponse>} Private spend key
   */
  async getSpendKey() {
    return this.queryKey('spend_key');
  }

  /**
   * Export outputs for cold signing
   * @param {boolean} [all=false] - Export all outputs
   * @returns {Promise<RPCResponse>} Outputs data
   */
  async exportOutputs(all = false) {
    return this.call('export_outputs', { all });
  }

  /**
   * Import outputs
   * @param {string} outputsDataHex - Outputs data from export_outputs
   * @returns {Promise<RPCResponse>} Number of outputs imported
   */
  async importOutputs(outputsDataHex) {
    return this.call('import_outputs', { outputs_data_hex: outputsDataHex });
  }

  /**
   * Export key images
   * @param {boolean} [all=false] - Export all key images
   * @returns {Promise<RPCResponse>} Key images data
   */
  async exportKeyImages(all = false) {
    return this.call('export_key_images', { all });
  }

  /**
   * Import key images
   * @param {Object[]} signedKeyImages - Key images with signatures
   * @param {string} signedKeyImages[].key_image - Key image
   * @param {string} signedKeyImages[].signature - Signature
   * @returns {Promise<RPCResponse>} Import result with balance updates
   */
  async importKeyImages(signedKeyImages) {
    return this.call('import_key_images', { signed_key_images: signedKeyImages });
  }

  // ============================================================
  // Signing & Verification
  // ============================================================

  /**
   * Sign arbitrary data
   * @param {string} data - Data to sign
   * @returns {Promise<RPCResponse>} Signature
   */
  async sign(data) {
    return this.call('sign', { data });
  }

  /**
   * Verify a signature
   * @param {string} data - Original data
   * @param {string} address - Signer's address
   * @param {string} signature - Signature to verify
   * @returns {Promise<RPCResponse>} Verification result
   */
  async verify(data, address, signature) {
    return this.call('verify', { data, address, signature });
  }

  // ============================================================
  // Multisig
  // ============================================================

  /**
   * Prepare multisig info for key exchange
   * @returns {Promise<RPCResponse>} Multisig info
   */
  async prepareMultisig() {
    return this.call('prepare_multisig');
  }

  /**
   * Make this wallet multisig
   * @param {string[]} multisigInfo - Multisig info from each participant
   * @param {number} threshold - Required signatures (M in M-of-N)
   * @param {string} [password=''] - Wallet password
   * @returns {Promise<RPCResponse>} Multisig address
   */
  async makeMultisig(multisigInfo, threshold, password = '') {
    return this.call('make_multisig', {
      multisig_info: multisigInfo,
      threshold,
      password
    });
  }

  /**
   * Export multisig info
   * @returns {Promise<RPCResponse>} Multisig info for sharing
   */
  async exportMultisigInfo() {
    return this.call('export_multisig_info');
  }

  /**
   * Import multisig info from other participants
   * @param {string[]} info - Multisig info from other participants
   * @returns {Promise<RPCResponse>} Import result
   */
  async importMultisigInfo(info) {
    return this.call('import_multisig_info', { info });
  }

  /**
   * Finalize multisig setup
   * @param {string[]} multisigInfo - Multisig info from all participants
   * @param {string} [password=''] - Wallet password
   * @returns {Promise<RPCResponse>} Finalized multisig address
   */
  async finalizeMultisig(multisigInfo, password = '') {
    return this.call('finalize_multisig', {
      multisig_info: multisigInfo,
      password
    });
  }

  /**
   * Sign a multisig transaction
   * @param {string} txDataHex - Transaction data
   * @returns {Promise<RPCResponse>} Partially signed transaction
   */
  async signMultisig(txDataHex) {
    return this.call('sign_multisig', { tx_data_hex: txDataHex });
  }

  /**
   * Submit a fully signed multisig transaction
   * @param {string} txDataHex - Fully signed transaction data
   * @returns {Promise<RPCResponse>} Transaction hashes
   */
  async submitMultisig(txDataHex) {
    return this.call('submit_multisig', { tx_data_hex: txDataHex });
  }

  /**
   * Exchange multisig keys
   * @param {string[]} multisigInfo - Multisig info from participants
   * @param {string} [password=''] - Wallet password
   * @returns {Promise<RPCResponse>} Exchange result
   */
  async exchangeMultisigKeys(multisigInfo, password = '') {
    return this.call('exchange_multisig_keys', {
      multisig_info: multisigInfo,
      password
    });
  }

  // ============================================================
  // Wallet Settings
  // ============================================================

  /**
   * Enable or disable auto-refresh
   * @param {boolean} enable - Enable auto-refresh
   * @param {number} [period] - Refresh period in seconds
   * @returns {Promise<RPCResponse>} Result
   */
  async autoRefresh(enable, period) {
    const params = { enable };
    if (period !== undefined) params.period = period;
    return this.call('auto_refresh', params);
  }

  /**
   * Manually refresh the wallet
   * @param {number} [startHeight] - Start height for refresh
   * @returns {Promise<RPCResponse>} Blocks fetched and received money
   */
  async refresh(startHeight) {
    const params = {};
    if (startHeight !== undefined) params.start_height = startHeight;
    return this.call('refresh', params);
  }

  /**
   * Rescan the blockchain
   * @param {boolean} [hard=false] - Hard rescan (delete all data)
   * @returns {Promise<RPCResponse>} Result
   */
  async rescanBlockchain(hard = false) {
    return this.call('rescan_blockchain', { hard });
  }

  /**
   * Rescan spent outputs
   * @returns {Promise<RPCResponse>} Result
   */
  async rescanSpent() {
    return this.call('rescan_spent');
  }

  /**
   * Start background mining
   * @param {boolean} doBackgroundMining - Enable background mining
   * @param {boolean} ignoreBattery - Ignore battery status
   * @param {number} [threadsCount] - Number of mining threads
   * @returns {Promise<RPCResponse>} Result
   */
  async startMining(doBackgroundMining, ignoreBattery, threadsCount) {
    const params = {
      do_background_mining: doBackgroundMining,
      ignore_battery: ignoreBattery
    };
    if (threadsCount !== undefined) params.threads_count = threadsCount;
    return this.call('start_mining', params);
  }

  /**
   * Stop background mining
   * @returns {Promise<RPCResponse>} Result
   */
  async stopMining() {
    return this.call('stop_mining');
  }

  /**
   * Set daemon connection
   * @param {Object} [options={}] - Daemon options
   * @param {string} [options.address] - Daemon address
   * @param {boolean} [options.trusted=false] - Mark as trusted daemon
   * @param {string} [options.ssl_support='autodetect'] - SSL support mode
   * @param {string} [options.ssl_private_key_path] - SSL key path
   * @param {string} [options.ssl_certificate_path] - SSL cert path
   * @param {string} [options.ssl_ca_file] - SSL CA file
   * @param {string[]} [options.ssl_allowed_fingerprints] - Allowed SSL fingerprints
   * @param {boolean} [options.ssl_allow_any_cert=false] - Allow any SSL cert
   * @param {string} [options.username] - Daemon username
   * @param {string} [options.password] - Daemon password
   * @returns {Promise<RPCResponse>} Result
   */
  async setDaemon(options = {}) {
    return this.call('set_daemon', {
      address: options.address,
      trusted: options.trusted || false,
      ssl_support: options.ssl_support || 'autodetect',
      ssl_private_key_path: options.ssl_private_key_path,
      ssl_certificate_path: options.ssl_certificate_path,
      ssl_ca_file: options.ssl_ca_file,
      ssl_allowed_fingerprints: options.ssl_allowed_fingerprints,
      ssl_allow_any_cert: options.ssl_allow_any_cert || false,
      username: options.username,
      password: options.password
    });
  }

  /**
   * Get a wallet attribute
   * @param {string} key - Attribute key
   * @returns {Promise<RPCResponse>} Attribute value
   */
  async getAttribute(key) {
    return this.call('get_attribute', { key });
  }

  /**
   * Set a wallet attribute
   * @param {string} key - Attribute key
   * @param {string} value - Attribute value
   * @returns {Promise<RPCResponse>} Result
   */
  async setAttribute(key, value) {
    return this.call('set_attribute', { key, value });
  }

  // ============================================================
  // URI Handling
  // ============================================================

  /**
   * Create a payment URI
   * @param {Object} options - URI options
   * @param {string} options.address - Recipient address
   * @param {number} [options.amount] - Amount in atomic units
   * @param {string} [options.payment_id] - Payment ID
   * @param {string} [options.recipient_name] - Recipient name
   * @param {string} [options.tx_description] - Transaction description
   * @returns {Promise<RPCResponse>} URI string
   */
  async makeUri(options) {
    return this.call('make_uri', {
      address: options.address,
      amount: options.amount,
      payment_id: options.payment_id,
      recipient_name: options.recipient_name,
      tx_description: options.tx_description
    });
  }

  /**
   * Parse a payment URI
   * @param {string} uri - Payment URI
   * @returns {Promise<RPCResponse>} Parsed URI components
   */
  async parseUri(uri) {
    return this.call('parse_uri', { uri });
  }

  // ============================================================
  // Utility Methods
  // ============================================================

  /**
   * Get unlocked balance for an account
   * @param {number} [accountIndex=0] - Account index
   * @returns {Promise<number|null>} Unlocked balance or null on error
   */
  async getUnlockedBalance(accountIndex = 0) {
    const response = await this.getBalance({ account_index: accountIndex });
    if (response.success && response.result && response.result.balances) {
      const balanceInfo = response.result.balances[0];
      return balanceInfo ? balanceInfo.unlocked_balance : 0;
    }
    return null;
  }

  /**
   * Get primary address for an account
   * @param {number} [accountIndex=0] - Account index
   * @returns {Promise<string|null>} Primary address or null on error
   */
  async getPrimaryAddress(accountIndex = 0) {
    const response = await this.getAddress({ account_index: accountIndex });
    if (response.success && response.result) {
      return response.result.address || null;
    }
    return null;
  }

  /**
   * Simple transfer to a single address
   * @param {string} address - Destination address
   * @param {number|string} amount - Amount in atomic units
   * @param {Object} [options={}] - Additional options
   * @returns {Promise<RPCResponse>} Transaction result
   */
  async sendTo(address, amount, options = {}) {
    return this.transfer({
      destinations: [{ address, amount }],
      ...options
    });
  }

  /**
   * Wait for wallet to be synchronized
   * @param {Object} [options={}] - Options
   * @param {number} [options.pollInterval=5000] - Poll interval in ms
   * @param {number} [options.timeout=0] - Timeout in ms (0 = no timeout)
   * @param {Function} [options.onProgress] - Progress callback (walletHeight, daemonHeight)
   * @returns {Promise<boolean>} True when synchronized
   */
  async waitForSync(options = {}) {
    const pollInterval = options.pollInterval || 5000;
    const timeout = options.timeout || 0;
    const onProgress = options.onProgress;
    const startTime = Date.now();

    while (true) {
      const heightResponse = await this.getHeight();
      if (heightResponse.success && heightResponse.result) {
        const walletHeight = heightResponse.result.height;

        // Try to get daemon height for comparison
        // This assumes wallet RPC knows daemon height
        if (onProgress) {
          onProgress(walletHeight, null);
        }

        // Check if refresh completes quickly (indicates sync is done)
        const refreshResponse = await this.refresh();
        if (refreshResponse.success && refreshResponse.result) {
          if (refreshResponse.result.blocks_fetched === 0) {
            return true;
          }
        }
      }

      if (timeout > 0 && Date.now() - startTime > timeout) {
        return false;
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
  }
}

/**
 * Create a new Wallet RPC client
 * @param {RPCClientOptions} [options={}] - Client configuration
 * @returns {WalletRPC}
 */
export function createWalletRPC(options = {}) {
  return new WalletRPC(options);
}

/**
 * Conventional mainnet wallet RPC URL (no default in source - daemon port + 1)
 */
export const MAINNET_URL = 'http://localhost:19083';

/**
 * Conventional testnet wallet RPC URL (no default in source - daemon port + 1)
 */
export const TESTNET_URL = 'http://localhost:29083';

/**
 * Conventional stagenet wallet RPC URL (no default in source - daemon port + 1)
 */
export const STAGENET_URL = 'http://localhost:39083';

export default {
  WalletRPC,
  createWalletRPC,
  PRIORITY,
  TRANSFER_TYPE,
  MAINNET_URL,
  TESTNET_URL,
  STAGENET_URL
};
