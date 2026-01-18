/**
 * Daemon RPC Client
 *
 * Provides access to Salvium daemon RPC endpoints.
 * Includes network info, block operations, transaction queries, mining, and more.
 *
 * Default ports from cryptonote_config.h:
 * - Mainnet:  P2P 19080, RPC 19081, ZMQ 19083
 * - Testnet:  P2P 29080, RPC 29081, ZMQ 29083
 * - Stagenet: P2P 39080, RPC 39081, ZMQ 39083
 *
 * Note: Restricted RPC has no default port in source code (user-specified).
 * Convention is typically daemon port + 8 (e.g., 19089 for mainnet).
 */

import { RPCClient, RPC_STATUS } from './client.js';

/**
 * @typedef {import('./client.js').RPCClientOptions} RPCClientOptions
 * @typedef {import('./client.js').RPCResponse} RPCResponse
 */

/**
 * @typedef {Object} BlockHeader
 * @property {number} major_version - Block major version
 * @property {number} minor_version - Block minor version
 * @property {number} timestamp - Block timestamp (Unix seconds)
 * @property {string} prev_hash - Previous block hash
 * @property {number} nonce - Mining nonce
 * @property {boolean} orphan_status - Is orphan block
 * @property {number} height - Block height
 * @property {number} depth - Depth from chain tip
 * @property {string} hash - Block hash
 * @property {number} difficulty - Block difficulty
 * @property {string} wide_difficulty - Difficulty as string (128-bit)
 * @property {number} cumulative_difficulty - Cumulative difficulty
 * @property {number} reward - Block reward (atomic units)
 * @property {number} block_size - Block size in bytes
 * @property {number} block_weight - Block weight
 * @property {number} num_txes - Number of transactions
 * @property {string} pow_hash - Proof of work hash
 * @property {string} miner_tx_hash - Miner transaction hash
 * @property {string} [protocol_tx_hash] - Protocol transaction hash (Salvium-specific)
 */

/**
 * @typedef {Object} TransactionEntry
 * @property {string} tx_hash - Transaction hash
 * @property {string} as_hex - Transaction as hex string
 * @property {string} [as_json] - Transaction as JSON string
 * @property {boolean} in_pool - Is in mempool
 * @property {boolean} double_spend_seen - Double spend detected
 * @property {number} [block_height] - Block height if confirmed
 * @property {number} [block_timestamp] - Block timestamp if confirmed
 * @property {number} [confirmations] - Number of confirmations
 * @property {number[]} [output_indices] - Global output indices
 */

/**
 * @typedef {Object} ConnectionInfo
 * @property {string} address - Peer address
 * @property {number} port - Peer port
 * @property {string} peer_id - Peer ID
 * @property {number} height - Peer's blockchain height
 * @property {boolean} incoming - Is incoming connection
 * @property {number} live_time - Connection duration (seconds)
 * @property {number} recv_count - Bytes received
 * @property {number} send_count - Bytes sent
 * @property {string} state - Connection state
 */

/**
 * @typedef {Object} PeerInfo
 * @property {string} host - Peer host
 * @property {number} port - Peer port
 * @property {string} id - Peer ID
 * @property {number} last_seen - Last seen timestamp
 */

/**
 * Daemon RPC Client
 */
export class DaemonRPC extends RPCClient {
  /**
   * Create a Daemon RPC client
   * @param {RPCClientOptions} options - Client configuration
   */
  constructor(options = {}) {
    // Default to mainnet port if no URL provided
    if (!options.url) {
      options.url = 'http://localhost:19081';
    }
    super(options);
  }

  // ============================================================
  // Network Information
  // ============================================================

  /**
   * Get general information about the node
   * @returns {Promise<RPCResponse>} Node info including height, difficulty, version, etc.
   */
  async getInfo() {
    return this.post('/get_info');
  }

  /**
   * Get current blockchain height
   * @returns {Promise<RPCResponse>} Height and top block hash
   */
  async getHeight() {
    return this.post('/get_height');
  }

  /**
   * Get block count (alias for height)
   * @returns {Promise<RPCResponse>} Block count
   */
  async getBlockCount() {
    return this.call('get_block_count');
  }

  /**
   * Get network traffic statistics
   * @returns {Promise<RPCResponse>} Network stats
   */
  async getNetStats() {
    return this.post('/get_net_stats');
  }

  /**
   * Get active peer connections
   * @returns {Promise<RPCResponse>} List of connections
   */
  async getConnections() {
    return this.call('get_connections');
  }

  /**
   * Get known peer list
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.white=true] - Include white (trusted) peers
   * @param {boolean} [options.gray=true] - Include gray (untrusted) peers
   * @returns {Promise<RPCResponse>} Peer lists
   */
  async getPeerList(options = {}) {
    return this.post('/get_peer_list', {
      white: options.white !== false,
      gray: options.gray !== false
    });
  }

  /**
   * Get public nodes
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.white=true] - Include white list nodes
   * @param {boolean} [options.gray=false] - Include gray list nodes
   * @returns {Promise<RPCResponse>} Public node lists
   */
  async getPublicNodes(options = {}) {
    return this.post('/get_public_nodes', {
      white: options.white !== false,
      gray: options.gray === true
    });
  }

  /**
   * Get synchronization info
   * @returns {Promise<RPCResponse>} Sync status and peer info
   */
  async syncInfo() {
    return this.call('sync_info');
  }

  /**
   * Get hard fork information
   * @returns {Promise<RPCResponse>} Hard fork version and voting status
   */
  async hardForkInfo() {
    return this.call('hard_fork_info');
  }

  /**
   * Get daemon version
   * @returns {Promise<RPCResponse>} Version info
   */
  async getVersion() {
    return this.call('get_version');
  }

  // ============================================================
  // Block Operations
  // ============================================================

  /**
   * Get block hash by height
   * @param {number} height - Block height
   * @returns {Promise<RPCResponse>} Block hash
   */
  async getBlockHash(height) {
    return this.call('on_get_block_hash', [height]);
  }

  /**
   * Get block header by hash
   * @param {string} hash - Block hash
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.fill_pow_hash=false] - Include proof of work hash
   * @returns {Promise<RPCResponse>} Block header
   */
  async getBlockHeaderByHash(hash, options = {}) {
    return this.call('get_block_header_by_hash', {
      hash,
      fill_pow_hash: options.fill_pow_hash || false
    });
  }

  /**
   * Get block header by height
   * @param {number} height - Block height
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.fill_pow_hash=false] - Include proof of work hash
   * @returns {Promise<RPCResponse>} Block header
   */
  async getBlockHeaderByHeight(height, options = {}) {
    return this.call('get_block_header_by_height', {
      height,
      fill_pow_hash: options.fill_pow_hash || false
    });
  }

  /**
   * Get range of block headers
   * @param {number} startHeight - Start height (inclusive)
   * @param {number} endHeight - End height (inclusive)
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.fill_pow_hash=false] - Include proof of work hash
   * @returns {Promise<RPCResponse>} Array of block headers
   */
  async getBlockHeadersRange(startHeight, endHeight, options = {}) {
    return this.call('get_block_headers_range', {
      start_height: startHeight,
      end_height: endHeight,
      fill_pow_hash: options.fill_pow_hash || false
    });
  }

  /**
   * Get last (most recent) block header
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.fill_pow_hash=false] - Include proof of work hash
   * @returns {Promise<RPCResponse>} Block header
   */
  async getLastBlockHeader(options = {}) {
    return this.call('get_last_block_header', {
      fill_pow_hash: options.fill_pow_hash || false
    });
  }

  /**
   * Get full block data
   * @param {Object} options - Query options (must specify hash OR height)
   * @param {string} [options.hash] - Block hash
   * @param {number} [options.height] - Block height
   * @param {boolean} [options.fill_pow_hash=false] - Include proof of work hash
   * @returns {Promise<RPCResponse>} Full block data including header, tx hashes, and blob
   */
  async getBlock(options = {}) {
    const params = {
      fill_pow_hash: options.fill_pow_hash || false
    };
    if (options.hash) params.hash = options.hash;
    if (options.height !== undefined) params.height = options.height;
    return this.call('get_block', params);
  }

  /**
   * Get blocks by height (efficient binary format)
   * @param {number[]} heights - Array of block heights
   * @returns {Promise<RPCResponse>} Blocks data
   */
  async getBlocksByHeight(heights) {
    return this.post('/get_blocks_by_height.bin', { heights });
  }

  /**
   * Get alternate chains (forks)
   * @returns {Promise<RPCResponse>} Alternate chain info
   */
  async getAlternateChains() {
    return this.post('/get_alternate_chains');
  }

  // ============================================================
  // Transaction Operations
  // ============================================================

  /**
   * Get transactions by hash
   * @param {string[]} txHashes - Array of transaction hashes
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.decode_as_json=false] - Decode as JSON
   * @param {boolean} [options.prune=false] - Prune transaction data
   * @param {boolean} [options.split=false] - Split pruned/prunable data
   * @returns {Promise<RPCResponse>} Transaction data and any missed hashes
   */
  async getTransactions(txHashes, options = {}) {
    return this.post('/get_transactions', {
      txs_hashes: txHashes,
      decode_as_json: options.decode_as_json || false,
      prune: options.prune || false,
      split: options.split || false
    });
  }

  /**
   * Get transaction pool (mempool) contents
   * @returns {Promise<RPCResponse>} Mempool transactions
   */
  async getTransactionPool() {
    return this.post('/get_transaction_pool');
  }

  /**
   * Get transaction pool hashes
   * @returns {Promise<RPCResponse>} Array of mempool transaction hashes
   */
  async getTransactionPoolHashes() {
    return this.post('/get_transaction_pool_hashes');
  }

  /**
   * Get transaction pool statistics
   * @returns {Promise<RPCResponse>} Pool stats including size, fees, etc.
   */
  async getTransactionPoolStats() {
    return this.post('/get_transaction_pool_stats');
  }

  /**
   * Get transaction pool backlog (sorted by fee)
   * @returns {Promise<RPCResponse>} Fee-sorted mempool entries
   */
  async getTxPoolBacklog() {
    return this.post('/get_txpool_backlog');
  }

  /**
   * Send a raw transaction to the network
   * @param {string} txAsHex - Transaction as hex string
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.do_not_relay=false] - Don't relay to network
   * @returns {Promise<RPCResponse>} Submission result
   */
  async sendRawTransaction(txAsHex, options = {}) {
    return this.post('/send_raw_transaction', {
      tx_as_hex: txAsHex,
      do_not_relay: options.do_not_relay || false
    });
  }

  /**
   * Alias for sendRawTransaction
   * @param {string} txAsHex - Transaction as hex string
   * @param {Object} [options={}] - Options
   * @returns {Promise<RPCResponse>} Submission result
   */
  async submitTransaction(txAsHex, options = {}) {
    return this.sendRawTransaction(txAsHex, options);
  }

  /**
   * Relay a transaction to the network
   * @param {string[]} txids - Transaction IDs to relay
   * @returns {Promise<RPCResponse>} Relay result
   */
  async relayTx(txids) {
    return this.post('/relay_tx', { txids });
  }

  // ============================================================
  // Output Operations
  // ============================================================

  /**
   * Get outputs by index
   * @param {Object[]} outputs - Array of {amount, index} objects
   * @param {Object} [options={}] - Options
   * @param {boolean} [options.get_txid=false] - Include transaction IDs
   * @returns {Promise<RPCResponse>} Output data
   */
  async getOuts(outputs, options = {}) {
    return this.post('/get_outs', {
      outputs,
      get_txid: options.get_txid || false
    });
  }

  /**
   * Get output histogram (distribution by age)
   * @param {Object} [options={}] - Options
   * @param {number[]} [options.amounts] - Specific amounts to query
   * @param {number} [options.min_count] - Minimum count filter
   * @param {number} [options.max_count] - Maximum count filter
   * @param {boolean} [options.unlocked=false] - Only unlocked outputs
   * @param {number} [options.recent_cutoff] - Recent cutoff timestamp
   * @returns {Promise<RPCResponse>} Output histogram
   */
  async getOutputHistogram(options = {}) {
    return this.call('get_output_histogram', {
      amounts: options.amounts || [],
      min_count: options.min_count,
      max_count: options.max_count,
      unlocked: options.unlocked || false,
      recent_cutoff: options.recent_cutoff
    });
  }

  /**
   * Get output distribution for decoy selection
   * @param {number[]} amounts - Amounts to query (use [0] for RingCT)
   * @param {Object} [options={}] - Options
   * @param {number} [options.from_height=0] - Start height
   * @param {number} [options.to_height] - End height
   * @param {boolean} [options.cumulative=false] - Return cumulative distribution
   * @param {boolean} [options.binary=true] - Use binary format
   * @param {boolean} [options.compress=false] - Compress response
   * @returns {Promise<RPCResponse>} Output distribution data
   */
  async getOutputDistribution(amounts, options = {}) {
    return this.call('get_output_distribution', {
      amounts,
      from_height: options.from_height || 0,
      to_height: options.to_height,
      cumulative: options.cumulative || false,
      binary: options.binary !== false,
      compress: options.compress || false
    });
  }

  /**
   * Check if key images have been spent
   * @param {string[]} keyImages - Array of key images (hex strings)
   * @returns {Promise<RPCResponse>} Spent status for each key image
   */
  async isKeyImageSpent(keyImages) {
    return this.post('/is_key_image_spent', {
      key_images: keyImages
    });
  }

  // ============================================================
  // Mining Operations
  // ============================================================

  /**
   * Get block template for mining
   * @param {string} walletAddress - Address to receive mining reward
   * @param {number} [reserveSize=60] - Extra nonce size
   * @returns {Promise<RPCResponse>} Block template data
   */
  async getBlockTemplate(walletAddress, reserveSize = 60) {
    return this.call('get_block_template', {
      wallet_address: walletAddress,
      reserve_size: reserveSize
    });
  }

  /**
   * Submit a mined block
   * @param {string[]} blockBlob - Block data as hex string array
   * @returns {Promise<RPCResponse>} Submission result
   */
  async submitBlock(blockBlob) {
    return this.call('submit_block', blockBlob);
  }

  /**
   * Generate blocks (regtest/testing only)
   * @param {number} amountOfBlocks - Number of blocks to generate
   * @param {string} walletAddress - Address to receive rewards
   * @param {string} [prevBlock] - Previous block hash
   * @param {number} [startingNonce] - Starting nonce
   * @returns {Promise<RPCResponse>} Generated block hashes
   */
  async generateBlocks(amountOfBlocks, walletAddress, prevBlock, startingNonce) {
    return this.call('generateblocks', {
      amount_of_blocks: amountOfBlocks,
      wallet_address: walletAddress,
      prev_block: prevBlock,
      starting_nonce: startingNonce
    });
  }

  /**
   * Get current mining data
   * @returns {Promise<RPCResponse>} Mining info including difficulty, height, seed hash
   */
  async getMinerData() {
    return this.call('get_miner_data');
  }

  /**
   * Calculate proof of work hash
   * @param {number} majorVersion - Block major version
   * @param {number} height - Block height
   * @param {string} blockBlob - Block blob as hex
   * @param {string} seedHash - Seed hash for RandomX
   * @returns {Promise<RPCResponse>} PoW hash
   */
  async calcPow(majorVersion, height, blockBlob, seedHash) {
    return this.call('calc_pow', {
      major_version: majorVersion,
      height,
      block_blob: blockBlob,
      seed_hash: seedHash
    });
  }

  /**
   * Add an auxiliary PoW for merge mining
   * @param {string} blockTemplateBlob - Block template blob
   * @param {string[]} auxPow - Auxiliary PoW data
   * @returns {Promise<RPCResponse>} Result with block template
   */
  async addAuxPow(blockTemplateBlob, auxPow) {
    return this.call('add_aux_pow', {
      blocktemplate_blob: blockTemplateBlob,
      aux_pow: auxPow
    });
  }

  // ============================================================
  // Fee Estimation
  // ============================================================

  /**
   * Get fee estimate
   * @param {number} [graceBlocks=10] - Grace blocks for estimation
   * @returns {Promise<RPCResponse>} Fee estimate in atomic units per byte
   */
  async getFeeEstimate(graceBlocks = 10) {
    return this.call('get_fee_estimate', {
      grace_blocks: graceBlocks
    });
  }

  /**
   * Get base fee estimate
   * @param {number} [graceBlocks=10] - Grace blocks for estimation
   * @returns {Promise<RPCResponse>} Base fee calculation
   */
  async getBaseFeeEstimate(graceBlocks = 10) {
    return this.post('/get_base_fee_estimate', {
      grace_blocks: graceBlocks
    });
  }

  /**
   * Get coinbase transaction sum (block reward + fees)
   * @param {number} height - Starting height
   * @param {number} count - Number of blocks
   * @returns {Promise<RPCResponse>} Emission and fee sums
   */
  async getCoinbaseTxSum(height, count) {
    return this.call('get_coinbase_tx_sum', {
      height,
      count
    });
  }

  // ============================================================
  // Node Management
  // ============================================================

  /**
   * Stop the daemon gracefully
   * @returns {Promise<RPCResponse>} Stop result
   */
  async stopDaemon() {
    return this.post('/stop_daemon');
  }

  /**
   * Set daemon log level
   * @param {number} level - Log level (0-4)
   * @returns {Promise<RPCResponse>} Result
   */
  async setLogLevel(level) {
    return this.post('/set_log_level', { level });
  }

  /**
   * Set daemon log categories
   * @param {string} categories - Log categories string
   * @returns {Promise<RPCResponse>} Result
   */
  async setLogCategories(categories) {
    return this.post('/set_log_categories', { categories });
  }

  /**
   * Set daemon log hash rate display
   * @param {boolean} visible - Show hash rate in logs
   * @returns {Promise<RPCResponse>} Result
   */
  async setLogHashRate(visible) {
    return this.post('/set_log_hash_rate', { visible });
  }

  /**
   * Flush blockchain data to disk
   * @returns {Promise<RPCResponse>} Result
   */
  async saveBlockchain() {
    return this.post('/save_bc');
  }

  /**
   * Set bandwidth limits
   * @param {number} limitDown - Download limit (kB/s, -1 for reset)
   * @param {number} limitUp - Upload limit (kB/s, -1 for reset)
   * @returns {Promise<RPCResponse>} Current limits
   */
  async setBans(limitDown, limitUp) {
    return this.post('/set_limit', {
      limit_down: limitDown,
      limit_up: limitUp
    });
  }

  /**
   * Get banned peers
   * @returns {Promise<RPCResponse>} List of banned peers
   */
  async getBans() {
    return this.post('/get_bans');
  }

  /**
   * Ban/unban a peer
   * @param {Object[]} bans - Array of ban entries
   * @param {string} bans[].host - Peer host
   * @param {number} [bans[].ip] - Peer IP (deprecated, use host)
   * @param {boolean} bans[].ban - True to ban, false to unban
   * @param {number} bans[].seconds - Ban duration in seconds
   * @returns {Promise<RPCResponse>} Result
   */
  async setBans(bans) {
    return this.post('/set_bans', { bans });
  }

  /**
   * Check if blockchain is pruned
   * @returns {Promise<RPCResponse>} Pruning status
   */
  async pruneBlockchain() {
    return this.post('/prune_blockchain');
  }

  /**
   * Flush transaction pool
   * @param {string[]} [txids] - Specific transaction IDs to flush
   * @returns {Promise<RPCResponse>} Result
   */
  async flushTxpool(txids) {
    return this.post('/flush_txpool', { txids });
  }

  /**
   * Flush cache
   * @param {boolean} [badTxs=false] - Flush bad transactions cache
   * @param {boolean} [badBlocks=false] - Flush bad blocks cache
   * @returns {Promise<RPCResponse>} Result
   */
  async flushCache(badTxs = false, badBlocks = false) {
    return this.post('/flush_cache', {
      bad_txs: badTxs,
      bad_blocks: badBlocks
    });
  }

  // ============================================================
  // Salvium-Specific Methods
  // ============================================================

  /**
   * Get supply information (Salvium-specific)
   * Returns multi-currency supply tally
   * @returns {Promise<RPCResponse>} Supply info with currency entries
   */
  async getSupplyInfo() {
    return this.call('get_supply_info');
  }

  /**
   * Get yield/staking information (Salvium-specific)
   * Returns staking economics data including burnt, staked, yield rates
   * @returns {Promise<RPCResponse>} Yield info with:
   *   - total_burnt: Total coins burned
   *   - total_staked: Total coins locked/staked
   *   - total_yield: Total yield generated
   *   - yield_per_stake: Yield rate per staked unit
   *   - yield_data[]: Per-block yield data with network health
   */
  async getYieldInfo() {
    return this.call('get_yield_info');
  }

  // ============================================================
  // Mining Control
  // ============================================================

  /**
   * Start mining on the daemon
   * @param {string} minerAddress - Address to receive mining rewards
   * @param {number} [threadsCount=1] - Number of mining threads
   * @param {boolean} [doBackgroundMining=false] - Background mining mode
   * @param {boolean} [ignoreBattery=false] - Ignore battery status
   * @returns {Promise<RPCResponse>} Result
   */
  async startMining(minerAddress, threadsCount = 1, doBackgroundMining = false, ignoreBattery = false) {
    return this.post('/start_mining', {
      miner_address: minerAddress,
      threads_count: threadsCount,
      do_background_mining: doBackgroundMining,
      ignore_battery: ignoreBattery
    });
  }

  /**
   * Stop mining on the daemon
   * @returns {Promise<RPCResponse>} Result
   */
  async stopMining() {
    return this.post('/stop_mining');
  }

  /**
   * Get current mining status
   * @returns {Promise<RPCResponse>} Mining status including:
   *   - active: boolean
   *   - speed: hashrate
   *   - threads_count: number of threads
   *   - address: mining address
   *   - difficulty: current difficulty
   *   - block_reward: current block reward
   */
  async miningStatus() {
    return this.post('/mining_status');
  }

  // ============================================================
  // Bandwidth Control
  // ============================================================

  /**
   * Get current bandwidth limits
   * @returns {Promise<RPCResponse>} Current limits (limit_down, limit_up in kB/s)
   */
  async getLimit() {
    return this.post('/get_limit');
  }

  /**
   * Set bandwidth limits
   * @param {number} limitDown - Download limit in kB/s (-1 to reset to default)
   * @param {number} limitUp - Upload limit in kB/s (-1 to reset to default)
   * @returns {Promise<RPCResponse>} New limits
   */
  async setLimit(limitDown, limitUp) {
    return this.post('/set_limit', {
      limit_down: limitDown,
      limit_up: limitUp
    });
  }

  /**
   * Reset download limit to default
   * @returns {Promise<RPCResponse>} New limits
   */
  async resetDownloadLimit() {
    return this.setLimit(-1, 0);
  }

  /**
   * Reset upload limit to default
   * @returns {Promise<RPCResponse>} New limits
   */
  async resetUploadLimit() {
    return this.setLimit(0, -1);
  }

  // ============================================================
  // Peer Control
  // ============================================================

  /**
   * Set maximum number of outgoing peers
   * @param {number} outPeers - Maximum outgoing peers (-1 for default)
   * @returns {Promise<RPCResponse>} Result with new out_peers value
   */
  async setOutPeers(outPeers) {
    return this.post('/out_peers', { out_peers: outPeers });
  }

  /**
   * Set maximum number of incoming peers
   * @param {number} inPeers - Maximum incoming peers (-1 for default)
   * @returns {Promise<RPCResponse>} Result with new in_peers value
   */
  async setInPeers(inPeers) {
    return this.post('/in_peers', { in_peers: inPeers });
  }

  /**
   * Check if an IP address is banned
   * @param {string} address - IP address to check
   * @returns {Promise<RPCResponse>} Ban status
   */
  async isBanned(address) {
    return this.call('banned', { address });
  }

  // ============================================================
  // Daemon Administration
  // ============================================================

  /**
   * Set bootstrap daemon for syncing
   * @param {string} address - Bootstrap daemon address (empty to disable)
   * @param {string} [username] - Optional username for authentication
   * @param {string} [password] - Optional password for authentication
   * @returns {Promise<RPCResponse>} Result
   */
  async setBootstrapDaemon(address, username, password) {
    const params = { address };
    if (username) params.username = username;
    if (password) params.password = password;
    return this.post('/set_bootstrap_daemon', params);
  }

  /**
   * Check for daemon updates
   * @param {string} [command='check'] - Command: 'check' or 'download'
   * @param {string} [path] - Download path (for 'download' command)
   * @returns {Promise<RPCResponse>} Update info including:
   *   - update: boolean if update available
   *   - version: new version string
   *   - user_uri: download URL
   *   - auto_uri: auto-update URL
   *   - hash: update file hash
   */
  async checkUpdate(command = 'check', path) {
    const params = { command };
    if (path) params.path = path;
    return this.post('/update', params);
  }

  /**
   * Download daemon update
   * @param {string} [path] - Download path
   * @returns {Promise<RPCResponse>} Download result
   */
  async downloadUpdate(path) {
    return this.checkUpdate('download', path);
  }

  /**
   * Pop blocks from the blockchain (for reorg/testing)
   * @param {number} nblocks - Number of blocks to pop
   * @returns {Promise<RPCResponse>} Result with new height
   */
  async popBlocks(nblocks) {
    return this.post('/pop_blocks', { nblocks });
  }

  // ============================================================
  // Binary Endpoints
  // ============================================================

  /**
   * Get output indexes for a transaction (binary format)
   * @param {string} txid - Transaction ID
   * @returns {Promise<RPCResponse>} Output indexes
   */
  async getOutputIndexes(txid) {
    return this.post('/get_o_indexes.bin', { txid });
  }

  /**
   * Get blocks in binary format
   * @param {string[]} blockIds - Block hashes to fetch
   * @param {number} startHeight - Start height for fetching
   * @param {boolean} [prune=false] - Prune block data
   * @param {boolean} [noMinerTx=false] - Exclude miner transactions
   * @returns {Promise<RPCResponse>} Blocks data
   */
  async getBlocksBin(blockIds, startHeight, prune = false, noMinerTx = false) {
    return this.post('/get_blocks.bin', {
      block_ids: blockIds,
      start_height: startHeight,
      prune,
      no_miner_tx: noMinerTx
    });
  }

  /**
   * Get block/transaction hashes (binary format)
   * @param {string[]} blockIds - Known block hashes
   * @param {number} startHeight - Start height
   * @returns {Promise<RPCResponse>} Hashes data
   */
  async getHashesBin(blockIds, startHeight) {
    return this.post('/get_hashes.bin', {
      block_ids: blockIds,
      start_height: startHeight
    });
  }

  // ============================================================
  // Utility Methods
  // ============================================================

  /**
   * Check if daemon is synchronized with the network
   * @returns {Promise<boolean>} True if synchronized
   */
  async isSynchronized() {
    const response = await this.getInfo();
    if (response.success && response.result) {
      return response.result.synchronized === true;
    }
    return false;
  }

  /**
   * Get the current network type
   * @returns {Promise<string|null>} 'mainnet', 'testnet', 'stagenet', or null on error
   */
  async getNetworkType() {
    const response = await this.getInfo();
    if (response.success && response.result) {
      return response.result.nettype || null;
    }
    return null;
  }

  /**
   * Wait for daemon to be synchronized
   * @param {Object} [options={}] - Options
   * @param {number} [options.pollInterval=5000] - Poll interval in ms
   * @param {number} [options.timeout=0] - Timeout in ms (0 = no timeout)
   * @param {Function} [options.onProgress] - Progress callback (height, targetHeight)
   * @returns {Promise<boolean>} True when synchronized, false on timeout
   */
  async waitForSync(options = {}) {
    const pollInterval = options.pollInterval || 5000;
    const timeout = options.timeout || 0;
    const onProgress = options.onProgress;
    const startTime = Date.now();

    while (true) {
      const response = await this.getInfo();
      if (response.success && response.result) {
        const { height, target_height, synchronized } = response.result;

        if (onProgress) {
          onProgress(height, target_height);
        }

        if (synchronized) {
          return true;
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
 * Create a new Daemon RPC client
 * @param {RPCClientOptions} [options={}] - Client configuration
 * @returns {DaemonRPC}
 */
export function createDaemonRPC(options = {}) {
  return new DaemonRPC(options);
}

/**
 * Default mainnet daemon RPC URL (from config::RPC_DEFAULT_PORT = 19081)
 */
export const MAINNET_URL = 'http://localhost:19081';

/**
 * Default testnet daemon RPC URL (from config::testnet::RPC_DEFAULT_PORT = 29081)
 */
export const TESTNET_URL = 'http://localhost:29081';

/**
 * Default stagenet daemon RPC URL (from config::stagenet::RPC_DEFAULT_PORT = 39081)
 */
export const STAGENET_URL = 'http://localhost:39081';

/**
 * Default mainnet ZMQ RPC URL (from config::ZMQ_RPC_DEFAULT_PORT = 19083)
 */
export const ZMQ_MAINNET_URL = 'http://localhost:19083';

/**
 * Default testnet ZMQ RPC URL (from config::testnet::ZMQ_RPC_DEFAULT_PORT = 29083)
 */
export const ZMQ_TESTNET_URL = 'http://localhost:29083';

/**
 * Default stagenet ZMQ RPC URL (from config::stagenet::ZMQ_RPC_DEFAULT_PORT = 39083)
 */
export const ZMQ_STAGENET_URL = 'http://localhost:39083';

/**
 * Mainnet restricted (public) RPC URL - no default in source, this is convention
 */
export const RESTRICTED_MAINNET_URL = 'http://localhost:19089';

/**
 * Testnet restricted (public) RPC URL - no default in source, this is convention
 */
export const RESTRICTED_TESTNET_URL = 'http://localhost:29089';

/**
 * Stagenet restricted (public) RPC URL - no default in source, this is convention
 */
export const RESTRICTED_STAGENET_URL = 'http://localhost:39089';

export default {
  DaemonRPC,
  createDaemonRPC,
  MAINNET_URL,
  TESTNET_URL,
  STAGENET_URL,
  ZMQ_MAINNET_URL,
  ZMQ_TESTNET_URL,
  ZMQ_STAGENET_URL,
  RESTRICTED_MAINNET_URL,
  RESTRICTED_TESTNET_URL,
  RESTRICTED_STAGENET_URL
};
