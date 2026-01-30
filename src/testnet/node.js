/**
 * Testnet Node - In-Memory Blockchain with DaemonRPC-Compatible Interface
 *
 * Provides the same RPC methods that WalletSync calls, backed by an
 * in-memory chain. No network, no disk — just a JavaScript blockchain.
 *
 * @module testnet/node
 */

import { bytesToHex, hexToBytes } from '../address.js';

/**
 * In-memory blockchain node with daemon RPC interface
 */
export class TestnetNode {
  constructor() {
    /** @type {Array<Object>} Blocks in chain order */
    this.blocks = [];

    /** @type {Map<string, Object>} Block lookup by hash */
    this.blocksByHash = new Map();

    /** @type {Map<string, Object>} Transaction lookup by hash */
    this.txsByHash = new Map();

    /** @type {bigint} Running total of generated coins */
    this.totalGeneratedCoins = 0n;

    /** @type {Array<Object>} Pending mempool transactions */
    this.mempool = [];
  }

  // ===========================================================================
  // Chain Mutation
  // ===========================================================================

  /**
   * Add a mined block to the chain
   *
   * @param {Object} block - Block object (header + miner_tx + protocol_tx)
   * @param {string} blockHash - Block hash (hex)
   * @param {string} minerTxHash - Miner transaction hash (hex)
   * @param {string} protocolTxHash - Protocol transaction hash (hex)
   * @param {Object} txData - Extra tx data for storage
   * @param {bigint} reward - Block reward
   */
  addBlock(block, blockHash, minerTxHash, protocolTxHash, txData, reward) {
    const height = this.blocks.length;

    const entry = {
      height,
      hash: blockHash,
      block,
      minerTxHash,
      protocolTxHash,
      txData: txData || {},
      reward,
      timestamp: block.timestamp || Math.floor(Date.now() / 1000),
    };

    this.blocks.push(entry);
    this.blocksByHash.set(blockHash, entry);
    this.totalGeneratedCoins += reward;

    // Store transactions for lookup
    if (minerTxHash) {
      this.txsByHash.set(minerTxHash, {
        tx: block.miner_tx,
        txHash: minerTxHash,
        blockHeight: height,
        ...txData.minerTx,
      });
    }
    if (protocolTxHash) {
      this.txsByHash.set(protocolTxHash, {
        tx: block.protocol_tx,
        txHash: protocolTxHash,
        blockHeight: height,
        ...txData.protocolTx,
      });
    }
  }

  getHeight() { return this.blocks.length; }
  getTopBlockHash() { return this.blocks.length > 0 ? this.blocks[this.blocks.length - 1].hash : '0'.repeat(64); }
  getTotalGeneratedCoins() { return this.totalGeneratedCoins; }

  addToMempool(tx) { this.mempool.push(tx); }
  drainMempool() { const txs = this.mempool; this.mempool = []; return txs; }

  // ===========================================================================
  // DaemonRPC-Compatible Interface (what WalletSync calls)
  // ===========================================================================

  async getInfo() {
    return {
      success: true,
      result: {
        height: this.blocks.length,
        top_block_hash: this.getTopBlockHash(),
        status: 'OK',
      },
    };
  }

  async getBlockHeaderByHeight(height) {
    if (height < 0 || height >= this.blocks.length) {
      return { success: false, error: { message: `Block ${height} not found` } };
    }
    const entry = this.blocks[height];
    return {
      success: true,
      result: {
        block_header: {
          height: entry.height,
          hash: entry.hash,
          timestamp: entry.timestamp,
          major_version: entry.block.major_version || 1,
          minor_version: entry.block.minor_version || 0,
          reward: Number(entry.reward),
        },
      },
    };
  }

  async getBlockHeadersRange(startHeight, endHeight) {
    const headers = [];
    for (let h = startHeight; h <= endHeight && h < this.blocks.length; h++) {
      const entry = this.blocks[h];
      headers.push({
        height: entry.height,
        hash: entry.hash,
        timestamp: entry.timestamp,
        major_version: entry.block.major_version || 1,
        minor_version: entry.block.minor_version || 0,
        reward: Number(entry.reward),
      });
    }
    return { success: true, result: { headers } };
  }

  async getBlock(opts) {
    const height = opts.height;
    if (height < 0 || height >= this.blocks.length) {
      return { success: false, error: { message: `Block ${height} not found` } };
    }

    const entry = this.blocks[height];
    const block = entry.block;

    // Build the JSON representation that WalletSync._processBlock expects
    const blockJson = {
      miner_tx: this._txToJson(block.miner_tx, entry.txData.minerTx),
      tx_hashes: [],
    };
    if (block.protocol_tx) {
      blockJson.protocol_tx = this._txToJson(block.protocol_tx, entry.txData.protocolTx);
    }

    return {
      success: true,
      result: {
        json: JSON.stringify(blockJson),
        miner_tx_hash: entry.minerTxHash,
        protocol_tx_hash: entry.protocolTxHash,
      },
    };
  }

  async getBlocksByHeight(heights) {
    const blocks = [];
    for (const h of heights) {
      if (h >= 0 && h < this.blocks.length) {
        const entry = this.blocks[h];
        const block = entry.block;
        const blockJson = {
          miner_tx: this._txToJson(block.miner_tx, entry.txData.minerTx),
          tx_hashes: [],
        };
        if (block.protocol_tx) {
          blockJson.protocol_tx = this._txToJson(block.protocol_tx, entry.txData.protocolTx);
        }
        blocks.push({
          block: '', // hex blob not needed since we provide json
          json: JSON.stringify(blockJson),
          miner_tx_hash: entry.minerTxHash,
          protocol_tx_hash: entry.protocolTxHash,
          txs: [],
        });
      }
    }
    return { success: true, result: { blocks } };
  }

  async getTransactions(hashes, opts) {
    const txs = [];
    for (const hash of hashes) {
      const stored = this.txsByHash.get(hash);
      if (stored) {
        txs.push({
          tx_hash: hash,
          as_json: JSON.stringify(this._txToJson(stored.tx, stored)),
        });
      }
    }
    return { success: true, result: { txs } };
  }

  async getTransactionPool() {
    return { success: true, result: { transactions: [] } };
  }

  // ===========================================================================
  // Internal: Convert internal tx format to JSON format WalletSync expects
  // ===========================================================================

  /**
   * Convert a tx object to the JSON representation that WalletSync parses
   *
   * WalletSync expects:
   *   vout[].target.tagged_key.{key, asset_type, view_tag}
   *   extra: [byte array]
   *   rct_signatures: { type }
   */
  _txToJson(tx, extraData = {}) {
    if (!tx) return null;

    const json = {
      version: tx.version,
      unlock_time: Number(tx.unlockTime || 0),
      vin: [],
      vout: [],
      extra: [],
      rct_signatures: { type: tx.rct_signatures?.type ?? 0 },
    };

    // Inputs
    for (const input of (tx.inputs || [])) {
      if (input.type === 'gen') {
        json.vin.push({ gen: { height: input.height } });
      }
    }

    // Outputs
    for (const output of (tx.outputs || [])) {
      const voutEntry = {
        amount: Number(output.amount || 0),
        target: {},
      };

      if (output.isCarrot) {
        // CARROT v1 output: 3-byte view tag, encrypted janus anchor
        const viewTagHex = output.viewTag instanceof Uint8Array
          ? bytesToHex(output.viewTag)
          : (typeof output.viewTag === 'number'
            ? (output.viewTag & 0xff).toString(16).padStart(2, '0')
            : output.viewTag);
        voutEntry.target.carrot_v1 = {
          key: typeof output.target === 'string' ? output.target : bytesToHex(output.target),
          asset_type: 'SAL',
          view_tag: viewTagHex,
          encrypted_janus_anchor: output.anchorEncrypted || '0'.repeat(32),
        };
      } else if (output.viewTag !== undefined) {
        // Tagged key output (legacy with 1-byte view tag)
        const viewTagHex = (output.viewTag & 0xff).toString(16).padStart(2, '0');
        voutEntry.target.tagged_key = {
          key: typeof output.target === 'string' ? output.target : bytesToHex(output.target),
          asset_type: 'SAL',
          view_tag: viewTagHex,
        };
      } else if (output.target) {
        // Regular key output
        voutEntry.target.key = typeof output.target === 'string' ? output.target : bytesToHex(output.target);
      }

      json.vout.push(voutEntry);
    }

    // Extra: convert to byte array
    if (tx.extra?.txPubKey) {
      const pkHex = typeof tx.extra.txPubKey === 'string' ? tx.extra.txPubKey : bytesToHex(tx.extra.txPubKey);
      const pkBytes = hexToBytes(pkHex);
      json.extra = [0x01, ...pkBytes];
    } else if (tx.extra instanceof Uint8Array) {
      json.extra = [...tx.extra];
    }

    return json;
  }
}
