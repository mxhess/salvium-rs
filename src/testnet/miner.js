/**
 * Testnet Miner - Block Assembly and RandomX Mining
 *
 * Assembles blocks from transactions, constructs the hashing blob,
 * and mines with real RandomX proof-of-work (difficulty 1 for instant mining).
 *
 * @module testnet/miner
 */

import { RandomXContext } from '../randomx/index.js';
import { constructBlockHashingBlob, findNonceOffset, setNonce, checkHash } from '../mining.js';
import { getBlockHash, serializeBlockHeader } from '../block/serialization.js';
import { cnFastHash } from '../crypto/index.js';
import { serializeTxPrefix } from '../transaction/serialization.js';
import { bytesToHex, hexToBytes } from '../address.js';
import { createMinerTransaction, createEmptyProtocolTransaction } from './miner-tx.js';
import {
  getBlockReward,
  getHfVersionForHeight,
  NETWORK_ID,
  CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
} from '../consensus.js';

/**
 * Testnet block miner
 */
export class TestnetMiner {
  /**
   * @param {import('./node.js').TestnetNode} node - Testnet node to mine into
   * @param {number} network - Network ID (default TESTNET)
   */
  constructor(node, network = NETWORK_ID.TESTNET) {
    this.node = node;
    this.network = network;
    this.rx = new RandomXContext();
    this.initialized = false;

    /** @type {string|null} Miner view public key (hex) - legacy */
    this.minerViewPub = null;
    /** @type {string|null} Miner spend public key (hex) - legacy */
    this.minerSpendPub = null;
    /** @type {string|null} CARROT view pubkey K^0_v (hex) */
    this.carrotViewPub = null;
    /** @type {string|null} CARROT spend pubkey K_s (hex) */
    this.carrotSpendPub = null;
  }

  /**
   * Initialize RandomX with a seed hash
   * @param {Uint8Array|string} seedHash - RandomX cache key
   */
  async init(seedHash) {
    await this.rx.init(seedHash || 'salvium-testnet-seed');
    this.initialized = true;
  }

  /**
   * Set the miner's address keys
   * @param {string} viewPub - View public key (hex)
   * @param {string} spendPub - Spend public key (hex)
   */
  setMinerAddress(viewPub, spendPub) {
    this.minerViewPub = viewPub;
    this.minerSpendPub = spendPub;
  }

  /**
   * Set the miner's CARROT address keys (used for HF >= 10)
   * @param {string} viewPub - CARROT primary address view pubkey K^0_v (hex)
   * @param {string} spendPub - CARROT account spend pubkey K_s (hex)
   */
  setCarrotAddress(viewPub, spendPub) {
    this.carrotViewPub = viewPub;
    this.carrotSpendPub = spendPub;
  }

  /**
   * Mine a single block and add it to the node
   * @returns {{ height: number, hash: string, reward: bigint }}
   */
  async mineBlock() {
    if (!this.initialized) {
      throw new Error('Miner not initialized. Call init() first.');
    }
    if (!this.minerViewPub || !this.minerSpendPub) {
      throw new Error('Miner address not set. Call setMinerAddress() first.');
    }

    const height = this.node.getHeight();
    const hfVersion = getHfVersionForHeight(height, this.network);

    // Calculate block reward
    const medianWeight = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
    const currentWeight = 1000; // Small block
    const alreadyGenerated = this.node.getTotalGeneratedCoins();
    const { reward } = getBlockReward(medianWeight, currentWeight, alreadyGenerated, hfVersion);

    // Create miner transaction — use CARROT keys for HF >= 10
    const useCarrot = hfVersion >= 10 && this.carrotViewPub && this.carrotSpendPub;
    const viewPub = useCarrot ? this.carrotViewPub : this.minerViewPub;
    const spendPub = useCarrot ? this.carrotSpendPub : this.minerSpendPub;
    const { tx: minerTx, txHash: minerTxHash, txSecretKey } =
      createMinerTransaction(height, reward, viewPub, spendPub, hfVersion);

    // Create protocol transaction
    const { tx: protocolTx, txHash: protocolTxHash } =
      createEmptyProtocolTransaction(height);

    // Drain mempool (user transactions)
    const mempoolTxs = this.node.drainMempool();

    // Collect user transaction hashes for the block (as Uint8Array for merkle tree)
    const userTxHashes = mempoolTxs.map(mtx => {
      const h = mtx._meta?.txHash || mtx.txHash;
      return typeof h === 'string' ? hexToBytes(h) : h;
    });

    // Assemble block
    const prevHash = height > 0
      ? hexToBytes(this.node.getTopBlockHash())
      : new Uint8Array(32);

    const block = {
      major_version: hfVersion,
      minor_version: 0,
      timestamp: Math.floor(Date.now() / 1000),
      prev_id: prevHash,
      nonce: 0,
      miner_tx: minerTx,
      protocol_tx: protocolTx,
      tx_hashes: userTxHashes,
    };

    // Build hashing blob for PoW
    // Transaction hashes for tree: [minerTxHash, protocolTxHash, ...mempoolTxHashes]
    const allTxHashes = [minerTxHash, protocolTxHash];
    for (const mtx of mempoolTxs) {
      const h = mtx._meta?.txHash || mtx.txHash;
      allTxHashes.push(typeof h === 'string' ? hexToBytes(h) : h);
    }

    const hashingBlob = constructBlockHashingBlob(block, allTxHashes);
    const nonceOffset = findNonceOffset(hashingBlob);

    // Mine with difficulty 1 — every hash passes, but we still run real RandomX
    const difficulty = 1n;
    let nonce = 0;
    let powHash;

    for (nonce = 0; nonce < 0xFFFFFFFF; nonce++) {
      const blob = setNonce(hashingBlob, nonce, nonceOffset);
      powHash = this.rx.hash(blob);
      if (checkHash(powHash, difficulty)) {
        break;
      }
    }

    // Set winning nonce
    block.nonce = nonce;

    // Compute block hash (block ID — different from PoW hash)
    const blockHashBytes = getBlockHash(block);
    const blockHash = bytesToHex(blockHashBytes);

    // Build user transaction data for the node
    const userTxs = mempoolTxs.map(mtx => {
      const txHashHex = typeof (mtx._meta?.txHash || mtx.txHash) === 'string'
        ? (mtx._meta?.txHash || mtx.txHash)
        : bytesToHex(mtx._meta?.txHash || mtx.txHash);
      return {
        txHash: txHashHex,
        keyImages: mtx._meta?.keyImages || [],
        outputs: (mtx.prefix?.vout || []).map((vout, i) => ({
          key: typeof vout.target === 'string' ? vout.target : bytesToHex(vout.target),
          mask: mtx.rct?.outPk?.[i] || null,
          commitment: mtx.rct?.outPk?.[i] || null,
        })),
        tx: mtx,
      };
    });

    // Store user transactions for lookup
    for (const utx of userTxs) {
      this.node.txsByHash.set(utx.txHash, {
        tx: utx.tx,
        txHash: utx.txHash,
        blockHeight: height,
        txSecretKey: utx.tx._meta?.txSecretKey || null,
      });
    }

    // Add block to chain
    this.node.addBlock(block, blockHash, bytesToHex(minerTxHash), bytesToHex(protocolTxHash), {
      minerTx: { txSecretKey: bytesToHex(txSecretKey) },
      protocolTx: {},
      userTxs,
    }, reward);

    return { height, hash: blockHash, reward };
  }

  /**
   * Mine multiple blocks sequentially
   * @param {number} count - Number of blocks to mine
   * @returns {Array<{ height: number, hash: string, reward: bigint }>}
   */
  async mineBlocks(count) {
    const results = [];
    for (let i = 0; i < count; i++) {
      results.push(await this.mineBlock());
    }
    return results;
  }
}
