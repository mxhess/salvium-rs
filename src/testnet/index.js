/**
 * Testnet Orchestrator
 *
 * High-level API for running a self-contained Salvium testnet.
 * Combines the in-memory node, miner, and wallet sync into a
 * unified interface for integration testing.
 *
 * @module testnet
 */

import { TestnetNode } from './node.js';
import { TestnetMiner } from './miner.js';
import { bytesToHex, hexToBytes } from '../address.js';
import { MemoryStorage } from '../wallet-store.js';
import { WalletSync } from '../wallet-sync.js';
import { NETWORK_ID, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW } from '../consensus.js';
import { generateSeed, deriveKeys, deriveCarrotKeys } from '../carrot.js';

/**
 * Self-contained Salvium testnet
 */
export class Testnet {
  constructor() {
    this.node = new TestnetNode();
    this.miner = new TestnetMiner(this.node, NETWORK_ID.TESTNET);

    // Miner wallet keys (legacy + CARROT)
    this._minerKeys = null;
    this._minerCarrotKeys = null;
    this._minerSeed = null;
  }

  /**
   * Initialize the testnet: set up RandomX, generate miner keys, mine genesis
   */
  async init() {
    // Generate miner wallet keys
    this._minerSeed = generateSeed();
    this._minerKeys = deriveKeys(this._minerSeed);
    this._minerCarrotKeys = deriveCarrotKeys(this._minerSeed);

    // Set miner address — for pre-CARROT blocks, use legacy keys
    // For CARROT blocks, the miner will use CARROT keys (K_s, K^0_v)
    this.miner.setMinerAddress(
      bytesToHex(this._minerKeys.viewPublicKey),
      bytesToHex(this._minerKeys.spendPublicKey)
    );
    this.miner.setCarrotAddress(
      this._minerCarrotKeys.primaryAddressViewPubkey,
      this._minerCarrotKeys.accountSpendPubkey
    );

    // Initialize RandomX
    await this.miner.init('salvium-testnet-seed');

    // Mine genesis block
    await this.miner.mineBlock();
  }

  /**
   * Mine blocks
   * @param {number} count - Number of blocks to mine
   * @returns {Array<{ height: number, hash: string, reward: bigint }>}
   */
  async mineBlocks(count) {
    return this.miner.mineBlocks(count);
  }

  /**
   * Create a new wallet with its own keys and sync engine
   * @returns {{ keys: Object, carrotKeys: Object, storage: MemoryStorage, sync: WalletSync }}
   */
  createWallet() {
    const seed = generateSeed();
    const keys = deriveKeys(seed);
    const carrotKeys = deriveCarrotKeys(seed);
    return this._buildWallet(keys, carrotKeys);
  }

  /**
   * Get the miner wallet (keys + sync engine pointed at the node)
   * @returns {{ keys: Object, carrotKeys: Object, storage: MemoryStorage, sync: WalletSync }}
   */
  getMinerWallet() {
    return this._buildWallet(this._minerKeys, this._minerCarrotKeys);
  }

  /**
   * Build a wallet object from keys
   * @private
   */
  _buildWallet(keys, carrotKeys) {
    // The subaddress map must contain the main account spend pubkey
    // mapped to {major: 0, minor: 0} for output detection to work
    const spendPubHex = bytesToHex(keys.spendPublicKey);
    const subaddresses = new Map();
    subaddresses.set(spendPubHex, { major: 0, minor: 0 });

    // CARROT subaddress map: accountSpendPubkey -> {major: 0, minor: 0}
    const carrotSubaddresses = new Map();
    if (carrotKeys) {
      carrotSubaddresses.set(carrotKeys.accountSpendPubkey, { major: 0, minor: 0 });
    }

    const storage = new MemoryStorage();
    const sync = new WalletSync({
      storage,
      daemon: this.node,
      keys: {
        viewSecretKey: keys.viewSecretKey,
        spendSecretKey: keys.spendSecretKey,
        spendPublicKey: keys.spendPublicKey,
      },
      subaddresses,
      carrotKeys: carrotKeys ? {
        viewIncomingKey: carrotKeys.viewIncomingKey,
        accountSpendPubkey: carrotKeys.accountSpendPubkey,
        generateImageKey: carrotKeys.generateImageKey,
      } : null,
      carrotSubaddresses,
    });

    return { keys, carrotKeys, storage, sync };
  }

  /**
   * Sync a wallet to the current chain tip
   * @param {{ storage: MemoryStorage, sync: WalletSync }} wallet
   */
  async syncWallet(wallet) {
    await wallet.storage.open();
    await wallet.sync.start(0);
  }

  /**
   * Get balance from wallet storage by summing outputs
   * @param {{ storage: MemoryStorage }} wallet
   * @param {number} currentHeight - Current chain height for unlock checking
   * @returns {{ balance: bigint, unlockedBalance: bigint }}
   */
  async getBalance(wallet, currentHeight) {
    if (currentHeight === undefined) {
      currentHeight = this.node.getHeight();
    }

    const outputs = await wallet.storage.getOutputs({});
    let balance = 0n;
    let unlockedBalance = 0n;

    for (const output of outputs) {
      if (output.isSpent) continue;
      const amount = typeof output.amount === 'bigint' ? output.amount : BigInt(output.amount);
      balance += amount;

      const confirmations = currentHeight - output.blockHeight;
      if (confirmations >= CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW) {
        unlockedBalance += amount;
      }
    }

    return { balance, unlockedBalance };
  }

  /**
   * Clean up resources
   */
  async destroy() {
    // Nothing to clean up for now — RandomX context is GC'd
  }
}

export { TestnetNode } from './node.js';
export { TestnetMiner } from './miner.js';
export { createMinerTransaction, createEmptyProtocolTransaction } from './miner-tx.js';
