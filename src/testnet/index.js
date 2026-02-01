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
import { generateKeyDerivation, deriveSecretKey } from '../crypto/index.js';
import { selectUTXOs } from '../transaction/utxo.js';
import {
  buildTransaction,
  prepareInputs,
  estimateTransactionFee,
} from '../transaction.js';
import { getTxPrefixHash } from '../transaction/serialization.js';

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
   * Send SAL from one wallet to another
   *
   * @param {Object} fromWallet - Sender wallet (from createWallet/getMinerWallet)
   * @param {{ viewPublicKey: string|Uint8Array, spendPublicKey: string|Uint8Array }} toAddress - Recipient public keys
   * @param {bigint} amount - Amount to send (atomic units)
   * @param {Object} options - Options
   * @param {boolean} options.mine - Mine a block after submitting (default: true)
   * @returns {{ txHash: string, fee: bigint }}
   */
  async transfer(fromWallet, toAddress, amount, options = {}) {
    const { mine = true } = options;
    amount = typeof amount === 'bigint' ? amount : BigInt(amount);

    // 1. Sync wallet to get latest outputs
    await this.syncWallet(fromWallet);
    const currentHeight = this.node.getHeight();

    // 2. Get spendable outputs
    const allOutputs = await fromWallet.storage.getOutputs({});
    const spendable = allOutputs.filter(o =>
      !o.isSpent && !o.isFrozen && o.keyImage &&
      (currentHeight - o.blockHeight) >= CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
    );

    // 3. Estimate fee
    const fee = estimateTransactionFee(1, 2); // Rough estimate with 1 input, 2 outputs

    // 4. Select UTXOs
    const { selected } = selectUTXOs(spendable, amount + fee, 0n, {
      currentHeight,
      minConfirmations: CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
      dustThreshold: 0n,
    });

    // 5. Assign global indices to selected outputs (needed for ring selection)
    for (const output of selected) {
      if (output.globalIndex === null || output.globalIndex === undefined) {
        output.globalIndex = this.node.getGlobalIndex(output.txHash, output.outputIndex);
      }
    }

    // 6. Re-derive one-time secret keys for each selected output
    const viewSecKey = fromWallet.keys.viewSecretKey;
    const spendSecKey = fromWallet.keys.spendSecretKey;
    for (const output of selected) {
      // Get the tx pubkey from the stored transaction
      const stored = this.node.txsByHash.get(output.txHash);
      if (!stored) throw new Error(`Transaction ${output.txHash} not found`);

      const txSecretKeyHex = stored.txSecretKey;
      if (txSecretKeyHex) {
        // We have the tx secret key — derive the output public key directly
        // For coinbase outputs where we're the miner, we can use the tx secret key
        // to compute the derivation: D = txSecretKey * viewPublicKey (but we need
        // the standard derivation: D = viewSecretKey * txPublicKey)
      }

      // Standard approach: derive using tx public key from the transaction
      let txPubKey;
      const tx = stored.tx;
      if (tx?.extra?.txPubKey) {
        txPubKey = typeof tx.extra.txPubKey === 'string'
          ? hexToBytes(tx.extra.txPubKey)
          : tx.extra.txPubKey;
      } else {
        throw new Error(`Cannot find tx pubkey for ${output.txHash}`);
      }

      const derivation = generateKeyDerivation(txPubKey, viewSecKey);
      const outputSecretKey = deriveSecretKey(derivation, output.outputIndex, spendSecKey);
      output.secretKey = outputSecretKey;

      // Coinbase outputs have null mask — set to identity scalar (blinding factor = 1)
      if (!output.mask) {
        output.mask = '0100000000000000000000000000000000000000000000000000000000000000';
      }
      // Coinbase outputs have null commitment — compute zeroCommit(amount)
      if (!output.commitment) {
        // For coinbase: C = G + amount*H (blinding factor 1)
        // We store the identity mask and let buildTransaction handle it
        // The commitment is needed for ring signature verification
        const { commit } = await import('../transaction/serialization.js');
        const scalarOne = hexToBytes('0100000000000000000000000000000000000000000000000000000000000000');
        output.commitment = bytesToHex(commit(output.amount, scalarOne));
      }
    }

    // 7. Prepare inputs (decoy selection + ring member fetching)
    const preparedInputs = await prepareInputs(selected, this.node, {
      ringSize: 16,
    });

    // 8. Build and sign the transaction
    const viewPub = toAddress.viewPublicKey;
    const spendPub = toAddress.spendPublicKey;
    const viewPubHex = typeof viewPub === 'string' ? viewPub : bytesToHex(viewPub);
    const spendPubHex = typeof spendPub === 'string' ? spendPub : bytesToHex(spendPub);

    // Change goes back to sender
    const senderViewPub = bytesToHex(fromWallet.keys.viewPublicKey);
    const senderSpendPub = bytesToHex(fromWallet.keys.spendPublicKey);

    const tx = buildTransaction({
      inputs: preparedInputs,
      destinations: [{
        viewPublicKey: viewPubHex,
        spendPublicKey: spendPubHex,
        amount,
      }],
      changeAddress: {
        viewPublicKey: senderViewPub,
        spendPublicKey: senderSpendPub,
      },
      fee,
    });

    // 9. Compute tx hash and attach to transaction
    const txHashBytes = getTxPrefixHash(tx.prefix);
    const txHashHex = bytesToHex(txHashBytes);
    tx.txHash = txHashHex;
    if (!tx._meta) tx._meta = {};
    tx._meta.txHash = txHashHex;

    // 10. Submit to mempool
    const result = await this.node.sendRawTransaction(tx);
    if (!result.success) {
      throw new Error(`Transaction rejected: ${result.error?.message}`);
    }

    // 11. Mine a block to confirm (optional)
    if (mine) {
      await this.miner.mineBlock();
    }

    return { tx, fee, txHash: txHashHex };
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
