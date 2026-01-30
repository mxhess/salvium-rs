/**
 * Testnet Integration Tests
 *
 * Tests the self-contained JavaScript testnet:
 * - Genesis block creation
 * - Block mining with real RandomX PoW
 * - Wallet sync and output detection
 * - Balance tracking with maturity window
 * - Mining past CARROT hard fork (height 1100)
 */

import { describe, test, expect, beforeAll } from 'bun:test';
import { Testnet } from '../src/testnet/index.js';
import { createMinerTransaction, createEmptyProtocolTransaction } from '../src/testnet/miner-tx.js';
import { TestnetNode } from '../src/testnet/node.js';
import { bytesToHex } from '../src/address.js';
import { PREMINE_AMOUNT } from '../src/consensus.js';
import { generateSeed, deriveKeys } from '../src/carrot.js';

// =============================================================================
// Unit Tests (no RandomX needed)
// =============================================================================

describe('createMinerTransaction', () => {
  const keys = deriveKeys(generateSeed());
  const spendPub = bytesToHex(keys.spendPublicKey);
  const viewPub = bytesToHex(keys.viewPublicKey);

  test('creates valid genesis coinbase tx (no stake deduction)', () => {
    const { tx, txHash, txSecretKey } = createMinerTransaction(0, PREMINE_AMOUNT, viewPub, spendPub, 1);

    expect(tx.version).toBe(2);
    expect(tx.txType).toBe(1); // MINER
    expect(tx.inputs).toHaveLength(1);
    expect(tx.inputs[0].type).toBe('gen');
    expect(tx.inputs[0].height).toBe(0);
    expect(tx.outputs).toHaveLength(1);
    expect(tx.amount_burnt).toBe(0n); // No stake deduction at genesis
    expect(tx.outputs[0].amount).toBe(PREMINE_AMOUNT);
    expect(txHash).toBeInstanceOf(Uint8Array);
    expect(txHash.length).toBe(32);
    expect(txSecretKey.length).toBe(32);
  });

  test('applies 20% stake deduction post-genesis', () => {
    const reward = 1000000000n;
    const { tx } = createMinerTransaction(100, reward, viewPub, spendPub, 1);

    expect(tx.amount_burnt).toBe(200000000n); // 20%
    expect(tx.outputs[0].amount).toBe(800000000n); // 80%
  });

  test('output has tagged key with view tag', () => {
    const { tx } = createMinerTransaction(1, 1000000000n, viewPub, spendPub, 1);

    const output = tx.outputs[0];
    expect(output.viewTag).toBeDefined();
    expect(typeof output.viewTag).toBe('number');
    expect(output.viewTag).toBeGreaterThanOrEqual(0);
    expect(output.viewTag).toBeLessThanOrEqual(255);
    expect(typeof output.target).toBe('string'); // hex key
    expect(output.target.length).toBe(64); // 32 bytes hex
  });
});

describe('createEmptyProtocolTransaction', () => {
  test('creates valid protocol tx', () => {
    const { tx, txHash } = createEmptyProtocolTransaction(100);

    expect(tx.version).toBe(2);
    expect(tx.txType).toBe(2); // PROTOCOL
    expect(tx.outputs).toHaveLength(0);
    expect(tx.amount_burnt).toBe(0n);
    expect(txHash.length).toBe(32);
  });
});

describe('TestnetNode', () => {
  test('starts empty', () => {
    const node = new TestnetNode();
    expect(node.getHeight()).toBe(0);
    expect(node.getTopBlockHash()).toBe('0'.repeat(64));
    expect(node.getTotalGeneratedCoins()).toBe(0n);
  });

  test('getInfo returns correct height', async () => {
    const node = new TestnetNode();
    const info = await node.getInfo();
    expect(info.success).toBe(true);
    expect(info.result.height).toBe(0);
  });

  test('getBlockHeaderByHeight returns error for missing blocks', async () => {
    const node = new TestnetNode();
    const result = await node.getBlockHeaderByHeight(0);
    expect(result.success).toBe(false);
  });
});

// =============================================================================
// Integration Tests (require RandomX — slower startup)
// =============================================================================

describe('Testnet Integration', () => {
  let testnet;

  beforeAll(async () => {
    testnet = new Testnet();
    await testnet.init();
  }, 30000); // RandomX init can take a few seconds

  test('genesis block exists after init', () => {
    expect(testnet.node.getHeight()).toBe(1);
    expect(testnet.node.getTotalGeneratedCoins()).toBe(PREMINE_AMOUNT);
  });

  test('genesis block has correct reward', async () => {
    const header = await testnet.node.getBlockHeaderByHeight(0);
    expect(header.success).toBe(true);
    expect(header.result.block_header.height).toBe(0);
  });

  test('can mine additional blocks', async () => {
    const results = await testnet.mineBlocks(5);
    expect(results).toHaveLength(5);
    expect(testnet.node.getHeight()).toBe(6);

    // Each result should have height, hash, reward
    for (const r of results) {
      expect(r.height).toBeDefined();
      expect(r.hash).toBeDefined();
      expect(r.hash.length).toBe(64);
      expect(r.reward).toBeGreaterThan(0n);
    }
  });

  test('block headers are retrievable', async () => {
    const headers = await testnet.node.getBlockHeadersRange(0, 5);
    expect(headers.success).toBe(true);
    expect(headers.result.headers).toHaveLength(6);
  });

  test('getBlock returns parseable JSON', async () => {
    const block = await testnet.node.getBlock({ height: 1 });
    expect(block.success).toBe(true);

    const json = JSON.parse(block.result.json);
    expect(json.miner_tx).toBeDefined();
    expect(json.miner_tx.vin).toHaveLength(1);
    expect(json.miner_tx.vin[0].gen).toBeDefined();
    expect(json.miner_tx.vout).toHaveLength(1);
    expect(json.miner_tx.vout[0].target.tagged_key).toBeDefined();
    expect(json.miner_tx.extra).toBeInstanceOf(Array);
    expect(json.miner_tx.extra[0]).toBe(0x01); // TX_EXTRA_TAG_PUBKEY
    expect(json.miner_tx.extra.length).toBe(33); // 1 tag + 32 bytes pubkey
  });

  test('miner wallet can sync and detect coinbase outputs', async () => {
    const wallet = testnet.getMinerWallet();
    await testnet.syncWallet(wallet);

    const outputs = await wallet.storage.getOutputs({});
    expect(outputs.length).toBeGreaterThan(0);

    // All outputs should belong to the miner
    for (const output of outputs) {
      expect(output.amount).toBeGreaterThan(0n);
      expect(output.blockHeight).toBeDefined();
    }
  });

  test('non-miner wallet finds no outputs', async () => {
    const wallet = testnet.createWallet();
    await testnet.syncWallet(wallet);

    const outputs = await wallet.storage.getOutputs({});
    expect(outputs.length).toBe(0);
  });

  test('balance tracks total and unlocked', async () => {
    // Mine enough blocks for some to mature (60 block unlock window)
    const currentHeight = testnet.node.getHeight();
    const blocksNeeded = 60 - currentHeight + 2; // +2 for safety
    if (blocksNeeded > 0) {
      await testnet.mineBlocks(blocksNeeded);
    }

    const wallet = testnet.getMinerWallet();
    await testnet.syncWallet(wallet);

    const { balance, unlockedBalance } = await testnet.getBalance(wallet);
    expect(balance).toBeGreaterThan(0n);
    expect(unlockedBalance).toBeGreaterThan(0n);
    expect(unlockedBalance).toBeLessThanOrEqual(balance);
  }, 30000);
});

describe('Testnet CARROT Hard Fork', () => {
  let testnet;

  beforeAll(async () => {
    testnet = new Testnet();
    await testnet.init();
    // Mine past CARROT activation height (1100 on testnet)
    // We already have genesis (height 0), need to get to 1101+
    await testnet.mineBlocks(1105);
  }, 180000); // Mining 1100+ blocks with RandomX

  test('chain height is past CARROT activation', () => {
    expect(testnet.node.getHeight()).toBeGreaterThan(1100);
  });

  test('blocks before and after fork have correct major version', async () => {
    // Before CARROT (height 1099, should be HF 9 = AUDIT2_PAUSE)
    const preFork = await testnet.node.getBlockHeaderByHeight(1099);
    expect(preFork.success).toBe(true);
    expect(preFork.result.block_header.major_version).toBeLessThan(10);

    // After CARROT (height 1100+)
    const postFork = await testnet.node.getBlockHeaderByHeight(1100);
    expect(postFork.success).toBe(true);
    expect(postFork.result.block_header.major_version).toBe(10);
  });

  test('miner wallet detects outputs across hard fork boundary', async () => {
    const wallet = testnet.getMinerWallet();
    await testnet.syncWallet(wallet);

    const outputs = await wallet.storage.getOutputs({});
    // Should have outputs from both pre and post CARROT
    expect(outputs.length).toBeGreaterThan(1100);

    // Verify we have both legacy and CARROT outputs
    const legacyOutputs = outputs.filter(o => !o.isCarrot);
    const carrotOutputs = outputs.filter(o => o.isCarrot);
    expect(legacyOutputs.length).toBe(1100); // Heights 0-1099
    expect(carrotOutputs.length).toBeGreaterThan(0); // Heights 1100+

    // All CARROT outputs should have non-zero amounts
    for (const o of carrotOutputs) {
      expect(o.amount).toBeGreaterThan(0n);
    }
  });

  test('post-fork blocks use carrot_v1 output format', async () => {
    const block = await testnet.node.getBlock({ height: 1100 });
    expect(block.success).toBe(true);
    const json = JSON.parse(block.result.json);
    expect(json.miner_tx.vout[0].target.carrot_v1).toBeDefined();
    expect(json.miner_tx.vout[0].target.carrot_v1.key).toBeDefined();
    expect(json.miner_tx.vout[0].target.carrot_v1.view_tag).toBeDefined();
    expect(json.miner_tx.vout[0].target.carrot_v1.encrypted_janus_anchor).toBeDefined();
  });

  test('balance includes both pre and post CARROT outputs', async () => {
    const wallet = testnet.getMinerWallet();
    await testnet.syncWallet(wallet);

    const { balance, unlockedBalance } = await testnet.getBalance(wallet);
    expect(balance).toBeGreaterThan(0n);
    // With 1100+ blocks mined, most should be unlocked (60-block window)
    expect(unlockedBalance).toBeGreaterThan(0n);
  });
});
