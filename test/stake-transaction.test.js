#!/usr/bin/env bun
/**
 * STAKE Transaction Tests
 *
 * Tests for Salvium STAKE transaction creation and serialization.
 */

import { describe, test, expect } from 'bun:test';
import {
  buildStakeTransaction,
  serializeTxPrefix,
  parseTransaction,
  TX_TYPE,
  scRandom
} from '../src/transaction.js';
import { scalarMultBase } from '../src/crypto/index.js';
import { bytesToHex, hexToBytes } from '../src/address.js';
import { MAINNET_CONFIG, TESTNET_CONFIG } from '../src/consensus.js';

// Generate test keys
function generateTestKeys() {
  const secretKey = scRandom();
  const publicKey = scalarMultBase(secretKey);
  return { secretKey, publicKey };
}

// Generate a mock input for testing
function generateMockInput(amount = 100000000000n) {
  const { secretKey, publicKey } = generateTestKeys();
  const mask = scRandom();

  // Generate ring members
  const ringSize = 11;
  const realIndex = Math.floor(Math.random() * ringSize);
  const ring = [];
  const ringCommitments = [];
  const ringIndices = [];

  for (let i = 0; i < ringSize; i++) {
    if (i === realIndex) {
      ring.push(publicKey);
      ringCommitments.push(scalarMultBase(mask)); // Simplified commitment
    } else {
      const { publicKey: decoyPk } = generateTestKeys();
      ring.push(decoyPk);
      ringCommitments.push(scalarMultBase(scRandom()));
    }
    ringIndices.push(i * 1000 + i); // Fake global indices
  }

  return {
    secretKey,
    publicKey,
    amount,
    mask,
    ring,
    ringCommitments,
    ringIndices,
    realIndex
  };
}

describe('STAKE Transaction', () => {

  describe('buildStakeTransaction', () => {

    test('creates valid STAKE transaction structure', () => {
      const input = generateMockInput(50000000000n); // 500 SAL
      const stakeAmount = 100000000n; // 1 SAL
      const fee = 100000000n; // 0.001 SAL

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      const tx = buildStakeTransaction(
        {
          inputs: [input],
          stakeAmount,
          returnAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          fee
        },
        {
          stakeLockPeriod: TESTNET_CONFIG.STAKE_LOCK_PERIOD,
          assetType: 'SAL'
        }
      );

      expect(tx).toBeDefined();
      expect(tx.prefix).toBeDefined();
      expect(tx.prefix.txType).toBe(TX_TYPE.STAKE);
      expect(tx.prefix.amount_burnt).toBe(stakeAmount);
      expect(tx.prefix.source_asset_type).toBe('SAL');
      expect(tx.prefix.destination_asset_type).toBe('SAL');
      expect(tx.prefix.unlockTime).toBe(TESTNET_CONFIG.STAKE_LOCK_PERIOD);
    });

    test('sets correct unlock time from stakeLockPeriod', () => {
      const input = generateMockInput();
      const stakeAmount = 100000000n;
      const fee = 100000000n;

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      // Test with mainnet lock period
      const txMainnet = buildStakeTransaction(
        {
          inputs: [input],
          stakeAmount,
          returnAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          fee
        },
        {
          stakeLockPeriod: MAINNET_CONFIG.STAKE_LOCK_PERIOD,
          assetType: 'SAL'
        }
      );

      expect(txMainnet.prefix.unlockTime).toBe(21600); // 30*24*30 blocks
    });

    test('throws error for zero stake amount', () => {
      const input = generateMockInput();
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      expect(() => {
        buildStakeTransaction(
          {
            inputs: [input],
            stakeAmount: 0n,
            returnAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            fee: 100000000n
          },
          { stakeLockPeriod: 20, assetType: 'SAL' }
        );
      }).toThrow('Stake amount must be positive');
    });

    test('throws error for insufficient funds', () => {
      const input = generateMockInput(100000000n); // 1 SAL
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      expect(() => {
        buildStakeTransaction(
          {
            inputs: [input],
            stakeAmount: 200000000n, // 2 SAL - more than input
            returnAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            fee: 100000000n
          },
          { stakeLockPeriod: 20, assetType: 'SAL' }
        );
      }).toThrow('Insufficient funds');
    });

    test('throws error for missing inputs', () => {
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      expect(() => {
        buildStakeTransaction(
          {
            inputs: [],
            stakeAmount: 100000000n,
            returnAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            fee: 100000000n
          },
          { stakeLockPeriod: 20, assetType: 'SAL' }
        );
      }).toThrow('At least one input is required');
    });

    test('throws error for missing return address', () => {
      const input = generateMockInput();

      expect(() => {
        buildStakeTransaction(
          {
            inputs: [input],
            stakeAmount: 100000000n,
            returnAddress: null,
            fee: 100000000n
          },
          { stakeLockPeriod: 20, assetType: 'SAL' }
        );
      }).toThrow('Return address is required');
    });

    test('supports SAL1 asset type', () => {
      const input = generateMockInput();
      const stakeAmount = 100000000n;
      const fee = 100000000n;

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      const tx = buildStakeTransaction(
        {
          inputs: [input],
          stakeAmount,
          returnAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          fee
        },
        {
          stakeLockPeriod: 20,
          assetType: 'SAL1'
        }
      );

      expect(tx.prefix.source_asset_type).toBe('SAL1');
      expect(tx.prefix.destination_asset_type).toBe('SAL1');
    });

    test('includes CLSAG signatures', () => {
      const input = generateMockInput();
      const stakeAmount = 100000000n;
      const fee = 100000000n;

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      const tx = buildStakeTransaction(
        {
          inputs: [input],
          stakeAmount,
          returnAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          fee
        },
        { stakeLockPeriod: 20, assetType: 'SAL' }
      );

      expect(tx.rct).toBeDefined();
      expect(tx.rct.CLSAGs).toBeDefined();
      expect(tx.rct.CLSAGs.length).toBe(1);
      expect(tx.rct.CLSAGs[0].s.length).toBe(11); // Ring size
      expect(tx.rct.CLSAGs[0].c1).toBeDefined();
      expect(tx.rct.CLSAGs[0].I).toBeDefined(); // Key image
      expect(tx.rct.CLSAGs[0].D).toBeDefined(); // Commitment key image
    });

  });

  describe('serializeTxPrefix with STAKE fields', () => {

    test('serializes STAKE transaction type', () => {
      const prefix = {
        version: 4,
        unlockTime: 21600,
        inputs: [],
        outputs: [],
        extra: {},
        txType: TX_TYPE.STAKE,
        amount_burnt: 100000000n,
        source_asset_type: 'SAL',
        destination_asset_type: 'SAL',
        return_address: new Uint8Array(32),
        return_pubkey: new Uint8Array(32),
        amount_slippage_limit: 0n
      };

      const serialized = serializeTxPrefix(prefix);
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBeGreaterThan(0);
    });

    test('serializes TRANSFER transaction type (default)', () => {
      const prefix = {
        version: 3,
        unlockTime: 0,
        inputs: [],
        outputs: [],
        extra: {},
        // No txType specified - should default to TRANSFER
        source_asset_type: 'SAL',
        destination_asset_type: 'SAL'
      };

      const serialized = serializeTxPrefix(prefix);
      expect(serialized).toBeInstanceOf(Uint8Array);
    });

  });

});

console.log('\n=== STAKE Transaction Tests ===\n');
