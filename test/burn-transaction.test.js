#!/usr/bin/env bun
/**
 * BURN Transaction Tests
 *
 * Tests for Salvium BURN transaction creation and serialization.
 */

import { describe, test, expect } from 'bun:test';
import {
  buildBurnTransaction,
  serializeTxPrefix,
  parseTransaction,
  TX_TYPE,
  scRandom
} from '../src/transaction.js';
import { scalarMultBase } from '../src/crypto/index.js';
import { bytesToHex, hexToBytes } from '../src/address.js';

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

describe('BURN Transaction', () => {

  describe('buildBurnTransaction', () => {

    test('creates valid BURN transaction structure', () => {
      const input = generateMockInput(50000000000n); // 500 SAL
      const burnAmount = 100000000n; // 1 SAL
      const fee = 100000000n; // 0.001 SAL

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      const tx = buildBurnTransaction(
        {
          inputs: [input],
          burnAmount,
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          fee
        },
        {
          assetType: 'SAL'
        }
      );

      expect(tx).toBeDefined();
      expect(tx.prefix).toBeDefined();
      expect(tx.prefix.txType).toBe(TX_TYPE.BURN);
      expect(tx.prefix.amount_burnt).toBe(burnAmount);
      expect(tx.prefix.source_asset_type).toBe('SAL');
      expect(tx.prefix.destination_asset_type).toBe('BURN');
      expect(tx.prefix.unlockTime).toBe(0); // BURN has no lock period
    });

    test('sets destination_asset_type to BURN', () => {
      const input = generateMockInput();
      const burnAmount = 100000000n;
      const fee = 100000000n;

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      const tx = buildBurnTransaction(
        {
          inputs: [input],
          burnAmount,
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          fee
        },
        { assetType: 'SAL' }
      );

      expect(tx.prefix.destination_asset_type).toBe('BURN');
    });

    test('throws error for zero burn amount', () => {
      const input = generateMockInput();
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      expect(() => {
        buildBurnTransaction(
          {
            inputs: [input],
            burnAmount: 0n,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            fee: 100000000n
          },
          { assetType: 'SAL' }
        );
      }).toThrow('Burn amount must be positive');
    });

    test('throws error for insufficient funds', () => {
      const input = generateMockInput(100000000n); // 1 SAL
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      expect(() => {
        buildBurnTransaction(
          {
            inputs: [input],
            burnAmount: 200000000n, // 2 SAL - more than input
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            fee: 100000000n
          },
          { assetType: 'SAL' }
        );
      }).toThrow('Insufficient funds');
    });

    test('throws error for missing inputs', () => {
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      expect(() => {
        buildBurnTransaction(
          {
            inputs: [],
            burnAmount: 100000000n,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            fee: 100000000n
          },
          { assetType: 'SAL' }
        );
      }).toThrow('At least one input is required');
    });

    test('throws error for missing change address', () => {
      const input = generateMockInput();

      expect(() => {
        buildBurnTransaction(
          {
            inputs: [input],
            burnAmount: 100000000n,
            changeAddress: null,
            fee: 100000000n
          },
          { assetType: 'SAL' }
        );
      }).toThrow('Change address is required');
    });

    test('supports SAL1 asset type', () => {
      const input = generateMockInput();
      const burnAmount = 100000000n;
      const fee = 100000000n;

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      const tx = buildBurnTransaction(
        {
          inputs: [input],
          burnAmount,
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          fee
        },
        {
          assetType: 'SAL1'
        }
      );

      expect(tx.prefix.source_asset_type).toBe('SAL1');
      expect(tx.prefix.destination_asset_type).toBe('BURN');
    });

    test('includes CLSAG signatures', () => {
      const input = generateMockInput();
      const burnAmount = 100000000n;
      const fee = 100000000n;

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();

      const tx = buildBurnTransaction(
        {
          inputs: [input],
          burnAmount,
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          fee
        },
        { assetType: 'SAL' }
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

  describe('serializeTxPrefix with BURN fields', () => {

    test('serializes BURN transaction type', () => {
      const prefix = {
        version: 4,
        unlockTime: 0,
        inputs: [],
        outputs: [],
        extra: {},
        txType: TX_TYPE.BURN,
        amount_burnt: 100000000n,
        source_asset_type: 'SAL',
        destination_asset_type: 'BURN',
        return_address: null,
        return_pubkey: null,
        amount_slippage_limit: 0n
      };

      const serialized = serializeTxPrefix(prefix);
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBeGreaterThan(0);
    });

  });

});

console.log('\n=== BURN Transaction Tests ===\n');
