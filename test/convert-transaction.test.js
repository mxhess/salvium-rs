#!/usr/bin/env bun
/**
 * CONVERT Transaction Tests
 *
 * Tests for Salvium CONVERT transaction creation and validation.
 * CONVERT enables SAL <-> VSD asset conversion using oracle pricing.
 *
 * NOTE: CONVERT transactions are currently gated behind HF version 255
 * and are not yet enabled on mainnet.
 */

import { describe, test, expect } from 'bun:test';
import {
  buildConvertTransaction,
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

describe('CONVERT Transaction', () => {

  describe('buildConvertTransaction', () => {

    test('creates valid CONVERT transaction structure (SAL -> VSD)', () => {
      const input = generateMockInput(100000000000n); // 1000 SAL
      const convertAmount = 10000000000n; // 100 SAL
      const fee = 100000000n; // 0.001 SAL

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildConvertTransaction(
        {
          inputs: [input],
          convertAmount,
          sourceAsset: 'SAL',
          destAsset: 'VSD',
          slippageLimit: convertAmount >> 5n, // 3.125%
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee
        }
      );

      expect(tx).toBeDefined();
      expect(tx.prefix).toBeDefined();
      expect(tx.prefix.txType).toBe(TX_TYPE.CONVERT);
      expect(tx.prefix.amount_burnt).toBe(convertAmount);
      expect(tx.prefix.source_asset_type).toBe('SAL');
      expect(tx.prefix.destination_asset_type).toBe('VSD');
      expect(tx.prefix.unlockTime).toBe(0); // CONVERT has no lock period
    });

    test('creates valid CONVERT transaction structure (VSD -> SAL)', () => {
      const input = generateMockInput(100000000000n);
      const convertAmount = 10000000000n;
      const fee = 100000000n;

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildConvertTransaction(
        {
          inputs: [input],
          convertAmount,
          sourceAsset: 'VSD',
          destAsset: 'SAL',
          slippageLimit: convertAmount >> 5n,
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee
        }
      );

      expect(tx.prefix.txType).toBe(TX_TYPE.CONVERT);
      expect(tx.prefix.source_asset_type).toBe('VSD');
      expect(tx.prefix.destination_asset_type).toBe('SAL');
    });

    test('sets amount_slippage_limit correctly', () => {
      const input = generateMockInput();
      const convertAmount = 32000000000n; // 320 SAL
      const expectedSlippage = convertAmount >> 5n; // 10 SAL (3.125%)

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildConvertTransaction(
        {
          inputs: [input],
          convertAmount,
          sourceAsset: 'SAL',
          destAsset: 'VSD',
          slippageLimit: expectedSlippage,
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee: 100000000n
        }
      );

      expect(tx.prefix.amount_slippage_limit).toBe(expectedSlippage);
    });

    test('throws error for zero convert amount', () => {
      const input = generateMockInput();
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildConvertTransaction(
          {
            inputs: [input],
            convertAmount: 0n,
            sourceAsset: 'SAL',
            destAsset: 'VSD',
            slippageLimit: 0n,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee: 100000000n
          }
        );
      }).toThrow('Convert amount must be positive');
    });

    test('throws error for same source and destination asset', () => {
      const input = generateMockInput();
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildConvertTransaction(
          {
            inputs: [input],
            convertAmount: 100000000n,
            sourceAsset: 'SAL',
            destAsset: 'SAL',  // Same as source
            slippageLimit: 3125000n,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee: 100000000n
          }
        );
      }).toThrow('Source and destination asset types must be different');
    });

    test('throws error for invalid conversion pair', () => {
      const input = generateMockInput();
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildConvertTransaction(
          {
            inputs: [input],
            convertAmount: 100000000n,
            sourceAsset: 'SAL',
            destAsset: 'BTC',  // Invalid - only SAL <-> VSD allowed
            slippageLimit: 3125000n,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee: 100000000n
          }
        );
      }).toThrow('Invalid conversion pair');
    });

    test('throws error for insufficient funds', () => {
      const input = generateMockInput(100000000n); // 1 SAL
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildConvertTransaction(
          {
            inputs: [input],
            convertAmount: 200000000n, // 2 SAL - more than input
            sourceAsset: 'SAL',
            destAsset: 'VSD',
            slippageLimit: 6250000n,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee: 100000000n
          }
        );
      }).toThrow('Insufficient funds');
    });

    test('throws error for missing inputs', () => {
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildConvertTransaction(
          {
            inputs: [],
            convertAmount: 100000000n,
            sourceAsset: 'SAL',
            destAsset: 'VSD',
            slippageLimit: 3125000n,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee: 100000000n
          }
        );
      }).toThrow('At least one input is required');
    });

    test('throws error for missing return address', () => {
      const input = generateMockInput();
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildConvertTransaction(
          {
            inputs: [input],
            convertAmount: 100000000n,
            sourceAsset: 'SAL',
            destAsset: 'VSD',
            slippageLimit: 3125000n,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            returnAddress: null,  // Missing
            returnPubkey: returnPub,
            fee: 100000000n
          }
        );
      }).toThrow('Return address is required');
    });

    test('throws error for missing return pubkey', () => {
      const input = generateMockInput();
      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();

      expect(() => {
        buildConvertTransaction(
          {
            inputs: [input],
            convertAmount: 100000000n,
            sourceAsset: 'SAL',
            destAsset: 'VSD',
            slippageLimit: 3125000n,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            returnAddress: returnAddr,
            returnPubkey: null,  // Missing
            fee: 100000000n
          }
        );
      }).toThrow('Return pubkey is required');
    });

    test('throws error for slippage limit below protocol minimum', () => {
      const input = generateMockInput();
      const convertAmount = 100000000n;
      const protocolMinSlippage = convertAmount >> 5n; // 3125000
      const tooLowSlippage = protocolMinSlippage - 1n;

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildConvertTransaction(
          {
            inputs: [input],
            convertAmount,
            sourceAsset: 'SAL',
            destAsset: 'VSD',
            slippageLimit: tooLowSlippage,
            changeAddress: {
              viewPublicKey: viewPubKey,
              spendPublicKey: spendPubKey,
              isSubaddress: false
            },
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee: 100000000n
          }
        );
      }).toThrow('below protocol minimum');
    });

    test('includes CLSAG signatures', () => {
      const input = generateMockInput();
      const convertAmount = 100000000n;
      const fee = 100000000n;

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildConvertTransaction(
        {
          inputs: [input],
          convertAmount,
          sourceAsset: 'SAL',
          destAsset: 'VSD',
          slippageLimit: convertAmount >> 5n,
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee
        }
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

  describe('serializeTxPrefix with CONVERT fields', () => {

    test('serializes CONVERT transaction type', () => {
      const prefix = {
        version: 4,
        unlockTime: 0,
        inputs: [],
        outputs: [],
        extra: {},
        txType: TX_TYPE.CONVERT,
        amount_burnt: 100000000n,
        source_asset_type: 'SAL',
        destination_asset_type: 'VSD',
        return_address: new Uint8Array(32),
        return_pubkey: new Uint8Array(32),
        amount_slippage_limit: 3125000n
      };

      const serialized = serializeTxPrefix(prefix);
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBeGreaterThan(0);
    });

  });

  describe('slippage calculation', () => {

    test('default slippage is 1/32 (3.125%) of convert amount', () => {
      const input = generateMockInput();
      const convertAmount = 32000000000n; // 320 SAL
      const expectedSlippage = 1000000000n; // 10 SAL = 320/32

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      // When slippageLimit is not provided, use default
      const tx = buildConvertTransaction(
        {
          inputs: [input],
          convertAmount,
          sourceAsset: 'SAL',
          destAsset: 'VSD',
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee: 100000000n
        }
      );

      expect(tx.prefix.amount_slippage_limit).toBe(expectedSlippage);
    });

    test('allows slippage limit higher than default', () => {
      const input = generateMockInput();
      const convertAmount = 32000000000n;
      const higherSlippage = 2000000000n; // 20 SAL (6.25%)

      const { publicKey: viewPubKey } = generateTestKeys();
      const { publicKey: spendPubKey } = generateTestKeys();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildConvertTransaction(
        {
          inputs: [input],
          convertAmount,
          sourceAsset: 'SAL',
          destAsset: 'VSD',
          slippageLimit: higherSlippage,
          changeAddress: {
            viewPublicKey: viewPubKey,
            spendPublicKey: spendPubKey,
            isSubaddress: false
          },
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee: 100000000n
        }
      );

      expect(tx.prefix.amount_slippage_limit).toBe(higherSlippage);
    });

  });

});

console.log('\n=== CONVERT Transaction Tests ===\n');
