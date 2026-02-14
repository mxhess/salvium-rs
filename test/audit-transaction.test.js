#!/usr/bin/env bun
/**
 * AUDIT Transaction Tests
 *
 * Tests for Salvium AUDIT transaction creation and validation.
 * AUDIT enables users to participate in compliance/transparency audits
 * by locking all their coins during designated hard fork periods.
 *
 * NOTE: AUDIT transactions are only valid during specific AUDIT hard fork
 * periods (HF v6, v8) and will be rejected outside these windows.
 */

import { describe, test, expect } from 'bun:test';
import {
  buildAuditTransaction,
  serializeTxPrefix,
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
      ringCommitments.push(scalarMultBase(mask));
    } else {
      const { publicKey: decoyPk } = generateTestKeys();
      ring.push(decoyPk);
      ringCommitments.push(scalarMultBase(scRandom()));
    }
    ringIndices.push(i * 1000 + i);
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

describe('AUDIT Transaction', () => {

  describe('buildAuditTransaction', () => {

    test('creates valid AUDIT transaction structure (SAL -> SAL1)', () => {
      const inputAmount = 100000000000n; // 1000 SAL
      const fee = 100000000n; // 0.001 SAL
      const auditAmount = inputAmount - fee; // All coins minus fee
      const input = generateMockInput(inputAmount);

      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildAuditTransaction(
        {
          inputs: [input],
          auditAmount,
          sourceAsset: 'SAL',
          destAsset: 'SAL1',
          unlockHeight: 500000,
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee
        }
      );

      expect(tx).toBeDefined();
      expect(tx.prefix).toBeDefined();
      expect(tx.prefix.txType).toBe(TX_TYPE.AUDIT);
      expect(tx.prefix.amount_burnt).toBe(auditAmount);
      expect(tx.prefix.source_asset_type).toBe('SAL');
      expect(tx.prefix.destination_asset_type).toBe('SAL1');
      expect(tx.prefix.unlockTime).toBe(500000);
    });

    test('creates valid AUDIT transaction structure (SAL1 -> SAL1)', () => {
      const inputAmount = 50000000000n;
      const fee = 100000000n;
      const auditAmount = inputAmount - fee;
      const input = generateMockInput(inputAmount);

      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildAuditTransaction(
        {
          inputs: [input],
          auditAmount,
          sourceAsset: 'SAL1',
          destAsset: 'SAL1',
          unlockHeight: 600000,
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee
        }
      );

      expect(tx.prefix.txType).toBe(TX_TYPE.AUDIT);
      expect(tx.prefix.source_asset_type).toBe('SAL1');
      expect(tx.prefix.destination_asset_type).toBe('SAL1');
    });

    test('enforces change-is-zero requirement', () => {
      const inputAmount = 100000000000n;
      const fee = 100000000n;
      const incorrectAuditAmount = inputAmount - fee - 1000n; // Leaves change
      const input = generateMockInput(inputAmount);

      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildAuditTransaction(
          {
            inputs: [input],
            auditAmount: incorrectAuditAmount,  // Not all coins
            sourceAsset: 'SAL',
            destAsset: 'SAL1',
            unlockHeight: 500000,
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee
          }
        );
      }).toThrow('AUDIT requires all inputs minus fee');
    });

    test('throws error for zero audit amount', () => {
      const input = generateMockInput();
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildAuditTransaction(
          {
            inputs: [input],
            auditAmount: 0n,
            sourceAsset: 'SAL',
            destAsset: 'SAL1',
            unlockHeight: 500000,
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee: 100000000n
          }
        );
      }).toThrow('Audit amount must be positive');
    });

    test('throws error for invalid asset pair (SAL -> SAL)', () => {
      const inputAmount = 100000000000n;
      const fee = 100000000n;
      const auditAmount = inputAmount - fee;
      const input = generateMockInput(inputAmount);

      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildAuditTransaction(
          {
            inputs: [input],
            auditAmount,
            sourceAsset: 'SAL',
            destAsset: 'SAL',  // Invalid - must be SAL1
            unlockHeight: 500000,
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee
          }
        );
      }).toThrow('Invalid audit asset pair');
    });

    test('throws error for invalid asset pair (VSD -> SAL1)', () => {
      const inputAmount = 100000000000n;
      const fee = 100000000n;
      const auditAmount = inputAmount - fee;
      const input = generateMockInput(inputAmount);

      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildAuditTransaction(
          {
            inputs: [input],
            auditAmount,
            sourceAsset: 'VSD',  // Invalid for AUDIT
            destAsset: 'SAL1',
            unlockHeight: 500000,
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee
          }
        );
      }).toThrow('Invalid audit asset pair');
    });

    test('throws error for missing inputs', () => {
      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildAuditTransaction(
          {
            inputs: [],
            auditAmount: 100000000n,
            sourceAsset: 'SAL',
            destAsset: 'SAL1',
            unlockHeight: 500000,
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee: 100000000n
          }
        );
      }).toThrow('At least one input is required');
    });

    test('throws error for missing return address', () => {
      const inputAmount = 100000000000n;
      const fee = 100000000n;
      const auditAmount = inputAmount - fee;
      const input = generateMockInput(inputAmount);

      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildAuditTransaction(
          {
            inputs: [input],
            auditAmount,
            sourceAsset: 'SAL',
            destAsset: 'SAL1',
            unlockHeight: 500000,
            returnAddress: null,
            returnPubkey: returnPub,
            fee
          }
        );
      }).toThrow('Return address is required');
    });

    test('throws error for missing return pubkey', () => {
      const inputAmount = 100000000000n;
      const fee = 100000000n;
      const auditAmount = inputAmount - fee;
      const input = generateMockInput(inputAmount);

      const { publicKey: returnAddr } = generateTestKeys();

      expect(() => {
        buildAuditTransaction(
          {
            inputs: [input],
            auditAmount,
            sourceAsset: 'SAL',
            destAsset: 'SAL1',
            unlockHeight: 500000,
            returnAddress: returnAddr,
            returnPubkey: null,
            fee
          }
        );
      }).toThrow('Return pubkey is required');
    });

    test('throws error for invalid unlock height', () => {
      const inputAmount = 100000000000n;
      const fee = 100000000n;
      const auditAmount = inputAmount - fee;
      const input = generateMockInput(inputAmount);

      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      expect(() => {
        buildAuditTransaction(
          {
            inputs: [input],
            auditAmount,
            sourceAsset: 'SAL',
            destAsset: 'SAL1',
            unlockHeight: 0,  // Invalid
            returnAddress: returnAddr,
            returnPubkey: returnPub,
            fee
          }
        );
      }).toThrow('Unlock height must be positive');
    });

    test('includes CLSAG signatures', () => {
      const inputAmount = 100000000000n;
      const fee = 100000000n;
      const auditAmount = inputAmount - fee;
      const input = generateMockInput(inputAmount);

      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildAuditTransaction(
        {
          inputs: [input],
          auditAmount,
          sourceAsset: 'SAL',
          destAsset: 'SAL1',
          unlockHeight: 500000,
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
    });

    test('has zero outputs (change-is-zero)', () => {
      const inputAmount = 100000000000n;
      const fee = 100000000n;
      const auditAmount = inputAmount - fee;
      const input = generateMockInput(inputAmount);

      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildAuditTransaction(
        {
          inputs: [input],
          auditAmount,
          sourceAsset: 'SAL',
          destAsset: 'SAL1',
          unlockHeight: 500000,
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee
        }
      );

      // AUDIT transactions should have 0 outputs (change-is-zero)
      expect(tx.prefix.vout.length).toBe(0);
    });

    test('handles multiple inputs correctly', () => {
      const input1Amount = 50000000000n;
      const input2Amount = 50000000000n;
      const fee = 100000000n;
      const totalInput = input1Amount + input2Amount;
      const auditAmount = totalInput - fee;

      const input1 = generateMockInput(input1Amount);
      const input2 = generateMockInput(input2Amount);

      const { publicKey: returnAddr } = generateTestKeys();
      const { publicKey: returnPub } = generateTestKeys();

      const tx = buildAuditTransaction(
        {
          inputs: [input1, input2],
          auditAmount,
          sourceAsset: 'SAL',
          destAsset: 'SAL1',
          unlockHeight: 500000,
          returnAddress: returnAddr,
          returnPubkey: returnPub,
          fee
        }
      );

      expect(tx.prefix.txType).toBe(TX_TYPE.AUDIT);
      expect(tx.prefix.amount_burnt).toBe(auditAmount);
      expect(tx.prefix.vin.length).toBe(2);
      expect(tx.rct.CLSAGs.length).toBe(2);
    });

  });

  describe('serializeTxPrefix with AUDIT fields', () => {

    test('serializes AUDIT transaction type', () => {
      const prefix = {
        version: 4,
        unlockTime: 500000,
        inputs: [],
        outputs: [],
        extra: {},
        txType: TX_TYPE.AUDIT,
        amount_burnt: 100000000n,
        source_asset_type: 'SAL',
        destination_asset_type: 'SAL1',
        return_address: new Uint8Array(32),
        return_pubkey: new Uint8Array(32),
        amount_slippage_limit: 0n
      };

      const serialized = serializeTxPrefix(prefix);
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBeGreaterThan(0);
    });

  });

});

console.log('\n=== AUDIT Transaction Tests ===\n');
