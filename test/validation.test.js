#!/usr/bin/env bun
/**
 * Validation Module Tests
 *
 * Tests for Salvium transaction and block validation rules.
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp
 *            ~/github/salvium/src/cryptonote_core/tx_verification_utils.cpp
 */

import { describe, test, expect } from 'bun:test';
import {
  // Constants
  MINIMUM_MIXIN,
  VALID_ASSET_TYPES,
  ASSET_TYPE_ID,
  RCT_TYPE_NAMES,
  TXOUT_TYPE,
  AUDIT_HARD_FORKS,

  // Asset type functions
  assetTypeFromId,
  assetIdFromType,
  validateAssetTypes,

  // Transaction type/version validation
  validateTxTypeAndVersion,

  // Output validation
  validateOutputTypes,
  validateOutputPubkeySorting,
  validateOutputsOverflow,

  // RCT validation
  validateRctType,

  // Input validation
  validateInputs,

  // Fee validation
  getFeeQuantizationMask,
  calculateRequiredFee,
  validateFee,

  // Weight validation
  getTransactionWeightLimit,
  validateTxWeight,

  // Miner transaction
  prevalidateMinerTransaction,

  // Yield calculation
  calculateYieldPayout,
  getStakeLockPeriod,

  // Comprehensive validation
  validateTransactionFull
} from '../src/validation.js';

import { TX_TYPE } from '../src/transaction.js';
import { HF_VERSION, COIN, DEFAULT_RING_SIZE } from '../src/consensus.js';


// =============================================================================
// TEST HELPERS
// =============================================================================

function createMockTransaction(overrides = {}) {
  return {
    prefix: {
      version: 4,
      txType: TX_TYPE.TRANSFER,
      source_asset_type: 'SAL1',
      destination_asset_type: 'SAL1',
      vin: [
        {
          type: 'key',
          k_image: '0'.repeat(64),
          key_offsets: new Array(16).fill(1)
        }
      ],
      vout: [
        {
          amount: 0,
          target: { type: TXOUT_TYPE.to_carrot_v1, key: 'a'.repeat(64) }
        }
      ],
      ...overrides
    },
    rct: {
      type: RCT_TYPE_NAMES.SalviumOne,
      ...overrides.rct
    }
  };
}


// =============================================================================
// CONSTANTS TESTS
// =============================================================================

describe('Validation Constants', () => {

  test('MINIMUM_MIXIN is 15', () => {
    expect(MINIMUM_MIXIN).toBe(15);
  });

  test('VALID_ASSET_TYPES includes SAL, SAL1, BURN', () => {
    expect(VALID_ASSET_TYPES).toContain('SAL');
    expect(VALID_ASSET_TYPES).toContain('SAL1');
    expect(VALID_ASSET_TYPES).toContain('BURN');
  });

  test('ASSET_TYPE_ID has correct values', () => {
    expect(ASSET_TYPE_ID.SAL).toBe(0x53414C00);
    expect(ASSET_TYPE_ID.SAL1).toBe(0x53414C31);
    expect(ASSET_TYPE_ID.BURN).toBe(0x4255524E);
  });

  test('RCT_TYPE_NAMES has expected values', () => {
    expect(RCT_TYPE_NAMES.Null).toBe(0);
    expect(RCT_TYPE_NAMES.CLSAG).toBe(5);
    expect(RCT_TYPE_NAMES.BulletproofPlus).toBe(6);
    expect(RCT_TYPE_NAMES.SalviumZero).toBe(7);
    expect(RCT_TYPE_NAMES.SalviumOne).toBe(8);
  });

  test('AUDIT_HARD_FORKS has audit periods configured', () => {
    expect(AUDIT_HARD_FORKS[6]).toBeDefined();
    expect(AUDIT_HARD_FORKS[6].name).toBe('AUDIT1');
    expect(AUDIT_HARD_FORKS[8]).toBeDefined();
    expect(AUDIT_HARD_FORKS[8].name).toBe('AUDIT2');
  });

});


// =============================================================================
// ASSET TYPE TESTS
// =============================================================================

describe('Asset Type Functions', () => {

  describe('assetTypeFromId', () => {

    test('converts SAL ID to string', () => {
      expect(assetTypeFromId(0x53414C00)).toBe('SAL');
    });

    test('converts SAL1 ID to string', () => {
      expect(assetTypeFromId(0x53414C31)).toBe('SAL1');
    });

    test('converts BURN ID to string', () => {
      expect(assetTypeFromId(0x4255524E)).toBe('BURN');
    });

    test('returns null for invalid ID', () => {
      expect(assetTypeFromId(0x12345678)).toBeNull();
    });

  });

  describe('assetIdFromType', () => {

    test('converts SAL string to ID', () => {
      expect(assetIdFromType('SAL')).toBe(0x53414C00);
    });

    test('converts SAL1 string to ID', () => {
      expect(assetIdFromType('SAL1')).toBe(0x53414C31);
    });

    test('converts BURN string to ID', () => {
      expect(assetIdFromType('BURN')).toBe(0x4255524E);
    });

    test('returns null for invalid type', () => {
      expect(assetIdFromType('INVALID')).toBeNull();
    });

  });

  describe('validateAssetTypes', () => {

    test('valid TRANSFER with matching assets', () => {
      const tx = createMockTransaction({
        txType: TX_TYPE.TRANSFER,
        source_asset_type: 'SAL1',
        destination_asset_type: 'SAL1'
      });
      const result = validateAssetTypes(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(true);
    });

    test('invalid source asset type', () => {
      const tx = createMockTransaction({
        source_asset_type: 'INVALID',
        destination_asset_type: 'SAL1'
      });
      const result = validateAssetTypes(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid source asset type');
    });

    test('BURN must have destination = BURN', () => {
      const tx = createMockTransaction({
        txType: TX_TYPE.BURN,
        source_asset_type: 'SAL',
        destination_asset_type: 'SAL'  // Should be BURN
      });
      const result = validateAssetTypes(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('destination_asset_type = "BURN"');
    });

    test('BURN with correct destination is valid', () => {
      const tx = createMockTransaction({
        txType: TX_TYPE.BURN,
        source_asset_type: 'SAL',
        destination_asset_type: 'BURN'
      });
      const result = validateAssetTypes(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(true);
    });

    test('cannot spend BURN coins', () => {
      const tx = createMockTransaction({
        txType: TX_TYPE.TRANSFER,
        source_asset_type: 'BURN',
        destination_asset_type: 'BURN'
      });
      const result = validateAssetTypes(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Cannot spend BURN');
    });

    test('non-BURN/CONVERT must have matching source and dest', () => {
      const tx = createMockTransaction({
        txType: TX_TYPE.TRANSFER,
        source_asset_type: 'SAL',
        destination_asset_type: 'SAL1'
      });
      const result = validateAssetTypes(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('must match');
    });

  });

});


// =============================================================================
// TRANSACTION TYPE/VERSION TESTS
// =============================================================================

describe('Transaction Type and Version Validation', () => {

  test('valid TRANSFER transaction', () => {
    const tx = createMockTransaction({ txType: TX_TYPE.TRANSFER });
    const result = validateTxTypeAndVersion(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(true);
  });

  test('invalid transaction type 0', () => {
    const tx = createMockTransaction({ txType: 0 });
    const result = validateTxTypeAndVersion(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('UNSET is invalid');
  });

  test('invalid transaction type > 8', () => {
    const tx = createMockTransaction({ txType: 99 });
    const result = validateTxTypeAndVersion(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid transaction type');
  });

  test('STAKE requires version 4 at Carrot fork', () => {
    const tx = createMockTransaction({ txType: TX_TYPE.STAKE, version: 2 });
    const result = validateTxTypeAndVersion(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('requires version 4');
  });

  test('CONVERT not allowed before oracle HF', () => {
    const tx = createMockTransaction({ txType: TX_TYPE.CONVERT });
    const result = validateTxTypeAndVersion(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('CONVERT transactions not enabled');
  });

  test('AUDIT only allowed in audit HF periods', () => {
    const tx = createMockTransaction({ txType: TX_TYPE.AUDIT });
    // HF version 5 is not an audit HF
    const result = validateTxTypeAndVersion(tx, 5);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('only allowed in audit hard fork');
  });

  test('AUDIT allowed in HF version 6', () => {
    const tx = createMockTransaction({ txType: TX_TYPE.AUDIT, version: 4 });
    const result = validateTxTypeAndVersion(tx, 6);
    expect(result.valid).toBe(true);
  });

});


// =============================================================================
// OUTPUT VALIDATION TESTS
// =============================================================================

describe('Output Validation', () => {

  describe('validateOutputTypes', () => {

    test('AUDIT must have 0 outputs', () => {
      const tx = createMockTransaction({
        txType: TX_TYPE.AUDIT,
        vout: [{ amount: 0, target: { type: TXOUT_TYPE.to_carrot_v1 } }]
      });
      const result = validateOutputTypes(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('0 outputs');
    });

    test('AUDIT with 0 outputs is valid', () => {
      const tx = createMockTransaction({
        txType: TX_TYPE.AUDIT,
        vout: []
      });
      const result = validateOutputTypes(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(true);
    });

    test('STAKE must have exactly 1 output', () => {
      const tx = createMockTransaction({
        txType: TX_TYPE.STAKE,
        vout: [
          { amount: 0, target: { type: TXOUT_TYPE.to_carrot_v1 } },
          { amount: 0, target: { type: TXOUT_TYPE.to_carrot_v1 } }
        ]
      });
      const result = validateOutputTypes(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('exactly 1 output');
    });

  });

  describe('validateOutputPubkeySorting', () => {

    test('sorted outputs are valid', () => {
      const tx = createMockTransaction({
        vout: [
          { amount: 0, target: { key: '1'.repeat(64) } },
          { amount: 0, target: { key: '2'.repeat(64) } }
        ]
      });
      const result = validateOutputPubkeySorting(tx, HF_VERSION.CARROT);
      expect(result.valid).toBe(true);
    });

    test('not enforced before Carrot fork', () => {
      const tx = createMockTransaction({
        vout: [
          { amount: 0, target: { key: '9'.repeat(64) } },
          { amount: 0, target: { key: '1'.repeat(64) } }
        ]
      });
      const result = validateOutputPubkeySorting(tx, HF_VERSION.AUDIT1);
      expect(result.valid).toBe(true);
    });

  });

  describe('validateOutputsOverflow', () => {

    test('normal amounts are valid', () => {
      const tx = createMockTransaction({
        vout: [
          { amount: 1000000000 },
          { amount: 2000000000 }
        ]
      });
      const result = validateOutputsOverflow(tx);
      expect(result.valid).toBe(true);
    });

    test('detects overflow', () => {
      const tx = createMockTransaction({
        vout: [
          { amount: 18446744073709551615n },
          { amount: 1n }
        ]
      });
      const result = validateOutputsOverflow(tx);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('overflow');
    });

  });

});


// =============================================================================
// RCT TYPE VALIDATION TESTS
// =============================================================================

describe('RCT Type Validation', () => {

  test('SalviumOne required at Carrot fork', () => {
    const tx = createMockTransaction({
      txType: TX_TYPE.TRANSFER,
      rct: { type: RCT_TYPE_NAMES.BulletproofPlus }
    });
    const result = validateRctType(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('RCTTypeSalviumOne');
  });

  test('SalviumOne is valid at Carrot fork', () => {
    const tx = createMockTransaction({
      txType: TX_TYPE.TRANSFER,
      rct: { type: RCT_TYPE_NAMES.SalviumOne }
    });
    const result = validateRctType(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(true);
  });

  test('MINER must have RCTTypeNull', () => {
    const tx = createMockTransaction({
      txType: TX_TYPE.MINER,
      rct: { type: RCT_TYPE_NAMES.SalviumOne }
    });
    const result = validateRctType(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('RCTTypeNull');
  });

  test('MINER with RCTTypeNull is valid', () => {
    const tx = createMockTransaction({
      txType: TX_TYPE.MINER,
      rct: { type: RCT_TYPE_NAMES.Null }
    });
    const result = validateRctType(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(true);
  });

});


// =============================================================================
// INPUT VALIDATION TESTS
// =============================================================================

describe('Input Validation', () => {

  test('valid inputs pass', () => {
    const tx = createMockTransaction();
    const result = validateInputs(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(true);
  });

  test('no inputs fails', () => {
    const tx = createMockTransaction({ vin: [] });
    const result = validateInputs(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('at least 1 input');
  });

  test('wrong ring size fails', () => {
    const tx = createMockTransaction({
      vin: [{
        type: 'key',
        k_image: '0'.repeat(64),
        key_offsets: new Array(11).fill(1)  // Wrong ring size
      }]
    });
    const result = validateInputs(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('ring size must be');
  });

  test('MINER must have txin_gen', () => {
    const tx = createMockTransaction({
      txType: TX_TYPE.MINER,
      vin: [{ height: 100 }]  // txin_gen has height
    });
    const result = validateInputs(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(true);
  });

  test('key images must be sorted', () => {
    const tx = createMockTransaction({
      vin: [
        { type: 'key', k_image: 'f'.repeat(64), key_offsets: new Array(16).fill(1) },
        { type: 'key', k_image: 'a'.repeat(64), key_offsets: new Array(16).fill(1) }
      ]
    });
    const result = validateInputs(tx, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('sorted');
  });

});


// =============================================================================
// FEE VALIDATION TESTS
// =============================================================================

describe('Fee Validation', () => {

  test('getFeeQuantizationMask returns correct mask', () => {
    const mask = getFeeQuantizationMask();
    expect(mask).toBe(99999999n);  // 10^8 - 1
  });

  test('calculateRequiredFee returns non-zero fee', () => {
    const fee = calculateRequiredFee(3000, COIN, 300000, HF_VERSION.CARROT);
    expect(fee).toBeGreaterThan(0n);
  });

  test('sufficient fee passes', () => {
    const requiredFee = calculateRequiredFee(3000, COIN, 300000, HF_VERSION.CARROT);
    const result = validateFee(requiredFee, 3000, COIN, 300000, HF_VERSION.CARROT);
    expect(result.valid).toBe(true);
  });

  test('insufficient fee fails', () => {
    const result = validateFee(1n, 3000, COIN, 300000, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Insufficient fee');
  });

});


// =============================================================================
// WEIGHT VALIDATION TESTS
// =============================================================================

describe('Weight Validation', () => {

  test('getTransactionWeightLimit returns reasonable limit', () => {
    const limit = getTransactionWeightLimit(HF_VERSION.CARROT);
    expect(limit).toBeGreaterThan(100000);  // Should be significant
    expect(limit).toBeLessThan(300000);     // But not too large
  });

  test('normal weight passes', () => {
    const result = validateTxWeight(10000, HF_VERSION.CARROT);
    expect(result.valid).toBe(true);
  });

  test('excessive weight fails', () => {
    const result = validateTxWeight(500000, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('exceeds limit');
  });

});


// =============================================================================
// MINER TRANSACTION TESTS
// =============================================================================

describe('Miner Transaction Validation', () => {

  test('valid miner transaction passes prevalidation', () => {
    const minerTx = {
      prefix: {
        version: 4,
        txType: TX_TYPE.MINER,
        vin: [{ height: 100 }],
        vout: [{ amount: COIN, target: { type: TXOUT_TYPE.to_carrot_v1, key: 'a'.repeat(64) } }]
      },
      rct: { type: RCT_TYPE_NAMES.Null }
    };
    const result = prevalidateMinerTransaction(minerTx, 100, HF_VERSION.CARROT);
    expect(result.valid).toBe(true);
  });

  test('miner tx with wrong input count fails', () => {
    const minerTx = {
      prefix: {
        version: 4,
        txType: TX_TYPE.MINER,
        vin: [],
        vout: []
      }
    };
    const result = prevalidateMinerTransaction(minerTx, 100, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('exactly 1 input');
  });

  test('miner tx with wrong height fails', () => {
    const minerTx = {
      prefix: {
        version: 4,
        txType: TX_TYPE.MINER,
        vin: [{ height: 50 }],  // Wrong height
        vout: []
      }
    };
    const result = prevalidateMinerTransaction(minerTx, 100, HF_VERSION.CARROT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('height');
  });

});


// =============================================================================
// YIELD CALCULATION TESTS
// =============================================================================

describe('Yield Calculation', () => {

  test('calculateYieldPayout returns 0 for empty blocks', () => {
    const yieldAmount = calculateYieldPayout(1000000000n, []);
    expect(yieldAmount).toBe(0n);
  });

  test('calculateYieldPayout calculates proportional yield', () => {
    const yieldBlocks = [
      { slippageTotal: 1000000n, lockedCoinsTally: 10000000000n },
      { slippageTotal: 2000000n, lockedCoinsTally: 10000000000n }
    ];
    const stakedAmount = 5000000000n;  // 50% of total
    const yieldAmount = calculateYieldPayout(stakedAmount, yieldBlocks);

    // Expected: (1M * 5B / 10B) + (2M * 5B / 10B) = 0.5M + 1M = 1.5M
    expect(yieldAmount).toBe(1500000n);
  });

  test('getStakeLockPeriod returns correct period for mainnet', () => {
    const period = getStakeLockPeriod('mainnet');
    expect(period).toBeGreaterThan(1000);  // Should be significant
  });

  test('getStakeLockPeriod returns shorter period for testnet', () => {
    const testnetPeriod = getStakeLockPeriod('testnet');
    const mainnetPeriod = getStakeLockPeriod('mainnet');
    expect(testnetPeriod).toBeLessThan(mainnetPeriod);
  });

});


// =============================================================================
// COMPREHENSIVE VALIDATION TESTS
// =============================================================================

describe('Comprehensive Transaction Validation', () => {

  test('valid transaction passes all checks', () => {
    const tx = createMockTransaction({
      txType: TX_TYPE.TRANSFER,
      source_asset_type: 'SAL1',
      destination_asset_type: 'SAL1',
      version: 4,
      vin: [{
        type: 'key',
        k_image: '0'.repeat(64),
        key_offsets: new Array(16).fill(1)
      }],
      vout: [{ amount: 0, target: { type: TXOUT_TYPE.to_carrot_v1, key: 'a'.repeat(64) } }],
      rct: { type: RCT_TYPE_NAMES.SalviumOne }
    });

    const result = validateTransactionFull(tx, { hfVersion: HF_VERSION.CARROT });
    expect(result.valid).toBe(true);
    expect(result.errors.length).toBe(0);
  });

  test('invalid transaction collects all errors', () => {
    const tx = {
      prefix: {
        version: 2,
        txType: 0,  // Invalid
        source_asset_type: 'INVALID',
        destination_asset_type: 'BURN',
        vin: [],  // Invalid - no inputs
        vout: []
      },
      rct: { type: RCT_TYPE_NAMES.BulletproofPlus }  // Wrong type
    };

    const result = validateTransactionFull(tx, { hfVersion: HF_VERSION.CARROT });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

});


console.log('\n=== Validation Module Tests ===\n');
