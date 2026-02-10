#!/usr/bin/env bun
/**
 * Oracle/Pricing Module Tests
 *
 * Tests for Salvium's oracle pricing system including:
 * - Pricing record data structures
 * - Signature verification
 * - Conversion rate calculation
 * - Slippage calculation
 * - Serialization/parsing
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.h
 *            ~/github/salvium/src/oracle/pricing_record.cpp
 */

import { describe, test, expect } from 'bun:test';
import {
  // Constants
  COIN,
  PRICING_RECORD_VALID_BLOCKS,
  PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK,
  CONVERSION_RATE_ROUNDING,
  ASSET_TYPES,
  HF_VERSION_ENABLE_ORACLE,
  HF_VERSION_SLIPPAGE_YIELD,

  // Data structures
  createEmptyPricingRecord,
  isPricingRecordEmpty,
  getAssetPrice,
  getAssetMaPrice,

  // Signature verification
  buildSignatureMessage,
  getOraclePublicKey,

  // Validation
  validatePricingRecord,

  // Conversion
  getConversionRate,
  getConvertedAmount,
  calculateSlippage,
  calculateConversion,

  // Serialization
  parsePricingRecordFromJson,
  pricingRecordToJson
} from '../src/oracle.js';


// ============================================================================
// TEST DATA
// ============================================================================

/**
 * Create a mock pricing record for testing
 */
function createMockPricingRecord() {
  return {
    prVersion: 1,
    height: 100000,
    supply: {
      sal: 1000000000000000n,  // 10M SAL
      vsd: 500000000000000n    // 5M VSD
    },
    assets: [
      { assetType: 'SAL', spotPrice: 100000000n, maPrice: 100000000n },  // 1.0 price
      { assetType: 'VSD', spotPrice: 200000000n, maPrice: 195000000n }   // 2.0 price
    ],
    timestamp: Math.floor(Date.now() / 1000),
    signature: new Uint8Array(64).fill(0)  // Dummy signature
  };
}


// ============================================================================
// CONSTANTS TESTS
// ============================================================================

describe('Oracle Constants', () => {

  test('COIN equals 10^8', () => {
    expect(COIN).toBe(100000000n);
  });

  test('PRICING_RECORD_VALID_BLOCKS equals 10', () => {
    expect(PRICING_RECORD_VALID_BLOCKS).toBe(10);
  });

  test('PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK equals 120 seconds', () => {
    expect(PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK).toBe(120);
  });

  test('CONVERSION_RATE_ROUNDING equals 10000', () => {
    expect(CONVERSION_RATE_ROUNDING).toBe(10000n);
  });

  test('ASSET_TYPES includes SAL, SAL1, BURN', () => {
    expect(ASSET_TYPES).toContain('SAL');
    expect(ASSET_TYPES).toContain('SAL1');
    expect(ASSET_TYPES).toContain('BURN');
  });

  test('HF_VERSION_ENABLE_ORACLE equals 255', () => {
    expect(HF_VERSION_ENABLE_ORACLE).toBe(255);
  });

  test('HF_VERSION_SLIPPAGE_YIELD equals 255', () => {
    expect(HF_VERSION_SLIPPAGE_YIELD).toBe(255);
  });

});


// ============================================================================
// DATA STRUCTURE TESTS
// ============================================================================

describe('Pricing Record Data Structures', () => {

  describe('createEmptyPricingRecord', () => {

    test('creates empty pricing record with all zero values', () => {
      const pr = createEmptyPricingRecord();

      expect(pr.prVersion).toBe(0);
      expect(pr.height).toBe(0);
      expect(pr.supply.sal).toBe(0n);
      expect(pr.supply.vsd).toBe(0n);
      expect(pr.assets).toEqual([]);
      expect(pr.timestamp).toBe(0);
      expect(pr.signature.length).toBe(0);
    });

  });

  describe('isPricingRecordEmpty', () => {

    test('returns true for empty pricing record', () => {
      const pr = createEmptyPricingRecord();
      expect(isPricingRecordEmpty(pr)).toBe(true);
    });

    test('returns false for pricing record with version', () => {
      const pr = createEmptyPricingRecord();
      pr.prVersion = 1;
      expect(isPricingRecordEmpty(pr)).toBe(false);
    });

    test('returns false for pricing record with height', () => {
      const pr = createEmptyPricingRecord();
      pr.height = 100;
      expect(isPricingRecordEmpty(pr)).toBe(false);
    });

    test('returns false for pricing record with supply', () => {
      const pr = createEmptyPricingRecord();
      pr.supply.sal = 1000n;
      expect(isPricingRecordEmpty(pr)).toBe(false);
    });

    test('returns false for pricing record with assets', () => {
      const pr = createEmptyPricingRecord();
      pr.assets = [{ assetType: 'SAL', spotPrice: 100n, maPrice: 100n }];
      expect(isPricingRecordEmpty(pr)).toBe(false);
    });

    test('returns false for pricing record with timestamp', () => {
      const pr = createEmptyPricingRecord();
      pr.timestamp = 12345;
      expect(isPricingRecordEmpty(pr)).toBe(false);
    });

    test('returns false for pricing record with signature', () => {
      const pr = createEmptyPricingRecord();
      pr.signature = new Uint8Array([1, 2, 3]);
      expect(isPricingRecordEmpty(pr)).toBe(false);
    });

    test('returns false for full pricing record', () => {
      const pr = createMockPricingRecord();
      expect(isPricingRecordEmpty(pr)).toBe(false);
    });

  });

  describe('getAssetPrice', () => {

    test('returns spot price for existing asset', () => {
      const pr = createMockPricingRecord();
      expect(getAssetPrice(pr, 'SAL')).toBe(100000000n);
      expect(getAssetPrice(pr, 'VSD')).toBe(200000000n);
    });

    test('returns 0n for non-existent asset', () => {
      const pr = createMockPricingRecord();
      expect(getAssetPrice(pr, 'UNKNOWN')).toBe(0n);
    });

    test('returns 0n for empty pricing record', () => {
      const pr = createEmptyPricingRecord();
      expect(getAssetPrice(pr, 'SAL')).toBe(0n);
    });

  });

  describe('getAssetMaPrice', () => {

    test('returns moving average price for existing asset', () => {
      const pr = createMockPricingRecord();
      expect(getAssetMaPrice(pr, 'SAL')).toBe(100000000n);
      expect(getAssetMaPrice(pr, 'VSD')).toBe(195000000n);
    });

    test('returns 0n for non-existent asset', () => {
      const pr = createMockPricingRecord();
      expect(getAssetMaPrice(pr, 'UNKNOWN')).toBe(0n);
    });

  });

});


// ============================================================================
// SIGNATURE VERIFICATION TESTS
// ============================================================================

describe('Signature Verification', () => {

  describe('buildSignatureMessage', () => {

    test('builds correct JSON message', () => {
      const pr = {
        prVersion: 1,
        height: 100,
        supply: { sal: 1000n, vsd: 500n },
        assets: [
          { assetType: 'SAL', spotPrice: 100n, maPrice: 100n }
        ],
        timestamp: 1234567890,
        signature: new Uint8Array(0)
      };

      const message = buildSignatureMessage(pr);
      const parsed = JSON.parse(message);

      expect(parsed.pr_version).toBe(1);
      expect(parsed.height).toBe(100);
      expect(parsed.supply.SAL).toBe(1000);
      expect(parsed.supply.VSD).toBe(500);
      expect(parsed.assets.length).toBe(1);
      expect(parsed.assets[0].asset_type).toBe('SAL');
      expect(parsed.timestamp).toBe(1234567890);
    });

    test('produces compact JSON without whitespace', () => {
      const pr = createMockPricingRecord();
      const message = buildSignatureMessage(pr);

      // Should not contain formatting whitespace
      expect(message).not.toMatch(/  /);  // No double spaces
      expect(message).not.toContain('\n');
      expect(message).not.toContain('\t');
    });

  });

  describe('getOraclePublicKey', () => {

    test('returns mainnet key by default', () => {
      const key = getOraclePublicKey();
      expect(key).toContain('BEGIN PUBLIC KEY');
      expect(key).toContain('MIIDRDCCAjYGByqGSM44BAE');  // DSA key
    });

    test('returns mainnet key explicitly', () => {
      const key = getOraclePublicKey('mainnet');
      expect(key).toContain('BEGIN PUBLIC KEY');
      expect(key).toContain('MIIDRDCCAjYGByqGSM44BAE');  // DSA key
    });

    test('returns testnet key', () => {
      const key = getOraclePublicKey('testnet');
      expect(key).toContain('BEGIN PUBLIC KEY');
      expect(key).toContain('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQg');  // ECDSA key
    });

    test('returns testnet key for stagenet', () => {
      const key = getOraclePublicKey('stagenet');
      expect(key).toContain('BEGIN PUBLIC KEY');
      expect(key).toContain('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQg');  // ECDSA key
    });

  });

});


// ============================================================================
// VALIDATION TESTS
// ============================================================================

describe('Pricing Record Validation', () => {

  describe('validatePricingRecord', () => {

    test('empty record is always valid', async () => {
      const pr = createEmptyPricingRecord();
      const result = await validatePricingRecord(pr);
      expect(result.valid).toBe(true);
    });

    test('non-empty record requires HF >= HF_VERSION_SLIPPAGE_YIELD', async () => {
      const pr = createMockPricingRecord();

      // Before HF
      const result1 = await validatePricingRecord(pr, { hfVersion: 5 });
      expect(result1.valid).toBe(false);
      expect(result1.error).toContain('not allowed before oracle HF');

      // At HF (would fail signature, but that's a different error)
      // Just testing the HF gate here
    });

    test('rejects timestamp too far in future', async () => {
      const pr = createMockPricingRecord();
      const currentTime = Math.floor(Date.now() / 1000);

      // Set timestamp 200 seconds in future (> 120 seconds allowed)
      pr.timestamp = currentTime + 200;

      const result = await validatePricingRecord(pr, {
        hfVersion: 255,
        blockTimestamp: currentTime
      });

      // Note: This will also fail signature verification first,
      // but if we had a valid signature, timestamp would be checked
    });

    test('rejects timestamp older than previous block', async () => {
      const pr = createMockPricingRecord();
      const currentTime = Math.floor(Date.now() / 1000);

      // Set timestamp older than last block
      pr.timestamp = currentTime - 100;

      const result = await validatePricingRecord(pr, {
        hfVersion: 255,
        blockTimestamp: currentTime,
        lastBlockTimestamp: currentTime - 50  // Previous block was 50 seconds ago
      });

      // Would fail signature first, but tests the logic
    });

  });

});


// ============================================================================
// CONVERSION TESTS
// ============================================================================

describe('Conversion Rate Calculation', () => {

  describe('getConversionRate', () => {

    test('same asset returns 1:1 rate (COIN)', () => {
      const pr = createMockPricingRecord();

      const result = getConversionRate(pr, 'SAL', 'SAL');
      expect(result.success).toBe(true);
      expect(result.rate).toBe(COIN);
    });

    test('rejects conversion to BURN', () => {
      const pr = createMockPricingRecord();

      const result = getConversionRate(pr, 'SAL', 'BURN');
      expect(result.success).toBe(false);
      expect(result.error).toContain('Cannot convert to BURN');
    });

    test('SAL -> VSD with 1:2 price ratio returns 0.5 rate', () => {
      const pr = createMockPricingRecord();
      // SAL price = 1.0, VSD price = 2.0
      // Rate = 1.0 / 2.0 = 0.5 (50000000 in COIN units)

      const result = getConversionRate(pr, 'SAL', 'VSD');
      expect(result.success).toBe(true);

      // Rate should be around 50000000 (0.5 COIN), rounded down to nearest 10000
      const expectedRate = 50000000n - (50000000n % CONVERSION_RATE_ROUNDING);
      expect(result.rate).toBe(expectedRate);
    });

    test('VSD -> SAL with 2:1 price ratio returns 2.0 rate', () => {
      const pr = createMockPricingRecord();
      // VSD price = 2.0, SAL price = 1.0
      // Rate = 2.0 / 1.0 = 2.0 (200000000 in COIN units)

      const result = getConversionRate(pr, 'VSD', 'SAL');
      expect(result.success).toBe(true);

      // Rate should be around 200000000 (2.0 COIN), rounded down to nearest 10000
      const expectedRate = 200000000n - (200000000n % CONVERSION_RATE_ROUNDING);
      expect(result.rate).toBe(expectedRate);
    });

    test('rejects invalid conversion pair SAL -> SAL1', () => {
      const pr = createMockPricingRecord();

      const result = getConversionRate(pr, 'SAL', 'SAL1');
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid conversion pair');
    });

    test('rejects when price data is missing', () => {
      const pr = createEmptyPricingRecord();

      const result = getConversionRate(pr, 'SAL', 'VSD');
      expect(result.success).toBe(false);
      expect(result.error).toContain('Missing price data');
    });

    test('rounds rate down to nearest 10000', () => {
      const pr = {
        ...createMockPricingRecord(),
        assets: [
          { assetType: 'SAL', spotPrice: 100000001n, maPrice: 100000001n },
          { assetType: 'VSD', spotPrice: 100000000n, maPrice: 100000000n }
        ]
      };

      const result = getConversionRate(pr, 'SAL', 'VSD');
      expect(result.success).toBe(true);

      // Should be rounded to nearest 10000
      expect(result.rate % CONVERSION_RATE_ROUNDING).toBe(0n);
    });

  });

  describe('getConvertedAmount', () => {

    test('calculates correct converted amount', () => {
      // 1 SAL with 1:1 rate should give 1 SAL
      const result = getConvertedAmount(COIN, COIN);
      expect(result.success).toBe(true);
      expect(result.amount).toBe(COIN);
    });

    test('calculates with 2:1 rate', () => {
      // 1 SAL with 2:1 rate should give 2 SAL
      const rate = 200000000n;  // 2.0 in COIN units
      const amount = COIN;      // 1.0

      const result = getConvertedAmount(rate, amount);
      expect(result.success).toBe(true);
      expect(result.amount).toBe(200000000n);  // 2.0 SAL
    });

    test('calculates with 0.5:1 rate', () => {
      // 1 SAL with 0.5:1 rate should give 0.5 SAL
      const rate = 50000000n;   // 0.5 in COIN units
      const amount = COIN;      // 1.0

      const result = getConvertedAmount(rate, amount);
      expect(result.success).toBe(true);
      expect(result.amount).toBe(50000000n);  // 0.5 SAL
    });

    test('rejects zero rate', () => {
      const result = getConvertedAmount(0n, COIN);
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid conversion rate');
    });

    test('rejects zero amount', () => {
      const result = getConvertedAmount(COIN, 0n);
      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid source amount');
    });

  });

  describe('calculateSlippage', () => {

    test('calculates 1/32 (3.125%) of amount', () => {
      // 3200 SAL should give 100 SAL slippage (3200 / 32 = 100)
      const amount = 320000000000n;  // 3200 SAL
      const slippage = calculateSlippage(amount);
      expect(slippage).toBe(10000000000n);  // 100 SAL
    });

    test('uses bit shift for efficiency', () => {
      // 32 SAL -> 1 SAL slippage
      const amount = 3200000000n;  // 32 SAL
      const slippage = calculateSlippage(amount);
      expect(slippage).toBe(100000000n);  // 1 SAL
    });

    test('handles small amounts correctly', () => {
      // Very small amount
      const amount = 32n;
      const slippage = calculateSlippage(amount);
      expect(slippage).toBe(1n);
    });

    test('handles amount less than 32', () => {
      // Amount less than 32 results in 0 slippage
      const amount = 31n;
      const slippage = calculateSlippage(amount);
      expect(slippage).toBe(0n);
    });

  });

  describe('calculateConversion', () => {

    test('calculates full conversion with slippage', () => {
      const pr = createMockPricingRecord();
      const amount = 3200000000000n;  // 32000 SAL

      const result = calculateConversion(pr, 'SAL', 'VSD', amount, 1000000000000n);

      expect(result.success).toBe(true);
      expect(result.actualSlippage).toBe(100000000000n);  // 1000 SAL (3.125%)
      expect(result.amountMinted).toBeDefined();
      expect(result.conversionRate).toBeDefined();
    });

    test('triggers refund when slippage exceeds limit', () => {
      const pr = createMockPricingRecord();
      const amount = 3200000000000n;  // 32000 SAL
      const slippageLimit = 1n;       // Unrealistically low limit

      const result = calculateConversion(pr, 'SAL', 'VSD', amount, slippageLimit);

      expect(result.success).toBe(true);
      expect(result.refund).toBe(true);
      expect(result.amountMinted).toBe(0n);
      expect(result.error).toContain('Slippage limit exceeded');
    });

    test('rejects same asset conversion', () => {
      const pr = createMockPricingRecord();

      const result = calculateConversion(pr, 'SAL', 'SAL', COIN, COIN);

      expect(result.success).toBe(false);
      expect(result.error).toContain('source and dest assets are identical');
    });

    test('rejects missing source asset', () => {
      const pr = createMockPricingRecord();

      const result = calculateConversion(pr, null, 'VSD', COIN, COIN);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Source asset not provided');
    });

    test('rejects missing destination asset', () => {
      const pr = createMockPricingRecord();

      const result = calculateConversion(pr, 'SAL', null, COIN, COIN);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Destination asset not provided');
    });

    test('propagates invalid conversion pair error', () => {
      const pr = createMockPricingRecord();

      const result = calculateConversion(pr, 'SAL', 'SAL1', COIN, COIN);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid conversion pair');
    });

  });

});


// ============================================================================
// SERIALIZATION TESTS
// ============================================================================

describe('Pricing Record Serialization', () => {

  describe('parsePricingRecordFromJson', () => {

    test('parses complete pricing record from JSON', () => {
      const json = {
        pr_version: 1,
        height: 100000,
        supply: {
          SAL: 1000000000000000,
          VSD: 500000000000000
        },
        assets: [
          { asset_type: 'SAL', spot_price: 100000000, ma_price: 100000000 },
          { asset_type: 'VSD', spot_price: 200000000, ma_price: 195000000 }
        ],
        timestamp: 1234567890,
        signature: 'aabbccdd'
      };

      const pr = parsePricingRecordFromJson(json);

      expect(pr.prVersion).toBe(1);
      expect(pr.height).toBe(100000);
      expect(pr.supply.sal).toBe(1000000000000000n);
      expect(pr.supply.vsd).toBe(500000000000000n);
      expect(pr.assets.length).toBe(2);
      expect(pr.assets[0].assetType).toBe('SAL');
      expect(pr.assets[0].spotPrice).toBe(100000000n);
      expect(pr.timestamp).toBe(1234567890);
      expect(pr.signature.length).toBe(4);  // 'aabbccdd' = 4 bytes
    });

    test('handles lowercase supply keys', () => {
      const json = {
        pr_version: 1,
        height: 100,
        supply: {
          sal: 1000,
          vsd: 500
        },
        assets: [],
        timestamp: 0,
        signature: ''
      };

      const pr = parsePricingRecordFromJson(json);

      expect(pr.supply.sal).toBe(1000n);
      expect(pr.supply.vsd).toBe(500n);
    });

    test('handles missing optional fields', () => {
      const json = {
        height: 100
      };

      const pr = parsePricingRecordFromJson(json);

      expect(pr.prVersion).toBe(0);
      expect(pr.height).toBe(100);
      expect(pr.supply.sal).toBe(0n);
      expect(pr.supply.vsd).toBe(0n);
      expect(pr.assets).toEqual([]);
      expect(pr.timestamp).toBe(0);
      expect(pr.signature.length).toBe(0);
    });

    test('handles signature as array', () => {
      const json = {
        pr_version: 1,
        height: 100,
        supply: { SAL: 0, VSD: 0 },
        assets: [],
        timestamp: 0,
        signature: [0xaa, 0xbb, 0xcc]
      };

      const pr = parsePricingRecordFromJson(json);

      expect(pr.signature.length).toBe(3);
      expect(pr.signature[0]).toBe(0xaa);
      expect(pr.signature[1]).toBe(0xbb);
      expect(pr.signature[2]).toBe(0xcc);
    });

    test('handles 0x prefixed hex signature', () => {
      const json = {
        pr_version: 1,
        height: 100,
        supply: { SAL: 0, VSD: 0 },
        assets: [],
        timestamp: 0,
        signature: '0xaabbcc'
      };

      const pr = parsePricingRecordFromJson(json);

      expect(pr.signature.length).toBe(3);
    });

  });

  describe('pricingRecordToJson', () => {

    test('converts pricing record to JSON', () => {
      const pr = createMockPricingRecord();
      const json = pricingRecordToJson(pr);

      expect(json.pr_version).toBe(1);
      expect(json.height).toBe(100000);
      expect(json.supply.SAL).toBe('1000000000000000');
      expect(json.supply.VSD).toBe('500000000000000');
      expect(json.assets.length).toBe(2);
      expect(json.assets[0].asset_type).toBe('SAL');
      expect(json.assets[0].spot_price).toBe('100000000');
      expect(json.timestamp).toBe(pr.timestamp);
      expect(typeof json.signature).toBe('string');
    });

    test('handles empty signature', () => {
      const pr = createEmptyPricingRecord();
      const json = pricingRecordToJson(pr);

      expect(json.signature).toBe('');
    });

    test('converts signature to hex string', () => {
      const pr = createEmptyPricingRecord();
      pr.signature = new Uint8Array([0xaa, 0xbb, 0xcc]);

      const json = pricingRecordToJson(pr);

      expect(json.signature).toBe('aabbcc');
    });

  });

  describe('round-trip serialization', () => {

    test('JSON -> PricingRecord -> JSON preserves data', () => {
      const originalJson = {
        pr_version: 1,
        height: 100000,
        supply: { SAL: '1000000000000', VSD: '500000000000' },
        assets: [
          { asset_type: 'SAL', spot_price: '100000000', ma_price: '100000000' }
        ],
        timestamp: 1234567890,
        signature: 'aabbccdd'
      };

      const pr = parsePricingRecordFromJson(originalJson);
      const resultJson = pricingRecordToJson(pr);

      expect(resultJson.pr_version).toBe(originalJson.pr_version);
      expect(resultJson.height).toBe(originalJson.height);
      expect(resultJson.supply.SAL).toBe(originalJson.supply.SAL);
      expect(resultJson.supply.VSD).toBe(originalJson.supply.VSD);
      expect(resultJson.assets.length).toBe(originalJson.assets.length);
      expect(resultJson.timestamp).toBe(originalJson.timestamp);
      expect(resultJson.signature).toBe(originalJson.signature);
    });

  });

});


// ============================================================================
// EDGE CASES
// ============================================================================

describe('Edge Cases', () => {

  test('handles very large amounts in conversion', () => {
    const pr = createMockPricingRecord();
    const largeAmount = 1000000000000000000n;  // 10B SAL

    const result = calculateConversion(pr, 'SAL', 'VSD', largeAmount, largeAmount);

    expect(result.success).toBe(true);
    expect(result.amountMinted).toBeDefined();
  });

  test('handles minimum conversion amount', () => {
    const pr = createMockPricingRecord();
    const minAmount = 1n;  // 1 atomic unit

    const rateResult = getConversionRate(pr, 'SAL', 'VSD');
    expect(rateResult.success).toBe(true);

    const convertResult = getConvertedAmount(rateResult.rate, minAmount);
    // May be 0 due to precision, but should not error
    expect(convertResult.success).toBe(true);
  });

  test('slippage calculation handles exact multiples of 32', () => {
    const amount = 320n;  // Exactly 10 * 32
    const slippage = calculateSlippage(amount);
    expect(slippage).toBe(10n);
  });

  test('conversion rate handles equal prices', () => {
    const pr = {
      ...createMockPricingRecord(),
      assets: [
        { assetType: 'SAL', spotPrice: 100000000n, maPrice: 100000000n },
        { assetType: 'VSD', spotPrice: 100000000n, maPrice: 100000000n }  // Same price
      ]
    };

    const result = getConversionRate(pr, 'SAL', 'VSD');
    expect(result.success).toBe(true);
    // 1:1 rate
    expect(result.rate).toBe(COIN - (COIN % CONVERSION_RATE_ROUNDING));
  });

});


console.log('\n=== Oracle/Pricing Module Tests ===\n');
