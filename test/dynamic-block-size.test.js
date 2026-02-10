/**
 * Dynamic Block Size Scaling Tests
 *
 * Tests the long-term/short-term block weight median system
 * that governs Salvium's dynamic block size limits.
 *
 * Reference: Salvium blockchain.cpp:5518-5608
 */

import { describe, test, expect } from 'bun:test';
import {
  getNextLongTermBlockWeight,
  getEffectiveMedianBlockWeight,
  getMedianBlockWeight,
  ChainState,
  CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
  CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR
} from '../src/consensus.js';

const FRZ = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5; // 300000

describe('getNextLongTermBlockWeight', () => {
  test('weight at median stays unchanged', () => {
    expect(getNextLongTermBlockWeight(FRZ, FRZ)).toBe(FRZ);
  });

  test('weight within ±70% stays unchanged', () => {
    const median = 500000;
    // 500000 * 10/17 = 294117, 500000 * 17/10 = 850000
    expect(getNextLongTermBlockWeight(400000, median)).toBe(400000);
    expect(getNextLongTermBlockWeight(700000, median)).toBe(700000);
  });

  test('weight below lower bound gets clamped up', () => {
    const median = 500000;
    const lowerBound = Math.floor(median * 10 / 17); // 294117
    expect(getNextLongTermBlockWeight(100000, median)).toBe(lowerBound);
  });

  test('weight above upper bound gets clamped down', () => {
    const median = 500000;
    const upperBound = median + Math.floor(median * 7 / 10); // 850000
    expect(getNextLongTermBlockWeight(1000000, median)).toBe(upperBound);
  });

  test('uses full reward zone as minimum median', () => {
    // Even if longTermMedian is 0, effectiveMedian = max(FRZ, 0) = FRZ
    const result = getNextLongTermBlockWeight(FRZ, 0);
    expect(result).toBe(FRZ);
  });

  test('small block gets clamped to lower bound', () => {
    const result = getNextLongTermBlockWeight(1000, FRZ);
    const lowerBound = Math.floor(FRZ * 10 / 17);
    expect(result).toBe(lowerBound);
  });
});

describe('getEffectiveMedianBlockWeight', () => {
  test('empty weights use full reward zone', () => {
    const result = getEffectiveMedianBlockWeight([], [], 2);
    expect(result.longTermEffectiveMedian).toBe(FRZ);
    expect(result.effectiveMedian).toBe(FRZ);
    expect(result.blockLimit).toBe(FRZ * 2);
  });

  test('all weights at FRZ gives standard limit', () => {
    const weights = Array(100).fill(FRZ);
    const result = getEffectiveMedianBlockWeight(weights, weights, 2);
    expect(result.effectiveMedian).toBe(FRZ);
    expect(result.blockLimit).toBe(FRZ * 2);
  });

  test('large short-term weights increase effective median', () => {
    const longTerm = Array(100).fill(FRZ);
    const shortTerm = Array(100).fill(FRZ * 2);
    const result = getEffectiveMedianBlockWeight(longTerm, shortTerm, 2);
    // Short-term median (600000) > long-term effective (300000)
    // But clamped to 50 * longTermEffective = 15000000
    expect(result.effectiveMedian).toBe(FRZ * 2);
    expect(result.blockLimit).toBe(FRZ * 4);
  });

  test('surge factor caps at 50x', () => {
    const longTerm = Array(100).fill(FRZ);
    const shortTerm = Array(100).fill(FRZ * 100); // Way above surge limit
    const result = getEffectiveMedianBlockWeight(longTerm, shortTerm, 2);
    // Capped at 50 * FRZ
    expect(result.effectiveMedian).toBe(
      CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * FRZ
    );
  });

  test('short-term below long-term uses long-term', () => {
    const longTerm = Array(100).fill(FRZ * 2);
    const shortTerm = Array(100).fill(FRZ);
    const result = getEffectiveMedianBlockWeight(longTerm, shortTerm, 2);
    // Long-term median = 600000 > short-term 300000
    expect(result.effectiveMedian).toBe(FRZ * 2);
  });

  test('full reward zone acts as floor', () => {
    const longTerm = Array(100).fill(1000); // Way below FRZ
    const shortTerm = Array(100).fill(1000);
    const result = getEffectiveMedianBlockWeight(longTerm, shortTerm, 2);
    expect(result.longTermEffectiveMedian).toBe(FRZ);
    expect(result.effectiveMedian).toBe(FRZ);
  });
});

describe('ChainState dynamic block size integration', () => {
  test('growing blocks increase block limit', () => {
    const cs = new ChainState();
    // Add 150 blocks with increasing weights
    for (let i = 0; i < 150; i++) {
      cs.addBlock(1000 + i * 120, 100n, FRZ + i * 1000);
    }
    const { blockLimit } = cs.getBlockWeightLimit(2);
    // With growing weights, limit should be above minimum
    expect(blockLimit).toBeGreaterThanOrEqual(FRZ * 2);
  });

  test('consistent blocks give stable limit', () => {
    const cs = new ChainState();
    for (let i = 0; i < 200; i++) {
      cs.addBlock(1000 + i * 120, 100n, FRZ);
    }
    const { blockLimit, effectiveMedian } = cs.getBlockWeightLimit(2);
    expect(effectiveMedian).toBe(FRZ);
    expect(blockLimit).toBe(FRZ * 2);
  });

  test('spike in block weight is limited by surge factor', () => {
    const cs = new ChainState();
    // 100 normal blocks
    for (let i = 0; i < 100; i++) {
      cs.addBlock(1000 + i * 120, 100n, FRZ);
    }
    // 50 huge blocks
    for (let i = 0; i < 50; i++) {
      cs.addBlock(13000 + i * 120, 100n, FRZ * 200);
    }
    const { effectiveMedian } = cs.getBlockWeightLimit(2);
    // Should be capped by surge factor (50x long-term effective median)
    expect(effectiveMedian).toBeLessThanOrEqual(
      CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * FRZ * 2
    );
  });
});

describe('getMedianBlockWeight edge cases', () => {
  test('two elements (upper median)', () => {
    expect(getMedianBlockWeight([10, 20])).toBe(20);
  });

  test('large spread (upper median)', () => {
    expect(getMedianBlockWeight([1, 1000000])).toBe(1000000);
  });

  test('duplicate values', () => {
    expect(getMedianBlockWeight([5, 5, 5, 5, 5])).toBe(5);
  });
});
