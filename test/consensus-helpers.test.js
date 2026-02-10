/**
 * Consensus Helpers Tests
 *
 * Tests for chain state management, cumulative difficulty tracking,
 * and median block weight calculation.
 */

import { describe, test, expect } from 'bun:test';
import {
  buildCumulativeDifficulties,
  getMedianBlockWeight,
  ChainState,
  nextDifficultyV2,
  DIFFICULTY_TARGET_V2,
  DIFFICULTY_WINDOW_V2,
  CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5
} from '../src/consensus.js';

describe('buildCumulativeDifficulties', () => {
  test('empty array returns empty', () => {
    expect(buildCumulativeDifficulties([])).toEqual([]);
  });

  test('single element', () => {
    expect(buildCumulativeDifficulties([100n])).toEqual([100n]);
  });

  test('multiple elements accumulate', () => {
    const result = buildCumulativeDifficulties([10n, 20n, 30n]);
    expect(result).toEqual([10n, 30n, 60n]);
  });

  test('handles large values (BigInt)', () => {
    const large = 1000000000000n;
    const result = buildCumulativeDifficulties([large, large, large]);
    expect(result[2]).toBe(3000000000000n);
  });

  test('accepts number inputs', () => {
    const result = buildCumulativeDifficulties([10, 20, 30]);
    expect(result).toEqual([10n, 30n, 60n]);
  });
});

describe('getMedianBlockWeight', () => {
  test('empty array returns 0', () => {
    expect(getMedianBlockWeight([])).toBe(0);
  });

  test('single element returns that element', () => {
    expect(getMedianBlockWeight([42])).toBe(42);
  });

  test('odd-length array returns middle', () => {
    expect(getMedianBlockWeight([1, 3, 5])).toBe(3);
  });

  test('even-length array returns upper median', () => {
    expect(getMedianBlockWeight([1, 3, 5, 7])).toBe(5);
  });

  test('unsorted input is handled', () => {
    expect(getMedianBlockWeight([5, 1, 3])).toBe(3);
  });

  test('does not mutate input', () => {
    const input = [5, 1, 3];
    getMedianBlockWeight(input);
    expect(input).toEqual([5, 1, 3]);
  });

  test('large dataset', () => {
    const values = Array.from({ length: 1000 }, (_, i) => i + 1);
    expect(getMedianBlockWeight(values)).toBe(501);
  });

  test('all same values', () => {
    expect(getMedianBlockWeight([300000, 300000, 300000])).toBe(300000);
  });
});

describe('ChainState', () => {
  test('starts at height 0', () => {
    const cs = new ChainState();
    expect(cs.height).toBe(0);
    expect(cs.getCumulativeDifficulty()).toBe(0n);
  });

  test('addBlock increments height', () => {
    const cs = new ChainState();
    cs.addBlock(1000, 100n, 300000);
    expect(cs.height).toBe(1);
    cs.addBlock(1120, 100n, 300000);
    expect(cs.height).toBe(2);
  });

  test('tracks cumulative difficulty', () => {
    const cs = new ChainState();
    cs.addBlock(1000, 100n, 300000);
    expect(cs.getCumulativeDifficulty()).toBe(100n);
    cs.addBlock(1120, 200n, 300000);
    expect(cs.getCumulativeDifficulty()).toBe(300n);
    cs.addBlock(1240, 150n, 300000);
    expect(cs.getCumulativeDifficulty()).toBe(450n);
  });

  test('getDifficultyWindow returns correct window for LWMA', () => {
    const cs = new ChainState();
    // Add 100 blocks
    for (let i = 0; i < 100; i++) {
      cs.addBlock(1000 + i * 120, 100n, 300000);
    }
    const { timestamps, cumulativeDifficulties } = cs.getDifficultyWindow(2);
    // LWMA window is DIFFICULTY_WINDOW_V2 + 1 = 71
    expect(timestamps.length).toBe(DIFFICULTY_WINDOW_V2 + 1);
    expect(cumulativeDifficulties.length).toBe(DIFFICULTY_WINDOW_V2 + 1);
  });

  test('getDifficultyWindow returns all data when chain is short', () => {
    const cs = new ChainState();
    for (let i = 0; i < 10; i++) {
      cs.addBlock(1000 + i * 120, 100n, 300000);
    }
    const { timestamps } = cs.getDifficultyWindow(2);
    expect(timestamps.length).toBe(10);
  });

  test('getNextDifficulty returns 1 for short chains', () => {
    const cs = new ChainState();
    for (let i = 0; i < 3; i++) {
      cs.addBlock(1000 + i * 120, 100n, 300000);
    }
    expect(cs.getNextDifficulty(2)).toBe(1n);
  });

  test('getNextDifficulty produces reasonable result for stable chain', () => {
    const cs = new ChainState();
    const baseDiff = 1000n;
    // Add blocks with target time (120s) and constant difficulty
    for (let i = 0; i < 80; i++) {
      cs.addBlock(1000 + i * 120, baseDiff, 300000);
    }
    const diff = cs.getNextDifficulty(2);
    // With perfect 120s blocks, difficulty should stay near baseDiff
    expect(diff).toBeGreaterThan(500n);
    expect(diff).toBeLessThan(2000n);
  });

  test('getNextDifficulty increases when blocks are fast', () => {
    const cs = new ChainState();
    const baseDiff = 1000n;
    // Blocks coming every 60s (half the target)
    for (let i = 0; i < 80; i++) {
      cs.addBlock(1000 + i * 60, baseDiff, 300000);
    }
    const diff = cs.getNextDifficulty(2);
    // Difficulty should increase above baseDiff
    expect(diff).toBeGreaterThan(baseDiff);
  });

  test('getNextDifficulty decreases when blocks are slow', () => {
    const cs = new ChainState();
    const baseDiff = 1000n;
    // Blocks coming every 240s (double the target)
    for (let i = 0; i < 80; i++) {
      cs.addBlock(1000 + i * 240, baseDiff, 300000);
    }
    const diff = cs.getNextDifficulty(2);
    // Difficulty should decrease below baseDiff
    expect(diff).toBeLessThan(baseDiff);
  });

  test('getShortTermWeights returns last 100', () => {
    const cs = new ChainState();
    for (let i = 0; i < 150; i++) {
      cs.addBlock(1000 + i * 120, 100n, 300000 + i);
    }
    const weights = cs.getShortTermWeights();
    expect(weights.length).toBe(100);
    expect(weights[0]).toBe(300050); // starts at index 50
  });

  test('getShortTermWeights returns all when chain is short', () => {
    const cs = new ChainState();
    for (let i = 0; i < 10; i++) {
      cs.addBlock(1000 + i * 120, 100n, 300000);
    }
    expect(cs.getShortTermWeights().length).toBe(10);
  });

  test('getBlockWeightLimit returns valid limit', () => {
    const cs = new ChainState();
    for (let i = 0; i < 10; i++) {
      cs.addBlock(1000 + i * 120, 100n, 300000);
    }
    const { blockLimit, effectiveMedian } = cs.getBlockWeightLimit(2);
    // With all weights at full_reward_zone, limit should be 2x that
    expect(blockLimit).toBe(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 * 2);
    expect(effectiveMedian).toBe(CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5);
  });
});

describe('Integration: ChainState with nextDifficultyV2', () => {
  test('directly calling nextDifficultyV2 matches ChainState.getNextDifficulty', () => {
    const cs = new ChainState();
    for (let i = 0; i < 80; i++) {
      cs.addBlock(1000 + i * 120, 1000n, 300000);
    }

    const { timestamps, cumulativeDifficulties } = cs.getDifficultyWindow(2);
    const directResult = nextDifficultyV2(timestamps, cumulativeDifficulties);
    const stateResult = cs.getNextDifficulty(2);

    expect(stateResult).toBe(directResult);
  });
});
