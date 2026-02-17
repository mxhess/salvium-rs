//! Chain state tracking with cumulative difficulties and block weights.
//!
//! Provides `ChainState` for maintaining rolling windows of timestamps,
//! difficulties, and block weights needed by consensus difficulty and
//! block-weight-limit algorithms.
//!
//! Reference: salvium/src/cryptonote_core/blockchain.cpp, consensus.js

use salvium_types::consensus::{
    BLOCK_GRANTED_FULL_REWARD_ZONE_V5, DIFFICULTY_TARGET_V2, DIFFICULTY_WINDOW_V2,
    SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR,
    next_difficulty_v2,
};

// =============================================================================
// Constants
// =============================================================================

/// Number of recent blocks used for the short-term block weight median.
const REWARD_BLOCKS_WINDOW: usize = 100;

// =============================================================================
// Free Functions
// =============================================================================

/// Build a cumulative-sum array from per-block difficulties.
///
/// Each entry `i` in the result equals the sum of `difficulties[0..=i]`.
///
/// ```
/// # use salvium_consensus::chain_state::build_cumulative_difficulties;
/// assert_eq!(build_cumulative_difficulties(&[10, 20, 30]), vec![10, 30, 60]);
/// assert!(build_cumulative_difficulties(&[]).is_empty());
/// ```
pub fn build_cumulative_difficulties(difficulties: &[u128]) -> Vec<u128> {
    let mut result = Vec::with_capacity(difficulties.len());
    let mut cumulative: u128 = 0;
    for &d in difficulties {
        cumulative += d;
        result.push(cumulative);
    }
    result
}

/// Compute the median of a slice of block weights.
///
/// Uses the CryptoNote convention: `sorted[len / 2]` (upper median for
/// even-length inputs). Returns `0` for an empty slice.
pub fn get_median_block_weight(weights: &[u64]) -> u64 {
    if weights.is_empty() {
        return 0;
    }
    let mut sorted = weights.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

// =============================================================================
// BlockInfo
// =============================================================================

/// Per-block metadata stored inside `ChainState`.
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub height: u64,
    pub timestamp: u64,
    pub difficulty: u128,
    pub cumulative_difficulty: u128,
    pub block_weight: u64,
}

// =============================================================================
// ChainState
// =============================================================================

/// Tracks the chain tip and rolling windows needed by difficulty and
/// block-weight-limit algorithms.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub blocks: Vec<BlockInfo>,
}

impl ChainState {
    /// Create an empty chain state (height 0).
    pub fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    /// Append a block, automatically computing cumulative difficulty and height.
    pub fn add_block(&mut self, timestamp: u64, difficulty: u128, block_weight: u64) {
        let prev_cum = self
            .blocks
            .last()
            .map_or(0u128, |b| b.cumulative_difficulty);
        let height = self.blocks.len() as u64;
        self.blocks.push(BlockInfo {
            height,
            timestamp,
            difficulty,
            cumulative_difficulty: prev_cum + difficulty,
            block_weight,
        });
    }

    /// Current height (number of blocks added).
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Cumulative difficulty at the tip (0 when chain is empty).
    pub fn get_cumulative_difficulty(&self) -> u128 {
        self.blocks
            .last()
            .map_or(0, |b| b.cumulative_difficulty)
    }

    // -------------------------------------------------------------------------
    // Difficulty
    // -------------------------------------------------------------------------

    /// Extract the timestamps and cumulative difficulties window suitable for
    /// the LWMA v2 difficulty algorithm.
    ///
    /// Returns the last `DIFFICULTY_WINDOW_V2 + 1` entries (or all entries if
    /// the chain is shorter).
    pub fn get_difficulty_window(&self) -> (Vec<u64>, Vec<u128>) {
        let window_size = DIFFICULTY_WINDOW_V2 + 1;
        let start = self.blocks.len().saturating_sub(window_size);
        let slice = &self.blocks[start..];
        let timestamps: Vec<u64> = slice.iter().map(|b| b.timestamp).collect();
        let cum_diffs: Vec<u128> = slice.iter().map(|b| b.cumulative_difficulty).collect();
        (timestamps, cum_diffs)
    }

    /// Compute the next difficulty using LWMA v2.
    ///
    /// Returns `1` when the chain has fewer than 6 blocks (matches
    /// `next_difficulty_v2` behaviour).
    pub fn get_next_difficulty(&self) -> u128 {
        let (timestamps, cum_diffs) = self.get_difficulty_window();
        next_difficulty_v2(&timestamps, &cum_diffs, DIFFICULTY_TARGET_V2)
    }

    // -------------------------------------------------------------------------
    // Block weight
    // -------------------------------------------------------------------------

    /// Return the most recent `REWARD_BLOCKS_WINDOW` block weights (or all
    /// weights when the chain is shorter).
    pub fn get_short_term_weights(&self) -> Vec<u64> {
        let start = self.blocks.len().saturating_sub(REWARD_BLOCKS_WINDOW);
        self.blocks[start..].iter().map(|b| b.block_weight).collect()
    }

    /// Compute the dynamic block weight limit.
    ///
    /// Returns `(effective_median, block_limit)` where
    /// `block_limit = 2 * effective_median`.
    ///
    /// The effective median is at least `BLOCK_GRANTED_FULL_REWARD_ZONE_V5`.
    pub fn get_block_weight_limit(&self) -> (u64, u64) {
        let short_term = self.get_short_term_weights();

        let short_term_median = if short_term.is_empty() {
            0
        } else {
            get_median_block_weight(&short_term)
        };

        // For a simplified model (without long-term weight tracking) we treat
        // the long-term effective median as BLOCK_GRANTED_FULL_REWARD_ZONE_V5
        // (matching the JS behaviour when the chain is young or long-term
        // weights are absent).
        let long_term_effective_median = BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

        let mut effective_median = long_term_effective_median.max(short_term_median);
        // Clamp to surge factor
        effective_median = effective_median
            .min(SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * long_term_effective_median);
        // Floor at full reward zone
        effective_median = effective_median.max(BLOCK_GRANTED_FULL_REWARD_ZONE_V5);

        let block_limit = effective_median * 2;
        (effective_median, block_limit)
    }

    // -------------------------------------------------------------------------
    // Rollback
    // -------------------------------------------------------------------------

    /// Truncate the chain to `target_height`, removing all blocks above it.
    ///
    /// # Panics
    ///
    /// Panics if `target_height` is greater than the current height.
    pub fn rollback_to_height(&mut self, target_height: u64) {
        assert!(
            target_height <= self.height(),
            "Invalid rollback target: {} (current height: {})",
            target_height,
            self.height()
        );
        self.blocks.truncate(target_height as usize);
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- build_cumulative_difficulties ---------------------------------------

    #[test]
    fn cumulative_empty() {
        assert!(build_cumulative_difficulties(&[]).is_empty());
    }

    #[test]
    fn cumulative_single() {
        assert_eq!(build_cumulative_difficulties(&[100]), vec![100]);
    }

    #[test]
    fn cumulative_multiple() {
        assert_eq!(
            build_cumulative_difficulties(&[10, 20, 30]),
            vec![10, 30, 60]
        );
    }

    #[test]
    fn cumulative_large_values() {
        let large: u128 = 1_000_000_000_000;
        let result = build_cumulative_difficulties(&[large, large, large]);
        assert_eq!(result, vec![large, 2 * large, 3 * large]);
    }

    // ---- get_median_block_weight ---------------------------------------------

    #[test]
    fn median_empty() {
        assert_eq!(get_median_block_weight(&[]), 0);
    }

    #[test]
    fn median_single() {
        assert_eq!(get_median_block_weight(&[42]), 42);
    }

    #[test]
    fn median_odd() {
        assert_eq!(get_median_block_weight(&[1, 3, 5]), 3);
    }

    #[test]
    fn median_even_upper() {
        // CryptoNote convention: sorted[len/2] which is 5 for [1,3,5,7]
        assert_eq!(get_median_block_weight(&[1, 3, 5, 7]), 5);
    }

    #[test]
    fn median_unsorted_input() {
        assert_eq!(get_median_block_weight(&[5, 1, 3]), 3);
    }

    #[test]
    fn median_does_not_mutate_input() {
        let input = vec![5u64, 1, 3];
        let _ = get_median_block_weight(&input);
        assert_eq!(input, vec![5, 1, 3]);
    }

    #[test]
    fn median_large_dataset() {
        let values: Vec<u64> = (1..=1000).collect();
        assert_eq!(get_median_block_weight(&values), 501);
    }

    #[test]
    fn median_all_same() {
        assert_eq!(get_median_block_weight(&[300_000, 300_000, 300_000]), 300_000);
    }

    // ---- ChainState ----------------------------------------------------------

    #[test]
    fn starts_at_height_zero() {
        let cs = ChainState::new();
        assert_eq!(cs.height(), 0);
        assert_eq!(cs.get_cumulative_difficulty(), 0);
    }

    #[test]
    fn add_block_increments_height() {
        let mut cs = ChainState::new();
        cs.add_block(1000, 100, 300_000);
        assert_eq!(cs.height(), 1);
        cs.add_block(1120, 100, 300_000);
        assert_eq!(cs.height(), 2);
    }

    #[test]
    fn tracks_cumulative_difficulty() {
        let mut cs = ChainState::new();
        cs.add_block(1000, 100, 300_000);
        assert_eq!(cs.get_cumulative_difficulty(), 100);
        cs.add_block(1120, 200, 300_000);
        assert_eq!(cs.get_cumulative_difficulty(), 300);
        cs.add_block(1240, 150, 300_000);
        assert_eq!(cs.get_cumulative_difficulty(), 450);
    }

    #[test]
    fn get_next_difficulty_short_chain_returns_one() {
        let mut cs = ChainState::new();
        for i in 0..3 {
            cs.add_block(1000 + i * 120, 100, 300_000);
        }
        assert_eq!(cs.get_next_difficulty(), 1);
    }

    #[test]
    fn difficulty_window_full() {
        let mut cs = ChainState::new();
        for i in 0..100u64 {
            cs.add_block(1000 + i * 120, 100, 300_000);
        }
        let (ts, cd) = cs.get_difficulty_window();
        assert_eq!(ts.len(), DIFFICULTY_WINDOW_V2 + 1);
        assert_eq!(cd.len(), DIFFICULTY_WINDOW_V2 + 1);
    }

    #[test]
    fn difficulty_window_short_chain() {
        let mut cs = ChainState::new();
        for i in 0..10u64 {
            cs.add_block(1000 + i * 120, 100, 300_000);
        }
        let (ts, _) = cs.get_difficulty_window();
        assert_eq!(ts.len(), 10);
    }

    #[test]
    fn next_difficulty_stable_chain() {
        let mut cs = ChainState::new();
        let base_diff: u128 = 1000;
        for i in 0..80u64 {
            cs.add_block(1000 + i * 120, base_diff, 300_000);
        }
        let diff = cs.get_next_difficulty();
        // With perfect 120s blocks, difficulty should stay near base_diff.
        assert!(diff > 500, "expected >500 got {diff}");
        assert!(diff < 2000, "expected <2000 got {diff}");
    }

    #[test]
    fn next_difficulty_increases_for_fast_blocks() {
        let mut cs = ChainState::new();
        let base_diff: u128 = 1000;
        for i in 0..80u64 {
            cs.add_block(1000 + i * 60, base_diff, 300_000);
        }
        let diff = cs.get_next_difficulty();
        assert!(diff > base_diff, "expected >{base_diff} got {diff}");
    }

    #[test]
    fn next_difficulty_decreases_for_slow_blocks() {
        let mut cs = ChainState::new();
        let base_diff: u128 = 1000;
        for i in 0..80u64 {
            cs.add_block(1000 + i * 240, base_diff, 300_000);
        }
        let diff = cs.get_next_difficulty();
        assert!(diff < base_diff, "expected <{base_diff} got {diff}");
    }

    #[test]
    fn short_term_weights_returns_last_100() {
        let mut cs = ChainState::new();
        for i in 0..150u64 {
            cs.add_block(1000 + i * 120, 100, 300_000 + i);
        }
        let weights = cs.get_short_term_weights();
        assert_eq!(weights.len(), 100);
        assert_eq!(weights[0], 300_050); // starts at block index 50
    }

    #[test]
    fn short_term_weights_short_chain() {
        let mut cs = ChainState::new();
        for i in 0..10u64 {
            cs.add_block(1000 + i * 120, 100, 300_000);
        }
        assert_eq!(cs.get_short_term_weights().len(), 10);
    }

    #[test]
    fn block_weight_limit_returns_valid_limit() {
        let mut cs = ChainState::new();
        for i in 0..10u64 {
            cs.add_block(1000 + i * 120, 100, 300_000);
        }
        let (effective_median, block_limit) = cs.get_block_weight_limit();
        assert_eq!(
            block_limit,
            BLOCK_GRANTED_FULL_REWARD_ZONE_V5 * 2,
            "block limit should be 2x full_reward_zone"
        );
        assert_eq!(effective_median, BLOCK_GRANTED_FULL_REWARD_ZONE_V5);
    }

    #[test]
    fn rollback_truncates_correctly() {
        let mut cs = ChainState::new();
        for i in 0..10u64 {
            cs.add_block(1000 + i * 120, 100, 300_000);
        }
        assert_eq!(cs.height(), 10);
        cs.rollback_to_height(5);
        assert_eq!(cs.height(), 5);
        assert_eq!(cs.get_cumulative_difficulty(), 500);
    }

    #[test]
    fn rollback_to_zero() {
        let mut cs = ChainState::new();
        cs.add_block(1000, 100, 300_000);
        cs.rollback_to_height(0);
        assert_eq!(cs.height(), 0);
        assert_eq!(cs.get_cumulative_difficulty(), 0);
    }

    #[test]
    #[should_panic(expected = "Invalid rollback target")]
    fn rollback_beyond_height_panics() {
        let mut cs = ChainState::new();
        cs.add_block(1000, 100, 300_000);
        cs.rollback_to_height(5);
    }

    #[test]
    fn integration_direct_lwma_matches_chain_state() {
        let mut cs = ChainState::new();
        for i in 0..80u64 {
            cs.add_block(1000 + i * 120, 1000, 300_000);
        }
        let (ts, cd) = cs.get_difficulty_window();
        let direct = next_difficulty_v2(&ts, &cd, DIFFICULTY_TARGET_V2);
        let state = cs.get_next_difficulty();
        assert_eq!(state, direct);
    }
}
