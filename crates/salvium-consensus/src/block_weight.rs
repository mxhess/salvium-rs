//! Dynamic block weight system.
//!
//! Implements the long-term / short-term block weight median system that
//! governs Salvium's dynamic block size limits.  The algorithm clamps
//! individual long-term weights within +/-70 % of the running median and
//! derives an effective median (with a surge-factor cap) that ultimately
//! determines the maximum block weight miners may produce.
//!
//! Reference: salvium/src/cryptonote_core/blockchain.cpp:5518-5608

use salvium_types::consensus::{
    BLOCK_GRANTED_FULL_REWARD_ZONE_V5, SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR,
};

use crate::chain_state::get_median_block_weight;

// Re-export the constant under the short alias used throughout this module's
// documentation and tests.
const FRZ: u64 = BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

// =============================================================================
// BlockWeightInfo
// =============================================================================

/// Result of [`get_effective_median_block_weight`]: the three numbers a miner
/// needs to evaluate whether a candidate block is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockWeightInfo {
    /// `max(FRZ, median(long_term_weights))`
    pub long_term_effective_median: u64,
    /// The effective median after applying surge-factor clamping and the FRZ
    /// floor.
    pub effective_median: u64,
    /// `2 * effective_median` -- the hard upper limit on block weight.
    pub block_limit: u64,
}

// =============================================================================
// Public API
// =============================================================================

/// Clamp `block_weight` to within +/-70 % of the long-term effective median.
///
/// The *effective median* used here is `max(FRZ, long_term_median)` so that the
/// network always allows blocks up to the full reward zone even when the chain
/// is young or mostly empty.
///
/// * **lower bound** = `effective_median * 10 / 17`
/// * **upper bound** = `effective_median + effective_median * 7 / 10`
///
/// Returns `block_weight` unchanged when it falls inside [lower, upper].
pub fn get_next_long_term_block_weight(block_weight: u64, long_term_median: u64) -> u64 {
    let effective_median = FRZ.max(long_term_median);

    let lower_bound = effective_median * 10 / 17;
    let upper_bound = effective_median + effective_median * 7 / 10;

    if block_weight < lower_bound {
        lower_bound
    } else if block_weight > upper_bound {
        upper_bound
    } else {
        block_weight
    }
}

/// Compute the effective median block weight and the resulting block limit from
/// the rolling long-term and short-term weight windows.
///
/// Algorithm:
///
/// 1. `long_term_effective_median = max(FRZ, median(long_term_weights))`
/// 2. `short_term_median = median(short_term_weights)`
/// 3. `effective_median = max(long_term_effective_median, short_term_median)`
/// 4. Clamp: `effective_median = min(effective_median, SURGE_FACTOR * long_term_effective_median)`
/// 5. Floor: `effective_median = max(effective_median, FRZ)`
/// 6. `block_limit = effective_median * 2`
pub fn get_effective_median_block_weight(
    long_term_weights: &[u64],
    short_term_weights: &[u64],
) -> BlockWeightInfo {
    let long_term_median = get_median_block_weight(long_term_weights);
    let long_term_effective_median = FRZ.max(long_term_median);

    let short_term_median = get_median_block_weight(short_term_weights);

    let mut effective_median = long_term_effective_median.max(short_term_median);

    // Clamp to surge factor.
    effective_median = effective_median
        .min(SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * long_term_effective_median);

    // Floor at full reward zone.
    effective_median = effective_median.max(FRZ);

    let block_limit = effective_median * 2;

    BlockWeightInfo {
        long_term_effective_median,
        effective_median,
        block_limit,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- get_next_long_term_block_weight ------------------------------------

    #[test]
    fn weight_at_median_stays_unchanged() {
        assert_eq!(get_next_long_term_block_weight(FRZ, FRZ), FRZ);
    }

    #[test]
    fn weight_within_70_pct_stays_unchanged() {
        let median: u64 = 500_000;
        // lower = 500000*10/17 = 294117, upper = 500000 + 500000*7/10 = 850000
        assert_eq!(get_next_long_term_block_weight(400_000, median), 400_000);
        assert_eq!(get_next_long_term_block_weight(700_000, median), 700_000);
    }

    #[test]
    fn weight_below_lower_bound_gets_clamped_up() {
        let median: u64 = 500_000;
        let lower_bound = median * 10 / 17; // 294117
        assert_eq!(get_next_long_term_block_weight(100_000, median), lower_bound);
    }

    #[test]
    fn weight_above_upper_bound_gets_clamped_down() {
        let median: u64 = 500_000;
        let upper_bound = median + median * 7 / 10; // 850000
        assert_eq!(get_next_long_term_block_weight(1_000_000, median), upper_bound);
    }

    #[test]
    fn uses_full_reward_zone_as_minimum_median() {
        // Even if long_term_median is 0, effective_median = max(FRZ, 0) = FRZ
        let result = get_next_long_term_block_weight(FRZ, 0);
        assert_eq!(result, FRZ);
    }

    #[test]
    fn small_block_gets_clamped_to_lower_bound() {
        let result = get_next_long_term_block_weight(1_000, FRZ);
        let lower_bound = FRZ * 10 / 17;
        assert_eq!(result, lower_bound);
    }

    // ---- get_effective_median_block_weight -----------------------------------

    #[test]
    fn empty_weights_use_full_reward_zone() {
        let info = get_effective_median_block_weight(&[], &[]);
        assert_eq!(info.long_term_effective_median, FRZ);
        assert_eq!(info.effective_median, FRZ);
        assert_eq!(info.block_limit, FRZ * 2);
    }

    #[test]
    fn all_weights_at_frz_gives_standard_limit() {
        let weights = vec![FRZ; 100];
        let info = get_effective_median_block_weight(&weights, &weights);
        assert_eq!(info.effective_median, FRZ);
        assert_eq!(info.block_limit, FRZ * 2);
    }

    #[test]
    fn large_short_term_weights_increase_effective_median() {
        let long_term = vec![FRZ; 100];
        let short_term = vec![FRZ * 2; 100];
        let info = get_effective_median_block_weight(&long_term, &short_term);
        // Short-term median (600000) > long-term effective (300000)
        // but still below surge cap (50 * 300000 = 15000000)
        assert_eq!(info.effective_median, FRZ * 2);
        assert_eq!(info.block_limit, FRZ * 4);
    }

    #[test]
    fn surge_factor_caps_at_50x() {
        let long_term = vec![FRZ; 100];
        let short_term = vec![FRZ * 100; 100]; // Way above surge limit
        let info = get_effective_median_block_weight(&long_term, &short_term);
        assert_eq!(
            info.effective_median,
            SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * FRZ,
        );
    }

    #[test]
    fn short_term_below_long_term_uses_long_term() {
        let long_term = vec![FRZ * 2; 100];
        let short_term = vec![FRZ; 100];
        let info = get_effective_median_block_weight(&long_term, &short_term);
        // Long-term median = 600000 > short-term 300000
        assert_eq!(info.effective_median, FRZ * 2);
    }

    #[test]
    fn full_reward_zone_acts_as_floor() {
        let long_term = vec![1_000u64; 100]; // Way below FRZ
        let short_term = vec![1_000u64; 100];
        let info = get_effective_median_block_weight(&long_term, &short_term);
        assert_eq!(info.long_term_effective_median, FRZ);
        assert_eq!(info.effective_median, FRZ);
    }

    // ---- get_median_block_weight edge cases (re-exported from chain_state) ---

    #[test]
    fn two_elements_upper_median() {
        assert_eq!(get_median_block_weight(&[10, 20]), 20);
    }

    #[test]
    fn large_spread_upper_median() {
        assert_eq!(get_median_block_weight(&[1, 1_000_000]), 1_000_000);
    }

    #[test]
    fn duplicate_values() {
        assert_eq!(get_median_block_weight(&[5, 5, 5, 5, 5]), 5);
    }
}
