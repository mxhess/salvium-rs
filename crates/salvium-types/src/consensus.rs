//! Salvium consensus rules and constants.
//!
//! Block reward calculation, difficulty algorithms, timestamp validation,
//! unlock time logic, and fee computation.
//!
//! Reference: salvium/src/cryptonote_config.h, cryptonote_basic_impl.cpp, difficulty.cpp

use crate::constants::{
    network_config, AssetType, HfVersion, Network, TxType,
};

// =============================================================================
// Core Constants
// =============================================================================

/// Total money supply: 184.4M coins × 10^8 atomic units.
pub const MONEY_SUPPLY: u64 = 18_440_000_000_000_000;

/// Emission speed factor per minute.
pub const EMISSION_SPEED_FACTOR_PER_MINUTE: u32 = 21;

/// Minimum subsidy per minute (tail emission): 3 × 10^7.
pub const FINAL_SUBSIDY_PER_MINUTE: u64 = 30_000_000;

/// Premine amount (genesis block reward).
pub const PREMINE_AMOUNT: u64 = 2_210_000_000_000_000;

/// Premine upfront portion.
pub const PREMINE_AMOUNT_UPFRONT: u64 = 650_000_000_000_000;

/// Premine monthly portion.
pub const PREMINE_AMOUNT_MONTHLY: u64 = 65_000_000_000_000;

/// Treasury SAL1 mint amount.
pub const TREASURY_SAL1_MINT_AMOUNT: u64 = 130_000_000_000_000;

/// Treasury SAL1 mint count.
pub const TREASURY_SAL1_MINT_COUNT: u32 = 8;

// Block timing
/// Target block time before first fork (seconds).
pub const DIFFICULTY_TARGET_V1: u64 = 60;

/// Current target block time (seconds).
pub const DIFFICULTY_TARGET_V2: u64 = 120;

/// Maximum allowed future timestamp offset (2 hours).
pub const BLOCK_FUTURE_TIME_LIMIT: u64 = 60 * 60 * 2;

/// Number of recent blocks to check for median timestamp.
pub const TIMESTAMP_CHECK_WINDOW: usize = 60;

// Difficulty adjustment
/// Difficulty window (original algorithm).
pub const DIFFICULTY_WINDOW: usize = 720;

/// Difficulty window (LWMA v2).
pub const DIFFICULTY_WINDOW_V2: usize = 70;

/// Difficulty lag (original algorithm).
pub const DIFFICULTY_LAG: usize = 15;

/// Difficulty cut (original algorithm).
pub const DIFFICULTY_CUT: usize = 60;

// Block weight
/// Full reward zone v1 (bytes).
pub const BLOCK_GRANTED_FULL_REWARD_ZONE_V1: u64 = 20_000;

/// Full reward zone v2 (bytes).
pub const BLOCK_GRANTED_FULL_REWARD_ZONE_V2: u64 = 60_000;

/// Full reward zone v5 (bytes).
pub const BLOCK_GRANTED_FULL_REWARD_ZONE_V5: u64 = 300_000;

/// Long-term block weight window size.
pub const LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE: u64 = 100_000;

/// Short-term block weight surge factor.
pub const SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR: u64 = 50;

// Transaction limits
/// Maximum transaction size (bytes).
pub const MAX_TX_SIZE: u64 = 1_000_000;

/// Maximum transactions per block.
pub const MAX_TX_PER_BLOCK: u64 = 0x1000_0000;

/// Maximum tx_extra size (bytes).
pub const MAX_TX_EXTRA_SIZE: usize = 1060;

/// Maximum Bulletproof/BP+ outputs.
pub const BULLETPROOF_MAX_OUTPUTS: usize = 16;

// Maturity and unlock
/// Coinbase maturity window (blocks).
pub const MINED_MONEY_UNLOCK_WINDOW: u64 = 60;

/// Default minimum age before spending (blocks).
pub const DEFAULT_TX_SPENDABLE_AGE: u64 = 10;

/// Allowed delta blocks for unlock time.
pub const LOCKED_TX_ALLOWED_DELTA_BLOCKS: u64 = 1;

// Fees
/// Per-byte fee.
pub const FEE_PER_BYTE: u64 = 30;

/// Per-KB fee (legacy).
pub const FEE_PER_KB: u64 = 200_000;

/// Dynamic fee base (per KB).
pub const DYNAMIC_FEE_PER_KB_BASE_FEE: u64 = 200_000;

/// Dynamic fee base block reward.
pub const DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD: u64 = 1_000_000_000;

/// Dynamic fee reference transaction weight.
pub const DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT: u64 = 3000;

/// Fee quantization decimals.
pub const PER_KB_FEE_QUANTIZATION_DECIMALS: u32 = 8;

/// Fee estimate grace blocks.
pub const FEE_ESTIMATE_GRACE_BLOCKS: u64 = 10;

/// Default dust threshold.
pub const DEFAULT_DUST_THRESHOLD: u64 = 2_000_000_000;

/// Base reward clamp threshold.
pub const BASE_REWARD_CLAMP_THRESHOLD: u64 = 100_000_000;

// Mempool
/// Mempool TX lifetime (3 days in seconds).
pub const MEMPOOL_TX_LIVETIME: u64 = 86400 * 3;

/// Mempool TX from alt block lifetime (1 week).
pub const MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME: u64 = 604800;

// Pricing record
/// Pricing record validity window (blocks).
pub const PRICING_RECORD_VALID_BLOCKS: u64 = 10;

/// Pricing record time diff tolerance (seconds).
pub const PRICING_RECORD_VALID_TIME_DIFF: u64 = 120;

// Lock periods
/// Burn lock period (blocks).
pub const BURN_LOCK_PERIOD: u64 = 0;

/// Convert lock period (blocks).
pub const CONVERT_LOCK_PERIOD: u64 = 0;

/// Unlock time threshold: below = height, above = timestamp.
pub const UNLOCK_TIME_THRESHOLD: u64 = 500_000_000;

// =============================================================================
// Hard Fork Queries
// =============================================================================

/// Get the hard fork version active at a given block height.
pub fn hf_version_for_height(height: u64, network: Network) -> u8 {
    let config = network_config(network);
    let mut active_version = 1u8;
    for &(version, activation_height) in config.hard_fork_heights {
        if height >= activation_height && version > active_version {
            active_version = version;
        }
    }
    active_version
}

/// Check if a specific hard fork is active at a given height.
pub fn is_hf_active(hf_version: u8, height: u64, network: Network) -> bool {
    hf_version_for_height(height, network) >= hf_version
}

/// Get the active asset type at a given height.
pub fn active_asset_type(height: u64, network: Network) -> AssetType {
    if is_hf_active(HfVersion::SALVIUM_ONE_PROOFS, height, network) {
        AssetType::Sal1
    } else {
        AssetType::Sal
    }
}

/// Check if CARROT outputs are enabled at a given height.
pub fn is_carrot_active(height: u64, network: Network) -> bool {
    is_hf_active(HfVersion::CARROT, height, network)
}

/// Get the correct TX version for a given TX type and height.
pub fn tx_version(tx_type: TxType, height: u64, network: Network) -> u8 {
    let hf = hf_version_for_height(height, network);
    if hf >= HfVersion::CARROT {
        4
    } else if hf >= HfVersion::ENABLE_N_OUTS && tx_type == TxType::Transfer {
        3
    } else {
        2
    }
}

/// Get the required RCT signature type for a given height.
pub fn rct_type(height: u64, network: Network) -> u8 {
    let hf = hf_version_for_height(height, network);
    if hf >= HfVersion::CARROT {
        9 // SalviumOne
    } else if hf >= HfVersion::SALVIUM_ONE_PROOFS {
        8 // SalviumZero
    } else if hf >= HfVersion::FULL_PROOFS {
        7 // FullProofs
    } else {
        6 // BulletproofPlus
    }
}

/// Get the signature type name for a given RCT type.
///
/// Returns "CLSAG" for rct_type < 8, "TCLSAG" for rct_type >= 8.
/// TCLSAG (Tree-based CLSAG) is used starting with SalviumZero (type 8)
/// proof system, but practically only appears at HF10+ (CARROT, type 9).
pub fn signature_type_for_rct(rct_type: u8) -> &'static str {
    if rct_type >= 8 {
        "TCLSAG"
    } else {
        "CLSAG"
    }
}

// =============================================================================
// Block Reward Calculation
// =============================================================================

/// Get minimum block weight for full reward.
pub fn min_block_weight(version: u8) -> u64 {
    if version < 2 {
        BLOCK_GRANTED_FULL_REWARD_ZONE_V1
    } else {
        BLOCK_GRANTED_FULL_REWARD_ZONE_V5
    }
}

/// Calculate block reward.
///
/// Formula: base_reward = (MONEY_SUPPLY - already_generated) >> emission_speed_factor
/// With penalty for blocks larger than median weight.
pub fn block_reward(
    median_weight: u64,
    current_block_weight: u64,
    already_generated_coins: u64,
    version: u8,
) -> Option<u64> {
    let target_minutes = DIFFICULTY_TARGET_V2 / 60;
    let emission_speed_factor = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes as u32 - 1);

    // Genesis block (premine)
    if already_generated_coins == 0 {
        return Some(PREMINE_AMOUNT);
    }

    // Calculate base reward using u128 to avoid overflow
    let remaining = MONEY_SUPPLY.saturating_sub(already_generated_coins);
    let mut base_reward = remaining >> emission_speed_factor;

    // Apply tail emission (minimum subsidy)
    let min_subsidy = FINAL_SUBSIDY_PER_MINUTE * target_minutes;
    if base_reward < min_subsidy {
        base_reward = min_subsidy;
    }

    // Get full reward zone
    let full_reward_zone = min_block_weight(version);
    let effective_median = median_weight.max(full_reward_zone);

    // No penalty if block is small
    if current_block_weight <= effective_median {
        return Some(base_reward);
    }

    // Block too large
    if current_block_weight > 2 * effective_median {
        return None; // reward = 0, block invalid
    }

    // Calculate penalty: reward × (2M - W) × W / M²
    let m = effective_median as u128;
    let w = current_block_weight as u128;
    let multiplicand = (2 * m - w) * w;
    let reward = (base_reward as u128 * multiplicand) / m / m;

    Some(reward as u64)
}

// =============================================================================
// Difficulty Calculation
// =============================================================================

/// Calculate next difficulty using original algorithm.
pub fn next_difficulty(
    timestamps: &[u64],
    cumulative_difficulties: &[u128],
    target_seconds: u64,
) -> u128 {
    let mut ts: Vec<u64> = timestamps.to_vec();
    let mut cd: Vec<u128> = cumulative_difficulties.to_vec();

    // Trim to window size
    if ts.len() > DIFFICULTY_WINDOW {
        ts.truncate(DIFFICULTY_WINDOW);
        cd.truncate(DIFFICULTY_WINDOW);
    }

    let length = ts.len();
    assert_eq!(length, cd.len(), "timestamps and difficulties must have same length");

    if length <= 1 {
        return 1;
    }

    // Sort pairs by timestamp
    let mut pairs: Vec<(u64, u128)> = ts.into_iter().zip(cd).collect();
    pairs.sort_by_key(|p| p.0);
    let ts: Vec<u64> = pairs.iter().map(|p| p.0).collect();
    let cd: Vec<u128> = pairs.iter().map(|p| p.1).collect();

    // Calculate cut points
    let (cut_begin, cut_end) = if length <= DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT {
        (0, length)
    } else {
        let begin = (length - (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT)).div_ceil(2);
        (begin, begin + (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT))
    };

    // Calculate time span and work
    let mut time_span = ts[cut_end - 1] as u128 - ts[cut_begin] as u128;
    if time_span == 0 {
        time_span = 1;
    }

    let total_work = cd[cut_end - 1] - cd[cut_begin];

    // difficulty = work × target / timeSpan
    (total_work * target_seconds as u128).div_ceil(time_span)
}

/// Calculate next difficulty using LWMA (Linearly Weighted Moving Average) v2.
///
/// LWMA algorithm by Zawy.
pub fn next_difficulty_v2(
    timestamps: &[u64],
    cumulative_difficulties: &[u128],
    target_seconds: u64,
) -> u128 {
    let t = target_seconds as i128;
    let mut n = DIFFICULTY_WINDOW_V2;

    let mut ts = timestamps.to_vec();
    let mut cd = cumulative_difficulties.to_vec();

    if ts.len() > n + 1 {
        ts.truncate(n + 1);
        cd.truncate(n + 1);
    }

    let count = ts.len();
    assert_eq!(count, cd.len());

    // First 5 blocks: return difficulty 1
    if count < 6 {
        return 1;
    }

    // Adjust N if we don't have enough data
    if count < n + 1 {
        n = count - 1;
    }

    let n_big = n as i128;

    // Normalization divisor: k = N × (N + 1) / 2
    let k = n_big * (n_big + 1) / 2;

    // Scale factor for fixed-point arithmetic
    const SCALE: i128 = 1_000_000;
    const ADJUST_NUM: i128 = 998;
    const ADJUST_DEN: i128 = 1000;

    let mut weighted_solve_time: i128 = 0;
    let mut total_difficulty: u128 = 0;

    for i in 1..=n {
        let mut solve_time = ts[i] as i128 - ts[i - 1] as i128;
        // Clamp solve time to [-7T, 7T]
        let max_st = 7 * t;
        if solve_time > max_st {
            solve_time = max_st;
        }
        if solve_time < -max_st {
            solve_time = -max_st;
        }

        let difficulty = cd[i] - cd[i - 1];
        weighted_solve_time += solve_time * i as i128;
        total_difficulty += difficulty;
    }

    // LWMA = weighted_solve_time / k
    let mut lwma_scaled = weighted_solve_time * SCALE / k;
    let min_lwma = t * SCALE / 20;
    if lwma_scaled < min_lwma {
        lwma_scaled = min_lwma;
    }

    // Next difficulty = avgD × T × adjust / LWMA
    let next_diff = total_difficulty as i128 * t * ADJUST_NUM * SCALE
        / (n_big * ADJUST_DEN * lwma_scaled);

    if next_diff < 1 { 1 } else { next_diff as u128 }
}

/// Check if a hash meets difficulty target: hash × difficulty ≤ 2^256.
pub fn check_hash(hash: &[u8; 32], difficulty: u128) -> bool {
    // Convert hash to 256-bit integer matching C++ byte order:
    // Four 64-bit LE words, read from word[3] down to word[0].
    let mut lo: u128 = 0;
    for word in 0..2 {
        let mut w: u64 = 0;
        let base = word * 8;
        for b in (0..8).rev() {
            w = (w << 8) | hash[base + b] as u64;
        }
        lo |= (w as u128) << (word * 64);
    }
    let mut hi: u128 = 0;
    for word in 2..4 {
        let mut w: u64 = 0;
        let base = word * 8;
        for b in (0..8).rev() {
            w = (w << 8) | hash[base + b] as u64;
        }
        hi |= (w as u128) << ((word - 2) * 64);
    }

    // Multiply 256-bit hash by 128-bit difficulty and check ≤ 2^256 - 1
    // Using u256 arithmetic via two u128s
    let (prod_lo, carry) = lo.overflowing_mul(difficulty);
    let prod_hi_part = hi.checked_mul(difficulty);

    match prod_hi_part {
        Some(ph) => {
            let (prod_hi, overflow) = ph.overflowing_add(carry as u128);
            // If overflow in high part, product > 2^256
            !overflow || (prod_hi == 0 && prod_lo == 0)
        }
        None => false, // overflow means > 2^256
    }
}

// =============================================================================
// Timestamp Validation
// =============================================================================

/// Get median timestamp from recent blocks.
pub fn median_timestamp(timestamps: &[u64]) -> u64 {
    if timestamps.is_empty() {
        return 0;
    }
    let mut sorted = timestamps.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

/// Validate a block timestamp.
pub fn validate_block_timestamp(
    timestamp: u64,
    recent_timestamps: &[u64],
    current_time: u64,
) -> Result<(), String> {
    if timestamp > current_time + BLOCK_FUTURE_TIME_LIMIT {
        return Err(format!(
            "Timestamp too far in future: {} > {}",
            timestamp,
            current_time + BLOCK_FUTURE_TIME_LIMIT
        ));
    }

    if recent_timestamps.len() >= TIMESTAMP_CHECK_WINDOW {
        let window = &recent_timestamps[..TIMESTAMP_CHECK_WINDOW];
        let median = median_timestamp(window);
        if timestamp <= median {
            return Err(format!(
                "Timestamp not greater than median: {} <= {}",
                timestamp, median
            ));
        }
    }

    Ok(())
}

// =============================================================================
// Unlock Time Validation
// =============================================================================

/// Check if an output is unlocked (spendable).
pub fn is_output_unlocked(
    unlock_time: u64,
    current_height: u64,
    current_time: u64,
    version: u8,
) -> bool {
    if unlock_time == 0 {
        return true;
    }

    if unlock_time < UNLOCK_TIME_THRESHOLD {
        // Block height based unlock
        current_height + LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time
    } else {
        // Timestamp based unlock
        let delta = if version >= 2 {
            DIFFICULTY_TARGET_V2 * LOCKED_TX_ALLOWED_DELTA_BLOCKS
        } else {
            DIFFICULTY_TARGET_V1 * LOCKED_TX_ALLOWED_DELTA_BLOCKS
        };
        current_time + delta >= unlock_time
    }
}

/// Check if coinbase output is mature (spendable).
pub fn is_coinbase_mature(output_height: u64, current_height: u64) -> bool {
    current_height >= output_height + MINED_MONEY_UNLOCK_WINDOW
}

/// Check if output meets minimum age requirement.
pub fn meets_minimum_age(output_height: u64, current_height: u64) -> bool {
    current_height >= output_height + DEFAULT_TX_SPENDABLE_AGE
}

// =============================================================================
// Fee Calculation
// =============================================================================

/// Calculate minimum required fee.
pub fn minimum_fee(tx_weight: u64, _base_reward: u64, version: u8) -> u64 {
    if version >= HfVersion::PER_BYTE_FEE {
        tx_weight * FEE_PER_BYTE
    } else {
        let kb = tx_weight.div_ceil(1024);
        kb * FEE_PER_KB
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hf_version_mainnet() {
        assert_eq!(hf_version_for_height(0, Network::Mainnet), 1);
        assert_eq!(hf_version_for_height(1, Network::Mainnet), 1);
        assert_eq!(hf_version_for_height(89800, Network::Mainnet), 2);
        assert_eq!(hf_version_for_height(154750, Network::Mainnet), 6);
        assert_eq!(hf_version_for_height(334750, Network::Mainnet), 10);
        assert_eq!(hf_version_for_height(500000, Network::Mainnet), 10);
    }

    #[test]
    fn test_hf_version_testnet() {
        assert_eq!(hf_version_for_height(0, Network::Testnet), 1);
        assert_eq!(hf_version_for_height(250, Network::Testnet), 2);
        assert_eq!(hf_version_for_height(815, Network::Testnet), 6);
        assert_eq!(hf_version_for_height(1100, Network::Testnet), 10);
    }

    #[test]
    fn test_active_asset_type() {
        assert_eq!(active_asset_type(100, Network::Mainnet), AssetType::Sal);
        assert_eq!(active_asset_type(154750, Network::Mainnet), AssetType::Sal1);
    }

    #[test]
    fn test_genesis_block_reward() {
        assert_eq!(block_reward(0, 0, 0, 1), Some(PREMINE_AMOUNT));
    }

    #[test]
    fn test_block_reward_no_penalty() {
        let reward = block_reward(300_000, 1000, PREMINE_AMOUNT, 2).unwrap();
        assert!(reward > 0);
        assert!(reward < MONEY_SUPPLY);
    }

    #[test]
    fn test_block_reward_oversize() {
        // Block > 2× median should fail
        assert_eq!(block_reward(300_000, 700_000, PREMINE_AMOUNT, 2), None);
    }

    #[test]
    fn test_coinbase_maturity() {
        assert!(!is_coinbase_mature(100, 150));
        assert!(is_coinbase_mature(100, 160));
    }

    #[test]
    fn test_minimum_age() {
        assert!(!meets_minimum_age(100, 105));
        assert!(meets_minimum_age(100, 110));
    }

    #[test]
    fn test_median_timestamp() {
        assert_eq!(median_timestamp(&[1, 3, 5, 7, 9]), 5);
        assert_eq!(median_timestamp(&[9, 1, 5, 3, 7]), 5);
        assert_eq!(median_timestamp(&[]), 0);
    }

    #[test]
    fn test_minimum_difficulty() {
        assert_eq!(next_difficulty(&[100], &[1000], DIFFICULTY_TARGET_V2), 1);
    }

    // =========================================================================
    // Hard Fork Boundary Tests (ported from test/cross-fork-tx.test.js)
    // =========================================================================

    /// Verify all 10 HF activation heights on testnet, including boundary edges.
    ///
    /// Testnet HF heights:
    ///   HF1: 1, HF2: 250, HF3: 500, HF4: 600, HF5: 800,
    ///   HF6: 815, HF7: 900, HF8: 950, HF9: 1000, HF10: 1100
    #[test]
    fn test_hf_boundaries_testnet() {
        let net = Network::Testnet;

        // Height 0 is before HF1 (activation at height 1), so defaults to 1
        assert_eq!(hf_version_for_height(0, net), 1);

        // HF1 at exact activation
        assert_eq!(hf_version_for_height(1, net), 1);
        // Just below HF2
        assert_eq!(hf_version_for_height(249, net), 1);

        // HF2 at exact activation
        assert_eq!(hf_version_for_height(250, net), 2);
        // Just below HF3
        assert_eq!(hf_version_for_height(499, net), 2);

        // HF3 at exact activation
        assert_eq!(hf_version_for_height(500, net), 3);
        // Just below HF4
        assert_eq!(hf_version_for_height(599, net), 3);

        // HF4 at exact activation
        assert_eq!(hf_version_for_height(600, net), 4);
        // Just below HF5
        assert_eq!(hf_version_for_height(799, net), 4);

        // HF5 at exact activation
        assert_eq!(hf_version_for_height(800, net), 5);
        // Just below HF6
        assert_eq!(hf_version_for_height(814, net), 5);

        // HF6 at exact activation
        assert_eq!(hf_version_for_height(815, net), 6);
        // Just below HF7
        assert_eq!(hf_version_for_height(899, net), 6);

        // HF7 at exact activation
        assert_eq!(hf_version_for_height(900, net), 7);
        // Just below HF8
        assert_eq!(hf_version_for_height(949, net), 7);

        // HF8 at exact activation
        assert_eq!(hf_version_for_height(950, net), 8);
        // Just below HF9
        assert_eq!(hf_version_for_height(999, net), 8);

        // HF9 at exact activation
        assert_eq!(hf_version_for_height(1000, net), 9);
        // Just below HF10
        assert_eq!(hf_version_for_height(1099, net), 9);

        // HF10 at exact activation
        assert_eq!(hf_version_for_height(1100, net), 10);
        // Well beyond all forks
        assert_eq!(hf_version_for_height(2000, net), 10);
        assert_eq!(hf_version_for_height(100_000, net), 10);
    }

    /// Verify TX version selection for each TX type across HF boundaries.
    ///
    /// Rules:
    /// - Pre-HF2: all TX types use v2
    /// - HF2-HF9: TRANSFER uses v3 (N_OUTS), all others use v2
    /// - HF10+: all TX types use v4 (CARROT)
    #[test]
    fn test_tx_version_matrix() {
        let net = Network::Testnet;

        // --- HF1 (height 100): everything is v2 ---
        assert_eq!(tx_version(TxType::Transfer, 100, net), 2);
        assert_eq!(tx_version(TxType::Stake, 100, net), 2);
        assert_eq!(tx_version(TxType::Burn, 100, net), 2);
        assert_eq!(tx_version(TxType::Convert, 100, net), 2);
        assert_eq!(tx_version(TxType::Audit, 100, net), 2);

        // --- HF2 (height 250): TRANSFER upgrades to v3, others stay v2 ---
        assert_eq!(tx_version(TxType::Transfer, 250, net), 3);
        assert_eq!(tx_version(TxType::Stake, 250, net), 2);
        assert_eq!(tx_version(TxType::Burn, 250, net), 2);
        assert_eq!(tx_version(TxType::Convert, 250, net), 2);
        assert_eq!(tx_version(TxType::Audit, 250, net), 2);

        // --- HF3 (height 500): same as HF2 ---
        assert_eq!(tx_version(TxType::Transfer, 500, net), 3);
        assert_eq!(tx_version(TxType::Stake, 500, net), 2);
        assert_eq!(tx_version(TxType::Burn, 500, net), 2);
        assert_eq!(tx_version(TxType::Convert, 500, net), 2);

        // --- HF6 (height 815): still v3 for TRANSFER, v2 for others ---
        assert_eq!(tx_version(TxType::Transfer, 815, net), 3);
        assert_eq!(tx_version(TxType::Stake, 815, net), 2);
        assert_eq!(tx_version(TxType::Burn, 815, net), 2);
        assert_eq!(tx_version(TxType::Convert, 815, net), 2);
        assert_eq!(tx_version(TxType::Audit, 815, net), 2);

        // --- HF9 (height 1000): still v3/v2 split ---
        assert_eq!(tx_version(TxType::Transfer, 1000, net), 3);
        assert_eq!(tx_version(TxType::Stake, 1000, net), 2);

        // --- HF10 (height 1100): everything upgrades to v4 ---
        assert_eq!(tx_version(TxType::Transfer, 1100, net), 4);
        assert_eq!(tx_version(TxType::Stake, 1100, net), 4);
        assert_eq!(tx_version(TxType::Burn, 1100, net), 4);
        assert_eq!(tx_version(TxType::Convert, 1100, net), 4);
        assert_eq!(tx_version(TxType::Audit, 1100, net), 4);

        // --- Well beyond HF10 (height 2000): still v4 ---
        assert_eq!(tx_version(TxType::Transfer, 2000, net), 4);
        assert_eq!(tx_version(TxType::Stake, 2000, net), 4);
    }

    /// Verify RCT type progression: 6 -> 7 -> 8 -> 9 across hard forks.
    ///
    /// - HF1-2:   BulletproofPlus (type 6)
    /// - HF3-5:   FullProofs (type 7)
    /// - HF6-9:   SalviumZero (type 8)
    /// - HF10+:   SalviumOne (type 9)
    #[test]
    fn test_rct_type_progression() {
        let net = Network::Testnet;

        // HF1 range: type 6 (BulletproofPlus)
        assert_eq!(rct_type(1, net), 6);
        assert_eq!(rct_type(100, net), 6);
        assert_eq!(rct_type(249, net), 6);

        // HF2 range: still type 6
        assert_eq!(rct_type(250, net), 6);
        assert_eq!(rct_type(499, net), 6);

        // HF3 boundary: transitions to type 7 (FullProofs)
        assert_eq!(rct_type(500, net), 7);
        assert_eq!(rct_type(600, net), 7);
        assert_eq!(rct_type(800, net), 7);
        assert_eq!(rct_type(814, net), 7);

        // HF6 boundary: transitions to type 8 (SalviumZero)
        assert_eq!(rct_type(815, net), 8);
        assert_eq!(rct_type(900, net), 8);
        assert_eq!(rct_type(950, net), 8);
        assert_eq!(rct_type(1000, net), 8);
        assert_eq!(rct_type(1099, net), 8);

        // HF10 boundary: transitions to type 9 (SalviumOne)
        assert_eq!(rct_type(1100, net), 9);
        assert_eq!(rct_type(2000, net), 9);
        assert_eq!(rct_type(100_000, net), 9);
    }

    /// Verify asset type transition: SAL before HF6, SAL1 at HF6+.
    #[test]
    fn test_asset_type_transitions() {
        let net = Network::Testnet;

        // Pre-HF6: SAL asset type
        assert_eq!(active_asset_type(1, net), AssetType::Sal);
        assert_eq!(active_asset_type(100, net), AssetType::Sal);
        assert_eq!(active_asset_type(250, net), AssetType::Sal);
        assert_eq!(active_asset_type(500, net), AssetType::Sal);
        assert_eq!(active_asset_type(814, net), AssetType::Sal);

        // HF6+ (SALVIUM_ONE_PROOFS): SAL1 asset type
        assert_eq!(active_asset_type(815, net), AssetType::Sal1);
        assert_eq!(active_asset_type(900, net), AssetType::Sal1);
        assert_eq!(active_asset_type(1000, net), AssetType::Sal1);
        assert_eq!(active_asset_type(1100, net), AssetType::Sal1);
        assert_eq!(active_asset_type(2000, net), AssetType::Sal1);
    }

    /// Verify CARROT activation at HF10.
    #[test]
    fn test_carrot_activation() {
        let net = Network::Testnet;

        // Pre-HF10: CARROT not active
        assert!(!is_carrot_active(1, net));
        assert!(!is_carrot_active(100, net));
        assert!(!is_carrot_active(500, net));
        assert!(!is_carrot_active(815, net));
        assert!(!is_carrot_active(1000, net));
        assert!(!is_carrot_active(1099, net));

        // HF10+: CARROT active
        assert!(is_carrot_active(1100, net));
        assert!(is_carrot_active(1101, net));
        assert!(is_carrot_active(2000, net));
        assert!(is_carrot_active(100_000, net));
    }

    /// Verify signature_type_for_rct helper: CLSAG for < 8, TCLSAG for >= 8.
    #[test]
    fn test_signature_type_for_rct() {
        // CLSAG range: rct types 0-7
        assert_eq!(signature_type_for_rct(0), "CLSAG");
        assert_eq!(signature_type_for_rct(1), "CLSAG");
        assert_eq!(signature_type_for_rct(5), "CLSAG");
        assert_eq!(signature_type_for_rct(6), "CLSAG");
        assert_eq!(signature_type_for_rct(7), "CLSAG");

        // TCLSAG range: rct types 8+
        assert_eq!(signature_type_for_rct(8), "TCLSAG");
        assert_eq!(signature_type_for_rct(9), "TCLSAG");
        assert_eq!(signature_type_for_rct(10), "TCLSAG");
        assert_eq!(signature_type_for_rct(255), "TCLSAG");
    }

    /// Verify signature types at actual testnet heights.
    #[test]
    fn test_signature_type_at_heights() {
        let net = Network::Testnet;

        // Pre-HF6: rct_type 6 or 7 -> CLSAG
        assert_eq!(signature_type_for_rct(rct_type(100, net)), "CLSAG");
        assert_eq!(signature_type_for_rct(rct_type(500, net)), "CLSAG");

        // HF6-9: rct_type 8 -> TCLSAG
        assert_eq!(signature_type_for_rct(rct_type(815, net)), "TCLSAG");
        assert_eq!(signature_type_for_rct(rct_type(900, net)), "TCLSAG");
        assert_eq!(signature_type_for_rct(rct_type(1099, net)), "TCLSAG");

        // HF10+: rct_type 9 -> TCLSAG
        assert_eq!(signature_type_for_rct(rct_type(1100, net)), "TCLSAG");
        assert_eq!(signature_type_for_rct(rct_type(2000, net)), "TCLSAG");
    }

    /// Full cross-fork TX format matrix: combines tx_version, rct_type,
    /// asset_type, and signature type at key HF boundaries.
    ///
    /// Reproduces the cross-fork-tx.test.js matrix for TRANSFER and STAKE.
    #[test]
    fn test_full_tx_format_matrix() {
        let net = Network::Testnet;

        // Helper struct for concise test case definition
        struct Case {
            height: u64,
            expected_hf: u8,
            tx_type: TxType,
            expected_tx_ver: u8,
            expected_rct: u8,
            expected_sig: &'static str,
            expected_asset: AssetType,
        }

        let cases = [
            // TRANSFER transactions across forks
            Case {
                height: 100,
                expected_hf: 1,
                tx_type: TxType::Transfer,
                expected_tx_ver: 2,
                expected_rct: 6,
                expected_sig: "CLSAG",
                expected_asset: AssetType::Sal,
            },
            Case {
                height: 250,
                expected_hf: 2,
                tx_type: TxType::Transfer,
                expected_tx_ver: 3,
                expected_rct: 6,
                expected_sig: "CLSAG",
                expected_asset: AssetType::Sal,
            },
            Case {
                height: 500,
                expected_hf: 3,
                tx_type: TxType::Transfer,
                expected_tx_ver: 3,
                expected_rct: 7,
                expected_sig: "CLSAG",
                expected_asset: AssetType::Sal,
            },
            Case {
                height: 815,
                expected_hf: 6,
                tx_type: TxType::Transfer,
                expected_tx_ver: 3,
                expected_rct: 8,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
            Case {
                height: 1100,
                expected_hf: 10,
                tx_type: TxType::Transfer,
                expected_tx_ver: 4,
                expected_rct: 9,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
            // STAKE transactions across forks
            Case {
                height: 100,
                expected_hf: 1,
                tx_type: TxType::Stake,
                expected_tx_ver: 2,
                expected_rct: 6,
                expected_sig: "CLSAG",
                expected_asset: AssetType::Sal,
            },
            Case {
                height: 815,
                expected_hf: 6,
                tx_type: TxType::Stake,
                expected_tx_ver: 2,
                expected_rct: 8,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
            Case {
                height: 1100,
                expected_hf: 10,
                tx_type: TxType::Stake,
                expected_tx_ver: 4,
                expected_rct: 9,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
            // BURN transactions
            Case {
                height: 500,
                expected_hf: 3,
                tx_type: TxType::Burn,
                expected_tx_ver: 2,
                expected_rct: 7,
                expected_sig: "CLSAG",
                expected_asset: AssetType::Sal,
            },
            Case {
                height: 900,
                expected_hf: 7,
                tx_type: TxType::Burn,
                expected_tx_ver: 2,
                expected_rct: 8,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
            Case {
                height: 1100,
                expected_hf: 10,
                tx_type: TxType::Burn,
                expected_tx_ver: 4,
                expected_rct: 9,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
            // CONVERT transactions
            Case {
                height: 500,
                expected_hf: 3,
                tx_type: TxType::Convert,
                expected_tx_ver: 2,
                expected_rct: 7,
                expected_sig: "CLSAG",
                expected_asset: AssetType::Sal,
            },
            Case {
                height: 900,
                expected_hf: 7,
                tx_type: TxType::Convert,
                expected_tx_ver: 2,
                expected_rct: 8,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
            Case {
                height: 1100,
                expected_hf: 10,
                tx_type: TxType::Convert,
                expected_tx_ver: 4,
                expected_rct: 9,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
            // AUDIT transactions
            Case {
                height: 815,
                expected_hf: 6,
                tx_type: TxType::Audit,
                expected_tx_ver: 2,
                expected_rct: 8,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
            Case {
                height: 1100,
                expected_hf: 10,
                tx_type: TxType::Audit,
                expected_tx_ver: 4,
                expected_rct: 9,
                expected_sig: "TCLSAG",
                expected_asset: AssetType::Sal1,
            },
        ];

        for (i, c) in cases.iter().enumerate() {
            let actual_hf = hf_version_for_height(c.height, net);
            assert_eq!(
                actual_hf, c.expected_hf,
                "case {}: HF at height {} expected {} got {}",
                i, c.height, c.expected_hf, actual_hf
            );

            let actual_tx_ver = tx_version(c.tx_type, c.height, net);
            assert_eq!(
                actual_tx_ver, c.expected_tx_ver,
                "case {}: tx_version({}, h={}) expected {} got {}",
                i, c.tx_type, c.height, c.expected_tx_ver, actual_tx_ver
            );

            let actual_rct = rct_type(c.height, net);
            assert_eq!(
                actual_rct, c.expected_rct,
                "case {}: rct_type(h={}) expected {} got {}",
                i, c.height, c.expected_rct, actual_rct
            );

            let actual_sig = signature_type_for_rct(actual_rct);
            assert_eq!(
                actual_sig, c.expected_sig,
                "case {}: sig_type(rct={}) expected {} got {}",
                i, actual_rct, c.expected_sig, actual_sig
            );

            let actual_asset = active_asset_type(c.height, net);
            assert_eq!(
                actual_asset, c.expected_asset,
                "case {}: asset(h={}) expected {:?} got {:?}",
                i, c.height, c.expected_asset, actual_asset
            );
        }
    }

    /// Verify that is_hf_active works correctly for feature gating.
    #[test]
    fn test_is_hf_active_feature_gates() {
        let net = Network::Testnet;

        // ENABLE_N_OUTS (HF2) not active at HF1
        assert!(!is_hf_active(HfVersion::ENABLE_N_OUTS, 100, net));
        // Active at HF2+
        assert!(is_hf_active(HfVersion::ENABLE_N_OUTS, 250, net));

        // FULL_PROOFS (HF3) not active at HF2
        assert!(!is_hf_active(HfVersion::FULL_PROOFS, 250, net));
        // Active at HF3+
        assert!(is_hf_active(HfVersion::FULL_PROOFS, 500, net));

        // SALVIUM_ONE_PROOFS (HF6) not active at HF5
        assert!(!is_hf_active(HfVersion::SALVIUM_ONE_PROOFS, 800, net));
        // Active at HF6+
        assert!(is_hf_active(HfVersion::SALVIUM_ONE_PROOFS, 815, net));

        // CARROT (HF10) not active at HF9
        assert!(!is_hf_active(HfVersion::CARROT, 1000, net));
        // Active at HF10+
        assert!(is_hf_active(HfVersion::CARROT, 1100, net));
    }

    /// Verify mainnet HF boundaries (sanity check against testnet).
    #[test]
    fn test_hf_boundaries_mainnet() {
        let net = Network::Mainnet;

        assert_eq!(hf_version_for_height(1, net), 1);
        assert_eq!(hf_version_for_height(89799, net), 1);
        assert_eq!(hf_version_for_height(89800, net), 2);
        assert_eq!(hf_version_for_height(121100, net), 3);
        assert_eq!(hf_version_for_height(121800, net), 4);
        assert_eq!(hf_version_for_height(136100, net), 5);
        assert_eq!(hf_version_for_height(154750, net), 6);
        assert_eq!(hf_version_for_height(161900, net), 7);
        assert_eq!(hf_version_for_height(172000, net), 8);
        assert_eq!(hf_version_for_height(179200, net), 9);
        assert_eq!(hf_version_for_height(334749, net), 9);
        assert_eq!(hf_version_for_height(334750, net), 10);
        assert_eq!(hf_version_for_height(500000, net), 10);
    }

    /// Verify mainnet asset type and CARROT activation at correct heights.
    #[test]
    fn test_mainnet_asset_and_carrot() {
        let net = Network::Mainnet;

        // SAL before HF6
        assert_eq!(active_asset_type(100, net), AssetType::Sal);
        assert_eq!(active_asset_type(154749, net), AssetType::Sal);
        // SAL1 at HF6+
        assert_eq!(active_asset_type(154750, net), AssetType::Sal1);
        assert_eq!(active_asset_type(334750, net), AssetType::Sal1);

        // CARROT not active before HF10
        assert!(!is_carrot_active(334749, net));
        // CARROT active at HF10+
        assert!(is_carrot_active(334750, net));
    }

    /// Verify RCT type transitions on mainnet.
    #[test]
    fn test_rct_type_mainnet() {
        let net = Network::Mainnet;

        // HF1-2: BulletproofPlus (6)
        assert_eq!(rct_type(1, net), 6);
        assert_eq!(rct_type(89800, net), 6);

        // HF3: FullProofs (7)
        assert_eq!(rct_type(121100, net), 7);

        // HF6: SalviumZero (8)
        assert_eq!(rct_type(154750, net), 8);
        assert_eq!(rct_type(334749, net), 8);

        // HF10: SalviumOne (9)
        assert_eq!(rct_type(334750, net), 9);
    }

    /// Edge case: TRANSFER tx version at exact HF2 boundary.
    #[test]
    fn test_transfer_tx_version_boundary() {
        let net = Network::Testnet;

        // Height 249: HF1, TRANSFER -> v2
        assert_eq!(tx_version(TxType::Transfer, 249, net), 2);
        // Height 250: HF2, TRANSFER -> v3
        assert_eq!(tx_version(TxType::Transfer, 250, net), 3);
        // Height 1099: HF9, TRANSFER -> v3
        assert_eq!(tx_version(TxType::Transfer, 1099, net), 3);
        // Height 1100: HF10, TRANSFER -> v4
        assert_eq!(tx_version(TxType::Transfer, 1100, net), 4);
    }

    /// Edge case: non-TRANSFER tx versions never go to v3, jump from v2 to v4.
    #[test]
    fn test_non_transfer_skips_v3() {
        let net = Network::Testnet;

        // STAKE at HF2 (where TRANSFER gets v3) stays at v2
        assert_eq!(tx_version(TxType::Stake, 250, net), 2);
        assert_eq!(tx_version(TxType::Stake, 500, net), 2);
        assert_eq!(tx_version(TxType::Stake, 815, net), 2);
        assert_eq!(tx_version(TxType::Stake, 900, net), 2);
        assert_eq!(tx_version(TxType::Stake, 1099, net), 2);
        // Jumps directly to v4 at HF10
        assert_eq!(tx_version(TxType::Stake, 1100, net), 4);

        // Same for BURN
        assert_eq!(tx_version(TxType::Burn, 500, net), 2);
        assert_eq!(tx_version(TxType::Burn, 900, net), 2);
        assert_eq!(tx_version(TxType::Burn, 1099, net), 2);
        assert_eq!(tx_version(TxType::Burn, 1100, net), 4);

        // Same for CONVERT
        assert_eq!(tx_version(TxType::Convert, 500, net), 2);
        assert_eq!(tx_version(TxType::Convert, 900, net), 2);
        assert_eq!(tx_version(TxType::Convert, 1100, net), 4);
    }

    /// Verify stagenet matches testnet HF heights (they use the same table).
    #[test]
    fn test_stagenet_matches_testnet() {
        let testnet = Network::Testnet;
        let stagenet = Network::Stagenet;

        let heights = [0, 1, 100, 249, 250, 499, 500, 599, 600, 799, 800,
                       814, 815, 899, 900, 949, 950, 999, 1000, 1099, 1100, 2000];

        for &h in &heights {
            assert_eq!(
                hf_version_for_height(h, testnet),
                hf_version_for_height(h, stagenet),
                "HF mismatch at height {} between testnet and stagenet",
                h
            );
            assert_eq!(
                rct_type(h, testnet),
                rct_type(h, stagenet),
                "rct_type mismatch at height {} between testnet and stagenet",
                h
            );
            assert_eq!(
                active_asset_type(h, testnet),
                active_asset_type(h, stagenet),
                "asset_type mismatch at height {} between testnet and stagenet",
                h
            );
        }
    }

    /// Verify the RCT type enum values match what consensus functions return.
    #[test]
    fn test_rct_type_enum_consistency() {
        use crate::constants::RctType;

        assert_eq!(RctType::BulletproofPlus as u8, 6);
        assert_eq!(RctType::FullProofs as u8, 7);
        assert_eq!(RctType::SalviumZero as u8, 8);
        assert_eq!(RctType::SalviumOne as u8, 9);

        let net = Network::Testnet;
        assert_eq!(rct_type(100, net), RctType::BulletproofPlus as u8);
        assert_eq!(rct_type(500, net), RctType::FullProofs as u8);
        assert_eq!(rct_type(815, net), RctType::SalviumZero as u8);
        assert_eq!(rct_type(1100, net), RctType::SalviumOne as u8);
    }
}
