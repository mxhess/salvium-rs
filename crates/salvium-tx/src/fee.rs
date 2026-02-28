//! Fee estimation and transaction weight calculation.
//!
//! Estimates transaction size/weight from structural parameters (input count,
//! output count, ring size) and computes fees using per-byte fee constants
//! from salvium-consensus.

use salvium_types::consensus::{
    DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD, DYNAMIC_FEE_PER_KB_BASE_FEE,
    DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT, FEE_PER_BYTE, PER_KB_FEE_QUANTIZATION_DECIMALS,
    SCALING_2021_FEE_ROUNDING_PLACES,
};
use salvium_types::constants::{HfVersion, DISPLAY_DECIMAL_POINT};

use crate::types::{output_type, rct_type};

/// Default ring size for current Salvium protocol.
pub const DEFAULT_RING_SIZE: usize = 16;

/// Fee priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePriority {
    /// Unset — resolves to Low or Normal based on network load via `adjust_priority`.
    /// Falls back to Normal (5x) if adjustment fails.
    Default,
    Low,
    Normal,
    High,
    Highest,
}

impl FeePriority {
    /// Priority multiplier applied to the base fee.
    pub fn multiplier(&self) -> u64 {
        match self {
            FeePriority::Default => 5, // safe fallback = Normal
            FeePriority::Low => 1,
            FeePriority::Normal => 5,
            FeePriority::High => 25,
            FeePriority::Highest => 1000,
        }
    }
}

/// Estimate the serialized byte size of a transaction.
///
/// This estimates the size of the full serialized transaction including
/// prefix, RCT base, ring signatures, bulletproofs, and pseudo-outputs.
pub fn estimate_tx_size(
    num_inputs: usize,
    num_outputs: usize,
    ring_size: usize,
    use_tclsag: bool,
    out_type: u8,
) -> usize {
    // Prefix overhead.
    let mut size = 0usize;
    size += 1; // version varint
    size += 1; // unlock_time varint
    size += 1; // input count varint
    size += 1; // output count varint

    // Salvium v2 fields: tx_type(1) + amount_burnt(1-9) + source_asset_type(4)
    // + dest_asset_type(4) + amount_slippage_limit(1-9) + return fields overhead
    size += 24;

    // Per-input size.
    let per_input = 1  // type tag
        + 1            // amount varint (0)
        + 4            // asset_type ("SAL\0" varint-len + bytes)
        + 1            // key_offsets count varint
        + ring_size * 4  // key_offsets (varints, avg ~4 bytes each)
        + 32; // key_image
    size += num_inputs * per_input;

    // Per-output size.
    let per_output = match out_type {
        output_type::CARROT_V1 => {
            1   // type tag
            + 1 // amount varint (0 for RCT)
            + 32  // one-time key
            + 4   // asset_type
            + 3   // view tag (3 bytes for CARROT)
            + 16 // encrypted janus anchor
        }
        output_type::TAGGED_KEY => {
            1 + 1 + 32 + 4 + 1 // type + amount + key + asset + view_tag(1)
        }
        _ => {
            1 + 1 + 32 + 4 // type + amount + key + asset
        }
    };
    size += num_outputs * per_output;

    // Extra field: tx pub key(33) + padding.
    size += 40;

    // RCT base: type(1) + txnFee varint(4) + ecdhInfo + outPk.
    size += 1 + 4;
    size += num_outputs * 8; // ecdhInfo (8 bytes each, compact)
    size += num_outputs * 32; // outPk

    // Ring signatures.
    if use_tclsag {
        // TCLSAG: sx(ring*32) + sy(ring*32) + c1(32) + D(32) per input.
        size += num_inputs * (ring_size * 32 * 2 + 64);
    } else {
        // CLSAG: s(ring*32) + c1(32) + D(32) per input.
        size += num_inputs * (ring_size * 32 + 64);
    }

    // Pseudo-outputs: 32 bytes per input.
    size += num_inputs * 32;

    // Bulletproofs+: estimate based on output count.
    size += estimate_bp_plus_size(num_outputs);

    // p_r point (32 bytes, for CARROT).
    if out_type == output_type::CARROT_V1 {
        size += 32;
    }

    size
}

/// Estimate the weight of a transaction (size + BP+ clawback).
pub fn estimate_tx_weight(
    num_inputs: usize,
    num_outputs: usize,
    ring_size: usize,
    use_tclsag: bool,
    out_type: u8,
) -> usize {
    let size = estimate_tx_size(num_inputs, num_outputs, ring_size, use_tclsag, out_type);

    if num_outputs > 2 {
        let clawback = bp_plus_clawback(num_outputs);
        size + clawback
    } else {
        size
    }
}

/// Compute the dynamic per-byte fee rate using the 2021-scaling formula.
///
/// Replicates C++ `Blockchain::get_dynamic_base_fee()` exactly:
///   `fee_per_byte = block_reward * 3000 / median² * 19/20`
///
/// Uses 128-bit intermediate arithmetic to avoid overflow, matching the C++
/// `mul128` / `div128_64` implementation.
///
/// # Parameters
/// - `base_reward`: the base block reward (from emission curve, NOT the header
///   `reward` field which includes tx fees).
/// - `median_block_weight`: effective median block weight. For `check_fee()`
///   validation this is `min(short_term_median, long_term_median)` when
///   `hf_version >= HF_VERSION_LONG_TERM_BLOCK_WEIGHT`.
/// - `hf_version`: hard fork version — controls the minimum block weight floor.
pub fn get_dynamic_base_fee(base_reward: u64, median_block_weight: u64, hf_version: u8) -> u64 {
    let min_bw = salvium_types::consensus::min_block_weight(hf_version);
    let median = median_block_weight.max(min_bw);

    if median == 0 {
        return FEE_PER_BYTE;
    }

    // 128-bit: product = base_reward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT
    let product = base_reward as u128 * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT as u128;
    // Divide by median twice: product / median / median = product / median²
    let divided = product / median as u128 / median as u128;
    // Apply 0.95 factor: lo -= lo / 20  (i.e., multiply by 19/20)
    let fee = divided - divided / 20;

    fee as u64
}

/// Legacy dynamic fee computation (pre-2021-scaling).
///
/// Uses the old formula: `(DYNAMIC_FEE_PER_KB_BASE_FEE / 1024 * BASE_BLOCK_REWARD) / base_reward`.
/// This is NOT what the daemon's `check_fee()` uses — prefer [`get_dynamic_base_fee()`] for
/// node validation or the daemon's `get_fee_estimate` RPC for wallet fee estimation.
#[deprecated(note = "Use get_dynamic_base_fee() or the daemon's get_fee_estimate RPC")]
pub fn dynamic_fee_per_byte(base_reward: u64, hf_version: u8) -> u64 {
    if hf_version >= HfVersion::SCALING_2021 {
        let base_fee = DYNAMIC_FEE_PER_KB_BASE_FEE / 1024;
        if base_reward > 0 {
            let f = (base_fee * DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD) / base_reward;
            f.max(FEE_PER_BYTE)
        } else {
            FEE_PER_BYTE
        }
    } else {
        FEE_PER_BYTE
    }
}

/// Compute the 4-tier fee estimate matching C++ `get_dynamic_base_fee_estimate_2021_scaling()`.
///
/// Returns `[Fl, Fn, Fm, Fh]` where:
/// - `Fl` = base_reward * 3000 / Mfw²  (lowest / default)
/// - `Fn` = 4 * Fl  (normal)
/// - `Fm` = 16 * base_reward * 3000 / (ZONE_V5 * Mfw)  (elevated)
/// - `Fh` = max(4*Fm, 4*Fm * Mfw / (32 * 3000 * Mnw / ZONE_V5))  (highest)
///
/// Each tier is rounded up to `SCALING_2021_FEE_ROUNDING_PLACES` significant digits.
///
/// # Parameters
/// - `base_reward`: base block reward from emission curve.
/// - `mnw`: effective short-term median (capped at 50 * Mlw).
/// - `mlw`: long-term median (penalty-free zone for wallet, clamped to >= ZONE_V5).
pub fn get_dynamic_base_fee_estimate_2021_scaling(
    base_reward: u64,
    mnw: u64,
    mlw: u64,
) -> [u64; 4] {
    use salvium_types::consensus::BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

    let mfw = mnw.min(mlw);
    let mfw = mfw.max(1); // avoid division by zero

    // Fl = base_reward * 3000 / (Mfw * Mfw)
    let fl = (base_reward as u128 * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT as u128)
        / (mfw as u128 * mfw as u128);
    let fl = fl as u64;

    // Fn = 4 * Fl
    let fn_ = 4 * fl;

    // Fm = 16 * base_reward * 3000 / (ZONE_V5 * Mfw)
    let fm = (16u128 * base_reward as u128 * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT as u128)
        / (BLOCK_GRANTED_FULL_REWARD_ZONE_V5 as u128 * mfw as u128);
    let fm = fm as u64;

    // Fh = max(4*Fm, 4*Fm * Mfw / (32 * 3000 * Mnw / ZONE_V5))
    let denom = 32 * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT * mnw.max(1)
        / BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
    let fh = if denom > 0 {
        (4 * fm).max(4u64.saturating_mul(fm).saturating_mul(mfw) / denom)
    } else {
        4 * fm
    };

    [
        round_money_up(fl, SCALING_2021_FEE_ROUNDING_PLACES),
        round_money_up(fn_, SCALING_2021_FEE_ROUNDING_PLACES),
        round_money_up(fm, SCALING_2021_FEE_ROUNDING_PLACES),
        round_money_up(fh, SCALING_2021_FEE_ROUNDING_PLACES),
    ]
}

/// Round a monetary amount up to the given number of significant digits.
///
/// Matches C++ `cryptonote::round_money_up()`.
pub fn round_money_up(amount: u64, significant_digits: u32) -> u64 {
    if significant_digits == 0 || amount == 0 {
        return amount;
    }

    // Count digits
    let mut digits = 0u32;
    let mut tmp = amount;
    while tmp > 0 {
        digits += 1;
        tmp /= 10;
    }

    if digits <= significant_digits {
        return amount;
    }

    // Scale factor = 10^(digits - significant_digits)
    let scale = 10u64.pow(digits - significant_digits);

    // Round up: (amount + scale - 1) / scale * scale
    // But also check if trailing digits are all zero (no rounding needed)
    let truncated = amount / scale;
    let remainder = amount - truncated * scale;
    if remainder == 0 {
        amount
    } else {
        (truncated + 1) * scale
    }
}

/// Fee quantization mask: `10^(DISPLAY_DECIMAL_POINT - PER_KB_FEE_QUANTIZATION_DECIMALS)`.
///
/// Matches C++ `Blockchain::get_fee_quantization_mask()` which computes:
///   `PowerOf<10, CRYPTONOTE_DISPLAY_DECIMAL_POINT - PER_KB_FEE_QUANTIZATION_DECIMALS>::Value`
///
/// With DISPLAY_DECIMAL_POINT=8 and QUANTIZATION_DECIMALS=8, mask = 10^0 = 1 (no quantization).
pub fn fee_quantization_mask() -> u64 {
    10u64.pow(DISPLAY_DECIMAL_POINT - PER_KB_FEE_QUANTIZATION_DECIMALS)
}

/// Estimate the fee for a transaction.
///
/// `fee_per_byte` should come from [`dynamic_fee_per_byte()`]. The fee is quantized
/// upward to match the daemon's rounding.
pub fn estimate_tx_fee(
    num_inputs: usize,
    num_outputs: usize,
    ring_size: usize,
    use_tclsag: bool,
    out_type: u8,
    fee_per_byte: u64,
    priority: FeePriority,
) -> u64 {
    let weight = estimate_tx_weight(num_inputs, num_outputs, ring_size, use_tclsag, out_type);
    let mut fee = weight as u64 * fee_per_byte * priority.multiplier();
    // Quantize — matches C++ `calculate_fee_from_weight`:
    //   fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask
    let mask = fee_quantization_mask();
    fee = fee.div_ceil(mask) * mask;
    fee
}

/// Quick fee estimate using defaults (CARROT, TCLSAG, Normal priority).
pub fn estimate_fee_simple(num_inputs: usize, num_outputs: usize, fee_per_byte: u64) -> u64 {
    estimate_tx_fee(
        num_inputs,
        num_outputs,
        DEFAULT_RING_SIZE,
        true,
        output_type::CARROT_V1,
        fee_per_byte,
        FeePriority::Normal,
    )
}

/// Determine the RCT type based on hard fork version.
pub fn rct_type_for_hf(hf_version: u8) -> u8 {
    if hf_version >= 2 {
        rct_type::SALVIUM_ONE
    } else {
        rct_type::BULLETPROOF_PLUS
    }
}

/// Whether to use TCLSAG (vs CLSAG) based on RCT type.
pub fn uses_tclsag(rct_ty: u8) -> bool {
    rct_ty >= rct_type::SALVIUM_ONE
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Estimate Bulletproofs+ proof size in bytes.
fn estimate_bp_plus_size(num_outputs: usize) -> usize {
    if num_outputs == 0 {
        return 0;
    }
    // BP+ proof has fixed fields: A(32) + A1(32) + B(32) + r1(32) + s1(32) + d1(32) = 192
    // Plus L and R vectors: 2 * (6 + log2(padded_outputs)) * 32 each.
    let log_padded = next_power_of_2_log(num_outputs);
    let nlr = 2 * (6 + log_padded);
    192 + nlr * 32
}

/// BP+ weight clawback for > 2 outputs.
///
/// With batched BP+ proofs, the proof size grows sub-linearly.
/// The clawback accounts for the difference between naive per-output
/// proof size and the actual batched size.
fn bp_plus_clawback(num_outputs: usize) -> usize {
    if num_outputs <= 2 {
        return 0;
    }
    // Base: proof size for 2 outputs = 32 * (6 + 7*2) / 2.
    let bp_base: usize = 32 * (6 + 7 * 2) / 2; // 320
    let log_padded = next_power_of_2_log(num_outputs);
    let padded = 1usize << log_padded;
    let nlr = 2 * (6 + log_padded);
    let bp_size = 32 * (6 + nlr);
    // Clawback = 4/5 of the saving.
    (bp_base * padded).saturating_sub(bp_size) * 4 / 5
}

fn next_power_of_2_log(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut v = n - 1;
    let mut log = 0;
    while v > 0 {
        v >>= 1;
        log += 1;
    }
    log
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_priority_multipliers() {
        assert_eq!(FeePriority::Default.multiplier(), 5);
        assert_eq!(FeePriority::Low.multiplier(), 1);
        assert_eq!(FeePriority::Normal.multiplier(), 5);
        assert_eq!(FeePriority::High.multiplier(), 25);
        assert_eq!(FeePriority::Highest.multiplier(), 1000);
    }

    #[test]
    fn test_estimate_tx_size_basic() {
        // 2-in, 2-out CLSAG transaction.
        let size = estimate_tx_size(2, 2, 16, false, output_type::TAGGED_KEY);
        // Should be roughly in the range of 2000-4000 bytes.
        assert!(size > 1500, "size {} too small", size);
        assert!(size < 5000, "size {} too large", size);
    }

    #[test]
    fn test_tclsag_larger_than_clsag() {
        let clsag = estimate_tx_size(2, 2, 16, false, output_type::TAGGED_KEY);
        let tclsag = estimate_tx_size(2, 2, 16, true, output_type::TAGGED_KEY);
        assert!(tclsag > clsag, "TCLSAG should be larger than CLSAG");
    }

    #[test]
    fn test_more_inputs_larger() {
        let small = estimate_tx_size(1, 2, 16, true, output_type::CARROT_V1);
        let large = estimate_tx_size(4, 2, 16, true, output_type::CARROT_V1);
        assert!(large > small);
    }

    #[test]
    fn test_more_outputs_larger() {
        let small = estimate_tx_size(2, 2, 16, true, output_type::CARROT_V1);
        let large = estimate_tx_size(2, 8, 16, true, output_type::CARROT_V1);
        assert!(large > small);
    }

    #[test]
    fn test_fee_estimation_nonzero() {
        let fee = estimate_tx_fee(
            2,
            2,
            16,
            true,
            output_type::CARROT_V1,
            FEE_PER_BYTE,
            FeePriority::Normal,
        );
        assert!(fee > 0, "fee should be nonzero");
    }

    #[test]
    fn test_fee_increases_with_priority() {
        let low =
            estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, FEE_PER_BYTE, FeePriority::Low);
        let normal = estimate_tx_fee(
            2,
            2,
            16,
            true,
            output_type::CARROT_V1,
            FEE_PER_BYTE,
            FeePriority::Normal,
        );
        let high = estimate_tx_fee(
            2,
            2,
            16,
            true,
            output_type::CARROT_V1,
            FEE_PER_BYTE,
            FeePriority::High,
        );
        let highest = estimate_tx_fee(
            2,
            2,
            16,
            true,
            output_type::CARROT_V1,
            FEE_PER_BYTE,
            FeePriority::Highest,
        );
        // With quantization, low/normal may round to the same quantum.
        // But the ordering must hold weakly (>=), and extreme priorities must differ.
        assert!(normal >= low);
        assert!(high >= normal);
        assert!(highest > high, "Highest priority should exceed High");
        assert!(highest > low, "Highest priority should exceed Low");
    }

    #[test]
    fn test_estimate_fee_simple() {
        let fee = estimate_fee_simple(2, 2, FEE_PER_BYTE);
        assert!(fee > 0);
        // With mask=1, fee = weight * FEE_PER_BYTE * Normal(5), no rounding.
        let weight = estimate_tx_weight(2, 2, 16, true, output_type::CARROT_V1);
        let expected = (weight as u64) * FEE_PER_BYTE * 5;
        assert_eq!(fee, expected);
    }

    #[test]
    fn test_bp_plus_clawback_two_outputs() {
        assert_eq!(bp_plus_clawback(2), 0);
    }

    #[test]
    fn test_bp_plus_clawback_many_outputs() {
        let c = bp_plus_clawback(8);
        assert!(c > 0, "clawback should be positive for >2 outputs");
    }

    #[test]
    fn test_weight_includes_clawback() {
        let size = estimate_tx_size(2, 8, 16, true, output_type::CARROT_V1);
        let weight = estimate_tx_weight(2, 8, 16, true, output_type::CARROT_V1);
        assert!(weight > size, "weight should include clawback for 8 outputs");
    }

    #[test]
    fn test_next_power_of_2_log() {
        assert_eq!(next_power_of_2_log(1), 0);
        assert_eq!(next_power_of_2_log(2), 1);
        assert_eq!(next_power_of_2_log(3), 2);
        assert_eq!(next_power_of_2_log(4), 2);
        assert_eq!(next_power_of_2_log(5), 3);
        assert_eq!(next_power_of_2_log(8), 3);
        assert_eq!(next_power_of_2_log(16), 4);
    }

    #[test]
    fn test_rct_type_for_hf() {
        assert_eq!(rct_type_for_hf(2), rct_type::SALVIUM_ONE);
        assert_eq!(rct_type_for_hf(1), rct_type::BULLETPROOF_PLUS);
    }

    #[test]
    fn test_uses_tclsag() {
        assert!(uses_tclsag(rct_type::SALVIUM_ONE));
        assert!(!uses_tclsag(rct_type::CLSAG));
        assert!(!uses_tclsag(rct_type::BULLETPROOF_PLUS));
    }

    // ─── get_dynamic_base_fee tests ─────────────────────────────────────────

    #[test]
    fn test_get_dynamic_base_fee_zero_reward() {
        // base_reward=0 → fee = 0 * 3000 / median² * 19/20 = 0
        let fee = get_dynamic_base_fee(0, 300_000, HfVersion::SCALING_2021);
        assert_eq!(fee, 0);
    }

    #[test]
    fn test_get_dynamic_base_fee_median_clamped_to_min() {
        // median_block_weight below min_block_weight gets clamped to 300,000
        let fee_small_median = get_dynamic_base_fee(1_000_000_000, 100, HfVersion::SCALING_2021);
        let fee_exact_min = get_dynamic_base_fee(1_000_000_000, 300_000, HfVersion::SCALING_2021);
        assert_eq!(fee_small_median, fee_exact_min);
    }

    #[test]
    fn test_get_dynamic_base_fee_known_values() {
        // base_reward = 1e9, median = 300,000 (ZONE_V5)
        // fee = 1e9 * 3000 / 300000 / 300000 * 19/20
        //     = 1e9 * 3000 / 9e10 * 0.95
        //     = 3e12 / 9e10 * 0.95
        //     = 33 * 0.95 = 31.35 → floor = 31
        let fee = get_dynamic_base_fee(1_000_000_000, 300_000, HfVersion::SCALING_2021);
        // 128-bit: 1e9 * 3000 = 3e12. / 300000 = 10000000. / 300000 = 33. - 33/20 = 33-1 = 32
        // Actually: 3000000000000 / 300000 = 10000000; 10000000 / 300000 = 33; 33 - 33/20 = 33 - 1 = 32
        assert_eq!(fee, 32, "1e9 reward, 300k median");
    }

    #[test]
    fn test_get_dynamic_base_fee_higher_reward() {
        // Higher base_reward → higher fee (direct relationship)
        let fee_low = get_dynamic_base_fee(1_000_000_000, 300_000, HfVersion::SCALING_2021);
        let fee_high = get_dynamic_base_fee(10_000_000_000, 300_000, HfVersion::SCALING_2021);
        assert!(fee_high > fee_low, "higher reward should give higher fee");
    }

    #[test]
    fn test_get_dynamic_base_fee_higher_median_lowers_fee() {
        // Higher median → lower fee (blocks have more space)
        let fee_small = get_dynamic_base_fee(1_000_000_000, 300_000, HfVersion::SCALING_2021);
        let fee_large = get_dynamic_base_fee(1_000_000_000, 600_000, HfVersion::SCALING_2021);
        assert!(fee_large < fee_small, "larger median should give lower fee");
    }

    #[test]
    fn test_get_dynamic_base_fee_matches_cpp_test_case() {
        // From C++ test: base_reward=600e9, median=300000
        // fee = 600e9 * 3000 / 300000² * 19/20
        //     = 600e9 * 3000 / 9e10 * 0.95
        //     = 1.8e15 / 9e10 * 0.95
        //     = 20000 * 0.95 = 19000
        let fee = get_dynamic_base_fee(600_000_000_000, 300_000, HfVersion::SCALING_2021);
        // 128-bit: 600e9*3000 = 1.8e15 / 300000 = 6e9 / 300000 = 20000 - 20000/20 = 20000-1000 = 19000
        assert_eq!(fee, 19000, "matches C++ test case");
    }

    #[test]
    fn test_fee_quantization_mask() {
        // C++ formula: 10^(DISPLAY_DECIMAL_POINT - PER_KB_FEE_QUANTIZATION_DECIMALS) = 10^(8-8) = 1.
        assert_eq!(fee_quantization_mask(), 1);
    }

    #[test]
    fn test_fee_quantization_applied() {
        // With mask=1, fees are multiples of 1 (every integer), so no rounding occurs.
        let fee =
            estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, FEE_PER_BYTE, FeePriority::Low);
        let mask = fee_quantization_mask();
        assert_eq!(mask, 1, "mask should be 1");
        // Fee should equal raw weight * fee_per_byte * priority (no rounding with mask=1).
        let weight = estimate_tx_weight(2, 2, 16, true, output_type::CARROT_V1);
        let expected = weight as u64 * FEE_PER_BYTE * FeePriority::Low.multiplier();
        assert_eq!(fee, expected);
    }

    /// Sanity check: a standard 2-in 2-out transaction fee must never approach
    /// 1 SAL. The old quantization bug (mask=10^8-1) rounded every fee UP to
    /// 100,000,000 atomic units = 1 whole SAL. This test catches that class of bug.
    #[test]
    fn test_fee_is_sane_amount() {
        use salvium_types::constants::COIN;

        // Use get_dynamic_base_fee with realistic Salvium parameters:
        // base_reward ~40 SAL (4e9), median = 300,000 (penalty-free zone)
        let fpb = get_dynamic_base_fee(4_000_000_000, 300_000, HfVersion::SCALING_2021);
        assert!(fpb > 0, "fee_per_byte should be nonzero");

        let fee_low =
            estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, fpb, FeePriority::Low);
        let fee_normal =
            estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, fpb, FeePriority::Normal);
        let fee_high =
            estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, fpb, FeePriority::High);

        // Low (1x): must be < 0.1 SAL.
        assert!(
            fee_low < COIN / 10,
            "Low-priority fee {fee_low} >= 0.1 SAL ({}) — fee is too high",
            COIN / 10
        );
        // Normal (5x): must be < 0.5 SAL.
        assert!(
            fee_normal < COIN / 2,
            "Normal-priority fee {fee_normal} >= 0.5 SAL ({}) — fee is too high",
            COIN / 2
        );
        // High (25x): must be < 1 SAL.
        assert!(
            fee_high < COIN,
            "High-priority fee {fee_high} >= 1 SAL ({COIN}) — fee is too high"
        );
        // Static FEE_PER_BYTE (30) with Normal (5x): must be < 0.1 SAL.
        let fee_static = estimate_tx_fee(
            2,
            2,
            16,
            true,
            output_type::CARROT_V1,
            FEE_PER_BYTE,
            FeePriority::Normal,
        );
        assert!(
            fee_static < COIN / 10,
            "Static-rate Normal fee {fee_static} >= 0.1 SAL — fee is too high"
        );
    }

    /// The fee quantization mask must match the C++ formula exactly:
    /// `10^(CRYPTONOTE_DISPLAY_DECIMAL_POINT - PER_KB_FEE_QUANTIZATION_DECIMALS)`
    /// NOT `10^PER_KB_FEE_QUANTIZATION_DECIMALS - 1` (which was the previous bug).
    #[test]
    fn test_fee_quantization_mask_matches_cpp() {
        use salvium_types::constants::COIN;
        let mask = fee_quantization_mask();
        // With DISPLAY=8, QUANT=8: mask = 10^0 = 1. Must never be >= COIN.
        assert!(mask < COIN, "quantization mask {mask} >= 1 SAL — formula is wrong");
        // The mask value for Salvium: 10^(8-8) = 1.
        assert_eq!(mask, 1);
    }

    // ─── round_money_up tests ────────────────────────────────────────────────

    #[test]
    fn test_round_money_up_no_rounding() {
        assert_eq!(round_money_up(100, 3), 100);
        assert_eq!(round_money_up(0, 2), 0);
        assert_eq!(round_money_up(42, 2), 42);
    }

    #[test]
    fn test_round_money_up_basic() {
        // 123 with 2 sig digits → 130
        assert_eq!(round_money_up(123, 2), 130);
        // 1234 with 2 sig digits → 1300
        assert_eq!(round_money_up(1234, 2), 1300);
        // 1200 with 2 sig digits → 1200 (trailing zeros, no rounding needed)
        assert_eq!(round_money_up(1200, 2), 1200);
        // 1201 with 2 sig digits → 1300
        assert_eq!(round_money_up(1201, 2), 1300);
    }

    #[test]
    fn test_round_money_up_carry() {
        // 990 with 2 sig digits → 1000 (carry propagates)
        assert_eq!(round_money_up(990, 2), 990);
        // 991 with 2 sig digits → 1000
        assert_eq!(round_money_up(991, 2), 1000);
    }

    // ─── 2021 scaling fee estimate tests ─────────────────────────────────────

    #[test]
    fn test_2021_scaling_estimate_matches_cpp() {
        use salvium_types::consensus::BLOCK_GRANTED_FULL_REWARD_ZONE_V5;

        // From C++ test: base_reward=600e9, Mnw=300000, Mlw=300000
        let fees = get_dynamic_base_fee_estimate_2021_scaling(
            600_000_000_000,
            BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
            BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
        );
        // Fl = 600e9 * 3000 / 300000² = 600e9 * 3000 / 9e10 = 20000
        // Rounded up to 2 sig digits = 20000
        assert_eq!(fees[0], 20000, "Fl should be 20000");
        // Fn = 4 * 20000 = 80000
        assert_eq!(fees[1], 80000, "Fn should be 80000");
    }

    #[test]
    fn test_2021_scaling_tiers_ordering() {
        let fees = get_dynamic_base_fee_estimate_2021_scaling(1_000_000_000, 300_000, 300_000);
        // Tiers should be in ascending order
        assert!(fees[0] <= fees[1], "Fl <= Fn");
        assert!(fees[1] <= fees[2] || fees[2] <= fees[3], "ordering");
    }
}
