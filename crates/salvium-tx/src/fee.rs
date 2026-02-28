//! Fee estimation and transaction weight calculation.
//!
//! Estimates transaction size/weight from structural parameters (input count,
//! output count, ring size) and computes fees using per-byte fee constants
//! from salvium-consensus.

use salvium_types::consensus::{
    DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD, DYNAMIC_FEE_PER_KB_BASE_FEE, FEE_PER_BYTE,
    PER_KB_FEE_QUANTIZATION_DECIMALS,
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

/// Compute the dynamic per-byte fee rate from the current base block reward.
///
/// Replicates the C++ formula from `blockchain.cpp get_dynamic_base_fee_estimate()`:
///   fee_per_byte = max((DYNAMIC_FEE_PER_KB_BASE_FEE / 1024 * DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD) / base_reward, FEE_PER_BYTE)
///
/// This is a pure function — no RPC calls needed. Pass `BlockHeader.reward` and
/// `BlockHeader.major_version` from block headers already fetched for priority adjustment.
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

    // ─── dynamic_fee_per_byte tests ──────────────────────────────────────────

    #[test]
    fn test_dynamic_fee_per_byte_zero_reward() {
        // base_reward=0 should fall back to FEE_PER_BYTE.
        assert_eq!(dynamic_fee_per_byte(0, HfVersion::SCALING_2021), FEE_PER_BYTE);
    }

    #[test]
    fn test_dynamic_fee_per_byte_pre_scaling() {
        // Pre-SCALING_2021 hf_version should always return FEE_PER_BYTE.
        assert_eq!(dynamic_fee_per_byte(500_000_000, 1), FEE_PER_BYTE);
        assert_eq!(dynamic_fee_per_byte(500_000_000, 0), FEE_PER_BYTE);
    }

    #[test]
    fn test_dynamic_fee_per_byte_known_reward() {
        // With base_reward = DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD (1e9),
        // fee = (200000/1024 * 1e9) / 1e9 = 200000/1024 = 195 (integer division).
        let fpb =
            dynamic_fee_per_byte(DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD, HfVersion::SCALING_2021);
        assert_eq!(fpb, DYNAMIC_FEE_PER_KB_BASE_FEE / 1024);
    }

    #[test]
    fn test_dynamic_fee_per_byte_large_reward() {
        // Very large base_reward → dynamic fee drops but floors to FEE_PER_BYTE.
        let fpb = dynamic_fee_per_byte(1_000_000_000_000, HfVersion::SCALING_2021);
        assert_eq!(fpb, FEE_PER_BYTE);
    }

    #[test]
    fn test_dynamic_fee_per_byte_small_reward() {
        // Small base_reward → high dynamic fee.
        let fpb = dynamic_fee_per_byte(100_000_000, HfVersion::SCALING_2021);
        // (200000/1024 * 1e9) / 1e8 = 195 * 10 = 1950
        let expected = (DYNAMIC_FEE_PER_KB_BASE_FEE / 1024 * DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD)
            / 100_000_000;
        assert_eq!(fpb, expected);
        assert!(fpb > FEE_PER_BYTE);
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

        // Use the reference base_reward (10 SAL) which gives fee_per_byte = 195.
        let fpb_ref =
            dynamic_fee_per_byte(DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD, HfVersion::SCALING_2021);
        assert_eq!(fpb_ref, DYNAMIC_FEE_PER_KB_BASE_FEE / 1024); // 195

        let fee_low =
            estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, fpb_ref, FeePriority::Low);
        let fee_normal =
            estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, fpb_ref, FeePriority::Normal);
        let fee_high =
            estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, fpb_ref, FeePriority::High);

        // Low (1x): typical ~660k atomic = ~0.0066 SAL. Must be < 0.1 SAL.
        assert!(
            fee_low < COIN / 10,
            "Low-priority fee {fee_low} >= 0.1 SAL ({}) — fee is too high",
            COIN / 10
        );
        // Normal (5x): typical ~3.3M atomic = ~0.033 SAL. Must be < 0.5 SAL.
        assert!(
            fee_normal < COIN / 2,
            "Normal-priority fee {fee_normal} >= 0.5 SAL ({}) — fee is too high",
            COIN / 2
        );
        // High (25x): typical ~16.5M atomic = ~0.165 SAL. Must be < 1 SAL.
        assert!(
            fee_high < COIN,
            "High-priority fee {fee_high} >= 1 SAL ({COIN}) — fee is too high"
        );
        // Static FEE_PER_BYTE (30) with Normal (5x): typical ~508k. Must be < 0.1 SAL.
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
}
