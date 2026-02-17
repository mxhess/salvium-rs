//! Fee estimation and transaction weight calculation.
//!
//! Estimates transaction size/weight from structural parameters (input count,
//! output count, ring size) and computes fees using per-byte fee constants
//! from salvium-consensus.

use salvium_types::consensus::minimum_fee;

#[cfg(test)]
use salvium_types::consensus::FEE_PER_BYTE;

use crate::types::{output_type, rct_type};

/// Default ring size for current Salvium protocol.
pub const DEFAULT_RING_SIZE: usize = 16;

/// Fee priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePriority {
    Low,
    Normal,
    High,
    Highest,
}

impl FeePriority {
    /// Priority multiplier applied to the base fee.
    pub fn multiplier(&self) -> u64 {
        match self {
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
        + 32;          // key_image
    size += num_inputs * per_input;

    // Per-output size.
    let per_output = match out_type {
        output_type::CARROT_V1 => {
            1   // type tag
            + 1 // amount varint (0 for RCT)
            + 32  // one-time key
            + 4   // asset_type
            + 3   // view tag (3 bytes for CARROT)
            + 16  // encrypted janus anchor
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

/// Estimate the fee for a transaction.
pub fn estimate_tx_fee(
    num_inputs: usize,
    num_outputs: usize,
    ring_size: usize,
    use_tclsag: bool,
    out_type: u8,
    priority: FeePriority,
) -> u64 {
    let weight = estimate_tx_weight(num_inputs, num_outputs, ring_size, use_tclsag, out_type);
    let base_fee = minimum_fee(weight as u64, 0, 2);
    base_fee * priority.multiplier()
}

/// Quick fee estimate using defaults (CARROT, TCLSAG, Normal priority).
pub fn estimate_fee_simple(num_inputs: usize, num_outputs: usize) -> u64 {
    estimate_tx_fee(
        num_inputs,
        num_outputs,
        DEFAULT_RING_SIZE,
        true,
        output_type::CARROT_V1,
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
        let fee = estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, FeePriority::Normal);
        assert!(fee > 0, "fee should be nonzero");
    }

    #[test]
    fn test_fee_increases_with_priority() {
        let low = estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, FeePriority::Low);
        let normal = estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, FeePriority::Normal);
        let high = estimate_tx_fee(2, 2, 16, true, output_type::CARROT_V1, FeePriority::High);
        assert!(normal > low);
        assert!(high > normal);
    }

    #[test]
    fn test_estimate_fee_simple() {
        let fee = estimate_fee_simple(2, 2);
        assert!(fee > 0);
        // Should be around FEE_PER_BYTE * weight * 5 (normal priority).
        let weight = estimate_tx_weight(2, 2, 16, true, output_type::CARROT_V1);
        assert_eq!(fee, (weight as u64) * FEE_PER_BYTE * 5);
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
}
