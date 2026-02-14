//! RCT signature batch verification.
//!
//! Provides a single WASM/FFI entry point that verifies all ring signatures
//! in a transaction, avoiding N JS↔WASM boundary crossings.
//!
//! The caller passes flat byte arrays for all inputs; this module:
//! 1. Computes the pre-MLSAG message hash (matching C++ get_pre_mlsag_hash)
//! 2. For each input, constructs the signature struct with key image from prefix
//! 3. Calls tclsag_verify / clsag_verify
//! 4. Returns on first failure (with index) or success

use std::panic;
use wasm_bindgen::prelude::*;

use crate::keccak256_internal;
use crate::to32;
use crate::tclsag::{TclsagSignature, tclsag_verify};
use crate::clsag::{ClsagSignature, clsag_verify};

// ─── RCT Type Constants ─────────────────────────────────────────────────────

const RCT_TYPE_CLSAG: u8 = 5;
const _RCT_TYPE_BULLETPROOF_PLUS: u8 = 6;
const _RCT_TYPE_FULL_PROOFS: u8 = 7;
const _RCT_TYPE_SALVIUM_ZERO: u8 = 8;
const RCT_TYPE_SALVIUM_ONE: u8 = 9;

// ─── Message Hash ────────────────────────────────────────────────────────────

/// Compute the pre-MLSAG/CLSAG message hash.
///
/// Matches C++ get_pre_mlsag_hash (rctSigs.cpp:794-871):
///   H(prefix_hash || H(rct_base_serialized) || H(bp_components))
pub fn compute_rct_message(
    prefix_hash: &[u8; 32],
    rct_base: &[u8],
    bp_components: &[u8],
) -> [u8; 32] {
    let h1 = keccak256_internal(rct_base);
    let h2 = keccak256_internal(bp_components);
    let mut combined = [0u8; 96];
    combined[..32].copy_from_slice(prefix_hash);
    combined[32..64].copy_from_slice(&h1);
    combined[64..96].copy_from_slice(&h2);
    keccak256_internal(&combined)
}

// ─── Batch Verification ─────────────────────────────────────────────────────

/// Verify all RCT signatures in a transaction.
///
/// Returns `(success, failed_input_index)`.
pub fn verify_rct_signatures(
    rct_type: u8,
    message: &[u8; 32],
    input_count: usize,
    ring_size: usize,
    key_images: &[[u8; 32]],
    pseudo_outs: &[[u8; 32]],
    sigs_flat: &[u8],
    ring_pubkeys: &[[u8; 32]],   // input_count * ring_size entries
    ring_commitments: &[[u8; 32]], // input_count * ring_size entries
) -> (bool, Option<u32>) {
    if input_count == 0 || ring_size == 0 {
        return (false, Some(0));
    }
    if key_images.len() < input_count || pseudo_outs.len() < input_count {
        return (false, Some(0));
    }
    if ring_pubkeys.len() < input_count * ring_size
        || ring_commitments.len() < input_count * ring_size
    {
        return (false, Some(0));
    }

    let is_tclsag = rct_type == RCT_TYPE_SALVIUM_ONE;

    // Compute expected sig size per input
    let sig_size_per_input = if is_tclsag {
        // TCLSAG: [sx_0..sx_{n-1}][sy_0..sy_{n-1}][c1][D]
        ring_size * 64 + 64
    } else {
        // CLSAG: [s_0..s_{n-1}][c1][D]
        ring_size * 32 + 64
    };

    let expected_total = input_count * sig_size_per_input;
    if sigs_flat.len() < expected_total {
        return (false, Some(0));
    }

    for i in 0..input_count {
        let sig_offset = i * sig_size_per_input;
        let sig_data = &sigs_flat[sig_offset..sig_offset + sig_size_per_input];

        // Extract ring for this input
        let ring_start = i * ring_size;
        let ring = &ring_pubkeys[ring_start..ring_start + ring_size];
        let commitments = &ring_commitments[ring_start..ring_start + ring_size];

        let valid = if is_tclsag {
            // Parse TCLSAG sig: [sx_0..sx_{n-1}][sy_0..sy_{n-1}][c1][D]
            let mut offset = 0;
            let mut sx = Vec::with_capacity(ring_size);
            for _ in 0..ring_size {
                sx.push(to32(&sig_data[offset..offset + 32]));
                offset += 32;
            }
            let mut sy = Vec::with_capacity(ring_size);
            for _ in 0..ring_size {
                sy.push(to32(&sig_data[offset..offset + 32]));
                offset += 32;
            }
            let c1 = to32(&sig_data[offset..offset + 32]);
            offset += 32;
            let commitment_image = to32(&sig_data[offset..offset + 32]);

            let sig = TclsagSignature {
                sx,
                sy,
                c1,
                key_image: key_images[i],
                commitment_image,
            };
            tclsag_verify(message, &sig, ring, commitments, &pseudo_outs[i])
        } else {
            // Parse CLSAG sig: [s_0..s_{n-1}][c1][D]
            let mut offset = 0;
            let mut s = Vec::with_capacity(ring_size);
            for _ in 0..ring_size {
                s.push(to32(&sig_data[offset..offset + 32]));
                offset += 32;
            }
            let c1 = to32(&sig_data[offset..offset + 32]);
            offset += 32;
            let commitment_image = to32(&sig_data[offset..offset + 32]);

            let sig = ClsagSignature {
                s,
                c1,
                key_image: key_images[i],
                commitment_image,
            };
            clsag_verify(message, &sig, ring, commitments, &pseudo_outs[i])
        };

        if !valid {
            return (false, Some(i as u32));
        }
    }

    (true, None)
}

// ─── WASM Binding ───────────────────────────────────────────────────────────

/// Batch-verify all RCT signatures in a transaction.
///
/// All data is passed as flat byte arrays to minimize JS↔WASM boundary crossings.
///
/// Sig flat format (no I field — key images passed separately):
/// - TCLSAG (type 9), per input: `[sx_0..sx_{n-1} (32B)][sy_0..sy_{n-1} (32B)][c1 (32B)][D (32B)]`
///   Size per input: `ring_size * 64 + 64`
/// - CLSAG (types 5-8), per input: `[s_0..s_{n-1} (32B)][c1 (32B)][D (32B)]`
///   Size per input: `ring_size * 32 + 64`
///
/// Returns:
/// - `[0x01]` if all signatures valid
/// - `[0x00, idx_u32_le]` if signature at index `idx` is invalid
/// - `[0xFF]` if input data is malformed
#[wasm_bindgen]
pub fn verify_rct_signatures_wasm(
    rct_type: u8,
    input_count: u32,
    ring_size: u32,
    tx_prefix_hash: &[u8],       // 32 bytes
    rct_base_bytes: &[u8],       // Serialized rctSigBase (variable)
    bp_components: &[u8],        // Concatenated BP+ fields (variable)
    key_images_flat: &[u8],      // input_count * 32 bytes
    pseudo_outs_flat: &[u8],     // input_count * 32 bytes
    sigs_flat: &[u8],            // Packed sig data (format per rct_type)
    ring_pubkeys_flat: &[u8],    // input_count * ring_size * 32 bytes
    ring_commitments_flat: &[u8], // input_count * ring_size * 32 bytes
) -> Vec<u8> {
    let ic = input_count as usize;
    let rs = ring_size as usize;

    // Validate input lengths
    if tx_prefix_hash.len() < 32 {
        return vec![0xFF];
    }
    if key_images_flat.len() < ic * 32
        || pseudo_outs_flat.len() < ic * 32
        || ring_pubkeys_flat.len() < ic * rs * 32
        || ring_commitments_flat.len() < ic * rs * 32
    {
        return vec![0xFF];
    }

    // Parse prefix hash
    let prefix_hash = to32(tx_prefix_hash);

    // Compute message
    let message = compute_rct_message(&prefix_hash, rct_base_bytes, bp_components);

    // Parse flat arrays into [u8; 32] slices
    let key_images: Vec<[u8; 32]> = (0..ic)
        .map(|i| to32(&key_images_flat[i * 32..(i + 1) * 32]))
        .collect();
    let pseudo_outs: Vec<[u8; 32]> = (0..ic)
        .map(|i| to32(&pseudo_outs_flat[i * 32..(i + 1) * 32]))
        .collect();
    let total_ring = ic * rs;
    let ring_pubkeys: Vec<[u8; 32]> = (0..total_ring)
        .map(|i| to32(&ring_pubkeys_flat[i * 32..(i + 1) * 32]))
        .collect();
    let ring_commitments: Vec<[u8; 32]> = (0..total_ring)
        .map(|i| to32(&ring_commitments_flat[i * 32..(i + 1) * 32]))
        .collect();

    // Catch panics from invalid curve points (decompress failures)
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        verify_rct_signatures(
            rct_type,
            &message,
            ic,
            rs,
            &key_images,
            &pseudo_outs,
            sigs_flat,
            &ring_pubkeys,
            &ring_commitments,
        )
    }));

    match result {
        Ok((true, _)) => vec![0x01],
        Ok((false, Some(idx))) => {
            let mut buf = vec![0x00, 0, 0, 0, 0];
            buf[1..5].copy_from_slice(&idx.to_le_bytes());
            buf
        }
        Ok((false, None)) => vec![0xFF],
        Err(_) => vec![0xFF], // Panic (invalid point, etc.)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clsag::{clsag_sign, random_scalar};
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::traits::VartimeMultiscalarMul;

    #[test]
    fn test_compute_rct_message() {
        let prefix_hash = keccak256_internal(b"prefix");
        let rct_base = b"rct base data";
        let bp_components = b"bp components";

        let message = compute_rct_message(&prefix_hash, rct_base, bp_components);

        // Manually compute expected:
        let h1 = keccak256_internal(rct_base);
        let h2 = keccak256_internal(bp_components);
        let mut combined = [0u8; 96];
        combined[..32].copy_from_slice(&prefix_hash);
        combined[32..64].copy_from_slice(&h1);
        combined[64..96].copy_from_slice(&h2);
        let expected = keccak256_internal(&combined);

        assert_eq!(message, expected);
    }

    #[test]
    fn test_verify_single_clsag() {
        // Generate a valid CLSAG signature and verify through batch interface
        let sk = random_scalar();
        let pk = (&sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();

        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;

        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();

        let message = keccak256_internal(b"test rct verify clsag");

        let sig = clsag_sign(
            &message,
            &[pk],
            &sk.to_bytes(),
            &[commitment],
            &z.to_bytes(),
            &pseudo_output,
            0,
        );

        // Pack sig flat: [s_0][c1][D] (no I, no length prefix)
        let ring_size = 1;
        let mut sigs_flat = Vec::new();
        for s in &sig.s {
            sigs_flat.extend_from_slice(s);
        }
        sigs_flat.extend_from_slice(&sig.c1);
        sigs_flat.extend_from_slice(&sig.commitment_image);

        let (valid, failed) = verify_rct_signatures(
            RCT_TYPE_CLSAG,
            &message,
            1,
            ring_size,
            &[sig.key_image],
            &[pseudo_output],
            &sigs_flat,
            &[pk],
            &[commitment],
        );

        assert!(valid, "CLSAG batch verify should succeed");
        assert!(failed.is_none());
    }

    #[test]
    fn test_verify_single_tclsag() {
        use crate::tclsag::tclsag_sign;

        // T generator
        const T_BYTES: [u8; 32] = [
            0x96, 0x6f, 0xc6, 0x6b, 0x82, 0xcd, 0x56, 0xcf,
            0x85, 0xea, 0xec, 0x80, 0x1c, 0x42, 0x84, 0x5f,
            0x5f, 0x40, 0x88, 0x78, 0xd1, 0x56, 0x1e, 0x00,
            0xd3, 0xd7, 0xde, 0xd2, 0x79, 0x4d, 0x09, 0x4f,
        ];
        let t_gen = curve25519_dalek::edwards::CompressedEdwardsY(T_BYTES)
            .decompress()
            .unwrap();

        let x = random_scalar();
        let y = random_scalar();
        let pk = EdwardsPoint::vartime_multiscalar_mul(
            &[x, y],
            &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, t_gen],
        )
        .compress()
        .to_bytes();

        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;

        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();

        let message = keccak256_internal(b"test rct verify tclsag");

        let sig = tclsag_sign(
            &message,
            &[pk],
            &x.to_bytes(),
            &y.to_bytes(),
            &[commitment],
            &z.to_bytes(),
            &pseudo_output,
            0,
        );

        // Pack sig flat: [sx_0][sy_0][c1][D]
        let ring_size = 1;
        let mut sigs_flat = Vec::new();
        for s in &sig.sx {
            sigs_flat.extend_from_slice(s);
        }
        for s in &sig.sy {
            sigs_flat.extend_from_slice(s);
        }
        sigs_flat.extend_from_slice(&sig.c1);
        sigs_flat.extend_from_slice(&sig.commitment_image);

        let (valid, failed) = verify_rct_signatures(
            RCT_TYPE_SALVIUM_ONE,
            &message,
            1,
            ring_size,
            &[sig.key_image],
            &[pseudo_output],
            &sigs_flat,
            &[pk],
            &[commitment],
        );

        assert!(valid, "TCLSAG batch verify should succeed");
        assert!(failed.is_none());
    }

    #[test]
    fn test_verify_bad_key_image() {
        let sk = random_scalar();
        let pk = (&sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();

        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;

        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();

        let message = keccak256_internal(b"test bad key image");

        let sig = clsag_sign(
            &message,
            &[pk],
            &sk.to_bytes(),
            &[commitment],
            &z.to_bytes(),
            &pseudo_output,
            0,
        );

        // Use wrong key image
        let wrong_ki = keccak256_internal(b"wrong key image");

        let mut sigs_flat = Vec::new();
        for s in &sig.s {
            sigs_flat.extend_from_slice(s);
        }
        sigs_flat.extend_from_slice(&sig.c1);
        sigs_flat.extend_from_slice(&sig.commitment_image);

        let (valid, failed) = verify_rct_signatures(
            RCT_TYPE_CLSAG,
            &message,
            1,
            1,
            &[wrong_ki],
            &[pseudo_output],
            &sigs_flat,
            &[pk],
            &[commitment],
        );

        assert!(!valid, "Wrong key image should fail");
        assert_eq!(failed, Some(0));
    }

    #[test]
    fn test_verify_bad_pseudo_output() {
        let sk = random_scalar();
        let pk = (&sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();

        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;

        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();

        let message = keccak256_internal(b"test bad pseudo out");

        let sig = clsag_sign(
            &message,
            &[pk],
            &sk.to_bytes(),
            &[commitment],
            &z.to_bytes(),
            &pseudo_output,
            0,
        );

        // Use wrong pseudo output
        let wrong_po = (random_scalar() * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();

        let mut sigs_flat = Vec::new();
        for s in &sig.s {
            sigs_flat.extend_from_slice(s);
        }
        sigs_flat.extend_from_slice(&sig.c1);
        sigs_flat.extend_from_slice(&sig.commitment_image);

        let (valid, failed) = verify_rct_signatures(
            RCT_TYPE_CLSAG,
            &message,
            1,
            1,
            &[sig.key_image],
            &[wrong_po],
            &sigs_flat,
            &[pk],
            &[commitment],
        );

        assert!(!valid, "Wrong pseudo output should fail");
        assert_eq!(failed, Some(0));
    }

    #[test]
    fn test_wasm_binding_clsag() {
        // Test the WASM binding end-to-end
        let sk = random_scalar();
        let pk = (&sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();

        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;

        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();

        // Use a known prefix hash & rct base to compute message
        let prefix_hash = keccak256_internal(b"tx prefix");
        let rct_base = b"rct base";
        let bp_components = b"bp components";
        let message = compute_rct_message(&prefix_hash, rct_base, bp_components);

        let sig = clsag_sign(
            &message,
            &[pk],
            &sk.to_bytes(),
            &[commitment],
            &z.to_bytes(),
            &pseudo_output,
            0,
        );

        // Pack flat arrays
        let mut sigs_flat = Vec::new();
        for s in &sig.s {
            sigs_flat.extend_from_slice(s);
        }
        sigs_flat.extend_from_slice(&sig.c1);
        sigs_flat.extend_from_slice(&sig.commitment_image);

        let result = verify_rct_signatures_wasm(
            RCT_TYPE_CLSAG,
            1,
            1,
            &prefix_hash,
            rct_base,
            bp_components,
            &sig.key_image,
            &pseudo_output,
            &sigs_flat,
            &pk,
            &commitment,
        );

        assert_eq!(result, vec![0x01], "WASM binding should return success");
    }

    #[test]
    fn test_wasm_binding_failure_result() {
        // Test that a valid CLSAG sig verified with a wrong key image returns failure
        let sk = random_scalar();
        let pk = (&sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        let z = random_scalar();
        let commitment = (&z * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        let pseudo_output = commitment;

        let prefix_hash = keccak256_internal(b"pfx");
        let rct_base = b"base";
        let bp_components = b"bp";
        let message = compute_rct_message(&prefix_hash, rct_base, bp_components);

        let sig = clsag_sign(&message, &[pk], &sk.to_bytes(), &[commitment], &z.to_bytes(), &pseudo_output, 0);

        // Use a WRONG key image (different from the one produced by sign)
        let wrong_ki = (&random_scalar() * ED25519_BASEPOINT_TABLE).compress().to_bytes();

        let mut sigs_flat = Vec::new();
        for s in &sig.s { sigs_flat.extend_from_slice(s); }
        sigs_flat.extend_from_slice(&sig.c1);
        sigs_flat.extend_from_slice(&sig.commitment_image);

        let result = verify_rct_signatures_wasm(
            RCT_TYPE_CLSAG,
            1,
            1,
            &prefix_hash,
            rct_base,
            bp_components,
            &wrong_ki,
            &pseudo_output,
            &sigs_flat,
            &pk,
            &commitment,
        );

        assert_eq!(result.len(), 5, "Failure result should be 5 bytes");
        assert_eq!(result[0], 0x00, "First byte should be 0x00 for failure");
        let idx = u32::from_le_bytes([result[1], result[2], result[3], result[4]]);
        assert_eq!(idx, 0, "Failed index should be 0");
    }

    #[test]
    fn test_wasm_binding_invalid_points() {
        // Test that invalid curve points return 0xFF error (not panic)
        let prefix_hash = keccak256_internal(b"pfx");
        let fake_ki = [0xAA; 32]; // Invalid point
        let fake_po = [0xBB; 32]; // Invalid point
        let fake_pk = [0xCC; 32]; // Invalid point
        let fake_comm = [0xDD; 32]; // Invalid point
        let sigs_flat = vec![0u8; 96]; // CLSAG: 1 * 32 + 64

        let result = verify_rct_signatures_wasm(
            RCT_TYPE_CLSAG, 1, 1,
            &prefix_hash, b"base", b"bp",
            &fake_ki, &fake_po, &sigs_flat,
            &fake_pk, &fake_comm,
        );

        assert_eq!(result, vec![0xFF], "Invalid points should return error");
    }
}
