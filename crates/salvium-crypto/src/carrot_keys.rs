//! CARROT key hierarchy — single-call derivation.
//!
//! Derives all 9 CARROT keys from a master secret in one call,
//! eliminating multiple FFI round-trips for blake2b + scalar reduce + point ops.
//!
//! Full derivation returns 288 bytes (9 × 32):
//!   [masterSecret | proveSpendKey | viewBalanceSecret | generateImageKey |
//!    viewIncomingKey | generateAddressSecret | accountSpendPubkey |
//!    primaryAddressViewPubkey | accountViewPubkey]
//!
//! View-only derivation returns 224 bytes (7 × 32):
//!   [viewBalanceSecret | viewIncomingKey | generateImageKey |
//!    generateAddressSecret | accountSpendPubkey |
//!    primaryAddressViewPubkey | accountViewPubkey]

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use crate::to32;
use crate::carrot_scan::T_BYTES;

// ─── Domain separators (matching carrot_core/config.h) ──────────────────────

const DOMAIN_PROVE_SPEND_KEY: &[u8] = b"Carrot prove-spend key";
const DOMAIN_VIEW_BALANCE_SECRET: &[u8] = b"Carrot view-balance secret";
const DOMAIN_GENERATE_IMAGE_KEY: &[u8] = b"Carrot generate-image key";
const DOMAIN_INCOMING_VIEW_KEY: &[u8] = b"Carrot incoming view key";
const DOMAIN_GENERATE_ADDRESS_SECRET: &[u8] = b"Carrot generate-address secret";

// ─── Transcript + hash helpers ──────────────────────────────────────────────

/// Build `[domain_len_byte] + domain` (SpFixedTranscript format, no extra data)
fn build_domain_transcript(domain: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + domain.len());
    buf.push(domain.len() as u8);
    buf.extend_from_slice(domain);
    buf
}

/// Keyed blake2b.
fn blake2b_keyed(transcript: &[u8], out_len: usize, key: &[u8]) -> Vec<u8> {
    blake2b_simd::Params::new()
        .hash_length(out_len)
        .key(key)
        .hash(transcript)
        .as_bytes()
        .to_vec()
}

/// H_32: blake2b 32 bytes keyed with domain separator.
fn derive_bytes_32(domain: &[u8], key: &[u8]) -> [u8; 32] {
    let transcript = build_domain_transcript(domain);
    let hash = blake2b_keyed(&transcript, 32, key);
    to32(&hash)
}

/// H_n: blake2b 64 bytes keyed with domain separator, then reduce to scalar.
fn derive_scalar(domain: &[u8], key: &[u8]) -> Scalar {
    let transcript = build_domain_transcript(domain);
    let hash64 = blake2b_keyed(&transcript, 64, key);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash64);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ─── Key derivation ─────────────────────────────────────────────────────────

/// Derive all 9 CARROT keys from master secret.
///
/// Returns 288 bytes: 9 contiguous 32-byte values in this order:
///   0: masterSecret (echo back)
///   1: proveSpendKey       = H_n("Carrot prove-spend key", masterSecret)
///   2: viewBalanceSecret   = H_32("Carrot view-balance secret", masterSecret)
///   3: generateImageKey    = H_n("Carrot generate-image key", viewBalanceSecret)
///   4: viewIncomingKey     = H_n("Carrot incoming view key", viewBalanceSecret)
///   5: generateAddressSecret = H_32("Carrot generate-address secret", viewBalanceSecret)
///   6: accountSpendPubkey  = k_gi*G + k_ps*T
///   7: primaryAddressViewPubkey = k_vi*G
///   8: accountViewPubkey   = k_vi*K_s
pub fn derive_carrot_keys(master_secret: &[u8; 32]) -> [u8; 288] {
    let mut out = [0u8; 288];

    // Secrets
    let prove_spend_key = derive_scalar(DOMAIN_PROVE_SPEND_KEY, master_secret);
    let view_balance_secret = derive_bytes_32(DOMAIN_VIEW_BALANCE_SECRET, master_secret);
    let generate_image_key = derive_scalar(DOMAIN_GENERATE_IMAGE_KEY, &view_balance_secret);
    let view_incoming_key = derive_scalar(DOMAIN_INCOMING_VIEW_KEY, &view_balance_secret);
    let generate_address_secret = derive_bytes_32(DOMAIN_GENERATE_ADDRESS_SECRET, &view_balance_secret);

    // K_s = k_gi*G + k_ps*T
    let t_point = CompressedEdwardsY(T_BYTES).decompress().expect("invalid T");
    let account_spend_pubkey = EdwardsPoint::vartime_multiscalar_mul(
        &[generate_image_key, prove_spend_key],
        &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, t_point],
    );

    // K^0_v = k_vi*G (primary address view pubkey)
    let primary_address_view_pubkey = ED25519_BASEPOINT_TABLE * &view_incoming_key;

    // K_v = k_vi*K_s (account view pubkey for subaddress derivation)
    let account_view_pubkey = EdwardsPoint::vartime_multiscalar_mul(
        &[view_incoming_key],
        &[account_spend_pubkey],
    );

    // Pack into output buffer
    out[0..32].copy_from_slice(master_secret);
    out[32..64].copy_from_slice(&prove_spend_key.to_bytes());
    out[64..96].copy_from_slice(&view_balance_secret);
    out[96..128].copy_from_slice(&generate_image_key.to_bytes());
    out[128..160].copy_from_slice(&view_incoming_key.to_bytes());
    out[160..192].copy_from_slice(&generate_address_secret);
    out[192..224].copy_from_slice(&account_spend_pubkey.compress().to_bytes());
    out[224..256].copy_from_slice(&primary_address_view_pubkey.compress().to_bytes());
    out[256..288].copy_from_slice(&account_view_pubkey.compress().to_bytes());

    out
}

/// Derive CARROT keys for view-only wallet.
///
/// Returns 224 bytes: 7 contiguous 32-byte values in this order:
///   0: viewBalanceSecret (echo back)
///   1: viewIncomingKey     = H_n("Carrot incoming view key", viewBalanceSecret)
///   2: generateImageKey    = H_n("Carrot generate-image key", viewBalanceSecret)
///   3: generateAddressSecret = H_32("Carrot generate-address secret", viewBalanceSecret)
///   4: accountSpendPubkey  (echo back — can't be derived from viewBalanceSecret)
///   5: primaryAddressViewPubkey = k_vi*G
///   6: accountViewPubkey   = k_vi*K_s
pub fn derive_carrot_view_only_keys(
    view_balance_secret: &[u8; 32],
    account_spend_pubkey: &[u8; 32],
) -> [u8; 224] {
    let mut out = [0u8; 224];

    let view_incoming_key = derive_scalar(DOMAIN_INCOMING_VIEW_KEY, view_balance_secret);
    let generate_image_key = derive_scalar(DOMAIN_GENERATE_IMAGE_KEY, view_balance_secret);
    let generate_address_secret = derive_bytes_32(DOMAIN_GENERATE_ADDRESS_SECRET, view_balance_secret);

    // K^0_v = k_vi*G
    let primary_address_view_pubkey = ED25519_BASEPOINT_TABLE * &view_incoming_key;

    // K_v = k_vi*K_s
    let ks_point = match CompressedEdwardsY(*account_spend_pubkey).decompress() {
        Some(pt) => pt,
        None => return out, // invalid — return zeros
    };
    let account_view_pubkey = EdwardsPoint::vartime_multiscalar_mul(
        &[view_incoming_key],
        &[ks_point],
    );

    out[0..32].copy_from_slice(view_balance_secret);
    out[32..64].copy_from_slice(&view_incoming_key.to_bytes());
    out[64..96].copy_from_slice(&generate_image_key.to_bytes());
    out[96..128].copy_from_slice(&generate_address_secret);
    out[128..160].copy_from_slice(account_spend_pubkey);
    out[160..192].copy_from_slice(&primary_address_view_pubkey.compress().to_bytes());
    out[192..224].copy_from_slice(&account_view_pubkey.compress().to_bytes());

    out
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_carrot_keys_deterministic() {
        let master = [0x42u8; 32];
        let k1 = derive_carrot_keys(&master);
        let k2 = derive_carrot_keys(&master);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_carrot_keys_echoes_master() {
        let master = [0x99u8; 32];
        let keys = derive_carrot_keys(&master);
        assert_eq!(&keys[0..32], &master);
    }

    #[test]
    fn test_derive_carrot_keys_all_different() {
        let master = [0x01u8; 32];
        let keys = derive_carrot_keys(&master);
        // All 9 keys should be different from each other
        for i in 0..9 {
            for j in (i+1)..9 {
                assert_ne!(
                    &keys[i*32..(i+1)*32],
                    &keys[j*32..(j+1)*32],
                    "keys at index {} and {} should differ", i, j
                );
            }
        }
    }

    #[test]
    fn test_derive_view_only_consistent_with_full() {
        let master = [0x55u8; 32];
        let full = derive_carrot_keys(&master);

        // Extract viewBalanceSecret and accountSpendPubkey from full derivation
        let vbs = &full[64..96];  // viewBalanceSecret
        let ks = &full[192..224]; // accountSpendPubkey

        let mut vbs_arr = [0u8; 32];
        let mut ks_arr = [0u8; 32];
        vbs_arr.copy_from_slice(vbs);
        ks_arr.copy_from_slice(ks);

        let view_only = derive_carrot_view_only_keys(&vbs_arr, &ks_arr);

        // viewBalanceSecret should match
        assert_eq!(&view_only[0..32], vbs);
        // viewIncomingKey should match (index 4 in full = index 1 in view-only)
        assert_eq!(&view_only[32..64], &full[128..160]);
        // generateImageKey should match (index 3 in full = index 2 in view-only)
        assert_eq!(&view_only[64..96], &full[96..128]);
        // generateAddressSecret should match (index 5 in full = index 3 in view-only)
        assert_eq!(&view_only[96..128], &full[160..192]);
        // accountSpendPubkey should match
        assert_eq!(&view_only[128..160], ks);
        // primaryAddressViewPubkey should match (index 7 in full = index 5 in view-only)
        assert_eq!(&view_only[160..192], &full[224..256]);
        // accountViewPubkey should match (index 8 in full = index 6 in view-only)
        assert_eq!(&view_only[192..224], &full[256..288]);
    }
}
