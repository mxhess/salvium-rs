//! CARROT output scanning — full 7-step pipeline in Rust.
//!
//! Moves the entire scan from JS (which hairpins every crypto op through FFI)
//! into a single native call.  Two entry points:
//!
//! * `scan_carrot_output` — standard path: X25519 ECDH → core steps 2-7
//! * `scan_carrot_internal_output` — self-send path: viewBalanceSecret used
//!   directly as s_sr_unctx (skips X25519)

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use crate::to32;

// T generator — same bytes as tclsag.rs and JS side
pub const T_BYTES: [u8; 32] = [
    0x96, 0x6f, 0xc6, 0x6b, 0x82, 0xcd, 0x56, 0xcf,
    0x85, 0xea, 0xec, 0x80, 0x1c, 0x42, 0x84, 0x5f,
    0x5f, 0x40, 0x88, 0x78, 0xd1, 0x56, 0x1e, 0x00,
    0xd3, 0xd7, 0xde, 0xd2, 0x79, 0x4d, 0x09, 0x4f,
];

/// H generator for Pedersen commitments (same as lib.rs)
const H_POINT_BYTES: [u8; 32] = crate::H_POINT_BYTES;

// ─── Domain separators (matching config.h) ──────────────────────────────────

const DOMAIN_VIEW_TAG: &[u8] = b"Carrot view tag";
const DOMAIN_SENDER_RECEIVER_SECRET: &[u8] = b"Carrot sender-receiver secret";
const DOMAIN_COMMITMENT_MASK: &[u8] = b"Carrot commitment mask";
const DOMAIN_EXTENSION_G: &[u8] = b"Carrot key extension G";
const DOMAIN_EXTENSION_T: &[u8] = b"Carrot key extension T";
const DOMAIN_ENCRYPTION_MASK_AMOUNT: &[u8] = b"Carrot encryption mask a";

// ─── Result ─────────────────────────────────────────────────────────────────

/// Result of a successful CARROT scan.
pub struct CarrotScanResult {
    pub amount: u64,
    pub mask: [u8; 32],
    /// 0 = PAYMENT, 1 = CHANGE
    pub enote_type: u8,
    pub shared_secret: [u8; 32],
    pub address_spend_pubkey: [u8; 32],
    pub subaddress_major: u32,
    pub subaddress_minor: u32,
    pub is_main_address: bool,
}

/// Serialize result to JSON with hex-encoded byte arrays.
#[cfg(not(target_arch = "wasm32"))]
impl CarrotScanResult {
    pub fn to_json(&self) -> Vec<u8> {
        let json = serde_json::json!({
            "amount": self.amount,
            "mask": hex::encode(self.mask),
            "enote_type": self.enote_type,
            "shared_secret": hex::encode(self.shared_secret),
            "address_spend_pubkey": hex::encode(self.address_spend_pubkey),
            "subaddress_major": self.subaddress_major,
            "subaddress_minor": self.subaddress_minor,
            "is_main_address": self.is_main_address,
        });
        serde_json::to_vec(&json).unwrap()
    }
}

// ─── Transcript builder (SpFixedTranscript) ─────────────────────────────────

/// Build `[domain_len_byte] + domain + data...`
pub fn build_transcript(domain: &[u8], data: &[&[u8]]) -> Vec<u8> {
    let total: usize = 1 + domain.len() + data.iter().map(|d| d.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.push(domain.len() as u8);
    buf.extend_from_slice(domain);
    for d in data {
        buf.extend_from_slice(d);
    }
    buf
}

/// Keyed blake2b with given output length.
fn blake2b_keyed(transcript: &[u8], out_len: usize, key: &[u8]) -> Vec<u8> {
    blake2b_simd::Params::new()
        .hash_length(out_len)
        .key(key)
        .hash(transcript)
        .as_bytes()
        .to_vec()
}

/// H_n: blake2b 64 bytes keyed, then sc_reduce to 32-byte scalar.
fn derive_scalar(key: &[u8], domain: &[u8], data: &[&[u8]]) -> Scalar {
    let transcript = build_transcript(domain, data);
    let hash64 = blake2b_keyed(&transcript, 64, key);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash64);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// H_32: blake2b 32 bytes keyed.
fn derive_bytes_32(key: &[u8], domain: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let transcript = build_transcript(domain, data);
    let hash = blake2b_keyed(&transcript, 32, key);
    to32(&hash)
}

/// H_8: blake2b 8 bytes keyed.
fn derive_bytes_8(key: &[u8], domain: &[u8], data: &[&[u8]]) -> [u8; 8] {
    let transcript = build_transcript(domain, data);
    let hash = blake2b_keyed(&transcript, 8, key);
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

// ─── Core scanning steps ────────────────────────────────────────────────────

/// Step 2: View tag test (3-byte fast filter).
pub fn compute_view_tag(s_sr_unctx: &[u8; 32], input_context: &[u8], ko: &[u8; 32]) -> [u8; 3] {
    let transcript = build_transcript(DOMAIN_VIEW_TAG, &[input_context, ko]);
    let hash = blake2b_keyed(&transcript, 3, s_sr_unctx);
    [hash[0], hash[1], hash[2]]
}

/// Step 3: Contextualized shared secret.
fn make_sender_receiver_secret(
    s_sr_unctx: &[u8; 32],
    d_e: &[u8; 32],
    input_context: &[u8],
) -> [u8; 32] {
    derive_bytes_32(s_sr_unctx, DOMAIN_SENDER_RECEIVER_SECRET, &[d_e, input_context])
}

/// Step 4a: k^o_g = H_n[s_sr_ctx]("Carrot key extension G", C_a)
fn derive_extension_g(s_sr_ctx: &[u8; 32], commitment: &[u8; 32]) -> Scalar {
    derive_scalar(s_sr_ctx, DOMAIN_EXTENSION_G, &[commitment])
}

/// Step 4b: k^o_t = H_n[s_sr_ctx]("Carrot key extension T", C_a)
fn derive_extension_t(s_sr_ctx: &[u8; 32], commitment: &[u8; 32]) -> Scalar {
    derive_scalar(s_sr_ctx, DOMAIN_EXTENSION_T, &[commitment])
}

/// Step 4: Recover address spend pubkey.
/// K^j_s = Ko - (k^o_g * G + k^o_t * T)
pub fn recover_address_spend_pubkey(
    ko: &[u8; 32],
    s_sr_ctx: &[u8; 32],
    commitment: &[u8; 32],
) -> Option<[u8; 32]> {
    let k_g = derive_extension_g(s_sr_ctx, commitment);
    let k_t = derive_extension_t(s_sr_ctx, commitment);

    let t_point = CompressedEdwardsY(T_BYTES).decompress()?;
    let ko_point = CompressedEdwardsY(*ko).decompress()?;

    // K^o_ext = k_g * G + k_t * T
    let ext = EdwardsPoint::vartime_multiscalar_mul(
        &[k_g, k_t],
        &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, t_point],
    );

    // K^j_s = Ko - ext
    let recovered = ko_point - ext;
    Some(recovered.compress().to_bytes())
}

/// Step 6: Decrypt amount.
pub fn decrypt_amount(
    enc_amount: &[u8; 8],
    s_sr_ctx: &[u8; 32],
    ko: &[u8; 32],
) -> u64 {
    let mask = derive_bytes_8(s_sr_ctx, DOMAIN_ENCRYPTION_MASK_AMOUNT, &[ko]);
    let mut decrypted = [0u8; 8];
    for i in 0..8 {
        decrypted[i] = enc_amount[i] ^ mask[i];
    }
    u64::from_le_bytes(decrypted)
}

/// Step 7a: Derive commitment mask.
pub fn derive_commitment_mask(
    s_sr_ctx: &[u8; 32],
    amount: u64,
    address_spend_pubkey: &[u8; 32],
    enote_type: u8,
) -> Scalar {
    let amount_bytes = amount.to_le_bytes();
    let type_byte = [enote_type];
    derive_scalar(
        s_sr_ctx,
        DOMAIN_COMMITMENT_MASK,
        &[&amount_bytes, address_spend_pubkey, &type_byte],
    )
}

/// Step 7b: Compute Pedersen commitment and compare.
fn pedersen_commit(amount: u64, mask: &Scalar) -> [u8; 32] {
    let h = CompressedEdwardsY(H_POINT_BYTES).decompress().expect("invalid H");
    let mut amount_bytes = [0u8; 32];
    let le = amount.to_le_bytes();
    amount_bytes[..8].copy_from_slice(&le);
    let amount_scalar = Scalar::from_bytes_mod_order(amount_bytes);
    EdwardsPoint::vartime_multiscalar_mul(
        &[*mask, amount_scalar],
        &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, h],
    )
    .compress()
    .to_bytes()
}

// ─── Core scan (steps 2-7) ──────────────────────────────────────────────────

/// Run the core CARROT scan steps 2-7 given an uncontextualized shared secret.
///
/// `subaddress_map`: slice of (32-byte spend pubkey, major, minor) tuples.
/// `account_spend_pubkey`: the main account K_s.
/// `clear_text_amount`: if Some, use this instead of decrypting (coinbase).
#[allow(clippy::too_many_arguments)]
fn scan_core(
    s_sr_unctx: &[u8; 32],
    ko: &[u8; 32],
    view_tag: &[u8; 3],
    d_e: &[u8; 32],
    enc_amount: &[u8; 8],
    commitment: Option<&[u8; 32]>,
    account_spend_pubkey: &[u8; 32],
    input_context: &[u8],
    subaddress_map: &[([u8; 32], u32, u32)],
    clear_text_amount: Option<u64>,
) -> Option<CarrotScanResult> {
    // Step 2: View tag test
    let expected_vt = compute_view_tag(s_sr_unctx, input_context, ko);
    if expected_vt != *view_tag {
        return None;
    }

    // Step 3: Contextualized shared secret
    let s_sr_ctx = make_sender_receiver_secret(s_sr_unctx, d_e, input_context);

    // Step 4: Recover address spend pubkey
    let commit_bytes = commitment.copied().unwrap_or([0u8; 32]);
    let recovered = recover_address_spend_pubkey(ko, &s_sr_ctx, &commit_bytes)?;

    // Step 5: Address matching
    let mut is_main_address = false;
    let mut major = 0u32;
    let mut minor = 0u32;

    if recovered == *account_spend_pubkey {
        is_main_address = true;
    } else {
        let mut found = false;
        for (pubkey, maj, min) in subaddress_map {
            if recovered == *pubkey {
                major = *maj;
                minor = *min;
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
    }

    // Step 6: Decrypt amount
    let amount = if let Some(ct) = clear_text_amount {
        ct
    } else {
        decrypt_amount(enc_amount, &s_sr_ctx, ko)
    };

    // Step 7: Derive commitment mask, try PAYMENT(0) then CHANGE(1)
    let mask_payment = derive_commitment_mask(&s_sr_ctx, amount, &recovered, 0);
    let (mask, enote_type) = if let Some(c) = commitment {
        let computed_payment = pedersen_commit(amount, &mask_payment);
        if computed_payment == *c {
            (mask_payment, 0u8)
        } else {
            let mask_change = derive_commitment_mask(&s_sr_ctx, amount, &recovered, 1);
            let computed_change = pedersen_commit(amount, &mask_change);
            if computed_change == *c {
                (mask_change, 1u8)
            } else {
                // Neither matched — fallback to PAYMENT (coinbase-like)
                (mask_payment, 0u8)
            }
        }
    } else {
        // No commitment to verify (coinbase) — PAYMENT
        (mask_payment, 0u8)
    };

    Some(CarrotScanResult {
        amount,
        mask: mask.to_bytes(),
        enote_type,
        shared_secret: s_sr_ctx,
        address_spend_pubkey: recovered,
        subaddress_major: major,
        subaddress_minor: minor,
        is_main_address,
    })
}

// ─── Public entry points ────────────────────────────────────────────────────

/// Standard CARROT scan: X25519 ECDH then core steps 2-7.
#[allow(clippy::too_many_arguments)]
pub fn scan_carrot_output(
    ko: &[u8; 32],
    view_tag: &[u8; 3],
    d_e: &[u8; 32],
    enc_amount: &[u8; 8],
    commitment: Option<&[u8; 32]>,
    k_vi: &[u8; 32],
    account_spend_pubkey: &[u8; 32],
    input_context: &[u8],
    subaddress_map: &[([u8; 32], u32, u32)],
    clear_text_amount: Option<u64>,
) -> Option<CarrotScanResult> {
    // Step 1: X25519 ECDH — s_sr_unctx = k_vi * D_e
    let mut clamped = *k_vi;
    clamped[31] &= 0x7F;
    let s_sr_unctx = to32(&crate::x25519::montgomery_ladder(&clamped, d_e));

    scan_core(
        &s_sr_unctx,
        ko, view_tag, d_e, enc_amount, commitment,
        account_spend_pubkey, input_context, subaddress_map,
        clear_text_amount,
    )
}

/// Self-send CARROT scan: viewBalanceSecret used directly as s_sr_unctx.
#[allow(clippy::too_many_arguments)]
pub fn scan_carrot_internal_output(
    ko: &[u8; 32],
    view_tag: &[u8; 3],
    d_e: &[u8; 32],
    enc_amount: &[u8; 8],
    commitment: Option<&[u8; 32]>,
    view_balance_secret: &[u8; 32],
    account_spend_pubkey: &[u8; 32],
    input_context: &[u8],
    subaddress_map: &[([u8; 32], u32, u32)],
    clear_text_amount: Option<u64>,
) -> Option<CarrotScanResult> {
    scan_core(
        view_balance_secret,
        ko, view_tag, d_e, enc_amount, commitment,
        account_spend_pubkey, input_context, subaddress_map,
        clear_text_amount,
    )
}

// ─── Key Derivation for Spending ─────────────────────────────────────────────

/// Derive the CARROT one-time spend keys for a CARROT output.
///
/// Returns `(secret_key_x, secret_key_y)` where:
///   secret_key_x = prove_spend_key + k^o_g
///   secret_key_y = generate_image_key + k^o_t
///
/// These are used with TCLSAG signing (dual-key ring signatures).
///
/// Parameters:
/// - `prove_spend_key`: from `CarrotKeys.prove_spend_key`
/// - `generate_image_key`: from `CarrotKeys.generate_image_key`
/// - `s_sr_ctx`: the contextualized shared secret (stored in OutputRow.carrot_shared_secret)
/// - `commitment`: the output commitment (stored in OutputRow.commitment)
pub fn derive_carrot_spend_keys(
    prove_spend_key: &[u8; 32],
    generate_image_key: &[u8; 32],
    s_sr_ctx: &[u8; 32],
    commitment: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let k_g = derive_extension_g(s_sr_ctx, commitment);
    let k_t = derive_extension_t(s_sr_ctx, commitment);

    let psk = Scalar::from_bytes_mod_order(*prove_spend_key);
    let gik = Scalar::from_bytes_mod_order(*generate_image_key);

    // x = generate_image_key + k^o_g  (scales G)
    // y = prove_spend_key + k^o_t     (scales T)
    let secret_x = (gik + k_g).to_bytes();
    let secret_y = (psk + k_t).to_bytes();

    (secret_x, secret_y)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_tag_deterministic() {
        let s_sr = [0x42u8; 32];
        let input_ctx = [0x52u8; 33]; // 'R' + 32 zero bytes
        let ko = [0x58u8; 32]; // G point
        let vt1 = compute_view_tag(&s_sr, &input_ctx, &ko);
        let vt2 = compute_view_tag(&s_sr, &input_ctx, &ko);
        assert_eq!(vt1, vt2);
        assert_ne!(vt1, [0, 0, 0]); // extremely unlikely to be all-zero
    }

    #[test]
    fn test_sender_receiver_secret_deterministic() {
        let s_sr_unctx = [0x01u8; 32];
        let d_e = [0x09u8; 32];
        let input_ctx = [0x43u8; 33];
        let s1 = make_sender_receiver_secret(&s_sr_unctx, &d_e, &input_ctx);
        let s2 = make_sender_receiver_secret(&s_sr_unctx, &d_e, &input_ctx);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_decrypt_amount_roundtrip() {
        let s_sr_ctx = [0x55u8; 32];
        let ko = [0x58u8; 32];
        let amount: u64 = 123456789;
        // Encrypt
        let mask = derive_bytes_8(&s_sr_ctx, DOMAIN_ENCRYPTION_MASK_AMOUNT, &[&ko]);
        let amount_le = amount.to_le_bytes();
        let mut enc = [0u8; 8];
        for i in 0..8 {
            enc[i] = amount_le[i] ^ mask[i];
        }
        // Decrypt
        let decrypted = decrypt_amount(&enc, &s_sr_ctx, &ko);
        assert_eq!(decrypted, amount);
    }

    #[test]
    fn test_commitment_mask_differs_by_enote_type() {
        let s_sr_ctx = [0x33u8; 32];
        let amount = 1000u64;
        let addr = [0x58u8; 32];
        let mask0 = derive_commitment_mask(&s_sr_ctx, amount, &addr, 0);
        let mask1 = derive_commitment_mask(&s_sr_ctx, amount, &addr, 1);
        assert_ne!(mask0.to_bytes(), mask1.to_bytes());
    }

    #[test]
    fn test_pedersen_commit_deterministic() {
        let mask = Scalar::from(42u64);
        let c1 = pedersen_commit(100, &mask);
        let c2 = pedersen_commit(100, &mask);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_view_tag_mismatch_returns_none() {
        let s_sr = [0x42u8; 32];
        let ko = [0x58u8; 32]; // G
        let view_tag = [0xff, 0xff, 0xff]; // wrong
        let d_e = [9u8; 32];
        let enc_amount = [0u8; 8];
        let ks = [0x58u8; 32];
        let input_ctx = [0x52u8; 33];

        let result = scan_carrot_output(
            &ko, &view_tag, &d_e, &enc_amount, None,
            &s_sr, &ks, &input_ctx, &[], None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_transcript_format() {
        let t = build_transcript(b"test", &[&[1, 2], &[3, 4, 5]]);
        assert_eq!(t.len(), 1 + 4 + 2 + 3);
        assert_eq!(t[0], 4); // domain length
        assert_eq!(&t[1..5], b"test");
        assert_eq!(&t[5..7], &[1, 2]);
        assert_eq!(&t[7..10], &[3, 4, 5]);
    }
}
