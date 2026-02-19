//! CryptoNote (pre-CARROT) output scanning — full pipeline in Rust.
//!
//! Replaces 5-12 individual FFI round-trips per output with a single native
//! call, matching the pattern established by `carrot_scan.rs` for CARROT.
//!
//! Entry point: `scan_cryptonote_output`

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use crate::{keccak256_internal, to32};
use crate::subaddress::cn_subaddress_secret_key;

// ─── Result ─────────────────────────────────────────────────────────────────

pub struct CnScanResult {
    pub amount: u64,
    pub mask: [u8; 32],
    pub subaddress_major: u32,
    pub subaddress_minor: u32,
    pub key_image: Option<[u8; 32]>,
}

#[cfg(not(target_arch = "wasm32"))]
impl CnScanResult {
    pub fn to_json(&self) -> Vec<u8> {
        let ki = self.key_image.map(hex::encode);
        let json = serde_json::json!({
            "amount": self.amount,
            "mask": hex::encode(self.mask),
            "subaddress_major": self.subaddress_major,
            "subaddress_minor": self.subaddress_minor,
            "key_image": ki,
        });
        serde_json::to_vec(&json).unwrap()
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn encode_varint(mut val: u32, buf: &mut Vec<u8>) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// H_s(derivation || varint(index)) — derivation_to_scalar
fn derivation_to_scalar(derivation: &[u8; 32], output_index: u32) -> Scalar {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(derivation);
    encode_varint(output_index, &mut buf);
    let hash = keccak256_internal(&buf);
    Scalar::from_bytes_mod_order(hash)
}

/// Hash-to-point: H_p(data) = 8 * elligator2(keccak256(data))
fn hash_to_point(data: &[u8]) -> EdwardsPoint {
    let hash = keccak256_internal(data);
    let point = crate::elligator2::ge_fromfe_frombytes_vartime(&hash);
    let t = point + point; // 2P
    let t = t + t;         // 4P
    t + t                  // 8P
}

/// Generate key image: KI = sec * H_p(pub)
fn generate_key_image(pub_key: &[u8; 32], sec_key: &Scalar) -> [u8; 32] {
    let hp = hash_to_point(pub_key);
    EdwardsPoint::vartime_multiscalar_mul(&[*sec_key], &[hp])
        .compress()
        .to_bytes()
}

/// CryptoNote view tag: keccak256("view_tag" || derivation || varint(index))[0]
pub fn derive_view_tag(derivation: &[u8; 32], output_index: u32) -> u8 {
    let salt = b"view_tag";
    let mut buf = Vec::with_capacity(salt.len() + 32 + 5);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(derivation);
    encode_varint(output_index, &mut buf);
    keccak256_internal(&buf)[0]
}

/// Derive subaddress public key: Ko - H_s(D || index) * G
fn derive_subaddress_pubkey(
    output_pubkey: &EdwardsPoint,
    derivation: &[u8; 32],
    output_index: u32,
) -> [u8; 32] {
    let scalar = derivation_to_scalar(derivation, output_index);
    let scalar_g = ED25519_BASEPOINT_TABLE * &scalar;
    (output_pubkey - scalar_g).compress().to_bytes()
}

/// Compute shared secret for ECDH amount decryption: H_s(D || index)
fn compute_shared_secret(derivation: &[u8; 32], output_index: u32) -> [u8; 32] {
    let scalar = derivation_to_scalar(derivation, output_index);
    scalar.to_bytes()
}

/// Generate amount encoding factor: keccak256("amount" || sharedSecret)
fn gen_amount_encoding_factor(shared_secret: &[u8; 32]) -> [u8; 32] {
    let prefix = b"amount";
    let mut buf = Vec::with_capacity(prefix.len() + 32);
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(shared_secret);
    keccak256_internal(&buf)
}

/// ECDH encode amount: XOR first 8 bytes of keccak256("amount" || sharedSecret)
pub fn ecdh_encode_amount(amount: u64, shared_secret: &[u8; 32]) -> [u8; 8] {
    let factor = gen_amount_encoding_factor(shared_secret);
    let amount_le = amount.to_le_bytes();
    let mut enc = [0u8; 8];
    for i in 0..8 {
        enc[i] = amount_le[i] ^ factor[i];
    }
    enc
}

/// ECDH decode amount: XOR first 8 bytes of keccak256("amount" || sharedSecret)
fn ecdh_decode_amount(encrypted_amount: &[u8; 8], shared_secret: &[u8; 32]) -> u64 {
    let factor = gen_amount_encoding_factor(shared_secret);
    let mut decrypted = [0u8; 8];
    for i in 0..8 {
        decrypted[i] = encrypted_amount[i] ^ factor[i];
    }
    u64::from_le_bytes(decrypted)
}

/// Generate commitment mask: scReduce32(keccak256("commitment_mask" || sharedSecret))
pub fn gen_commitment_mask(shared_secret: &[u8; 32]) -> [u8; 32] {
    let prefix = b"commitment_mask";
    let mut buf = Vec::with_capacity(prefix.len() + 32);
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(shared_secret);
    let hash = keccak256_internal(&buf);
    Scalar::from_bytes_mod_order(hash).to_bytes()
}

// ─── Core scanning ──────────────────────────────────────────────────────────

/// Scan a CryptoNote output in a single call.
///
/// `subaddrs`: slice of (32-byte spend pubkey, major, minor) tuples.
///
/// Returns `Some(CnScanResult)` if the output belongs to us, `None` otherwise.
#[allow(clippy::too_many_arguments)]
pub fn scan_cryptonote_output(
    output_pubkey: &[u8; 32],
    derivation: &[u8; 32],
    output_index: u32,
    view_tag: Option<u8>,
    rct_type: u8,
    clear_text_amount: Option<u64>,
    ecdh_encrypted_amount: &[u8; 8],
    spend_secret_key: Option<&[u8; 32]>,
    view_secret_key: &[u8; 32],
    subaddrs: &[([u8; 32], u32, u32)],
) -> Option<CnScanResult> {
    // Step 1: View tag fast-reject
    if let Some(expected_vt) = view_tag {
        let computed_vt = derive_view_tag(derivation, output_index);
        if expected_vt != computed_vt {
            return None;
        }
    }

    // Step 2: Derive subaddress public key (reverse derivation)
    // Ko_derived = Ko - H_s(D || index) * G
    let ko_point = CompressedEdwardsY(*output_pubkey).decompress()?;
    let derived_spend_pubkey = derive_subaddress_pubkey(&ko_point, derivation, output_index);

    // Step 3: Subaddress map lookup
    // Check main address first (index 0 in subaddrs, or compare directly)
    let mut major = 0u32;
    let mut minor = 0u32;
    let mut found = false;

    for (pubkey, maj, min) in subaddrs {
        if derived_spend_pubkey == *pubkey {
            major = *maj;
            minor = *min;
            found = true;
            break;
        }
    }

    if !found {
        return None;
    }

    // Step 4: Amount decryption
    let amount;
    let mask;

    if rct_type == 0 {
        // Coinbase: clear text amount, identity mask
        amount = clear_text_amount.unwrap_or(0);
        // Identity mask (scalar 1) for coinbase
        let mut identity = [0u8; 32];
        identity[0] = 1;
        mask = identity;
    } else {
        // RCT: decrypt from ECDH info
        let shared_secret = compute_shared_secret(derivation, output_index);
        amount = ecdh_decode_amount(ecdh_encrypted_amount, &shared_secret);
        mask = gen_commitment_mask(&shared_secret);
    }

    // Step 5: Key image generation (if spend key available)
    let key_image = if let Some(spend_key) = spend_secret_key {
        let spend_scalar = Scalar::from_bytes_mod_order(to32(spend_key));

        let base_spend = if major != 0 || minor != 0 {
            // Subaddress: spend_key + H_s("SubAddr\0" || view_key || major || minor)
            let m = cn_subaddress_secret_key(view_secret_key, major, minor);
            spend_scalar + m
        } else {
            spend_scalar
        };

        // output_secret_key = base_spend + H_s(D || index)
        let d2s = derivation_to_scalar(derivation, output_index);
        let output_secret_key = base_spend + d2s;

        Some(generate_key_image(output_pubkey, &output_secret_key))
    } else {
        None
    };

    Some(CnScanResult {
        amount,
        mask,
        subaddress_major: major,
        subaddress_minor: minor,
        key_image,
    })
}

// ─── Key Derivation for Spending ─────────────────────────────────────────────

/// Derive the one-time spend secret key for a CryptoNote output.
///
/// Reconstructs the secret key needed to sign a transaction that spends this
/// output. All parameters come from the wallet's master keys and the stored
/// output metadata (`OutputRow`).
///
/// For main address outputs (major=0, minor=0):
///   output_secret = spend_secret + H_s(view_secret * tx_pubkey || index)
///
/// For subaddress outputs:
///   output_secret = spend_secret + subaddr_key(major, minor)
///                   + H_s(view_secret * tx_pubkey || index)
pub fn derive_output_spend_key(
    view_secret_key: &[u8; 32],
    spend_secret_key: &[u8; 32],
    tx_pub_key: &[u8; 32],
    output_index: u32,
    subaddress_major: u32,
    subaddress_minor: u32,
) -> [u8; 32] {
    let view_scalar = Scalar::from_bytes_mod_order(to32(view_secret_key));

    // derivation = 8 * (view_secret * tx_pub_key) — CryptoNote cofactor multiplication
    let tx_pub = CompressedEdwardsY(to32(tx_pub_key))
        .decompress()
        .expect("invalid tx pubkey");
    let shared = view_scalar * tx_pub;
    let t = shared + shared; // 2P
    let t = t + t;           // 4P
    let derivation = (t + t).compress().to_bytes(); // 8P

    let d2s = derivation_to_scalar(&derivation, output_index);
    let spend_scalar = Scalar::from_bytes_mod_order(to32(spend_secret_key));

    let base_spend = if subaddress_major != 0 || subaddress_minor != 0 {
        let m = crate::subaddress::cn_subaddress_secret_key(
            view_secret_key,
            subaddress_major,
            subaddress_minor,
        );
        spend_scalar + m
    } else {
        spend_scalar
    };

    (base_spend + d2s).to_bytes()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_tag_deterministic() {
        let deriv = [0x42u8; 32];
        let vt1 = derive_view_tag(&deriv, 0);
        let vt2 = derive_view_tag(&deriv, 0);
        assert_eq!(vt1, vt2);
    }

    #[test]
    fn test_view_tag_varies_by_index() {
        let deriv = [0x42u8; 32];
        let vt0 = derive_view_tag(&deriv, 0);
        let vt1 = derive_view_tag(&deriv, 1);
        // Extremely unlikely to match
        assert_ne!(vt0, vt1);
    }

    #[test]
    fn test_ecdh_decode_amount_roundtrip() {
        let shared_secret = [0x55u8; 32];
        let amount: u64 = 123456789;
        let factor = gen_amount_encoding_factor(&shared_secret);
        let amount_le = amount.to_le_bytes();
        let mut enc = [0u8; 8];
        for i in 0..8 {
            enc[i] = amount_le[i] ^ factor[i];
        }
        let decoded = ecdh_decode_amount(&enc, &shared_secret);
        assert_eq!(decoded, amount);
    }

    #[test]
    fn test_commitment_mask_deterministic() {
        let ss = [0x33u8; 32];
        let m1 = gen_commitment_mask(&ss);
        let m2 = gen_commitment_mask(&ss);
        assert_eq!(m1, m2);
        // Should not be all zeros
        assert!(!m1.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_scan_view_tag_mismatch_returns_none() {
        let ko = [0x58u8; 32]; // G
        let derivation = [0x42u8; 32];
        let enc_amount = [0u8; 8];
        let view_key = [0x01u8; 32];
        let subaddrs: Vec<([u8; 32], u32, u32)> = vec![];

        let result = scan_cryptonote_output(
            &ko,
            &derivation,
            0,
            Some(0xFF), // wrong view tag
            1,
            None,
            &enc_amount,
            None,
            &view_key,
            &subaddrs,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_scan_no_matching_subaddress_returns_none() {
        let ko = [0x58u8; 32]; // G
        let derivation = [0x42u8; 32];
        let enc_amount = [0u8; 8];
        let view_key = [0x01u8; 32];
        // Empty subaddress map — nothing to match
        let subaddrs: Vec<([u8; 32], u32, u32)> = vec![];

        let result = scan_cryptonote_output(
            &ko,
            &derivation,
            0,
            None, // skip view tag check
            1,
            None,
            &enc_amount,
            None,
            &view_key,
            &subaddrs,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_derivation_to_scalar_matches_lib() {
        // Verify our local derivation_to_scalar matches lib.rs
        let derivation = [0x11u8; 32];
        let s1 = derivation_to_scalar(&derivation, 0);
        let s2 = crate::derivation_to_scalar(&derivation, 0);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_key_image_generation_matches_lib() {
        // Generate a known keypair: secret = 1, public = G
        let secret = Scalar::ONE;
        let public = (ED25519_BASEPOINT_TABLE * &secret).compress().to_bytes();

        let ki = generate_key_image(&public, &secret);
        let ki_lib = crate::generate_key_image(&public, &secret.to_bytes());

        assert_eq!(ki.to_vec(), ki_lib);
    }
}
