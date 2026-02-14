//! Batch subaddress map generation for CryptoNote and CARROT.
//!
//! Generates the full subaddress lookup map in a single call, eliminating
//! per-entry FFI round-trips. Each function returns a flat binary buffer:
//!
//! Format: `[count: u32 LE] [entry0] [entry1] ...`
//! Entry:  `[spend_pubkey: 32 bytes] [major: u32 LE] [minor: u32 LE]`
//!
//! Total per entry: 40 bytes.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use crate::{to32, keccak256_internal};

// ─── CryptoNote subaddress derivation ────────────────────────────────────────

/// CryptoNote subaddress secret key:
///   m = H_s("SubAddr\0" || view_key || major_LE || minor_LE)
pub(crate) fn cn_subaddress_secret_key(view_secret_key: &[u8; 32], major: u32, minor: u32) -> Scalar {
    let mut data = Vec::with_capacity(8 + 32 + 4 + 4);
    // "SubAddr\0" (8 bytes including null terminator)
    data.extend_from_slice(b"SubAddr\0");
    data.extend_from_slice(view_secret_key);
    data.extend_from_slice(&major.to_le_bytes());
    data.extend_from_slice(&minor.to_le_bytes());
    let hash = keccak256_internal(&data);
    Scalar::from_bytes_mod_order(hash)
}

/// CryptoNote subaddress spend public key:
///   D = K_spend + m*G  (for non-zero indices)
///   D = K_spend         (for 0,0)
fn cn_subaddress_spend_pubkey(
    spend_pubkey: &EdwardsPoint,
    view_secret_key: &[u8; 32],
    major: u32,
    minor: u32,
) -> EdwardsPoint {
    if major == 0 && minor == 0 {
        return *spend_pubkey;
    }
    let m = cn_subaddress_secret_key(view_secret_key, major, minor);
    let m_g = ED25519_BASEPOINT_TABLE * &m;
    spend_pubkey + m_g
}

/// Generate the full CryptoNote subaddress map as a flat binary buffer.
///
/// Iterates major 0..=major_count, minor 0..=minor_count.
/// Returns: `[count: u32 LE] [spend_pub(32) | major(u32 LE) | minor(u32 LE)] ...`
pub fn cn_subaddress_map_batch(
    spend_pubkey: &[u8; 32],
    view_secret_key: &[u8; 32],
    major_count: u32,
    minor_count: u32,
) -> Vec<u8> {
    let total = ((major_count as u64 + 1) * (minor_count as u64 + 1)) as u32;
    let mut buf = Vec::with_capacity(4 + total as usize * 40);
    buf.extend_from_slice(&total.to_le_bytes());

    let spend_pt = match CompressedEdwardsY(*spend_pubkey).decompress() {
        Some(pt) => pt,
        None => return buf, // invalid point — return count=total but entries will be wrong
    };

    for major in 0..=major_count {
        for minor in 0..=minor_count {
            let sub_spend = cn_subaddress_spend_pubkey(&spend_pt, view_secret_key, major, minor);
            buf.extend_from_slice(&sub_spend.compress().to_bytes());
            buf.extend_from_slice(&major.to_le_bytes());
            buf.extend_from_slice(&minor.to_le_bytes());
        }
    }

    buf
}

// ─── CARROT subaddress derivation ────────────────────────────────────────────

/// Build `[domain_len_byte] + domain + data...` (SpFixedTranscript format)
fn build_transcript(domain: &[u8], data: &[&[u8]]) -> Vec<u8> {
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

/// H_32: blake2b 32 bytes keyed.
fn derive_bytes_32(key: &[u8], domain: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let transcript = build_transcript(domain, data);
    let hash = blake2b_keyed(&transcript, 32, key);
    to32(&hash)
}

/// H_n: blake2b 64 bytes keyed, then sc_reduce to scalar.
fn derive_scalar(key: &[u8], domain: &[u8], data: &[&[u8]]) -> Scalar {
    let transcript = build_transcript(domain, data);
    let hash64 = blake2b_keyed(&transcript, 64, key);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash64);
    Scalar::from_bytes_mod_order_wide(&wide)
}

const DOMAIN_ADDRESS_INDEX_GEN: &[u8] = b"Carrot address index generator";
const DOMAIN_SUBADDRESS_SCALAR: &[u8] = b"Carrot subaddress scalar";

/// CARROT address index extension generator:
///   s^j_gen = H_32[s_ga](domain || major_LE || minor_LE)
fn carrot_index_extension_generator(
    generate_address_secret: &[u8; 32],
    major: u32,
    minor: u32,
) -> [u8; 32] {
    let major_le = major.to_le_bytes();
    let minor_le = minor.to_le_bytes();
    derive_bytes_32(
        generate_address_secret,
        DOMAIN_ADDRESS_INDEX_GEN,
        &[&major_le, &minor_le],
    )
}

/// CARROT subaddress scalar:
///   k^j_subscal = H_n(K_s, major, minor, s^j_gen)
fn carrot_subaddress_scalar(
    account_spend_pubkey: &[u8; 32],
    address_index_generator: &[u8; 32],
    major: u32,
    minor: u32,
) -> Scalar {
    let major_le = major.to_le_bytes();
    let minor_le = minor.to_le_bytes();
    derive_scalar(
        address_index_generator,
        DOMAIN_SUBADDRESS_SCALAR,
        &[account_spend_pubkey, &major_le, &minor_le],
    )
}

/// CARROT subaddress spend public key:
///   K^j_s = k^j_subscal * K_s  (for non-zero indices)
///   K^j_s = K_s                 (for 0,0)
fn carrot_subaddress_spend_pubkey(
    account_spend_pt: &EdwardsPoint,
    account_spend_pubkey: &[u8; 32],
    generate_address_secret: &[u8; 32],
    major: u32,
    minor: u32,
) -> EdwardsPoint {
    if major == 0 && minor == 0 {
        return *account_spend_pt;
    }
    let s_gen = carrot_index_extension_generator(generate_address_secret, major, minor);
    let k_subscal = carrot_subaddress_scalar(account_spend_pubkey, &s_gen, major, minor);
    EdwardsPoint::vartime_multiscalar_mul(&[k_subscal], &[*account_spend_pt])
}

/// Generate the full CARROT subaddress map as a flat binary buffer.
///
/// Iterates major 0..=major_count, minor 0..=minor_count.
/// Returns: `[count: u32 LE] [spend_pub(32) | major(u32 LE) | minor(u32 LE)] ...`
pub fn carrot_subaddress_map_batch(
    account_spend_pubkey: &[u8; 32],
    account_view_pubkey: &[u8; 32],
    generate_address_secret: &[u8; 32],
    major_count: u32,
    minor_count: u32,
) -> Vec<u8> {
    // Note: account_view_pubkey is not needed for the spend key derivation map.
    // The map maps spend_pub → (major, minor). View pubkey is only needed for
    // full subaddress construction, not the lookup map.
    let _ = account_view_pubkey;

    let total = ((major_count as u64 + 1) * (minor_count as u64 + 1)) as u32;
    let mut buf = Vec::with_capacity(4 + total as usize * 40);
    buf.extend_from_slice(&total.to_le_bytes());

    let spend_pt = match CompressedEdwardsY(*account_spend_pubkey).decompress() {
        Some(pt) => pt,
        None => return buf,
    };

    for major in 0..=major_count {
        for minor in 0..=minor_count {
            let sub_spend = carrot_subaddress_spend_pubkey(
                &spend_pt,
                account_spend_pubkey,
                generate_address_secret,
                major,
                minor,
            );
            buf.extend_from_slice(&sub_spend.compress().to_bytes());
            buf.extend_from_slice(&major.to_le_bytes());
            buf.extend_from_slice(&minor.to_le_bytes());
        }
    }

    buf
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cn_batch_first_entry_matches_spend_key() {
        // For (0,0) the subaddress spend pubkey should be the original spend pubkey
        let view_key = [0x01u8; 32];
        let view_scalar = Scalar::from_bytes_mod_order(view_key);
        let spend_scalar = Scalar::from(42u64);
        let spend_pub = (ED25519_BASEPOINT_TABLE * &spend_scalar).compress().to_bytes();

        let buf = cn_subaddress_map_batch(&spend_pub, &view_key, 1, 1);
        let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(count, 4); // (0..=1) * (0..=1) = 2*2

        // First entry should be the original spend pubkey at (0,0)
        let first_key = &buf[4..36];
        assert_eq!(first_key, &spend_pub);
        let first_major = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let first_minor = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
        assert_eq!(first_major, 0);
        assert_eq!(first_minor, 0);
    }

    #[test]
    fn test_cn_batch_entry_count() {
        let spend_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from(1u64)).compress().to_bytes();
        let view_key = [0x02u8; 32];

        let buf = cn_subaddress_map_batch(&spend_pub, &view_key, 2, 3);
        let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(count, 12); // 3*4
        assert_eq!(buf.len(), 4 + 12 * 40);
    }

    #[test]
    fn test_carrot_batch_first_entry_matches_account_spend() {
        let spend_scalar = Scalar::from(99u64);
        let spend_pub = (ED25519_BASEPOINT_TABLE * &spend_scalar).compress().to_bytes();
        let view_pub = [0x58u8; 32]; // dummy — unused in map generation
        let s_ga = [0x33u8; 32];

        let buf = carrot_subaddress_map_batch(&spend_pub, &view_pub, &s_ga, 0, 0);
        let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(count, 1);

        let first_key = &buf[4..36];
        assert_eq!(first_key, &spend_pub);
    }

    #[test]
    fn test_carrot_batch_deterministic() {
        let spend_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from(7u64)).compress().to_bytes();
        let view_pub = [0x58u8; 32];
        let s_ga = [0x42u8; 32];

        let buf1 = carrot_subaddress_map_batch(&spend_pub, &view_pub, &s_ga, 1, 1);
        let buf2 = carrot_subaddress_map_batch(&spend_pub, &view_pub, &s_ga, 1, 1);
        assert_eq!(buf1, buf2);
    }
}
