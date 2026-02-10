//! CLSAG (Compact Linkable Anonymous Group) ring signatures.
//!
//! Implements signing and verification matching the JS in transaction.js
//! and Salvium C++ rctSigs.cpp CLSAG_Gen / CLSAG_Ver.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use wasm_bindgen::prelude::*;

use crate::{keccak256_internal, to32};

// ─── Domain separators (32-byte zero-padded) ────────────────────────────────

fn pad_domain(s: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let len = s.len().min(32);
    buf[..len].copy_from_slice(&s[..len]);
    buf
}

fn clsag_agg_0() -> [u8; 32] { pad_domain(b"CLSAG_agg_0") }
fn clsag_agg_1() -> [u8; 32] { pad_domain(b"CLSAG_agg_1") }
fn clsag_round() -> [u8; 32] { pad_domain(b"CLSAG_round") }

// ─── Helpers ────────────────────────────────────────────────────────────────

pub(crate) fn decompress(bytes: &[u8; 32]) -> EdwardsPoint {
    CompressedEdwardsY(*bytes).decompress().expect("invalid point")
}

pub(crate) fn compress(p: &EdwardsPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

/// Hash to scalar: keccak256(concat(data...)) then reduce mod L
pub(crate) fn hash_to_scalar(data: &[&[u8]]) -> Scalar {
    let total: usize = data.iter().map(|d| d.len()).sum();
    let mut combined = Vec::with_capacity(total);
    for d in data {
        combined.extend_from_slice(d);
    }
    let hash = keccak256_internal(&combined);
    Scalar::from_bytes_mod_order(hash)
}

/// Hash to point: keccak256 -> elligator2 -> cofactor multiply
pub(crate) fn hash_to_point(key: &[u8; 32]) -> EdwardsPoint {
    let hash = keccak256_internal(key);
    let p = crate::elligator2::ge_fromfe_frombytes_vartime(&hash);
    // Cofactor multiply by 8
    let t = p + p;
    let t = t + t;
    t + t
}

/// INV_EIGHT: 8^(-1) mod L
pub(crate) fn inv_eight() -> Scalar {
    Scalar::from(8u64).invert()
}

/// Generate a random scalar using OS randomness
pub(crate) fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    #[cfg(target_arch = "wasm32")]
    {
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
    }
    Scalar::from_bytes_mod_order_wide(&bytes)
}

// ─── CLSAG Signature Structure ──────────────────────────────────────────────

/// CLSAG signature: s[0..n], c1, I (key image), D (commitment key image / 8)
pub struct ClsagSignature {
    pub s: Vec<[u8; 32]>,
    pub c1: [u8; 32],
    pub key_image: [u8; 32],   // I
    pub commitment_image: [u8; 32], // D (= D_full * inv_eight)
}

// ─── Core CLSAG Sign ────────────────────────────────────────────────────────

/// CLSAG ring signature — sign
///
/// All byte slices are 32-byte compressed Edwards Y points or scalars.
pub fn clsag_sign(
    message: &[u8; 32],
    ring: &[[u8; 32]],
    secret_key: &[u8; 32],
    commitments: &[[u8; 32]],
    commitment_mask: &[u8; 32],
    pseudo_output: &[u8; 32],
    secret_index: usize,
) -> ClsagSignature {
    let n = ring.len();
    assert!(n > 0 && n == commitments.len());
    assert!(secret_index < n);

    let sk = Scalar::from_bytes_mod_order(*secret_key);
    let z = Scalar::from_bytes_mod_order(*commitment_mask);

    // Decompress pseudo output
    let pseudo_pt = decompress(pseudo_output);

    // Commitment differences: C[i] = commitments[i] - pseudo_output
    let c_diff: Vec<EdwardsPoint> = commitments.iter()
        .map(|c| decompress(&to32(c)) - pseudo_pt)
        .collect();
    // Key image: I = sk * H_p(ring[secret_index])
    let p_l = ring[secret_index];
    let h_p = hash_to_point(&p_l);
    let key_image_pt = sk * h_p;
    let key_image = compress(&key_image_pt);

    // Commitment key image: D = z * H_p(ring[secret_index])
    let d_full_pt = z * h_p;

    // D_8 = D * inv(8) — stored in signature
    let d8_pt = inv_eight() * d_full_pt;
    let d8 = compress(&d8_pt);

    // Aggregate coefficients mu_P and mu_C
    // aggData = [domain, ring[0..n-1], commitments[0..n-1], I, D_8, pseudo_output]
    let agg0 = clsag_agg_0();
    let agg1 = clsag_agg_1();
    let mut agg_parts: Vec<&[u8]> = Vec::with_capacity(2 * n + 4);
    agg_parts.push(&agg0);
    for pk in ring { agg_parts.push(pk); }
    for c in commitments { agg_parts.push(c); }
    agg_parts.push(&key_image);
    agg_parts.push(&d8);
    agg_parts.push(pseudo_output);
    let mu_p = hash_to_scalar(&agg_parts);

    agg_parts[0] = &agg1;
    let mu_c = hash_to_scalar(&agg_parts);

    // Random alpha
    let alpha = random_scalar();

    // aG = alpha * G, aH = alpha * H_p(P_l)
    let a_g = &alpha * ED25519_BASEPOINT_TABLE;
    let a_h = alpha * h_p;

    // Build challenge hash: H_n(CLSAG_round, ring[0..n-1], commitments[0..n-1], pseudo_output, message, L, R)
    let round_domain = clsag_round();
    let build_challenge = |l: &[u8; 32], r: &[u8; 32]| -> Scalar {
        let mut parts: Vec<&[u8]> = Vec::with_capacity(2 * n + 5);
        parts.push(&round_domain);
        for pk in ring { parts.push(pk); }
        for c in commitments { parts.push(c); }
        parts.push(pseudo_output);
        parts.push(message);
        parts.push(l);
        parts.push(r);
        hash_to_scalar(&parts)
    };

    // First challenge from alpha commitments
    let a_g_bytes = compress(&a_g);
    let a_h_bytes = compress(&a_h);
    let mut c = build_challenge(&a_g_bytes, &a_h_bytes);

    let mut s = vec![[0u8; 32]; n];
    let mut c1: Option<Scalar> = None;

    // Start at position after secret index
    let mut i = (secret_index + 1) % n;

    // Capture c1 when we hit index 0
    if i == 0 {
        c1 = Some(c);
    }

    // Go around the ring
    while i != secret_index {
        let s_i = random_scalar();
        s[i] = s_i.to_bytes();

        let h_p_i = hash_to_point(&ring[i]);
        let ring_pt = decompress(&ring[i]);

        let c_mu_p = c * mu_p;
        let c_mu_c = c * mu_c;

        // L = s[i]*G + c_mu_p*P[i] + c_mu_c*C[i]
        let l_pt = EdwardsPoint::vartime_multiscalar_mul(
            &[s_i, c_mu_p, c_mu_c],
            &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, ring_pt, c_diff[i]],
        );

        // R = s[i]*H_p(P[i]) + c_mu_p*I + c_mu_c*D_full
        let r_pt = EdwardsPoint::vartime_multiscalar_mul(
            &[s_i, c_mu_p, c_mu_c],
            &[h_p_i, key_image_pt, d_full_pt],
        );

        let l_bytes = compress(&l_pt);
        let r_bytes = compress(&r_pt);
        c = build_challenge(&l_bytes, &r_bytes);

        i = (i + 1) % n;
        if i == 0 {
            c1 = Some(c);
        }
    }

    // Close the ring: s[l] = alpha - c * (mu_P * p + mu_C * z)
    let s_l = alpha - c * (mu_p * sk + mu_c * z);
    s[secret_index] = s_l.to_bytes();

    // If c1 wasn't captured (single member ring), compute now
    let c1 = match c1 {
        Some(c1_val) => c1_val,
        None => {
            let h_p_l = hash_to_point(&ring[secret_index]);
            let ring_pt = decompress(&ring[secret_index]);

            let c_mu_p = c * mu_p;
            let c_mu_c = c * mu_c;

            let l_pt = EdwardsPoint::vartime_multiscalar_mul(
                &[s_l, c_mu_p, c_mu_c],
                &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, ring_pt, c_diff[secret_index]],
            );
            let r_pt = EdwardsPoint::vartime_multiscalar_mul(
                &[s_l, c_mu_p, c_mu_c],
                &[h_p_l, key_image_pt, d_full_pt],
            );

            let l_bytes = compress(&l_pt);
            let r_bytes = compress(&r_pt);
            build_challenge(&l_bytes, &r_bytes)
        }
    };

    ClsagSignature {
        s,
        c1: c1.to_bytes(),
        key_image,
        commitment_image: d8,
    }
}

// ─── Core CLSAG Verify ─────────────────────────────────────────────────────

/// CLSAG ring signature — verify
pub fn clsag_verify(
    message: &[u8; 32],
    sig: &ClsagSignature,
    ring: &[[u8; 32]],
    commitments: &[[u8; 32]],
    pseudo_output: &[u8; 32],
) -> bool {
    let n = ring.len();
    if n == 0 || n != commitments.len() || sig.s.len() != n {
        return false;
    }

    let pseudo_pt = match CompressedEdwardsY(*pseudo_output).decompress() {
        Some(p) => p,
        None => return false,
    };

    // Commitment differences
    let c_diff: Vec<EdwardsPoint> = commitments.iter()
        .map(|c| decompress(&to32(c)) - pseudo_pt)
        .collect();

    // D_full = D_8 * 8 (3 doublings)
    let d8_pt = match CompressedEdwardsY(sig.commitment_image).decompress() {
        Some(p) => p,
        None => return false,
    };
    let d_full_pt = {
        let t = d8_pt + d8_pt;
        let t = t + t;
        t + t
    };

    let key_image_pt = match CompressedEdwardsY(sig.key_image).decompress() {
        Some(p) => p,
        None => return false,
    };

    // Aggregate coefficients
    let mut agg_parts: Vec<&[u8]> = Vec::with_capacity(2 * n + 4);
    let agg0 = clsag_agg_0();
    agg_parts.push(&agg0);
    for pk in ring { agg_parts.push(pk); }
    for c in commitments { agg_parts.push(c); }
    agg_parts.push(&sig.key_image);
    agg_parts.push(&sig.commitment_image);
    agg_parts.push(pseudo_output);
    let mu_p = hash_to_scalar(&agg_parts);

    let agg1 = clsag_agg_1();
    agg_parts[0] = &agg1;
    let mu_c = hash_to_scalar(&agg_parts);

    let round_domain = clsag_round();

    // Verify the ring
    let mut c = Scalar::from_bytes_mod_order(sig.c1);

    for i in 0..n {
        let s_i = Scalar::from_bytes_mod_order(sig.s[i]);
        let h_p_i = hash_to_point(&ring[i]);
        let ring_pt = decompress(&ring[i]);

        let c_mu_p = c * mu_p;
        let c_mu_c = c * mu_c;

        // L = s[i]*G + c_mu_p*P[i] + c_mu_c*C[i]
        let l_pt = EdwardsPoint::vartime_multiscalar_mul(
            &[s_i, c_mu_p, c_mu_c],
            &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, ring_pt, c_diff[i]],
        );

        // R = s[i]*H_p(P[i]) + c_mu_p*I + c_mu_c*D_full
        let r_pt = EdwardsPoint::vartime_multiscalar_mul(
            &[s_i, c_mu_p, c_mu_c],
            &[h_p_i, key_image_pt, d_full_pt],
        );

        let l_bytes = compress(&l_pt);
        let r_bytes = compress(&r_pt);

        // Next challenge
        let mut parts: Vec<&[u8]> = Vec::with_capacity(2 * n + 5);
        parts.push(&round_domain);
        for pk in ring { parts.push(pk); }
        for cm in commitments { parts.push(cm); }
        parts.push(pseudo_output);
        parts.push(message);
        parts.push(&l_bytes);
        parts.push(&r_bytes);
        c = hash_to_scalar(&parts);
    }

    // After going around, c should equal c1
    c.to_bytes() == sig.c1
}

// ─── Serialization ──────────────────────────────────────────────────────────

/// Serialize CLSAG signature to bytes.
/// Format: [n as u32 LE][s_0..s_n-1 (32 bytes each)][c1 (32)][I (32)][D (32)]
fn serialize_clsag(sig: &ClsagSignature) -> Vec<u8> {
    let n = sig.s.len();
    let mut out = Vec::with_capacity(4 + n * 32 + 96);
    out.extend_from_slice(&(n as u32).to_le_bytes());
    for s in &sig.s {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(&sig.c1);
    out.extend_from_slice(&sig.key_image);
    out.extend_from_slice(&sig.commitment_image);
    out
}

/// Deserialize CLSAG signature from bytes.
fn deserialize_clsag(bytes: &[u8]) -> Option<ClsagSignature> {
    if bytes.len() < 4 { return None; }
    let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let expected = 4 + n * 32 + 96;
    if bytes.len() < expected { return None; }

    let mut offset = 4;
    let mut s = Vec::with_capacity(n);
    for _ in 0..n {
        s.push(to32(&bytes[offset..offset + 32]));
        offset += 32;
    }

    let c1 = to32(&bytes[offset..offset + 32]);
    offset += 32;
    let key_image = to32(&bytes[offset..offset + 32]);
    offset += 32;
    let commitment_image = to32(&bytes[offset..offset + 32]);

    Some(ClsagSignature { s, c1, key_image, commitment_image })
}

// ─── WASM Bindings ──────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn clsag_sign_wasm(
    message: &[u8],
    ring_flat: &[u8],
    secret_key: &[u8],
    commitments_flat: &[u8],
    commitment_mask: &[u8],
    pseudo_output: &[u8],
    secret_index: u32,
) -> Vec<u8> {
    let n = ring_flat.len() / 32;
    let ring: Vec<[u8; 32]> = (0..n).map(|i| to32(&ring_flat[i*32..(i+1)*32])).collect();
    let comms: Vec<[u8; 32]> = (0..n).map(|i| to32(&commitments_flat[i*32..(i+1)*32])).collect();

    let sig = clsag_sign(
        &to32(message),
        &ring,
        &to32(secret_key),
        &comms,
        &to32(commitment_mask),
        &to32(pseudo_output),
        secret_index as usize,
    );
    serialize_clsag(&sig)
}

#[wasm_bindgen]
pub fn clsag_verify_wasm(
    message: &[u8],
    sig_bytes: &[u8],
    ring_flat: &[u8],
    commitments_flat: &[u8],
    pseudo_output: &[u8],
) -> bool {
    let sig = match deserialize_clsag(sig_bytes) {
        Some(s) => s,
        None => return false,
    };
    let n = ring_flat.len() / 32;
    let ring: Vec<[u8; 32]> = (0..n).map(|i| to32(&ring_flat[i*32..(i+1)*32])).collect();
    let comms: Vec<[u8; 32]> = (0..n).map(|i| to32(&commitments_flat[i*32..(i+1)*32])).collect();

    clsag_verify(
        &to32(message),
        &sig,
        &ring,
        &comms,
        &to32(pseudo_output),
    )
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clsag_sign_verify_ring_1() {
        let sk = random_scalar();
        let pk = (&sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();

        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;

        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();

        let message = keccak256_internal(b"test message");

        let sig = clsag_sign(&message, &[pk], &sk.to_bytes(), &[commitment], &z.to_bytes(), &pseudo_output, 0);

        assert!(clsag_verify(&message, &sig, &[pk], &[commitment], &pseudo_output));

        // Wrong message should fail
        let wrong_msg = keccak256_internal(b"wrong message");
        assert!(!clsag_verify(&wrong_msg, &sig, &[pk], &[commitment], &pseudo_output));
    }

    #[test]
    fn test_clsag_sign_verify_ring_11() {
        let n = 11;
        let secret_index = 5;

        let mut ring = Vec::with_capacity(n);
        let mut secrets = Vec::with_capacity(n);
        let mut masks = Vec::with_capacity(n);
        let mut commitments = Vec::with_capacity(n);

        for _ in 0..n {
            let sk = random_scalar();
            let pk = (&sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();
            let mask = random_scalar();
            let c = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
            ring.push(pk);
            secrets.push(sk);
            masks.push(mask);
            commitments.push(c);
        }

        let pseudo_mask = random_scalar();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
        let z = masks[secret_index] - pseudo_mask;

        let message = keccak256_internal(b"test ring 11");

        let sig = clsag_sign(
            &message, &ring, &secrets[secret_index].to_bytes(),
            &commitments, &z.to_bytes(), &pseudo_output, secret_index,
        );

        assert!(clsag_verify(&message, &sig, &ring, &commitments, &pseudo_output));
    }

    #[test]
    fn test_clsag_serialize_roundtrip() {
        let sk = random_scalar();
        let pk = (&sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;
        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
        let message = keccak256_internal(b"roundtrip test");

        let sig = clsag_sign(&message, &[pk], &sk.to_bytes(), &[commitment], &z.to_bytes(), &pseudo_output, 0);
        let bytes = serialize_clsag(&sig);
        let sig2 = deserialize_clsag(&bytes).unwrap();

        assert_eq!(sig.c1, sig2.c1);
        assert_eq!(sig.key_image, sig2.key_image);
        assert_eq!(sig.commitment_image, sig2.commitment_image);
        assert_eq!(sig.s.len(), sig2.s.len());
        assert!(clsag_verify(&message, &sig2, &[pk], &[commitment], &pseudo_output));
    }
}
