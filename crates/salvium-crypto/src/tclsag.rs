//! TCLSAG (Twin CLSAG) ring signatures.
//!
//! Extends CLSAG with dual secret keys (x, y) and generator T for CARROT protocol.
//! Used in RCTTypeSalviumOne transactions.
//! Reference: Salvium rctSigs.cpp TCLSAG_Gen / TCLSAG_Ver

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use wasm_bindgen::prelude::*;

use crate::to32;
use crate::clsag::{hash_to_point, hash_to_scalar, compress, decompress, inv_eight, random_scalar};

// T generator (second basis point for twin commitments)
const T_BYTES: [u8; 32] = [
    0x96, 0x6f, 0xc6, 0x6b, 0x82, 0xcd, 0x56, 0xcf,
    0x85, 0xea, 0xec, 0x80, 0x1c, 0x42, 0x84, 0x5f,
    0x5f, 0x40, 0x88, 0x78, 0xd1, 0x56, 0x1e, 0x00,
    0xd3, 0xd7, 0xde, 0xd2, 0x79, 0x4d, 0x09, 0x4f,
];

fn t_point() -> EdwardsPoint {
    CompressedEdwardsY(T_BYTES).decompress().expect("invalid T generator")
}

// Domain separators (same as CLSAG)
fn pad_domain(s: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let len = s.len().min(32);
    buf[..len].copy_from_slice(&s[..len]);
    buf
}

fn clsag_agg_0() -> [u8; 32] { pad_domain(b"CLSAG_agg_0") }
fn clsag_agg_1() -> [u8; 32] { pad_domain(b"CLSAG_agg_1") }
fn clsag_round() -> [u8; 32] { pad_domain(b"CLSAG_round") }

// ─── TCLSAG Signature Structure ─────────────────────────────────────────────

pub struct TclsagSignature {
    pub sx: Vec<[u8; 32]>,
    pub sy: Vec<[u8; 32]>,
    pub c1: [u8; 32],
    pub key_image: [u8; 32],
    pub commitment_image: [u8; 32], // D_8
}

// ─── Core TCLSAG Sign ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn tclsag_sign(
    message: &[u8; 32],
    ring: &[[u8; 32]],
    secret_key_x: &[u8; 32],
    secret_key_y: &[u8; 32],
    commitments: &[[u8; 32]],
    commitment_mask: &[u8; 32],
    pseudo_output: &[u8; 32],
    secret_index: usize,
) -> TclsagSignature {
    let n = ring.len();
    assert!(n > 0 && n == commitments.len());
    assert!(secret_index < n);

    let x = Scalar::from_bytes_mod_order(*secret_key_x);
    let y = Scalar::from_bytes_mod_order(*secret_key_y);
    let z = Scalar::from_bytes_mod_order(*commitment_mask);
    let t_gen = t_point();

    let pseudo_pt = decompress(pseudo_output);

    // Commitment differences
    let c_diff: Vec<EdwardsPoint> = commitments.iter()
        .map(|c| decompress(&to32(c)) - pseudo_pt)
        .collect();

    // Key image: I = x * H_p(P_l)
    let p_l = ring[secret_index];
    let h_p = hash_to_point(&p_l);
    let key_image_pt = x * h_p;
    let key_image = compress(&key_image_pt);

    // Commitment key image: D = z * H_p(P_l)
    let d_full_pt = z * h_p;

    // D_8 = D * inv(8)
    let d8_pt = inv_eight() * d_full_pt;
    let d8 = compress(&d8_pt);

    // Aggregate coefficients
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

    // Random scalars for real input
    let a = random_scalar(); // For x component
    let b = random_scalar(); // For y component

    // L_init = a*G + b*T
    let l_init = EdwardsPoint::vartime_multiscalar_mul(
        &[a, b],
        &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, t_gen],
    );
    // R_init = a * H_p(P_l)
    let r_init = a * h_p;

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

    let l_init_bytes = compress(&l_init);
    let r_init_bytes = compress(&r_init);
    let mut c = build_challenge(&l_init_bytes, &r_init_bytes);

    let mut sx = vec![[0u8; 32]; n];
    let mut sy = vec![[0u8; 32]; n];
    let mut c1: Option<Scalar> = None;

    let mut i = (secret_index + 1) % n;
    if i == 0 {
        c1 = Some(c);
    }

    while i != secret_index {
        let sx_i = random_scalar();
        let sy_i = random_scalar();
        sx[i] = sx_i.to_bytes();
        sy[i] = sy_i.to_bytes();

        let h_p_i = hash_to_point(&ring[i]);
        let ring_pt = decompress(&ring[i]);

        let c_mu_p = c * mu_p;
        let c_mu_c = c * mu_c;

        // L = sx[i]*G + sy[i]*T + c*mu_P*P[i] + c*mu_C*C[i]
        let l_pt = EdwardsPoint::vartime_multiscalar_mul(
            &[sx_i, sy_i, c_mu_p, c_mu_c],
            &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, t_gen, ring_pt, c_diff[i]],
        );

        // R = sx[i]*H_p(P[i]) + c*mu_P*I + c*mu_C*D_full
        let r_pt = EdwardsPoint::vartime_multiscalar_mul(
            &[sx_i, c_mu_p, c_mu_c],
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

    // Close: sx[l] = a - c * (mu_P * x + mu_C * z)
    let sx_l = a - c * (mu_p * x + mu_c * z);
    sx[secret_index] = sx_l.to_bytes();

    // sy[l] = b - c * mu_P * y
    let sy_l = b - c * mu_p * y;
    sy[secret_index] = sy_l.to_bytes();

    // If c1 wasn't captured, compute now
    let c1 = match c1 {
        Some(val) => val,
        None => {
            let h_p_l = hash_to_point(&ring[secret_index]);
            let ring_pt = decompress(&ring[secret_index]);

            let c_mu_p = c * mu_p;
            let c_mu_c = c * mu_c;

            let l_pt = EdwardsPoint::vartime_multiscalar_mul(
                &[sx_l, sy_l, c_mu_p, c_mu_c],
                &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, t_gen, ring_pt, c_diff[secret_index]],
            );
            let r_pt = EdwardsPoint::vartime_multiscalar_mul(
                &[sx_l, c_mu_p, c_mu_c],
                &[h_p_l, key_image_pt, d_full_pt],
            );

            let l_bytes = compress(&l_pt);
            let r_bytes = compress(&r_pt);
            build_challenge(&l_bytes, &r_bytes)
        }
    };

    TclsagSignature {
        sx, sy,
        c1: c1.to_bytes(),
        key_image,
        commitment_image: d8,
    }
}

// ─── Core TCLSAG Verify ─────────────────────────────────────────────────────

pub fn tclsag_verify(
    message: &[u8; 32],
    sig: &TclsagSignature,
    ring: &[[u8; 32]],
    commitments: &[[u8; 32]],
    pseudo_output: &[u8; 32],
) -> bool {
    let n = ring.len();
    if n == 0 || n != commitments.len() || sig.sx.len() != n || sig.sy.len() != n {
        return false;
    }

    let t_gen = t_point();

    let pseudo_pt = match CompressedEdwardsY(*pseudo_output).decompress() {
        Some(p) => p,
        None => return false,
    };

    let c_diff: Vec<EdwardsPoint> = commitments.iter()
        .map(|c| decompress(&to32(c)) - pseudo_pt)
        .collect();

    // D_full = D_8 * 8
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

    let mut c = Scalar::from_bytes_mod_order(sig.c1);

    for i in 0..n {
        let sx_i = Scalar::from_bytes_mod_order(sig.sx[i]);
        let sy_i = Scalar::from_bytes_mod_order(sig.sy[i]);
        let h_p_i = hash_to_point(&ring[i]);
        let ring_pt = decompress(&ring[i]);

        let c_mu_p = c * mu_p;
        let c_mu_c = c * mu_c;

        // L = sx[i]*G + sy[i]*T + c*mu_P*P[i] + c*mu_C*C[i]
        let l_pt = EdwardsPoint::vartime_multiscalar_mul(
            &[sx_i, sy_i, c_mu_p, c_mu_c],
            &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, t_gen, ring_pt, c_diff[i]],
        );

        // R = sx[i]*H_p(P[i]) + c*mu_P*I + c*mu_C*D_full
        let r_pt = EdwardsPoint::vartime_multiscalar_mul(
            &[sx_i, c_mu_p, c_mu_c],
            &[h_p_i, key_image_pt, d_full_pt],
        );

        let l_bytes = compress(&l_pt);
        let r_bytes = compress(&r_pt);

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

    c.to_bytes() == sig.c1
}

// ─── Serialization ──────────────────────────────────────────────────────────

/// Format: [n as u32 LE][sx_0..sx_n-1][sy_0..sy_n-1][c1][I][D]
fn serialize_tclsag(sig: &TclsagSignature) -> Vec<u8> {
    let n = sig.sx.len();
    let mut out = Vec::with_capacity(4 + 2 * n * 32 + 96);
    out.extend_from_slice(&(n as u32).to_le_bytes());
    for s in &sig.sx { out.extend_from_slice(s); }
    for s in &sig.sy { out.extend_from_slice(s); }
    out.extend_from_slice(&sig.c1);
    out.extend_from_slice(&sig.key_image);
    out.extend_from_slice(&sig.commitment_image);
    out
}

fn deserialize_tclsag(bytes: &[u8]) -> Option<TclsagSignature> {
    if bytes.len() < 4 { return None; }
    let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let expected = 4 + 2 * n * 32 + 96;
    if bytes.len() < expected { return None; }

    let mut offset = 4;
    let mut sx = Vec::with_capacity(n);
    for _ in 0..n {
        sx.push(to32(&bytes[offset..offset + 32]));
        offset += 32;
    }
    let mut sy = Vec::with_capacity(n);
    for _ in 0..n {
        sy.push(to32(&bytes[offset..offset + 32]));
        offset += 32;
    }
    let c1 = to32(&bytes[offset..offset + 32]); offset += 32;
    let key_image = to32(&bytes[offset..offset + 32]); offset += 32;
    let commitment_image = to32(&bytes[offset..offset + 32]);

    Some(TclsagSignature { sx, sy, c1, key_image, commitment_image })
}

// ─── WASM Bindings ──────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn tclsag_sign_wasm(
    message: &[u8],
    ring_flat: &[u8],
    secret_key_x: &[u8],
    secret_key_y: &[u8],
    commitments_flat: &[u8],
    commitment_mask: &[u8],
    pseudo_output: &[u8],
    secret_index: u32,
) -> Vec<u8> {
    let n = ring_flat.len() / 32;
    let ring: Vec<[u8; 32]> = (0..n).map(|i| to32(&ring_flat[i*32..(i+1)*32])).collect();
    let comms: Vec<[u8; 32]> = (0..n).map(|i| to32(&commitments_flat[i*32..(i+1)*32])).collect();

    let sig = tclsag_sign(
        &to32(message), &ring, &to32(secret_key_x), &to32(secret_key_y),
        &comms, &to32(commitment_mask), &to32(pseudo_output), secret_index as usize,
    );
    serialize_tclsag(&sig)
}

#[wasm_bindgen]
pub fn tclsag_verify_wasm(
    message: &[u8],
    sig_bytes: &[u8],
    ring_flat: &[u8],
    commitments_flat: &[u8],
    pseudo_output: &[u8],
) -> bool {
    let sig = match deserialize_tclsag(sig_bytes) {
        Some(s) => s,
        None => return false,
    };
    let n = ring_flat.len() / 32;
    let ring: Vec<[u8; 32]> = (0..n).map(|i| to32(&ring_flat[i*32..(i+1)*32])).collect();
    let comms: Vec<[u8; 32]> = (0..n).map(|i| to32(&commitments_flat[i*32..(i+1)*32])).collect();

    tclsag_verify(&to32(message), &sig, &ring, &comms, &to32(pseudo_output))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keccak256_internal;

    fn tclsag_public_key(x: &Scalar, y: &Scalar) -> [u8; 32] {
        let t = t_point();
        EdwardsPoint::vartime_multiscalar_mul(
            &[*x, *y],
            &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, t],
        ).compress().to_bytes()
    }

    #[test]
    fn test_tclsag_sign_verify_ring_1() {
        let x = random_scalar();
        let y = random_scalar();
        let pk = tclsag_public_key(&x, &y);

        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;

        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();

        let message = keccak256_internal(b"tclsag test");

        let sig = tclsag_sign(&message, &[pk], &x.to_bytes(), &y.to_bytes(), &[commitment], &z.to_bytes(), &pseudo_output, 0);

        assert!(tclsag_verify(&message, &sig, &[pk], &[commitment], &pseudo_output));

        let wrong_msg = keccak256_internal(b"wrong message");
        assert!(!tclsag_verify(&wrong_msg, &sig, &[pk], &[commitment], &pseudo_output));
    }

    #[test]
    fn test_tclsag_sign_verify_ring_4() {
        let n = 4;
        let secret_index = 2;

        let x = random_scalar();
        let y = random_scalar();

        let mut ring = Vec::new();
        let mut commitments = Vec::new();
        let mut masks = Vec::new();

        for i in 0..n {
            if i == secret_index {
                ring.push(tclsag_public_key(&x, &y));
            } else {
                ring.push(tclsag_public_key(&random_scalar(), &random_scalar()));
            }
            let mask = random_scalar();
            commitments.push((mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes());
            masks.push(mask);
        }

        let pseudo_mask = random_scalar();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
        let z = masks[secret_index] - pseudo_mask;

        let message = keccak256_internal(b"tclsag ring 4");

        let sig = tclsag_sign(
            &message, &ring, &x.to_bytes(), &y.to_bytes(),
            &commitments, &z.to_bytes(), &pseudo_output, secret_index,
        );

        assert!(tclsag_verify(&message, &sig, &ring, &commitments, &pseudo_output));
    }

    #[test]
    fn test_tclsag_key_image_consistency() {
        let x = random_scalar();
        let y = random_scalar();
        let pk = tclsag_public_key(&x, &y);

        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;
        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();

        let msg1 = keccak256_internal(b"msg 1");
        let msg2 = keccak256_internal(b"msg 2");

        let sig1 = tclsag_sign(&msg1, &[pk], &x.to_bytes(), &y.to_bytes(), &[commitment], &z.to_bytes(), &pseudo_output, 0);
        let sig2 = tclsag_sign(&msg2, &[pk], &x.to_bytes(), &y.to_bytes(), &[commitment], &z.to_bytes(), &pseudo_output, 0);

        // Key image should be the same for same secret key
        assert_eq!(sig1.key_image, sig2.key_image);
        // Commitment image should be the same for same mask
        assert_eq!(sig1.commitment_image, sig2.commitment_image);
        // c1 should differ for different messages
        assert_ne!(sig1.c1, sig2.c1);
    }

    #[test]
    fn test_tclsag_serialize_roundtrip() {
        let x = random_scalar();
        let y = random_scalar();
        let pk = tclsag_public_key(&x, &y);

        let mask = random_scalar();
        let pseudo_mask = random_scalar();
        let z = mask - pseudo_mask;
        let commitment = (mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
        let pseudo_output = (pseudo_mask * curve25519_dalek::constants::ED25519_BASEPOINT_POINT).compress().to_bytes();
        let message = keccak256_internal(b"serialize test");

        let sig = tclsag_sign(&message, &[pk], &x.to_bytes(), &y.to_bytes(), &[commitment], &z.to_bytes(), &pseudo_output, 0);
        let bytes = serialize_tclsag(&sig);
        let sig2 = deserialize_tclsag(&bytes).unwrap();

        assert!(tclsag_verify(&message, &sig2, &[pk], &[commitment], &pseudo_output));
    }
}
