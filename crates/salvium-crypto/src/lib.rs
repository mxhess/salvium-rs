use wasm_bindgen::prelude::*;
use tiny_keccak::{Hasher, Keccak};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::traits::VartimeMultiscalarMul;

/// Keccak-256 hash (CryptoNote variant with 0x01 padding, NOT SHA3)
/// Matches Salvium C++ cn_fast_hash / keccak()
#[wasm_bindgen]
pub fn keccak256(data: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(data);
    keccak.finalize(&mut output);
    output.to_vec()
}

/// Blake2b with variable output length (unkeyed)
/// Matches Salvium C++ blake2b(out, outLen, data, dataLen, NULL, 0)
#[wasm_bindgen]
pub fn blake2b_hash(data: &[u8], out_len: usize) -> Vec<u8> {
    blake2b_simd::Params::new()
        .hash_length(out_len)
        .hash(data)
        .as_bytes()
        .to_vec()
}

/// Blake2b with key (keyed variant per RFC 7693)
/// Matches Salvium C++ blake2b(out, outLen, data, dataLen, key, keyLen)
/// Used by CARROT protocol for domain-separated hashing
#[wasm_bindgen]
pub fn blake2b_keyed(data: &[u8], out_len: usize, key: &[u8]) -> Vec<u8> {
    blake2b_simd::Params::new()
        .hash_length(out_len)
        .key(key)
        .hash(data)
        .as_bytes()
        .to_vec()
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn to32(s: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let len = s.len().min(32);
    buf[..len].copy_from_slice(&s[..len]);
    buf
}

fn to64(s: &[u8]) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let len = s.len().min(64);
    buf[..len].copy_from_slice(&s[..len]);
    buf
}

// ─── Scalar Operations (mod L) ─────────────────────────────────────────────

#[wasm_bindgen]
pub fn sc_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let sa = Scalar::from_bytes_mod_order(to32(a));
    let sb = Scalar::from_bytes_mod_order(to32(b));
    (sa + sb).to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn sc_sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let sa = Scalar::from_bytes_mod_order(to32(a));
    let sb = Scalar::from_bytes_mod_order(to32(b));
    (sa - sb).to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn sc_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    let sa = Scalar::from_bytes_mod_order(to32(a));
    let sb = Scalar::from_bytes_mod_order(to32(b));
    (sa * sb).to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn sc_mul_add(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> {
    let sa = Scalar::from_bytes_mod_order(to32(a));
    let sb = Scalar::from_bytes_mod_order(to32(b));
    let sc = Scalar::from_bytes_mod_order(to32(c));
    (sa * sb + sc).to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn sc_mul_sub(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> {
    let sa = Scalar::from_bytes_mod_order(to32(a));
    let sb = Scalar::from_bytes_mod_order(to32(b));
    let sc = Scalar::from_bytes_mod_order(to32(c));
    (sc - sa * sb).to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn sc_reduce32(s: &[u8]) -> Vec<u8> {
    Scalar::from_bytes_mod_order(to32(s)).to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn sc_reduce64(s: &[u8]) -> Vec<u8> {
    Scalar::from_bytes_mod_order_wide(&to64(s)).to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn sc_invert(a: &[u8]) -> Vec<u8> {
    Scalar::from_bytes_mod_order(to32(a)).invert().to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn sc_check(s: &[u8]) -> bool {
    bool::from(Scalar::from_canonical_bytes(to32(s)).is_some())
}

#[wasm_bindgen]
pub fn sc_is_zero(s: &[u8]) -> bool {
    Scalar::from_bytes_mod_order(to32(s)) == Scalar::ZERO
}

// ─── Point Operations (compressed Edwards) ──────────────────────────────────

#[wasm_bindgen]
pub fn scalar_mult_base(s: &[u8]) -> Vec<u8> {
    let scalar = Scalar::from_bytes_mod_order(to32(s));
    (ED25519_BASEPOINT_TABLE * &scalar).compress().to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn scalar_mult_point(s: &[u8], p: &[u8]) -> Vec<u8> {
    let scalar = Scalar::from_bytes_mod_order(to32(s));
    let point = CompressedEdwardsY(to32(p)).decompress().expect("invalid point");
    // Use variable-time Straus/wNAF — much faster than constant-time mul
    EdwardsPoint::vartime_multiscalar_mul(&[scalar], &[point])
        .compress().to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn point_add_compressed(p: &[u8], q: &[u8]) -> Vec<u8> {
    let pp = CompressedEdwardsY(to32(p)).decompress().expect("invalid point p");
    let qq = CompressedEdwardsY(to32(q)).decompress().expect("invalid point q");
    (pp + qq).compress().to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn point_sub_compressed(p: &[u8], q: &[u8]) -> Vec<u8> {
    let pp = CompressedEdwardsY(to32(p)).decompress().expect("invalid point p");
    let qq = CompressedEdwardsY(to32(q)).decompress().expect("invalid point q");
    (pp - qq).compress().to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn point_negate(p: &[u8]) -> Vec<u8> {
    let pp = CompressedEdwardsY(to32(p)).decompress().expect("invalid point");
    (-pp).compress().to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn double_scalar_mult_base(a: &[u8], p: &[u8], b: &[u8]) -> Vec<u8> {
    let sa = Scalar::from_bytes_mod_order(to32(a));
    let sb = Scalar::from_bytes_mod_order(to32(b));
    let pp = CompressedEdwardsY(to32(p)).decompress().expect("invalid point");
    // Variable-time multi-scalar: a*P + b*G
    EdwardsPoint::vartime_multiscalar_mul(
        &[sa, sb],
        &[pp, curve25519_dalek::constants::ED25519_BASEPOINT_POINT],
    ).compress().to_bytes().to_vec()
}
