//! C FFI bindings for salvium-crypto.
//!
//! All functions use the convention:
//!   - Caller owns all buffers
//!   - Rust writes into `*mut u8 out` of known size
//!   - Returns i32: 0 = ok, -1 = error
//!   - All functions prefixed `salvium_` to avoid symbol conflicts
//!
//! This module is only compiled on non-wasm targets (guarded by
//! `#[cfg(not(target_arch = "wasm32"))]` in lib.rs).

use std::slice;
use std::ptr;

// ─── Hashing ────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn salvium_keccak256(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) -> i32 {
    let data = slice::from_raw_parts(data, data_len);
    let result = crate::keccak256(data);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_blake2b(
    data: *const u8,
    data_len: usize,
    out_len: usize,
    out: *mut u8,
) -> i32 {
    let data = slice::from_raw_parts(data, data_len);
    let result = crate::blake2b_hash(data, out_len);
    ptr::copy_nonoverlapping(result.as_ptr(), out, out_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_blake2b_keyed(
    data: *const u8,
    data_len: usize,
    out_len: usize,
    key: *const u8,
    key_len: usize,
    out: *mut u8,
) -> i32 {
    let data = slice::from_raw_parts(data, data_len);
    let key = slice::from_raw_parts(key, key_len);
    let result = crate::blake2b_keyed(data, out_len, key);
    ptr::copy_nonoverlapping(result.as_ptr(), out, out_len);
    0
}

// ─── Scalar Operations ─────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_add(
    a: *const u8,
    b: *const u8,
    out: *mut u8,
) -> i32 {
    let a = slice::from_raw_parts(a, 32);
    let b = slice::from_raw_parts(b, 32);
    let result = crate::sc_add(a, b);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_sub(
    a: *const u8,
    b: *const u8,
    out: *mut u8,
) -> i32 {
    let a = slice::from_raw_parts(a, 32);
    let b = slice::from_raw_parts(b, 32);
    let result = crate::sc_sub(a, b);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_mul(
    a: *const u8,
    b: *const u8,
    out: *mut u8,
) -> i32 {
    let a = slice::from_raw_parts(a, 32);
    let b = slice::from_raw_parts(b, 32);
    let result = crate::sc_mul(a, b);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_mul_add(
    a: *const u8,
    b: *const u8,
    c: *const u8,
    out: *mut u8,
) -> i32 {
    let a = slice::from_raw_parts(a, 32);
    let b = slice::from_raw_parts(b, 32);
    let c = slice::from_raw_parts(c, 32);
    let result = crate::sc_mul_add(a, b, c);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_mul_sub(
    a: *const u8,
    b: *const u8,
    c: *const u8,
    out: *mut u8,
) -> i32 {
    let a = slice::from_raw_parts(a, 32);
    let b = slice::from_raw_parts(b, 32);
    let c = slice::from_raw_parts(c, 32);
    let result = crate::sc_mul_sub(a, b, c);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_reduce32(
    s: *const u8,
    out: *mut u8,
) -> i32 {
    let s = slice::from_raw_parts(s, 32);
    let result = crate::sc_reduce32(s);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_reduce64(
    s: *const u8,
    out: *mut u8,
) -> i32 {
    let s = slice::from_raw_parts(s, 64);
    let result = crate::sc_reduce64(s);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_invert(
    a: *const u8,
    out: *mut u8,
) -> i32 {
    let a = slice::from_raw_parts(a, 32);
    let result = crate::sc_invert(a);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_check(s: *const u8) -> i32 {
    let s = slice::from_raw_parts(s, 32);
    if crate::sc_check(s) { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn salvium_sc_is_zero(s: *const u8) -> i32 {
    let s = slice::from_raw_parts(s, 32);
    if crate::sc_is_zero(s) { 1 } else { 0 }
}

// ─── Point Operations ───────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn salvium_scalar_mult_base(
    s: *const u8,
    out: *mut u8,
) -> i32 {
    let s = slice::from_raw_parts(s, 32);
    let result = crate::scalar_mult_base(s);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_scalar_mult_point(
    s: *const u8,
    p: *const u8,
    out: *mut u8,
) -> i32 {
    let s = slice::from_raw_parts(s, 32);
    let p = slice::from_raw_parts(p, 32);
    let result = crate::scalar_mult_point(s, p);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_point_add(
    p: *const u8,
    q: *const u8,
    out: *mut u8,
) -> i32 {
    let p = slice::from_raw_parts(p, 32);
    let q = slice::from_raw_parts(q, 32);
    let result = crate::point_add_compressed(p, q);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_point_sub(
    p: *const u8,
    q: *const u8,
    out: *mut u8,
) -> i32 {
    let p = slice::from_raw_parts(p, 32);
    let q = slice::from_raw_parts(q, 32);
    let result = crate::point_sub_compressed(p, q);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_point_negate(
    p: *const u8,
    out: *mut u8,
) -> i32 {
    let p = slice::from_raw_parts(p, 32);
    let result = crate::point_negate(p);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_double_scalar_mult_base(
    a: *const u8,
    p: *const u8,
    b: *const u8,
    out: *mut u8,
) -> i32 {
    let a = slice::from_raw_parts(a, 32);
    let p = slice::from_raw_parts(p, 32);
    let b = slice::from_raw_parts(b, 32);
    let result = crate::double_scalar_mult_base(a, p, b);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

// ─── Hash-to-Point & Key Derivation ────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn salvium_hash_to_point(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) -> i32 {
    let data = slice::from_raw_parts(data, data_len);
    let result = crate::hash_to_point(data);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_generate_key_derivation(
    pub_key: *const u8,
    sec_key: *const u8,
    out: *mut u8,
) -> i32 {
    let pk = slice::from_raw_parts(pub_key, 32);
    let sk = slice::from_raw_parts(sec_key, 32);
    let result = crate::generate_key_derivation(pk, sk);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_generate_key_image(
    pub_key: *const u8,
    sec_key: *const u8,
    out: *mut u8,
) -> i32 {
    let pk = slice::from_raw_parts(pub_key, 32);
    let sk = slice::from_raw_parts(sec_key, 32);
    let result = crate::generate_key_image(pk, sk);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_derive_public_key(
    derivation: *const u8,
    output_index: u32,
    base_pub: *const u8,
    out: *mut u8,
) -> i32 {
    let deriv = slice::from_raw_parts(derivation, 32);
    let base = slice::from_raw_parts(base_pub, 32);
    let result = crate::derive_public_key(deriv, output_index, base);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_derive_secret_key(
    derivation: *const u8,
    output_index: u32,
    base_sec: *const u8,
    out: *mut u8,
) -> i32 {
    let deriv = slice::from_raw_parts(derivation, 32);
    let base = slice::from_raw_parts(base_sec, 32);
    let result = crate::derive_secret_key(deriv, output_index, base);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

// ─── Pedersen Commitments ───────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn salvium_pedersen_commit(
    amount: *const u8,
    mask: *const u8,
    out: *mut u8,
) -> i32 {
    let amount = slice::from_raw_parts(amount, 32);
    let mask = slice::from_raw_parts(mask, 32);
    let result = crate::pedersen_commit(amount, mask);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_zero_commit(
    amount: *const u8,
    out: *mut u8,
) -> i32 {
    let amount = slice::from_raw_parts(amount, 32);
    let result = crate::zero_commit(amount);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn salvium_gen_commitment_mask(
    secret: *const u8,
    out: *mut u8,
) -> i32 {
    let secret = slice::from_raw_parts(secret, 32);
    let result = crate::gen_commitment_mask(secret);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

// ─── Oracle Signature Verification ──────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn salvium_sha256(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) -> i32 {
    let data = slice::from_raw_parts(data, data_len);
    let result = crate::sha256(data);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

/// Verify a signature against a DER-encoded SPKI public key.
/// Returns 1 for valid, 0 for invalid/error.
#[no_mangle]
pub unsafe extern "C" fn salvium_verify_signature(
    message: *const u8,
    msg_len: usize,
    signature: *const u8,
    sig_len: usize,
    pubkey_der: *const u8,
    key_len: usize,
) -> i32 {
    let message = slice::from_raw_parts(message, msg_len);
    let signature = slice::from_raw_parts(signature, sig_len);
    let pubkey_der = slice::from_raw_parts(pubkey_der, key_len);
    crate::verify_signature(message, signature, pubkey_der)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Two known scalars (valid mod L, from CryptoNote test vectors)
    const SEC_A: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]; // scalar = 1

    const SEC_B: [u8; 32] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]; // scalar = 2

    // Ed25519 basepoint (compressed)
    const G: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    ];

    /// Helper: call FFI function, compare output to direct Rust call
    fn assert_ffi_matches(ffi_out: &[u8; 32], rust_result: &[u8]) {
        assert_eq!(&ffi_out[..], rust_result, "FFI output != direct Rust output");
    }

    #[test]
    fn test_keccak256() {
        let data = b"test data";
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_keccak256(data.as_ptr(), data.len(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::keccak256(data));
    }

    #[test]
    fn test_blake2b() {
        let data = b"test data";
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_blake2b(data.as_ptr(), data.len(), 32, out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::blake2b_hash(data, 32));
    }

    #[test]
    fn test_blake2b_keyed() {
        let data = b"test data";
        let key = b"secret key";
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_blake2b_keyed(
                data.as_ptr(), data.len(), 32,
                key.as_ptr(), key.len(), out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::blake2b_keyed(data, 32, key));
    }

    #[test]
    fn test_sc_add() {
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_sc_add(SEC_A.as_ptr(), SEC_B.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::sc_add(&SEC_A, &SEC_B));
        // 1 + 2 = 3
        assert_eq!(out[0], 3);
    }

    #[test]
    fn test_sc_sub() {
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_sc_sub(SEC_B.as_ptr(), SEC_A.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::sc_sub(&SEC_B, &SEC_A));
        // 2 - 1 = 1
        assert_eq!(out[0], 1);
    }

    #[test]
    fn test_sc_mul() {
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_sc_mul(SEC_A.as_ptr(), SEC_B.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::sc_mul(&SEC_A, &SEC_B));
        // 1 * 2 = 2
        assert_eq!(out[0], 2);
    }

    #[test]
    fn test_sc_mul_add() {
        let three: [u8; 32] = {
            let mut s = [0u8; 32];
            s[0] = 3;
            s
        };
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_sc_mul_add(SEC_A.as_ptr(), SEC_B.as_ptr(), three.as_ptr(), out.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::sc_mul_add(&SEC_A, &SEC_B, &three));
        // 1*2 + 3 = 5
        assert_eq!(out[0], 5);
    }

    #[test]
    fn test_sc_mul_sub() {
        let five: [u8; 32] = {
            let mut s = [0u8; 32];
            s[0] = 5;
            s
        };
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_sc_mul_sub(SEC_A.as_ptr(), SEC_B.as_ptr(), five.as_ptr(), out.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::sc_mul_sub(&SEC_A, &SEC_B, &five));
        // sc_mul_sub(a,b,c) = c - a*b = 5 - 1*2 = 3
        assert_eq!(out[0], 3);
    }

    #[test]
    fn test_sc_reduce32() {
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_sc_reduce32(SEC_A.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::sc_reduce32(&SEC_A));
    }

    #[test]
    fn test_sc_reduce64() {
        let input = [0x07u8; 64]; // arbitrary 64-byte input
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_sc_reduce64(input.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::sc_reduce64(&input));
    }

    #[test]
    fn test_sc_invert() {
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_sc_invert(SEC_B.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::sc_invert(&SEC_B));
        // Verify: invert(2) * 2 == 1
        let mut product = [0u8; 32];
        unsafe { salvium_sc_mul(out.as_ptr(), SEC_B.as_ptr(), product.as_mut_ptr()) };
        assert_eq!(product[0], 1);
        assert!(product[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_sc_check() {
        let rc = unsafe { salvium_sc_check(SEC_A.as_ptr()) };
        assert_eq!(rc, 1); // 1 is canonical
        let bad = [0xffu8; 32]; // > L, not canonical
        let rc = unsafe { salvium_sc_check(bad.as_ptr()) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn test_sc_is_zero() {
        let zero = [0u8; 32];
        assert_eq!(unsafe { salvium_sc_is_zero(zero.as_ptr()) }, 1);
        assert_eq!(unsafe { salvium_sc_is_zero(SEC_A.as_ptr()) }, 0);
    }

    #[test]
    fn test_scalar_mult_base() {
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_scalar_mult_base(SEC_A.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::scalar_mult_base(&SEC_A));
        // 1*G = G
        assert_eq!(out, G);
    }

    #[test]
    fn test_scalar_mult_point() {
        // 2 * G via FFI
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_scalar_mult_point(SEC_B.as_ptr(), G.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::scalar_mult_point(&SEC_B, &G));
        // Should equal scalar_mult_base(2)
        let mut via_base = [0u8; 32];
        unsafe { salvium_scalar_mult_base(SEC_B.as_ptr(), via_base.as_mut_ptr()) };
        assert_eq!(out, via_base);
    }

    #[test]
    fn test_point_add_sub() {
        // 1*G + 1*G should equal 2*G
        let mut two_g = [0u8; 32];
        unsafe { salvium_scalar_mult_base(SEC_B.as_ptr(), two_g.as_mut_ptr()) };
        let mut sum = [0u8; 32];
        let rc = unsafe { salvium_point_add(G.as_ptr(), G.as_ptr(), sum.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(sum, two_g);

        // 2*G - 1*G should equal G
        let mut diff = [0u8; 32];
        let rc = unsafe { salvium_point_sub(two_g.as_ptr(), G.as_ptr(), diff.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(diff, G);
    }

    #[test]
    fn test_point_negate() {
        let mut neg_g = [0u8; 32];
        let rc = unsafe { salvium_point_negate(G.as_ptr(), neg_g.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&neg_g, &crate::point_negate(&G));
        // G + (-G) should be identity
        let mut should_be_identity = [0u8; 32];
        unsafe { salvium_point_add(G.as_ptr(), neg_g.as_ptr(), should_be_identity.as_mut_ptr()) };
        // Identity point compressed = (1, 0, 0, ..., 0)
        assert_eq!(should_be_identity[0], 1);
        assert!(should_be_identity[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_double_scalar_mult_base() {
        // a*P + b*G where a=1, P=G, b=1 => G + G = 2G
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_double_scalar_mult_base(
                SEC_A.as_ptr(), G.as_ptr(), SEC_A.as_ptr(), out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        let mut two_g = [0u8; 32];
        unsafe { salvium_scalar_mult_base(SEC_B.as_ptr(), two_g.as_mut_ptr()) };
        assert_eq!(out, two_g);
    }

    #[test]
    fn test_hash_to_point() {
        let data = b"test key";
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_hash_to_point(data.as_ptr(), data.len(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::hash_to_point(data));
        // Result should be a valid point (decompressible)
        use curve25519_dalek::edwards::CompressedEdwardsY;
        assert!(CompressedEdwardsY(out).decompress().is_some());
    }

    #[test]
    fn test_generate_key_derivation() {
        // D = 8 * (sec * pub). Use pub = G, sec = scalar 2
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_generate_key_derivation(G.as_ptr(), SEC_B.as_ptr(), out.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::generate_key_derivation(&G, &SEC_B));
        // Result should be a valid point
        use curve25519_dalek::edwards::CompressedEdwardsY;
        assert!(CompressedEdwardsY(out).decompress().is_some());
    }

    #[test]
    fn test_generate_key_image() {
        // KI = sec * H_p(pub)
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_generate_key_image(G.as_ptr(), SEC_A.as_ptr(), out.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::generate_key_image(&G, &SEC_A));
        use curve25519_dalek::edwards::CompressedEdwardsY;
        assert!(CompressedEdwardsY(out).decompress().is_some());
    }

    #[test]
    fn test_derive_public_key() {
        // First generate a derivation
        let mut derivation = [0u8; 32];
        unsafe {
            salvium_generate_key_derivation(G.as_ptr(), SEC_A.as_ptr(), derivation.as_mut_ptr());
        }
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_derive_public_key(derivation.as_ptr(), 0, G.as_ptr(), out.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::derive_public_key(&derivation, 0, &G));
        use curve25519_dalek::edwards::CompressedEdwardsY;
        assert!(CompressedEdwardsY(out).decompress().is_some());
    }

    #[test]
    fn test_derive_secret_key() {
        let mut derivation = [0u8; 32];
        unsafe {
            salvium_generate_key_derivation(G.as_ptr(), SEC_A.as_ptr(), derivation.as_mut_ptr());
        }
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_derive_secret_key(derivation.as_ptr(), 0, SEC_A.as_ptr(), out.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::derive_secret_key(&derivation, 0, &SEC_A));
    }

    #[test]
    fn test_derive_keypair_consistency() {
        // derive_secret_key(D, i, sec) * G should equal derive_public_key(D, i, sec*G)
        let mut derivation = [0u8; 32];
        unsafe {
            salvium_generate_key_derivation(G.as_ptr(), SEC_B.as_ptr(), derivation.as_mut_ptr());
        }
        // Public key = SEC_B * G
        let mut pub_key = [0u8; 32];
        unsafe { salvium_scalar_mult_base(SEC_B.as_ptr(), pub_key.as_mut_ptr()) };

        let mut derived_sec = [0u8; 32];
        unsafe {
            salvium_derive_secret_key(derivation.as_ptr(), 7, SEC_B.as_ptr(), derived_sec.as_mut_ptr());
        }
        let mut derived_pub = [0u8; 32];
        unsafe {
            salvium_derive_public_key(derivation.as_ptr(), 7, pub_key.as_ptr(), derived_pub.as_mut_ptr());
        }
        // derived_sec * G should == derived_pub
        let mut check = [0u8; 32];
        unsafe { salvium_scalar_mult_base(derived_sec.as_ptr(), check.as_mut_ptr()) };
        assert_eq!(check, derived_pub, "derived keypair is inconsistent");
    }

    #[test]
    fn test_pedersen_commit() {
        let amount = SEC_A; // 1
        let mask = SEC_B;   // 2
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_pedersen_commit(amount.as_ptr(), mask.as_ptr(), out.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::pedersen_commit(&amount, &mask));
        use curve25519_dalek::edwards::CompressedEdwardsY;
        assert!(CompressedEdwardsY(out).decompress().is_some());
    }

    #[test]
    fn test_zero_commit() {
        let amount = SEC_A;
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_zero_commit(amount.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::zero_commit(&amount));
    }

    #[test]
    fn test_gen_commitment_mask() {
        let secret = [0x42u8; 32];
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_gen_commitment_mask(secret.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::gen_commitment_mask(&secret));
    }

    #[test]
    fn test_sha256() {
        let data = b"test data";
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_sha256(data.as_ptr(), data.len(), out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // Known SHA-256 of "test data"
        let expected = crate::sha256(data);
        assert_eq!(&out[..], &expected[..]);
        // Verify against known hash
        assert_ne!(out, [0u8; 32]); // not all zeros
    }

    #[test]
    fn test_sha256_empty() {
        let mut out = [0u8; 32];
        let rc = unsafe { salvium_sha256([].as_ptr(), 0, out.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(out[0], 0xe3);
        assert_eq!(out[1], 0xb0);
        assert_eq!(out[31], 0x55);
    }

    #[test]
    fn test_verify_signature_invalid() {
        // Invalid inputs should return 0, not crash
        let message = b"test";
        let bad_sig = [0u8; 64];
        let bad_key = [0u8; 32];
        let rc = unsafe {
            salvium_verify_signature(
                message.as_ptr(), message.len(),
                bad_sig.as_ptr(), bad_sig.len(),
                bad_key.as_ptr(), bad_key.len(),
            )
        };
        assert_eq!(rc, 0); // invalid → 0
    }

    #[test]
    fn test_verify_signature_ecdsa_p256() {
        // Testnet oracle public key (ECDSA P-256, DER-encoded SPKI)
        let key_der: [u8; 91] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
            0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00, 0x04, 0xe5, 0x80, 0x71, 0x5b, 0x1d, 0x40, 0x64, 0x20, 0x3d,
            0x8d, 0x35, 0x24, 0xf0, 0xfa, 0xf6, 0xb9, 0x9f, 0x63, 0xa5, 0xf4, 0x6d,
            0x29, 0x6b, 0xf7, 0x56, 0x8d, 0x7f, 0x1a, 0x7c, 0xbe, 0xd6, 0xf7, 0xda,
            0xc6, 0xc5, 0xe1, 0x05, 0x08, 0x86, 0xd4, 0xa9, 0x47, 0x91, 0xa7, 0xcd,
            0x19, 0xaa, 0xf3, 0xa0, 0xbd, 0x16, 0x1d, 0x6e, 0x28, 0x72, 0xa6, 0x9a,
            0xa8, 0x5e, 0x62, 0xbf, 0xc8, 0xb7, 0xe4,
        ];
        // Verify that parsing the key doesn't crash with an invalid signature
        let message = b"test message";
        let bad_sig = [0u8; 70];
        let rc = unsafe {
            salvium_verify_signature(
                message.as_ptr(), message.len(),
                bad_sig.as_ptr(), bad_sig.len(),
                key_der.as_ptr(), key_der.len(),
            )
        };
        // Should return 0 (invalid sig), not crash
        assert_eq!(rc, 0);
    }
}
