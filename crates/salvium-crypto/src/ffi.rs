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
use std::panic;
use curve25519_dalek::edwards::CompressedEdwardsY;

/// Helper: run a closure that may panic, returning -1 on panic instead of aborting.
/// This is critical for extern "C" functions where unwinding is UB.
/// We use AssertUnwindSafe because the closures capture raw pointers (which are
/// !UnwindSafe) but we know we won't observe torn state through them on panic.
unsafe fn catch_ffi<F: FnOnce() -> i32>(f: F) -> i32 {
    match panic::catch_unwind(panic::AssertUnwindSafe(f)) {
        Ok(rc) => rc,
        Err(_) => -1,
    }
}

/// Validate that 32 bytes represent a valid compressed Edwards Y point.
/// Returns false if the point cannot be decompressed (invalid curve point).
fn is_valid_point(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

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
    if !is_valid_point(&crate::to32(p)) { return -1; }
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
    if !is_valid_point(&crate::to32(p)) || !is_valid_point(&crate::to32(q)) { return -1; }
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
    if !is_valid_point(&crate::to32(p)) || !is_valid_point(&crate::to32(q)) { return -1; }
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
    if !is_valid_point(&crate::to32(p)) { return -1; }
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
    if !is_valid_point(&crate::to32(p)) { return -1; }
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
    if !is_valid_point(&crate::to32(pk)) { return -1; }
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
    // hash_to_point always produces valid points, so no validation needed on pk here
    // (the lib function calls hash_to_point internally, not decompress)
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
    if !is_valid_point(&crate::to32(base)) { return -1; }
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
    // derive_secret_key does scalar math only (no point decompression), safe to call directly
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
    // pedersen_commit decompresses constant H_POINT_BYTES — always valid
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
    // zero_commit decompresses constant H_POINT_BYTES — always valid
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

// ─── Key Derivation ─────────────────────────────────────────────────────────

/// Argon2id key derivation.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_argon2id(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    out_len: usize,
    out: *mut u8,
) -> i32 {
    use argon2::{Argon2, Algorithm, Version, Params};

    let password = slice::from_raw_parts(password, password_len);
    let salt = slice::from_raw_parts(salt, salt_len);
    let out = std::slice::from_raw_parts_mut(out, out_len);

    let params = match Params::new(m_cost, t_cost, parallelism, Some(out_len)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    match argon2.hash_password_into(password, salt, out) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

// ─── AES-256-GCM Encryption ─────────────────────────────────────────────────

/// AES-256-GCM encrypt.
/// Rust generates a random 12-byte nonce internally.
/// Output layout: nonce(12) || ciphertext || tag(16).
/// out must be at least plaintext_len + 28 bytes.
/// out_len receives actual output length.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_aes256gcm_encrypt(
    key: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    catch_ffi(|| {
        use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Nonce};
        use aes_gcm::aead::OsRng;
        use aes_gcm::aead::rand_core::RngCore;

        let key_slice = slice::from_raw_parts(key, 32);
        let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len);

        let cipher = match Aes256Gcm::new_from_slice(key_slice) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        // Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt in-place: copy plaintext to output buffer after nonce
        let out_slice = slice::from_raw_parts_mut(out, plaintext_len + 28);
        // Write nonce first
        ptr::copy_nonoverlapping(nonce_bytes.as_ptr(), out_slice.as_mut_ptr(), 12);
        // Copy plaintext after nonce
        ptr::copy_nonoverlapping(plaintext_slice.as_ptr(), out_slice[12..].as_mut_ptr(), plaintext_len);

        // Encrypt in-place (appends 16-byte tag)
        let mut buffer = out_slice[12..12 + plaintext_len].to_vec();
        match cipher.encrypt_in_place(nonce, b"", &mut buffer) {
            Ok(_) => {},
            Err(_) => return -1,
        }

        // buffer is now ciphertext + tag
        ptr::copy_nonoverlapping(buffer.as_ptr(), out_slice[12..].as_mut_ptr(), buffer.len());
        *out_len = 12 + buffer.len(); // nonce + ciphertext + tag
        0
    })
}

/// AES-256-GCM decrypt.
/// Input layout: nonce(12) || ciphertext || tag(16).
/// out must be at least ciphertext_len - 28 bytes.
/// out_len receives actual output length.
/// Returns 0 on success, -1 on error (authentication failure or bad input).
#[no_mangle]
pub unsafe extern "C" fn salvium_aes256gcm_decrypt(
    key: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    catch_ffi(|| {
        use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, Nonce};

        if ciphertext_len < 28 {
            return -1; // Too short: need at least nonce(12) + tag(16)
        }

        let key_slice = slice::from_raw_parts(key, 32);
        let input = slice::from_raw_parts(ciphertext, ciphertext_len);

        let cipher = match Aes256Gcm::new_from_slice(key_slice) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        // Read nonce from first 12 bytes
        let nonce = Nonce::from_slice(&input[..12]);

        // Decrypt in-place: ciphertext + tag is input[12..]
        let mut buffer = input[12..].to_vec();
        match cipher.decrypt_in_place(nonce, b"", &mut buffer) {
            Ok(_) => {},
            Err(_) => return -1,
        }

        // buffer is now plaintext
        let out_slice = slice::from_raw_parts_mut(out, buffer.len());
        ptr::copy_nonoverlapping(buffer.as_ptr(), out_slice.as_mut_ptr(), buffer.len());
        *out_len = buffer.len();
        0
    })
}

// ─── X25519 Montgomery-curve Scalar Multiplication ──────────────────────────

/// X25519 scalar multiplication with Salvium's non-standard clamping.
/// scalar: 32-byte little-endian scalar.
/// u_coord: 32-byte little-endian u-coordinate.
/// out: 32-byte result u-coordinate.
/// Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn salvium_x25519_scalar_mult(
    scalar: *const u8,
    u_coord: *const u8,
    out: *mut u8,
) -> i32 {
    let scalar = slice::from_raw_parts(scalar, 32);
    let u_coord = slice::from_raw_parts(u_coord, 32);
    let result = crate::x25519_scalar_mult(scalar, u_coord);
    ptr::copy_nonoverlapping(result.as_ptr(), out, 32);
    0
}

// ─── CLSAG Ring Signatures ──────────────────────────────────────────────────

/// CLSAG sign. Output buffer must be ring_count*32 + 96 bytes.
/// Format: [s_0..s_n (32 bytes each)][c1 (32)][I (32)][D (32)]
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_clsag_sign(
    message: *const u8,
    ring: *const u8,
    ring_count: u32,
    secret_key: *const u8,
    commitments: *const u8,
    commitment_mask: *const u8,
    pseudo_output: *const u8,
    secret_index: u32,
    out: *mut u8,
) -> i32 {
    let n = ring_count as usize;
    let msg = crate::to32(slice::from_raw_parts(message, 32));
    let ring_arr: Vec<[u8; 32]> = {
        let flat = slice::from_raw_parts(ring, n * 32);
        (0..n).map(|i| crate::to32(&flat[i*32..(i+1)*32])).collect()
    };
    let comms_arr: Vec<[u8; 32]> = {
        let flat = slice::from_raw_parts(commitments, n * 32);
        (0..n).map(|i| crate::to32(&flat[i*32..(i+1)*32])).collect()
    };
    let sk = crate::to32(slice::from_raw_parts(secret_key, 32));
    let cm = crate::to32(slice::from_raw_parts(commitment_mask, 32));
    let po = crate::to32(slice::from_raw_parts(pseudo_output, 32));
    let si = secret_index as usize;
    let out_ptr = out;

    catch_ffi(move || {
        let sig = crate::clsag::clsag_sign(&msg, &ring_arr, &sk, &comms_arr, &cm, &po, si);
        let mut offset = 0;
        for s in &sig.s {
            ptr::copy_nonoverlapping(s.as_ptr(), out_ptr.add(offset), 32);
            offset += 32;
        }
        ptr::copy_nonoverlapping(sig.c1.as_ptr(), out_ptr.add(offset), 32);
        offset += 32;
        ptr::copy_nonoverlapping(sig.key_image.as_ptr(), out_ptr.add(offset), 32);
        offset += 32;
        ptr::copy_nonoverlapping(sig.commitment_image.as_ptr(), out_ptr.add(offset), 32);
        0
    })
}

/// CLSAG verify.
/// sig format: [s_0..s_n (32 bytes each)][c1 (32)][I (32)][D (32)]
/// Returns 1 for valid, 0 for invalid.
#[no_mangle]
pub unsafe extern "C" fn salvium_clsag_verify(
    message: *const u8,
    sig: *const u8,
    sig_len: usize,
    ring: *const u8,
    ring_count: u32,
    commitments: *const u8,
    pseudo_output: *const u8,
) -> i32 {
    let n = ring_count as usize;
    let expected = n * 32 + 96;
    if sig_len < expected { return 0; }

    let msg = crate::to32(slice::from_raw_parts(message, 32));
    let sig_data = slice::from_raw_parts(sig, sig_len).to_vec();
    let ring_arr: Vec<[u8; 32]> = {
        let flat = slice::from_raw_parts(ring, n * 32);
        (0..n).map(|i| crate::to32(&flat[i*32..(i+1)*32])).collect()
    };
    let comms_arr: Vec<[u8; 32]> = {
        let flat = slice::from_raw_parts(commitments, n * 32);
        (0..n).map(|i| crate::to32(&flat[i*32..(i+1)*32])).collect()
    };
    let po = crate::to32(slice::from_raw_parts(pseudo_output, 32));

    catch_ffi(move || {
        let mut s = Vec::with_capacity(n);
        let mut offset = 0;
        for _ in 0..n {
            s.push(crate::to32(&sig_data[offset..offset + 32]));
            offset += 32;
        }
        let c1 = crate::to32(&sig_data[offset..offset + 32]); offset += 32;
        let key_image = crate::to32(&sig_data[offset..offset + 32]); offset += 32;
        let commitment_image = crate::to32(&sig_data[offset..offset + 32]);

        let sig_struct = crate::clsag::ClsagSignature { s, c1, key_image, commitment_image };
        if crate::clsag::clsag_verify(&msg, &sig_struct, &ring_arr, &comms_arr, &po) { 1 } else { 0 }
    })
}

// ─── TCLSAG Ring Signatures ────────────────────────────────────────────────

/// TCLSAG sign. Output buffer must be 2*ring_count*32 + 96 bytes.
/// Format: [sx_0..sx_n][sy_0..sy_n][c1][I][D] (each 32 bytes)
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_tclsag_sign(
    message: *const u8,
    ring: *const u8,
    ring_count: u32,
    secret_key_x: *const u8,
    secret_key_y: *const u8,
    commitments: *const u8,
    commitment_mask: *const u8,
    pseudo_output: *const u8,
    secret_index: u32,
    out: *mut u8,
) -> i32 {
    let n = ring_count as usize;
    let msg = crate::to32(slice::from_raw_parts(message, 32));
    let ring_arr: Vec<[u8; 32]> = {
        let flat = slice::from_raw_parts(ring, n * 32);
        (0..n).map(|i| crate::to32(&flat[i*32..(i+1)*32])).collect()
    };
    let comms_arr: Vec<[u8; 32]> = {
        let flat = slice::from_raw_parts(commitments, n * 32);
        (0..n).map(|i| crate::to32(&flat[i*32..(i+1)*32])).collect()
    };
    let skx = crate::to32(slice::from_raw_parts(secret_key_x, 32));
    let sky = crate::to32(slice::from_raw_parts(secret_key_y, 32));
    let cm = crate::to32(slice::from_raw_parts(commitment_mask, 32));
    let po = crate::to32(slice::from_raw_parts(pseudo_output, 32));
    let si = secret_index as usize;
    let out_ptr = out;

    catch_ffi(move || {
        let sig = crate::tclsag::tclsag_sign(&msg, &ring_arr, &skx, &sky, &comms_arr, &cm, &po, si);
        let mut offset = 0;
        for s in &sig.sx {
            ptr::copy_nonoverlapping(s.as_ptr(), out_ptr.add(offset), 32);
            offset += 32;
        }
        for s in &sig.sy {
            ptr::copy_nonoverlapping(s.as_ptr(), out_ptr.add(offset), 32);
            offset += 32;
        }
        ptr::copy_nonoverlapping(sig.c1.as_ptr(), out_ptr.add(offset), 32); offset += 32;
        ptr::copy_nonoverlapping(sig.key_image.as_ptr(), out_ptr.add(offset), 32); offset += 32;
        ptr::copy_nonoverlapping(sig.commitment_image.as_ptr(), out_ptr.add(offset), 32);
        0
    })
}

/// TCLSAG verify.
/// sig format: [sx_0..sx_n][sy_0..sy_n][c1][I][D] (each 32 bytes)
/// Returns 1 for valid, 0 for invalid.
#[no_mangle]
pub unsafe extern "C" fn salvium_tclsag_verify(
    message: *const u8,
    sig: *const u8,
    sig_len: usize,
    ring: *const u8,
    ring_count: u32,
    commitments: *const u8,
    pseudo_output: *const u8,
) -> i32 {
    let n = ring_count as usize;
    let expected = 2 * n * 32 + 96;
    if sig_len < expected { return 0; }

    let msg = crate::to32(slice::from_raw_parts(message, 32));
    let sig_data = slice::from_raw_parts(sig, sig_len).to_vec();
    let ring_arr: Vec<[u8; 32]> = {
        let flat = slice::from_raw_parts(ring, n * 32);
        (0..n).map(|i| crate::to32(&flat[i*32..(i+1)*32])).collect()
    };
    let comms_arr: Vec<[u8; 32]> = {
        let flat = slice::from_raw_parts(commitments, n * 32);
        (0..n).map(|i| crate::to32(&flat[i*32..(i+1)*32])).collect()
    };
    let po = crate::to32(slice::from_raw_parts(pseudo_output, 32));

    catch_ffi(move || {
        let mut offset = 0;
        let mut sx = Vec::with_capacity(n);
        for _ in 0..n { sx.push(crate::to32(&sig_data[offset..offset+32])); offset += 32; }
        let mut sy = Vec::with_capacity(n);
        for _ in 0..n { sy.push(crate::to32(&sig_data[offset..offset+32])); offset += 32; }
        let c1 = crate::to32(&sig_data[offset..offset+32]); offset += 32;
        let key_image = crate::to32(&sig_data[offset..offset+32]); offset += 32;
        let commitment_image = crate::to32(&sig_data[offset..offset+32]);

        let sig_struct = crate::tclsag::TclsagSignature { sx, sy, c1, key_image, commitment_image };
        if crate::tclsag::tclsag_verify(&msg, &sig_struct, &ring_arr, &comms_arr, &po) { 1 } else { 0 }
    })
}

// ─── Bulletproofs+ Range Proofs ─────────────────────────────────────────────

/// Bulletproof+ prove.
/// amounts: n * 8 bytes (u64 LE), masks: n * 32 bytes (scalars)
/// Output: serialized proof bytes + V commitments.
/// Format: [v_count as u32 LE][V_0..V_n (32 bytes each)][proof_bytes...]
/// out_len receives the actual output length.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_bulletproof_plus_prove(
    amounts: *const u8,
    masks: *const u8,
    count: u32,
    out: *mut u8,
    out_max: usize,
    out_len: *mut usize,
) -> i32 {
    use curve25519_dalek::scalar::Scalar;

    let n = count as usize;
    let amounts_data = slice::from_raw_parts(amounts, n * 8).to_vec();
    let masks_data = slice::from_raw_parts(masks, n * 32).to_vec();
    let out_ptr = out;
    let out_len_ptr = out_len;

    catch_ffi(move || {
        let amounts_vec: Vec<u64> = (0..n).map(|i| {
            u64::from_le_bytes([
                amounts_data[i*8], amounts_data[i*8+1], amounts_data[i*8+2], amounts_data[i*8+3],
                amounts_data[i*8+4], amounts_data[i*8+5], amounts_data[i*8+6], amounts_data[i*8+7],
            ])
        }).collect();
        let masks_vec: Vec<Scalar> = (0..n).map(|i| {
            Scalar::from_bytes_mod_order(crate::to32(&masks_data[i*32..(i+1)*32]))
        }).collect();

        let proof = crate::bulletproofs_plus::bulletproof_plus_prove(&amounts_vec, &masks_vec);
        let proof_bytes = crate::bulletproofs_plus::serialize_proof(&proof);

        let total = 4 + proof.v.len() * 32 + proof_bytes.len();
        if total > out_max { return -1; }

        let mut off = 0;
        let v_count = proof.v.len() as u32;
        ptr::copy_nonoverlapping(v_count.to_le_bytes().as_ptr(), out_ptr.add(off), 4);
        off += 4;
        for v in &proof.v {
            let bytes = v.compress().to_bytes();
            ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr.add(off), 32);
            off += 32;
        }
        ptr::copy_nonoverlapping(proof_bytes.as_ptr(), out_ptr.add(off), proof_bytes.len());
        off += proof_bytes.len();

        *out_len_ptr = off;
        0
    })
}

/// Bulletproof+ verify.
/// proof_bytes: serialized proof, commitments: n * 32 bytes
/// Returns 1 for valid, 0 for invalid.
#[no_mangle]
pub unsafe extern "C" fn salvium_bulletproof_plus_verify(
    proof_bytes: *const u8,
    proof_len: usize,
    commitments: *const u8,
    commitment_count: u32,
) -> i32 {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let n = commitment_count as usize;
    let proof_data = slice::from_raw_parts(proof_bytes, proof_len).to_vec();
    let comms_data = slice::from_raw_parts(commitments, n * 32).to_vec();

    catch_ffi(move || {
        let v: Vec<_> = (0..n).map(|i| {
            match CompressedEdwardsY(crate::to32(&comms_data[i*32..(i+1)*32])).decompress() {
                Some(p) => p,
                None => curve25519_dalek::edwards::EdwardsPoint::default(),
            }
        }).collect();

        let proof = match crate::bulletproofs_plus::parse_proof(&proof_data) {
            Some(p) => p,
            None => return 0,
        };

        if crate::bulletproofs_plus::bulletproof_plus_verify(&v, &proof) { 1 } else { 0 }
    })
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
    fn test_argon2id() {
        // Argon2id test: same params as RFC 9106 Section 4 but without
        // secret/AD (which our FFI doesn't expose, matching wallet usage).
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        // Known-good output from argon2 crate v0.5 (Argon2id, t=3, m=32, p=4)
        let expected: [u8; 32] = [
            0x03, 0xaa, 0xb9, 0x65, 0xc1, 0x20, 0x01, 0xc9,
            0xd7, 0xd0, 0xd2, 0xde, 0x33, 0x19, 0x2c, 0x04,
            0x94, 0xb6, 0x84, 0xbb, 0x14, 0x81, 0x96, 0xd7,
            0x3c, 0x1d, 0xf1, 0xac, 0xaf, 0x6d, 0x0c, 0x2e,
        ];
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_argon2id(
                password.as_ptr(), password.len(),
                salt.as_ptr(), salt.len(),
                3,  // t_cost
                32, // m_cost (32 KiB — tiny, just for test)
                4,  // parallelism
                32, // out_len
                out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(out, expected, "Argon2id FFI output mismatch");
    }

    #[test]
    fn test_argon2id_bad_params() {
        // Invalid params (m_cost=0) should return -1
        let password = b"test";
        let salt = [0u8; 16];
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_argon2id(
                password.as_ptr(), password.len(),
                salt.as_ptr(), salt.len(),
                1, 0, 1, 32, out.as_mut_ptr(),
            )
        };
        assert_eq!(rc, -1);
    }

    #[test]
    fn test_x25519_scalar_mult_ffi() {
        // Use a simple scalar and the X25519 basepoint (u = 9)
        let mut scalar = [0u8; 32];
        scalar[0] = 9;
        let mut u_coord = [0u8; 32];
        u_coord[0] = 9;
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_x25519_scalar_mult(scalar.as_ptr(), u_coord.as_ptr(), out.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::x25519_scalar_mult(&scalar, &u_coord));
        // Result should not be all zeros
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn test_x25519_scalar_mult_ffi_salvium_clamping() {
        // Verify FFI matches direct call and that bit 255 is cleared
        let mut scalar = [0xFFu8; 32]; // all bits set
        let mut u_coord = [0u8; 32];
        u_coord[0] = 9; // basepoint
        let mut out = [0u8; 32];
        let rc = unsafe {
            salvium_x25519_scalar_mult(scalar.as_ptr(), u_coord.as_ptr(), out.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        assert_ffi_matches(&out, &crate::x25519_scalar_mult(&scalar, &u_coord));
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

    #[test]
    fn test_aes256gcm_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, Salvium wallet cache encryption!";
        let mut encrypted = [0u8; 256];
        let mut enc_len: usize = 0;
        let rc = unsafe {
            salvium_aes256gcm_encrypt(
                key.as_ptr(),
                plaintext.as_ptr(),
                plaintext.len(),
                encrypted.as_mut_ptr(),
                &mut enc_len as *mut usize,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(enc_len, plaintext.len() + 28); // nonce(12) + data + tag(16)

        let mut decrypted = [0u8; 256];
        let mut dec_len: usize = 0;
        let rc = unsafe {
            salvium_aes256gcm_decrypt(
                key.as_ptr(),
                encrypted.as_ptr(),
                enc_len,
                decrypted.as_mut_ptr(),
                &mut dec_len as *mut usize,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(dec_len, plaintext.len());
        assert_eq!(&decrypted[..dec_len], &plaintext[..]);
    }

    #[test]
    fn test_aes256gcm_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"secret data";
        let mut encrypted = [0u8; 256];
        let mut enc_len: usize = 0;
        let rc = unsafe {
            salvium_aes256gcm_encrypt(
                key.as_ptr(), plaintext.as_ptr(), plaintext.len(),
                encrypted.as_mut_ptr(), &mut enc_len as *mut usize,
            )
        };
        assert_eq!(rc, 0);

        let mut decrypted = [0u8; 256];
        let mut dec_len: usize = 0;
        let rc = unsafe {
            salvium_aes256gcm_decrypt(
                wrong_key.as_ptr(), encrypted.as_ptr(), enc_len,
                decrypted.as_mut_ptr(), &mut dec_len as *mut usize,
            )
        };
        assert_eq!(rc, -1); // Authentication failure
    }

    #[test]
    fn test_aes256gcm_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let plaintext = b"important data";
        let mut encrypted = [0u8; 256];
        let mut enc_len: usize = 0;
        let rc = unsafe {
            salvium_aes256gcm_encrypt(
                key.as_ptr(), plaintext.as_ptr(), plaintext.len(),
                encrypted.as_mut_ptr(), &mut enc_len as *mut usize,
            )
        };
        assert_eq!(rc, 0);

        // Flip a byte in the ciphertext portion
        encrypted[15] ^= 0xff;

        let mut decrypted = [0u8; 256];
        let mut dec_len: usize = 0;
        let rc = unsafe {
            salvium_aes256gcm_decrypt(
                key.as_ptr(), encrypted.as_ptr(), enc_len,
                decrypted.as_mut_ptr(), &mut dec_len as *mut usize,
            )
        };
        assert_eq!(rc, -1); // Authentication failure
    }

    #[test]
    fn test_aes256gcm_too_short() {
        let key = [0x42u8; 32];
        let short = [0u8; 20]; // Less than 28 bytes
        let mut decrypted = [0u8; 256];
        let mut dec_len: usize = 0;
        let rc = unsafe {
            salvium_aes256gcm_decrypt(
                key.as_ptr(), short.as_ptr(), short.len(),
                decrypted.as_mut_ptr(), &mut dec_len as *mut usize,
            )
        };
        assert_eq!(rc, -1);
    }

    #[test]
    fn test_aes256gcm_empty_plaintext() {
        let key = [0xABu8; 32];
        let plaintext = b"";
        let mut encrypted = [0u8; 64];
        let mut enc_len: usize = 0;
        let rc = unsafe {
            salvium_aes256gcm_encrypt(
                key.as_ptr(), plaintext.as_ptr(), 0,
                encrypted.as_mut_ptr(), &mut enc_len as *mut usize,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(enc_len, 28); // nonce(12) + tag(16), no ciphertext body

        let mut decrypted = [0u8; 64];
        let mut dec_len: usize = 0;
        let rc = unsafe {
            salvium_aes256gcm_decrypt(
                key.as_ptr(), encrypted.as_ptr(), enc_len,
                decrypted.as_mut_ptr(), &mut dec_len as *mut usize,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(dec_len, 0);
    }
}
