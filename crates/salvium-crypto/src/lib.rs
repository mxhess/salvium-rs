use wasm_bindgen::prelude::*;
use tiny_keccak::{Hasher, Keccak};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use sha2::{Sha256, Digest};

mod elligator2;

#[cfg(not(target_arch = "wasm32"))]
mod ffi;

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

// ─── Phase 3: Hash-to-Point & Key Derivation ────────────────────────────────

fn keccak256_internal(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(data);
    keccak.finalize(&mut output);
    output
}

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

fn derivation_to_scalar(derivation: &[u8], output_index: u32) -> Scalar {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(derivation);
    encode_varint(output_index, &mut buf);
    let hash = keccak256_internal(&buf);
    Scalar::from_bytes_mod_order(hash)
}

/// Hash-to-point: H_p(data) = cofactor * elligator2(keccak256(data))
/// Matches Salvium C++ hash_to_ec / ge_fromfe_frombytes_vartime
#[wasm_bindgen]
pub fn hash_to_point(data: &[u8]) -> Vec<u8> {
    let hash = keccak256_internal(data);
    let point = elligator2::ge_fromfe_frombytes_vartime(&hash);
    // Multiply by cofactor 8
    let cofactored = point + point; // 2P
    let cofactored = cofactored + cofactored; // 4P
    let cofactored = cofactored + cofactored; // 8P
    cofactored.compress().to_bytes().to_vec()
}

/// Generate key image: KI = sec * H_p(pub)
#[wasm_bindgen]
pub fn generate_key_image(pub_key: &[u8], sec_key: &[u8]) -> Vec<u8> {
    let hash = keccak256_internal(pub_key);
    let hp = elligator2::ge_fromfe_frombytes_vartime(&hash);
    // Cofactor multiply
    let hp8 = {
        let t = hp + hp;
        let t = t + t;
        t + t
    };
    let scalar = Scalar::from_bytes_mod_order(to32(sec_key));
    EdwardsPoint::vartime_multiscalar_mul(&[scalar], &[hp8])
        .compress().to_bytes().to_vec()
}

/// Generate key derivation: D = 8 * (sec * pub)
#[wasm_bindgen]
pub fn generate_key_derivation(pub_key: &[u8], sec_key: &[u8]) -> Vec<u8> {
    let point = CompressedEdwardsY(to32(pub_key)).decompress().expect("invalid pub key");
    let scalar = Scalar::from_bytes_mod_order(to32(sec_key));
    let shared = scalar * point;
    // Cofactor multiply by 8
    let result = {
        let t = shared + shared;
        let t = t + t;
        t + t
    };
    result.compress().to_bytes().to_vec()
}

/// Derive public key: base + H(derivation || index) * G
#[wasm_bindgen]
pub fn derive_public_key(derivation: &[u8], output_index: u32, base_pub: &[u8]) -> Vec<u8> {
    let scalar = derivation_to_scalar(derivation, output_index);
    let base = CompressedEdwardsY(to32(base_pub)).decompress().expect("invalid base pub key");
    let derived = ED25519_BASEPOINT_TABLE * &scalar + base;
    derived.compress().to_bytes().to_vec()
}

/// Derive secret key: base + H(derivation || index) mod L
#[wasm_bindgen]
pub fn derive_secret_key(derivation: &[u8], output_index: u32, base_sec: &[u8]) -> Vec<u8> {
    let scalar = derivation_to_scalar(derivation, output_index);
    let base = Scalar::from_bytes_mod_order(to32(base_sec));
    (base + scalar).to_bytes().to_vec()
}

// ─── Phase 4: Pedersen Commitments ──────────────────────────────────────────

/// H generator for Pedersen commitments: H = H_p(G)
/// Precomputed from Salvium/CryptoNote rctTypes.h
const H_POINT_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// Pedersen commitment: C = mask*G + amount*H
#[wasm_bindgen]
pub fn pedersen_commit(amount: &[u8], mask: &[u8]) -> Vec<u8> {
    let amount_scalar = Scalar::from_bytes_mod_order(to32(amount));
    let mask_scalar = Scalar::from_bytes_mod_order(to32(mask));
    let h = CompressedEdwardsY(H_POINT_BYTES).decompress().expect("invalid H");
    // mask*G + amount*H
    EdwardsPoint::vartime_multiscalar_mul(
        &[mask_scalar, amount_scalar],
        &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, h],
    ).compress().to_bytes().to_vec()
}

/// Zero commitment: C = 1*G + amount*H (blinding factor = 1)
/// Matches C++ rct::zeroCommit() used for coinbase outputs and fee commitments.
#[wasm_bindgen]
pub fn zero_commit(amount: &[u8]) -> Vec<u8> {
    let amount_scalar = Scalar::from_bytes_mod_order(to32(amount));
    let mask_scalar = Scalar::ONE;
    let h = CompressedEdwardsY(H_POINT_BYTES).decompress().expect("invalid H");
    // 1*G + amount*H
    EdwardsPoint::vartime_multiscalar_mul(
        &[mask_scalar, amount_scalar],
        &[curve25519_dalek::constants::ED25519_BASEPOINT_POINT, h],
    ).compress().to_bytes().to_vec()
}

/// Generate commitment mask from shared secret
/// mask = scReduce32(keccak256("commitment_mask" || sharedSecret))
#[wasm_bindgen]
pub fn gen_commitment_mask(shared_secret: &[u8]) -> Vec<u8> {
    let prefix = b"commitment_mask";
    let mut data = Vec::with_capacity(prefix.len() + shared_secret.len());
    data.extend_from_slice(prefix);
    data.extend_from_slice(shared_secret);
    let hash = keccak256_internal(&data);
    Scalar::from_bytes_mod_order(hash).to_bytes().to_vec()
}

// ============================================================================
// Oracle Signature Verification (SHA-256, ECDSA P-256, DSA)
// ============================================================================

/// SHA-256 hash
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Verify a signature against a DER-encoded SubjectPublicKeyInfo (SPKI) key.
///
/// Supports:
///   - ECDSA P-256 (testnet oracle) — OID 1.2.840.10045.2.1
///   - DSA (mainnet oracle) — OID 1.2.840.10040.4.1
///
/// The message is hashed with SHA-256 internally (matching Node.js createVerify('SHA256')).
/// Signature must be DER-encoded (ASN.1 SEQUENCE of two INTEGERs r, s).
/// Public key is the raw DER bytes of the SPKI structure (base64-decoded PEM body).
///
/// Returns 1 for valid, 0 for invalid/error.
///
/// Only available on native targets (not WASM). On WASM, the JS crypto shim is used.
#[cfg(not(target_arch = "wasm32"))]
#[wasm_bindgen]
pub fn verify_signature(message: &[u8], signature: &[u8], pubkey_der: &[u8]) -> i32 {
    verify_signature_internal(message, signature, pubkey_der)
        .unwrap_or(0)
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_signature_internal(message: &[u8], signature: &[u8], pubkey_der: &[u8]) -> Option<i32> {
    use spki::SubjectPublicKeyInfoRef;
    use der::Decode;

    // Parse the SPKI structure to determine algorithm
    let spki = SubjectPublicKeyInfoRef::from_der(pubkey_der).ok()?;
    let algorithm_oid = spki.algorithm.oid;

    // OID 1.2.840.10045.2.1 = id-ecPublicKey (ECDSA)
    const EC_PUBLIC_KEY_OID: der::oid::ObjectIdentifier =
        der::oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    // OID 1.2.840.10040.4.1 = id-dsa (DSA)
    const DSA_OID: der::oid::ObjectIdentifier =
        der::oid::ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");

    if algorithm_oid == EC_PUBLIC_KEY_OID {
        verify_ecdsa_p256(message, signature, pubkey_der)
    } else if algorithm_oid == DSA_OID {
        verify_dsa(message, signature, pubkey_der)
    } else {
        None // Unknown algorithm
    }
}

/// Verify ECDSA P-256 signature (SHA-256 digest)
#[cfg(not(target_arch = "wasm32"))]
fn verify_ecdsa_p256(message: &[u8], signature: &[u8], pubkey_der: &[u8]) -> Option<i32> {
    use p256::ecdsa::{VerifyingKey, Signature};
    use spki::DecodePublicKey;

    let verifying_key = VerifyingKey::from_public_key_der(pubkey_der).ok()?;
    let sig = Signature::from_der(signature).ok()?;

    // SHA-256 hash the message first (matching createVerify('SHA256'))
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize()
    };

    // p256 ecdsa Verifier::verify expects pre-hashed when using verify_prehash
    // But the standard Verifier trait hashes internally. Since createVerify('SHA256')
    // hashes with SHA-256 then verifies, we use verify_prehash.
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    match verifying_key.verify_prehash(&digest, &sig) {
        Ok(()) => Some(1),
        Err(_) => Some(0),
    }
}

/// Verify DSA signature (SHA-256 digest)
#[cfg(not(target_arch = "wasm32"))]
fn verify_dsa(message: &[u8], signature: &[u8], pubkey_der: &[u8]) -> Option<i32> {
    use dsa::{VerifyingKey, Signature, signature::hazmat::PrehashVerifier};
    use spki::DecodePublicKey;
    use der::Decode as _;

    let verifying_key = VerifyingKey::from_public_key_der(pubkey_der).ok()?;

    // Parse DER signature
    let sig = Signature::from_der(signature).ok()?;

    // SHA-256 hash the message
    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize()
    };

    match verifying_key.verify_prehash(&digest, &sig) {
        Ok(()) => Some(1),
        Err(_) => Some(0),
    }
}
