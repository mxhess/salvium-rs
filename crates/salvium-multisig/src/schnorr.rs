//! CryptoNote-style Schnorr signatures over Ed25519.
//!
//! Implements the same scheme used by the C++ multisig KEX message signing:
//! - `k = sc_reduce64(random_64_bytes)` — ephemeral nonce
//! - `R = k * G`
//! - `c = sc_reduce32(keccak256(message || pubkey || R))`
//! - `s = k - c * privkey` (via `sc_mul_sub(c, privkey, k)`)
//!
//! Verification:
//! - `R' = c * pubkey + s * G` (via `double_scalar_mult_base`)
//! - `c' = sc_reduce32(keccak256(message || pubkey || R'))`
//! - Accept if `c == c'`

use serde::{Deserialize, Serialize};

/// A CryptoNote Schnorr signature: (c, s), each 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrSignature {
    /// Challenge scalar c.
    pub c: [u8; 32],
    /// Response scalar s.
    pub s: [u8; 32],
}

impl SchnorrSignature {
    /// Serialize to 64 bytes: `c || s`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.c);
        out[32..].copy_from_slice(&self.s);
        out
    }

    /// Deserialize from 64 bytes: `c || s`.
    pub fn from_bytes(data: &[u8; 64]) -> Self {
        let mut c = [0u8; 32];
        let mut s = [0u8; 32];
        c.copy_from_slice(&data[..32]);
        s.copy_from_slice(&data[32..]);
        Self { c, s }
    }
}

/// Sign a message with a CryptoNote Schnorr signature.
///
/// - `message`: arbitrary-length data to sign
/// - `pubkey`: the signer's 32-byte compressed Ed25519 public key
/// - `privkey`: the signer's 32-byte scalar secret key
///
/// Returns a `SchnorrSignature { c, s }`.
pub fn schnorr_sign(message: &[u8], pubkey: &[u8; 32], privkey: &[u8; 32]) -> SchnorrSignature {
    // Generate random nonce: k = sc_reduce64(random_64_bytes)
    let mut nonce_bytes = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let k = salvium_crypto::sc_reduce64(&nonce_bytes);

    // R = k * G
    let r_point = salvium_crypto::scalar_mult_base(&k);

    // c = sc_reduce32(keccak256(message || pubkey || R))
    let mut hash_data = Vec::with_capacity(message.len() + 32 + 32);
    hash_data.extend_from_slice(message);
    hash_data.extend_from_slice(pubkey);
    hash_data.extend_from_slice(&r_point);
    let c_hash = salvium_crypto::keccak256(&hash_data);
    let c_vec = salvium_crypto::sc_reduce32(&c_hash);

    // s = k - c * privkey  (sc_mul_sub computes c - a*b, i.e. c_arg - a_arg * b_arg)
    // sc_mul_sub(a, b, c) = c - a*b, so sc_mul_sub(c, privkey, k) = k - c*privkey
    let s_vec = salvium_crypto::sc_mul_sub(&c_vec, privkey, &k);

    let mut c = [0u8; 32];
    let mut s = [0u8; 32];
    c.copy_from_slice(&c_vec);
    s.copy_from_slice(&s_vec);

    SchnorrSignature { c, s }
}

/// Verify a CryptoNote Schnorr signature.
///
/// - `message`: the signed data
/// - `pubkey`: the signer's 32-byte compressed Ed25519 public key
/// - `sig`: the `SchnorrSignature` to verify
///
/// Returns `true` if the signature is valid.
pub fn schnorr_verify(message: &[u8], pubkey: &[u8; 32], sig: &SchnorrSignature) -> bool {
    // R' = c * pubkey + s * G  (double_scalar_mult_base(a, p, b) = a*P + b*G)
    let r_prime = salvium_crypto::double_scalar_mult_base(&sig.c, pubkey, &sig.s);
    if r_prime.is_empty() {
        return false;
    }

    // c' = sc_reduce32(keccak256(message || pubkey || R'))
    let mut hash_data = Vec::with_capacity(message.len() + 32 + 32);
    hash_data.extend_from_slice(message);
    hash_data.extend_from_slice(pubkey);
    hash_data.extend_from_slice(&r_prime);
    let c_hash = salvium_crypto::keccak256(&hash_data);
    let c_prime = salvium_crypto::sc_reduce32(&c_hash);

    // Accept if c == c'
    sig.c[..] == c_prime[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> ([u8; 32], [u8; 32]) {
        let privkey_hash = salvium_crypto::keccak256(b"schnorr_test_key");
        let privkey_vec = salvium_crypto::sc_reduce32(&privkey_hash);
        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(&privkey_vec);
        let pubkey_vec = salvium_crypto::scalar_mult_base(&privkey);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_vec);
        (privkey, pubkey)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (privkey, pubkey) = test_keypair();
        let message = b"test message for schnorr signing";
        let sig = schnorr_sign(message, &pubkey, &privkey);
        assert!(schnorr_verify(message, &pubkey, &sig));
    }

    #[test]
    fn wrong_message_fails() {
        let (privkey, pubkey) = test_keypair();
        let sig = schnorr_sign(b"correct message", &pubkey, &privkey);
        assert!(!schnorr_verify(b"wrong message", &pubkey, &sig));
    }

    #[test]
    fn wrong_pubkey_fails() {
        let (privkey, pubkey) = test_keypair();
        let sig = schnorr_sign(b"test message", &pubkey, &privkey);

        // Generate a different pubkey
        let other_hash = salvium_crypto::keccak256(b"other_key");
        let other_priv = salvium_crypto::sc_reduce32(&other_hash);
        let other_pub_vec = salvium_crypto::scalar_mult_base(&other_priv);
        let mut other_pub = [0u8; 32];
        other_pub.copy_from_slice(&other_pub_vec);

        assert!(!schnorr_verify(b"test message", &other_pub, &sig));
    }

    #[test]
    fn corrupted_signature_fails() {
        let (privkey, pubkey) = test_keypair();
        let mut sig = schnorr_sign(b"test message", &pubkey, &privkey);

        // Corrupt the c component
        sig.c[0] ^= 0xFF;
        assert!(!schnorr_verify(b"test message", &pubkey, &sig));

        // Restore c, corrupt s
        sig.c[0] ^= 0xFF;
        sig.s[0] ^= 0xFF;
        assert!(!schnorr_verify(b"test message", &pubkey, &sig));
    }

    #[test]
    fn different_nonces_produce_different_signatures() {
        let (privkey, pubkey) = test_keypair();
        let message = b"same message";
        let sig1 = schnorr_sign(message, &pubkey, &privkey);
        let sig2 = schnorr_sign(message, &pubkey, &privkey);

        // Different random nonces should produce different (c, s) pairs
        // (astronomically unlikely to collide)
        assert_ne!(sig1.c, sig2.c);
        assert_ne!(sig1.s, sig2.s);

        // But both should verify
        assert!(schnorr_verify(message, &pubkey, &sig1));
        assert!(schnorr_verify(message, &pubkey, &sig2));
    }

    #[test]
    fn empty_message_works() {
        let (privkey, pubkey) = test_keypair();
        let sig = schnorr_sign(b"", &pubkey, &privkey);
        assert!(schnorr_verify(b"", &pubkey, &sig));
        assert!(!schnorr_verify(b"non-empty", &pubkey, &sig));
    }

    #[test]
    fn serialization_roundtrip() {
        let (privkey, pubkey) = test_keypair();
        let sig = schnorr_sign(b"test", &pubkey, &privkey);
        let bytes = sig.to_bytes();
        let restored = SchnorrSignature::from_bytes(&bytes);
        assert_eq!(sig, restored);
        assert!(schnorr_verify(b"test", &pubkey, &restored));
    }

    #[test]
    fn large_message() {
        let (privkey, pubkey) = test_keypair();
        let message = vec![0xABu8; 10_000];
        let sig = schnorr_sign(&message, &pubkey, &privkey);
        assert!(schnorr_verify(&message, &pubkey, &sig));
    }
}
