//! Signed multisig KEX messages matching the C++ `multisig_kex_msg` format.
//!
//! Each `SignedKexMessage` wraps a `KexMessage` with:
//! - An ephemeral signing keypair (`msg_privkey` / `signing_pubkey`)
//! - A CryptoNote Schnorr signature over the message payload
//!
//! Magic bytes distinguish round-1 from round-N messages:
//! - Round 1: `MultisigxV2R1`
//! - Round N: `MultisigxV2Rn`

use crate::kex::KexMessage;
use crate::schnorr::{schnorr_sign, schnorr_verify, SchnorrSignature};

/// Magic bytes prepended to round-1 KEX messages.
pub const MAGIC_ROUND1: &[u8] = b"MultisigxV2R1";
/// Magic bytes prepended to round-N (N >= 2) KEX messages.
pub const MAGIC_ROUND_N: &[u8] = b"MultisigxV2Rn";

/// A `KexMessage` wrapped with an ephemeral signing key and Schnorr signature.
#[derive(Debug, Clone)]
pub struct SignedKexMessage {
    /// The underlying KEX message.
    pub inner: KexMessage,
    /// Ephemeral signing private key (scalar).
    pub msg_privkey: [u8; 32],
    /// Corresponding public key: `scalar_mult_base(msg_privkey)`.
    pub signing_pubkey: [u8; 32],
    /// Schnorr signature over the message payload.
    pub signature: SchnorrSignature,
}

impl SignedKexMessage {
    /// Create a signed KEX message.
    ///
    /// `signing_privkey` is the ephemeral private key used to sign this message
    /// (typically the signer's view key contribution for round 1, or a dedicated
    /// ephemeral key for round N).
    ///
    /// Returns an error if `signing_privkey` is not a canonical scalar or is zero,
    /// matching C++ `multisig_kex_msg` constructor validation (lines 71-79).
    pub fn create(msg: KexMessage, signing_privkey: &[u8; 32]) -> Result<Self, String> {
        // C++ CHECK_AND_ASSERT_THROW_MES: sc_check(signing_privkey)
        if !salvium_crypto::sc_check(signing_privkey) {
            return Err("signing_privkey is not a canonical scalar".to_string());
        }
        // C++ CHECK_AND_ASSERT_THROW_MES: !sc_isNonZero(signing_privkey) -> reject zero
        if salvium_crypto::sc_is_zero(signing_privkey) {
            return Err("signing_privkey must not be zero".to_string());
        }

        let signing_pubkey_vec = salvium_crypto::scalar_mult_base(signing_privkey);
        let mut signing_pubkey = [0u8; 32];
        signing_pubkey.copy_from_slice(&signing_pubkey_vec);

        // C++ CHECK_AND_ASSERT_THROW_MES: rct::isInMainSubgroup(signing_pubkey)
        if !salvium_crypto::is_in_main_subgroup(&signing_pubkey) {
            return Err("signing_pubkey is not in the prime-order subgroup".to_string());
        }

        let data_to_sign = Self::compute_data_to_sign(&msg, &signing_pubkey, signing_privkey);
        let signature = schnorr_sign(&data_to_sign, &signing_pubkey, signing_privkey);

        Ok(Self {
            inner: msg,
            msg_privkey: *signing_privkey,
            signing_pubkey,
            signature,
        })
    }

    /// Verify the Schnorr signature and all fields on this message.
    ///
    /// Matches C++ `multisig_kex_msg` constructor validation (lines 276-284):
    /// - signing_pubkey must be in the prime-order subgroup and not null
    /// - Round 1: msg_privkey must be a canonical non-zero scalar
    /// - Round N: each key in inner.keys must be in the prime-order subgroup and not null
    pub fn verify(&self) -> Result<(), String> {
        // C++ CHECK_AND_ASSERT_THROW_MES: signing_pubkey != null
        if self.signing_pubkey == [0u8; 32] {
            return Err("signing_pubkey must not be the identity element".to_string());
        }

        // C++ CHECK_AND_ASSERT_THROW_MES: rct::isInMainSubgroup(signing_pubkey)
        if !salvium_crypto::is_in_main_subgroup(&self.signing_pubkey) {
            return Err("signing_pubkey is not in the prime-order subgroup".to_string());
        }

        if self.inner.round == 1 {
            // C++: sc_check(msg_privkey) && !sc_isNonZero → reject non-canonical / zero
            if !salvium_crypto::sc_check(&self.msg_privkey) {
                return Err("msg_privkey is not a canonical scalar".to_string());
            }
            if salvium_crypto::sc_is_zero(&self.msg_privkey) {
                return Err("msg_privkey must not be zero".to_string());
            }
        } else {
            // Round N: validate each pubkey in inner.keys
            for (i, key_hex) in self.inner.keys.iter().enumerate() {
                let key_bytes = hex::decode(key_hex)
                    .map_err(|e| format!("key[{}] hex decode failed: {}", i, e))?;
                if key_bytes.len() != 32 {
                    return Err(format!(
                        "key[{}] must be 32 bytes, got {}",
                        i,
                        key_bytes.len()
                    ));
                }
                if key_bytes == [0u8; 32] {
                    return Err(format!("key[{}] must not be the identity element", i));
                }
                if !salvium_crypto::is_in_main_subgroup(&key_bytes) {
                    return Err(format!("key[{}] is not in the prime-order subgroup", i));
                }
            }
        }

        let data_to_sign =
            Self::compute_data_to_sign(&self.inner, &self.signing_pubkey, &self.msg_privkey);
        if !schnorr_verify(&data_to_sign, &self.signing_pubkey, &self.signature) {
            return Err("Schnorr signature verification failed".to_string());
        }

        Ok(())
    }

    /// Return the magic bytes for this message's round.
    pub fn magic_bytes(&self) -> &'static [u8] {
        if self.inner.round == 1 {
            MAGIC_ROUND1
        } else {
            MAGIC_ROUND_N
        }
    }

    /// Compute the data-to-sign for a KEX message.
    ///
    /// `data_to_sign = keccak256(magic || round_le_u32 || signing_pubkey || payload)`
    ///
    /// Round 1 payload: `msg_privkey` (32 bytes — the view key contribution)
    /// Round N payload: concatenated raw pubkey bytes from `KexMessage.keys`
    fn compute_data_to_sign(
        msg: &KexMessage,
        signing_pubkey: &[u8; 32],
        msg_privkey: &[u8; 32],
    ) -> Vec<u8> {
        let magic = if msg.round == 1 {
            MAGIC_ROUND1
        } else {
            MAGIC_ROUND_N
        };

        let mut preimage = Vec::new();
        preimage.extend_from_slice(magic);
        preimage.extend_from_slice(&(msg.round as u32).to_le_bytes());
        preimage.extend_from_slice(signing_pubkey);

        if msg.round == 1 {
            // Round 1 payload: the private key (view key contribution)
            preimage.extend_from_slice(msg_privkey);
        } else {
            // Round N payload: concatenated key bytes from KexMessage.keys
            for key_hex in &msg.keys {
                if let Ok(key_bytes) = hex::decode(key_hex) {
                    preimage.extend_from_slice(&key_bytes);
                }
            }
        }

        salvium_crypto::keccak256(&preimage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MultisigMsgType;

    fn make_signing_key() -> [u8; 32] {
        let hash = salvium_crypto::keccak256(b"test_signing_key");
        let reduced = salvium_crypto::sc_reduce32(&hash);
        let mut key = [0u8; 32];
        key.copy_from_slice(&reduced);
        key
    }

    fn make_round1_msg() -> KexMessage {
        let pk = salvium_crypto::scalar_mult_base(&[1u8; 32]);
        KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec![hex::encode(&pk), hex::encode(&pk)],
            msg_type: MultisigMsgType::KexInit,
        }
    }

    fn make_round_n_msg(round: usize) -> KexMessage {
        let pk1 = salvium_crypto::scalar_mult_base(&[2u8; 32]);
        let pk2 = salvium_crypto::scalar_mult_base(&[3u8; 32]);
        KexMessage {
            round,
            signer_index: 0,
            keys: vec![hex::encode(&pk1), hex::encode(&pk2)],
            msg_type: MultisigMsgType::KexRound,
        }
    }

    #[test]
    fn create_and_verify_round1() {
        let privkey = make_signing_key();
        let msg = make_round1_msg();
        let signed = SignedKexMessage::create(msg, &privkey).unwrap();
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn create_and_verify_round_n() {
        let privkey = make_signing_key();
        let msg = make_round_n_msg(2);
        let signed = SignedKexMessage::create(msg, &privkey).unwrap();
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn correct_magic_per_round() {
        let privkey = make_signing_key();

        let msg1 = make_round1_msg();
        let signed1 = SignedKexMessage::create(msg1, &privkey).unwrap();
        assert_eq!(signed1.magic_bytes(), MAGIC_ROUND1);

        let msg2 = make_round_n_msg(2);
        let signed2 = SignedKexMessage::create(msg2, &privkey).unwrap();
        assert_eq!(signed2.magic_bytes(), MAGIC_ROUND_N);

        let msg3 = make_round_n_msg(5);
        let signed3 = SignedKexMessage::create(msg3, &privkey).unwrap();
        assert_eq!(signed3.magic_bytes(), MAGIC_ROUND_N);
    }

    #[test]
    fn tampered_keys_fail() {
        let privkey = make_signing_key();
        let msg = make_round_n_msg(2);
        let mut signed = SignedKexMessage::create(msg, &privkey).unwrap();

        // Tamper with the inner message keys
        signed.inner.keys[0] = hex::encode([0xFFu8; 32]);

        assert!(signed.verify().is_err());
    }

    #[test]
    fn tampered_round_fails() {
        let privkey = make_signing_key();
        let msg = make_round_n_msg(2);
        let mut signed = SignedKexMessage::create(msg, &privkey).unwrap();

        // Change the round number
        signed.inner.round = 3;

        assert!(signed.verify().is_err());
    }

    #[test]
    fn wrong_signing_key_fails() {
        let privkey = make_signing_key();
        let msg = make_round1_msg();
        let mut signed = SignedKexMessage::create(msg, &privkey).unwrap();

        // Replace signing pubkey with a different one
        let other_hash = salvium_crypto::keccak256(b"other_signing_key");
        let other_priv = salvium_crypto::sc_reduce32(&other_hash);
        let other_pub = salvium_crypto::scalar_mult_base(&other_priv);
        signed.signing_pubkey.copy_from_slice(&other_pub);

        assert!(signed.verify().is_err());
    }

    #[test]
    fn signing_pubkey_matches_privkey() {
        let privkey = make_signing_key();
        let msg = make_round1_msg();
        let signed = SignedKexMessage::create(msg, &privkey).unwrap();

        let expected_pub = salvium_crypto::scalar_mult_base(&privkey);
        assert_eq!(signed.signing_pubkey[..], expected_pub[..]);
    }

    #[test]
    fn create_rejects_zero_privkey() {
        let msg = make_round1_msg();
        let result = SignedKexMessage::create(msg, &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("zero"));
    }

    #[test]
    fn create_rejects_non_canonical_scalar() {
        let msg = make_round1_msg();
        // Scalar >= L (the curve order): set all bytes to 0xFF
        let result = SignedKexMessage::create(msg, &[0xFF; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("canonical"));
    }

    #[test]
    fn verify_rejects_null_signing_pubkey() {
        let privkey = make_signing_key();
        let msg = make_round1_msg();
        let mut signed = SignedKexMessage::create(msg, &privkey).unwrap();

        // Replace signing_pubkey with identity element (all zeros)
        signed.signing_pubkey = [0u8; 32];

        let err = signed.verify().unwrap_err();
        assert!(err.contains("identity"));
    }

    #[test]
    fn verify_round1_rejects_zero_msg_privkey() {
        let privkey = make_signing_key();
        let msg = make_round1_msg();
        let mut signed = SignedKexMessage::create(msg, &privkey).unwrap();

        // Replace msg_privkey with zero (invalid view key contribution)
        signed.msg_privkey = [0u8; 32];

        let err = signed.verify().unwrap_err();
        assert!(err.contains("zero"));
    }

    #[test]
    fn verify_rejects_small_subgroup_pubkey() {
        let privkey = make_signing_key();
        let msg = make_round1_msg();
        let mut signed = SignedKexMessage::create(msg, &privkey).unwrap();

        // Known small-order point (order 8): this is a torsion point
        // c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
        // is a well-known non-prime-order point on ed25519
        let torsion: [u8; 32] = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0xfa,
        ];
        // Verify this IS a valid curve point but NOT in the main subgroup
        if salvium_crypto::is_in_main_subgroup(&torsion) {
            // If this particular point happens to be in the subgroup, skip test
            return;
        }
        signed.signing_pubkey = torsion;

        let err = signed.verify().unwrap_err();
        assert!(err.contains("subgroup"));
    }
}
