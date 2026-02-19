//! JS wallet file decryption.
//!
//! Decrypts wallet-*.json files created by the JavaScript wallet using the
//! hybrid post-quantum encryption scheme:
//!   1. Argon2id (PIN → classical key)
//!   2. ML-KEM-768 (PIN → deterministic keypair → decapsulate → quantum key)
//!   3. HKDF-SHA256 (classical + quantum → AES key)
//!   4. AES-256-GCM (decrypt ciphertext → JSON plaintext)

use crate::error::WalletError;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use ml_kem::{KemCore, MlKem768};
use sha2::Sha256;

/// Domain separator for KEM seed derivation (appended to kemSalt).
const KEM_DOMAIN: &[u8] = b"salvium-wallet-kem-v1";

/// HKDF info string for combining classical + quantum keys.
const HKDF_INFO: &[u8] = b"salvium-wallet-encryption-key-v1";

/// Decrypted secrets from a JS wallet file.
#[derive(Debug)]
pub struct JsWalletSecrets {
    /// 32-byte wallet seed.
    pub seed: [u8; 32],
    /// CryptoNote spend secret key.
    pub spend_secret_key: [u8; 32],
    /// CryptoNote view secret key.
    pub view_secret_key: [u8; 32],
    /// 25-word mnemonic (if present).
    pub mnemonic: Option<String>,
}

/// Decrypt a JS wallet JSON file using the given PIN.
///
/// The `wallet_json` parameter is the raw contents of the wallet-*.json file.
/// The `pin` is the 6-digit PIN string.
#[allow(deprecated)] // aes-gcm 0.10 uses generic-array 0.x
pub fn decrypt_js_wallet(wallet_json: &str, pin: &str) -> Result<JsWalletSecrets, WalletError> {
    let envelope: serde_json::Value =
        serde_json::from_str(wallet_json).map_err(|e| WalletError::InvalidFile(e.to_string()))?;

    let encrypted = envelope
        .get("encrypted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !encrypted {
        return Err(WalletError::InvalidFile("wallet is not encrypted".into()));
    }

    let enc = envelope
        .get("encryption")
        .ok_or_else(|| WalletError::InvalidFile("missing encryption metadata".into()))?;

    // Parse encryption parameters.
    let kdf_salt = hex_decode_field(enc, "kdfSalt")?;
    let kem_salt = hex_decode_field(enc, "kemSalt")?;
    let kyber_ct = hex_decode_field(enc, "kyberCiphertext")?;
    let iv = hex_decode_field(enc, "iv")?;
    let ciphertext = hex_decode_field(enc, "ciphertext")?;

    let argon2_params = enc.get("argon2").ok_or_else(|| {
        WalletError::InvalidFile("missing argon2 parameters".into())
    })?;
    let t_cost = argon2_params
        .get("t")
        .and_then(|v| v.as_u64())
        .unwrap_or(3) as u32;
    let m_cost = argon2_params
        .get("m")
        .and_then(|v| v.as_u64())
        .unwrap_or(65536) as u32;
    let parallelism = argon2_params
        .get("p")
        .and_then(|v| v.as_u64())
        .unwrap_or(4) as u32;

    let pin_bytes = pin.as_bytes();

    // 1. Classical key: argon2id(pin, kdfSalt) → 32 bytes.
    let classical_key =
        salvium_crypto::argon2id_hash(pin_bytes, &kdf_salt, t_cost, m_cost, parallelism, 32);
    if classical_key.len() != 32 {
        return Err(WalletError::KeyDerivation(
            "argon2id classical key derivation failed".into(),
        ));
    }

    // 2. KEM seed: argon2id(pin, kemSalt ++ KEM_DOMAIN) → 64 bytes.
    let mut kem_salt_with_domain = Vec::with_capacity(kem_salt.len() + KEM_DOMAIN.len());
    kem_salt_with_domain.extend_from_slice(&kem_salt);
    kem_salt_with_domain.extend_from_slice(KEM_DOMAIN);

    let kem_seed =
        salvium_crypto::argon2id_hash(pin_bytes, &kem_salt_with_domain, t_cost, m_cost, parallelism, 64);
    if kem_seed.len() != 64 {
        return Err(WalletError::KeyDerivation(
            "argon2id KEM seed derivation failed".into(),
        ));
    }

    // 3. Deterministic ML-KEM-768 keygen from seed (d = first 32, z = last 32).
    let d: [u8; 32] = kem_seed[..32].try_into().unwrap();
    let z: [u8; 32] = kem_seed[32..64].try_into().unwrap();
    let (dk, _ek) = MlKem768::generate_deterministic(&d.into(), &z.into());

    // 4. Decapsulate to get quantum shared secret.
    use ml_kem::kem::Decapsulate;
    let ct_array: ml_kem::Ciphertext<MlKem768> = kyber_ct
        .as_slice()
        .try_into()
        .map_err(|_| WalletError::InvalidFile("invalid kyber ciphertext length".into()))?;
    let quantum_key = dk
        .decapsulate(&ct_array)
        .map_err(|_| WalletError::DecryptionFailed)?;

    // 5. HKDF-SHA256: combine classical + quantum → 32-byte AES key.
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&classical_key);
    ikm.extend_from_slice(quantum_key.as_slice());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut aes_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut aes_key)
        .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;

    // 6. AES-256-GCM decrypt.
    if iv.len() != 12 {
        return Err(WalletError::InvalidFile(format!(
            "invalid IV length: expected 12, got {}",
            iv.len()
        )));
    }

    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| WalletError::DecryptionFailed)?;

    // 7. Parse the JSON plaintext.
    let secrets: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| WalletError::InvalidFile(format!("invalid decrypted JSON: {}", e)))?;

    let seed = hex_to_32(
        secrets
            .get("seed")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::InvalidFile("missing seed in decrypted data".into()))?,
    )?;

    let spend_secret_key = hex_to_32(
        secrets
            .get("spendSecretKey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                WalletError::InvalidFile("missing spendSecretKey in decrypted data".into())
            })?,
    )?;

    let view_secret_key = hex_to_32(
        secrets
            .get("viewSecretKey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                WalletError::InvalidFile("missing viewSecretKey in decrypted data".into())
            })?,
    )?;

    let mnemonic = secrets
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(JsWalletSecrets {
        seed,
        spend_secret_key,
        view_secret_key,
        mnemonic,
    })
}

fn hex_decode_field(obj: &serde_json::Value, field: &str) -> Result<Vec<u8>, WalletError> {
    let hex_str = obj
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| WalletError::InvalidFile(format!("missing field: {}", field)))?;
    hex::decode(hex_str)
        .map_err(|e| WalletError::InvalidFile(format!("invalid hex in {}: {}", field, e)))
}

fn hex_to_32(hex_str: &str) -> Result<[u8; 32], WalletError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WalletError::InvalidFile(format!("invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(WalletError::InvalidFile(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn testnet_wallet_dir() -> PathBuf {
        dirs::home_dir().unwrap().join("testnet-wallet")
    }

    #[test]
    fn test_decrypt_wallet_a() {
        let dir = testnet_wallet_dir();
        let wallet_path = dir.join("wallet-a.json");
        let pin_path = dir.join("wallet-a.pin");

        if !wallet_path.exists() {
            eprintln!("Skipping: {:?} not found", wallet_path);
            return;
        }

        let wallet_json = std::fs::read_to_string(&wallet_path).unwrap();
        let pin = std::fs::read_to_string(&pin_path).unwrap().trim().to_string();

        let secrets = decrypt_js_wallet(&wallet_json, &pin).unwrap();

        // Verify seed is non-zero.
        assert_ne!(secrets.seed, [0u8; 32], "seed should not be zero");
        assert_ne!(
            secrets.spend_secret_key,
            [0u8; 32],
            "spend key should not be zero"
        );
        assert_ne!(
            secrets.view_secret_key,
            [0u8; 32],
            "view key should not be zero"
        );

        // Verify the seed produces the expected public keys.
        let spend_pub = salvium_crypto::scalar_mult_base(&secrets.spend_secret_key);
        let expected_spend_pub = "74547ce24f8a18b602276c2f5fb361ff8e77a6dc8056386cb33b5cce4a44343a";
        assert_eq!(
            hex::encode(&spend_pub[..32]),
            expected_spend_pub,
            "spend public key mismatch"
        );

        let view_pub = salvium_crypto::scalar_mult_base(&secrets.view_secret_key);
        let expected_view_pub = "0d35458cceb342262359219253f8f3a20a8ba525005062728ce9dd31bc22a908";
        assert_eq!(
            hex::encode(&view_pub[..32]),
            expected_view_pub,
            "view public key mismatch"
        );

        if let Some(ref mnemonic) = secrets.mnemonic {
            let words: Vec<&str> = mnemonic.split_whitespace().collect();
            assert_eq!(words.len(), 25, "mnemonic should be 25 words");
        }

        println!("Wallet A decrypted successfully!");
        println!("  Seed:      {}", hex::encode(secrets.seed));
        println!("  Spend pub: {}", hex::encode(&spend_pub[..32]));
        println!("  View pub:  {}", hex::encode(&view_pub[..32]));
        if let Some(ref m) = secrets.mnemonic {
            println!("  Mnemonic:  {}...", &m[..40]);
        }
    }

    #[test]
    fn test_decrypt_invalid_pin_fails() {
        let dir = testnet_wallet_dir();
        let wallet_path = dir.join("wallet-a.json");

        if !wallet_path.exists() {
            eprintln!("Skipping: {:?} not found", wallet_path);
            return;
        }

        let wallet_json = std::fs::read_to_string(&wallet_path).unwrap();
        let result = decrypt_js_wallet(&wallet_json, "000000");
        assert!(result.is_err(), "wrong PIN should fail");
    }

    #[test]
    fn test_decrypt_non_encrypted_wallet_fails() {
        let json = r#"{"encrypted": false, "version": 3}"#;
        let result = decrypt_js_wallet(json, "123456");
        assert!(result.is_err());
    }
}
