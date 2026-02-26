//! Hybrid post-quantum wallet encryption.
//!
//! Implements the double-layer encryption scheme:
//!   Layer 1 (outer): PIN/password -> Argon2id + ML-KEM-768 -> HKDF -> AES-256-GCM
//!   Layer 2 (inner): Random per-wallet `data_key` -> SQLCipher database encryption
//!
//! The PQC envelope encrypts `WalletSecrets` (seed, keys, random data_key) so that
//! cracking one wallet's password reveals nothing about another's database key.

use crate::error::WalletError;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use ml_kem::{KemCore, MlKem768};
use rand::RngCore;
use sha2::Sha256;

/// Domain separator for KEM seed derivation (appended to kemSalt).
const KEM_DOMAIN: &[u8] = b"salvium-wallet-kem-v1";

/// HKDF info string for combining classical + quantum keys.
const HKDF_INFO: &[u8] = b"salvium-wallet-encryption-key-v1";

/// Default Argon2id parameters (OWASP recommended minimums).
const DEFAULT_T_COST: u32 = 3;
const DEFAULT_M_COST: u32 = 65536; // 64 MiB
const DEFAULT_PARALLELISM: u32 = 4;

/// Current envelope format version.
const ENVELOPE_VERSION: u32 = 2;

/// Decrypted wallet secrets stored inside the PQC envelope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletSecrets {
    /// 32-byte wallet seed (hex).
    pub seed: String,
    /// CryptoNote spend secret key (hex).
    #[serde(rename = "spendSecretKey")]
    pub spend_secret_key: String,
    /// CryptoNote view secret key (hex).
    #[serde(rename = "viewSecretKey")]
    pub view_secret_key: String,
    /// Random per-wallet SQLCipher key (hex).
    #[serde(rename = "dataKey")]
    pub data_key: String,
    /// 25-word mnemonic (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    /// Network name (mainnet/testnet/stagenet).
    pub network: String,
}

/// JSON-serializable PQC envelope stored as the `.meta` file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PqcEnvelope {
    pub version: u32,
    #[serde(rename = "kdfSalt")]
    pub kdf_salt: String,
    #[serde(rename = "kemSalt")]
    pub kem_salt: String,
    #[serde(rename = "kyberCiphertext")]
    pub kyber_ciphertext: String,
    pub iv: String,
    pub ciphertext: String,
    pub argon2: Argon2Params,
}

/// Argon2id parameters stored in the envelope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub t: u32,
    pub m: u32,
    pub p: u32,
}

/// Intermediate derived keys from the password.
pub struct DerivedKeys {
    pub classical_key: [u8; 32],
    pub kem_seed: Vec<u8>, // 64 bytes
}

/// Derive classical key and KEM seed from a PIN/password.
///
/// - `classical_key` = Argon2id(pin, kdf_salt) -> 32 bytes
/// - `kem_seed` = Argon2id(pin, kem_salt || KEM_DOMAIN) -> 64 bytes
pub fn derive_keys(
    pin: &[u8],
    kdf_salt: &[u8],
    kem_salt: &[u8],
    t: u32,
    m: u32,
    p: u32,
) -> Result<DerivedKeys, WalletError> {
    // 1. Classical key: argon2id(pin, kdfSalt) -> 32 bytes.
    let classical_key = salvium_crypto::argon2id_hash(pin, kdf_salt, t, m, p, 32);
    if classical_key.len() != 32 {
        return Err(WalletError::KeyDerivation("argon2id classical key derivation failed".into()));
    }

    // 2. KEM seed: argon2id(pin, kemSalt || KEM_DOMAIN) -> 64 bytes.
    let mut kem_salt_with_domain = Vec::with_capacity(kem_salt.len() + KEM_DOMAIN.len());
    kem_salt_with_domain.extend_from_slice(kem_salt);
    kem_salt_with_domain.extend_from_slice(KEM_DOMAIN);

    let kem_seed = salvium_crypto::argon2id_hash(pin, &kem_salt_with_domain, t, m, p, 64);
    if kem_seed.len() != 64 {
        return Err(WalletError::KeyDerivation("argon2id KEM seed derivation failed".into()));
    }

    Ok(DerivedKeys { classical_key: classical_key[..32].try_into().unwrap(), kem_seed })
}

/// Combine classical + quantum keys via HKDF-SHA256 into a 32-byte AES key.
fn derive_aes_key(classical_key: &[u8; 32], quantum_key: &[u8]) -> Result<[u8; 32], WalletError> {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(classical_key);
    ikm.extend_from_slice(quantum_key);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut aes_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut aes_key).map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
    Ok(aes_key)
}

/// Encrypt wallet secrets into a PQC envelope.
///
/// 1. Generate random kdfSalt (32), kemSalt (32), nonce (12)
/// 2. derive_keys(pin, kdfSalt, kemSalt)
/// 3. ML-KEM-768 keygen from kem_seed -> (dk, ek)
/// 4. Encapsulate(ek) -> (kyber_ct, quantum_key)
/// 5. HKDF(classical || quantum, HKDF_INFO) -> aes_key
/// 6. AES-256-GCM encrypt(secrets_json, aes_key, nonce)
/// 7. Return JSON envelope bytes
#[allow(deprecated)]
pub fn encrypt_envelope(secrets: &WalletSecrets, pin: &str) -> Result<Vec<u8>, WalletError> {
    let mut rng = rand::thread_rng();

    // 1. Generate random salts and nonce.
    let mut kdf_salt = [0u8; 32];
    let mut kem_salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut kdf_salt);
    rng.fill_bytes(&mut kem_salt);
    rng.fill_bytes(&mut nonce_bytes);

    // 2. Derive keys.
    let keys = derive_keys(
        pin.as_bytes(),
        &kdf_salt,
        &kem_salt,
        DEFAULT_T_COST,
        DEFAULT_M_COST,
        DEFAULT_PARALLELISM,
    )?;

    // 3. ML-KEM-768 deterministic keygen from kem_seed.
    let d: [u8; 32] = keys.kem_seed[..32].try_into().unwrap();
    let z: [u8; 32] = keys.kem_seed[32..64].try_into().unwrap();
    let (_dk, ek) = MlKem768::generate_deterministic(&d.into(), &z.into());

    // 4. Encapsulate to get quantum shared secret + ciphertext.
    use ml_kem::kem::Encapsulate;
    let (kyber_ct, quantum_key) = ek
        .encapsulate(&mut rng)
        .map_err(|_| WalletError::Encryption("ML-KEM encapsulation failed".into()))?;

    // 5. HKDF to combine classical + quantum -> AES key.
    let aes_key = derive_aes_key(&keys.classical_key, quantum_key.as_slice())?;

    // 6. AES-256-GCM encrypt the secrets JSON.
    let plaintext =
        serde_json::to_vec(secrets).map_err(|e| WalletError::Encryption(e.to_string()))?;

    let key = Key::<Aes256Gcm>::from_slice(&aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| WalletError::Encryption(e.to_string()))?;

    // 7. Build and serialize the envelope.
    let envelope = PqcEnvelope {
        version: ENVELOPE_VERSION,
        kdf_salt: hex::encode(kdf_salt),
        kem_salt: hex::encode(kem_salt),
        kyber_ciphertext: hex::encode(kyber_ct.as_slice()),
        iv: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        argon2: Argon2Params { t: DEFAULT_T_COST, m: DEFAULT_M_COST, p: DEFAULT_PARALLELISM },
    };

    serde_json::to_vec_pretty(&envelope).map_err(|e| WalletError::Encryption(e.to_string()))
}

/// Decrypt a PQC envelope to recover wallet secrets.
///
/// 1. Parse JSON envelope
/// 2. derive_keys(pin, kdfSalt, kemSalt)
/// 3. ML-KEM-768 keygen from kem_seed -> (dk, _)
/// 4. Decapsulate(dk, kyber_ct) -> quantum_key
/// 5. HKDF(classical || quantum, HKDF_INFO) -> aes_key
/// 6. AES-256-GCM decrypt(ciphertext, aes_key, iv)
/// 7. Parse JSON -> WalletSecrets
#[allow(deprecated)]
pub fn decrypt_envelope(envelope_bytes: &[u8], pin: &str) -> Result<WalletSecrets, WalletError> {
    // 1. Parse envelope.
    let envelope: PqcEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|e| WalletError::InvalidFile(format!("invalid PQC envelope: {}", e)))?;

    let kdf_salt = hex_decode(&envelope.kdf_salt, "kdfSalt")?;
    let kem_salt = hex_decode(&envelope.kem_salt, "kemSalt")?;
    let kyber_ct = hex_decode(&envelope.kyber_ciphertext, "kyberCiphertext")?;
    let iv = hex_decode(&envelope.iv, "iv")?;
    let ciphertext = hex_decode(&envelope.ciphertext, "ciphertext")?;

    // 2. Derive keys.
    let keys = derive_keys(
        pin.as_bytes(),
        &kdf_salt,
        &kem_salt,
        envelope.argon2.t,
        envelope.argon2.m,
        envelope.argon2.p,
    )?;

    // 3. ML-KEM-768 deterministic keygen from kem_seed.
    let d: [u8; 32] = keys.kem_seed[..32].try_into().unwrap();
    let z: [u8; 32] = keys.kem_seed[32..64].try_into().unwrap();
    let (dk, _ek) = MlKem768::generate_deterministic(&d.into(), &z.into());

    // 4. Decapsulate to get quantum shared secret.
    use ml_kem::kem::Decapsulate;
    let ct_array: ml_kem::Ciphertext<MlKem768> = kyber_ct
        .as_slice()
        .try_into()
        .map_err(|_| WalletError::InvalidFile("invalid kyber ciphertext length".into()))?;
    let quantum_key = dk.decapsulate(&ct_array).map_err(|_| WalletError::DecryptionFailed)?;

    // 5. HKDF to combine classical + quantum -> AES key.
    let aes_key = derive_aes_key(&keys.classical_key, quantum_key.as_slice())?;

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
    let plaintext =
        cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| WalletError::DecryptionFailed)?;

    // 7. Parse JSON -> WalletSecrets.
    serde_json::from_slice(&plaintext)
        .map_err(|e| WalletError::InvalidFile(format!("invalid decrypted JSON: {}", e)))
}

/// Helper: hex-decode a string, returning a WalletError on failure.
fn hex_decode(hex_str: &str, field: &str) -> Result<Vec<u8>, WalletError> {
    hex::decode(hex_str)
        .map_err(|e| WalletError::InvalidFile(format!("invalid hex in {}: {}", field, e)))
}

/// Helper: hex string -> [u8; 32].
pub fn hex_to_32(hex_str: &str) -> Result<[u8; 32], WalletError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WalletError::InvalidFile(format!("invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(WalletError::InvalidFile(format!("expected 32 bytes, got {}", bytes.len())));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

impl WalletSecrets {
    /// Get the seed as a 32-byte array.
    pub fn seed_bytes(&self) -> Result<[u8; 32], WalletError> {
        hex_to_32(&self.seed)
    }

    /// Get the data_key as a 32-byte array.
    pub fn data_key_bytes(&self) -> Result<[u8; 32], WalletError> {
        hex_to_32(&self.data_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_secrets() -> WalletSecrets {
        WalletSecrets {
            seed: hex::encode([0xABu8; 32]),
            spend_secret_key: hex::encode([0xCDu8; 32]),
            view_secret_key: hex::encode([0xEFu8; 32]),
            data_key: hex::encode([0x42u8; 32]),
            mnemonic: Some("test mnemonic words here for testing purposes only not real words at all but enough".into()),
            network: "testnet".into(),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secrets = make_test_secrets();
        let pin = "test_password_123";

        let envelope_bytes = encrypt_envelope(&secrets, pin).unwrap();

        // Envelope should be valid JSON.
        let envelope: PqcEnvelope = serde_json::from_slice(&envelope_bytes).unwrap();
        assert_eq!(envelope.version, ENVELOPE_VERSION);

        // Decrypt should recover the same secrets.
        let recovered = decrypt_envelope(&envelope_bytes, pin).unwrap();
        assert_eq!(recovered.seed, secrets.seed);
        assert_eq!(recovered.spend_secret_key, secrets.spend_secret_key);
        assert_eq!(recovered.view_secret_key, secrets.view_secret_key);
        assert_eq!(recovered.data_key, secrets.data_key);
        assert_eq!(recovered.mnemonic, secrets.mnemonic);
        assert_eq!(recovered.network, secrets.network);
    }

    #[test]
    fn test_wrong_pin_fails() {
        let secrets = make_test_secrets();
        let envelope_bytes = encrypt_envelope(&secrets, "correct_pin").unwrap();
        let result = decrypt_envelope(&envelope_bytes, "wrong_pin");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_encryptions_differ() {
        let secrets = make_test_secrets();
        let e1 = encrypt_envelope(&secrets, "pin").unwrap();
        let e2 = encrypt_envelope(&secrets, "pin").unwrap();
        // Different random salts/nonces -> different envelopes.
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let pin = b"test_pin";
        let kdf_salt = [1u8; 32];
        let kem_salt = [2u8; 32];

        let k1 = derive_keys(pin, &kdf_salt, &kem_salt, 3, 65536, 4).unwrap();
        let k2 = derive_keys(pin, &kdf_salt, &kem_salt, 3, 65536, 4).unwrap();

        assert_eq!(k1.classical_key, k2.classical_key);
        assert_eq!(k1.kem_seed, k2.kem_seed);
    }

    #[test]
    fn test_no_mnemonic() {
        let mut secrets = make_test_secrets();
        secrets.mnemonic = None;

        let envelope_bytes = encrypt_envelope(&secrets, "pin").unwrap();
        let recovered = decrypt_envelope(&envelope_bytes, "pin").unwrap();
        assert_eq!(recovered.mnemonic, None);
    }

    #[test]
    fn test_data_key_bytes() {
        let secrets = make_test_secrets();
        let dk = secrets.data_key_bytes().unwrap();
        assert_eq!(dk, [0x42u8; 32]);
    }

    #[test]
    fn test_invalid_envelope_json() {
        let result = decrypt_envelope(b"not json", "pin");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let secrets = make_test_secrets();
        let envelope_bytes = encrypt_envelope(&secrets, "pin").unwrap();

        let mut envelope: PqcEnvelope = serde_json::from_slice(&envelope_bytes).unwrap();
        // Tamper with ciphertext.
        let mut ct = hex::decode(&envelope.ciphertext).unwrap();
        ct[0] ^= 0xFF;
        envelope.ciphertext = hex::encode(ct);

        let tampered = serde_json::to_vec(&envelope).unwrap();
        let result = decrypt_envelope(&tampered, "pin");
        assert!(result.is_err());
    }
}
