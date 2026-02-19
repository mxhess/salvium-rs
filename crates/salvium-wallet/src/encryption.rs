//! Wallet file encryption.
//!
//! Encrypts wallet data using Argon2id key derivation + AES-256-GCM.
//! The encrypted format is self-contained with all parameters needed for
//! decryption (except the password).

use crate::error::WalletError;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;

/// Magic bytes identifying a Salvium wallet file.
const MAGIC: &[u8; 4] = b"SALW";

/// Current wallet file format version.
const VERSION: u8 = 1;

/// Header size: 4 (magic) + 1 (version) + 32 (salt) + 12 (nonce) = 49 bytes.
const HEADER_SIZE: usize = 49;

/// Argon2id parameters (OWASP recommended minimums).
const ARGON2_T_COST: u32 = 3;
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_DK_LEN: u32 = 32;

/// Encrypt wallet data with a password.
///
/// Returns the complete encrypted file contents (header + ciphertext).
#[allow(deprecated)] // aes-gcm 0.10 uses generic-array 0.x
pub fn encrypt_wallet_data(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, WalletError> {
    let mut rng = rand::thread_rng();

    // Generate random salt and nonce.
    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    // Derive encryption key via Argon2id.
    let key_bytes = salvium_crypto::argon2id_hash(
        password,
        &salt,
        ARGON2_T_COST,
        ARGON2_M_COST,
        ARGON2_PARALLELISM,
        ARGON2_DK_LEN,
    );

    // Encrypt with AES-256-GCM.
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| WalletError::Encryption(e.to_string()))?;

    // Build file: header + ciphertext.
    let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Check if data is an encrypted wallet file (has SALW magic).
pub fn is_encrypted_wallet(data: &[u8]) -> bool {
    data.len() >= HEADER_SIZE && &data[0..4] == MAGIC
}

/// Re-encrypt wallet data with a new password.
///
/// Decrypts with the old password, then encrypts with the new one.
pub fn reencrypt_wallet_data(
    encrypted: &[u8],
    old_password: &[u8],
    new_password: &[u8],
) -> Result<Vec<u8>, WalletError> {
    let plaintext = decrypt_wallet_data(encrypted, old_password)?;
    encrypt_wallet_data(&plaintext, new_password)
}

/// Get the version byte from an encrypted wallet file.
pub fn wallet_file_version(data: &[u8]) -> Option<u8> {
    if data.len() >= 5 && &data[0..4] == MAGIC {
        Some(data[4])
    } else {
        None
    }
}

/// Decrypt wallet data with a password.
///
/// Takes the complete encrypted file contents, returns the decrypted plaintext.
#[allow(deprecated)] // aes-gcm 0.10 uses generic-array 0.x
pub fn decrypt_wallet_data(encrypted: &[u8], password: &[u8]) -> Result<Vec<u8>, WalletError> {
    if encrypted.len() < HEADER_SIZE {
        return Err(WalletError::InvalidFile("file too short".into()));
    }

    // Verify magic.
    if &encrypted[0..4] != MAGIC {
        return Err(WalletError::InvalidFile("invalid magic bytes".into()));
    }

    // Check version.
    let version = encrypted[4];
    if version != VERSION {
        return Err(WalletError::InvalidFile(format!(
            "unsupported version: {}",
            version
        )));
    }

    // Extract salt, nonce, and ciphertext.
    let salt = &encrypted[5..37];
    let nonce_bytes = &encrypted[37..49];
    let ciphertext = &encrypted[49..];

    if ciphertext.is_empty() {
        return Err(WalletError::InvalidFile("no ciphertext".into()));
    }

    // Derive encryption key via Argon2id.
    let key_bytes = salvium_crypto::argon2id_hash(
        password,
        salt,
        ARGON2_T_COST,
        ARGON2_M_COST,
        ARGON2_PARALLELISM,
        ARGON2_DK_LEN,
    );

    // Decrypt with AES-256-GCM.
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| WalletError::DecryptionFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"salvium wallet secret data";
        let password = b"test_password_123";

        let encrypted = encrypt_wallet_data(data, password).unwrap();
        assert!(encrypted.len() > HEADER_SIZE);
        assert_eq!(&encrypted[0..4], MAGIC);
        assert_eq!(encrypted[4], VERSION);

        let decrypted = decrypt_wallet_data(&encrypted, password).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_wrong_password_fails() {
        let data = b"secret data";
        let encrypted = encrypt_wallet_data(data, b"correct_password").unwrap();
        let result = decrypt_wallet_data(&encrypted, b"wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_magic_fails() {
        let mut bad = vec![0u8; 100];
        bad[0..4].copy_from_slice(b"XXXX");
        let result = decrypt_wallet_data(&bad, b"password");
        assert!(matches!(result, Err(WalletError::InvalidFile(_))));
    }

    #[test]
    fn test_truncated_file_fails() {
        let result = decrypt_wallet_data(&[0u8; 10], b"password");
        assert!(matches!(result, Err(WalletError::InvalidFile(_))));
    }

    #[test]
    fn test_different_encryptions_differ() {
        let data = b"same data";
        let e1 = encrypt_wallet_data(data, b"pass").unwrap();
        let e2 = encrypt_wallet_data(data, b"pass").unwrap();
        // Different random salt/nonce → different ciphertext.
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_empty_plaintext() {
        let encrypted = encrypt_wallet_data(b"", b"password").unwrap();
        let decrypted = decrypt_wallet_data(&encrypted, b"password").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_is_encrypted_wallet_true() {
        let data = b"some wallet data";
        let encrypted = encrypt_wallet_data(data, b"password").unwrap();
        assert!(is_encrypted_wallet(&encrypted));
    }

    #[test]
    fn test_is_encrypted_wallet_false() {
        let random_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
        assert!(!is_encrypted_wallet(&random_data));
    }

    #[test]
    fn test_is_encrypted_wallet_too_short() {
        // Fewer bytes than HEADER_SIZE should return false even with correct magic.
        let short = b"SALW";
        assert!(!is_encrypted_wallet(short));
        assert!(!is_encrypted_wallet(&[]));
        assert!(!is_encrypted_wallet(&[0u8; 10]));
    }

    #[test]
    fn test_reencrypt_wallet_data() {
        let data = b"wallet secrets here";
        let encrypted = encrypt_wallet_data(data, b"old_password").unwrap();

        let reencrypted = reencrypt_wallet_data(&encrypted, b"old_password", b"new_password").unwrap();

        // Old password should no longer work.
        assert!(decrypt_wallet_data(&reencrypted, b"old_password").is_err());

        // New password should work and produce the original data.
        let decrypted = decrypt_wallet_data(&reencrypted, b"new_password").unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_reencrypt_wrong_old_password() {
        let data = b"wallet secrets";
        let encrypted = encrypt_wallet_data(data, b"correct").unwrap();
        let result = reencrypt_wallet_data(&encrypted, b"wrong", b"new");
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_file_version() {
        let data = b"test data";
        let encrypted = encrypt_wallet_data(data, b"password").unwrap();
        assert_eq!(wallet_file_version(&encrypted), Some(VERSION));
    }

    #[test]
    fn test_wallet_file_version_invalid() {
        // Non-wallet data returns None.
        assert_eq!(wallet_file_version(b"not a wallet"), None);
        assert_eq!(wallet_file_version(&[]), None);
        assert_eq!(wallet_file_version(&[0u8; 4]), None);
    }

    #[test]
    fn test_encrypt_preserves_data_integrity() {
        // 1 MiB of patterned data.
        let mut large_data = vec![0u8; 1024 * 1024];
        for (i, byte) in large_data.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let encrypted = encrypt_wallet_data(&large_data, b"strong_password").unwrap();
        let decrypted = decrypt_wallet_data(&encrypted, b"strong_password").unwrap();
        assert_eq!(decrypted, large_data);
    }
}
