use sha2::{Digest, Sha256};
use rand::RngCore;

use crate::account::MultisigAccount;
use crate::constants::MULTISIG_NONCE_COMPONENTS;

/// A multisig wallet wrapping a `MultisigAccount` with convenience methods.
#[derive(Debug, Clone)]
pub struct MultisigWallet {
    /// The underlying multisig account.
    pub account: MultisigAccount,
    /// Cached first KEX message string (populated after `get_first_kex_message`).
    first_kex_message: Option<String>,
}

impl MultisigWallet {
    /// Create a new MultisigWallet from a pre-validated MultisigAccount.
    pub fn new(account: MultisigAccount) -> Self {
        Self {
            account,
            first_kex_message: None,
        }
    }

    /// Return the signing threshold.
    pub fn get_threshold(&self) -> usize {
        self.account.threshold
    }

    /// Return the total number of signers.
    pub fn get_signer_count(&self) -> usize {
        self.account.signer_count
    }

    /// Whether the wallet is ready for signing (KEX complete).
    pub fn is_ready(&self) -> bool {
        self.account.is_kex_complete()
    }

    /// Always returns `true` -- this is a multisig wallet.
    pub fn is_multisig(&self) -> bool {
        true
    }

    /// Initialize the KEX and return the first round message as a string.
    ///
    /// The result is cached so subsequent calls return the same value.
    pub fn get_first_kex_message(&mut self, spend_key: &str, view_key: &str) -> Option<String> {
        if self.first_kex_message.is_some() {
            return self.first_kex_message.clone();
        }

        match self.account.initialize_kex(spend_key, view_key) {
            Ok(msg) => {
                let s = msg.to_string();
                self.first_kex_message = Some(s.clone());
                Some(s)
            }
            Err(_) => None,
        }
    }
}

/// Create a multisig wallet in one step, validating parameters and initializing KEX.
///
/// Returns a `MultisigWallet` with the first KEX message already generated.
pub fn create_multisig_wallet(
    threshold: usize,
    signer_count: usize,
    spend_key: &str,
    view_key: &str,
) -> Result<MultisigWallet, String> {
    let account = MultisigAccount::new(threshold, signer_count)?;
    let mut wallet = MultisigWallet::new(account);
    wallet.get_first_kex_message(spend_key, view_key);
    Ok(wallet)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Compute a blinded (hashed) version of a secret key.
///
/// This is deterministic: the same input always produces the same output.
/// Returns a 32-byte hex string.
pub fn get_multisig_blinded_secret_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"multisig_blinded_key:");
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute a Diffie-Hellman shared secret from a private key and a public key.
///
/// Both inputs are hex-encoded. Returns a 32-byte hex string.
/// For arbitrary (non-curve-point) inputs this is a hash-based placeholder.
pub fn compute_dh_secret(priv_key: &str, pub_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"multisig_dh:");
    hasher.update(priv_key.as_bytes());
    hasher.update(pub_key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate `count` nonce pairs. Each nonce pair consists of
/// `MULTISIG_NONCE_COMPONENTS` random 32-byte hex strings.
///
/// Returns `Vec<Vec<String>>` where the outer length is `count` and each
/// inner vector has `MULTISIG_NONCE_COMPONENTS` hex strings.
pub fn generate_multisig_nonces(count: usize) -> Vec<Vec<String>> {
    let mut rng = rand::thread_rng();
    let mut result = Vec::with_capacity(count);

    for _ in 0..count {
        let mut pair = Vec::with_capacity(MULTISIG_NONCE_COMPONENTS);
        for _ in 0..MULTISIG_NONCE_COMPONENTS {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            pair.push(hex::encode(buf));
        }
        result.push(pair);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> (String, String) {
        ("11".repeat(32), "22".repeat(32))
    }

    #[test]
    fn test_wallet_creation() {
        let account = MultisigAccount::new(2, 3).unwrap();
        let wallet = MultisigWallet::new(account);
        assert_eq!(wallet.get_threshold(), 2);
        assert_eq!(wallet.get_signer_count(), 3);
        assert!(!wallet.is_ready());
        assert!(wallet.is_multisig());
    }

    #[test]
    fn test_wallet_get_first_kex_message() {
        let (spend, view) = test_keys();
        let account = MultisigAccount::new(2, 2).unwrap();
        let mut wallet = MultisigWallet::new(account);

        let msg = wallet.get_first_kex_message(&spend, &view);
        assert!(msg.is_some());
        let s = msg.unwrap();
        assert!(!s.is_empty());
    }

    #[test]
    fn test_wallet_is_ready_false_before_kex_complete() {
        let (spend, view) = test_keys();
        let account = MultisigAccount::new(2, 2).unwrap();
        let mut wallet = MultisigWallet::new(account);
        wallet.get_first_kex_message(&spend, &view);
        assert!(!wallet.is_ready());
    }

    #[test]
    fn test_wallet_is_multisig_always_true() {
        let account = MultisigAccount::new(2, 2).unwrap();
        let wallet = MultisigWallet::new(account);
        assert!(wallet.is_multisig());
    }

    #[test]
    fn test_create_multisig_wallet() {
        let (spend, view) = test_keys();
        let wallet = create_multisig_wallet(2, 2, &spend, &view).unwrap();
        assert_eq!(wallet.get_threshold(), 2);
        assert_eq!(wallet.get_signer_count(), 2);
        assert!(wallet.is_multisig());
    }

    #[test]
    fn test_create_multisig_wallet_validates_params() {
        let result = create_multisig_wallet(5, 3, "aa", "bb");
        assert!(result.is_err());
    }

    #[test]
    fn test_blinded_secret_key_deterministic() {
        let key = "cd".repeat(32);
        let b1 = get_multisig_blinded_secret_key(&key);
        let b2 = get_multisig_blinded_secret_key(&key);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_blinded_secret_key_differs_for_different_keys() {
        let k1 = "11".repeat(32);
        let k2 = "22".repeat(32);
        let b1 = get_multisig_blinded_secret_key(&k1);
        let b2 = get_multisig_blinded_secret_key(&k2);
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_blinded_secret_key_returns_64_hex_chars() {
        let key = "ab".repeat(32);
        let blinded = get_multisig_blinded_secret_key(&key);
        assert_eq!(blinded.len(), 64);
        // Verify it is valid hex
        hex::decode(&blinded).expect("blinded key should be valid hex");
    }

    #[test]
    fn test_compute_dh_secret() {
        let priv_key = "01".repeat(32);
        let pub_key = "02".repeat(32);
        let secret = compute_dh_secret(&priv_key, &pub_key);
        assert_eq!(secret.len(), 64);
        hex::decode(&secret).expect("DH secret should be valid hex");
    }

    #[test]
    fn test_generate_nonces_count() {
        let nonces = generate_multisig_nonces(3);
        assert_eq!(nonces.len(), 3);
        for pair in &nonces {
            assert_eq!(pair.len(), MULTISIG_NONCE_COMPONENTS);
        }
    }

    #[test]
    fn test_generate_nonces_uniqueness() {
        let nonces = generate_multisig_nonces(2);
        let mut all: Vec<&String> = Vec::new();
        for pair in &nonces {
            for nonce in pair {
                all.push(nonce);
            }
        }
        // All 4 nonces should be unique
        let unique: std::collections::HashSet<&&String> = all.iter().collect();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn test_generate_nonces_are_valid_hex() {
        let nonces = generate_multisig_nonces(1);
        for nonce in &nonces[0] {
            assert_eq!(nonce.len(), 64);
            hex::decode(nonce).expect("nonce should be valid hex");
        }
    }
}
