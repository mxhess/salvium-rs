use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use crate::constants::{MULTISIG_MAX_SIGNERS, MULTISIG_MIN_THRESHOLD, MultisigMsgType};
use crate::kex::KexMessage;
use crate::signer::MultisigSigner;

/// A multisig account holding the group configuration and KEX state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigAccount {
    /// Number of signers required to authorize a transaction.
    pub threshold: usize,
    /// Total number of signers in the group.
    pub signer_count: usize,
    /// Registered signers.
    pub signers: Vec<MultisigSigner>,
    /// Current KEX round (0 means not started).
    pub kex_round: usize,
    /// Whether key exchange is complete.
    pub kex_complete: bool,
    /// Hex-encoded spend secret key for this participant (if provided).
    spend_key: Option<String>,
    /// Hex-encoded view secret key for this participant (if provided).
    view_key: Option<String>,
}

impl MultisigAccount {
    /// Create a new MultisigAccount, validating the threshold and signer count.
    ///
    /// # Errors
    /// Returns `Err` if:
    /// - `threshold` < `MULTISIG_MIN_THRESHOLD` (2)
    /// - `threshold` > `signer_count`
    /// - `signer_count` > `MULTISIG_MAX_SIGNERS` (16)
    pub fn new(threshold: usize, signer_count: usize) -> Result<Self, String> {
        if threshold < MULTISIG_MIN_THRESHOLD {
            return Err(format!(
                "Multisig threshold must be at least {}, got {}",
                MULTISIG_MIN_THRESHOLD, threshold
            ));
        }
        if threshold > signer_count {
            return Err(format!(
                "Threshold ({}) must not exceed signer count ({})",
                threshold, signer_count
            ));
        }
        if signer_count > MULTISIG_MAX_SIGNERS {
            return Err(format!(
                "Signer count ({}) exceeds max allowed ({})",
                signer_count, MULTISIG_MAX_SIGNERS
            ));
        }

        Ok(Self {
            threshold,
            signer_count,
            signers: Vec::new(),
            kex_round: 0,
            kex_complete: false,
            spend_key: None,
            view_key: None,
        })
    }

    /// Initialize the key-exchange protocol using the provided secret keys.
    ///
    /// Generates the first-round `KexMessage` containing derived public keys.
    ///
    /// # Errors
    /// Returns `Err` if the spend or view keys have not been set.
    pub fn initialize_kex(
        &mut self,
        spend_key: &str,
        view_key: &str,
    ) -> Result<KexMessage, String> {
        if spend_key.is_empty() {
            return Err("Base spend key is required to initialize KEX".to_string());
        }
        if view_key.is_empty() {
            return Err("Base view key is required to initialize KEX".to_string());
        }

        self.spend_key = Some(spend_key.to_string());
        self.view_key = Some(view_key.to_string());

        // Derive a public key from the spend key via hashing (placeholder for real
        // curve scalar-to-point multiplication).
        let pub_spend = {
            let mut hasher = Sha256::new();
            hasher.update(b"multisig_pub_spend:");
            hasher.update(spend_key.as_bytes());
            hex::encode(hasher.finalize())
        };

        let pub_view = {
            let mut hasher = Sha256::new();
            hasher.update(b"multisig_pub_view:");
            hasher.update(view_key.as_bytes());
            hex::encode(hasher.finalize())
        };

        self.kex_round = 1;

        let msg = KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec![pub_spend, pub_view],
            msg_type: MultisigMsgType::KexInit,
        };

        Ok(msg)
    }

    /// Whether the key exchange has completed.
    pub fn is_kex_complete(&self) -> bool {
        self.kex_complete
    }

    /// Return a reference to the stored spend key, if any.
    pub fn spend_key(&self) -> Option<&str> {
        self.spend_key.as_deref()
    }

    /// Return a reference to the stored view key, if any.
    pub fn view_key(&self) -> Option<&str> {
        self.view_key.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation() {
        let account = MultisigAccount::new(2, 3).unwrap();
        assert_eq!(account.threshold, 2);
        assert_eq!(account.signer_count, 3);
        assert_eq!(account.kex_round, 0);
        assert!(!account.kex_complete);
    }

    #[test]
    fn test_account_threshold_too_low() {
        let result = MultisigAccount::new(1, 2);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("threshold") || msg.contains("2"));
    }

    #[test]
    fn test_account_threshold_exceeds_signers() {
        let result = MultisigAccount::new(5, 3);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Threshold") || msg.contains("exceed"));
    }

    #[test]
    fn test_account_signers_exceed_max() {
        let result = MultisigAccount::new(2, 20);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("16") || msg.contains("max"));
    }

    #[test]
    fn test_account_exact_max_signers() {
        let account = MultisigAccount::new(2, 16);
        assert!(account.is_ok());
    }

    #[test]
    fn test_initialize_kex_returns_message() {
        let mut account = MultisigAccount::new(2, 2).unwrap();
        let spend = "11".repeat(32);
        let view = "22".repeat(32);
        let msg = account.initialize_kex(&spend, &view).unwrap();

        assert_eq!(msg.round, 1);
        assert_eq!(msg.signer_index, 0);
        assert_eq!(msg.keys.len(), 2);
        assert!(!msg.keys[0].is_empty());
        assert!(!msg.keys[1].is_empty());
        assert_eq!(account.kex_round, 1);
    }

    #[test]
    fn test_initialize_kex_requires_spend_key() {
        let mut account = MultisigAccount::new(2, 2).unwrap();
        let result = account.initialize_kex("", "22".repeat(32).as_str());
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("key") || msg.contains("Base"));
    }

    #[test]
    fn test_initialize_kex_requires_view_key() {
        let mut account = MultisigAccount::new(2, 2).unwrap();
        let result = account.initialize_kex("11".repeat(32).as_str(), "");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_kex_complete_initially_false() {
        let account = MultisigAccount::new(2, 2).unwrap();
        assert!(!account.is_kex_complete());
    }

    #[test]
    fn test_is_kex_complete_after_manual_set() {
        let mut account = MultisigAccount::new(2, 2).unwrap();
        account.kex_complete = true;
        assert!(account.is_kex_complete());
    }
}
