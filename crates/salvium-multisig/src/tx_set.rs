use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::signing::{SignerNonces, PartialClsag};

/// A pending multisig transaction awaiting signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMultisigTx {
    /// The unsigned transaction data (hex-encoded).
    pub tx_blob: String,
    /// Key images for this transaction's inputs.
    pub key_images: Vec<String>,
    /// Transaction prefix hash (hex-encoded).
    pub tx_prefix_hash: String,
    /// Per-input nonces from all signers who have contributed.
    #[serde(default)]
    pub input_nonces: Vec<Vec<SignerNonces>>,
    /// Per-input partial CLSAG signatures accumulated so far.
    #[serde(default)]
    pub input_partials: Vec<Vec<PartialClsag>>,
    /// Fee for this transaction (atomic units).
    #[serde(default)]
    pub fee: u64,
    /// Destination addresses (for display).
    #[serde(default)]
    pub destinations: Vec<String>,
}

/// A set of transactions prepared for multisig signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigTxSet {
    /// Serialized transactions (hex-encoded or JSON strings).
    pub transactions: Vec<String>,
    /// Key images associated with the transaction inputs.
    pub key_images: Vec<String>,
    /// Structured pending transactions with nonces and partial signatures.
    #[serde(default)]
    pub pending_txs: Vec<PendingMultisigTx>,
    /// Public keys of signers who have contributed partial signatures.
    #[serde(default)]
    pub signers_contributed: HashSet<String>,
    /// Required threshold for this TX set.
    #[serde(default)]
    pub threshold: usize,
    /// Total number of signers.
    #[serde(default)]
    pub signer_count: usize,
}

impl MultisigTxSet {
    /// Create a new empty transaction set.
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            key_images: Vec::new(),
            pending_txs: Vec::new(),
            signers_contributed: HashSet::new(),
            threshold: 0,
            signer_count: 0,
        }
    }

    /// Create a new transaction set with threshold configuration.
    pub fn with_config(threshold: usize, signer_count: usize) -> Self {
        Self {
            threshold,
            signer_count,
            ..Self::new()
        }
    }

    /// Add a pending multisig transaction.
    pub fn add_pending_tx(&mut self, tx: PendingMultisigTx) {
        self.pending_txs.push(tx);
    }

    /// Record that a signer has contributed partial signatures.
    pub fn mark_signer_contributed(&mut self, signer_pubkey: &str) {
        self.signers_contributed.insert(signer_pubkey.to_string());
    }

    /// Whether enough signers have contributed to meet the threshold.
    pub fn is_complete(&self) -> bool {
        self.threshold > 0 && self.signers_contributed.len() >= self.threshold
    }

    /// Add a transaction (as a hex/JSON string) to the set.
    pub fn add_transaction(&mut self, tx: String) {
        self.transactions.push(tx);
    }

    /// Add a key image (hex-encoded) to the set.
    pub fn add_key_image(&mut self, key_image: String) {
        self.key_images.push(key_image);
    }

    /// Serialize to a JSON byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("MultisigTxSet serialization should not fail")
    }

    /// Deserialize from a JSON byte slice.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data)
            .map_err(|e| format!("Failed to deserialize MultisigTxSet: {}", e))
    }

    /// Deserialize from a JSON string.
    pub fn from_string(s: &str) -> Result<Self, String> {
        serde_json::from_str(s)
            .map_err(|e| format!("Failed to parse MultisigTxSet: {}", e))
    }
}

impl std::fmt::Display for MultisigTxSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).expect("MultisigTxSet to_string should not fail"))
    }
}

impl Default for MultisigTxSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tx_set() {
        let set = MultisigTxSet::new();
        assert!(set.transactions.is_empty());
        assert!(set.key_images.is_empty());
    }

    #[test]
    fn test_add_transaction() {
        let mut set = MultisigTxSet::new();
        set.add_transaction("tx_data_1".to_string());
        set.add_transaction("tx_data_2".to_string());
        assert_eq!(set.transactions.len(), 2);
        assert_eq!(set.transactions[0], "tx_data_1");
    }

    #[test]
    fn test_add_key_image() {
        let mut set = MultisigTxSet::new();
        set.add_key_image("aa".repeat(32));
        assert_eq!(set.key_images.len(), 1);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut set = MultisigTxSet::new();
        set.add_transaction("tx_hex_data".to_string());
        set.add_key_image("aa".repeat(32));

        let serialized = set.serialize();
        let restored = MultisigTxSet::deserialize(&serialized).unwrap();

        assert_eq!(restored.transactions.len(), 1);
        assert_eq!(restored.transactions[0], "tx_hex_data");
        assert_eq!(restored.key_images.len(), 1);
        assert_eq!(restored.key_images[0], "aa".repeat(32));
    }

    #[test]
    fn test_to_string_from_string_roundtrip() {
        let mut set = MultisigTxSet::new();
        set.add_transaction("some_tx".to_string());

        let s = set.to_string();
        let restored = MultisigTxSet::from_string(&s).unwrap();

        assert_eq!(restored.transactions.len(), 1);
        assert_eq!(restored.transactions[0], "some_tx");
    }

    #[test]
    fn test_deserialize_invalid() {
        let result = MultisigTxSet::deserialize(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_string_invalid() {
        let result = MultisigTxSet::from_string("not json");
        assert!(result.is_err());
    }
}
