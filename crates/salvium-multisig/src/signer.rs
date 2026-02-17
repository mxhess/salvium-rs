use serde::{Deserialize, Serialize};

/// Represents a single participant in a multisig group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigSigner {
    /// Zero-based index of this signer within the group.
    pub index: usize,
    /// Hex-encoded public spend key.
    pub public_spend_key: String,
    /// Hex-encoded public view key.
    pub public_view_key: String,
    /// Human-readable label for this signer.
    pub label: String,
}

impl MultisigSigner {
    /// Create a new signer with default (empty) values.
    pub fn new() -> Self {
        Self {
            index: 0,
            public_spend_key: String::new(),
            public_view_key: String::new(),
            label: String::new(),
        }
    }

    /// Create a signer with all fields specified.
    pub fn with_config(
        index: usize,
        public_spend_key: String,
        public_view_key: String,
        label: String,
    ) -> Self {
        Self {
            index,
            public_spend_key,
            public_view_key,
            label,
        }
    }
}

impl Default for MultisigSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_defaults() {
        let signer = MultisigSigner::new();
        assert_eq!(signer.index, 0);
        assert_eq!(signer.public_spend_key, "");
        assert_eq!(signer.public_view_key, "");
        assert_eq!(signer.label, "");
    }

    #[test]
    fn test_signer_with_config() {
        let spend = "aa".repeat(32);
        let view = "bb".repeat(32);
        let signer = MultisigSigner::with_config(1, spend.clone(), view.clone(), "Signer 1".to_string());
        assert_eq!(signer.index, 1);
        assert_eq!(signer.public_spend_key, spend);
        assert_eq!(signer.public_view_key, view);
        assert_eq!(signer.label, "Signer 1");
    }

    #[test]
    fn test_signer_clone() {
        let signer = MultisigSigner::with_config(
            2,
            "cc".repeat(32),
            "dd".repeat(32),
            "Clone Test".to_string(),
        );
        let cloned = signer.clone();
        assert_eq!(cloned.index, signer.index);
        assert_eq!(cloned.public_spend_key, signer.public_spend_key);
        assert_eq!(cloned.public_view_key, signer.public_view_key);
        assert_eq!(cloned.label, signer.label);
    }

    #[test]
    fn test_signer_serde_roundtrip() {
        let signer = MultisigSigner::with_config(
            3,
            "ee".repeat(32),
            "ff".repeat(32),
            "Serde Test".to_string(),
        );
        let json = serde_json::to_string(&signer).unwrap();
        let restored: MultisigSigner = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.index, signer.index);
        assert_eq!(restored.public_spend_key, signer.public_spend_key);
        assert_eq!(restored.public_view_key, signer.public_view_key);
        assert_eq!(restored.label, signer.label);
    }
}
