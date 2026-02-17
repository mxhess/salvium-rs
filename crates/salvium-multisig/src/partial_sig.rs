use serde::{Deserialize, Serialize};

/// A partial signature produced by one signer during multisig signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigPartialSig {
    /// Index of the signer who produced this partial signature.
    pub signer_index: usize,
    /// Index of the transaction this signature applies to.
    pub tx_index: usize,
    /// Hex-encoded scalar responses for each input.
    pub responses: Vec<String>,
    /// Hex-encoded public nonces used for this signing attempt.
    pub pub_nonces: Vec<String>,
}

impl MultisigPartialSig {
    /// Create a new empty partial signature.
    pub fn new() -> Self {
        Self {
            signer_index: 0,
            tx_index: 0,
            responses: Vec::new(),
            pub_nonces: Vec::new(),
        }
    }

    /// Serialize to a JSON byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("MultisigPartialSig serialization should not fail")
    }

    /// Deserialize from a JSON byte slice.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data)
            .map_err(|e| format!("Failed to deserialize MultisigPartialSig: {}", e))
    }

    /// Serialize to a JSON string.
    pub fn to_string(&self) -> String {
        serde_json::to_string(self).expect("MultisigPartialSig to_string should not fail")
    }

    /// Deserialize from a JSON string.
    pub fn from_string(s: &str) -> Result<Self, String> {
        serde_json::from_str(s)
            .map_err(|e| format!("Failed to parse MultisigPartialSig: {}", e))
    }
}

impl Default for MultisigPartialSig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partial_sig_defaults() {
        let sig = MultisigPartialSig::new();
        assert_eq!(sig.signer_index, 0);
        assert_eq!(sig.tx_index, 0);
        assert!(sig.responses.is_empty());
        assert!(sig.pub_nonces.is_empty());
    }

    #[test]
    fn test_partial_sig_serialize_deserialize_roundtrip() {
        let sig = MultisigPartialSig {
            signer_index: 1,
            tx_index: 0,
            responses: vec!["11".repeat(32)],
            pub_nonces: vec!["22".repeat(32), "33".repeat(32)],
        };

        let serialized = sig.serialize();
        let restored = MultisigPartialSig::deserialize(&serialized).unwrap();

        assert_eq!(restored.signer_index, 1);
        assert_eq!(restored.tx_index, 0);
        assert_eq!(restored.responses.len(), 1);
        assert_eq!(restored.pub_nonces.len(), 2);
        assert_eq!(restored.responses[0], "11".repeat(32));
        assert_eq!(restored.pub_nonces[0], "22".repeat(32));
    }

    #[test]
    fn test_partial_sig_to_string_from_string_roundtrip() {
        let sig = MultisigPartialSig {
            signer_index: 2,
            tx_index: 1,
            responses: vec![],
            pub_nonces: vec![],
        };

        let s = sig.to_string();
        let restored = MultisigPartialSig::from_string(&s).unwrap();

        assert_eq!(restored.signer_index, 2);
        assert_eq!(restored.tx_index, 1);
    }

    #[test]
    fn test_partial_sig_deserialize_invalid() {
        let result = MultisigPartialSig::deserialize(b"bad");
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_sig_from_string_invalid() {
        let result = MultisigPartialSig::from_string("{invalid");
        assert!(result.is_err());
    }
}
