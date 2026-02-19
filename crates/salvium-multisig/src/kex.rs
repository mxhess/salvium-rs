use serde::{Deserialize, Serialize};

use crate::constants::MultisigMsgType;

/// Returns the number of KEX rounds required for a given M-of-N multisig.
/// In the current protocol, this equals the number of signers (N).
pub fn kex_rounds_required(_threshold: usize, signers: usize) -> usize {
    signers
}

/// A message exchanged during the multisig key-exchange protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KexMessage {
    /// The KEX round number (1-indexed).
    pub round: usize,
    /// Index of the signer who produced this message.
    pub signer_index: usize,
    /// Hex-encoded public keys contributed during this round.
    pub keys: Vec<String>,
    /// The type of this message.
    pub msg_type: MultisigMsgType,
}

impl KexMessage {
    /// Create a new KexMessage with default values.
    pub fn new() -> Self {
        Self {
            round: 0,
            signer_index: 0,
            keys: Vec::new(),
            msg_type: MultisigMsgType::KexInit,
        }
    }

    /// Serialize to a JSON byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("KexMessage serialization should not fail")
    }

    /// Deserialize from a JSON byte slice.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("Failed to deserialize KexMessage: {}", e))
    }

    /// Deserialize from a JSON string.
    pub fn from_string(s: &str) -> Result<Self, String> {
        serde_json::from_str(s).map_err(|e| format!("Failed to parse KexMessage: {}", e))
    }
}

impl std::fmt::Display for KexMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).expect("KexMessage to_string should not fail"))
    }
}

impl Default for KexMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kex_rounds_required_2_of_2() {
        assert_eq!(kex_rounds_required(2, 2), 2);
    }

    #[test]
    fn test_kex_rounds_required_2_of_3() {
        assert_eq!(kex_rounds_required(2, 3), 3);
    }

    #[test]
    fn test_kex_rounds_required_3_of_3() {
        assert_eq!(kex_rounds_required(3, 3), 3);
    }

    #[test]
    fn test_kex_rounds_required_various() {
        assert_eq!(kex_rounds_required(2, 4), 4);
        assert_eq!(kex_rounds_required(3, 4), 4);
        assert_eq!(kex_rounds_required(4, 4), 4);
        assert_eq!(kex_rounds_required(5, 5), 5);
        assert_eq!(kex_rounds_required(2, 10), 10);
    }

    #[test]
    fn test_kex_message_default() {
        let msg = KexMessage::new();
        assert_eq!(msg.round, 0);
        assert_eq!(msg.signer_index, 0);
        assert!(msg.keys.is_empty());
        assert_eq!(msg.msg_type, MultisigMsgType::KexInit);
    }

    #[test]
    fn test_kex_message_serialize_deserialize_roundtrip() {
        let msg = KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec![
                "aa".repeat(32),
                "bb".repeat(32),
            ],
            msg_type: MultisigMsgType::KexRound,
        };

        let serialized = msg.serialize();
        let restored = KexMessage::deserialize(&serialized).unwrap();

        assert_eq!(restored.round, msg.round);
        assert_eq!(restored.signer_index, msg.signer_index);
        assert_eq!(restored.keys.len(), 2);
        assert_eq!(restored.keys[0], msg.keys[0]);
        assert_eq!(restored.keys[1], msg.keys[1]);
        assert_eq!(restored.msg_type, MultisigMsgType::KexRound);
    }

    #[test]
    fn test_kex_message_to_string_from_string_roundtrip() {
        let msg = KexMessage {
            round: 2,
            signer_index: 1,
            keys: vec!["11".repeat(32)],
            msg_type: MultisigMsgType::KexVerify,
        };

        let s = msg.to_string();
        let restored = KexMessage::from_string(&s).unwrap();

        assert_eq!(restored.round, msg.round);
        assert_eq!(restored.signer_index, msg.signer_index);
        assert_eq!(restored.keys.len(), 1);
        assert_eq!(restored.msg_type, MultisigMsgType::KexVerify);
    }

    #[test]
    fn test_kex_message_deserialize_invalid() {
        let result = KexMessage::deserialize(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_kex_message_from_string_invalid() {
        let result = KexMessage::from_string("not json");
        assert!(result.is_err());
    }
}
