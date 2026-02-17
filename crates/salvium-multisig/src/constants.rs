use serde::{Deserialize, Serialize};

/// Maximum number of signers allowed in a multisig group.
pub const MULTISIG_MAX_SIGNERS: usize = 16;

/// Minimum threshold required for a valid multisig configuration.
pub const MULTISIG_MIN_THRESHOLD: usize = 2;

/// Number of nonce components per signer per signing attempt.
pub const MULTISIG_NONCE_COMPONENTS: usize = 2;

/// Types of messages exchanged during multisig protocol rounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultisigMsgType {
    KexInit,
    KexRound,
    KexVerify,
    TxSet,
    PartialSig,
    FinalTx,
}

impl MultisigMsgType {
    /// Returns the string representation matching the JS constants.
    pub fn as_str(&self) -> &'static str {
        match self {
            MultisigMsgType::KexInit => "kex_init",
            MultisigMsgType::KexRound => "kex_round",
            MultisigMsgType::KexVerify => "kex_verify",
            MultisigMsgType::TxSet => "tx_set",
            MultisigMsgType::PartialSig => "partial_sig",
            MultisigMsgType::FinalTx => "final_tx",
        }
    }

    /// Parse from a string representation.
    pub fn from_str_repr(s: &str) -> Option<Self> {
        match s {
            "kex_init" => Some(MultisigMsgType::KexInit),
            "kex_round" => Some(MultisigMsgType::KexRound),
            "kex_verify" => Some(MultisigMsgType::KexVerify),
            "tx_set" => Some(MultisigMsgType::TxSet),
            "partial_sig" => Some(MultisigMsgType::PartialSig),
            "final_tx" => Some(MultisigMsgType::FinalTx),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_signers_is_16() {
        assert_eq!(MULTISIG_MAX_SIGNERS, 16);
    }

    #[test]
    fn test_min_threshold_is_2() {
        assert_eq!(MULTISIG_MIN_THRESHOLD, 2);
    }

    #[test]
    fn test_nonce_components_is_2() {
        assert_eq!(MULTISIG_NONCE_COMPONENTS, 2);
    }

    #[test]
    fn test_msg_type_as_str() {
        assert_eq!(MultisigMsgType::KexInit.as_str(), "kex_init");
        assert_eq!(MultisigMsgType::KexRound.as_str(), "kex_round");
        assert_eq!(MultisigMsgType::KexVerify.as_str(), "kex_verify");
        assert_eq!(MultisigMsgType::TxSet.as_str(), "tx_set");
        assert_eq!(MultisigMsgType::PartialSig.as_str(), "partial_sig");
        assert_eq!(MultisigMsgType::FinalTx.as_str(), "final_tx");
    }

    #[test]
    fn test_msg_type_from_str_repr() {
        assert_eq!(
            MultisigMsgType::from_str_repr("kex_init"),
            Some(MultisigMsgType::KexInit)
        );
        assert_eq!(
            MultisigMsgType::from_str_repr("kex_round"),
            Some(MultisigMsgType::KexRound)
        );
        assert_eq!(
            MultisigMsgType::from_str_repr("kex_verify"),
            Some(MultisigMsgType::KexVerify)
        );
        assert_eq!(
            MultisigMsgType::from_str_repr("tx_set"),
            Some(MultisigMsgType::TxSet)
        );
        assert_eq!(
            MultisigMsgType::from_str_repr("partial_sig"),
            Some(MultisigMsgType::PartialSig)
        );
        assert_eq!(
            MultisigMsgType::from_str_repr("final_tx"),
            Some(MultisigMsgType::FinalTx)
        );
        assert_eq!(MultisigMsgType::from_str_repr("invalid"), None);
    }

    #[test]
    fn test_msg_type_serde_roundtrip() {
        let msg = MultisigMsgType::KexInit;
        let json = serde_json::to_string(&msg).unwrap();
        let restored: MultisigMsgType = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, restored);
    }
}
