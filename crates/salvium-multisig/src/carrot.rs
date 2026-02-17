use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use crate::account::MultisigAccount;

// ---------------------------------------------------------------------------
// CarrotEnoteType
// ---------------------------------------------------------------------------

/// Enote types for the CARROT protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CarrotEnoteType {
    Payment = 0,
    Change = 1,
    SelfSpend = 2,
}

impl CarrotEnoteType {
    /// Convert from an integer discriminant.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(CarrotEnoteType::Payment),
            1 => Some(CarrotEnoteType::Change),
            2 => Some(CarrotEnoteType::SelfSpend),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// CarrotPaymentProposal
// ---------------------------------------------------------------------------

/// A single payment output in a CARROT transaction proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrotPaymentProposal {
    /// Destination address string.
    pub destination: String,
    /// Amount in atomic units.
    pub amount: u64,
    /// Asset type (e.g. "SAL", "VSD").
    pub asset_type: String,
    /// Whether the destination is a subaddress.
    pub is_subaddress: bool,
}

impl CarrotPaymentProposal {
    /// Create a proposal with default values.
    pub fn new() -> Self {
        Self {
            destination: String::new(),
            amount: 0,
            asset_type: "SAL".to_string(),
            is_subaddress: false,
        }
    }

    /// Create a proposal with all fields specified.
    pub fn with_config(
        destination: &str,
        amount: u64,
        asset_type: &str,
        is_subaddress: bool,
    ) -> Self {
        Self {
            destination: destination.to_string(),
            amount,
            asset_type: asset_type.to_string(),
            is_subaddress,
        }
    }
}

impl Default for CarrotPaymentProposal {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CarrotSelfSendProposal (internal helper)
// ---------------------------------------------------------------------------

/// A self-send (change / self-spend) output in a CARROT transaction proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrotSelfSendProposal {
    pub destination: String,
    pub amount: u64,
    pub enote_type: CarrotEnoteType,
}

// ---------------------------------------------------------------------------
// CarrotTransactionProposal
// ---------------------------------------------------------------------------

/// A complete CARROT transaction proposal containing payment and self-send outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrotTransactionProposal {
    pub payment_proposals: Vec<CarrotPaymentProposal>,
    pub self_send_proposals: Vec<CarrotSelfSendProposal>,
    pub fee: u64,
    pub tx_type: u32,
}

impl CarrotTransactionProposal {
    /// Create an empty proposal.
    pub fn new() -> Self {
        Self {
            payment_proposals: Vec::new(),
            self_send_proposals: Vec::new(),
            fee: 0,
            tx_type: 3,
        }
    }

    /// Add a payment output.
    pub fn add_payment(
        &mut self,
        dest: &str,
        amount: u64,
        asset_type: &str,
        is_subaddress: bool,
    ) {
        self.payment_proposals.push(CarrotPaymentProposal {
            destination: dest.to_string(),
            amount,
            asset_type: asset_type.to_string(),
            is_subaddress,
        });
    }

    /// Add a self-send output (change, self-spend, etc.).
    pub fn add_self_send(&mut self, dest: &str, amount: u64, enote_type: CarrotEnoteType) {
        self.self_send_proposals.push(CarrotSelfSendProposal {
            destination: dest.to_string(),
            amount,
            enote_type,
        });
    }

    /// Total amount across all payment and self-send proposals.
    pub fn get_total_amount(&self) -> u64 {
        let payments: u64 = self.payment_proposals.iter().map(|p| p.amount).sum();
        let self_sends: u64 = self.self_send_proposals.iter().map(|s| s.amount).sum();
        payments + self_sends
    }

    /// Compute a deterministic 32-byte SHA-256 hash over the canonical JSON
    /// representation of this proposal, suitable for signing.
    pub fn get_signable_hash(&self) -> [u8; 32] {
        let json = serde_json::to_string(self)
            .expect("CarrotTransactionProposal serialization should not fail");
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Serialize to a JSON byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("CarrotTransactionProposal serialize should not fail")
    }

    /// Deserialize from a JSON byte slice.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data)
            .map_err(|e| format!("Failed to deserialize CarrotTransactionProposal: {}", e))
    }
}

impl Default for CarrotTransactionProposal {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CarrotKeys
// ---------------------------------------------------------------------------

/// Derived CARROT key material for a multisig account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrotKeys {
    /// Hex-encoded prove-spend key.
    pub prove_spend_key: String,
    /// Hex-encoded view-incoming key.
    pub view_incoming_key: String,
    /// Hex-encoded generate-image key.
    pub generate_image_key: String,
    /// Hex-encoded generate-address secret.
    pub generate_address_secret: String,
    /// Hex-encoded account spend public key.
    pub account_spend_pubkey: String,
}

// ---------------------------------------------------------------------------
// MultisigCarrotAccount
// ---------------------------------------------------------------------------

/// A multisig account extended with CARROT key derivation capabilities.
#[derive(Debug, Clone)]
pub struct MultisigCarrotAccount {
    /// The underlying multisig account.
    pub account: MultisigAccount,
    /// Derived CARROT keys (populated after `derive_carrot_keys`).
    pub carrot_keys: Option<CarrotKeys>,
}

impl MultisigCarrotAccount {
    /// Create a new CARROT-capable multisig account.
    pub fn new(threshold: usize, signer_count: usize) -> Result<Self, String> {
        let account = MultisigAccount::new(threshold, signer_count)?;
        Ok(Self {
            account,
            carrot_keys: None,
        })
    }

    /// Derive the CARROT key set from secret spend and view keys.
    ///
    /// # Errors
    /// Returns `Err` if KEX has not completed.
    pub fn derive_carrot_keys(
        &mut self,
        secret_spend: &str,
        secret_view: &str,
    ) -> Result<CarrotKeys, String> {
        if !self.account.is_kex_complete() {
            return Err("Key exchange must be complete before deriving CARROT keys".to_string());
        }

        let prove_spend_key = hash_derive("carrot_prove_spend", secret_spend);
        let view_incoming_key = hash_derive("carrot_view_incoming", secret_view);
        let generate_image_key = hash_derive("carrot_generate_image", secret_spend);
        let generate_address_secret = hash_derive("carrot_generate_address", secret_view);
        let account_spend_pubkey = hash_derive("carrot_account_spend_pub", secret_spend);

        let keys = CarrotKeys {
            prove_spend_key,
            view_incoming_key,
            generate_image_key,
            generate_address_secret,
            account_spend_pubkey,
        };

        self.carrot_keys = Some(keys.clone());
        Ok(keys)
    }

    /// Get the primary CARROT address for this account.
    ///
    /// # Errors
    /// Returns `Err` if `derive_carrot_keys` has not been called.
    pub fn get_carrot_address(&self, network: &str) -> Result<String, String> {
        let keys = self
            .carrot_keys
            .as_ref()
            .ok_or_else(|| "CARROT keys not derived".to_string())?;

        let prefix = match network {
            "testnet" => "SC1T",
            _ => "SC1",
        };

        // Build a representative address from the account spend pubkey.
        // Take a truncated form of the pubkey for the address body.
        let body = &keys.account_spend_pubkey[..16];
        Ok(format!("{}{}", prefix, body))
    }

    /// Get a CARROT subaddress for the given major/minor indices.
    ///
    /// # Errors
    /// Returns `Err` if `derive_carrot_keys` has not been called.
    pub fn get_carrot_subaddress(
        &self,
        network: &str,
        major: u32,
        minor: u32,
    ) -> Result<String, String> {
        let keys = self
            .carrot_keys
            .as_ref()
            .ok_or_else(|| "CARROT keys not derived".to_string())?;

        let prefix = match network {
            "testnet" => "SC1T",
            _ => "SC1",
        };

        // Derive subaddress by hashing the address secret with the indices.
        let mut hasher = Sha256::new();
        hasher.update(b"carrot_subaddress:");
        hasher.update(keys.generate_address_secret.as_bytes());
        hasher.update(major.to_le_bytes());
        hasher.update(minor.to_le_bytes());
        let sub_hash = hex::encode(hasher.finalize());
        let body = &sub_hash[..16];

        Ok(format!("{}sub{}", prefix, body))
    }
}

// ---------------------------------------------------------------------------
// Aspirational functions (not yet implemented)
// ---------------------------------------------------------------------------

/// Build a full multisig CARROT transaction.
///
/// Currently returns an error indicating the protocol is not yet implemented.
pub fn build_multisig_carrot_tx(
    _proposal: &CarrotTransactionProposal,
    _account: &MultisigCarrotAccount,
) -> Result<Vec<u8>, String> {
    Err("CARROT multisig protocol support not yet implemented".to_string())
}

/// Generate a CARROT key image for a multisig input.
///
/// Currently returns an error indicating the protocol is not yet implemented.
pub fn generate_multisig_carrot_key_image(
    _account: &MultisigCarrotAccount,
    _output_pubkey: &[u8; 32],
) -> Result<[u8; 32], String> {
    Err("CARROT multisig key image protocol support not yet implemented".to_string())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte hex key by hashing a domain tag and an input.
fn hash_derive(domain: &str, input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b":");
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn completed_account() -> MultisigCarrotAccount {
        let mut acct = MultisigCarrotAccount::new(2, 2).unwrap();
        acct.account.kex_complete = true;
        acct
    }

    // --- CarrotEnoteType ---

    #[test]
    fn test_enote_type_values() {
        assert_eq!(CarrotEnoteType::Payment as u8, 0);
        assert_eq!(CarrotEnoteType::Change as u8, 1);
        assert_eq!(CarrotEnoteType::SelfSpend as u8, 2);
    }

    #[test]
    fn test_enote_type_from_u8() {
        assert_eq!(CarrotEnoteType::from_u8(0), Some(CarrotEnoteType::Payment));
        assert_eq!(CarrotEnoteType::from_u8(1), Some(CarrotEnoteType::Change));
        assert_eq!(CarrotEnoteType::from_u8(2), Some(CarrotEnoteType::SelfSpend));
        assert_eq!(CarrotEnoteType::from_u8(3), None);
    }

    // --- CarrotPaymentProposal ---

    #[test]
    fn test_payment_proposal_defaults() {
        let p = CarrotPaymentProposal::new();
        assert_eq!(p.destination, "");
        assert_eq!(p.amount, 0);
        assert_eq!(p.asset_type, "SAL");
        assert!(!p.is_subaddress);
    }

    #[test]
    fn test_payment_proposal_with_config() {
        let p = CarrotPaymentProposal::with_config("SC1test", 1_000_000_000, "VSD", true);
        assert_eq!(p.destination, "SC1test");
        assert_eq!(p.amount, 1_000_000_000);
        assert_eq!(p.asset_type, "VSD");
        assert!(p.is_subaddress);
    }

    #[test]
    fn test_payment_proposal_json_roundtrip() {
        let original = CarrotPaymentProposal::with_config("SC1abc123", 5_000_000_000, "SAL", false);
        let json = serde_json::to_string(&original).unwrap();
        let restored: CarrotPaymentProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.destination, original.destination);
        assert_eq!(restored.amount, original.amount);
        assert_eq!(restored.asset_type, original.asset_type);
        assert_eq!(restored.is_subaddress, original.is_subaddress);
    }

    // --- CarrotTransactionProposal ---

    #[test]
    fn test_transaction_proposal_defaults() {
        let tp = CarrotTransactionProposal::new();
        assert!(tp.payment_proposals.is_empty());
        assert!(tp.self_send_proposals.is_empty());
        assert_eq!(tp.fee, 0);
        assert_eq!(tp.tx_type, 3);
    }

    #[test]
    fn test_add_payment() {
        let mut tp = CarrotTransactionProposal::new();
        tp.add_payment("SC1dest", 1_000_000_000, "SAL", false);
        assert_eq!(tp.payment_proposals.len(), 1);
        assert_eq!(tp.payment_proposals[0].destination, "SC1dest");
        assert_eq!(tp.payment_proposals[0].amount, 1_000_000_000);
    }

    #[test]
    fn test_add_payment_with_asset_type() {
        let mut tp = CarrotTransactionProposal::new();
        tp.add_payment("SC1dest", 500_000_000, "VSD", true);
        assert_eq!(tp.payment_proposals[0].asset_type, "VSD");
        assert!(tp.payment_proposals[0].is_subaddress);
    }

    #[test]
    fn test_add_self_send() {
        let mut tp = CarrotTransactionProposal::new();
        tp.add_self_send("SC1self", 200_000_000, CarrotEnoteType::Change);
        assert_eq!(tp.self_send_proposals.len(), 1);
        assert_eq!(tp.self_send_proposals[0].amount, 200_000_000);
        assert_eq!(tp.self_send_proposals[0].enote_type, CarrotEnoteType::Change);
    }

    #[test]
    fn test_get_total_amount() {
        let mut tp = CarrotTransactionProposal::new();
        tp.add_payment("SC1a", 1_000_000_000, "SAL", false);
        tp.add_payment("SC1b", 500_000_000, "SAL", false);
        tp.add_self_send("SC1self", 200_000_000, CarrotEnoteType::SelfSpend);
        assert_eq!(tp.get_total_amount(), 1_700_000_000);
    }

    #[test]
    fn test_get_signable_hash_returns_32_bytes() {
        let mut tp = CarrotTransactionProposal::new();
        tp.add_payment("SC1dest", 1_000_000_000, "SAL", false);
        tp.fee = 10_000_000;
        let hash = tp.get_signable_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_get_signable_hash_deterministic() {
        let make = || {
            let mut tp = CarrotTransactionProposal::new();
            tp.add_payment("SC1dest", 1_000_000_000, "SAL", false);
            tp.fee = 10_000_000;
            tp
        };

        let h1 = make().get_signable_hash();
        let h2 = make().get_signable_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_get_signable_hash_differs_for_different_proposals() {
        let mut tp1 = CarrotTransactionProposal::new();
        tp1.add_payment("SC1dest", 1_000_000_000, "SAL", false);
        tp1.fee = 10_000_000;

        let mut tp2 = CarrotTransactionProposal::new();
        tp2.add_payment("SC1dest", 2_000_000_000, "SAL", false);
        tp2.fee = 10_000_000;

        assert_ne!(tp1.get_signable_hash(), tp2.get_signable_hash());
    }

    #[test]
    fn test_transaction_proposal_serialize_deserialize() {
        let mut original = CarrotTransactionProposal::new();
        original.add_payment("SC1dest1", 1_000_000_000, "SAL", false);
        original.add_payment("SC1dest2", 500_000_000, "VSD", true);
        original.add_self_send("SC1change", 300_000_000, CarrotEnoteType::Change);
        original.fee = 10_000_000;
        original.tx_type = 4;

        let data = original.serialize();
        let restored = CarrotTransactionProposal::deserialize(&data).unwrap();

        assert_eq!(restored.payment_proposals.len(), 2);
        assert_eq!(restored.self_send_proposals.len(), 1);
        assert_eq!(restored.fee, 10_000_000);
        assert_eq!(restored.tx_type, 4);
        assert_eq!(restored.payment_proposals[0].destination, "SC1dest1");
        assert_eq!(restored.payment_proposals[1].asset_type, "VSD");
        assert_eq!(restored.self_send_proposals[0].amount, 300_000_000);
    }

    // --- MultisigCarrotAccount ---

    #[test]
    fn test_carrot_account_creation() {
        let acct = MultisigCarrotAccount::new(2, 3).unwrap();
        assert_eq!(acct.account.threshold, 2);
        assert_eq!(acct.account.signer_count, 3);
        assert!(acct.carrot_keys.is_none());
    }

    #[test]
    fn test_derive_carrot_keys_fails_before_kex() {
        let mut acct = MultisigCarrotAccount::new(2, 2).unwrap();
        let spend = "11".repeat(32);
        let view = "22".repeat(32);
        let result = acct.derive_carrot_keys(&spend, &view);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Key exchange must be complete"));
    }

    #[test]
    fn test_derive_carrot_keys_succeeds_after_kex() {
        let mut acct = completed_account();
        let spend = "11".repeat(32);
        let view = "22".repeat(32);
        let keys = acct.derive_carrot_keys(&spend, &view).unwrap();

        assert_eq!(keys.prove_spend_key.len(), 64);
        assert_eq!(keys.view_incoming_key.len(), 64);
        assert_eq!(keys.generate_image_key.len(), 64);
        assert_eq!(keys.generate_address_secret.len(), 64);
        assert_eq!(keys.account_spend_pubkey.len(), 64);
    }

    #[test]
    fn test_derive_carrot_keys_deterministic() {
        let spend = "aa".repeat(32);
        let view = "bb".repeat(32);

        let mut a1 = completed_account();
        let k1 = a1.derive_carrot_keys(&spend, &view).unwrap();

        let mut a2 = completed_account();
        let k2 = a2.derive_carrot_keys(&spend, &view).unwrap();

        assert_eq!(k1.account_spend_pubkey, k2.account_spend_pubkey);
        assert_eq!(k1.view_incoming_key, k2.view_incoming_key);
        assert_eq!(k1.prove_spend_key, k2.prove_spend_key);
    }

    #[test]
    fn test_get_carrot_address_fails_without_keys() {
        let acct = completed_account();
        let result = acct.get_carrot_address("mainnet");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CARROT keys not derived"));
    }

    #[test]
    fn test_get_carrot_address_mainnet() {
        let mut acct = completed_account();
        acct.derive_carrot_keys(&"11".repeat(32), &"22".repeat(32))
            .unwrap();
        let addr = acct.get_carrot_address("mainnet").unwrap();
        assert!(addr.starts_with("SC1"));
        // Should NOT start with SC1T for mainnet
        assert!(!addr.starts_with("SC1T"));
    }

    #[test]
    fn test_get_carrot_address_testnet() {
        let mut acct = completed_account();
        acct.derive_carrot_keys(&"11".repeat(32), &"22".repeat(32))
            .unwrap();
        let addr = acct.get_carrot_address("testnet").unwrap();
        assert!(addr.starts_with("SC1T"));
    }

    #[test]
    fn test_get_carrot_subaddress() {
        let mut acct = completed_account();
        acct.derive_carrot_keys(&"11".repeat(32), &"22".repeat(32))
            .unwrap();
        let sub = acct.get_carrot_subaddress("mainnet", 0, 1).unwrap();
        assert!(sub.starts_with("SC1"));
        assert!(!sub.is_empty());
    }

    #[test]
    fn test_get_carrot_subaddress_fails_without_keys() {
        let acct = completed_account();
        let result = acct.get_carrot_subaddress("mainnet", 0, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CARROT keys not derived"));
    }

    // --- Aspirational functions ---

    #[test]
    fn test_build_multisig_carrot_tx_not_implemented() {
        let mut acct = completed_account();
        acct.derive_carrot_keys(&"11".repeat(32), &"22".repeat(32))
            .unwrap();
        let mut proposal = CarrotTransactionProposal::new();
        proposal.add_payment("SC1dest", 1_000_000_000, "SAL", false);

        let result = build_multisig_carrot_tx(&proposal, &acct);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("protocol support"));
    }

    #[test]
    fn test_generate_multisig_carrot_key_image_not_implemented() {
        let acct = completed_account();
        let pubkey = [0u8; 32];
        let result = generate_multisig_carrot_key_image(&acct, &pubkey);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("protocol support"));
    }
}
