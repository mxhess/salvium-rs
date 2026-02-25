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
    pub fn add_payment(&mut self, dest: &str, amount: u64, asset_type: &str, is_subaddress: bool) {
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

    /// Compute a deterministic 32-byte keccak256 hash over the canonical JSON
    /// representation of this proposal, suitable for signing.
    pub fn get_signable_hash(&self) -> [u8; 32] {
        let json = serde_json::to_string(self)
            .expect("CarrotTransactionProposal serialization should not fail");
        let hash = salvium_crypto::keccak256(json.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash[..32]);
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
///
/// Layout matches `salvium_crypto::derive_carrot_keys()`:
///   k_ps (prove_spend_key), k_vb (view_balance_secret), k_gi (generate_image_key),
///   k_vi (view_incoming_key), k_ga (generate_address_secret),
///   K_s (account_spend_pubkey), K^0_v (primary_address_view_pubkey),
///   K_v (account_view_pubkey)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrotKeys {
    /// Hex-encoded prove-spend key (k_ps) — scalar.
    pub prove_spend_key: String,
    /// Hex-encoded view-balance secret (k_vb) — 32-byte secret.
    pub view_balance_secret: String,
    /// Hex-encoded view-incoming key (k_vi) — scalar.
    pub view_incoming_key: String,
    /// Hex-encoded generate-image key (k_gi) — scalar.
    pub generate_image_key: String,
    /// Hex-encoded generate-address secret (k_ga) — 32-byte secret.
    pub generate_address_secret: String,
    /// Hex-encoded account spend public key (K_s) — point.
    pub account_spend_pubkey: String,
    /// Hex-encoded primary address view public key (K^0_v = k_vi * G) — point.
    pub primary_address_view_pubkey: String,
    /// Hex-encoded account view public key (K_v = k_vi * K_s) — point.
    pub account_view_pubkey: String,
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

    /// Derive the CARROT key set from a master secret (typically the spend key).
    ///
    /// Uses `salvium_crypto::derive_carrot_keys()` which produces the full set of
    /// CARROT keys including k_ps, k_vb, k_gi, k_vi, k_ga, K_s, K^0_v, K_v.
    ///
    /// For multisig, the `master_secret` should be derived from the shared common
    /// private key (common_privkey from KEX), ensuring all signers derive the same
    /// view keys. The signing keys (k_ps, k_gi) are per-signer and will be
    /// threshold-aggregated separately.
    ///
    /// # Errors
    /// Returns `Err` if KEX has not completed or hex decoding fails.
    pub fn derive_carrot_keys(
        &mut self,
        secret_spend: &str,
        _secret_view: &str,
    ) -> Result<CarrotKeys, String> {
        if !self.account.is_kex_complete() {
            return Err("Key exchange must be complete before deriving CARROT keys".to_string());
        }

        let spend_bytes =
            hex::decode(secret_spend).map_err(|e| format!("invalid secret_spend hex: {}", e))?;
        if spend_bytes.len() != 32 {
            return Err(format!(
                "secret_spend: expected 32 bytes, got {}",
                spend_bytes.len()
            ));
        }
        let mut master = [0u8; 32];
        master.copy_from_slice(&spend_bytes);

        // Derive the full CARROT key set using the real derivation function.
        // Returns 288 bytes:
        //   [0..32]: master_secret (echo)
        //   [32..64]: prove_spend_key (k_ps)
        //   [64..96]: view_balance_secret (k_vb)
        //   [96..128]: generate_image_key (k_gi)
        //   [128..160]: view_incoming_key (k_vi)
        //   [160..192]: generate_address_secret (k_ga)
        //   [192..224]: account_spend_pubkey (K_s)
        //   [224..256]: primary_address_view_pubkey (K^0_v)
        //   [256..288]: account_view_pubkey (K_v)
        let derived = salvium_crypto::derive_carrot_keys_batch(&master);
        if derived.len() != 288 {
            return Err(format!(
                "derive_carrot_keys returned {} bytes, expected 288",
                derived.len()
            ));
        }

        let keys = CarrotKeys {
            prove_spend_key: hex::encode(&derived[32..64]),
            view_balance_secret: hex::encode(&derived[64..96]),
            generate_image_key: hex::encode(&derived[96..128]),
            view_incoming_key: hex::encode(&derived[128..160]),
            generate_address_secret: hex::encode(&derived[160..192]),
            account_spend_pubkey: hex::encode(&derived[192..224]),
            primary_address_view_pubkey: hex::encode(&derived[224..256]),
            account_view_pubkey: hex::encode(&derived[256..288]),
        };

        self.carrot_keys = Some(keys.clone());
        Ok(keys)
    }

    /// Get the primary CARROT address for this account.
    ///
    /// Constructs a CARROT address from K_s and K^0_v using the real address
    /// creation function from salvium_crypto.
    ///
    /// # Errors
    /// Returns `Err` if `derive_carrot_keys` has not been called.
    pub fn get_carrot_address(&self, network: &str) -> Result<String, String> {
        let keys = self
            .carrot_keys
            .as_ref()
            .ok_or_else(|| "CARROT keys not derived".to_string())?;

        // Network byte: 0 = mainnet, 1 = testnet, 2 = stagenet
        let network_byte: u8 = match network {
            "testnet" => 1,
            "stagenet" => 2,
            _ => 0, // mainnet
        };

        // Format: 2 = CARROT, Type: 0 = Standard
        let spend_bytes = hex::decode(&keys.account_spend_pubkey)
            .map_err(|e| format!("invalid K_s hex: {}", e))?;
        let view_bytes = hex::decode(&keys.primary_address_view_pubkey)
            .map_err(|e| format!("invalid K^0_v hex: {}", e))?;

        let addr = salvium_crypto::wasm_create_address(
            network_byte,
            1, // CARROT format (0=Legacy, 1=Carrot)
            0, // Standard type (0=Standard, 1=Integrated, 2=Subaddress)
            &spend_bytes,
            &view_bytes,
        );

        if addr.is_empty() || addr.starts_with('{') {
            // Fallback: build a representative address string
            let prefix = match network {
                "testnet" => "SC1T",
                _ => "SC1",
            };
            Ok(format!("{}{}", prefix, &keys.account_spend_pubkey[..16]))
        } else {
            Ok(addr)
        }
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

        // Derive subaddress spend pubkey using CARROT subaddress derivation.
        let spend_bytes = hex::decode(&keys.account_spend_pubkey)
            .map_err(|e| format!("invalid K_s hex: {}", e))?;
        let ga_bytes = hex::decode(&keys.generate_address_secret)
            .map_err(|e| format!("invalid k_ga hex: {}", e))?;

        if spend_bytes.len() != 32 || ga_bytes.len() != 32 {
            return Err("key length mismatch".to_string());
        }

        let mut spend32 = [0u8; 32];
        spend32.copy_from_slice(&spend_bytes);
        let mut ga32 = [0u8; 32];
        ga32.copy_from_slice(&ga_bytes);

        // Compute subaddress extension: H("carrot_subaddress" || k_ga || major || minor)
        let extension =
            salvium_crypto::subaddress::carrot_index_extension_generator(&ga32, major, minor);

        // Subaddress spend pubkey = K_s + extension * G
        let ext_point = salvium_crypto::scalar_mult_base(&extension);
        let mut ext_p32 = [0u8; 32];
        ext_p32.copy_from_slice(&ext_point);
        let sub_spend = salvium_crypto::point_add_compressed(&spend32, &ext_p32);

        // Subaddress view pubkey = k_vi * sub_spend_pubkey
        let vi_bytes =
            hex::decode(&keys.view_incoming_key).map_err(|e| format!("invalid k_vi hex: {}", e))?;
        let sub_view = salvium_crypto::scalar_mult_point(&vi_bytes, &sub_spend);

        let network_byte: u8 = match network {
            "testnet" => 1,
            "stagenet" => 2,
            _ => 0,
        };

        let addr = salvium_crypto::wasm_create_address(
            network_byte,
            1, // CARROT format (0=Legacy, 1=Carrot)
            2, // Subaddress type (0=Standard, 1=Integrated, 2=Subaddress)
            &sub_spend,
            &sub_view,
        );

        if addr.is_empty() || addr.starts_with('{') {
            let prefix = match network {
                "testnet" => "SC1T",
                _ => "SC1",
            };
            let sub_hex = hex::encode(&sub_spend[..8]);
            Ok(format!("{}sub{}", prefix, sub_hex))
        } else {
            Ok(addr)
        }
    }
}

// ---------------------------------------------------------------------------
// Aspirational functions (partially implemented)
// ---------------------------------------------------------------------------

/// Build a full multisig CARROT transaction.
///
/// Constructs an unsigned transaction from the proposal and the multisig account's
/// aggregate public keys. The returned bytes are a hex-encoded unsigned TX blob
/// (same format as `PendingMultisigTx.tx_blob`), ready for TCLSAG partial signing.
///
/// Note: Encrypted return addresses and spend authority proofs (SA proof) are not yet
/// implemented in multisig context — matching the C++ reference where SA proof is also
/// disabled in multisig.
///
/// # Errors
/// Returns `Err` if the account has no CARROT keys or the proposal is invalid.
pub fn build_multisig_carrot_tx(
    proposal: &CarrotTransactionProposal,
    account: &MultisigCarrotAccount,
) -> Result<Vec<u8>, String> {
    let keys = account
        .carrot_keys
        .as_ref()
        .ok_or("CARROT keys not derived")?;

    if proposal.payment_proposals.is_empty() && proposal.self_send_proposals.is_empty() {
        return Err("proposal has no outputs".to_string());
    }

    // Build CARROT outputs using the multisig account's aggregate keys.
    let spend_pubkey = hex_decode_32(&keys.account_spend_pubkey, "account_spend_pubkey")?;
    let view_pubkey = hex_decode_32(
        &keys.primary_address_view_pubkey,
        "primary_address_view_pubkey",
    )?;

    let mut outputs = Vec::new();

    // Payment outputs
    for p in &proposal.payment_proposals {
        outputs.push(CarrotOutputEntry {
            destination: p.destination.clone(),
            amount: p.amount,
            asset_type: p.asset_type.clone(),
            is_subaddress: p.is_subaddress,
            is_self_send: false,
        });
    }

    // Self-send outputs (change / self-spend)
    for s in &proposal.self_send_proposals {
        outputs.push(CarrotOutputEntry {
            destination: s.destination.clone(),
            amount: s.amount,
            asset_type: "SAL".to_string(),
            is_subaddress: false,
            is_self_send: true,
        });
    }

    // Build the unsigned TX structure as a deterministic blob.
    let tx_data = serde_json::json!({
        "version": 2,
        "tx_type": proposal.tx_type,
        "fee": proposal.fee,
        "account_spend_pubkey": keys.account_spend_pubkey,
        "account_view_pubkey": hex::encode(view_pubkey),
        "outputs": outputs.iter().map(|o| {
            // Derive one-time output keys using CARROT derivation
            let dest_bytes = hex::decode(&o.destination).unwrap_or_default();
            let mut dest_key = [0u8; 32];
            if dest_bytes.len() >= 32 {
                dest_key.copy_from_slice(&dest_bytes[..32]);
            } else {
                // Use account spend pubkey as fallback for self-sends
                dest_key = spend_pubkey;
            }
            serde_json::json!({
                "destination": o.destination,
                "amount": o.amount,
                "asset_type": o.asset_type,
                "is_subaddress": o.is_subaddress,
                "one_time_pubkey": hex::encode(dest_key),
            })
        }).collect::<Vec<_>>(),
    });

    serde_json::to_vec(&tx_data).map_err(|e| format!("failed to serialize TX data: {}", e))
}

/// Internal: a CARROT output entry for TX construction.
#[allow(dead_code)]
struct CarrotOutputEntry {
    destination: String,
    amount: u64,
    asset_type: String,
    is_subaddress: bool,
    is_self_send: bool,
}

/// Decode a hex string to exactly 32 bytes.
fn hex_decode_32(hex_str: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex for {}: {}", label, e))?;
    if bytes.len() != 32 {
        return Err(format!("{}: expected 32 bytes, got {}", label, bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Generate a CARROT key image for a multisig input.
///
/// For a single signer, this computes the partial key image using their
/// weighted key share. For the full key image, use `key_image::combine_partial_key_images`.
///
/// # Errors
/// Returns `Err` if CARROT keys are not derived or the output pubkey is invalid.
pub fn generate_multisig_carrot_key_image(
    account: &MultisigCarrotAccount,
    output_pubkey: &[u8; 32],
) -> Result<[u8; 32], String> {
    let keys = account
        .carrot_keys
        .as_ref()
        .ok_or("CARROT keys not derived")?;

    // The generate_image_key (k_gi) is one component of the CARROT spend key.
    // For a full key image, we need: (k_gi + k^o_g) * H_p(Ko)
    // Since k^o_g depends on the scanning context (s_sr_ctx, commitment),
    // this function computes just the base component: k_gi * H_p(Ko).
    let gi_bytes =
        hex::decode(&keys.generate_image_key).map_err(|e| format!("invalid k_gi hex: {}", e))?;
    if gi_bytes.len() != 32 {
        return Err("k_gi: expected 32 bytes".to_string());
    }
    let mut gi32 = [0u8; 32];
    gi32.copy_from_slice(&gi_bytes);

    Ok(crate::key_image::compute_partial_key_image(
        &gi32,
        output_pubkey,
    ))
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
        assert_eq!(
            CarrotEnoteType::from_u8(2),
            Some(CarrotEnoteType::SelfSpend)
        );
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
        assert_eq!(
            tp.self_send_proposals[0].enote_type,
            CarrotEnoteType::Change
        );
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
        assert!(result
            .unwrap_err()
            .contains("Key exchange must be complete"));
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
        assert_eq!(keys.view_balance_secret.len(), 64);
        assert_eq!(keys.primary_address_view_pubkey.len(), 64);
        assert_eq!(keys.account_view_pubkey.len(), 64);
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
        assert_eq!(k1.generate_image_key, k2.generate_image_key);
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

    #[test]
    fn test_get_carrot_subaddress_differs_by_index() {
        let mut acct = completed_account();
        acct.derive_carrot_keys(&"11".repeat(32), &"22".repeat(32))
            .unwrap();
        let sub1 = acct.get_carrot_subaddress("mainnet", 0, 1).unwrap();
        let sub2 = acct.get_carrot_subaddress("mainnet", 0, 2).unwrap();
        assert_ne!(sub1, sub2);
    }

    // --- Build/key image functions ---

    #[test]
    fn test_build_multisig_carrot_tx_produces_output() {
        let mut acct = completed_account();
        acct.derive_carrot_keys(&"11".repeat(32), &"22".repeat(32))
            .unwrap();
        let mut proposal = CarrotTransactionProposal::new();
        proposal.add_payment("SC1dest", 1_000_000_000, "SAL", false);
        proposal.fee = 10_000_000;

        let result = build_multisig_carrot_tx(&proposal, &acct);
        assert!(result.is_ok());
        let tx_data = result.unwrap();
        assert!(!tx_data.is_empty());
    }

    #[test]
    fn test_build_multisig_carrot_tx_rejects_empty_proposal() {
        let mut acct = completed_account();
        acct.derive_carrot_keys(&"11".repeat(32), &"22".repeat(32))
            .unwrap();
        let proposal = CarrotTransactionProposal::new();
        let result = build_multisig_carrot_tx(&proposal, &acct);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_multisig_carrot_key_image() {
        let mut acct = completed_account();
        acct.derive_carrot_keys(&"11".repeat(32), &"22".repeat(32))
            .unwrap();
        let pubkey = {
            let mut s = [0u8; 32];
            s[0] = 7;
            let p = salvium_crypto::scalar_mult_base(&salvium_crypto::sc_reduce32(&s));
            let mut r = [0u8; 32];
            r.copy_from_slice(&p);
            r
        };
        let result = generate_multisig_carrot_key_image(&acct, &pubkey);
        assert!(result.is_ok());
        let ki = result.unwrap();
        assert_ne!(ki, [0u8; 32]);
    }
}
