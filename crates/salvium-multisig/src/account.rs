use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::constants::{MultisigMsgType, MULTISIG_MAX_SIGNERS, MULTISIG_MIN_THRESHOLD};
use crate::kex::{KexMessage, KexRoundProcessor};
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
    /// This participant's index in the signer group.
    pub signer_index: usize,
    /// Private key shares for multisig signing (hex-encoded).
    #[serde(default)]
    pub multisig_privkeys: Vec<String>,
    /// Common (shared view) private key (hex-encoded).
    #[serde(default)]
    pub common_privkey: Option<String>,
    /// Aggregate multisig public spend key (hex-encoded).
    #[serde(default)]
    pub multisig_pubkey: Option<String>,
    /// Aggregate common (view) public key (hex-encoded).
    #[serde(default)]
    pub common_pubkey: Option<String>,
    /// DH key → signer index mapping from KEX (hex key → indices).
    #[serde(default)]
    pub kex_keys_to_origins: HashMap<String, Vec<usize>>,
    /// Round keys from each completed KEX round (hex-encoded [u8; 32]).
    /// Persisted so that rounds 2+ can restore `KexRoundProcessor.round_keys`.
    #[serde(default)]
    pub round_keys: Vec<Vec<String>>,
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
            signer_index: 0,
            multisig_privkeys: Vec::new(),
            common_privkey: None,
            multisig_pubkey: None,
            common_pubkey: None,
            kex_keys_to_origins: HashMap::new(),
            round_keys: Vec::new(),
        })
    }

    /// Initialize the key-exchange protocol using the provided secret keys.
    ///
    /// Derives public keys using real Ed25519 scalar-to-point multiplication
    /// via salvium_crypto, then generates the first-round `KexMessage`.
    ///
    /// # Errors
    /// Returns `Err` if the spend or view keys are empty.
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

        // Derive public keys from secret keys using real Ed25519 curve operations.
        // spend_pub = sc_reduce32(keccak256(spend_key_bytes)) * G
        let spend_bytes =
            hex::decode(spend_key).map_err(|e| format!("invalid spend key hex: {}", e))?;
        let view_bytes =
            hex::decode(view_key).map_err(|e| format!("invalid view key hex: {}", e))?;

        // Reduce the secret key to a valid scalar, then compute the public point.
        let spend_scalar = salvium_crypto::sc_reduce32(&spend_bytes);
        let pub_spend = salvium_crypto::scalar_mult_base(&spend_scalar);

        let view_scalar = salvium_crypto::sc_reduce32(&view_bytes);
        let pub_view = salvium_crypto::scalar_mult_base(&view_scalar);

        self.kex_round = 1;

        let msg = KexMessage {
            round: 1,
            signer_index: self.signer_index,
            keys: vec![hex::encode(&pub_spend), hex::encode(&pub_view)],
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

    /// Set this participant's signer index.
    pub fn set_signer_index(&mut self, index: usize) {
        self.signer_index = index;
    }

    /// Process a KEX round using the incoming messages from all signers.
    ///
    /// State machine:
    /// - Round 0 (not started): call `initialize_kex()` first
    /// - Round 1: collect base pubkeys, compute DH secrets
    /// - Round 2..N-M+1: exchange DH-derived keys
    /// - Final: verification round, derive aggregate key
    ///
    /// Returns `Some(message)` if there's a next round message to send,
    /// or `None` if KEX is complete.
    pub fn process_kex_round(
        &mut self,
        messages: &[KexMessage],
    ) -> Result<Option<KexMessage>, String> {
        if self.kex_round == 0 {
            return Err("KEX not initialized — call initialize_kex() first".to_string());
        }

        let spend_hex = self.spend_key.as_ref().ok_or("no spend key set")?.clone();
        let spend_bytes =
            hex::decode(&spend_hex).map_err(|e| format!("invalid spend key hex: {}", e))?;
        let spend_scalar = salvium_crypto::sc_reduce32(&spend_bytes);
        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(&spend_scalar[..32]);

        let main_rounds = crate::kex::kex_rounds_required(self.threshold, self.signer_count);

        if self.kex_round == 1 {
            // Process round 1
            let mut processor = KexRoundProcessor::new(
                self.signer_index,
                self.signer_count,
                self.threshold,
                privkey,
            );

            let next_msg = processor.process_round1(messages)?;

            // Store processor state
            for (key, origins) in &processor.kex_keys_to_origins {
                self.kex_keys_to_origins.insert(hex::encode(key), origins.clone());
            }

            // Persist round_keys from processor
            self.round_keys = processor
                .round_keys()
                .iter()
                .map(|round| round.iter().map(hex::encode).collect())
                .collect();

            if next_msg.is_none() {
                // All main rounds done (N-of-N with 1 round)
                let (agg, view) = processor.finalize()?;
                self.multisig_pubkey = Some(hex::encode(agg));
                let view_pub = salvium_crypto::scalar_mult_base(&view);
                self.common_privkey = Some(hex::encode(view));
                self.common_pubkey = Some(hex::encode(view_pub));

                // Populate multisig_privkeys: the weighted spend key share.
                self.populate_multisig_privkeys();

                // Generate verification message
                let verify = processor.verification_message(&agg, &view);
                self.kex_round = main_rounds + 1;
                return Ok(Some(verify));
            }

            self.kex_round = 2;
            Ok(next_msg)
        } else if self.kex_round <= main_rounds {
            // Process intermediate rounds
            let mut processor = KexRoundProcessor::new(
                self.signer_index,
                self.signer_count,
                self.threshold,
                privkey,
            );
            // Rebuild processor base pubkeys from signers
            for signer in &self.signers {
                let pk = hex::decode(&signer.public_spend_key)
                    .map_err(|e| format!("invalid signer pubkey: {}", e))?;
                let mut pk32 = [0u8; 32];
                if pk.len() >= 32 {
                    pk32.copy_from_slice(&pk[..32]);
                }
                processor.base_pubkeys.push(pk32);
                let vk = hex::decode(&signer.public_view_key)
                    .map_err(|e| format!("invalid signer view key: {}", e))?;
                let mut vk32 = [0u8; 32];
                if vk.len() >= 32 {
                    vk32.copy_from_slice(&vk[..32]);
                }
                processor.base_common_privkeys.push(vk32);
            }

            // Restore round_keys from persistent state
            processor.restore_round_keys(
                &self
                    .round_keys
                    .iter()
                    .map(|round| {
                        round
                            .iter()
                            .map(|hex_str| {
                                let bytes = hex::decode(hex_str).unwrap_or_default();
                                let mut arr = [0u8; 32];
                                if bytes.len() >= 32 {
                                    arr.copy_from_slice(&bytes[..32]);
                                }
                                arr
                            })
                            .collect::<Vec<[u8; 32]>>()
                    })
                    .collect::<Vec<Vec<[u8; 32]>>>(),
            );

            let next_msg = processor.process_round_n(self.kex_round, messages)?;

            // Merge kex_keys_to_origins
            for (key, origins) in &processor.kex_keys_to_origins {
                self.kex_keys_to_origins.insert(hex::encode(key), origins.clone());
            }

            // Persist updated round_keys
            self.round_keys = processor
                .round_keys()
                .iter()
                .map(|round| round.iter().map(hex::encode).collect())
                .collect();

            if next_msg.is_none() {
                // Main rounds complete, finalize
                let (agg, view) = processor.finalize()?;
                self.multisig_pubkey = Some(hex::encode(agg));
                let view_pub = salvium_crypto::scalar_mult_base(&view);
                self.common_privkey = Some(hex::encode(view));
                self.common_pubkey = Some(hex::encode(view_pub));

                // Populate multisig_privkeys: the weighted spend key share.
                self.populate_multisig_privkeys();

                let verify = processor.verification_message(&agg, &view);
                self.kex_round = main_rounds + 1;
                return Ok(Some(verify));
            }

            self.kex_round += 1;
            Ok(next_msg)
        } else {
            // Verification round
            // Parse our aggregate key from stored state
            let agg_hex = self.multisig_pubkey.as_ref().ok_or("multisig_pubkey not set")?;
            let agg_bytes =
                hex::decode(agg_hex).map_err(|e| format!("invalid multisig_pubkey hex: {}", e))?;
            let mut agg = [0u8; 32];
            agg.copy_from_slice(&agg_bytes[..32]);

            let view_hex = self.common_privkey.as_ref().ok_or("common_privkey not set")?;
            let view_bytes =
                hex::decode(view_hex).map_err(|e| format!("invalid common_privkey hex: {}", e))?;
            let mut view = [0u8; 32];
            view.copy_from_slice(&view_bytes[..32]);

            let processor = KexRoundProcessor::new(
                self.signer_index,
                self.signer_count,
                self.threshold,
                privkey,
            );
            processor.verify_kex(messages, &agg, &view)?;

            self.kex_complete = true;
            Ok(None)
        }
    }

    /// Register signers from round 1 messages.
    ///
    /// # Errors
    /// Returns `Err` if any message has missing or empty keys.
    pub fn register_signers(&mut self, messages: &[KexMessage]) -> Result<(), String> {
        self.signers.clear();
        for msg in messages {
            let spend_key =
                msg.keys.first().filter(|k| !k.is_empty()).cloned().ok_or_else(|| {
                    format!("signer {} has missing/empty spend key", msg.signer_index)
                })?;
            let view_key =
                msg.keys.get(1).filter(|k| !k.is_empty()).cloned().ok_or_else(|| {
                    format!("signer {} has missing/empty view key", msg.signer_index)
                })?;
            self.signers.push(MultisigSigner::with_config(
                msg.signer_index,
                spend_key,
                view_key,
                format!("signer_{}", msg.signer_index),
            ));
        }
        Ok(())
    }

    /// Populate `multisig_privkeys` with the weighted spend key share.
    ///
    /// Called after KEX finalization. The weighted share is used during
    /// partial signing so that all signers' contributions sum correctly.
    fn populate_multisig_privkeys(&mut self) {
        if let Ok(weighted) = self.get_weighted_spend_key_share() {
            self.multisig_privkeys = vec![hex::encode(weighted)];
        }
    }

    /// Compute the aggregation coefficient for this signer.
    ///
    /// Requires that signers have been registered (via `register_signers`).
    pub fn get_aggregation_coefficient(&self) -> Result<[u8; 32], String> {
        if self.signers.is_empty() {
            return Err("no signers registered".to_string());
        }

        // Collect and sort all signer spend pubkeys
        let mut all_pubkeys: Vec<[u8; 32]> = Vec::with_capacity(self.signers.len());
        for signer in &self.signers {
            let pk_bytes = hex::decode(&signer.public_spend_key)
                .map_err(|e| format!("invalid signer pubkey hex: {}", e))?;
            if pk_bytes.len() != 32 {
                return Err(format!(
                    "signer {} pubkey: expected 32 bytes, got {}",
                    signer.index,
                    pk_bytes.len()
                ));
            }
            let mut pk32 = [0u8; 32];
            pk32.copy_from_slice(&pk_bytes);
            all_pubkeys.push(pk32);
        }

        let mut sorted = all_pubkeys.clone();
        sorted.sort();

        // Find our own pubkey
        let my_pubkey = all_pubkeys
            .get(self.signer_index)
            .ok_or_else(|| format!("signer_index {} out of range", self.signer_index))?;

        Ok(crate::kex::aggregation_coefficient(my_pubkey, &sorted))
    }

    /// Compute this signer's weighted spend key share: coeff_i * k_i.
    ///
    /// The sum of all signers' weighted shares' public points equals the aggregate
    /// multisig public key.
    ///
    /// # Errors
    /// Returns `Err` if the spend key is not set or signers are not registered.
    pub fn get_weighted_spend_key_share(&self) -> Result<[u8; 32], String> {
        let spend_hex = self.spend_key.as_ref().ok_or("no spend key set")?;
        let spend_bytes =
            hex::decode(spend_hex).map_err(|e| format!("invalid spend key hex: {}", e))?;
        let spend_scalar = salvium_crypto::sc_reduce32(&spend_bytes);

        let coeff = self.get_aggregation_coefficient()?;

        // weighted = coeff * spend_scalar
        let weighted = salvium_crypto::sc_mul(&coeff, &spend_scalar);
        let mut result = [0u8; 32];
        result.copy_from_slice(&weighted[..32]);
        Ok(result)
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
    fn test_initialize_kex_produces_valid_pubkeys() {
        let mut account = MultisigAccount::new(2, 2).unwrap();
        let spend = "11".repeat(32);
        let view = "22".repeat(32);
        let msg = account.initialize_kex(&spend, &view).unwrap();

        // Public keys should be 32 bytes (64 hex chars).
        assert_eq!(msg.keys[0].len(), 64);
        assert_eq!(msg.keys[1].len(), 64);
        // They should be valid hex.
        hex::decode(&msg.keys[0]).expect("spend pubkey should be valid hex");
        hex::decode(&msg.keys[1]).expect("view pubkey should be valid hex");
    }

    #[test]
    fn test_initialize_kex_requires_spend_key() {
        let mut account = MultisigAccount::new(2, 2).unwrap();
        let result = account.initialize_kex("", &"22".repeat(32));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("key") || msg.contains("Base"));
    }

    #[test]
    fn test_initialize_kex_requires_view_key() {
        let mut account = MultisigAccount::new(2, 2).unwrap();
        let result = account.initialize_kex(&"11".repeat(32), "");
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
