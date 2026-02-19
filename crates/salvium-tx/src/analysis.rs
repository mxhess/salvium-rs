//! Transaction analysis utilities.
//!
//! Provides helpers for extracting information from parsed transactions:
//! key images, output keys, amount decryption, fee extraction, and
//! transaction classification.

use crate::types::*;
use crate::TxError;

/// Summary of a parsed transaction.
#[derive(Debug)]
pub struct TxSummary {
    /// Transaction type name.
    pub tx_type_name: &'static str,
    /// Number of inputs.
    pub num_inputs: usize,
    /// Number of outputs.
    pub num_outputs: usize,
    /// Transaction fee (0 for coinbase).
    pub fee: u64,
    /// Source asset type.
    pub source_asset: String,
    /// Destination asset type.
    pub destination_asset: String,
    /// Amount burnt (for BURN/CONVERT txs).
    pub amount_burnt: u64,
    /// Whether this is a coinbase (miner) transaction.
    pub is_coinbase: bool,
    /// RCT type name.
    pub rct_type_name: &'static str,
}

impl Transaction {
    /// Generate a summary of this transaction.
    pub fn summary(&self) -> TxSummary {
        let is_coinbase = self.prefix.inputs.iter().any(|i| matches!(i, TxInput::Gen { .. }));
        let fee = self.rct.as_ref().map(|r| r.txn_fee).unwrap_or(0);

        TxSummary {
            tx_type_name: tx_type_name(self.prefix.tx_type),
            num_inputs: self.prefix.inputs.len(),
            num_outputs: self.prefix.outputs.len(),
            fee,
            source_asset: self.prefix.source_asset_type.clone(),
            destination_asset: self.prefix.destination_asset_type.clone(),
            amount_burnt: self.prefix.amount_burnt,
            is_coinbase,
            rct_type_name: rct_type_name(self.rct.as_ref().map(|r| r.rct_type).unwrap_or(0)),
        }
    }

    /// Extract all key images from the transaction inputs.
    pub fn key_images(&self) -> Vec<[u8; 32]> {
        self.prefix
            .inputs
            .iter()
            .filter_map(|i| i.key_image().copied())
            .collect()
    }

    /// Extract all output one-time keys.
    pub fn output_keys(&self) -> Vec<[u8; 32]> {
        self.prefix.outputs.iter().map(|o| *o.key()).collect()
    }

    /// Get the coinbase height (if this is a coinbase tx).
    pub fn coinbase_height(&self) -> Option<u64> {
        self.prefix.inputs.iter().find_map(|i| match i {
            TxInput::Gen { height } => Some(*height),
            _ => None,
        })
    }

    /// Get the fee from RCT signatures.
    pub fn fee(&self) -> u64 {
        self.rct.as_ref().map(|r| r.txn_fee).unwrap_or(0)
    }

    /// Check if this transaction is a coinbase (miner) transaction.
    pub fn is_coinbase(&self) -> bool {
        self.prefix.inputs.iter().any(|i| matches!(i, TxInput::Gen { .. }))
    }

    /// Get the total number of ring members across all inputs.
    pub fn total_ring_members(&self) -> usize {
        self.prefix
            .inputs
            .iter()
            .map(|i| match i {
                TxInput::Key { key_offsets, .. } => key_offsets.len(),
                _ => 0,
            })
            .sum()
    }

    /// Check if this is a CARROT-era transaction (uses TCLSAG).
    pub fn is_carrot_era(&self) -> bool {
        self.rct
            .as_ref()
            .map(|r| r.rct_type >= rct_type::SALVIUM_ONE)
            .unwrap_or(false)
    }

    /// Get the output commitment public keys (for verification).
    pub fn output_commitments(&self) -> Vec<[u8; 32]> {
        self.rct.as_ref().map(|r| r.out_pk.clone()).unwrap_or_default()
    }

    /// Get the encrypted amount data for each output.
    pub fn encrypted_amounts(&self) -> Vec<[u8; 8]> {
        self.rct
            .as_ref()
            .map(|r| r.ecdh_info.iter().map(|e| e.amount).collect())
            .unwrap_or_default()
    }

    /// Extract the tx public key from the extra field.
    ///
    /// The extra field format: tag(1) + pubkey(32).
    /// Tag 0x01 = tx public key.
    pub fn tx_public_key(&self) -> Option<[u8; 32]> {
        let extra = &self.prefix.extra;
        let mut i = 0;
        while i < extra.len() {
            match extra[i] {
                0x01 => {
                    // TX public key.
                    if i + 33 <= extra.len() {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&extra[i + 1..i + 33]);
                        return Some(key);
                    }
                    return None;
                }
                0x02 => {
                    // Nonce: length-prefixed.
                    if i + 1 < extra.len() {
                        let len = extra[i + 1] as usize;
                        i += 2 + len;
                    } else {
                        break;
                    }
                }
                0x04 => {
                    // Additional public keys: count + keys.
                    if i + 1 < extra.len() {
                        let count = extra[i + 1] as usize;
                        i += 2 + count * 32;
                    } else {
                        break;
                    }
                }
                _ => {
                    i += 1;
                }
            }
        }
        None
    }

    /// Extract additional public keys from the extra field.
    pub fn additional_public_keys(&self) -> Vec<[u8; 32]> {
        let extra = &self.prefix.extra;
        let mut i = 0;
        while i < extra.len() {
            match extra[i] {
                0x01 => {
                    i += 33; // skip tx pub key
                }
                0x02 => {
                    if i + 1 < extra.len() {
                        let len = extra[i + 1] as usize;
                        i += 2 + len;
                    } else {
                        break;
                    }
                }
                0x04 => {
                    if i + 1 < extra.len() {
                        let count = extra[i + 1] as usize;
                        let mut keys = Vec::with_capacity(count);
                        i += 2;
                        for _ in 0..count {
                            if i + 32 <= extra.len() {
                                let mut key = [0u8; 32];
                                key.copy_from_slice(&extra[i..i + 32]);
                                keys.push(key);
                                i += 32;
                            }
                        }
                        return keys;
                    }
                    break;
                }
                _ => {
                    i += 1;
                }
            }
        }
        Vec::new()
    }
}

/// Convert a transaction type byte to a human-readable name.
pub fn tx_type_name(t: u8) -> &'static str {
    match t {
        tx_type::UNSET => "UNSET",
        tx_type::MINER => "MINER",
        tx_type::PROTOCOL => "PROTOCOL",
        tx_type::TRANSFER => "TRANSFER",
        tx_type::CONVERT => "CONVERT",
        tx_type::BURN => "BURN",
        tx_type::STAKE => "STAKE",
        tx_type::RETURN => "RETURN",
        tx_type::AUDIT => "AUDIT",
        _ => "UNKNOWN",
    }
}

/// Convert an RCT type byte to a human-readable name.
pub fn rct_type_name(t: u8) -> &'static str {
    match t {
        rct_type::NULL => "Null",
        rct_type::FULL => "Full",
        rct_type::SIMPLE => "Simple",
        rct_type::BULLETPROOF => "Bulletproof",
        rct_type::BULLETPROOF2 => "Bulletproof2",
        rct_type::CLSAG => "CLSAG",
        rct_type::BULLETPROOF_PLUS => "BulletproofPlus",
        rct_type::FULL_PROOFS => "FullProofs",
        rct_type::SALVIUM_ZERO => "SalviumZero",
        rct_type::SALVIUM_ONE => "SalviumOne",
        _ => "Unknown",
    }
}

/// Decrypt an encrypted amount using the shared secret.
///
/// The shared secret should be the ECDH shared secret derived during scanning.
/// Uses keccak256("amount" || shared_secret) to derive the XOR mask.
pub fn decrypt_amount_cn(encrypted: &[u8; 8], shared_secret: &[u8; 32]) -> u64 {
    let mut key_data = Vec::with_capacity(6 + 32);
    key_data.extend_from_slice(b"amount");
    key_data.extend_from_slice(shared_secret);
    let mask = salvium_crypto::keccak256(&key_data);

    let mut amount_bytes = [0u8; 8];
    for i in 0..8 {
        amount_bytes[i] = encrypted[i] ^ mask[i];
    }
    u64::from_le_bytes(amount_bytes)
}

/// Decrypt a CARROT encrypted amount using the contextualized shared secret.
pub fn decrypt_amount_carrot(encrypted: &[u8; 8], s_ctx: &[u8; 32], ko: &[u8; 32]) -> u64 {
    salvium_crypto::carrot_scan::decrypt_amount(encrypted, s_ctx, ko)
}

/// Validate basic transaction structure.
pub fn validate_structure(tx: &Transaction) -> Result<(), TxError> {
    if tx.prefix.version == 0 {
        return Err(TxError::Invalid("version cannot be 0".into()));
    }

    if tx.prefix.inputs.is_empty() {
        return Err(TxError::Invalid("transaction has no inputs".into()));
    }

    if tx.prefix.outputs.is_empty() {
        return Err(TxError::Invalid("transaction has no outputs".into()));
    }

    // For non-coinbase txs, all inputs must be Key type.
    if !tx.is_coinbase() {
        for input in &tx.prefix.inputs {
            match input {
                TxInput::Key { key_offsets, .. } => {
                    if key_offsets.is_empty() {
                        return Err(TxError::Invalid("input has empty ring".into()));
                    }
                }
                TxInput::Gen { .. } => {
                    return Err(TxError::Invalid(
                        "non-coinbase tx has generation input".into(),
                    ));
                }
            }
        }
    }

    // Check RCT signature presence for v2+ txs.
    if tx.prefix.version >= 2 && !tx.is_coinbase() && tx.rct.is_none() {
        return Err(TxError::Invalid("v2 tx missing RCT signatures".into()));
    }

    // Verify output count matches RCT data.
    if let Some(ref rct) = tx.rct {
        if !tx.is_coinbase() {
            let out_count = tx.prefix.outputs.len();
            if rct.ecdh_info.len() != out_count {
                return Err(TxError::Invalid(format!(
                    "ECDH info count {} != output count {}",
                    rct.ecdh_info.len(),
                    out_count
                )));
            }
            if rct.out_pk.len() != out_count {
                return Err(TxError::Invalid(format!(
                    "outPk count {} != output count {}",
                    rct.out_pk.len(),
                    out_count
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_tx() -> Transaction {
        Transaction {
            prefix: TxPrefix {
                version: 2,
                unlock_time: 0,
                inputs: vec![TxInput::Key {
                    amount: 0,
                    asset_type: "SAL".to_string(),
                    key_offsets: vec![100, 50, 30],
                    key_image: [0xAA; 32],
                }],
                outputs: vec![
                    TxOutput::TaggedKey {
                        amount: 0,
                        key: [0xBB; 32],
                        asset_type: "SAL".to_string(),
                        unlock_time: 0,
                        view_tag: 42,
                    },
                    TxOutput::TaggedKey {
                        amount: 0,
                        key: [0xCC; 32],
                        asset_type: "SAL".to_string(),
                        unlock_time: 0,
                        view_tag: 43,
                    },
                ],
                extra: vec![0x01, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                            0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                            0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                            0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD],
                tx_type: tx_type::TRANSFER,
                amount_burnt: 0,
                return_address: None,
                return_pubkey: None,
                return_address_list: None,
                return_address_change_mask: None,
                protocol_tx_data: None,
                source_asset_type: "SAL".to_string(),
                destination_asset_type: "SAL".to_string(),
                amount_slippage_limit: 0,
            },
            rct: Some(RctSignatures {
                rct_type: rct_type::SALVIUM_ONE,
                txn_fee: 30000000,
                ecdh_info: vec![
                    EcdhInfo { amount: [1; 8] },
                    EcdhInfo { amount: [2; 8] },
                ],
                out_pk: vec![[0xEE; 32], [0xFF; 32]],
                p_r: None,
                salvium_data: None,
                bulletproof_plus: vec![],
                clsags: vec![],
                tclsags: vec![],
                pseudo_outs: vec![],
            }),
        }
    }

    #[test]
    fn test_tx_summary() {
        let tx = make_test_tx();
        let summary = tx.summary();
        assert_eq!(summary.tx_type_name, "TRANSFER");
        assert_eq!(summary.num_inputs, 1);
        assert_eq!(summary.num_outputs, 2);
        assert_eq!(summary.fee, 30000000);
        assert!(!summary.is_coinbase);
        assert_eq!(summary.rct_type_name, "SalviumOne");
    }

    #[test]
    fn test_key_images() {
        let tx = make_test_tx();
        let kis = tx.key_images();
        assert_eq!(kis.len(), 1);
        assert_eq!(kis[0], [0xAA; 32]);
    }

    #[test]
    fn test_output_keys() {
        let tx = make_test_tx();
        let keys = tx.output_keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], [0xBB; 32]);
        assert_eq!(keys[1], [0xCC; 32]);
    }

    #[test]
    fn test_is_coinbase() {
        let tx = make_test_tx();
        assert!(!tx.is_coinbase());

        let coinbase = Transaction {
            prefix: TxPrefix {
                version: 2,
                unlock_time: 160,
                inputs: vec![TxInput::Gen { height: 100 }],
                outputs: vec![TxOutput::TaggedKey {
                    amount: 600000000000,
                    key: [0xAA; 32],
                    asset_type: "SAL".to_string(),
                    unlock_time: 160,
                    view_tag: 0,
                }],
                extra: vec![0x01; 33],
                tx_type: tx_type::MINER,
                amount_burnt: 0,
                return_address: None,
                return_pubkey: None,
                return_address_list: None,
                return_address_change_mask: None,
                protocol_tx_data: None,
                source_asset_type: "SAL".to_string(),
                destination_asset_type: "SAL".to_string(),
                amount_slippage_limit: 0,
            },
            rct: None,
        };
        assert!(coinbase.is_coinbase());
        assert_eq!(coinbase.coinbase_height(), Some(100));
    }

    #[test]
    fn test_is_carrot_era() {
        let tx = make_test_tx();
        assert!(tx.is_carrot_era());
    }

    #[test]
    fn test_total_ring_members() {
        let tx = make_test_tx();
        assert_eq!(tx.total_ring_members(), 3);
    }

    #[test]
    fn test_output_commitments() {
        let tx = make_test_tx();
        let comms = tx.output_commitments();
        assert_eq!(comms.len(), 2);
    }

    #[test]
    fn test_encrypted_amounts() {
        let tx = make_test_tx();
        let amounts = tx.encrypted_amounts();
        assert_eq!(amounts.len(), 2);
        assert_eq!(amounts[0], [1; 8]);
    }

    #[test]
    fn test_tx_public_key_extraction() {
        let tx = make_test_tx();
        let pk = tx.tx_public_key();
        assert!(pk.is_some());
        assert_eq!(pk.unwrap(), [0xDD; 32]);
    }

    #[test]
    fn test_validate_structure_valid() {
        let tx = make_test_tx();
        assert!(validate_structure(&tx).is_ok());
    }

    #[test]
    fn test_validate_structure_no_inputs() {
        let mut tx = make_test_tx();
        tx.prefix.inputs.clear();
        assert!(validate_structure(&tx).is_err());
    }

    #[test]
    fn test_validate_structure_no_outputs() {
        let mut tx = make_test_tx();
        tx.prefix.outputs.clear();
        assert!(validate_structure(&tx).is_err());
    }

    #[test]
    fn test_validate_structure_mismatched_rct() {
        let mut tx = make_test_tx();
        // Add an extra output without matching RCT data.
        tx.prefix.outputs.push(TxOutput::TaggedKey {
            amount: 0,
            key: [0x11; 32],
            asset_type: "SAL".to_string(),
            unlock_time: 0,
            view_tag: 0,
        });
        assert!(validate_structure(&tx).is_err());
    }

    #[test]
    fn test_tx_type_names() {
        assert_eq!(tx_type_name(tx_type::MINER), "MINER");
        assert_eq!(tx_type_name(tx_type::TRANSFER), "TRANSFER");
        assert_eq!(tx_type_name(tx_type::STAKE), "STAKE");
        assert_eq!(tx_type_name(tx_type::CONVERT), "CONVERT");
        assert_eq!(tx_type_name(tx_type::BURN), "BURN");
        assert_eq!(tx_type_name(tx_type::RETURN), "RETURN");
        assert_eq!(tx_type_name(tx_type::AUDIT), "AUDIT");
        assert_eq!(tx_type_name(99), "UNKNOWN");
    }

    #[test]
    fn test_rct_type_names() {
        assert_eq!(rct_type_name(rct_type::NULL), "Null");
        assert_eq!(rct_type_name(rct_type::CLSAG), "CLSAG");
        assert_eq!(rct_type_name(rct_type::SALVIUM_ONE), "SalviumOne");
        assert_eq!(rct_type_name(99), "Unknown");
    }

    #[test]
    fn test_decrypt_amount_cn() {
        // Test with known values — the decryption XORs with keccak256("amount" + secret).
        let secret = [0x42; 32];
        let amount: u64 = 1_000_000_000;
        let amount_le = amount.to_le_bytes();

        // Encrypt.
        let mut key_data = Vec::new();
        key_data.extend_from_slice(b"amount");
        key_data.extend_from_slice(&secret);
        let mask = salvium_crypto::keccak256(&key_data);
        let mut encrypted = [0u8; 8];
        for i in 0..8 {
            encrypted[i] = amount_le[i] ^ mask[i];
        }

        // Decrypt and verify.
        let decrypted = decrypt_amount_cn(&encrypted, &secret);
        assert_eq!(decrypted, amount);
    }
}
