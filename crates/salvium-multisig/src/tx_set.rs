use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::signing::{
    combine_partial_signatures_ext, MultisigClsagContext, PartialClsag, SignerNonces,
};

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
    /// Per-input CLSAG signing contexts (ring data, key images, fake responses, etc.).
    /// Other signers use these to reconstruct `ClsagContext` for ring traversal.
    #[serde(default)]
    pub signing_contexts: Vec<MultisigClsagContext>,
    /// The proper signing message: H(prefix_hash || H(rct_base) || H(bp_components)).
    /// Shared across all inputs; also stored in each signing context's `message` field.
    #[serde(default)]
    pub signing_message: String,
    /// Per-input derivation scalar (hex). Proposer adds this to their weighted key share.
    #[serde(default)]
    pub input_key_offsets: Vec<String>,
    /// Per-input z = input_mask - pseudo_mask (hex). Proposer uses full z; co-signers use zero.
    #[serde(default)]
    pub input_z_values: Vec<String>,
    /// Per-input TCLSAG y key (hex). Empty string for CLSAG inputs.
    #[serde(default)]
    pub input_y_keys: Vec<String>,
    /// True after the proposer has signed (consumed the offsets/z/y values).
    #[serde(default)]
    pub proposer_signed: bool,
}

/// Result of finalizing a single pending multisig TX.
#[derive(Debug, Clone)]
pub struct FinalizedTx {
    /// The signed transaction blob (raw bytes from the unsigned blob with
    /// combined CLSAG/TCLSAG signatures injected).
    pub tx_blob: Vec<u8>,
    /// Per-input combined signature data.
    pub signatures: Vec<FinalizedInputSig>,
}

/// Combined signature data for one input.
#[derive(Debug, Clone)]
pub struct FinalizedInputSig {
    /// Combined `s` response scalar at the real index (hex).
    pub s: String,
    /// Challenge `c_0` at ring position 0 (hex).
    pub c_0: String,
    /// TCLSAG: combined `sy` response scalar (hex), if applicable.
    pub sy: Option<String>,
    /// Full response vector for the ring (hex-encoded scalars).
    /// `responses[real_index]` is the combined `s`, rest are fake responses.
    pub responses: Vec<String>,
    /// Real index in the ring (for convenience).
    pub real_index: usize,
}

/// Decode a hex string to exactly 32 bytes.
fn hex_to_32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

impl FinalizedTx {
    /// Inject combined signatures into the unsigned TX blob and return
    /// a broadcast-ready signed transaction.
    pub fn to_broadcast_blob(&self) -> Result<Vec<u8>, String> {
        let mut tx = salvium_tx::types::Transaction::from_bytes(&self.tx_blob)
            .map_err(|e| format!("failed to parse TX: {}", e))?;

        let rct = tx.rct.as_mut().ok_or("TX has no RCT data")?;

        for (i, sig) in self.signatures.iter().enumerate() {
            let c_0 = hex_to_32(&sig.c_0)?;
            let responses: Vec<[u8; 32]> = sig
                .responses
                .iter()
                .map(|r| hex_to_32(r))
                .collect::<Result<_, _>>()?;

            if i < rct.tclsags.len() {
                // TCLSAG input
                rct.tclsags[i].c1 = c_0;
                rct.tclsags[i].sx = responses.clone();
                if let Some(ref sy_hex) = sig.sy {
                    // Build sy vector: zeros everywhere except real_index
                    let mut sy = vec![[0u8; 32]; responses.len()];
                    if sig.real_index < sy.len() {
                        sy[sig.real_index] = hex_to_32(sy_hex)?;
                    }
                    rct.tclsags[i].sy = sy;
                }
            } else {
                // CLSAG input (index offset by tclsag count)
                let clsag_idx = i - rct.tclsags.len();
                if clsag_idx < rct.clsags.len() {
                    rct.clsags[clsag_idx].c1 = c_0;
                    rct.clsags[clsag_idx].s = responses;
                }
            }
        }

        tx.to_bytes()
            .map_err(|e| format!("failed to serialize TX: {}", e))
    }
}

impl PendingMultisigTx {
    /// Combine partial signatures from all contributing signers and produce
    /// a finalized transaction.
    ///
    /// `threshold` is the minimum number of partial signatures required per input.
    ///
    /// # Errors
    /// Returns `Err` if any input has fewer partials than the threshold, or if
    /// signature combination fails.
    pub fn finalize(&self, threshold: usize) -> Result<FinalizedTx, String> {
        if self.input_partials.is_empty() {
            return Err("no input partials to finalize".to_string());
        }

        let mut signatures = Vec::with_capacity(self.input_partials.len());

        for (i, partials) in self.input_partials.iter().enumerate() {
            if partials.len() < threshold {
                return Err(format!(
                    "input {} has {} partials, need at least {}",
                    i,
                    partials.len(),
                    threshold
                ));
            }

            let combined = combine_partial_signatures_ext(partials)?;

            // Build the full response vector from signing context if available.
            let (responses, real_index) = if i < self.signing_contexts.len() {
                let ctx = &self.signing_contexts[i];
                let mut resp: Vec<String> = ctx.fake_responses.clone();
                if ctx.real_index < resp.len() {
                    resp[ctx.real_index] = combined.s.clone();
                }
                (resp, ctx.real_index)
            } else {
                // Legacy: no signing context, return just the combined s
                (vec![combined.s.clone()], 0)
            };

            signatures.push(FinalizedInputSig {
                s: combined.s,
                c_0: combined.c_0,
                sy: combined.sy,
                responses,
                real_index,
            });
        }

        let tx_bytes =
            hex::decode(&self.tx_blob).unwrap_or_else(|_| self.tx_blob.as_bytes().to_vec());

        Ok(FinalizedTx {
            tx_blob: tx_bytes,
            signatures,
        })
    }
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
        serde_json::from_str(s).map_err(|e| format!("Failed to parse MultisigTxSet: {}", e))
    }

    /// Finalize all pending transactions, combining partial signatures.
    ///
    /// # Errors
    /// Returns `Err` if the threshold is not met or combination fails.
    pub fn finalize_all(&self) -> Result<Vec<FinalizedTx>, String> {
        if self.threshold == 0 {
            return Err("threshold is 0".to_string());
        }
        if !self.is_complete() {
            return Err(format!(
                "not enough signers: have {}, need {}",
                self.signers_contributed.len(),
                self.threshold
            ));
        }

        let mut results = Vec::with_capacity(self.pending_txs.len());
        for (i, pending) in self.pending_txs.iter().enumerate() {
            let finalized = pending
                .finalize(self.threshold)
                .map_err(|e| format!("failed to finalize TX {}: {}", i, e))?;
            results.push(finalized);
        }
        Ok(results)
    }
}

impl std::fmt::Display for MultisigTxSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self).expect("MultisigTxSet to_string should not fail")
        )
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

    #[test]
    fn test_finalize_pending_tx() {
        let pending = PendingMultisigTx {
            tx_blob: hex::encode(b"test_tx_data"),
            key_images: vec!["aa".repeat(32)],
            tx_prefix_hash: "bb".repeat(32),
            input_nonces: Vec::new(),
            input_partials: vec![vec![
                PartialClsag {
                    signer_index: 0,
                    s_partial: "01".repeat(32),
                    c_0: "cc".repeat(32),
                    sy_partial: None,
                },
                PartialClsag {
                    signer_index: 1,
                    s_partial: "02".repeat(32),
                    c_0: "cc".repeat(32),
                    sy_partial: None,
                },
            ]],
            fee: 10_000_000,
            destinations: vec![],
            signing_contexts: Vec::new(),
            signing_message: String::new(),
            input_key_offsets: Vec::new(),
            input_z_values: Vec::new(),
            input_y_keys: Vec::new(),
            proposer_signed: false,
        };

        let result = pending.finalize(2).unwrap();
        assert_eq!(result.signatures.len(), 1);
        assert_eq!(result.signatures[0].c_0, "cc".repeat(32));
        assert!(result.signatures[0].sy.is_none());
    }

    #[test]
    fn test_finalize_pending_tx_not_enough_partials() {
        let pending = PendingMultisigTx {
            tx_blob: "deadbeef".to_string(),
            key_images: vec![],
            tx_prefix_hash: "bb".repeat(32),
            input_nonces: Vec::new(),
            input_partials: vec![vec![PartialClsag {
                signer_index: 0,
                s_partial: "01".repeat(32),
                c_0: "cc".repeat(32),
                sy_partial: None,
            }]],
            fee: 0,
            destinations: vec![],
            signing_contexts: Vec::new(),
            signing_message: String::new(),
            input_key_offsets: Vec::new(),
            input_z_values: Vec::new(),
            input_y_keys: Vec::new(),
            proposer_signed: false,
        };

        let result = pending.finalize(2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("need at least 2"));
    }

    #[test]
    fn test_finalize_all() {
        let mut set = MultisigTxSet::with_config(2, 3);
        set.mark_signer_contributed("pk0");
        set.mark_signer_contributed("pk1");

        set.add_pending_tx(PendingMultisigTx {
            tx_blob: hex::encode(b"tx_data"),
            key_images: vec!["aa".repeat(32)],
            tx_prefix_hash: "bb".repeat(32),
            input_nonces: Vec::new(),
            input_partials: vec![vec![
                PartialClsag {
                    signer_index: 0,
                    s_partial: "01".repeat(32),
                    c_0: "dd".repeat(32),
                    sy_partial: None,
                },
                PartialClsag {
                    signer_index: 1,
                    s_partial: "02".repeat(32),
                    c_0: "dd".repeat(32),
                    sy_partial: None,
                },
            ]],
            fee: 5_000_000,
            destinations: vec![],
            signing_contexts: Vec::new(),
            signing_message: String::new(),
            input_key_offsets: Vec::new(),
            input_z_values: Vec::new(),
            input_y_keys: Vec::new(),
            proposer_signed: false,
        });

        let finalized = set.finalize_all().unwrap();
        assert_eq!(finalized.len(), 1);
        assert_eq!(finalized[0].signatures.len(), 1);
    }

    #[test]
    fn test_finalize_all_incomplete() {
        let mut set = MultisigTxSet::with_config(2, 3);
        set.mark_signer_contributed("pk0");
        // Only 1 signer, need 2
        let result = set.finalize_all();
        assert!(result.is_err());
    }
}
