//! Stake lifecycle tracking.
//!
//! Mirrors the JS `StakeRecord` / `MemoryStorage` stake operations so that
//! Rust-side wallet code can track STAKE -> PROTOCOL-return -> reorg-rollback
//! lifecycles identically to the TypeScript wallet.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Transaction type value for a STAKE transaction.
pub const TX_TYPE_STAKE: u32 = 6;

/// Transaction type value for a PROTOCOL (return) transaction.
pub const TX_TYPE_PROTOCOL: u32 = 7;

// ---------------------------------------------------------------------------
// StakeStatus
// ---------------------------------------------------------------------------

/// Status of a stake record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StakeStatus {
    Locked,
    Returned,
}

// ---------------------------------------------------------------------------
// StakeRecord
// ---------------------------------------------------------------------------

/// A record tracking the lifecycle of a staking transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeRecord {
    pub tx_hash: String,
    pub output_key: String,
    pub amount_staked: u64,
    pub fee: u64,
    pub block_height: u64,
    pub asset_type: String,
    pub status: StakeStatus,
    pub return_tx_hash: Option<String>,
    pub return_amount: Option<u64>,
    pub return_height: Option<u64>,
    pub return_origin_key: Option<String>,
}

impl Default for StakeRecord {
    fn default() -> Self {
        Self {
            tx_hash: String::new(),
            output_key: String::new(),
            amount_staked: 0,
            fee: 0,
            block_height: 0,
            asset_type: "SAL".to_string(),
            status: StakeStatus::Locked,
            return_tx_hash: None,
            return_amount: None,
            return_height: None,
            return_origin_key: None,
        }
    }
}

// ---------------------------------------------------------------------------
// StakeStore
// ---------------------------------------------------------------------------

/// In-memory stake storage for tracking stake lifecycles.
#[derive(Debug, Clone, Default)]
pub struct StakeStore {
    stakes: Vec<StakeRecord>,
}

impl StakeStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a stake record (matched by `tx_hash`).
    pub fn put_stake(&mut self, record: StakeRecord) {
        if let Some(existing) = self.stakes.iter_mut().find(|s| s.tx_hash == record.tx_hash) {
            *existing = record;
        } else {
            self.stakes.push(record);
        }
    }

    /// Look up a stake by its originating transaction hash.
    pub fn get_stake(&self, tx_hash: &str) -> Option<&StakeRecord> {
        self.stakes.iter().find(|s| s.tx_hash == tx_hash)
    }

    /// Look up a stake by its output key (the `return_pubkey` / change-output
    /// public key recorded at stake time).
    pub fn get_stake_by_output_key(&self, output_key: &str) -> Option<&StakeRecord> {
        self.stakes.iter().find(|s| s.output_key == output_key)
    }

    /// Return stakes matching optional filters for status and/or asset type.
    ///
    /// When both filters are `None` all stakes are returned.
    pub fn get_stakes(
        &self,
        status: Option<StakeStatus>,
        asset_type: Option<&str>,
    ) -> Vec<&StakeRecord> {
        self.stakes
            .iter()
            .filter(|s| {
                status.is_none_or(|st| s.status == st)
                    && asset_type.is_none_or(|at| s.asset_type == at)
            })
            .collect()
    }

    /// Mark a locked stake as returned, filling in the return metadata.
    ///
    /// Returns `true` if a matching stake was found and updated, `false`
    /// otherwise.
    pub fn mark_stake_returned(
        &mut self,
        tx_hash: &str,
        return_tx_hash: &str,
        return_amount: u64,
        return_height: u64,
    ) -> bool {
        if let Some(stake) = self.stakes.iter_mut().find(|s| s.tx_hash == tx_hash) {
            stake.status = StakeStatus::Returned;
            stake.return_tx_hash = Some(return_tx_hash.to_string());
            stake.return_amount = Some(return_amount);
            stake.return_height = Some(return_height);
            true
        } else {
            false
        }
    }

    /// Handle a blockchain reorganisation by removing stakes whose
    /// `block_height` is strictly above `height`, and reverting any returned
    /// stakes whose `return_height` is strictly above `height` back to
    /// [`StakeStatus::Locked`].
    pub fn delete_stakes_above(&mut self, height: u64) {
        // First, revert returned stakes where return_height > height but
        // block_height <= height back to Locked.
        for stake in &mut self.stakes {
            if stake.block_height <= height {
                if let Some(rh) = stake.return_height {
                    if rh > height {
                        stake.status = StakeStatus::Locked;
                        stake.return_tx_hash = None;
                        stake.return_amount = None;
                        stake.return_height = None;
                    }
                }
            }
        }

        // Then remove stakes whose block_height is above the cut-off.
        self.stakes.retain(|s| s.block_height <= height);
    }

    /// Number of stake records in the store.
    pub fn len(&self) -> usize {
        self.stakes.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.stakes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Extract the `return_pubkey` from a transaction JSON blob.
///
/// CARROT path:  `prefix.protocol_tx_data.return_pubkey`
/// Pre-CARROT:   `prefix.return_pubkey`
///
/// Returns `None` when neither path yields a string value.
pub fn extract_return_pubkey(tx_json: &serde_json::Value) -> Option<String> {
    // Try the CARROT path first (preferred).
    let prefix = tx_json.get("prefix");

    if let Some(prefix) = prefix {
        // CARROT: prefix.protocol_tx_data.return_pubkey
        if let Some(ptd) = prefix.get("protocol_tx_data") {
            if let Some(rp) = ptd.get("return_pubkey") {
                if let Some(s) = rp.as_str() {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }

        // Pre-CARROT: prefix.return_pubkey
        if let Some(rp) = prefix.get("return_pubkey") {
            if let Some(s) = rp.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
    }

    // Fallback: top-level return_pubkey (no prefix wrapper).
    if let Some(rp) = tx_json.get("return_pubkey") {
        if let Some(s) = rp.as_str() {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }

    None
}

/// Record or update stake lifecycle state from a scanned transaction.
///
/// * `tx_type == TX_TYPE_STAKE` (6) — create a new locked [`StakeRecord`].
/// * `tx_type == TX_TYPE_PROTOCOL` (7) — try to match via
///   `return_origin_key` (CARROT) or `output_key` (pre-CARROT) and call
///   [`StakeStore::mark_stake_returned`].
///
/// `owned_output_keys` is a list of `(output_public_key, return_origin_key,
/// amount)` triples for outputs that belong to this wallet.
///
/// `is_our_stake` should be `true` when the wallet spent inputs in a STAKE
/// transaction (i.e. it was **our** stake, not someone else's).
#[allow(clippy::too_many_arguments)]
pub fn record_stake_lifecycle(
    store: &mut StakeStore,
    tx_json: &serde_json::Value,
    tx_hash: &str,
    block_height: u64,
    tx_type: u32,
    amount_staked: u64,
    fee: u64,
    asset_type: &str,
    is_our_stake: bool,
    owned_output_keys: &[(String, Option<String>, u64)],
) {
    match tx_type {
        TX_TYPE_STAKE => {
            if !is_our_stake {
                return;
            }

            // Determine the output key to use for matching returns later.
            let return_pubkey = extract_return_pubkey(tx_json);
            let output_key = return_pubkey
                .or_else(|| owned_output_keys.first().map(|(pk, _, _)| pk.clone()))
                .unwrap_or_default();

            let record = StakeRecord {
                tx_hash: tx_hash.to_string(),
                output_key,
                amount_staked,
                fee,
                block_height,
                asset_type: asset_type.to_string(),
                status: StakeStatus::Locked,
                return_tx_hash: None,
                return_amount: None,
                return_height: None,
                return_origin_key: None,
            };
            store.put_stake(record);
        }
        TX_TYPE_PROTOCOL => {
            // Try to match each owned output to an existing locked stake.
            for (pub_key, return_origin, amount) in owned_output_keys {
                // CARROT path: returnOriginKey -> stake.output_key
                if let Some(origin) = return_origin {
                    if let Some(stake) = store.get_stake_by_output_key(origin) {
                        if stake.status == StakeStatus::Locked {
                            let stake_hash = stake.tx_hash.clone();
                            store.mark_stake_returned(
                                &stake_hash,
                                tx_hash,
                                *amount,
                                block_height,
                            );
                            continue;
                        }
                    }
                }

                // Pre-CARROT path: output public key == stake.output_key
                if let Some(stake) = store.get_stake_by_output_key(pub_key) {
                    if stake.status == StakeStatus::Locked {
                        let stake_hash = stake.tx_hash.clone();
                        store.mark_stake_returned(
                            &stake_hash,
                            tx_hash,
                            *amount,
                            block_height,
                        );
                    }
                }
            }
        }
        _ => {
            // Other transaction types are not relevant to stake tracking.
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- StakeRecord creation / defaults ------------------------------------

    #[test]
    fn stake_record_default_values() {
        let sr = StakeRecord::default();
        assert_eq!(sr.tx_hash, "");
        assert_eq!(sr.output_key, "");
        assert_eq!(sr.amount_staked, 0);
        assert_eq!(sr.fee, 0);
        assert_eq!(sr.block_height, 0);
        assert_eq!(sr.asset_type, "SAL");
        assert_eq!(sr.status, StakeStatus::Locked);
        assert!(sr.return_tx_hash.is_none());
        assert!(sr.return_amount.is_none());
        assert!(sr.return_height.is_none());
        assert!(sr.return_origin_key.is_none());
    }

    #[test]
    fn stake_record_with_provided_values() {
        let sr = StakeRecord {
            tx_hash: "abc123".into(),
            output_key: "pubkey_hex_abc".into(),
            amount_staked: 130_130_000_000_000,
            fee: 50_000_000,
            block_height: 417_082,
            asset_type: "SAL".into(),
            status: StakeStatus::Returned,
            return_tx_hash: Some("def456".into()),
            return_amount: Some(130_200_000_000_000),
            return_height: Some(417_200),
            return_origin_key: None,
        };
        assert_eq!(sr.tx_hash, "abc123");
        assert_eq!(sr.block_height, 417_082);
        assert_eq!(sr.amount_staked, 130_130_000_000_000);
        assert_eq!(sr.fee, 50_000_000);
        assert_eq!(sr.output_key, "pubkey_hex_abc");
        assert_eq!(sr.status, StakeStatus::Returned);
        assert_eq!(sr.return_tx_hash.as_deref(), Some("def456"));
        assert_eq!(sr.return_height, Some(417_200));
        assert_eq!(sr.return_amount, Some(130_200_000_000_000));
    }

    // -- JSON round-trip ----------------------------------------------------

    #[test]
    fn stake_record_json_roundtrip() {
        let original = StakeRecord {
            tx_hash: "roundtrip_hash".into(),
            output_key: "change_key_hex".into(),
            amount_staked: 123_456_789_012,
            fee: 999_999,
            block_height: 500_000,
            asset_type: "SAL".into(),
            status: StakeStatus::Returned,
            return_tx_hash: Some("return_hash".into()),
            return_amount: Some(123_500_000_000),
            return_height: Some(500_100),
            return_origin_key: Some("origin_key".into()),
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let restored: StakeRecord = serde_json::from_str(&serialized).unwrap();

        assert_eq!(restored.tx_hash, original.tx_hash);
        assert_eq!(restored.output_key, original.output_key);
        assert_eq!(restored.amount_staked, original.amount_staked);
        assert_eq!(restored.fee, original.fee);
        assert_eq!(restored.block_height, original.block_height);
        assert_eq!(restored.asset_type, original.asset_type);
        assert_eq!(restored.status, original.status);
        assert_eq!(restored.return_tx_hash, original.return_tx_hash);
        assert_eq!(restored.return_amount, original.return_amount);
        assert_eq!(restored.return_height, original.return_height);
        assert_eq!(restored.return_origin_key, original.return_origin_key);
    }

    // -- StakeStore put / get / get_by_output_key ---------------------------

    #[test]
    fn store_put_and_get() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord {
            tx_hash: "stake_tx_1".into(),
            output_key: "change_key_1".into(),
            amount_staked: 100_000_000_000,
            block_height: 1000,
            ..Default::default()
        });

        let retrieved = store.get_stake("stake_tx_1").unwrap();
        assert_eq!(retrieved.tx_hash, "stake_tx_1");
        assert_eq!(retrieved.block_height, 1000);
        assert_eq!(retrieved.amount_staked, 100_000_000_000);
        assert_eq!(retrieved.output_key, "change_key_1");
        assert_eq!(retrieved.status, StakeStatus::Locked);
    }

    #[test]
    fn store_get_nonexistent_returns_none() {
        let store = StakeStore::new();
        assert!(store.get_stake("nonexistent").is_none());
    }

    #[test]
    fn store_get_by_output_key() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord {
            tx_hash: "stake_tx_2".into(),
            output_key: "output_key_abc".into(),
            ..Default::default()
        });

        let found = store.get_stake_by_output_key("output_key_abc").unwrap();
        assert_eq!(found.tx_hash, "stake_tx_2");

        assert!(store.get_stake_by_output_key("nonexistent_key").is_none());
    }

    #[test]
    fn store_put_updates_existing() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord {
            tx_hash: "dup".into(),
            amount_staked: 100,
            ..Default::default()
        });
        store.put_stake(StakeRecord {
            tx_hash: "dup".into(),
            amount_staked: 200,
            ..Default::default()
        });
        assert_eq!(store.len(), 1);
        assert_eq!(store.get_stake("dup").unwrap().amount_staked, 200);
    }

    // -- Filter by status ---------------------------------------------------

    #[test]
    fn filter_by_status_locked() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord { tx_hash: "st1".into(), status: StakeStatus::Locked, ..Default::default() });
        store.put_stake(StakeRecord { tx_hash: "st2".into(), status: StakeStatus::Returned, ..Default::default() });
        store.put_stake(StakeRecord { tx_hash: "st3".into(), status: StakeStatus::Locked, ..Default::default() });

        let locked = store.get_stakes(Some(StakeStatus::Locked), None);
        assert_eq!(locked.len(), 2);
    }

    #[test]
    fn filter_by_status_returned() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord { tx_hash: "st1".into(), status: StakeStatus::Locked, ..Default::default() });
        store.put_stake(StakeRecord { tx_hash: "st2".into(), status: StakeStatus::Returned, ..Default::default() });
        store.put_stake(StakeRecord { tx_hash: "st3".into(), status: StakeStatus::Locked, ..Default::default() });

        let returned = store.get_stakes(Some(StakeStatus::Returned), None);
        assert_eq!(returned.len(), 1);
        assert_eq!(returned[0].tx_hash, "st2");
    }

    // -- Filter by asset type -----------------------------------------------

    #[test]
    fn filter_by_asset_type() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord { tx_hash: "st1".into(), asset_type: "SAL".into(), ..Default::default() });
        store.put_stake(StakeRecord { tx_hash: "st2".into(), asset_type: "USD".into(), ..Default::default() });

        let sal = store.get_stakes(None, Some("SAL"));
        assert_eq!(sal.len(), 1);
        assert_eq!(sal[0].tx_hash, "st1");

        let usd = store.get_stakes(None, Some("USD"));
        assert_eq!(usd.len(), 1);
        assert_eq!(usd[0].tx_hash, "st2");
    }

    // -- mark_stake_returned ------------------------------------------------

    #[test]
    fn mark_stake_returned_updates_fields() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord {
            tx_hash: "stake_mark".into(),
            amount_staked: 100_000_000_000,
            status: StakeStatus::Locked,
            ..Default::default()
        });

        let ok = store.mark_stake_returned("stake_mark", "return_tx", 101_000_000_000, 2000);
        assert!(ok);

        let updated = store.get_stake("stake_mark").unwrap();
        assert_eq!(updated.status, StakeStatus::Returned);
        assert_eq!(updated.return_tx_hash.as_deref(), Some("return_tx"));
        assert_eq!(updated.return_height, Some(2000));
        assert_eq!(updated.return_amount, Some(101_000_000_000));
    }

    #[test]
    fn mark_stake_returned_nonexistent_returns_false() {
        let mut store = StakeStore::new();
        assert!(!store.mark_stake_returned("nonexistent", "ret", 0, 100));
    }

    // -- delete_stakes_above ------------------------------------------------

    #[test]
    fn delete_stakes_above_removes_stakes() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord { tx_hash: "st_low".into(), block_height: 100, output_key: "k1".into(), ..Default::default() });
        store.put_stake(StakeRecord { tx_hash: "st_mid".into(), block_height: 200, output_key: "k2".into(), ..Default::default() });
        store.put_stake(StakeRecord { tx_hash: "st_high".into(), block_height: 300, output_key: "k3".into(), ..Default::default() });

        store.delete_stakes_above(150);

        let remaining = store.get_stakes(None, None);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].tx_hash, "st_low");

        assert!(store.get_stake_by_output_key("k2").is_none());
        assert!(store.get_stake_by_output_key("k1").is_some());
    }

    #[test]
    fn delete_stakes_above_reverts_returned_to_locked() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord {
            tx_hash: "st_returned".into(),
            block_height: 100,
            status: StakeStatus::Locked,
            ..Default::default()
        });
        store.mark_stake_returned("st_returned", "ret_tx", 105_000_000_000, 250);

        // Verify it is returned.
        let stake = store.get_stake("st_returned").unwrap();
        assert_eq!(stake.status, StakeStatus::Returned);
        assert_eq!(stake.return_amount, Some(105_000_000_000));

        // Rollback to height 200 — return at 250 should be undone.
        store.delete_stakes_above(200);

        let stake = store.get_stake("st_returned").unwrap();
        assert_eq!(stake.status, StakeStatus::Locked);
        assert!(stake.return_tx_hash.is_none());
        assert!(stake.return_height.is_none());
        assert!(stake.return_amount.is_none());
    }

    // -- extract_return_pubkey ----------------------------------------------

    #[test]
    fn extract_return_pubkey_carrot_format() {
        let tx = json!({
            "prefix": {
                "protocol_tx_data": {
                    "return_pubkey": "aabbccdd"
                }
            }
        });
        assert_eq!(extract_return_pubkey(&tx), Some("aabbccdd".into()));
    }

    #[test]
    fn extract_return_pubkey_pre_carrot_format() {
        let tx = json!({
            "prefix": {
                "return_pubkey": "11223344"
            }
        });
        assert_eq!(extract_return_pubkey(&tx), Some("11223344".into()));
    }

    #[test]
    fn extract_return_pubkey_prefers_protocol_tx_data() {
        let tx = json!({
            "prefix": {
                "return_pubkey": "fallback",
                "protocol_tx_data": {
                    "return_pubkey": "preferred"
                }
            }
        });
        assert_eq!(extract_return_pubkey(&tx), Some("preferred".into()));
    }

    #[test]
    fn extract_return_pubkey_missing_data_returns_none() {
        let tx = json!({ "prefix": {} });
        assert_eq!(extract_return_pubkey(&tx), None);
    }

    #[test]
    fn extract_return_pubkey_no_prefix_wrapper() {
        let tx = json!({ "return_pubkey": "direct_key" });
        assert_eq!(extract_return_pubkey(&tx), Some("direct_key".into()));
    }

    // -- record_stake_lifecycle: STAKE transaction --------------------------

    #[test]
    fn record_lifecycle_stake_transaction() {
        let mut store = StakeStore::new();
        let tx = json!({
            "prefix": {
                "return_pubkey": "return_pubkey_hex"
            }
        });

        record_stake_lifecycle(
            &mut store,
            &tx,
            "stake_hash_1",
            417_082,
            TX_TYPE_STAKE,
            130_130_000_000_000,
            50_000_000,
            "SAL",
            true,
            &[("change_pubkey".into(), None, 0)],
        );

        let stake = store.get_stake("stake_hash_1").unwrap();
        assert_eq!(stake.tx_hash, "stake_hash_1");
        assert_eq!(stake.block_height, 417_082);
        assert_eq!(stake.amount_staked, 130_130_000_000_000);
        assert_eq!(stake.fee, 50_000_000);
        assert_eq!(stake.asset_type, "SAL");
        assert_eq!(stake.output_key, "return_pubkey_hex");
        assert_eq!(stake.status, StakeStatus::Locked);
    }

    #[test]
    fn record_lifecycle_stake_falls_back_to_change_output_key() {
        let mut store = StakeStore::new();
        let tx = json!({ "prefix": {} }); // No return_pubkey

        record_stake_lifecycle(
            &mut store,
            &tx,
            "st_fallback",
            100,
            TX_TYPE_STAKE,
            1000,
            10,
            "SAL",
            true,
            &[("fallback_pk".into(), None, 0)],
        );

        let stake = store.get_stake("st_fallback").unwrap();
        assert_eq!(stake.output_key, "fallback_pk");
    }

    #[test]
    fn record_lifecycle_stake_not_ours_is_ignored() {
        let mut store = StakeStore::new();
        let tx = json!({ "prefix": {} });

        record_stake_lifecycle(
            &mut store,
            &tx,
            "st_other",
            100,
            TX_TYPE_STAKE,
            1000,
            10,
            "SAL",
            false, // not our stake
            &[],
        );

        assert!(store.get_stake("st_other").is_none());
    }

    // -- record_stake_lifecycle: PROTOCOL return matching --------------------

    #[test]
    fn record_lifecycle_protocol_carrot_return_matching() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord {
            tx_hash: "orig_stake".into(),
            output_key: "carrot_origin_key".into(),
            amount_staked: 50_000_000_000,
            block_height: 100,
            status: StakeStatus::Locked,
            ..Default::default()
        });

        let tx = json!({ "prefix": {} });

        // The owned output has a return_origin_key that matches.
        record_stake_lifecycle(
            &mut store,
            &tx,
            "prot_tx_1",
            200,
            TX_TYPE_PROTOCOL,
            0,
            0,
            "SAL",
            false,
            &[("some_different_key".into(), Some("carrot_origin_key".into()), 51_000_000_000)],
        );

        let stake = store.get_stake("orig_stake").unwrap();
        assert_eq!(stake.status, StakeStatus::Returned);
        assert_eq!(stake.return_tx_hash.as_deref(), Some("prot_tx_1"));
        assert_eq!(stake.return_height, Some(200));
        assert_eq!(stake.return_amount, Some(51_000_000_000));
    }

    #[test]
    fn record_lifecycle_protocol_pre_carrot_return_matching() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord {
            tx_hash: "precarrot_stake".into(),
            output_key: "matching_pubkey".into(),
            amount_staked: 30_000_000_000,
            block_height: 50,
            status: StakeStatus::Locked,
            ..Default::default()
        });

        let tx = json!({ "prefix": {} });

        // No return_origin_key — pre-CARROT path: pub key == output_key.
        record_stake_lifecycle(
            &mut store,
            &tx,
            "prot_tx_2",
            150,
            TX_TYPE_PROTOCOL,
            0,
            0,
            "SAL",
            false,
            &[("matching_pubkey".into(), None, 31_000_000_000)],
        );

        let stake = store.get_stake("precarrot_stake").unwrap();
        assert_eq!(stake.status, StakeStatus::Returned);
        assert_eq!(stake.return_tx_hash.as_deref(), Some("prot_tx_2"));
        assert_eq!(stake.return_height, Some(150));
        assert_eq!(stake.return_amount, Some(31_000_000_000));
    }

    #[test]
    fn record_lifecycle_protocol_nonmatching_does_not_update() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord {
            tx_hash: "untouched_stake".into(),
            output_key: "specific_key".into(),
            amount_staked: 10_000,
            block_height: 100,
            status: StakeStatus::Locked,
            ..Default::default()
        });

        let tx = json!({ "prefix": {} });

        record_stake_lifecycle(
            &mut store,
            &tx,
            "prot_nm",
            200,
            TX_TYPE_PROTOCOL,
            0,
            0,
            "SAL",
            false,
            &[("different_key".into(), None, 5000)],
        );

        let stake = store.get_stake("untouched_stake").unwrap();
        assert_eq!(stake.status, StakeStatus::Locked);
        assert!(stake.return_tx_hash.is_none());
    }

    #[test]
    fn record_lifecycle_non_stake_non_protocol_ignored() {
        let mut store = StakeStore::new();
        let tx = json!({ "prefix": {} });

        record_stake_lifecycle(
            &mut store,
            &tx,
            "transfer_tx",
            100,
            0, // TRANSFER
            0,
            0,
            "SAL",
            true,
            &[("pk_t".into(), None, 1000)],
        );

        assert_eq!(store.len(), 0);
    }

    // -- Full lifecycle: STAKE -> PROTOCOL return -> reorg rollback ----------

    #[test]
    fn full_lifecycle_stake_return_reorg() {
        let mut store = StakeStore::new();

        // Step 1: User creates a STAKE.
        let stake_tx = json!({
            "prefix": {
                "protocol_tx_data": {
                    "return_pubkey": "aabbccddeeff"
                }
            }
        });

        record_stake_lifecycle(
            &mut store,
            &stake_tx,
            "lifecycle_stake",
            1000,
            TX_TYPE_STAKE,
            100_000_000_000_000,
            50_000_000,
            "SAL",
            true,
            &[("lifecycle_change_key".into(), None, 0)],
        );

        let stake = store.get_stake("lifecycle_stake").unwrap();
        assert_eq!(stake.status, StakeStatus::Locked);
        assert_eq!(stake.amount_staked, 100_000_000_000_000);
        assert_eq!(stake.output_key, "aabbccddeeff");

        // Step 2: PROTOCOL tx returns the stake (pre-CARROT path: pub key match).
        let prot_tx = json!({ "prefix": {} });

        record_stake_lifecycle(
            &mut store,
            &prot_tx,
            "lifecycle_return",
            1100,
            TX_TYPE_PROTOCOL,
            0,
            0,
            "SAL",
            false,
            &[("aabbccddeeff".into(), None, 101_000_000_000_000)],
        );

        let stake = store.get_stake("lifecycle_stake").unwrap();
        assert_eq!(stake.status, StakeStatus::Returned);
        assert_eq!(stake.return_tx_hash.as_deref(), Some("lifecycle_return"));
        assert_eq!(stake.return_height, Some(1100));
        assert_eq!(stake.return_amount, Some(101_000_000_000_000));

        // Step 3: Reorg to height 1050 undoes the return.
        store.delete_stakes_above(1050);

        let stake = store.get_stake("lifecycle_stake").unwrap();
        assert_eq!(stake.status, StakeStatus::Locked);
        assert!(stake.return_tx_hash.is_none());
        assert!(stake.return_height.is_none());
        assert!(stake.return_amount.is_none());

        // Stake itself (at height 1000) survives.
        assert_eq!(stake.block_height, 1000);
        assert_eq!(stake.amount_staked, 100_000_000_000_000);
    }

    // -- Multiple stakes with different assets ------------------------------

    #[test]
    fn multiple_stakes_different_assets() {
        let mut store = StakeStore::new();
        store.put_stake(StakeRecord { tx_hash: "sal_stake".into(), asset_type: "SAL".into(), amount_staked: 1000, ..Default::default() });
        store.put_stake(StakeRecord { tx_hash: "usd_stake".into(), asset_type: "USD".into(), amount_staked: 2000, ..Default::default() });
        store.put_stake(StakeRecord { tx_hash: "sal_stake_2".into(), asset_type: "SAL".into(), amount_staked: 3000, ..Default::default() });

        let sal = store.get_stakes(None, Some("SAL"));
        assert_eq!(sal.len(), 2);

        let usd = store.get_stakes(None, Some("USD"));
        assert_eq!(usd.len(), 1);
        assert_eq!(usd[0].tx_hash, "usd_stake");

        assert_eq!(store.get_stakes(None, None).len(), 3);
    }

    // -- Empty store operations ---------------------------------------------

    #[test]
    fn empty_store_operations() {
        let mut store = StakeStore::new();

        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert!(store.get_stake("anything").is_none());
        assert!(store.get_stake_by_output_key("anything").is_none());
        assert!(store.get_stakes(None, None).is_empty());
        assert!(store.get_stakes(Some(StakeStatus::Locked), None).is_empty());
        assert!(!store.mark_stake_returned("none", "ret", 0, 0));

        // Should not panic.
        store.delete_stakes_above(0);
        assert_eq!(store.len(), 0);
    }

    // -- Reorg above stake height removes the stake entirely ----------------

    #[test]
    fn reorg_above_stake_height_removes_stake() {
        let mut store = StakeStore::new();
        let tx = json!({ "prefix": { "return_pubkey": "reorg_key" } });

        record_stake_lifecycle(
            &mut store,
            &tx,
            "reorg_stake",
            500,
            TX_TYPE_STAKE,
            1000,
            10,
            "SAL",
            true,
            &[("pk_r".into(), None, 0)],
        );

        assert!(store.get_stake("reorg_stake").is_some());

        // Reorg to height 400 — stake at 500 should be removed.
        store.delete_stakes_above(400);

        assert!(store.get_stake("reorg_stake").is_none());
        assert!(store.get_stake_by_output_key("reorg_key").is_none());
    }
}
