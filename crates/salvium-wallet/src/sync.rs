//! Blockchain synchronization engine.
//!
//! Fetches blocks from the daemon, scans transactions for owned outputs,
//! stores results in the wallet database, and handles chain reorganizations.

use crate::error::WalletError;
use crate::scanner::{self, FoundOutput, ScanContext, ScanTxData, TxOutput};
use salvium_rpc::DaemonRpc;
use serde::Deserialize;

/// Sync progress events.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Sync started.
    Started { target_height: u64 },
    /// Block range processed.
    Progress {
        current_height: u64,
        target_height: u64,
        outputs_found: usize,
    },
    /// Sync completed.
    Complete { height: u64 },
    /// Chain reorganization detected.
    Reorg { from_height: u64, to_height: u64 },
    /// Error during sync.
    Error(String),
}

/// Blockchain sync engine.
pub struct SyncEngine;

impl SyncEngine {
    /// Sync the wallet from the current sync height to the daemon's tip.
    ///
    /// Fetches blocks one at a time, scans all transactions in each block,
    /// stores found outputs, and handles reorganizations.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn sync(
        daemon: &DaemonRpc,
        db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
        scan_ctx: &ScanContext,
        event_tx: Option<&tokio::sync::mpsc::Sender<SyncEvent>>,
    ) -> Result<u64, WalletError> {
        let daemon_height = daemon
            .get_height()
            .await
            .map_err(|e| WalletError::Sync(e.to_string()))?;

        // daemon_height is the block count, so the last valid block index
        // is daemon_height - 1.
        let top_block = daemon_height.saturating_sub(1);

        let sync_height = {
            let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
            db.get_sync_height()
                .map_err(|e| WalletError::Storage(e.to_string()))?
        };

        if sync_height as u64 >= top_block {
            return Ok(sync_height as u64);
        }

        if let Some(tx) = event_tx {
            let _ = tx
                .send(SyncEvent::Started {
                    target_height: top_block,
                })
                .await;
        }

        let mut current = sync_height as u64;
        let mut total_outputs_found = 0usize;

        while current < top_block {
            let next_height = current + 1;

            // Check for chain reorg.
            if current > 0 {
                let expected_hash = {
                    let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                    db.get_block_hash(current as i64)
                        .map_err(|e| WalletError::Storage(e.to_string()))?
                };

                if let Some(expected) = expected_hash {
                    let header = daemon
                        .get_block_header_by_height(next_height)
                        .await
                        .map_err(|e| WalletError::Sync(e.to_string()))?;

                    if header.prev_hash != expected {
                        // Reorganization detected — rollback.
                        let reorg_start = find_fork_point(daemon, db, current).await?;

                        if let Some(tx) = event_tx {
                            let _ = tx
                                .send(SyncEvent::Reorg {
                                    from_height: current,
                                    to_height: reorg_start,
                                })
                                .await;
                        }

                        {
                            let db =
                                db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                            db.rollback(reorg_start as i64)
                                .map_err(|e| WalletError::Storage(e.to_string()))?;
                        }

                        current = reorg_start;
                        continue;
                    }
                }
            }

            // Fetch and scan the block.
            let outputs_found =
                sync_block(daemon, db, scan_ctx, next_height).await?;
            total_outputs_found += outputs_found;

            // Update sync height.
            {
                let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                db.set_sync_height(next_height as i64)
                    .map_err(|e| WalletError::Storage(e.to_string()))?;
            }

            current = next_height;

            if let Some(tx) = event_tx {
                let _ = tx
                    .send(SyncEvent::Progress {
                        current_height: current,
                        target_height: top_block,
                        outputs_found: total_outputs_found,
                    })
                    .await;
            }
        }

        if let Some(tx) = event_tx {
            let _ = tx
                .send(SyncEvent::Complete {
                    height: top_block,
                })
                .await;
        }

        Ok(top_block)
    }
}

/// Parsed block JSON from salvium-crypto's parse_block_bytes.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParsedBlock {
    #[serde(default)]
    miner_tx: Option<serde_json::Value>,
    #[serde(default)]
    tx_hashes: Vec<String>,
}

/// Fetch and scan a single block.
#[cfg(not(target_arch = "wasm32"))]
async fn sync_block(
    daemon: &DaemonRpc,
    db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
    scan_ctx: &ScanContext,
    height: u64,
) -> Result<usize, WalletError> {
    // Get block data.
    let block = daemon
        .get_block(height)
        .await
        .map_err(|e| WalletError::Sync(format!("get_block({}): {}", height, e)))?;

    let block_hash = block.block_header.hash.clone();
    let block_timestamp = block.block_header.timestamp;
    let mut outputs_found = 0;

    // Parse the block blob to get miner tx.
    let block_blob = hex::decode(&block.blob)
        .map_err(|e| WalletError::Sync(format!("hex decode block: {}", e)))?;
    let block_json_str = salvium_crypto::parse_block_bytes(&block_blob);

    if let Ok(parsed_block) = serde_json::from_str::<ParsedBlock>(&block_json_str) {
        // Scan miner transaction.
        if let Some(miner_tx_json) = &parsed_block.miner_tx {
            if let Some(scan_data) =
                parse_tx_for_scanning(miner_tx_json, &block.miner_tx_hash, height, true)
            {
                let found = scanner::scan_transaction(scan_ctx, &scan_data);
                outputs_found += found.len();
                store_found_outputs(db, &found, &scan_data, block_timestamp)?;
            }
        }
    }

    // Fetch and scan regular transactions.
    if !block.tx_hashes.is_empty() {
        let hash_refs: Vec<&str> = block.tx_hashes.iter().map(|s| s.as_str()).collect();
        let tx_entries = daemon
            .get_transactions(&hash_refs, false)
            .await
            .map_err(|e| WalletError::Sync(format!("get_transactions: {}", e)))?;

        for (entry, tx_hash_hex) in tx_entries.iter().zip(block.tx_hashes.iter()) {
            let tx_hex = &entry.as_hex;

            if tx_hex.is_empty() {
                continue;
            }

            if let Ok(tx_bytes) = hex::decode(tx_hex) {
                let tx_json_str = salvium_crypto::parse_transaction_bytes(&tx_bytes);
                if let Ok(tx_json) = serde_json::from_str::<serde_json::Value>(&tx_json_str) {
                    // Detect spent outputs: check if any inputs spend our UTXOs.
                    detect_spent_outputs(db, &tx_json, tx_hash_hex, height)?;

                    if let Some(scan_data) =
                        parse_tx_for_scanning(&tx_json, tx_hash_hex, height, false)
                    {
                        let found = scanner::scan_transaction(scan_ctx, &scan_data);
                        outputs_found += found.len();
                        store_found_outputs(db, &found, &scan_data, block_timestamp)?;
                    }
                }
            }
        }
    }

    // Store block hash for reorg detection.
    {
        let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        db.put_block_hash(height as i64, &block_hash)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
    }

    Ok(outputs_found)
}

/// Parse a transaction JSON (from parse_block_bytes / parse_transaction_bytes)
/// into ScanTxData.
///
/// The JSON format from salvium-crypto uses camelCase and a nested `prefix`
/// structure:
/// ```json
/// {
///   "prefix": {
///     "txType": 1,
///     "extra": [{ "type": 1, "tag": "tx_pubkey", "key": "hex..." }],
///     "vout": [{ "key": "hex...", "viewTag": "hex...", "type": 4, "amount": "123" }],
///     "vin": [{ "type": 255, "height": 1230 }]
///   },
///   "rct": { "type": 0 }
/// }
/// ```
fn parse_tx_for_scanning(
    tx_json: &serde_json::Value,
    tx_hash_hex: &str,
    block_height: u64,
    is_coinbase: bool,
) -> Option<ScanTxData> {
    let tx_hash = hex_to_32(tx_hash_hex)?;

    // The prefix may be nested under "prefix" or at top level.
    let prefix = tx_json.get("prefix").unwrap_or(tx_json);

    // Extract tx public key from extra.
    let tx_pub_key = extract_tx_pub_key_from_parsed(prefix)
        .or_else(|| extract_tx_pub_key_from_raw(tx_json))?;

    // Extract first key image (for non-coinbase).
    let first_key_image = if !is_coinbase {
        extract_first_key_image(prefix)
    } else {
        None
    };

    // Determine tx_type.
    let tx_type = prefix
        .get("txType")
        .or_else(|| prefix.get("tx_type"))
        .and_then(|v| v.as_u64())
        .unwrap_or(if is_coinbase { 1 } else { 3 }) as u8;

    // Extract RCT type.
    let rct_type = tx_json
        .get("rct")
        .or_else(|| tx_json.get("rct_signatures"))
        .and_then(|r| r.get("type"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;

    // Parse outputs — try new format (prefix.vout[]) first, then legacy (vout[]).
    let vout = prefix
        .get("vout")
        .or_else(|| tx_json.get("vout"))
        .and_then(|v| v.as_array())?;

    // Legacy ECDH info and output commitments.
    let rct_section = tx_json
        .get("rct")
        .or_else(|| tx_json.get("rct_signatures"));
    let ecdh_info = rct_section
        .and_then(|r| r.get("ecdhInfo"))
        .and_then(|e| e.as_array());
    let out_pk = rct_section
        .and_then(|r| r.get("outPk"))
        .and_then(|e| e.as_array());

    let mut outputs = Vec::with_capacity(vout.len());
    for (i, out) in vout.iter().enumerate() {
        // Amount: try string first (new format), then integer (legacy).
        let amount = out
            .get("amount")
            .and_then(|a| {
                a.as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| a.as_u64())
            })
            .unwrap_or(0);

        // Output public key: try flat "key" (new format), then nested
        // "target.tagged_key.key" or "target.key" (legacy).
        let (public_key, target_view_tag) = if let Some(k) = out.get("key").and_then(|v| v.as_str())
        {
            // New format: flat key with optional 1-byte CryptoNote view tag.
            let pk = hex_to_32(k)?;
            let vt = out
                .get("targetViewTag")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| if b.is_empty() { None } else { Some(b[0]) });
            (pk, vt)
        } else if let Some(target) = out.get("target") {
            // Legacy format.
            if let Some(tk) = target.get("tagged_key") {
                let pk = hex_to_32(tk.get("key")?.as_str()?)?;
                let vt = tk
                    .get("view_tag")
                    .and_then(|v| v.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .and_then(|b| if b.is_empty() { None } else { Some(b[0]) });
                (pk, vt)
            } else if let Some(k) = target.get("key") {
                let pk = hex_to_32(k.as_str()?)?;
                (pk, None)
            } else {
                continue;
            }
        } else {
            continue;
        };

        // Output type field (type 4 = CARROT).
        let out_type = out
            .get("type")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        // CARROT 3-byte view tag (from "viewTag" field, 3 hex bytes = 6 chars).
        let carrot_view_tag = if out_type == 4 {
            out.get("viewTag")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| {
                    if b.len() == 3 {
                        let mut arr = [0u8; 3];
                        arr.copy_from_slice(&b);
                        Some(arr)
                    } else {
                        None
                    }
                })
        } else {
            None
        };

        // CARROT ephemeral pubkey (D_e).
        // For CARROT outputs, D_e IS the tx_pubkey stored in tx_extra — it's
        // already in X25519 Montgomery u-coordinate form.
        let carrot_ephemeral_pubkey = if out_type == 4 {
            Some(tx_pub_key)
        } else {
            out.get("ephemeralPubkey")
                .and_then(|v| v.as_str())
                .and_then(hex_to_32)
        };

        // ECDH encrypted amount (from ecdhInfo if present).
        let enc_amount = ecdh_info
            .and_then(|info| info.get(i))
            .and_then(|e| e.get("amount"))
            .and_then(|a| a.as_str())
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| {
                if b.len() >= 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&b[..8]);
                    Some(arr)
                } else {
                    None
                }
            })
            .unwrap_or([0u8; 8]);

        // Pedersen commitment.
        let commitment = out_pk
            .and_then(|pks| pks.get(i))
            .and_then(|v| v.as_str())
            .and_then(hex_to_32);

        // Asset type from on-chain output (e.g. "SAL", "SAL1").
        // New format: flat field at vout level ("assetType" or "asset_type").
        // Legacy format: nested inside target sub-object
        //   (target.tagged_key.asset_type, target.to_tagged_key.asset_type,
        //    target.to_key.asset_type, target.to_carrot_v1.asset_type).
        let asset_type = out
            .get("assetType")
            .or_else(|| out.get("asset_type"))
            .or_else(|| {
                out.get("target").and_then(|t| {
                    t.get("tagged_key")
                        .or_else(|| t.get("to_tagged_key"))
                        .or_else(|| t.get("key"))
                        .or_else(|| t.get("to_key"))
                        .or_else(|| t.get("to_carrot_v1"))
                        .and_then(|inner| inner.get("asset_type"))
                })
            })
            .and_then(|v| v.as_str())
            .unwrap_or("SAL")
            .to_string();

        outputs.push(TxOutput {
            index: i as u32,
            public_key,
            target_view_tag,
            amount,
            rct_type,
            ecdh_encrypted_amount: enc_amount,
            commitment,
            carrot_view_tag,
            carrot_ephemeral_pubkey,
            asset_type,
        });
    }

    Some(ScanTxData {
        tx_hash,
        tx_pub_key,
        outputs,
        is_coinbase,
        block_height,
        first_key_image,
        tx_type,
    })
}

/// Extract tx pubkey from structured extra (parse_block_bytes format).
///
/// Extra is an array of objects like:
/// `[{ "type": 1, "tag": "tx_pubkey", "key": "hex..." }, ...]`
fn extract_tx_pub_key_from_parsed(prefix: &serde_json::Value) -> Option<[u8; 32]> {
    let extra = prefix.get("extra")?.as_array()?;
    for entry in extra {
        // Match on type == 1 or tag == "tx_pubkey".
        let is_pubkey = entry
            .get("type")
            .and_then(|v| v.as_u64())
            .map(|t| t == 1)
            .unwrap_or(false)
            || entry
                .get("tag")
                .and_then(|v| v.as_str())
                .map(|t| t == "tx_pubkey")
                .unwrap_or(false);

        if is_pubkey {
            if let Some(key_hex) = entry.get("key").and_then(|v| v.as_str()) {
                return hex_to_32(key_hex);
            }
        }
    }
    None
}

/// Extract tx pubkey from raw extra bytes (legacy daemon RPC format).
///
/// Extra is an array of integers; tag 0x01 followed by 32-byte key.
fn extract_tx_pub_key_from_raw(tx_json: &serde_json::Value) -> Option<[u8; 32]> {
    // Try extra_parsed field.
    if let Some(extra) = tx_json.get("extra_parsed") {
        if let Some(pk) = extra.get("tx_pub_key").and_then(|v| v.as_str()) {
            return hex_to_32(pk);
        }
    }

    // Try raw byte array.
    if let Some(extra) = tx_json.get("extra").and_then(|v| v.as_array()) {
        let bytes: Vec<u8> = extra
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u8))
            .collect();
        for i in 0..bytes.len() {
            if bytes[i] == 0x01 && i + 33 <= bytes.len() {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes[i + 1..i + 33]);
                return Some(key);
            }
        }
    }

    None
}

/// Extract the first key image from transaction inputs.
fn extract_first_key_image(prefix: &serde_json::Value) -> Option<[u8; 32]> {
    let vin = prefix.get("vin")?.as_array()?;
    let first = vin.first()?;

    // New format: { "keyImage": "hex", ... } or { "key": { "keyImage": "hex" } }
    if let Some(ki) = first
        .get("keyImage")
        .and_then(|v| v.as_str())
        .and_then(hex_to_32)
    {
        return Some(ki);
    }

    // Legacy format: { "key": { "k_image": "hex" } }
    if let Some(key) = first.get("key") {
        if let Some(ki) = key
            .get("k_image")
            .or_else(|| key.get("keyImage"))
            .and_then(|v| v.as_str())
            .and_then(hex_to_32)
        {
            return Some(ki);
        }
    }

    None
}

/// Extract ALL key images from transaction inputs.
fn extract_all_key_images(prefix: &serde_json::Value) -> Vec<String> {
    let mut key_images = Vec::new();
    let vin = match prefix.get("vin").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return key_images,
    };

    for input in vin {
        // New format: { "keyImage": "hex", ... }
        if let Some(ki) = input.get("keyImage").and_then(|v| v.as_str()) {
            if ki.len() == 64 {
                key_images.push(ki.to_string());
            }
        }
        // Legacy format: { "key": { "k_image": "hex" } }
        else if let Some(key) = input.get("key") {
            if let Some(ki) = key
                .get("k_image")
                .or_else(|| key.get("keyImage"))
                .and_then(|v| v.as_str())
            {
                if ki.len() == 64 {
                    key_images.push(ki.to_string());
                }
            }
        }
    }

    key_images
}

/// Check transaction inputs for key images that belong to our wallet and mark
/// the corresponding outputs as spent.
#[cfg(not(target_arch = "wasm32"))]
fn detect_spent_outputs(
    db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
    tx_json: &serde_json::Value,
    tx_hash_hex: &str,
    block_height: u64,
) -> Result<usize, WalletError> {
    let prefix = tx_json.get("prefix").unwrap_or(tx_json);
    let key_images = extract_all_key_images(prefix);

    if key_images.is_empty() {
        return Ok(0);
    }

    let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
    let mut spent_count = 0;

    for ki_hex in &key_images {
        // Check if this key image belongs to one of our outputs.
        let output = db
            .get_output(ki_hex)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        if let Some(row) = output {
            if !row.is_spent {
                db.mark_spent(ki_hex, tx_hash_hex, block_height as i64)
                    .map_err(|e| WalletError::Storage(e.to_string()))?;
                spent_count += 1;
            }
        }
    }

    Ok(spent_count)
}

/// Store found outputs in the database.
#[cfg(not(target_arch = "wasm32"))]
fn store_found_outputs(
    db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
    found: &[FoundOutput],
    tx: &ScanTxData,
    block_timestamp: u64,
) -> Result<(), WalletError> {
    if found.is_empty() {
        return Ok(());
    }

    let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;

    for output in found {
        let row = salvium_crypto::storage::OutputRow {
            key_image: output.key_image.map(|ki| hex::encode(ki)),
            public_key: Some(hex::encode(output.output_public_key)),
            tx_hash: hex::encode(tx.tx_hash),
            output_index: output.output_index as i64,
            global_index: None,
            asset_type_index: None,
            block_height: Some(tx.block_height as i64),
            block_timestamp: Some(block_timestamp as i64),
            amount: output.amount.to_string(),
            asset_type: output.asset_type.clone(),
            commitment: None,
            mask: Some(hex::encode(output.mask)),
            subaddress_index: salvium_crypto::storage::SubaddressIndex {
                major: output.subaddress_major as i64,
                minor: output.subaddress_minor as i64,
            },
            is_carrot: output.is_carrot,
            carrot_ephemeral_pubkey: None,
            carrot_shared_secret: output.carrot_shared_secret.map(|s| hex::encode(s)),
            carrot_enote_type: output.carrot_enote_type.map(|t| t as i64),
            is_spent: false,
            spent_height: None,
            spent_tx_hash: None,
            unlock_time: "0".to_string(),
            tx_type: tx.tx_type as i64,
            tx_pub_key: Some(hex::encode(tx.tx_pub_key)),
            is_frozen: false,
            created_at: None,
            updated_at: None,
        };

        // Use key_image as primary key. Skip if no key image (view-only wallet).
        if row.key_image.is_some() {
            db.put_output(&row)
                .map_err(|e| WalletError::Storage(e.to_string()))?;
        }
    }

    Ok(())
}

/// Convert a hex string to a 32-byte array.
fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Walk back from `height` to find the fork point during a reorg.
#[cfg(not(target_arch = "wasm32"))]
async fn find_fork_point(
    daemon: &DaemonRpc,
    db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
    mut height: u64,
) -> Result<u64, WalletError> {
    while height > 0 {
        let stored_hash = {
            let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
            db.get_block_hash(height as i64)
                .map_err(|e| WalletError::Storage(e.to_string()))?
        };

        if let Some(stored) = stored_hash {
            let remote_hash = daemon
                .get_block_hash(height)
                .await
                .map_err(|e| WalletError::Sync(e.to_string()))?;

            if stored == remote_hash {
                return Ok(height);
            }
        }

        height -= 1;
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_32() {
        let hex = "aa".repeat(32);
        let result = hex_to_32(&hex).unwrap();
        assert_eq!(result, [0xAA; 32]);
    }

    #[test]
    fn test_hex_to_32_wrong_length() {
        assert!(hex_to_32("aabb").is_none());
        assert!(hex_to_32("not_hex").is_none());
    }

    #[test]
    fn test_extract_tx_pub_key_from_raw_extra() {
        let tx_json = serde_json::json!({
            "extra": [1, 170, 170, 170, 170, 170, 170, 170, 170,
                      170, 170, 170, 170, 170, 170, 170, 170,
                      170, 170, 170, 170, 170, 170, 170, 170,
                      170, 170, 170, 170, 170, 170, 170, 170]
        });
        let key = extract_tx_pub_key_from_raw(&tx_json).unwrap();
        assert_eq!(key, [0xAA; 32]);
    }

    #[test]
    fn test_extract_tx_pub_key_from_parsed_extra() {
        let prefix = serde_json::json!({
            "extra": [
                { "type": 1, "tag": "tx_pubkey", "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
            ]
        });
        let key = extract_tx_pub_key_from_parsed(&prefix).unwrap();
        assert_eq!(key, [0xAA; 32]);
    }

    #[test]
    fn test_sync_event_variants() {
        let _started = SyncEvent::Started {
            target_height: 1000,
        };
        let _progress = SyncEvent::Progress {
            current_height: 500,
            target_height: 1000,
            outputs_found: 3,
        };
        let _complete = SyncEvent::Complete { height: 1000 };
        let _reorg = SyncEvent::Reorg {
            from_height: 1000,
            to_height: 990,
        };
    }

    #[test]
    fn test_sync_event_all_variants() {
        // Create every SyncEvent variant and verify fields via Debug format.
        let started = SyncEvent::Started {
            target_height: 5000,
        };
        let debug_str = format!("{:?}", started);
        assert!(debug_str.contains("Started"));
        assert!(debug_str.contains("5000"));

        let progress = SyncEvent::Progress {
            current_height: 2500,
            target_height: 5000,
            outputs_found: 7,
        };
        let debug_str = format!("{:?}", progress);
        assert!(debug_str.contains("Progress"));
        assert!(debug_str.contains("2500"));
        assert!(debug_str.contains("5000"));
        assert!(debug_str.contains("7"));

        let complete = SyncEvent::Complete { height: 5000 };
        let debug_str = format!("{:?}", complete);
        assert!(debug_str.contains("Complete"));
        assert!(debug_str.contains("5000"));

        let reorg = SyncEvent::Reorg {
            from_height: 5000,
            to_height: 4990,
        };
        let debug_str = format!("{:?}", reorg);
        assert!(debug_str.contains("Reorg"));
        assert!(debug_str.contains("5000"));
        assert!(debug_str.contains("4990"));

        let error = SyncEvent::Error("connection timeout".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Error"));
        assert!(debug_str.contains("connection timeout"));

        // Verify Clone works on all variants.
        let _started_clone = started.clone();
        let _progress_clone = progress.clone();
        let _complete_clone = complete.clone();
        let _reorg_clone = reorg.clone();
        let _error_clone = error.clone();
    }

    #[test]
    fn test_parse_tx_for_scanning_miner() {
        // Miner TX with structured extra (parsed format from parse_block_bytes).
        let tx_pub_hex = "bb".repeat(32);
        let tx_hash_hex = "cc".repeat(32);
        let out_key_hex = "dd".repeat(32);

        let tx_json = serde_json::json!({
            "prefix": {
                "txType": 1,
                "extra": [
                    { "type": 1, "tag": "tx_pubkey", "key": tx_pub_hex }
                ],
                "vin": [{ "type": 255, "height": 1230 }],
                "vout": [
                    {
                        "amount": "1000000000",
                        "key": out_key_hex,
                        "type": 2
                    }
                ]
            },
            "rct": { "type": 0 }
        });

        let result = parse_tx_for_scanning(&tx_json, &tx_hash_hex, 1230, true).unwrap();

        assert_eq!(result.tx_hash, [0xCC; 32]);
        assert_eq!(result.tx_pub_key, [0xBB; 32]);
        assert!(result.is_coinbase);
        assert_eq!(result.block_height, 1230);
        assert_eq!(result.tx_type, 1);
        assert!(result.first_key_image.is_none()); // coinbase has no key image
        assert_eq!(result.outputs.len(), 1);

        let out = &result.outputs[0];
        assert_eq!(out.index, 0);
        assert_eq!(out.public_key, [0xDD; 32]);
        assert_eq!(out.amount, 1_000_000_000);
        assert_eq!(out.rct_type, 0);
        assert!(out.carrot_view_tag.is_none()); // type != 4
        assert!(out.target_view_tag.is_none());
    }

    #[test]
    fn test_parse_tx_for_scanning_user_tx() {
        // User TX with key image in vin.
        let tx_pub_hex = "aa".repeat(32);
        let tx_hash_hex = "bb".repeat(32);
        let out_key_hex = "cc".repeat(32);
        let ki_hex = "ee".repeat(32);

        let tx_json = serde_json::json!({
            "prefix": {
                "txType": 3,
                "extra": [
                    { "type": 1, "tag": "tx_pubkey", "key": tx_pub_hex }
                ],
                "vin": [
                    { "keyImage": ki_hex, "keyOffsets": [100, 200, 300] }
                ],
                "vout": [
                    {
                        "amount": "0",
                        "key": out_key_hex,
                        "type": 2
                    }
                ]
            },
            "rct": { "type": 6 }
        });

        let result = parse_tx_for_scanning(&tx_json, &tx_hash_hex, 5000, false).unwrap();

        assert!(!result.is_coinbase);
        assert_eq!(result.tx_type, 3);
        assert_eq!(result.block_height, 5000);
        assert_eq!(result.tx_pub_key, [0xAA; 32]);
        assert_eq!(result.first_key_image.unwrap(), [0xEE; 32]);
        assert_eq!(result.outputs.len(), 1);

        let out = &result.outputs[0];
        assert_eq!(out.amount, 0);
        assert_eq!(out.rct_type, 6);
    }

    #[test]
    fn test_parse_tx_for_scanning_carrot_output() {
        // TX with type=4 CARROT output and 3-byte view tag.
        let tx_pub_hex = "aa".repeat(32);
        let tx_hash_hex = "bb".repeat(32);
        let out_key_hex = "cc".repeat(32);
        let ki_hex = "dd".repeat(32);
        let view_tag_hex = "abcdef"; // 3 bytes

        let tx_json = serde_json::json!({
            "prefix": {
                "txType": 3,
                "extra": [
                    { "type": 1, "tag": "tx_pubkey", "key": tx_pub_hex }
                ],
                "vin": [
                    { "keyImage": ki_hex }
                ],
                "vout": [
                    {
                        "amount": "0",
                        "key": out_key_hex,
                        "type": 4,
                        "viewTag": view_tag_hex
                    }
                ]
            },
            "rct": { "type": 6 }
        });

        let result = parse_tx_for_scanning(&tx_json, &tx_hash_hex, 8000, false).unwrap();

        assert_eq!(result.outputs.len(), 1);
        let out = &result.outputs[0];

        // type == 4 means CARROT output
        assert_eq!(out.carrot_view_tag, Some([0xAB, 0xCD, 0xEF]));
        // CARROT ephemeral pubkey is the tx pubkey for type 4
        assert_eq!(out.carrot_ephemeral_pubkey, Some([0xAA; 32]));
        assert_eq!(out.public_key, [0xCC; 32]);
    }

    #[test]
    fn test_parse_tx_for_scanning_legacy_output() {
        // TX with target.tagged_key format (legacy daemon RPC).
        let tx_pub_hex = "aa".repeat(32);
        let tx_hash_hex = "bb".repeat(32);
        let out_key_hex = "cc".repeat(32);
        let view_tag_hex = "ff"; // 1 byte

        let tx_json = serde_json::json!({
            "extra": [1,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
            ],
            "vin": [],
            "vout": [
                {
                    "amount": 500000,
                    "target": {
                        "tagged_key": {
                            "key": out_key_hex,
                            "view_tag": view_tag_hex
                        }
                    }
                }
            ]
        });

        let result = parse_tx_for_scanning(&tx_json, &tx_hash_hex, 100, true).unwrap();

        assert_eq!(result.tx_pub_key, [0xAA; 32]);
        assert_eq!(result.outputs.len(), 1);

        let out = &result.outputs[0];
        assert_eq!(out.public_key, [0xCC; 32]);
        assert_eq!(out.target_view_tag, Some(0xFF));
        assert_eq!(out.amount, 500_000);
        // Not a CARROT output (no type field or type != 4)
        assert!(out.carrot_view_tag.is_none());
    }

    #[test]
    fn test_extract_first_key_image() {
        // JSON with keyImage field in vin (new format).
        let ki_hex = "ff".repeat(32);
        let prefix = serde_json::json!({
            "vin": [
                { "keyImage": ki_hex, "keyOffsets": [10, 20, 30] },
                { "keyImage": "aa".repeat(32) }
            ]
        });

        let ki = extract_first_key_image(&prefix).unwrap();
        assert_eq!(ki, [0xFF; 32]);
    }

    #[test]
    fn test_extract_first_key_image_legacy() {
        // JSON with key.k_image format (legacy daemon RPC).
        let ki_hex = "ee".repeat(32);
        let prefix = serde_json::json!({
            "vin": [
                {
                    "key": {
                        "k_image": ki_hex,
                        "key_offsets": [5, 10, 15]
                    }
                }
            ]
        });

        let ki = extract_first_key_image(&prefix).unwrap();
        assert_eq!(ki, [0xEE; 32]);
    }

    #[test]
    fn test_extract_first_key_image_empty_vin() {
        // Empty vin array returns None.
        let prefix = serde_json::json!({
            "vin": []
        });

        assert!(extract_first_key_image(&prefix).is_none());
    }

    #[test]
    fn test_extract_first_key_image_missing_vin() {
        let prefix = serde_json::json!({});
        assert!(extract_first_key_image(&prefix).is_none());
    }

    #[test]
    fn test_extract_first_key_image_coinbase_vin() {
        // Coinbase vin entries have no key image
        let prefix = serde_json::json!({
            "vin": [{ "type": 255, "height": 1000 }]
        });
        assert!(extract_first_key_image(&prefix).is_none());
    }

    // ── Progress Calculation Tests ──────────────────────────────────────

    #[test]
    fn test_progress_calculation_basic() {
        let current = 500u64;
        let target = 1000u64;
        let start = 0u64;
        let percent = if target > start {
            ((current - start) as f64 / (target - start) as f64 * 100.0) as u32
        } else {
            100
        };
        assert_eq!(percent, 50);
    }

    #[test]
    fn test_progress_calculation_complete() {
        let current = 1000u64;
        let target = 1000u64;
        let start = 0u64;
        let percent = if target > start {
            ((current - start) as f64 / (target - start) as f64 * 100.0).min(100.0) as u32
        } else {
            100
        };
        assert_eq!(percent, 100);
    }

    #[test]
    fn test_progress_calculation_zero_range() {
        // When already synced (start == target), progress is 100%.
        let target = 500u64;
        let start = 500u64;
        let percent = if target > start { 0 } else { 100 };
        assert_eq!(percent, 100);
    }

    #[test]
    fn test_progress_calculation_partial() {
        let current = 250u64;
        let target = 1000u64;
        let start = 0u64;
        let percent = ((current - start) as f64 / (target - start) as f64 * 100.0) as u32;
        assert_eq!(percent, 25);
    }

    // ── Batch Processing Tests ──────────────────────────────────────────

    #[test]
    fn test_batch_size_calculation() {
        let default_batch_size = 20u64;
        let target_height = 1000u64;
        let current_height = 500u64;
        let remaining = target_height - current_height;
        let batch = remaining.min(default_batch_size);
        assert_eq!(batch, 20);
    }

    #[test]
    fn test_batch_size_at_end() {
        let default_batch_size = 20u64;
        let target_height = 1000u64;
        let current_height = 995u64;
        let remaining = target_height - current_height;
        let batch = remaining.min(default_batch_size);
        assert_eq!(batch, 5);
    }

    // ── Parse TX Edge Cases ─────────────────────────────────────────────

    #[test]
    fn test_parse_tx_for_scanning_multiple_outputs() {
        let tx_pub_hex = "aa".repeat(32);
        let tx_hash_hex = "bb".repeat(32);
        let out_key1 = "cc".repeat(32);
        let out_key2 = "dd".repeat(32);
        let out_key3 = "ee".repeat(32);

        let tx_json = serde_json::json!({
            "prefix": {
                "txType": 3,
                "extra": [
                    { "type": 1, "tag": "tx_pubkey", "key": tx_pub_hex }
                ],
                "vin": [
                    { "keyImage": "ff".repeat(32) }
                ],
                "vout": [
                    { "amount": "0", "key": out_key1, "type": 2 },
                    { "amount": "0", "key": out_key2, "type": 2 },
                    { "amount": "0", "key": out_key3, "type": 2 }
                ]
            },
            "rct": { "type": 6 }
        });

        let result = parse_tx_for_scanning(&tx_json, &tx_hash_hex, 1000, false).unwrap();
        assert_eq!(result.outputs.len(), 3);
        assert_eq!(result.outputs[0].index, 0);
        assert_eq!(result.outputs[1].index, 1);
        assert_eq!(result.outputs[2].index, 2);
    }

    #[test]
    fn test_parse_tx_for_scanning_no_outputs() {
        let tx_pub_hex = "aa".repeat(32);
        let tx_hash_hex = "bb".repeat(32);

        let tx_json = serde_json::json!({
            "prefix": {
                "txType": 3,
                "extra": [
                    { "type": 1, "tag": "tx_pubkey", "key": tx_pub_hex }
                ],
                "vin": [
                    { "keyImage": "ff".repeat(32) }
                ],
                "vout": []
            },
            "rct": { "type": 6 }
        });

        let result = parse_tx_for_scanning(&tx_json, &tx_hash_hex, 1000, false).unwrap();
        assert_eq!(result.outputs.len(), 0);
    }

    #[test]
    fn test_sync_event_clone_eq() {
        let e1 = SyncEvent::Started { target_height: 100 };
        let e2 = e1.clone();
        // Verify clone produces equivalent Debug output
        assert_eq!(format!("{:?}", e1), format!("{:?}", e2));
    }

    #[test]
    fn test_sync_event_error_message_preserved() {
        let msg = "daemon connection failed: timeout after 30s".to_string();
        let event = SyncEvent::Error(msg.clone());
        if let SyncEvent::Error(ref s) = event {
            assert_eq!(s, &msg);
        } else {
            panic!("expected Error variant");
        }
    }

    #[test]
    fn test_hex_to_32_all_zeros() {
        let hex = "00".repeat(32);
        let result = hex_to_32(&hex).unwrap();
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_hex_to_32_all_ff() {
        let hex = "ff".repeat(32);
        let result = hex_to_32(&hex).unwrap();
        assert_eq!(result, [0xFF; 32]);
    }

    #[test]
    fn test_hex_to_32_odd_length() {
        assert!(hex_to_32("abc").is_none());
    }
}
