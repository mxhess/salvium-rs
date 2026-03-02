//! Mempool transaction scanning.
//!
//! Replicates the C++ `update_pool_state_by_pool_query()` behaviour: fetch
//! pool TX hashes, compare against known pool TXs in the DB, scan new ones
//! for wallet-relevant outputs/spends, and clean up dropped ones.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::error::WalletError;
use crate::scanner::{self, ScanContext};
use crate::sync::{
    build_transaction_row, detect_spent_outputs, extract_fee, parse_tx_for_scanning,
};
use salvium_crypto::storage::WalletDb;
use salvium_rpc::NodePool;

/// Result of a mempool scan pass.
pub struct PoolScanResult {
    pub new_pool_txs: usize,
    pub dropped_pool_txs: usize,
}

/// Scan the mempool for pending transactions relevant to this wallet.
///
/// Algorithm (matches C++ `update_pool_state_by_pool_query()`):
/// 1. Fetch pool hashes from the daemon.
/// 2. Load known pool TXs from the wallet DB.
/// 3. Fetch & scan new TXs (pool_hashes − known_hashes).
/// 4. Clean up dropped TXs (known_hashes − pool_hashes).
pub(crate) async fn scan_mempool(
    pool: &NodePool,
    db: Arc<Mutex<WalletDb>>,
    scan_ctx: &ScanContext,
) -> Result<PoolScanResult, WalletError> {
    // 1. Fetch current pool hashes from daemon.
    let pool_hashes: HashSet<String> =
        pool.get_transaction_pool_hashes().await.map_err(WalletError::Rpc)?.into_iter().collect();

    // 2. Load known pool TXs from DB.
    let known_pool_txs = {
        let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_txs(&salvium_crypto::storage::TxQuery {
            is_incoming: None,
            is_outgoing: None,
            is_confirmed: None,
            in_pool: Some(true),
            tx_type: None,
            min_height: None,
            max_height: None,
            tx_hash: None,
        })
        .map_err(|e| WalletError::Storage(e.to_string()))?
    };
    let known_hashes: HashSet<String> =
        known_pool_txs.iter().map(|tx| tx.tx_hash.clone()).collect();

    // 3. Find new TXs to fetch and dropped TXs to clean up.
    let new_hashes: Vec<&str> = pool_hashes
        .iter()
        .filter(|h| !known_hashes.contains(h.as_str()))
        .map(|h| h.as_str())
        .collect();
    let dropped_hashes: Vec<&str> = known_hashes
        .iter()
        .filter(|h| !pool_hashes.contains(h.as_str()))
        .map(|h| h.as_str())
        .collect();

    let mut new_pool_txs = 0usize;
    let dropped_pool_txs = dropped_hashes.len();

    // 4. Fetch and scan new pool TXs.
    if !new_hashes.is_empty() {
        let entries = pool.get_transactions(&new_hashes, true).await.map_err(WalletError::Rpc)?;

        for entry in &entries {
            // Parse the TX JSON — prefer as_json, fall back to decoding as_hex.
            let tx_json: serde_json::Value = if let Some(ref json_str) = entry.as_json {
                match serde_json::from_str(json_str) {
                    Ok(v) => v,
                    Err(e) => {
                        log::debug!("pool TX {}: as_json parse failed: {}", &entry.tx_hash, e);
                        continue;
                    }
                }
            } else if !entry.as_hex.is_empty() {
                let raw = match hex::decode(&entry.as_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        log::debug!("pool TX {}: hex decode failed: {}", &entry.tx_hash, e);
                        continue;
                    }
                };
                let json_str = salvium_crypto::parse_transaction_bytes(&raw);
                match serde_json::from_str(&json_str) {
                    Ok(v) => v,
                    Err(e) => {
                        log::debug!(
                            "pool TX {}: parse_transaction_bytes failed: {}",
                            &entry.tx_hash,
                            e
                        );
                        continue;
                    }
                }
            } else {
                log::debug!("pool TX {}: no as_json or as_hex", &entry.tx_hash);
                continue;
            };

            // Parse into ScanTxData (block_height=0, not coinbase).
            let scan_data = match parse_tx_for_scanning(&tx_json, &entry.tx_hash, 0, false) {
                Some(sd) => sd,
                None => {
                    log::debug!("pool TX {}: parse_tx_for_scanning returned None", &entry.tx_hash);
                    continue;
                }
            };

            // Scan for wallet outputs.
            let found = scanner::scan_transaction(scan_ctx, &scan_data);

            // Detect spent wallet inputs.
            let spent_info = {
                let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                let ki_cache =
                    db.get_all_key_images().map_err(|e| WalletError::Storage(e.to_string()))?;
                let gi_cache =
                    db.get_all_global_indices().map_err(|e| WalletError::Storage(e.to_string()))?;
                detect_spent_outputs(&db, &tx_json, &entry.tx_hash, 0, &ki_cache, &gi_cache)?
            };

            // Only store if wallet-relevant.
            if found.is_empty() && spent_info.count == 0 {
                continue;
            }

            let fee = extract_fee(&tx_json);
            let tx_pub_key_hex = hex::encode(scan_data.tx_pub_key);

            // Build the transaction row with pool flags.
            let mut row = build_transaction_row(
                &entry.tx_hash,
                &tx_pub_key_hex,
                0, // block_height
                0, // block_timestamp
                &found,
                &spent_info,
                fee,
                scan_data.tx_type,
                false, // is_coinbase
                scan_data.unlock_time,
            );
            row.in_pool = true;
            row.is_confirmed = false;

            // Persist to DB.
            {
                let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                db.put_tx(&row).map_err(|e| WalletError::Storage(e.to_string()))?;
            }

            // store_found_outputs needs &mut ScanContext, but we only have &ScanContext.
            // For pool TXs we skip the full store_found_outputs path (which handles
            // salvium_txs population and subaddress map updates) since those are only
            // meaningful for confirmed block outputs. The outputs will be properly
            // stored when the TX confirms during block sync.
            //
            // However, we do need to store outputs so they appear in the balance.
            if !found.is_empty() {
                let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                for output in &found {
                    let pub_key_hex = hex::encode(output.output_public_key);
                    let output_unlock_time = scan_data
                        .outputs
                        .get(output.output_index as usize)
                        .map(|o| o.unlock_time)
                        .unwrap_or(scan_data.unlock_time);

                    let mut out_row = salvium_crypto::storage::OutputRow {
                        key_image: output.key_image.map(hex::encode),
                        public_key: Some(pub_key_hex),
                        tx_hash: hex::encode(scan_data.tx_hash),
                        output_index: output.output_index as i64,
                        global_index: None,
                        asset_type_index: None,
                        block_height: None, // not confirmed yet
                        block_timestamp: None,
                        amount: output.amount.to_string(),
                        asset_type: output.asset_type.clone(),
                        commitment: scan_data
                            .outputs
                            .get(output.output_index as usize)
                            .and_then(|o| o.commitment)
                            .map(hex::encode),
                        mask: Some(hex::encode(output.mask)),
                        subaddress_index: salvium_crypto::storage::SubaddressIndex {
                            major: output.subaddress_major as i64,
                            minor: output.subaddress_minor as i64,
                        },
                        is_carrot: output.is_carrot,
                        carrot_ephemeral_pubkey: None,
                        carrot_shared_secret: output.carrot_shared_secret.map(hex::encode),
                        carrot_enote_type: output.carrot_enote_type.map(|t| t as i64),
                        is_spent: false,
                        spent_height: None,
                        spent_tx_hash: None,
                        unlock_time: output_unlock_time.to_string(),
                        tx_type: scan_data.tx_type as i64,
                        tx_pub_key: Some(hex::encode(scan_data.tx_pub_key)),
                        is_frozen: false,
                        created_at: None,
                        updated_at: None,
                    };

                    // View-only CN outputs: synthetic key image.
                    if out_row.key_image.is_none() {
                        let mut buf = Vec::with_capacity(36);
                        buf.extend_from_slice(&scan_data.tx_hash);
                        buf.extend_from_slice(&output.output_index.to_le_bytes());
                        let synthetic = salvium_crypto::keccak256(&buf);
                        out_row.key_image = Some(format!("vo:{}", hex::encode(synthetic)));
                    }
                    db.put_output(&out_row).map_err(|e| WalletError::Storage(e.to_string()))?;
                }
            }

            new_pool_txs += 1;
            log::info!(
                "pool TX {}: {} outputs, {} spends",
                &entry.tx_hash[..entry.tx_hash.len().min(16)],
                found.len(),
                spent_info.count,
            );
        }
    }

    // 5. Handle dropped TXs.
    if !dropped_hashes.is_empty() {
        let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        for tx_hash in &dropped_hashes {
            // Check if this TX was confirmed in a block (block_height > 0).
            let txs = db
                .get_txs(&salvium_crypto::storage::TxQuery {
                    is_incoming: None,
                    is_outgoing: None,
                    is_confirmed: None,
                    in_pool: None,
                    tx_type: None,
                    min_height: None,
                    max_height: None,
                    tx_hash: Some(tx_hash.to_string()),
                })
                .map_err(|e| WalletError::Storage(e.to_string()))?;

            if let Some(tx_row) = txs.first() {
                if tx_row.block_height.unwrap_or(0) > 0 {
                    // Already confirmed — just clear the pool flag.
                    // put_tx with INSERT OR REPLACE will handle this during block sync,
                    // but if we see it dropped before the next sync, clear it now.
                    log::debug!("pool TX {} confirmed, clearing in_pool flag", tx_hash);
                } else {
                    // Never confirmed — mark as failed and restore spent outputs.
                    let spent_kis = db
                        .get_pool_tx_spent_key_images(tx_hash)
                        .map_err(|e| WalletError::Storage(e.to_string()))?;
                    for ki in &spent_kis {
                        db.mark_unspent(ki).map_err(|e| WalletError::Storage(e.to_string()))?;
                    }
                    db.mark_tx_failed(tx_hash).map_err(|e| WalletError::Storage(e.to_string()))?;
                    log::info!(
                        "pool TX {} dropped (never confirmed), marked failed, restored {} outputs",
                        &tx_hash[..tx_hash.len().min(16)],
                        spent_kis.len(),
                    );
                }
            }
        }
    }

    Ok(PoolScanResult { new_pool_txs, dropped_pool_txs })
}
