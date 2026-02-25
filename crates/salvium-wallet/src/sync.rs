//! Blockchain synchronization engine.
//!
//! Fetches blocks from the daemon, scans transactions for owned outputs,
//! stores results in the wallet database, and handles chain reorganizations.
//!
//! Uses adaptive batch sizing with the `/get_blocks_by_height.bin` binary
//! endpoint to fetch hundreds of blocks (with all their transactions) in a
//! single HTTP request. The batch size tunes itself based on throughput.

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
        parse_errors: usize,
        empty_blobs: usize,
    },
    /// Sync completed.
    Complete { height: u64 },
    /// Chain reorganization detected.
    Reorg { from_height: u64, to_height: u64 },
    /// Error during sync.
    Error(String),
    /// Block parse failure (block blob returned error JSON or empty blob).
    ParseError {
        height: u64,
        blob_len: usize,
        error: String,
    },
}

/// Blockchain sync engine.
pub struct SyncEngine;

/// Adaptive batch size controller.
///
/// Tunes the number of blocks fetched per round based on how long each batch
/// takes relative to a target duration. Scales up when batches are fast (early
/// blocks are small) and scales down when blocks are heavy or network is slow.
struct BatchController {
    batch_size: usize,
    min_batch: usize,
    max_batch: usize,
    target_batch_time_ms: u64,
    consecutive_errors: u32,
}

impl BatchController {
    fn new() -> Self {
        Self {
            batch_size: 64,
            min_batch: 2,
            max_batch: 1000,
            target_batch_time_ms: 1000,
            consecutive_errors: 0,
        }
    }

    /// Adjust batch size based on how long the last batch took.
    fn adjust(&mut self, elapsed_ms: u64, had_error: bool) {
        if had_error {
            self.batch_size = (self.batch_size / 2).max(self.min_batch);
            self.consecutive_errors += 1;
            if self.consecutive_errors >= 3 {
                self.batch_size = self.min_batch;
            }
            return;
        }

        self.consecutive_errors = 0;

        if elapsed_ms < self.target_batch_time_ms {
            // Batch was fast — scale up by 50%.
            self.batch_size = (self.batch_size + self.batch_size / 2).min(self.max_batch);
        } else {
            // Batch was slow — scale down by 25%.
            self.batch_size = (self.batch_size - self.batch_size / 4).max(self.min_batch);
        }
    }

    /// Return the batch size for the next round, capped by remaining blocks.
    fn next_batch_size(&self, remaining: u64) -> usize {
        (self.batch_size as u64).min(remaining) as usize
    }

    /// True if too many consecutive errors have occurred (likely a permanent
    /// failure like a protocol mismatch rather than a transient network issue).
    fn should_abort(&self) -> bool {
        self.consecutive_errors >= 10
    }
}

impl SyncEngine {
    /// Sync the wallet from the current sync height to the daemon's tip.
    ///
    /// Uses `/get_blocks_by_height.bin` to fetch hundreds of blocks (with all
    /// their transactions) in a single HTTP request. The adaptive batch
    /// controller tunes the batch size based on throughput — scaling up when
    /// batches are fast, scaling down when they're heavy or the network is slow.
    ///
    /// Both RPC calls per batch (`get_block_headers_range` and
    /// `get_blocks_by_height.bin`) are issued **concurrently** via
    /// `tokio::join!`, so per-batch latency is the slower of the two
    /// rather than their sum.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn sync(
        daemon: &DaemonRpc,
        db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
        scan_ctx: &mut ScanContext,
        stake_lock_period: u64,
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

        // Load salvium_txs change output Kos into CN subaddress map so
        // pre-CARROT PROTOCOL return outputs can be found during scanning.
        {
            let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
            if let Ok(keys) = db.get_all_salvium_tx_keys() {
                for (ko, major, minor) in keys {
                    if !scan_ctx.cn_subaddress_map.iter().any(|(k, _, _)| *k == ko) {
                        scan_ctx.cn_subaddress_map.push((ko, major, minor));
                    }
                }
            }
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
        let mut total_parse_errors = 0usize;
        let mut total_empty_blobs = 0usize;
        let mut controller = BatchController::new();

        while current < top_block {
            let remaining = top_block - current;
            let batch_size = controller.next_batch_size(remaining);
            let batch_start = current + 1;
            let batch_end = current + batch_size as u64;

            let batch_timer = std::time::Instant::now();
            let heights: Vec<u64> = (batch_start..=batch_end).collect();

            // ── 1. Concurrent fetch: headers + binary blocks ──────────
            // Both calls overlap on the wire. This halves the per-batch
            // network latency compared to issuing them sequentially.
            let (headers_result, bin_result) = tokio::join!(
                daemon.get_block_headers_range(batch_start, batch_end),
                daemon.get_blocks_by_height_bin(&heights),
            );

            let headers = match headers_result {
                Ok(h) => h,
                Err(e) => {
                    controller.adjust(batch_timer.elapsed().as_millis() as u64, true);
                    if let Some(tx) = event_tx {
                        let _ = tx.send(SyncEvent::Error(e.to_string())).await;
                    }
                    if controller.should_abort() {
                        return Err(WalletError::Sync(format!(
                            "aborting after {} consecutive errors: {}",
                            controller.consecutive_errors, e
                        )));
                    }
                    continue;
                }
            };

            // Reorg check: verify first header's prev_hash matches our stored hash.
            if current > 0 {
                let expected_hash = {
                    let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                    db.get_block_hash(current as i64)
                        .map_err(|e| WalletError::Storage(e.to_string()))?
                };

                if let Some(expected) = expected_hash {
                    if let Some(first) = headers.first() {
                        if first.prev_hash != expected {
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
                            controller.adjust(batch_timer.elapsed().as_millis() as u64, true);
                            continue;
                        }
                    }
                }
            }

            // ── 2. Handle binary block result ────────────────────────────
            let bin_blocks = match bin_result {
                Ok(blocks) => blocks,
                Err(e) => {
                    controller.adjust(batch_timer.elapsed().as_millis() as u64, true);
                    if let Some(tx) = event_tx {
                        let _ = tx
                            .send(SyncEvent::Error(format!("get_blocks_by_height.bin: {}", e)))
                            .await;
                    }
                    if controller.should_abort() {
                        return Err(WalletError::Sync(format!(
                            "aborting after {} consecutive errors: {}",
                            controller.consecutive_errors, e
                        )));
                    }
                    continue;
                }
            };

            if bin_blocks.len() != heights.len() {
                controller.adjust(batch_timer.elapsed().as_millis() as u64, true);
                if let Some(tx) = event_tx {
                    let _ = tx
                        .send(SyncEvent::Error(format!(
                            "get_blocks_by_height.bin: expected {} blocks, got {}",
                            heights.len(),
                            bin_blocks.len()
                        )))
                        .await;
                }
                if controller.should_abort() {
                    return Err(WalletError::Sync(format!(
                        "aborting: block count mismatch after {} errors",
                        controller.consecutive_errors
                    )));
                }
                continue;
            }

            // ── 3. Sequential processing ────────────────────────────────
            for (i, entry) in bin_blocks.iter().enumerate() {
                let height = heights[i];
                // Use header from the batch fetch (same index).
                let header = if i < headers.len() {
                    &headers[i]
                } else {
                    // Shouldn't happen, but skip gracefully.
                    continue;
                };

                // Detect empty block blobs from RPC.
                if entry.block.is_empty() {
                    total_empty_blobs += 1;
                    log::error!("empty block blob from RPC at height={}", height);
                    if let Some(tx) = event_tx {
                        let _ = tx
                            .send(SyncEvent::ParseError {
                                height,
                                blob_len: 0,
                                error: "empty block blob from RPC".into(),
                            })
                            .await;
                    }
                }

                let outputs_found = process_bin_block(
                    db,
                    scan_ctx,
                    height,
                    entry,
                    header,
                    stake_lock_period,
                    event_tx,
                )
                .await?;
                if outputs_found.parse_error {
                    total_parse_errors += 1;
                }
                total_outputs_found += outputs_found.outputs;

                // Update sync height per block for crash safety.
                {
                    let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                    db.set_sync_height(height as i64)
                        .map_err(|e| WalletError::Storage(e.to_string()))?;
                }
            }

            current = batch_end;

            // ── 4. Progress event (one per batch) ───────────────────────
            if let Some(tx) = event_tx {
                let _ = tx
                    .send(SyncEvent::Progress {
                        current_height: current,
                        target_height: top_block,
                        outputs_found: total_outputs_found,
                        parse_errors: total_parse_errors,
                        empty_blobs: total_empty_blobs,
                    })
                    .await;
            }

            // ── 5. Resolve global output indices ─────────────────────────
            // The output tracker cache (detect_spent_outputs Pass 2) needs
            // global_index to match ring members against our stored outputs.
            // BinBlockEntry doesn't include output_indices, so resolve them
            // post-hoc via get_transactions.
            if total_outputs_found > 0 {
                if let Err(e) = resolve_global_indices(daemon, db).await {
                    log::warn!("global index resolution failed: {}", e);
                }
            }

            // ── 6. Adapt batch size ─────────────────────────────────────
            controller.adjust(batch_timer.elapsed().as_millis() as u64, false);
        }

        if let Some(tx) = event_tx {
            let _ = tx.send(SyncEvent::Complete { height: top_block }).await;
        }

        Ok(top_block)
    }
}

/// Result of processing a single block.
struct BlockProcessResult {
    outputs: usize,
    parse_error: bool,
}

/// Parsed block JSON from salvium-crypto's `parse_block_bytes`.
///
/// Field names use camelCase to match the JSON output:
/// `{ header: {...}, minerTx: {...}, protocolTx: {...}, txHashes: [...] }`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParsedBlock {
    #[serde(default)]
    miner_tx: Option<serde_json::Value>,
    /// Salvium protocol transaction (yields, staking returns, conversions).
    /// Present in every block since the protocol_tx hardfork.
    #[serde(default)]
    protocol_tx: Option<serde_json::Value>,
    #[serde(default)]
    tx_hashes: Vec<serde_json::Value>,
}

/// Process a block from the binary `/get_blocks_by_height.bin` response.
///
/// The `BinBlockEntry` contains the raw block blob (with miner tx) and all
/// regular transaction blobs. The `BlockHeader` (from `get_block_headers_range`)
/// provides the block hash, timestamp, and miner tx hash that aren't in the blob.
#[cfg(not(target_arch = "wasm32"))]
async fn process_bin_block(
    db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
    scan_ctx: &mut ScanContext,
    height: u64,
    entry: &salvium_rpc::daemon::BinBlockEntry,
    header: &salvium_rpc::daemon::BlockHeader,
    stake_lock_period: u64,
    event_tx: Option<&tokio::sync::mpsc::Sender<SyncEvent>>,
) -> Result<BlockProcessResult, WalletError> {
    let mut outputs_found = 0;
    let mut parse_error = false;
    let block_hash = &header.hash;
    let block_timestamp = header.timestamp;
    let miner_tx_hash = header.miner_tx_hash.as_deref().unwrap_or("");

    // Parse the block blob to get miner tx and tx hashes.
    let block_json_str = salvium_crypto::parse_block_bytes(&entry.block);

    // Detect silent parse failures: parse_block_bytes returns {"error":"..."} on failure
    if block_json_str.starts_with(r#"{"error":"#) {
        parse_error = true;
        let snippet = &block_json_str[..block_json_str.len().min(200)];
        log::error!(
            "block parse failed at height={} blob_len={} err={}",
            height,
            entry.block.len(),
            snippet
        );
        if let Some(tx) = event_tx {
            let _ = tx
                .send(SyncEvent::ParseError {
                    height,
                    blob_len: entry.block.len(),
                    error: snippet.to_string(),
                })
                .await;
        }
    }

    let parsed: ParsedBlock = serde_json::from_str(&block_json_str)
        .map_err(|e| WalletError::Sync(format!("parse block at {}: {}", height, e)))?;

    // Scan miner transaction.
    if let Some(miner_tx_json) = &parsed.miner_tx {
        if !miner_tx_hash.is_empty() {
            if let Some(scan_data) =
                parse_tx_for_scanning(miner_tx_json, miner_tx_hash, height, true)
            {
                let found = scanner::scan_transaction(scan_ctx, &scan_data);
                outputs_found += found.len();
                store_found_outputs(db, scan_ctx, &found, &scan_data, block_timestamp)?;
            }
        }
    }

    // Scan protocol transaction (Salvium-specific: yields, staking returns, conversions).
    if let Some(protocol_tx_json) = &parsed.protocol_tx {
        // Count protocol_tx outputs to check for non-empty protocol TXs.
        let ptx_prefix = protocol_tx_json.get("prefix").unwrap_or(protocol_tx_json);
        let ptx_vout = ptx_prefix.get("vout").and_then(|v| v.as_array());
        let ptx_vout_count = ptx_vout.map(|a| a.len()).unwrap_or(0);

        let protocol_tx_hash = header.protocol_tx_hash.as_deref().filter(|s| !s.is_empty());

        let ptx_hash_str: Option<String> = protocol_tx_hash
            .map(|s| s.to_string())
            .or_else(|| compute_coinbase_tx_hash(protocol_tx_json));

        if ptx_vout_count > 0 {
            log::debug!(
                "protocol_tx at height={}: {} outputs, hash={}, has_header_hash={}",
                height,
                ptx_vout_count,
                &ptx_hash_str.as_deref().unwrap_or("NONE")
                    [..16.min(ptx_hash_str.as_ref().map(|s| s.len()).unwrap_or(0))],
                protocol_tx_hash.is_some()
            );
        }

        // TX-ID-based stake return matching: check each protocol TX output's
        // public key (Ko) against stored stakes' return_output_key.
        // C++ ref: construct_protocol_tx uses entry.return_address as the
        // onetime_address of the return enote. When we recorded the STAKE TX,
        // we stored this Ko. Now we match it directly — no CARROT scanning needed.
        if ptx_vout_count > 0 {
            if let Some(ref ptx_hash) = ptx_hash_str {
                if let Some(vout_arr) = ptx_vout {
                    let db_lock = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                    for out in vout_arr {
                        if let Some(key_hex) = out.get("key").and_then(|v| v.as_str()) {
                            if let Ok(Some(stake)) =
                                db_lock.get_locked_stake_by_return_output_key(key_hex)
                            {
                                if let Err(e) = db_lock.mark_stake_returned(
                                    &stake.stake_tx_hash,
                                    ptx_hash,
                                    height as i64,
                                    block_timestamp as i64,
                                    &stake.amount_staked,
                                ) {
                                    log::warn!("failed to mark stake as returned: {}", e);
                                } else {
                                    log::info!(
                                        "stake return (tx-id match): stake_tx={} ptx_hash={} height={} amount={} asset={}",
                                        &stake.stake_tx_hash[..stake.stake_tx_hash.len().min(16)],
                                        &ptx_hash[..ptx_hash.len().min(16)],
                                        height,
                                        stake.amount_staked,
                                        stake.asset_type
                                    );
                                }
                            }
                        }
                    }
                    drop(db_lock);
                }
            }
        }

        // Also attempt CARROT/CN scanning for protocol TX outputs (may find
        // return outputs that we can add to our wallet's output set).
        if let Some(ref ptx_hash) = ptx_hash_str {
            if let Some(scan_data) = parse_tx_for_scanning(protocol_tx_json, ptx_hash, height, true)
            {
                let found = scanner::scan_transaction(scan_ctx, &scan_data);
                if !found.is_empty() {
                    log::info!(
                        "protocol_tx match: height={} found={} outputs, tx_type={}",
                        height,
                        found.len(),
                        scan_data.tx_type
                    );
                }
                outputs_found += found.len();
                store_found_outputs(db, scan_ctx, &found, &scan_data, block_timestamp)?;
            } else if ptx_vout_count > 0 {
                // parse_tx_for_scanning returned None — likely no tx_pub_key
                log::debug!(
                    "protocol_tx at height={}: parse_tx_for_scanning returned None ({} outputs skipped)",
                    height, ptx_vout_count
                );
            }
        } else if ptx_vout_count > 0 {
            log::warn!(
                "protocol_tx at height={}: no hash available ({} outputs skipped)",
                height,
                ptx_vout_count
            );
        }
    }

    // Build tx hash list from the parsed block blob.
    let tx_hashes: Vec<String> = parsed
        .tx_hashes
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    // Scan regular transactions from the binary blobs.
    for (i, tx_blob) in entry.txs.iter().enumerate() {
        let tx_json_str = salvium_crypto::parse_transaction_bytes(tx_blob);

        // Detect silent parse failures from parse_transaction_bytes.
        if tx_json_str.starts_with(r#"{"error":"#) {
            parse_error = true;
            let snippet = &tx_json_str[..tx_json_str.len().min(200)];
            log::error!(
                "tx parse failed at height={} tx_idx={} blob_len={} err={}",
                height,
                i,
                tx_blob.len(),
                snippet
            );
            if let Some(tx) = event_tx {
                let _ = tx
                    .send(SyncEvent::ParseError {
                        height,
                        blob_len: tx_blob.len(),
                        error: format!("tx[{}]: {}", i, snippet),
                    })
                    .await;
            }
            continue;
        }

        match serde_json::from_str::<serde_json::Value>(&tx_json_str) {
            Ok(tx_json) => {
                let tx_hash_hex = if i < tx_hashes.len() {
                    &tx_hashes[i]
                } else {
                    log::warn!(
                        "tx hash missing at height={} tx_idx={} (have {} hashes, {} blobs)",
                        height,
                        i,
                        tx_hashes.len(),
                        entry.txs.len()
                    );
                    continue;
                };

                detect_spent_outputs(db, &tx_json, tx_hash_hex, height)?;

                if let Some(scan_data) = parse_tx_for_scanning(&tx_json, tx_hash_hex, height, false)
                {
                    let found = scanner::scan_transaction(scan_ctx, &scan_data);
                    outputs_found += found.len();
                    store_found_outputs(db, scan_ctx, &found, &scan_data, block_timestamp)?;
                }
            }
            Err(e) => {
                parse_error = true;
                log::error!(
                    "tx JSON deserialize failed at height={} tx_idx={}: {}",
                    height,
                    i,
                    e
                );
            }
        }
    }

    // Store block hash for reorg detection.
    {
        let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        db.put_block_hash(height as i64, block_hash)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
    }

    // Height-based stake return detection (fallback for pre-CARROT stakes).
    // C++ ref: blockchain.cpp:1586 — matured_height = height - stake_lock_period - 1
    // When the current block height >= stake_height + stake_lock_period + 1, the
    // protocol TX at this height contains the return for that stake. Mark it as
    // 'returned' so it no longer counts toward the locked balance.
    //
    // Only applies to stakes WITHOUT a return_output_key — those stakes use
    // TX-ID matching (above) as the primary return detection method.
    if stake_lock_period > 0 {
        let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        let locked_stakes = db
            .get_stakes(Some("locked"), None)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        for stake in &locked_stakes {
            // Skip stakes that have return_output_key — they use TX-ID matching.
            if stake.return_output_key.is_some() {
                continue;
            }
            if let Some(stake_height) = stake.stake_height {
                let return_height = stake_height as u64 + stake_lock_period + 1;
                if height >= return_height {
                    let ptx_hash = header
                        .protocol_tx_hash
                        .as_deref()
                        .unwrap_or("height-based-return");
                    if let Err(e) = db.mark_stake_returned(
                        &stake.stake_tx_hash,
                        ptx_hash,
                        height as i64,
                        block_timestamp as i64,
                        &stake.amount_staked,
                    ) {
                        log::warn!("failed to mark stake as returned: {}", e);
                    } else {
                        log::info!(
                            "stake return (height-based fallback): stake_tx={} stake_h={} return_h={} amount={} asset={}",
                            &stake.stake_tx_hash[..stake.stake_tx_hash.len().min(16)],
                            stake_height,
                            height,
                            stake.amount_staked,
                            stake.asset_type
                        );
                    }
                }
            }
        }
    }

    Ok(BlockProcessResult {
        outputs: outputs_found,
        parse_error,
    })
}

/// Process an already-fetched block: parse blob, scan miner tx and regular txs.
///
/// This is the "no-RPC" phase of block processing — the block data and
/// transaction entries have already been fetched. Transaction entries and
/// hashes are passed in from the batch fetch.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn process_block_data(
    db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
    scan_ctx: &mut ScanContext,
    height: u64,
    block: &salvium_rpc::daemon::BlockResult,
    tx_entries: &[salvium_rpc::daemon::TransactionEntry],
    tx_hashes: &[String],
) -> Result<usize, WalletError> {
    let block_hash = block.block_header.hash.clone();
    let block_timestamp = block.block_header.timestamp;
    let mut outputs_found = 0;

    // Parse the block blob to get miner tx.
    let block_blob = hex::decode(&block.blob)
        .map_err(|e| WalletError::Sync(format!("hex decode block: {}", e)))?;
    let block_json_str = salvium_crypto::parse_block_bytes(&block_blob);

    if block_json_str.starts_with(r#"{"error":"#) {
        log::error!(
            "block parse failed at height={} blob_len={} err={}",
            height,
            block_blob.len(),
            &block_json_str[..block_json_str.len().min(200)]
        );
    }

    if let Ok(parsed_block) = serde_json::from_str::<ParsedBlock>(&block_json_str) {
        // Scan miner transaction.
        if let Some(miner_tx_json) = &parsed_block.miner_tx {
            if let Some(scan_data) =
                parse_tx_for_scanning(miner_tx_json, &block.miner_tx_hash, height, true)
            {
                let found = scanner::scan_transaction(scan_ctx, &scan_data);
                outputs_found += found.len();
                store_found_outputs(db, scan_ctx, &found, &scan_data, block_timestamp)?;
            }
        }

        // Scan protocol transaction.
        if let Some(protocol_tx_json) = &parsed_block.protocol_tx {
            let ptx_hash = block
                .block_header
                .protocol_tx_hash
                .as_deref()
                .filter(|s| !s.is_empty());

            let ptx_hash_str = ptx_hash
                .map(|s| s.to_string())
                .or_else(|| compute_coinbase_tx_hash(protocol_tx_json));

            if let Some(ref hash) = ptx_hash_str {
                if let Some(scan_data) = parse_tx_for_scanning(protocol_tx_json, hash, height, true)
                {
                    let found = scanner::scan_transaction(scan_ctx, &scan_data);
                    outputs_found += found.len();
                    store_found_outputs(db, scan_ctx, &found, &scan_data, block_timestamp)?;
                }
            }
        }
    }

    // Scan regular transactions (already fetched).
    for (i, (entry, tx_hash_hex)) in tx_entries.iter().zip(tx_hashes.iter()).enumerate() {
        let tx_hex = &entry.as_hex;

        if tx_hex.is_empty() {
            log::warn!("empty tx hex at height={} tx_idx={}", height, i);
            continue;
        }

        let tx_bytes = match hex::decode(tx_hex) {
            Ok(b) => b,
            Err(e) => {
                log::error!(
                    "tx hex decode failed at height={} tx_idx={}: {}",
                    height,
                    i,
                    e
                );
                continue;
            }
        };

        let tx_json_str = salvium_crypto::parse_transaction_bytes(&tx_bytes);

        if tx_json_str.starts_with(r#"{"error":"#) {
            log::error!(
                "tx parse failed at height={} tx_idx={} blob_len={} err={}",
                height,
                i,
                tx_bytes.len(),
                &tx_json_str[..tx_json_str.len().min(200)]
            );
            continue;
        }

        match serde_json::from_str::<serde_json::Value>(&tx_json_str) {
            Ok(tx_json) => {
                detect_spent_outputs(db, &tx_json, tx_hash_hex, height)?;

                if let Some(scan_data) = parse_tx_for_scanning(&tx_json, tx_hash_hex, height, false)
                {
                    let found = scanner::scan_transaction(scan_ctx, &scan_data);
                    outputs_found += found.len();
                    store_found_outputs(db, scan_ctx, &found, &scan_data, block_timestamp)?;
                }
            }
            Err(e) => {
                log::error!(
                    "tx JSON deserialize failed at height={} tx_idx={}: {}",
                    height,
                    i,
                    e
                );
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

/// Fetch and scan a single block.
///
/// Retained for compatibility — the batch sync loop uses [`process_block_data`]
/// after concurrent fetching instead.
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
async fn sync_block(
    daemon: &DaemonRpc,
    db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
    scan_ctx: &mut ScanContext,
    height: u64,
) -> Result<usize, WalletError> {
    // Get block data.
    let block = daemon
        .get_block(height)
        .await
        .map_err(|e| WalletError::Sync(format!("get_block({}): {}", height, e)))?;

    // Fetch regular transactions.
    let tx_entries = if !block.tx_hashes.is_empty() {
        let hash_refs: Vec<&str> = block.tx_hashes.iter().map(|s| s.as_str()).collect();
        daemon
            .get_transactions(&hash_refs, false)
            .await
            .map_err(|e| WalletError::Sync(format!("get_transactions: {}", e)))?
    } else {
        Vec::new()
    };

    let tx_hashes = block.tx_hashes.clone();
    process_block_data(db, scan_ctx, height, &block, &tx_entries, &tx_hashes)
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

    // Extract tx public key (tag 0x01) and additional per-output pubkeys (tag 0x04).
    let tx_pub_key_01 =
        extract_tx_pub_key_from_parsed(prefix).or_else(|| extract_tx_pub_key_from_raw(tx_json));
    let additional_pubkeys = extract_additional_pubkeys(prefix);

    // tx_pub_key: prefer tag 0x01, fall back to additional_pubkeys[0].
    // Multi-output CARROT txs (including coinbase) may only have tag 0x04.
    let tx_pub_key = tx_pub_key_01.or_else(|| additional_pubkeys.first().copied())?;

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

    // Extract unlock_time from prefix.
    let unlock_time = prefix
        .get("unlockTime")
        .or_else(|| prefix.get("unlock_time"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

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
    let rct_section = tx_json.get("rct").or_else(|| tx_json.get("rct_signatures"));
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
        let out_type = out.get("type").and_then(|v| v.as_u64()).unwrap_or(0) as u8;

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
        // C++ ref: format_utils.cpp try_load_carrot_ephemeral_pubkeys_from_extra
        //   - If tag 0x01 exists: shared D_e → use for ALL outputs
        //   - If tag 0x04 exists: per-output D_e → use additional_pubkeys[i]
        // The decision is based on which tag is present, NOT on rct_type.
        let carrot_ephemeral_pubkey = if out_type == 4 {
            if tx_pub_key_01.is_some() {
                // Shared D_e from tag 0x01: same key for all outputs
                tx_pub_key_01
            } else {
                // Per-output D_e from tag 0x04 array
                additional_pubkeys.get(i).copied()
            }
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

        // Per-output unlock_time from output target struct.
        // CARROT outputs (type 4) don't have unlock_time (always 0).
        // For txout_to_key/txout_to_tagged_key, read from the output's
        // own "unlockTime" field. Falls back to TX prefix unlock_time.
        let output_unlock_time = if out_type == 4 {
            0 // CARROT outputs have no per-output unlock_time
        } else {
            out.get("unlockTime")
                .or_else(|| out.get("unlock_time"))
                .and_then(|v| v.as_u64())
                .unwrap_or(unlock_time) // fall back to TX prefix
        };

        // Encrypted Janus anchor (16 bytes, CARROT outputs only).
        let encrypted_janus_anchor = if out_type == 4 {
            out.get("encryptedJanusAnchor")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| {
                    if b.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&b);
                        Some(arr)
                    } else {
                        None
                    }
                })
        } else {
            None
        };

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
            unlock_time: output_unlock_time,
            encrypted_janus_anchor,
        });
    }

    Some(ScanTxData {
        tx_hash,
        tx_pub_key,
        additional_pubkeys,
        outputs,
        is_coinbase,
        block_height,
        first_key_image,
        tx_type,
        unlock_time,
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

/// Extract additional per-output pubkeys (tag 0x04) from structured extra.
///
/// Returns a vector of 32-byte pubkeys, one per output.
/// Multi-output CARROT transactions use these as per-output ephemeral pubkeys (D_e)
/// instead of a single shared tx_pubkey (tag 0x01).
fn extract_additional_pubkeys(prefix: &serde_json::Value) -> Vec<[u8; 32]> {
    let extra = match prefix.get("extra").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };

    for entry in extra {
        let is_additional = entry
            .get("type")
            .and_then(|v| v.as_u64())
            .map(|t| t == 4)
            .unwrap_or(false)
            || entry
                .get("tag")
                .and_then(|v| v.as_str())
                .map(|t| t == "additional_pubkeys")
                .unwrap_or(false);

        if is_additional {
            if let Some(keys) = entry.get("keys").and_then(|v| v.as_array()) {
                return keys
                    .iter()
                    .filter_map(|v| v.as_str().and_then(hex_to_32))
                    .collect();
            }
        }
    }

    Vec::new()
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

/// Parsed transaction input with ring member global indices.
struct ParsedTxInput {
    key_image: String,
    /// Absolute global output indices of ring members.
    ring_member_indices: Vec<u64>,
    /// Asset type from the input (for HF6+).
    asset_type: Option<String>,
}

/// Extract inputs with key_offsets from a transaction prefix.
/// Converts relative key_offsets to absolute global output indices.
fn extract_inputs_with_offsets(prefix: &serde_json::Value) -> Vec<ParsedTxInput> {
    let mut inputs = Vec::new();
    let vin = match prefix.get("vin").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return inputs,
    };

    for input in vin {
        let (ki_hex, offsets, asset_type) =
            if let Some(ki) = input.get("keyImage").and_then(|v| v.as_str()) {
                // New format: { "keyImage": "hex", "keyOffsets": [...], "assetType": "..." }
                let offsets = input
                    .get("keyOffsets")
                    .or_else(|| input.get("key_offsets"))
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
                    .unwrap_or_default();
                let asset = input
                    .get("assetType")
                    .or_else(|| input.get("asset_type"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                (ki.to_string(), offsets, asset)
            } else if let Some(key) = input.get("key") {
                // Legacy format: { "key": { "k_image": "hex", "key_offsets": [...] } }
                let ki = key
                    .get("k_image")
                    .or_else(|| key.get("keyImage"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let offsets = key
                    .get("key_offsets")
                    .or_else(|| key.get("keyOffsets"))
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
                    .unwrap_or_default();
                let asset = key
                    .get("asset_type")
                    .or_else(|| key.get("assetType"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                (ki, offsets, asset)
            } else {
                continue;
            };

        if ki_hex.len() != 64 || offsets.is_empty() {
            continue;
        }

        // Convert relative offsets to absolute indices.
        // C++ ref: cryptonote::relative_output_offsets_to_absolute
        let mut absolute = Vec::with_capacity(offsets.len());
        let mut running = 0u64;
        for offset in &offsets {
            running += offset;
            absolute.push(running);
        }

        inputs.push(ParsedTxInput {
            key_image: ki_hex,
            ring_member_indices: absolute,
            asset_type,
        });
    }

    inputs
}

/// Check transaction inputs for key images that belong to our wallet and mark
/// the corresponding outputs as spent.
///
/// Uses two complementary detection mechanisms:
/// 1. **Key image matching** (primary): direct lookup of on-chain key images
///    against stored output key images. Works for full wallets (all eras) and
///    view-only wallets (CARROT outputs only, via generate_image_key).
/// 2. **Output tracker cache** (fallback): matches ring member global indices
///    against stored outputs. C++ ref: wallet2.cpp:2833-2853. When our output
///    appears as a ring member and has a synthetic "vo:" key image (CN view-only),
///    we learn its real key image from the on-chain input and mark it as spent.
///
/// Fix #4: When a STAKE TX (tx_type=6) spends our output, record the stake
/// in the stakes table so staked amounts appear in the total balance.
/// C++ ref: wallet2.cpp:2759-2764 (m_locked_coins tracking)
///
/// Uses `tx.amount_burnt` (not sum of spent inputs) as the staked amount,
/// matching C++: `m_locked_coins.insert({pk, {0, tx.amount_burnt, tx.source_asset_type}})`.
/// Using spent input amounts would overcount by (fee + change), since the
/// change output is already counted in unspent outputs.
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

    // Determine tx_type for STAKE tracking.
    let tx_type = prefix
        .get("txType")
        .or_else(|| prefix.get("tx_type"))
        .and_then(|v| v.as_u64())
        .unwrap_or(3);

    let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
    let mut spent_count = 0;

    // ── Pass 1: Key image matching (primary mechanism) ──────────────────
    let mut matched_key_images = std::collections::HashSet::new();
    for ki_hex in &key_images {
        // Check if this key image belongs to one of our outputs.
        let output = db
            .get_output(ki_hex)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        if let Some(row) = output {
            // Count all outputs that belong to us, even if already marked spent
            // (e.g. by mark_inputs_spent after TX submission). This ensures
            // stake recording still triggers when the block is later synced.
            spent_count += 1;
            matched_key_images.insert(ki_hex.clone());
            if !row.is_spent {
                db.mark_spent(ki_hex, tx_hash_hex, block_height as i64)
                    .map_err(|e| WalletError::Storage(e.to_string()))?;
            }
        }
    }

    // ── Pass 2: Output tracker cache (ring member usage tracking) ───────
    // C++ ref: wallet2.cpp:2833-2853 (output_tracker_cache)
    //
    // When our output appears as a ring member of an on-chain input, we
    // record usage but do NOT mark it as spent. We cannot distinguish
    // real spends from decoy usage without the spending secret — marking
    // on ring membership alone would cause false positives (~15/16 of the
    // time for a standard ring size of 16).
    //
    // For view-only wallets, CN outputs will always show a balance >=
    // the real balance. This matches C++ behavior: the tracker just sets
    // `recognized_owned_possibly_spent_enote = true` and caches the TX
    // for potential re-processing when the spend key becomes available.
    let inputs = extract_inputs_with_offsets(prefix);
    for input in &inputs {
        if matched_key_images.contains(&input.key_image) {
            continue; // Already matched by key image in Pass 1
        }

        let asset_type = input.asset_type.as_deref().unwrap_or("SAL");

        for &global_idx in &input.ring_member_indices {
            let output = db
                .get_output_by_global_index(asset_type, global_idx as i64)
                .map_err(|e| WalletError::Storage(e.to_string()))?;
            if let Some(row) = output {
                log::debug!(
                    "output tracker: our output global_idx={} asset={} seen as ring member (ki={}, tx={})",
                    global_idx, asset_type,
                    row.key_image.as_deref().unwrap_or("none"),
                    &tx_hash_hex[..16]
                );
                break;
            }
        }
    }

    // Fix #4: Record the stake using amount_burnt from the TX prefix.
    // C++ uses tx.amount_burnt (the actual staked amount, excluding fee and change),
    // and tx.source_asset_type for the asset. This avoids double-counting: the change
    // output is already in unspent outputs, so using spent input amounts would add
    // (fee + change) extra to the staked total.
    if spent_count > 0 && (tx_type == 6 || tx_type == 8) {
        let amount_burnt: u64 = prefix
            .get("amount_burnt")
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse().ok())
                    .or_else(|| v.as_u64())
            })
            .unwrap_or(0);

        let source_asset_type = prefix
            .get("source_asset_type")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("SAL")
            .to_string();

        if amount_burnt > 0 {
            // Extract return_output_key from protocol_tx_data (CARROT v4+ STAKE TXs).
            // This is the pre-computed Ko (onetime address) of the return output,
            // used for TX-ID-based stake return matching against protocol TX outputs.
            // C++ ref: cryptonote_tx_utils.cpp:340 — construct_protocol_tx uses
            // entry.return_address as the onetime_address of the return enote.
            let return_output_key = prefix
                .get("protocol_tx_data")
                .and_then(|ptd| ptd.get("return_address"))
                .and_then(|v| v.as_str())
                .filter(|s| s.len() == 64) // 32 bytes = 64 hex chars
                .map(|s| s.to_string());

            let stake_row = salvium_crypto::storage::StakeRow {
                stake_tx_hash: tx_hash_hex.to_string(),
                stake_height: Some(block_height as i64),
                stake_timestamp: None,
                amount_staked: amount_burnt.to_string(),
                fee: "0".to_string(),
                asset_type: source_asset_type.clone(),
                change_output_key: None,
                status: "locked".to_string(),
                return_tx_hash: None,
                return_height: None,
                return_timestamp: None,
                return_amount: "0".to_string(),
                return_output_key: return_output_key.clone(),
                created_at: None,
                updated_at: None,
            };
            db.put_stake(&stake_row)
                .map_err(|e| WalletError::Storage(e.to_string()))?;
            log::info!(
                "stake tracked: tx={} amount_burnt={} asset={} return_key={}",
                &tx_hash_hex[..16],
                amount_burnt,
                source_asset_type,
                return_output_key
                    .as_deref()
                    .map(|k| &k[..k.len().min(16)])
                    .unwrap_or("none")
            );
        }
    }

    Ok(spent_count)
}

/// Store found outputs in the database.
///
/// Includes Fix #1 (per-output unlock_time), Fix #2 (return output detection),
/// and Fix #3 (burning bug detection).
#[cfg(not(target_arch = "wasm32"))]
fn store_found_outputs(
    db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
    scan_ctx: &mut ScanContext,
    found: &[FoundOutput],
    tx: &ScanTxData,
    block_timestamp: u64,
) -> Result<(), WalletError> {
    if found.is_empty() {
        return Ok(());
    }

    let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;

    for output in found {
        let pub_key_hex = hex::encode(output.output_public_key);

        // Log non-coinbase CARROT matches for diagnostics.
        if output.is_carrot && !tx.is_coinbase {
            let scan_path = if output.is_carrot_internal {
                "INTERNAL"
            } else {
                "EXTERNAL"
            };
            log::debug!(
                "CARROT {} match: height={} tx_type={} out_idx={} amount={} addr=({},{}) asset={}",
                scan_path,
                tx.block_height,
                tx.tx_type,
                output.output_index,
                output.amount,
                output.subaddress_major,
                output.subaddress_minor,
                output.asset_type,
            );
        }

        // Fix #3: Burning bug detection — check for duplicate onetime addresses.
        // C++ ref: wallet2.cpp:2597-2612
        // If the same onetime address already exists with >= amount, skip this
        // duplicate to avoid double-counting. Matches C++ exactly: only check
        // the amount condition, NOT the spent status.
        let existing = db
            .get_output_by_public_key(&pub_key_hex)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        if let Some(ref existing_row) = existing {
            let existing_amount: u64 = existing_row.amount.parse().unwrap_or(0);
            if existing_amount >= output.amount {
                log::debug!(
                    "burning bug: skipping duplicate output pk={} (existing amount={} >= new={})",
                    &pub_key_hex[..16],
                    existing_row.amount,
                    output.amount
                );
                continue;
            }
        }

        // Fix #1: Use per-output unlock_time from the matching TxOutput,
        // not the TX prefix unlock_time.
        let output_unlock_time = tx
            .outputs
            .get(output.output_index as usize)
            .map(|o| o.unlock_time)
            .unwrap_or(tx.unlock_time);

        let mut row = salvium_crypto::storage::OutputRow {
            key_image: output.key_image.map(hex::encode),
            public_key: Some(pub_key_hex),
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
            carrot_shared_secret: output.carrot_shared_secret.map(hex::encode),
            carrot_enote_type: output.carrot_enote_type.map(|t| t as i64),
            is_spent: false,
            spent_height: None,
            spent_tx_hash: None,
            unlock_time: output_unlock_time.to_string(),
            tx_type: tx.tx_type as i64,
            tx_pub_key: Some(hex::encode(tx.tx_pub_key)),
            is_frozen: false,
            created_at: None,
            updated_at: None,
        };

        // View-only CN outputs have no key image (spend secret unavailable).
        // Generate a synthetic key from tx_hash + output_index so the output
        // can still be stored for balance tracking.
        if row.key_image.is_none() {
            let mut buf = Vec::with_capacity(36);
            buf.extend_from_slice(&tx.tx_hash);
            buf.extend_from_slice(&output.output_index.to_le_bytes());
            let synthetic = salvium_crypto::keccak256(&buf);
            row.key_image = Some(format!("vo:{}", hex::encode(synthetic)));
        }
        db.put_output(&row)
            .map_err(|e| WalletError::Storage(e.to_string()))?;

        // Populate salvium_txs for CONVERT(4)/STAKE(6)/AUDIT(8) change outputs.
        // These entries are needed later for pre-CARROT PROTOCOL return key
        // image overrides. Also add the Ko to the live CN subaddress map so
        // subsequent blocks can find PROTOCOL returns.
        // C++ ref: `m_salvium_txs` population in wallet2.cpp
        if matches!(tx.tx_type, 4 | 6 | 8) {
            let ko_hex = hex::encode(output.output_public_key);
            let tx_pub_hex = hex::encode(tx.tx_pub_key);
            let _ = db.put_salvium_tx(
                &ko_hex,
                &tx_pub_hex,
                output.output_index as i64,
                output.subaddress_major as i64,
                output.subaddress_minor as i64,
                tx.tx_type as i64,
            );

            // Add to live CN subaddress map if not already present.
            if !scan_ctx
                .cn_subaddress_map
                .iter()
                .any(|(k, _, _)| *k == output.output_public_key)
            {
                scan_ctx.cn_subaddress_map.push((
                    output.output_public_key,
                    output.subaddress_major,
                    output.subaddress_minor,
                ));
            }

            // Update the stake's change_output_key for STAKE TXs.
            if tx.tx_type == 6 {
                let ko_hex = hex::encode(output.output_public_key);
                let tx_hash_hex = hex::encode(tx.tx_hash);
                if let Ok(stakes) = db.get_stakes(Some("locked"), None) {
                    if let Some(stake) = stakes.iter().find(|s| s.stake_tx_hash == tx_hash_hex) {
                        let _ = db.update_stake_change_key(&stake.stake_tx_hash, &ko_hex);
                    }
                }
            }
        }

        // Pre-CARROT PROTOCOL return key image override.
        // C++ ref: wallet2.cpp:2684-2719, generate_key_image_helper_precomp use_origin_data
        // For non-CARROT outputs in PROTOCOL_TX (tx_type=2), the key image
        // must use two-step derivation through the origin STAKE/AUDIT/CONVERT TX.
        if tx.tx_type == 2 && !output.is_carrot {
            if let Some(ref spend_secret) = scan_ctx.cn_spend_secret {
                let derivation = salvium_crypto::generate_key_derivation(
                    &tx.tx_pub_key,
                    &scan_ctx.cn_view_secret,
                );
                if derivation.len() == 32 {
                    let mut d = [0u8; 32];
                    d.copy_from_slice(&derivation);
                    // P_change = Ko_return - Hs(D || 0) * G
                    let p_change = salvium_crypto::cn_scan::derive_subaddress_pubkey_bytes(
                        &output.output_public_key,
                        &d,
                        0,
                    );
                    let p_change_hex = hex::encode(p_change);

                    if let Ok(Some(origin)) = db.get_salvium_tx(&p_change_hex) {
                        if let Ok(origin_pub) = hex::decode(&origin.origin_tx_pub) {
                            if origin_pub.len() == 32 {
                                let mut origin_pub_arr = [0u8; 32];
                                origin_pub_arr.copy_from_slice(&origin_pub);

                                // Two-step derivation (faithful to C++ generate_key_image_helper_precomp)
                                // Step 1: sk_change = derive_output_spend_key(view, spend, origin_pub, origin_idx, major, minor)
                                let sk_change = salvium_crypto::cn_scan::derive_output_spend_key(
                                    &scan_ctx.cn_view_secret,
                                    spend_secret,
                                    &origin_pub_arr,
                                    origin.origin_out_idx as u32,
                                    origin.subaddr_major as u32,
                                    origin.subaddr_minor as u32,
                                );
                                // Step 2: x_return = derive_output_spend_key(view, &sk_change, protocol_pub, 0, 0, 0)
                                let x_return = salvium_crypto::cn_scan::derive_output_spend_key(
                                    &scan_ctx.cn_view_secret,
                                    &sk_change,
                                    &tx.tx_pub_key,
                                    0,
                                    0,
                                    0,
                                );
                                // Step 3: KI = generate_key_image(Ko_return, x_return)
                                let ki = salvium_crypto::generate_key_image(
                                    &output.output_public_key,
                                    &x_return,
                                );
                                if ki.len() == 32 {
                                    let new_ki = hex::encode(&ki);
                                    let old_ki = row.key_image.as_deref().unwrap_or("");
                                    if old_ki != new_ki {
                                        log::info!(
                                            "key image override: height={} old={:.16} new={:.16}",
                                            tx.block_height,
                                            old_ki,
                                            &new_ki
                                        );
                                        let _ = db.replace_key_image(old_ki, &new_ki);
                                        row.key_image = Some(new_ki);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fix #2: Return output detection for PROTOCOL_TX.
        // C++ ref: wallet2.cpp:2754-2756 (m_locked_coins.erase on return)
        // When we find an output in a PROTOCOL_TX (tx_type=2) that belongs to us,
        // it may be a return of previously staked funds. Match against locked stakes
        // by asset type and mark the oldest matching stake as returned, preventing
        // double-counting (staked amount + returned output).
        if tx.tx_type == 2 {
            log::info!(
                "protocol_tx output found: height={} amount={} asset={} out_idx={}",
                tx.block_height,
                output.amount,
                output.asset_type,
                output.output_index
            );
            if let Ok(stakes) = db.get_stakes(Some("locked"), Some(&output.asset_type)) {
                if let Some(stake) = stakes.first() {
                    let tx_hash_hex = hex::encode(tx.tx_hash);
                    if let Err(e) = db.mark_stake_returned(
                        &stake.stake_tx_hash,
                        &tx_hash_hex,
                        tx.block_height as i64,
                        block_timestamp as i64,
                        &output.amount.to_string(),
                    ) {
                        log::warn!("failed to mark stake as returned: {}", e);
                    } else {
                        log::info!(
                            "stake return detected: stake_tx={} return_tx={} amount={} asset={}",
                            &stake.stake_tx_hash[..stake.stake_tx_hash.len().min(16)],
                            &tx_hash_hex[..16],
                            output.amount,
                            output.asset_type
                        );
                    }
                } else {
                    log::debug!(
                        "protocol_tx output at height={}: no locked stakes match asset={}",
                        tx.block_height,
                        output.asset_type
                    );
                }
            }
        }
    }

    Ok(())
}

/// Compute transaction hash for a coinbase/protocol tx (RCTTypeNull) from parsed JSON.
///
/// Uses the CryptoNote v2 3-hash scheme:
///   prefix_hash = keccak256(serialized_prefix_bytes)
///   tx_hash = keccak256(prefix_hash || null_hash || null_hash)
///
/// For RCTTypeNull transactions, hashes[1] and hashes[2] are 32 zero bytes.
#[cfg(not(target_arch = "wasm32"))]
fn compute_coinbase_tx_hash(tx_json: &serde_json::Value) -> Option<String> {
    let tx_str = serde_json::to_string(tx_json).ok()?;
    let prefix_bytes = salvium_crypto::tx_serialize::serialize_tx_prefix(&tx_str).ok()?;
    let prefix_hash = salvium_crypto::keccak256(&prefix_bytes);

    // CryptoNote v2 3-hash scheme with null_hash for RCTTypeNull
    let mut combined = [0u8; 96];
    let ph = prefix_hash;
    if ph.len() == 32 {
        combined[..32].copy_from_slice(&ph);
    } else {
        return None;
    }
    // hashes[1] and hashes[2] are zero (null_hash) for RCTTypeNull
    let hash = salvium_crypto::keccak256(&combined);
    if hash.len() == 32 {
        Some(hex::encode(&hash))
    } else {
        None
    }
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

/// Resolve global output indices for newly stored outputs.
///
/// After each batch of blocks, outputs are stored with `global_index = NULL`
/// because `get_blocks_by_height.bin` doesn't return output indices. This
/// function fetches the missing indices via `get_transactions` and updates
/// the stored outputs.
///
/// C++ ref: wallet2.cpp stores global_index at scan time because it uses
/// `getblocks.bin` which returns output indices. We use `get_blocks_by_height.bin`
/// (which doesn't) for performance, so we resolve indices post-hoc.
///
/// These indices are required by the output tracker cache (detect_spent_outputs
/// Pass 2) to match ring member global indices against our stored outputs.
#[cfg(not(target_arch = "wasm32"))]
async fn resolve_global_indices(
    daemon: &DaemonRpc,
    db: &std::sync::Mutex<salvium_crypto::storage::WalletDb>,
) -> Result<usize, WalletError> {
    // Get outputs that need global_index resolution.
    let pending = {
        let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_outputs_needing_global_index()
            .map_err(|e| WalletError::Storage(e.to_string()))?
    };

    if pending.is_empty() {
        return Ok(0);
    }

    // Group by tx_hash for batched lookup.
    let mut by_tx: std::collections::HashMap<String, Vec<(String, i64)>> =
        std::collections::HashMap::new();
    for (key_image, tx_hash, output_index) in &pending {
        by_tx
            .entry(tx_hash.clone())
            .or_default()
            .push((key_image.clone(), *output_index));
    }

    // Fetch transaction entries (which include output_indices).
    let tx_hashes: Vec<String> = by_tx.keys().cloned().collect();
    let hash_refs: Vec<&str> = tx_hashes.iter().map(|s| s.as_str()).collect();

    // Process in batches of 100 to avoid huge RPC requests.
    let mut resolved = 0;
    for chunk in hash_refs.chunks(100) {
        let entries = daemon
            .get_transactions(chunk, false)
            .await
            .map_err(|e| WalletError::Sync(format!("resolve_global_indices: {}", e)))?;

        let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        for (entry, &tx_hash_str) in entries.iter().zip(chunk.iter()) {
            if entry.output_indices.is_empty() {
                continue;
            }

            if let Some(outputs) = by_tx.get(tx_hash_str) {
                for (key_image, output_index) in outputs {
                    if (*output_index as usize) < entry.output_indices.len() {
                        let global_idx = entry.output_indices[*output_index as usize];
                        db.update_global_index(key_image, global_idx as i64)
                            .map_err(|e| WalletError::Storage(e.to_string()))?;
                        resolved += 1;
                    }
                }
            }
        }
    }

    if resolved > 0 {
        log::debug!("resolved {} global output indices", resolved);
    }

    Ok(resolved)
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
            parse_errors: 0,
            empty_blobs: 0,
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
            parse_errors: 0,
            empty_blobs: 0,
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

        let parse_error = SyncEvent::ParseError {
            height: 334750,
            blob_len: 1024,
            error: r#"{"error":"unexpected byte"}"#.to_string(),
        };
        let debug_str = format!("{:?}", parse_error);
        assert!(debug_str.contains("ParseError"));
        assert!(debug_str.contains("334750"));

        // Verify Clone works on all variants.
        let _started_clone = started.clone();
        let _progress_clone = progress.clone();
        let _complete_clone = complete.clone();
        let _reorg_clone = reorg.clone();
        let _error_clone = error.clone();
        let _parse_error_clone = parse_error.clone();
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
        let _tx_pub_hex = "aa".repeat(32);
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

    // ── BatchController Tests ─────────────────────────────────────────

    #[test]
    fn test_batch_controller_initial() {
        let ctrl = BatchController::new();
        assert_eq!(ctrl.batch_size, 64);
        assert_eq!(ctrl.min_batch, 2);
        assert_eq!(ctrl.max_batch, 1000);
        assert_eq!(ctrl.consecutive_errors, 0);
    }

    #[test]
    fn test_batch_controller_scale_up() {
        let mut ctrl = BatchController::new();
        // Fast batch → scale up by 50%
        ctrl.adjust(500, false); // 500ms < 1s target
        assert_eq!(ctrl.batch_size, 96); // 64 + 32
        ctrl.adjust(500, false);
        assert_eq!(ctrl.batch_size, 144); // 96 + 48
    }

    #[test]
    fn test_batch_controller_scale_down() {
        let mut ctrl = BatchController::new();
        ctrl.batch_size = 40;
        // Slow batch → scale down by 25%
        ctrl.adjust(5000, false); // 5s > 3s target
        assert_eq!(ctrl.batch_size, 30); // 40 - 10
    }

    #[test]
    fn test_batch_controller_error_halves() {
        let mut ctrl = BatchController::new();
        ctrl.batch_size = 20;
        ctrl.adjust(0, true);
        assert_eq!(ctrl.batch_size, 10); // 20 / 2
        assert_eq!(ctrl.consecutive_errors, 1);
    }

    #[test]
    fn test_batch_controller_consecutive_errors_drop_to_min() {
        let mut ctrl = BatchController::new();
        ctrl.batch_size = 50;
        ctrl.adjust(0, true); // 25
        ctrl.adjust(0, true); // 12
        ctrl.adjust(0, true); // 3 consecutive → drops to min
        assert_eq!(ctrl.batch_size, ctrl.min_batch);
        assert_eq!(ctrl.consecutive_errors, 3);
    }

    #[test]
    fn test_batch_controller_error_resets_on_success() {
        let mut ctrl = BatchController::new();
        ctrl.adjust(0, true);
        ctrl.adjust(0, true);
        assert_eq!(ctrl.consecutive_errors, 2);
        ctrl.adjust(1000, false);
        assert_eq!(ctrl.consecutive_errors, 0);
    }

    #[test]
    fn test_batch_controller_respects_max() {
        let mut ctrl = BatchController::new();
        ctrl.batch_size = 90;
        ctrl.adjust(100, false); // fast → scale up
        assert!(ctrl.batch_size <= ctrl.max_batch);
    }

    #[test]
    fn test_batch_controller_respects_min() {
        let mut ctrl = BatchController::new();
        ctrl.batch_size = 2;
        ctrl.adjust(10000, false); // slow → scale down
        assert!(ctrl.batch_size >= ctrl.min_batch);
    }

    #[test]
    fn test_batch_controller_next_batch_size() {
        let ctrl = BatchController::new();
        assert_eq!(ctrl.next_batch_size(500), 64); // batch_size < remaining
        assert_eq!(ctrl.next_batch_size(5), 5); // remaining < batch_size
        assert_eq!(ctrl.next_batch_size(64), 64); // equal
    }

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

    #[test]
    fn test_extract_additional_pubkeys() {
        let prefix = serde_json::json!({
            "extra": [
                { "type": 4, "tag": "additional_pubkeys", "keys": [
                    "aa".repeat(32),
                    "bb".repeat(32)
                ]}
            ]
        });
        let keys = extract_additional_pubkeys(&prefix);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], [0xAA; 32]);
        assert_eq!(keys[1], [0xBB; 32]);
    }

    #[test]
    fn test_extract_additional_pubkeys_empty() {
        let prefix = serde_json::json!({
            "extra": [
                { "type": 1, "tag": "tx_pubkey", "key": "aa".repeat(32) }
            ]
        });
        let keys = extract_additional_pubkeys(&prefix);
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_tx_for_scanning_carrot_coinbase_tag_04() {
        // CARROT miner_tx with tag 0x04 (per-output D_e), no tag 0x01.
        // This is the common case for multi-output CARROT coinbase txs where
        // each output has a different ephemeral pubkey.
        let tx_hash_hex = "cc".repeat(32);
        let out_key1 = "dd".repeat(32);
        let out_key2 = "ee".repeat(32);
        let de1_hex = "a1".repeat(32);
        let de2_hex = "b2".repeat(32);

        let tx_json = serde_json::json!({
            "prefix": {
                "txType": 1,
                "extra": [
                    { "type": 4, "tag": "additional_pubkeys", "keys": [
                        de1_hex, de2_hex
                    ]}
                ],
                "vin": [{ "type": 255, "height": 5000 }],
                "vout": [
                    {
                        "amount": "80000000",
                        "key": out_key1,
                        "type": 4,
                        "viewTag": "abcdef",
                        "assetType": "SAL1"
                    },
                    {
                        "amount": "20000000",
                        "key": out_key2,
                        "type": 4,
                        "viewTag": "123456",
                        "assetType": "SAL"
                    }
                ]
            },
            "rct": { "type": 0 }
        });

        // Should succeed despite no tag 0x01 (falls back to additional_pubkeys[0]).
        let result = parse_tx_for_scanning(&tx_json, &tx_hash_hex, 5000, true).unwrap();

        assert!(result.is_coinbase);
        assert_eq!(result.tx_type, 1);
        // tx_pub_key should be additional_pubkeys[0] as fallback.
        assert_eq!(result.tx_pub_key, [0xA1; 32]);
        assert_eq!(result.outputs.len(), 2);

        // Output 0: D_e = additional_pubkeys[0].
        let out0 = &result.outputs[0];
        assert_eq!(out0.carrot_view_tag, Some([0xAB, 0xCD, 0xEF]));
        assert_eq!(out0.carrot_ephemeral_pubkey, Some([0xA1; 32]));
        assert_eq!(out0.amount, 80_000_000);
        assert_eq!(out0.asset_type, "SAL1");

        // Output 1: D_e = additional_pubkeys[1].
        let out1 = &result.outputs[1];
        assert_eq!(out1.carrot_view_tag, Some([0x12, 0x34, 0x56]));
        assert_eq!(out1.carrot_ephemeral_pubkey, Some([0xB2; 32]));
        assert_eq!(out1.amount, 20_000_000);
        assert_eq!(out1.asset_type, "SAL");
    }
}
