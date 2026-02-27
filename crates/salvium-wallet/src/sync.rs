//! Blockchain synchronization engine.
//!
//! Fetches blocks from the daemon, scans transactions for owned outputs,
//! stores results in the wallet database, and handles chain reorganizations.
//!
//! Uses adaptive batch sizing with the `/get_blocks_by_height.bin` binary
//! endpoint to fetch hundreds of blocks (with all their transactions) in a
//! single HTTP request. The batch size tunes itself based on throughput.

use std::sync::Arc;

use crate::error::WalletError;
use crate::scanner::{self, FoundOutput, ScanContext, ScanTxData, TxOutput};
use salvium_rpc::NodePool;
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
    ParseError { height: u64, blob_len: usize, error: String },
    /// Sync cancelled by caller.
    Cancelled { height: u64 },
}

/// Blockchain sync engine.
pub struct SyncEngine;

/// Adaptive batch size controller with throughput tracking.
///
/// Tunes the number of blocks fetched per round based on how long each batch
/// takes relative to a target duration and byte throughput. Scales up when
/// batches are fast (early blocks are small), scales down when blocks are
/// heavy or the network is slow. Caps batch size to ~2MB for mobile.
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

    /// Adjust batch size based on elapsed time per batch.
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
            self.batch_size = (self.batch_size + self.batch_size / 2).min(self.max_batch);
        } else {
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

/// Prefetched batch result for pipeline overlap.
struct PrefetchResult {
    batch_start: u64,
    batch_end: u64,
    result: Result<salvium_rpc::DistributedBatchResult, salvium_rpc::RpcError>,
}

/// Message sent from the sync loop to the store worker thread.
#[cfg(not(target_arch = "wasm32"))]
struct StoreBatchMsg {
    parse_results: Vec<ParsedBlockResult>,
    scan_ctx: ScanContext,
    stake_lock_period: u64,
    batch_start: u64,
    batch_end: u64,
    fetch_ms: u64,
    parse_ms: u64,
    pool: NodePool,
}

/// Result sent back from the store worker to the sync loop.
#[cfg(not(target_arch = "wasm32"))]
struct StoreResultMsg {
    /// New cn_subaddress_map entries discovered during store (STAKE/CONVERT/AUDIT change outputs).
    new_cn_subaddr_entries: Vec<([u8; 32], u32, u32)>,
    /// Block hashes from the committed batch (for reorg checking without DB lock).
    block_hashes: Vec<(u64, String)>,
    /// The highest block height committed in this batch.
    _committed_height: u64,
    /// Number of outputs found in this batch.
    outputs_found: usize,
    /// Number of parse errors in this batch.
    parse_errors: usize,
    /// Number of empty blobs in this batch.
    empty_blobs: usize,
    /// Error that occurred during store, if any.
    error: Option<WalletError>,
}

/// Result of executing the store logic for a batch (used internally by store worker).
#[cfg(not(target_arch = "wasm32"))]
struct StoreBatchResult {
    max_height: u64,
    outputs_found: usize,
    parse_errors: usize,
    empty_blobs: usize,
    block_hashes: Vec<(u64, String)>,
}

impl SyncEngine {
    /// Sync the wallet from the current sync height to the daemon's tip.
    ///
    /// Uses `/get_blocks_by_height.bin` to fetch hundreds of blocks (with all
    /// their transactions) in a single HTTP request. Features:
    ///
    /// - **NodePool**: routes calls through the active node with failover
    /// - **Prefetch pipeline**: fetch batch N+1 while processing batch N
    /// - **Parallel block parsing**: CPU-bound parse+scan runs in parallel via
    ///   `spawn_blocking`, results stored sequentially
    /// - **Throughput-aware batching**: adapts batch size based on time and bytes
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn sync(
        pool: &NodePool,
        db: Arc<std::sync::Mutex<salvium_crypto::storage::WalletDb>>,
        scan_ctx: &mut ScanContext,
        stake_lock_period: u64,
        event_tx: Option<&tokio::sync::mpsc::Sender<SyncEvent>>,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<u64, WalletError> {
        let daemon_height =
            pool.get_height().await.map_err(|e| WalletError::Sync(e.to_string()))?;

        // daemon_height is the block count, so the last valid block index
        // is daemon_height - 1.
        let top_block = daemon_height.saturating_sub(1);

        let sync_height = {
            let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
            // Persist chain tip so non-sync code (e.g. subaddress creation)
            // can determine the active hardfork without daemon access.
            let _ = db.set_attribute("chain_tip_height", &top_block.to_string());
            db.get_sync_height().map_err(|e| WalletError::Storage(e.to_string()))?
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
            let _ = tx.send(SyncEvent::Started { target_height: top_block }).await;
        }

        let mut current = sync_height as u64;
        let mut total_outputs_found = 0usize;
        let mut total_parse_errors = 0usize;
        let mut total_empty_blobs = 0usize;
        let mut controller = BatchController::new();
        let mut prefetch: Option<tokio::task::JoinHandle<PrefetchResult>> = None;

        // Block hash cache: populated from StoreResultMsg so we can check
        // for reorgs without locking the DB (which the store worker may hold).
        let mut block_hash_cache: std::collections::HashMap<u64, String> =
            std::collections::HashMap::new();

        // ── Store worker pipeline ──────────────────────────────────────
        // Bounded channel (capacity 2) provides backpressure.
        let (store_tx, store_rx) = std::sync::mpsc::sync_channel::<StoreBatchMsg>(2);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel::<StoreResultMsg>(2);

        let store_db = db.clone();
        let store_handle = std::thread::spawn(move || {
            store_worker_loop(store_db, store_rx, result_tx);
        });

        // Populate latency data across all nodes before the first fetch so
        // fetch_batch_distributed can distribute work effectively.
        pool.force_race().await;

        // Track the final result to return after cleanup.
        let sync_result: Result<u64, WalletError> = async {
            while current < top_block {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Some(tx) = event_tx {
                        let _ = tx.send(SyncEvent::Cancelled { height: current }).await;
                    }
                    return Err(WalletError::Cancelled);
                }

                // ── 0. Drain completed store results ────────────────────────
                while let Ok(result) = result_rx.try_recv() {
                    apply_store_result(
                        scan_ctx,
                        &mut block_hash_cache,
                        &mut total_outputs_found,
                        &mut total_parse_errors,
                        &mut total_empty_blobs,
                        &result,
                    )?;
                }

                let remaining = top_block - current;
                let batch_size = controller.next_batch_size(remaining);
                let batch_start = current + 1;
                let batch_end = current + batch_size as u64;

                let batch_timer = std::time::Instant::now();
                let heights: Vec<u64> = (batch_start..=batch_end).collect();

                // ── 1. Get batch data (from prefetch or fresh fetch) ────────
                let batch_result = if let Some(handle) = prefetch.take() {
                    match handle.await {
                        Ok(pf) if pf.batch_start == batch_start && pf.batch_end == batch_end => {
                            pf.result
                        }
                        _ => {
                            // Prefetch range doesn't match (batch size changed) — fetch fresh.
                            pool.fetch_batch_distributed(batch_start, batch_end).await
                        }
                    }
                } else {
                    pool.fetch_batch_distributed(batch_start, batch_end).await
                };

                let batch_data = match batch_result {
                    Ok(r) => r,
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
                let headers = batch_data.headers;
                let bin_blocks = batch_data.bin_blocks;

                // Reorg check: verify first header's prev_hash matches our stored hash.
                // Primary: check block_hash_cache (populated from store results).
                // Fallback: query DB (may briefly block if store worker holds the lock).
                if current > 0 {
                    let expected_hash = if let Some(cached) = block_hash_cache.get(&current) {
                        Some(cached.clone())
                    } else {
                        let db_guard =
                            db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
                        db_guard
                            .get_block_hash(current as i64)
                            .map_err(|e| WalletError::Storage(e.to_string()))?
                    };

                    if let Some(expected) = expected_hash {
                        if let Some(first) = headers.first() {
                            if first.prev_hash != expected {
                                // Drain all pending store results before handling reorg.
                                while let Ok(result) = result_rx.try_recv() {
                                    apply_store_result(
                                        scan_ctx,
                                        &mut block_hash_cache,
                                        &mut total_outputs_found,
                                        &mut total_parse_errors,
                                        &mut total_empty_blobs,
                                        &result,
                                    )?;
                                }

                                let reorg_start = find_fork_point(pool, &db, current).await?;

                                if let Some(tx) = event_tx {
                                    let _ = tx
                                        .send(SyncEvent::Reorg {
                                            from_height: current,
                                            to_height: reorg_start,
                                        })
                                        .await;
                                }

                                {
                                    let db_guard = db
                                        .lock()
                                        .map_err(|e| WalletError::Storage(e.to_string()))?;
                                    db_guard
                                        .rollback(reorg_start as i64)
                                        .map_err(|e| WalletError::Storage(e.to_string()))?;
                                }

                                // Clear block hash cache since we rolled back.
                                block_hash_cache.retain(|&h, _| h <= reorg_start);

                                current = reorg_start;
                                controller.adjust(batch_timer.elapsed().as_millis() as u64, true);
                                continue;
                            }
                        }
                    }
                }

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

                let fetch_ms = batch_timer.elapsed().as_millis() as u64;

                // ── 2b. Start prefetching next batch ────────────────────────
                let next_start = batch_end + 1;
                if next_start <= top_block {
                    let next_size = controller.next_batch_size(top_block - batch_end);
                    let next_end = batch_end + next_size as u64;
                    let pool_clone = pool.clone();
                    prefetch = Some(tokio::spawn(async move {
                        let result = pool_clone.fetch_batch_distributed(next_start, next_end).await;
                        PrefetchResult { batch_start: next_start, batch_end: next_end, result }
                    }));
                }

                // ── 3. Parallel parse ───────────────────────────────────────
                let parse_timer = std::time::Instant::now();

                // Drain results before cloning scan_ctx so new cn_subaddr entries
                // from previous batches are included in the parse.
                while let Ok(result) = result_rx.try_recv() {
                    apply_store_result(
                        scan_ctx,
                        &mut block_hash_cache,
                        &mut total_outputs_found,
                        &mut total_parse_errors,
                        &mut total_empty_blobs,
                        &result,
                    )?;
                }

                let scan_ctx_clone = scan_ctx.clone();
                let parse_results: Vec<ParsedBlockResult> = {
                    let mut handles = Vec::with_capacity(bin_blocks.len());
                    for (i, entry) in bin_blocks.iter().enumerate() {
                        let height = heights[i];
                        let header = if i < headers.len() {
                            headers[i].clone()
                        } else {
                            continue;
                        };
                        let entry_block = entry.block.clone();
                        let entry_txs = entry.txs.clone();
                        let ctx = scan_ctx_clone.clone();

                        handles.push(tokio::task::spawn_blocking(move || {
                            parse_and_scan_block(ctx, height, &entry_block, &entry_txs, &header)
                        }));
                    }

                    let mut results = Vec::with_capacity(handles.len());
                    for handle in handles {
                        match handle.await {
                            Ok(r) => results.push(r),
                            Err(e) => {
                                log::error!("block parse task panicked: {}", e);
                                results.push(ParsedBlockResult {
                                    height: 0,
                                    outputs: Vec::new(),
                                    tx_rows: Vec::new(),
                                    regular_txs: Vec::new(),
                                    block_hash: String::new(),
                                    parse_error: true,
                                    empty_blob: false,
                                    block_timestamp: 0,
                                    header_protocol_tx_hash: None,
                                    ptx_kos: Vec::new(),
                                });
                            }
                        }
                    }
                    results
                };

                let parse_ms = parse_timer.elapsed().as_millis() as u64;

                // ── 4. Send to store worker (pipelined) ─────────────────────
                // The store worker processes this batch on its dedicated thread
                // while we proceed to fetch+parse the next batch.
                if store_tx
                    .send(StoreBatchMsg {
                        parse_results,
                        scan_ctx: scan_ctx.clone(),
                        stake_lock_period,
                        batch_start,
                        batch_end,
                        fetch_ms,
                        parse_ms,
                        pool: pool.clone(),
                    })
                    .is_err()
                {
                    return Err(WalletError::Sync(
                        "store worker channel closed unexpectedly".into(),
                    ));
                }

                current = batch_end;

                // ── 5. Progress event (one per batch) ───────────────────────
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

                // ── 6. Adapt batch size + race nodes ────────────────────────
                controller.adjust(batch_timer.elapsed().as_millis() as u64, false);
                pool.maybe_race().await;
            }

            Ok(top_block)
        }
        .await;

        // ── Shutdown store worker ───────────────────────────────────────
        // Drop the send channel to signal the worker to exit after finishing
        // its current batch.
        drop(store_tx);

        // Drain all remaining store results.
        while let Ok(result) = result_rx.recv() {
            if let Err(e) = apply_store_result(
                scan_ctx,
                &mut block_hash_cache,
                &mut total_outputs_found,
                &mut total_parse_errors,
                &mut total_empty_blobs,
                &result,
            ) {
                // If we already have an error from the sync loop, keep that;
                // otherwise propagate the store error.
                if sync_result.is_ok() {
                    let _ = store_handle.join();
                    return Err(e);
                }
            }
        }

        // Wait for the store thread to exit.
        let _ = store_handle.join();

        // Propagate sync loop error if any.
        let final_height = sync_result?;

        if let Some(tx) = event_tx {
            let _ = tx.send(SyncEvent::Complete { height: final_height }).await;
        }

        Ok(final_height)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parallel parse+scan types and functions
// ─────────────────────────────────────────────────────────────────────────────

/// Info needed to store a found output (extracted during parallel parse phase).
#[derive(Clone)]
struct FoundOutputInfo {
    tx_hash: [u8; 32],
    tx_pub_key: [u8; 32],
    block_timestamp: u64,
    is_coinbase: bool,
    block_height: u64,
    tx_type: u8,
    unlock_time: u64,
}

/// Data from a regular (non-coinbase) transaction carried from the parallel
/// parse phase to the sequential store phase. Includes the full parsed JSON
/// so `detect_spent_outputs` can run with DB access.
struct RegularTxData {
    tx_hash_hex: String,
    tx_pub_key: [u8; 32],
    fee: u64,
    tx_type: u8,
    unlock_time: u64,
    /// Found outputs and their storage info (may be empty if tx only spends).
    found_outputs: Vec<(FoundOutput, FoundOutputInfo)>,
    /// Full parsed transaction JSON — needed by detect_spent_outputs.
    tx_json: serde_json::Value,
}

/// Result of parsing and scanning a single block (produced in parallel).
struct ParsedBlockResult {
    height: u64,
    /// Coinbase/protocol found outputs (no spent detection needed).
    outputs: Vec<(FoundOutput, FoundOutputInfo)>,
    /// Coinbase/protocol transaction rows.
    tx_rows: Vec<salvium_crypto::storage::TransactionRow>,
    /// Regular transactions needing spent detection in store phase.
    regular_txs: Vec<RegularTxData>,
    block_hash: String,
    parse_error: bool,
    empty_blob: bool,
    block_timestamp: u64,
    header_protocol_tx_hash: Option<String>,
    /// (key_hex, stake_tx_hash, amount_staked) for TX-ID stake return matching.
    ptx_kos: Vec<(String, String, String)>,
}

/// Parse and scan a block entirely on a blocking thread.
/// This function is CPU-bound (no async, no DB writes).
fn parse_and_scan_block(
    scan_ctx: ScanContext,
    height: u64,
    block_blob: &[u8],
    tx_blobs: &[Vec<u8>],
    header: &salvium_rpc::daemon::BlockHeader,
) -> ParsedBlockResult {
    let mut outputs = Vec::new();
    let mut tx_rows = Vec::new();
    let mut regular_txs = Vec::new();
    let mut parse_error = false;
    let empty_blob = block_blob.is_empty();
    let block_hash = header.hash.clone();
    let block_timestamp = header.timestamp;
    let miner_tx_hash = header.miner_tx_hash.as_deref().unwrap_or("");
    let header_protocol_tx_hash = header.protocol_tx_hash.clone();
    let mut ptx_kos = Vec::new();

    if empty_blob {
        log::error!("empty block blob from RPC at height={}", height);
    }

    // Parse block blob.
    let block_json_str = salvium_crypto::parse_block_bytes(block_blob);

    if block_json_str.starts_with(r#"{"error":"#) {
        parse_error = true;
        log::error!(
            "block parse failed at height={} blob_len={} err={}",
            height,
            block_blob.len(),
            &block_json_str[..block_json_str.len().min(200)]
        );
    }

    let parsed: ParsedBlock = match serde_json::from_str(&block_json_str) {
        Ok(p) => p,
        Err(e) => {
            log::error!("block JSON parse failed at height={}: {}", height, e);
            return ParsedBlockResult {
                height,
                outputs,
                tx_rows,
                regular_txs,
                block_hash,
                parse_error: true,
                empty_blob,
                block_timestamp,
                header_protocol_tx_hash,
                ptx_kos,
            };
        }
    };

    // Scan miner transaction.
    if let Some(miner_tx_json) = &parsed.miner_tx {
        if !miner_tx_hash.is_empty() {
            if let Some(scan_data) =
                parse_tx_for_scanning(miner_tx_json, miner_tx_hash, height, true)
            {
                let found = scanner::scan_transaction(&scan_ctx, &scan_data);
                for fo in &found {
                    outputs.push((
                        fo.clone(),
                        FoundOutputInfo {
                            tx_hash: scan_data.tx_hash,
                            tx_pub_key: scan_data.tx_pub_key,
                            block_timestamp,
                            is_coinbase: true,
                            block_height: height,
                            tx_type: scan_data.tx_type,
                            unlock_time: scan_data.unlock_time,
                        },
                    ));
                }
                if !found.is_empty() {
                    let row = build_transaction_row(
                        miner_tx_hash,
                        &hex::encode(scan_data.tx_pub_key),
                        height,
                        block_timestamp,
                        &found,
                        &SpentInfo::default(),
                        0,
                        scan_data.tx_type,
                        true,
                        scan_data.unlock_time,
                    );
                    tx_rows.push(row);
                }
            }
        }
    }

    // Scan protocol transaction.
    if let Some(protocol_tx_json) = &parsed.protocol_tx {
        let ptx_prefix = protocol_tx_json.get("prefix").unwrap_or(protocol_tx_json);
        let ptx_vout = ptx_prefix.get("vout").and_then(|v| v.as_array());
        let ptx_vout_count = ptx_vout.map(|a| a.len()).unwrap_or(0);

        let protocol_tx_hash_opt = header_protocol_tx_hash
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .or_else(|| compute_coinbase_tx_hash(protocol_tx_json));

        // TX-ID based stake return matching (collect Ko keys for store phase).
        if ptx_vout_count > 0 {
            if let Some(ref ptx_hash) = protocol_tx_hash_opt {
                if let Some(vout_arr) = ptx_vout {
                    for out in vout_arr {
                        if let Some(key_hex) = out.get("key").and_then(|v| v.as_str()) {
                            // We can't query the DB here (no DB access in parallel phase),
                            // so collect the key for the store phase.
                            ptx_kos.push((
                                key_hex.to_string(),
                                ptx_hash.clone(),
                                String::new(), // will be filled from DB lookup in store phase
                            ));
                        }
                    }
                }
            }
        }

        // CARROT/CN scanning for protocol TX.
        if let Some(ref ptx_hash) = protocol_tx_hash_opt {
            if let Some(scan_data) = parse_tx_for_scanning(protocol_tx_json, ptx_hash, height, true)
            {
                let found = scanner::scan_transaction(&scan_ctx, &scan_data);
                for fo in &found {
                    outputs.push((
                        fo.clone(),
                        FoundOutputInfo {
                            tx_hash: scan_data.tx_hash,
                            tx_pub_key: scan_data.tx_pub_key,
                            block_timestamp,
                            is_coinbase: true,
                            block_height: height,
                            tx_type: scan_data.tx_type,
                            unlock_time: scan_data.unlock_time,
                        },
                    ));
                }
                if !found.is_empty() {
                    let row = build_transaction_row(
                        ptx_hash,
                        &hex::encode(scan_data.tx_pub_key),
                        height,
                        block_timestamp,
                        &found,
                        &SpentInfo::default(),
                        0,
                        scan_data.tx_type,
                        true,
                        scan_data.unlock_time,
                    );
                    tx_rows.push(row);
                }
            }
        }
    }

    // Build tx hash list.
    let tx_hashes: Vec<String> =
        parsed.tx_hashes.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();

    // Scan regular transactions — carry forward tx_json for spent detection
    // in the sequential store phase (detect_spent_outputs needs DB access).
    for (i, tx_blob) in tx_blobs.iter().enumerate() {
        let tx_json_str = salvium_crypto::parse_transaction_bytes(tx_blob);

        if tx_json_str.starts_with(r#"{"error":"#) {
            parse_error = true;
            log::error!(
                "tx parse failed at height={} tx_idx={} blob_len={}",
                height,
                i,
                tx_blob.len()
            );
            continue;
        }

        match serde_json::from_str::<serde_json::Value>(&tx_json_str) {
            Ok(tx_json) => {
                let tx_hash_hex = if i < tx_hashes.len() {
                    &tx_hashes[i]
                } else {
                    continue;
                };

                let fee = extract_fee(&tx_json);
                let scan_result = parse_tx_for_scanning(&tx_json, tx_hash_hex, height, false);

                let mut found_pairs = Vec::new();
                let (tx_pub_key, tx_type, unlock_time) = if let Some(ref sd) = scan_result {
                    let found = scanner::scan_transaction(&scan_ctx, sd);
                    for fo in &found {
                        found_pairs.push((
                            fo.clone(),
                            FoundOutputInfo {
                                tx_hash: sd.tx_hash,
                                tx_pub_key: sd.tx_pub_key,
                                block_timestamp,
                                is_coinbase: false,
                                block_height: height,
                                tx_type: sd.tx_type,
                                unlock_time: sd.unlock_time,
                            },
                        ));
                    }
                    (sd.tx_pub_key, sd.tx_type, sd.unlock_time)
                } else {
                    // parse_tx_for_scanning failed — still carry forward for spent detection.
                    let prefix = tx_json.get("prefix").unwrap_or(&tx_json);
                    let tt = prefix
                        .get("txType")
                        .or_else(|| prefix.get("tx_type"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(3) as u8;
                    ([0u8; 32], tt, 0u64)
                };

                regular_txs.push(RegularTxData {
                    tx_hash_hex: tx_hash_hex.to_string(),
                    tx_pub_key,
                    fee,
                    tx_type,
                    unlock_time,
                    found_outputs: found_pairs,
                    tx_json,
                });
            }
            Err(e) => {
                parse_error = true;
                log::error!("tx JSON deserialize failed at height={} tx_idx={}: {}", height, i, e);
            }
        }
    }

    ParsedBlockResult {
        height,
        outputs,
        tx_rows,
        regular_txs,
        block_hash,
        parse_error,
        empty_blob,
        block_timestamp,
        header_protocol_tx_hash,
        ptx_kos,
    }
}

/// Execute the store phase for one batch: write all parsed block data to the DB.
///
/// Called by the store worker thread with the DB lock already held.
/// Returns aggregated stats and block hashes for the sync loop.
#[cfg(not(target_arch = "wasm32"))]
fn execute_store_batch(
    db: &salvium_crypto::storage::WalletDb,
    scan_ctx: &mut ScanContext,
    parse_results: &[ParsedBlockResult],
    stake_lock_period: u64,
) -> Result<StoreBatchResult, WalletError> {
    let mut max_height = 0u64;
    let mut outputs_found = 0usize;
    let mut parse_errors = 0usize;
    let mut empty_blobs = 0usize;
    let mut block_hashes = Vec::new();

    for pr in parse_results {
        if pr.empty_blob {
            empty_blobs += 1;
        }
        if pr.parse_error {
            parse_errors += 1;
        }
        if pr.height > max_height {
            max_height = pr.height;
        }

        // Store coinbase/protocol found outputs.
        for (found_output, scan_data_info) in &pr.outputs {
            store_found_output_row(db, scan_ctx, found_output, scan_data_info)?;
        }

        // Store coinbase/protocol transaction rows.
        for row in &pr.tx_rows {
            db.put_tx(row).map_err(|e| WalletError::Storage(e.to_string()))?;
        }

        // Process regular transactions: store outputs, detect spent, build tx rows.
        for tx_data in &pr.regular_txs {
            for (found_output, info) in &tx_data.found_outputs {
                store_found_output_row(db, scan_ctx, found_output, info)?;
            }

            let spent_info =
                detect_spent_outputs(db, &tx_data.tx_json, &tx_data.tx_hash_hex, pr.height)?;

            let found_outputs: Vec<&FoundOutput> =
                tx_data.found_outputs.iter().map(|(fo, _)| fo).collect();
            if !found_outputs.is_empty() || spent_info.count > 0 {
                let row = build_transaction_row(
                    &tx_data.tx_hash_hex,
                    &hex::encode(tx_data.tx_pub_key),
                    pr.height,
                    pr.block_timestamp,
                    &found_outputs.iter().map(|fo| (*fo).clone()).collect::<Vec<_>>(),
                    &spent_info,
                    tx_data.fee,
                    tx_data.tx_type,
                    false,
                    tx_data.unlock_time,
                );
                db.put_tx(&row).map_err(|e| WalletError::Storage(e.to_string()))?;
            }
        }

        // TX-ID stake return matching.
        for (key_hex, _ptx_hash_hint, _amount_hint) in &pr.ptx_kos {
            let ptx_hash = pr.header_protocol_tx_hash.as_deref().unwrap_or("");
            if !ptx_hash.is_empty() {
                if let Ok(Some(stake)) = db.get_locked_stake_by_return_output_key(key_hex) {
                    if let Err(e) = db.mark_stake_returned(
                        &stake.stake_tx_hash,
                        ptx_hash,
                        pr.height as i64,
                        pr.block_timestamp as i64,
                        &stake.amount_staked,
                    ) {
                        log::warn!("failed to mark stake as returned: {}", e);
                    }
                }
            }
        }

        // Store block hash.
        if !pr.block_hash.is_empty() {
            db.put_block_hash(pr.height as i64, &pr.block_hash)
                .map_err(|e| WalletError::Storage(e.to_string()))?;
            block_hashes.push((pr.height, pr.block_hash.clone()));
        }

        // Count outputs: coinbase/protocol + regular.
        outputs_found +=
            pr.outputs.len() + pr.regular_txs.iter().map(|t| t.found_outputs.len()).sum::<usize>();
    }

    // Height-based stake return detection (once per batch, not per block).
    // Query locked stakes once, then check each against the batch's max height.
    // The per-block protocol_tx_hash is needed for the return record, so we
    // find the block at or just after the return height for each stake.
    if stake_lock_period > 0 && max_height > 0 {
        let locked_stakes =
            db.get_stakes(Some("locked"), None).map_err(|e| WalletError::Storage(e.to_string()))?;
        for stake in &locked_stakes {
            if stake.return_output_key.is_some() {
                continue;
            }
            if let Some(stake_height) = stake.stake_height {
                let return_height = stake_height as u64 + stake_lock_period + 1;
                if max_height >= return_height {
                    // Find the block at or just after the return height for its
                    // protocol_tx_hash and timestamp.
                    let matching_block = parse_results
                        .iter()
                        .filter(|pr| pr.height >= return_height)
                        .min_by_key(|pr| pr.height);
                    let (ptx_hash, block_height, block_timestamp) = match matching_block {
                        Some(pr) => (
                            pr.header_protocol_tx_hash.as_deref().unwrap_or("height-based-return"),
                            pr.height,
                            pr.block_timestamp,
                        ),
                        None => ("height-based-return", max_height, 0),
                    };
                    if let Err(e) = db.mark_stake_returned(
                        &stake.stake_tx_hash,
                        ptx_hash,
                        block_height as i64,
                        block_timestamp as i64,
                        &stake.amount_staked,
                    ) {
                        log::warn!("failed to mark stake as returned: {}", e);
                    }
                }
            }
        }
    }

    // Set sync height once at end of batch.
    if max_height > 0 {
        db.set_sync_height(max_height as i64).map_err(|e| WalletError::Storage(e.to_string()))?;
    }

    Ok(StoreBatchResult { max_height, outputs_found, parse_errors, empty_blobs, block_hashes })
}

/// Store worker loop: runs on a dedicated std::thread.
///
/// Receives `StoreBatchMsg` from the sync loop, locks the DB, writes data,
/// commits, resolves global indices, and sends `StoreResultMsg` back.
/// Exits when the channel closes (sender dropped).
#[cfg(not(target_arch = "wasm32"))]
fn store_worker_loop(
    db: Arc<std::sync::Mutex<salvium_crypto::storage::WalletDb>>,
    work_rx: std::sync::mpsc::Receiver<StoreBatchMsg>,
    result_tx: std::sync::mpsc::SyncSender<StoreResultMsg>,
) {
    while let Ok(mut msg) = work_rx.recv() {
        let store_timer = std::time::Instant::now();

        // Snapshot the cn_subaddress_map before store to diff afterwards.
        let cn_map_len_before = msg.scan_ctx.cn_subaddress_map.len();

        // Lock DB and execute the store batch inside a transaction.
        let store_result = (|| -> Result<StoreBatchResult, WalletError> {
            let db_lock = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
            db_lock.begin_batch().map_err(|e| WalletError::Storage(e.to_string()))?;

            match execute_store_batch(
                &db_lock,
                &mut msg.scan_ctx,
                &msg.parse_results,
                msg.stake_lock_period,
            ) {
                Ok(result) => {
                    db_lock.commit_batch().map_err(|e| WalletError::Storage(e.to_string()))?;
                    Ok(result)
                }
                Err(e) => {
                    let _ = db_lock.rollback_batch();
                    Err(e)
                }
            }
        })();

        match store_result {
            Ok(batch_result) => {
                // Resolve global indices (needs async RPC — create a temporary tokio runtime).
                if batch_result.outputs_found > 0 {
                    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build();
                    if let Ok(rt) = rt {
                        if let Err(e) = rt.block_on(resolve_global_indices(&msg.pool, &db)) {
                            log::warn!("global index resolution failed: {}", e);
                        }
                    }
                }

                // Diff cn_subaddress_map to find new entries added during store.
                let new_entries: Vec<([u8; 32], u32, u32)> = msg
                    .scan_ctx
                    .cn_subaddress_map
                    .iter()
                    .skip(cn_map_len_before)
                    .cloned()
                    .collect();

                let store_ms = store_timer.elapsed().as_millis() as u64;
                log::info!(
                    "store worker batch {}-{}: fetch={}ms parse={}ms store={}ms ({} outputs)",
                    msg.batch_start,
                    msg.batch_end,
                    msg.fetch_ms,
                    msg.parse_ms,
                    store_ms,
                    batch_result.outputs_found
                );

                let _ = result_tx.send(StoreResultMsg {
                    new_cn_subaddr_entries: new_entries,
                    block_hashes: batch_result.block_hashes,
                    _committed_height: batch_result.max_height,
                    outputs_found: batch_result.outputs_found,
                    parse_errors: batch_result.parse_errors,
                    empty_blobs: batch_result.empty_blobs,
                    error: None,
                });
            }
            Err(e) => {
                log::error!(
                    "store worker batch {}-{} failed: {}",
                    msg.batch_start,
                    msg.batch_end,
                    e
                );
                let _ = result_tx.send(StoreResultMsg {
                    new_cn_subaddr_entries: Vec::new(),
                    block_hashes: Vec::new(),
                    _committed_height: 0,
                    outputs_found: 0,
                    parse_errors: 0,
                    empty_blobs: 0,
                    error: Some(e),
                });
            }
        }
    }
}

/// Apply a store result to the sync loop's state.
///
/// Merges new cn_subaddress_map entries, updates the block hash cache,
/// and accumulates output/error/blob counts.
#[cfg(not(target_arch = "wasm32"))]
fn apply_store_result(
    scan_ctx: &mut ScanContext,
    block_hash_cache: &mut std::collections::HashMap<u64, String>,
    total_outputs_found: &mut usize,
    total_parse_errors: &mut usize,
    total_empty_blobs: &mut usize,
    result: &StoreResultMsg,
) -> Result<(), WalletError> {
    if let Some(ref e) = result.error {
        return Err(WalletError::Sync(format!("store worker error: {}", e)));
    }

    // Merge new cn_subaddress_map entries.
    for &(ko, major, minor) in &result.new_cn_subaddr_entries {
        if !scan_ctx.cn_subaddress_map.iter().any(|(k, _, _)| *k == ko) {
            scan_ctx.cn_subaddress_map.push((ko, major, minor));
        }
    }

    // Update block hash cache.
    for (height, hash) in &result.block_hashes {
        block_hash_cache.insert(*height, hash.clone());
    }
    // Prune to ~2000 entries — remove the lowest heights.
    if block_hash_cache.len() > 2500 {
        let mut heights: Vec<u64> = block_hash_cache.keys().copied().collect();
        heights.sort_unstable();
        for &h in heights.iter().take(block_hash_cache.len() - 2000) {
            block_hash_cache.remove(&h);
        }
    }

    // Accumulate counts.
    *total_outputs_found += result.outputs_found;
    *total_parse_errors += result.parse_errors;
    *total_empty_blobs += result.empty_blobs;

    Ok(())
}

/// Store a single found output row into the DB (sequential phase).
#[cfg(not(target_arch = "wasm32"))]
fn store_found_output_row(
    db: &salvium_crypto::storage::WalletDb,
    scan_ctx: &mut ScanContext,
    found: &FoundOutput,
    info: &FoundOutputInfo,
) -> Result<(), WalletError> {
    // Build a minimal ScanTxData for store_found_outputs compatibility.
    let scan_data = ScanTxData {
        tx_hash: info.tx_hash,
        tx_pub_key: info.tx_pub_key,
        additional_pubkeys: vec![],
        outputs: vec![], // not needed for storage
        is_coinbase: info.is_coinbase,
        block_height: info.block_height,
        first_key_image: None,
        tx_type: info.tx_type,
        unlock_time: info.unlock_time,
    };

    store_found_outputs(
        db,
        scan_ctx,
        std::slice::from_ref(found),
        &scan_data,
        info.block_timestamp,
    )?;
    Ok(())
}

/// Information about spent outputs detected in a transaction.
#[derive(Debug, Default)]
struct SpentInfo {
    count: usize,
    total_amount: u64,
    asset_type: Option<String>,
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
    let first_key_image = if !is_coinbase { extract_first_key_image(prefix) } else { None };

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
    let vout = prefix.get("vout").or_else(|| tx_json.get("vout")).and_then(|v| v.as_array())?;

    // Legacy ECDH info and output commitments.
    let rct_section = tx_json.get("rct").or_else(|| tx_json.get("rct_signatures"));
    let ecdh_info = rct_section.and_then(|r| r.get("ecdhInfo")).and_then(|e| e.as_array());
    let out_pk = rct_section.and_then(|r| r.get("outPk")).and_then(|e| e.as_array());

    let mut outputs = Vec::with_capacity(vout.len());
    for (i, out) in vout.iter().enumerate() {
        // Amount: try string first (new format), then integer (legacy).
        let amount = out
            .get("amount")
            .and_then(|a| a.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| a.as_u64()))
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
            out.get("viewTag").and_then(|v| v.as_str()).and_then(|s| hex::decode(s).ok()).and_then(
                |b| {
                    if b.len() == 3 {
                        let mut arr = [0u8; 3];
                        arr.copy_from_slice(&b);
                        Some(arr)
                    } else {
                        None
                    }
                },
            )
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
            out.get("ephemeralPubkey").and_then(|v| v.as_str()).and_then(hex_to_32)
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
        let commitment =
            out_pk.and_then(|pks| pks.get(i)).and_then(|v| v.as_str()).and_then(hex_to_32);

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
        let is_pubkey = entry.get("type").and_then(|v| v.as_u64()).map(|t| t == 1).unwrap_or(false)
            || entry.get("tag").and_then(|v| v.as_str()).map(|t| t == "tx_pubkey").unwrap_or(false);

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
        let bytes: Vec<u8> = extra.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
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
        let is_additional =
            entry.get("type").and_then(|v| v.as_u64()).map(|t| t == 4).unwrap_or(false)
                || entry
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .map(|t| t == "additional_pubkeys")
                    .unwrap_or(false);

        if is_additional {
            if let Some(keys) = entry.get("keys").and_then(|v| v.as_array()) {
                return keys.iter().filter_map(|v| v.as_str().and_then(hex_to_32)).collect();
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
    if let Some(ki) = first.get("keyImage").and_then(|v| v.as_str()).and_then(hex_to_32) {
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
///
/// Used by `detect_spent_outputs` in the store phase for key image matching.
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
            if let Some(ki) =
                key.get("k_image").or_else(|| key.get("keyImage")).and_then(|v| v.as_str())
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

        inputs.push(ParsedTxInput { key_image: ki_hex, ring_member_indices: absolute, asset_type });
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
/// Extract the transaction fee from parsed TX JSON.
///
/// Looks for `rct.txnFee` or `rct_signatures.txnFee`. Returns 0 for
/// coinbase/protocol transactions (which have no fee).
fn extract_fee(tx_json: &serde_json::Value) -> u64 {
    tx_json
        .get("rct")
        .or_else(|| tx_json.get("rct_signatures"))
        .and_then(|r| r.get("txnFee").or_else(|| r.get("txn_fee")))
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0)
}

/// Build a `TransactionRow` from sync data for persistence.
#[allow(clippy::too_many_arguments)]
fn build_transaction_row(
    tx_hash_hex: &str,
    tx_pub_key_hex: &str,
    block_height: u64,
    block_timestamp: u64,
    found: &[FoundOutput],
    spent_info: &SpentInfo,
    fee: u64,
    tx_type: u8,
    is_coinbase: bool,
    unlock_time: u64,
) -> salvium_crypto::storage::TransactionRow {
    let has_outputs = !found.is_empty();
    let is_outgoing = spent_info.count > 0;
    let incoming_amount: u64 = found.iter().map(|o| o.amount).sum();
    let outgoing_amount = spent_info.total_amount;
    // When we're the sender, received outputs are change back to us.
    // Don't mark as "incoming" when all received outputs are change —
    // the user sent funds, they didn't receive anything.
    let change_amount = if is_outgoing { incoming_amount } else { 0 };
    let is_incoming = if is_outgoing {
        // Only mark as incoming if we received MORE than we spent (net positive).
        // This handles self-transfers (stake returns, etc.) correctly.
        incoming_amount > outgoing_amount
    } else {
        has_outputs
    };

    // Asset type: prefer spent asset type, then first found output, then "SAL"
    let asset_type = spent_info
        .asset_type
        .clone()
        .or_else(|| found.first().map(|o| o.asset_type.clone()))
        .unwrap_or_else(|| "SAL".to_string());

    let is_miner_tx = is_coinbase && tx_type == 1;
    let is_protocol_tx = tx_type == 2;

    salvium_crypto::storage::TransactionRow {
        tx_hash: tx_hash_hex.to_string(),
        tx_pub_key: Some(tx_pub_key_hex.to_string()),
        block_height: Some(block_height as i64),
        block_timestamp: Some(block_timestamp as i64),
        confirmations: 0,
        in_pool: false,
        is_failed: false,
        is_confirmed: true,
        is_incoming,
        is_outgoing,
        incoming_amount: incoming_amount.to_string(),
        outgoing_amount: outgoing_amount.to_string(),
        fee: fee.to_string(),
        change_amount: change_amount.to_string(),
        transfers: None,
        payment_id: None,
        unlock_time: unlock_time.to_string(),
        tx_type: tx_type as i64,
        asset_type,
        is_miner_tx,
        is_protocol_tx,
        note: String::new(),
        created_at: None,
        updated_at: None,
    }
}

/// Fix #4: When a STAKE TX (tx_type=6) spends our output, record the stake
/// in the stakes table so staked amounts appear in the total balance.
/// C++ ref: wallet2.cpp:2759-2764 (m_locked_coins tracking)
///
/// Uses `tx.amount_burnt` (not sum of spent inputs) as the staked amount,
///// matching C++: `m_locked_coins.insert({pk, {0, tx.amount_burnt, tx.source_asset_type}})`.
/// Using spent input amounts would overcount by (fee + change), since the
/// change output is already counted in unspent outputs.
///
/// Called during the sequential store phase for each regular transaction.
#[cfg(not(target_arch = "wasm32"))]
fn detect_spent_outputs(
    db: &salvium_crypto::storage::WalletDb,
    tx_json: &serde_json::Value,
    tx_hash_hex: &str,
    block_height: u64,
) -> Result<SpentInfo, WalletError> {
    let prefix = tx_json.get("prefix").unwrap_or(tx_json);
    let key_images = extract_all_key_images(prefix);

    if key_images.is_empty() {
        return Ok(SpentInfo::default());
    }

    // Determine tx_type for STAKE tracking.
    let tx_type = prefix
        .get("txType")
        .or_else(|| prefix.get("tx_type"))
        .and_then(|v| v.as_u64())
        .unwrap_or(3);

    let mut spent_info = SpentInfo::default();

    // ── Pass 1: Key image matching (primary mechanism) ──────────────────
    let mut matched_key_images = std::collections::HashSet::new();
    for ki_hex in &key_images {
        // Check if this key image belongs to one of our outputs.
        let output = db.get_output(ki_hex).map_err(|e| WalletError::Storage(e.to_string()))?;
        if let Some(row) = output {
            // Count all outputs that belong to us, even if already marked spent
            // (e.g. by mark_inputs_spent after TX submission). This ensures
            // stake recording still triggers when the block is later synced.
            spent_info.count += 1;
            spent_info.total_amount += row.amount.parse::<u64>().unwrap_or(0);
            if spent_info.asset_type.is_none() {
                spent_info.asset_type = Some(row.asset_type.clone());
            }
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
    if spent_info.count > 0 && (tx_type == 6 || tx_type == 8) {
        let amount_burnt: u64 = prefix
            .get("amount_burnt")
            .and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64()))
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
            db.put_stake(&stake_row).map_err(|e| WalletError::Storage(e.to_string()))?;
            log::info!(
                "stake tracked: tx={} amount_burnt={} asset={} return_key={}",
                &tx_hash_hex[..16],
                amount_burnt,
                source_asset_type,
                return_output_key.as_deref().map(|k| &k[..k.len().min(16)]).unwrap_or("none")
            );
        }
    }

    Ok(spent_info)
}

/// Store found outputs in the database.
///
/// Includes Fix #1 (per-output unlock_time), Fix #2 (return output detection),
/// and Fix #3 (burning bug detection).
#[cfg(not(target_arch = "wasm32"))]
fn store_found_outputs(
    db: &salvium_crypto::storage::WalletDb,
    scan_ctx: &mut ScanContext,
    found: &[FoundOutput],
    tx: &ScanTxData,
    block_timestamp: u64,
) -> Result<(), WalletError> {
    if found.is_empty() {
        return Ok(());
    }

    for output in found {
        let pub_key_hex = hex::encode(output.output_public_key);

        // Log non-coinbase CARROT matches for diagnostics.
        if output.is_carrot && !tx.is_coinbase {
            let scan_path = if output.is_carrot_internal { "INTERNAL" } else { "EXTERNAL" };
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
            commitment: tx
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
        db.put_output(&row).map_err(|e| WalletError::Storage(e.to_string()))?;

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
            if !scan_ctx.cn_subaddress_map.iter().any(|(k, _, _)| *k == output.output_public_key) {
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

        // Pre-CARROT PROTOCOL return key image override + origin-based stake matching.
        // C++ ref: wallet2.cpp:2684-2719, generate_key_image_helper_precomp use_origin_data
        // For non-CARROT outputs in PROTOCOL_TX (tx_type=2), the key image
        // must use two-step derivation through the origin STAKE/AUDIT/CONVERT TX.
        //
        // CRITICAL: Protocol TXs often use per-output keys (additional_pubkeys)
        // instead of the shared tx_pub_key. We must use the same pubkey that
        // was used to detect the output, otherwise the P_change recovery and
        // step-2 derivation will be wrong and the key image override won't fire.
        let mut origin_stake_tx_hash: Option<String> = None;
        if tx.tx_type == 2 && !output.is_carrot {
            if let Some(ref spend_secret) = scan_ctx.cn_spend_secret {
                // Use the derivation pubkey that actually matched this output
                // (shared tx_pub_key or per-output additional_pubkey).
                let deriv_pubkey = output.cn_derivation_pubkey.as_ref().unwrap_or(&tx.tx_pub_key);
                let derivation =
                    salvium_crypto::generate_key_derivation(deriv_pubkey, &scan_ctx.cn_view_secret);
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
                        // Look up the origin output to get the stake TX hash.
                        // This links the return directly to its origin stake.
                        if let Ok(Some(origin_output)) = db.get_output_by_public_key(&p_change_hex)
                        {
                            origin_stake_tx_hash = Some(origin_output.tx_hash.clone());
                        }

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
                                // Step 2: x_return = derive_output_spend_key(view, &sk_change, deriv_pubkey, 0, 0, 0)
                                let x_return = salvium_crypto::cn_scan::derive_output_spend_key(
                                    &scan_ctx.cn_view_secret,
                                    &sk_change,
                                    deriv_pubkey,
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
        // it may be a return of previously staked funds.
        //
        // Primary: match via origin TX hash from salvium_txs (precise, links
        // return to exact stake). Falls back to asset-type matching (oldest first).
        if tx.tx_type == 2 {
            log::info!(
                "protocol_tx output found: height={} amount={} asset={} out_idx={} origin_tx={}",
                tx.block_height,
                output.amount,
                output.asset_type,
                output.output_index,
                origin_stake_tx_hash.as_deref().map(|h| &h[..h.len().min(16)]).unwrap_or("none")
            );

            let tx_hash_hex = hex::encode(tx.tx_hash);
            let mut matched = false;

            // Primary: match by origin TX hash (precise).
            if let Some(ref stake_tx_hash) = origin_stake_tx_hash {
                if let Ok(stakes) = db.get_stakes(Some("locked"), None) {
                    if let Some(stake) = stakes.iter().find(|s| &s.stake_tx_hash == stake_tx_hash) {
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
                                "stake return (origin match): stake_tx={} return_tx={} amount={} asset={}",
                                &stake.stake_tx_hash[..stake.stake_tx_hash.len().min(16)],
                                &tx_hash_hex[..16],
                                output.amount,
                                output.asset_type
                            );
                            matched = true;
                        }
                    }
                }
            }

            // Fallback: match by asset type (oldest first).
            if !matched {
                if let Ok(stakes) = db.get_stakes(Some("locked"), Some(&output.asset_type)) {
                    if let Some(stake) = stakes.first() {
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
                                "stake return (asset fallback): stake_tx={} return_tx={} amount={} asset={}",
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
    daemon: &NodePool,
    db: &Arc<std::sync::Mutex<salvium_crypto::storage::WalletDb>>,
) -> Result<usize, WalletError> {
    // Get outputs that need global_index resolution.
    let pending = {
        let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_outputs_needing_global_index().map_err(|e| WalletError::Storage(e.to_string()))?
    };

    if pending.is_empty() {
        return Ok(0);
    }

    // Group by tx_hash for batched lookup.
    let mut by_tx: std::collections::HashMap<String, Vec<(String, i64)>> =
        std::collections::HashMap::new();
    for (key_image, tx_hash, output_index) in &pending {
        by_tx.entry(tx_hash.clone()).or_default().push((key_image.clone(), *output_index));
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
    daemon: &NodePool,
    db: &Arc<std::sync::Mutex<salvium_crypto::storage::WalletDb>>,
    mut height: u64,
) -> Result<u64, WalletError> {
    while height > 0 {
        let stored_hash = {
            let db = db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
            db.get_block_hash(height as i64).map_err(|e| WalletError::Storage(e.to_string()))?
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
        let _started = SyncEvent::Started { target_height: 1000 };
        let _progress = SyncEvent::Progress {
            current_height: 500,
            target_height: 1000,
            outputs_found: 3,
            parse_errors: 0,
            empty_blobs: 0,
        };
        let _complete = SyncEvent::Complete { height: 1000 };
        let _reorg = SyncEvent::Reorg { from_height: 1000, to_height: 990 };
    }

    #[test]
    fn test_sync_event_all_variants() {
        // Create every SyncEvent variant and verify fields via Debug format.
        let started = SyncEvent::Started { target_height: 5000 };
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

        let reorg = SyncEvent::Reorg { from_height: 5000, to_height: 4990 };
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
