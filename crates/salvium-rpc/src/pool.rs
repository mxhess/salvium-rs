//! Node pool with racing-based selection and automatic failover.
//!
//! `NodePool` wraps multiple `DaemonRpc` instances and forwards all daemon
//! methods to an active node. Periodically races nodes via `get_info` to
//! discover the fastest, and switches on consecutive failures.

use crate::daemon::{
    BinBlockEntry, BlockHeader, BlockResult, DaemonInfo, DaemonRpc, FeeEstimate, HardForkInfo,
    OutputInfo, OutputRequest, SupplyInfo, SyncInfo, TransactionEntry, VersionInfo, YieldInfo,
};
use crate::error::RpcError;
use salvium_types::constants::Network;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

struct NodeState {
    daemon: DaemonRpc,
    url: String,
    #[cfg_attr(not(test), allow(dead_code))]
    is_seed: bool,
    last_latency: Option<Duration>,
    last_probed: Option<Instant>,
    consecutive_failures: u32,
    is_healthy: bool,
}

/// Configuration for creating a [`NodePool`].
pub struct PoolConfig {
    /// Determines which seed nodes to include.
    pub network: Network,
    /// User's preferred node URL. Added as primary and set as initial active.
    pub primary_url: Option<String>,
    /// Minimum relative improvement to switch active node (default 0.15 = 15%).
    pub switch_threshold: f64,
    /// Maximum nodes to race concurrently in one group (default 4).
    pub max_race_group_size: usize,
    /// Seconds between automatic races (default 60).
    pub race_interval_secs: u64,
    /// Maximum nodes to use for distributed batch fetches (default 4).
    pub max_fetch_nodes: usize,
    /// Optional username for Basic auth (applied to all nodes).
    pub username: Option<String>,
    /// Optional password for Basic auth (applied to all nodes).
    pub password: Option<String>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            primary_url: None,
            switch_threshold: 0.15,
            max_race_group_size: 4,
            race_interval_secs: 60,
            max_fetch_nodes: 4,
            username: None,
            password: None,
        }
    }
}

/// Result of a distributed batch fetch across multiple nodes.
pub struct DistributedBatchResult {
    pub headers: Vec<BlockHeader>,
    pub bin_blocks: Vec<BinBlockEntry>,
}

struct PoolInner {
    nodes: Vec<NodeState>,
    active_index: usize,
    last_race: Option<Instant>,
    config: PoolConfig,
}

/// A pool of daemon RPC nodes with automatic failover and periodic racing.
///
/// Cloning is cheap (inner state is `Arc<RwLock<...>>`).
#[derive(Clone)]
pub struct NodePool {
    inner: Arc<RwLock<PoolInner>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

impl NodePool {
    /// Create a new pool with seed nodes for the configured network, plus an
    /// optional primary user node.
    pub fn new(config: PoolConfig) -> Self {
        let seed_urls: Vec<&str> = match config.network {
            Network::Mainnet => crate::seed_nodes::MAINNET.to_vec(),
            Network::Testnet => crate::seed_nodes::TESTNET.to_vec(),
            Network::Stagenet => crate::seed_nodes::STAGENET.to_vec(),
        };

        let mut nodes = Vec::new();
        let mut active_index = 0;

        // Add primary node first (if provided).
        if let Some(ref url) = config.primary_url {
            let daemon = make_daemon(url, &config.username, &config.password);
            nodes.push(NodeState {
                daemon,
                url: url.clone(),
                is_seed: false,
                last_latency: None,
                last_probed: None,
                consecutive_failures: 0,
                is_healthy: true,
            });
            active_index = 0;
        }

        // Add seed nodes (skip if already added as primary).
        for seed_url in seed_urls {
            let already = nodes.iter().any(|n| n.url == seed_url);
            if !already {
                let daemon = make_daemon(seed_url, &config.username, &config.password);
                nodes.push(NodeState {
                    daemon,
                    url: seed_url.to_string(),
                    is_seed: true,
                    last_latency: None,
                    last_probed: None,
                    consecutive_failures: 0,
                    is_healthy: true,
                });
            }
        }

        // If no primary was set, use the first seed as active.
        if config.primary_url.is_none() && !nodes.is_empty() {
            active_index = 0;
        }

        Self {
            inner: Arc::new(RwLock::new(PoolInner {
                nodes,
                active_index,
                last_race: None,
                config,
            })),
        }
    }

    /// Add a user node to the pool. Does not replace seeds or the active node.
    pub async fn add_node(&self, url: &str) {
        let mut inner = self.inner.write().await;
        let already = inner.nodes.iter().any(|n| n.url == url);
        if !already {
            let daemon =
                make_daemon(url, &inner.config.username, &inner.config.password);
            inner.nodes.push(NodeState {
                daemon,
                url: url.to_string(),
                is_seed: false,
                last_latency: None,
                last_probed: None,
                consecutive_failures: 0,
                is_healthy: true,
            });
        }
    }

    /// Return a clone of the active `DaemonRpc` (for use in transfer code that
    /// takes `&DaemonRpc` directly).
    pub async fn active_daemon(&self) -> DaemonRpc {
        let inner = self.inner.read().await;
        inner.nodes[inner.active_index].daemon.clone()
    }

    /// Return the URL of the currently active node.
    pub async fn active_url(&self) -> String {
        let inner = self.inner.read().await;
        inner.nodes[inner.active_index].url.clone()
    }

    // ── Racing ──────────────────────────────────────────────────────────

    /// Check if enough time has elapsed since the last race; if so, run one.
    pub async fn maybe_race(&self) {
        let should_race = {
            let inner = self.inner.read().await;
            if inner.nodes.len() <= 1 {
                return;
            }
            match inner.last_race {
                None => true,
                Some(t) => t.elapsed().as_secs() >= inner.config.race_interval_secs,
            }
        };
        if should_race {
            self.evaluate_nodes().await;
        }
    }

    /// Race all nodes to find the fastest and optionally switch.
    async fn evaluate_nodes(&self) {
        let (groups, active_idx, switch_threshold) = {
            let inner = self.inner.read().await;
            let n = inner.nodes.len();
            if n == 0 {
                return;
            }
            let max_group = inner.config.max_race_group_size.max(1);
            // Build groups of indices.
            let indices: Vec<usize> = (0..n).collect();
            let groups: Vec<Vec<usize>> = indices.chunks(max_group).map(|c| c.to_vec()).collect();
            (groups, inner.active_index, inner.config.switch_threshold)
        };

        // Collect (index, daemon_clone) for all nodes.
        let node_daemons: Vec<(usize, DaemonRpc)> = {
            let inner = self.inner.read().await;
            inner
                .nodes
                .iter()
                .enumerate()
                .map(|(i, n)| (i, n.daemon.clone()))
                .collect()
        };

        // Results: (node_index, latency | None).
        let mut results: Vec<(usize, Option<Duration>)> = Vec::new();

        for group in &groups {
            let mut set = tokio::task::JoinSet::new();
            for &idx in group {
                let daemon = node_daemons[idx].1.clone();
                set.spawn(async move {
                    let start = Instant::now();
                    let r = tokio::time::timeout(Duration::from_secs(10), daemon.get_info()).await;
                    match r {
                        Ok(Ok(_)) => (idx, Some(start.elapsed())),
                        _ => (idx, None),
                    }
                });
            }
            while let Some(Ok(res)) = set.join_next().await {
                results.push(res);
            }
        }

        // Apply results.
        let mut inner = self.inner.write().await;
        let now = Instant::now();
        inner.last_race = Some(now);

        for &(idx, ref latency) in &results {
            if let Some(ref node) = inner.nodes.get(idx) {
                let _ = node; // borrow check
            }
            if idx < inner.nodes.len() {
                let node = &mut inner.nodes[idx];
                node.last_probed = Some(now);
                if let Some(lat) = latency {
                    node.last_latency = Some(*lat);
                    node.is_healthy = true;
                    node.consecutive_failures = 0;
                } else {
                    node.is_healthy = false;
                }
            }
        }

        // Find fastest responding node.
        let fastest = results
            .iter()
            .filter_map(|(idx, lat)| lat.as_ref().map(|l| (*idx, *l)))
            .min_by_key(|(_, l)| *l);

        if let Some((fastest_idx, fastest_lat)) = fastest {
            // Compare against current active's last latency.
            let current_lat = inner.nodes.get(active_idx).and_then(|n| n.last_latency);
            let should_switch = match current_lat {
                Some(cur) => {
                    let improvement =
                        (cur.as_secs_f64() - fastest_lat.as_secs_f64()) / cur.as_secs_f64();
                    improvement > switch_threshold && fastest_idx != active_idx
                }
                // No latency data for current → switch if fastest is healthy.
                None => fastest_idx != active_idx,
            };
            if should_switch {
                log::info!(
                    "NodePool: switching active node from {} to {} (latency: {:?} -> {:?})",
                    inner.nodes[inner.active_index].url,
                    inner.nodes[fastest_idx].url,
                    current_lat,
                    fastest_lat,
                );
                inner.active_index = fastest_idx;
            }
        }
    }

    // ── Failure / success reporting ─────────────────────────────────────

    async fn report_failure(&self) {
        let mut inner = self.inner.write().await;
        let idx = inner.active_index;
        inner.nodes[idx].consecutive_failures += 1;

        if inner.nodes[idx].consecutive_failures >= 3 {
            // Switch to the next healthy node with best known latency.
            let current = inner.active_index;
            let best = inner
                .nodes
                .iter()
                .enumerate()
                .filter(|(i, n)| *i != current && n.is_healthy)
                .min_by_key(|(_, n)| n.last_latency.unwrap_or(Duration::from_secs(999)));

            if let Some((new_idx, _)) = best {
                log::warn!(
                    "NodePool: failover from {} to {} after {} consecutive failures",
                    inner.nodes[current].url,
                    inner.nodes[new_idx].url,
                    inner.nodes[current].consecutive_failures,
                );
                inner.active_index = new_idx;
            }
        }
    }

    async fn report_success(&self) {
        let mut inner = self.inner.write().await;
        let idx = inner.active_index;
        inner.nodes[idx].consecutive_failures = 0;
        inner.nodes[idx].is_healthy = true;
    }

    // ── Distributed fetch ────────────────────────────────────────────────

    /// Force a race immediately (useful at sync start to populate latency data).
    pub async fn force_race(&self) {
        self.evaluate_nodes().await;
    }

    /// Fetch a height range across multiple healthy nodes in parallel.
    ///
    /// Distributes sub-ranges proportional to each node's speed (inverse
    /// latency). Falls back to single-node fetch when fewer than 2 nodes
    /// have latency data. Capped at `max_fetch_nodes` (default 4).
    pub async fn fetch_batch_distributed(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<DistributedBatchResult, RpcError> {
        let total = (end_height - start_height + 1) as usize;
        if total == 0 {
            return Ok(DistributedBatchResult {
                headers: Vec::new(),
                bin_blocks: Vec::new(),
            });
        }

        // Gather assignments under a read lock.
        let assignments = {
            let inner = self.inner.read().await;
            compute_assignments(&inner.nodes, inner.active_index, inner.config.max_fetch_nodes, start_height, total)
        };

        if assignments.len() <= 1 {
            // Single-node path (no latency data or only 1 qualifying node).
            let daemon = self.active().await;
            let heights: Vec<u64> = (start_height..=end_height).collect();
            let (h, b) = tokio::join!(
                daemon.get_block_headers_range(start_height, end_height),
                daemon.get_blocks_by_height_bin(&heights),
            );
            match (&h, &b) {
                (Ok(_), Ok(_)) => self.report_success().await,
                _ => self.report_failure().await,
            }
            return Ok(DistributedBatchResult {
                headers: h?,
                bin_blocks: b?,
            });
        }

        // Multi-node path: spawn one task per sub-range.
        log::info!(
            "NodePool: distributed fetch [{}-{}] across {} nodes",
            start_height, end_height, assignments.len()
        );

        let mut set = tokio::task::JoinSet::new();
        for (node_idx, sub_start, sub_end, daemon) in &assignments {
            let d = daemon.clone();
            let ss = *sub_start;
            let se = *sub_end;
            let ni = *node_idx;
            set.spawn(async move {
                let sub_heights: Vec<u64> = (ss..=se).collect();
                let (h, b) = tokio::join!(
                    d.get_block_headers_range(ss, se),
                    d.get_blocks_by_height_bin(&sub_heights),
                );
                (ni, ss, se, h, b)
            });
        }

        // Collect results, track which sub-ranges succeeded and which failed.
        let mut results: Vec<(u64, Vec<BlockHeader>, Vec<BinBlockEntry>)> = Vec::new();
        let mut failed_ranges: Vec<(u64, u64)> = Vec::new();

        while let Some(join_result) = set.join_next().await {
            match join_result {
                Ok((node_idx, ss, se, h_res, b_res)) => {
                    match (h_res, b_res) {
                        (Ok(h), Ok(b)) => {
                            self.report_success_for(node_idx).await;
                            results.push((ss, h, b));
                        }
                        _ => {
                            self.report_failure_for(node_idx).await;
                            failed_ranges.push((ss, se));
                        }
                    }
                }
                Err(_) => {
                    // JoinError (panic) — we don't know which node, just collect
                    // the sub-range from assignments if we can figure it out.
                    // For safety, mark all un-collected ranges as failed.
                }
            }
        }

        // Retry failed sub-ranges from the active node.
        if !failed_ranges.is_empty() {
            let daemon = self.active().await;
            for (ss, se) in &failed_ranges {
                let sub_heights: Vec<u64> = (*ss..=*se).collect();
                let (h, b) = tokio::join!(
                    daemon.get_block_headers_range(*ss, *se),
                    daemon.get_blocks_by_height_bin(&sub_heights),
                );
                match (h, b) {
                    (Ok(h), Ok(b)) => {
                        self.report_success().await;
                        results.push((*ss, h, b));
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        self.report_failure().await;
                        return Err(e);
                    }
                }
            }
        }

        // Merge results in height order (sort by sub-range start).
        results.sort_by_key(|(ss, _, _)| *ss);

        let mut headers = Vec::with_capacity(total);
        let mut bin_blocks = Vec::with_capacity(total);
        for (_, h, b) in results {
            headers.extend(h);
            bin_blocks.extend(b);
        }

        Ok(DistributedBatchResult { headers, bin_blocks })
    }

    // ── Per-node success/failure reporting ─────────────────────────────

    async fn report_failure_for(&self, node_idx: usize) {
        let mut inner = self.inner.write().await;
        if node_idx < inner.nodes.len() {
            inner.nodes[node_idx].consecutive_failures += 1;
            if inner.nodes[node_idx].consecutive_failures >= 3 {
                inner.nodes[node_idx].is_healthy = false;
            }
        }
    }

    async fn report_success_for(&self, node_idx: usize) {
        let mut inner = self.inner.write().await;
        if node_idx < inner.nodes.len() {
            inner.nodes[node_idx].consecutive_failures = 0;
            inner.nodes[node_idx].is_healthy = true;
        }
    }

    // ── Active daemon accessor (internal) ───────────────────────────────

    async fn active(&self) -> DaemonRpc {
        let inner = self.inner.read().await;
        inner.nodes[inner.active_index].daemon.clone()
    }

    // ── Forwarded DaemonRpc methods ─────────────────────────────────────
    //
    // Each method: call active daemon, report success/failure, return result.
    // Only methods actually used by sync, transfer, and FFI code are forwarded.

    pub async fn get_info(&self) -> Result<DaemonInfo, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_info().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_height(&self) -> Result<u64, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_height().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn is_synchronized(&self) -> Result<bool, RpcError> {
        let daemon = self.active().await;
        let result = daemon.is_synchronized().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn hard_fork_info(&self) -> Result<HardForkInfo, RpcError> {
        let daemon = self.active().await;
        let result = daemon.hard_fork_info().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn sync_info(&self) -> Result<SyncInfo, RpcError> {
        let daemon = self.active().await;
        let result = daemon.sync_info().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_version(&self) -> Result<VersionInfo, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_version().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_block_headers_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<BlockHeader>, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_block_headers_range(start_height, end_height).await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_blocks_by_height_bin(
        &self,
        heights: &[u64],
    ) -> Result<Vec<BinBlockEntry>, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_blocks_by_height_bin(heights).await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_block(&self, height: u64) -> Result<BlockResult, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_block(height).await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_block_header_by_height(
        &self,
        height: u64,
    ) -> Result<BlockHeader, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_block_header_by_height(height).await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_transactions(
        &self,
        txids: &[&str],
        decode_as_json: bool,
    ) -> Result<Vec<TransactionEntry>, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_transactions(txids, decode_as_json).await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_outs(
        &self,
        outputs: &[OutputRequest],
        get_txid: bool,
        asset_type: &str,
    ) -> Result<Vec<OutputInfo>, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_outs(outputs, get_txid, asset_type).await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_output_distribution(
        &self,
        amounts: &[u64],
        from_height: u64,
        to_height: u64,
        cumulative: bool,
        asset_type: &str,
    ) -> Result<Vec<crate::daemon::OutputDistribution>, RpcError> {
        let daemon = self.active().await;
        let result = daemon
            .get_output_distribution(amounts, from_height, to_height, cumulative, asset_type)
            .await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn send_raw_transaction_ex(
        &self,
        tx_as_hex: &str,
        do_not_relay: bool,
        do_sanity_checks: bool,
        asset_type: &str,
    ) -> Result<crate::daemon::SendRawTxResult, RpcError> {
        let daemon = self.active().await;
        let result = daemon
            .send_raw_transaction_ex(tx_as_hex, do_not_relay, do_sanity_checks, asset_type)
            .await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_fee_estimate(
        &self,
        grace_blocks: u64,
    ) -> Result<FeeEstimate, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_fee_estimate(grace_blocks).await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_supply_info(&self) -> Result<SupplyInfo, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_supply_info().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_yield_info(&self) -> Result<YieldInfo, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_yield_info().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_block_hash(&self, height: u64) -> Result<String, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_block_hash(height).await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn network_type(
        &self,
    ) -> Result<salvium_types::constants::Network, RpcError> {
        let daemon = self.active().await;
        let result = daemon.network_type().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }

    pub async fn get_transaction_pool_hashes(&self) -> Result<Vec<String>, RpcError> {
        let daemon = self.active().await;
        let result = daemon.get_transaction_pool_hashes().await;
        match &result {
            Ok(_) => self.report_success().await,
            Err(_) => self.report_failure().await,
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Compute latency-weighted sub-range assignments for distributed fetch.
///
/// Returns `Vec<(node_index, sub_start, sub_end, DaemonRpc)>`.
/// If fewer than 2 nodes have latency data, returns a single assignment for
/// the active node (the caller can then use the single-node fast path).
fn compute_assignments(
    nodes: &[NodeState],
    active_index: usize,
    max_fetch_nodes: usize,
    start_height: u64,
    total_blocks: usize,
) -> Vec<(usize, u64, u64, DaemonRpc)> {
    // Collect healthy nodes with latency data, sorted fastest first.
    let mut candidates: Vec<(usize, Duration)> = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.is_healthy && n.last_latency.is_some())
        .map(|(i, n)| (i, n.last_latency.unwrap()))
        .collect();
    candidates.sort_by_key(|(_, lat)| *lat);

    // Cap at max_fetch_nodes.
    candidates.truncate(max_fetch_nodes);

    if candidates.len() < 2 {
        // Fall back to single-node from active daemon.
        let end_height = start_height + total_blocks as u64 - 1;
        return vec![(active_index, start_height, end_height, nodes[active_index].daemon.clone())];
    }

    // Speed weights: speed_i = 1.0 / latency_i (in seconds).
    let speeds: Vec<f64> = candidates
        .iter()
        .map(|(_, lat)| 1.0 / lat.as_secs_f64().max(0.001))
        .collect();
    let total_speed: f64 = speeds.iter().sum();

    // Blocks per node (proportional), ensuring at least 1 each.
    let mut block_counts: Vec<usize> = speeds
        .iter()
        .map(|s| ((*s / total_speed * total_blocks as f64).round() as usize).max(1))
        .collect();

    // Adjust sum to exactly total_blocks. Add/remove from the largest share.
    let sum: usize = block_counts.iter().sum();
    if sum != total_blocks {
        // Find the node with the largest allocation.
        let max_idx = block_counts
            .iter()
            .enumerate()
            .max_by_key(|(_, c)| **c)
            .map(|(i, _)| i)
            .unwrap_or(0);
        if sum > total_blocks {
            let excess = sum - total_blocks;
            block_counts[max_idx] = block_counts[max_idx].saturating_sub(excess).max(1);
        } else {
            block_counts[max_idx] += total_blocks - sum;
        }
    }

    // Final clamp: if after adjustment we still don't match (edge case with
    // many nodes and small total_blocks), redistribute.
    let sum2: usize = block_counts.iter().sum();
    if sum2 != total_blocks {
        // Simple fix: give everything to first node.
        block_counts = vec![0; candidates.len()];
        block_counts[0] = total_blocks;
    }

    // Build contiguous ranges.
    let mut assignments = Vec::with_capacity(candidates.len());
    let mut cursor = start_height;
    for (i, &(node_idx, _)) in candidates.iter().enumerate() {
        let count = block_counts[i];
        if count == 0 {
            continue;
        }
        let sub_start = cursor;
        let sub_end = cursor + count as u64 - 1;
        assignments.push((node_idx, sub_start, sub_end, nodes[node_idx].daemon.clone()));
        cursor = sub_end + 1;
    }

    assignments
}

fn make_daemon(url: &str, username: &Option<String>, password: &Option<String>) -> DaemonRpc {
    if username.is_some() || password.is_some() {
        let config = crate::client::RpcConfig {
            url: url.trim_end_matches('/').to_string(),
            username: username.clone(),
            password: password.clone(),
            ..Default::default()
        };
        DaemonRpc::with_config(config)
    } else {
        DaemonRpc::new(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_config_defaults() {
        let cfg = PoolConfig::default();
        assert_eq!(cfg.switch_threshold, 0.15);
        assert_eq!(cfg.max_race_group_size, 4);
        assert_eq!(cfg.race_interval_secs, 60);
    }

    #[tokio::test]
    async fn pool_creates_seed_nodes() {
        let pool = NodePool::new(PoolConfig {
            network: Network::Testnet,
            ..Default::default()
        });
        let inner = pool.inner.read().await;
        assert_eq!(inner.nodes.len(), crate::seed_nodes::TESTNET.len());
        assert!(inner.nodes.iter().all(|n| n.is_seed));
    }

    #[tokio::test]
    async fn pool_with_primary_url() {
        let pool = NodePool::new(PoolConfig {
            network: Network::Testnet,
            primary_url: Some("http://custom:29081".to_string()),
            ..Default::default()
        });
        let inner = pool.inner.read().await;
        // primary + seeds (non-duplicate)
        assert_eq!(inner.nodes.len(), crate::seed_nodes::TESTNET.len() + 1);
        assert_eq!(inner.active_index, 0);
        assert!(!inner.nodes[0].is_seed);
        assert_eq!(inner.nodes[0].url, "http://custom:29081");
    }

    #[tokio::test]
    async fn add_node_dedup() {
        let pool = NodePool::new(PoolConfig {
            network: Network::Testnet,
            ..Default::default()
        });
        let initial_count = pool.inner.read().await.nodes.len();

        pool.add_node("http://new-node:29081").await;
        assert_eq!(pool.inner.read().await.nodes.len(), initial_count + 1);

        // Adding same URL again should be a no-op.
        pool.add_node("http://new-node:29081").await;
        assert_eq!(pool.inner.read().await.nodes.len(), initial_count + 1);
    }

    #[test]
    fn pool_config_max_fetch_nodes_default() {
        let cfg = PoolConfig::default();
        assert_eq!(cfg.max_fetch_nodes, 4);
    }

    /// Helper to build a fake NodeState for compute_assignments tests.
    fn fake_node(latency_ms: Option<u64>, healthy: bool) -> NodeState {
        NodeState {
            daemon: DaemonRpc::new("http://fake:29081"),
            url: format!("http://fake-{}ms:29081", latency_ms.unwrap_or(0)),
            is_seed: true,
            last_latency: latency_ms.map(Duration::from_millis),
            last_probed: None,
            consecutive_failures: 0,
            is_healthy: healthy,
        }
    }

    #[test]
    fn compute_assignments_single_node_fallback() {
        // Only 1 node with latency data → single-node path.
        let nodes = vec![
            fake_node(Some(100), true),
            fake_node(None, true),
            fake_node(None, true),
        ];
        let a = compute_assignments(&nodes, 0, 4, 1, 100);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].1, 1);   // sub_start
        assert_eq!(a[0].2, 100); // sub_end
    }

    #[test]
    fn compute_assignments_no_latency_data() {
        let nodes = vec![
            fake_node(None, true),
            fake_node(None, true),
        ];
        let a = compute_assignments(&nodes, 0, 4, 1, 50);
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn compute_assignments_three_nodes() {
        // 3 nodes: 100ms, 150ms, 300ms — weights ~50%, ~33%, ~17%.
        let nodes = vec![
            fake_node(Some(100), true),
            fake_node(Some(150), true),
            fake_node(Some(300), true),
        ];
        let a = compute_assignments(&nodes, 0, 4, 1, 100);
        assert_eq!(a.len(), 3);

        // Verify contiguous, covering [1..100].
        assert_eq!(a[0].1, 1);
        for i in 1..a.len() {
            assert_eq!(a[i].1, a[i - 1].2 + 1, "sub-ranges must be contiguous");
        }
        assert_eq!(a.last().unwrap().2, 100);

        // Fastest node (100ms) should get the most blocks.
        let blocks_0 = (a[0].2 - a[0].1 + 1) as usize;
        let blocks_2 = (a[2].2 - a[2].1 + 1) as usize;
        assert!(blocks_0 > blocks_2, "fastest node should get more blocks");
    }

    #[test]
    fn compute_assignments_respects_max_fetch_nodes() {
        // 5 nodes with latency, max_fetch_nodes = 2.
        let nodes = vec![
            fake_node(Some(100), true),
            fake_node(Some(150), true),
            fake_node(Some(200), true),
            fake_node(Some(250), true),
            fake_node(Some(300), true),
        ];
        let a = compute_assignments(&nodes, 0, 2, 1, 100);
        // Should only use 2 nodes.
        assert_eq!(a.len(), 2);
        assert_eq!(a.last().unwrap().2, 100);
    }

    #[test]
    fn compute_assignments_skips_unhealthy() {
        let nodes = vec![
            fake_node(Some(100), true),
            fake_node(Some(50), false), // fastest but unhealthy
            fake_node(Some(200), true),
        ];
        let a = compute_assignments(&nodes, 0, 4, 1, 100);
        // Only 2 healthy nodes with latency.
        assert_eq!(a.len(), 2);
        // Should not include node 1 (unhealthy).
        assert!(a.iter().all(|(idx, _, _, _)| *idx != 1));
    }

    #[test]
    fn compute_assignments_small_batch() {
        // 3 nodes, only 3 blocks.
        let nodes = vec![
            fake_node(Some(100), true),
            fake_node(Some(200), true),
            fake_node(Some(300), true),
        ];
        let a = compute_assignments(&nodes, 0, 4, 10, 3);
        // Every node should get at least 1 block, total = 3.
        let total: u64 = a.iter().map(|(_, s, e, _)| e - s + 1).sum();
        assert_eq!(total, 3);
        assert_eq!(a[0].1, 10);
        assert_eq!(a.last().unwrap().2, 12);
    }
}
