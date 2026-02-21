//! Daemon RPC client.
//!
//! Typed async methods for all major Salvium daemon RPC endpoints.
//! Covers network info, blocks, transactions, outputs, mining, and fees.
//!
//! Reference: salvium daemon RPC documentation, daemon.js

use crate::client::{RpcClient, RpcConfig};
use crate::error::RpcError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

// =============================================================================
// Response Types
// =============================================================================

/// Daemon `/get_info` response.
#[derive(Debug, Clone, Deserialize)]
pub struct DaemonInfo {
    pub height: u64,
    pub target_height: u64,
    pub difficulty: u64,
    #[serde(default)]
    pub wide_difficulty: Option<String>,
    #[serde(default)]
    pub difficulty_top64: Option<u64>,
    pub tx_count: u64,
    pub tx_pool_size: u64,
    #[serde(default)]
    pub alt_blocks_count: u64,
    #[serde(default)]
    pub outgoing_connections_count: u64,
    #[serde(default)]
    pub incoming_connections_count: u64,
    #[serde(default)]
    pub white_peerlist_size: u64,
    #[serde(default)]
    pub grey_peerlist_size: u64,
    #[serde(default)]
    pub mainnet: bool,
    #[serde(default)]
    pub testnet: bool,
    #[serde(default)]
    pub stagenet: bool,
    #[serde(default)]
    pub synchronized: bool,
    #[serde(default)]
    pub top_block_hash: String,
    #[serde(default)]
    pub cumulative_difficulty: u64,
    #[serde(default)]
    pub database_size: u64,
    #[serde(default)]
    pub free_space: u64,
    pub status: String,
    /// Catch-all for additional fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Block header from RPC.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeader {
    pub major_version: u8,
    pub minor_version: u8,
    pub timestamp: u64,
    pub prev_hash: String,
    pub nonce: u32,
    #[serde(default)]
    pub orphan_status: bool,
    pub height: u64,
    #[serde(default)]
    pub depth: u64,
    pub hash: String,
    pub difficulty: u64,
    #[serde(default)]
    pub wide_difficulty: Option<String>,
    #[serde(default)]
    pub cumulative_difficulty: u64,
    pub reward: u64,
    #[serde(default)]
    pub block_size: u64,
    pub block_weight: u64,
    pub num_txes: u64,
    #[serde(default)]
    pub pow_hash: Option<String>,
    #[serde(default)]
    pub miner_tx_hash: Option<String>,
    #[serde(default)]
    pub protocol_tx_hash: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Block template from `get_block_template`.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockTemplate {
    pub difficulty: u64,
    #[serde(default)]
    pub wide_difficulty: Option<String>,
    #[serde(default)]
    pub difficulty_top64: Option<u64>,
    pub height: u64,
    pub reserved_offset: u32,
    pub expected_reward: u64,
    pub prev_hash: String,
    #[serde(default)]
    pub seed_height: u64,
    #[serde(default)]
    pub seed_hash: String,
    #[serde(default)]
    pub next_seed_hash: Option<String>,
    pub blocktemplate_blob: String,
    pub blockhashing_blob: String,
    pub status: String,
}

/// Full block response from `get_block`.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockResult {
    pub blob: String,
    pub block_header: BlockHeader,
    pub miner_tx_hash: String,
    #[serde(default)]
    pub tx_hashes: Vec<String>,
    #[serde(default)]
    pub json: String,
    pub status: String,
}

/// Transaction entry from `/get_transactions`.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionEntry {
    #[serde(default)]
    pub tx_hash: String,
    #[serde(default)]
    pub as_hex: String,
    #[serde(default)]
    pub as_json: Option<String>,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub block_timestamp: u64,
    #[serde(default)]
    pub in_pool: bool,
    #[serde(default)]
    pub double_spend_seen: bool,
    #[serde(default)]
    pub output_indices: Vec<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Output info from `/get_outs`.
#[derive(Debug, Clone, Deserialize)]
pub struct OutputInfo {
    pub key: String,
    pub mask: String,
    pub unlocked: bool,
    pub height: u64,
    #[serde(default)]
    pub txid: Option<String>,
    /// Global output ID (only populated when `asset_type` is set in the request).
    #[serde(default)]
    pub output_id: Option<u64>,
}

/// Output distribution entry.
#[derive(Debug, Clone, Deserialize)]
pub struct OutputDistribution {
    pub amount: u64,
    #[serde(default)]
    pub start_height: u64,
    pub distribution: Vec<u64>,
    #[serde(default)]
    pub base: u64,
}

/// Fee estimate response.
#[derive(Debug, Clone, Deserialize)]
pub struct FeeEstimate {
    pub fee: u64,
    #[serde(default)]
    pub quantization_mask: u64,
    pub status: String,
}

/// Key image spent status.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyImageSpentStatus {
    pub spent_status: Vec<u8>,
    pub status: String,
}

/// Send raw transaction response.
#[derive(Debug, Clone, Deserialize)]
pub struct SendRawTxResult {
    pub status: String,
    #[serde(default)]
    pub double_spend: bool,
    #[serde(default)]
    pub fee_too_low: bool,
    #[serde(default)]
    pub invalid_input: bool,
    #[serde(default)]
    pub invalid_output: bool,
    #[serde(default)]
    pub too_big: bool,
    #[serde(default)]
    pub overspend: bool,
    #[serde(default)]
    pub not_relayed: bool,
    #[serde(default)]
    pub sanity_check_failed: bool,
    #[serde(default)]
    pub tx_extra_too_big: bool,
    #[serde(default)]
    pub reason: String,
}

/// Hard fork info.
#[derive(Debug, Clone, Deserialize)]
pub struct HardForkInfo {
    pub version: u8,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub earliest_height: u64,
    pub status: String,
}

/// Yield info (Salvium-specific).
#[derive(Debug, Clone, Deserialize)]
pub struct YieldInfo {
    #[serde(default)]
    pub total_burnt: u64,
    #[serde(default)]
    pub total_staked: u64,
    #[serde(default)]
    pub total_yield: u64,
    #[serde(default)]
    pub yield_per_stake: f64,
    pub status: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Supply info (Salvium-specific).
#[derive(Debug, Clone, Deserialize)]
pub struct SupplyInfo {
    pub status: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Sync info.
#[derive(Debug, Clone, Deserialize)]
pub struct SyncInfo {
    pub height: u64,
    pub target_height: u64,
    pub status: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

// =============================================================================
// New Response Types: Network / Version
// =============================================================================

/// Response from `get_version` JSON-RPC method.
#[derive(Debug, Clone, Deserialize)]
pub struct VersionInfo {
    pub version: u32,
    #[serde(default)]
    pub release: bool,
    pub status: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Response from `get_block_count` JSON-RPC method.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockCount {
    pub count: u64,
    pub status: String,
}

// =============================================================================
// New Response Types: Peer / Network
// =============================================================================

/// Connection info returned by `get_connections`.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionInfo {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub peer_id: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub incoming: bool,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub recv_count: u64,
    #[serde(default)]
    pub send_count: u64,
    #[serde(default)]
    pub recv_idle_time: u64,
    #[serde(default)]
    pub send_idle_time: u64,
    #[serde(default)]
    pub avg_download: u64,
    #[serde(default)]
    pub avg_upload: u64,
    #[serde(default)]
    pub current_download: u64,
    #[serde(default)]
    pub current_upload: u64,
    #[serde(default)]
    pub live_time: u64,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub connection_id: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Peer entry from `get_peer_list`.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerEntry {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub ip: u32,
    #[serde(default)]
    pub last_seen: u64,
    #[serde(default)]
    pub pruning_seed: u32,
    #[serde(default)]
    pub rpc_port: u16,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Public node entry from `get_public_nodes`.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicNode {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub rpc_port: u16,
    #[serde(default)]
    pub last_seen: u64,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Response from `/get_net_stats`.
#[derive(Debug, Clone, Deserialize)]
pub struct NetStats {
    #[serde(default)]
    pub start_time: u64,
    #[serde(default)]
    pub total_packets_in: u64,
    #[serde(default)]
    pub total_bytes_in: u64,
    #[serde(default)]
    pub total_packets_out: u64,
    #[serde(default)]
    pub total_bytes_out: u64,
    #[serde(default)]
    pub status: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Response from `/get_limit` or `/set_limit`.
#[derive(Debug, Clone, Deserialize)]
pub struct LimitInfo {
    #[serde(default)]
    pub limit_down: i64,
    #[serde(default)]
    pub limit_up: i64,
    #[serde(default)]
    pub status: String,
}

/// Response from `/out_peers`.
#[derive(Debug, Clone, Deserialize)]
pub struct OutPeersResult {
    #[serde(default)]
    pub out_peers: u64,
    #[serde(default)]
    pub status: String,
}

/// Response from `/in_peers`.
#[derive(Debug, Clone, Deserialize)]
pub struct InPeersResult {
    #[serde(default)]
    pub in_peers: u64,
    #[serde(default)]
    pub status: String,
}

// =============================================================================
// New Response Types: Ban Management
// =============================================================================

/// Ban entry for `set_bans` request.
#[derive(Debug, Clone, Serialize)]
pub struct BanEntry {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default)]
    pub ip: u32,
    pub ban: bool,
    pub seconds: u32,
}

/// Ban info returned by `get_bans`.
#[derive(Debug, Clone, Deserialize)]
pub struct BanInfo {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ip: u32,
    #[serde(default)]
    pub seconds: u32,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Response from `banned`.
#[derive(Debug, Clone, Deserialize)]
pub struct BannedResult {
    #[serde(default)]
    pub banned: bool,
    #[serde(default)]
    pub seconds: u32,
    pub status: String,
}

// =============================================================================
// New Response Types: Transaction Pool
// =============================================================================

/// Transaction pool entry from `/get_transaction_pool`.
#[derive(Debug, Clone, Deserialize)]
pub struct TxPoolEntry {
    #[serde(default)]
    pub id_hash: String,
    #[serde(default)]
    pub tx_json: String,
    #[serde(default)]
    pub tx_blob: String,
    #[serde(default)]
    pub blob_size: u64,
    #[serde(default)]
    pub weight: u64,
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub max_used_block_hash: String,
    #[serde(default)]
    pub max_used_block_height: u64,
    #[serde(default)]
    pub kept_by_block: bool,
    #[serde(default)]
    pub last_failed_height: u64,
    #[serde(default)]
    pub last_failed_id_hash: String,
    #[serde(default)]
    pub receive_time: u64,
    #[serde(default)]
    pub relayed: bool,
    #[serde(default)]
    pub last_relayed_time: u64,
    #[serde(default)]
    pub do_not_relay: bool,
    #[serde(default)]
    pub double_spend_seen: bool,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Spent key image info from `/get_transaction_pool`.
#[derive(Debug, Clone, Deserialize)]
pub struct SpentKeyImageInfo {
    #[serde(default)]
    pub id_hash: String,
    #[serde(default)]
    pub txs_hashes: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Transaction pool statistics from `/get_transaction_pool_stats`.
#[derive(Debug, Clone, Deserialize)]
pub struct TxPoolStats {
    #[serde(default)]
    pub bytes_max: u64,
    #[serde(default)]
    pub bytes_med: u64,
    #[serde(default)]
    pub bytes_min: u64,
    #[serde(default)]
    pub bytes_total: u64,
    #[serde(default)]
    pub fee_total: u64,
    #[serde(default)]
    pub num_10m: u32,
    #[serde(default)]
    pub num_double_spends: u32,
    #[serde(default)]
    pub num_failing: u32,
    #[serde(default)]
    pub num_not_relayed: u32,
    #[serde(default)]
    pub oldest: u64,
    #[serde(default)]
    pub txs_total: u32,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

// =============================================================================
// New Response Types: Output Operations
// =============================================================================

/// Histogram entry from `get_output_histogram`.
#[derive(Debug, Clone, Deserialize)]
pub struct HistogramEntry {
    #[serde(default)]
    pub amount: u64,
    #[serde(default)]
    pub total_instances: u64,
    #[serde(default)]
    pub unlocked_instances: u64,
    #[serde(default)]
    pub recent_instances: u64,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

// =============================================================================
// New Response Types: Mining Control
// =============================================================================

/// Mining status from `/mining_status`.
#[derive(Debug, Clone, Deserialize)]
pub struct MiningStatus {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub speed: u64,
    #[serde(default)]
    pub threads_count: u32,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub is_background_mining_enabled: bool,
    #[serde(default)]
    pub block_target: u64,
    #[serde(default)]
    pub block_reward: u64,
    #[serde(default)]
    pub difficulty: u64,
    #[serde(default)]
    pub wide_difficulty: Option<String>,
    #[serde(default)]
    pub pow_algorithm: String,
    pub status: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

// =============================================================================
// New Response Types: Admin / Maintenance
// =============================================================================

/// Response from `get_coinbase_tx_sum`.
#[derive(Debug, Clone, Deserialize)]
pub struct CoinbaseTxSum {
    #[serde(default)]
    pub emission_amount: u64,
    #[serde(default)]
    pub fee_amount: u64,
    #[serde(default)]
    pub emission_amount_top64: u64,
    #[serde(default)]
    pub fee_amount_top64: u64,
    pub status: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Alternate chain entry from `get_alternate_chains`.
#[derive(Debug, Clone, Deserialize)]
pub struct AltChain {
    #[serde(default)]
    pub block_hash: String,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub length: u64,
    #[serde(default)]
    pub difficulty: u64,
    #[serde(default)]
    pub wide_difficulty: Option<String>,
    #[serde(default)]
    pub block_hashes: Vec<String>,
    #[serde(default)]
    pub main_chain_parent_block: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Response from `prune_blockchain`.
#[derive(Debug, Clone, Deserialize)]
pub struct PruneResult {
    #[serde(default)]
    pub pruned: bool,
    #[serde(default)]
    pub pruning_seed: u32,
    pub status: String,
}

// =============================================================================
// New Response Types: Advanced
// =============================================================================

/// Response from `generate_blocks` (regtest only).
#[derive(Debug, Clone, Deserialize)]
pub struct GenerateBlocksResult {
    #[serde(default)]
    pub blocks: Vec<String>,
    #[serde(default)]
    pub height: u64,
    pub status: String,
}

// =============================================================================
// DaemonRpc
// =============================================================================

/// Async RPC client for the Salvium daemon.
pub struct DaemonRpc {
    client: RpcClient,
}

impl DaemonRpc {
    /// Create a daemon RPC client connected to the given URL.
    pub fn new(url: &str) -> Self {
        Self {
            client: RpcClient::new(url),
        }
    }

    /// Create with full configuration.
    pub fn with_config(config: RpcConfig) -> Self {
        Self {
            client: RpcClient::with_config(config),
        }
    }

    /// Get the underlying RPC client for custom calls.
    pub fn client(&self) -> &RpcClient {
        &self.client
    }

    // =========================================================================
    // Network Information
    // =========================================================================

    /// Get daemon info (height, difficulty, sync status, etc.).
    pub async fn get_info(&self) -> Result<DaemonInfo, RpcError> {
        let val = self.client.post("/get_info", &serde_json::json!({})).await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get current blockchain height.
    pub async fn get_height(&self) -> Result<u64, RpcError> {
        let val = self.client.post("/get_height", &serde_json::json!({})).await?;
        val.get("height")
            .and_then(|v| v.as_u64())
            .ok_or(RpcError::NoResult { context: "get_height".into() })
    }

    /// Check if daemon is synchronized.
    pub async fn is_synchronized(&self) -> Result<bool, RpcError> {
        let info = self.get_info().await?;
        Ok(info.synchronized)
    }

    /// Get hard fork info.
    pub async fn hard_fork_info(&self) -> Result<HardForkInfo, RpcError> {
        let val = self.client.call("hard_fork_info", serde_json::json!({})).await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get sync info (heights, peers, spans).
    pub async fn sync_info(&self) -> Result<SyncInfo, RpcError> {
        let val = self.client.call("sync_info", serde_json::json!({})).await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get daemon version information.
    pub async fn get_version(&self) -> Result<VersionInfo, RpcError> {
        let val = self.client.call("get_version", serde_json::json!({})).await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get the current block count (alias for height).
    pub async fn get_block_count(&self) -> Result<BlockCount, RpcError> {
        let val = self
            .client
            .call("get_block_count", serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // Block Operations
    // =========================================================================

    /// Get the last (most recent) block header.
    pub async fn get_last_block_header(&self) -> Result<BlockHeader, RpcError> {
        let val = self
            .client
            .call("get_last_block_header", serde_json::json!({}))
            .await?;
        let header = val.get("block_header").ok_or(RpcError::NoResult { context: "get_last_block_header".into() })?;
        Ok(serde_json::from_value(header.clone())?)
    }

    /// Get a block header by height.
    pub async fn get_block_header_by_height(&self, height: u64) -> Result<BlockHeader, RpcError> {
        let val = self
            .client
            .call(
                "get_block_header_by_height",
                serde_json::json!({ "height": height }),
            )
            .await?;
        let header = val.get("block_header").ok_or(RpcError::NoResult { context: format!("get_block_header_by_height({})", height) })?;
        Ok(serde_json::from_value(header.clone())?)
    }

    /// Get a block header by hash.
    pub async fn get_block_header_by_hash(&self, hash: &str) -> Result<BlockHeader, RpcError> {
        let val = self
            .client
            .call(
                "get_block_header_by_hash",
                serde_json::json!({ "hash": hash }),
            )
            .await?;
        let header = val.get("block_header").ok_or(RpcError::NoResult { context: format!("get_block_header_by_hash({})", &hash[..8.min(hash.len())]) })?;
        Ok(serde_json::from_value(header.clone())?)
    }

    /// Get block headers for a height range.
    pub async fn get_block_headers_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<BlockHeader>, RpcError> {
        let val = self
            .client
            .call(
                "get_block_headers_range",
                serde_json::json!({
                    "start_height": start_height,
                    "end_height": end_height,
                }),
            )
            .await?;
        let headers = val.get("headers").ok_or(RpcError::NoResult { context: "get_block_headers_range".into() })?;
        Ok(serde_json::from_value(headers.clone())?)
    }

    /// Get a full block by height (header + miner tx hash + tx hashes).
    pub async fn get_block(&self, height: u64) -> Result<BlockResult, RpcError> {
        let val = self
            .client
            .call("get_block", serde_json::json!({"height": height}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get block hash at a given height.
    pub async fn get_block_hash(&self, height: u64) -> Result<String, RpcError> {
        let val = self
            .client
            .call("on_get_block_hash", serde_json::json!([height]))
            .await?;
        val.as_str()
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "get_block_hash".into() })
    }

    // =========================================================================
    // Transaction Operations
    // =========================================================================

    /// Get transactions by hash.
    pub async fn get_transactions(
        &self,
        tx_hashes: &[&str],
        decode_as_json: bool,
    ) -> Result<Vec<TransactionEntry>, RpcError> {
        let val = self
            .client
            .post(
                "/get_transactions",
                &serde_json::json!({
                    "txs_hashes": tx_hashes,
                    "decode_as_json": decode_as_json,
                }),
            )
            .await?;
        let txs = val.get("txs").ok_or(RpcError::NoResult { context: "get_transactions(txs)".into() })?;
        Ok(serde_json::from_value(txs.clone())?)
    }

    /// Send a raw transaction.
    pub async fn send_raw_transaction(
        &self,
        tx_as_hex: &str,
        do_not_relay: bool,
    ) -> Result<SendRawTxResult, RpcError> {
        self.send_raw_transaction_ex(tx_as_hex, do_not_relay, true, "SAL1").await
    }

    /// Send a raw transaction with explicit parameters.
    pub async fn send_raw_transaction_ex(
        &self,
        tx_as_hex: &str,
        do_not_relay: bool,
        do_sanity_checks: bool,
        source_asset_type: &str,
    ) -> Result<SendRawTxResult, RpcError> {
        let val = self
            .client
            .post(
                "/send_raw_transaction",
                &serde_json::json!({
                    "tx_as_hex": tx_as_hex,
                    "do_not_relay": do_not_relay,
                    "do_sanity_checks": do_sanity_checks,
                    "source_asset_type": source_asset_type,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get transaction pool (mempool) hashes.
    pub async fn get_transaction_pool_hashes(&self) -> Result<Vec<String>, RpcError> {
        let val = self
            .client
            .post("/get_transaction_pool_hashes", &serde_json::json!({}))
            .await?;
        let hashes = val
            .get("tx_hashes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(hashes)
    }

    /// Check if key images are spent.
    ///
    /// Returns spent status per key image: 0=unspent, 1=spent in chain, 2=spent in pool.
    pub async fn is_key_image_spent(
        &self,
        key_images: &[&str],
    ) -> Result<KeyImageSpentStatus, RpcError> {
        let val = self
            .client
            .post(
                "/is_key_image_spent",
                &serde_json::json!({ "key_images": key_images }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // Output Operations
    // =========================================================================

    /// Get output details by amount and index.
    ///
    /// When `asset_type` is non-empty, indices in `OutputRequest` are treated as
    /// asset-type-specific indices (unless `is_global_out` is set on individual
    /// entries). The daemon converts them to global output IDs internally.
    /// When `asset_type` is empty, indices are treated as global output IDs.
    pub async fn get_outs(
        &self,
        outputs: &[OutputRequest],
        get_txid: bool,
        asset_type: &str,
    ) -> Result<Vec<OutputInfo>, RpcError> {
        let mut req = serde_json::json!({
            "outputs": outputs,
            "get_txid": get_txid,
        });
        if !asset_type.is_empty() {
            req["asset_type"] = serde_json::Value::String(asset_type.to_string());
        }
        let val = self.client.post("/get_outs", &req).await?;
        let outs = val.get("outs").ok_or(RpcError::NoResult { context: "get_outs".into() })?;
        Ok(serde_json::from_value(outs.clone())?)
    }

    /// Get output distribution for decoy selection.
    ///
    /// This is critical for wallet output scanning and ring member selection.
    /// When `rct_asset_type` is non-empty, returns the distribution for that
    /// specific asset type (indices are asset-type-specific). When empty,
    /// returns the global distribution.
    pub async fn get_output_distribution(
        &self,
        amounts: &[u64],
        from_height: u64,
        to_height: u64,
        cumulative: bool,
        rct_asset_type: &str,
    ) -> Result<Vec<OutputDistribution>, RpcError> {
        let mut params = serde_json::json!({
            "amounts": amounts,
            "from_height": from_height,
            "to_height": to_height,
            "cumulative": cumulative,
            "binary": false,
        });
        if !rct_asset_type.is_empty() {
            params["rct_asset_type"] = serde_json::Value::String(rct_asset_type.to_string());
        }
        let val = self
            .client
            .call("get_output_distribution", params)
            .await?;
        let dists = val.get("distributions").ok_or(RpcError::NoResult { context: "get_output_distribution".into() })?;
        Ok(serde_json::from_value(dists.clone())?)
    }

    /// Get output histogram.
    ///
    /// Returns a histogram of output amounts, useful for determining common
    /// output denominations on the network.
    pub async fn get_output_histogram(
        &self,
        amounts: &[u64],
        min_count: u64,
        max_count: u64,
        unlocked: bool,
        recent_cutoff: u64,
    ) -> Result<Vec<HistogramEntry>, RpcError> {
        let val = self
            .client
            .call(
                "get_output_histogram",
                serde_json::json!({
                    "amounts": amounts,
                    "min_count": min_count,
                    "max_count": max_count,
                    "unlocked": unlocked,
                    "recent_cutoff": recent_cutoff,
                }),
            )
            .await?;
        let histogram = val
            .get("histogram")
            .ok_or(RpcError::NoResult { context: "get_output_histogram".into() })?;
        Ok(serde_json::from_value(histogram.clone())?)
    }

    // =========================================================================
    // Mining Operations
    // =========================================================================

    /// Get block template for mining.
    pub async fn get_block_template(
        &self,
        wallet_address: &str,
        reserve_size: u32,
    ) -> Result<BlockTemplate, RpcError> {
        let val = self
            .client
            .call(
                "get_block_template",
                serde_json::json!({
                    "wallet_address": wallet_address,
                    "reserve_size": reserve_size,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Submit a mined block.
    pub async fn submit_block(&self, block_blob_hex: &str) -> Result<(), RpcError> {
        self.client
            .call("submit_block", serde_json::json!([block_blob_hex]))
            .await?;
        Ok(())
    }

    /// Get miner data (difficulty, height, seed info).
    pub async fn get_miner_data(&self) -> Result<Value, RpcError> {
        self.client
            .call("get_miner_data", serde_json::json!({}))
            .await
    }

    /// Start mining on the daemon. (Restricted)
    ///
    /// Begins mining blocks to the given `miner_address` using the specified
    /// number of threads.
    pub async fn start_mining(
        &self,
        miner_address: &str,
        threads_count: u64,
        do_background_mining: bool,
        ignore_battery: bool,
    ) -> Result<Value, RpcError> {
        self.client
            .post(
                "/start_mining",
                &serde_json::json!({
                    "miner_address": miner_address,
                    "threads_count": threads_count,
                    "do_background_mining": do_background_mining,
                    "ignore_battery": ignore_battery,
                }),
            )
            .await
    }

    /// Stop mining on the daemon. (Restricted)
    pub async fn stop_mining(&self) -> Result<Value, RpcError> {
        self.client
            .post("/stop_mining", &serde_json::json!({}))
            .await
    }

    /// Get mining status. (Restricted)
    ///
    /// Returns whether the daemon is actively mining, the hashrate, thread
    /// count, and target block information.
    pub async fn mining_status(&self) -> Result<MiningStatus, RpcError> {
        let val = self
            .client
            .post("/mining_status", &serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // Fee Estimation
    // =========================================================================

    /// Get fee estimate.
    pub async fn get_fee_estimate(&self, grace_blocks: u64) -> Result<FeeEstimate, RpcError> {
        let val = self
            .client
            .call(
                "get_fee_estimate",
                serde_json::json!({ "grace_blocks": grace_blocks }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // Salvium-Specific
    // =========================================================================

    /// Get supply info (multi-asset supply tally).
    pub async fn get_supply_info(&self) -> Result<SupplyInfo, RpcError> {
        let val = self
            .client
            .call("get_supply_info", serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get yield info (staking economics).
    pub async fn get_yield_info(&self) -> Result<YieldInfo, RpcError> {
        let val = self
            .client
            .call("get_yield_info", serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // Peer / Network
    // =========================================================================

    /// Get list of active connections to the daemon. (Restricted)
    pub async fn get_connections(&self) -> Result<Vec<ConnectionInfo>, RpcError> {
        let val = self
            .client
            .call("get_connections", serde_json::json!({}))
            .await?;
        let conns = val
            .get("connections")
            .ok_or(RpcError::NoResult { context: "get_connections".into() })?;
        Ok(serde_json::from_value(conns.clone())?)
    }

    /// Get the daemon's peer list (white and gray). (Restricted)
    pub async fn get_peer_list(&self) -> Result<(Vec<PeerEntry>, Vec<PeerEntry>), RpcError> {
        let val = self
            .client
            .call("get_peer_list", serde_json::json!({}))
            .await?;
        let white: Vec<PeerEntry> = val
            .get("white_list")
            .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
            .unwrap_or_default();
        let gray: Vec<PeerEntry> = val
            .get("gray_list")
            .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
            .unwrap_or_default();
        Ok((white, gray))
    }

    /// Get list of public nodes known to the daemon.
    pub async fn get_public_nodes(&self) -> Result<(Vec<PublicNode>, Vec<PublicNode>), RpcError> {
        let val = self
            .client
            .call("get_public_nodes", serde_json::json!({}))
            .await?;
        let white: Vec<PublicNode> = val
            .get("white")
            .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
            .unwrap_or_default();
        let gray: Vec<PublicNode> = val
            .get("gray")
            .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
            .unwrap_or_default();
        Ok((white, gray))
    }

    /// Get network statistics. (Restricted)
    pub async fn get_net_stats(&self) -> Result<NetStats, RpcError> {
        let val = self
            .client
            .post("/get_net_stats", &serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Set bandwidth limits (kB/s). (Restricted)
    ///
    /// Pass -1 to reset to default, 0 to leave unchanged.
    pub async fn set_limit(&self, limit_down: i64, limit_up: i64) -> Result<LimitInfo, RpcError> {
        let val = self
            .client
            .post(
                "/set_limit",
                &serde_json::json!({
                    "limit_down": limit_down,
                    "limit_up": limit_up,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get current bandwidth limits (kB/s).
    pub async fn get_limit(&self) -> Result<LimitInfo, RpcError> {
        let val = self
            .client
            .post("/get_limit", &serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Set the max number of outgoing peers. (Restricted)
    pub async fn out_peers(&self, out_peers: u64) -> Result<OutPeersResult, RpcError> {
        let val = self
            .client
            .post(
                "/out_peers",
                &serde_json::json!({ "out_peers": out_peers }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Set the max number of incoming peers. (Restricted)
    pub async fn in_peers(&self, in_peers: u64) -> Result<InPeersResult, RpcError> {
        let val = self
            .client
            .post(
                "/in_peers",
                &serde_json::json!({ "in_peers": in_peers }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // Ban Management
    // =========================================================================

    /// Set bans on peers. (Restricted)
    pub async fn set_bans(&self, bans: &[BanEntry]) -> Result<Value, RpcError> {
        self.client
            .call("set_bans", serde_json::json!({ "bans": bans }))
            .await
    }

    /// Get list of banned peers. (Restricted)
    pub async fn get_bans(&self) -> Result<Vec<BanInfo>, RpcError> {
        let val = self
            .client
            .call("get_bans", serde_json::json!({}))
            .await?;
        let bans = val
            .get("bans")
            .ok_or(RpcError::NoResult { context: "get_bans".into() })?;
        Ok(serde_json::from_value(bans.clone())?)
    }

    /// Check if a specific address is banned. (Restricted)
    pub async fn banned(&self, address: &str) -> Result<BannedResult, RpcError> {
        let val = self
            .client
            .call("banned", serde_json::json!({ "address": address }))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // Transaction Pool
    // =========================================================================

    /// Get full transaction pool (mempool) contents.
    ///
    /// Returns all transactions in the pool along with spent key image info.
    pub async fn get_transaction_pool(
        &self,
    ) -> Result<(Vec<TxPoolEntry>, Vec<SpentKeyImageInfo>), RpcError> {
        let val = self
            .client
            .post("/get_transaction_pool", &serde_json::json!({}))
            .await?;
        let txs: Vec<TxPoolEntry> = val
            .get("transactions")
            .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
            .unwrap_or_default();
        let kis: Vec<SpentKeyImageInfo> = val
            .get("spent_key_images")
            .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
            .unwrap_or_default();
        Ok((txs, kis))
    }

    /// Get transaction pool statistics.
    pub async fn get_transaction_pool_stats(&self) -> Result<TxPoolStats, RpcError> {
        let val = self
            .client
            .post("/get_transaction_pool_stats", &serde_json::json!({}))
            .await?;
        let stats = val
            .get("pool_stats")
            .ok_or(RpcError::NoResult { context: "get_transaction_pool_stats".into() })?;
        Ok(serde_json::from_value(stats.clone())?)
    }

    /// Get transaction pool backlog.
    pub async fn get_txpool_backlog(&self) -> Result<Value, RpcError> {
        self.client
            .post("/get_txpool_backlog", &serde_json::json!({}))
            .await
    }

    /// Relay specific transactions by ID. (Restricted)
    pub async fn relay_tx(&self, txids: &[&str]) -> Result<Value, RpcError> {
        self.client
            .call("relay_tx", serde_json::json!({ "txids": txids }))
            .await
    }

    /// Flush transactions from the pool. (Restricted)
    ///
    /// If `txids` is `None`, flush all transactions. Otherwise flush only the
    /// specified transaction IDs.
    pub async fn flush_txpool(&self, txids: Option<&[&str]>) -> Result<Value, RpcError> {
        let params = match txids {
            Some(ids) => serde_json::json!({ "txids": ids }),
            None => serde_json::json!({}),
        };
        self.client.call("flush_txpool", params).await
    }

    // =========================================================================
    // Admin / Maintenance
    // =========================================================================

    /// Set the daemon log level (0-4). (Restricted)
    pub async fn set_log_level(&self, level: u8) -> Result<Value, RpcError> {
        self.client
            .post(
                "/set_log_level",
                &serde_json::json!({ "level": level }),
            )
            .await
    }

    /// Set log categories. (Restricted)
    ///
    /// Returns the resulting category string.
    pub async fn set_log_categories(&self, categories: &str) -> Result<String, RpcError> {
        let val = self
            .client
            .post(
                "/set_log_categories",
                &serde_json::json!({ "categories": categories }),
            )
            .await?;
        Ok(val
            .get("categories")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// Save the blockchain to disk. (Restricted)
    pub async fn save_bc(&self) -> Result<Value, RpcError> {
        self.client
            .post("/save_bc", &serde_json::json!({}))
            .await
    }

    /// Stop the daemon. (Restricted)
    pub async fn stop_daemon(&self) -> Result<Value, RpcError> {
        self.client
            .post("/stop_daemon", &serde_json::json!({}))
            .await
    }

    /// Get coinbase transaction sum for a range of blocks. (Restricted)
    ///
    /// Returns the total emission and fee amounts for blocks starting at
    /// `height` for `count` blocks.
    pub async fn get_coinbase_tx_sum(
        &self,
        height: u64,
        count: u64,
    ) -> Result<CoinbaseTxSum, RpcError> {
        let val = self
            .client
            .call(
                "get_coinbase_tx_sum",
                serde_json::json!({
                    "height": height,
                    "count": count,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get list of alternate (orphan) chains. (Restricted)
    pub async fn get_alternate_chains(&self) -> Result<Vec<AltChain>, RpcError> {
        let val = self
            .client
            .call("get_alternate_chains", serde_json::json!({}))
            .await?;
        let chains = val
            .get("chains")
            .ok_or(RpcError::NoResult { context: "get_alternate_chains".into() })?;
        Ok(serde_json::from_value(chains.clone())?)
    }

    /// Pop blocks from the top of the blockchain. (Restricted)
    ///
    /// Returns the new blockchain height after popping.
    pub async fn pop_blocks(&self, nblocks: u64) -> Result<u64, RpcError> {
        let val = self
            .client
            .post(
                "/pop_blocks",
                &serde_json::json!({ "nblocks": nblocks }),
            )
            .await?;
        val.get("height")
            .and_then(|v| v.as_u64())
            .ok_or(RpcError::NoResult { context: "pop_blocks".into() })
    }

    /// Prune the blockchain. (Restricted)
    ///
    /// If `check` is true, only checks the current pruning status without
    /// performing additional pruning.
    pub async fn prune_blockchain(&self, check: bool) -> Result<PruneResult, RpcError> {
        let val = self
            .client
            .call(
                "prune_blockchain",
                serde_json::json!({ "check": check }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Flush internal caches. (Restricted)
    ///
    /// Can flush bad-tx and/or bad-block caches.
    pub async fn flush_cache(
        &self,
        bad_txs: bool,
        bad_blocks: bool,
    ) -> Result<Value, RpcError> {
        self.client
            .call(
                "flush_cache",
                serde_json::json!({
                    "bad_txs": bad_txs,
                    "bad_blocks": bad_blocks,
                }),
            )
            .await
    }

    // =========================================================================
    // Advanced
    // =========================================================================

    /// Generate blocks in regtest mode. (Restricted, regtest only)
    ///
    /// Generates `amount_of_blocks` blocks, sending the coinbase reward to
    /// `wallet_address`. Returns the hashes of generated blocks and the new
    /// height.
    pub async fn generate_blocks(
        &self,
        amount_of_blocks: u64,
        wallet_address: &str,
    ) -> Result<GenerateBlocksResult, RpcError> {
        let val = self
            .client
            .call(
                "generateblocks",
                serde_json::json!({
                    "amount_of_blocks": amount_of_blocks,
                    "wallet_address": wallet_address,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Calculate proof-of-work hash for a block. (Restricted)
    ///
    /// Returns the PoW hash as a hex string.
    pub async fn calc_pow(
        &self,
        major_version: u8,
        height: u64,
        block_blob: &str,
        seed_hash: &str,
    ) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "calc_pow",
                serde_json::json!({
                    "major_version": major_version,
                    "height": height,
                    "block_blob": block_blob,
                    "seed_hash": seed_hash,
                }),
            )
            .await?;
        val.as_str()
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "calc_pow".into() })
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /// Wait for the daemon to synchronize.
    ///
    /// Polls `get_info` until `synchronized` is true or timeout is reached.
    pub async fn wait_for_sync(
        &self,
        poll_interval: Duration,
        timeout: Duration,
    ) -> Result<bool, RpcError> {
        let start = tokio::time::Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Ok(false);
            }
            match self.get_info().await {
                Ok(info) if info.synchronized => return Ok(true),
                _ => {}
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Determine network type from daemon info.
    pub async fn network_type(&self) -> Result<salvium_types::constants::Network, RpcError> {
        let info = self.get_info().await?;
        if info.testnet {
            Ok(salvium_types::constants::Network::Testnet)
        } else if info.stagenet {
            Ok(salvium_types::constants::Network::Stagenet)
        } else {
            Ok(salvium_types::constants::Network::Mainnet)
        }
    }
}

/// Request for a specific output by amount and index.
///
/// When `asset_type` is set on the parent `get_outs` request, `index` is treated
/// as an asset-type-specific index. Without `asset_type`, it's a global output ID.
#[derive(Debug, Clone, Serialize)]
pub struct OutputRequest {
    pub amount: u64,
    pub index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_rpc_creation() {
        let daemon = DaemonRpc::new("http://localhost:19081");
        assert_eq!(daemon.client().url(), "http://localhost:19081");
    }

    #[test]
    fn test_output_request_serialize() {
        let req = OutputRequest {
            amount: 0,
            index: 42,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["amount"], 0);
        assert_eq!(json["index"], 42);
    }

    #[test]
    fn test_daemon_info_deserialize() {
        let json = serde_json::json!({
            "height": 12345,
            "target_height": 12345,
            "difficulty": 1000000,
            "tx_count": 500,
            "tx_pool_size": 3,
            "synchronized": true,
            "mainnet": true,
            "status": "OK"
        });
        let info: DaemonInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.height, 12345);
        assert!(info.synchronized);
        assert!(info.mainnet);
    }

    #[test]
    fn test_block_header_deserialize() {
        let json = serde_json::json!({
            "major_version": 10,
            "minor_version": 10,
            "timestamp": 1700000000,
            "prev_hash": "abcd",
            "nonce": 12345,
            "height": 100,
            "hash": "efgh",
            "difficulty": 500000,
            "reward": 60000000000_u64,
            "block_weight": 1234,
            "num_txes": 5,
            "block_size": 1234
        });
        let header: BlockHeader = serde_json::from_value(json).unwrap();
        assert_eq!(header.major_version, 10);
        assert_eq!(header.height, 100);
    }

    #[test]
    fn test_send_raw_tx_result_deserialize() {
        let json = serde_json::json!({
            "status": "OK",
            "double_spend": false,
            "fee_too_low": false,
            "not_relayed": false,
            "reason": ""
        });
        let result: SendRawTxResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.status, "OK");
        assert!(!result.double_spend);
    }

    #[test]
    fn test_version_info_deserialize() {
        let json = serde_json::json!({
            "version": 196621,
            "release": true,
            "status": "OK",
            "untrusted": false
        });
        let info: VersionInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.version, 196621);
        assert!(info.release);
        assert_eq!(info.status, "OK");
        // "untrusted" should be captured in the extra map
        assert!(info.extra.contains_key("untrusted"));
    }

    #[test]
    fn test_connection_info_deserialize() {
        let json = serde_json::json!({
            "address": "192.168.1.1:19080",
            "host": "192.168.1.1",
            "port": "19080",
            "peer_id": "abc123",
            "state": "normal",
            "incoming": false,
            "ip": "192.168.1.1",
            "recv_count": 1024,
            "send_count": 2048,
            "live_time": 3600,
            "height": 50000,
            "connection_id": "conn-001"
        });
        let conn: ConnectionInfo = serde_json::from_value(json).unwrap();
        assert_eq!(conn.address, "192.168.1.1:19080");
        assert_eq!(conn.host, "192.168.1.1");
        assert!(!conn.incoming);
        assert_eq!(conn.height, 50000);
        assert_eq!(conn.live_time, 3600);
    }

    #[test]
    fn test_mining_status_deserialize() {
        let json = serde_json::json!({
            "active": true,
            "speed": 42000,
            "threads_count": 4,
            "address": "Svk1abc...",
            "is_background_mining_enabled": false,
            "block_target": 120,
            "block_reward": 600000000000_u64,
            "difficulty": 1234567,
            "pow_algorithm": "RandomX",
            "status": "OK"
        });
        let ms: MiningStatus = serde_json::from_value(json).unwrap();
        assert!(ms.active);
        assert_eq!(ms.speed, 42000);
        assert_eq!(ms.threads_count, 4);
        assert_eq!(ms.block_target, 120);
        assert_eq!(ms.pow_algorithm, "RandomX");
        assert_eq!(ms.status, "OK");
    }

    #[test]
    fn test_tx_pool_stats_deserialize() {
        let json = serde_json::json!({
            "bytes_max": 50000,
            "bytes_med": 10000,
            "bytes_min": 1000,
            "bytes_total": 250000,
            "fee_total": 100000000,
            "num_10m": 2,
            "num_double_spends": 0,
            "num_failing": 0,
            "num_not_relayed": 1,
            "oldest": 1700000000,
            "txs_total": 15
        });
        let stats: TxPoolStats = serde_json::from_value(json).unwrap();
        assert_eq!(stats.bytes_total, 250000);
        assert_eq!(stats.txs_total, 15);
        assert_eq!(stats.fee_total, 100000000);
        assert_eq!(stats.num_double_spends, 0);
    }

    #[test]
    fn test_coinbase_tx_sum_deserialize() {
        let json = serde_json::json!({
            "emission_amount": 9000000000000_u64,
            "fee_amount": 500000000,
            "emission_amount_top64": 0,
            "fee_amount_top64": 0,
            "status": "OK"
        });
        let sum: CoinbaseTxSum = serde_json::from_value(json).unwrap();
        assert_eq!(sum.emission_amount, 9000000000000);
        assert_eq!(sum.fee_amount, 500000000);
        assert_eq!(sum.status, "OK");
    }

    #[test]
    fn test_ban_entry_serialize() {
        let ban = BanEntry {
            host: "192.168.1.100".to_string(),
            ip: 0,
            ban: true,
            seconds: 3600,
        };
        let json = serde_json::to_value(&ban).unwrap();
        assert_eq!(json["host"], "192.168.1.100");
        assert_eq!(json["ban"], true);
        assert_eq!(json["seconds"], 3600);
    }

    #[test]
    fn test_histogram_entry_deserialize() {
        let json = serde_json::json!({
            "amount": 0,
            "total_instances": 100000,
            "unlocked_instances": 99000,
            "recent_instances": 500
        });
        let entry: HistogramEntry = serde_json::from_value(json).unwrap();
        assert_eq!(entry.amount, 0);
        assert_eq!(entry.total_instances, 100000);
        assert_eq!(entry.unlocked_instances, 99000);
        assert_eq!(entry.recent_instances, 500);
    }
}
