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
            .ok_or(RpcError::NoResult)
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

    // =========================================================================
    // Block Operations
    // =========================================================================

    /// Get the last (most recent) block header.
    pub async fn get_last_block_header(&self) -> Result<BlockHeader, RpcError> {
        let val = self
            .client
            .call("get_last_block_header", serde_json::json!({}))
            .await?;
        let header = val.get("block_header").ok_or(RpcError::NoResult)?;
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
        let header = val.get("block_header").ok_or(RpcError::NoResult)?;
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
        let header = val.get("block_header").ok_or(RpcError::NoResult)?;
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
        let headers = val.get("headers").ok_or(RpcError::NoResult)?;
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
            .ok_or(RpcError::NoResult)
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
        let txs = val.get("txs").ok_or(RpcError::NoResult)?;
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
        let outs = val.get("outs").ok_or(RpcError::NoResult)?;
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
        let dists = val.get("distributions").ok_or(RpcError::NoResult)?;
        Ok(serde_json::from_value(dists.clone())?)
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
}
