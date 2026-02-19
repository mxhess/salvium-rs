//! Salvium daemon JSON-RPC client
//!
//! Implements the subset of RPC methods needed for solo mining:
//! get_block_template, submit_block, get_info

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub struct DaemonClient {
    url: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct BlockTemplate {
    pub difficulty: u64,
    pub wide_difficulty: Option<String>,
    pub height: u64,
    pub seed_hash: String,
    pub next_seed_hash: Option<String>,
    pub blocktemplate_blob: String,
    pub blockhashing_blob: String,
    pub expected_reward: u64,
    pub prev_hash: String,
    pub reserved_offset: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DaemonInfo {
    pub height: u64,
    pub difficulty: u64,
    pub wide_difficulty: Option<String>,
    pub testnet: bool,
    pub mainnet: bool,
    pub synchronized: bool,
    pub status: String,
}

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: &'static str,
    method: String,
    params: Value,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<Value>,
}

impl DaemonClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: "0",
            method: method.to_string(),
            params,
        };

        let resp = self
            .client
            .post(format!("{}/json_rpc", self.url))
            .json(&req)
            .send()
            .map_err(|e| format!("HTTP error: {}", e))?;

        let body: JsonRpcResponse = resp.json().map_err(|e| format!("JSON parse error: {}", e))?;

        if let Some(err) = body.error {
            return Err(format!("RPC error: {}", err));
        }

        body.result.ok_or_else(|| "No result in response".to_string())
    }

    pub fn get_info(&self) -> Result<DaemonInfo, String> {
        let result = self.call("get_info", serde_json::json!({}))?;
        serde_json::from_value(result).map_err(|e| format!("Parse error: {}", e))
    }

    pub fn get_block_template(&self, address: &str, reserve_size: u32) -> Result<BlockTemplate, String> {
        let result = self.call(
            "get_block_template",
            serde_json::json!({
                "wallet_address": address,
                "reserve_size": reserve_size
            }),
        )?;
        serde_json::from_value(result).map_err(|e| format!("Parse error: {}", e))
    }

    pub fn submit_block(&self, block_blob_hex: &str) -> Result<(), String> {
        // submit_block takes an array of hex strings (not a JSON-RPC params object)
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: "0",
            method: "submit_block".to_string(),
            params: serde_json::json!([block_blob_hex]),
        };

        let resp = self
            .client
            .post(format!("{}/json_rpc", self.url))
            .json(&req)
            .send()
            .map_err(|e| format!("HTTP error: {}", e))?;

        let body: JsonRpcResponse = resp.json().map_err(|e| format!("JSON parse error: {}", e))?;

        if let Some(err) = body.error {
            return Err(format!("Block rejected: {}", err));
        }

        Ok(())
    }
}
