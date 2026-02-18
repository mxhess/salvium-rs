//! Base JSON-RPC 2.0 HTTP client.
//!
//! Provides `call()` for JSON-RPC methods (POST to `/json_rpc`) and
//! `post()` / `post_binary()` for raw endpoints.
//! Supports Basic auth, configurable timeout, and retry with exponential backoff.

use crate::error::RpcError;
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// JSON-RPC 2.0 request envelope.
#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

/// Configuration for an RPC client.
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Base URL (e.g., `http://localhost:19081`).
    pub url: String,
    /// Optional username for Basic auth.
    pub username: Option<String>,
    /// Optional password for Basic auth.
    pub password: Option<String>,
    /// Request timeout.
    pub timeout: Duration,
    /// Number of retry attempts on transient failure.
    pub retries: u32,
    /// Initial delay between retries (doubles each attempt).
    pub retry_delay: Duration,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:19081".to_string(),
            username: None,
            password: None,
            timeout: Duration::from_secs(30),
            retries: 2,
            retry_delay: Duration::from_millis(500),
        }
    }
}

/// Async RPC client for Salvium JSON-RPC and raw HTTP endpoints.
pub struct RpcClient {
    client: reqwest::Client,
    config: RpcConfig,
    request_id: AtomicU64,
}

impl RpcClient {
    /// Create a new client with the given URL.
    pub fn new(url: &str) -> Self {
        Self::with_config(RpcConfig {
            url: url.trim_end_matches('/').to_string(),
            ..Default::default()
        })
    }

    /// Create a new client with full configuration.
    pub fn with_config(config: RpcConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .pool_max_idle_per_host(4)
            .build()
            .expect("failed to create HTTP client");

        Self {
            client,
            config,
            request_id: AtomicU64::new(0),
        }
    }

    /// Get the configured base URL.
    pub fn url(&self) -> &str {
        &self.config.url
    }

    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn auth_header(&self) -> Option<HeaderValue> {
        match (&self.config.username, &self.config.password) {
            (Some(user), Some(pass)) => {
                let creds = format!("{}:{}", user, pass);
                let encoded = base64::engine::general_purpose::STANDARD.encode(creds);
                HeaderValue::from_str(&format!("Basic {}", encoded)).ok()
            }
            _ => None,
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(auth) = self.auth_header() {
            headers.insert(AUTHORIZATION, auth);
        }
        headers
    }

    /// Call a JSON-RPC 2.0 method (POST to `/json_rpc`).
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let url = format!("{}/json_rpc", self.config.url);
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: self.next_id(),
            method,
            params,
        };

        let attempts = self.config.retries + 1;
        let mut last_err = RpcError::NoResult {
            context: method.to_string(),
        };

        for attempt in 0..attempts {
            if attempt > 0 {
                let delay = self.config.retry_delay * 2u32.saturating_pow(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            match self.do_call(&url, &req, method).await {
                Ok(val) => return Ok(val),
                Err(e) => {
                    let should_retry = e.is_transient() && attempt + 1 < attempts;
                    if !should_retry {
                        return Err(e);
                    }
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }

    async fn do_call(
        &self,
        url: &str,
        req: &JsonRpcRequest<'_>,
        method: &str,
    ) -> Result<Value, RpcError> {
        let resp = self
            .client
            .post(url)
            .headers(self.build_headers())
            .json(req)
            .send()
            .await
            .map_err(|e| RpcError::Http {
                method: method.to_string(),
                url: url.to_string(),
                source: e,
            })?;

        let status = resp.status().as_u16();

        if status == 401 {
            return Err(RpcError::AuthFailed {
                url: url.to_string(),
            });
        }

        if status >= 400 {
            let body = resp.text().await.unwrap_or_default();
            return Err(RpcError::HttpStatus {
                method: method.to_string(),
                url: url.to_string(),
                status,
                body: body.chars().take(500).collect(),
            });
        }

        let body: JsonRpcResponse =
            resp.json()
                .await
                .map_err(|e| RpcError::Http {
                    method: method.to_string(),
                    url: url.to_string(),
                    source: e,
                })?;

        if let Some(err) = body.error {
            if err.message == "BUSY" {
                return Err(RpcError::Busy {
                    context: method.to_string(),
                });
            }
            return Err(RpcError::Rpc {
                code: err.code,
                message: err.message,
                method: method.to_string(),
            });
        }

        body.result.ok_or(RpcError::NoResult {
            context: method.to_string(),
        })
    }

    /// POST JSON to a raw endpoint (not JSON-RPC).
    pub async fn post(&self, endpoint: &str, body: &Value) -> Result<Value, RpcError> {
        let url = format!("{}{}", self.config.url, endpoint);

        let attempts = self.config.retries + 1;
        let mut last_err = RpcError::NoResult {
            context: endpoint.to_string(),
        };

        for attempt in 0..attempts {
            if attempt > 0 {
                let delay = self.config.retry_delay * 2u32.saturating_pow(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            match self.do_post(&url, body, endpoint).await {
                Ok(val) => return Ok(val),
                Err(e) => {
                    let should_retry = e.is_transient() && attempt + 1 < attempts;
                    if !should_retry {
                        return Err(e);
                    }
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }

    async fn do_post(
        &self,
        url: &str,
        body: &Value,
        endpoint: &str,
    ) -> Result<Value, RpcError> {
        let resp = self
            .client
            .post(url)
            .headers(self.build_headers())
            .json(body)
            .send()
            .await
            .map_err(|e| RpcError::Http {
                method: endpoint.to_string(),
                url: url.to_string(),
                source: e,
            })?;

        let status = resp.status().as_u16();

        if status == 401 {
            return Err(RpcError::AuthFailed {
                url: url.to_string(),
            });
        }

        if status >= 400 {
            let body = resp.text().await.unwrap_or_default();
            return Err(RpcError::HttpStatus {
                method: endpoint.to_string(),
                url: url.to_string(),
                status,
                body: body.chars().take(500).collect(),
            });
        }

        let val: Value = resp.json().await.map_err(|e| RpcError::Http {
            method: endpoint.to_string(),
            url: url.to_string(),
            source: e,
        })?;

        Ok(val)
    }

    /// POST binary data to a `.bin` endpoint.
    pub async fn post_binary(&self, endpoint: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        let url = format!("{}{}", self.config.url, endpoint);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(auth) = self.auth_header() {
            headers.insert(AUTHORIZATION, auth);
        }

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| RpcError::Http {
                method: endpoint.to_string(),
                url: url.to_string(),
                source: e,
            })?;

        let status = resp.status().as_u16();

        if status == 401 {
            return Err(RpcError::AuthFailed {
                url: url.to_string(),
            });
        }

        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(RpcError::HttpStatus {
                method: endpoint.to_string(),
                url: url.to_string(),
                status,
                body: body_text.chars().take(500).collect(),
            });
        }

        let bytes = resp.bytes().await.map_err(|e| RpcError::Http {
            method: endpoint.to_string(),
            url: url.to_string(),
            source: e,
        })?;
        Ok(bytes.to_vec())
    }

    /// Simple connectivity check (GET /get_info).
    pub async fn is_connected(&self) -> bool {
        self.post("/get_info", &serde_json::json!({}))
            .await
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = RpcConfig::default();
        assert_eq!(config.url, "http://localhost:19081");
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.retries, 2);
    }

    #[test]
    fn test_client_url() {
        let client = RpcClient::new("http://example.com:19081/");
        assert_eq!(client.url(), "http://example.com:19081");
    }

    #[test]
    fn test_request_ids_increment() {
        let client = RpcClient::new("http://localhost:19081");
        let id1 = client.next_id();
        let id2 = client.next_id();
        assert_eq!(id2, id1 + 1);
    }
}
