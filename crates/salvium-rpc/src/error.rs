//! RPC error types.

use thiserror::Error;

/// JSON-RPC 2.0 standard error codes.
pub mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
}

#[derive(Debug, Error)]
pub enum RpcError {
    /// HTTP transport error (includes reqwest errors).
    #[error("HTTP error on {method} {url}: {source}")]
    Http {
        method: String,
        url: String,
        source: reqwest::Error,
    },

    /// Daemon returned a non-2xx HTTP status code.
    #[error("{method} {url} returned HTTP {status}: {body}")]
    HttpStatus {
        method: String,
        url: String,
        status: u16,
        body: String,
    },

    #[error("JSON parse error on {context}: {source}")]
    Json {
        context: String,
        source: serde_json::Error,
    },

    #[error("RPC error {code} on {method}: {message}")]
    Rpc {
        code: i64,
        message: String,
        method: String,
    },

    /// Daemon returned status != "OK" in a raw endpoint response.
    #[error("{endpoint} returned status={status}: {reason}")]
    DaemonError {
        endpoint: String,
        status: String,
        reason: String,
    },

    #[error("no result in {context} response")]
    NoResult { context: String },

    #[error("request timed out: {context}")]
    Timeout { context: String },

    #[error("authentication failed on {url}")]
    AuthFailed { url: String },

    #[error("daemon busy (syncing): {context}")]
    Busy { context: String },

    #[error("connection failed to {url}: {reason}")]
    Connection { url: String, reason: String },

    #[error("portable storage error: {0}")]
    PortableStorage(String),

    #[error("{0}")]
    Other(String),
}

impl RpcError {
    /// Returns true if this error is transient and the request should be retried.
    pub fn is_transient(&self) -> bool {
        match self {
            RpcError::Http { source, .. } => {
                source.is_connect() || source.is_timeout() || source.is_request()
            }
            RpcError::HttpStatus { status, .. } => {
                *status == 429 || *status == 502 || *status == 503 || *status == 504
            }
            RpcError::Busy { .. } => true,
            RpcError::Connection { .. } => true,
            RpcError::Timeout { .. } => true,
            _ => false,
        }
    }
}

// Keep From<serde_json::Error> for backwards compat in simple cases
impl From<serde_json::Error> for RpcError {
    fn from(e: serde_json::Error) -> Self {
        RpcError::Json {
            context: "unknown".to_string(),
            source: e,
        }
    }
}
