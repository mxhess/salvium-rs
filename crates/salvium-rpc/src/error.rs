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
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("RPC error {code}: {message}")]
    Rpc { code: i64, message: String },

    #[error("no result in response")]
    NoResult,

    #[error("request timed out")]
    Timeout,

    #[error("authentication failed")]
    AuthFailed,

    #[error("daemon busy (syncing)")]
    Busy,

    #[error("connection failed: {0}")]
    Connection(String),

    #[error("portable storage error: {0}")]
    PortableStorage(String),

    #[error("{0}")]
    Other(String),
}
