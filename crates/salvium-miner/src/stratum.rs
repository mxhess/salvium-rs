//! Stratum protocol client (stub for future implementation)
//!
//! TODO: Implement stratum+tcp/ssl for pool mining
//! - Login (mining.subscribe, mining.authorize)
//! - Job reception (mining.notify)
//! - Share submission (mining.submit)
//! - Keepalive
//! - TLS support

/// Placeholder for future stratum pool client
#[allow(dead_code)]
pub struct StratumClient {
    _pool_url: String,
}

impl StratumClient {
    #[allow(dead_code)]
    pub fn new(pool_url: &str) -> Self {
        Self {
            _pool_url: pool_url.to_string(),
        }
    }
}
