//! Salvium RPC client library.
//!
//! Provides async HTTP clients for the Salvium daemon and wallet JSON-RPC
//! interfaces, plus Epee portable storage binary format support for `.bin`
//! endpoints.
//!
//! # Example
//!
//! ```ignore
//! use salvium_rpc::DaemonRpc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let daemon = DaemonRpc::new("http://localhost:19081");
//!     let info = daemon.get_info().await.unwrap();
//!     println!("Height: {}", info.height);
//! }
//! ```

pub mod error;
pub mod client;
pub mod daemon;
pub mod wallet_rpc;
pub mod portable_storage;

pub use client::RpcClient;
pub use daemon::DaemonRpc;
pub use wallet_rpc::WalletRpc;
pub use error::RpcError;

/// Seed nodes per network.
pub mod seed_nodes {
    pub const MAINNET: &[&str] = &[
        "http://seed01.salvium.io:19081",
        "http://seed02.salvium.io:19081",
        "http://seed03.salvium.io:19081",
    ];
    pub const TESTNET: &[&str] = &[
        "http://seed01.salvium.io:29081",
        "http://seed02.salvium.io:29081",
        "http://seed03.salvium.io:29081",
    ];
    pub const STAGENET: &[&str] = &[
        "http://seed01.salvium.io:39081",
        "http://seed02.salvium.io:39081",
        "http://seed03.salvium.io:39081",
    ];
}

/// Default RPC ports.
pub mod ports {
    pub const DAEMON_MAINNET: u16 = 19081;
    pub const DAEMON_TESTNET: u16 = 29081;
    pub const DAEMON_STAGENET: u16 = 39081;
    pub const WALLET_MAINNET: u16 = 19083;
    pub const WALLET_TESTNET: u16 = 29083;
    pub const WALLET_STAGENET: u16 = 39083;
}
