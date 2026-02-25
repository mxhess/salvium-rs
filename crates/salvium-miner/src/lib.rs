//! Salvium miner library: shared mining infrastructure.
//!
//! Provides daemon RPC client, IPC protocol, generic mining loop,
//! RandomX utilities, and the `HashAlgorithm` trait for pluggable PoW algorithms.

pub mod background;
pub mod daemon;
pub mod ipc;
pub mod miner;
pub mod mining;
pub mod randomx;
pub mod stratum;
