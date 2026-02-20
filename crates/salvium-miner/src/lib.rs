//! Salvium miner library: shared mining infrastructure.
//!
//! Provides daemon RPC client, IPC protocol, generic mining loop,
//! RandomX utilities, and the `HashAlgorithm` trait for pluggable PoW algorithms.

pub mod randomx;
pub mod daemon;
pub mod miner;
pub mod ipc;
pub mod stratum;
pub mod mining;
