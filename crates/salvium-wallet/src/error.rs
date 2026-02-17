//! Wallet error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("invalid seed length: expected 32, got {0}")]
    InvalidSeedLength(usize),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("RPC error: {0}")]
    Rpc(#[from] salvium_rpc::RpcError),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption failed (wrong password or corrupted data)")]
    DecryptionFailed,

    #[error("sync error: {0}")]
    Sync(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u64, have: u64 },

    #[error("no suitable outputs for selection")]
    NoOutputs,

    #[error("wallet is view-only, cannot {0}")]
    ViewOnly(String),

    #[error("wallet not synced")]
    NotSynced,

    #[error("invalid wallet file: {0}")]
    InvalidFile(String),

    #[error("{0}")]
    Other(String),
}
