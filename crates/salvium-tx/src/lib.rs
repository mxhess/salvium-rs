//! Salvium transaction construction, parsing, and analysis.
//!
//! Provides typed transaction structures, a builder pattern for constructing
//! transactions, CARROT output creation, decoy ring member selection, and
//! fee estimation. Delegates low-level crypto to salvium-crypto.

pub mod types;
pub mod builder;
pub mod carrot;
pub mod decoy;
pub mod fee;
pub mod analysis;
pub mod sign;
pub mod offline;

pub use types::{Transaction, TxPrefix, TxInput, TxOutput, RctSignatures, ProtocolTxData};
pub use builder::TransactionBuilder;
pub use decoy::DecoySelector;
pub use fee::estimate_tx_fee;
pub use sign::sign_transaction;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TxError {
    #[error("parse error: {0}")]
    Parse(String),

    #[error("serialization error: {0}")]
    Serialize(String),

    #[error("invalid transaction: {0}")]
    Invalid(String),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("insufficient inputs: need {need}, have {have}")]
    InsufficientInputs { need: u64, have: u64 },

    #[error("no destinations specified")]
    NoDestinations,

    #[error("ring size mismatch: expected {expected}, got {got}")]
    RingSizeMismatch { expected: usize, got: usize },

    #[error("decoy selection failed: {0}")]
    DecoySelection(String),

    #[error("CARROT output error: {0}")]
    CarrotOutput(String),

    #[error("{0}")]
    Other(String),
}
