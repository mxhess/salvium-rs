//! Core types and constants for the Salvium cryptocurrency.
//!
//! This crate provides the foundational types used across all Salvium crates:
//! network configurations, address encoding/decoding, mnemonic seed phrases,
//! consensus constants, and transaction type definitions.

pub mod address;
pub mod base58;
pub mod consensus;
pub mod constants;
pub mod mnemonic;
pub mod wordlists;

pub use address::ParsedAddress;
pub use constants::{AddressFormat, AddressType, Network, TxType, RctType, HfVersion};
