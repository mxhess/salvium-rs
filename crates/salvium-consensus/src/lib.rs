//! Salvium consensus: blockchain validation, tree hash, oracle pricing, mining.
//!
//! Builds on `salvium-types` (constants, block reward, difficulty) and adds:
//! - CryptoNote tree hash (Merkle root)
//! - Transaction validation rules (type/version, asset, RCT, inputs, fee, weight)
//! - Oracle pricing records and conversion rate calculation
//! - Block template handling and mining utilities

pub mod tree_hash;
pub mod validation;
pub mod oracle;
pub mod mining;
pub mod chain_state;
pub mod block_weight;
pub mod alt_chain;
