//! Transaction type, RCT type, and I/O type constants.
//!
//! Port of `src/transaction/constants.js` — shared between tx_parse and tx_serialize.

// ─── Transaction Types (cryptonote_protocol/enums.h) ─────────────────────────

pub const TX_TYPE_UNSET: u8 = 0;
pub const TX_TYPE_MINER: u8 = 1;
pub const TX_TYPE_PROTOCOL: u8 = 2;
pub const TX_TYPE_TRANSFER: u8 = 3;
pub const TX_TYPE_CONVERT: u8 = 4;
pub const TX_TYPE_BURN: u8 = 5;
pub const TX_TYPE_STAKE: u8 = 6;
pub const TX_TYPE_RETURN: u8 = 7;
pub const TX_TYPE_AUDIT: u8 = 8;

// ─── RingCT Types ────────────────────────────────────────────────────────────

pub const RCT_TYPE_NULL: u8 = 0;
pub const RCT_TYPE_FULL: u8 = 1;
pub const RCT_TYPE_SIMPLE: u8 = 2;
pub const RCT_TYPE_BULLETPROOF: u8 = 3;
pub const RCT_TYPE_BULLETPROOF2: u8 = 4;
pub const RCT_TYPE_CLSAG: u8 = 5;
pub const RCT_TYPE_BULLETPROOF_PLUS: u8 = 6;
pub const RCT_TYPE_FULL_PROOFS: u8 = 7;
pub const RCT_TYPE_SALVIUM_ZERO: u8 = 8;
pub const RCT_TYPE_SALVIUM_ONE: u8 = 9;

// ─── Transaction Input Types ─────────────────────────────────────────────────

pub const TXIN_GEN: u8 = 0xff;
pub const TXIN_KEY: u8 = 0x02;

// ─── Transaction Output Types ────────────────────────────────────────────────

pub const TXOUT_KEY: u8 = 0x02;
pub const TXOUT_TAGGED_KEY: u8 = 0x03;
pub const TXOUT_CARROT_V1: u8 = 0x04;

// ─── Network Parameters ──────────────────────────────────────────────────────

pub const HF_VERSION_ENABLE_ORACLE: u64 = 255;
