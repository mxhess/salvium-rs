//! Salvium network constants, address prefixes, and type definitions.
//!
//! Reference: salvium/src/cryptonote_config.h, cryptonote_basic.h

use serde::{Deserialize, Serialize};

// =============================================================================
// Network Types
// =============================================================================

/// Network type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
    Stagenet,
}

/// Address format (legacy CryptoNote vs CARROT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressFormat {
    /// Legacy CryptoNote style (SaLv...)
    Legacy,
    /// CARROT style (SC1...)
    Carrot,
}

/// Address type within a format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressType {
    Standard,
    Integrated,
    Subaddress,
}

// =============================================================================
// Address Prefixes
// =============================================================================

/// Address prefix entry: the varint prefix value and its human-readable text.
#[derive(Debug, Clone, Copy)]
pub struct PrefixInfo {
    pub prefix: u64,
    pub text: &'static str,
    pub network: Network,
    pub format: AddressFormat,
    pub address_type: AddressType,
}

/// All 18 address prefix entries (3 networks × 2 formats × 3 types).
pub static ALL_PREFIXES: [PrefixInfo; 18] = [
    // Mainnet Legacy
    PrefixInfo { prefix: 0x3ef318,     text: "SaLv",   network: Network::Mainnet,  format: AddressFormat::Legacy, address_type: AddressType::Standard },
    PrefixInfo { prefix: 0x55ef318,    text: "SaLvi",  network: Network::Mainnet,  format: AddressFormat::Legacy, address_type: AddressType::Integrated },
    PrefixInfo { prefix: 0xf5ef318,    text: "SaLvs",  network: Network::Mainnet,  format: AddressFormat::Legacy, address_type: AddressType::Subaddress },
    // Mainnet CARROT
    PrefixInfo { prefix: 0x180c96,     text: "SC1",    network: Network::Mainnet,  format: AddressFormat::Carrot, address_type: AddressType::Standard },
    PrefixInfo { prefix: 0x2ccc96,     text: "SC1i",   network: Network::Mainnet,  format: AddressFormat::Carrot, address_type: AddressType::Integrated },
    PrefixInfo { prefix: 0x314c96,     text: "SC1s",   network: Network::Mainnet,  format: AddressFormat::Carrot, address_type: AddressType::Subaddress },
    // Testnet Legacy
    PrefixInfo { prefix: 0x15beb318,   text: "SaLvT",  network: Network::Testnet,  format: AddressFormat::Legacy, address_type: AddressType::Standard },
    PrefixInfo { prefix: 0xd055eb318,  text: "SaLvTi", network: Network::Testnet,  format: AddressFormat::Legacy, address_type: AddressType::Integrated },
    PrefixInfo { prefix: 0xa59eb318,   text: "SaLvTs", network: Network::Testnet,  format: AddressFormat::Legacy, address_type: AddressType::Subaddress },
    // Testnet CARROT
    PrefixInfo { prefix: 0x254c96,     text: "SC1T",   network: Network::Testnet,  format: AddressFormat::Carrot, address_type: AddressType::Standard },
    PrefixInfo { prefix: 0x1ac50c96,   text: "SC1Ti",  network: Network::Testnet,  format: AddressFormat::Carrot, address_type: AddressType::Integrated },
    PrefixInfo { prefix: 0x3c54c96,    text: "SC1Ts",  network: Network::Testnet,  format: AddressFormat::Carrot, address_type: AddressType::Subaddress },
    // Stagenet Legacy
    PrefixInfo { prefix: 0x149eb318,   text: "SaLvS",  network: Network::Stagenet, format: AddressFormat::Legacy, address_type: AddressType::Standard },
    PrefixInfo { prefix: 0xf343eb318,  text: "SaLvSi", network: Network::Stagenet, format: AddressFormat::Legacy, address_type: AddressType::Integrated },
    PrefixInfo { prefix: 0x2d47eb318,  text: "SaLvSs", network: Network::Stagenet, format: AddressFormat::Legacy, address_type: AddressType::Subaddress },
    // Stagenet CARROT
    PrefixInfo { prefix: 0x24cc96,     text: "SC1S",   network: Network::Stagenet, format: AddressFormat::Carrot, address_type: AddressType::Standard },
    PrefixInfo { prefix: 0x1a848c96,   text: "SC1Si",  network: Network::Stagenet, format: AddressFormat::Carrot, address_type: AddressType::Integrated },
    PrefixInfo { prefix: 0x384cc96,    text: "SC1Ss",  network: Network::Stagenet, format: AddressFormat::Carrot, address_type: AddressType::Subaddress },
];

/// Look up prefix info by varint prefix value.
pub fn prefix_info(prefix: u64) -> Option<&'static PrefixInfo> {
    ALL_PREFIXES.iter().find(|p| p.prefix == prefix)
}

/// Get the prefix value for a specific network/format/type combination.
pub fn get_prefix(network: Network, format: AddressFormat, addr_type: AddressType) -> Option<u64> {
    ALL_PREFIXES.iter()
        .find(|p| p.network == network && p.format == format && p.address_type == addr_type)
        .map(|p| p.prefix)
}

// =============================================================================
// Key and Data Sizes
// =============================================================================

/// Size of a public/private key in bytes.
pub const KEY_SIZE: usize = 32;

/// Size of the address checksum in bytes.
pub const CHECKSUM_SIZE: usize = 4;

/// Size of the payment ID for integrated addresses.
pub const PAYMENT_ID_SIZE: usize = 8;

/// Address data sizes (without prefix), indexed by address type.
pub fn address_data_size(addr_type: AddressType) -> usize {
    match addr_type {
        AddressType::Standard   => KEY_SIZE * 2,                     // 64 bytes
        AddressType::Integrated => KEY_SIZE * 2 + PAYMENT_ID_SIZE,   // 72 bytes
        AddressType::Subaddress => KEY_SIZE * 2,                     // 64 bytes
    }
}

// =============================================================================
// Transaction Types
// =============================================================================

/// Salvium transaction type.
///
/// Reference: salvium/src/cryptonote_basic/cryptonote_basic.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum TxType {
    Unset    = 0,
    Miner    = 1,
    Protocol = 2,
    Transfer = 3,
    Convert  = 4,
    Burn     = 5,
    Stake    = 6,
    Return   = 7,
    Audit    = 8,
}

impl TxType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::Unset),
            1 => Some(Self::Miner),
            2 => Some(Self::Protocol),
            3 => Some(Self::Transfer),
            4 => Some(Self::Convert),
            5 => Some(Self::Burn),
            6 => Some(Self::Stake),
            7 => Some(Self::Return),
            8 => Some(Self::Audit),
            _ => None,
        }
    }
}

impl std::fmt::Display for TxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unset    => write!(f, "UNSET"),
            Self::Miner    => write!(f, "MINER"),
            Self::Protocol => write!(f, "PROTOCOL"),
            Self::Transfer => write!(f, "TRANSFER"),
            Self::Convert  => write!(f, "CONVERT"),
            Self::Burn     => write!(f, "BURN"),
            Self::Stake    => write!(f, "STAKE"),
            Self::Return   => write!(f, "RETURN"),
            Self::Audit    => write!(f, "AUDIT"),
        }
    }
}

// =============================================================================
// RingCT Types
// =============================================================================

/// RingCT signature type.
///
/// Reference: salvium/src/ringct/rctTypes.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RctType {
    Null             = 0,
    Full             = 1,
    Simple           = 2,
    Bulletproof      = 3,
    Bulletproof2     = 4,
    Clsag            = 5,
    BulletproofPlus  = 6,
    FullProofs       = 7,
    SalviumZero      = 8,
    SalviumOne       = 9,
}

impl RctType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Null),
            1 => Some(Self::Full),
            2 => Some(Self::Simple),
            3 => Some(Self::Bulletproof),
            4 => Some(Self::Bulletproof2),
            5 => Some(Self::Clsag),
            6 => Some(Self::BulletproofPlus),
            7 => Some(Self::FullProofs),
            8 => Some(Self::SalviumZero),
            9 => Some(Self::SalviumOne),
            _ => None,
        }
    }
}

// =============================================================================
// Transaction Versions
// =============================================================================

/// Current transaction version (CARROT).
pub const CURRENT_TRANSACTION_VERSION: u8 = 4;

/// TX version supporting 2 outputs.
pub const TRANSACTION_VERSION_2_OUTS: u8 = 2;

/// TX version supporting N outputs.
pub const TRANSACTION_VERSION_N_OUTS: u8 = 3;

/// TX version with CARROT support.
pub const TRANSACTION_VERSION_CARROT: u8 = 4;

// =============================================================================
// Hard Fork Versions
// =============================================================================

/// Hard fork version constants for feature gating.
///
/// Reference: salvium/src/cryptonote_config.h HF_VERSION_* defines
pub struct HfVersion;

impl HfVersion {
    // Version 1 features
    pub const DYNAMIC_FEE: u8 = 1;
    pub const PER_BYTE_FEE: u8 = 1;
    pub const ENFORCE_MIN_AGE: u8 = 1;
    pub const EXACT_COINBASE: u8 = 1;
    pub const CLSAG: u8 = 1;
    pub const DETERMINISTIC_UNLOCK_TIME: u8 = 1;
    pub const SMALLER_BP: u8 = 1;
    pub const MIN_V2_COINBASE_TX: u8 = 1;
    pub const REJECT_SIGS_IN_COINBASE: u8 = 1;
    pub const BULLETPROOF_PLUS: u8 = 1;
    pub const ENABLE_RETURN: u8 = 1;
    pub const VIEW_TAGS: u8 = 1;

    // Version 2 features
    pub const LONG_TERM_BLOCK_WEIGHT: u8 = 2;
    pub const SCALING_2021: u8 = 2;
    pub const ENABLE_N_OUTS: u8 = 2;

    // Version 3+
    pub const FULL_PROOFS: u8 = 3;
    pub const ENFORCE_FULL_PROOFS: u8 = 4;
    pub const SHUTDOWN_USER_TXS: u8 = 5;
    pub const AUDIT1: u8 = 6;
    pub const SALVIUM_ONE_PROOFS: u8 = 6;
    pub const AUDIT1_PAUSE: u8 = 7;
    pub const AUDIT2: u8 = 8;
    pub const AUDIT2_PAUSE: u8 = 9;
    pub const CARROT: u8 = 10;

    // Future (placeholder)
    pub const REQUIRE_VIEW_TAGS: u8 = 255;
    pub const ENABLE_CONVERT: u8 = 255;
    pub const ENABLE_ORACLE: u8 = 255;
    pub const SLIPPAGE_YIELD: u8 = 255;
}

// =============================================================================
// Asset Types
// =============================================================================

/// Asset type identifier (SAL pre-HF6, SAL1 post-HF6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetType {
    Sal,
    Sal1,
}

impl AssetType {
    /// The 4-byte tag written into transactions.
    pub fn tag(&self) -> &'static [u8] {
        match self {
            Self::Sal  => b"SAL\0",
            Self::Sal1 => b"SAL1",
        }
    }

    /// Parse from string representation.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "SAL"  => Some(Self::Sal),
            "SAL1" => Some(Self::Sal1),
            _ => None,
        }
    }

    /// Check if two asset types are equivalent (SAL and SAL1 are the same
    /// underlying asset — SAL1 is the post-HF6 rename).
    pub fn equivalent(_a: AssetType, _b: AssetType) -> bool {
        // Both SAL and SAL1 represent the same native asset
        true
    }
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sal  => write!(f, "SAL"),
            Self::Sal1 => write!(f, "SAL1"),
        }
    }
}

// =============================================================================
// Network Configuration
// =============================================================================

/// Hard fork height mapping: version → activation height.
pub type HardForkHeights = &'static [(u8, u64)];

/// Network-specific configuration.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub network: Network,
    pub address_prefix: u64,
    pub integrated_address_prefix: u64,
    pub subaddress_prefix: u64,
    pub carrot_address_prefix: u64,
    pub carrot_integrated_prefix: u64,
    pub carrot_subaddress_prefix: u64,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub zmq_port: u16,
    pub genesis_nonce: u32,
    pub genesis_tx: &'static str,
    pub stake_lock_period: u64,
    pub treasury_sal1_mint_period: u64,
    pub treasury_address: &'static str,
    pub hard_fork_heights: HardForkHeights,
}

// Mainnet hard fork heights
static MAINNET_HF_HEIGHTS: [(u8, u64); 10] = [
    (1, 1),
    (2, 89800),
    (3, 121100),
    (4, 121800),
    (5, 136100),
    (6, 154750),
    (7, 161900),
    (8, 172000),
    (9, 179200),
    (10, 334750),
];

// Testnet hard fork heights
static TESTNET_HF_HEIGHTS: [(u8, u64); 10] = [
    (1, 1),
    (2, 250),
    (3, 500),
    (4, 600),
    (5, 800),
    (6, 815),
    (7, 900),
    (8, 950),
    (9, 1000),
    (10, 1100),
];

// Stagenet hard fork heights (matches testnet)
static STAGENET_HF_HEIGHTS: [(u8, u64); 10] = [
    (1, 1),
    (2, 250),
    (3, 500),
    (4, 600),
    (5, 800),
    (6, 815),
    (7, 900),
    (8, 950),
    (9, 1000),
    (10, 1100),
];

pub static MAINNET_CONFIG: NetworkConfig = NetworkConfig {
    network: Network::Mainnet,
    address_prefix: 0x3ef318,
    integrated_address_prefix: 0x55ef318,
    subaddress_prefix: 0xf5ef318,
    carrot_address_prefix: 0x180c96,
    carrot_integrated_prefix: 0x2ccc96,
    carrot_subaddress_prefix: 0x314c96,
    p2p_port: 19080,
    rpc_port: 19081,
    zmq_port: 19082,
    genesis_nonce: 10000,
    genesis_tx: "020001ff000180c0d0c7bbbff603031c7d3e2240c8ddbc2966c9dcbf703c3aa99624d34b82fbfebd71dcfa001c59800353414c3cb42101d7be8f8312cdd54e1ae390e86d6733c3d8f1ef7be27f75f5acbf0dc57aa8e60d010000",
    stake_lock_period: 21600, // 30 * 24 * 30
    treasury_sal1_mint_period: 21600,
    treasury_address: "SaLvdZR6w1A21sf2Wh6jYEh1wzY4GSbT7RX6FjyPsnLsffWLrzFQeXUXJcmBLRWDzZC2YXeYe5t7qKsnrg9FpmxmEcxPHsEYfqA",
    hard_fork_heights: &MAINNET_HF_HEIGHTS,
};

pub static TESTNET_CONFIG: NetworkConfig = NetworkConfig {
    network: Network::Testnet,
    address_prefix: 0x15beb318,
    integrated_address_prefix: 0xd055eb318,
    subaddress_prefix: 0xa59eb318,
    carrot_address_prefix: 0x254c96,
    carrot_integrated_prefix: 0x1ac50c96,
    carrot_subaddress_prefix: 0x3c54c96,
    p2p_port: 29080,
    rpc_port: 29081,
    zmq_port: 29082,
    genesis_nonce: 10001,
    genesis_tx: "020001ff000180c0d0c7bbbff60302838f76f69b70bb0d0f1961a12f6082a033d22285c07d4f12ec93c28197ae2a600353414c3c2101009e8b0abce686c417a1b1344eb7337176bdca90cc928b0facec8a9516190645010000",
    stake_lock_period: 20,
    treasury_sal1_mint_period: 20,
    treasury_address: "SaLvTyLFta9BiAXeUfFkKvViBkFt4ay5nEUBpWyDKewYggtsoxBbtCUVqaBjtcCDyY1euun8Giv7LLEgvztuurLo5a6Km1zskZn36",
    hard_fork_heights: &TESTNET_HF_HEIGHTS,
};

pub static STAGENET_CONFIG: NetworkConfig = NetworkConfig {
    network: Network::Stagenet,
    address_prefix: 0x149eb318,
    integrated_address_prefix: 0xf343eb318,
    subaddress_prefix: 0x2d47eb318,
    carrot_address_prefix: 0x24cc96,
    carrot_integrated_prefix: 0x1a848c96,
    carrot_subaddress_prefix: 0x384cc96,
    p2p_port: 39080,
    rpc_port: 39081,
    zmq_port: 39082,
    genesis_nonce: 10002,
    genesis_tx: "013c01ff0001ffffffffffff0302df5d56da0c7d643ddd1ce61901c7bdc5fb1738bfe39fbe69c28a3a7032729c0f2101168d0c4ca86fb55a4cf6a36d31431be1c53a3bd7411bb24e8832410289fa6f3b",
    stake_lock_period: 20,
    treasury_sal1_mint_period: 20,
    treasury_address: "fuLMowH85abK8nz9BBMEem7MAfUbQu4aSHHUV9j5Z86o6Go9Lv2U5ZQiJCWPY9R9HA8p5idburazjAhCqDngLo7fYPCD9ciM9ee1A",
    hard_fork_heights: &STAGENET_HF_HEIGHTS,
};

/// Get the network configuration for a given network.
pub fn network_config(network: Network) -> &'static NetworkConfig {
    match network {
        Network::Mainnet  => &MAINNET_CONFIG,
        Network::Testnet  => &TESTNET_CONFIG,
        Network::Stagenet => &STAGENET_CONFIG,
    }
}

// =============================================================================
// Ring Size
// =============================================================================

/// Default ring size for Salvium (16 members).
pub const DEFAULT_RING_SIZE: usize = 16;

// =============================================================================
// Amount Helpers
// =============================================================================

/// Atomic units per coin (10^8).
pub const COIN: u64 = 100_000_000;

/// Number of decimal places for display.
pub const DISPLAY_DECIMAL_POINT: u32 = 8;

/// Format an atomic amount as a human-readable string (e.g., 1.23456789).
pub fn format_amount(atomic: u64) -> String {
    let whole = atomic / COIN;
    let frac = atomic % COIN;
    if frac == 0 {
        format!("{}.0", whole)
    } else {
        let frac_str = format!("{:08}", frac);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{}.{}", whole, trimmed)
    }
}

/// Parse a human-readable amount string to atomic units.
pub fn parse_amount(s: &str) -> Option<u64> {
    let s = s.trim();
    let (whole_str, frac_str) = if let Some(dot_pos) = s.find('.') {
        (&s[..dot_pos], &s[dot_pos + 1..])
    } else {
        (s, "")
    };

    let whole: u64 = whole_str.parse().ok()?;
    let frac: u64 = if frac_str.is_empty() {
        0
    } else {
        if frac_str.len() > 8 {
            return None;
        }
        let padded = format!("{:0<8}", frac_str);
        padded.parse().ok()?
    };

    whole.checked_mul(COIN)?.checked_add(frac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(0), "0.0");
        assert_eq!(format_amount(100_000_000), "1.0");
        assert_eq!(format_amount(123_456_789), "1.23456789");
        assert_eq!(format_amount(100_000_001), "1.00000001");
        assert_eq!(format_amount(50_000_000), "0.5");
    }

    #[test]
    fn test_parse_amount() {
        assert_eq!(parse_amount("0"), Some(0));
        assert_eq!(parse_amount("1.0"), Some(100_000_000));
        assert_eq!(parse_amount("1.23456789"), Some(123_456_789));
        assert_eq!(parse_amount("0.5"), Some(50_000_000));
        assert_eq!(parse_amount("100"), Some(10_000_000_000));
    }

    #[test]
    fn test_prefix_lookup() {
        let info = prefix_info(0x3ef318).unwrap();
        assert_eq!(info.network, Network::Mainnet);
        assert_eq!(info.format, AddressFormat::Legacy);
        assert_eq!(info.address_type, AddressType::Standard);
        assert_eq!(info.text, "SaLv");
    }

    #[test]
    fn test_get_prefix() {
        assert_eq!(
            get_prefix(Network::Testnet, AddressFormat::Carrot, AddressType::Standard),
            Some(0x254c96)
        );
    }

    #[test]
    fn test_tx_type_roundtrip() {
        for v in 0..=8u16 {
            let tt = TxType::from_u16(v).unwrap();
            assert_eq!(tt as u16, v);
        }
        assert!(TxType::from_u16(9).is_none());
    }
}
