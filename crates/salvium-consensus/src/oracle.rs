//! Oracle pricing records and conversion rate calculation for Salvium.
//!
//! Handles pricing record parsing, validation, and asset conversion logic.
//! Signature verification is deferred to the crypto backend (salvium-crypto).
//!
//! Reference: salvium/src/oracle/pricing_record.h, pricing_record.cpp
//!            salvium/src/cryptonote_core/cryptonote_tx_utils.cpp

use salvium_types::constants::{COIN, HfVersion};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Pricing record validity window in blocks.
pub const PRICING_RECORD_VALID_BLOCKS: u64 = 10;

/// Maximum time difference (seconds) between pricing record and block timestamp.
pub const PRICING_RECORD_VALID_TIME_DIFF: u64 = 120;

/// Conversion rate rounding divisor.
pub const CONVERSION_RATE_ROUNDING: u64 = 10_000;

/// Oracle server URLs (mainnet).
pub const ORACLE_URLS: &[&str] = &[
    "https://oracle.salvium.io:8443",
];

/// Oracle public key for mainnet (DSA format, PEM).
pub const ORACLE_PUBLIC_KEY_MAINNET: &str = "-----BEGIN PUBLIC KEY-----
MIIDRDCCAjYGByqGSM44BAEwggIpAoIBAQCZP7IJ5PcNvGbWiEqAioKF9wViVxEN
ZBDHvhr8IR6KoSYUXMU154DC6NDiSr6FtPBWuw9LcXlfWdG0l3hd6zObg0GpEQig
jEeOEeBm45ug9lMBSZiaiCHeU8ats1YIQBYDO8m7iAj9Q9/N1nJHDpypsVu5WGLm
+xSmcNULTbqwJ4Sr49TD++sv2MZEJeYRwmmxlqeFFtZlxguwJ90Y5U7aSi4w4vaU
pu/Ce6EWi8pVhUlM5xBBk3tc+Z6FMMgKFN/kHyu3SbxFaRQppbsTo0N3yDAr3sN3
4JmXpRmDidd3czfKlFko11YwK9lohjrgBnStuFRBxDACx4NRfvRfwPqnAh0AhKyn
pbe2No+7lLGSWuQvIEz+2o6coQ3ZWPbxqQKCAQEAkErfS61wvKxbMwPuuqhCpZG/
uQ+WYHwRwyxpU7ImKiH6ubqModIvZoHrRD8MIJhbRmBlA58SSnBWrEcAUIaaDM6Z
xX/VyOFy2mJH3TJJa83oZe275w1JMVrVq1ZybXSYF595zAHNiJcYsskqTbZP8S30
i3Bq//HMUaRhmB60BLmPpmgF3FVsRkCyEL/yH9cUQWdUcuxIG3C7EzgxGUCaR42J
cu+NN8z6W/m/joEe6QkFT3tLh1yXIFBK1MamWC0EZ6YCMcozZfGQ15P3rMrGptKN
+YQRNusTDSqBky+f40dLiYcT28ePQWNPLdsZTqoGWGawqCyWWCh5eWJZSqJPfQOC
AQYAAoIBAQCE+8kHJmagnDPQWiuHziNha5yia7viwasxcsKhYGx+Z3wVbMrDPwLo
CUgljEEsOKXLZsg/EmfVQu9nYoTcMa0hNq0/0bEV9oZ0t4O8gLp2Y4URLngR9zxE
WaVgFLlNtndHUQA2kquP3XLkv/TZVQaqne6tO6p4gLC4ky0YH0vZhWXMOH/4Xfgf
FZHC7SBC3oYsK9UKX3tJoibcL9L18GOe27pIw70x0280IB/C+TBnAXjslNgJe5ZU
rSdr1h2nXji0rXL9DoypVC40QGIzzjCGMsSBnSYgVuITeqX8/o/w5LBK8Dl5wXFt
F9dg9A0deyw/3CA3gwB32zkfi4MEH+il
-----END PUBLIC KEY-----";

/// Oracle public key for testnet/stagenet (ECDSA format, PEM).
pub const ORACLE_PUBLIC_KEY_TESTNET: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5YBxWx1AZCA9jTUk8Pr2uZ9jpfRt
KWv3Vo1/Gny+1vfaxsXhBQiG1KlHkafNGarzoL0WHW4ocqaaqF5iv8i35A==
-----END PUBLIC KEY-----";

// =============================================================================
// Error Type
// =============================================================================

#[derive(Debug, Error)]
pub enum OracleError {
    #[error("pricing records not allowed before oracle HF")]
    NotEnabled,

    #[error("invalid pricing record signature")]
    InvalidSignature,

    #[error("pricing record timestamp too far in future")]
    TimestampFuture,

    #[error("pricing record timestamp not newer than previous block")]
    TimestampStale,

    #[error("cannot convert to BURN")]
    ConvertToBurn,

    #[error("invalid conversion pair: {from} -> {to}")]
    InvalidConversionPair { from: String, to: String },

    #[error("missing price data for conversion")]
    MissingPriceData,

    #[error("invalid conversion rate")]
    InvalidRate,

    #[error("invalid source amount")]
    InvalidAmount,

    #[error("slippage limit exceeded")]
    SlippageExceeded,

    #[error("source and destination assets are identical")]
    SameAsset,
}

// =============================================================================
// Data Structures
// =============================================================================

/// Individual asset pricing data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetData {
    pub asset_type: String,
    pub spot_price: u64,
    pub ma_price: u64,
}

/// Circulating supply data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SupplyData {
    pub sal: u64,
    pub vsd: u64,
}

/// Oracle pricing record.
///
/// Reference: salvium/src/oracle/pricing_record.h
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingRecord {
    pub pr_version: u32,
    pub height: u64,
    pub supply: SupplyData,
    pub assets: Vec<AssetData>,
    pub timestamp: u64,
    #[serde(with = "hex_serde")]
    pub signature: Vec<u8>,
}

/// Hex serialization for signature bytes.
mod hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

impl PricingRecord {
    /// Create an empty pricing record.
    pub fn empty() -> Self {
        Self {
            pr_version: 0,
            height: 0,
            supply: SupplyData::default(),
            assets: Vec::new(),
            timestamp: 0,
            signature: Vec::new(),
        }
    }

    /// Check if this pricing record is empty.
    pub fn is_empty(&self) -> bool {
        self.pr_version == 0
            && self.height == 0
            && self.supply.sal == 0
            && self.supply.vsd == 0
            && self.assets.is_empty()
            && self.timestamp == 0
            && self.signature.is_empty()
    }

    /// Get spot price for a specific asset.
    pub fn spot_price(&self, asset_type: &str) -> u64 {
        self.assets
            .iter()
            .find(|a| a.asset_type == asset_type)
            .map_or(0, |a| a.spot_price)
    }

    /// Get moving average price for a specific asset.
    pub fn ma_price(&self, asset_type: &str) -> u64 {
        self.assets
            .iter()
            .find(|a| a.asset_type == asset_type)
            .map_or(0, |a| a.ma_price)
    }

    /// Build the JSON message that was signed (compact, no whitespace).
    ///
    /// The signature covers this exact JSON representation.
    ///
    /// Reference: pricing_record.cpp verifySignature()
    pub fn signature_message(&self) -> String {
        // Build with explicit field ordering matching C++
        let assets_json: Vec<serde_json::Value> = self.assets.iter().map(|a| {
            serde_json::json!({
                "asset_type": a.asset_type,
                "spot_price": a.spot_price,
                "ma_price": a.ma_price,
            })
        }).collect();

        let message = serde_json::json!({
            "pr_version": self.pr_version,
            "height": self.height,
            "supply": {
                "SAL": self.supply.sal,
                "VSD": self.supply.vsd,
            },
            "assets": assets_json,
            "timestamp": self.timestamp,
        });

        // Compact JSON (no whitespace)
        serde_json::to_string(&message).unwrap_or_default()
    }
}

// =============================================================================
// Validation
// =============================================================================

/// Get the oracle public key PEM for a given network.
pub fn oracle_public_key(network: salvium_types::constants::Network) -> &'static str {
    match network {
        salvium_types::constants::Network::Mainnet => ORACLE_PUBLIC_KEY_MAINNET,
        _ => ORACLE_PUBLIC_KEY_TESTNET,
    }
}

/// Validate a pricing record (without signature verification).
///
/// Signature verification requires a crypto backend and is done separately.
///
/// Reference: pricing_record.cpp valid()
pub fn validate_pricing_record_structure(
    pr: &PricingRecord,
    hf_version: u8,
    block_timestamp: u64,
    last_block_timestamp: u64,
) -> Result<(), OracleError> {
    // Before SLIPPAGE_YIELD HF, pricing records must be empty
    if hf_version < HfVersion::SLIPPAGE_YIELD && !pr.is_empty() {
        return Err(OracleError::NotEnabled);
    }

    // Empty records are always valid
    if pr.is_empty() {
        return Ok(());
    }

    // Timestamp must not be too far in the future
    if pr.timestamp > block_timestamp + PRICING_RECORD_VALID_TIME_DIFF {
        return Err(OracleError::TimestampFuture);
    }

    // Timestamp must be newer than previous block
    if last_block_timestamp > 0 && pr.timestamp <= last_block_timestamp {
        return Err(OracleError::TimestampStale);
    }

    Ok(())
}

// =============================================================================
// Conversion Rate Calculation
// =============================================================================

/// Get conversion rate between two assets.
///
/// Returns the rate as atomic units per COIN (10^8).
///
/// Reference: cryptonote_tx_utils.cpp get_conversion_rate()
pub fn conversion_rate(
    pr: &PricingRecord,
    from_asset: &str,
    to_asset: &str,
) -> Result<u64, OracleError> {
    // Cannot convert to BURN
    if to_asset == "BURN" {
        return Err(OracleError::ConvertToBurn);
    }

    // Same asset = 1:1
    if from_asset == to_asset {
        return Ok(COIN);
    }

    // Only SAL<->VSD conversions allowed
    if !((from_asset == "SAL" && to_asset == "VSD")
        || (from_asset == "VSD" && to_asset == "SAL"))
    {
        return Err(OracleError::InvalidConversionPair {
            from: from_asset.to_string(),
            to: to_asset.to_string(),
        });
    }

    let from_price = pr.spot_price(from_asset);
    let to_price = pr.spot_price(to_asset);

    if from_price == 0 || to_price == 0 {
        return Err(OracleError::MissingPriceData);
    }

    // rate = (from_price * COIN) / to_price, rounded down to nearest 10000
    let rate = (from_price as u128 * COIN as u128 / to_price as u128) as u64;
    let rate = rate - (rate % CONVERSION_RATE_ROUNDING);

    Ok(rate)
}

/// Calculate converted amount given a conversion rate.
///
/// `dest = (source × rate) / COIN`
///
/// Reference: cryptonote_tx_utils.cpp get_converted_amount()
pub fn converted_amount(rate: u64, source_amount: u64) -> Result<u64, OracleError> {
    if rate == 0 {
        return Err(OracleError::InvalidRate);
    }
    if source_amount == 0 {
        return Err(OracleError::InvalidAmount);
    }

    let dest = (source_amount as u128 * rate as u128 / COIN as u128) as u64;
    Ok(dest)
}

/// Calculate slippage amount for a conversion.
///
/// Slippage is fixed at 1/32 (3.125%) of the amount.
///
/// Reference: cryptonote_tx_utils.cpp calculate_conversion()
pub fn calculate_slippage(amount: u64) -> u64 {
    amount >> 5 // amount / 32 = 3.125%
}

/// Result of a full conversion calculation.
#[derive(Debug, Clone)]
pub struct ConversionResult {
    /// Amount minted in destination asset (0 if refund triggered).
    pub amount_minted: u64,
    /// Actual slippage deducted.
    pub actual_slippage: u64,
    /// Conversion rate used.
    pub rate: u64,
    /// Whether a refund was triggered (slippage exceeded limit).
    pub refund: bool,
}

/// Perform a full conversion calculation with slippage.
///
/// Reference: cryptonote_tx_utils.cpp calculate_conversion()
pub fn calculate_conversion(
    pr: &PricingRecord,
    source_asset: &str,
    dest_asset: &str,
    amount_burnt: u64,
    slippage_limit: u64,
) -> Result<ConversionResult, OracleError> {
    if source_asset == dest_asset {
        return Err(OracleError::SameAsset);
    }

    let rate = conversion_rate(pr, source_asset, dest_asset)?;
    let actual_slippage = calculate_slippage(amount_burnt);

    // If slippage exceeds limit, trigger refund
    if actual_slippage > slippage_limit {
        return Ok(ConversionResult {
            amount_minted: 0,
            actual_slippage,
            rate,
            refund: true,
        });
    }

    let amount_after_slippage = amount_burnt - actual_slippage;
    let minted = converted_amount(rate, amount_after_slippage)?;

    Ok(ConversionResult {
        amount_minted: minted,
        actual_slippage,
        rate,
        refund: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pricing_record() -> PricingRecord {
        PricingRecord {
            pr_version: 1,
            height: 100,
            supply: SupplyData { sal: 1_000_000, vsd: 500_000 },
            assets: vec![
                AssetData {
                    asset_type: "SAL".to_string(),
                    spot_price: 200_000_000, // 2.0 COIN
                    ma_price: 190_000_000,
                },
                AssetData {
                    asset_type: "VSD".to_string(),
                    spot_price: 100_000_000, // 1.0 COIN
                    ma_price: 100_000_000,
                },
            ],
            timestamp: 1000,
            signature: Vec::new(),
        }
    }

    #[test]
    fn test_empty_pricing_record() {
        let pr = PricingRecord::empty();
        assert!(pr.is_empty());
    }

    #[test]
    fn test_spot_price_lookup() {
        let pr = test_pricing_record();
        assert_eq!(pr.spot_price("SAL"), 200_000_000);
        assert_eq!(pr.spot_price("VSD"), 100_000_000);
        assert_eq!(pr.spot_price("UNKNOWN"), 0);
    }

    #[test]
    fn test_conversion_rate_same_asset() {
        let pr = test_pricing_record();
        assert_eq!(conversion_rate(&pr, "SAL", "SAL").unwrap(), COIN);
    }

    #[test]
    fn test_conversion_rate_sal_to_vsd() {
        let pr = test_pricing_record();
        let rate = conversion_rate(&pr, "SAL", "VSD").unwrap();
        // SAL price 200M, VSD price 100M → rate = 200M * 100M / 100M = 200M
        // Rounded to nearest 10000: 200_000_000
        assert_eq!(rate, 200_000_000);
    }

    #[test]
    fn test_conversion_rate_to_burn() {
        let pr = test_pricing_record();
        assert!(conversion_rate(&pr, "SAL", "BURN").is_err());
    }

    #[test]
    fn test_converted_amount() {
        // Rate = 2.0 COIN, source = 1.0 COIN
        let amount = converted_amount(200_000_000, 100_000_000).unwrap();
        // (100M * 200M) / 100M = 200M
        assert_eq!(amount, 200_000_000);
    }

    #[test]
    fn test_slippage() {
        assert_eq!(calculate_slippage(3200), 100); // 3200/32 = 100
        assert_eq!(calculate_slippage(100_000_000), 3_125_000); // 3.125%
    }

    #[test]
    fn test_full_conversion() {
        let pr = test_pricing_record();
        let result = calculate_conversion(
            &pr, "SAL", "VSD",
            100_000_000, // 1 SAL
            10_000_000,  // slippage limit
        ).unwrap();

        assert!(!result.refund);
        assert_eq!(result.actual_slippage, 3_125_000); // 3.125% of 100M
        assert!(result.amount_minted > 0);
    }

    #[test]
    fn test_conversion_slippage_refund() {
        let pr = test_pricing_record();
        let result = calculate_conversion(
            &pr, "SAL", "VSD",
            100_000_000, // 1 SAL
            1_000_000,   // very low slippage limit
        ).unwrap();

        assert!(result.refund);
        assert_eq!(result.amount_minted, 0);
    }

    #[test]
    fn test_conversion_same_asset_error() {
        let pr = test_pricing_record();
        assert!(calculate_conversion(&pr, "SAL", "SAL", 100, 10).is_err());
    }

    #[test]
    fn test_validate_empty_record() {
        let pr = PricingRecord::empty();
        assert!(validate_pricing_record_structure(&pr, 1, 1000, 0).is_ok());
    }

    #[test]
    fn test_validate_record_before_hf() {
        let pr = test_pricing_record();
        // Before SLIPPAGE_YIELD HF, non-empty records are invalid
        assert!(validate_pricing_record_structure(&pr, 1, 1000, 0).is_err());
    }

    #[test]
    fn test_signature_message() {
        let pr = test_pricing_record();
        let msg = pr.signature_message();
        assert!(msg.contains("\"pr_version\":1"));
        assert!(msg.contains("\"height\":100"));
        assert!(!msg.contains(' ')); // compact JSON
    }
}
