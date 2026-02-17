//! Transaction and block validation rules for Salvium.
//!
//! Provides validation functions for transaction type/version, asset types,
//! output types, RCT signature types, input structure, fees, and weight.
//!
//! Functions take individual fields rather than a monolithic TX struct so they
//! can be called from any context (TX builder, block validator, wallet).
//!
//! Reference: salvium/src/cryptonote_core/blockchain.cpp
//!            salvium/src/cryptonote_core/tx_verification_utils.cpp

use salvium_types::constants::{
    HfVersion, TxType, RctType, Network,
    DEFAULT_RING_SIZE, TRANSACTION_VERSION_2_OUTS,
    TRANSACTION_VERSION_CARROT,
    network_config,
};
use salvium_types::consensus::{
    FEE_PER_BYTE, DYNAMIC_FEE_PER_KB_BASE_FEE,
    DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD,
    PER_KB_FEE_QUANTIZATION_DECIMALS,
    min_block_weight,
};
use thiserror::Error;

// =============================================================================
// Error Type
// =============================================================================

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("transaction type UNSET is invalid")]
    TxTypeUnset,

    #[error("invalid transaction type: {0}")]
    InvalidTxType(u16),

    #[error("TX version {version} not allowed at HF {hf_version}")]
    InvalidTxVersion { version: u8, hf_version: u8 },

    #[error("TX type {tx_type} requires version {required} at HF {hf_version}")]
    TxVersionMismatch { tx_type: String, required: u8, hf_version: u8 },

    #[error("CONVERT transactions not enabled before oracle HF")]
    ConvertNotEnabled,

    #[error("AUDIT transactions only allowed in audit HF periods (HF {0})")]
    AuditNotAllowed(u8),

    #[error("invalid source asset type: {0}")]
    InvalidSourceAsset(String),

    #[error("invalid destination asset type: {0}")]
    InvalidDestAsset(String),

    #[error("BURN destination must be BURN, got {0}")]
    BurnDestMismatch(String),

    #[error("BURN source must be SAL or SAL1")]
    BurnSourceInvalid,

    #[error("cannot spend BURN coins")]
    SpendBurn,

    #[error("source asset ({src_asset}) must match destination ({dest_asset}) for TX type {tx_type}")]
    AssetMismatch { src_asset: String, dest_asset: String, tx_type: String },

    #[error("MINER/PROTOCOL must have RCTTypeNull")]
    CoinbaseRctNotNull,

    #[error("TX type {tx_type} must use {required} at HF {hf_version}, got {actual}")]
    WrongRctType { tx_type: String, required: String, actual: String, hf_version: u8 },

    #[error("MINER/PROTOCOL must have exactly 1 input")]
    CoinbaseInputCount,

    #[error("transaction must have at least 1 input")]
    NoInputs,

    #[error("input {index} ring size must be {expected}, got {actual}")]
    WrongRingSize { index: usize, expected: usize, actual: usize },

    #[error("key images must be sorted in strictly increasing order")]
    KeyImagesUnsorted,

    #[error("output public keys must be sorted in increasing order (Carrot fork)")]
    OutputKeysUnsorted,

    #[error("output amounts overflow")]
    OutputOverflow,

    #[error("AUDIT transactions must have 0 outputs")]
    AuditOutputCount,

    #[error("STAKE transactions must have exactly 1 output")]
    StakeOutputCount,

    #[error("non-PROTOCOL transactions must use txout_to_carrot_v1 at Carrot fork")]
    WrongOutputType,

    #[error("all outputs must have the same target type")]
    MixedOutputTypes,

    #[error("insufficient fee: {fee} < {required}")]
    InsufficientFee { fee: u64, required: u64 },

    #[error("transaction weight {weight} exceeds limit {limit}")]
    WeightExceeded { weight: u64, limit: u64 },

    #[error("miner TX input height {input_height} != block height {block_height}")]
    CoinbaseHeightMismatch { input_height: u64, block_height: u64 },

    #[error("miner TX version must be > 1")]
    CoinbaseVersionTooLow,

    #[error("miner TX reward {reward} exceeds allowed {allowed}")]
    CoinbaseRewardTooHigh { reward: u64, allowed: u64 },

    #[error("AUDIT transactions require a return address")]
    AuditReturnRequired,

    #[error("AUDIT transactions must have zero change, got {0}")]
    AuditNonZeroChange(u64),

    #[error("AUDIT transactions must have positive unlock height")]
    AuditZeroUnlockHeight,
}

// =============================================================================
// Constants
// =============================================================================

/// Minimum mixin (ring size - 1). Salvium requires 15 decoys (ring size 16).
pub const MINIMUM_MIXIN: usize = 15;

/// Reserved size for coinbase blob.
pub const COINBASE_BLOB_RESERVED_SIZE: u64 = 600;

/// Valid asset type strings.
pub const VALID_ASSET_TYPES: &[&str] = &["SAL", "SAL1", "BURN"];

/// Output target types (matching C++ cryptonote_basic.h).
pub mod output_type {
    pub const TO_KEY: u8 = 0x02;
    pub const TO_TAGGED_KEY: u8 = 0x03;
    pub const TO_CARROT_V1: u8 = 0x04;
}

/// Audit hard fork periods: maps HF version → allowed.
pub fn is_audit_hf(hf_version: u8) -> bool {
    matches!(hf_version, 6 | 8)
}

/// Blacklisted transaction hashes.
pub const TX_BLACKLIST: &[&str] = &[
    "017a79539e69ce16e91d9aa2267c102f336678c41636567c1129e3e72149499a",
];

// =============================================================================
// Transaction Type and Version Validation
// =============================================================================

/// Validate transaction type and version against hard fork rules.
///
/// Reference: blockchain.cpp:3786-3881
pub fn validate_tx_type_and_version(
    tx_type: TxType,
    version: u8,
    hf_version: u8,
) -> Result<(), ValidationError> {
    // UNSET is always invalid
    if tx_type == TxType::Unset {
        return Err(ValidationError::TxTypeUnset);
    }

    // TX type must be in valid range (1-8)
    let type_val = tx_type as u16;
    if type_val < 1 || type_val > 8 {
        return Err(ValidationError::InvalidTxType(type_val));
    }

    // Before ENABLE_N_OUTS: only TX v2 allowed
    if hf_version < HfVersion::ENABLE_N_OUTS && version != TRANSACTION_VERSION_2_OUTS {
        return Err(ValidationError::InvalidTxVersion {
            version,
            hf_version,
        });
    }

    // Carrot fork requirements
    if hf_version >= HfVersion::CARROT {
        if tx_type != TxType::Transfer
            && tx_type != TxType::Miner
            && tx_type != TxType::Protocol
            && version != TRANSACTION_VERSION_CARROT
        {
            return Err(ValidationError::TxVersionMismatch {
                tx_type: tx_type.to_string(),
                required: TRANSACTION_VERSION_CARROT,
                hf_version,
            });
        }
    }

    // CONVERT requires oracle HF
    if tx_type == TxType::Convert && hf_version < HfVersion::ENABLE_CONVERT {
        return Err(ValidationError::ConvertNotEnabled);
    }

    // AUDIT only in designated periods
    if tx_type == TxType::Audit && !is_audit_hf(hf_version) {
        return Err(ValidationError::AuditNotAllowed(hf_version));
    }

    Ok(())
}

// =============================================================================
// Asset Type Validation
// =============================================================================

fn is_valid_asset(s: &str) -> bool {
    VALID_ASSET_TYPES.contains(&s)
}

/// Validate asset types for a transaction.
///
/// Reference: blockchain.cpp:3852-3860
pub fn validate_asset_types(
    tx_type: TxType,
    source_asset: &str,
    dest_asset: &str,
    _hf_version: u8,
) -> Result<(), ValidationError> {
    if !is_valid_asset(source_asset) {
        return Err(ValidationError::InvalidSourceAsset(source_asset.to_string()));
    }
    if !is_valid_asset(dest_asset) {
        return Err(ValidationError::InvalidDestAsset(dest_asset.to_string()));
    }

    // BURN: dest must be "BURN", source must be SAL or SAL1
    if tx_type == TxType::Burn {
        if dest_asset != "BURN" {
            return Err(ValidationError::BurnDestMismatch(dest_asset.to_string()));
        }
        if source_asset != "SAL" && source_asset != "SAL1" {
            return Err(ValidationError::BurnSourceInvalid);
        }
        return Ok(());
    }

    // Cannot spend BURN coins
    if source_asset == "BURN" {
        return Err(ValidationError::SpendBurn);
    }

    // CONVERT allows different source and dest
    if tx_type == TxType::Convert {
        return Ok(());
    }

    // AUDIT has special rules
    if tx_type == TxType::Audit {
        return Ok(());
    }

    // For all other types, source must equal dest
    if source_asset != dest_asset {
        return Err(ValidationError::AssetMismatch {
            src_asset: source_asset.to_string(),
            dest_asset: dest_asset.to_string(),
            tx_type: tx_type.to_string(),
        });
    }

    Ok(())
}

// =============================================================================
// RCT Type Validation
// =============================================================================

/// Validate RCT signature type for hard fork version.
///
/// Reference: blockchain.cpp:3729-3765
pub fn validate_rct_type(
    tx_type: TxType,
    rct_type: RctType,
    hf_version: u8,
) -> Result<(), ValidationError> {
    // MINER/PROTOCOL must have RCTTypeNull
    if tx_type == TxType::Miner || tx_type == TxType::Protocol {
        if hf_version >= HfVersion::REJECT_SIGS_IN_COINBASE && rct_type != RctType::Null {
            return Err(ValidationError::CoinbaseRctNotNull);
        }
        return Ok(());
    }

    // User transactions
    if hf_version >= HfVersion::CARROT {
        if rct_type != RctType::SalviumOne {
            return Err(ValidationError::WrongRctType {
                tx_type: tx_type.to_string(),
                required: "SalviumOne".to_string(),
                actual: format!("{:?}", rct_type),
                hf_version,
            });
        }
    } else if hf_version >= HfVersion::SALVIUM_ONE_PROOFS {
        if rct_type != RctType::SalviumZero {
            return Err(ValidationError::WrongRctType {
                tx_type: tx_type.to_string(),
                required: "SalviumZero".to_string(),
                actual: format!("{:?}", rct_type),
                hf_version,
            });
        }
    } else if hf_version >= HfVersion::ENFORCE_FULL_PROOFS {
        if rct_type != RctType::FullProofs {
            return Err(ValidationError::WrongRctType {
                tx_type: tx_type.to_string(),
                required: "FullProofs".to_string(),
                actual: format!("{:?}", rct_type),
                hf_version,
            });
        }
    } else if hf_version >= HfVersion::BULLETPROOF_PLUS {
        if rct_type != RctType::BulletproofPlus && rct_type != RctType::Clsag {
            return Err(ValidationError::WrongRctType {
                tx_type: tx_type.to_string(),
                required: "BulletproofPlus or CLSAG".to_string(),
                actual: format!("{:?}", rct_type),
                hf_version,
            });
        }
    }

    Ok(())
}

// =============================================================================
// Input Validation
// =============================================================================

/// Validate input ring sizes.
///
/// Each input must use exactly `DEFAULT_RING_SIZE` (16) ring members.
pub fn validate_input_ring_sizes(ring_sizes: &[usize]) -> Result<(), ValidationError> {
    for (i, &size) in ring_sizes.iter().enumerate() {
        if size != DEFAULT_RING_SIZE {
            return Err(ValidationError::WrongRingSize {
                index: i,
                expected: DEFAULT_RING_SIZE,
                actual: size,
            });
        }
    }
    Ok(())
}

/// Validate that key images are sorted in strictly increasing lexicographic order.
///
/// `key_images` is a slice of 32-byte key images.
pub fn validate_key_image_sorting(key_images: &[[u8; 32]]) -> Result<(), ValidationError> {
    for i in 1..key_images.len() {
        if key_images[i] <= key_images[i - 1] {
            return Err(ValidationError::KeyImagesUnsorted);
        }
    }
    Ok(())
}

/// Validate that output public keys are sorted (Carrot fork requirement).
///
/// Only enforced from CARROT hard fork onwards.
pub fn validate_output_key_sorting(
    output_keys: &[[u8; 32]],
    hf_version: u8,
) -> Result<(), ValidationError> {
    if hf_version < HfVersion::CARROT || output_keys.len() < 2 {
        return Ok(());
    }

    for i in 1..output_keys.len() {
        if output_keys[i] < output_keys[i - 1] {
            return Err(ValidationError::OutputKeysUnsorted);
        }
    }
    Ok(())
}

// =============================================================================
// Output Validation
// =============================================================================

/// Validate output count for special TX types.
pub fn validate_output_count(
    tx_type: TxType,
    output_count: usize,
) -> Result<(), ValidationError> {
    if tx_type == TxType::Audit && output_count != 0 {
        return Err(ValidationError::AuditOutputCount);
    }
    if tx_type == TxType::Stake && output_count != 1 {
        return Err(ValidationError::StakeOutputCount);
    }
    Ok(())
}

/// Validate output target types for Carrot fork.
///
/// `output_types` contains the target type byte for each output.
pub fn validate_output_target_types(
    tx_type: TxType,
    output_types: &[u8],
    hf_version: u8,
) -> Result<(), ValidationError> {
    if hf_version >= HfVersion::CARROT {
        for &otype in output_types {
            if tx_type != TxType::Protocol && tx_type != TxType::Miner {
                if otype != output_type::TO_CARROT_V1 {
                    return Err(ValidationError::WrongOutputType);
                }
            }
        }
    }

    // All outputs must have same type
    if output_types.len() > 1 {
        let first = output_types[0];
        for &otype in &output_types[1..] {
            if otype != first {
                return Err(ValidationError::MixedOutputTypes);
            }
        }
    }

    Ok(())
}

/// Validate AUDIT transaction-specific rules.
///
/// AUDIT transactions:
/// - Must have at least one input
/// - Must have zero outputs
/// - Must have valid asset pair: source SAL or SAL1, dest SAL1
/// - Must have a return address (non-empty)
/// - Must have zero change
/// - Must have positive unlock height
pub fn validate_audit_tx(
    source_asset: &str,
    dest_asset: &str,
    return_address: &str,
    change_amount: u64,
    unlock_height: u64,
    output_count: usize,
    input_count: usize,
) -> Result<(), ValidationError> {
    // Must have at least one input
    if input_count == 0 {
        return Err(ValidationError::NoInputs);
    }

    // Must have zero outputs
    if output_count != 0 {
        return Err(ValidationError::AuditOutputCount);
    }

    // Validate asset pair: dest must be SAL1
    if dest_asset != "SAL1" {
        return Err(ValidationError::InvalidDestAsset(
            format!("AUDIT dest must be SAL1, got {}", dest_asset),
        ));
    }

    // Source must be SAL or SAL1
    if source_asset != "SAL" && source_asset != "SAL1" {
        return Err(ValidationError::InvalidSourceAsset(
            format!("AUDIT source must be SAL or SAL1, got {}", source_asset),
        ));
    }

    // Return address required
    if return_address.is_empty() {
        return Err(ValidationError::AuditReturnRequired);
    }

    // Zero change required
    if change_amount != 0 {
        return Err(ValidationError::AuditNonZeroChange(change_amount));
    }

    // Positive unlock height required
    if unlock_height == 0 {
        return Err(ValidationError::AuditZeroUnlockHeight);
    }

    Ok(())
}

/// Validate that output amounts don't overflow u64.
pub fn validate_output_amounts_overflow(amounts: &[u64]) -> Result<(), ValidationError> {
    let mut total: u64 = 0;
    for &amount in amounts {
        total = total.checked_add(amount).ok_or(ValidationError::OutputOverflow)?;
    }
    Ok(())
}

// =============================================================================
// Fee Validation
// =============================================================================

/// Get the fee quantization mask.
pub fn fee_quantization_mask() -> u64 {
    10u64.pow(PER_KB_FEE_QUANTIZATION_DECIMALS) - 1
}

/// Calculate the required fee for a transaction.
///
/// Reference: blockchain.cpp:4411-4440
pub fn calculate_required_fee(
    tx_weight: u64,
    base_reward: u64,
    hf_version: u8,
) -> u64 {
    let fee_per_byte = if hf_version >= HfVersion::SCALING_2021 {
        let base_fee = DYNAMIC_FEE_PER_KB_BASE_FEE / 1024;
        if base_reward > 0 {
            let f = (base_fee * DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD) / base_reward;
            f.max(FEE_PER_BYTE)
        } else {
            FEE_PER_BYTE
        }
    } else {
        FEE_PER_BYTE
    };

    let mut needed_fee = tx_weight * fee_per_byte;

    // Quantize
    let mask = fee_quantization_mask();
    needed_fee = ((needed_fee + mask) / (mask + 1)) * (mask + 1);

    needed_fee
}

/// Validate that a transaction fee meets the minimum requirement.
///
/// Allows 2% tolerance.
pub fn validate_fee(
    fee: u64,
    tx_weight: u64,
    base_reward: u64,
    hf_version: u8,
) -> Result<(), ValidationError> {
    let needed = calculate_required_fee(tx_weight, base_reward, hf_version);

    // Allow 2% tolerance
    let min_fee = needed - (needed / 50);

    if fee < min_fee {
        return Err(ValidationError::InsufficientFee {
            fee,
            required: needed,
        });
    }

    Ok(())
}

// =============================================================================
// Transaction Weight Validation
// =============================================================================

/// Get maximum transaction weight limit.
///
/// Reference: tx_verification_utils.cpp:144-151
pub fn max_tx_weight(hf_version: u8) -> u64 {
    let min_weight = min_block_weight(hf_version);
    if hf_version >= 2 {
        min_weight / 2 - COINBASE_BLOB_RESERVED_SIZE
    } else {
        min_weight - COINBASE_BLOB_RESERVED_SIZE
    }
}

/// Validate transaction weight against limit.
pub fn validate_tx_weight(tx_weight: u64, hf_version: u8) -> Result<(), ValidationError> {
    let limit = max_tx_weight(hf_version);
    if tx_weight > limit {
        return Err(ValidationError::WeightExceeded {
            weight: tx_weight,
            limit,
        });
    }
    Ok(())
}

// =============================================================================
// Coinbase (Miner TX) Validation
// =============================================================================

/// Validate a miner transaction's basic structure.
///
/// Reference: blockchain.cpp:1344-1386
pub fn validate_miner_tx_structure(
    input_height: u64,
    block_height: u64,
    tx_version: u8,
    tx_type: TxType,
    hf_version: u8,
) -> Result<(), ValidationError> {
    // Input height must match block height
    if input_height != block_height {
        return Err(ValidationError::CoinbaseHeightMismatch {
            input_height,
            block_height,
        });
    }

    // Version must be > 1
    if tx_version <= 1 {
        return Err(ValidationError::CoinbaseVersionTooLow);
    }

    // Carrot fork: must use CARROT version and MINER type
    if hf_version >= HfVersion::CARROT {
        if tx_version != TRANSACTION_VERSION_CARROT {
            return Err(ValidationError::InvalidTxVersion {
                version: tx_version,
                hf_version,
            });
        }
        if tx_type != TxType::Miner {
            return Err(ValidationError::TxVersionMismatch {
                tx_type: tx_type.to_string(),
                required: TRANSACTION_VERSION_CARROT,
                hf_version,
            });
        }
    }

    Ok(())
}

/// Validate miner transaction reward against block reward + fees.
pub fn validate_miner_tx_reward(
    output_total: u64,
    base_reward: u64,
    total_fees: u64,
) -> Result<(), ValidationError> {
    let allowed = base_reward + total_fees;
    if output_total > allowed {
        return Err(ValidationError::CoinbaseRewardTooHigh {
            reward: output_total,
            allowed,
        });
    }
    Ok(())
}

// =============================================================================
// Stake / Yield
// =============================================================================

/// Get the stake lock period for a network.
pub fn stake_lock_period(network: Network) -> u64 {
    network_config(network).stake_lock_period
}

/// Calculate yield payout for a STAKE transaction.
///
/// For each block in the lock period, yield is:
///   `(slippage_total × staked_amount) / locked_coins_tally`
///
/// Reference: blockchain.cpp:4714-4777
pub fn calculate_yield_payout(
    staked_amount: u64,
    block_slippages: &[(u64, u64)], // (slippage_total, locked_coins_tally)
) -> u64 {
    let mut total_yield: u128 = 0;

    for &(slippage, tally) in block_slippages {
        if tally == 0 {
            continue;
        }
        // Use u128 to avoid overflow: (slippage * staked) / tally
        total_yield += (slippage as u128 * staked_amount as u128) / tally as u128;
    }

    total_yield as u64
}

// =============================================================================
// Transaction Blacklist
// =============================================================================

/// Check if a transaction hash is blacklisted.
pub fn is_tx_blacklisted(tx_hash_hex: &str) -> bool {
    TX_BLACKLIST.contains(&tx_hash_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_tx_type_unset() {
        let result = validate_tx_type_and_version(TxType::Unset, 2, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_tx_type_transfer() {
        let result = validate_tx_type_and_version(TxType::Transfer, 2, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tx_type_carrot_version() {
        // At Carrot fork, non-transfer types need version 4
        let result = validate_tx_type_and_version(TxType::Stake, 2, HfVersion::CARROT);
        assert!(result.is_err());

        let result = validate_tx_type_and_version(TxType::Stake, 4, HfVersion::CARROT);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_asset_burn() {
        let result = validate_asset_types(TxType::Burn, "SAL", "BURN", 6);
        assert!(result.is_ok());

        let result = validate_asset_types(TxType::Burn, "SAL", "SAL", 6);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_asset_spend_burn() {
        let result = validate_asset_types(TxType::Transfer, "BURN", "BURN", 6);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_asset_mismatch() {
        let result = validate_asset_types(TxType::Transfer, "SAL", "SAL1", 6);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rct_type_coinbase() {
        let result = validate_rct_type(TxType::Miner, RctType::Null, 1);
        assert!(result.is_ok());

        let result = validate_rct_type(TxType::Miner, RctType::BulletproofPlus, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rct_type_carrot() {
        let result = validate_rct_type(TxType::Transfer, RctType::SalviumOne, HfVersion::CARROT);
        assert!(result.is_ok());

        let result = validate_rct_type(TxType::Transfer, RctType::SalviumZero, HfVersion::CARROT);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ring_size() {
        let sizes = vec![16, 16, 16];
        assert!(validate_input_ring_sizes(&sizes).is_ok());

        let sizes = vec![16, 11, 16];
        assert!(validate_input_ring_sizes(&sizes).is_err());
    }

    #[test]
    fn test_validate_key_image_sorting() {
        let ki1 = [0x01u8; 32];
        let ki2 = [0x02u8; 32];
        let ki3 = [0x03u8; 32];

        assert!(validate_key_image_sorting(&[ki1, ki2, ki3]).is_ok());
        assert!(validate_key_image_sorting(&[ki2, ki1, ki3]).is_err());
        assert!(validate_key_image_sorting(&[ki1, ki1, ki3]).is_err());
    }

    #[test]
    fn test_validate_output_count_audit() {
        assert!(validate_output_count(TxType::Audit, 0).is_ok());
        assert!(validate_output_count(TxType::Audit, 1).is_err());
    }

    #[test]
    fn test_validate_output_count_stake() {
        assert!(validate_output_count(TxType::Stake, 1).is_ok());
        assert!(validate_output_count(TxType::Stake, 2).is_err());
    }

    #[test]
    fn test_validate_output_overflow() {
        assert!(validate_output_amounts_overflow(&[100, 200, 300]).is_ok());
        assert!(validate_output_amounts_overflow(&[u64::MAX, 1]).is_err());
    }

    #[test]
    fn test_validate_tx_weight() {
        // HF v2: limit = 300000/2 - 600 = 149400
        assert!(validate_tx_weight(100_000, 2).is_ok());
        assert!(validate_tx_weight(200_000, 2).is_err());
    }

    #[test]
    fn test_fee_quantization() {
        let mask = fee_quantization_mask();
        assert_eq!(mask, 99_999_999); // 10^8 - 1
    }

    #[test]
    fn test_stake_lock_period() {
        assert_eq!(stake_lock_period(Network::Mainnet), 21600);
        assert_eq!(stake_lock_period(Network::Testnet), 20);
    }

    #[test]
    fn test_yield_payout() {
        // 100 SAL staked, 3 blocks: (slippage=10, tally=1000)
        let blocks = vec![(10u64, 1000u64), (20, 1000), (0, 0)];
        let payout = calculate_yield_payout(100_000_000, &blocks);
        // Block 0: (10 * 100M) / 1000 = 1_000_000
        // Block 1: (20 * 100M) / 1000 = 2_000_000
        // Block 2: skipped (tally=0)
        assert_eq!(payout, 3_000_000);
    }

    #[test]
    fn test_tx_blacklist() {
        assert!(is_tx_blacklisted(
            "017a79539e69ce16e91d9aa2267c102f336678c41636567c1129e3e72149499a"
        ));
        assert!(!is_tx_blacklisted("0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn test_validate_miner_tx_structure() {
        assert!(validate_miner_tx_structure(100, 100, 2, TxType::Miner, 1).is_ok());
        assert!(validate_miner_tx_structure(99, 100, 2, TxType::Miner, 1).is_err());
        assert!(validate_miner_tx_structure(100, 100, 1, TxType::Miner, 1).is_err());
    }

    #[test]
    fn test_validate_miner_tx_reward() {
        assert!(validate_miner_tx_reward(1000, 900, 100).is_ok());
        assert!(validate_miner_tx_reward(1001, 900, 100).is_err());
    }

    // =========================================================================
    // AUDIT transaction validation tests
    // =========================================================================

    #[test]
    fn test_audit_valid_sal_to_sal1() {
        let result = validate_audit_tx("SAL", "SAL1", "SaLvAddress123", 0, 500000, 0, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_valid_sal1_to_sal1() {
        let result = validate_audit_tx("SAL1", "SAL1", "SaLvAddress123", 0, 600000, 0, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_invalid_sal_to_sal() {
        // SAL -> SAL is rejected because dest must be SAL1
        let result = validate_audit_tx("SAL", "SAL", "SaLvAddress123", 0, 500000, 0, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidDestAsset(_)));
    }

    #[test]
    fn test_audit_invalid_burn_source() {
        // BURN source is rejected
        let result = validate_audit_tx("BURN", "SAL1", "SaLvAddress123", 0, 500000, 0, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidSourceAsset(_)));
    }

    #[test]
    fn test_audit_invalid_dest_sal() {
        // dest SAL rejected (must be SAL1)
        let result = validate_audit_tx("SAL", "SAL", "SaLvAddress123", 0, 500000, 0, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidDestAsset(_)));
    }

    #[test]
    fn test_audit_invalid_dest_burn() {
        // dest BURN rejected
        let result = validate_audit_tx("SAL", "BURN", "SaLvAddress123", 0, 500000, 0, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidDestAsset(_)));
    }

    #[test]
    fn test_audit_missing_return_address() {
        // Empty return address rejected
        let result = validate_audit_tx("SAL", "SAL1", "", 0, 500000, 0, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::AuditReturnRequired));
    }

    #[test]
    fn test_audit_nonzero_change() {
        // Nonzero change rejected
        let result = validate_audit_tx("SAL", "SAL1", "SaLvAddress123", 1000, 500000, 0, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::AuditNonZeroChange(1000)));
    }

    #[test]
    fn test_audit_zero_unlock_height() {
        // Zero unlock height rejected
        let result = validate_audit_tx("SAL", "SAL1", "SaLvAddress123", 0, 0, 0, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::AuditZeroUnlockHeight));
    }

    #[test]
    fn test_audit_nonzero_outputs() {
        // output_count > 0 rejected
        let result = validate_audit_tx("SAL", "SAL1", "SaLvAddress123", 0, 500000, 2, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::AuditOutputCount));
    }

    #[test]
    fn test_audit_no_inputs() {
        // input_count = 0 rejected
        let result = validate_audit_tx("SAL", "SAL1", "SaLvAddress123", 0, 500000, 0, 0);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::NoInputs));
    }

    #[test]
    fn test_audit_all_valid_fields() {
        // Verify all fields are checked in a valid case
        let result = validate_audit_tx(
            "SAL",           // valid source
            "SAL1",          // valid dest
            "SaLvAddr",      // non-empty return address
            0,               // zero change
            500000,          // positive unlock height
            0,               // zero outputs
            2,               // multiple inputs OK
        );
        assert!(result.is_ok());

        // Also verify SAL1 source variant
        let result = validate_audit_tx("SAL1", "SAL1", "SaLvAddr", 0, 1, 0, 1);
        assert!(result.is_ok());
    }
}
