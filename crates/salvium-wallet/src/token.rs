//! Token creation helpers.
//!
//! Validates token parameters and prepares CREATE_TOKEN transaction inputs,
//! matching the C++ wallet2::create_token() validation logic.

use crate::error::WalletError;
use salvium_types::consensus::MONEY_SUPPLY;
use salvium_types::constants::COIN;

/// Cost in SAL1 atomic units to create a token (1000 SAL1).
pub const CREATE_TOKEN_COST: u64 = 1000 * COIN;

/// Maximum allowed decimals for a SAL token.
pub const MAX_TOKEN_DECIMALS: u64 = 8;

/// Required length of a token symbol (asset_type).
pub const TOKEN_SYMBOL_LEN: usize = 4;

/// Reserved asset type prefixes/names that cannot be used for custom tokens.
const RESERVED_NAMES: &[&str] = &["SAL", "SAL1", "SAL2", "BURN"];

/// Validated parameters for creating a token.
#[derive(Debug, Clone)]
pub struct CreateTokenParams {
    pub coin_symbol: String,
    pub coin_supply: u64,
    pub coin_decimals: u64,
    pub metadata: String,
}

/// Validate token creation parameters.
///
/// Matches the C++ wallet_rpc_server::on_create_token() validation:
/// - Symbol must be exactly 4 uppercase alphanumeric characters
/// - Symbol cannot start with "SAL" or be a reserved name
/// - Supply must be 1..=MONEY_SUPPLY
/// - Decimals must be 0..=8
pub fn validate_create_token_params(
    coin_symbol: &str,
    coin_supply: u64,
    coin_decimals: u64,
    metadata: &str,
) -> Result<CreateTokenParams, WalletError> {
    // Symbol must not be empty
    if coin_symbol.is_empty() {
        return Err(WalletError::Other("token symbol cannot be empty".into()));
    }

    // Symbol must be exactly 4 characters
    if coin_symbol.len() != TOKEN_SYMBOL_LEN {
        return Err(WalletError::Other(format!(
            "token symbol must be exactly {} characters, got {}",
            TOKEN_SYMBOL_LEN,
            coin_symbol.len()
        )));
    }

    // Symbol must be uppercase alphanumeric only
    if !coin_symbol.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return Err(WalletError::Other(
            "token symbol must contain only uppercase letters (A-Z) and digits (0-9)".into(),
        ));
    }

    // Cannot start with "SAL"
    if coin_symbol.starts_with("SAL") {
        return Err(WalletError::Other("token symbol cannot start with 'SAL' (reserved)".into()));
    }

    // Cannot be a reserved name
    if RESERVED_NAMES.contains(&coin_symbol) {
        return Err(WalletError::Other(format!("token symbol '{}' is reserved", coin_symbol)));
    }

    // Supply must be at least 1
    if coin_supply == 0 {
        return Err(WalletError::Other("token supply must be at least 1".into()));
    }

    // Supply must not exceed MONEY_SUPPLY
    if coin_supply > MONEY_SUPPLY {
        return Err(WalletError::Other(format!(
            "token supply {} exceeds maximum {}",
            coin_supply, MONEY_SUPPLY
        )));
    }

    // Decimals must not exceed 8
    if coin_decimals > MAX_TOKEN_DECIMALS {
        return Err(WalletError::Other(format!(
            "token decimals {} exceeds maximum {}",
            coin_decimals, MAX_TOKEN_DECIMALS
        )));
    }

    Ok(CreateTokenParams {
        coin_symbol: coin_symbol.to_string(),
        coin_supply,
        coin_decimals,
        metadata: metadata.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_token() {
        let result = validate_create_token_params("TEST", 100_000_000, 8, "A test token");
        assert!(result.is_ok());
        let params = result.unwrap();
        assert_eq!(params.coin_symbol, "TEST");
        assert_eq!(params.coin_supply, 100_000_000);
        assert_eq!(params.coin_decimals, 8);
    }

    #[test]
    fn test_empty_symbol() {
        let result = validate_create_token_params("", 100, 8, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_symbol_too_short() {
        let result = validate_create_token_params("AB", 100, 8, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_symbol_too_long() {
        let result = validate_create_token_params("ABCDE", 100, 8, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_symbol_lowercase_rejected() {
        let result = validate_create_token_params("test", 100, 8, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_symbol_special_chars_rejected() {
        let result = validate_create_token_params("TE-T", 100, 8, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_symbol_with_digits() {
        let result = validate_create_token_params("AB12", 100, 8, "");
        assert!(result.is_ok());
    }

    #[test]
    fn test_sal_prefix_rejected() {
        let result = validate_create_token_params("SALX", 100, 8, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_reserved_names_rejected() {
        // These are all less than 4 chars, so they'd fail length check first,
        // but the prefix check catches "SAL*" patterns at 4 chars.
        let result = validate_create_token_params("BURN", 100, 8, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_supply() {
        let result = validate_create_token_params("TEST", 0, 8, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_supply_exceeds_max() {
        let result = validate_create_token_params("TEST", MONEY_SUPPLY + 1, 8, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_decimals_exceeds_max() {
        let result = validate_create_token_params("TEST", 100, 9, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_decimals_ok() {
        let result = validate_create_token_params("TEST", 100, 0, "");
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_token_cost() {
        assert_eq!(CREATE_TOKEN_COST, 1000 * 100_000_000);
    }
}
