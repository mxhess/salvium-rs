//! Salvium address parsing, validation, and creation.
//!
//! Supports all 18 address types across 3 networks × 2 formats × 3 types.

use crate::base58;
use crate::constants::{
    address_data_size, prefix_info, get_prefix,
    AddressFormat, AddressType, Network,
    KEY_SIZE, PAYMENT_ID_SIZE,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("address must be a non-empty string")]
    Empty,

    #[error("invalid address length ({0})")]
    InvalidLength(usize),

    #[error("base58 decode error: {0}")]
    Base58(#[from] base58::Base58Error),

    #[error("unknown address prefix: 0x{0:x}")]
    UnknownPrefix(u64),

    #[error("invalid data length: expected {expected} bytes, got {actual}")]
    InvalidDataLength { expected: usize, actual: usize },

    #[error("spendPublicKey is required")]
    MissingSpendKey,

    #[error("viewPublicKey is required")]
    MissingViewKey,

    #[error("key must be {expected} bytes, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    #[error("paymentId is required for integrated addresses")]
    MissingPaymentId,

    #[error("paymentId must be {expected} bytes, got {actual}")]
    InvalidPaymentIdSize { expected: usize, actual: usize },

    #[error("invalid network/format/type combination")]
    InvalidCombination,

    #[error("address must be a standard address, got {0:?}")]
    NotStandard(AddressType),

    #[error("address must be an integrated address, got {0:?}")]
    NotIntegrated(AddressType),
}

/// Result of parsing an address.
#[derive(Debug, Clone)]
pub struct ParsedAddress {
    pub network: Network,
    pub format: AddressFormat,
    pub address_type: AddressType,
    pub prefix_text: &'static str,
    pub spend_public_key: [u8; KEY_SIZE],
    pub view_public_key: [u8; KEY_SIZE],
    pub payment_id: Option<[u8; PAYMENT_ID_SIZE]>,
}

impl ParsedAddress {
    pub fn is_carrot(&self) -> bool {
        self.format == AddressFormat::Carrot
    }

    pub fn is_legacy(&self) -> bool {
        self.format == AddressFormat::Legacy
    }

    /// Re-encode this parsed address back to a Base58 string.
    pub fn to_address_string(&self) -> String {
        create_address_raw(
            self.network,
            self.format,
            self.address_type,
            &self.spend_public_key,
            &self.view_public_key,
            self.payment_id.as_ref().map(|p| p.as_slice()),
        )
        .expect("ParsedAddress should always re-encode successfully")
    }
}

/// Parse and validate a Salvium address string.
pub fn parse_address(address: &str) -> Result<ParsedAddress, AddressError> {
    let address = address.trim();
    if address.is_empty() {
        return Err(AddressError::Empty);
    }

    // Rough length bounds (standard ~95-99, integrated ~106-110)
    if address.len() < 90 || address.len() > 150 {
        return Err(AddressError::InvalidLength(address.len()));
    }

    let (tag, data) = base58::decode_address(address)?;

    let info = prefix_info(tag).ok_or(AddressError::UnknownPrefix(tag))?;

    let expected_size = address_data_size(info.address_type);
    if data.len() != expected_size {
        return Err(AddressError::InvalidDataLength {
            expected: expected_size,
            actual: data.len(),
        });
    }

    let mut spend_public_key = [0u8; KEY_SIZE];
    spend_public_key.copy_from_slice(&data[..KEY_SIZE]);

    let mut view_public_key = [0u8; KEY_SIZE];
    view_public_key.copy_from_slice(&data[KEY_SIZE..KEY_SIZE * 2]);

    let payment_id = if info.address_type == AddressType::Integrated {
        let mut pid = [0u8; PAYMENT_ID_SIZE];
        pid.copy_from_slice(&data[KEY_SIZE * 2..KEY_SIZE * 2 + PAYMENT_ID_SIZE]);
        Some(pid)
    } else {
        None
    };

    Ok(ParsedAddress {
        network: info.network,
        format: info.format,
        address_type: info.address_type,
        prefix_text: info.text,
        spend_public_key,
        view_public_key,
        payment_id,
    })
}

/// Validate a Salvium address string.
pub fn is_valid_address(address: &str) -> bool {
    parse_address(address).is_ok()
}

/// Create an address string from components.
pub fn create_address_raw(
    network: Network,
    format: AddressFormat,
    addr_type: AddressType,
    spend_public_key: &[u8],
    view_public_key: &[u8],
    payment_id: Option<&[u8]>,
) -> Result<String, AddressError> {
    if spend_public_key.len() != KEY_SIZE {
        return Err(AddressError::InvalidKeySize {
            expected: KEY_SIZE,
            actual: spend_public_key.len(),
        });
    }
    if view_public_key.len() != KEY_SIZE {
        return Err(AddressError::InvalidKeySize {
            expected: KEY_SIZE,
            actual: view_public_key.len(),
        });
    }

    let prefix = get_prefix(network, format, addr_type)
        .ok_or(AddressError::InvalidCombination)?;

    let data = match addr_type {
        AddressType::Integrated => {
            let pid = payment_id.ok_or(AddressError::MissingPaymentId)?;
            if pid.len() != PAYMENT_ID_SIZE {
                return Err(AddressError::InvalidPaymentIdSize {
                    expected: PAYMENT_ID_SIZE,
                    actual: pid.len(),
                });
            }
            let mut d = Vec::with_capacity(KEY_SIZE * 2 + PAYMENT_ID_SIZE);
            d.extend_from_slice(spend_public_key);
            d.extend_from_slice(view_public_key);
            d.extend_from_slice(pid);
            d
        }
        _ => {
            let mut d = Vec::with_capacity(KEY_SIZE * 2);
            d.extend_from_slice(spend_public_key);
            d.extend_from_slice(view_public_key);
            d
        }
    };

    Ok(base58::encode_address(prefix, &data))
}

/// Convert a standard address to an integrated address by adding a payment ID.
pub fn to_integrated_address(
    address: &str,
    payment_id: &[u8; PAYMENT_ID_SIZE],
) -> Result<String, AddressError> {
    let parsed = parse_address(address)?;
    if parsed.address_type != AddressType::Standard {
        return Err(AddressError::NotStandard(parsed.address_type));
    }

    create_address_raw(
        parsed.network,
        parsed.format,
        AddressType::Integrated,
        &parsed.spend_public_key,
        &parsed.view_public_key,
        Some(payment_id),
    )
}

/// Extract the standard address from an integrated address.
pub fn to_standard_address(address: &str) -> Result<String, AddressError> {
    let parsed = parse_address(address)?;
    if parsed.address_type != AddressType::Integrated {
        return Err(AddressError::NotIntegrated(parsed.address_type));
    }

    create_address_raw(
        parsed.network,
        parsed.format,
        AddressType::Standard,
        &parsed.spend_public_key,
        &parsed.view_public_key,
        None,
    )
}

/// Describe an address in human-readable form.
pub fn describe_address(address: &str) -> String {
    match parse_address(address) {
        Ok(parsed) => {
            let network = match parsed.network {
                Network::Mainnet => "Mainnet",
                Network::Testnet => "Testnet",
                Network::Stagenet => "Stagenet",
            };
            let format = match parsed.format {
                AddressFormat::Legacy => "Legacy",
                AddressFormat::Carrot => "CARROT",
            };
            let addr_type = match parsed.address_type {
                AddressType::Standard => "standard",
                AddressType::Integrated => "integrated",
                AddressType::Subaddress => "subaddress",
            };

            if let Some(pid) = &parsed.payment_id {
                format!(
                    "{} {} {} (Payment ID: {})",
                    network, format, addr_type, hex::encode(pid)
                )
            } else {
                format!("{} {} {}", network, format, addr_type)
            }
        }
        Err(e) => format!("Invalid address: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_address_roundtrip() {
        // Create a mainnet legacy standard address with known keys
        let spend_key = [0x01u8; 32];
        let view_key = [0x02u8; 32];

        let address = create_address_raw(
            Network::Mainnet,
            AddressFormat::Legacy,
            AddressType::Standard,
            &spend_key,
            &view_key,
            None,
        )
        .unwrap();

        // Parse it back
        let parsed = parse_address(&address).unwrap();
        assert_eq!(parsed.network, Network::Mainnet);
        assert_eq!(parsed.format, AddressFormat::Legacy);
        assert_eq!(parsed.address_type, AddressType::Standard);
        assert_eq!(parsed.spend_public_key, spend_key);
        assert_eq!(parsed.view_public_key, view_key);
        assert!(parsed.payment_id.is_none());
    }

    #[test]
    fn test_integrated_address_roundtrip() {
        let spend_key = [0x11u8; 32];
        let view_key = [0x22u8; 32];
        let payment_id = [0xAA; PAYMENT_ID_SIZE];

        let address = create_address_raw(
            Network::Testnet,
            AddressFormat::Carrot,
            AddressType::Integrated,
            &spend_key,
            &view_key,
            Some(&payment_id),
        )
        .unwrap();

        let parsed = parse_address(&address).unwrap();
        assert_eq!(parsed.network, Network::Testnet);
        assert_eq!(parsed.format, AddressFormat::Carrot);
        assert_eq!(parsed.address_type, AddressType::Integrated);
        assert_eq!(parsed.payment_id, Some(payment_id));
    }

    #[test]
    fn test_integrated_conversion() {
        let spend_key = [0x33u8; 32];
        let view_key = [0x44u8; 32];

        let standard = create_address_raw(
            Network::Mainnet,
            AddressFormat::Legacy,
            AddressType::Standard,
            &spend_key,
            &view_key,
            None,
        )
        .unwrap();

        let payment_id = [0xBB; PAYMENT_ID_SIZE];
        let integrated = to_integrated_address(&standard, &payment_id).unwrap();
        let back = to_standard_address(&integrated).unwrap();

        let parsed_std = parse_address(&standard).unwrap();
        let parsed_back = parse_address(&back).unwrap();
        assert_eq!(parsed_std.spend_public_key, parsed_back.spend_public_key);
        assert_eq!(parsed_std.view_public_key, parsed_back.view_public_key);
    }
}
