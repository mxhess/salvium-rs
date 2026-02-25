//! Hardware wallet device abstraction layer.
//!
//! Provides a trait-based interface for Ledger and Trezor hardware wallets,
//! with device detection, key image export, and address display.

#[cfg(feature = "hardware-wallet")]
pub mod ledger;
#[cfg(feature = "hardware-wallet")]
pub mod trezor;

use crate::error::WalletError;

/// Supported hardware wallet device types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    None,
    Ledger,
    Trezor,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Ledger => write!(f, "Ledger"),
            Self::Trezor => write!(f, "Trezor"),
        }
    }
}

/// Result of a key image sync operation.
#[derive(Debug)]
pub struct KeyImageSyncResult {
    pub key_images: Vec<ExportedKeyImage>,
    pub num_exported: usize,
}

/// A key image exported from a hardware wallet.
#[derive(Debug, Clone)]
pub struct ExportedKeyImage {
    pub key_image: [u8; 32],
    pub signature: [u8; 64],
    pub output_index: u64,
}

/// Hardware device abstraction trait.
///
/// Implementations for Ledger (APDU over USB HID) and Trezor (protobuf over USB HID).
pub trait HwDevice: Send {
    /// Get the device type.
    fn device_type(&self) -> DeviceType;

    /// Check if the device is currently connected.
    fn is_connected(&self) -> bool;

    /// Attempt to reconnect to the device.
    fn reconnect(&mut self) -> Result<(), WalletError>;

    /// Get the view secret key from the device.
    fn get_view_key(&self) -> Result<[u8; 32], WalletError>;

    /// Export key images for all outputs.
    fn export_key_images(
        &self,
        outputs: &[(u64, [u8; 32])],
    ) -> Result<KeyImageSyncResult, WalletError>;

    /// Display an address on the device screen for verification.
    fn display_address(
        &self,
        major: u32,
        minor: u32,
        payment_id: Option<&[u8; 8]>,
    ) -> Result<(), WalletError>;
}

/// Detect connected hardware wallet devices.
///
/// Tries Ledger first, then Trezor. Returns None if no device is found.
pub fn detect_device() -> Option<Box<dyn HwDevice>> {
    #[cfg(feature = "hardware-wallet")]
    {
        // Try Ledger first.
        if let Some(device) = ledger::LedgerDevice::detect() {
            return Some(Box::new(device));
        }
        // Then Trezor.
        if let Some(device) = trezor::TrezorDevice::detect() {
            return Some(Box::new(device));
        }
    }

    None
}
