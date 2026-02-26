//! Ledger hardware wallet support via USB HID (APDU protocol).
//!
//! Communicates with the Monero/Salvium app on Ledger devices using
//! the standard APDU instruction set over USB HID.

use super::*;

/// Ledger USB Vendor ID.
const LEDGER_VENDOR_ID: u16 = 0x2C97;

/// APDU instruction codes for the Monero/Salvium Ledger app.
const INS_GET_KEY: u8 = 0x20;
const INS_EXPORT_KEY_IMAGE: u8 = 0x62;
const INS_DISPLAY_ADDRESS: u8 = 0x64;

/// CLA byte for the Monero/Salvium Ledger app.
const CLA: u8 = 0x00;

/// Ledger device communicating via USB HID.
pub struct LedgerDevice {
    #[cfg(feature = "hardware-wallet")]
    device: hidapi::HidDevice,
    connected: bool,
}

impl LedgerDevice {
    /// Try to detect and open a connected Ledger device.
    #[cfg(feature = "hardware-wallet")]
    pub fn detect() -> Option<Self> {
        let api = hidapi::HidApi::new().ok()?;
        for device_info in api.device_list() {
            if device_info.vendor_id() == LEDGER_VENDOR_ID {
                if let Ok(device) = api.open_path(device_info.path()) {
                    return Some(Self { device, connected: true });
                }
            }
        }
        None
    }

    #[cfg(not(feature = "hardware-wallet"))]
    pub fn detect() -> Option<Self> {
        None
    }

    /// Send an APDU command and receive the response.
    #[cfg(feature = "hardware-wallet")]
    fn exchange_apdu(&self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>, WalletError> {
        // Build APDU: CLA INS P1 P2 Lc Data
        let mut apdu = vec![CLA, ins, p1, p2, data.len() as u8];
        apdu.extend_from_slice(data);

        // HID framing: prepend 2-byte channel ID and sequence.
        let mut frame = vec![0x00, 0x01, 0x00, 0x00, 0x00];
        let apdu_len = apdu.len() as u16;
        frame.push((apdu_len >> 8) as u8);
        frame.push((apdu_len & 0xFF) as u8);
        frame.extend_from_slice(&apdu);

        // Pad to 64 bytes.
        frame.resize(64, 0);

        self.device
            .write(&frame)
            .map_err(|e| WalletError::Device(format!("USB write failed: {}", e)))?;

        // Read response.
        let mut buf = [0u8; 64];
        let n = self
            .device
            .read_timeout(&mut buf, 30000)
            .map_err(|e| WalletError::Device(format!("USB read failed: {}", e)))?;

        if n < 7 {
            return Err(WalletError::Device("response too short".to_string()));
        }

        // Extract response length and data.
        let resp_len = ((buf[5] as usize) << 8) | (buf[6] as usize);
        if resp_len > n - 7 {
            return Err(WalletError::Device("response length mismatch".to_string()));
        }

        let response = buf[7..7 + resp_len].to_vec();

        // Check status word (last 2 bytes).
        if response.len() >= 2 {
            let sw =
                ((response[response.len() - 2] as u16) << 8) | response[response.len() - 1] as u16;
            if sw != 0x9000 {
                return Err(WalletError::Device(format!("Ledger returned error: 0x{:04X}", sw)));
            }
        }

        Ok(response)
    }
}

impl HwDevice for LedgerDevice {
    fn device_type(&self) -> DeviceType {
        DeviceType::Ledger
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn reconnect(&mut self) -> Result<(), WalletError> {
        #[cfg(feature = "hardware-wallet")]
        {
            let api = hidapi::HidApi::new()
                .map_err(|e| WalletError::Device(format!("HID init failed: {}", e)))?;
            for device_info in api.device_list() {
                if device_info.vendor_id() == LEDGER_VENDOR_ID {
                    match api.open_path(device_info.path()) {
                        Ok(device) => {
                            self.device = device;
                            self.connected = true;
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(WalletError::Device(format!(
                                "failed to open Ledger: {}",
                                e
                            )));
                        }
                    }
                }
            }
            self.connected = false;
            Err(WalletError::Device("Ledger device not found".to_string()))
        }

        #[cfg(not(feature = "hardware-wallet"))]
        Err(WalletError::Device("hardware wallet support not compiled".to_string()))
    }

    fn get_view_key(&self) -> Result<[u8; 32], WalletError> {
        #[cfg(feature = "hardware-wallet")]
        {
            // INS_GET_KEY with P1=0x02 for view key.
            let response = self.exchange_apdu(INS_GET_KEY, 0x02, 0x00, &[])?;
            if response.len() < 34 {
                return Err(WalletError::Device("invalid view key response".to_string()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&response[..32]);
            Ok(key)
        }

        #[cfg(not(feature = "hardware-wallet"))]
        Err(WalletError::Device("hardware wallet support not compiled".to_string()))
    }

    fn export_key_images(
        &self,
        outputs: &[(u64, [u8; 32])],
    ) -> Result<KeyImageSyncResult, WalletError> {
        #[cfg(feature = "hardware-wallet")]
        {
            let mut key_images = Vec::new();

            for (idx, (output_index, public_key)) in outputs.iter().enumerate() {
                // INS_EXPORT_KEY_IMAGE: P1=first/continue, data=public_key.
                let p1 = if idx == 0 { 0x00 } else { 0x01 };
                let response = self.exchange_apdu(INS_EXPORT_KEY_IMAGE, p1, 0x00, public_key)?;

                if response.len() >= 98 {
                    // 32 bytes key image + 64 bytes signature + 2 bytes SW.
                    let mut ki = [0u8; 32];
                    ki.copy_from_slice(&response[..32]);
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&response[32..96]);

                    key_images.push(ExportedKeyImage {
                        key_image: ki,
                        signature: sig,
                        output_index: *output_index,
                    });
                }
            }

            let num = key_images.len();
            Ok(KeyImageSyncResult { key_images, num_exported: num })
        }

        #[cfg(not(feature = "hardware-wallet"))]
        {
            let _ = outputs;
            Err(WalletError::Device("hardware wallet support not compiled".to_string()))
        }
    }

    fn display_address(
        &self,
        major: u32,
        minor: u32,
        payment_id: Option<&[u8; 8]>,
    ) -> Result<(), WalletError> {
        #[cfg(feature = "hardware-wallet")]
        {
            // INS_DISPLAY_ADDRESS: data = major(4) + minor(4) + optional payment_id(8).
            let mut data = Vec::with_capacity(16);
            data.extend_from_slice(&major.to_le_bytes());
            data.extend_from_slice(&minor.to_le_bytes());
            if let Some(pid) = payment_id {
                data.extend_from_slice(pid);
            }

            self.exchange_apdu(INS_DISPLAY_ADDRESS, 0x00, 0x00, &data)?;
            Ok(())
        }

        #[cfg(not(feature = "hardware-wallet"))]
        {
            let _ = (major, minor, payment_id);
            Err(WalletError::Device("hardware wallet support not compiled".to_string()))
        }
    }
}
