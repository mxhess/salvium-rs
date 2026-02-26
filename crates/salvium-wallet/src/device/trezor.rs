//! Trezor hardware wallet support via USB HID (protobuf protocol).
//!
//! Communicates with the Monero/Salvium app on Trezor devices using
//! protobuf-serialized messages over USB HID.

use super::*;

/// Trezor USB Vendor ID.
const TREZOR_VENDOR_ID: u16 = 0x534C;

/// Trezor message type IDs (Monero-specific).
const MSG_MONERO_GET_WATCH_KEY: u16 = 546;
const MSG_MONERO_WATCH_KEY: u16 = 547;
const MSG_MONERO_KEY_IMAGE_EXPORT_INIT: u16 = 558;
const MSG_MONERO_KEY_IMAGE_SYNC_STEP: u16 = 560;
const MSG_MONERO_KEY_IMAGE_SYNC_FINAL: u16 = 562;
const MSG_MONERO_GET_ADDRESS: u16 = 540;

/// Trezor device communicating via USB HID.
pub struct TrezorDevice {
    #[cfg(feature = "hardware-wallet")]
    device: hidapi::HidDevice,
    connected: bool,
}

impl TrezorDevice {
    /// Try to detect and open a connected Trezor device.
    #[cfg(feature = "hardware-wallet")]
    pub fn detect() -> Option<Self> {
        let api = hidapi::HidApi::new().ok()?;
        for device_info in api.device_list() {
            if device_info.vendor_id() == TREZOR_VENDOR_ID {
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

    /// Send a protobuf message to the Trezor and receive a response.
    #[cfg(feature = "hardware-wallet")]
    fn exchange(&self, msg_type: u16, data: &[u8]) -> Result<(u16, Vec<u8>), WalletError> {
        // Trezor V2 protocol framing:
        // Header: '##' + msg_type(2BE) + data_len(4BE) + data
        let mut frame = Vec::new();
        frame.extend_from_slice(b"##");
        frame.push((msg_type >> 8) as u8);
        frame.push((msg_type & 0xFF) as u8);
        let data_len = data.len() as u32;
        frame.extend_from_slice(&data_len.to_be_bytes());
        frame.extend_from_slice(data);

        // Send in 63-byte chunks (first byte is report ID = 0x00).
        for chunk in frame.chunks(63) {
            let mut report = vec![0x00]; // Report ID.
            report.extend_from_slice(chunk);
            report.resize(64, 0);
            self.device
                .write(&report)
                .map_err(|e| WalletError::Device(format!("USB write failed: {}", e)))?;
        }

        // Read response header.
        let mut header_buf = [0u8; 64];
        let n = self
            .device
            .read_timeout(&mut header_buf, 60000)
            .map_err(|e| WalletError::Device(format!("USB read failed: {}", e)))?;

        if n < 9 || header_buf[0] != b'#' || header_buf[1] != b'#' {
            return Err(WalletError::Device("invalid Trezor response header".to_string()));
        }

        let resp_type = ((header_buf[2] as u16) << 8) | header_buf[3] as u16;
        let resp_len =
            u32::from_be_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]])
                as usize;

        let mut response = Vec::with_capacity(resp_len);
        let first_chunk_len = std::cmp::min(resp_len, n - 8);
        response.extend_from_slice(&header_buf[8..8 + first_chunk_len]);

        // Read remaining chunks if needed.
        while response.len() < resp_len {
            let mut buf = [0u8; 64];
            let n = self
                .device
                .read_timeout(&mut buf, 30000)
                .map_err(|e| WalletError::Device(format!("USB read failed: {}", e)))?;
            let chunk_len = std::cmp::min(resp_len - response.len(), n);
            response.extend_from_slice(&buf[..chunk_len]);
        }

        Ok((resp_type, response))
    }
}

impl HwDevice for TrezorDevice {
    fn device_type(&self) -> DeviceType {
        DeviceType::Trezor
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
                if device_info.vendor_id() == TREZOR_VENDOR_ID {
                    match api.open_path(device_info.path()) {
                        Ok(device) => {
                            self.device = device;
                            self.connected = true;
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(WalletError::Device(format!(
                                "failed to open Trezor: {}",
                                e
                            )));
                        }
                    }
                }
            }
            self.connected = false;
            Err(WalletError::Device("Trezor device not found".to_string()))
        }

        #[cfg(not(feature = "hardware-wallet"))]
        Err(WalletError::Device("hardware wallet support not compiled".to_string()))
    }

    fn get_view_key(&self) -> Result<[u8; 32], WalletError> {
        #[cfg(feature = "hardware-wallet")]
        {
            // MoneroGetWatchKey message (empty body).
            let (resp_type, response) = self.exchange(MSG_MONERO_GET_WATCH_KEY, &[])?;

            if resp_type != MSG_MONERO_WATCH_KEY {
                return Err(WalletError::Device(format!(
                    "unexpected response type: {}",
                    resp_type
                )));
            }

            // Parse protobuf response: field 1 = watch_key (bytes).
            // Simple protobuf parsing for a single bytes field.
            if response.len() < 34 {
                return Err(WalletError::Device("view key response too short".to_string()));
            }

            // Skip protobuf field header (tag + length) to get raw key bytes.
            let key_start = if response[0] == 0x0A {
                // Field 1, wire type 2 (length-delimited).
                let len = response[1] as usize;
                if len != 32 || response.len() < len + 2 {
                    return Err(WalletError::Device("invalid view key length".to_string()));
                }
                2
            } else {
                return Err(WalletError::Device("unexpected protobuf format".to_string()));
            };

            let mut key = [0u8; 32];
            key.copy_from_slice(&response[key_start..key_start + 32]);
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
            // Step 1: Initialize key image export.
            // MoneroKeyImageExportInit: field 1 = num_outputs (varint).
            let num = outputs.len() as u64;
            let mut init_data = Vec::new();
            init_data.push(0x08); // Field 1, wire type 0 (varint).
            encode_varint(&mut init_data, num);

            let (resp_type, _) = self.exchange(MSG_MONERO_KEY_IMAGE_EXPORT_INIT, &init_data)?;
            if resp_type != MSG_MONERO_KEY_IMAGE_EXPORT_INIT + 1 {
                return Err(WalletError::Device("key image export init failed".to_string()));
            }

            // Step 2: Sync each output.
            let mut key_images = Vec::new();
            for (output_index, public_key) in outputs {
                let mut step_data = Vec::new();
                // Field 1: output public key (bytes).
                step_data.push(0x0A);
                step_data.push(32);
                step_data.extend_from_slice(public_key);

                let (resp_type, response) =
                    self.exchange(MSG_MONERO_KEY_IMAGE_SYNC_STEP, &step_data)?;
                if resp_type != MSG_MONERO_KEY_IMAGE_SYNC_STEP + 1 {
                    continue;
                }

                // Parse response: field 1 = key_image (32 bytes), field 2 = signature (64 bytes).
                if response.len() >= 100 {
                    let mut ki = [0u8; 32];
                    let mut sig = [0u8; 64];
                    // Simple extraction (skip protobuf headers).
                    let ki_start = 2; // 0x0A 0x20
                    ki.copy_from_slice(&response[ki_start..ki_start + 32]);
                    let sig_start = ki_start + 32 + 2; // 0x12 0x40
                    sig.copy_from_slice(&response[sig_start..sig_start + 64]);

                    key_images.push(ExportedKeyImage {
                        key_image: ki,
                        signature: sig,
                        output_index: *output_index,
                    });
                }
            }

            // Step 3: Finalize.
            let _ = self.exchange(MSG_MONERO_KEY_IMAGE_SYNC_FINAL, &[]);

            let num_exported = key_images.len();
            Ok(KeyImageSyncResult { key_images, num_exported })
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
            // MoneroGetAddress message.
            let mut data = Vec::new();
            // Field 1: address_n (subaddress indices).
            // major index.
            data.push(0x08);
            encode_varint(&mut data, major as u64);
            // minor index.
            data.push(0x08);
            encode_varint(&mut data, minor as u64);
            // Field 3: show_display = true.
            data.push(0x18);
            data.push(0x01);
            // Field 4: payment_id (optional).
            if let Some(pid) = payment_id {
                data.push(0x22);
                data.push(8);
                data.extend_from_slice(pid);
            }

            let (resp_type, _) = self.exchange(MSG_MONERO_GET_ADDRESS, &data)?;
            if resp_type != MSG_MONERO_GET_ADDRESS + 1 {
                return Err(WalletError::Device("display address failed".to_string()));
            }

            Ok(())
        }

        #[cfg(not(feature = "hardware-wallet"))]
        {
            let _ = (major, minor, payment_id);
            Err(WalletError::Device("hardware wallet support not compiled".to_string()))
        }
    }
}

/// Encode a varint (protobuf wire format).
#[cfg(feature = "hardware-wallet")]
fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}
