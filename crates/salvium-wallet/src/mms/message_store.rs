//! MMS message store — higher-level API over the raw database methods.
//!
//! Provides typed access to messages and signers, converting between
//! the raw storage rows and the typed MMS domain objects.

use super::types::*;
use crate::error::WalletError;
use crate::Wallet;

impl Wallet {
    /// Initialize the MMS with a configuration.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mms_init(
        &self,
        threshold: usize,
        signer_count: usize,
        own_index: usize,
    ) -> Result<(), WalletError> {
        // Clear any existing MMS data.
        self.clear_mms()?;

        // Store MMS config as a wallet attribute.
        let config = MmsConfig {
            active: true,
            threshold,
            signer_count,
            own_index,
            auto_send: true,
        };
        let json = serde_json::to_string(&config).map_err(|e| WalletError::Other(e.to_string()))?;
        self.set_attribute("mms_config", &json)?;

        // Create signer slots.
        for i in 0..signer_count {
            self.set_mms_signer(i as i64, &format!("Signer #{}", i), "", "", i == own_index)?;
        }

        Ok(())
    }

    /// Get the current MMS configuration.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mms_config(&self) -> Result<MmsConfig, WalletError> {
        match self.get_attribute("mms_config")? {
            Some(json) => {
                serde_json::from_str(&json).map_err(|e| WalletError::Other(e.to_string()))
            }
            None => Ok(MmsConfig::default()),
        }
    }

    /// Check if MMS is active.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mms_active(&self) -> Result<bool, WalletError> {
        Ok(self.mms_config()?.active)
    }

    /// Get all typed MMS messages.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mms_get_all_messages(&self) -> Result<Vec<Message>, WalletError> {
        let rows = self.get_mms_messages()?;
        Ok(rows.iter().filter_map(Message::from_row).collect())
    }

    /// Get a typed MMS message by ID.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mms_get_message(&self, id: i64) -> Result<Option<Message>, WalletError> {
        match self.get_mms_message(id)? {
            Some(row) => Ok(Message::from_row(&row)),
            None => Ok(None),
        }
    }

    /// Create and store a new outgoing MMS message.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mms_create_message(
        &self,
        msg_type: MessageType,
        signer_index: i64,
        content: &[u8],
        round: i64,
    ) -> Result<i64, WalletError> {
        let hash = hex::encode(&salvium_crypto::keccak256(content)[..8]);
        self.add_mms_message(
            msg_type as i64,
            MessageDirection::Out as i64,
            content,
            signer_index,
            MessageState::ReadyToSend as i64,
            &hash,
            round,
            0,
            "",
        )
    }

    /// Store a received MMS message.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mms_store_received(
        &self,
        msg_type: MessageType,
        signer_index: i64,
        content: &[u8],
        round: i64,
        transport_id: &str,
    ) -> Result<i64, WalletError> {
        let hash = hex::encode(&salvium_crypto::keccak256(content)[..8]);
        self.add_mms_message(
            msg_type as i64,
            MessageDirection::In as i64,
            content,
            signer_index,
            MessageState::Waiting as i64,
            &hash,
            round,
            0,
            transport_id,
        )
    }

    /// Get all authorized signers.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mms_get_signers(&self) -> Result<Vec<AuthorizedSigner>, WalletError> {
        let rows = self.get_mms_signers()?;
        Ok(rows
            .into_iter()
            .map(|r| AuthorizedSigner {
                index: r.signer_index as usize,
                label: r.label,
                transport_address: r.transport_address,
                monero_address: r.monero_address,
                is_me: r.is_me,
                auto_config_token: r.auto_config_token,
                auto_config_running: r.auto_config_running,
            })
            .collect())
    }

    /// Update a signer's details.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mms_update_signer(
        &self,
        index: usize,
        label: Option<&str>,
        transport_address: Option<&str>,
        monero_address: Option<&str>,
    ) -> Result<(), WalletError> {
        let signers = self.get_mms_signers()?;
        let existing = signers
            .iter()
            .find(|s| s.signer_index == index as i64)
            .ok_or_else(|| WalletError::Other(format!("signer #{} not found", index)))?;

        self.set_mms_signer(
            index as i64,
            label.unwrap_or(&existing.label),
            transport_address.unwrap_or(&existing.transport_address),
            monero_address.unwrap_or(&existing.monero_address),
            existing.is_me,
        )
    }
}
