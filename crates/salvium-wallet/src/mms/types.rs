//! MMS type definitions: message types, states, directions, processing actions.

use serde::{Deserialize, Serialize};

/// Type of MMS message content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum MessageType {
    KeySet = 0,
    AdditionalKeySet = 1,
    MultisigSyncData = 2,
    PartiallySignedTx = 3,
    FullySignedTx = 4,
    Note = 5,
    SignerConfig = 6,
    AutoConfigData = 7,
}

impl MessageType {
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::KeySet),
            1 => Some(Self::AdditionalKeySet),
            2 => Some(Self::MultisigSyncData),
            3 => Some(Self::PartiallySignedTx),
            4 => Some(Self::FullySignedTx),
            5 => Some(Self::Note),
            6 => Some(Self::SignerConfig),
            7 => Some(Self::AutoConfigData),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::KeySet => "key_set",
            Self::AdditionalKeySet => "additional_key_set",
            Self::MultisigSyncData => "multisig_sync_data",
            Self::PartiallySignedTx => "partially_signed_tx",
            Self::FullySignedTx => "fully_signed_tx",
            Self::Note => "note",
            Self::SignerConfig => "signer_config",
            Self::AutoConfigData => "auto_config_data",
        }
    }
}

/// State of an MMS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum MessageState {
    ReadyToSend = 0,
    Sent = 1,
    Waiting = 2,
    Processed = 3,
    Cancelled = 4,
}

impl MessageState {
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::ReadyToSend),
            1 => Some(Self::Sent),
            2 => Some(Self::Waiting),
            3 => Some(Self::Processed),
            4 => Some(Self::Cancelled),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ReadyToSend => "ready_to_send",
            Self::Sent => "sent",
            Self::Waiting => "waiting",
            Self::Processed => "processed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Direction of an MMS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum MessageDirection {
    In = 0,
    Out = 1,
}

impl MessageDirection {
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::In),
            1 => Some(Self::Out),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }
}

/// Next action the MMS state machine recommends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessingAction {
    PrepareMultisig,
    MakeMultisig,
    ExchangeMultisigKeys,
    CreateSyncData,
    ProcessSyncData,
    SignTx,
    SubmitTx,
    ProcessSignerConfig,
    ProcessAutoConfigData,
}

impl ProcessingAction {
    pub fn name(&self) -> &'static str {
        match self {
            Self::PrepareMultisig => "prepare_multisig",
            Self::MakeMultisig => "make_multisig",
            Self::ExchangeMultisigKeys => "exchange_multisig_keys",
            Self::CreateSyncData => "create_sync_data",
            Self::ProcessSyncData => "process_sync_data",
            Self::SignTx => "sign_tx",
            Self::SubmitTx => "submit_tx",
            Self::ProcessSignerConfig => "process_signer_config",
            Self::ProcessAutoConfigData => "process_auto_config_data",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::PrepareMultisig => "Run 'prepare_multisig' to start multisig wallet setup",
            Self::MakeMultisig => "Run 'make_multisig' with the received key sets",
            Self::ExchangeMultisigKeys => "Run 'exchange_multisig_keys' with the additional key sets",
            Self::CreateSyncData => "Run 'export_multisig_info' to create sync data for other signers",
            Self::ProcessSyncData => "Run 'import_multisig_info' with the received sync data",
            Self::SignTx => "Run 'sign_multisig' with the received partially signed tx",
            Self::SubmitTx => "Run 'submit_multisig' with the fully signed tx",
            Self::ProcessSignerConfig => "Process the received signer configuration",
            Self::ProcessAutoConfigData => "Process the received auto-config data",
        }
    }
}

/// MMS configuration for this wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmsConfig {
    pub active: bool,
    pub threshold: usize,
    pub signer_count: usize,
    pub own_index: usize,
    pub auto_send: bool,
}

impl Default for MmsConfig {
    fn default() -> Self {
        Self {
            active: false,
            threshold: 0,
            signer_count: 0,
            own_index: 0,
            auto_send: true,
        }
    }
}

/// An authorized signer in the MMS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedSigner {
    pub index: usize,
    pub label: String,
    pub transport_address: String,
    pub monero_address: String,
    pub is_me: bool,
    pub auto_config_token: String,
    pub auto_config_running: bool,
}

/// A high-level MMS message (wraps the raw database row with typed enums).
#[derive(Debug, Clone)]
pub struct Message {
    pub id: i64,
    pub msg_type: MessageType,
    pub direction: MessageDirection,
    pub content: Vec<u8>,
    pub signer_index: i64,
    pub state: MessageState,
    pub hash: String,
    pub round: i64,
    pub signature_count: i64,
    pub transport_id: String,
    pub created_at: Option<i64>,
}

impl Message {
    /// Convert from a raw database row.
    pub fn from_row(row: &salvium_crypto::storage::MmsMessageRow) -> Option<Self> {
        Some(Self {
            id: row.id,
            msg_type: MessageType::from_i64(row.msg_type)?,
            direction: MessageDirection::from_i64(row.direction)?,
            content: row.content.clone(),
            signer_index: row.signer_index,
            state: MessageState::from_i64(row.state)?,
            hash: row.hash.clone(),
            round: row.round,
            signature_count: row.signature_count,
            transport_id: row.transport_id.clone(),
            created_at: row.created_at,
        })
    }
}
