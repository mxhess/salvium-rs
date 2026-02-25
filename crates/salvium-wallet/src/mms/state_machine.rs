//! MMS state machine — determines the next recommended action based on
//! the current multisig status and pending messages.

use super::types::*;
use crate::wallet::MultisigStatus;

/// Determine the next MMS processing action based on current state.
///
/// Logic follows the C++ MMS state machine:
/// 1. If not multisig and no key sets → PrepareMultisig
/// 2. If not multisig but have enough key sets → MakeMultisig
/// 3. If KEX incomplete and have enough additional key sets → ExchangeMultisigKeys
/// 4. If KEX complete and have sync data waiting → ProcessSyncData
/// 5. If have partial TX waiting → SignTx
/// 6. If have fully signed TX waiting → SubmitTx
/// 7. If have signer config waiting → ProcessSignerConfig
/// 8. If have auto-config data waiting → ProcessAutoConfigData
pub fn next_action(
    status: &MultisigStatus,
    messages: &[Message],
    config: &MmsConfig,
) -> Option<ProcessingAction> {
    // Count waiting messages by type.
    let waiting: Vec<&Message> = messages
        .iter()
        .filter(|m| m.state == MessageState::Waiting && m.direction == MessageDirection::In)
        .collect();

    let key_sets: Vec<&&Message> = waiting
        .iter()
        .filter(|m| m.msg_type == MessageType::KeySet)
        .collect();

    let additional_key_sets: Vec<&&Message> = waiting
        .iter()
        .filter(|m| m.msg_type == MessageType::AdditionalKeySet)
        .collect();

    let sync_data: Vec<&&Message> = waiting
        .iter()
        .filter(|m| m.msg_type == MessageType::MultisigSyncData)
        .collect();

    let partial_txs: Vec<&&Message> = waiting
        .iter()
        .filter(|m| m.msg_type == MessageType::PartiallySignedTx)
        .collect();

    let full_txs: Vec<&&Message> = waiting
        .iter()
        .filter(|m| m.msg_type == MessageType::FullySignedTx)
        .collect();

    let signer_configs: Vec<&&Message> = waiting
        .iter()
        .filter(|m| m.msg_type == MessageType::SignerConfig)
        .collect();

    let auto_config: Vec<&&Message> = waiting
        .iter()
        .filter(|m| m.msg_type == MessageType::AutoConfigData)
        .collect();

    // Check for auto-config data first.
    if !auto_config.is_empty() {
        return Some(ProcessingAction::ProcessAutoConfigData);
    }

    // Check for signer config.
    if !signer_configs.is_empty() {
        return Some(ProcessingAction::ProcessSignerConfig);
    }

    let needed_signers = config.signer_count - 1; // Messages needed from other signers.

    if !status.is_multisig {
        // Not yet a multisig wallet.
        if key_sets.len() >= needed_signers {
            return Some(ProcessingAction::MakeMultisig);
        }
        return Some(ProcessingAction::PrepareMultisig);
    }

    if !status.kex_complete {
        // KEX in progress.
        if additional_key_sets.len() >= needed_signers {
            return Some(ProcessingAction::ExchangeMultisigKeys);
        }
        // Still waiting for key sets.
        return None;
    }

    // KEX complete — check for pending operations.
    if !full_txs.is_empty() {
        return Some(ProcessingAction::SubmitTx);
    }

    if !partial_txs.is_empty() {
        return Some(ProcessingAction::SignTx);
    }

    if !sync_data.is_empty() {
        return Some(ProcessingAction::ProcessSyncData);
    }

    // Check if we need to create sync data (if there are outgoing messages that
    // need sync data before they can proceed).
    let has_ready_to_send = messages.iter().any(|m| {
        m.state == MessageState::ReadyToSend && m.direction == MessageDirection::Out
    });

    if has_ready_to_send {
        return Some(ProcessingAction::CreateSyncData);
    }

    None
}
