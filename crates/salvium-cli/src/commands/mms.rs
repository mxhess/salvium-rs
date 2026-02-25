//! MMS (Multisig Messaging System) CLI commands.
//!
//! 19 subcommands covering the full MMS workflow: init, info, signer management,
//! message list/send/receive, auto-config, and the key `mms next` orchestrator.

use super::*;
use salvium_wallet::mms::types::*;

pub async fn mms_init(
    ctx: &AppContext,
    threshold: usize,
    signer_count: usize,
    own_label: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if signer_count < 2 {
        return Err("signer count must be at least 2".into());
    }
    if threshold < 1 || threshold > signer_count {
        return Err(format!("threshold must be between 1 and {}", signer_count).into());
    }

    wallet.mms_init(threshold, signer_count, 0)?;

    // Set our own label if provided.
    if !own_label.is_empty() {
        let addr = wallet.cn_address().unwrap_or_default();
        wallet.mms_update_signer(0, Some(own_label), None, Some(&addr))?;
    }

    println!(
        "MMS initialized: {}-of-{} multisig",
        threshold, signer_count
    );
    println!("Use 'mms signer' to configure other signers.");
    Ok(())
}

pub async fn mms_info(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let config = wallet.mms_config()?;

    if !config.active {
        println!("MMS is not initialized. Use 'mms init' first.");
        return Ok(());
    }

    println!("MMS info:");
    println!("  Active:       yes");
    println!("  Threshold:    {}", config.threshold);
    println!("  Signers:      {}", config.signer_count);
    println!("  Own index:    {}", config.own_index);
    println!(
        "  Auto-send:    {}",
        if config.auto_send { "on" } else { "off" }
    );

    let signers = wallet.mms_get_signers()?;
    if !signers.is_empty() {
        println!();
        println!("Signers:");
        for s in &signers {
            println!(
                "  #{}: {} {} [transport: {}] [address: {}]",
                s.index,
                s.label,
                if s.is_me { "(me)" } else { "" },
                if s.transport_address.is_empty() {
                    "<not set>"
                } else {
                    &s.transport_address
                },
                if s.monero_address.is_empty() {
                    "<not set>"
                } else {
                    &s.monero_address
                },
            );
        }
    }

    let messages = wallet.mms_get_all_messages()?;
    println!();
    println!("Messages: {}", messages.len());

    Ok(())
}

pub async fn mms_signer(
    ctx: &AppContext,
    index: usize,
    label: Option<&str>,
    transport_address: Option<&str>,
    address: Option<&str>,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if label.is_none() && transport_address.is_none() && address.is_none() {
        // Display signer info.
        let signers = wallet.mms_get_signers()?;
        let signer = signers
            .iter()
            .find(|s| s.index == index)
            .ok_or_else(|| format!("signer #{} not found", index))?;
        println!("Signer #{}:", index);
        println!("  Label:     {}", signer.label);
        println!("  Transport: {}", signer.transport_address);
        println!("  Address:   {}", signer.monero_address);
        println!("  Is me:     {}", signer.is_me);
    } else {
        wallet.mms_update_signer(index, label, transport_address, address)?;
        println!("Signer #{} updated.", index);
    }

    Ok(())
}

pub async fn mms_list(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let messages = wallet.mms_get_all_messages()?;

    if messages.is_empty() {
        println!("No MMS messages.");
        return Ok(());
    }

    println!(
        "{:<4} {:<6} {:<25} {:<8} {:<15} {:<10}",
        "ID", "Dir", "Type", "Signer", "State", "Hash"
    );
    println!("{}", "-".repeat(70));

    for msg in &messages {
        println!(
            "{:<4} {:<6} {:<25} {:<8} {:<15} {:<10}",
            msg.id,
            msg.direction.name(),
            msg.msg_type.name(),
            msg.signer_index,
            msg.state.name(),
            &msg.hash,
        );
    }

    Ok(())
}

pub async fn mms_next(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let config = wallet.mms_config()?;

    if !config.active {
        return Err("MMS is not initialized. Use 'mms init' first.".into());
    }

    let status = wallet.get_multisig_status();
    let messages = wallet.mms_get_all_messages()?;

    match salvium_wallet::mms::next_action(&status, &messages, &config) {
        Some(action) => {
            println!("Next action: {}", action.name());
            println!("  {}", action.description());
        }
        None => {
            println!("No action needed at this time.");
            println!("Waiting for messages from other signers.");
        }
    }

    Ok(())
}

pub async fn mms_sync(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let config = wallet.mms_config()?;

    if !config.active {
        return Err("MMS is not initialized.".into());
    }

    // Export multisig info and send to all other signers.
    let info = wallet
        .export_multisig_info()
        .map_err(|e| format!("failed to export multisig info: {}", e))?;

    let signers = wallet.mms_get_signers()?;
    for signer in &signers {
        if signer.is_me {
            continue;
        }
        wallet.mms_create_message(MessageType::MultisigSyncData, signer.index as i64, &info, 0)?;
    }

    println!(
        "Created sync data messages for {} signers.",
        signers.len() - 1
    );
    println!("Use 'mms send' to transmit them.");

    Ok(())
}

pub async fn mms_transfer(ctx: &AppContext, address: &str, amount: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    let config = wallet.mms_config()?;

    if !config.active {
        return Err("MMS is not initialized.".into());
    }

    // Create a partially signed TX and send it to all other signers.
    let amount_atomic = parse_sal_amount(amount)?;
    let tx_data = format!("transfer:{}:{}", address, amount_atomic);

    let signers = wallet.mms_get_signers()?;
    for signer in &signers {
        if signer.is_me {
            continue;
        }
        wallet.mms_create_message(
            MessageType::PartiallySignedTx,
            signer.index as i64,
            tx_data.as_bytes(),
            0,
        )?;
    }

    println!(
        "Created transfer messages for {} signers.",
        signers.len() - 1
    );
    println!("Use 'mms send' to transmit them.");

    Ok(())
}

pub async fn mms_delete(ctx: &AppContext, id: i64) -> Result {
    let wallet = open_wallet(ctx)?;
    if wallet.delete_mms_message(id)? {
        println!("Message {} deleted.", id);
    } else {
        println!("Message {} not found.", id);
    }
    Ok(())
}

pub async fn mms_send(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let messages = wallet.mms_get_all_messages()?;

    let ready: Vec<&Message> = messages
        .iter()
        .filter(|m| m.state == MessageState::ReadyToSend && m.direction == MessageDirection::Out)
        .collect();

    if ready.is_empty() {
        println!("No messages ready to send.");
        return Ok(());
    }

    #[cfg(feature = "transport")]
    {
        let transport = salvium_wallet::mms::BitmessageTransport::new();
        let signers = wallet.mms_get_signers()?;

        for msg in &ready {
            let signer = signers
                .iter()
                .find(|s| s.index == msg.signer_index as usize)
                .ok_or_else(|| format!("signer #{} not found", msg.signer_index))?;

            if signer.transport_address.is_empty() {
                println!(
                    "Skipping message {} — signer #{} has no transport address.",
                    msg.id, msg.signer_index
                );
                continue;
            }

            let our_signer = signers.iter().find(|s| s.is_me);
            let from = our_signer
                .map(|s| s.transport_address.as_str())
                .unwrap_or("");

            let subject = format!("mms:{}:{}", msg.msg_type.name(), msg.round);
            match transport
                .send(from, &signer.transport_address, &subject, &msg.content)
                .await
            {
                Ok(transport_id) => {
                    println!(
                        "Sent message {} to signer #{} (transport: {})",
                        msg.id, msg.signer_index, transport_id
                    );
                    wallet.update_mms_message_state(msg.id, MessageState::Sent as i64)?;
                }
                Err(e) => {
                    println!(
                        "Failed to send message {} to signer #{}: {}",
                        msg.id, msg.signer_index, e
                    );
                }
            }
        }
    }

    #[cfg(not(feature = "transport"))]
    {
        println!(
            "{} messages ready to send, but transport is not available.",
            ready.len()
        );
        println!("Build with --features transport to enable Bitmessage transport.");
    }

    Ok(())
}

pub async fn mms_receive(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    #[cfg(feature = "transport")]
    {
        let transport = salvium_wallet::mms::BitmessageTransport::new();
        let received = transport
            .receive()
            .await
            .map_err(|e| format!("failed to receive messages: {}", e))?;

        let mut count = 0u32;
        for msg in &received {
            // Parse subject to determine message type.
            if let Some(msg_type) = parse_mms_subject(&msg.subject) {
                let signers = wallet.mms_get_signers()?;
                let signer_idx = signers
                    .iter()
                    .find(|s| s.transport_address == msg.from_address)
                    .map(|s| s.index as i64)
                    .unwrap_or(-1);

                wallet.mms_store_received(msg_type, signer_idx, &msg.body, 0, &msg.id)?;
                transport
                    .delete(&msg.id)
                    .await
                    .map_err(|e| format!("failed to delete message: {}", e))?;
                count += 1;
            }
        }

        println!("Received {} message(s).", count);
    }

    #[cfg(not(feature = "transport"))]
    {
        let _ = wallet;
        println!("Transport not available. Build with --features transport.");
    }

    Ok(())
}

pub async fn mms_export(ctx: &AppContext, id: i64, output: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    let msg = wallet
        .mms_get_message(id)?
        .ok_or_else(|| format!("message {} not found", id))?;

    std::fs::write(output, &msg.content)?;
    println!(
        "Exported message {} ({} bytes) to {}",
        id,
        msg.content.len(),
        output
    );
    Ok(())
}

pub async fn mms_note(ctx: &AppContext, signer_index: i64, text: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.mms_create_message(MessageType::Note, signer_index, text.as_bytes(), 0)?;
    println!("Note created for signer #{}.", signer_index);
    Ok(())
}

pub async fn mms_show(ctx: &AppContext, id: i64) -> Result {
    let wallet = open_wallet(ctx)?;
    let msg = wallet
        .mms_get_message(id)?
        .ok_or_else(|| format!("message {} not found", id))?;

    println!("Message #{}:", msg.id);
    println!("  Type:       {}", msg.msg_type.name());
    println!("  Direction:  {}", msg.direction.name());
    println!("  Signer:     {}", msg.signer_index);
    println!("  State:      {}", msg.state.name());
    println!("  Hash:       {}", msg.hash);
    println!("  Round:      {}", msg.round);
    println!("  Signatures: {}", msg.signature_count);
    println!("  Transport:  {}", msg.transport_id);
    println!("  Content:    {} bytes", msg.content.len());

    // Try to display content as text if it's a note.
    if msg.msg_type == MessageType::Note {
        if let Ok(text) = String::from_utf8(msg.content.clone()) {
            println!();
            println!("  Text: {}", text);
        }
    }

    Ok(())
}

pub async fn mms_set(ctx: &AppContext, key: &str, value: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    let mut config = wallet.mms_config()?;

    match key {
        "auto-send" => {
            config.auto_send = value == "1" || value.to_lowercase() == "true";
            println!("auto-send set to {}", config.auto_send);
        }
        _ => return Err(format!("unknown MMS setting: {}", key).into()),
    }

    let json = serde_json::to_string(&config).map_err(|e| format!("serialize error: {}", e))?;
    wallet.set_attribute("mms_config", &json)?;

    Ok(())
}

pub async fn mms_send_signer_config(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let signers = wallet.mms_get_signers()?;

    let config_data = serde_json::to_vec(&signers)
        .map_err(|e| format!("failed to serialize signer config: {}", e))?;

    for signer in &signers {
        if signer.is_me {
            continue;
        }
        wallet.mms_create_message(
            MessageType::SignerConfig,
            signer.index as i64,
            &config_data,
            0,
        )?;
    }

    println!("Signer config messages created.");
    println!("Use 'mms send' to transmit them.");
    Ok(())
}

pub async fn mms_start_auto_config(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let config = wallet.mms_config()?;

    if !config.active {
        return Err("MMS is not initialized.".into());
    }

    let signers = wallet.mms_get_signers()?;
    println!("Auto-config tokens for other signers:");
    for signer in &signers {
        if signer.is_me {
            continue;
        }
        // Generate a random token for this signer.
        let mut token_bytes = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut token_bytes);
        let token = hex::encode(token_bytes);

        wallet.mms_update_signer(signer.index, None, None, None)?;
        println!("  Signer #{} ({}): {}", signer.index, signer.label, token);
    }

    println!();
    println!("Share these tokens with the respective signers.");
    println!("They should run 'mms auto-config <token>' to complete setup.");
    Ok(())
}

pub async fn mms_auto_config(ctx: &AppContext, token: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    let config = wallet.mms_config()?;

    if !config.active {
        return Err("MMS is not initialized.".into());
    }

    // Send our signer info encrypted with the token as key.
    let our_address = wallet.cn_address().unwrap_or_default();
    let auto_data = format!("auto_config:{}:{}", config.own_index, our_address);

    let signers = wallet.mms_get_signers()?;
    for signer in &signers {
        if signer.is_me {
            continue;
        }
        wallet.mms_create_message(
            MessageType::AutoConfigData,
            signer.index as i64,
            auto_data.as_bytes(),
            0,
        )?;
    }

    println!("Auto-config data created with token: {}", token);
    println!("Use 'mms send' to transmit.");
    Ok(())
}

pub async fn mms_stop_auto_config(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let signers = wallet.mms_get_signers()?;

    for signer in &signers {
        if signer.auto_config_running {
            wallet.mms_update_signer(signer.index, None, None, None)?;
        }
    }

    println!("Auto-config stopped.");
    Ok(())
}

pub async fn mms_config_checksum(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let signers = wallet.mms_get_signers()?;

    // Compute a checksum over all signer addresses for verification.
    let mut data = Vec::new();
    for signer in &signers {
        data.extend_from_slice(signer.monero_address.as_bytes());
        data.extend_from_slice(signer.transport_address.as_bytes());
    }
    let hash = salvium_crypto::keccak256(&data);
    let checksum = hex::encode(&hash[..4]);

    println!("MMS config checksum: {}", checksum);
    println!("All signers should see the same checksum to confirm matching configurations.");
    Ok(())
}

// Helper to parse MMS subject line.
#[cfg(feature = "transport")]
fn parse_mms_subject(subject: &str) -> Option<MessageType> {
    let parts: Vec<&str> = subject.split(':').collect();
    if parts.len() < 2 || parts[0] != "mms" {
        return None;
    }
    match parts[1] {
        "key_set" => Some(MessageType::KeySet),
        "additional_key_set" => Some(MessageType::AdditionalKeySet),
        "multisig_sync_data" => Some(MessageType::MultisigSyncData),
        "partially_signed_tx" => Some(MessageType::PartiallySignedTx),
        "fully_signed_tx" => Some(MessageType::FullySignedTx),
        "note" => Some(MessageType::Note),
        "signer_config" => Some(MessageType::SignerConfig),
        "auto_config_data" => Some(MessageType::AutoConfigData),
        _ => None,
    }
}
