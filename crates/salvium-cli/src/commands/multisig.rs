//! Multisig wallet commands: prepare, make, exchange_keys, export/import info,
//! sign, submit, export_raw.
//!
//! Uses the `salvium_multisig` library for all cryptographic operations.

use super::*;

pub async fn prepare_multisig(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("wallet has no spend secret key — cannot participate in multisig".into());
    }

    // We don't know the final signer count yet; use placeholder 2-of-2 to initialize KEX.
    // The actual threshold/count will be set in `make_multisig`.
    let keys = wallet.keys();
    let spend_secret = keys
        .cn
        .spend_secret_key
        .ok_or("wallet has no spend secret key")?;

    // Use the multisig library's blinding function.
    let blinded =
        salvium_multisig::wallet::get_multisig_blinded_secret_key(&hex::encode(spend_secret));

    // Derive the public key from the blinded secret.
    let blinded_bytes = hex::decode(&blinded)?;
    let pub_key = salvium_crypto::scalar_mult_base(&blinded_bytes);

    // Create KEX round 1 message using the multisig account.
    let mut account = salvium_multisig::account::MultisigAccount::new(2, 2)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let msg = account
        .initialize_kex(
            &hex::encode(spend_secret),
            &hex::encode(keys.cn.view_secret_key),
        )
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    println!("{}", msg);
    println!();
    println!("Send this message to all other participants.");
    println!("Then use 'make_multisig' with their messages to create the multisig wallet.");
    let _ = pub_key;

    Ok(())
}

pub async fn make_multisig(ctx: &AppContext, threshold: usize, messages: &[String]) -> Result {
    let mut wallet = open_wallet(ctx)?;
    let signer_count = messages.len() + 1; // includes self

    if threshold < 2 {
        return Err("threshold must be at least 2".into());
    }
    if threshold > signer_count {
        return Err(format!(
            "threshold ({}) exceeds signer count ({})",
            threshold, signer_count
        )
        .into());
    }

    println!(
        "Creating {}-of-{} multisig wallet...",
        threshold, signer_count
    );

    // Initialize multisig via the wallet library.
    let first_msg = wallet
        .create_multisig(threshold, signer_count)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    // Build the message list including our own first message.
    let mut all_messages = vec![first_msg];
    all_messages.extend(messages.iter().cloned());

    // Process round 1 KEX.
    let next = wallet
        .process_multisig_kex(&all_messages)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    let status = wallet.get_multisig_status();
    println!("Multisig wallet created!");
    println!("  Threshold:       {}-of-{}", threshold, signer_count);
    if let Some(ref pk) = status.multisig_pubkey {
        println!("  Multisig pubkey: {}", pk);
    }
    println!("  KEX round:       {}", status.kex_round);
    println!("  KEX complete:    {}", status.kex_complete);

    if let Some(msg) = next {
        println!();
        println!("Next round message:");
        println!("{}", msg);
        println!();
        println!("Exchange this message with other participants and run 'exchange_multisig_keys'.");
    } else {
        println!();
        println!("Key exchange complete! The wallet is ready for multisig signing.");
    }

    Ok(())
}

pub async fn exchange_multisig_keys(ctx: &AppContext, messages: &[String]) -> Result {
    let mut wallet = open_wallet(ctx)?;

    println!(
        "Processing {} KEX messages for next round...",
        messages.len()
    );

    let next = wallet
        .process_multisig_kex(messages)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    let status = wallet.get_multisig_status();
    println!("  KEX round:    {}", status.kex_round);
    println!("  KEX complete: {}", status.kex_complete);

    if let Some(msg) = next {
        println!();
        println!("Next round message:");
        println!("{}", msg);
        println!();
        println!("Exchange this message and run this command again.");
    } else {
        println!();
        println!("Key exchange complete! The wallet is ready for multisig signing.");
        if let Some(ref pk) = status.multisig_pubkey {
            println!("Multisig pubkey: {}", pk);
        }
    }

    Ok(())
}

pub async fn export_multisig_info(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    let info = wallet
        .export_multisig_info()
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    println!("{}", hex::encode(&info));
    println!();
    println!("Share this info with other signers before creating a transaction.");
    Ok(())
}

pub async fn import_multisig_info(ctx: &AppContext, infos: &[String]) -> Result {
    let mut wallet = open_wallet(ctx)?;

    let decoded: Vec<Vec<u8>> = infos
        .iter()
        .enumerate()
        .map(|(i, info)| {
            hex::decode(info).map_err(|e| format!("invalid hex in info #{}: {}", i + 1, e))
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let count = wallet
        .import_multisig_info(&decoded)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    println!("Imported multisig info from {} signer(s).", count);
    Ok(())
}

pub async fn sign_multisig(ctx: &AppContext, input_file: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sign with a view-only wallet".into());
    }

    let data = std::fs::read_to_string(input_file)?;
    let mut tx_set = salvium_multisig::tx_set::MultisigTxSet::from_string(&data)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    println!(
        "Signing {} transaction(s) in multisig set...",
        tx_set.transactions.len().max(tx_set.pending_txs.len())
    );

    let complete = wallet
        .sign_multisig_tx(&mut tx_set)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    let output_file = format!("{}.signed", input_file);
    let signed_data =
        serde_json::to_string(&tx_set).map_err(|e| format!("serialization error: {}", e))?;
    std::fs::write(&output_file, &signed_data)?;

    println!("Signed multisig TX written to {}", output_file);
    if complete {
        println!("Threshold met! Transaction is ready to submit.");
    } else {
        println!(
            "Collected {}/{} signatures. Share the file with remaining signers.",
            tx_set.signers_contributed.len(),
            tx_set.threshold
        );
    }

    Ok(())
}

pub async fn submit_multisig(ctx: &AppContext, input_file: &str) -> Result {
    let data = std::fs::read_to_string(input_file)?;
    let tx_set = salvium_multisig::tx_set::MultisigTxSet::from_string(&data)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let daemon = DaemonRpc::new(&ctx.daemon_url);

    for (i, tx_hex) in tx_set.transactions.iter().enumerate() {
        println!(
            "Submitting multisig transaction {}/{}...",
            i + 1,
            tx_set.transactions.len()
        );
        let result = daemon
            .send_raw_transaction(tx_hex, false)
            .await
            .map_err(|e| format!("submission: {}", e))?;

        if result.status == "OK" {
            println!("  Transaction {} submitted successfully!", i + 1);
        } else {
            return Err(format!(
                "daemon rejected transaction {}: status={}",
                i + 1,
                result.status
            )
            .into());
        }
    }

    Ok(())
}

pub async fn export_raw_multisig_tx(ctx: &AppContext, input_file: &str) -> Result {
    let _wallet = open_wallet(ctx)?;
    let data = std::fs::read_to_string(input_file)?;
    let tx_set = salvium_multisig::tx_set::MultisigTxSet::from_string(&data)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    for (i, tx_hex) in tx_set.transactions.iter().enumerate() {
        let output_file = format!("{}.raw_{}", input_file, i);
        std::fs::write(&output_file, tx_hex)?;
        println!("Exported raw TX {} to {}", i, output_file);
    }

    Ok(())
}
