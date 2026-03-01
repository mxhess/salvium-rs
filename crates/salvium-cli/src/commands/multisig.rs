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
    let spend_secret = keys.cn.spend_secret_key.ok_or("wallet has no spend secret key")?;

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
        .initialize_kex(&hex::encode(spend_secret), &hex::encode(keys.cn.view_secret_key))
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
        return Err(
            format!("threshold ({}) exceeds signer count ({})", threshold, signer_count).into()
        );
    }

    println!("Creating {}-of-{} multisig wallet...", threshold, signer_count);

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

    println!("Processing {} KEX messages for next round...", messages.len());

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
        println!("Submitting multisig transaction {}/{}...", i + 1, tx_set.transactions.len());
        let result = daemon
            .send_raw_transaction(tx_hex, false)
            .await
            .map_err(|e| format!("submission: {}", e))?;

        if result.status == "OK" {
            println!("  Transaction {} submitted successfully!", i + 1);
        } else {
            return Err(
                format!("daemon rejected transaction {}: status={}", i + 1, result.status).into()
            );
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

/// Build a multisig transaction: select UTXOs, derive key offsets, fetch
/// ring members, create signing contexts, and sign with the proposer's share.
///
/// Writes the resulting `MultisigTxSet` to `multisig_tx_set.json` for
/// co-signers to sign with `sign_multisig`.
pub async fn transfer_multisig(ctx: &AppContext, address: &str, amount_str: &str) -> Result {
    use crate::tx_common::{self, hex_to_32, TxPipeline};

    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot send from a view-only wallet".into());
    }

    let status = wallet.get_multisig_status();
    if !status.is_multisig || !status.kex_complete {
        return Err("wallet is not a fully-configured multisig wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;
    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;

    println!("Multisig Transfer:");
    println!("  To:     {}", address);
    println!("  Amount: {} SAL", format_sal_u64(amount));
    println!();

    let fee_ctx =
        tx_common::resolve_fee_context(&ctx.pool, salvium_tx::fee::FeePriority::Default).await?;
    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_ctx.fee_per_byte);
    println!("  Estimated fee: {} SAL", format_sal_u64(est_fee));

    let balance = wallet.get_balance("SAL", 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + est_fee {
        return Err(format!(
            "insufficient unlocked balance: have {} SAL, need {} SAL",
            format_sal_u64(unlocked),
            format_sal_u64(amount + est_fee)
        )
        .into());
    }

    if !tx_common::confirm("Confirm multisig transfer? [y/N] ")? {
        println!("Transfer cancelled.");
        return Ok(());
    }

    // 1. Select UTXOs and derive per-output secret keys.
    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (input_data, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;

    // 2. Fetch decoys from the daemon and build rings.
    let prepared = pipeline.fetch_decoys(&input_data).await?;
    println!(
        "Built rings for {} input(s), fee = {} SAL",
        prepared.len(),
        format_sal_u64(actual_fee)
    );

    // 3. Compute per-input key offsets, key images, and y keys.
    //    key_offset = full_secret_key - weighted_share
    //    The weighted_share is obtained from the multisig account.
    let multisig_account = wallet.multisig_account().ok_or("multisig account not found")?;
    let weighted_share = multisig_account
        .get_weighted_spend_key_share()
        .map_err(|e| format!("weighted key share: {}", e))?;

    let mut multisig_inputs = Vec::new();
    let mut input_key_offsets = Vec::new();
    let mut input_y_keys = Vec::new();
    let mut key_images_hex = Vec::new();

    for (idx, prep) in prepared.iter().enumerate() {
        let inp = &input_data[idx];

        // Compute key image: I = secret_key * H_p(public_key)
        let hp = salvium_crypto::hash_to_point(&inp.public_key);
        let ki = salvium_crypto::scalar_mult_point(&inp.secret_key, &hp);
        let mut ki_arr = [0u8; 32];
        ki_arr.copy_from_slice(&ki[..32]);
        key_images_hex.push(hex::encode(ki_arr));

        // Key offset = full_secret_key - weighted_share (mod L)
        let offset = salvium_crypto::sc_sub(&inp.secret_key, &weighted_share);
        let mut offset_arr = [0u8; 32];
        offset_arr.copy_from_slice(&offset[..32]);
        input_key_offsets.push(hex::encode(offset_arr));

        // TCLSAG: y key; CLSAG: empty
        let use_tclsag = inp.secret_key_y.is_some();
        let ki_y = if let Some(sky) = &inp.secret_key_y {
            let hp_y = salvium_crypto::hash_to_point(&inp.public_key);
            let ki_y_bytes = salvium_crypto::scalar_mult_point(sky, &hp_y);
            let mut ki_y_arr = [0u8; 32];
            ki_y_arr.copy_from_slice(&ki_y_bytes[..32]);
            input_y_keys.push(hex::encode(sky));
            Some(ki_y_arr)
        } else {
            input_y_keys.push(String::new());
            None
        };

        multisig_inputs.push(salvium_multisig::tx_builder::MultisigInput {
            ring: prep.ring.clone(),
            ring_commitments: prep.ring_commitments.clone(),
            real_index: prep.real_index,
            key_image: ki_arr,
            amount: inp.amount,
            input_mask: inp.mask,
            use_tclsag,
            key_image_y: ki_y,
        });
    }

    // 4. Build an unsigned TX via TransactionBuilder to get prefix, outputs, etc.
    let keys = wallet.keys();
    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_fee(actual_fee);

    println!("Building unsigned transaction...");
    let unsigned = builder.build().map_err(|e| format!("tx build: {}", e))?;

    // 5. Compute the prefix hash.
    let prefix_json = unsigned.prefix.to_json();
    let prefix_str =
        serde_json::to_string(&prefix_json).map_err(|e| format!("prefix serialize: {}", e))?;
    let prefix_bytes = salvium_crypto::tx_serialize::serialize_tx_prefix(&prefix_str)
        .map_err(|e| format!("prefix binary serialize: {}", e))?;
    let prefix_hash = hex_to_32(&hex::encode(salvium_crypto::keccak256(&prefix_bytes)))?;

    // Serialize the unsigned TX as the blob for co-signers.
    let tx_blob_json =
        serde_json::to_string(&unsigned.prefix.to_json()).map_err(|e| format!("tx blob: {}", e))?;
    let tx_blob_hex = hex::encode(tx_blob_json.as_bytes());

    // 6. Call build_multisig_contexts with all the data.
    println!("Building multisig signing contexts...");
    let pending = salvium_multisig::tx_builder::build_multisig_contexts(
        &multisig_inputs,
        &unsigned.output_amounts,
        &unsigned.output_masks,
        &unsigned.output_commitments,
        &unsigned.encrypted_amounts,
        actual_fee,
        unsigned.rct_type,
        &prefix_hash,
        &tx_blob_hex,
        &key_images_hex,
        &[format!("{}:{}", address, amount)],
        &input_key_offsets,
        &input_y_keys,
    )
    .map_err(|e| format!("build_multisig_contexts: {}", e))?;

    // 7. Wrap in MultisigTxSet and sign with proposer's share.
    let mut tx_set =
        salvium_multisig::tx_set::MultisigTxSet::with_config(status.threshold, status.signer_count);
    tx_set.add_pending_tx(pending);

    println!("Signing with proposer's key share...");
    let complete = wallet
        .sign_multisig_tx(&mut tx_set)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

    // 8. Write to file.
    let output_file = "multisig_tx_set.json";
    let set_json =
        serde_json::to_string_pretty(&tx_set).map_err(|e| format!("serialization: {}", e))?;
    std::fs::write(output_file, &set_json)?;

    println!();
    println!("Multisig TX set written to {}", output_file);
    if complete {
        println!("Threshold met! Transaction is ready to submit.");
    } else {
        println!(
            "Signed 1/{} — share '{}' with co-signers for signing.",
            status.threshold, output_file
        );
    }

    Ok(())
}
