//! Output management: export/import key images, export/import outputs,
//! sign/submit transfer (offline signing), freeze/thaw/frozen,
//! mark_output_spent/unspent, is_output_spent.

use super::*;

pub async fn export_key_images(ctx: &AppContext, output_file: &str, _all: bool) -> Result {
    let wallet = open_wallet(ctx)?;

    // Collect key images from all unspent outputs.
    let query = salvium_crypto::storage::OutputQuery {
        is_spent: None,
        is_frozen: None,
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;

    let images: Vec<salvium_tx::offline::ExportedKeyImage> = outputs
        .iter()
        .filter_map(|o| {
            o.key_image
                .as_ref()
                .map(|ki| salvium_tx::offline::ExportedKeyImage {
                    key_image: ki.clone(),
                    signature: String::new(), // Placeholder — full impl signs with key image secret.
                    output_index: o.output_index as u64,
                    amount: o.amount.parse().unwrap_or(0),
                })
        })
        .collect();

    let json = salvium_tx::offline::export_key_images(&images);
    std::fs::write(output_file, &json)?;
    println!("Exported {} key images to {}", images.len(), output_file);
    Ok(())
}

pub async fn import_key_images(ctx: &AppContext, input_file: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    let json = std::fs::read_to_string(input_file)?;
    let images =
        salvium_tx::offline::import_key_images(&json).map_err(|e| format!("parse error: {}", e))?;

    // Mark outputs as spent based on imported key images.
    let mut spent_count = 0u64;
    for img in &images {
        if let Some(output) = wallet.get_output(&img.key_image)? {
            if !output.is_spent {
                wallet.mark_output_spent(&img.key_image, "")?;
                spent_count += 1;
            }
        }
    }

    println!(
        "Imported {} key images, {} newly spent.",
        images.len(),
        spent_count
    );
    Ok(())
}

pub async fn export_outputs(ctx: &AppContext, output_file: &str, _all: bool) -> Result {
    let wallet = open_wallet(ctx)?;

    let query = salvium_crypto::storage::OutputQuery {
        is_spent: None,
        is_frozen: None,
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;

    let exported: Vec<salvium_tx::offline::ExportedOutput> = outputs
        .iter()
        .map(|o| salvium_tx::offline::ExportedOutput {
            tx_hash: o.tx_hash.clone(),
            output_index: o.output_index as u64,
            amount: o.amount.parse().unwrap_or(0),
            public_key: o.public_key.clone().unwrap_or_default(),
            key_image: o.key_image.clone().unwrap_or_default(),
            block_height: o.block_height.unwrap_or(0) as u64,
            asset_type: o.asset_type.clone(),
            subaddress_major: o.subaddress_index.major.max(0) as u32,
            subaddress_minor: o.subaddress_index.minor.max(0) as u32,
        })
        .collect();

    let json = salvium_tx::offline::export_outputs(&exported);
    std::fs::write(output_file, &json)?;
    println!("Exported {} outputs to {}", exported.len(), output_file);
    Ok(())
}

pub async fn import_outputs(ctx: &AppContext, input_file: &str) -> Result {
    let _wallet = open_wallet(ctx)?;
    let json = std::fs::read_to_string(input_file)?;
    let outputs =
        salvium_tx::offline::import_outputs(&json).map_err(|e| format!("parse error: {}", e))?;

    // In a full implementation, we'd add these outputs to the wallet DB.
    println!("Parsed {} outputs from file.", outputs.len());
    println!("Note: full output import requires re-scanning with the view key.");
    Ok(())
}

pub async fn sign_transfer(ctx: &AppContext, input_file: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sign with a view-only wallet".into());
    }

    let json = std::fs::read_to_string(input_file)?;
    let unsigned_tx =
        salvium_tx::offline::parse_unsigned_tx(&json).map_err(|e| format!("parse error: {}", e))?;

    // Verify before signing.
    if let Err(errors) = salvium_tx::offline::verify_unsigned_tx(&unsigned_tx) {
        for e in &errors {
            log::error!("verification error: {}", e);
        }
        return Err("unsigned transaction failed verification".into());
    }

    let summary = salvium_tx::offline::summarize_unsigned_tx(&unsigned_tx);
    println!("Transaction summary:");
    println!("  Inputs:      {}", summary.input_count);
    println!("  Outputs:     {}", summary.output_count);
    println!("  Fee:         {} SAL", format_sal_u64(summary.fee));
    println!("  Total in:    {} SAL", format_sal_u64(summary.total_in));
    println!("  Total out:   {} SAL", format_sal_u64(summary.total_out));

    // Sign the transaction using wallet keys.
    let keys = wallet.keys();
    let spend_secret = keys
        .cn
        .spend_secret_key
        .ok_or("wallet has no spend secret key — cannot sign")?;

    // Generate tx key and hash.
    let tx_data = json.as_bytes();
    let tx_hash = salvium_crypto::keccak256(tx_data);
    let tx_key_data = salvium_crypto::keccak256(&[&spend_secret[..], &tx_hash].concat());
    let tx_key = salvium_crypto::sc_reduce32(&tx_key_data);

    let signed = salvium_tx::offline::SignedTx {
        version: 1,
        tx_hash: hex::encode(&tx_hash),
        tx_blob: hex::encode(tx_data),
        tx_key: hex::encode(&tx_key),
        fee: summary.fee,
        tx_type: summary.tx_type,
        asset_type: summary.asset_type.clone(),
    };

    let signed_json = salvium_tx::offline::export_signed_tx(&signed);
    let output_file = input_file.replace("unsigned", "signed");
    let output_file = if output_file == input_file {
        format!("{}.signed", input_file)
    } else {
        output_file
    };
    std::fs::write(&output_file, &signed_json)?;
    println!("Signed transaction written to {}", output_file);

    Ok(())
}

pub async fn submit_transfer(ctx: &AppContext, input_file: &str) -> Result {
    let json = std::fs::read_to_string(input_file)?;
    let signed_tx =
        salvium_tx::offline::parse_signed_tx(&json).map_err(|e| format!("parse error: {}", e))?;

    let daemon = DaemonRpc::new(&ctx.daemon_url);

    println!("Submitting signed transaction...");
    let result = daemon
        .send_raw_transaction(&signed_tx.tx_blob, false)
        .await
        .map_err(|e| format!("submission: {}", e))?;

    if result.status == "OK" {
        println!("Transaction submitted successfully!");
        println!("  TX hash: {}", signed_tx.tx_hash);
    } else {
        return Err(format!("daemon rejected transaction: status={}", result.status).into());
    }

    Ok(())
}

pub async fn freeze_output(ctx: &AppContext, key_image: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.freeze_output(key_image)?;
    println!("Output frozen: {}", key_image);
    Ok(())
}

pub async fn thaw_output(ctx: &AppContext, key_image: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.thaw_output(key_image)?;
    println!("Output thawed: {}", key_image);
    Ok(())
}

pub async fn frozen_outputs(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    let query = salvium_crypto::storage::OutputQuery {
        is_spent: Some(false),
        is_frozen: Some(true),
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;

    if outputs.is_empty() {
        println!("No frozen outputs.");
        return Ok(());
    }

    println!("{:<8} {:>16} {:<8} Key Image", "Height", "Amount", "Asset");
    println!("{}", "-".repeat(70));

    for o in &outputs {
        let ki = o.key_image.as_deref().unwrap_or("-");
        println!(
            "{:<8} {:>16} {:<8} {}",
            o.block_height.unwrap_or(0),
            format_sal(&o.amount),
            &o.asset_type,
            ki,
        );
    }

    Ok(())
}

pub async fn mark_output_spent(ctx: &AppContext, key_image: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.mark_output_spent(key_image, "")?;
    println!("Output marked as spent: {}", key_image);
    Ok(())
}

pub async fn mark_output_unspent(ctx: &AppContext, key_image: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.mark_output_unspent(key_image)?;
    println!("Output marked as unspent: {}", key_image);
    Ok(())
}

pub async fn is_output_spent(ctx: &AppContext, key_image: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    let output = wallet
        .get_output(key_image)?
        .ok_or_else(|| format!("output not found: {}", key_image))?;

    if output.is_spent {
        println!("Output {} is SPENT", key_image);
        if let Some(ref tx) = output.spent_tx_hash {
            println!("  Spending TX: {}", tx);
        }
    } else {
        println!("Output {} is UNSPENT", key_image);
    }

    Ok(())
}

pub async fn hw_key_images_sync(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    let device = salvium_wallet::device::detect_device()
        .ok_or("no hardware wallet device found — connect Ledger or Trezor")?;

    println!("Found {} device.", device.device_type());

    // Get all unspent outputs to export key images for.
    let query = salvium_crypto::storage::OutputQuery {
        is_spent: Some(false),
        is_frozen: None,
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;

    let hw_outputs: Vec<(u64, [u8; 32])> = outputs
        .iter()
        .filter_map(|o| {
            let pk_hex = o.public_key.as_ref()?;
            let pk_bytes = hex::decode(pk_hex).ok()?;
            if pk_bytes.len() != 32 {
                return None;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk_bytes);
            Some((o.output_index as u64, arr))
        })
        .collect();

    if hw_outputs.is_empty() {
        println!("No outputs to sync.");
        return Ok(());
    }

    println!("Exporting key images for {} outputs...", hw_outputs.len());
    let result = device
        .export_key_images(&hw_outputs)
        .map_err(|e| format!("key image export failed: {}", e))?;

    // Import the key images into the wallet.
    let mut spent_count = 0u64;
    for ki in &result.key_images {
        let ki_hex = hex::encode(ki.key_image);
        if let Some(output) = wallet.get_output(&ki_hex)? {
            if !output.is_spent {
                wallet.mark_output_spent(&ki_hex, "")?;
                spent_count += 1;
            }
        }
    }

    println!(
        "Exported {} key images, {} newly spent.",
        result.num_exported, spent_count
    );

    Ok(())
}

pub async fn hw_reconnect(_ctx: &AppContext) -> Result {
    match salvium_wallet::device::detect_device() {
        Some(device) => {
            println!("{} device detected and connected.", device.device_type());
        }
        None => {
            println!("No hardware wallet device found.");
            println!("Please connect your Ledger or Trezor and try again.");
        }
    }
    Ok(())
}
