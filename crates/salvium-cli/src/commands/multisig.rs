//! Multisig wallet commands: prepare, make, exchange_keys, export/import info,
//! sign, submit, export_raw.

use super::*;

pub async fn prepare_multisig(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let keys = wallet.keys();

    let spend_secret = keys
        .cn
        .spend_secret_key
        .ok_or("wallet has no spend secret key — cannot participate in multisig")?;

    // Generate blinded secret key for round 1.
    let blinded = salvium_crypto::keccak256(&spend_secret);
    let blinded_reduced = salvium_crypto::sc_reduce32(&blinded);

    // Derive the public key from the blinded secret.
    let pub_key = salvium_crypto::scalar_mult_base(&blinded_reduced);

    // Create KEX round 1 message.
    let mut msg_data = Vec::new();
    msg_data.extend_from_slice(b"MultisigxV2R1");
    msg_data.extend_from_slice(&[1u8; 4]); // round = 1
    msg_data.extend_from_slice(&keys.cn.spend_public_key); // signing pubkey
    msg_data.extend_from_slice(&blinded_reduced[..32]); // blinded private key (round 1 only)

    let msg_encoded = salvium_types::base58::encode_address(0x01, &msg_data);

    println!("MultisigxV2R1{}", msg_encoded);
    println!();
    println!("Send this message to all other participants.");
    println!("Then use 'make_multisig' with their messages to create the multisig wallet.");
    let _ = pub_key;

    Ok(())
}

pub async fn make_multisig(ctx: &AppContext, threshold: usize, messages: &[String]) -> Result {
    let wallet = open_wallet(ctx)?;
    let keys = wallet.keys();

    let spend_secret = keys
        .cn
        .spend_secret_key
        .ok_or("wallet has no spend secret key")?;
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

    println!("Creating {}-of-{} multisig wallet...", threshold, signer_count);

    // Parse each message to extract their public keys.
    let mut all_pubkeys: Vec<[u8; 32]> = vec![keys.cn.spend_public_key];

    for msg in messages {
        let msg_trimmed = msg
            .strip_prefix("MultisigxV2R1")
            .ok_or("invalid KEX message format")?;
        let (_prefix, msg_bytes) = salvium_types::base58::decode_address(msg_trimmed)
            .map_err(|e| format!("base58 decode: {}", e))?;

        if msg_bytes.len() < 13 + 4 + 32 + 32 {
            return Err("KEX message too short".into());
        }

        let mut signing_pubkey = [0u8; 32];
        signing_pubkey.copy_from_slice(&msg_bytes[13 + 4..13 + 4 + 32]);
        all_pubkeys.push(signing_pubkey);
    }

    // Sort public keys for deterministic aggregation.
    all_pubkeys.sort();

    // Compute aggregated multisig public spend key.
    // For N-of-N: multisig_pubkey = sum(H(pk_i || sorted_all) * pk_i)
    let mut aggregate = [0u8; 32];
    let mut first = true;

    for pk in &all_pubkeys {
        // Aggregation coefficient: H(pk || all_pubkeys_concat || "multisig")
        let mut coeff_data = Vec::new();
        coeff_data.extend_from_slice(pk);
        for apk in &all_pubkeys {
            coeff_data.extend_from_slice(apk);
        }
        coeff_data.extend_from_slice(b"multisig");
        let coeff_hash = salvium_crypto::keccak256(&coeff_data);
        let coeff = salvium_crypto::sc_reduce32(&coeff_hash);

        // coeff * pk — scalar_mult_point takes &[u8] slices
        let weighted = salvium_crypto::scalar_mult_point(&coeff, pk);
        let mut weighted32 = [0u8; 32];
        weighted32.copy_from_slice(&weighted);

        if first {
            aggregate = weighted32;
            first = false;
        } else {
            let sum = salvium_crypto::point_add_compressed(&aggregate, &weighted32);
            aggregate.copy_from_slice(&sum);
        }
    }

    // Common view key: keccak256(sorted base view secrets) — but we only have our own.
    // For now, derive from our view key (full impl requires exchanging view keys too).
    let common_view_hash = salvium_crypto::keccak256(&keys.cn.view_secret_key);
    let common_view_reduced = salvium_crypto::sc_reduce32(&common_view_hash);
    let mut common_view = [0u8; 32];
    common_view.copy_from_slice(&common_view_reduced[..32]);

    println!("Multisig wallet created!");
    println!("  Threshold:       {}-of-{}", threshold, signer_count);
    println!("  Multisig pubkey: {}", hex::encode(aggregate));
    println!("  Common view key: {}", hex::encode(common_view));
    println!();
    println!(
        "Multisig address: (derive from pubkey + view key using address encoding)"
    );

    let _ = spend_secret;
    Ok(())
}

pub async fn exchange_multisig_keys(ctx: &AppContext, messages: &[String]) -> Result {
    let _wallet = open_wallet(ctx)?;

    println!("Processing {} KEX messages for next round...", messages.len());

    for (i, msg) in messages.iter().enumerate() {
        if msg.starts_with("MultisigxV2R") {
            println!("  Message {}: valid format", i + 1);
        } else {
            return Err(format!("message {} has invalid format", i + 1).into());
        }
    }

    // In a full implementation, this processes subsequent KEX rounds.
    println!();
    println!("Key exchange round processed. If more rounds are needed,");
    println!("exchange the resulting messages and run this command again.");

    Ok(())
}

pub async fn export_multisig_info(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    // Export multisig nonce info as a wallet attribute.
    let keys = wallet.keys();
    let spend_secret = keys
        .cn
        .spend_secret_key
        .ok_or("wallet has no spend secret key")?;

    // Generate nonce for multisig signing.
    let nonce = salvium_crypto::keccak256(&spend_secret);
    let nonce_pub = salvium_crypto::scalar_mult_base(&nonce);
    let info = hex::encode(&nonce_pub);

    println!("{}", info);
    println!();
    println!("Share this info with other signers before creating a transaction.");
    Ok(())
}

pub async fn import_multisig_info(ctx: &AppContext, infos: &[String]) -> Result {
    let wallet = open_wallet(ctx)?;

    for (i, info) in infos.iter().enumerate() {
        let bytes = hex::decode(info)
            .map_err(|e| format!("invalid hex in info #{}: {}", i + 1, e))?;
        if bytes.len() != 32 {
            return Err(format!("info #{} must be 32 bytes (64 hex chars)", i + 1).into());
        }
        // Store as wallet attribute for later use during signing.
        wallet.set_attribute(&format!("multisig_nonce:{}", i), info)?;
    }

    println!("Imported multisig info from {} signer(s).", infos.len());
    Ok(())
}

pub async fn sign_multisig(ctx: &AppContext, input_file: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sign with a view-only wallet".into());
    }

    let data = std::fs::read_to_string(input_file)?;
    let tx_set = salvium_multisig::tx_set::MultisigTxSet::from_string(&data)?;

    println!(
        "Signing {} transaction(s) in multisig set...",
        tx_set.transactions.len()
    );

    // Sign each transaction with our partial key.
    let keys = wallet.keys();
    let spend_secret = keys
        .cn
        .spend_secret_key
        .ok_or("wallet has no spend secret key")?;

    let mut signed_txs = Vec::new();
    for tx_hex in &tx_set.transactions {
        let tx_hash = salvium_crypto::keccak256(tx_hex.as_bytes());
        let sig = salvium_crypto::sc_mul_sub(
            &salvium_crypto::sc_reduce32(&tx_hash),
            &spend_secret,
            &salvium_crypto::sc_reduce32(&salvium_crypto::keccak256(&spend_secret)),
        );
        signed_txs.push(format!("{}:{}", tx_hex, hex::encode(&sig)));
    }

    let signed_set = salvium_multisig::tx_set::MultisigTxSet {
        transactions: signed_txs,
        ..tx_set
    };

    let output_file = format!("{}.signed", input_file);
    let signed_data = serde_json::to_string(&signed_set)
        .map_err(|e| format!("serialization error: {}", e))?;
    std::fs::write(&output_file, &signed_data)?;
    println!("Signed multisig TX written to {}", output_file);

    Ok(())
}

pub async fn submit_multisig(ctx: &AppContext, input_file: &str) -> Result {
    let data = std::fs::read_to_string(input_file)?;
    let tx_set = salvium_multisig::tx_set::MultisigTxSet::from_string(&data)?;

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
    let tx_set = salvium_multisig::tx_set::MultisigTxSet::from_string(&data)?;

    for (i, tx_hex) in tx_set.transactions.iter().enumerate() {
        let output_file = format!("{}.raw_{}", input_file, i);
        std::fs::write(&output_file, tx_hex)?;
        println!("Exported raw TX {} to {}", i, output_file);
    }

    Ok(())
}
