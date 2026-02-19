//! CLI command implementations.

use crate::AppContext;
use salvium_rpc::DaemonRpc;
use salvium_wallet::{SyncEvent, Wallet, WalletKeys};
use std::path::PathBuf;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn hex_to_32(s: &str) -> std::result::Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn prompt_password(prompt: &str) -> std::result::Result<String, Box<dyn std::error::Error>> {
    let pass = rpassword::prompt_password(prompt)?;
    if pass.is_empty() {
        return Err("password cannot be empty".into());
    }
    Ok(pass)
}

fn prompt_password_confirm() -> std::result::Result<String, Box<dyn std::error::Error>> {
    let pass = prompt_password("Wallet password: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    if pass != confirm {
        return Err("passwords do not match".into());
    }
    Ok(pass)
}

fn derive_db_key(password: &str) -> [u8; 32] {
    let salt = b"salvium-wallet-db-key-v1________"; // 32 bytes
    let hash = salvium_crypto::argon2id_hash(
        password.as_bytes(),
        salt,
        3,     // t_cost
        65536, // m_cost (64MB)
        4,     // parallelism
        32,    // output length
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    key
}

fn wallet_path(ctx: &AppContext, name: Option<String>) -> PathBuf {
    if let Some(name) = name {
        let dir = ctx.wallet_path.parent().unwrap_or(&ctx.wallet_path);
        dir.join(format!("{}.db", name))
    } else {
        ctx.wallet_path.clone()
    }
}

/// Path for the encrypted metadata sidecar file.
fn meta_path(db_path: &std::path::Path) -> PathBuf {
    db_path.with_extension("meta")
}

/// Save seed + network to an encrypted sidecar file.
fn save_wallet_meta(
    db_path: &std::path::Path,
    seed: &[u8; 32],
    network: &str,
    password: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let data = format!("{}:{}", hex::encode(seed), network);
    let encrypted = salvium_wallet::encryption::encrypt_wallet_data(
        data.as_bytes(),
        password.as_bytes(),
    )?;
    std::fs::write(meta_path(db_path), encrypted)?;
    Ok(())
}

/// Load seed + network from the encrypted sidecar file.
fn load_wallet_meta(
    db_path: &std::path::Path,
    password: &str,
) -> std::result::Result<([u8; 32], String), Box<dyn std::error::Error>> {
    let mp = meta_path(db_path);
    if !mp.exists() {
        return Err(format!(
            "wallet metadata file not found: {}\nWallet may need to be restored.",
            mp.display()
        )
        .into());
    }
    let encrypted = std::fs::read(&mp)?;
    let decrypted = salvium_wallet::encryption::decrypt_wallet_data(
        &encrypted,
        password.as_bytes(),
    )
    .map_err(|e| format!("failed to decrypt wallet metadata (wrong password?): {}", e))?;

    let text = String::from_utf8(decrypted)
        .map_err(|_| "corrupted wallet metadata")?;
    let parts: Vec<&str> = text.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("corrupted wallet metadata format".into());
    }

    let seed_bytes = hex::decode(parts[0])?;
    if seed_bytes.len() != 32 {
        return Err("invalid seed length in metadata".into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    Ok((seed, parts[1].to_string()))
}

fn open_wallet(ctx: &AppContext) -> std::result::Result<Wallet, Box<dyn std::error::Error>> {
    let path = &ctx.wallet_path;
    if !path.exists() {
        return Err(format!(
            "wallet file not found: {}\nUse 'create' or 'restore' first, or specify --wallet-file",
            path.display()
        )
        .into());
    }

    let password = prompt_password("Wallet password: ")?;
    let db_key = derive_db_key(&password);
    let path_str = path.to_str().ok_or("invalid wallet path")?;

    let (seed, network_str) = load_wallet_meta(path, &password)?;

    let network = match network_str.as_str() {
        "testnet" => salvium_types::constants::Network::Testnet,
        "stagenet" => salvium_types::constants::Network::Stagenet,
        _ => salvium_types::constants::Network::Mainnet,
    };

    let keys = WalletKeys::from_seed(seed, network);
    Wallet::open(keys, path_str, &db_key).map_err(|e| e.into())
}

fn format_sal(atomic_str: &str) -> String {
    let atomic: u64 = atomic_str.parse().unwrap_or(0);
    format_sal_u64(atomic)
}

fn format_sal_u64(atomic: u64) -> String {
    let whole = atomic / 1_000_000_000;
    let frac = atomic % 1_000_000_000;
    if frac == 0 {
        format!("{}.000000000", whole)
    } else {
        format!("{}.{:09}", whole, frac)
    }
}

fn parse_sal_amount(s: &str) -> std::result::Result<u64, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = s.split('.').collect();
    let whole: u64 = if parts[0].is_empty() {
        0
    } else {
        parts[0].parse()?
    };
    let frac: u64 = if parts.len() > 1 {
        let frac_str = parts[1];
        if frac_str.len() > 9 {
            return Err("too many decimal places (max 9)".into());
        }
        let padded = format!("{:0<9}", frac_str);
        padded.parse()?
    } else {
        0
    };
    Ok(whole * 1_000_000_000 + frac)
}

fn tx_type_name(t: i64) -> &'static str {
    match t {
        0 => "UNSET",
        1 => "MINER",
        2 => "PROTOCOL",
        3 => "TRANSFER",
        4 => "CONVERT",
        5 => "BURN",
        6 => "STAKE",
        7 => "RETURN",
        8 => "AUDIT",
        _ => "UNKNOWN",
    }
}

// ─── Commands ───────────────────────────────────────────────────────────────

pub async fn create_wallet(ctx: &AppContext, name: Option<String>) -> Result {
    let path = wallet_path(ctx, name);

    if path.exists() {
        return Err(format!("wallet file already exists: {}", path.display()).into());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let password = prompt_password_confirm()?;
    let db_key = derive_db_key(&password);
    let path_str = path.to_str().ok_or("invalid wallet path")?;

    let seed = WalletKeys::random_seed();
    let wallet = Wallet::create(seed, ctx.network, path_str, &db_key)?;

    let network_str = match ctx.network {
        salvium_types::constants::Network::Testnet => "testnet",
        salvium_types::constants::Network::Stagenet => "stagenet",
        _ => "mainnet",
    };
    save_wallet_meta(&path, &seed, network_str, &password)?;

    println!("Wallet created: {}", path.display());
    println!();

    if let Some(Ok(mnemonic)) = wallet.mnemonic() {
        println!("IMPORTANT: Write down your seed phrase and keep it safe!");
        println!("If you lose it, you will lose access to your funds.");
        println!();
        println!("Seed phrase (25 words):");
        println!("  {}", mnemonic);
        println!();
    }

    print_addresses(&wallet);
    Ok(())
}

pub async fn restore_wallet(
    ctx: &AppContext,
    name: Option<String>,
    _restore_height: u64,
) -> Result {
    let path = wallet_path(ctx, name);

    if path.exists() {
        return Err(format!("wallet file already exists: {}", path.display()).into());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    println!("Enter your 25-word mnemonic seed phrase:");
    let mut mnemonic = String::new();
    std::io::stdin().read_line(&mut mnemonic)?;
    let mnemonic = mnemonic.trim();

    let password = prompt_password_confirm()?;
    let db_key = derive_db_key(&password);
    let path_str = path.to_str().ok_or("invalid wallet path")?;

    let wallet = Wallet::from_mnemonic(mnemonic, ctx.network, path_str, &db_key)?;

    let keys = wallet.keys();
    if let Some(seed) = keys.seed {
        let network_str = match ctx.network {
            salvium_types::constants::Network::Testnet => "testnet",
            salvium_types::constants::Network::Stagenet => "stagenet",
            _ => "mainnet",
        };
        save_wallet_meta(&path, &seed, network_str, &password)?;
    }

    println!("Wallet restored: {}", path.display());
    println!();
    print_addresses(&wallet);

    println!("Run 'sync' to scan the blockchain for your transactions.");
    Ok(())
}

pub async fn wallet_info(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    println!("Wallet type: {:?}", wallet.wallet_type());
    println!("Network:     {:?}", wallet.network());
    println!();
    print_addresses(&wallet);

    let height = wallet.sync_height().unwrap_or(0);
    println!("Sync height: {}", height);

    Ok(())
}

pub async fn show_seed(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("this is a view-only wallet — no seed available".into());
    }

    match wallet.mnemonic() {
        Some(Ok(mnemonic)) => {
            println!("Seed phrase (25 words):");
            println!("  {}", mnemonic);
            println!();
            println!("WARNING: Never share your seed phrase with anyone!");
        }
        Some(Err(e)) => return Err(format!("failed to generate mnemonic: {}", e).into()),
        None => return Err("no seed available for this wallet".into()),
    }

    Ok(())
}

pub async fn show_balance(ctx: &AppContext, account: i32) -> Result {
    let wallet = open_wallet(ctx)?;

    let balances = wallet.get_all_balances(account)?;

    if balances.is_empty() {
        println!("No balances found (wallet may need syncing).");
        return Ok(());
    }

    println!("Account #{}", account);
    println!("{:<8} {:>20} {:>20}", "Asset", "Balance", "Unlocked");
    println!("{}", "-".repeat(50));

    for (asset, bal) in &balances {
        println!(
            "{:<8} {:>20} {:>20}",
            asset,
            format_sal(&bal.balance),
            format_sal(&bal.unlocked_balance),
        );
    }

    let height = wallet.sync_height().unwrap_or(0);
    println!();
    println!("Synced to height: {}", height);

    Ok(())
}

pub async fn sync_wallet(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let daemon = DaemonRpc::new(&ctx.daemon_url);

    let info = daemon.get_info().await?;
    println!(
        "Connected to daemon at {} (height: {})",
        ctx.daemon_url, info.height
    );

    let wallet_height = wallet.sync_height().unwrap_or(0);
    if wallet_height >= info.height {
        println!("Wallet is already synchronized at height {}.", wallet_height);
        return Ok(());
    }

    println!(
        "Syncing from height {} to {} ...",
        wallet_height, info.height
    );

    let (tx, rx) = tokio::sync::mpsc::channel(32);

    let progress_task = tokio::spawn(async move {
        let mut rx = rx;
        while let Some(event) = rx.recv().await {
            match event {
                SyncEvent::Started { target_height } => {
                    println!("Sync started (target: {})", target_height);
                }
                SyncEvent::Progress {
                    current_height,
                    target_height,
                    outputs_found,
                } => {
                    let pct = if target_height > 0 {
                        (current_height as f64 / target_height as f64 * 100.0) as u32
                    } else {
                        0
                    };
                    print!(
                        "\rHeight {}/{} ({}%) — {} outputs found",
                        current_height, target_height, pct, outputs_found
                    );
                }
                SyncEvent::Complete { height } => {
                    println!("\nSync complete at height {}.", height);
                }
                SyncEvent::Reorg {
                    from_height,
                    to_height,
                } => {
                    println!(
                        "\nReorg detected: rolling back from {} to {}",
                        from_height, to_height
                    );
                }
                SyncEvent::Error(msg) => {
                    eprintln!("\nSync error: {}", msg);
                }
            }
        }
    });

    let _final_height = wallet.sync(&daemon, Some(&tx)).await?;
    drop(tx);
    let _ = progress_task.await;

    println!();
    let balances = wallet.get_all_balances(0)?;
    if !balances.is_empty() {
        for (asset, bal) in &balances {
            println!(
                "{}: {} (unlocked: {})",
                asset,
                format_sal(&bal.balance),
                format_sal(&bal.unlocked_balance)
            );
        }
    }

    Ok(())
}

pub async fn show_address(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    print_addresses(&wallet);
    Ok(())
}

pub async fn transfer(
    ctx: &AppContext,
    address: &str,
    amount_str: &str,
    priority: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot send from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;

    let fee_priority = match priority {
        "low" => salvium_tx::fee::FeePriority::Low,
        "high" => salvium_tx::fee::FeePriority::High,
        "urgent" => salvium_tx::fee::FeePriority::Highest,
        _ => salvium_tx::fee::FeePriority::Normal,
    };

    println!("Transfer:");
    println!("  To:     {}", address);
    println!("  Amount: {} SAL", format_sal_u64(amount));
    println!("  Format: {:?}", parsed_addr.format);
    println!();

    // Estimate fee (2 inputs, 2 outputs is typical).
    let fee = salvium_tx::estimate_tx_fee(
        2, 2, 16, true, 0x04, fee_priority,
    );
    println!("  Estimated fee: {} SAL", format_sal_u64(fee));
    println!();

    let balance = wallet.get_balance("SAL", 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + fee {
        return Err(format!(
            "insufficient unlocked balance: have {} SAL, need {} SAL",
            format_sal_u64(unlocked),
            format_sal_u64(amount + fee)
        )
        .into());
    }

    println!("Confirm transfer? [y/N] ");
    let mut confirm = String::new();
    std::io::stdin().read_line(&mut confirm)?;
    if confirm.trim().to_lowercase() != "y" {
        println!("Transfer cancelled.");
        return Ok(());
    }

    // ── Full transaction construction pipeline ───────────────────────

    // 1. Select UTXOs.
    let selection = wallet.select_outputs(
        amount, fee, "SAL",
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    println!(
        "Selected {} input(s), total {} SAL",
        selection.selected.len(),
        format_sal_u64(selection.total)
    );

    // 2. Re-estimate fee with actual input count.
    let actual_fee = salvium_tx::estimate_tx_fee(
        selection.selected.len(),
        2, // dest + change
        salvium_tx::decoy::DEFAULT_RING_SIZE,
        true,
        0x04,
        fee_priority,
    );

    // 3. Derive spend keys for each selected UTXO.
    let keys = wallet.keys();
    let cn_spend_secret = keys.cn.spend_secret_key
        .ok_or("wallet has no spend secret key")?;
    let carrot_prove_spend = keys.carrot.prove_spend_key
        .ok_or("wallet has no CARROT prove_spend key")?;

    let mut input_data = Vec::new();
    for utxo in &selection.selected {
        let output = wallet
            .get_output(&utxo.key_image)?
            .ok_or_else(|| format!("output not found for key image: {}", utxo.key_image))?;

        let public_key = hex_to_32(
            output.public_key.as_deref().ok_or("output missing public_key")?,
        )?;
        let mask = hex_to_32(
            output.mask.as_deref().ok_or("output missing mask")?,
        )?;

        let (secret_key, secret_key_y) = if output.is_carrot {
            let s_sr_ctx = hex_to_32(
                output.carrot_shared_secret.as_deref()
                    .ok_or("CARROT output missing shared_secret")?,
            )?;
            let commitment = hex_to_32(
                output.commitment.as_deref()
                    .ok_or("CARROT output missing commitment")?,
            )?;
            let (sk_x, sk_y) = salvium_crypto::carrot_scan::derive_carrot_spend_keys(
                &carrot_prove_spend,
                &keys.carrot.generate_image_key,
                &s_sr_ctx,
                &commitment,
            );
            (sk_x, Some(sk_y))
        } else {
            let tx_pub_key = hex_to_32(
                output.tx_pub_key.as_deref()
                    .ok_or("CN output missing tx_pub_key")?,
            )?;
            let sk = salvium_crypto::cn_scan::derive_output_spend_key(
                &keys.cn.view_secret_key,
                &cn_spend_secret,
                &tx_pub_key,
                output.output_index as u32,
                output.subaddress_index.major as u32,
                output.subaddress_index.minor as u32,
            );
            (sk, None)
        };

        input_data.push((utxo.global_index, public_key, mask, secret_key, secret_key_y, utxo.amount));
    }

    // 4. Fetch output distribution for decoy selection.
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    println!("Fetching decoy data from daemon...");
    let info = daemon.get_info().await?;
    let dist = daemon
        .get_output_distribution(&[0], 0, info.height, true, "")
        .await?;
    let rct_offsets = dist
        .first()
        .ok_or("no output distribution returned from daemon")?
        .distribution
        .clone();
    let decoy_selector = salvium_tx::DecoySelector::new(rct_offsets)
        .map_err(|e| format!("decoy selector: {}", e))?;

    // 5. Build ring for each input and fetch ring member data.
    let ring_size = salvium_tx::decoy::DEFAULT_RING_SIZE;
    let mut prepared_inputs = Vec::new();

    for (global_index, public_key, mask, secret_key, secret_key_y, input_amount) in &input_data {
        let (ring_indices, real_pos) = decoy_selector
            .build_ring(*global_index, ring_size)
            .map_err(|e| format!("ring build: {}", e))?;

        let requests: Vec<salvium_rpc::daemon::OutputRequest> = ring_indices
            .iter()
            .map(|&idx| salvium_rpc::daemon::OutputRequest { amount: 0, index: idx })
            .collect();
        let outs_info = daemon.get_outs(&requests, false, "").await?;

        let mut ring_keys = Vec::with_capacity(ring_size);
        let mut ring_commitments = Vec::with_capacity(ring_size);
        for o in &outs_info {
            ring_keys.push(hex_to_32(&o.key)?);
            ring_commitments.push(hex_to_32(&o.mask)?);
        }

        prepared_inputs.push(salvium_tx::builder::PreparedInput {
            secret_key: *secret_key,
            secret_key_y: *secret_key_y,
            public_key: *public_key,
            amount: *input_amount,
            mask: *mask,
            asset_type: "SAL".to_string(),
            global_index: *global_index,
            ring: ring_keys,
            ring_commitments,
            ring_indices: ring_indices.clone(),
            real_index: real_pos,
        });
    }

    // 6. Build unsigned transaction.
    println!("Building transaction...");
    let is_subaddress = parsed_addr.address_type
        == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared_inputs)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_change_address(
            keys.carrot.account_spend_pubkey,
            keys.carrot.account_view_pubkey,
        )
        .set_fee(actual_fee);

    let unsigned = builder.build().map_err(|e| format!("tx build: {}", e))?;

    // 7. Sign transaction.
    println!("Signing transaction...");
    let signed_tx = salvium_tx::sign_transaction(unsigned)
        .map_err(|e| format!("signing: {}", e))?;

    // 8. Serialize and submit.
    let tx_bytes = signed_tx.to_bytes().map_err(|e| format!("serialize: {}", e))?;
    let tx_hex = hex::encode(&tx_bytes);
    let tx_hash = signed_tx.tx_hash().map_err(|e| format!("tx hash: {}", e))?;

    println!("Submitting transaction...");
    let result = daemon
        .send_raw_transaction(&tx_hex, false)
        .await
        .map_err(|e| format!("submission: {}", e))?;

    if result.status == "OK" {
        println!("Transaction submitted successfully!");
        println!("  TX hash: {}", hex::encode(tx_hash));
        println!("  Fee:     {} SAL", format_sal_u64(actual_fee));
    } else {
        return Err(format!(
            "daemon rejected transaction: status={}, double_spend={}, fee_too_low={}, invalid_input={}, invalid_output={}",
            result.status, result.double_spend, result.fee_too_low,
            result.invalid_input, result.invalid_output,
        ).into());
    }

    Ok(())
}

pub async fn stake(ctx: &AppContext, amount_str: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot stake from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;

    println!("Stake:");
    println!("  Amount: {} SAL", format_sal_u64(amount));
    println!();

    let fee = salvium_tx::estimate_tx_fee(
        2, 2, 16, true, 0x04,
        salvium_tx::fee::FeePriority::Normal,
    );
    println!("  Estimated fee: {} SAL", format_sal_u64(fee));
    println!();

    let balance = wallet.get_balance("SAL", 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + fee {
        return Err(format!(
            "insufficient unlocked balance: have {} SAL, need {} SAL",
            format_sal_u64(unlocked),
            format_sal_u64(amount + fee)
        )
        .into());
    }

    println!("Confirm stake? [y/N] ");
    let mut confirm = String::new();
    std::io::stdin().read_line(&mut confirm)?;
    if confirm.trim().to_lowercase() != "y" {
        println!("Stake cancelled.");
        return Ok(());
    }

    // ── Stake transaction construction ───────────────────────────────

    // 1. Select UTXOs.
    let selection = wallet.select_outputs(
        amount, fee, "SAL",
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    println!(
        "Selected {} input(s), total {} SAL",
        selection.selected.len(),
        format_sal_u64(selection.total)
    );

    let actual_fee = salvium_tx::estimate_tx_fee(
        selection.selected.len(),
        2,
        salvium_tx::decoy::DEFAULT_RING_SIZE,
        true,
        0x04,
        salvium_tx::fee::FeePriority::Normal,
    );

    // 2. Derive spend keys for each selected UTXO.
    let keys = wallet.keys();
    let cn_spend_secret = keys.cn.spend_secret_key
        .ok_or("wallet has no spend secret key")?;
    let carrot_prove_spend = keys.carrot.prove_spend_key
        .ok_or("wallet has no CARROT prove_spend key")?;

    let mut input_data = Vec::new();
    for utxo in &selection.selected {
        let output = wallet
            .get_output(&utxo.key_image)?
            .ok_or_else(|| format!("output not found for key image: {}", utxo.key_image))?;

        let public_key = hex_to_32(
            output.public_key.as_deref().ok_or("output missing public_key")?,
        )?;
        let mask = hex_to_32(
            output.mask.as_deref().ok_or("output missing mask")?,
        )?;

        let (secret_key, secret_key_y) = if output.is_carrot {
            let s_sr_ctx = hex_to_32(
                output.carrot_shared_secret.as_deref()
                    .ok_or("CARROT output missing shared_secret")?,
            )?;
            let commitment = hex_to_32(
                output.commitment.as_deref()
                    .ok_or("CARROT output missing commitment")?,
            )?;
            let (sk_x, sk_y) = salvium_crypto::carrot_scan::derive_carrot_spend_keys(
                &carrot_prove_spend,
                &keys.carrot.generate_image_key,
                &s_sr_ctx,
                &commitment,
            );
            (sk_x, Some(sk_y))
        } else {
            let tx_pub_key = hex_to_32(
                output.tx_pub_key.as_deref()
                    .ok_or("CN output missing tx_pub_key")?,
            )?;
            let sk = salvium_crypto::cn_scan::derive_output_spend_key(
                &keys.cn.view_secret_key,
                &cn_spend_secret,
                &tx_pub_key,
                output.output_index as u32,
                output.subaddress_index.major as u32,
                output.subaddress_index.minor as u32,
            );
            (sk, None)
        };

        input_data.push((utxo.global_index, public_key, mask, secret_key, secret_key_y, utxo.amount));
    }

    // 3. Fetch decoy data.
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    println!("Fetching decoy data from daemon...");
    let info = daemon.get_info().await?;
    let dist = daemon
        .get_output_distribution(&[0], 0, info.height, true, "")
        .await?;
    let rct_offsets = dist
        .first()
        .ok_or("no output distribution returned from daemon")?
        .distribution
        .clone();
    let decoy_selector = salvium_tx::DecoySelector::new(rct_offsets)
        .map_err(|e| format!("decoy selector: {}", e))?;

    // 4. Build rings and fetch ring members.
    let ring_size = salvium_tx::decoy::DEFAULT_RING_SIZE;
    let mut prepared_inputs = Vec::new();

    for (global_index, public_key, mask, secret_key, secret_key_y, input_amount) in &input_data {
        let (ring_indices, real_pos) = decoy_selector
            .build_ring(*global_index, ring_size)
            .map_err(|e| format!("ring build: {}", e))?;

        let requests: Vec<salvium_rpc::daemon::OutputRequest> = ring_indices
            .iter()
            .map(|&idx| salvium_rpc::daemon::OutputRequest { amount: 0, index: idx })
            .collect();
        let outs_info = daemon.get_outs(&requests, false, "").await?;

        let mut ring_keys = Vec::with_capacity(ring_size);
        let mut ring_commitments = Vec::with_capacity(ring_size);
        for o in &outs_info {
            ring_keys.push(hex_to_32(&o.key)?);
            ring_commitments.push(hex_to_32(&o.mask)?);
        }

        prepared_inputs.push(salvium_tx::builder::PreparedInput {
            secret_key: *secret_key,
            secret_key_y: *secret_key_y,
            public_key: *public_key,
            amount: *input_amount,
            mask: *mask,
            asset_type: "SAL".to_string(),
            global_index: *global_index,
            ring: ring_keys,
            ring_commitments,
            ring_indices: ring_indices.clone(),
            real_index: real_pos,
        });
    }

    // 5. Build stake transaction (destination = self, tx_type = STAKE).
    println!("Building stake transaction...");
    let unsigned = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared_inputs)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount,
            asset_type: "SAL".to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_change_address(
            keys.carrot.account_spend_pubkey,
            keys.carrot.account_view_pubkey,
        )
        .set_tx_type(salvium_tx::types::tx_type::STAKE)
        .set_fee(actual_fee)
        .build()
        .map_err(|e| format!("tx build: {}", e))?;

    // 6. Sign.
    println!("Signing transaction...");
    let signed_tx = salvium_tx::sign_transaction(unsigned)
        .map_err(|e| format!("signing: {}", e))?;

    // 7. Submit.
    let tx_bytes = signed_tx.to_bytes().map_err(|e| format!("serialize: {}", e))?;
    let tx_hex = hex::encode(&tx_bytes);
    let tx_hash = signed_tx.tx_hash().map_err(|e| format!("tx hash: {}", e))?;

    println!("Submitting stake transaction...");
    let result = daemon
        .send_raw_transaction(&tx_hex, false)
        .await
        .map_err(|e| format!("submission: {}", e))?;

    if result.status == "OK" {
        println!("Stake transaction submitted successfully!");
        println!("  TX hash: {}", hex::encode(tx_hash));
        println!("  Amount:  {} SAL", format_sal_u64(amount));
        println!("  Fee:     {} SAL", format_sal_u64(actual_fee));
    } else {
        return Err(format!(
            "daemon rejected stake transaction: status={}, double_spend={}, fee_too_low={}",
            result.status, result.double_spend, result.fee_too_low,
        ).into());
    }

    Ok(())
}

pub async fn show_history(ctx: &AppContext, _account: i32, limit: usize) -> Result {
    let wallet = open_wallet(ctx)?;

    let query = salvium_crypto::storage::TxQuery {
        is_incoming: None,
        is_outgoing: None,
        is_confirmed: None,
        in_pool: None,
        tx_type: None,
        min_height: None,
        max_height: None,
        tx_hash: None,
    };
    let transfers = wallet.get_transfers(&query)?;

    if transfers.is_empty() {
        println!("No transactions found. Run 'sync' to scan the blockchain.");
        return Ok(());
    }

    let display_count = transfers.len().min(limit);
    println!(
        "Showing {}/{} transactions:",
        display_count,
        transfers.len()
    );
    println!();
    println!(
        "{:<8} {:<10} {:<8} {:>16} TX Hash",
        "Height", "Type", "Asset", "Amount"
    );
    println!("{}", "-".repeat(80));

    for tx in transfers.iter().rev().take(limit) {
        let height = tx.block_height.unwrap_or(0);
        let hash_short = if tx.tx_hash.len() > 16 {
            format!("{}...", &tx.tx_hash[..16])
        } else {
            tx.tx_hash.clone()
        };

        // Show whichever amount is nonzero.
        let amount_str = if tx.incoming_amount != "0" {
            format!("+{}", format_sal(&tx.incoming_amount))
        } else if tx.outgoing_amount != "0" {
            format!("-{}", format_sal(&tx.outgoing_amount))
        } else {
            "0".to_string()
        };

        println!(
            "{:<8} {:<10} {:<8} {:>16} {}",
            height,
            tx_type_name(tx.tx_type),
            &tx.asset_type,
            amount_str,
            hash_short,
        );
    }

    Ok(())
}

pub async fn show_stakes(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    let stakes = wallet.get_stakes(None)?;

    if stakes.is_empty() {
        println!("No stakes found.");
        return Ok(());
    }

    println!(
        "{:<8} {:>16} {:<10} TX Hash",
        "Height", "Amount", "Status"
    );
    println!("{}", "-".repeat(70));

    for stake in &stakes {
        let height = stake.stake_height.unwrap_or(0);
        let hash_short = if stake.stake_tx_hash.len() > 16 {
            format!("{}...", &stake.stake_tx_hash[..16])
        } else {
            stake.stake_tx_hash.clone()
        };

        println!(
            "{:<8} {:>16} {:<10} {}",
            height,
            format_sal(&stake.amount_staked),
            &stake.status,
            hash_short,
        );
    }

    Ok(())
}

pub async fn show_status(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);

    println!("Connecting to {} ...", ctx.daemon_url);

    let info = daemon.get_info().await?;

    println!("Daemon status:");
    println!("  Height:           {}", info.height);
    println!("  Difficulty:       {}", info.difficulty);
    println!("  Network hashrate: ~{} H/s", info.difficulty / 120);
    println!("  TX pool size:     {}", info.tx_pool_size);
    println!(
        "  Connections:      {} in / {} out",
        info.incoming_connections_count, info.outgoing_connections_count
    );
    println!(
        "  Synchronized:     {}",
        if info.synchronized { "yes" } else { "no" }
    );

    // Try to get yield info (staking economics).
    if let Ok(yi) = daemon.get_yield_info().await {
        println!();
        println!("Staking info:");
        println!("  Total staked:     {}", format_sal_u64(yi.total_staked));
        println!("  Total yield:      {}", format_sal_u64(yi.total_yield));
        if yi.yield_per_stake > 0.0 {
            println!("  Yield per stake:  {:.4}", yi.yield_per_stake);
        }
    }

    Ok(())
}

pub async fn export_view_key(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    println!("View secret key:  {}", wallet.view_secret_key_hex());
    println!("Spend public key: {}", wallet.spend_public_key_hex());
    println!();
    println!("Use these keys to create a view-only wallet that can");
    println!("monitor incoming transactions but cannot spend funds.");

    Ok(())
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn print_addresses(wallet: &Wallet) {
    match wallet.cn_address() {
        Ok(addr) => println!("CryptoNote address: {}", addr),
        Err(e) => println!("CryptoNote address: (error: {})", e),
    }
    match wallet.carrot_address() {
        Ok(addr) => println!("CARROT address:     {}", addr),
        Err(e) => println!("CARROT address:     (error: {})", e),
    }
    println!();
}
