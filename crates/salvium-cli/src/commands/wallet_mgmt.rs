//! Wallet lifecycle commands: create, restore, info, seed, password, save.

use super::*;

pub async fn create_wallet(ctx: &AppContext, name: Option<String>) -> Result {
    let path = wallet_path(ctx, name);

    if path.exists() {
        return Err(format!("wallet file already exists: {}", path.display()).into());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let password = prompt_password_confirm()?;
    let path_str = path.to_str().ok_or("invalid wallet path")?;

    // Generate random seed and random per-wallet data_key.
    let seed = WalletKeys::random_seed();
    let mut data_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data_key);

    let wallet = Wallet::create(seed, ctx.network, path_str, &data_key)?;

    // Derive keys from seed to populate secrets.
    let keys = WalletKeys::from_seed(seed, ctx.network);
    let mnemonic = wallet.mnemonic().and_then(|r| r.ok());

    let spend_sk = keys
        .cn
        .spend_secret_key
        .ok_or("wallet has no spend secret key")?;
    let secrets = salvium_wallet::WalletSecrets {
        seed: hex::encode(seed),
        spend_secret_key: hex::encode(spend_sk),
        view_secret_key: hex::encode(keys.cn.view_secret_key),
        data_key: hex::encode(data_key),
        mnemonic: mnemonic.clone(),
        network: network_str(ctx.network).to_string(),
    };

    save_wallet_meta(&path, &secrets, &password)?;

    println!("Wallet created: {}", path.display());
    println!();

    if let Some(ref mnemonic) = mnemonic {
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
    let path_str = path.to_str().ok_or("invalid wallet path")?;

    // Generate random per-wallet data_key.
    let mut data_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data_key);

    let wallet = Wallet::from_mnemonic(mnemonic, ctx.network, path_str, &data_key)?;

    let keys = wallet.keys();
    if let Some(seed) = keys.seed {
        let spend_sk = keys.cn.spend_secret_key.unwrap_or([0u8; 32]);
        let secrets = salvium_wallet::WalletSecrets {
            seed: hex::encode(seed),
            spend_secret_key: hex::encode(spend_sk),
            view_secret_key: hex::encode(keys.cn.view_secret_key),
            data_key: hex::encode(data_key),
            mnemonic: Some(mnemonic.to_string()),
            network: network_str(ctx.network).to_string(),
        };
        save_wallet_meta(&path, &secrets, &password)?;
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

pub async fn change_password(ctx: &AppContext) -> Result {
    let path = &ctx.wallet_path;
    if !path.exists() {
        return Err(format!("wallet file not found: {}", path.display()).into());
    }

    let old_pass = prompt_password("Current password: ")?;
    let secrets = load_wallet_meta(path, &old_pass)?;

    let new_pass = prompt_password("New password: ")?;
    let confirm = prompt_password("Confirm new password: ")?;
    if new_pass != confirm {
        return Err("passwords do not match".into());
    }

    // Re-encrypt the meta file with the new password.
    // The data_key stays the same — only the PQC envelope changes.
    // No database re-encryption needed.
    save_wallet_meta(path, &secrets, &new_pass)?;

    println!("Password changed successfully.");
    Ok(())
}

pub async fn save_wallet(ctx: &AppContext) -> Result {
    let _wallet = open_wallet(ctx)?;
    // The wallet uses SQLite which auto-commits; no explicit save needed.
    println!("Wallet data is automatically persisted to disk.");
    Ok(())
}

pub async fn save_watch_only(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    let keys = wallet.keys();
    let view_key = hex::encode(keys.cn.view_secret_key);
    let spend_pub = hex::encode(keys.cn.spend_public_key);

    println!("View-only wallet data:");
    println!("  View secret key:  {}", view_key);
    println!("  Spend public key: {}", spend_pub);

    if keys.carrot.view_balance_secret != [0u8; 32] {
        println!(
            "  CARROT view balance secret: {}",
            hex::encode(keys.carrot.view_balance_secret)
        );
        println!(
            "  CARROT account spend pubkey: {}",
            hex::encode(keys.carrot.account_spend_pubkey)
        );
    }

    println!();
    println!("Use these keys to create a view-only wallet.");
    Ok(())
}

pub async fn show_restore_height(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let height = wallet.sync_height().unwrap_or(0);
    println!("Restore height: {}", height);
    Ok(())
}
