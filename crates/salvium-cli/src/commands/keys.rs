//! Key display and file-signing commands.

use super::*;

pub async fn show_viewkey(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    println!("View secret key: {}", wallet.view_secret_key_hex());
    println!(
        "View public key: {}",
        hex::encode(wallet.keys().cn.view_public_key)
    );

    Ok(())
}

pub async fn show_spendkey(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        println!("Spend public key: {}", wallet.spend_public_key_hex());
        println!("(spend secret key not available — view-only wallet)");
        return Ok(());
    }

    let keys = wallet.keys();
    if let Some(sk) = keys.cn.spend_secret_key {
        println!("Spend secret key: {}", hex::encode(sk));
    }
    println!("Spend public key: {}", wallet.spend_public_key_hex());

    Ok(())
}

pub async fn show_carrot_keys(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let keys = wallet.keys();

    println!("CARROT key set:");
    if let Some(ps) = keys.carrot.prove_spend_key {
        println!("  Prove spend key:          {}", hex::encode(ps));
    }
    println!(
        "  View balance secret:      {}",
        hex::encode(keys.carrot.view_balance_secret)
    );
    println!(
        "  Generate image key:       {}",
        hex::encode(keys.carrot.generate_image_key)
    );
    println!(
        "  View incoming key:        {}",
        hex::encode(keys.carrot.view_incoming_key)
    );
    println!(
        "  Generate address secret:  {}",
        hex::encode(keys.carrot.generate_address_secret)
    );
    println!(
        "  Account spend pubkey:     {}",
        hex::encode(keys.carrot.account_spend_pubkey)
    );
    println!(
        "  Primary address view pub: {}",
        hex::encode(keys.carrot.primary_address_view_pubkey)
    );
    println!(
        "  Account view pubkey:      {}",
        hex::encode(keys.carrot.account_view_pubkey)
    );

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

pub async fn sign_data(ctx: &AppContext, file_path: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sign with a view-only wallet".into());
    }

    let data = std::fs::read(file_path)
        .map_err(|e| format!("failed to read file {}: {}", file_path, e))?;

    let keys = wallet.keys();
    let spend_secret = keys
        .cn
        .spend_secret_key
        .ok_or("wallet has no spend secret key")?;

    // Hash the data, then sign with Ed25519: sig = spend_secret * H(data).
    let hash = salvium_crypto::keccak256(&data);
    let mut hash32 = [0u8; 32];
    hash32.copy_from_slice(&hash[..32]);

    // Generate signature: R = r*G, s = r - c*key where c = H(R || pubkey || message).
    let r_scalar = salvium_crypto::keccak256(&[&spend_secret[..], &hash32[..]].concat());
    let mut r32 = [0u8; 32];
    r32.copy_from_slice(&salvium_crypto::sc_reduce32(&r_scalar));
    let r_pub = salvium_crypto::scalar_mult_base(&r32);
    let mut r_pub32 = [0u8; 32];
    r_pub32.copy_from_slice(&r_pub);

    let c_data = [&r_pub32[..], &keys.cn.spend_public_key[..], &hash32[..]].concat();
    let c_hash = salvium_crypto::keccak256(&c_data);
    let c_reduced = salvium_crypto::sc_reduce32(&c_hash);

    let s = salvium_crypto::sc_mul_sub(&c_reduced, &spend_secret, &r32);

    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&c_reduced[..32]);
    sig.extend_from_slice(&s[..32]);

    println!("SigV2{}", hex::encode(&sig));

    Ok(())
}

pub async fn verify_data(
    ctx: &AppContext,
    file_path: &str,
    address: &str,
    signature: &str,
) -> Result {
    let _wallet = open_wallet(ctx)?;

    let data = std::fs::read(file_path)
        .map_err(|e| format!("failed to read file {}: {}", file_path, e))?;

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid address: {}", e))?;

    let sig_hex = signature
        .strip_prefix("SigV2")
        .ok_or("invalid signature format (expected SigV2 prefix)")?;
    let sig_bytes = hex::decode(sig_hex)?;
    if sig_bytes.len() != 64 {
        return Err("invalid signature length".into());
    }

    let hash = salvium_crypto::keccak256(&data);
    let mut hash32 = [0u8; 32];
    hash32.copy_from_slice(&hash[..32]);

    let c = &sig_bytes[..32];
    let s = &sig_bytes[32..];

    // Verify: R' = s*G + c*PubKey, then check c == H(R' || pubkey || message).
    let r_prime = salvium_crypto::double_scalar_mult_base(c, &parsed_addr.spend_public_key, s);
    let mut r_prime32 = [0u8; 32];
    r_prime32.copy_from_slice(&r_prime);

    let c_check_data = [
        &r_prime32[..],
        &parsed_addr.spend_public_key[..],
        &hash32[..],
    ]
    .concat();
    let c_check = salvium_crypto::keccak256(&c_check_data);
    let c_check_reduced = salvium_crypto::sc_reduce32(&c_check);

    if c_check_reduced[..32] == *c {
        println!("Good signature from {}", address);
    } else {
        println!("BAD signature!");
        return Err("signature verification failed".into());
    }

    Ok(())
}
