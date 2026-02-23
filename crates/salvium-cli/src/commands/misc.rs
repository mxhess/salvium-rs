//! Miscellaneous commands: version, payment_id, set, lock, welcome.

use super::*;

pub async fn show_version() -> Result {
    println!(
        "Salvium wallet CLI v{} (salvium-rs)",
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}

pub async fn generate_payment_id() -> Result {
    let random = salvium_crypto::keccak256(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let payment_id = hex::encode(&random[..8]);
    println!("{}", payment_id);
    Ok(())
}

pub async fn set_config(ctx: &AppContext, key: &str, value: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.set_attribute(key, value)?;
    println!("Set {} = {}", key, value);
    Ok(())
}

pub async fn get_config(ctx: &AppContext, key: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    match wallet.get_attribute(key)? {
        Some(val) => println!("{} = {}", key, val),
        None => println!("{} is not set", key),
    }
    Ok(())
}

pub async fn lock_wallet(ctx: &AppContext) -> Result {
    // In a CLI context, "lock" just means the wallet file is closed.
    let _ = ctx;
    println!("Wallet locked. You will need to enter your password again.");
    Ok(())
}

pub async fn welcome() -> Result {
    println!("Welcome to the Salvium wallet CLI!");
    println!();
    println!("Quick start:");
    println!("  salvium-wallet-cli create           Create a new wallet");
    println!("  salvium-wallet-cli restore           Restore from seed phrase");
    println!("  salvium-wallet-cli sync              Sync with the blockchain");
    println!("  salvium-wallet-cli balance            Show balance");
    println!("  salvium-wallet-cli transfer           Send SAL");
    println!("  salvium-wallet-cli stake              Stake SAL tokens");
    println!("  salvium-wallet-cli --help             Show all commands");
    Ok(())
}
