//! CLI command implementations, split by domain.

mod wallet_mgmt;
mod balance;
mod transfers;
mod history;
mod keys;
mod proofs;
mod address;
mod notes;
mod outputs;
mod daemon;
mod misc;
mod multisig;

use crate::AppContext;
use salvium_rpc::DaemonRpc;
use salvium_wallet::{Wallet, WalletKeys};
use std::path::PathBuf;

pub type Result = std::result::Result<(), Box<dyn std::error::Error>>;

// Re-export all public command functions so main.rs can call `commands::foo()`.
pub use wallet_mgmt::*;
pub use balance::*;
pub use transfers::*;
pub use history::*;
pub use keys::*;
pub use proofs::*;
pub use address::*;
pub use notes::*;
pub use outputs::*;
pub use daemon::*;
pub use misc::*;
pub use multisig::*;

// ─── Shared helpers used across multiple command modules ─────────────────────

pub(crate) fn hex_to_32(s: &str) -> std::result::Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub(crate) fn prompt_password(
    prompt: &str,
) -> std::result::Result<String, Box<dyn std::error::Error>> {
    let pass = rpassword::prompt_password(prompt)?;
    if pass.is_empty() {
        return Err("password cannot be empty".into());
    }
    Ok(pass)
}

pub(crate) fn prompt_password_confirm(
) -> std::result::Result<String, Box<dyn std::error::Error>> {
    let pass = prompt_password("Wallet password: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    if pass != confirm {
        return Err("passwords do not match".into());
    }
    Ok(pass)
}

/// Legacy DB key derivation — ONLY used for migrating old (SALW-magic) wallets.
/// New wallets use a random `data_key` stored inside the PQC envelope.
fn derive_legacy_db_key(password: &str) -> [u8; 32] {
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

pub(crate) fn wallet_path(ctx: &AppContext, name: Option<String>) -> PathBuf {
    if let Some(name) = name {
        let dir = ctx.wallet_path.parent().unwrap_or(&ctx.wallet_path);
        dir.join(format!("{}.db", name))
    } else {
        ctx.wallet_path.clone()
    }
}

/// Path for the encrypted metadata sidecar file.
pub(crate) fn meta_path(db_path: &std::path::Path) -> PathBuf {
    db_path.with_extension("meta")
}

/// Save wallet secrets to a PQC-encrypted sidecar `.meta` file.
pub(crate) fn save_wallet_meta(
    db_path: &std::path::Path,
    secrets: &salvium_wallet::WalletSecrets,
    password: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let envelope_bytes = salvium_wallet::encrypt_envelope(secrets, password)?;
    std::fs::write(meta_path(db_path), envelope_bytes)?;
    Ok(())
}

/// Load wallet secrets from the encrypted sidecar file.
///
/// Detects format automatically:
/// - JSON (starts with `{`) -> PQC envelope -> `decrypt_envelope()`
/// - SALW magic -> legacy classical -> `decrypt_wallet_data()` + migration
pub(crate) fn load_wallet_meta(
    db_path: &std::path::Path,
    password: &str,
) -> std::result::Result<salvium_wallet::WalletSecrets, Box<dyn std::error::Error>> {
    let mp = meta_path(db_path);
    if !mp.exists() {
        return Err(format!(
            "wallet metadata file not found: {}\nWallet may need to be restored.",
            mp.display()
        )
        .into());
    }
    let raw = std::fs::read(&mp)?;

    if raw.first() == Some(&b'{') {
        // PQC JSON envelope.
        let secrets = salvium_wallet::decrypt_envelope(&raw, password)
            .map_err(|e| format!("failed to decrypt wallet metadata (wrong password?): {}", e))?;
        Ok(secrets)
    } else if salvium_wallet::encryption::is_encrypted_wallet(&raw) {
        // Legacy SALW-magic format -> decrypt and migrate.
        let decrypted = salvium_wallet::encryption::decrypt_wallet_data(
            &raw,
            password.as_bytes(),
        )
        .map_err(|e| format!("failed to decrypt wallet metadata (wrong password?): {}", e))?;

        let text = String::from_utf8(decrypted).map_err(|_| "corrupted wallet metadata")?;
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
        let network = parts[1].to_string();

        // Derive keys from seed to populate the secrets struct.
        let net = match network.as_str() {
            "testnet" => salvium_types::constants::Network::Testnet,
            "stagenet" => salvium_types::constants::Network::Stagenet,
            _ => salvium_types::constants::Network::Mainnet,
        };
        let keys = WalletKeys::from_seed(seed, net);

        // Legacy: derive db_key from password (same as old derive_db_key).
        let legacy_db_key = derive_legacy_db_key(password);

        // Generate a new random data_key for migration.
        let mut data_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data_key);

        // Re-encrypt the database with the new random data_key.
        let path_str = db_path.to_str().ok_or("invalid wallet path")?;
        let db = salvium_wallet::WalletDb::open(path_str, &legacy_db_key)
            .map_err(|e| format!("failed to open legacy wallet DB: {}", e))?;
        db.rekey(&data_key)
            .map_err(|e| format!("failed to rekey wallet DB: {}", e))?;

        let spend_sk = keys.cn.spend_secret_key.unwrap_or([0u8; 32]);
        let secrets = salvium_wallet::WalletSecrets {
            seed: hex::encode(seed),
            spend_secret_key: hex::encode(spend_sk),
            view_secret_key: hex::encode(keys.cn.view_secret_key),
            data_key: hex::encode(data_key),
            mnemonic: None,
            network,
        };

        // Overwrite the .meta file with the PQC envelope.
        save_wallet_meta(db_path, &secrets, password)?;

        log::info!("migrated wallet to PQC encryption");
        Ok(secrets)
    } else {
        Err("unrecognized wallet metadata format".into())
    }
}

pub(crate) fn open_wallet(
    ctx: &AppContext,
) -> std::result::Result<Wallet, Box<dyn std::error::Error>> {
    let path = &ctx.wallet_path;
    if !path.exists() {
        return Err(format!(
            "wallet file not found: {}\nUse 'create' or 'restore' first, or specify --wallet-file",
            path.display()
        )
        .into());
    }

    let password = prompt_password("Wallet password: ")?;
    let path_str = path.to_str().ok_or("invalid wallet path")?;

    let secrets = load_wallet_meta(path, &password)?;
    let seed = secrets.seed_bytes()?;
    let data_key = secrets.data_key_bytes()?;

    let network = match secrets.network.as_str() {
        "testnet" => salvium_types::constants::Network::Testnet,
        "stagenet" => salvium_types::constants::Network::Stagenet,
        _ => salvium_types::constants::Network::Mainnet,
    };

    let keys = WalletKeys::from_seed(seed, network);
    Wallet::open(keys, path_str, &data_key).map_err(|e| e.into())
}

pub(crate) fn format_sal(atomic_str: &str) -> String {
    let atomic: u64 = atomic_str.parse().unwrap_or(0);
    format_sal_u64(atomic)
}

pub fn format_sal_u64(atomic: u64) -> String {
    use salvium_types::constants::COIN;
    let whole = atomic / COIN;
    let frac = atomic % COIN;
    if frac == 0 {
        format!("{}.00000000", whole)
    } else {
        format!("{}.{:08}", whole, frac)
    }
}

pub(crate) fn parse_sal_amount(
    s: &str,
) -> std::result::Result<u64, Box<dyn std::error::Error>> {
    use salvium_types::constants::COIN;
    let parts: Vec<&str> = s.split('.').collect();
    let whole: u64 = if parts[0].is_empty() {
        0
    } else {
        parts[0].parse()?
    };
    let frac: u64 = if parts.len() > 1 {
        let frac_str = parts[1];
        if frac_str.len() > 8 {
            return Err("too many decimal places (max 8)".into());
        }
        let padded = format!("{:0<8}", frac_str);
        padded.parse()?
    } else {
        0
    };
    Ok(whole * COIN + frac)
}

pub(crate) fn tx_type_name(t: i64) -> &'static str {
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

pub(crate) fn print_addresses(wallet: &Wallet) {
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

pub(crate) fn network_str(network: salvium_types::constants::Network) -> &'static str {
    match network {
        salvium_types::constants::Network::Testnet => "testnet",
        salvium_types::constants::Network::Stagenet => "stagenet",
        _ => "mainnet",
    }
}
