//! Miscellaneous commands: version, payment_id, set, lock, welcome, set_log, apropos, show_qr_code.

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

pub async fn set_log(level: &str) -> Result {
    let filter = match level.to_lowercase().as_str() {
        "0" | "off" => log::LevelFilter::Off,
        "1" | "error" => log::LevelFilter::Error,
        "2" | "warn" => log::LevelFilter::Warn,
        "3" | "info" => log::LevelFilter::Info,
        "4" | "debug" => log::LevelFilter::Debug,
        "5" | "trace" => log::LevelFilter::Trace,
        _ => return Err(format!("unknown log level: {} (use 0-5, off/error/warn/info/debug/trace)", level).into()),
    };
    log::set_max_level(filter);
    println!("Log level set to: {}", filter);
    Ok(())
}

pub fn apropos(keyword: &str, app: &clap::Command) -> Result {
    let lower = keyword.to_lowercase();
    let mut found = false;

    for cmd in app.get_subcommands() {
        let name = cmd.get_name();
        let about = cmd.get_about().map(|s| s.to_string()).unwrap_or_default();

        if name.to_lowercase().contains(&lower) || about.to_lowercase().contains(&lower) {
            println!("  {:<30} {}", name, about);
            found = true;
        }
    }

    if !found {
        println!("No commands found matching \"{}\".", keyword);
    }

    Ok(())
}

pub async fn show_qr_code(ctx: &AppContext, use_carrot: bool) -> Result {
    let wallet = open_wallet(ctx)?;

    let address = if use_carrot {
        wallet
            .carrot_address()
            .map_err(|e| format!("failed to get CARROT address: {}", e))?
    } else {
        wallet
            .cn_address()
            .map_err(|e| format!("failed to get CryptoNote address: {}", e))?
    };

    println!(
        "{} address:",
        if use_carrot { "CARROT" } else { "CryptoNote" }
    );
    println!("  {}", address);
    println!();

    // Generate QR code and render with Unicode half-block characters.
    let qr = qrcode::QrCode::new(address.as_bytes())
        .map_err(|e| format!("failed to generate QR code: {}", e))?;

    let width = qr.width();
    let data = qr.into_colors();

    // Each printed row covers 2 QR rows using half-block characters:
    //   U+2588 = FULL BLOCK  (both top and bottom dark)
    //   U+2580 = UPPER HALF  (top dark, bottom light)
    //   U+2584 = LOWER HALF  (top light, bottom dark)
    //   ' '    = SPACE       (both light)
    // Add a 1-module quiet zone on each side.

    // Top quiet zone (one row of spaces with border).
    let border = "  ".repeat(width + 2);
    println!("{}", border);

    let mut y = 0;
    while y < width {
        let mut line = String::from("  "); // left quiet zone
        for x in 0..width {
            let top = data[y * width + x] == qrcode::Color::Dark;
            let bottom = if y + 1 < width {
                data[(y + 1) * width + x] == qrcode::Color::Dark
            } else {
                false
            };
            let ch = match (top, bottom) {
                (true, true) => '\u{2588}',   // FULL BLOCK
                (true, false) => '\u{2580}',  // UPPER HALF BLOCK
                (false, true) => '\u{2584}',  // LOWER HALF BLOCK
                (false, false) => ' ',
            };
            line.push(ch);
        }
        line.push_str("  "); // right quiet zone
        println!("{}", line);
        y += 2;
    }

    println!("{}", border); // bottom quiet zone
    Ok(())
}
