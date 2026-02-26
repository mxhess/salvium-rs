//! Address and account management commands.

use super::*;

pub async fn show_address(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    print_addresses(&wallet);
    Ok(())
}

pub async fn account_new(ctx: &AppContext, label: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    // Track account labels via wallet attributes.
    // In the full C++ implementation, accounts map to subaddress major indices.
    let next_idx_str = wallet.get_attribute("account_count")?.unwrap_or_else(|| "1".to_string());
    let next_idx: u32 = next_idx_str.parse().unwrap_or(1);

    wallet.set_attribute(&format!("account_label:{}", next_idx), label)?;
    wallet.set_attribute("account_count", &(next_idx + 1).to_string())?;

    println!("Created account #{}: (label: {})", next_idx, label);
    println!("Note: subaddress derivation for new accounts requires a full sync.");
    Ok(())
}

pub async fn account_switch(ctx: &AppContext, index: u32) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.set_attribute("active_account", &index.to_string())?;
    println!("Switched to account #{}", index);
    Ok(())
}

pub async fn account_label(ctx: &AppContext, index: u32, label: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.set_attribute(&format!("account_label:{}", index), label)?;
    println!("Account #{} labelled: {}", index, label);
    Ok(())
}

pub async fn account_list(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    let count_str = wallet.get_attribute("account_count")?.unwrap_or_else(|| "1".to_string());
    let count: u32 = count_str.parse().unwrap_or(1);

    println!("{:<6} {:<20} {:>20} {:>20}", "Index", "Label", "Balance", "Unlocked");
    println!("{}", "-".repeat(70));

    for i in 0..count {
        let label = wallet.get_attribute(&format!("account_label:{}", i))?.unwrap_or_else(|| {
            if i == 0 {
                "Primary".to_string()
            } else {
                format!("Account #{}", i)
            }
        });
        let bal = wallet.get_balance("SAL", i as i32)?;
        println!(
            "{:<6} {:<20} {:>20} {:>20}",
            i,
            label,
            format_sal(&bal.balance),
            format_sal(&bal.unlocked_balance),
        );
    }

    Ok(())
}

pub async fn account_tag(ctx: &AppContext, tag: &str, accounts: &[u32]) -> Result {
    let wallet = open_wallet(ctx)?;
    for &idx in accounts {
        wallet.set_attribute(&format!("account_tag:{}", idx), tag)?;
    }
    println!("Tagged accounts {:?} with '{}'", accounts, tag);
    Ok(())
}

pub async fn account_untag(ctx: &AppContext, accounts: &[u32]) -> Result {
    let wallet = open_wallet(ctx)?;
    for &idx in accounts {
        wallet.set_attribute(&format!("account_tag:{}", idx), "")?;
    }
    println!("Untagged accounts {:?}", accounts);
    Ok(())
}

pub async fn address_new(ctx: &AppContext, _account: u32, label: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    // For subaddress derivation, we use the subaddress_maps() to determine
    // the next index, then derive via CryptoNote subaddress key derivation.
    let keys = wallet.keys();
    let view_key = &keys.cn.view_secret_key;
    let spend_pub = &keys.cn.spend_public_key;

    let count_key = format!("subaddr_count:{}", _account);
    let count_str = wallet.get_attribute(&count_key)?.unwrap_or_else(|| "1".to_string());
    let next_idx: u32 = count_str.parse().unwrap_or(1);

    // CryptoNote subaddress derivation:
    // m = Hs("SubAddr\0" || view_secret || major || minor)
    // D = m*G + spend_pub
    let mut data = Vec::new();
    data.extend_from_slice(b"SubAddr\0");
    data.extend_from_slice(view_key);
    data.extend_from_slice(&_account.to_le_bytes());
    data.extend_from_slice(&next_idx.to_le_bytes());
    let m = salvium_crypto::sc_reduce32(&salvium_crypto::keccak256(&data));
    let m_g = salvium_crypto::scalar_mult_base(&m);
    let mut m_g32 = [0u8; 32];
    m_g32.copy_from_slice(&m_g[..32]);
    let subaddr_spend = salvium_crypto::point_add_compressed(&m_g32, spend_pub);

    // Subaddress view key: subaddr_view = view_secret * subaddr_spend_pub
    let mut subaddr_spend32 = [0u8; 32];
    subaddr_spend32.copy_from_slice(&subaddr_spend[..32]);

    // Encode as subaddress.
    let network_tag = match wallet.network() {
        salvium_types::constants::Network::Mainnet => 0x2A_u64,
        salvium_types::constants::Network::Testnet => 0x3F,
        salvium_types::constants::Network::Stagenet => 0x24,
    };
    let view_pub = salvium_crypto::scalar_mult_point(view_key, &subaddr_spend32);
    let mut addr_data = Vec::new();
    addr_data.extend_from_slice(&subaddr_spend32);
    addr_data.extend_from_slice(&view_pub);
    let address = salvium_types::base58::encode_address(network_tag, &addr_data);

    wallet.set_attribute(&count_key, &(next_idx + 1).to_string())?;
    if !label.is_empty() {
        wallet.set_attribute(&format!("subaddr_label:{}:{}", _account, next_idx), label)?;
    }

    println!("New address [{}/{}]: {}", _account, next_idx, address);
    Ok(())
}

pub async fn address_all(ctx: &AppContext, account: u32) -> Result {
    let wallet = open_wallet(ctx)?;

    let count_key = format!("subaddr_count:{}", account);
    let count_str = wallet.get_attribute(&count_key)?.unwrap_or_else(|| "1".to_string());
    let count: u32 = count_str.parse().unwrap_or(1);

    println!("Account #{} addresses:", account);

    // Primary address for account 0.
    if account == 0 {
        let primary = wallet.cn_address().unwrap_or_default();
        println!("  [0/0] {}", primary);
    }

    // Show any additional subaddresses.
    for i in if account == 0 { 1 } else { 0 }..count {
        let label =
            wallet.get_attribute(&format!("subaddr_label:{}:{}", account, i))?.unwrap_or_default();

        println!("  [{}/{}] (subaddress)", account, i);
        if !label.is_empty() {
            println!("         Label: {}", label);
        }
    }

    Ok(())
}

pub async fn address_label(ctx: &AppContext, major: u32, minor: u32, label: &str) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.set_attribute(&format!("subaddr_label:{}:{}", major, minor), label)?;
    println!("Address [{}/{}] labelled: {}", major, minor, label);
    Ok(())
}

pub async fn integrated_address(ctx: &AppContext, payment_id: Option<&str>) -> Result {
    let wallet = open_wallet(ctx)?;

    let pid = if let Some(pid) = payment_id {
        let bytes = hex::decode(pid)?;
        if bytes.len() != 8 {
            return Err("payment ID must be 8 bytes (16 hex characters)".into());
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        // Generate random payment ID from current time.
        let random_bytes = salvium_crypto::keccak256(
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );
        let mut rng = [0u8; 8];
        rng.copy_from_slice(&random_bytes[..8]);
        rng
    };

    // Build integrated address from standard address + payment ID.
    let standard_addr = wallet.cn_address().unwrap_or_default();
    let integrated = salvium_types::address::to_integrated_address(&standard_addr, &pid)
        .map_err(|e| format!("failed to create integrated address: {}", e))?;

    println!("Integrated address: {}", integrated);
    println!("Payment ID:         {}", hex::encode(pid));

    Ok(())
}

pub async fn address_book_list(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let entries = wallet.get_address_book()?;

    if entries.is_empty() {
        println!("Address book is empty.");
        return Ok(());
    }

    println!("{:<4} {:<20} Address", "ID", "Label");
    println!("{}", "-".repeat(70));

    for entry in &entries {
        println!("{:<4} {:<20} {}", entry.row_id, &entry.label, &entry.address);
        if !entry.description.is_empty() {
            println!("     {}", &entry.description);
        }
    }

    Ok(())
}

pub async fn address_book_add(
    ctx: &AppContext,
    address: &str,
    label: &str,
    description: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    // Validate the address.
    salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid address: {}", e))?;

    let id = wallet.add_address_book_entry(address, label, description, "")?;
    println!("Added address book entry #{}", id);

    Ok(())
}

pub async fn address_book_delete(ctx: &AppContext, index: i64) -> Result {
    let wallet = open_wallet(ctx)?;
    let deleted = wallet.delete_address_book_entry(index)?;
    if deleted {
        println!("Deleted address book entry #{}", index);
    } else {
        println!("Address book entry #{} not found", index);
    }
    Ok(())
}
