//! Balance, incoming transfers, and unspent output commands.

use super::*;

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

pub async fn incoming_transfers(ctx: &AppContext, transfer_type: &str, account: i32) -> Result {
    let wallet = open_wallet(ctx)?;

    let query = salvium_crypto::storage::OutputQuery {
        is_spent: match transfer_type {
            "available" => Some(false),
            "unavailable" => Some(true),
            _ => None, // "all"
        },
        is_frozen: None,
        asset_type: None,
        tx_type: None,
        account_index: Some(account as i64),
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;

    if outputs.is_empty() {
        println!("No incoming transfers found.");
        return Ok(());
    }

    println!(
        "{:<8} {:>16} {:<8} {:<10} Key Image",
        "Height", "Amount", "Asset", "Status"
    );
    println!("{}", "-".repeat(80));

    for o in &outputs {
        let status = if o.is_spent { "spent" } else { "unspent" };
        let height = o.block_height.unwrap_or(0);
        let ki = o.key_image.as_deref().unwrap_or("-");
        println!(
            "{:<8} {:>16} {:<8} {:<10} {}",
            height,
            format_sal(&o.amount),
            &o.asset_type,
            status,
            ki,
        );
    }

    Ok(())
}

pub async fn unspent_outputs(ctx: &AppContext, account: i32) -> Result {
    let wallet = open_wallet(ctx)?;

    let query = salvium_crypto::storage::OutputQuery {
        is_spent: Some(false),
        is_frozen: Some(false),
        asset_type: None,
        tx_type: None,
        account_index: Some(account as i64),
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;

    if outputs.is_empty() {
        println!("No unspent outputs found.");
        return Ok(());
    }

    println!(
        "{:<8} {:>16} {:<8} {:<6} Key Image",
        "Height", "Amount", "Asset", "Frozen"
    );
    println!("{}", "-".repeat(80));

    for o in &outputs {
        let ki = o.key_image.as_deref().unwrap_or("-");
        println!(
            "{:<8} {:>16} {:<8} {:<6} {}",
            o.block_height.unwrap_or(0),
            format_sal(&o.amount),
            &o.asset_type,
            if o.is_frozen { "yes" } else { "no" },
            ki,
        );
    }

    Ok(())
}

pub async fn payments(ctx: &AppContext, payment_id: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    let query = salvium_crypto::storage::TxQuery {
        is_incoming: Some(true),
        is_outgoing: None,
        is_confirmed: None,
        in_pool: None,
        tx_type: None,
        min_height: None,
        max_height: None,
        tx_hash: None,
    };
    let transfers = wallet.get_transfers(&query)?;

    let filtered: Vec<_> = transfers
        .iter()
        .filter(|tx| tx.payment_id.as_deref() == Some(payment_id))
        .collect();

    if filtered.is_empty() {
        println!("No payments found for payment ID: {}", payment_id);
        return Ok(());
    }

    println!(
        "{:<8} {:>16} TX Hash",
        "Height", "Amount"
    );
    println!("{}", "-".repeat(60));

    for tx in &filtered {
        println!(
            "{:<8} {:>16} {}",
            tx.block_height.unwrap_or(0),
            format_sal(&tx.incoming_amount),
            &tx.tx_hash,
        );
    }

    Ok(())
}
