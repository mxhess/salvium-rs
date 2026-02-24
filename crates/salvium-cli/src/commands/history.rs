//! Transaction history commands: show_transfers, show_transfer, export_transfers.

use super::*;

/// Options for filtering `show_transfers`.
#[allow(dead_code)]
pub struct TransferFilters {
    pub in_: bool,
    pub out: bool,
    pub pending: bool,
    pub failed: bool,
    pub pool: bool,
    pub coinbase: bool,
    pub burnt: bool,
    pub staked: bool,
    pub min_height: Option<u64>,
    pub max_height: Option<u64>,
    pub account: i32,
    pub limit: usize,
}

impl Default for TransferFilters {
    fn default() -> Self {
        Self {
            in_: true,
            out: true,
            pending: false,
            failed: false,
            pool: false,
            coinbase: false,
            burnt: false,
            staked: false,
            min_height: None,
            max_height: None,
            account: 0,
            limit: 25,
        }
    }
}

pub async fn show_transfers(ctx: &AppContext, f: &TransferFilters) -> Result {
    let wallet = open_wallet(ctx)?;

    let query = salvium_crypto::storage::TxQuery {
        is_incoming: if f.in_ && !f.out {
            Some(true)
        } else if f.out && !f.in_ {
            Some(false)
        } else {
            None
        },
        is_outgoing: if f.out && !f.in_ {
            Some(true)
        } else if f.in_ && !f.out {
            Some(false)
        } else {
            None
        },
        is_confirmed: if f.pending { Some(false) } else { None },
        in_pool: if f.pool { Some(true) } else { None },
        tx_type: if f.burnt {
            Some(salvium_tx::types::tx_type::BURN as i64)
        } else if f.staked {
            Some(salvium_tx::types::tx_type::STAKE as i64)
        } else {
            None
        },
        min_height: f.min_height.map(|h| h as i64),
        max_height: f.max_height.map(|h| h as i64),
        tx_hash: None,
    };
    let transfers = wallet.get_transfers(&query)?;

    if transfers.is_empty() {
        println!("No transactions found. Run 'sync' to scan the blockchain.");
        return Ok(());
    }

    let display_count = transfers.len().min(f.limit);
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

    for tx in transfers.iter().rev().take(f.limit) {
        let height = tx.block_height.unwrap_or(0);
        let hash_short = if tx.tx_hash.len() > 16 {
            format!("{}...", &tx.tx_hash[..16])
        } else {
            tx.tx_hash.clone()
        };

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

pub async fn show_history(ctx: &AppContext, _account: i32, limit: usize) -> Result {
    let f = TransferFilters {
        limit,
        account: _account,
        ..Default::default()
    };
    show_transfers(ctx, &f).await
}

pub async fn show_transfer(ctx: &AppContext, tx_hash: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    let query = salvium_crypto::storage::TxQuery {
        is_incoming: None,
        is_outgoing: None,
        is_confirmed: None,
        in_pool: None,
        tx_type: None,
        min_height: None,
        max_height: None,
        tx_hash: Some(tx_hash.to_string()),
    };
    let transfers = wallet.get_transfers(&query)?;

    let tx = transfers
        .first()
        .ok_or_else(|| format!("transaction not found: {}", tx_hash))?;

    println!("Transaction details:");
    println!("  TX hash:    {}", tx.tx_hash);
    println!("  Type:       {}", tx_type_name(tx.tx_type));
    println!("  Asset:      {}", tx.asset_type);
    println!("  Height:     {}", tx.block_height.unwrap_or(0));
    println!("  Timestamp:  {}", tx.block_timestamp.unwrap_or(0));
    println!("  Fee:        {}", format_sal(&tx.fee));

    if tx.incoming_amount != "0" {
        println!("  Incoming:   {}", format_sal(&tx.incoming_amount));
    }
    if tx.outgoing_amount != "0" {
        println!("  Outgoing:   {}", format_sal(&tx.outgoing_amount));
    }

    if !tx.note.is_empty() {
        println!("  Note:       {}", tx.note);
    }

    if let Some(ref pid) = tx.payment_id {
        if !pid.is_empty() && pid != "0000000000000000" {
            println!("  Payment ID: {}", pid);
        }
    }

    Ok(())
}

pub async fn export_transfers(ctx: &AppContext, output_file: &str) -> Result {
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

    let mut csv =
        String::from("height,type,direction,asset,amount,fee,tx_hash,timestamp,payment_id\n");

    for tx in &transfers {
        let direction = if tx.incoming_amount != "0" {
            "in"
        } else {
            "out"
        };
        let amount = if tx.incoming_amount != "0" {
            &tx.incoming_amount
        } else {
            &tx.outgoing_amount
        };
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            tx.block_height.unwrap_or(0),
            tx_type_name(tx.tx_type),
            direction,
            tx.asset_type,
            format_sal(amount),
            format_sal(&tx.fee),
            tx.tx_hash,
            tx.block_timestamp.unwrap_or(0),
            tx.payment_id.as_deref().unwrap_or(""),
        ));
    }

    std::fs::write(output_file, &csv)?;
    println!(
        "Exported {} transactions to {}",
        transfers.len(),
        output_file
    );

    Ok(())
}

pub async fn show_stakes(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    let stakes = wallet.get_stakes(None)?;

    if stakes.is_empty() {
        println!("No stakes found.");
        return Ok(());
    }

    println!("{:<8} {:>16} {:<10} TX Hash", "Height", "Amount", "Status");
    println!("{}", "-".repeat(70));

    for s in &stakes {
        let height = s.stake_height.unwrap_or(0);
        let hash_short = if s.stake_tx_hash.len() > 16 {
            format!("{}...", &s.stake_tx_hash[..16])
        } else {
            s.stake_tx_hash.clone()
        };

        println!(
            "{:<8} {:>16} {:<10} {}",
            height,
            format_sal(&s.amount_staked),
            &s.status,
            hash_short,
        );
    }

    Ok(())
}
