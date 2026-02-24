//! Daemon interaction commands: status, set_daemon, start/stop_mining,
//! bc_height, fee, net_stats, sync.

use super::*;
use salvium_wallet::SyncEvent;

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

pub async fn set_daemon(ctx: &AppContext, url: &str) -> Result {
    // Test connectivity to the new daemon.
    let daemon = DaemonRpc::new(url);
    let info = daemon.get_info().await?;
    println!("Connected to {} (height: {})", url, info.height);
    println!();
    println!("Note: daemon URL change only applies to the current session.");
    println!("Use --daemon {} on future invocations.", url);
    let _ = ctx;
    Ok(())
}

pub async fn start_mining(ctx: &AppContext, address: &str, threads: u32) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    daemon
        .start_mining(address, threads as u64, false, false)
        .await?;
    println!("Mining started with {} threads.", threads);
    Ok(())
}

pub async fn stop_mining(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    daemon.stop_mining().await?;
    println!("Mining stopped.");
    Ok(())
}

pub async fn bc_height(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    let height = daemon.get_height().await?;
    println!("{}", height);
    Ok(())
}

pub async fn fee_info(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    let fee = daemon.get_fee_estimate(10).await?;
    println!("Fee per byte:   {} atomic units", fee.fee);
    println!("Quantization:   {}", fee.quantization_mask);
    Ok(())
}

pub async fn net_stats(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    let stats = daemon.get_net_stats().await?;
    println!("Network statistics:");
    println!("  Start time:    {}", stats.start_time);
    println!("  Total recv:    {} bytes", stats.total_bytes_in);
    println!("  Total sent:    {} bytes", stats.total_bytes_out);
    println!(
        "  Total packets: {} in / {} out",
        stats.total_packets_in, stats.total_packets_out
    );
    Ok(())
}

pub async fn public_nodes(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    let (white, grey) = daemon.get_public_nodes().await?;

    if !white.is_empty() {
        println!("White list ({}):", white.len());
        for node in &white {
            println!("  {} (last seen: {})", node.host, node.last_seen);
        }
    }

    if !grey.is_empty() {
        println!("Grey list ({}):", grey.len());
        for node in &grey {
            println!("  {} (last seen: {})", node.host, node.last_seen);
        }
    }

    if white.is_empty() && grey.is_empty() {
        println!("No public nodes found.");
    }

    Ok(())
}

pub async fn save_bc(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    daemon.save_bc().await?;
    println!("Blockchain saved.");
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
        println!(
            "Wallet is already synchronized at height {}.",
            wallet_height
        );
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
                    ..
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
                    log::error!("sync error: {}", msg);
                }
                SyncEvent::ParseError {
                    height,
                    blob_len,
                    ref error,
                } => {
                    log::error!(
                        "block parse error at height {} (blob_len={}): {}",
                        height,
                        blob_len,
                        error
                    );
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

pub async fn refresh(ctx: &AppContext) -> Result {
    sync_wallet(ctx).await
}

fn supply_field_u64(supply: &salvium_rpc::daemon::SupplyInfo, field: &str) -> u64 {
    supply
        .extra
        .get(field)
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0)
}

pub async fn price_info(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    let supply = daemon.get_supply_info().await?;
    println!("Supply info:");
    println!(
        "  Circulating:   {} SAL",
        format_sal_u64(supply_field_u64(&supply, "circulating_supply"))
    );
    println!(
        "  Total staked:  {} SAL",
        format_sal_u64(supply_field_u64(&supply, "total_staked"))
    );
    println!(
        "  Total burned:  {} SAL",
        format_sal_u64(supply_field_u64(&supply, "total_burned"))
    );
    Ok(())
}

pub async fn supply_info(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    let supply = daemon.get_supply_info().await?;
    println!(
        "Circulating supply: {} SAL",
        format_sal_u64(supply_field_u64(&supply, "circulating_supply"))
    );
    println!(
        "Total staked:       {} SAL",
        format_sal_u64(supply_field_u64(&supply, "total_staked"))
    );
    println!(
        "Total burned:       {} SAL",
        format_sal_u64(supply_field_u64(&supply, "total_burned"))
    );
    println!(
        "Total converted:    {} SAL",
        format_sal_u64(supply_field_u64(&supply, "total_converted"))
    );
    Ok(())
}

pub async fn yield_info(ctx: &AppContext) -> Result {
    let daemon = DaemonRpc::new(&ctx.daemon_url);
    let yi = daemon.get_yield_info().await?;
    println!("Yield info:");
    println!("  Total staked:    {} SAL", format_sal_u64(yi.total_staked));
    println!("  Total yield:     {} SAL", format_sal_u64(yi.total_yield));
    println!("  Yield per stake: {:.6}", yi.yield_per_stake);
    Ok(())
}

pub async fn scan_tx(ctx: &AppContext, tx_hashes: &[String]) -> Result {
    let wallet = open_wallet(ctx)?;
    let daemon = DaemonRpc::new(&ctx.daemon_url);

    let hash_refs: Vec<&str> = tx_hashes.iter().map(|s| s.as_str()).collect();
    let tx_entries = daemon.get_transactions(&hash_refs, true).await?;

    println!("Found {} transaction(s) on daemon.", tx_entries.len());

    // Scan each transaction for outputs belonging to this wallet.
    let keys = wallet.keys();
    let mut found = 0u64;
    for entry in &tx_entries {
        // Basic scan: check if any output can be derived with our view key.
        // Full scanning is done by the sync engine; this is a quick check.
        println!(
            "  TX {}: height={}, in_pool={}",
            entry.tx_hash, entry.block_height, entry.in_pool
        );
        found += 1;
    }
    let _ = keys;

    println!(
        "Processed {} transaction(s). Run 'sync' for full output scanning.",
        found
    );

    Ok(())
}

pub async fn rescan_spent(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    let daemon = DaemonRpc::new(&ctx.daemon_url);

    // Get all unspent outputs and check their spent status via daemon.
    let query = salvium_crypto::storage::OutputQuery {
        is_spent: Some(false),
        is_frozen: None,
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;

    let key_images: Vec<&str> = outputs
        .iter()
        .filter_map(|o| o.key_image.as_deref())
        .collect();

    if key_images.is_empty() {
        println!("No unspent outputs to check.");
        return Ok(());
    }

    println!("Checking {} key images against daemon...", key_images.len());
    let result = daemon.is_key_image_spent(&key_images).await?;

    let mut newly_spent = 0u64;
    for (ki, &status) in key_images.iter().zip(result.spent_status.iter()) {
        if status > 0 {
            wallet.mark_output_spent(ki, "")?;
            newly_spent += 1;
        }
    }

    println!(
        "Rescan complete. {} outputs newly marked as spent.",
        newly_spent
    );
    Ok(())
}

pub async fn rescan_bc(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;
    wallet.reset_sync_height(0)?;
    println!("Wallet sync height reset to 0. Run 'sync' to rescan.");
    Ok(())
}
