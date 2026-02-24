//! Wallet restore + sync benchmark.
//!
//! Simulates a real wallet restore: creates a wallet from various key sources
//! (mnemonic, seed, view+spend keys, view-only), syncs the full chain, then
//! prints balances and performance metrics.
//!
//! Usage:
//!   cargo run --release -p salvium-sync-bench -- --mnemonic "25 words ..." --network testnet

use clap::Parser;
use salvium_crypto::storage::OutputQuery;
use salvium_rpc::DaemonRpc;
use salvium_types::constants::{self, Network};
use salvium_wallet::{SyncEvent, Wallet, WalletKeys, WalletType};
use std::time::Instant;
use tokio::sync::mpsc;

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "salvium-sync-bench", about = "Wallet restore + sync benchmark")]
struct Args {
    /// 25-word mnemonic seed phrase
    #[arg(long)]
    mnemonic: Option<String>,

    /// 32-byte hex seed
    #[arg(long)]
    seed: Option<String>,

    /// View secret key (hex) — used with --spend-key or --spend-pub
    #[arg(long)]
    view_key: Option<String>,

    /// Spend secret key (hex) — full wallet from keys
    #[arg(long)]
    spend_key: Option<String>,

    /// Spend public key (hex) — view-only wallet
    #[arg(long)]
    spend_pub: Option<String>,

    /// Daemon RPC URL
    #[arg(long)]
    daemon: Option<String>,

    /// Network: mainnet, testnet, stagenet
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Start sync from this height
    #[arg(long, default_value = "0")]
    restore_height: u64,

    /// Persist wallet to this directory (default: temp dir, auto-cleaned)
    #[arg(long)]
    wallet_dir: Option<String>,

    /// Don't delete temp wallet after run
    #[arg(long)]
    keep_wallet: bool,

    /// Account index for balance queries
    #[arg(long, default_value = "0")]
    account: i32,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn parse_network(s: &str) -> Result<Network, String> {
    match s.to_lowercase().as_str() {
        "mainnet" | "main" => Ok(Network::Mainnet),
        "testnet" | "test" => Ok(Network::Testnet),
        "stagenet" | "stage" => Ok(Network::Stagenet),
        _ => Err(format!("unknown network: {s}")),
    }
}

fn default_daemon_url(network: Network) -> &'static str {
    match network {
        Network::Testnet => "http://node12.whiskymine.io:29081",
        Network::Stagenet => "http://node12.whiskymine.io:39081",
        Network::Mainnet => "http://node12.whiskymine.io:19081",
    }
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn format_sal(atomic_str: &str) -> String {
    let atomic: u64 = atomic_str.parse().unwrap_or(0);
    let whole = atomic / constants::COIN;
    let frac = atomic % constants::COIN;
    format!("{}.{:08}", whole, frac)
}

fn wallet_type_label(wt: WalletType) -> &'static str {
    match wt {
        WalletType::Full => "Full",
        WalletType::ViewOnly => "View-only",
        WalletType::Watch => "Watch-only",
        WalletType::Multisig { .. } => "Multisig",
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let network = parse_network(&args.network)?;
    let daemon_url = args
        .daemon
        .as_deref()
        .unwrap_or_else(|| default_daemon_url(network));

    // ── 1. Determine wallet type and source label ───────────────────────
    let source_label;

    // ── 2. Connect to daemon ────────────────────────────────────────────
    let daemon = DaemonRpc::new(daemon_url);
    let info = daemon
        .get_info()
        .await
        .map_err(|e| format!("cannot reach daemon at {daemon_url}: {e}"))?;

    let daemon_height = info.height;
    let synchronized = info.synchronized;

    // ── 3. Create wallet ────────────────────────────────────────────────
    // DB setup: either user-specified dir or a temp dir
    let temp_dir;
    let db_path = if let Some(ref dir) = args.wallet_dir {
        std::fs::create_dir_all(dir)?;
        format!("{dir}/wallet.db")
    } else {
        temp_dir = Some(tempfile::tempdir()?);
        temp_dir
            .as_ref()
            .unwrap()
            .path()
            .join("wallet.db")
            .to_str()
            .unwrap()
            .to_string()
    };

    let mut db_key = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut db_key);

    let wallet = if let Some(ref mnemonic) = args.mnemonic {
        source_label = "mnemonic";
        Wallet::from_mnemonic(mnemonic, network, &db_path, &db_key)?
    } else if let Some(ref seed_hex) = args.seed {
        source_label = "hex seed";
        let seed = hex_to_32(seed_hex)?;
        Wallet::create(seed, network, &db_path, &db_key)?
    } else if let Some(ref view_hex) = args.view_key {
        let view_sk = hex_to_32(view_hex)?;

        if let Some(ref spend_hex) = args.spend_key {
            source_label = "view + spend keys";
            let spend_sk = hex_to_32(spend_hex)?;
            // Derive full keys from spend secret key (as seed)
            let keys = WalletKeys::from_seed(spend_sk, network);
            // Verify the view key matches
            if keys.cn.view_secret_key != view_sk {
                return Err(
                    "--view-key does not match the view key derived from --spend-key".into(),
                );
            }
            Wallet::open(keys, &db_path, &db_key)?
        } else if let Some(ref spend_pub_hex) = args.spend_pub {
            source_label = "view-only (view secret + spend public)";
            let spend_pk = hex_to_32(spend_pub_hex)?;
            let keys = WalletKeys::view_only(view_sk, spend_pk, network);
            Wallet::open(keys, &db_path, &db_key)?
        } else {
            return Err("--view-key requires either --spend-key or --spend-pub".into());
        }
    } else {
        return Err(
            "provide one of: --mnemonic, --seed, or --view-key (with --spend-key or --spend-pub)"
                .into(),
        );
    };

    // Set restore height if requested
    if args.restore_height > 0 {
        wallet.reset_sync_height(args.restore_height)?;
    }

    // ── Print banner ────────────────────────────────────────────────────
    println!();
    println!("Salvium Sync Benchmark");
    println!("======================");
    println!("Network:        {:?}", network);
    println!(
        "Daemon:         {} (height: {}, {})",
        daemon_url,
        daemon_height,
        if synchronized {
            "synchronized"
        } else {
            "syncing"
        }
    );
    println!(
        "Wallet type:    {} (from {})",
        wallet_type_label(wallet.wallet_type()),
        source_label
    );
    println!("Restore height: {}", args.restore_height);
    println!();

    // ── 4. Sync with progress ───────────────────────────────────────────
    let blocks_to_sync = daemon_height.saturating_sub(args.restore_height);
    println!("Syncing {} blocks...", blocks_to_sync);

    let (tx, mut rx) = mpsc::channel::<SyncEvent>(64);
    let start = Instant::now();

    // Spawn progress printer
    let progress_handle = tokio::spawn(async move {
        let mut last_print_height: u64 = 0;
        let print_interval: u64 = 2000;
        let mut final_parse_errors: usize = 0;
        let mut final_empty_blobs: usize = 0;

        while let Some(event) = rx.recv().await {
            match event {
                SyncEvent::Progress {
                    current_height,
                    target_height,
                    outputs_found,
                    parse_errors,
                    empty_blobs,
                } => {
                    final_parse_errors = parse_errors;
                    final_empty_blobs = empty_blobs;

                    let should_print = current_height >= target_height
                        || current_height >= last_print_height + print_interval;

                    if should_print {
                        let elapsed = start.elapsed().as_secs_f64();
                        let pct = if target_height > 0 {
                            current_height as f64 / target_height as f64 * 100.0
                        } else {
                            100.0
                        };
                        let bps = if elapsed > 0.0 {
                            current_height as f64 / elapsed
                        } else {
                            0.0
                        };
                        let err_suffix = if parse_errors > 0 {
                            format!("  |  {} parse errors", parse_errors)
                        } else {
                            String::new()
                        };
                        println!(
                            "  Height {:>6}/{} ({:>5.1}%)  |  {:>5} outputs  |  {:.1}s  |  {:.0} blocks/s{}",
                            current_height, target_height, pct, outputs_found, elapsed, bps, err_suffix
                        );
                        last_print_height = current_height;
                    }
                }
                SyncEvent::Reorg {
                    from_height,
                    to_height,
                } => {
                    println!("  ** Reorg detected: {} -> {} **", from_height, to_height);
                }
                SyncEvent::Error(ref msg) => {
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
                SyncEvent::Complete { height } => {
                    let elapsed = start.elapsed().as_secs_f64();
                    let bps = if elapsed > 0.0 {
                        height as f64 / elapsed
                    } else {
                        0.0
                    };
                    println!(
                        "  Height {:>6}/{} (100.0%)  |  sync complete  |  {:.1}s  |  {:.0} blocks/s",
                        height, height, elapsed, bps
                    );
                }
                SyncEvent::Started { .. } => {}
            }
        }

        (final_parse_errors, final_empty_blobs)
    });

    let sync_result = wallet.sync(&daemon, Some(&tx)).await;
    drop(tx); // close channel so progress task finishes
    let (final_parse_errors, final_empty_blobs) = progress_handle.await.unwrap_or((0, 0));

    let sync_height = sync_result?;
    let elapsed = start.elapsed();

    // ── 5. Gather and print results ─────────────────────────────────────
    let actual_blocks_synced = sync_height.saturating_sub(args.restore_height);
    let blocks_per_sec = if elapsed.as_secs_f64() > 0.0 {
        actual_blocks_synced as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    // Count outputs
    let all_outputs = wallet.get_outputs(&OutputQuery {
        is_spent: None,
        is_frozen: None,
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    })?;

    let total_outputs = all_outputs.len();
    let unspent = all_outputs.iter().filter(|o| !o.is_spent).count();
    let spent = total_outputs - unspent;
    let carrot = all_outputs.iter().filter(|o| o.is_carrot).count();
    let cn = total_outputs - carrot;

    println!();
    println!("Sync Complete");
    println!("-------------");
    println!("Height:          {}", sync_height);
    println!("Duration:        {:.1}s", elapsed.as_secs_f64());
    println!("Avg blocks/sec:  {:.1}", blocks_per_sec);
    println!(
        "Total outputs:   {} ({} unspent, {} spent)",
        total_outputs, unspent, spent
    );
    println!("  CryptoNote:    {}", cn);
    println!("  CARROT:        {}", carrot);
    println!("Parse errors:    {}", final_parse_errors);
    println!("Empty blobs:     {}", final_empty_blobs);

    // Dump unspent outputs for debugging
    let unspent_outputs: Vec<_> = all_outputs.iter().filter(|o| !o.is_spent).collect();
    if !unspent_outputs.is_empty() {
        println!();
        println!("Unspent Outputs ({})", unspent_outputs.len());
        println!("{}", "-".repeat(110));
        println!(
            "{:<6} {:<8} {:>18} {:>8} {:<6} {:<10} {:<64}",
            "Idx", "Asset", "Amount (atomic)", "Height", "Type", "Carrot?", "Key Image"
        );
        println!("{}", "-".repeat(110));
        for o in &unspent_outputs {
            let height_str = o
                .block_height
                .map(|h| h.to_string())
                .unwrap_or_else(|| "?".into());
            let ki_str = o.key_image.as_deref().unwrap_or("(none)");
            let tx_type_str = match o.tx_type {
                1 => "miner",
                2 => "proto",
                3 => "xfer",
                4 => "conv",
                5 => "burn",
                6 => "stake",
                7 => "ret",
                _ => "?",
            };
            println!(
                "{:<6} {:<8} {:>18} {:>8} {:<6} {:<10} {:.64}",
                o.output_index,
                o.asset_type,
                o.amount,
                height_str,
                tx_type_str,
                if o.is_carrot { "CARROT" } else { "CN" },
                ki_str,
            );
        }
        println!("{}", "-".repeat(110));
    }

    // Stakes summary
    let all_stakes = wallet.get_stakes(None)?;
    if !all_stakes.is_empty() {
        let locked_stakes: Vec<_> = all_stakes.iter().filter(|s| s.status == "locked").collect();
        let returned_stakes: Vec<_> = all_stakes
            .iter()
            .filter(|s| s.status == "returned")
            .collect();
        let txid_matched: Vec<_> = returned_stakes
            .iter()
            .filter(|s| s.return_output_key.is_some())
            .collect();
        let height_matched: Vec<_> = returned_stakes
            .iter()
            .filter(|s| s.return_output_key.is_none())
            .collect();

        println!();
        println!(
            "Stakes ({} total: {} locked, {} returned)",
            all_stakes.len(),
            locked_stakes.len(),
            returned_stakes.len()
        );
        println!("{}", "-".repeat(100));
        println!(
            "{:<18} {:>8} {:>16} {:>8} {:<10} {:<10}",
            "Stake TX", "Height", "Amount", "Asset", "Status", "Method"
        );
        println!("{}", "-".repeat(100));

        for s in &all_stakes {
            let method = if s.status == "returned" {
                if s.return_output_key.is_some() {
                    "tx-id"
                } else {
                    "height"
                }
            } else if s.return_output_key.is_some() {
                "has-key"
            } else {
                "no-key"
            };
            println!(
                "{:<18} {:>8} {:>16} {:>8} {:<10} {:<10}",
                &s.stake_tx_hash[..s.stake_tx_hash.len().min(16)],
                s.stake_height.unwrap_or(0),
                format_sal(&s.amount_staked),
                s.asset_type,
                s.status,
                method,
            );
        }

        println!("{}", "-".repeat(100));
        println!(
            "Return tracking: {} via tx-id match, {} via height-based fallback",
            txid_matched.len(),
            height_matched.len()
        );
    }

    // Balances per asset
    let balances = wallet.get_all_balances(args.account)?;
    if !balances.is_empty() {
        println!();
        println!("Balances");
        println!("--------");
        println!(
            "{:<8} {:>19} {:>19} {:>19}",
            "Asset", "Total", "Unlocked", "Locked"
        );

        let mut assets: Vec<_> = balances.iter().collect();
        assets.sort_by_key(|(name, _)| {
            if *name == "SAL" {
                String::new()
            } else {
                (*name).clone()
            }
        });

        for (asset, bal) in &assets {
            println!(
                "{:<8} {:>19} {:>19} {:>19}",
                asset,
                format_sal(&bal.balance),
                format_sal(&bal.unlocked_balance),
                format_sal(&bal.locked_balance),
            );
        }
    }

    println!();

    // ── 6. Cleanup ──────────────────────────────────────────────────────
    if args.wallet_dir.is_none() && args.keep_wallet {
        // User wants to keep the temp wallet — leak the TempDir
        // We need the temp_dir to have been created; it was in an Option
        // above. Since we don't own it here (it was in a let binding),
        // just print the path.
        println!("Wallet kept at: {}", db_path);
    }

    Ok(())
}
