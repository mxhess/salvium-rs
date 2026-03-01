//! Testnet integration tests for the FFI transfer/stake/sweep pipeline.
//!
//! These tests exercise the **exact same code path** that the mobile app uses:
//! `do_transfer`, `do_stake`, `do_sweep` from `salvium_ffi::transfer`.
//!
//! All tests broadcast real transactions and mine blocks to confirm them.
//!
//! Pre-requisites:
//!   - Pre-funded testnet wallet files in `~/testnet-wallet/`:
//!     - `wallet-a.json` + `wallet-a.pin`
//!   - Access to testnet daemon (default: node12.whiskymine.io:29081)
//!
//! Run with:
//!   cargo test -p salvium-ffi --test testnet_ffi -- --ignored --nocapture

use salvium_ffi::transfer::{self, DestinationParam, StakeParams, SweepParams, TransferParams};
use salvium_rpc::{NodePool, PoolConfig};
use salvium_tx::fee::FeePriority;
use salvium_types::constants::Network;
use salvium_wallet::{decrypt_js_wallet, Wallet};

use std::path::PathBuf;

const DAEMON_URL: &str = "http://node12.whiskymine.io:29081";
const TRANSFER_AMOUNT: u64 = 100_000_000; // 0.1 SAL
const STAKE_AMOUNT: u64 = 1_000_000_000; // 1 SAL
/// Blocks to mine for output maturity (coinbase lock).
const MATURITY_BLOCKS: u64 = 10;

// =============================================================================
// Helpers
// =============================================================================

fn testnet_wallet_dir() -> PathBuf {
    dirs::home_dir().unwrap().join("testnet-wallet")
}

fn pool() -> NodePool {
    let url = std::env::var("TESTNET_DAEMON_URL").unwrap_or_else(|_| DAEMON_URL.to_string());
    NodePool::new(PoolConfig {
        network: Network::Testnet,
        primary_url: Some(url),
        ..Default::default()
    })
}

async fn load_and_sync_wallet(name: &str) -> (Wallet, NodePool) {
    let dir = testnet_wallet_dir();
    let json_file = format!("{}.json", name);
    let pin_file = format!("{}.pin", name);

    let wallet_json = std::fs::read_to_string(dir.join(&json_file))
        .unwrap_or_else(|_| panic!("{} not found in ~/testnet-wallet/", json_file));
    let pin = std::fs::read_to_string(dir.join(&pin_file))
        .unwrap_or_else(|_| panic!("{} not found in ~/testnet-wallet/", pin_file))
        .trim()
        .to_string();

    let secrets = decrypt_js_wallet(&wallet_json, &pin).expect("failed to decrypt wallet");

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join(format!("{}.db", name));
    let mut wallet =
        Wallet::create(secrets.seed, Network::Testnet, db_path.to_str().unwrap(), &[0u8; 32])
            .expect("create wallet");

    let p = pool();
    let height = wallet
        .sync(&p, None, &std::sync::atomic::AtomicBool::new(false))
        .await
        .expect("sync failed");

    println!("  Synced {} to height {}", name, height);
    println!("  CARROT address: {}", wallet.carrot_address().unwrap());

    // Leak the tempdir so it doesn't get cleaned up during the test
    std::mem::forget(temp_dir);

    (wallet, p)
}

fn miner_binary_path() -> PathBuf {
    let workspace =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf();
    let release = workspace.join("target/release/salvium-miner");
    if release.exists() {
        return release;
    }
    let debug = workspace.join("target/debug/salvium-miner");
    if debug.exists() {
        return debug;
    }
    panic!(
        "salvium-miner not found. Run: cargo build -p salvium-miner --release\n  Checked: {}\n  Checked: {}",
        release.display(), debug.display()
    );
}

fn daemon_url() -> String {
    std::env::var("TESTNET_DAEMON_URL").unwrap_or_else(|_| DAEMON_URL.to_string())
}

/// Mine `count` blocks using salvium-miner, then re-sync the wallet.
async fn mine_and_sync(wallet: &mut Wallet, pool: &NodePool, count: u64) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    let daemon = pool.active_daemon().await;
    let address = wallet.carrot_address().unwrap();
    let start_height = daemon.get_info().await.unwrap().height;
    let target = start_height + count;
    let url = daemon_url();

    println!("  Mining {} blocks ({} -> {})...", count, start_height, target);

    let miner = miner_binary_path();
    let mut child = Command::new(&miner)
        .args(["--daemon", &url, "--wallet", &address, "--threads", "4", "--light"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn salvium-miner");

    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr).lines();
    let mut accepted = 0u64;

    while let Ok(Some(line)) = reader.next_line().await {
        if line.contains("Block accepted!") {
            accepted += 1;
            if accepted.is_multiple_of(50) || accepted >= count {
                println!("    {} blocks accepted...", accepted);
            }
        }
        if accepted >= count {
            break;
        }
    }

    let _ = child.kill().await;
    let _ = child.wait().await;

    let final_height = daemon.get_info().await.unwrap().height;
    println!("  Mined to height {} ({} blocks)", final_height, final_height - start_height);

    let height = wallet
        .sync(pool, None, &std::sync::atomic::AtomicBool::new(false))
        .await
        .expect("re-sync failed");
    println!("  Re-synced to height {}", height);
}

/// Print balance and return unlocked amount.
fn print_balance(wallet: &Wallet, asset: &str) -> u64 {
    let balance = wallet.get_balance(asset, 0).unwrap();
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap();
    let total: u64 = balance.balance.parse().unwrap();
    println!(
        "  Balance: {:.9} {} (unlocked: {:.9})",
        total as f64 / 1e9,
        asset,
        unlocked as f64 / 1e9
    );
    unlocked
}

/// Parse the JSON result and print key fields.
fn print_result(label: &str, result: &str) {
    let v: serde_json::Value = serde_json::from_str(result).expect("invalid JSON result");
    println!("\n  {} result:", label);
    if let Some(hash) = v.get("tx_hash") {
        println!("    tx_hash: {}", hash.as_str().unwrap_or("?"));
    }
    if let Some(fee) = v.get("fee") {
        let fee_val: u64 = fee.as_str().unwrap_or("0").parse().unwrap_or(0);
        println!("    fee: {} ({:.9} SAL)", fee_val, fee_val as f64 / 1e9);
    }
    if let Some(w) = v.get("weight") {
        println!("    weight (actual): {}", w);
    }
    if let Some(ew) = v.get("estimated_weight") {
        println!("    weight (estimated): {}", ew);
    }
    if let Some(fpb) = v.get("fee_per_byte") {
        println!("    fee_per_byte: {}", fpb);
    }
    // Show weight delta (estimate vs actual)
    if let (Some(w), Some(ew)) = (v.get("weight"), v.get("estimated_weight")) {
        let actual = w.as_u64().unwrap_or(0) as i64;
        let estimated = ew.as_u64().unwrap_or(0) as i64;
        let delta = actual - estimated;
        let pct = if estimated > 0 { 100.0 * delta as f64 / estimated as f64 } else { 0.0 };
        println!("    weight delta: {} ({:+.1}%)", delta, pct);
    }
    // Fee accuracy: fee should exactly match weight * fee_per_byte (build-measure-rebuild)
    if let (Some(fee), Some(w), Some(fpb)) = (v.get("fee"), v.get("weight"), v.get("fee_per_byte"))
    {
        let fee_val: u64 = fee.as_str().unwrap_or("0").parse().unwrap_or(0);
        let weight = w.as_u64().unwrap_or(0);
        let fpb_val = fpb.as_u64().unwrap_or(0);
        if fpb_val > 0 {
            let fee_needed = weight * fpb_val;
            let fee_diff = fee_val as i64 - fee_needed as i64;
            println!(
                "    fee accuracy: fee={} needed={} diff={} {}",
                fee_val,
                fee_needed,
                fee_diff,
                if fee_diff >= 0 { "OK" } else { "*** TOO LOW ***" }
            );
        }
    }
}

/// Parse batched sweep result (multiple TXs) and print summary.
fn print_sweep_result(label: &str, result: &str) {
    let v: serde_json::Value = serde_json::from_str(result).expect("invalid JSON result");
    let n_txs = v.get("num_transactions").and_then(|n| n.as_u64()).unwrap_or(0);
    let total_inputs = v.get("total_inputs").and_then(|n| n.as_u64()).unwrap_or(0);
    let total_fee: u64 =
        v.get("total_fee").and_then(|f| f.as_str()).unwrap_or("0").parse().unwrap_or(0);
    let total_amount: u64 =
        v.get("total_amount").and_then(|f| f.as_str()).unwrap_or("0").parse().unwrap_or(0);

    println!("\n  {} summary:", label);
    println!(
        "    {} TX(s), {} total inputs, {:.9} SAL swept, {:.9} SAL fee",
        n_txs,
        total_inputs,
        total_amount as f64 / 1e9,
        total_fee as f64 / 1e9
    );

    if let Some(txs) = v.get("transactions").and_then(|t| t.as_array()) {
        for (i, tx) in txs.iter().enumerate() {
            println!(
                "    TX {}/{}: hash={} inputs={} fee={} weight={}",
                i + 1,
                n_txs,
                tx.get("tx_hash").and_then(|h| h.as_str()).unwrap_or("?"),
                tx.get("inputs").and_then(|n| n.as_u64()).unwrap_or(0),
                tx.get("fee").and_then(|f| f.as_str()).unwrap_or("?"),
                tx.get("weight").and_then(|w| w.as_u64()).unwrap_or(0),
            );
        }
    }
}

// =============================================================================
// Single integration test: Transfer -> mine -> Stake -> mine -> Sweep
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_ffi_full_pipeline() {
    println!("\n=== FFI Full Pipeline (Transfer -> Stake -> Sweep -> All Priorities) ===\n");

    let (mut wallet, p) = load_and_sync_wallet("wallet-a").await;
    let daemon = p.active_daemon().await;
    let (_, _, native_asset) = transfer::detect_fork_params(&daemon).await.unwrap();
    let asset_type = &native_asset;
    let self_address = wallet.carrot_address().unwrap();
    println!("  Asset type: {}\n", asset_type);

    let mut pass = 0u32;
    let mut fail = 0u32;

    // ── Mine blocks first to flush any pending mempool TXs from prior runs ──
    println!("  Mining {} blocks to flush mempool and mature outputs...", MATURITY_BLOCKS);
    mine_and_sync(&mut wallet, &p, MATURITY_BLOCKS).await;

    // ── Ensure we have unlocked outputs ──
    let unlocked = print_balance(&wallet, "SAL");
    if unlocked < TRANSFER_AMOUNT + STAKE_AMOUNT + 100_000_000 {
        println!("\n  Low balance — mining {} more blocks for maturity...", MATURITY_BLOCKS);
        mine_and_sync(&mut wallet, &p, MATURITY_BLOCKS).await;
        print_balance(&wallet, "SAL");
    }

    // ── 1. Transfer ──
    {
        println!("\n--- Transfer: {:.9} {} to self ---", TRANSFER_AMOUNT as f64 / 1e9, asset_type);
        let fee_ctx = transfer::resolve_fee_context(&p, FeePriority::Normal).await.unwrap();
        let params = TransferParams {
            destinations: vec![DestinationParam {
                address: self_address.clone(),
                amount: TRANSFER_AMOUNT.to_string(),
            }],
            asset_type: asset_type.to_string(),
            priority: "normal".to_string(),
            ring_size: 16,
            dry_run: false,
        };
        match transfer::do_transfer(
            &wallet,
            &daemon,
            &params,
            fee_ctx.priority,
            fee_ctx.fee_per_byte,
        )
        .await
        {
            Ok(json) => {
                print_result("Transfer", &json);
                pass += 1;
            }
            Err(e) => {
                println!("  TRANSFER FAILED: {}", e);
                fail += 1;
            }
        }
    }

    // Mine to confirm + mature the transfer output
    println!("\n  Mining {} blocks for maturity...", MATURITY_BLOCKS);
    mine_and_sync(&mut wallet, &p, MATURITY_BLOCKS).await;
    print_balance(&wallet, "SAL");

    // ── 2. Stake ──
    {
        println!("\n--- Stake: {:.9} {} ---", STAKE_AMOUNT as f64 / 1e9, asset_type);
        let fee_ctx = transfer::resolve_fee_context(&p, FeePriority::Normal).await.unwrap();
        let params = StakeParams {
            amount: STAKE_AMOUNT.to_string(),
            asset_type: asset_type.to_string(),
            priority: "normal".to_string(),
            ring_size: 16,
        };
        match transfer::do_stake(
            &wallet,
            &daemon,
            &params,
            fee_ctx.priority,
            fee_ctx.fee_per_byte,
            false,
        )
        .await
        {
            Ok(json) => {
                print_result("Stake", &json);
                pass += 1;
            }
            Err(e) => {
                println!("  STAKE FAILED: {}", e);
                fail += 1;
            }
        }
    }

    // Mine to confirm + mature
    println!("\n  Mining {} blocks for maturity...", MATURITY_BLOCKS);
    mine_and_sync(&mut wallet, &p, MATURITY_BLOCKS).await;
    print_balance(&wallet, "SAL");

    // ── 3. Sweep (batched, 64 inputs per TX) ──
    {
        println!("\n--- Sweep: all inputs to self (batched) ---");
        let fee_ctx = transfer::resolve_fee_context(&p, FeePriority::Normal).await.unwrap();
        let params = SweepParams {
            address: self_address.clone(),
            asset_type: asset_type.to_string(),
            priority: "normal".to_string(),
            ring_size: 16,
            dry_run: false,
        };
        match transfer::do_sweep(&wallet, &daemon, &params, fee_ctx.priority, fee_ctx.fee_per_byte)
            .await
        {
            Ok(json) => {
                print_sweep_result("Sweep", &json);
                pass += 1;
            }
            Err(e) => {
                println!("  SWEEP FAILED: {}", e);
                fail += 1;
            }
        }
    }

    // Mine to confirm sweep outputs
    println!("\n  Mining {} blocks for maturity...", MATURITY_BLOCKS);
    mine_and_sync(&mut wallet, &p, MATURITY_BLOCKS).await;
    print_balance(&wallet, "SAL");

    // ── 4. All priority levels ──
    {
        println!("\n--- Transfer at all priority levels ---");
        let priorities = [
            ("low", FeePriority::Low),
            ("normal", FeePriority::Normal),
            ("elevated", FeePriority::High),
            ("urgent", FeePriority::Highest),
        ];
        let amount: u64 = 10_000_000; // 0.01 SAL per priority level

        for (label, priority) in &priorities {
            let unlocked = print_balance(&wallet, "SAL");
            if unlocked < amount + 100_000_000 {
                println!("  Low balance — mining maturity blocks...");
                mine_and_sync(&mut wallet, &p, MATURITY_BLOCKS).await;
            }

            println!("\n  Priority: {}", label);
            let fee_ctx = transfer::resolve_fee_context(&p, *priority).await.unwrap();
            println!(
                "    Resolved: priority={:?}, fee_per_byte={}",
                fee_ctx.priority, fee_ctx.fee_per_byte
            );

            let params = TransferParams {
                destinations: vec![DestinationParam {
                    address: self_address.clone(),
                    amount: amount.to_string(),
                }],
                asset_type: asset_type.to_string(),
                priority: label.to_string(),
                ring_size: 16,
                dry_run: false,
            };

            match transfer::do_transfer(
                &wallet,
                &daemon,
                &params,
                fee_ctx.priority,
                fee_ctx.fee_per_byte,
            )
            .await
            {
                Ok(json) => {
                    print_result(&format!("Transfer ({})", label), &json);
                    pass += 1;
                }
                Err(e) => {
                    println!("    FAILED: {}", e);
                    fail += 1;
                }
            }

            // Mine between priority levels so outputs mature
            println!("    Mining {} blocks...", MATURITY_BLOCKS);
            mine_and_sync(&mut wallet, &p, MATURITY_BLOCKS).await;
        }
    }

    println!("\n=== Results: {} passed, {} failed ===", pass, fail);
    assert_eq!(fail, 0, "{} operations failed", fail);
}
