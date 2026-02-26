//! Wallet sync integration test.
//!
//! Syncs a wallet (from seed, mnemonic, or view keys) across the Salvium
//! blockchain and reports balances for ALL asset types (SAL, SAL1, etc.).
//!
//! # Environment Variables
//!
//! Required (one of):
//!   SYNC_SEED        — 64-char hex seed (32 bytes)
//!   SYNC_MNEMONIC    — 25-word mnemonic seed phrase
//!   SYNC_VIEW_KEY    — hex view secret key (for view-only wallet)
//!   SYNC_SPEND_PUB   — hex spend public key (required with SYNC_VIEW_KEY)
//!
//! Optional:
//!   SYNC_DAEMON_URL       — daemon RPC URL (default: http://node12.whiskymine.io:19081)
//!   SYNC_NETWORK          — "mainnet" (default), "testnet", or "stagenet"
//!   SYNC_EXPECTED_BALANCE — expected balance (atomic units) for SYNC_ASSET_TYPE
//!   SYNC_MIN_BALANCE      — minimum balance (atomic units) for SYNC_ASSET_TYPE
//!   SYNC_ASSET_TYPE       — asset type for balance assertions (default: "SAL")
//!   SYNC_DB_KEY           — hex database encryption key (default: all zeros)
//!
//! # Usage
//!
//! Full sync from seed, verify exact balance:
//! ```sh
//! SYNC_SEED=abcdef...1234 \
//! SYNC_EXPECTED_BALANCE=50000000000 \
//! cargo test -p salvium-ffi --test wallet_sync -- --ignored --nocapture
//! ```
//!
//! Full sync from mnemonic on testnet:
//! ```sh
//! SYNC_MNEMONIC="word1 word2 ... word25" \
//! SYNC_DAEMON_URL=http://localhost:29081 \
//! SYNC_NETWORK=testnet \
//! SYNC_MIN_BALANCE=1000000000 \
//! cargo test -p salvium-ffi --test wallet_sync -- --ignored --nocapture
//! ```
//!
//! View-only wallet sync:
//! ```sh
//! SYNC_VIEW_KEY=abcd...1234 \
//! SYNC_SPEND_PUB=5678...abcd \
//! SYNC_NETWORK=mainnet \
//! cargo test -p salvium-ffi --test wallet_sync -- --ignored --nocapture
//! ```

use salvium_rpc::DaemonRpc;
use salvium_types::constants::Network;
use salvium_wallet::{SyncEvent, Wallet, WalletKeys};
use std::time::Instant;

// =============================================================================
// Default Constants
// =============================================================================

const DEFAULT_DAEMON_URL_MAINNET: &str = "http://node12.whiskymine.io:19081";
const DEFAULT_DAEMON_URL_TESTNET: &str = "http://node12.whiskymine.io:29081";
const DEFAULT_ASSET_TYPE: &str = "SAL";

// =============================================================================
// Helpers
// =============================================================================

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn parse_network(s: &str) -> Network {
    match s.to_lowercase().as_str() {
        "mainnet" | "main" => Network::Mainnet,
        "testnet" | "test" => Network::Testnet,
        "stagenet" | "stage" => Network::Stagenet,
        _ => panic!(
            "invalid SYNC_NETWORK: '{}' (expected mainnet/testnet/stagenet)",
            s
        ),
    }
}

fn hex_to_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).unwrap_or_else(|e| panic!("invalid hex '{}': {}", hex_str, e));
    assert_eq!(
        bytes.len(),
        32,
        "expected 32 bytes, got {} from hex",
        bytes.len()
    );
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

fn fmt_sal(atomic: u64) -> String {
    format!("{:.9}", atomic as f64 / 1_000_000_000.0)
}

fn fmt_duration(secs: f64) -> String {
    if secs < 60.0 {
        format!("{:.1}s", secs)
    } else if secs < 3600.0 {
        format!("{}m {:02}s", secs as u64 / 60, secs as u64 % 60)
    } else {
        format!(
            "{}h {:02}m {:02}s",
            secs as u64 / 3600,
            (secs as u64 % 3600) / 60,
            secs as u64 % 60
        )
    }
}

fn default_daemon_url(network: Network) -> &'static str {
    match network {
        Network::Mainnet => DEFAULT_DAEMON_URL_MAINNET,
        Network::Testnet | Network::Stagenet => DEFAULT_DAEMON_URL_TESTNET,
    }
}

// =============================================================================
// Test: Full Wallet Sync & Balance Verification
// =============================================================================

#[tokio::test]
#[ignore]
async fn wallet_sync_and_balance_check() {
    println!("\n{}", "=".repeat(64));
    println!("  Wallet Sync & Balance Verification");
    println!("{}\n", "=".repeat(64));

    // ── Parse configuration ─────────────────────────────────────────────
    let network = parse_network(&env_or("SYNC_NETWORK", "mainnet"));
    let daemon_url = env_or("SYNC_DAEMON_URL", default_daemon_url(network));
    // Asset type is only used for optional balance assertions, not for filtering sync.
    let assert_asset = env_or("SYNC_ASSET_TYPE", DEFAULT_ASSET_TYPE);
    let expected_balance: Option<u64> = env_opt("SYNC_EXPECTED_BALANCE").map(|s| {
        s.parse()
            .expect("invalid SYNC_EXPECTED_BALANCE (must be u64 atomic units)")
    });
    let min_balance: Option<u64> = env_opt("SYNC_MIN_BALANCE").map(|s| {
        s.parse()
            .expect("invalid SYNC_MIN_BALANCE (must be u64 atomic units)")
    });

    let db_key = env_opt("SYNC_DB_KEY")
        .map(|h| hex::decode(&h).expect("invalid SYNC_DB_KEY hex"))
        .unwrap_or_else(|| vec![0u8; 32]);

    // ── Create wallet keys ──────────────────────────────────────────────
    let (keys, wallet_mode) = if let Some(seed_hex) = env_opt("SYNC_SEED") {
        let seed = hex_to_32(&seed_hex);
        (WalletKeys::from_seed(seed, network), "full (from seed)")
    } else if let Some(mnemonic) = env_opt("SYNC_MNEMONIC") {
        let keys = WalletKeys::from_mnemonic(&mnemonic, network).expect("invalid SYNC_MNEMONIC");
        (keys, "full (from mnemonic)")
    } else if let Some(view_key_hex) = env_opt("SYNC_VIEW_KEY") {
        let spend_pub_hex =
            env_opt("SYNC_SPEND_PUB").expect("SYNC_SPEND_PUB is required when using SYNC_VIEW_KEY");
        let view_key = hex_to_32(&view_key_hex);
        let spend_pub = hex_to_32(&spend_pub_hex);
        (
            WalletKeys::view_only(view_key, spend_pub, network),
            "view-only",
        )
    } else {
        panic!(
            "No wallet key material provided.\n\
             Set one of: SYNC_SEED, SYNC_MNEMONIC, or SYNC_VIEW_KEY+SYNC_SPEND_PUB"
        );
    };

    println!("  Network:      {:?}", network);
    println!("  Daemon:       {}", daemon_url);
    println!("  Wallet mode:  {}", wallet_mode);
    println!("  Can spend:    {}", keys.can_spend());

    // Print addresses
    if let Ok(addr) = keys.cn_address() {
        println!(
            "  CN address:   {}...{}",
            &addr[..20],
            &addr[addr.len() - 8..]
        );
    }
    if let Ok(addr) = keys.carrot_address() {
        println!(
            "  CARROT addr:  {}...{}",
            &addr[..20],
            &addr[addr.len() - 8..]
        );
    }

    // ── Create wallet + database ────────────────────────────────────────
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("sync_test.db");
    let mut wallet =
        Wallet::open(keys, db_path.to_str().unwrap(), &db_key).expect("failed to open wallet");

    // ── Connect to daemon ───────────────────────────────────────────────
    let daemon = DaemonRpc::new(&daemon_url);
    let info = daemon
        .get_info()
        .await
        .expect("failed to connect to daemon");
    println!("\n  Daemon height:       {}", info.height);
    println!("  Daemon synchronized: {}", info.synchronized);
    assert!(
        info.synchronized,
        "daemon is not fully synchronized — wait and retry"
    );

    // ── Sync wallet ─────────────────────────────────────────────────────
    println!("\n  Starting full sync from genesis...\n");
    let start = Instant::now();

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<SyncEvent>(256);

    // Spawn a progress reporter.
    let progress_task = tokio::spawn(async move {
        let mut last_percent = 0u64;
        let mut total_outputs = 0u32;
        while let Some(event) = event_rx.recv().await {
            match event {
                SyncEvent::Started { target_height } => {
                    println!("  Sync started — target height: {}", target_height);
                }
                SyncEvent::Progress {
                    current_height,
                    target_height,
                    outputs_found,
                    ..
                } => {
                    total_outputs += outputs_found as u32;
                    let percent = if target_height > 0 {
                        (current_height * 100) / target_height
                    } else {
                        0
                    };
                    // Print every 5% or when outputs are found.
                    if percent >= last_percent + 5 || outputs_found > 0 {
                        println!(
                            "  [{:>3}%] height {}/{} — {} outputs found (batch: {})",
                            percent, current_height, target_height, total_outputs, outputs_found
                        );
                        last_percent = percent;
                    }
                }
                SyncEvent::Complete { height } => {
                    println!(
                        "  Sync complete at height {} — {} total outputs",
                        height, total_outputs
                    );
                }
                SyncEvent::Reorg {
                    from_height,
                    to_height,
                } => {
                    println!("  REORG detected: {} -> {}", from_height, to_height);
                }
                SyncEvent::Error(msg) => {
                    eprintln!("  SYNC ERROR: {}", msg);
                }
                SyncEvent::ParseError {
                    height,
                    blob_len,
                    ref error,
                } => {
                    eprintln!(
                        "  PARSE ERROR at height {} (blob_len={}): {}",
                        height, blob_len, error
                    );
                }
                SyncEvent::Cancelled { height } => {
                    println!("  ** Sync cancelled at height {} **", height);
                }
            }
        }
    });

    let no_cancel = std::sync::atomic::AtomicBool::new(false);
    let sync_height = wallet
        .sync(&daemon, Some(&event_tx), &no_cancel)
        .await
        .expect("wallet sync failed");

    drop(event_tx); // Close channel so progress reporter exits.
    let _ = progress_task.await;

    let elapsed = start.elapsed().as_secs_f64();
    println!("\n  Sync completed in {}", fmt_duration(elapsed));
    println!("  Final sync height: {}", sync_height);

    // ── Verify sync height ──────────────────────────────────────────────
    assert!(sync_height > 0, "sync height should be > 0");
    assert!(
        sync_height >= info.height.saturating_sub(2),
        "sync height ({}) should be near daemon tip ({})",
        sync_height,
        info.height
    );

    // ── Check balances (all asset types) ────────────────────────────────
    println!("\n  Balance Summary (all asset types):");
    println!("  {:-<60}", "");

    let all_balances = wallet.get_all_balances(0).unwrap();

    // Sort by asset name for consistent output.
    let mut assets: Vec<_> = all_balances.iter().collect();
    assets.sort_by_key(|(name, _)| (*name).clone());

    for (asset, bal) in &assets {
        let total: u64 = bal.balance.parse().unwrap_or(0);
        let unlocked: u64 = bal.unlocked_balance.parse().unwrap_or(0);
        let locked: u64 = bal.locked_balance.parse().unwrap_or(0);
        println!(
            "  {:>6}: total = {:>15}  unlocked = {:>15}  locked = {:>15}",
            asset,
            fmt_sal(total),
            fmt_sal(unlocked),
            fmt_sal(locked)
        );
    }

    if all_balances.is_empty() {
        println!("  (no outputs found — wallet may have zero balance)");
    }

    println!("  {:-<60}", "");

    // ── Balance assertions (optional, for a specific asset type) ─────
    if expected_balance.is_some() || min_balance.is_some() {
        let target_balance = wallet.get_balance(&assert_asset, 0).unwrap();
        let target_total: u64 = target_balance.balance.parse().unwrap_or(0);
        let target_unlocked: u64 = target_balance.unlocked_balance.parse().unwrap_or(0);

        println!("\n  Assertion target '{}' balance:", assert_asset);
        println!(
            "    total:    {} ({} atomic units)",
            fmt_sal(target_total),
            target_total
        );
        println!(
            "    unlocked: {} ({} atomic units)",
            fmt_sal(target_unlocked),
            target_unlocked
        );

        if let Some(expected) = expected_balance {
            println!(
                "  Expected: {} ({} atomic units)",
                fmt_sal(expected),
                expected
            );
            assert_eq!(
                target_total, expected,
                "\n  BALANCE MISMATCH for '{}'!\n  Expected: {} ({} atomic)\n  Got:      {} ({} atomic)\n  Diff:     {} atomic units",
                assert_asset,
                fmt_sal(expected), expected,
                fmt_sal(target_total), target_total,
                (target_total as i128 - expected as i128).abs()
            );
            println!("  PASS: {} balance matches expected value", assert_asset);
        }

        if let Some(min) = min_balance {
            println!("  Minimum: {} ({} atomic units)", fmt_sal(min), min);
            assert!(
                target_total >= min,
                "\n  BALANCE TOO LOW for '{}'!\n  Minimum:  {} ({} atomic)\n  Got:      {} ({} atomic)",
                assert_asset,
                fmt_sal(min), min,
                fmt_sal(target_total), target_total
            );
            println!("  PASS: {} balance >= minimum", assert_asset);
        }
    }

    // ── Output statistics ───────────────────────────────────────────────
    let all_outputs = wallet
        .get_outputs(&salvium_wallet::OutputQuery {
            is_spent: None,
            is_frozen: None,
            asset_type: None,
            tx_type: None,
            account_index: None,
            subaddress_index: None,
            min_amount: None,
            max_amount: None,
        })
        .unwrap();

    let unspent = all_outputs.iter().filter(|o| !o.is_spent).count();
    let spent = all_outputs.iter().filter(|o| o.is_spent).count();
    let carrot = all_outputs.iter().filter(|o| o.is_carrot).count();
    let legacy = all_outputs.iter().filter(|o| !o.is_carrot).count();

    println!("\n  Output Statistics:");
    println!("    Total outputs:   {}", all_outputs.len());
    println!("    Unspent:         {}", unspent);
    println!("    Spent:           {}", spent);
    println!("    Legacy (CN):     {}", legacy);
    println!("    CARROT:          {}", carrot);

    // ── Transfer history ────────────────────────────────────────────────
    let transfers = wallet
        .get_transfers(&salvium_wallet::TxQuery {
            is_incoming: None,
            is_outgoing: None,
            is_confirmed: None,
            in_pool: None,
            tx_type: None,
            min_height: None,
            max_height: None,
            tx_hash: None,
        })
        .unwrap();

    let incoming = transfers.iter().filter(|t| t.is_incoming).count();
    let outgoing = transfers.iter().filter(|t| t.is_outgoing).count();

    println!("\n  Transfer History:");
    println!("    Total transfers: {}", transfers.len());
    println!("    Incoming:        {}", incoming);
    println!("    Outgoing:        {}", outgoing);

    // ── Staking info ────────────────────────────────────────────────────
    let stakes = wallet.get_stakes(None).unwrap();
    if !stakes.is_empty() {
        println!("\n  Stakes:");
        for stake in &stakes {
            let amount: u64 = stake.amount_staked.parse().unwrap_or(0);
            println!(
                "    tx={:.16}...  amount={}  status={}",
                stake.stake_tx_hash,
                fmt_sal(amount),
                stake.status
            );
        }
    }

    // ── Sync idempotency check ──────────────────────────────────────────
    println!("\n  Verifying sync idempotency...");
    let height2 = wallet
        .sync(&daemon, None, &no_cancel)
        .await
        .expect("second sync failed");
    let all_balances_2 = wallet.get_all_balances(0).unwrap();

    assert!(
        height2 >= sync_height,
        "second sync should not go backwards"
    );
    for (asset, bal1) in &all_balances {
        if let Some(bal2) = all_balances_2.get(asset) {
            assert_eq!(
                bal1.balance, bal2.balance,
                "{} balance should be consistent between syncs ({} vs {})",
                asset, bal1.balance, bal2.balance
            );
        }
    }
    println!("  PASS: Sync is idempotent (all asset balances match)");

    // ── Summary ─────────────────────────────────────────────────────────
    println!("\n{}", "=".repeat(64));
    println!("  WALLET SYNC TEST PASSED");
    println!("  Height:     {}", sync_height);
    println!(
        "  Assets:     {}",
        all_balances.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    println!("  Time:       {}", fmt_duration(elapsed));
    println!("{}\n", "=".repeat(64));
}

// =============================================================================
// Test: C FFI Sync (validates the FFI layer works end-to-end)
// =============================================================================

#[test]
#[ignore]
fn ffi_wallet_sync_and_balance_check() {
    use std::ffi::{CStr, CString};

    println!("\n  FFI Wallet Sync Test\n");

    let seed_hex = match env_opt("SYNC_SEED") {
        Some(s) => s,
        None => {
            println!("  SKIP: SYNC_SEED not set (required for FFI test)");
            return;
        }
    };

    let network = parse_network(&env_or("SYNC_NETWORK", "mainnet"));
    let daemon_url = env_or("SYNC_DAEMON_URL", default_daemon_url(network));
    let assert_asset = env_or("SYNC_ASSET_TYPE", DEFAULT_ASSET_TYPE);
    let expected_balance: Option<u64> =
        env_opt("SYNC_EXPECTED_BALANCE").map(|s| s.parse().expect("invalid SYNC_EXPECTED_BALANCE"));

    let seed = hex_to_32(&seed_hex);
    let network_int: i32 = match network {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Stagenet => 2,
    };

    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("ffi_sync_test.db");
    let db_path_cstr = CString::new(db_path.to_str().unwrap()).unwrap();
    let db_key = [0u8; 32];

    // ── FFI: Init runtime ───────────────────────────────────────────────
    let rc = salvium_ffi::salvium_ffi_init();
    assert_eq!(rc, 0, "salvium_ffi_init failed");

    // ── FFI: Create wallet ──────────────────────────────────────────────
    let wallet_handle = unsafe {
        salvium_ffi::wallet::salvium_wallet_create(
            seed.as_ptr(),
            network_int,
            db_path_cstr.as_ptr(),
            db_key.as_ptr(),
            db_key.len(),
        )
    };
    assert!(
        !wallet_handle.is_null(),
        "salvium_wallet_create failed: {:?}",
        get_last_error()
    );

    // ── FFI: Check address ──────────────────────────────────────────────
    let addr_ptr = unsafe { salvium_ffi::wallet::salvium_wallet_get_address(wallet_handle, 0) };
    assert!(!addr_ptr.is_null(), "get_address failed");
    let addr = unsafe { CStr::from_ptr(addr_ptr) }
        .to_str()
        .unwrap()
        .to_string();
    println!(
        "  Wallet address: {}...{}",
        &addr[..20],
        &addr[addr.len() - 8..]
    );
    unsafe {
        salvium_ffi::strings::salvium_string_free(addr_ptr);
    }

    // ── FFI: Connect daemon ─────────────────────────────────────────────
    let daemon_url_cstr = CString::new(daemon_url.as_str()).unwrap();
    let daemon_handle =
        unsafe { salvium_ffi::daemon::salvium_daemon_connect(daemon_url_cstr.as_ptr()) };
    assert!(
        !daemon_handle.is_null(),
        "salvium_daemon_connect failed: {:?}",
        get_last_error()
    );

    // ── FFI: Get daemon height ──────────────────────────────────────────
    let height = unsafe { salvium_ffi::daemon::salvium_daemon_get_height(daemon_handle) };
    assert_ne!(height, u64::MAX, "daemon_get_height failed");
    println!("  Daemon height: {}", height);

    // ── FFI: Sync wallet ────────────────────────────────────────────────
    println!("  Syncing via FFI...");
    let start = Instant::now();

    // Use a callback to track progress.
    extern "C" fn sync_callback(
        event_type: i32,
        current_height: u64,
        target_height: u64,
        outputs_found: u32,
        _error_msg: *const std::ffi::c_char,
    ) {
        match event_type {
            0 => println!("  [FFI] Sync started — target: {}", target_height),
            1 => {
                let pct = if target_height > 0 {
                    (current_height * 100) / target_height
                } else {
                    0
                };
                if pct % 10 == 0 || outputs_found > 0 {
                    println!(
                        "  [FFI] [{:>3}%] {}/{} outputs_found={}",
                        pct, current_height, target_height, outputs_found
                    );
                }
            }
            2 => println!("  [FFI] Sync complete at height {}", current_height),
            3 => println!("  [FFI] Reorg: {} -> {}", current_height, target_height),
            4 => {
                let msg = if _error_msg.is_null() {
                    "unknown error"
                } else {
                    unsafe { CStr::from_ptr(_error_msg) }
                        .to_str()
                        .unwrap_or("?")
                };
                eprintln!("  [FFI] Error: {}", msg);
            }
            _ => {}
        }
    }

    let rc = unsafe {
        salvium_ffi::wallet::salvium_wallet_sync(wallet_handle, daemon_handle, Some(sync_callback))
    };
    let elapsed = start.elapsed().as_secs_f64();
    assert_eq!(rc, 0, "salvium_wallet_sync failed: {:?}", get_last_error());
    println!("  Sync completed in {}", fmt_duration(elapsed));

    // ── FFI: Check all balances ────────────────────────────────────────
    let all_bal_ptr =
        unsafe { salvium_ffi::wallet::salvium_wallet_get_all_balances(wallet_handle, 0) };
    assert!(
        !all_bal_ptr.is_null(),
        "get_all_balances failed: {:?}",
        get_last_error()
    );
    let all_bal_json = unsafe { CStr::from_ptr(all_bal_ptr) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe {
        salvium_ffi::strings::salvium_string_free(all_bal_ptr);
    }

    let all_bal: serde_json::Value = serde_json::from_str(&all_bal_json).unwrap();
    println!("\n  Balances (all asset types):");
    if let Some(obj) = all_bal.as_object() {
        for (asset, bal) in obj {
            let total: u64 = bal["balance"].as_str().unwrap_or("0").parse().unwrap_or(0);
            let unlocked: u64 = bal["unlocked_balance"]
                .as_str()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
            println!(
                "    {:>6}: total = {}  unlocked = {}",
                asset,
                fmt_sal(total),
                fmt_sal(unlocked)
            );
        }
    }

    // Optional: assert a specific asset's balance.
    if let Some(expected) = expected_balance {
        let asset_cstr = CString::new(assert_asset.as_str()).unwrap();
        let balance_ptr = unsafe {
            salvium_ffi::wallet::salvium_wallet_get_balance(wallet_handle, asset_cstr.as_ptr(), 0)
        };
        assert!(
            !balance_ptr.is_null(),
            "get_balance('{}') failed: {:?}",
            assert_asset,
            get_last_error()
        );
        let balance_json = unsafe { CStr::from_ptr(balance_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        unsafe {
            salvium_ffi::strings::salvium_string_free(balance_ptr);
        }

        let bal: serde_json::Value = serde_json::from_str(&balance_json).unwrap();
        let total: u64 = bal["balance"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            total, expected,
            "FFI balance mismatch for '{}': expected {} got {}",
            assert_asset, expected, total
        );
        println!("  PASS: FFI {} balance matches expected", assert_asset);
    }

    // ── FFI: Cleanup ────────────────────────────────────────────────────
    unsafe {
        salvium_ffi::wallet::salvium_wallet_close(wallet_handle);
        salvium_ffi::daemon::salvium_daemon_close(daemon_handle);
    }

    println!("\n  FFI Wallet Sync Test PASSED\n");
}

fn get_last_error() -> String {
    let ptr = salvium_ffi::error::salvium_last_error();
    if ptr.is_null() {
        "no error".to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()
            .unwrap_or("?")
            .to_string()
    }
}
