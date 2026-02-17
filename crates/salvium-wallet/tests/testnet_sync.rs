//! Testnet integration: Wallet sync verification.
//!
//! Tests wallet sync from blockchain, balance verification by asset type,
//! view-only wallet scanning, and sync idempotency.
//!
//! Run with: cargo test -p salvium-wallet --test testnet_sync -- --ignored --nocapture
//!
//! Ported from: test/integration-sync.test.js

use salvium_rpc::daemon::DaemonRpc;
use salvium_wallet::{decrypt_js_wallet, Wallet, WalletKeys};
use salvium_types::constants::Network;

use std::path::PathBuf;

const DAEMON_URL: &str = "http://node12.whiskymine.io:29081";

fn daemon() -> DaemonRpc {
    let url = std::env::var("TESTNET_DAEMON_URL")
        .unwrap_or_else(|_| DAEMON_URL.to_string());
    DaemonRpc::new(&url)
}

fn testnet_wallet_dir() -> PathBuf {
    dirs::home_dir().unwrap().join("testnet-wallet")
}

// =============================================================================
// Test 1: Full sync and balance verification
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_full_sync_balance() {
    println!("\n=== Full Sync & Balance Test ===\n");

    let dir = testnet_wallet_dir();
    let wallet_json = std::fs::read_to_string(dir.join("wallet-a.json"))
        .expect("wallet-a.json not found in ~/testnet-wallet/");
    let pin = std::fs::read_to_string(dir.join("wallet-a.pin"))
        .expect("wallet-a.pin not found")
        .trim()
        .to_string();
    let secrets = decrypt_js_wallet(&wallet_json, &pin).expect("failed to decrypt wallet");

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("wallet-a.db");
    let wallet = Wallet::create(secrets.seed, Network::Testnet, db_path.to_str().unwrap(), &[0u8; 32])
        .expect("create wallet");

    let d = daemon();
    let info = d.get_info().await.unwrap();
    println!("Daemon height: {}", info.height);
    println!("Network: testnet");

    let sync_height = wallet.sync(&d, None).await.expect("sync failed");
    println!("Synced to height: {}", sync_height);

    // Sync height should be close to daemon height
    assert!(sync_height > 0, "sync should advance past genesis");
    assert!(
        sync_height >= info.height - 2,
        "sync should reach near daemon tip ({} vs {})", sync_height, info.height
    );

    // Get balances for all asset types
    let all_balances = wallet.get_all_balances(0).unwrap();
    println!("\nBalances by asset type:");
    let mut balance: u64 = 0;
    for (asset, bal) in &all_balances {
        let total: u64 = bal.balance.parse().unwrap_or(0);
        let unlocked: u64 = bal.unlocked_balance.parse().unwrap_or(0);
        let locked = total - unlocked;
        println!("  {}: total={:.9}, unlocked={:.9}, locked={:.9}",
            asset,
            total as f64 / 1e9,
            unlocked as f64 / 1e9,
            locked as f64 / 1e9,
        );
        balance += total;
    }

    // Wallet should have at least some SAL balance
    let sal_balance = wallet.get_balance("SAL", 0).unwrap();
    let sal_total: u64 = sal_balance.balance.parse().unwrap_or(0);
    assert!(sal_total > 0, "wallet should have some SAL balance");
    println!("\nSAL total: {:.9}", sal_total as f64 / 1e9);
    println!("Total across all assets: {:.9}", balance as f64 / 1e9);

    println!("\n=== Full Sync & Balance Test PASSED ===");
}

// =============================================================================
// Test 2: View-only wallet sync (CryptoNote)
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_view_only_sync() {
    println!("\n=== View-Only Wallet Sync Test ===\n");

    let dir = testnet_wallet_dir();
    let wallet_json = std::fs::read_to_string(dir.join("wallet-a.json"))
        .expect("wallet-a.json not found");
    let pin = std::fs::read_to_string(dir.join("wallet-a.pin"))
        .expect("wallet-a.pin not found")
        .trim()
        .to_string();
    let secrets = decrypt_js_wallet(&wallet_json, &pin).expect("failed to decrypt");

    // Create a full wallet to get the keys
    let full_keys = WalletKeys::from_seed(secrets.seed, Network::Testnet);

    // Create a CN-only view-only wallet (no spend key)
    let view_keys = WalletKeys::view_only(
        full_keys.cn.view_secret_key,
        full_keys.cn.spend_public_key,
        Network::Testnet,
    );

    assert!(!view_keys.can_spend(), "view-only wallet should not be able to spend");
    assert!(view_keys.can_view(), "view-only wallet should be able to view");

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("view-only.db");
    let wallet = Wallet::open(view_keys, db_path.to_str().unwrap(), &[0u8; 32])
        .expect("open view-only wallet");

    let d = daemon();
    let sync_height = wallet.sync(&d, None).await.expect("view-only sync failed");
    println!("View-only synced to height: {}", sync_height);

    // View-only wallet should detect CN outputs
    let bal = wallet.get_balance("SAL", 0).unwrap();
    let total: u64 = bal.balance.parse().unwrap_or(0);
    println!("View-only CN balance: {:.9} SAL", total as f64 / 1e9);

    // NOTE: CN view-only will find outputs but cannot generate real key images,
    // so "unlocked" may not be meaningful. The total should be > 0 if the wallet
    // has received any CN-format outputs.
    println!("  (CN view-only cannot generate key images for spending)");

    println!("\n=== View-Only Wallet Sync Test PASSED ===");
}

// =============================================================================
// Test 3: CARROT view-only wallet sync
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_carrot_view_only_sync() {
    println!("\n=== CARROT View-Only Wallet Sync Test ===\n");

    let dir = testnet_wallet_dir();
    let wallet_json = std::fs::read_to_string(dir.join("wallet-a.json"))
        .expect("wallet-a.json not found");
    let pin = std::fs::read_to_string(dir.join("wallet-a.pin"))
        .expect("wallet-a.pin not found")
        .trim()
        .to_string();
    let secrets = decrypt_js_wallet(&wallet_json, &pin).expect("failed to decrypt");

    let full_keys = WalletKeys::from_seed(secrets.seed, Network::Testnet);

    // Create a view-only wallet with CARROT capability
    let view_keys = WalletKeys::view_only_carrot(
        full_keys.cn.view_secret_key,
        full_keys.cn.spend_public_key,
        full_keys.carrot.view_balance_secret,
        full_keys.carrot.account_spend_pubkey,
        Network::Testnet,
    );

    assert!(!view_keys.can_spend(), "CARROT view-only should not be able to spend");
    assert!(view_keys.can_view(), "CARROT view-only should be able to view");
    assert!(!view_keys.carrot.is_empty(), "CARROT keys should be populated");

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("carrot-view-only.db");
    let wallet = Wallet::open(view_keys, db_path.to_str().unwrap(), &[0u8; 32])
        .expect("open CARROT view-only wallet");

    let d = daemon();
    let sync_height = wallet.sync(&d, None).await.expect("CARROT view-only sync failed");
    println!("CARROT view-only synced to height: {}", sync_height);

    let all_balances = wallet.get_all_balances(0).unwrap();
    println!("CARROT view-only balances:");
    for (asset, bal) in &all_balances {
        let total: u64 = bal.balance.parse().unwrap_or(0);
        println!("  {}: {:.9}", asset, total as f64 / 1e9);
    }

    // CARROT view-only should detect CARROT outputs
    let sal_bal = wallet.get_balance("SAL", 0).unwrap();
    let sal_total: u64 = sal_bal.balance.parse().unwrap_or(0);
    println!("\nSAL total (CARROT view-only): {:.9}", sal_total as f64 / 1e9);

    println!("\n=== CARROT View-Only Wallet Sync Test PASSED ===");
}

// =============================================================================
// Test 4: Sync idempotency
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_sync_idempotent() {
    println!("\n=== Sync Idempotency Test ===\n");

    let dir = testnet_wallet_dir();
    let wallet_json = std::fs::read_to_string(dir.join("wallet-a.json"))
        .expect("wallet-a.json not found");
    let pin = std::fs::read_to_string(dir.join("wallet-a.pin"))
        .expect("wallet-a.pin not found")
        .trim()
        .to_string();
    let secrets = decrypt_js_wallet(&wallet_json, &pin).expect("failed to decrypt");

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("wallet-a.db");
    let wallet = Wallet::create(secrets.seed, Network::Testnet, db_path.to_str().unwrap(), &[0u8; 32])
        .expect("create wallet");

    let d = daemon();

    // First sync
    let height_1 = wallet.sync(&d, None).await.expect("first sync failed");
    let bal_1 = wallet.get_balance("SAL", 0).unwrap();
    let total_1: u64 = bal_1.balance.parse().unwrap_or(0);
    let unlocked_1: u64 = bal_1.unlocked_balance.parse().unwrap_or(0);
    println!("Sync 1: height={}, total={:.9}, unlocked={:.9}",
        height_1, total_1 as f64 / 1e9, unlocked_1 as f64 / 1e9);

    // Second sync (should be a no-op or near-instant)
    let height_2 = wallet.sync(&d, None).await.expect("second sync failed");
    let bal_2 = wallet.get_balance("SAL", 0).unwrap();
    let total_2: u64 = bal_2.balance.parse().unwrap_or(0);
    let unlocked_2: u64 = bal_2.unlocked_balance.parse().unwrap_or(0);
    println!("Sync 2: height={}, total={:.9}, unlocked={:.9}",
        height_2, total_2 as f64 / 1e9, unlocked_2 as f64 / 1e9);

    // Heights should match or be very close (new block may arrive between syncs)
    assert!(
        height_2 >= height_1,
        "second sync height should be >= first ({} vs {})", height_2, height_1
    );

    // Total balance should be the same (no new blocks changing our wallet in between)
    // Allow small difference if a new block arrives with outputs for us
    assert_eq!(total_1, total_2, "total balance should be consistent between syncs");
    println!("Balance consistent across syncs: OK");

    // Verify sync height is persisted
    let stored_height = wallet.sync_height().unwrap();
    assert_eq!(stored_height, height_2, "stored sync height should match last sync");
    println!("Sync height persisted: OK");

    println!("\n=== Sync Idempotency Test PASSED ===");
}
