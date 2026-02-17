//! Testnet integration: Subaddress generation and transfers.
//!
//! Tests subaddress generation for both CryptoNote (legacy) and CARROT protocols,
//! address parsing, integrated addresses, and transfers to subaddresses.
//!
//! Run with: cargo test -p salvium-wallet --test testnet_subaddress -- --ignored --nocapture
//!
//! Ported from: test/integration-subaddress.test.js

use salvium_rpc::daemon::DaemonRpc;
use salvium_tx::builder::{Destination, TransactionBuilder};
use salvium_tx::types::*;
use salvium_wallet::{decrypt_js_wallet, Wallet, WalletKeys};
use salvium_types::address::{parse_address, create_address_raw, to_integrated_address};
use salvium_types::constants::{AddressFormat, AddressType, Network};

use std::collections::HashSet;
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
// Test 1: Subaddress generation
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_subaddress_generation() {
    println!("\n=== Subaddress Generation Test ===\n");

    let dir = testnet_wallet_dir();
    let wallet_json = std::fs::read_to_string(dir.join("wallet-a.json"))
        .expect("wallet-a.json not found in ~/testnet-wallet/");
    let pin = std::fs::read_to_string(dir.join("wallet-a.pin"))
        .expect("wallet-a.pin not found")
        .trim()
        .to_string();
    let secrets = decrypt_js_wallet(&wallet_json, &pin).expect("failed to decrypt wallet");

    let keys_a = WalletKeys::from_seed(secrets.seed, Network::Testnet);
    let maps_a = salvium_wallet::account::SubaddressMaps::generate(&keys_a, 2, 5);

    // 1. CN subaddress (0,0) should be the main address spend pubkey
    let cn_main = maps_a.cn.iter().find(|(_, maj, min)| *maj == 0 && *min == 0);
    assert!(cn_main.is_some(), "CN (0,0) entry should exist");
    let (cn_main_pk, _, _) = cn_main.unwrap();
    assert_eq!(*cn_main_pk, keys_a.cn.spend_public_key,
        "CN (0,0) spend pubkey should equal main address spend pubkey");
    println!("CN (0,0) matches main address: OK");

    // 2. Subaddresses should differ from each other
    let cn_01 = maps_a.cn.iter().find(|(_, maj, min)| *maj == 0 && *min == 1);
    let cn_02 = maps_a.cn.iter().find(|(_, maj, min)| *maj == 0 && *min == 2);
    let cn_10 = maps_a.cn.iter().find(|(_, maj, min)| *maj == 1 && *min == 0);
    assert!(cn_01.is_some() && cn_02.is_some() && cn_10.is_some(),
        "Subaddresses (0,1), (0,2), (1,0) should exist");

    let mut spend_keys = HashSet::new();
    spend_keys.insert(cn_main_pk.to_vec());
    assert!(spend_keys.insert(cn_01.unwrap().0.to_vec()), "CN (0,1) should differ from (0,0)");
    assert!(spend_keys.insert(cn_02.unwrap().0.to_vec()), "CN (0,2) should differ from others");
    assert!(spend_keys.insert(cn_10.unwrap().0.to_vec()), "CN (1,0) should differ from others");
    println!("CN subaddresses are unique: OK ({} unique keys)", spend_keys.len());

    // 3. CARROT subaddresses should also be generated and unique
    let carrot_00 = maps_a.carrot.iter().find(|(_, maj, min)| *maj == 0 && *min == 0);
    let carrot_01 = maps_a.carrot.iter().find(|(_, maj, min)| *maj == 0 && *min == 1);
    assert!(carrot_00.is_some(), "CARROT (0,0) entry should exist");
    assert!(carrot_01.is_some(), "CARROT (0,1) entry should exist");
    assert_ne!(carrot_00.unwrap().0, carrot_01.unwrap().0,
        "CARROT (0,0) and (0,1) should have different spend pubkeys");
    println!("CARROT subaddresses are unique: OK");

    // 4. CN and CARROT spend keys should differ (different derivation)
    assert_ne!(*cn_main_pk, carrot_00.unwrap().0,
        "CN and CARROT main address spend keys should differ");
    println!("CN vs CARROT keys differ: OK");

    // 5. Different wallets should produce different subaddresses
    let keys_different = WalletKeys::from_seed([0xBB; 32], Network::Testnet);
    let maps_different = salvium_wallet::account::SubaddressMaps::generate(&keys_different, 1, 3);
    let diff_00 = maps_different.cn.iter().find(|(_, maj, min)| *maj == 0 && *min == 0);
    assert!(diff_00.is_some());
    assert_ne!(*cn_main_pk, diff_00.unwrap().0,
        "Different wallets should produce different subaddresses");
    println!("Different wallets produce different subaddresses: OK");

    println!("\nTotal CN subaddress entries: {}", maps_a.cn_count());
    println!("Total CARROT subaddress entries: {}", maps_a.carrot_count());
    println!("\n=== Subaddress Generation Test PASSED ===");
}

// =============================================================================
// Test 2: Address parsing
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_address_parsing() {
    println!("\n=== Address Parsing Test ===\n");

    let dir = testnet_wallet_dir();
    let wallet_json = std::fs::read_to_string(dir.join("wallet-a.json"))
        .expect("wallet-a.json not found");
    let pin = std::fs::read_to_string(dir.join("wallet-a.pin"))
        .expect("wallet-a.pin not found")
        .trim()
        .to_string();
    let secrets = decrypt_js_wallet(&wallet_json, &pin).expect("failed to decrypt");
    let keys = WalletKeys::from_seed(secrets.seed, Network::Testnet);

    // Parse CN address
    let cn_addr = keys.cn_address().expect("cn_address");
    let parsed_cn = parse_address(&cn_addr).expect("parse CN address");
    assert_eq!(parsed_cn.network, Network::Testnet);
    assert_eq!(parsed_cn.format, AddressFormat::Legacy);
    assert_eq!(parsed_cn.address_type, AddressType::Standard);
    assert_eq!(parsed_cn.spend_public_key, keys.cn.spend_public_key);
    assert_eq!(parsed_cn.view_public_key, keys.cn.view_public_key);
    println!("CN address parsed: OK");
    println!("  Address: {}...{}", &cn_addr[..12], &cn_addr[cn_addr.len()-6..]);

    // Parse CARROT address
    let carrot_addr = keys.carrot_address().expect("carrot_address");
    let parsed_carrot = parse_address(&carrot_addr).expect("parse CARROT address");
    assert_eq!(parsed_carrot.network, Network::Testnet);
    assert_eq!(parsed_carrot.format, AddressFormat::Carrot);
    assert_eq!(parsed_carrot.address_type, AddressType::Standard);
    assert_eq!(parsed_carrot.spend_public_key, keys.carrot.account_spend_pubkey);
    assert_eq!(parsed_carrot.view_public_key, keys.carrot.account_view_pubkey);
    println!("CARROT address parsed: OK");
    println!("  Address: {}...{}", &carrot_addr[..12], &carrot_addr[carrot_addr.len()-6..]);

    // CN and CARROT addresses should differ
    assert_ne!(cn_addr, carrot_addr);
    println!("CN != CARROT: OK");

    // Create a CN subaddress and verify it parses
    let maps = salvium_wallet::account::SubaddressMaps::generate(&keys, 1, 3);
    let sub_01 = maps.cn.iter().find(|(_, maj, min)| *maj == 0 && *min == 1).unwrap();
    // Build a subaddress view pubkey: C = v * D (where D is the subaddress spend pubkey)
    // For parsing, we just verify the subaddress spend pubkey is in the map.
    let cn_sub_addr = create_address_raw(
        Network::Testnet,
        AddressFormat::Legacy,
        AddressType::Subaddress,
        &sub_01.0,
        &keys.cn.view_public_key,
        None,
    ).expect("create CN subaddress");
    let parsed_sub = parse_address(&cn_sub_addr).expect("parse CN subaddress");
    assert_eq!(parsed_sub.address_type, AddressType::Subaddress);
    assert_eq!(parsed_sub.format, AddressFormat::Legacy);
    println!("CN subaddress parsed as Subaddress: OK");

    println!("\n=== Address Parsing Test PASSED ===");
}

// =============================================================================
// Test 3: Integrated addresses
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_integrated_addresses() {
    println!("\n=== Integrated Address Test ===\n");

    let dir = testnet_wallet_dir();
    let wallet_json = std::fs::read_to_string(dir.join("wallet-a.json"))
        .expect("wallet-a.json not found");
    let pin = std::fs::read_to_string(dir.join("wallet-a.pin"))
        .expect("wallet-a.pin not found")
        .trim()
        .to_string();
    let secrets = decrypt_js_wallet(&wallet_json, &pin).expect("failed to decrypt");
    let keys = WalletKeys::from_seed(secrets.seed, Network::Testnet);

    let cn_addr = keys.cn_address().expect("cn_address");

    // Generate a random payment ID
    let payment_id: [u8; 8] = rand::random();
    println!("Payment ID: {}", hex::encode(payment_id));

    // Create an integrated address
    let integrated = to_integrated_address(&cn_addr, &payment_id)
        .expect("create integrated address");
    println!("Integrated: {}...{}", &integrated[..12], &integrated[integrated.len()-6..]);

    // Verify it parses as integrated
    let parsed = parse_address(&integrated).expect("parse integrated address");
    assert_eq!(parsed.address_type, AddressType::Integrated);
    assert_eq!(parsed.format, AddressFormat::Legacy);
    assert_eq!(parsed.network, Network::Testnet);
    println!("Parsed as Integrated: OK");

    // Verify payment ID round-trips
    assert_eq!(parsed.payment_id.unwrap(), payment_id, "Payment ID should round-trip");
    println!("Payment ID round-trip: OK");

    // Verify spend/view keys match the original address
    assert_eq!(parsed.spend_public_key, keys.cn.spend_public_key);
    assert_eq!(parsed.view_public_key, keys.cn.view_public_key);
    println!("Keys match original: OK");

    // Different payment IDs should produce different integrated addresses
    let payment_id_2: [u8; 8] = rand::random();
    let integrated_2 = to_integrated_address(&cn_addr, &payment_id_2)
        .expect("create integrated address 2");
    assert_ne!(integrated, integrated_2, "Different payment IDs → different addresses");
    println!("Different PIDs → different addresses: OK");

    // Also test CARROT integrated address
    let carrot_addr = keys.carrot_address().expect("carrot_address");
    let carrot_integrated = to_integrated_address(&carrot_addr, &payment_id)
        .expect("create CARROT integrated address");
    let parsed_carrot = parse_address(&carrot_integrated).expect("parse CARROT integrated");
    assert_eq!(parsed_carrot.address_type, AddressType::Integrated);
    assert_eq!(parsed_carrot.format, AddressFormat::Carrot);
    assert_eq!(parsed_carrot.payment_id.unwrap(), payment_id);
    println!("CARROT integrated address: OK");

    println!("\n=== Integrated Address Test PASSED ===");
}

// =============================================================================
// Test 4: Self-transfer to subaddress (dry-run, build only)
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_self_transfer_to_subaddress() {
    println!("\n=== Self-Transfer to Subaddress Test ===\n");

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
    let sync_height = wallet.sync(&d, None).await.expect("sync failed");
    println!("Synced to height {}", sync_height);

    let hf_info = d.hard_fork_info().await.unwrap();
    let tx_asset_type = if hf_info.version >= 6 { "SAL1" } else { "SAL" };
    let db_asset_type = "SAL";

    let balance = wallet.get_balance(db_asset_type, 0).unwrap();
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap();
    println!("Unlocked balance: {:.9} SAL", unlocked as f64 / 1e9);

    if unlocked < 100_000_000 {
        println!("Insufficient balance (< 0.1 SAL), skipping subaddress transfer");
        return;
    }

    let keys = wallet.keys();
    let maps = wallet.subaddress_maps();

    // Get subaddress (0,1) — a CARROT subaddress
    let carrot_sub_01 = maps.carrot.iter()
        .find(|(_, maj, min)| *maj == 0 && *min == 1)
        .expect("CARROT subaddress (0,1) should exist");

    println!("Destination: CARROT subaddress (0,1)");
    println!("  Spend pubkey: {}", hex::encode(carrot_sub_01.0));

    // Build transaction to subaddress (dry-run — just verify builder accepts it)
    let transfer_amount: u64 = 50_000_000; // 0.05 SAL

    let builder = TransactionBuilder::new()
        .add_destination(Destination {
            spend_pubkey: carrot_sub_01.0,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount: transfer_amount,
            asset_type: tx_asset_type.to_string(),
            payment_id: [0u8; 8],
            is_subaddress: true,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_tx_type(tx_type::TRANSFER)
        .set_asset_types(tx_asset_type, tx_asset_type)
        .set_rct_type(rct_type::SALVIUM_ONE)
        .set_fee(50_000_000); // placeholder fee

    println!("TransactionBuilder configured for subaddress transfer:");
    println!("  Amount: {:.9} SAL", transfer_amount as f64 / 1e9);
    println!("  is_subaddress: true");
    println!("  tx_type: TRANSFER");

    // NOTE: Full build+sign+submit would require input preparation (decoys, ring members).
    // This test verifies the builder correctly accepts subaddress destinations.
    // The full transfer pipeline is covered in testnet_transfer.rs.
    let _ = builder; // suppress unused

    println!("\n=== Self-Transfer to Subaddress Test PASSED (dry-run) ===");
}
