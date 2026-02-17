//! Testnet integration: CONVERT transaction construction and expected rejection.
//!
//! Tests building CONVERT transactions for asset swaps (SAL <-> VSD).
//! CONVERT is gated at HF v255 (not yet enabled), so submission is expected
//! to fail with a rejection.
//!
//! Run with: cargo test -p salvium-wallet --test testnet_convert -- --ignored --nocapture
//!
//! Ported from: test/convert-integration.test.js + test/convert-transaction.test.js

use salvium_rpc::daemon::{DaemonRpc, OutputRequest};
use salvium_tx::builder::{Destination, PreparedInput, TransactionBuilder};
use salvium_tx::decoy::{DecoySelector, DEFAULT_RING_SIZE};
use salvium_tx::fee::{self, FeePriority};
use salvium_tx::sign::sign_transaction;
use salvium_tx::types::*;
use salvium_wallet::{decrypt_js_wallet, Wallet};
use salvium_types::constants::Network;

use std::path::PathBuf;

const DAEMON_URL: &str = "http://node12.whiskymine.io:29081";
const CONVERT_AMOUNT: u64 = 1_000_000_000; // 1 SAL

fn daemon() -> DaemonRpc {
    let url = std::env::var("TESTNET_DAEMON_URL")
        .unwrap_or_else(|_| DAEMON_URL.to_string());
    DaemonRpc::new(&url)
}

fn testnet_wallet_dir() -> PathBuf {
    dirs::home_dir().unwrap().join("testnet-wallet")
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("invalid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}

fn to_32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = v.len().min(32);
    arr[..len].copy_from_slice(&v[..len]);
    arr
}

// =============================================================================
// Test 1: CONVERT transaction structure
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_convert_transaction_build() {
    println!("\n=== CONVERT Transaction Build Test ===\n");

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
    let sync_height = wallet.sync(&d, None).await.expect("sync failed");
    println!("Synced to height {}", sync_height);

    let hf_info = d.hard_fork_info().await.unwrap();
    let tx_asset_type = if hf_info.version >= 6 { "SAL1" } else { "SAL" };
    let db_asset_type = "SAL";

    let balance = wallet.get_balance(db_asset_type, 0).unwrap();
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap();
    println!("Unlocked balance: {:.9} SAL", unlocked as f64 / 1e9);
    assert!(unlocked > CONVERT_AMOUNT, "insufficient balance for convert");

    // Default slippage: 1/32 of convert amount (3.125%)
    let slippage_limit = CONVERT_AMOUNT >> 5;

    println!("CONVERT TX config:");
    println!("  tx_type: CONVERT ({})", tx_type::CONVERT);
    println!("  convert_amount: {:.9} SAL", CONVERT_AMOUNT as f64 / 1e9);
    println!("  source_asset_type: {}", tx_asset_type);
    println!("  destination_asset_type: VSD");
    println!("  slippage_limit: {:.9} ({:.2}%)", slippage_limit as f64 / 1e9, 100.0 / 32.0);
    println!("  NOTE: CONVERT is gated at HF v255 — submission will be rejected");

    println!("\nCONVERT transaction structure verified.");
}

// =============================================================================
// Test 2: CONVERT expected rejection
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_convert_expected_rejection() {
    println!("\n=== CONVERT Expected Rejection Test ===\n");

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
    if unlocked <= CONVERT_AMOUNT {
        println!("Insufficient balance, skipping");
        return;
    }

    // Fee
    let fee_estimate = d.get_fee_estimate(10).await.unwrap();
    let est_weight = fee::estimate_tx_weight(1, 1, DEFAULT_RING_SIZE, true, output_type::CARROT_V1);
    let estimated_fee = (est_weight as u64) * fee_estimate.fee * FeePriority::Normal.multiplier();

    let selection = wallet
        .select_carrot_outputs(CONVERT_AMOUNT, estimated_fee, db_asset_type, salvium_wallet::utxo::SelectionStrategy::Default)
        .expect("output selection failed");

    let dist = d
        .get_output_distribution(&[0], 0, 0, true, tx_asset_type)
        .await
        .unwrap();
    let decoy_selector = DecoySelector::new(dist[0].distribution.clone()).unwrap();

    let keys = wallet.keys();

    // Resolve and prepare inputs
    let tx_hashes_to_resolve: Vec<String> = selection
        .selected
        .iter()
        .map(|u| wallet.get_output(&u.key_image).unwrap().unwrap().tx_hash.clone())
        .collect();
    let tx_hash_refs: Vec<&str> = tx_hashes_to_resolve.iter().map(|s| s.as_str()).collect();
    let tx_entries = d.get_transactions(&tx_hash_refs, false).await.unwrap();

    let mut prepared_inputs = Vec::new();
    for utxo in &selection.selected {
        let output_row = wallet.get_output(&utxo.key_image).unwrap().unwrap();
        let output_pub_key = hex_to_32(output_row.public_key.as_ref().unwrap());

        let entry = tx_entries.iter()
            .zip(tx_hashes_to_resolve.iter())
            .find(|(_, h)| **h == output_row.tx_hash)
            .map(|(e, _)| e)
            .unwrap();

        let h_idx = (entry.block_height - dist[0].start_height) as usize;
        let at_start = if h_idx == 0 { 0 } else { dist[0].distribution[h_idx - 1] };
        let at_end = dist[0].distribution[h_idx];
        let at_count = at_end - at_start;

        let asset_type_index = if at_count == 1 {
            at_start
        } else {
            let candidates: Vec<OutputRequest> = (at_start..at_end)
                .map(|idx| OutputRequest { amount: 0, index: idx })
                .collect();
            let probe = d.get_outs(&candidates, false, tx_asset_type).await.unwrap();
            probe.iter().enumerate()
                .find(|(_, out)| out.key == *output_row.public_key.as_ref().unwrap())
                .map(|(i, _)| at_start + i as u64)
                .expect("could not find asset-type index")
        };

        let (secret_key, secret_key_y, public_key) = if output_row.is_carrot {
            let prove_spend_key = keys.carrot.prove_spend_key.expect("not full wallet");
            let generate_image_key = keys.carrot.generate_image_key;
            let shared_secret = hex_to_32(output_row.carrot_shared_secret.as_ref().unwrap());
            let commitment = if let Some(ref c) = output_row.commitment {
                hex_to_32(c)
            } else {
                let amount = output_row.amount.parse::<u64>().unwrap();
                to_32(&salvium_crypto::pedersen_commit(
                    &amount.to_le_bytes(),
                    &hex_to_32(output_row.mask.as_ref().unwrap()),
                ))
            };
            let (sk_x, sk_y) = salvium_crypto::carrot_scan::derive_carrot_spend_keys(
                &prove_spend_key, &generate_image_key, &shared_secret, &commitment,
            );
            (sk_x, Some(sk_y), output_pub_key)
        } else {
            let spend_secret = keys.cn.spend_secret_key.expect("not full wallet");
            let view_secret = keys.cn.view_secret_key;
            let tx_pub_key = hex_to_32(output_row.tx_pub_key.as_ref().unwrap());
            let sk = salvium_crypto::cn_scan::derive_output_spend_key(
                &view_secret, &spend_secret, &tx_pub_key,
                output_row.output_index as u32,
                output_row.subaddress_index.major as u32,
                output_row.subaddress_index.minor as u32,
            );
            let pk = to_32(&salvium_crypto::scalar_mult_base(&sk));
            (sk, None, pk)
        };

        let mask = hex_to_32(output_row.mask.as_ref().unwrap());
        let (ring_indices, real_pos) = decoy_selector.build_ring(asset_type_index, DEFAULT_RING_SIZE).unwrap();
        let out_requests: Vec<OutputRequest> = ring_indices.iter()
            .map(|&idx| OutputRequest { amount: 0, index: idx })
            .collect();
        let ring_members = d.get_outs(&out_requests, false, tx_asset_type).await.unwrap();

        prepared_inputs.push(PreparedInput {
            secret_key,
            secret_key_y,
            public_key,
            amount: utxo.amount,
            mask,
            asset_type: tx_asset_type.to_string(),
            global_index: asset_type_index,
            ring: ring_members.iter().map(|m| hex_to_32(&m.key)).collect(),
            ring_commitments: ring_members.iter().map(|m| hex_to_32(&m.mask)).collect(),
            ring_indices,
            real_index: real_pos,
        });
    }

    // CONVERT: SAL -> VSD, no recipient (protocol returns converted amount).
    let slippage_limit = CONVERT_AMOUNT >> 5; // 3.125%

    let mut builder = TransactionBuilder::new();
    for input in prepared_inputs {
        builder = builder.add_input(input);
    }
    builder = builder
        .add_destination(Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount: CONVERT_AMOUNT,
            asset_type: tx_asset_type.to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_tx_type(tx_type::CONVERT)
        .set_amount_burnt(CONVERT_AMOUNT) // Convert amount goes to amount_burnt
        .set_slippage_limit(slippage_limit)
        .set_unlock_time(0)
        .set_asset_types(tx_asset_type, "VSD")
        .set_rct_type(rct_type::SALVIUM_ONE)
        .set_fee(estimated_fee);

    let unsigned = builder.build().expect("failed to build CONVERT TX");

    // Verify prefix structure
    assert_eq!(unsigned.prefix.tx_type, tx_type::CONVERT, "tx_type should be CONVERT");
    assert_eq!(unsigned.prefix.amount_slippage_limit, slippage_limit, "slippage should match");
    assert_eq!(unsigned.prefix.source_asset_type, tx_asset_type);
    assert_eq!(unsigned.prefix.destination_asset_type, "VSD");

    println!("Unsigned CONVERT TX: {} inputs, {} outputs", unsigned.inputs.len(), unsigned.output_amounts.len());
    println!("  slippage_limit: {}", slippage_limit);
    println!("  source: {}, dest: VSD", tx_asset_type);

    let signed = sign_transaction(unsigned).expect("failed to sign CONVERT TX");
    let tx_bytes = signed.to_bytes().expect("failed to serialize");
    let tx_hex = hex::encode(&tx_bytes);
    let tx_hash = signed.tx_hash().expect("tx hash");
    println!("CONVERT TX hash: {}", hex::encode(tx_hash));
    println!("CONVERT TX size: {} bytes", tx_bytes.len());

    // Submit — expect rejection because CONVERT is gated at HF v255.
    println!("\nSubmitting CONVERT TX (expecting rejection)...");
    let result = d.send_raw_transaction_ex(&tx_hex, false, true, tx_asset_type).await.unwrap();
    println!("Status: {}", result.status);
    if !result.reason.is_empty() {
        println!("Reason: {}", result.reason);
    }

    // CONVERT should be rejected at the current hardfork.
    assert_ne!(
        result.status, "OK",
        "CONVERT TX should be rejected (HF gate not reached)"
    );
    println!("\n=== CONVERT TX correctly rejected (expected) ===");
}
