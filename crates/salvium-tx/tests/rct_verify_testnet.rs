//! Testnet integration: RCT signature verification against real on-chain data.
//!
//! Fetches real transactions from the Salvium testnet daemon, parses them,
//! retrieves ring member data via `get_outs`, and verifies TCLSAG/CLSAG
//! signatures. Also tests tamper detection.
//!
//! Run with: cargo test -p salvium-tx --test rct_verify_testnet -- --ignored --nocapture
//!
//! Ported from: test/rct-verify-testnet.test.js

mod common;

use common::{fetch_and_parse_tx, fetch_mix_ring, prepare_verification_data};
use salvium_rpc::daemon::DaemonRpc;
use salvium_tx::builder::relative_to_absolute;
use salvium_tx::types::*;

const DAEMON_URL: &str = "http://node12.whiskymine.io:29081";

fn daemon() -> DaemonRpc {
    let url = std::env::var("TESTNET_DAEMON_URL").unwrap_or_else(|_| DAEMON_URL.to_string());
    DaemonRpc::new(&url)
}

/// Scan recent blocks to find user (non-coinbase) transaction hashes.
async fn find_user_tx_hashes(d: &DaemonRpc, max_txs: usize) -> Vec<String> {
    let info = d.get_info().await.expect("daemon unreachable");
    let chain_height = info.height;
    let scan_start = chain_height.saturating_sub(200);

    let mut tx_hashes = Vec::new();
    for h in scan_start..chain_height {
        if tx_hashes.len() >= max_txs {
            break;
        }
        match d.get_block(h).await {
            Ok(block) => {
                for hash in &block.tx_hashes {
                    if tx_hashes.len() < max_txs {
                        tx_hashes.push(hash.clone());
                    }
                }
            }
            Err(_) => continue,
        }
    }
    tx_hashes
}

// =============================================================================
// Test 1: Daemon connectivity and TX discovery
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_daemon_reachable() {
    let d = daemon();
    let info = d.get_info().await.expect("daemon unreachable");
    assert!(info.height > 0, "chain height should be > 0");
    println!("Daemon: {} (height {})", DAEMON_URL, info.height);
}

#[tokio::test]
#[ignore]
async fn test_daemon_has_user_transactions() {
    let d = daemon();
    let tx_hashes = find_user_tx_hashes(&d, 5).await;
    println!(
        "Found {} user TX(s): {}",
        tx_hashes.len(),
        tx_hashes.iter().take(3).map(|h| format!("{}...", &h[..12])).collect::<Vec<_>>().join(", ")
    );
    // Informational — if 0 TXs, the verification tests will skip.
}

// =============================================================================
// Test 2: Parse real transaction
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_parse_real_transaction() {
    let d = daemon();
    let tx_hashes = find_user_tx_hashes(&d, 1).await;
    if tx_hashes.is_empty() {
        println!("  (skipped: no user transactions found)");
        return;
    }

    let (tx, _raw) = fetch_and_parse_tx(&d, &tx_hashes[0]).await;

    assert!(!tx.prefix.inputs.is_empty(), "TX should have inputs");
    let rct = tx.rct.as_ref().expect("TX should have RCT data");
    assert!(
        rct.rct_type >= rct_type::CLSAG,
        "RCT type should be CLSAG or higher, got {}",
        rct.rct_type
    );

    let rct_name =
        if rct.rct_type == rct_type::SALVIUM_ONE { "TCLSAG/SalviumOne" } else { "CLSAG" };

    println!("TX {}...", &tx_hashes[0][..16]);
    println!("  RCT type: {} ({})", rct.rct_type, rct_name);
    println!("  Inputs: {}", tx.prefix.inputs.len());
    println!("  Outputs: {}", tx.prefix.outputs.len());
    if let TxInput::Key { key_offsets, .. } = &tx.prefix.inputs[0] {
        println!("  Ring size: {}", key_offsets.len());
    }
}

// =============================================================================
// Test 3: Fetch ring members
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_fetch_ring_members() {
    let d = daemon();
    let tx_hashes = find_user_tx_hashes(&d, 1).await;
    if tx_hashes.is_empty() {
        println!("  (skipped: no user transactions found)");
        return;
    }

    let (tx, _) = fetch_and_parse_tx(&d, &tx_hashes[0]).await;
    let mix_ring = fetch_mix_ring(&d, &tx).await;

    let key_inputs: Vec<_> =
        tx.prefix.inputs.iter().filter(|i| matches!(i, TxInput::Key { .. })).collect();
    assert_eq!(mix_ring.len(), key_inputs.len(), "mix_ring should have one entry per key input");

    for (i, ring) in mix_ring.iter().enumerate() {
        if let TxInput::Key { key_offsets, .. } = &key_inputs[i] {
            assert_eq!(
                ring.len(),
                key_offsets.len(),
                "ring {} should have {} members",
                i,
                key_offsets.len()
            );
        }
        // Each member should have valid 32-byte keys.
        for (key, mask) in ring {
            assert_ne!(key, &[0u8; 32], "ring member key should not be zero");
            assert_ne!(mask, &[0u8; 32], "ring member mask should not be zero");
        }
    }

    println!(
        "Fetched ring members for {} input(s), ring size {}",
        mix_ring.len(),
        mix_ring.first().map_or(0, |r| r.len())
    );
}

// =============================================================================
// Test 4: Verify TCLSAG on a real TX
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_verify_tclsag_real_tx() {
    let d = daemon();
    let tx_hashes = find_user_tx_hashes(&d, 1).await;
    if tx_hashes.is_empty() {
        println!("  (skipped: no user transactions found)");
        return;
    }

    let tx_hash = &tx_hashes[0];
    println!("Verifying TX: {}", tx_hash);

    let (tx, raw_bytes) = fetch_and_parse_tx(&d, tx_hash).await;
    let mix_ring = fetch_mix_ring(&d, &tx).await;
    let vd = prepare_verification_data(&tx, &mix_ring, &raw_bytes);

    let (valid, failed_idx) = salvium_crypto::rct_verify::verify_rct_signatures(
        vd.rct_type,
        &vd.message,
        vd.input_count,
        vd.ring_size,
        &vd.key_images,
        &vd.pseudo_outs,
        &vd.sigs_flat,
        &vd.ring_pubkeys,
        &vd.ring_commitments,
    );

    if valid {
        println!("  Result: VALID");
    } else {
        println!("  Result: INVALID (failed at input {:?})", failed_idx);
    }

    assert!(valid, "TCLSAG verification should pass on real TX");
}

// =============================================================================
// Test 5: Verify multiple TXs
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_verify_multiple_txs() {
    let d = daemon();
    let tx_hashes = find_user_tx_hashes(&d, 5).await;
    if tx_hashes.is_empty() {
        println!("  (skipped: no user transactions found)");
        return;
    }

    let mut verified = 0u32;
    let mut failed = 0u32;

    for tx_hash in &tx_hashes {
        let (tx, raw_bytes) = fetch_and_parse_tx(&d, tx_hash).await;

        // Skip if no key inputs (coinbase-only).
        let has_key_inputs = tx.prefix.inputs.iter().any(|i| matches!(i, TxInput::Key { .. }));
        if !has_key_inputs {
            println!("  Skipping {}... (coinbase only)", &tx_hash[..12]);
            continue;
        }

        let mix_ring = fetch_mix_ring(&d, &tx).await;
        let vd = prepare_verification_data(&tx, &mix_ring, &raw_bytes);

        let rct = tx.rct.as_ref().unwrap();
        let rct_name = if rct.rct_type == rct_type::SALVIUM_ONE { "TCLSAG" } else { "CLSAG" };

        let (valid, failed_idx) = salvium_crypto::rct_verify::verify_rct_signatures(
            vd.rct_type,
            &vd.message,
            vd.input_count,
            vd.ring_size,
            &vd.key_images,
            &vd.pseudo_outs,
            &vd.sigs_flat,
            &vd.ring_pubkeys,
            &vd.ring_commitments,
        );

        if valid {
            verified += 1;
            println!(
                "  OK {}... ({}, {} in, ring {})",
                &tx_hash[..16],
                rct_name,
                vd.input_count,
                vd.ring_size
            );
        } else {
            failed += 1;
            println!("  FAIL {}... (failed at input {:?})", &tx_hash[..16], failed_idx);
        }
    }

    println!("Summary: {} verified, {} failed out of {}", verified, failed, tx_hashes.len());
    assert!(verified > 0, "should verify at least one TX");
    assert_eq!(failed, 0, "no TX should fail verification");
}

// =============================================================================
// Test 6: Tampered TX should fail verification
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_tampered_tx_fails() {
    let d = daemon();
    let tx_hashes = find_user_tx_hashes(&d, 1).await;
    if tx_hashes.is_empty() {
        println!("  (skipped: no user transactions found)");
        return;
    }

    let (tx, raw_bytes) = fetch_and_parse_tx(&d, &tx_hashes[0]).await;
    let mut mix_ring = fetch_mix_ring(&d, &tx).await;

    // Tamper: flip one byte in the first ring member's dest key.
    assert!(!mix_ring.is_empty() && !mix_ring[0].is_empty());
    mix_ring[0][0].0[0] ^= 0xFF;

    let vd = prepare_verification_data(&tx, &mix_ring, &raw_bytes);

    let (valid, failed_idx) = salvium_crypto::rct_verify::verify_rct_signatures(
        vd.rct_type,
        &vd.message,
        vd.input_count,
        vd.ring_size,
        &vd.key_images,
        &vd.pseudo_outs,
        &vd.sigs_flat,
        &vd.ring_pubkeys,
        &vd.ring_commitments,
    );

    assert!(!valid, "tampered TX should fail verification");
    println!("Tampered TX correctly rejected (failed at input {:?})", failed_idx);
}

// =============================================================================
// Test 7: Offset-to-absolute indices correctness
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_offset_to_absolute_indices() {
    let d = daemon();
    let tx_hashes = find_user_tx_hashes(&d, 1).await;
    if tx_hashes.is_empty() {
        println!("  (skipped: no user transactions found)");
        return;
    }

    let (tx, _) = fetch_and_parse_tx(&d, &tx_hashes[0]).await;

    for input in &tx.prefix.inputs {
        if let TxInput::Key { key_offsets, .. } = input {
            let indices = relative_to_absolute(key_offsets);

            // Indices should be monotonically increasing.
            for i in 1..indices.len() {
                assert!(
                    indices[i] > indices[i - 1],
                    "indices should be monotonically increasing: {:?}",
                    indices
                );
            }

            // First index equals first offset.
            assert_eq!(indices[0], key_offsets[0]);

            // Verify reconstruction: indices back to offsets.
            for i in 0..indices.len() {
                let expected_offset = if i == 0 { indices[0] } else { indices[i] - indices[i - 1] };
                assert_eq!(
                    expected_offset, key_offsets[i],
                    "offset reconstruction mismatch at index {}: expected {}, got {}",
                    i, key_offsets[i], expected_offset
                );
            }

            println!(
                "Ring indices: [{}{} ({} members)",
                indices.iter().take(4).map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
                if indices.len() > 4 { ", ..." } else { "]" },
                indices.len()
            );
        }
    }
}
