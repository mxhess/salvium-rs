//! Testnet integration: RCT signature verification against real on-chain data.
//!
//! Fetches real transactions from the Salvium testnet daemon, parses them,
//! retrieves ring member data via `get_outs`, and verifies TCLSAG/CLSAG
//! signatures. Also tests tamper detection.
//!
//! Run with: cargo test -p salvium-tx --test rct_verify_testnet -- --ignored --nocapture
//!
//! Ported from: test/rct-verify-testnet.test.js

use salvium_rpc::daemon::{DaemonRpc, OutputRequest};
use salvium_tx::builder::relative_to_absolute;
use salvium_tx::types::*;

const DAEMON_URL: &str = "http://node12.whiskymine.io:29081";

fn daemon() -> DaemonRpc {
    let url = std::env::var("TESTNET_DAEMON_URL")
        .unwrap_or_else(|_| DAEMON_URL.to_string());
    DaemonRpc::new(&url)
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("invalid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
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

/// Fetch a transaction by hash and parse it.
async fn fetch_and_parse_tx(d: &DaemonRpc, tx_hash: &str) -> (Transaction, Vec<u8>) {
    let entries = d
        .get_transactions(&[tx_hash], true)
        .await
        .expect("get_transactions failed");
    let entry = &entries[0];
    assert!(!entry.as_hex.is_empty(), "TX {} has no hex data", tx_hash);

    let raw_bytes = hex::decode(&entry.as_hex).expect("invalid TX hex");
    let tx = Transaction::from_bytes(&raw_bytes).expect("failed to parse TX");
    (tx, raw_bytes)
}

/// Fetch ring members for all key inputs in a transaction.
/// Returns one Vec<(key, mask)> per key input.
async fn fetch_mix_ring(
    d: &DaemonRpc,
    tx: &Transaction,
) -> Vec<Vec<([u8; 32], [u8; 32])>> {
    let mut mix_ring = Vec::new();

    for input in &tx.prefix.inputs {
        match input {
            TxInput::Gen { .. } => continue,
            TxInput::Key {
                key_offsets,
                asset_type,
                ..
            } => {
                let abs_indices = relative_to_absolute(key_offsets);
                let requests: Vec<OutputRequest> = abs_indices
                    .iter()
                    .map(|&idx| OutputRequest { amount: 0, index: idx })
                    .collect();

                let outs = d
                    .get_outs(&requests, false, asset_type)
                    .await
                    .expect("get_outs failed");
                assert_eq!(
                    outs.len(),
                    abs_indices.len(),
                    "get_outs returned wrong count"
                );

                let ring: Vec<([u8; 32], [u8; 32])> = outs
                    .iter()
                    .map(|out| (hex_to_32(&out.key), hex_to_32(&out.mask)))
                    .collect();
                mix_ring.push(ring);
            }
        }
    }

    mix_ring
}

/// Build the flat data arrays needed for rct_verify from a parsed TX and its ring.
fn prepare_verification_data(
    tx: &Transaction,
    mix_ring: &[Vec<([u8; 32], [u8; 32])>],
    _raw_bytes: &[u8],
) -> VerificationData {
    let rct = tx.rct.as_ref().expect("TX has no RCT data");

    // Compute prefix hash from raw bytes.
    // The prefix ends where the RCT section begins.
    // We can get this from the JSON parse metadata, but since we have the full TX
    // we can use the typed prefix serialization.
    let prefix_hash = tx.prefix_hash().expect("failed to compute prefix hash");

    // Build rct_base bytes for message hash computation.
    let mut rct_base = Vec::new();
    write_varint(&mut rct_base, rct.rct_type as u64);
    write_varint(&mut rct_base, rct.txn_fee);
    for ei in &rct.ecdh_info {
        rct_base.extend_from_slice(&ei.amount);
    }
    for pk in &rct.out_pk {
        rct_base.extend_from_slice(pk);
    }
    // p_r
    if let Some(ref pr) = rct.p_r {
        rct_base.extend_from_slice(pr);
    } else {
        let mut identity = [0u8; 32];
        identity[0] = 0x01;
        rct_base.extend_from_slice(&identity);
    }
    // salvium_data
    serialize_salvium_data_for_hash(&mut rct_base, &rct.salvium_data);

    // Build BP+ components bytes.
    let mut bp_bytes = Vec::new();
    for bp in &rct.bulletproof_plus {
        bp_bytes.extend_from_slice(&bp.a);
        bp_bytes.extend_from_slice(&bp.a1);
        bp_bytes.extend_from_slice(&bp.b);
        bp_bytes.extend_from_slice(&bp.r1);
        bp_bytes.extend_from_slice(&bp.s1);
        bp_bytes.extend_from_slice(&bp.d1);
        for l in &bp.l_vec {
            bp_bytes.extend_from_slice(l);
        }
        for r in &bp.r_vec {
            bp_bytes.extend_from_slice(r);
        }
    }

    // Compute message.
    let message =
        salvium_crypto::rct_verify::compute_rct_message(&prefix_hash, &rct_base, &bp_bytes);

    // Collect key images from prefix inputs.
    let key_images: Vec<[u8; 32]> = tx
        .prefix
        .inputs
        .iter()
        .filter_map(|i| i.key_image().copied())
        .collect();

    // Flatten ring data.
    let ring_size = if !mix_ring.is_empty() {
        mix_ring[0].len()
    } else {
        0
    };
    let mut ring_pubkeys = Vec::new();
    let mut ring_commitments = Vec::new();
    for ring in mix_ring {
        for (key, mask) in ring {
            ring_pubkeys.push(*key);
            ring_commitments.push(*mask);
        }
    }

    // Build flat sig bytes.
    let mut sigs_flat = Vec::new();
    let is_tclsag = rct.rct_type == rct_type::SALVIUM_ONE;
    if is_tclsag {
        for sig in &rct.tclsags {
            for s in &sig.sx {
                sigs_flat.extend_from_slice(s);
            }
            for s in &sig.sy {
                sigs_flat.extend_from_slice(s);
            }
            sigs_flat.extend_from_slice(&sig.c1);
            sigs_flat.extend_from_slice(&sig.d);
        }
    } else {
        for sig in &rct.clsags {
            for s in &sig.s {
                sigs_flat.extend_from_slice(s);
            }
            sigs_flat.extend_from_slice(&sig.c1);
            sigs_flat.extend_from_slice(&sig.d);
        }
    }

    VerificationData {
        rct_type: rct.rct_type,
        message,
        input_count: key_images.len(),
        ring_size,
        key_images,
        pseudo_outs: rct.pseudo_outs.clone(),
        sigs_flat,
        ring_pubkeys,
        ring_commitments,
    }
}

struct VerificationData {
    rct_type: u8,
    message: [u8; 32],
    input_count: usize,
    ring_size: usize,
    key_images: Vec<[u8; 32]>,
    pseudo_outs: Vec<[u8; 32]>,
    sigs_flat: Vec<u8>,
    ring_pubkeys: Vec<[u8; 32]>,
    ring_commitments: Vec<[u8; 32]>,
}

fn write_varint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val > 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

fn serialize_salvium_data_for_hash(buf: &mut Vec<u8>, sd: &Option<serde_json::Value>) {
    let sd = match sd {
        Some(v) => v,
        None => return,
    };
    let dt = sd
        .get("salvium_data_type")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    write_varint(buf, dt);

    // pr_proof
    serialize_zk_proof_for_hash(buf, sd.get("pr_proof"));
    // sa_proof
    serialize_zk_proof_for_hash(buf, sd.get("sa_proof"));

    if dt == 1 {
        // SalviumZeroAudit: cz_proof + input_verification_data + spend_pubkey + enc_view_privkey
        serialize_zk_proof_for_hash(buf, sd.get("cz_proof"));

        if let Some(ivd) = sd.get("input_verification_data").and_then(|v| v.as_array()) {
            write_varint(buf, ivd.len() as u64);
            for item in ivd {
                let ar = item.get("aR").and_then(|v| v.as_str()).unwrap_or("");
                if let Ok(bytes) = hex::decode(ar) {
                    buf.extend_from_slice(&bytes);
                } else {
                    buf.extend_from_slice(&[0u8; 32]);
                }
                let amount = item.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                write_varint(buf, amount);
                let i_val = item.get("i").and_then(|v| v.as_u64()).unwrap_or(0);
                write_varint(buf, i_val);
                let origin = item
                    .get("origin_tx_type")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                write_varint(buf, origin);
                if origin != 0 {
                    let ar_stake =
                        item.get("aR_stake").and_then(|v| v.as_str()).unwrap_or("");
                    if let Ok(bytes) = hex::decode(ar_stake) {
                        buf.extend_from_slice(&bytes);
                    } else {
                        buf.extend_from_slice(&[0u8; 32]);
                    }
                    let i_stake = item.get("i_stake").and_then(|v| v.as_u64()).unwrap_or(0);
                    buf.extend_from_slice(&i_stake.to_le_bytes());
                }
            }
        } else {
            write_varint(buf, 0);
        }

        // spend_pubkey
        let spk = sd.get("spend_pubkey").and_then(|v| v.as_str()).unwrap_or("");
        if let Ok(bytes) = hex::decode(spk) {
            buf.extend_from_slice(&bytes);
        } else {
            buf.extend_from_slice(&[0u8; 32]);
        }

        // enc_view_privkey_str
        let evp = sd
            .get("enc_view_privkey_str")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let evp_bytes = evp.as_bytes();
        write_varint(buf, evp_bytes.len() as u64);
        buf.extend_from_slice(evp_bytes);
    }
}

fn serialize_zk_proof_for_hash(buf: &mut Vec<u8>, proof: Option<&serde_json::Value>) {
    let proof = match proof {
        Some(v) if !v.is_null() => v,
        _ => {
            buf.extend_from_slice(&[0u8; 96]);
            return;
        }
    };

    let r = proof.get("R").and_then(|v| v.as_str()).unwrap_or("");
    let z1 = proof.get("z1").and_then(|v| v.as_str()).unwrap_or("");
    let z2 = proof.get("z2").and_then(|v| v.as_str()).unwrap_or("");

    if r.is_empty() {
        buf.extend_from_slice(&[0u8; 96]);
    } else {
        if let (Ok(r_b), Ok(z1_b), Ok(z2_b)) =
            (hex::decode(r), hex::decode(z1), hex::decode(z2))
        {
            buf.extend_from_slice(&r_b);
            buf.extend_from_slice(&z1_b);
            buf.extend_from_slice(&z2_b);
        } else {
            buf.extend_from_slice(&[0u8; 96]);
        }
    }
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
        tx_hashes
            .iter()
            .take(3)
            .map(|h| format!("{}...", &h[..12]))
            .collect::<Vec<_>>()
            .join(", ")
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

    let rct_name = if rct.rct_type == rct_type::SALVIUM_ONE {
        "TCLSAG/SalviumOne"
    } else {
        "CLSAG"
    };

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

    let key_inputs: Vec<_> = tx
        .prefix
        .inputs
        .iter()
        .filter(|i| matches!(i, TxInput::Key { .. }))
        .collect();
    assert_eq!(
        mix_ring.len(),
        key_inputs.len(),
        "mix_ring should have one entry per key input"
    );

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
        println!(
            "  Result: INVALID (failed at input {:?})",
            failed_idx
        );
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
        let has_key_inputs = tx
            .prefix
            .inputs
            .iter()
            .any(|i| matches!(i, TxInput::Key { .. }));
        if !has_key_inputs {
            println!("  Skipping {}... (coinbase only)", &tx_hash[..12]);
            continue;
        }

        let mix_ring = fetch_mix_ring(&d, &tx).await;
        let vd = prepare_verification_data(&tx, &mix_ring, &raw_bytes);

        let rct = tx.rct.as_ref().unwrap();
        let rct_name = if rct.rct_type == rct_type::SALVIUM_ONE {
            "TCLSAG"
        } else {
            "CLSAG"
        };

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
            println!(
                "  FAIL {}... (failed at input {:?})",
                &tx_hash[..16],
                failed_idx
            );
        }
    }

    println!(
        "Summary: {} verified, {} failed out of {}",
        verified,
        failed,
        tx_hashes.len()
    );
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

    assert!(
        !valid,
        "tampered TX should fail verification"
    );
    println!(
        "Tampered TX correctly rejected (failed at input {:?})",
        failed_idx
    );
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
                let expected_offset = if i == 0 {
                    indices[0]
                } else {
                    indices[i] - indices[i - 1]
                };
                assert_eq!(
                    expected_offset, key_offsets[i],
                    "offset reconstruction mismatch at index {}: expected {}, got {}",
                    i, key_offsets[i], expected_offset
                );
            }

            println!(
                "Ring indices: [{}{} ({} members)",
                indices
                    .iter()
                    .take(4)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                if indices.len() > 4 { ", ..." } else { "]" },
                indices.len()
            );
        }
    }
}
