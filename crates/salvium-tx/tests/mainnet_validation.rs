//! Mainnet data validation tests — per hard-fork era.
//!
//! Fetches real blocks and transactions from the public Salvium mainnet daemon,
//! exercising the full parsing/verification pipeline across every hard fork era
//! (HF1 through HF10+). Each test samples blocks from each era independently,
//! catching structural changes introduced by each fork.
//!
//! Run with:
//!   cargo test -p salvium-tx --test mainnet_validation -- --ignored --nocapture
//!
//! Override daemon URL:
//!   MAINNET_DAEMON_URL=http://your-node:19081 cargo test ...

mod common;

use common::{fetch_and_parse_tx, fetch_mix_ring, hex_to_32, prepare_verification_data};
use rand::Rng;
use salvium_consensus::tree_hash::tree_hash;
use salvium_rpc::daemon::DaemonRpc;
use salvium_tx::types::*;
use salvium_types::constants::MAINNET_CONFIG;

const MAINNET_DAEMONS: &[&str] = &[
    "http://seed01.salvium.io:19081",
    "http://seed02.salvium.io:19081",
    "http://seed03.salvium.io:19081",
];

/// Blocks to sample per hard-fork era.
const SAMPLES_PER_ERA: usize = 5;

fn daemon() -> DaemonRpc {
    let url = std::env::var("MAINNET_DAEMON_URL").unwrap_or_else(|_| {
        let idx = rand::thread_rng().gen_range(0..MAINNET_DAEMONS.len());
        MAINNET_DAEMONS[idx].to_string()
    });
    DaemonRpc::new(&url)
}

// =============================================================================
// Hard fork era helpers
// =============================================================================

struct HfEra {
    version: u8,
    start: u64,
    end: u64, // exclusive
}

impl HfEra {
    fn label(&self) -> String {
        format!("HF{} [{}, {})", self.version, self.start, self.end)
    }

    fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// Build HF era ranges from the mainnet config and current chain height.
/// Each era runs from its activation height to the next era's activation height
/// (or chain_height for the latest era).
fn hf_eras(chain_height: u64) -> Vec<HfEra> {
    let hf = MAINNET_CONFIG.hard_fork_heights;
    let mut eras = Vec::new();
    for (i, &(version, start)) in hf.iter().enumerate() {
        let end = if i + 1 < hf.len() {
            hf[i + 1].1
        } else {
            chain_height.saturating_sub(10) // avoid tip reorgs
        };
        if start < end {
            eras.push(HfEra { version, start, end });
        }
    }
    eras
}

/// Pick `count` random heights from the given range.
fn random_heights(range: std::ops::Range<u64>, count: usize) -> Vec<u64> {
    if range.is_empty() {
        return Vec::new();
    }
    let mut rng = rand::thread_rng();
    (0..count).map(|_| rng.gen_range(range.clone())).collect()
}

/// Pick random heights within an era, avoiding height 0 (genesis oddities).
fn era_sample_heights(era: &HfEra, count: usize) -> Vec<u64> {
    let safe_start = era.start.max(1);
    if safe_start >= era.end {
        return Vec::new();
    }
    random_heights(safe_start..era.end, count.min(era.len() as usize))
}

/// Find user (non-coinbase) transaction hashes from blocks at specific heights.
async fn find_txs_at_heights(d: &DaemonRpc, heights: &[u64], max_txs: usize) -> Vec<(String, u64)> {
    let mut results = Vec::new();
    for &h in heights {
        if results.len() >= max_txs {
            break;
        }
        match d.get_block(h).await {
            Ok(block) => {
                for hash in &block.tx_hashes {
                    if results.len() < max_txs {
                        results.push((hash.clone(), h));
                    }
                }
            }
            Err(_) => continue,
        }
    }
    results
}

/// Scan a wider height range to find blocks that contain user transactions.
async fn find_blocks_with_txs(d: &DaemonRpc, era: &HfEra, count: usize) -> Vec<u64> {
    let mut found = Vec::new();
    let candidates = era_sample_heights(era, count * 30);
    for h in candidates {
        if found.len() >= count {
            break;
        }
        match d.get_block(h).await {
            Ok(block) if !block.tx_hashes.is_empty() => {
                found.push(h);
            }
            _ => continue,
        }
    }
    found
}

// =============================================================================
// Test 1: Daemon reachability
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_mainnet_daemon_reachable() {
    let d = daemon();
    let info = d.get_info().await.expect("mainnet daemon unreachable");
    assert!(info.height > 0, "chain height should be > 0");
    println!("Mainnet daemon reachable: height={}, mainnet={}", info.height, info.mainnet);

    let eras = hf_eras(info.height);
    println!("Hard fork eras:");
    for era in &eras {
        println!("  {} ({} blocks)", era.label(), era.len());
    }
}

// =============================================================================
// Test 2: Parse blocks from every HF era
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_parse_blocks_per_hf_era() {
    let d = daemon();
    let info = d.get_info().await.expect("daemon unreachable");
    let eras = hf_eras(info.height);

    for era in &eras {
        println!("\n--- {} ---", era.label());
        let heights = era_sample_heights(era, SAMPLES_PER_ERA);

        for &h in &heights {
            let block = d.get_block(h).await.unwrap_or_else(|e| {
                panic!("get_block({}) failed in {}: {:?}", h, era.label(), e);
            });

            // Parse the raw block blob.
            let blob_bytes = hex::decode(&block.blob).expect("invalid block blob hex");
            let block_json_str = salvium_crypto::parse_block_bytes(&blob_bytes);
            let block_json: serde_json::Value =
                serde_json::from_str(&block_json_str).expect("failed to parse block JSON");

            assert!(
                block_json.get("error").is_none(),
                "block parse error at h={} ({}): {}",
                h,
                era.label(),
                block_json
            );

            let header = &block_json["header"];
            let major_version = header["majorVersion"].as_u64().unwrap();

            // Major version should match the HF era.
            assert_eq!(
                major_version, era.version as u64,
                "block at h={} should have majorVersion={}, got {}",
                h, era.version, major_version
            );

            // prevId should be non-zero (except genesis).
            let prev_id = header["prevId"].as_str().unwrap_or("");
            if h > 1 {
                assert!(!prev_id.chars().all(|c| c == '0'), "prevId at h={} should be non-zero", h);
            }

            // minerTx should parse.
            assert!(!block_json["minerTx"].is_null(), "minerTx should parse at h={}", h);

            // TX count should match header.
            let parsed_tx_count = block_json["txHashes"].as_array().map_or(0, |a| a.len());
            assert_eq!(
                parsed_tx_count as u64, block.block_header.num_txes,
                "TX count mismatch at h={}",
                h
            );

            println!(
                "  h={}: v{}.{}, {} user txs, prev={}...",
                h,
                major_version,
                header["minorVersion"].as_u64().unwrap_or(0),
                parsed_tx_count,
                &prev_id[..16.min(prev_id.len())]
            );
        }
    }
}

// =============================================================================
// Test 3: Block header fields from every HF era
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_block_headers_per_hf_era() {
    let d = daemon();
    let info = d.get_info().await.expect("daemon unreachable");
    let eras = hf_eras(info.height);

    for era in &eras {
        println!("\n--- {} ---", era.label());
        let heights = era_sample_heights(era, SAMPLES_PER_ERA);

        for &h in &heights {
            let header = d
                .get_block_header_by_height(h)
                .await
                .unwrap_or_else(|e| panic!("get_block_header({}) failed: {:?}", h, e));

            assert_eq!(header.height, h);
            assert!(header.difficulty > 0, "difficulty should be > 0 at h={}", h);
            assert!(header.reward > 0, "reward should be > 0 at h={}", h);
            assert_eq!(header.hash.len(), 64, "hash should be 64 hex chars at h={}", h);
            assert_eq!(
                header.major_version, era.version,
                "major_version should be {} at h={}, got {}",
                era.version, h, header.major_version
            );

            // CARROT-era (HF10+) blocks should have a protocol TX hash.
            if era.version >= 10 {
                let ptx = header.protocol_tx_hash.as_deref().unwrap_or("");
                assert!(
                    !ptx.is_empty(),
                    "HF{} block at h={} should have protocol_tx_hash",
                    era.version,
                    h
                );
            }

            println!(
                "  h={}: v{}.{}, diff={}, reward={}, txs={}",
                h,
                header.major_version,
                header.minor_version,
                header.difficulty,
                header.reward,
                header.num_txes
            );
        }
    }
}

// =============================================================================
// Test 4: Block tree hash from every HF era
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_block_tree_hash_per_hf_era() {
    let d = daemon();
    let info = d.get_info().await.expect("daemon unreachable");
    let eras = hf_eras(info.height);

    for era in &eras {
        println!("\n--- {} ---", era.label());
        let blocks = find_blocks_with_txs(&d, era, 3).await;

        if blocks.is_empty() {
            println!("  (no blocks with user TXs found — skipping tree hash)");
            continue;
        }

        for &h in &blocks {
            let block = d.get_block(h).await.unwrap();

            let mut all_hashes: Vec<[u8; 32]> = Vec::new();
            all_hashes.push(hex_to_32(&block.miner_tx_hash));

            // CARROT-era includes protocol TX hash in the tree.
            if era.version >= 10 {
                if let Some(ref ptx_hash) = block.block_header.protocol_tx_hash {
                    if !ptx_hash.is_empty() && ptx_hash != &"0".repeat(64) {
                        all_hashes.push(hex_to_32(ptx_hash));
                    }
                }
            }

            for tx_hash in &block.tx_hashes {
                all_hashes.push(hex_to_32(tx_hash));
            }

            let tree = tree_hash(&all_hashes);
            assert_ne!(tree, [0u8; 32], "tree_hash should be non-zero at h={}", h);

            // Determinism check.
            let tree2 = tree_hash(&all_hashes);
            assert_eq!(tree, tree2, "tree_hash must be deterministic");

            println!("  h={}: {} hashes -> {}", h, all_hashes.len(), hex::encode(tree));
        }
    }
}

// =============================================================================
// Test 5: Parse user transactions from every HF era
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_parse_transactions_per_hf_era() {
    let d = daemon();
    let info = d.get_info().await.expect("daemon unreachable");
    let eras = hf_eras(info.height);

    for era in &eras {
        println!("\n--- {} ---", era.label());

        // Sample more candidates for narrow eras or eras with few TXs (e.g. HF5).
        let sample_count = if era.len() < 1000 { era.len() as usize } else { 100 };
        let heights = era_sample_heights(era, sample_count);
        let txs = find_txs_at_heights(&d, &heights, SAMPLES_PER_ERA).await;

        if txs.is_empty() {
            println!("  (no user transactions found — may be expected for HF{})", era.version);
            continue;
        }

        for (tx_hash, height) in &txs {
            let (tx, _raw) = fetch_and_parse_tx(&d, tx_hash).await;
            let rct = tx.rct.as_ref().expect("TX should have RCT data");

            // Structural assertions that apply to all eras.
            assert!(!tx.prefix.inputs.is_empty(), "TX at h={} should have inputs", height);
            assert!(!tx.prefix.outputs.is_empty(), "TX at h={} should have outputs", height);

            // Key images should be non-zero.
            for input in &tx.prefix.inputs {
                if let Some(ki) = input.key_image() {
                    assert_ne!(ki, &[0u8; 32], "key image should be non-zero at h={}", height);
                }
            }

            // ECDH info count should match output count.
            assert_eq!(
                rct.ecdh_info.len(),
                tx.prefix.outputs.len(),
                "ECDH info count mismatch at h={}",
                height
            );

            // out_pk count should match output count.
            assert_eq!(
                rct.out_pk.len(),
                tx.prefix.outputs.len(),
                "out_pk count mismatch at h={}",
                height
            );

            // Era-specific assertions.
            let rct_name = match rct.rct_type {
                rct_type::CLSAG => "CLSAG",
                rct_type::BULLETPROOF_PLUS => "BP+",
                rct_type::FULL_PROOFS => "FULL_PROOFS",
                rct_type::SALVIUM_ZERO => "SALVIUM_ZERO",
                rct_type::SALVIUM_ONE => "TCLSAG",
                other => {
                    panic!("unexpected RCT type {} at h={} (HF{})", other, height, era.version);
                }
            };

            if era.version >= 10 {
                // CARROT era: version 4, TCLSAG, p_r present.
                assert_eq!(
                    tx.prefix.version, 4,
                    "HF{} TX at h={} should have version 4, got {}",
                    era.version, height, tx.prefix.version
                );
                assert_eq!(
                    rct.rct_type,
                    rct_type::SALVIUM_ONE,
                    "HF{} TX at h={} should be TCLSAG (9), got {}",
                    era.version,
                    height,
                    rct.rct_type
                );
                assert!(
                    !rct.tclsags.is_empty(),
                    "HF{} TX at h={} should have TCLSAG sigs",
                    era.version,
                    height
                );
                assert!(rct.p_r.is_some(), "HF{} TX at h={} should have p_r", era.version, height);
            }

            println!(
                "  TX {}... h={}: v{}, {}, {} in, {} out",
                &tx_hash[..16],
                height,
                tx.prefix.version,
                rct_name,
                tx.prefix.inputs.len(),
                tx.prefix.outputs.len()
            );
        }
    }
}

// =============================================================================
// Test 6: TX serialize roundtrip from every HF era
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_tx_serialize_roundtrip_per_hf_era() {
    let d = daemon();
    let info = d.get_info().await.expect("daemon unreachable");
    let eras = hf_eras(info.height);

    for era in &eras {
        println!("\n--- {} ---", era.label());

        let sample_count = if era.len() < 1000 { era.len() as usize } else { 100 };
        let heights = era_sample_heights(era, sample_count);
        let txs = find_txs_at_heights(&d, &heights, 3).await;

        if txs.is_empty() {
            println!("  (no user transactions found — skipping roundtrip)");
            continue;
        }

        for (tx_hash, height) in &txs {
            let (tx, raw_bytes) = fetch_and_parse_tx(&d, tx_hash).await;

            match tx.to_bytes() {
                Ok(reserialized) => {
                    assert_eq!(
                        raw_bytes,
                        reserialized,
                        "roundtrip mismatch for TX {}... at h={} (HF{})",
                        &tx_hash[..16],
                        height,
                        era.version
                    );
                    println!(
                        "  roundtrip OK: {}... h={} ({} bytes)",
                        &tx_hash[..16],
                        height,
                        raw_bytes.len()
                    );
                }
                Err(e) => {
                    panic!(
                        "serialization failed for TX {}... at h={} (HF{}): {}",
                        &tx_hash[..16],
                        height,
                        era.version,
                        e
                    );
                }
            }
        }
    }
}

// =============================================================================
// Test 7: Verify ring signatures from every HF era
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_verify_signatures_per_hf_era() {
    let d = daemon();
    let info = d.get_info().await.expect("daemon unreachable");
    let eras = hf_eras(info.height);

    let mut total_verified = 0u32;

    for era in &eras {
        println!("\n--- {} ---", era.label());

        let sample_count = if era.len() < 1000 { era.len() as usize } else { 100 };
        let heights = era_sample_heights(era, sample_count);
        let txs = find_txs_at_heights(&d, &heights, 3).await;

        if txs.is_empty() {
            println!("  (no user transactions found — skipping verification)");
            continue;
        }

        for (tx_hash, height) in &txs {
            let (tx, raw_bytes) = fetch_and_parse_tx(&d, tx_hash).await;
            let rct = tx.rct.as_ref().expect("TX should have RCT data");
            let mix_ring = fetch_mix_ring(&d, &tx).await;
            let vd = prepare_verification_data(&tx, &mix_ring, &raw_bytes);

            let sig_type = if rct.rct_type == rct_type::SALVIUM_ONE { "TCLSAG" } else { "CLSAG" };

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
                valid,
                "{} verification failed for TX {}... at h={} (HF{}, failed input: {:?})",
                sig_type,
                &tx_hash[..16],
                height,
                era.version,
                failed_idx
            );

            total_verified += 1;
            println!(
                "  {} verified: {}... h={} ({} inputs, ring {})",
                sig_type,
                &tx_hash[..16],
                height,
                vd.input_count,
                vd.ring_size
            );
        }
    }

    assert!(total_verified > 0, "should verify at least one TX across all eras");
    println!("\nTotal TXs verified across all eras: {}", total_verified);
}

// =============================================================================
// Test 8: Tampered mainnet TX should fail verification
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_verify_tampered_mainnet_tx() {
    let d = daemon();
    let info = d.get_info().await.expect("daemon unreachable");

    // Try CARROT-era first, fall back to earlier eras.
    let eras = hf_eras(info.height);
    let mut txs = Vec::new();
    for era in eras.iter().rev() {
        let heights = era_sample_heights(era, 50);
        txs = find_txs_at_heights(&d, &heights, 1).await;
        if !txs.is_empty() {
            break;
        }
    }

    if txs.is_empty() {
        println!("  (skipped: no user transactions found)");
        return;
    }

    let (tx_hash, height) = &txs[0];
    let (tx, raw_bytes) = fetch_and_parse_tx(&d, tx_hash).await;
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

    assert!(!valid, "tampered mainnet TX should fail verification");
    println!(
        "  Tampered TX {}... h={} correctly rejected (failed at input {:?})",
        &tx_hash[..16],
        height,
        failed_idx
    );
}

// =============================================================================
// Test 9: Bulletproof+ range proof structure
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_bulletproof_plus_structure() {
    let d = daemon();
    let info = d.get_info().await.expect("daemon unreachable");
    let eras = hf_eras(info.height);

    // BP+ proofs are present in all eras with user TXs.
    let mut found_any = false;
    for era in &eras {
        let sample_count = if era.len() < 1000 { era.len() as usize } else { 50 };
        let heights = era_sample_heights(era, sample_count);
        let txs = find_txs_at_heights(&d, &heights, 2).await;

        if txs.is_empty() {
            continue;
        }

        println!("\n--- {} ---", era.label());
        for (tx_hash, height) in &txs {
            let (tx, _raw) = fetch_and_parse_tx(&d, tx_hash).await;
            let rct = tx.rct.as_ref().expect("TX should have RCT data");

            if rct.bulletproof_plus.is_empty() {
                println!(
                    "  TX {}... h={}: no BP+ proofs (rct_type={})",
                    &tx_hash[..16],
                    height,
                    rct.rct_type
                );
                continue;
            }

            found_any = true;
            for (i, bp) in rct.bulletproof_plus.iter().enumerate() {
                assert_ne!(bp.a, [0u8; 32], "BP+ a should be non-zero");
                assert_ne!(bp.a1, [0u8; 32], "BP+ a1 should be non-zero");
                assert_ne!(bp.b, [0u8; 32], "BP+ b should be non-zero");
                assert_ne!(bp.r1, [0u8; 32], "BP+ r1 should be non-zero");
                assert_ne!(bp.s1, [0u8; 32], "BP+ s1 should be non-zero");
                assert_ne!(bp.d1, [0u8; 32], "BP+ d1 should be non-zero");

                assert_eq!(
                    bp.l_vec.len(),
                    bp.r_vec.len(),
                    "BP+ l_vec and r_vec length mismatch in proof {} at h={}",
                    i,
                    height
                );
                assert!(
                    !bp.l_vec.is_empty(),
                    "BP+ l_vec should be non-empty in proof {} at h={}",
                    i,
                    height
                );

                println!(
                    "  BP+ proof {}: TX {}... h={}, l/r_vec len={}, outputs={}",
                    i,
                    &tx_hash[..16],
                    height,
                    bp.l_vec.len(),
                    tx.prefix.outputs.len()
                );
            }
        }
    }

    assert!(found_any, "should find at least one TX with BP+ proofs");
}
