//! Testnet integration tests for the RPC client.
//!
//! Run with: cargo test -p salvium-rpc --test testnet -- --ignored
//!
//! Requires a testnet daemon at TESTNET_DAEMON_URL (default: http://node12.whiskymine.io:29081).

use salvium_rpc::DaemonRpc;

fn daemon() -> DaemonRpc {
    let url = std::env::var("TESTNET_DAEMON_URL")
        .unwrap_or_else(|_| "http://node12.whiskymine.io:29081".to_string());
    DaemonRpc::new(&url)
}

// ─── 1. Connectivity ────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_get_info() {
    let d = daemon();
    let info = d.get_info().await.expect("get_info failed");

    assert!(!info.mainnet, "should be testnet, not mainnet");
    assert!(info.height > 0, "height should be positive");
    assert!(info.synchronized, "daemon should be synchronized");
    println!("Daemon height: {}", info.height);
    println!("Difficulty: {}", info.difficulty);
    println!("TX pool size: {}", info.tx_pool_size);
}

#[tokio::test]
#[ignore]
async fn test_get_block_count() {
    let d = daemon();
    let info = d.get_info().await.expect("get_info failed");
    assert!(info.height >= 1300, "testnet should have at least 1300 blocks");
}

// ─── 2. Block Fetching ──────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_get_block_header() {
    let d = daemon();
    let header = d.get_block_header_by_height(0).await.expect("get_block_header failed");

    assert_eq!(header.height, 0);
    assert!(header.reward > 0, "genesis block should have a reward");
    assert!(!header.hash.is_empty(), "block hash should not be empty");
    println!("Genesis block reward: {} atomic units", header.reward);
    println!("Genesis hash: {}", header.hash);
}

#[tokio::test]
#[ignore]
async fn test_get_block_header_at_mined_height() {
    let d = daemon();
    // Our wallet mined blocks 1230-1292.
    let header = d.get_block_header_by_height(1250).await.expect("get_block_header failed");

    assert_eq!(header.height, 1250);
    assert!(header.reward > 0);
    println!("Block 1250 reward: {} ({:.9} SAL)", header.reward, header.reward as f64 / 1e9);
}

// ─── 3. Output Fetching (get_outs) ──────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_get_outs_single() {
    let d = daemon();
    let outputs = d
        .get_outs(
            &[salvium_rpc::daemon::OutputRequest { amount: 0, index: 0 }],
            false,
            "",
        )
        .await
        .expect("get_outs failed");

    assert_eq!(outputs.len(), 1);
    let out = &outputs[0];
    assert_eq!(out.key.len(), 64, "key should be 64 hex chars");
    assert_eq!(out.mask.len(), 64, "mask should be 64 hex chars");
    assert!(out.unlocked, "genesis output should be unlocked");
    assert_eq!(out.height, 0, "output 0 should be at height 0");
    println!("Output 0 key: {}", &out.key[..32]);
    println!("Output 0 mask: {}", &out.mask[..32]);
}

#[tokio::test]
#[ignore]
async fn test_get_outs_batch() {
    let d = daemon();
    let requests: Vec<salvium_rpc::daemon::OutputRequest> = (0..16)
        .map(|i| salvium_rpc::daemon::OutputRequest { amount: 0, index: i })
        .collect();

    let outputs = d.get_outs(&requests, false, "").await.expect("get_outs batch failed");

    assert_eq!(outputs.len(), 16, "should return 16 outputs");
    for (i, out) in outputs.iter().enumerate() {
        assert_eq!(out.key.len(), 64, "output {} key should be 64 hex chars", i);
        assert_eq!(out.mask.len(), 64, "output {} mask should be 64 hex chars", i);
        // Verify the key parses as valid hex → 32 bytes.
        let key_bytes = hex::decode(&out.key).expect("key should be valid hex");
        assert_eq!(key_bytes.len(), 32);
        let mask_bytes = hex::decode(&out.mask).expect("mask should be valid hex");
        assert_eq!(mask_bytes.len(), 32);
    }
    println!("Fetched 16 outputs successfully, all keys/masks valid");
}

// ─── 4. Output Distribution ─────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_get_output_distribution() {
    let d = daemon();
    let dist = d
        .get_output_distribution(&[0], 0, 0, true, "")
        .await
        .expect("get_output_distribution failed");

    assert!(!dist.is_empty(), "should have at least one distribution entry");
    let entry = &dist[0];
    assert_eq!(entry.amount, 0, "should be RCT (amount=0) distribution");
    assert!(
        !entry.distribution.is_empty(),
        "distribution array should not be empty"
    );

    let total_outputs = *entry.distribution.last().unwrap();
    println!(
        "Output distribution: {} blocks, {} total RCT outputs",
        entry.distribution.len(),
        total_outputs
    );
    assert!(total_outputs > 0, "should have some outputs");
}

// ─── 5. Yield Info ──────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_get_yield_info() {
    let d = daemon();
    match d.get_yield_info().await {
        Ok(yi) => {
            println!("Total staked: {} atomic", yi.total_staked);
            println!("Total yield: {} atomic", yi.total_yield);
            println!("Yield per stake: {:.6}", yi.yield_per_stake);
        }
        Err(e) => {
            // Some daemons may not support this RPC yet.
            println!("get_yield_info not available: {} (ok for older daemons)", e);
        }
    }
}

// ─── 6. Send Raw TX (dry run — invalid TX should be rejected cleanly) ───────

#[tokio::test]
#[ignore]
async fn test_send_raw_tx_rejects_garbage() {
    let d = daemon();
    // Submit obviously invalid data — daemon should reject, not crash.
    let result = d.send_raw_transaction("deadbeef", false).await;
    match result {
        Ok(r) => {
            assert_ne!(r.status, "OK", "garbage TX should not be accepted");
            println!("Daemon correctly rejected garbage TX: status={}", r.status);
        }
        Err(e) => {
            // An RPC error is also acceptable for invalid TX.
            println!("Daemon returned error for garbage TX: {} (expected)", e);
        }
    }
}
