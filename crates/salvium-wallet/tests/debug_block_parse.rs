//! Diagnostic test: parse blocks at specific heights to detect silent failures.
//!
//! Run with:
//!   cargo test -p salvium-wallet --test debug_block_parse -- --nocapture --ignored

use salvium_rpc::DaemonRpc;

/// Test heights spanning the full chain, with focus on the CARROT era (HF10+).
const TEST_HEIGHTS: &[u64] = &[
    100,     // early chain
    10_000,  // pre-HF
    100_000, // mid chain
    200_000, // mid chain
    300_000, // approaching HF10
    334_750, // HF10 boundary (CARROT era start)
    350_000, // early CARROT era
    400_000, // mid CARROT era
    417_800, // just before known outputs
    417_810, // first known output for second wallet
    425_000, // within known output range
];

#[tokio::test]
#[ignore]
async fn debug_block_parse_at_heights() {
    let daemon = DaemonRpc::new("http://node12.whiskymine.io:19081");
    let info = daemon.get_info().await.expect("cannot reach mainnet daemon");
    println!("Daemon height: {} (synchronized: {})", info.height, info.synchronized);
    println!();

    let mut pass = 0usize;
    let mut fail = 0usize;

    for &height in TEST_HEIGHTS {
        if height >= info.height {
            println!("SKIP  height={} (beyond daemon tip {})", height, info.height);
            continue;
        }

        // Fetch block via binary endpoint
        let heights = vec![height];
        let blocks = match daemon.get_blocks_by_height_bin(&heights).await {
            Ok(b) => b,
            Err(e) => {
                println!("FETCH FAIL  height={}  err={}", height, e);
                fail += 1;
                continue;
            }
        };

        let headers = match daemon.get_block_headers_range(height, height).await {
            Ok(h) => h,
            Err(e) => {
                println!("HEADER FAIL  height={}  err={}", height, e);
                fail += 1;
                continue;
            }
        };

        if blocks.is_empty() {
            println!("EMPTY  height={}  (no blocks returned)", height);
            fail += 1;
            continue;
        }

        let entry = &blocks[0];
        let header = &headers[0];

        // Check for empty blob
        if entry.block.is_empty() {
            println!("EMPTY BLOB  height={}", height);
            fail += 1;
            continue;
        }

        // Parse the block
        let block_json_str = salvium_crypto::parse_block_bytes(&entry.block);

        // Check for error response
        if block_json_str.starts_with(r#"{"error":"#) {
            println!(
                "PARSE FAIL  height={}  blob_len={}  err={}",
                height,
                entry.block.len(),
                &block_json_str[..block_json_str.len().min(300)]
            );
            // Print first 64 bytes of blob as hex for debugging
            let hex_preview: String = entry.block.iter().take(64).map(|b| format!("{:02x}", b)).collect();
            println!("  blob_hex_prefix: {}", hex_preview);
            fail += 1;
            continue;
        }

        // Try to parse as JSON
        let parsed: serde_json::Value = match serde_json::from_str(&block_json_str) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "JSON FAIL  height={}  blob_len={}  err={}",
                    height, entry.block.len(), e
                );
                println!("  raw json (first 500 chars): {}", &block_json_str[..block_json_str.len().min(500)]);
                fail += 1;
                continue;
            }
        };

        // Count miner_tx outputs
        let miner_out_count = parsed
            .get("minerTx")
            .and_then(|mtx| mtx.get("prefix").unwrap_or(mtx).get("vout"))
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        // Count protocol_tx outputs
        let protocol_out_count = parsed
            .get("protocolTx")
            .and_then(|ptx| ptx.get("prefix").unwrap_or(ptx).get("vout"))
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        // Count tx_hashes
        let tx_hash_count = parsed
            .get("txHashes")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        // Count regular tx blobs
        let tx_blob_count = entry.txs.len();

        // Check miner_tx_hash from header
        let has_miner_hash = header.miner_tx_hash.is_some();
        let has_protocol_hash = header.protocol_tx_hash.is_some();

        // Test parsing each regular tx blob
        let mut tx_parse_fails = 0usize;
        for (i, tx_blob) in entry.txs.iter().enumerate() {
            let tx_json_str = salvium_crypto::parse_transaction_bytes(tx_blob);
            if tx_json_str.starts_with(r#"{"error":"#) {
                tx_parse_fails += 1;
                if tx_parse_fails <= 3 {
                    println!(
                        "  TX PARSE FAIL  height={}  tx_idx={}  blob_len={}  err={}",
                        height, i, tx_blob.len(),
                        &tx_json_str[..tx_json_str.len().min(200)]
                    );
                }
            }
        }

        let status = if tx_parse_fails > 0 { "PARTIAL" } else { "OK" };
        println!(
            "{:<7}  height={:<7}  blob_len={:<6}  miner_outs={}  proto_outs={}  tx_hashes={}  tx_blobs={}  tx_fails={}  hdr_miner={}  hdr_proto={}",
            status,
            height,
            entry.block.len(),
            miner_out_count,
            protocol_out_count,
            tx_hash_count,
            tx_blob_count,
            tx_parse_fails,
            has_miner_hash,
            has_protocol_hash,
        );

        if tx_parse_fails > 0 {
            fail += 1;
        } else {
            pass += 1;
        }
    }

    println!();
    println!("=== Summary ===");
    println!("Pass: {}  Fail: {}  Total: {}", pass, fail, pass + fail);

    if fail > 0 {
        println!("WARNING: {} heights had parse failures — investigate above output", fail);
    } else {
        println!("All tested heights parsed successfully.");
    }
}

/// Extended range test: parse every block in a range to find the exact failure point.
///
/// Run with:
///   cargo test -p salvium-wallet --test debug_block_parse -- debug_block_parse_range --nocapture --ignored
#[tokio::test]
#[ignore]
async fn debug_block_parse_range() {
    let daemon = DaemonRpc::new("http://node12.whiskymine.io:19081");
    let info = daemon.get_info().await.expect("cannot reach mainnet daemon");

    // Scan the CARROT era range where outputs are missing (334750 to 417810).
    // Adjust these as needed based on initial diagnostic results.
    let range_start: u64 = 334_750;
    let range_end: u64 = 335_000.min(info.height - 1); // small batch first
    let batch_size: usize = 100;

    println!("Scanning blocks {}..{} for parse failures", range_start, range_end);
    println!("Daemon height: {}", info.height);
    println!();

    let mut total_blocks = 0usize;
    let mut total_parse_errors = 0usize;
    let mut total_empty_blobs = 0usize;
    let mut first_error_height: Option<u64> = None;

    let mut current = range_start;
    while current <= range_end {
        let batch_end = (current + batch_size as u64 - 1).min(range_end);
        let heights: Vec<u64> = (current..=batch_end).collect();

        let blocks = match daemon.get_blocks_by_height_bin(&heights).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("RPC ERROR at heights {}..{}: {}", current, batch_end, e);
                current = batch_end + 1;
                continue;
            }
        };

        for (i, entry) in blocks.iter().enumerate() {
            let height = heights[i];
            total_blocks += 1;

            if entry.block.is_empty() {
                total_empty_blobs += 1;
                eprintln!("EMPTY BLOB height={}", height);
                if first_error_height.is_none() {
                    first_error_height = Some(height);
                }
                continue;
            }

            let block_json_str = salvium_crypto::parse_block_bytes(&entry.block);

            if block_json_str.starts_with(r#"{"error":"#) {
                total_parse_errors += 1;
                let snippet = &block_json_str[..block_json_str.len().min(200)];
                eprintln!(
                    "PARSE FAIL height={} blob_len={} err={}",
                    height, entry.block.len(), snippet
                );
                if first_error_height.is_none() {
                    first_error_height = Some(height);
                }
            }
        }

        current = batch_end + 1;
    }

    println!();
    println!("=== Range Scan Summary ===");
    println!("Range:          {}..{}", range_start, range_end);
    println!("Blocks scanned: {}", total_blocks);
    println!("Parse errors:   {}", total_parse_errors);
    println!("Empty blobs:    {}", total_empty_blobs);
    if let Some(h) = first_error_height {
        println!("First error at: {}", h);
    } else {
        println!("No errors found in this range.");
    }
}
