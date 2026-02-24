//! Debug: inspect protocol_tx content at various heights.
//!
//! Run with: cargo test -p salvium-wallet --test debug_protocol_tx -- --nocapture --ignored

use salvium_rpc::DaemonRpc;

#[tokio::test]
#[ignore]
async fn debug_protocol_tx_content() {
    let daemon = DaemonRpc::new("http://node12.whiskymine.io:19081");
    let info = daemon.get_info().await.expect("daemon unreachable");
    let top = info.height;
    println!("Daemon height: {}\n", top);

    // Check blocks at various heights where protocol_tx returns might exist.
    // Stake heights from the first wallet: 270519, 277516, 281006, 288004, 289006,
    // 292306, 293006, 293506, 310308, 355606, 362506, 379108
    // Returns would be at approximately stake_height + 21600.
    let check_ranges: Vec<(u64, u64, &str)> = vec![
        // Around earliest returns
        (292100, 292200, "earliest return range (~270519+21600)"),
        // Around mid returns
        (299100, 299200, "mid return range (~277516+21600)"),
        // Around later returns
        (310500, 310600, "later return range (~288004+21600)"),
        // Post-CARROT transition
        (417800, 417850, "HF10 CARROT transition"),
        // Recent blocks (known to work)
        (
            top.saturating_sub(10),
            top.saturating_sub(1),
            "recent blocks",
        ),
    ];

    for (start, end, label) in &check_ranges {
        let end = (*end).min(top.saturating_sub(1));
        let start = *start;
        if start >= end {
            continue;
        }

        println!("=== {} (heights {}-{}) ===", label, start, end);

        let heights: Vec<u64> = (start..=end).collect();
        let blocks = match daemon.get_blocks_by_height_bin(&heights).await {
            Ok(b) => b,
            Err(e) => {
                println!("  Failed to fetch: {}\n", e);
                continue;
            }
        };

        let mut found_with_outputs = 0;

        for (i, entry) in blocks.iter().enumerate() {
            let height = heights[i];
            let block_json_str = salvium_crypto::parse_block_bytes(&entry.block);
            let parsed: serde_json::Value = match serde_json::from_str(&block_json_str) {
                Ok(v) => v,
                Err(e) => {
                    println!("  Height {}: PARSE ERROR: {}", height, e);
                    continue;
                }
            };

            if let Some(ptx) = parsed.get("protocolTx") {
                let prefix = ptx.get("prefix").unwrap_or(ptx);
                let vout = prefix.get("vout").and_then(|v| v.as_array());
                let out_count = vout.map(|v| v.len()).unwrap_or(0);
                let tx_type_val = prefix.get("txType").and_then(|v| v.as_u64()).unwrap_or(0);

                if out_count > 0 {
                    found_with_outputs += 1;

                    let has_pubkey = prefix
                        .get("extra")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .any(|e| e.get("type").and_then(|v| v.as_u64()) == Some(1))
                        })
                        .unwrap_or(false);

                    let has_additional = prefix
                        .get("extra")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .any(|e| e.get("type").and_then(|v| v.as_u64()) == Some(4))
                        })
                        .unwrap_or(false);

                    // Only print first 3 matches per range
                    if found_with_outputs <= 3 {
                        println!(
                            "  Height {}: {} outputs, txType={}, pubkey={}, additional={}",
                            height, out_count, tx_type_val, has_pubkey, has_additional
                        );

                        let extra = prefix.get("extra");
                        println!("    extra: {:?}", extra);

                        for (j, out) in vout.unwrap().iter().enumerate().take(3) {
                            let asset =
                                out.get("assetType").and_then(|v| v.as_str()).unwrap_or("?");
                            let amount = out.get("amount").and_then(|v| v.as_str()).unwrap_or("?");
                            let out_type = out.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
                            let key = out.get("key").and_then(|v| v.as_str()).unwrap_or("?");
                            println!(
                                "    out[{}]: type={} asset={} amount={} key={}...",
                                j,
                                out_type,
                                asset,
                                amount,
                                &key[..key.len().min(16)]
                            );
                        }
                    }
                }
            }
        }

        let total_blocks = heights.len();
        println!(
            "  {}/{} blocks had protocol_tx outputs\n",
            found_with_outputs, total_blocks
        );
    }
}
