//! Debug: fetch a mined block and inspect the miner TX parsing.
//! Run: cargo test -p salvium-wallet --test debug_scan -- --ignored --nocapture

use salvium_rpc::daemon::DaemonRpc;
use salvium_wallet::{decrypt_js_wallet, Wallet};
use salvium_types::constants::Network;

const DAEMON_URL: &str = "http://node12.whiskymine.io:29081";

#[tokio::test]
#[ignore]
async fn debug_block_1230() {
    let daemon = DaemonRpc::new(DAEMON_URL);

    // Check output types across different block ranges.
    for height in [1u64, 100, 500, 1000, 1100, 1200, 1230, 1300] {
        let block = daemon.get_block(height).await.expect("get_block failed");
        let blob = hex::decode(&block.blob).expect("hex decode");
        let json_str = salvium_crypto::parse_block_bytes(&blob);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
            if let Some(miner_tx) = val.get("minerTx") {
                if let Some(prefix) = miner_tx.get("prefix") {
                    if let Some(vout) = prefix.get("vout").and_then(|v| v.as_array()) {
                        for out in vout {
                            let out_type = out.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
                            let amount = out.get("amount").and_then(|v| v.as_str()).unwrap_or("?");
                            let vt = out.get("viewTag").and_then(|v| v.as_str()).unwrap_or("none");
                            let asset = out.get("assetType").and_then(|v| v.as_str()).unwrap_or("?");
                            println!("Block {}: type={}, amount={}, viewTag={}, asset={}", height, out_type, amount, vt, asset);
                        }
                    }
                }
            }
        }
    }

    // Now detailed analysis of block 1230.
    let block = daemon.get_block(1230).await.expect("get_block failed");
    println!("Block 1230 hash: {}", block.block_header.hash);
    println!("Miner TX hash: {}", block.miner_tx_hash);
    println!("TX hashes in block: {:?}", block.tx_hashes);
    println!("Blob length: {}", block.blob.len());

    // Parse the block blob.
    let block_blob = hex::decode(&block.blob).expect("hex decode failed");
    let block_json_str = salvium_crypto::parse_block_bytes(&block_blob);
    println!("\n=== Parsed block JSON ===");
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&block_json_str) {
        println!("{}", serde_json::to_string_pretty(&val).unwrap());
    } else {
        println!("Failed to parse as JSON: {}", &block_json_str[..200.min(block_json_str.len())]);
    }

    // Decrypt wallet-a to get keys.
    let dir = dirs::home_dir().unwrap().join("testnet-wallet");
    let wallet_json = std::fs::read_to_string(dir.join("wallet-a.json")).unwrap();
    let pin = std::fs::read_to_string(dir.join("wallet-a.pin")).unwrap().trim().to_string();
    let secrets = decrypt_js_wallet(&wallet_json, &pin).unwrap();

    println!("\n=== Wallet A keys ===");
    println!("View secret: {}", hex::encode(secrets.view_secret_key));
    println!("Spend secret: {}", hex::encode(secrets.spend_secret_key));

    let view_pub = salvium_crypto::scalar_mult_base(&secrets.view_secret_key);
    let spend_pub = salvium_crypto::scalar_mult_base(&secrets.spend_secret_key);
    println!("View pub: {}", hex::encode(&view_pub[..32]));
    println!("Spend pub: {}", hex::encode(&spend_pub[..32]));

    // Create wallet and check scan context.
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("debug.db");
    let wallet = Wallet::create(secrets.seed, Network::Testnet, db_path.to_str().unwrap(), &[0u8; 32]).unwrap();

    let keys = wallet.keys();
    println!("\n=== Wallet keys from seed ===");
    println!("CN view secret: {}", hex::encode(keys.cn.view_secret_key));
    println!("CN spend pub: {}", hex::encode(keys.cn.spend_public_key));
    println!("CN view pub: {}", hex::encode(keys.cn.view_public_key));
    println!("Keys match JS?: view={}, spend_pub={}",
        keys.cn.view_secret_key == secrets.view_secret_key,
        hex::encode(keys.cn.spend_public_key) == hex::encode(&spend_pub[..32]));

    let ctx = wallet.scan_context();
    println!("\n=== Scan context ===");
    println!("CN subaddress map entries: {}", ctx.cn_subaddress_map.len());
    println!("CARROT subaddress map entries: {}", ctx.carrot_subaddress_map.len());
    println!("CARROT enabled: {}", ctx.carrot_enabled);

    if !ctx.cn_subaddress_map.is_empty() {
        println!("First CN subaddr entry: key={}, major={}, minor={}",
            hex::encode(ctx.cn_subaddress_map[0].0),
            ctx.cn_subaddress_map[0].1,
            ctx.cn_subaddress_map[0].2);
    }

    // Try to manually scan the miner TX of block 1230.
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&block_json_str) {
        if let Some(miner_tx) = val.get("miner_tx") {
            println!("\n=== Miner TX fields ===");
            if let Some(extra) = miner_tx.get("extra") {
                println!("Extra: {:?}", extra);
            }
            if let Some(vout) = miner_tx.get("vout") {
                println!("Vout count: {}", vout.as_array().map_or(0, |a| a.len()));
                if let Some(arr) = vout.as_array() {
                    for (i, out) in arr.iter().enumerate() {
                        println!("  Output {}: {:?}", i, out);
                    }
                }
            }

            // Try extracting tx_pub_key from extra.
            if let Some(extra) = miner_tx.get("extra").and_then(|v| v.as_array()) {
                let bytes: Vec<u8> = extra.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
                println!("\nExtra bytes ({} total): {:?}", bytes.len(), &bytes[..bytes.len().min(40)]);
                for i in 0..bytes.len() {
                    if bytes[i] == 0x01 && i + 33 <= bytes.len() {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes[i + 1..i + 33]);
                        println!("Found tx_pub_key at offset {}: {}", i, hex::encode(key));

                        // Try key derivation.
                        let derivation = salvium_crypto::generate_key_derivation(&key, &secrets.view_secret_key);
                        println!("Derivation: {} ({} bytes)", hex::encode(&derivation), derivation.len());

                        if derivation.len() == 32 {
                            let mut d = [0u8; 32];
                            d.copy_from_slice(&derivation);
                            // Derive expected output key for index 0.
                            let derived_pub = salvium_crypto::derive_public_key(&d, 0, &keys.cn.spend_public_key);
                            println!("Derived output pub key (idx 0): {}", hex::encode(&derived_pub));

                            // Check against actual output key.
                            if let Some(vout) = miner_tx.get("vout").and_then(|v| v.as_array()) {
                                if let Some(first_out) = vout.first() {
                                    if let Some(target) = first_out.get("target") {
                                        let actual_key = if let Some(tk) = target.get("tagged_key") {
                                            tk.get("key").and_then(|k| k.as_str()).map(String::from)
                                        } else if let Some(k) = target.get("key") {
                                            k.as_str().map(String::from)
                                        } else {
                                            None
                                        };
                                        if let Some(ak) = actual_key {
                                            println!("Actual output key: {}", ak);
                                            println!("Match: {}", hex::encode(&derived_pub) == ak);
                                        }
                                    }
                                }
                            }
                        }

                        break;
                    }
                }
            }
        } else {
            println!("\nNo miner_tx found in parsed block JSON");
        }
    }
}
