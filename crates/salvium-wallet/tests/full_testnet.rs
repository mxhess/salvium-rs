//! Full Testnet Hardfork Progression Test.
//!
//! Mines from genesis through all 10 hard forks, testing transfers/stakes/burns/sweeps
//! at each era boundary. This is the critical integration test that proves the entire
//! Rust stack works end-to-end against a real daemon.
//!
//! Ported from: test/legacy-js/full-testnet.js
//!
//! Pre-requisites:
//!   cargo build -p salvium-miner --release
//!
//! Run:
//!   cargo test -p salvium-wallet --test full_testnet -- --ignored --nocapture
//!
//! With custom daemon:
//!   TESTNET_DAEMON_URL=http://localhost:29081 cargo test -p salvium-wallet --test full_testnet -- --ignored --nocapture
//!
//! Resume from a specific fork:
//!   RESUME_FROM_HF=6 cargo test -p salvium-wallet --test full_testnet -- --ignored --nocapture

use salvium_rpc::daemon::{DaemonRpc, OutputRequest};
use salvium_tx::builder::{Destination, PreparedInput, TransactionBuilder};
use salvium_tx::decoy::{DecoySelector, DEFAULT_RING_SIZE};
use salvium_tx::fee::{self, FeePriority};
use salvium_tx::sign::sign_transaction;
use salvium_tx::types::{output_type, tx_type, Transaction, TxInput};
use salvium_wallet::utxo::SelectionStrategy;
use salvium_wallet::{decrypt_js_wallet, Wallet};
use salvium_types::address::parse_address;
use salvium_types::constants::Network;

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

// ─── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_DAEMON: &str = "http://node12.whiskymine.io:29081";
const MATURITY_OFFSET: u64 = 80; // blocks after fork for coinbase maturity
const MATURITY_BLOCKS: u64 = 10; // blocks after TX for spendable age
const COIN: u64 = 100_000_000; // 1 SAL in atomic units
const MINER_THREADS: usize = 4;
const MINER_RETRIES: usize = 3;

// ─── Fork Table ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum AddrFormat {
    Legacy,
    Carrot,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TestMode {
    Genesis,
    Full,
    Lightweight,
    Paused,
}

#[derive(Debug, Clone, Copy)]
struct ForkSpec {
    hf: u8,
    height: u64,
    asset: &'static str,
    addr_format: AddrFormat,
    test_mode: TestMode,
    rct_type: u8,
}

static FORKS: &[ForkSpec] = &[
    ForkSpec { hf: 1,  height: 1,    asset: "SAL",  addr_format: AddrFormat::Legacy, test_mode: TestMode::Genesis,     rct_type: 6 },
    ForkSpec { hf: 2,  height: 250,  asset: "SAL",  addr_format: AddrFormat::Legacy, test_mode: TestMode::Full,        rct_type: 6 },
    ForkSpec { hf: 3,  height: 500,  asset: "SAL",  addr_format: AddrFormat::Legacy, test_mode: TestMode::Lightweight, rct_type: 7 },
    ForkSpec { hf: 4,  height: 600,  asset: "SAL",  addr_format: AddrFormat::Legacy, test_mode: TestMode::Lightweight, rct_type: 7 },
    ForkSpec { hf: 5,  height: 800,  asset: "SAL",  addr_format: AddrFormat::Legacy, test_mode: TestMode::Paused,      rct_type: 7 },
    ForkSpec { hf: 6,  height: 815,  asset: "SAL1", addr_format: AddrFormat::Legacy, test_mode: TestMode::Full,        rct_type: 8 },
    ForkSpec { hf: 7,  height: 900,  asset: "SAL1", addr_format: AddrFormat::Legacy, test_mode: TestMode::Paused,      rct_type: 8 },
    ForkSpec { hf: 8,  height: 950,  asset: "SAL1", addr_format: AddrFormat::Legacy, test_mode: TestMode::Paused,      rct_type: 8 },
    ForkSpec { hf: 9,  height: 1000, asset: "SAL1", addr_format: AddrFormat::Legacy, test_mode: TestMode::Paused,      rct_type: 8 },
    ForkSpec { hf: 10, height: 1100, asset: "SAL1", addr_format: AddrFormat::Carrot, test_mode: TestMode::Full,        rct_type: 9 },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn sal(n: f64) -> u64 {
    (n * COIN as f64).round() as u64
}

fn fmt_sal(atomic: u64) -> String {
    format!("{:.8}", atomic as f64 / COIN as f64)
}

fn fmt_duration(secs: f64) -> String {
    if secs < 60.0 {
        format!("{:.1}s", secs)
    } else if secs < 3600.0 {
        format!("{}m {}s", secs as u64 / 60, secs as u64 % 60)
    } else {
        format!(
            "{}h {}m",
            secs as u64 / 3600,
            (secs as u64 % 3600) / 60
        )
    }
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

fn testnet_wallet_dir() -> PathBuf {
    dirs::home_dir().unwrap().join("testnet-wallet")
}

fn daemon_url() -> String {
    std::env::var("TESTNET_DAEMON_URL").unwrap_or_else(|_| DEFAULT_DAEMON.to_string())
}

fn resume_from_hf() -> u8 {
    std::env::var("RESUME_FROM_HF")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

async fn get_daemon_height(daemon: &DaemonRpc) -> u64 {
    let info = daemon.get_info().await.expect("failed to get daemon info");
    info.height
}

fn miner_binary_path() -> PathBuf {
    // Look relative to the workspace root
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let release = workspace.join("target/release/salvium-miner");
    if release.exists() {
        return release;
    }
    let debug = workspace.join("target/debug/salvium-miner");
    if debug.exists() {
        return debug;
    }
    panic!(
        "salvium-miner binary not found. Run: cargo build -p salvium-miner --release\n  Checked: {}\n  Checked: {}",
        release.display(),
        debug.display()
    );
}

// ─── Mining Orchestrator ─────────────────────────────────────────────────────

struct MiningStats {
    blocks_mined: u64,
    elapsed_secs: f64,
}

/// Mine blocks until the daemon reaches `target_height`.
async fn mine_to(
    daemon: &DaemonRpc,
    target_height: u64,
    address: &str,
    daemon_url: &str,
) -> MiningStats {
    let current = get_daemon_height(daemon).await;
    if current >= target_height {
        println!(
            "  Already at height {} (target {}), skipping",
            current, target_height
        );
        return MiningStats {
            blocks_mined: 0,
            elapsed_secs: 0.0,
        };
    }

    let blocks_needed = target_height - current;
    println!(
        "  Mining {} blocks ({} -> {})...",
        blocks_needed, current, target_height
    );

    let t0 = Instant::now();
    let miner_path = miner_binary_path();

    for attempt in 1..=MINER_RETRIES {
        let mut child = Command::new(&miner_path)
            .args([
                "--daemon",
                daemon_url,
                "--wallet",
                address,
                "--threads",
                &MINER_THREADS.to_string(),
                "--light",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn salvium-miner");

        let stderr = child.stderr.take().unwrap();
        let mut reader = BufReader::new(stderr).lines();
        let mut accepted_count = 0u64;

        while let Ok(Some(line)) = reader.next_line().await {
            if line.contains("Block accepted!") {
                accepted_count += 1;
                if accepted_count.is_multiple_of(50) || accepted_count >= blocks_needed {
                    println!("    {} blocks accepted...", accepted_count);
                }
            }
            if line.contains("Block rejected:") {
                eprintln!("    WARNING: {}", line);
            }

            // Check if we've reached target
            if accepted_count >= blocks_needed {
                break;
            }
        }

        // Kill the miner
        let _ = child.kill().await;
        let _ = child.wait().await;

        // Verify height
        let final_height = get_daemon_height(daemon).await;
        if final_height >= target_height {
            let elapsed = t0.elapsed().as_secs_f64();
            let mined = final_height - current;
            println!(
                "  Reached height {} in {} ({} blocks)",
                final_height,
                fmt_duration(elapsed),
                mined
            );
            return MiningStats {
                blocks_mined: mined,
                elapsed_secs: elapsed,
            };
        }

        if attempt < MINER_RETRIES {
            println!(
                "  Miner stopped at height {} (target {}), retrying ({}/{})...",
                final_height, target_height, attempt, MINER_RETRIES
            );
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }

    let final_height = get_daemon_height(daemon).await;
    panic!(
        "Failed to mine to height {} after {} attempts (stuck at {})",
        target_height, MINER_RETRIES, final_height
    );
}

// ─── Test Fixture ────────────────────────────────────────────────────────────

struct TestFixture {
    wallet_a: Wallet,
    wallet_b: Wallet,
    _tmp_a: tempfile::TempDir,
    _tmp_b: tempfile::TempDir,
}

impl TestFixture {
    fn create() -> Self {
        let dir = testnet_wallet_dir();

        // Wallet A
        let wallet_a_json = std::fs::read_to_string(dir.join("wallet-a.json"))
            .expect("wallet-a.json not found in ~/testnet-wallet/");
        let pin_a = std::fs::read_to_string(dir.join("wallet-a.pin"))
            .expect("wallet-a.pin not found")
            .trim()
            .to_string();
        let secrets_a = decrypt_js_wallet(&wallet_a_json, &pin_a)
            .expect("failed to decrypt wallet-a");

        let tmp_a = tempfile::tempdir().expect("failed to create temp dir");
        let db_path_a = tmp_a.path().join("wallet-a.db");
        let wallet_a =
            Wallet::create(secrets_a.seed, Network::Testnet, db_path_a.to_str().unwrap(), &[0u8; 32])
                .expect("failed to create wallet A");

        // Wallet B
        let wallet_b_json = std::fs::read_to_string(dir.join("wallet-b.json"))
            .expect("wallet-b.json not found in ~/testnet-wallet/");
        let pin_b = std::fs::read_to_string(dir.join("wallet-b.pin"))
            .expect("wallet-b.pin not found")
            .trim()
            .to_string();
        let secrets_b = decrypt_js_wallet(&wallet_b_json, &pin_b)
            .expect("failed to decrypt wallet-b");

        let tmp_b = tempfile::tempdir().expect("failed to create temp dir");
        let db_path_b = tmp_b.path().join("wallet-b.db");
        let wallet_b =
            Wallet::create(secrets_b.seed, Network::Testnet, db_path_b.to_str().unwrap(), &[0u8; 32])
                .expect("failed to create wallet B");

        TestFixture {
            wallet_a,
            wallet_b,
            _tmp_a: tmp_a,
            _tmp_b: tmp_b,
        }
    }
}

// ─── Test Transactor ─────────────────────────────────────────────────────────

struct TestTransactor<'a> {
    daemon: &'a DaemonRpc,
    wallet: &'a Wallet,
}

struct TxResult {
    tx_hash: String,
    fee: u64,
}

impl<'a> TestTransactor<'a> {
    fn new(daemon: &'a DaemonRpc, wallet: &'a Wallet) -> Self {
        Self { daemon, wallet }
    }

    /// Mark the inputs of a signed transaction as spent in the wallet DB.
    /// This prevents re-spending when multiple TXs are submitted before mining.
    fn mark_inputs_spent(&self, signed: &Transaction, tx_hash: &str) {
        for input in &signed.prefix.inputs {
            if let TxInput::Key { key_image, .. } = input {
                let ki_hex = hex::encode(key_image);
                let _ = self.wallet.mark_output_spent(&ki_hex, tx_hash);
            }
        }
    }

    /// Prepare inputs: select UTXOs, resolve asset-type indices, build rings.
    async fn prepare_inputs(
        &self,
        amount: u64,
        estimated_fee: u64,
        fork: &ForkSpec,
    ) -> Vec<PreparedInput> {
        let db_asset_type = self.db_asset_type(fork);

        // Select outputs based on era.
        // CARROT outputs only exist at HF10+; before that, all outputs are legacy CryptoNote.
        // Use select_outputs for ALL eras — the wallet may contain a mix of
        // legacy and CARROT outputs. The is_carrot flag on each output tells
        // prepare_inputs how to derive spending keys.
        let selection = self.wallet
            .select_outputs(amount, estimated_fee, db_asset_type, SelectionStrategy::Default)
            .expect("output selection failed");
        println!(
            "    Selected {} output(s), total: {} SAL, change: {} SAL",
            selection.selected.len(),
            fmt_sal(selection.total),
            fmt_sal(selection.change),
        );

        // Resolve TX block heights
        let mut tx_hashes: Vec<String> = selection
            .selected
            .iter()
            .map(|u| {
                self.wallet
                    .get_output(&u.key_image)
                    .unwrap()
                    .unwrap()
                    .tx_hash
                    .clone()
            })
            .collect();
        tx_hashes.sort();
        tx_hashes.dedup();

        let tx_hash_refs: Vec<&str> = tx_hashes.iter().map(|s| s.as_str()).collect();
        let tx_entries = self
            .daemon
            .get_transactions(&tx_hash_refs, false)
            .await
            .expect("failed to get transactions");

        let keys = self.wallet.keys();
        let mut prepared_inputs = Vec::new();

        // Cache distributions per asset type (SAL and SAL1 may have separate distributions)
        let mut dist_cache: std::collections::HashMap<String, (Vec<u64>, u64)> = std::collections::HashMap::new();

        for utxo in &selection.selected {
            let output_row = self
                .wallet
                .get_output(&utxo.key_image)
                .unwrap()
                .unwrap();
            let output_pub_key = hex_to_32(output_row.public_key.as_ref().unwrap());

            // Find block height
            let entry = tx_entries
                .iter()
                .zip(tx_hashes.iter())
                .find(|(_, h)| **h == output_row.tx_hash)
                .map(|(e, _)| e)
                .expect("tx not found in entries");

            // Determine the ring asset type. The daemon has separate distributions
            // for "SAL" (pre-HF6) and "SAL1" (post-HF6). Our wallet DB may store
            // post-HF6 outputs as "SAL" if the scanner doesn't detect SAL1. Try the
            // stored type first, then the equivalent type.
            let stored_asset = &output_row.asset_type;
            let equivalent_asset = if stored_asset == "SAL" { "SAL1" } else { "SAL" };
            let candidates_to_try = [stored_asset.as_str(), equivalent_asset];

            let mut ring_asset_resolved: Option<String> = None;
            let mut resolved_distribution: Option<Vec<u64>> = None;
            let mut _resolved_start_height: u64 = 0;
            let mut resolved_at_index: u64 = 0;

            for try_asset in &candidates_to_try {
                // Get or fetch the distribution for this asset type
                let try_asset_str = try_asset.to_string();
                if !dist_cache.contains_key(&try_asset_str) {
                    let dist = self
                        .daemon
                        .get_output_distribution(&[0], 0, 0, true, try_asset)
                        .await
                        .expect("failed to get output distribution");
                    dist_cache.insert(
                        try_asset_str.clone(),
                        (dist[0].distribution.clone(), dist[0].start_height),
                    );
                }
                let (ref distribution, start_height) = dist_cache[&try_asset_str];

                if entry.block_height < start_height {
                    continue; // This distribution doesn't cover the output's height
                }
                let h_idx = (entry.block_height - start_height) as usize;
                if h_idx >= distribution.len() {
                    continue;
                }
                let at_start = if h_idx == 0 { 0 } else { distribution[h_idx - 1] };
                let at_end = distribution[h_idx];
                let at_count = at_end - at_start;

                if at_count == 0 {
                    continue; // No outputs of this type at this height, try equivalent
                }

                let asset_type_index = if at_count == 1 {
                    at_start
                } else {
                    let candidates: Vec<OutputRequest> = (at_start..at_end)
                        .map(|idx| OutputRequest {
                            amount: 0,
                            index: idx,
                        })
                        .collect();
                    let probe = self
                        .daemon
                        .get_outs(&candidates, false, try_asset)
                        .await
                        .expect("failed to probe outputs");
                    match probe
                        .iter()
                        .enumerate()
                        .find(|(_, out)| out.key == *output_row.public_key.as_ref().unwrap())
                    {
                        Some((i, _)) => at_start + i as u64,
                        None => continue, // Not found in this distribution
                    }
                };

                ring_asset_resolved = Some(try_asset_str);
                resolved_distribution = Some(distribution.clone());
                _resolved_start_height = start_height;
                resolved_at_index = asset_type_index;
                break;
            }

            let ring_asset = ring_asset_resolved.unwrap_or_else(|| {
                panic!(
                    "output not found in any asset distribution at height {} for tx {}",
                    entry.block_height, output_row.tx_hash
                )
            });
            let distribution = resolved_distribution.unwrap();
            let decoy_selector =
                DecoySelector::new(distribution).expect("failed to create decoy selector");
            let asset_type_index = resolved_at_index;

            // Derive spending keys
            let (secret_key, secret_key_y, public_key) = if output_row.is_carrot {
                let prove_spend_key = keys.carrot.prove_spend_key.expect("not a full wallet");
                let generate_image_key = keys.carrot.generate_image_key;
                let shared_secret =
                    hex_to_32(output_row.carrot_shared_secret.as_ref().unwrap());
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
                    &prove_spend_key,
                    &generate_image_key,
                    &shared_secret,
                    &commitment,
                );
                (sk_x, Some(sk_y), output_pub_key)
            } else {
                let spend_secret = keys.cn.spend_secret_key.expect("not a full wallet");
                let view_secret = keys.cn.view_secret_key;
                let tx_pub_key =
                    hex_to_32(output_row.tx_pub_key.as_ref().unwrap());
                let sk = salvium_crypto::cn_scan::derive_output_spend_key(
                    &view_secret,
                    &spend_secret,
                    &tx_pub_key,
                    output_row.output_index as u32,
                    output_row.subaddress_index.major as u32,
                    output_row.subaddress_index.minor as u32,
                );
                let pk = to_32(&salvium_crypto::scalar_mult_base(&sk));
                // For TCLSAG (rct_type >= 9), legacy outputs need secret_key_y = 0.
                // The C++ code sets ctkey.y = rct::zero() for non-CARROT outputs.
                let sk_y = if fork.rct_type >= 9 {
                    Some([0u8; 32])
                } else {
                    None
                };
                (sk, sk_y, pk)
            };

            let mask = hex_to_32(output_row.mask.as_ref().expect("missing mask"));

            // Build ring
            let (ring_indices, real_pos) = decoy_selector
                .build_ring(asset_type_index, DEFAULT_RING_SIZE)
                .expect("failed to build ring");
            let out_requests: Vec<OutputRequest> = ring_indices
                .iter()
                .map(|&idx| OutputRequest {
                    amount: 0,
                    index: idx,
                })
                .collect();
            let ring_members = self
                .daemon
                .get_outs(&out_requests, false, &ring_asset)
                .await
                .expect("failed to fetch ring members");

            // Diagnostic: verify the derived public key matches ring at real position
            let ring_pub_keys: Vec<[u8; 32]> = ring_members.iter().map(|m| hex_to_32(&m.key)).collect();
            if public_key != ring_pub_keys[real_pos] {
                eprintln!("    WARNING: derived pk != ring[real_pos]!");
                eprintln!("      derived pk:    {}", hex::encode(public_key));
                eprintln!("      ring[{}]:   {}", real_pos, hex::encode(ring_pub_keys[real_pos]));
                eprintln!("      output_pub_key: {}", hex::encode(output_pub_key));
            }
            eprintln!("    Input: asset_idx={}, ring_size={}, real_pos={}, ring_indices={:?}",
                asset_type_index, ring_indices.len(), real_pos, &ring_indices[..ring_indices.len().min(5)]);

            prepared_inputs.push(PreparedInput {
                secret_key,
                secret_key_y,
                public_key,
                amount: utxo.amount,
                mask,
                asset_type: ring_asset.to_string(),
                global_index: asset_type_index,
                ring: ring_pub_keys,
                ring_commitments: ring_members.iter().map(|m| hex_to_32(&m.mask)).collect(),
                ring_indices,
                real_index: real_pos,
            });
        }

        prepared_inputs
    }

    /// Estimate fee using daemon's dynamic fee rate.
    async fn estimate_fee(&self, n_inputs: usize, n_outputs: usize, fork: &ForkSpec) -> u64 {
        let fee_estimate = self
            .daemon
            .get_fee_estimate(10)
            .await
            .expect("failed to get fee estimate");
        let out_type = if fork.hf >= 10 {
            output_type::CARROT_V1
        } else {
            output_type::TAGGED_KEY
        };
        let est_weight = fee::estimate_tx_weight(n_inputs, n_outputs, DEFAULT_RING_SIZE, true, out_type);
        (est_weight as u64) * fee_estimate.fee * FeePriority::Normal.multiplier()
    }

    fn db_asset_type(&self, fork: &ForkSpec) -> &str {
        // SAL and SAL1 are equivalent asset types. After HF6, the active asset
        // becomes SAL1 but old SAL outputs remain spendable. We query "SAL"
        // because that's what our pre-HF6 mined outputs are stored as.
        // When SAL1 coinbase outputs start appearing they'll be stored as "SAL1",
        // but for now the wallet's SAL balance covers both.
        if fork.hf >= 6 {
            // Try SAL1 first (post-HF6 coinbase), fall back to SAL (pre-HF6)
            let sal1_balance = self.wallet.get_balance("SAL1", 0);
            let has_sal1 = sal1_balance
                .map(|b| b.unlocked_balance.parse::<u64>().unwrap_or(0) > 0)
                .unwrap_or(false);
            if has_sal1 {
                "SAL1"
            } else {
                "SAL"
            }
        } else {
            "SAL"
        }
    }

    /// Build, sign, and submit a TRANSFER transaction.
    async fn transfer(
        &self,
        dest_spend: [u8; 32],
        dest_view: [u8; 32],
        amount: u64,
        fork: &ForkSpec,
    ) -> TxResult {
        let estimated_fee = self.estimate_fee(1, 2, fork).await;
        let inputs = self.prepare_inputs(amount, estimated_fee, fork).await;

        let mut builder = TransactionBuilder::new();
        for input in inputs {
            builder = builder.add_input(input);
        }

        let (chg_spend, chg_view) = change_keys(self.wallet, fork);
        builder = builder
            .add_destination(Destination {
                spend_pubkey: dest_spend,
                view_pubkey: dest_view,
                amount,
                asset_type: fork.asset.to_string(),
                payment_id: [0u8; 8],
                is_subaddress: false,
            })
            .set_change_address(chg_spend, chg_view)
            .set_asset_types(fork.asset, fork.asset)
            .set_rct_type(fork.rct_type)
            .set_fee(estimated_fee);

        let unsigned = builder.build().expect("failed to build transfer TX");
        let fee = unsigned.fee;
        let signed = sign_transaction(unsigned).expect("failed to sign transfer TX");
        let tx_hash = hex::encode(signed.tx_hash().expect("tx hash"));
        let tx_bytes = signed.to_bytes().expect("serialize TX");

        // Roundtrip verification: parse the bytes back and re-serialize
        let parsed_json = salvium_crypto::tx_parse::parse_transaction(&tx_bytes)
            .expect("failed to parse our own TX");
        let re_serialized = salvium_crypto::tx_serialize::serialize_transaction(&parsed_json)
            .expect("failed to re-serialize TX");
        if tx_bytes != re_serialized {
            eprintln!("    ROUNDTRIP MISMATCH: {} bytes vs {} bytes", tx_bytes.len(), re_serialized.len());
            for (i, (a, b)) in tx_bytes.iter().zip(re_serialized.iter()).enumerate() {
                if a != b {
                    eprintln!("    First diff at byte {}: {:02x} vs {:02x}", i, a, b);
                    break;
                }
            }
        } else {
            eprintln!("    Roundtrip OK ({} bytes)", tx_bytes.len());
        }

        // Print parsed transaction summary
        let pj = &parsed_json;
        eprintln!("    Parsed TX: {}", serde_json::to_string_pretty(pj).unwrap_or("?".to_string()).lines().take(30).collect::<Vec<_>>().join("\n    "));

        let tx_hex = hex::encode(&tx_bytes);

        let result = self
            .daemon
            .send_raw_transaction_ex(&tx_hex, false, true, fork.asset)
            .await
            .expect("RPC send failed");
        if result.status != "OK" {
            eprintln!("    DAEMON REJECT: {:?}", result);
            eprintln!("    TX hex ({} bytes): {}...{}", tx_bytes.len(), &tx_hex[..80], &tx_hex[tx_hex.len()-40..]);
        }
        assert_eq!(
            result.status, "OK",
            "transfer TX rejected: {} (reason: {})",
            result.status, result.reason
        );

        // Mark spent inputs in the wallet DB so we don't re-spend them.
        self.mark_inputs_spent(&signed, &tx_hash);

        TxResult { tx_hash, fee }
    }

    /// Build, sign, and submit a STAKE transaction.
    async fn stake(&self, amount: u64, fork: &ForkSpec) -> TxResult {
        // STAKE: the staked amount goes into amount_burnt (protocol pool).
        // Only 1 output: the change (total_input - amount_burnt - fee).
        let estimated_fee = self.estimate_fee(1, 1, fork).await;
        let inputs = self.prepare_inputs(amount, estimated_fee, fork).await;

        let current_height = get_daemon_height(self.daemon).await;
        let unlock_time = current_height + 20; // testnet stake lock period

        let keys = self.wallet.keys();
        let mut builder = TransactionBuilder::new();
        for input in inputs {
            builder = builder.add_input(input);
        }

        let (chg_spend, chg_view) = change_keys(self.wallet, fork);
        builder = builder
            .set_change_address(chg_spend, chg_view)
            .set_tx_type(tx_type::STAKE)
            .set_unlock_time(unlock_time)
            .set_asset_types(fork.asset, fork.asset)
            .set_rct_type(fork.rct_type)
            .set_fee(estimated_fee)
            .set_amount_burnt(amount)
            .set_view_secret_key(keys.cn.view_secret_key);

        let unsigned = builder.build().expect("failed to build STAKE TX");
        let fee = unsigned.fee;
        let signed = sign_transaction(unsigned).expect("failed to sign STAKE TX");
        let tx_hash = hex::encode(signed.tx_hash().expect("tx hash"));
        let tx_bytes = signed.to_bytes().expect("serialize TX");
        let tx_hex = hex::encode(&tx_bytes);

        let result = self
            .daemon
            .send_raw_transaction_ex(&tx_hex, false, true, fork.asset)
            .await
            .expect("RPC send failed");
        assert_eq!(
            result.status, "OK",
            "STAKE TX rejected: {} (reason: {})",
            result.status, result.reason
        );

        self.mark_inputs_spent(&signed, &tx_hash);

        TxResult { tx_hash, fee }
    }

    /// Build, sign, and submit a BURN transaction.
    async fn burn(&self, amount: u64, fork: &ForkSpec) -> TxResult {
        // BURN: 1 input, 1 output (change only)
        let estimated_fee = self.estimate_fee(1, 1, fork).await;
        let inputs = self.prepare_inputs(amount, estimated_fee, fork).await;

        let mut builder = TransactionBuilder::new();
        for input in inputs {
            builder = builder.add_input(input);
        }

        let (chg_spend, chg_view) = change_keys(self.wallet, fork);
        builder = builder
            .add_destination(Destination {
                spend_pubkey: chg_spend,
                view_pubkey: chg_view,
                amount,
                asset_type: fork.asset.to_string(),
                payment_id: [0u8; 8],
                is_subaddress: false,
            })
            .set_change_address(chg_spend, chg_view)
            .set_tx_type(tx_type::BURN)
            .set_amount_burnt(amount)
            .set_unlock_time(0)
            .set_asset_types(fork.asset, "BURN")
            .set_rct_type(fork.rct_type)
            .set_fee(estimated_fee);

        let unsigned = builder.build().expect("failed to build BURN TX");
        let fee = unsigned.fee;
        let signed = sign_transaction(unsigned).expect("failed to sign BURN TX");
        let tx_hash = hex::encode(signed.tx_hash().expect("tx hash"));
        let tx_bytes = signed.to_bytes().expect("serialize TX");
        let tx_hex = hex::encode(&tx_bytes);

        let result = self
            .daemon
            .send_raw_transaction_ex(&tx_hex, false, true, fork.asset)
            .await
            .expect("RPC send failed");
        assert_eq!(
            result.status, "OK",
            "BURN TX rejected: {} (reason: {})",
            result.status, result.reason
        );

        self.mark_inputs_spent(&signed, &tx_hash);

        TxResult { tx_hash, fee }
    }

    /// Build, sign, and submit a SWEEP transaction (transfer entire balance).
    async fn sweep(
        &self,
        dest_spend: [u8; 32],
        dest_view: [u8; 32],
        fork: &ForkSpec,
    ) -> TxResult {
        // Sweep: get full unlocked balance, send it all minus fee
        let db_asset_type = self.db_asset_type(fork);
        let balance = self
            .wallet
            .get_balance(db_asset_type, 0)
            .expect("get_balance failed");
        let unlocked: u64 = balance.unlocked_balance.parse().expect("invalid balance");
        let estimated_fee = self.estimate_fee(1, 1, fork).await;
        assert!(
            unlocked > estimated_fee,
            "insufficient balance for sweep: {} < fee {}",
            unlocked,
            estimated_fee
        );
        let sweep_amount = unlocked - estimated_fee;

        let inputs = self.prepare_inputs(sweep_amount, estimated_fee, fork).await;

        let mut builder = TransactionBuilder::new();
        for input in inputs {
            builder = builder.add_input(input);
        }

        builder = builder
            .add_destination(Destination {
                spend_pubkey: dest_spend,
                view_pubkey: dest_view,
                amount: sweep_amount,
                asset_type: fork.asset.to_string(),
                payment_id: [0u8; 8],
                is_subaddress: false,
            })
            .set_change_address(
                change_keys(self.wallet, fork).0,
                change_keys(self.wallet, fork).1,
            )
            .set_asset_types(fork.asset, fork.asset)
            .set_rct_type(fork.rct_type)
            .set_fee(estimated_fee);

        let unsigned = builder.build().expect("failed to build sweep TX");
        let fee = unsigned.fee;
        let signed = sign_transaction(unsigned).expect("failed to sign sweep TX");
        let tx_hash = hex::encode(signed.tx_hash().expect("tx hash"));
        let tx_bytes = signed.to_bytes().expect("serialize TX");
        let tx_hex = hex::encode(&tx_bytes);

        let result = self
            .daemon
            .send_raw_transaction_ex(&tx_hex, false, true, fork.asset)
            .await
            .expect("RPC send failed");
        assert_eq!(
            result.status, "OK",
            "sweep TX rejected: {} (reason: {})",
            result.status, result.reason
        );

        self.mark_inputs_spent(&signed, &tx_hash);

        println!("    sweep amount: {} SAL", fmt_sal(sweep_amount));
        TxResult { tx_hash, fee }
    }
}

// ─── Wallet Helpers ──────────────────────────────────────────────────────────

async fn sync_wallet(wallet: &Wallet, daemon: &DaemonRpc, label: &str) {
    println!("  Syncing wallet {}...", label);
    let t0 = Instant::now();
    let sync_height = wallet
        .sync(daemon, None)
        .await
        .expect("wallet sync failed");
    let elapsed = t0.elapsed().as_secs_f64();
    println!(
        "  Wallet {} synced to height {} ({})",
        label,
        sync_height,
        fmt_duration(elapsed)
    );
}

fn print_balance(wallet: &Wallet, label: &str, asset_type: &str) -> (u64, u64) {
    let bal = wallet
        .get_balance(asset_type, 0)
        .expect("get_balance failed");
    let total: u64 = bal.balance.parse().unwrap_or(0);
    let unlocked: u64 = bal.unlocked_balance.parse().unwrap_or(0);
    let locked: u64 = bal.locked_balance.parse().unwrap_or(0);
    println!(
        "  {} [{}]: balance={} unlocked={} locked={}",
        label,
        asset_type,
        fmt_sal(total),
        fmt_sal(unlocked),
        fmt_sal(locked),
    );
    (total, unlocked)
}

fn mining_address(wallet: &Wallet, fork: &ForkSpec) -> String {
    match fork.addr_format {
        AddrFormat::Carrot => wallet.carrot_address().expect("carrot address"),
        AddrFormat::Legacy => wallet.cn_address().expect("cn address"),
    }
}

fn dest_keys(wallet: &Wallet, fork: &ForkSpec) -> ([u8; 32], [u8; 32]) {
    let addr_str = mining_address(wallet, fork);
    let parsed = parse_address(&addr_str).expect("failed to parse address");
    (parsed.spend_public_key, parsed.view_public_key)
}

fn change_keys(wallet: &Wallet, fork: &ForkSpec) -> ([u8; 32], [u8; 32]) {
    let keys = wallet.keys();
    match fork.addr_format {
        AddrFormat::Legacy => (keys.cn.spend_public_key, keys.cn.view_public_key),
        AddrFormat::Carrot => (keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey),
    }
}

// ─── TX Test Runners ─────────────────────────────────────────────────────────

/// Tracking stats for the entire test run.
struct RunStats {
    tx_succeeded: u32,
    tx_failed: u32,
    total_fees: u64,
    total_blocks_mined: u64,
    total_mining_secs: f64,
}

impl RunStats {
    fn new() -> Self {
        Self {
            tx_succeeded: 0,
            tx_failed: 0,
            total_fees: 0,
            total_blocks_mined: 0,
            total_mining_secs: 0.0,
        }
    }

    fn record_mining(&mut self, stats: &MiningStats) {
        self.total_blocks_mined += stats.blocks_mined;
        self.total_mining_secs += stats.elapsed_secs;
    }

    fn record_tx(&mut self, result: &TxResult) {
        self.tx_succeeded += 1;
        self.total_fees += result.fee;
    }
}

/// Run full TX tests for era boundaries (HF2, HF6, HF10).
async fn run_full_tests(
    daemon: &DaemonRpc,
    daemon_url: &str,
    fixture: &TestFixture,
    fork: &ForkSpec,
    stats: &mut RunStats,
) {
    let transactor_a = TestTransactor::new(daemon, &fixture.wallet_a);
    let transactor_b = TestTransactor::new(daemon, &fixture.wallet_b);

    let (dest_b_spend, dest_b_view) = dest_keys(&fixture.wallet_b, fork);
    let (dest_a_spend, dest_a_view) = dest_keys(&fixture.wallet_a, fork);
    let addr_a = mining_address(&fixture.wallet_a, fork);

    // 3 transfers A→B
    for (i, (amount_f, amount_s)) in [(1.0, "1"), (2.0, "2"), (5.0, "5")].iter().enumerate() {
        println!(
            "\n  TX {}: Transfer A->B {} {} SAL",
            i + 1,
            amount_s,
            fork.asset
        );
        let result =
            transactor_a.transfer(dest_b_spend, dest_b_view, sal(*amount_f), fork).await;
        println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
        stats.record_tx(&result);
    }

    // Mine maturity so B can spend
    println!("\n  Mining {} maturity blocks...", MATURITY_BLOCKS);
    let ms = mine_to(
        daemon,
        get_daemon_height(daemon).await + MATURITY_BLOCKS,
        &addr_a,
        daemon_url,
    )
    .await;
    stats.record_mining(&ms);

    sync_wallet(&fixture.wallet_a, daemon, "A").await;
    sync_wallet(&fixture.wallet_b, daemon, "B").await;

    // Transfer B→A
    println!("\n  TX 4: Transfer B->A 0.5 {} SAL", fork.asset);
    let result = transactor_b
        .transfer(dest_a_spend, dest_a_view, sal(0.5), fork)
        .await;
    println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
    stats.record_tx(&result);

    // Stake (HF6+)
    if fork.hf >= 6 {
        println!("\n  Mining {} maturity blocks for stake...", MATURITY_BLOCKS);
        let ms = mine_to(
            daemon,
            get_daemon_height(daemon).await + MATURITY_BLOCKS,
            &addr_a,
            daemon_url,
        )
        .await;
        stats.record_mining(&ms);
        sync_wallet(&fixture.wallet_a, daemon, "A").await;

        println!("\n  TX 5: Stake 10 {} SAL", fork.asset);
        let result = transactor_a.stake(sal(10.0), fork).await;
        println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
        stats.record_tx(&result);
    }

    // Burn + Sweep (HF10+)
    if fork.hf >= 10 {
        println!("\n  Mining {} maturity blocks for burn...", MATURITY_BLOCKS);
        let ms = mine_to(
            daemon,
            get_daemon_height(daemon).await + MATURITY_BLOCKS,
            &addr_a,
            daemon_url,
        )
        .await;
        stats.record_mining(&ms);
        sync_wallet(&fixture.wallet_a, daemon, "A").await;

        println!("\n  TX 6: Burn 0.1 {} SAL", fork.asset);
        let result = transactor_a.burn(sal(0.1), fork).await;
        println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
        stats.record_tx(&result);

        println!("\n  Mining {} maturity blocks for sweep...", MATURITY_BLOCKS);
        let ms = mine_to(
            daemon,
            get_daemon_height(daemon).await + MATURITY_BLOCKS,
            &addr_a,
            daemon_url,
        )
        .await;
        stats.record_mining(&ms);
        sync_wallet(&fixture.wallet_b, daemon, "B").await;

        println!("\n  TX 7: Sweep B->B");
        let result = transactor_b
            .sweep(dest_b_spend, dest_b_view, fork)
            .await;
        println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
        stats.record_tx(&result);
    }
}

/// Run lightweight transfer test at intermediate forks.
async fn run_lightweight_test(
    daemon: &DaemonRpc,
    fixture: &TestFixture,
    fork: &ForkSpec,
    stats: &mut RunStats,
) {
    let transactor_a = TestTransactor::new(daemon, &fixture.wallet_a);
    let (dest_b_spend, dest_b_view) = dest_keys(&fixture.wallet_b, fork);

    println!("\n  TX: Transfer A->B 0.5 {} SAL (lightweight)", fork.asset);
    let result = transactor_a
        .transfer(dest_b_spend, dest_b_view, sal(0.5), fork)
        .await;
    println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
    stats.record_tx(&result);
}

// ─── Main Test ───────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn full_testnet_hardfork_progression() {
    let overall_start = Instant::now();

    println!("\n{}", "=".repeat(64));
    println!("  Full Testnet Hardfork Progression — salvium-rs");
    println!("{}\n", "=".repeat(64));

    // ── Phase 0: Setup ──────────────────────────────────────────────────
    println!("=== Phase 0: Setup ===\n");

    let url = daemon_url();
    let resume_hf = resume_from_hf();
    let daemon = DaemonRpc::new(&url);

    let info = daemon.get_info().await.expect("cannot connect to daemon");
    println!("  Daemon: {}", url);
    println!(
        "  Height: {}, synchronized: {}",
        info.height, info.synchronized
    );
    assert!(info.synchronized, "daemon is not synchronized");

    if resume_hf > 0 {
        println!("  Resuming from HF{}", resume_hf);
    }

    let fixture = TestFixture::create();
    println!("  Wallet A (CN):     {}...", &fixture.wallet_a.cn_address().unwrap()[..30]);
    println!(
        "  Wallet A (CARROT): {}...",
        &fixture.wallet_a.carrot_address().unwrap()[..30]
    );
    println!("  Wallet B (CN):     {}...", &fixture.wallet_b.cn_address().unwrap()[..30]);
    println!(
        "  Wallet B (CARROT): {}...",
        &fixture.wallet_b.carrot_address().unwrap()[..30]
    );

    let start_height = info.height;
    let mut stats = RunStats::new();

    // ── Fork-driven mining and testing ──────────────────────────────────
    for fork in FORKS {
        if fork.hf < resume_hf {
            println!("\n  Skipping HF{} — resume-from={}", fork.hf, resume_hf);
            continue;
        }

        println!("\n{}", "=".repeat(60));
        println!(
            "  HF{} @ height {} — {} / {:?}",
            fork.hf, fork.height, fork.asset, fork.addr_format
        );
        println!("{}", "=".repeat(60));

        // Mine to fork boundary.
        // For HF10: mine to boundary with legacy address, then switch to CARROT.
        if fork.hf == 10 {
            let legacy_addr = fixture.wallet_a.cn_address().unwrap();
            let ms = mine_to(&daemon, fork.height, &legacy_addr, &url).await;
            stats.record_mining(&ms);
        } else {
            let addr = mining_address(&fixture.wallet_a, fork);
            let ms = mine_to(&daemon, fork.height, &addr, &url).await;
            stats.record_mining(&ms);
        }

        // Mine maturity for Full test forks
        if fork.test_mode == TestMode::Full {
            let addr = mining_address(&fixture.wallet_a, fork);
            let target = fork.height + MATURITY_OFFSET;
            println!(
                "\n  Mining maturity to height {} (fork {} + {})...",
                target, fork.height, MATURITY_OFFSET
            );
            let ms = mine_to(&daemon, target, &addr, &url).await;
            stats.record_mining(&ms);
        }

        // Sync wallets
        sync_wallet(&fixture.wallet_a, &daemon, "A").await;
        sync_wallet(&fixture.wallet_b, &daemon, "B").await;

        // Print pre-test balances
        print_balance(&fixture.wallet_a, "A", fork.asset);
        print_balance(&fixture.wallet_b, "B", fork.asset);

        // Run fork-specific tests
        match fork.test_mode {
            TestMode::Genesis => {
                println!(
                    "  (HF1 genesis — no TX tests, coinbase not yet mature)"
                );
            }
            TestMode::Full => {
                run_full_tests(&daemon, &url, &fixture, fork, &mut stats).await;
            }
            TestMode::Lightweight => {
                run_lightweight_test(&daemon, &fixture, fork, &mut stats).await;
            }
            TestMode::Paused => {
                println!(
                    "  (HF{} paused — user transactions disabled by daemon)",
                    fork.hf
                );
            }
        }

        // Mine maturity after last TX
        let addr = mining_address(&fixture.wallet_a, fork);
        let ms = mine_to(
            &daemon,
            get_daemon_height(&daemon).await + MATURITY_BLOCKS,
            &addr,
            &url,
        )
        .await;
        stats.record_mining(&ms);

        // Sync and print post-test balances
        sync_wallet(&fixture.wallet_a, &daemon, "A").await;
        sync_wallet(&fixture.wallet_b, &daemon, "B").await;
        print_balance(&fixture.wallet_a, "A", fork.asset);
        print_balance(&fixture.wallet_b, "B", fork.asset);

        println!("\n  HF{} complete.", fork.hf);
    }

    // ── Phase 7: Reconciliation ─────────────────────────────────────────
    println!("\n{}", "=".repeat(60));
    println!("  Phase 7: Final Reconciliation");
    println!("{}", "=".repeat(60));

    sync_wallet(&fixture.wallet_a, &daemon, "A").await;
    sync_wallet(&fixture.wallet_b, &daemon, "B").await;

    let final_height = get_daemon_height(&daemon).await;
    println!("\n  Chain height: {}", final_height);

    // Print balances for all asset types
    println!("\n  --- Wallet A ---");
    print_balance(&fixture.wallet_a, "A", "SAL");
    if let Ok(bal) = fixture.wallet_a.get_balance("SAL1", 0) {
        let total: u64 = bal.balance.parse().unwrap_or(0);
        if total > 0 {
            print_balance(&fixture.wallet_a, "A", "SAL1");
        }
    }

    println!("\n  --- Wallet B ---");
    print_balance(&fixture.wallet_b, "B", "SAL");
    if let Ok(bal) = fixture.wallet_b.get_balance("SAL1", 0) {
        let total: u64 = bal.balance.parse().unwrap_or(0);
        if total > 0 {
            print_balance(&fixture.wallet_b, "B", "SAL1");
        }
    }

    // TX summary
    println!("\n  Transactions: {} succeeded, {} failed", stats.tx_succeeded, stats.tx_failed);
    println!("  Total fees: {} SAL", fmt_sal(stats.total_fees));
    println!("  Total blocks mined: {}", stats.total_blocks_mined);
    println!(
        "  Total mining time: {}",
        fmt_duration(stats.total_mining_secs)
    );

    // ── Phase 8: Gap Sync ───────────────────────────────────────────────
    println!("\n{}", "=".repeat(60));
    println!("  Phase 8: Gap Sync — Fresh Wallet C");
    println!("{}", "=".repeat(60));

    let tmp_c = tempfile::tempdir().expect("temp dir");
    let db_path_c = tmp_c.path().join("wallet-c.db");

    // Generate a fresh random seed for wallet C
    let mut seed_c = [0u8; 32];
    seed_c[0] = 0xCA; // Just needs to be unique, not cryptographically random for test
    seed_c[1] = 0xFE;
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    seed_c[2..10].copy_from_slice(&ts.to_le_bytes());

    let wallet_c = Wallet::create(
        seed_c,
        Network::Testnet,
        db_path_c.to_str().unwrap(),
        &[0u8; 32],
    )
    .expect("create wallet C");

    println!(
        "  Wallet C: {}...",
        &wallet_c.cn_address().unwrap()[..30]
    );
    println!("  Syncing from genesis...");

    let t0 = Instant::now();
    let sync_height = wallet_c
        .sync(&daemon, None)
        .await
        .expect("wallet C sync failed");
    let elapsed = t0.elapsed().as_secs_f64();
    println!(
        "  Wallet C synced to height {} in {}",
        sync_height,
        fmt_duration(elapsed)
    );

    // Verify zero balance
    let hf_info = daemon.hard_fork_info().await.unwrap();
    let at = if hf_info.version >= 6 { "SAL1" } else { "SAL" };
    let (total_c, _) = print_balance(&wallet_c, "C", at);
    assert_eq!(total_c, 0, "fresh wallet C should have zero balance");

    // ── Summary ─────────────────────────────────────────────────────────
    let total_elapsed = overall_start.elapsed().as_secs_f64();

    println!("\n{}", "=".repeat(64));
    println!("  TEST COMPLETE");
    println!("{}", "=".repeat(64));
    println!("  Total time: {}", fmt_duration(total_elapsed));
    println!("  Start height: {}", start_height);
    println!("  Final height: {}", final_height);
    println!(
        "  TX results: {} passed, {} failed",
        stats.tx_succeeded, stats.tx_failed
    );
    println!("  Total blocks mined: {}", stats.total_blocks_mined);
    println!("  Total fees: {} SAL", fmt_sal(stats.total_fees));

    assert_eq!(stats.tx_failed, 0, "some transactions failed");
    println!("\n  All tests passed!");
}
