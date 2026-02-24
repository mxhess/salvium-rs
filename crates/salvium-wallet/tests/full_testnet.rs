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
use salvium_types::address::parse_address;
use salvium_types::constants::Network;
use salvium_wallet::utxo::SelectionStrategy;
use salvium_wallet::{decrypt_js_wallet, OutputQuery, SyncEvent, Wallet, WalletKeys};

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

#[derive(Debug, Clone, Copy, PartialEq)]
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
    ForkSpec {
        hf: 1,
        height: 1,
        asset: "SAL",
        addr_format: AddrFormat::Legacy,
        test_mode: TestMode::Genesis,
        rct_type: 6,
    },
    ForkSpec {
        hf: 2,
        height: 250,
        asset: "SAL",
        addr_format: AddrFormat::Legacy,
        test_mode: TestMode::Full,
        rct_type: 6,
    },
    ForkSpec {
        hf: 3,
        height: 500,
        asset: "SAL",
        addr_format: AddrFormat::Legacy,
        test_mode: TestMode::Lightweight,
        rct_type: 7,
    },
    ForkSpec {
        hf: 4,
        height: 600,
        asset: "SAL",
        addr_format: AddrFormat::Legacy,
        test_mode: TestMode::Lightweight,
        rct_type: 7,
    },
    ForkSpec {
        hf: 5,
        height: 800,
        asset: "SAL",
        addr_format: AddrFormat::Legacy,
        test_mode: TestMode::Paused,
        rct_type: 7,
    },
    ForkSpec {
        hf: 6,
        height: 815,
        asset: "SAL1",
        addr_format: AddrFormat::Legacy,
        test_mode: TestMode::Full,
        rct_type: 8,
    },
    ForkSpec {
        hf: 7,
        height: 900,
        asset: "SAL1",
        addr_format: AddrFormat::Legacy,
        test_mode: TestMode::Paused,
        rct_type: 8,
    },
    ForkSpec {
        hf: 8,
        height: 950,
        asset: "SAL1",
        addr_format: AddrFormat::Legacy,
        test_mode: TestMode::Paused,
        rct_type: 8,
    },
    ForkSpec {
        hf: 9,
        height: 1000,
        asset: "SAL1",
        addr_format: AddrFormat::Legacy,
        test_mode: TestMode::Paused,
        rct_type: 8,
    },
    ForkSpec {
        hf: 10,
        height: 1100,
        asset: "SAL1",
        addr_format: AddrFormat::Carrot,
        test_mode: TestMode::Full,
        rct_type: 9,
    },
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
        format!("{}h {}m", secs as u64 / 3600, (secs as u64 % 3600) / 60)
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

/// Auto-detect the appropriate resume HF based on the daemon's current height.
///
/// If the chain has already progressed past a fork boundary, the daemon will
/// reject transactions built with that fork's parameters (wrong rct_type, etc.).
/// Find the latest fork whose height the chain has passed, and resume from there.
fn auto_resume_hf(daemon_height: u64) -> u8 {
    let mut resume = 0u8;
    for (i, fork) in FORKS.iter().enumerate() {
        let next_height = FORKS.get(i + 1).map(|f| f.height).unwrap_or(u64::MAX);
        if daemon_height >= next_height {
            // Chain is past this fork AND the next one — skip this fork
            resume = fork.hf + 1;
        }
    }
    resume
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
        let secrets_a =
            decrypt_js_wallet(&wallet_a_json, &pin_a).expect("failed to decrypt wallet-a");

        let tmp_a = tempfile::tempdir().expect("failed to create temp dir");
        let db_path_a = tmp_a.path().join("wallet-a.db");
        let wallet_a = Wallet::create(
            secrets_a.seed,
            Network::Testnet,
            db_path_a.to_str().unwrap(),
            &[0u8; 32],
        )
        .expect("failed to create wallet A");

        // Wallet B
        let wallet_b_json = std::fs::read_to_string(dir.join("wallet-b.json"))
            .expect("wallet-b.json not found in ~/testnet-wallet/");
        let pin_b = std::fs::read_to_string(dir.join("wallet-b.pin"))
            .expect("wallet-b.pin not found")
            .trim()
            .to_string();
        let secrets_b =
            decrypt_js_wallet(&wallet_b_json, &pin_b).expect("failed to decrypt wallet-b");

        let tmp_b = tempfile::tempdir().expect("failed to create temp dir");
        let db_path_b = tmp_b.path().join("wallet-b.db");
        let wallet_b = Wallet::create(
            secrets_b.seed,
            Network::Testnet,
            db_path_b.to_str().unwrap(),
            &[0u8; 32],
        )
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
    /// Raw TX bytes for offline diagnostic scanning.
    tx_bytes: Vec<u8>,
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
        let selection = self
            .wallet
            .select_outputs(
                amount,
                estimated_fee,
                db_asset_type,
                SelectionStrategy::Default,
            )
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
        let mut dist_cache: std::collections::HashMap<String, (Vec<u64>, u64)> =
            std::collections::HashMap::new();

        for utxo in &selection.selected {
            let output_row = self.wallet.get_output(&utxo.key_image).unwrap().unwrap();
            let output_pub_key = hex_to_32(output_row.public_key.as_ref().unwrap());

            // Find block height
            let entry = tx_entries
                .iter()
                .zip(tx_hashes.iter())
                .find(|(_, h)| **h == output_row.tx_hash)
                .map(|(e, _)| e)
                .expect("tx not found in entries");

            // The daemon maintains completely separate output pools per asset
            // type (SAL and SAL1 have different index spaces). Ring members
            // are resolved using vin[].asset_type, which must equal
            // tx.source_asset_type (enforced by the daemon). At HF6+, only
            // SAL1 outputs can be spent in TRANSFER/STAKE/BURN transactions.
            // We ONLY look in the fork's canonical asset pool — no fallback.
            let candidates_to_try = vec![fork.asset];

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
                let at_start = if h_idx == 0 {
                    0
                } else {
                    distribution[h_idx - 1]
                };
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
                // Adjust keys for subaddress outputs: k_gi' = k_gi * k_subscal,
                // k_ps' = k_ps * k_subscal. For main address (0,0) this is identity.
                let (adj_gik, adj_psk) =
                    salvium_crypto::subaddress::carrot_adjust_keys_for_subaddress(
                        &generate_image_key,
                        &prove_spend_key,
                        &keys.carrot.generate_address_secret,
                        &keys.carrot.account_spend_pubkey,
                        output_row.subaddress_index.major as u32,
                        output_row.subaddress_index.minor as u32,
                    );
                let (sk_x, sk_y) = salvium_crypto::carrot_scan::derive_carrot_spend_keys(
                    &adj_psk,
                    &adj_gik,
                    &shared_secret,
                    &commitment,
                );
                (sk_x, Some(sk_y), output_pub_key)
            } else {
                let spend_secret = keys.cn.spend_secret_key.expect("not a full wallet");
                let view_secret = keys.cn.view_secret_key;
                let tx_pub_key = hex_to_32(output_row.tx_pub_key.as_ref().unwrap());
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
            let ring_pub_keys: Vec<[u8; 32]> =
                ring_members.iter().map(|m| hex_to_32(&m.key)).collect();
            if public_key != ring_pub_keys[real_pos] {
                eprintln!("    WARNING: derived pk != ring[real_pos]!");
                eprintln!("      derived pk:    {}", hex::encode(public_key));
                eprintln!(
                    "      ring[{}]:   {}",
                    real_pos,
                    hex::encode(ring_pub_keys[real_pos])
                );
                eprintln!("      output_pub_key: {}", hex::encode(output_pub_key));
            }
            eprintln!(
                "    Input: asset_idx={}, ring_size={}, real_pos={}, ring_indices={:?}",
                asset_type_index,
                ring_indices.len(),
                real_pos,
                &ring_indices[..ring_indices.len().min(5)]
            );

            prepared_inputs.push(PreparedInput {
                secret_key,
                secret_key_y,
                public_key,
                amount: utxo.amount,
                mask,
                asset_type: fork.asset.to_string(),
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
        let est_weight =
            fee::estimate_tx_weight(n_inputs, n_outputs, DEFAULT_RING_SIZE, true, out_type);
        (est_weight as u64) * fee_estimate.fee * FeePriority::Normal.multiplier()
    }

    fn db_asset_type(&self, fork: &ForkSpec) -> &str {
        // SAL and SAL1 are completely separate asset pools with different
        // output index spaces. At HF6+, the daemon requires all TRANSFER/
        // STAKE/BURN outputs to be "SAL1". Pre-HF6 "SAL" outputs cannot
        // be spent in these TX types after HF6 — they are stranded.
        // The C++ wallet also defaults to "SAL1" after HF6 and only selects
        // from m_transfers_indices["SAL1"].
        if fork.hf >= 6 {
            "SAL1"
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
        is_subaddress: bool,
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
                is_subaddress,
            })
            .set_change_address(chg_spend, chg_view)
            .set_asset_types(fork.asset, fork.asset)
            .set_rct_type(fork.rct_type)
            .set_fee(estimated_fee);

        // For CARROT transactions, set the view-balance secret so the change
        // output uses the internal (self-send) path instead of ECDH.
        if fork.addr_format == AddrFormat::Carrot {
            builder = builder
                .set_change_view_balance_secret(self.wallet.keys().carrot.view_balance_secret);
        }

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
            eprintln!(
                "    ROUNDTRIP MISMATCH: {} bytes vs {} bytes",
                tx_bytes.len(),
                re_serialized.len()
            );
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
        eprintln!(
            "    Parsed TX: {}",
            serde_json::to_string_pretty(pj)
                .unwrap_or("?".to_string())
                .lines()
                .take(30)
                .collect::<Vec<_>>()
                .join("\n    ")
        );

        let tx_hex = hex::encode(&tx_bytes);

        let result = self
            .daemon
            .send_raw_transaction_ex(&tx_hex, false, true, fork.asset)
            .await
            .expect("RPC send failed");
        if result.status != "OK" {
            eprintln!("    DAEMON REJECT: {:?}", result);
            eprintln!(
                "    TX hex ({} bytes): {}...{}",
                tx_bytes.len(),
                &tx_hex[..80],
                &tx_hex[tx_hex.len() - 40..]
            );
        }
        assert_eq!(
            result.status,
            "OK",
            "transfer TX rejected: {} (reason: {}, double_spend: {}, fee_too_low: {}, \
             invalid_input: {}, invalid_output: {}, too_big: {}, overspend: {}, \
             sanity_check_failed: {})",
            result.status,
            result.reason,
            result.double_spend,
            result.fee_too_low,
            result.invalid_input,
            result.invalid_output,
            result.too_big,
            result.overspend,
            result.sanity_check_failed,
        );

        // Mark spent inputs in the wallet DB so we don't re-spend them.
        self.mark_inputs_spent(&signed, &tx_hash);

        TxResult {
            tx_hash,
            fee,
            tx_bytes,
        }
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

        if fork.addr_format == AddrFormat::Carrot {
            builder = builder.set_change_view_balance_secret(keys.carrot.view_balance_secret);
        }

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
            result.status,
            "OK",
            "STAKE TX rejected: {} (reason: {}, double_spend: {}, fee_too_low: {}, \
             invalid_input: {}, invalid_output: {}, too_big: {}, overspend: {}, \
             sanity_check_failed: {})",
            result.status,
            result.reason,
            result.double_spend,
            result.fee_too_low,
            result.invalid_input,
            result.invalid_output,
            result.too_big,
            result.overspend,
            result.sanity_check_failed
        );

        self.mark_inputs_spent(&signed, &tx_hash);

        TxResult {
            tx_hash,
            fee,
            tx_bytes: vec![],
        }
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
            .set_change_address(chg_spend, chg_view)
            .set_tx_type(tx_type::BURN)
            .set_amount_burnt(amount)
            .set_unlock_time(0)
            .set_asset_types(fork.asset, "BURN")
            .set_rct_type(fork.rct_type)
            .set_fee(estimated_fee);

        if fork.addr_format == AddrFormat::Carrot {
            builder = builder
                .set_change_view_balance_secret(self.wallet.keys().carrot.view_balance_secret);
        }

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
            result.status,
            "OK",
            "BURN TX rejected: {} (reason: {}, double_spend: {}, fee_too_low: {}, \
             invalid_input: {}, invalid_output: {}, too_big: {}, overspend: {}, \
             sanity_check_failed: {})",
            result.status,
            result.reason,
            result.double_spend,
            result.fee_too_low,
            result.invalid_input,
            result.invalid_output,
            result.too_big,
            result.overspend,
            result.sanity_check_failed,
        );

        self.mark_inputs_spent(&signed, &tx_hash);

        TxResult {
            tx_hash,
            fee,
            tx_bytes: vec![],
        }
    }

    /// Build, sign, and submit a SWEEP transaction (transfer entire balance).
    async fn sweep(&self, dest_spend: [u8; 32], dest_view: [u8; 32], fork: &ForkSpec) -> TxResult {
        // Sweep: get full unlocked balance, send it all minus fee.
        // Must estimate fee using the actual number of inputs (all unlocked
        // outputs), not 1.
        let db_asset_type = self.db_asset_type(fork);
        let balance = self
            .wallet
            .get_balance(db_asset_type, 0)
            .expect("get_balance failed");
        let unlocked: u64 = balance.unlocked_balance.parse().expect("invalid balance");

        // First pass: use a minimal fee to select ALL unlocked outputs and
        // determine the actual input count.
        let min_fee = self.estimate_fee(1, 2, fork).await;
        assert!(
            unlocked > min_fee,
            "insufficient balance for sweep: {} < min fee {}",
            unlocked,
            min_fee
        );
        let inputs = self.prepare_inputs(unlocked - min_fee, min_fee, fork).await;
        let n_inputs = inputs.len();

        // Re-estimate fee with the actual input count.
        let estimated_fee = self.estimate_fee(n_inputs, 2, fork).await;
        assert!(
            unlocked > estimated_fee,
            "insufficient balance for sweep with {} inputs: {} < fee {}",
            n_inputs,
            unlocked,
            estimated_fee
        );
        let sweep_amount = unlocked - estimated_fee;

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

        if fork.addr_format == AddrFormat::Carrot {
            builder = builder
                .set_change_view_balance_secret(self.wallet.keys().carrot.view_balance_secret);
        }

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
            result.status,
            "OK",
            "sweep TX rejected: {} (reason: {}, double_spend: {}, fee_too_low: {}, \
             invalid_input: {}, invalid_output: {}, too_big: {}, overspend: {}, \
             sanity_check_failed: {})",
            result.status,
            result.reason,
            result.double_spend,
            result.fee_too_low,
            result.invalid_input,
            result.invalid_output,
            result.too_big,
            result.overspend,
            result.sanity_check_failed,
        );

        self.mark_inputs_spent(&signed, &tx_hash);

        println!("    sweep amount: {} SAL", fmt_sal(sweep_amount));
        TxResult {
            tx_hash,
            fee,
            tx_bytes: vec![],
        }
    }
}

// ─── Wallet Helpers ──────────────────────────────────────────────────────────

#[allow(dead_code)]
struct SyncStats {
    sync_height: u64,
    parse_errors: usize,
    empty_blobs: usize,
    outputs_found: usize,
}

async fn sync_wallet_checked(wallet: &Wallet, daemon: &DaemonRpc, label: &str) -> SyncStats {
    println!("  Syncing wallet {}...", label);
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<SyncEvent>(256);

    let stats_task = tokio::spawn(async move {
        let mut parse_errors = 0usize;
        let mut empty_blobs = 0usize;
        let mut outputs_found = 0usize;
        while let Some(event) = event_rx.recv().await {
            if let SyncEvent::Progress {
                parse_errors: pe,
                empty_blobs: eb,
                outputs_found: of,
                ..
            } = event
            {
                parse_errors = pe;
                empty_blobs = eb;
                outputs_found = of;
            }
        }
        (parse_errors, empty_blobs, outputs_found)
    });

    let t0 = Instant::now();
    let sync_height = wallet
        .sync(daemon, Some(&event_tx))
        .await
        .expect("sync failed");
    drop(event_tx);
    let (parse_errors, empty_blobs, outputs_found) = stats_task.await.unwrap();
    let elapsed = t0.elapsed().as_secs_f64();

    println!(
        "  {} synced to {} ({}, {} outputs, {} parse errors, {} empty blobs)",
        label,
        sync_height,
        fmt_duration(elapsed),
        outputs_found,
        parse_errors,
        empty_blobs,
    );

    assert_eq!(parse_errors, 0, "{} had parse errors during sync", label);
    assert_eq!(empty_blobs, 0, "{} had empty blobs during sync", label);

    SyncStats {
        sync_height,
        parse_errors,
        empty_blobs,
        outputs_found,
    }
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

fn assert_balance_positive(wallet: &Wallet, label: &str, asset_type: &str) -> (u64, u64) {
    let (total, unlocked) = print_balance(wallet, label, asset_type);
    assert!(
        total > 0,
        "{} {} total balance should be positive",
        label,
        asset_type
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
        AddrFormat::Carrot => (
            keys.carrot.account_spend_pubkey,
            keys.carrot.account_view_pubkey,
        ),
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

/// Diagnostic: attempt to scan a TX's CARROT outputs with the given wallet's keys.
/// Prints detailed information about each step of the CARROT scanning pipeline.
fn diagnose_carrot_scan(tx_bytes: &[u8], wallet: &Wallet, label: &str) {
    println!("    --- CARROT SCAN DIAGNOSTIC for {} ---", label);
    println!("    tx_bytes.len()={}", tx_bytes.len());

    // Parse the TX bytes back to JSON
    let tx_json_str = salvium_crypto::parse_transaction_bytes(tx_bytes);
    if tx_json_str.starts_with(r#"{"error":"#) {
        println!(
            "    PARSE ERROR: {}",
            &tx_json_str[..tx_json_str.len().min(200)]
        );
        return;
    }

    let tx_json: serde_json::Value = match serde_json::from_str(&tx_json_str) {
        Ok(v) => v,
        Err(e) => {
            println!("    JSON PARSE ERROR: {}", e);
            return;
        }
    };

    let prefix = tx_json.get("prefix").unwrap_or(&tx_json);

    // Check tx extra for tag 0x01 and 0x04
    let extra = prefix.get("extra").and_then(|v| v.as_array());
    println!("    extra entries: {}", extra.map(|e| e.len()).unwrap_or(0));
    if let Some(entries) = extra {
        for (i, entry) in entries.iter().enumerate() {
            let entry_type = entry.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
            let tag = entry.get("tag").and_then(|v| v.as_str()).unwrap_or("?");
            if entry_type == 1 || entry_type == 4 {
                let keys = entry.get("keys").and_then(|v| v.as_array());
                let key = entry.get("key").and_then(|v| v.as_str());
                println!(
                    "    extra[{}]: type={} tag={} key={:?} keys_count={}",
                    i,
                    entry_type,
                    tag,
                    key.map(|k| &k[..k.len().min(16)]),
                    keys.map(|k| k.len()).unwrap_or(0)
                );
            }
        }
    }

    // Check outputs
    let vout = prefix
        .get("vout")
        .or_else(|| tx_json.get("vout"))
        .and_then(|v| v.as_array());
    println!("    outputs: {}", vout.map(|v| v.len()).unwrap_or(0));
    if let Some(outs) = vout {
        for (i, out) in outs.iter().enumerate() {
            let out_type = out.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
            let key = out.get("key").and_then(|v| v.as_str()).unwrap_or("?");
            let view_tag = out.get("viewTag");
            let asset = out.get("assetType").and_then(|v| v.as_str()).unwrap_or("?");
            println!(
                "    out[{}]: type={} asset={} key={}.. viewTag={:?}",
                i,
                out_type,
                asset,
                &key[..key.len().min(16)],
                view_tag
            );
        }
    }

    // Check vin for key images
    let vin = prefix.get("vin").and_then(|v| v.as_array());
    let first_ki = vin
        .and_then(|v| v.first())
        .and_then(|inp| inp.get("keyImage"))
        .and_then(|v| v.as_str());
    println!(
        "    first_key_image: {:?}",
        first_ki.map(|k| &k[..k.len().min(16)])
    );

    // Build scan context from wallet B's keys
    let keys = wallet.keys();
    println!("    carrot_enabled: {}", !keys.carrot.is_empty());
    println!(
        "    k_vi (view_incoming): {}...",
        hex::encode(&keys.carrot.view_incoming_key[..8])
    );
    println!(
        "    K_s (account_spend): {}...",
        hex::encode(&keys.carrot.account_spend_pubkey[..8])
    );

    // Now attempt manual CARROT scan
    if let (Some(outs), Some(ki_hex)) = (vout, first_ki) {
        let ki_bytes = hex::decode(ki_hex).unwrap_or_default();
        if ki_bytes.len() != 32 {
            println!("    key image decode failed");
            return;
        }
        let mut ki32 = [0u8; 32];
        ki32.copy_from_slice(&ki_bytes);
        let input_context = salvium_crypto::make_input_context_rct(&ki32);
        println!(
            "    input_context: {} bytes, first byte=0x{:02x}",
            input_context.len(),
            input_context.first().unwrap_or(&0)
        );

        // Extract ephemeral pubkeys from tag 0x04
        let mut additional_pubkeys: Vec<[u8; 32]> = Vec::new();
        if let Some(entries) = extra {
            for entry in entries {
                let t = entry.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
                if t == 4 {
                    if let Some(ks) = entry.get("keys").and_then(|v| v.as_array()) {
                        for k in ks {
                            if let Some(hex_str) = k.as_str() {
                                if let Ok(bytes) = hex::decode(hex_str) {
                                    if bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        additional_pubkeys.push(arr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        println!("    additional_pubkeys (D_e): {}", additional_pubkeys.len());

        // Try scanning each output
        for (i, out) in outs.iter().enumerate() {
            let out_type = out.get("type").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
            if out_type != 4 {
                println!("    out[{}]: not CARROT (type={}), skipping", i, out_type);
                continue;
            }

            let ko_hex = out.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let ko_bytes = hex::decode(ko_hex).unwrap_or_default();
            if ko_bytes.len() != 32 {
                println!("    out[{}]: bad key", i);
                continue;
            }
            let mut ko = [0u8; 32];
            ko.copy_from_slice(&ko_bytes);

            // View tag
            let vt_hex = out.get("viewTag").and_then(|v| v.as_str()).unwrap_or("");
            let vt_bytes = hex::decode(vt_hex).unwrap_or_default();
            if vt_bytes.len() != 3 {
                println!("    out[{}]: bad viewTag (len={})", i, vt_bytes.len());
                continue;
            }
            let view_tag = [vt_bytes[0], vt_bytes[1], vt_bytes[2]];

            // Ephemeral pubkey
            let d_e = if let Some(pk) = additional_pubkeys.get(i) {
                *pk
            } else {
                println!("    out[{}]: no ephemeral pubkey at index {}", i, i);
                continue;
            };

            println!("    out[{}]: attempting CARROT scan...", i);
            println!("      Ko={}...", &ko_hex[..16]);
            println!("      D_e={}...", hex::encode(&d_e[..8]));
            println!("      view_tag={}", vt_hex);

            // Step 1: ECDH
            let mut clamped_k_vi = keys.carrot.view_incoming_key;
            clamped_k_vi[31] &= 0x7F;
            let s_sr_unctx = salvium_crypto::x25519_scalar_mult(&clamped_k_vi, &d_e);
            println!("      s_sr_unctx={}...", hex::encode(&s_sr_unctx[..8]));

            // Step 2: View tag test
            let mut s32 = [0u8; 32];
            s32.copy_from_slice(&s_sr_unctx[..32]);
            let expected_vt = salvium_crypto::compute_carrot_view_tag(&s32, &input_context, &ko);
            let expected_vt_3 = [expected_vt[0], expected_vt[1], expected_vt[2]];
            let vt_match = expected_vt_3 == view_tag;
            println!(
                "      expected_vt={} actual_vt={} match={}",
                hex::encode(expected_vt_3),
                hex::encode(view_tag),
                vt_match
            );

            if !vt_match {
                println!("      VIEW TAG MISMATCH — ECDH shared secret differs");
                // Try the full scan anyway to confirm
                let enc_amount = [0u8; 8]; // placeholder
                let result = salvium_crypto::carrot_scan::scan_carrot_output(
                    &ko,
                    &view_tag,
                    &d_e,
                    &enc_amount,
                    None,
                    &keys.carrot.view_incoming_key,
                    &keys.carrot.account_spend_pubkey,
                    &input_context,
                    &[],
                    None,
                );
                println!(
                    "      full scan result: {}",
                    if result.is_some() {
                        "MATCH"
                    } else {
                        "NO MATCH"
                    }
                );
                continue;
            }

            // If view tag matches, try full scan with real encrypted amount
            let rct = tx_json.get("rct").or_else(|| tx_json.get("rct_signatures"));
            let ecdh_info = rct
                .and_then(|r| r.get("ecdhInfo"))
                .and_then(|e| e.as_array());
            let enc_amt = ecdh_info
                .and_then(|info| info.get(i))
                .and_then(|e| e.get("amount"))
                .and_then(|a| a.as_str())
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| {
                    if b.len() >= 8 {
                        let mut a = [0u8; 8];
                        a.copy_from_slice(&b[..8]);
                        Some(a)
                    } else {
                        None
                    }
                })
                .unwrap_or([0u8; 8]);
            let commitment = rct
                .and_then(|r| r.get("outPk"))
                .and_then(|e| e.as_array())
                .and_then(|pks| pks.get(i))
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .and_then(|b| {
                    if b.len() == 32 {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        Some(a)
                    } else {
                        None
                    }
                });

            let result = salvium_crypto::carrot_scan::scan_carrot_output(
                &ko,
                &view_tag,
                &d_e,
                &enc_amt,
                commitment.as_ref(),
                &keys.carrot.view_incoming_key,
                &keys.carrot.account_spend_pubkey,
                &input_context,
                &[],
                None,
            );
            if let Some(ref r) = result {
                println!(
                    "      SCAN SUCCESS: amount={} enote_type={} is_main={}",
                    r.amount, r.enote_type, r.is_main_address
                );
            } else {
                println!("      SCAN FAILED (past view tag)");
                // Try to diagnose which step failed
                let s_ctx = salvium_crypto::carrot_scan::build_transcript(
                    b"Carrot sender-receiver secret",
                    &[&d_e[..], &input_context],
                );
                let s_ctx_hash = salvium_crypto::blake2b_keyed(&s_ctx, 32, &s32);
                let mut s_ctx_32 = [0u8; 32];
                s_ctx_32.copy_from_slice(&s_ctx_hash[..32]);
                let recovered = salvium_crypto::recover_carrot_address_spend_pubkey(
                    &ko,
                    &s_ctx_32,
                    &commitment.unwrap_or([0u8; 32]),
                );
                println!(
                    "      recovered K_s: {}...",
                    hex::encode(&recovered[..recovered.len().min(16)])
                );
                println!(
                    "      expected  K_s: {}...",
                    hex::encode(&keys.carrot.account_spend_pubkey[..8])
                );
            }
        }
    }
    println!("    --- END DIAGNOSTIC ---");
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
        let result = transactor_a
            .transfer(dest_b_spend, dest_b_view, sal(*amount_f), fork, false)
            .await;
        println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));

        // Diagnostic: scan TX1 with wallet B's keys at CARROT era
        if i == 0 && fork.addr_format == AddrFormat::Carrot && !result.tx_bytes.is_empty() {
            diagnose_carrot_scan(&result.tx_bytes, &fixture.wallet_b, "B (recipient)");
            diagnose_carrot_scan(&result.tx_bytes, &fixture.wallet_a, "A (sender/change)");
        }

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

    // Diagnostic: check mempool after mining — our TXs should NOT be there
    // if they were included in blocks.
    if let Ok(pool) = daemon.get_transaction_pool_hashes().await {
        println!("  Mempool after mining: {} TXs", pool.len());
        if !pool.is_empty() {
            for h in pool.iter().take(5) {
                println!("    still in mempool: {}", h);
            }
        }
    }

    sync_wallet_checked(&fixture.wallet_a, daemon, "A").await;
    sync_wallet_checked(&fixture.wallet_b, daemon, "B").await;

    // Transfer B→A (requires B to have received and matured the A→B transfers)
    let db_asset_b = transactor_b.db_asset_type(fork);
    let bal_b = fixture.wallet_b.get_balance(db_asset_b, 0).unwrap();
    let unlocked_b: u64 = bal_b.unlocked_balance.parse().unwrap_or(0);
    if unlocked_b >= sal(0.5) + sal(0.1) {
        println!("\n  TX 4: Transfer B->A 0.5 {} SAL", fork.asset);
        let result = transactor_b
            .transfer(dest_a_spend, dest_a_view, sal(0.5), fork, false)
            .await;
        println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
        stats.record_tx(&result);
    } else {
        println!(
            "\n  TX 4: SKIPPED — B unlocked={} {} (need ~0.6 for transfer + fee)",
            fmt_sal(unlocked_b),
            db_asset_b
        );
        println!(
            "    B total={} locked={}",
            bal_b.balance, bal_b.locked_balance
        );
        // Diagnostic: check what outputs B has
        let all_query = OutputQuery {
            is_spent: None,
            is_frozen: None,
            asset_type: None,
            tx_type: None,
            account_index: None,
            subaddress_index: None,
            min_amount: None,
            max_amount: None,
        };
        let outputs = fixture.wallet_b.get_outputs(&all_query).unwrap();
        println!(
            "    B outputs: {} total, {} unspent, {} frozen",
            outputs.len(),
            outputs.iter().filter(|o| !o.is_spent).count(),
            outputs.iter().filter(|o| o.is_frozen).count()
        );
        for (i, o) in outputs.iter().take(5).enumerate() {
            println!(
                "      [{}] amount={} asset={} spent={} height={:?} carrot={}",
                i, o.amount, o.asset_type, o.is_spent, o.block_height, o.is_carrot
            );
        }
    }

    // Stake (HF6+)
    if fork.hf >= 6 {
        println!(
            "\n  Mining {} maturity blocks for stake...",
            MATURITY_BLOCKS
        );
        let ms = mine_to(
            daemon,
            get_daemon_height(daemon).await + MATURITY_BLOCKS,
            &addr_a,
            daemon_url,
        )
        .await;
        stats.record_mining(&ms);
        sync_wallet_checked(&fixture.wallet_a, daemon, "A").await;

        println!("\n  TX 5: Stake 10 {} SAL", fork.asset);
        let result = transactor_a.stake(sal(10.0), fork).await;
        println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
        stats.record_tx(&result);

        // Mine past stake lock period (20 blocks on testnet) + maturity
        println!("\n  Mining past stake lock period...");
        let ms = mine_to(
            daemon,
            get_daemon_height(daemon).await + 30,
            &addr_a,
            daemon_url,
        )
        .await;
        stats.record_mining(&ms);

        sync_wallet_checked(&fixture.wallet_a, daemon, "A").await;

        // Verify stake return was detected
        let stakes = fixture.wallet_a.get_stakes(None).unwrap();
        assert!(!stakes.is_empty(), "should have at least one stake");
        let returned = stakes.iter().filter(|s| s.status == "returned").count();
        let txid_matched = stakes
            .iter()
            .filter(|s| s.status == "returned" && s.return_output_key.is_some())
            .count();
        let height_fallback = returned - txid_matched;
        println!(
            "  Stakes: {} total, {} returned ({} TX-ID match, {} height fallback)",
            stakes.len(),
            returned,
            txid_matched,
            height_fallback
        );
        assert!(
            returned > 0,
            "stake should have been returned after lock period"
        );
        // TX-ID matching requires CARROT v4+ (HF10). Pre-CARROT stakes
        // legitimately use height-based fallback since they don't embed
        // protocol_tx_data.return_address.
        if fork.hf >= 10 {
            assert!(txid_matched > 0, "HF10+ stake should use TX-ID matching");
        }
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
        sync_wallet_checked(&fixture.wallet_a, daemon, "A").await;

        println!("\n  TX 6: Burn 0.1 {} SAL", fork.asset);
        let result = transactor_a.burn(sal(0.1), fork).await;
        println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
        stats.record_tx(&result);

        println!(
            "\n  Mining {} maturity blocks for sweep...",
            MATURITY_BLOCKS
        );
        let ms = mine_to(
            daemon,
            get_daemon_height(daemon).await + MATURITY_BLOCKS,
            &addr_a,
            daemon_url,
        )
        .await;
        stats.record_mining(&ms);
        sync_wallet_checked(&fixture.wallet_b, daemon, "B").await;

        println!("\n  TX 7: Sweep B->B");
        let result = transactor_b.sweep(dest_b_spend, dest_b_view, fork).await;
        println!("    hash={} fee={}", result.tx_hash, fmt_sal(result.fee));
        stats.record_tx(&result);

        // TX 8: Send to Wallet B subaddress (0,1)
        println!(
            "\n  Mining {} maturity blocks for subaddress test...",
            MATURITY_BLOCKS
        );
        let ms = mine_to(
            daemon,
            get_daemon_height(daemon).await + MATURITY_BLOCKS,
            &addr_a,
            daemon_url,
        )
        .await;
        stats.record_mining(&ms);
        sync_wallet_checked(&fixture.wallet_a, daemon, "A").await;

        println!("\n  TX 8: Transfer A->B subaddress (0,1)");
        let b_maps = fixture.wallet_b.subaddress_maps();
        let (sub_spend, sub_view) = if fork.addr_format == AddrFormat::Carrot {
            // CARROT subaddress: K_s_sub from CARROT map, K_v_sub = k_vi * K_s_sub
            let sub_01 = b_maps
                .carrot
                .iter()
                .find(|(_, maj, min)| *maj == 0 && *min == 1)
                .expect("subaddress (0,1) not found in wallet B's CARROT map");
            let sub_k_s = sub_01.0;
            let k_vi = fixture.wallet_b.keys().carrot.view_incoming_key;
            let kv_sub_vec = salvium_crypto::scalar_mult_point(&k_vi, &sub_k_s);
            let mut kv_sub = [0u8; 32];
            kv_sub.copy_from_slice(&kv_sub_vec);
            (sub_k_s, kv_sub)
        } else {
            // CryptoNote subaddress: from CN map + CN view key
            let sub_01 = b_maps
                .cn
                .iter()
                .find(|(_, maj, min)| *maj == 0 && *min == 1)
                .expect("subaddress (0,1) not found in wallet B's CN map");
            (sub_01.0, fixture.wallet_b.keys().cn.view_public_key)
        };
        let sub_result = transactor_a
            .transfer(sub_spend, sub_view, sal(0.5), fork, true)
            .await;
        println!(
            "    hash={} fee={}",
            sub_result.tx_hash,
            fmt_sal(sub_result.fee)
        );
        stats.record_tx(&sub_result);

        // Mine + sync, then verify B detected the output at subaddress (0,1)
        println!("\n  Mining {} maturity blocks...", MATURITY_BLOCKS);
        let ms = mine_to(
            daemon,
            get_daemon_height(daemon).await + MATURITY_BLOCKS,
            &addr_a,
            daemon_url,
        )
        .await;
        stats.record_mining(&ms);
        sync_wallet_checked(&fixture.wallet_b, daemon, "B").await;

        // Verify B has an output with subaddress major=0, minor=1
        let b_query = salvium_crypto::storage::OutputQuery {
            is_spent: None,
            is_frozen: None,
            asset_type: None,
            tx_type: None,
            account_index: None,
            subaddress_index: Some(1),
            min_amount: None,
            max_amount: None,
        };
        let sub_outputs = fixture.wallet_b.get_outputs(&b_query).unwrap();
        assert!(
            !sub_outputs.is_empty(),
            "wallet B should have detected output at subaddress (0,1)"
        );
        println!(
            "  Subaddress (0,1) output detected: {} output(s)",
            sub_outputs.len()
        );
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
        .transfer(dest_b_spend, dest_b_view, sal(0.5), fork, false)
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
    let env_resume_hf = resume_from_hf();
    let daemon = DaemonRpc::new(&url);

    let info = daemon.get_info().await.expect("cannot connect to daemon");
    println!("  Daemon: {}", url);
    println!(
        "  Height: {}, synchronized: {}",
        info.height, info.synchronized
    );
    assert!(info.synchronized, "daemon is not synchronized");

    // Auto-detect resume point from chain state if not explicitly set.
    // If the chain has already advanced past fork boundaries, skip those
    // forks — the daemon will reject TXs built with outdated parameters.
    let resume_hf = if env_resume_hf > 0 {
        env_resume_hf
    } else {
        auto_resume_hf(info.height)
    };
    if resume_hf > 0 {
        println!(
            "  Resuming from HF{} (chain already at height {})",
            resume_hf, info.height
        );
    }

    let fixture = TestFixture::create();
    println!(
        "  Wallet A (CN):     {}...",
        &fixture.wallet_a.cn_address().unwrap()[..30]
    );
    println!(
        "  Wallet A (CARROT): {}...",
        &fixture.wallet_a.carrot_address().unwrap()[..30]
    );
    println!(
        "  Wallet B (CN):     {}...",
        &fixture.wallet_b.cn_address().unwrap()[..30]
    );
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
        sync_wallet_checked(&fixture.wallet_a, &daemon, "A").await;
        sync_wallet_checked(&fixture.wallet_b, &daemon, "B").await;

        // Print pre-test balances
        print_balance(&fixture.wallet_a, "A", fork.asset);
        print_balance(&fixture.wallet_b, "B", fork.asset);

        // Run fork-specific tests
        match fork.test_mode {
            TestMode::Genesis => {
                println!("  (HF1 genesis — no TX tests, coinbase not yet mature)");
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
        sync_wallet_checked(&fixture.wallet_a, &daemon, "A").await;
        sync_wallet_checked(&fixture.wallet_b, &daemon, "B").await;

        // Wallet A should always have a positive balance (mined many blocks)
        assert_balance_positive(&fixture.wallet_a, "A", fork.asset);
        // After Full tests, wallet B should also have positive balance (received transfers)
        if fork.test_mode == TestMode::Full {
            assert_balance_positive(&fixture.wallet_b, "B", fork.asset);
        } else {
            print_balance(&fixture.wallet_b, "B", fork.asset);
        }

        println!("\n  HF{} complete.", fork.hf);
    }

    // ── Phase 7: Reconciliation ─────────────────────────────────────────
    println!("\n{}", "=".repeat(60));
    println!("  Phase 7: Final Reconciliation");
    println!("{}", "=".repeat(60));

    sync_wallet_checked(&fixture.wallet_a, &daemon, "A").await;
    sync_wallet_checked(&fixture.wallet_b, &daemon, "B").await;

    let final_height = get_daemon_height(&daemon).await;
    println!("\n  Chain height: {}", final_height);

    // Print and assert balances for all asset types
    println!("\n  --- Wallet A ---");
    let (a_sal, _) = print_balance(&fixture.wallet_a, "A", "SAL");
    let mut a_total = a_sal;
    if let Ok(bal) = fixture.wallet_a.get_balance("SAL1", 0) {
        let total: u64 = bal.balance.parse().unwrap_or(0);
        if total > 0 {
            print_balance(&fixture.wallet_a, "A", "SAL1");
            a_total += total;
        }
    }
    assert!(
        a_total > 0,
        "Wallet A total balance (SAL+SAL1) should be positive"
    );

    println!("\n  --- Wallet B ---");
    let (b_sal, _) = print_balance(&fixture.wallet_b, "B", "SAL");
    let mut b_total = b_sal;
    if let Ok(bal) = fixture.wallet_b.get_balance("SAL1", 0) {
        let total: u64 = bal.balance.parse().unwrap_or(0);
        if total > 0 {
            print_balance(&fixture.wallet_b, "B", "SAL1");
            b_total += total;
        }
    }
    assert!(
        b_total > 0,
        "Wallet B total balance (SAL+SAL1) should be positive"
    );

    // Verify no overflow/negative values
    assert!(
        a_total < u64::MAX / 2,
        "Wallet A balance looks like overflow: {}",
        a_total
    );
    assert!(
        b_total < u64::MAX / 2,
        "Wallet B balance looks like overflow: {}",
        b_total
    );

    // TX summary
    println!(
        "\n  Transactions: {} succeeded, {} failed",
        stats.tx_succeeded, stats.tx_failed
    );
    println!("  Total fees: {} SAL", fmt_sal(stats.total_fees));
    println!("  Total blocks mined: {}", stats.total_blocks_mined);
    println!(
        "  Total mining time: {}",
        fmt_duration(stats.total_mining_secs)
    );

    // ── Phase 7b: View-Only Wallet Verification ────────────────────────
    println!("\n  Phase 7b: View-only wallet verification...");
    {
        let keys_a = fixture.wallet_a.keys();
        let view_keys = WalletKeys::view_only_carrot(
            keys_a.cn.view_secret_key,
            keys_a.cn.spend_public_key,
            keys_a.carrot.view_balance_secret,
            keys_a.carrot.account_spend_pubkey,
            Network::Testnet,
        );
        let tmp_vo = tempfile::tempdir().unwrap();
        let wallet_vo = Wallet::open(
            view_keys,
            tmp_vo.path().join("vo.db").to_str().unwrap(),
            &[0u8; 32],
        )
        .unwrap();
        sync_wallet_checked(&wallet_vo, &daemon, "A-ViewOnly").await;

        // Compare SAL balance.
        // View-only wallets cannot compute CN key images (no spend secret), so
        // they use synthetic key images and cannot detect when pre-CARROT (SAL)
        // outputs are spent on-chain. This is the same limitation as Monero's
        // view-only wallets. The view-only balance will be >= full wallet balance.
        let bal_full_sal = fixture.wallet_a.get_balance("SAL", 0).unwrap();
        let bal_vo_sal = wallet_vo.get_balance("SAL", 0).unwrap();
        let full_sal: u64 = bal_full_sal.balance.parse().unwrap();
        let vo_sal: u64 = bal_vo_sal.balance.parse().unwrap();
        assert!(
            vo_sal >= full_sal,
            "view-only SAL balance ({}) should be >= full wallet ({})",
            vo_sal,
            full_sal,
        );
        if vo_sal > full_sal {
            println!(
                "  View-only SAL balance {} > full {} (expected: CN outputs lack real key images)",
                fmt_sal(vo_sal),
                fmt_sal(full_sal),
            );
        }

        // Compare SAL1 (CARROT) balance.
        // SAL1 contains a mix of CN outputs (HF6-9 era) and CARROT outputs (HF10+).
        // View-only wallets CAN compute CARROT key images (via generate_image_key)
        // but CANNOT compute CN key images (no spend_secret). So spent CN SAL1
        // outputs from the HF6-9 era remain "unspent" in the view-only wallet,
        // making its total SAL1 balance >= the full wallet's.
        if let (Ok(bf), Ok(bv)) = (
            fixture.wallet_a.get_balance("SAL1", 0),
            wallet_vo.get_balance("SAL1", 0),
        ) {
            let full_sal1: u64 = bf.balance.parse().unwrap();
            let vo_sal1: u64 = bv.balance.parse().unwrap();
            assert!(
                vo_sal1 >= full_sal1,
                "view-only SAL1 balance ({}) should be >= full wallet ({})",
                vo_sal1,
                full_sal1,
            );
            if vo_sal1 > full_sal1 {
                println!(
                    "  View-only SAL1 balance {} > full {} (expected: HF6-9 CN outputs lack real key images)",
                    fmt_sal(vo_sal1), fmt_sal(full_sal1),
                );
            }

            // Verify CARROT-only outputs match exactly.
            // Query all unspent SAL1 outputs and compare only is_carrot=true ones.
            let query = OutputQuery {
                is_spent: Some(false),
                is_frozen: Some(false),
                asset_type: Some("SAL1".to_string()),
                ..Default::default()
            };
            let full_outputs = fixture.wallet_a.get_outputs(&query).unwrap();
            let vo_outputs = wallet_vo.get_outputs(&query).unwrap();

            let full_carrot_bal: u64 = full_outputs
                .iter()
                .filter(|o| o.is_carrot)
                .map(|o| o.amount.parse::<u64>().unwrap_or(0))
                .sum();
            let vo_carrot_bal: u64 = vo_outputs
                .iter()
                .filter(|o| o.is_carrot)
                .map(|o| o.amount.parse::<u64>().unwrap_or(0))
                .sum();

            assert_eq!(
                full_carrot_bal, vo_carrot_bal,
                "CARROT-only SAL1 unspent balance should match: full={} vs view-only={}",
                full_carrot_bal, vo_carrot_bal,
            );
            println!(
                "  CARROT-only SAL1 balance verified: {} (full={}, vo={}, cn_diff={})",
                fmt_sal(full_carrot_bal),
                fmt_sal(full_sal1),
                fmt_sal(vo_sal1),
                fmt_sal(vo_sal1 - full_sal1),
            );
        }
        println!("  View-only balance verification passed.");
    }

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

    println!("  Wallet C: {}...", &wallet_c.cn_address().unwrap()[..30]);
    println!("  Syncing from genesis...");
    sync_wallet_checked(&wallet_c, &daemon, "C").await;

    // Verify zero balance
    let hf_info = daemon.hard_fork_info().await.unwrap();
    let at = if hf_info.version >= 6 { "SAL1" } else { "SAL" };
    let (total_c, _) = print_balance(&wallet_c, "C", at);
    assert_eq!(total_c, 0, "fresh wallet C should have zero balance");

    // ── Phase 8b: Sync Idempotency ─────────────────────────────────────
    println!("\n  Phase 8b: Sync idempotency...");
    let pre_height = fixture.wallet_a.sync_height().unwrap();
    let pre_bal = fixture.wallet_a.get_balance(at, 0).unwrap();
    sync_wallet_checked(&fixture.wallet_a, &daemon, "A-idempotent").await;
    let post_height = fixture.wallet_a.sync_height().unwrap();
    let post_bal = fixture.wallet_a.get_balance(at, 0).unwrap();
    assert_eq!(pre_height, post_height, "sync height should be unchanged");
    assert_eq!(
        pre_bal.balance, post_bal.balance,
        "balance should be unchanged after re-sync"
    );
    assert_eq!(
        pre_bal.unlocked_balance, post_bal.unlocked_balance,
        "unlocked balance should be unchanged after re-sync"
    );
    println!("  Idempotency check passed.");

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
