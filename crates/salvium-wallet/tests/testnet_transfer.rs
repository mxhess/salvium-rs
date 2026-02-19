//! End-to-end testnet transfer integration test.
//!
//! Performs a real SAL transfer from Wallet A → Wallet B on the Salvium testnet:
//!   1. Decrypt JS wallet file using its PIN
//!   2. Create a Rust Wallet from the extracted seed
//!   3. Sync against the testnet daemon
//!   4. Verify mined balance
//!   5. Build, sign, and submit a real transfer transaction
//!
//! Run with: cargo test -p salvium-wallet --test testnet_transfer -- --ignored --nocapture

use salvium_rpc::daemon::{DaemonRpc, OutputRequest};
use salvium_tx::builder::{Destination, PreparedInput, TransactionBuilder};
use salvium_tx::decoy::{DecoySelector, DEFAULT_RING_SIZE};
use salvium_tx::fee::{self, FeePriority};
use salvium_tx::sign::sign_transaction;
use salvium_tx::types::output_type;
use salvium_wallet::utxo::SelectionStrategy;
use salvium_wallet::{decrypt_js_wallet, Wallet};
use salvium_types::address::parse_address;
use salvium_types::constants::Network;

use std::path::PathBuf;

const DAEMON_URL: &str = "http://node12.whiskymine.io:29081";
const SEND_AMOUNT: u64 = 1_000_000_000; // 1 SAL (atomic units)

/// Wallet B's CN address (destination).
const WALLET_B_CN_ADDRESS: &str =
    "SaLvTyM4m5xBg4t4nnBYXS34HgkziW7rP42yNzvvafz34vqCkvxKCcLgy6AhhEHf8EEyjntA1Vo2wUNegJjQZgXpTaZ3nk159e33a";

fn testnet_wallet_dir() -> PathBuf {
    dirs::home_dir().unwrap().join("testnet-wallet")
}

#[tokio::test]
#[ignore]
async fn test_real_testnet_transfer() {
    println!("\n=== Salvium Testnet Transfer: Wallet A → Wallet B ===\n");

    // ── Step 1: Decrypt Wallet A ────────────────────────────────────────────
    println!("[1/8] Decrypting wallet-a.json...");
    let dir = testnet_wallet_dir();
    let wallet_json = std::fs::read_to_string(dir.join("wallet-a.json"))
        .expect("wallet-a.json not found in ~/testnet-wallet/");
    let pin = std::fs::read_to_string(dir.join("wallet-a.pin"))
        .expect("wallet-a.pin not found")
        .trim()
        .to_string();

    let secrets = decrypt_js_wallet(&wallet_json, &pin).expect("failed to decrypt wallet");
    println!(
        "  Seed:      {}...{}",
        &hex::encode(secrets.seed)[..8],
        &hex::encode(secrets.seed)[56..]
    );
    println!(
        "  Spend pub: {}",
        hex::encode(&salvium_crypto::scalar_mult_base(&secrets.spend_secret_key)[..32])
    );

    // ── Step 2: Create Rust Wallet ──────────────────────────────────────────
    println!("\n[2/8] Creating wallet from seed...");
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("wallet-a.db");
    let db_key = [0u8; 32];

    let wallet =
        Wallet::create(secrets.seed, Network::Testnet, db_path.to_str().unwrap(), &db_key)
            .expect("failed to create wallet");
    println!("  CN address:     {}", wallet.cn_address().unwrap());
    println!("  CARROT address: {}", wallet.carrot_address().unwrap());

    // ── Step 3: Sync against daemon ─────────────────────────────────────────
    println!("\n[3/8] Syncing wallet against {}...", DAEMON_URL);
    let daemon = DaemonRpc::new(DAEMON_URL);

    let info = daemon.get_info().await.expect("cannot connect to daemon");
    println!(
        "  Daemon height: {}, synchronized: {}",
        info.height, info.synchronized
    );
    assert!(info.synchronized, "daemon is not synchronized");

    // Query hardfork version to determine correct asset type.
    // HF >= 6 (SALVIUM_ONE_PROOFS): "SAL1" for TRANSFER/MINER/STAKE
    // HF < 6: "SAL"
    // Future hardforks may introduce additional asset types.
    let hf_info = daemon.hard_fork_info().await.expect("failed to get hard_fork_info");
    let hf_version = hf_info.version;
    let tx_asset_type = if hf_version >= 6 { "SAL1" } else { "SAL" };
    // DB stores outputs with whatever asset type was on-chain at scan time.
    // Pre-HF6 outputs are stored as "SAL", post-HF6 as "SAL1".
    let db_asset_type = "SAL"; // mined outputs from early blocks use "SAL"
    println!(
        "  Hardfork version: {}, tx_asset_type: {}, db_asset_type: {}",
        hf_version, tx_asset_type, db_asset_type
    );

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(100);
    let sync_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                salvium_wallet::SyncEvent::Progress {
                    current_height,
                    target_height,
                    outputs_found,
                } => {
                    if current_height % 100 == 0 || current_height == target_height {
                        println!(
                            "  Synced block {}/{} ({} outputs found)",
                            current_height, target_height, outputs_found
                        );
                    }
                }
                salvium_wallet::SyncEvent::Complete { height } => {
                    println!("  Sync complete at height {}", height);
                }
                salvium_wallet::SyncEvent::Reorg {
                    from_height,
                    to_height,
                } => {
                    println!("  Reorg detected: {} -> {}", from_height, to_height);
                }
                _ => {}
            }
        }
    });

    let sync_height = wallet
        .sync(&daemon, Some(&event_tx))
        .await
        .expect("sync failed");
    drop(event_tx);
    let _ = sync_handle.await;
    println!("  Final sync height: {}", sync_height);

    // ── Step 4: Verify balance ──────────────────────────────────────────────
    println!("\n[4/8] Checking balance...");
    let balance = wallet
        .get_balance(db_asset_type, 0)
        .expect("failed to get balance");
    let total_balance: u64 = balance.balance.parse().expect("invalid balance string");
    let unlocked_balance: u64 = balance
        .unlocked_balance
        .parse()
        .expect("invalid unlocked_balance string");
    println!(
        "  Total:    {:.9} SAL ({} atomic)",
        total_balance as f64 / 1e9,
        total_balance
    );
    println!(
        "  Unlocked: {:.9} SAL ({} atomic)",
        unlocked_balance as f64 / 1e9,
        unlocked_balance
    );
    assert!(
        unlocked_balance > 0,
        "wallet has no unlocked balance to spend"
    );
    assert!(
        unlocked_balance > SEND_AMOUNT,
        "insufficient balance: need {} but have {} unlocked",
        SEND_AMOUNT,
        unlocked_balance
    );

    // ── Step 5: Select UTXOs ────────────────────────────────────────────────
    println!("\n[5/8] Selecting outputs...");

    // Use daemon's dynamic fee estimate (accounts for current block size/reward).
    let fee_estimate = daemon.get_fee_estimate(10).await.expect("failed to get fee estimate");
    let daemon_fee_per_byte = fee_estimate.fee;
    println!("  Daemon fee per byte: {} atomic", daemon_fee_per_byte);

    // Estimate TX weight and compute fee using daemon's rate.
    let est_weight = fee::estimate_tx_weight(
        1, 2, DEFAULT_RING_SIZE, true, output_type::CARROT_V1,
    );
    let estimated_fee = (est_weight as u64) * daemon_fee_per_byte * FeePriority::Normal.multiplier();
    println!("  Estimated weight: {} bytes", est_weight);
    println!("  Estimated fee: {:.9} SAL ({} atomic)", estimated_fee as f64 / 1e9, estimated_fee);

    let selection = wallet
        .select_carrot_outputs(SEND_AMOUNT, estimated_fee, db_asset_type, SelectionStrategy::Default)
        .expect("CARROT output selection failed (no CARROT outputs?)");
    println!(
        "  Selected {} output(s), total: {:.9} SAL, change: {:.9} SAL",
        selection.selected.len(),
        selection.total as f64 / 1e9,
        selection.change as f64 / 1e9,
    );

    // ── Step 6: Build rings (decoy selection) ───────────────────────────────
    println!("\n[6/8] Building rings (decoy selection)...");
    // Get asset-type-specific output distribution. The daemon's verification
    // treats key_offsets as asset-type-specific indices, so we must use the
    // SAL1-specific distribution and indices throughout.
    let dist = daemon
        .get_output_distribution(&[0], 0, 0, true, tx_asset_type)
        .await
        .expect("failed to get output distribution");
    let dist_entry = &dist[0];
    let rct_offsets = &dist_entry.distribution;
    let total_at_outputs = *rct_offsets.last().unwrap_or(&0);
    println!(
        "  {} distribution: start_height={}, base={}, {} entries, {} total outputs",
        tx_asset_type,
        dist_entry.start_height,
        dist_entry.base,
        rct_offsets.len(),
        total_at_outputs
    );

    let decoy_selector =
        DecoySelector::new(rct_offsets.clone()).expect("failed to create decoy selector");

    // Parse destination address to get public keys.
    let dest_addr = parse_address(WALLET_B_CN_ADDRESS).expect("invalid destination address");

    // ── Step 5b: Resolve asset-type-specific output indices ─────────────────
    // The daemon uses asset-type-specific indices for TX key_offsets (see C++
    // scan_outputkeys_for_indexes → get_output_id_from_asset_type_output_index).
    // We resolve each real output's asset-type index using the cumulative
    // distribution + probing the daemon.
    println!("\n[5b/8] Resolving asset-type-specific output indices...");

    // Get block heights from get_transactions.
    let mut tx_hashes_to_resolve: Vec<String> = selection
        .selected
        .iter()
        .map(|u| {
            wallet
                .get_output(&u.key_image)
                .unwrap()
                .unwrap()
                .tx_hash
                .clone()
        })
        .collect();
    tx_hashes_to_resolve.sort();
    tx_hashes_to_resolve.dedup();

    let tx_hash_refs: Vec<&str> = tx_hashes_to_resolve.iter().map(|s| s.as_str()).collect();
    let tx_entries = daemon
        .get_transactions(&tx_hash_refs, false)
        .await
        .expect("failed to get transactions for index resolution");

    // Build a map: tx_hash → block_height.
    let mut tx_height_map: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    for (entry, tx_hash) in tx_entries.iter().zip(tx_hashes_to_resolve.iter()) {
        tx_height_map.insert(tx_hash.clone(), entry.block_height);
    }

    // Derive spending keys for each selected output and build rings.
    let keys = wallet.keys();
    let mut prepared_inputs = Vec::new();

    for utxo in &selection.selected {
        // Look up the output row for full metadata.
        let output_row = wallet
            .get_output(&utxo.key_image)
            .expect("failed to get output")
            .expect("output not found in DB");

        let output_index = output_row.output_index as u32;
        let output_pub_key_hex = output_row.public_key.as_ref().expect("missing public_key");
        let output_pub_key = hex_to_32(output_pub_key_hex);

        // Resolve asset-type-specific index from the cumulative distribution.
        // cumDist[h - start_height] = total asset-type outputs up to and including block h.
        let block_height = *tx_height_map
            .get(&output_row.tx_hash)
            .expect("tx not found in height map");
        let start_h = dist_entry.start_height;

        // Print distribution values around this height for debugging.
        let h_idx = (block_height - start_h) as usize;
        println!(
            "  Height {}: dist_idx={}, start_h={}",
            block_height, h_idx, start_h
        );
        if h_idx > 0 && h_idx < rct_offsets.len() {
            let before = if h_idx >= 2 { rct_offsets[h_idx - 2] } else { 0 };
            println!(
                "    cumDist[h-2]={}, cumDist[h-1]={}, cumDist[h]={}, cumDist[h+1]={}",
                before,
                rct_offsets[h_idx - 1],
                rct_offsets[h_idx],
                if h_idx + 1 < rct_offsets.len() { rct_offsets[h_idx + 1] } else { 0 }
            );
        }

        // Also verify by fetching with global index (no asset_type).
        {
            // Global index lookup is done via get_transactions output_indices below.
            // Actually let's get the global index from get_transactions output_indices
            let (_, ref global_indices_for_tx) = tx_entries.iter()
                .zip(tx_hashes_to_resolve.iter())
                .find(|(_, h)| **h == output_row.tx_hash)
                .map(|(e, h)| (h.clone(), e.output_indices.clone()))
                .unwrap_or_default();
            if !global_indices_for_tx.is_empty() {
                let gi = global_indices_for_tx[output_row.output_index as usize];
                println!("    Global index (from get_transactions): {}", gi);
                let probe_global = daemon
                    .get_outs(&[OutputRequest { amount: 0, index: gi }], false, "")
                    .await
                    .expect("probe global index");
                if !probe_global.is_empty() {
                    println!(
                        "    Global probe key: {}, height: {}",
                        &probe_global[0].key[..32], probe_global[0].height
                    );
                    if probe_global[0].key == *output_pub_key_hex {
                        println!("    Global probe: KEY MATCHES our output");
                    } else {
                        println!("    Global probe: KEY DOES NOT MATCH (wrong global index?)");
                    }
                }
            }
        }

        let at_start = if h_idx == 0 {
            0
        } else {
            rct_offsets[h_idx - 1]
        };
        let at_end = rct_offsets[h_idx];
        let at_count = at_end - at_start;

        let asset_type_index = if at_count == 1 {
            // Only one asset-type output at this height — must be ours.
            at_start
        } else if at_count == 0 {
            panic!(
                "no {} outputs at height {} for tx {}",
                tx_asset_type, block_height, output_row.tx_hash
            );
        } else {
            // Multiple outputs at this height. Probe to find ours by public key.
            let candidates: Vec<OutputRequest> = (at_start..at_end)
                .map(|idx| OutputRequest {
                    amount: 0,
                    index: idx,
                })
                .collect();
            let probe = daemon
                .get_outs(&candidates, false, tx_asset_type)
                .await
                .expect("failed to probe outputs for asset-type index");

            let mut found_idx = None;
            for (i, out) in probe.iter().enumerate() {
                if out.key == *output_pub_key_hex {
                    found_idx = Some(at_start + i as u64);
                    break;
                }
            }
            found_idx.unwrap_or_else(|| {
                panic!(
                    "could not find asset-type index for output {} at height {} (checked {} candidates)",
                    output_pub_key_hex, block_height, at_count
                );
            })
        };

        println!(
            "  Resolved asset-type index: tx={}...{}, height={}, at_idx={} (range {}..{})",
            &output_row.tx_hash[..8],
            &output_row.tx_hash[output_row.tx_hash.len() - 8..],
            block_height,
            asset_type_index,
            at_start,
            at_end
        );

        // Derive spending keys depending on output type.
        let (secret_key, secret_key_y, public_key) = if output_row.is_carrot {
            // CARROT output: needs prove_spend_key, generate_image_key, shared_secret, commitment.
            let prove_spend_key = keys.carrot.prove_spend_key.expect("not a full wallet");
            let generate_image_key = keys.carrot.generate_image_key;

            let shared_secret_hex = output_row
                .carrot_shared_secret
                .as_ref()
                .expect("missing carrot_shared_secret");
            let shared_secret = hex_to_32(shared_secret_hex);

            // The commitment is needed to derive extensions.
            // Use the stored commitment, or compute from mask + amount if not stored.
            let commitment = if let Some(ref c_hex) = output_row.commitment {
                hex_to_32(c_hex)
            } else {
                // Compute: C = mask*G + amount*H
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

            // Reconstruct the public key = sk_x*G + sk_y*T to verify.
            let pk = output_pub_key; // The stored output public key is the one-time address.
            (sk_x, Some(sk_y), pk)
        } else {
            // CryptoNote output: derive one-time spending key.
            let spend_secret = keys.cn.spend_secret_key.expect("not a full wallet");
            let view_secret = keys.cn.view_secret_key;
            let tx_pub_key_hex =
                output_row.tx_pub_key.as_ref().expect("missing tx_pub_key");
            let tx_pub_key = hex_to_32(tx_pub_key_hex);
            let subaddr_major = output_row.subaddress_index.major as u32;
            let subaddr_minor = output_row.subaddress_index.minor as u32;

            let sk = salvium_crypto::cn_scan::derive_output_spend_key(
                &view_secret,
                &spend_secret,
                &tx_pub_key,
                output_index,
                subaddr_major,
                subaddr_minor,
            );
            let pk = to_32(&salvium_crypto::scalar_mult_base(&sk));
            (sk, None, pk)
        };

        // Parse the output mask (commitment blinding factor).
        let mask = hex_to_32(output_row.mask.as_ref().expect("missing mask"));

        // Build ring with decoy selection using asset-type-specific indices.
        let (ring_indices, real_pos) = decoy_selector
            .build_ring(asset_type_index, DEFAULT_RING_SIZE)
            .expect("failed to build ring");

        // Fetch ring member public keys and commitments from daemon.
        // Pass asset_type so the daemon interprets indices as asset-type-specific.
        let out_requests: Vec<OutputRequest> = ring_indices
            .iter()
            .map(|&idx| OutputRequest {
                amount: 0,
                index: idx,
            })
            .collect();

        let ring_members = daemon
            .get_outs(&out_requests, false, tx_asset_type)
            .await
            .expect("failed to fetch ring members");

        let ring_keys: Vec<[u8; 32]> = ring_members.iter().map(|m| hex_to_32(&m.key)).collect();
        let ring_commitments: Vec<[u8; 32]> =
            ring_members.iter().map(|m| hex_to_32(&m.mask)).collect();

        // Verify the ring member at real_pos matches our expected public key.
        if ring_keys[real_pos] != public_key {
            println!(
                "  WARNING: ring[{}] key mismatch! ring={} expected={}",
                real_pos,
                hex::encode(ring_keys[real_pos]),
                hex::encode(public_key)
            );
        }

        println!(
            "  Input: {} SAL, at_idx={}, ring_size={}, real_pos={}, is_carrot={}",
            utxo.amount as f64 / 1e9,
            asset_type_index,
            ring_keys.len(),
            real_pos,
            output_row.is_carrot,
        );

        prepared_inputs.push(PreparedInput {
            secret_key,
            secret_key_y,
            public_key,
            amount: utxo.amount,
            mask,
            asset_type: tx_asset_type.to_string(),
            global_index: asset_type_index, // asset-type-specific index for key_offsets
            ring: ring_keys,
            ring_commitments,
            ring_indices,
            real_index: real_pos,
        });
    }

    // ── Step 7: Build and sign transaction ──────────────────────────────────
    println!("\n[7/8] Building and signing transaction...");
    println!(
        "  Sending {:.9} SAL to {}...{}",
        SEND_AMOUNT as f64 / 1e9,
        &WALLET_B_CN_ADDRESS[..20],
        &WALLET_B_CN_ADDRESS[WALLET_B_CN_ADDRESS.len() - 10..]
    );

    // Always use SALVIUM_ONE (TCLSAG) — the current testnet hardfork
    // requires it, and the builder only supports CARROT output construction.
    let rct = salvium_tx::types::rct_type::SALVIUM_ONE;
    assert!(
        prepared_inputs.iter().all(|i| i.secret_key_y.is_some()),
        "all inputs must be CARROT (have secret_key_y) for SALVIUM_ONE rct_type"
    );
    println!("  Using rct_type: {} (TCLSAG/CARROT)", rct);

    let mut builder = TransactionBuilder::new();

    for input in prepared_inputs {
        builder = builder.add_input(input);
    }

    builder = builder
        .add_destination(Destination {
            spend_pubkey: dest_addr.spend_public_key,
            view_pubkey: dest_addr.view_public_key,
            amount: SEND_AMOUNT,
            asset_type: tx_asset_type.to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_change_address(
            keys.carrot.account_spend_pubkey,
            keys.carrot.account_view_pubkey,
        )
        .set_asset_types(tx_asset_type, tx_asset_type)
        .set_rct_type(rct)
        .set_fee(estimated_fee);

    let unsigned = builder.build().expect("failed to build transaction");
    println!(
        "  Unsigned TX: {} inputs, {} outputs, fee: {:.9} SAL",
        unsigned.inputs.len(),
        unsigned.output_amounts.len(),
        unsigned.fee as f64 / 1e9
    );

    // Store the output commitments and masks before signing consumes the unsigned tx.
    let verify_output_masks = unsigned.output_masks.clone();
    let verify_output_amounts = unsigned.output_amounts.clone();
    let verify_output_commitments = unsigned.output_commitments.clone();
    #[allow(clippy::type_complexity)]
    let verify_inputs: Vec<(u64, [u8; 32], [u8; 32], Option<[u8; 32]>, Vec<[u8; 32]>, Vec<[u8; 32]>, usize)> = unsigned.inputs.iter().map(|i| {
        (i.amount, i.public_key, i.secret_key, i.secret_key_y, i.ring.clone(), i.ring_commitments.clone(), i.real_index)
    }).collect();
    let verify_fee = unsigned.fee;
    let verify_rct_type = unsigned.rct_type;
    let verify_input_masks: Vec<[u8; 32]> = unsigned.inputs.iter().map(|i| i.mask).collect();

    let signed_tx = sign_transaction(unsigned).expect("failed to sign transaction");
    let tx_hash = signed_tx.tx_hash().expect("failed to compute TX hash");
    println!("  TX hash: {}", hex::encode(tx_hash));

    let tx_bytes = signed_tx.to_bytes().expect("failed to serialize TX");
    let tx_hex = hex::encode(&tx_bytes);
    println!("  TX size: {} bytes", tx_bytes.len());

    // ── Crypto verification ─────────────────────────────────────────────────
    println!("\n[7b/8] Verifying cryptographic validity...");
    let rct = signed_tx.rct.as_ref().unwrap();

    // 1. Verify output commitments: C = mask*G + amount*H
    for (i, (mask, amount)) in verify_output_masks.iter().zip(verify_output_amounts.iter()).enumerate() {
        let expected = to_32(&salvium_crypto::pedersen_commit(&amount.to_le_bytes(), mask));
        if expected == verify_output_commitments[i] {
            println!("  Output {} commitment: MATCH", i);
        } else {
            println!("  Output {} commitment: MISMATCH!", i);
            println!("    Expected: {}", hex::encode(expected));
            println!("    Got:      {}", hex::encode(verify_output_commitments[i]));
        }
    }

    // 2. Verify pseudo-output commitments match input amounts.
    for (i, pseudo_out) in rct.pseudo_outs.iter().enumerate() {
        let (input_amount, _, _, _, _, _, _) = &verify_inputs[i];
        println!("  Input {} pseudo-out: {} (amount={})", i, hex::encode(pseudo_out), input_amount);
    }

    // 3. Balance check: sum(pseudo_outs) == sum(out_pk) + fee*H
    {
        // Compute fee commitment: fee * H (with zero mask)
        let zero_mask = [0u8; 32];
        let fee_commit = to_32(&salvium_crypto::pedersen_commit(&verify_fee.to_le_bytes(), &zero_mask));

        // Sum pseudo_outs
        let mut pseudo_sum = rct.pseudo_outs[0];
        for po in &rct.pseudo_outs[1..] {
            pseudo_sum = to_32(&salvium_crypto::point_add_compressed(
                &pseudo_sum, po
            ));
        }

        // Sum out_pk + fee
        let mut out_sum = rct.out_pk[0];
        for pk in &rct.out_pk[1..] {
            out_sum = to_32(&salvium_crypto::point_add_compressed(
                &out_sum, pk
            ));
        }
        out_sum = to_32(&salvium_crypto::point_add_compressed(
            &out_sum, &fee_commit
        ));

        if pseudo_sum == out_sum {
            println!("  Balance check: PASS");
        } else {
            println!("  Balance check: FAIL");
            println!("    sum(pseudo_outs) = {}", hex::encode(pseudo_sum));
            println!("    sum(out_pk)+fee*H = {}", hex::encode(out_sum));
        }
    }

    // 4. Verify TCLSAG signature.
    if !rct.tclsags.is_empty() {
        let prefix_hash = signed_tx.prefix_hash().expect("prefix hash");
        // Recompute message.
        let rct_base = {
            let mut buf = Vec::new();
            fn wv(buf: &mut Vec<u8>, mut val: u64) {
                loop {
                    let mut byte = (val & 0x7F) as u8;
                    val >>= 7;
                    if val > 0 { byte |= 0x80; }
                    buf.push(byte);
                    if val == 0 { break; }
                }
            }
            wv(&mut buf, verify_rct_type as u64);
            wv(&mut buf, verify_fee);
            for ei in &rct.ecdh_info { buf.extend_from_slice(&ei.amount); }
            for pk in &rct.out_pk { buf.extend_from_slice(pk); }
            // p_r (from signed TX)
            if let Some(ref pr) = rct.p_r {
                buf.extend_from_slice(pr);
            } else {
                let mut identity = [0u8; 32];
                identity[0] = 0x01;
                buf.extend_from_slice(&identity);
            }
            // salvium_data (extract actual pr_proof from signed TX)
            if let Some(ref sd) = rct.salvium_data {
                let dt = sd.get("salvium_data_type").and_then(|v| v.as_u64()).unwrap_or(0);
                wv(&mut buf, dt);
                // pr_proof
                if let Some(pr) = sd.get("pr_proof") {
                    let r = hex::decode(pr.get("R").and_then(|v| v.as_str()).unwrap_or("")).unwrap_or_default();
                    let z1 = hex::decode(pr.get("z1").and_then(|v| v.as_str()).unwrap_or("")).unwrap_or_default();
                    let z2 = hex::decode(pr.get("z2").and_then(|v| v.as_str()).unwrap_or("")).unwrap_or_default();
                    buf.extend_from_slice(&r);
                    buf.extend_from_slice(&z1);
                    buf.extend_from_slice(&z2);
                } else {
                    buf.extend_from_slice(&[0u8; 96]);
                }
                // sa_proof (zero for type 0)
                buf.extend_from_slice(&[0u8; 96]);
            }
            buf
        };
        let bp = &rct.bulletproof_plus[0];
        // BP+ hash components: flat concatenation of 32-byte keys (matching C++
        // get_pre_mlsag_hash rctSigs.cpp:830-843 — NO varint size prefixes).
        let bp_bytes = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&bp.a); buf.extend_from_slice(&bp.a1);
            buf.extend_from_slice(&bp.b); buf.extend_from_slice(&bp.r1);
            buf.extend_from_slice(&bp.s1); buf.extend_from_slice(&bp.d1);
            for l in &bp.l_vec { buf.extend_from_slice(l); }
            for r in &bp.r_vec { buf.extend_from_slice(r); }
            buf
        };
        let message = salvium_crypto::rct_verify::compute_rct_message(
            &prefix_hash, &rct_base, &bp_bytes
        );
        println!("  Message hash: {}", hex::encode(message));

        for (i, tclsag) in rct.tclsags.iter().enumerate() {
            let (_, input_pk, input_sk_x, _, ring, ring_commits, real_idx) = &verify_inputs[i];
            let ki = to_32(&salvium_crypto::generate_key_image(input_pk, input_sk_x));
            println!("  TCLSAG {} key_image: {}", i, hex::encode(ki));
            println!("  TCLSAG {} ring_size: {}, real_idx: {}", i, ring.len(), real_idx);
            println!("  TCLSAG {} real key: {}", i, hex::encode(ring[*real_idx]));
            println!("  TCLSAG {} input pk: {}", i, hex::encode(input_pk));
            // Check key match.
            if ring[*real_idx] != *input_pk {
                println!("  TCLSAG {} WARNING: ring[real_idx] != input_pk!", i);
            }

            let sig = salvium_crypto::tclsag::TclsagSignature {
                sx: tclsag.sx.clone(),
                sy: tclsag.sy.clone(),
                c1: tclsag.c1,
                key_image: ki,
                commitment_image: tclsag.d,
            };
            let valid = salvium_crypto::tclsag::tclsag_verify(
                &message, &sig, ring, ring_commits, &rct.pseudo_outs[i],
            );
            println!("  TCLSAG {} verify: {}", i, if valid { "PASS" } else { "FAIL" });

            // Debug: verify Ko = sk_x*G + sk_y*T
            let (_, _, sk_x, sk_y_opt, _, _, _) = &verify_inputs[i];
            if let Some(sk_y) = sk_y_opt {
                let g_part = salvium_crypto::scalar_mult_base(sk_x);
                let t_bytes: [u8; 32] = [
                    0x96, 0x6f, 0xc6, 0x6b, 0x82, 0xcd, 0x56, 0xcf,
                    0x85, 0xea, 0xec, 0x80, 0x1c, 0x42, 0x84, 0x5f,
                    0x5f, 0x40, 0x88, 0x78, 0xd1, 0x56, 0x1e, 0x00,
                    0xd3, 0xd7, 0xde, 0xd2, 0x79, 0x4d, 0x09, 0x4f,
                ];
                let t_part = salvium_crypto::scalar_mult_point(sk_y, &t_bytes);
                let expected_pk = to_32(&salvium_crypto::point_add_compressed(&g_part, &t_part));
                println!("  TCLSAG {} Ko verification:", i);
                println!("    Expected Ko = sk_x*G + sk_y*T: {}", hex::encode(expected_pk));
                println!("    Actual Ko (from DB):           {}", hex::encode(input_pk));
                println!("    Match: {}", expected_pk == *input_pk);
                println!("    sk_x: {}", hex::encode(sk_x));
                println!("    sk_y: {}", hex::encode(sk_y));
            }

            // Debug: verify commitment relationship
            let input_mask = &verify_input_masks[i];
            let input_commitment = ring_commits[*real_idx];
            let expected_commit = to_32(&salvium_crypto::pedersen_commit(
                &verify_inputs[i].0.to_le_bytes(), input_mask,
            ));
            println!("  TCLSAG {} commitment at real_idx:", i);
            println!("    Ring commit[{}]: {}", real_idx, hex::encode(input_commitment));
            println!("    Expected C=mask*G+amt*H: {}", hex::encode(expected_commit));
            println!("    Match: {}", input_commitment == expected_commit);
        }
    }

    // 5. BP+ verification skipped (requires curve25519-dalek dependency).

    // Diagnostic: verify serialization roundtrip.
    println!("\n[7c/8] Verifying serialization roundtrip...");
    let tx_json = signed_tx.to_json();
    let _json_str = serde_json::to_string_pretty(&tx_json).unwrap();
    println!("  TX JSON prefix version: {}", tx_json["prefix"]["version"]);
    println!("  TX JSON prefix txType: {}", tx_json["prefix"]["txType"]);
    println!("  TX JSON rct type: {}", tx_json["rct"]["type"]);
    println!("  TX JSON vout count: {}", tx_json["prefix"]["vout"].as_array().map_or(0, |a| a.len()));
    if let Some(vout) = tx_json["prefix"]["vout"].as_array() {
        for (i, out) in vout.iter().enumerate() {
            println!("    Output {}: type={}, assetType={}, viewTag={}",
                i,
                out["type"],
                out["assetType"],
                out["viewTag"]);
        }
    }
    println!("  TX JSON extra: {:?}", tx_json["prefix"]["extra"]);
    println!("  TX JSON salvium_data: {:?}", tx_json["rct"]["salvium_data"]);

    // Try parsing the bytes back.
    let roundtrip_json_str = salvium_crypto::parse_transaction_bytes(&tx_bytes);
    match serde_json::from_str::<serde_json::Value>(&roundtrip_json_str) {
        Ok(parsed) => {
            println!("  Roundtrip parse: OK");
            println!("    version: {}", parsed["prefix"]["version"]);
            println!("    txType: {}", parsed["prefix"]["txType"]);
            println!("    rct type: {}", parsed["rct"]["type"]);
            println!("    vout count: {}", parsed["prefix"]["vout"].as_array().map_or(0, |a| a.len()));
            if let Some(vout) = parsed["prefix"]["vout"].as_array() {
                for (i, out) in vout.iter().enumerate() {
                    println!("    Output {}: type={}, assetType={}", i, out["type"], out["assetType"]);
                }
            }

            // Re-serialize and compare.
            let roundtrip_bytes = salvium_crypto::serialize_transaction_json(&roundtrip_json_str);
            if roundtrip_bytes == tx_bytes {
                println!("  Re-serialization: MATCH ({} bytes)", roundtrip_bytes.len());
            } else {
                println!("  Re-serialization: MISMATCH (original={}, roundtrip={})",
                    tx_bytes.len(), roundtrip_bytes.len());
                // Find first difference.
                for i in 0..tx_bytes.len().min(roundtrip_bytes.len()) {
                    if tx_bytes[i] != roundtrip_bytes[i] {
                        println!("    First diff at byte {}: original=0x{:02x}, roundtrip=0x{:02x}",
                            i, tx_bytes[i], roundtrip_bytes[i]);
                        break;
                    }
                }
            }
        }
        Err(e) => {
            println!("  Roundtrip parse FAILED: {}", e);
            println!("  Raw parse result: {}...", &roundtrip_json_str[..200.min(roundtrip_json_str.len())]);
        }
    }

    // ── Step 7d: Hex dump analysis ──────────────────────────────────────────
    println!("\n[7d/8] TX hex dump analysis...");
    let tx_bytes_for_dump = hex::decode(&tx_hex).unwrap();
    println!("  Total TX size: {} bytes", tx_bytes_for_dump.len());
    println!("  First 128 bytes: {}", hex::encode(&tx_bytes_for_dump[..128.min(tx_bytes_for_dump.len())]));
    println!("  Last 64 bytes: {}", hex::encode(&tx_bytes_for_dump[tx_bytes_for_dump.len().saturating_sub(64)..]));
    // Manual decode of prefix start
    {
        let b = &tx_bytes_for_dump;
        let mut pos = 0;
        fn read_varint(b: &[u8], pos: &mut usize) -> u64 {
            let mut result: u64 = 0;
            let mut shift = 0;
            loop {
                if *pos >= b.len() { break; }
                let byte = b[*pos];
                *pos += 1;
                result |= ((byte & 0x7f) as u64) << shift;
                if byte & 0x80 == 0 { break; }
                shift += 7;
            }
            result
        }
        let version = read_varint(b, &mut pos);
        let unlock_time = read_varint(b, &mut pos);
        let vin_count = read_varint(b, &mut pos);
        println!("  Decoded prefix: version={}, unlock_time={}, vin_count={}", version, unlock_time, vin_count);

        for i in 0..vin_count {
            let tag = b[pos]; pos += 1;
            if tag == 0x02 { // txin_to_key
                let amount = read_varint(b, &mut pos);
                let at_len = read_varint(b, &mut pos);
                let asset_type = std::str::from_utf8(&b[pos..pos+at_len as usize]).unwrap_or("?");
                pos += at_len as usize;
                let ko_count = read_varint(b, &mut pos);
                println!("  Input {}: tag=0x{:02x}, amount={}, asset_type={}, key_offsets_count={}", i, tag, amount, asset_type, ko_count);
                for j in 0..ko_count { let ko = read_varint(b, &mut pos); if j < 3 { print!("    offset[{}]={} ", j, ko); } }
                if ko_count > 3 { print!("... "); }
                println!();
                println!("    key_image: {}", hex::encode(&b[pos..pos+32])); pos += 32;
            } else {
                println!("  Input {}: tag=0x{:02x}", i, tag);
                break;
            }
        }

        let vout_count = read_varint(b, &mut pos);
        println!("  vout_count={}", vout_count);
        for i in 0..vout_count {
            let amount = read_varint(b, &mut pos);
            let tag = b[pos]; pos += 1;
            if tag == 0x04 { // txout_to_carrot_v1
                let key = hex::encode(&b[pos..pos+32]); pos += 32;
                let at_len = read_varint(b, &mut pos);
                let asset_type = std::str::from_utf8(&b[pos..pos+at_len as usize]).unwrap_or("?");
                pos += at_len as usize;
                let view_tag = hex::encode(&b[pos..pos+3]); pos += 3;
                let janus = hex::encode(&b[pos..pos+16]); pos += 16;
                println!("  Output {}: amount={}, tag=CARROT, key={}..., asset={}, vt={}, janus={}...", i, amount, &key[..16], asset_type, view_tag, &janus[..16]);
            } else {
                println!("  Output {}: amount={}, tag=0x{:02x}", i, amount, tag);
                break;
            }
        }

        let extra_len = read_varint(b, &mut pos);
        println!("  extra: {} bytes, pos_after_extra={}", extra_len, pos + extra_len as usize);
        pos += extra_len as usize;

        let tx_type = read_varint(b, &mut pos);
        println!("  txType={}", tx_type);
        if tx_type != 0 && tx_type != 2 { // not UNSET, not PROTOCOL
            let amount_burnt = read_varint(b, &mut pos);
            println!("  amount_burnt={}", amount_burnt);
            if tx_type != 1 { // not MINER
                if tx_type == 3 && version >= 3 { // TRANSFER v3+
                    let ral_count = read_varint(b, &mut pos);
                    println!("  return_address_list: {} entries", ral_count);
                    for j in 0..ral_count {
                        println!("    [{}]: {}", j, hex::encode(&b[pos..pos+32])); pos += 32;
                    }
                    let mask_len = read_varint(b, &mut pos);
                    println!("  return_address_change_mask: {} bytes = {:?}", mask_len, &b[pos..pos+mask_len as usize]);
                    pos += mask_len as usize;
                }
                let sat_len = read_varint(b, &mut pos);
                let source_asset = std::str::from_utf8(&b[pos..pos+sat_len as usize]).unwrap_or("?");
                pos += sat_len as usize;
                let dat_len = read_varint(b, &mut pos);
                let dest_asset = std::str::from_utf8(&b[pos..pos+dat_len as usize]).unwrap_or("?");
                pos += dat_len as usize;
                let slippage = read_varint(b, &mut pos);
                println!("  source_asset={}, dest_asset={}, slippage={}", source_asset, dest_asset, slippage);
            }
        }
        println!("  --- PREFIX END at byte {} ---", pos);

        // RCT base
        let rct_type = b[pos]; pos += 1;
        println!("  RCT type={}", rct_type);
        if rct_type != 0 {
            let fee = read_varint(b, &mut pos);
            println!("  RCT fee={}", fee);
            println!("  ecdhInfo starts at byte {}", pos);
            // Skip ecdhInfo (2 outputs * 8 bytes)
            let _ecdh_start = pos;
            pos += (vout_count as usize) * 8;
            println!("  outPk starts at byte {}", pos);
            pos += (vout_count as usize) * 32;
            println!("  p_r at byte {}: {}", pos, hex::encode(&b[pos..pos+32]));
            pos += 32;
            println!("  salvium_data starts at byte {}", pos);
            let sd_type = read_varint(b, &mut pos);
            println!("  salvium_data_type={}", sd_type);
            println!("  pr_proof.R: {}", hex::encode(&b[pos..pos+32])); pos += 32;
            println!("  pr_proof.z1: {}", hex::encode(&b[pos..pos+32])); pos += 32;
            println!("  pr_proof.z2: {}", hex::encode(&b[pos..pos+32])); pos += 32;
            println!("  sa_proof.R: {}", hex::encode(&b[pos..pos+32])); pos += 32;
            println!("  sa_proof.z1: {}", hex::encode(&b[pos..pos+32])); pos += 32;
            println!("  sa_proof.z2: {}", hex::encode(&b[pos..pos+32])); pos += 32;
            println!("  --- RCT BASE END at byte {} ---", pos);

            // RCT prunable
            let nbp = read_varint(b, &mut pos);
            println!("  BP+ proofs: {}", nbp);
            // Skip BP+ proof details
            pos += 6 * 32; // A, A1, B, r1, s1, d1
            let l_count = read_varint(b, &mut pos);
            pos += (l_count as usize) * 32;
            let r_count = read_varint(b, &mut pos);
            pos += (r_count as usize) * 32;
            println!("  BP+ L_count={}, R_count={}", l_count, r_count);
            println!("  TCLSAG starts at byte {}", pos);
            // TCLSAG: ring_size * 32 (sx) + ring_size * 32 (sy) + 32 (c1) + 32 (D)
            let ring_size = 16; // known
            let tclsag_size = ring_size * 32 * 2 + 64;
            println!("  TCLSAG expected size: {} bytes (ring={})", tclsag_size, ring_size);
            pos += tclsag_size;
            println!("  pseudoOuts at byte {}: {}", pos, hex::encode(&b[pos..pos+32]));
            pos += 32;
            println!("  --- END at byte {} (total={}) ---", pos, b.len());
        }
    }

    // ── Step 8: Submit to daemon ────────────────────────────────────────────
    println!("\n[8/8] Submitting transaction to daemon...");

    // Try with source_asset_type and sanity checks enabled
    let result = daemon
        .send_raw_transaction_ex(&tx_hex, false, true, "SAL1")
        .await
        .expect("RPC call failed");

    println!("  Full response: {:?}", result);
    println!("  Status: {}", result.status);
    if !result.reason.is_empty() {
        println!("  Reason: {}", result.reason);
    }
    println!("  Flags: double_spend={}, fee_too_low={}, invalid_input={}, invalid_output={}, too_big={}, overspend={}, not_relayed={}, sanity_check_failed={}, tx_extra_too_big={}",
        result.double_spend, result.fee_too_low, result.invalid_input, result.invalid_output,
        result.too_big, result.overspend, result.not_relayed, result.sanity_check_failed, result.tx_extra_too_big);

    if result.status != "OK" {
        // Retry without sanity checks and with do_not_relay to isolate
        println!("\n  Retrying with do_sanity_checks=false, do_not_relay=true...");
        let result2 = daemon
            .send_raw_transaction_ex(&tx_hex, true, false, "SAL1")
            .await
            .expect("RPC call failed");
        println!("  Retry response: {:?}", result2);
    }

    assert_eq!(
        result.status, "OK",
        "transaction was rejected: {} (reason: {})",
        result.status, result.reason
    );

    println!("\n=== SUCCESS ===");
    println!("TX hash: {}", hex::encode(tx_hash));
    println!(
        "Sent {:.9} SAL from Wallet A to Wallet B",
        SEND_AMOUNT as f64 / 1e9
    );
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("invalid hex");
    assert!(
        bytes.len() == 32,
        "expected 32 bytes, got {}",
        bytes.len()
    );
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

fn to_32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = v.len().min(32);
    arr[..len].copy_from_slice(&v[..len]);
    arr
}
