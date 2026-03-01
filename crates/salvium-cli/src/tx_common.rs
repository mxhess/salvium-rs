//! Shared transaction construction pipeline.
//!
//! Extracts the common UTXO-selection → key-derivation → decoy-fetch → ring-build
//! → sign → submit logic used by transfer, stake, burn, convert, sweep, etc.

use crate::AppContext;
use salvium_rpc::NodePool;
use salvium_wallet::Wallet;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A fully-prepared, signed transaction ready for submission.
#[allow(dead_code)]
pub struct SignedResult {
    pub tx_hash: [u8; 32],
    pub tx_hex: String,
    pub fee: u64,
}

/// Resolved network fee context — per-byte rate with priority already baked in.
///
/// Produced by [`resolve_fee_context()`]. The `fee_per_byte` comes from
/// `fees[priority.tier_index()]` of the daemon's `get_fee_estimate` RPC,
/// so priority is already incorporated — do NOT multiply again.
pub struct FeeContext {
    pub fee_per_byte: u64,
    /// Native asset type for the current network HF ("SAL" or "SAL1").
    pub native_asset: String,
}

/// Shared pipeline for building, signing, and optionally submitting transactions.
pub struct TxPipeline<'a> {
    pub wallet: &'a Wallet,
    pub pool: NodePool,
    pub fee_per_byte: u64,
}

impl<'a> TxPipeline<'a> {
    pub fn new(wallet: &'a Wallet, ctx: &AppContext, fee_ctx: &FeeContext) -> Self {
        Self { wallet, pool: ctx.pool.clone(), fee_per_byte: fee_ctx.fee_per_byte }
    }

    /// Select UTXOs for the given amount + fee, derive spend keys, and return
    /// input data ready for ring building.
    pub fn select_and_prepare_inputs(
        &self,
        amount: u64,
        estimated_fee: u64,
        asset_type: &str,
        strategy: salvium_wallet::utxo::SelectionStrategy,
    ) -> Result<(Vec<InputData>, u64)> {
        let selection = self.wallet.select_outputs(amount, estimated_fee, asset_type, strategy)?;
        println!(
            "Selected {} input(s), total {} {}",
            selection.selected.len(),
            crate::commands::format_sal_u64(selection.total),
            asset_type,
        );

        let actual_fee = salvium_tx::estimate_tx_fee(
            selection.selected.len(),
            2,
            salvium_tx::decoy::DEFAULT_RING_SIZE,
            true,
            0x04,
            self.fee_per_byte,
        );

        let keys = self.wallet.keys();
        let cn_spend_secret = keys.cn.spend_secret_key.ok_or("wallet has no spend secret key")?;
        let carrot_prove_spend =
            keys.carrot.prove_spend_key.ok_or("wallet has no CARROT prove_spend key")?;

        let mut inputs = Vec::new();
        for utxo in &selection.selected {
            let output = self
                .wallet
                .get_output(&utxo.key_image)?
                .ok_or_else(|| format!("output not found for key image: {}", utxo.key_image))?;

            let public_key =
                hex_to_32(output.public_key.as_deref().ok_or("output missing public_key")?)?;
            let mask = hex_to_32(output.mask.as_deref().ok_or("output missing mask")?)?;

            let (secret_key, secret_key_y) = if output.is_carrot {
                let s_sr_ctx = hex_to_32(
                    output
                        .carrot_shared_secret
                        .as_deref()
                        .ok_or("CARROT output missing shared_secret")?,
                )?;
                let commitment = if let Some(c) = output.commitment.as_deref() {
                    hex_to_32(c)?
                } else {
                    // Fallback: recompute from mask + amount (matches C++ wallet2).
                    let mask_hex = output.mask.as_deref().ok_or("CARROT output missing mask")?;
                    let mask = hex_to_32(mask_hex)?;
                    let amount =
                        output.amount.parse::<u64>().map_err(|e| format!("bad amount: {e}"))?;
                    let c = salvium_crypto::pedersen_commit(&amount.to_le_bytes(), &mask);
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&c[..32]);
                    arr
                };
                let (sk_x, sk_y) = salvium_crypto::carrot_scan::derive_carrot_spend_keys(
                    &carrot_prove_spend,
                    &keys.carrot.generate_image_key,
                    &s_sr_ctx,
                    &commitment,
                );
                (sk_x, Some(sk_y))
            } else {
                let tx_pub_key =
                    hex_to_32(output.tx_pub_key.as_deref().ok_or("CN output missing tx_pub_key")?)?;
                let sk = salvium_crypto::cn_scan::derive_output_spend_key(
                    &keys.cn.view_secret_key,
                    &cn_spend_secret,
                    &tx_pub_key,
                    output.output_index as u32,
                    output.subaddress_index.major as u32,
                    output.subaddress_index.minor as u32,
                );
                (sk, None)
            };

            inputs.push(InputData {
                block_height: utxo.block_height,
                public_key,
                mask,
                secret_key,
                secret_key_y,
                amount: utxo.amount,
            });
        }

        Ok((inputs, actual_fee))
    }

    /// Fetch decoy data from the daemon and build rings for each input,
    /// returning fully-prepared inputs ready for `TransactionBuilder`.
    ///
    /// Uses asset-type-specific indices for distribution, rings, and output
    /// fetches — matching how the daemon verifies ring members.
    pub async fn fetch_decoys(
        &self,
        inputs: &[InputData],
        asset_type: &str,
    ) -> Result<Vec<salvium_tx::builder::PreparedInput>> {
        println!("Fetching decoy data from daemon...");
        let dist = self.pool.get_output_distribution(&[0], 0, 0, true, asset_type).await?;
        let dist_entry = dist.first().ok_or("no output distribution returned from daemon")?;
        let rct_offsets = dist_entry.distribution.clone();
        let dist_start_height = dist_entry.start_height;
        let decoy_selector = salvium_tx::DecoySelector::new(rct_offsets.clone())
            .map_err(|e| format!("decoy selector: {}", e))?;

        let ring_size = salvium_tx::decoy::DEFAULT_RING_SIZE;
        let mut prepared = Vec::new();

        for inp in inputs {
            // Convert global_index → asset-type-specific index.
            let h_idx = if inp.block_height >= dist_start_height {
                (inp.block_height - dist_start_height) as usize
            } else {
                0
            };

            let at_start =
                if h_idx == 0 { 0 } else { rct_offsets[h_idx.min(rct_offsets.len()) - 1] };
            let at_end = rct_offsets[h_idx.min(rct_offsets.len() - 1)];
            let at_count = at_end - at_start;

            let asset_type_index = if at_count == 1 {
                at_start
            } else {
                // Multiple outputs at this height — probe to find the matching public key.
                let candidates: Vec<salvium_rpc::daemon::OutputRequest> = (at_start..at_end)
                    .map(|idx| salvium_rpc::daemon::OutputRequest { amount: 0, index: idx })
                    .collect();
                let probe = self.pool.get_outs(&candidates, false, asset_type).await?;

                let pub_key_hex = hex::encode(inp.public_key);
                probe
                    .iter()
                    .enumerate()
                    .find(|(_, out)| out.key == pub_key_hex)
                    .map(|(i, _)| at_start + i as u64)
                    .ok_or_else(|| {
                        format!(
                            "could not find asset-type index for output at height {} (range {}..{}, key={})",
                            inp.block_height, at_start, at_end, pub_key_hex
                        )
                    })?
            };

            // Pick decoy indices in asset-type index space.
            let (ring_indices, real_pos) = decoy_selector
                .build_ring(asset_type_index, ring_size)
                .map_err(|e| format!("ring build: {}", e))?;

            // Fetch ring member data using asset-type indices.
            let requests: Vec<salvium_rpc::daemon::OutputRequest> = ring_indices
                .iter()
                .map(|&idx| salvium_rpc::daemon::OutputRequest { amount: 0, index: idx })
                .collect();
            let outs_info = self.pool.get_outs(&requests, true, asset_type).await?;

            let mut ring_keys = Vec::with_capacity(ring_size);
            let mut ring_commitments = Vec::with_capacity(ring_size);
            for o in &outs_info {
                ring_keys.push(hex_to_32(&o.key)?);
                ring_commitments.push(hex_to_32(&o.mask)?);
            }

            prepared.push(salvium_tx::builder::PreparedInput {
                secret_key: inp.secret_key,
                secret_key_y: inp.secret_key_y,
                public_key: inp.public_key,
                amount: inp.amount,
                mask: inp.mask,
                asset_type: asset_type.to_string(),
                global_index: asset_type_index, // asset-type-specific index for key_offsets
                ring: ring_keys,
                ring_commitments,
                ring_indices,
                real_index: real_pos,
            });
        }

        Ok(prepared)
    }

    /// Build, sign, and submit a transaction from a configured builder.
    pub async fn build_sign_submit(
        &self,
        builder: salvium_tx::TransactionBuilder,
        asset_type: &str,
    ) -> Result<SignedResult> {
        println!("Building transaction...");
        let unsigned = builder.build().map_err(|e| format!("tx build: {}", e))?;

        println!("Signing transaction...");
        let signed_tx =
            salvium_tx::sign_transaction(unsigned).map_err(|e| format!("signing: {}", e))?;

        let tx_bytes = signed_tx.to_bytes().map_err(|e| format!("serialize: {}", e))?;
        let tx_hex = hex::encode(&tx_bytes);
        let tx_hash = signed_tx.tx_hash().map_err(|e| format!("tx hash: {}", e))?;

        println!("Submitting transaction...");
        let result = self
            .pool
            .send_raw_transaction_ex(&tx_hex, false, true, asset_type)
            .await
            .map_err(|e| format!("submission: {}", e))?;

        if result.status == "OK" {
            Ok(SignedResult {
                tx_hash,
                tx_hex,
                fee: 0, // caller sets this from their own context
            })
        } else {
            Err(format!(
                "daemon rejected transaction: status={}, double_spend={}, fee_too_low={}, invalid_input={}, invalid_output={}",
                result.status, result.double_spend, result.fee_too_low,
                result.invalid_input, result.invalid_output,
            )
            .into())
        }
    }
}

/// Intermediate representation of a selected UTXO with derived keys.
pub struct InputData {
    pub block_height: u64,
    pub public_key: [u8; 32],
    pub mask: [u8; 32],
    pub secret_key: [u8; 32],
    pub secret_key_y: Option<[u8; 32]>,
    pub amount: u64,
}

pub fn hex_to_32(s: &str) -> std::result::Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a fee priority string to the enum.
pub fn parse_fee_priority(s: &str) -> salvium_tx::fee::FeePriority {
    match s {
        "low" => salvium_tx::fee::FeePriority::Low,
        "normal" => salvium_tx::fee::FeePriority::Normal,
        "high" => salvium_tx::fee::FeePriority::High,
        "urgent" | "highest" => salvium_tx::fee::FeePriority::Highest,
        _ => salvium_tx::fee::FeePriority::Default,
    }
}

/// Adjust priority from network conditions AND fetch the dynamic `fee_per_byte`.
///
/// Resolves fee context from the daemon's `get_fee_estimate` RPC.
///
/// Uses `fees[priority.tier_index()]` directly — matching the C++ wallet2
/// behavior where 2021-scaling tiers already include priority.
///
/// Returns an error if the RPC fails — no silent fallback to a wrong constant.
pub async fn resolve_fee_context(
    pool: &NodePool,
    priority: salvium_tx::fee::FeePriority,
) -> Result<FeeContext> {
    use salvium_tx::fee::FeePriority;

    let info = pool.get_info().await?;
    let height = info.height;

    // --- Priority adjustment ---
    let adjusted = if priority != FeePriority::Default {
        priority
    } else {
        // 1. Mempool backlog -> Normal
        if info.tx_pool_size > 0 {
            log::info!("resolve_fee_context: mempool has {} txs, using Normal", info.tx_pool_size);
            FeePriority::Normal
        } else {
            // 2. Block fullness check
            let block_weight_limit =
                info.extra.get("block_weight_limit").and_then(|v| v.as_u64()).unwrap_or(600_000); // safe default = 2 * ZONE_V5
            let full_reward_zone = block_weight_limit / 2;

            if full_reward_zone == 0 || height < 10 {
                FeePriority::Normal
            } else {
                match pool.get_block_headers_range(height.saturating_sub(10), height - 1).await {
                    Ok(headers) => {
                        let weight_sum: u64 = headers.iter().map(|h| h.block_weight).sum();
                        let fullness_pct = 100 * weight_sum / (10 * full_reward_zone);
                        if fullness_pct > 80 {
                            log::info!(
                                "resolve_fee_context: blocks {fullness_pct}% full, using Normal"
                            );
                            FeePriority::Normal
                        } else {
                            log::info!(
                                "resolve_fee_context: blocks {fullness_pct}% full, using Low"
                            );
                            FeePriority::Low
                        }
                    }
                    Err(_) => FeePriority::Normal,
                }
            }
        }
    };

    // --- Fee per byte from daemon's get_fee_estimate RPC ---
    // The daemon returns fees[] = [Fl, Fn, Fm, Fh] with priority already baked in.
    // Select the right tier — matches C++ wallet2::get_base_fee(priority).
    let fee_estimate = pool.get_fee_estimate(10).await?;

    let tier = adjusted.tier_index();
    let fee_per_byte = if tier < fee_estimate.fees.len() {
        fee_estimate.fees[tier]
    } else {
        // Fallback: older daemon without fees array — use fee (= fees[0])
        fee_estimate.fee
    };
    log::info!(
        "resolve_fee_context: priority={:?} tier={} fee_per_byte={} (fees={:?})",
        adjusted,
        tier,
        fee_per_byte,
        fee_estimate.fees
    );

    // Derive native asset from hard fork version.
    let native_asset = match pool.hard_fork_info().await {
        Ok(hf) => if hf.version >= 6 { "SAL1" } else { "SAL" }.to_string(),
        Err(_) => "SAL1".to_string(), // all active networks are past HF6
    };

    Ok(FeeContext { fee_per_byte, native_asset })
}

/// Confirm with the user before proceeding.
pub fn confirm(prompt: &str) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    println!("{}", prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_lowercase() == "y")
}
