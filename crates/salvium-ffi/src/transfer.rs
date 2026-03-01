//! High-level transfer, stake, and sweep operations.
//!
//! These wrap the full TX construction pipeline:
//! 1. Parse params + validate addresses
//! 2. UTXO selection
//! 3. Derive spend keys for selected UTXOs
//! 4. Decoy selection + fetch ring members
//! 5. Build unsigned TX
//! 6. Sign
//! 7. Broadcast (unless dry-run)
//! 8. Mark spent outputs in wallet DB
//! 9. Return result JSON

use std::ffi::{c_char, c_void};

use crate::error::ffi_try_string;
use crate::handles::borrow_handle;
use crate::strings::c_str_to_str;

use salvium_rpc::DaemonRpc;
use salvium_tx::builder::{Destination, PreparedInput, TransactionBuilder};
use salvium_tx::decoy::DecoySelector;
use salvium_tx::fee::{self, FeePriority};
use salvium_tx::types::{output_type, rct_type, tx_type};
use salvium_wallet::Wallet;

/// Transfer parameters (deserialized from JSON).
#[derive(serde::Deserialize)]
struct TransferParams {
    destinations: Vec<DestinationParam>,
    #[serde(default)]
    asset_type: String,
    #[serde(default = "default_priority")]
    priority: String,
    #[serde(default = "default_ring_size")]
    ring_size: usize,
    /// If true, build + sign but don't broadcast. Returns tx_hex in result.
    #[serde(default)]
    dry_run: bool,
}

#[derive(serde::Deserialize)]
struct DestinationParam {
    address: String,
    amount: String,
}

/// Stake parameters (deserialized from JSON).
#[derive(serde::Deserialize)]
struct StakeParams {
    amount: String,
    #[serde(default)]
    asset_type: String,
    #[serde(default = "default_priority")]
    priority: String,
    #[serde(default = "default_ring_size")]
    ring_size: usize,
}

/// Sweep parameters (deserialized from JSON).
#[derive(serde::Deserialize)]
struct SweepParams {
    address: String,
    #[serde(default)]
    asset_type: String,
    #[serde(default = "default_priority")]
    priority: String,
    #[serde(default = "default_ring_size")]
    ring_size: usize,
    /// If true, build + sign but don't broadcast. Returns tx_hex in result.
    #[serde(default)]
    dry_run: bool,
}

fn default_priority() -> String {
    "default".into()
}
fn default_ring_size() -> usize {
    16
}

fn parse_priority(s: &str) -> FeePriority {
    match s.to_lowercase().as_str() {
        "low" => FeePriority::Low,
        "normal" => FeePriority::Normal,
        "high" | "elevated" => FeePriority::High,
        "highest" | "urgent" => FeePriority::Highest,
        _ => FeePriority::Default,
    }
}

/// Resolved network fee context — priority + per-byte rate with priority already baked in.
struct FeeContext {
    priority: FeePriority,
    /// Per-byte fee rate from `fees[priority.tier_index()]`.
    /// Priority is already baked in — do NOT multiply again.
    fee_per_byte: u64,
}

/// Resolve fee context from the daemon's `get_fee_estimate` RPC.
///
/// Uses `fees[priority.tier_index()]` directly — matching the C++ wallet2
/// behavior where 2021-scaling tiers already include priority.
///
/// Returns an error if the RPC fails — no silent fallback to a wrong constant.
async fn resolve_fee_context(
    pool: &salvium_rpc::NodePool,
    priority: FeePriority,
) -> Result<FeeContext, String> {
    let info = pool.get_info().await.map_err(|e| format!("get_info failed: {e}"))?;
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
    let fee_estimate =
        pool.get_fee_estimate(10).await.map_err(|e| format!("get_fee_estimate failed: {e}"))?;

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

    Ok(FeeContext { priority: adjusted, fee_per_byte })
}

/// Transfer funds to one or more destinations.
///
/// `params_json` schema:
/// ```json
/// {
///   "destinations": [{"address": "Svk1...", "amount": "1000000000"}],
///   "assetType": "SAL1",
///   "priority": "normal",
///   "ring_size": 16
/// }
/// ```
///
/// Returns JSON on success: `{"tx_hash": "...", "fee": "...", "amount": "..."}`
/// Returns null on error.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_transfer(
    wallet: *mut c_void,
    daemon: *mut c_void,
    params_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wh = unsafe { borrow_handle::<crate::wallet::WalletHandle>(wallet) }?;
        let dh = unsafe { borrow_handle::<crate::daemon::DaemonHandle>(daemon) }?;
        let json_str = unsafe { c_str_to_str(params_json) }?;

        let params: TransferParams =
            serde_json::from_str(json_str).map_err(|e| format!("invalid transfer params: {e}"))?;

        if params.destinations.is_empty() {
            return Err("no destinations specified".into());
        }

        if !wh.wallet.can_spend() {
            return Err("wallet is view-only, cannot sign transactions".into());
        }

        let priority = parse_priority(&params.priority);
        let rt = crate::runtime();

        rt.block_on(async {
            let fee_ctx = resolve_fee_context(&dh.pool, priority).await?;
            let daemon = dh.pool.active_daemon().await;
            do_transfer(&wh.wallet, &daemon, &params, fee_ctx.priority, fee_ctx.fee_per_byte).await
        })
    })
}

/// Stake funds.
///
/// `params_json` schema:
/// ```json
/// {
///   "amount": "1000000000",
///   "assetType": "SAL1",
///   "priority": "normal",
///   "ring_size": 16
/// }
/// ```
///
/// Returns JSON on success: `{"tx_hash": "...", "fee": "...", "amount": "..."}`
/// Returns null on error.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_stake(
    wallet: *mut c_void,
    daemon: *mut c_void,
    params_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wh = unsafe { borrow_handle::<crate::wallet::WalletHandle>(wallet) }?;
        let dh = unsafe { borrow_handle::<crate::daemon::DaemonHandle>(daemon) }?;
        let json_str = unsafe { c_str_to_str(params_json) }?;

        let params: StakeParams =
            serde_json::from_str(json_str).map_err(|e| format!("invalid stake params: {e}"))?;

        if !wh.wallet.can_spend() {
            return Err("wallet is view-only, cannot sign transactions".into());
        }

        let priority = parse_priority(&params.priority);
        let rt = crate::runtime();

        rt.block_on(async {
            let fee_ctx = resolve_fee_context(&dh.pool, priority).await?;
            let daemon = dh.pool.active_daemon().await;
            do_stake(&wh.wallet, &daemon, &params, fee_ctx.priority, fee_ctx.fee_per_byte, false)
                .await
        })
    })
}

/// Build a stake transaction without broadcasting (dry run).
///
/// Same params as `salvium_wallet_stake`. Returns the estimated fee and
/// weight so the UI can show a confirmation dialog before committing.
///
/// Returns JSON: `{"fee": "...", "weight": ...}`
/// Returns null on error.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_stake_dry_run(
    wallet: *mut c_void,
    daemon: *mut c_void,
    params_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wh = unsafe { borrow_handle::<crate::wallet::WalletHandle>(wallet) }?;
        let dh = unsafe { borrow_handle::<crate::daemon::DaemonHandle>(daemon) }?;
        let json_str = unsafe { c_str_to_str(params_json) }?;

        let params: StakeParams =
            serde_json::from_str(json_str).map_err(|e| format!("invalid stake params: {e}"))?;

        if !wh.wallet.can_spend() {
            return Err("wallet is view-only, cannot sign transactions".into());
        }

        let priority = parse_priority(&params.priority);
        let rt = crate::runtime();

        rt.block_on(async {
            let fee_ctx = resolve_fee_context(&dh.pool, priority).await?;
            let daemon = dh.pool.active_daemon().await;
            do_stake(&wh.wallet, &daemon, &params, fee_ctx.priority, fee_ctx.fee_per_byte, true)
                .await
        })
    })
}

/// Sweep all unlocked funds of a given asset type to a single address.
///
/// `params_json` schema:
/// ```json
/// {
///   "address": "Svk1...",
///   "assetType": "SAL1",
///   "priority": "normal",
///   "ring_size": 16,
///   "dry_run": false
/// }
/// ```
///
/// Returns JSON on success: `{"tx_hash": "...", "fee": "...", "amount": "...", "tx_hex": "..."}`
/// `tx_hex` is only populated when `dry_run` is true.
/// Returns null on error.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_sweep(
    wallet: *mut c_void,
    daemon: *mut c_void,
    params_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wh = unsafe { borrow_handle::<crate::wallet::WalletHandle>(wallet) }?;
        let dh = unsafe { borrow_handle::<crate::daemon::DaemonHandle>(daemon) }?;
        let json_str = unsafe { c_str_to_str(params_json) }?;

        let params: SweepParams =
            serde_json::from_str(json_str).map_err(|e| format!("invalid sweep params: {e}"))?;

        if !wh.wallet.can_spend() {
            return Err("wallet is view-only, cannot sign transactions".into());
        }

        let priority = parse_priority(&params.priority);
        let rt = crate::runtime();

        rt.block_on(async {
            let fee_ctx = resolve_fee_context(&dh.pool, priority).await?;
            let daemon = dh.pool.active_daemon().await;
            do_sweep(&wh.wallet, &daemon, &params, fee_ctx.priority, fee_ctx.fee_per_byte).await
        })
    })
}

/// Build a transfer without broadcasting (dry run).
///
/// Same params as `salvium_wallet_transfer`. The `dry_run` field is
/// forced to `true` regardless of the JSON value.
///
/// Returns JSON: `{"tx_hash": "...", "fee": "...", "amount": "...", "tx_hex": "...", "weight": ...}`
/// Returns null on error.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_transfer_dry_run(
    wallet: *mut c_void,
    daemon: *mut c_void,
    params_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wh = unsafe { borrow_handle::<crate::wallet::WalletHandle>(wallet) }?;
        let dh = unsafe { borrow_handle::<crate::daemon::DaemonHandle>(daemon) }?;
        let json_str = unsafe { c_str_to_str(params_json) }?;

        let mut params: TransferParams =
            serde_json::from_str(json_str).map_err(|e| format!("invalid transfer params: {e}"))?;
        params.dry_run = true;

        if params.destinations.is_empty() {
            return Err("no destinations specified".into());
        }
        if !wh.wallet.can_spend() {
            return Err("wallet is view-only, cannot sign transactions".into());
        }

        let priority = parse_priority(&params.priority);
        let rt = crate::runtime();

        rt.block_on(async {
            let fee_ctx = resolve_fee_context(&dh.pool, priority).await?;
            let daemon = dh.pool.active_daemon().await;
            do_transfer(&wh.wallet, &daemon, &params, fee_ctx.priority, fee_ctx.fee_per_byte).await
        })
    })
}

// =============================================================================
// Internal Transfer Flow
// =============================================================================

/// Determine the fork-appropriate rct_type and output format from the daemon.
async fn detect_fork_params(daemon: &DaemonRpc) -> Result<(u8, bool), String> {
    let hf = daemon.hard_fork_info().await.map_err(|e| format!("hard_fork_info failed: {e}"))?;

    let (rct, is_carrot) = if hf.version >= 10 {
        (rct_type::SALVIUM_ONE, true)
    } else if hf.version >= 6 {
        (rct_type::SALVIUM_ZERO, false)
    } else {
        (rct_type::BULLETPROOF_PLUS, false)
    };

    Ok((rct, is_carrot))
}

async fn do_transfer(
    wallet: &Wallet,
    daemon: &DaemonRpc,
    params: &TransferParams,
    priority: FeePriority,
    fee_per_byte: u64,
) -> Result<String, String> {
    let (fork_rct, is_carrot) = detect_fork_params(daemon).await?;

    if params.asset_type.is_empty() {
        return Err("asset_type is required".into());
    }

    // 1. Parse and validate destinations.
    let mut destinations = Vec::new();
    let mut total_amount: u64 = 0;

    for d in &params.destinations {
        let parsed = salvium_types::address::parse_address(&d.address)
            .map_err(|e| format!("invalid address '{}': {e}", d.address))?;
        let amount: u64 =
            d.amount.parse().map_err(|e| format!("invalid amount '{}': {e}", d.amount))?;
        if amount == 0 {
            return Err("destination amount must be > 0".into());
        }
        total_amount = total_amount.checked_add(amount).ok_or("total amount overflow")?;

        destinations.push(Destination {
            spend_pubkey: parsed.spend_public_key,
            view_pubkey: parsed.view_public_key,
            amount,
            asset_type: params.asset_type.clone(),
            payment_id: parsed.payment_id.unwrap_or([0u8; 8]),
            is_subaddress: parsed.address_type == salvium_types::constants::AddressType::Subaddress,
        });
    }

    // 2. Estimate fee.
    let out_type = if is_carrot { output_type::CARROT_V1 } else { output_type::TAGGED_KEY };
    let num_outputs = destinations.len() + 1; // +1 for change
    let est_fee =
        fee::estimate_tx_fee(2, num_outputs, params.ring_size, is_carrot, out_type, fee_per_byte);

    // 3. Select UTXOs — caller specifies asset type, no output format filter.
    let selection = wallet
        .select_outputs(
            total_amount,
            est_fee,
            &params.asset_type,
            salvium_wallet::SelectionStrategy::Default,
        )
        .map_err(|e| format!("UTXO selection failed: {e}"))?;

    // 4. Build the transaction.
    let built = build_sign_maybe_broadcast(
        wallet,
        daemon,
        &destinations,
        &selection,
        &params.asset_type,
        tx_type::TRANSFER,
        params.ring_size,
        priority,
        fee_per_byte,
        0, // amount_burnt
        0, // unlock_time (no lock for TRANSFER)
        fork_rct,
        is_carrot,
        params.dry_run,
    )
    .await?;

    let mut result = serde_json::json!({
        "tx_hash": built.tx_hash,
        "fee": built.fee.to_string(),
        "amount": total_amount.to_string(),
        "weight": built.weight,
        "estimated_weight": built.estimated_weight,
        "fee_per_byte": built.fee_per_byte,
    });
    if params.dry_run {
        result["tx_hex"] = serde_json::Value::String(built.tx_hex);
    }
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

async fn do_stake(
    wallet: &Wallet,
    daemon: &DaemonRpc,
    params: &StakeParams,
    priority: FeePriority,
    fee_per_byte: u64,
    dry_run: bool,
) -> Result<String, String> {
    let (fork_rct, is_carrot) = detect_fork_params(daemon).await?;

    if params.asset_type.is_empty() {
        return Err("asset_type is required".into());
    }

    let amount: u64 =
        params.amount.parse().map_err(|e| format!("invalid amount '{}': {e}", params.amount))?;
    if amount == 0 {
        return Err("stake amount must be > 0".into());
    }

    // STAKE: the staked amount is handled entirely via amount_burnt.
    // No explicit destination — only a change output is created by the builder.
    // The protocol returns the staked amount + yield later.
    let out_type = if is_carrot { output_type::CARROT_V1 } else { output_type::TAGGED_KEY };
    let est_fee = fee::estimate_tx_fee(2, 1, params.ring_size, is_carrot, out_type, fee_per_byte);

    let selection = wallet
        .select_outputs(
            amount,
            est_fee,
            &params.asset_type,
            salvium_wallet::SelectionStrategy::Default,
        )
        .map_err(|e| format!("UTXO selection failed: {e}"))?;

    // STAKE requires unlock_time = current_height + stake_lock_period.
    let info = daemon.get_info().await.map_err(|e| format!("get_info failed: {e}"))?;
    let lock_period = salvium_types::constants::network_config(wallet.network()).stake_lock_period;
    let unlock_time = info.height + lock_period;

    let built = build_sign_maybe_broadcast(
        wallet,
        daemon,
        &[], // no destinations — stake amount is in amount_burnt
        &selection,
        &params.asset_type,
        tx_type::STAKE,
        params.ring_size,
        priority,
        fee_per_byte,
        amount, // amount_burnt = staked amount
        unlock_time,
        fork_rct,
        is_carrot,
        dry_run,
    )
    .await?;

    let result = serde_json::json!({
        "tx_hash": built.tx_hash,
        "fee": built.fee.to_string(),
        "amount": amount.to_string(),
        "weight": built.weight,
        "estimated_weight": built.estimated_weight,
        "fee_per_byte": built.fee_per_byte,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

async fn do_sweep(
    wallet: &Wallet,
    daemon: &DaemonRpc,
    params: &SweepParams,
    priority: FeePriority,
    fee_per_byte: u64,
) -> Result<String, String> {
    let (fork_rct, is_carrot) = detect_fork_params(daemon).await?;

    if params.asset_type.is_empty() {
        return Err("asset_type is required".into());
    }

    let parsed = salvium_types::address::parse_address(&params.address)
        .map_err(|e| format!("invalid address '{}': {e}", params.address))?;

    // 1. Select ALL unlocked outputs.
    let all_selection = wallet
        .select_outputs(0, 0, &params.asset_type, salvium_wallet::SelectionStrategy::All)
        .map_err(|e| format!("UTXO selection failed: {e}"))?;

    if all_selection.selected.is_empty() {
        return Err("no unlocked outputs to sweep".into());
    }

    // 2. Estimate fee with actual input count.
    let n_inputs = all_selection.selected.len();
    let out_type = if is_carrot { output_type::CARROT_V1 } else { output_type::TAGGED_KEY };
    let actual_fee =
        fee::estimate_tx_fee(n_inputs, 2, params.ring_size, is_carrot, out_type, fee_per_byte);

    let sweep_amount =
        all_selection.total.checked_sub(actual_fee).ok_or("balance too low to cover fee")?;

    if sweep_amount == 0 {
        return Err("balance too low to cover fee".into());
    }

    let destinations = vec![Destination {
        spend_pubkey: parsed.spend_public_key,
        view_pubkey: parsed.view_public_key,
        amount: sweep_amount,
        asset_type: params.asset_type.clone(),
        payment_id: parsed.payment_id.unwrap_or([0u8; 8]),
        is_subaddress: parsed.address_type == salvium_types::constants::AddressType::Subaddress,
    }];

    // 3. Build, sign, broadcast.
    let built = build_sign_maybe_broadcast(
        wallet,
        daemon,
        &destinations,
        &all_selection,
        &params.asset_type,
        tx_type::TRANSFER,
        params.ring_size,
        priority,
        fee_per_byte,
        0, // amount_burnt
        0, // unlock_time (no lock for sweep)
        fork_rct,
        is_carrot,
        params.dry_run,
    )
    .await?;

    let mut result = serde_json::json!({
        "tx_hash": built.tx_hash,
        "fee": built.fee.to_string(),
        "amount": sweep_amount.to_string(),
        "weight": built.weight,
        "estimated_weight": built.estimated_weight,
        "fee_per_byte": built.fee_per_byte,
    });
    if params.dry_run {
        result["tx_hex"] = serde_json::Value::String(built.tx_hex);
    }
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// Result of building (and optionally broadcasting) a transaction.
struct BuiltTx {
    tx_hash: String,
    fee: u64,
    tx_hex: String,
    weight: u64,
    estimated_weight: u64,
    fee_per_byte: u64,
}

/// Core TX construction pipeline shared by transfer, stake, and sweep.
#[allow(clippy::too_many_arguments)]
async fn build_sign_maybe_broadcast(
    wallet: &Wallet,
    daemon: &DaemonRpc,
    destinations: &[Destination],
    selection: &salvium_wallet::utxo::SelectionResult,
    asset_type: &str,
    tt: u8,
    ring_size: usize,
    priority: FeePriority,
    fee_per_byte: u64,
    amount_burnt: u64,
    unlock_time: u64,
    fork_rct_type: u8,
    is_carrot: bool,
    dry_run: bool,
) -> Result<BuiltTx, String> {
    let keys = wallet.keys();

    // 1. Get output distribution for decoy selection.
    // We use global index space (empty asset_type) because our wallet stores
    // global output indices. Both decoys and the real output use global IDs,
    // so the index spaces are consistent. This matches salvium-cli's approach.
    let dist = daemon
        .get_output_distribution(&[0], 0, 0, true, "")
        .await
        .map_err(|e| format!("get_output_distribution failed: {e}"))?;

    let rct_offsets = if dist.is_empty() {
        return Err("empty output distribution from daemon".into());
    } else {
        dist[0].distribution.clone()
    };

    let decoy_selector =
        DecoySelector::new(rct_offsets).map_err(|e| format!("decoy selector init failed: {e}"))?;

    // 2. For each selected UTXO, pick decoys and fetch ring member data.
    let mut prepared_inputs = Vec::new();

    for utxo in &selection.selected {
        // Pick decoy indices.
        let (ring_indices, real_pos) = decoy_selector
            .build_ring(utxo.global_index, ring_size)
            .map_err(|e| format!("build_ring failed: {e}"))?;

        // Fetch ring member data from daemon.
        let requests: Vec<salvium_rpc::daemon::OutputRequest> = ring_indices
            .iter()
            .map(|&idx| salvium_rpc::daemon::OutputRequest { amount: 0, index: idx })
            .collect();

        let outs = daemon
            .get_outs(&requests, true, "")
            .await
            .map_err(|e| format!("get_outs failed: {e}"))?;

        if outs.len() != ring_size {
            return Err(format!("expected {ring_size} ring members, got {}", outs.len()));
        }

        let ring: Vec<[u8; 32]> =
            outs.iter().map(|o| hex_to_32(&o.key)).collect::<Result<Vec<_>, _>>()?;

        let ring_commitments: Vec<[u8; 32]> =
            outs.iter().map(|o| hex_to_32(&o.mask)).collect::<Result<Vec<_>, _>>()?;

        // Derive the spend key for this output.
        let output_row = wallet
            .get_output(&utxo.key_image)
            .map_err(|e| format!("get_output failed: {e}"))?
            .ok_or_else(|| format!("output not found for key_image {}", utxo.key_image))?;

        let output_pub_key =
            hex_to_32(output_row.public_key.as_deref().ok_or("output missing public_key")?)?;

        let (secret_key, secret_key_y) = if output_row.is_carrot {
            // CARROT output: derive both x and y keys with subaddress adjustment.
            let prove_spend =
                keys.carrot.prove_spend_key.ok_or("no prove_spend_key (wallet is view-only)")?;
            let generate_image_key = keys.carrot.generate_image_key;

            let shared_secret = hex_to_32(
                output_row
                    .carrot_shared_secret
                    .as_deref()
                    .ok_or("CARROT output missing shared_secret")?,
            )?;

            let commitment = if let Some(c) = output_row.commitment.as_deref() {
                hex_to_32(c)?
            } else {
                // Fallback: recompute commitment from mask + amount (matches C++ wallet2 approach).
                let mask_hex = output_row.mask.as_deref().ok_or("CARROT output missing mask")?;
                let mask = hex_to_32(mask_hex)?;
                let amount =
                    output_row.amount.parse::<u64>().map_err(|e| format!("bad amount: {e}"))?;
                let c = salvium_crypto::pedersen_commit(&amount.to_le_bytes(), &mask);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&c[..32]);
                arr
            };

            // Adjust keys for subaddress outputs.
            let (adj_gik, adj_psk) = salvium_crypto::subaddress::carrot_adjust_keys_for_subaddress(
                &generate_image_key,
                &prove_spend,
                &keys.carrot.generate_address_secret,
                &keys.carrot.account_spend_pubkey,
                output_row.subaddress_index.major as u32,
                output_row.subaddress_index.minor as u32,
            );

            let (sx, sy) = salvium_crypto::carrot_scan::derive_carrot_spend_keys(
                &adj_psk,
                &adj_gik,
                &shared_secret,
                &commitment,
            );
            (sx, Some(sy))
        } else {
            // CryptoNote output.
            let spend_secret =
                keys.cn.spend_secret_key.ok_or("no spend_secret_key (wallet is view-only)")?;
            let tx_pub_key =
                hex_to_32(output_row.tx_pub_key.as_deref().ok_or("output missing tx_pub_key")?)?;

            let secret = salvium_crypto::cn_scan::derive_output_spend_key(
                &keys.cn.view_secret_key,
                &spend_secret,
                &tx_pub_key,
                output_row.output_index as u32,
                output_row.subaddress_index.major as u32,
                output_row.subaddress_index.minor as u32,
            );
            // For TCLSAG (rct_type >= SALVIUM_ONE), legacy outputs need secret_key_y = zero.
            // C++ uses carrot_ctkey{x, y=rct::zero(), mask} for non-CARROT inputs.
            let sk_y = if fork_rct_type >= rct_type::SALVIUM_ONE { Some([0u8; 32]) } else { None };
            (secret, sk_y)
        };

        let mask = hex_to_32(
            output_row
                .mask
                .as_deref()
                .unwrap_or("0100000000000000000000000000000000000000000000000000000000000000"),
        )?;

        prepared_inputs.push(PreparedInput {
            secret_key,
            secret_key_y,
            public_key: output_pub_key,
            amount: utxo.amount,
            mask,
            asset_type: asset_type.to_string(),
            global_index: utxo.global_index,
            ring,
            ring_commitments,
            ring_indices,
            real_index: real_pos,
        });
    }

    // 3. Build the unsigned transaction.
    let out_type = if is_carrot { output_type::CARROT_V1 } else { output_type::TAGGED_KEY };
    let n_inputs = prepared_inputs.len();
    let n_outputs = destinations.len() + 1; // +1 for change
    let estimated_weight =
        fee::estimate_tx_weight(n_inputs, n_outputs, ring_size, is_carrot, out_type);
    let actual_fee = fee::calculate_fee_from_weight(fee_per_byte, estimated_weight as u64);

    // Change address: use CARROT keys when in CARROT mode, CN keys otherwise.
    let (chg_spend, chg_view) = if is_carrot {
        (keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
    } else {
        (keys.cn.spend_public_key, keys.cn.view_public_key)
    };

    let mut builder = TransactionBuilder::new()
        .add_inputs(prepared_inputs)
        .set_change_address(chg_spend, chg_view)
        .set_tx_type(tt)
        .set_fee(actual_fee)
        .set_unlock_time(unlock_time)
        .set_priority(priority)
        .set_asset_types(asset_type, asset_type)
        .set_rct_type(fork_rct_type)
        .set_view_secret_key(keys.cn.view_secret_key);

    // CARROT outputs need the view_balance_secret for self-send ECDH.
    if is_carrot {
        builder = builder.set_change_view_balance_secret(keys.carrot.view_balance_secret);
    }

    if amount_burnt > 0 {
        builder = builder.set_amount_burnt(amount_burnt);
    }

    for dest in destinations {
        builder = builder.add_destination(dest.clone());
    }

    let unsigned = builder.build().map_err(|e| format!("transaction build failed: {e}"))?;
    let actual_fee = unsigned.fee;

    // 4. Sign the transaction.
    let signed = salvium_tx::sign_transaction(unsigned)
        .map_err(|e| format!("transaction signing failed: {e}"))?;

    // 5. Serialize.
    let tx_hash = hex::encode(signed.tx_hash().map_err(|e| format!("tx hash failed: {e}"))?);
    let tx_bytes = signed.to_bytes().map_err(|e| format!("tx serialize failed: {e}"))?;
    let tx_hex = hex::encode(&tx_bytes);
    let weight = tx_bytes.len() as u64;

    // Diagnostic: compare estimated weight vs actual serialized size.
    let fee_needed_for_actual = fee::calculate_fee_from_weight(fee_per_byte, weight);
    let weight_diff = weight as i64 - estimated_weight as i64;
    let weight_pct = if estimated_weight > 0 {
        100.0 * weight_diff as f64 / estimated_weight as f64
    } else {
        0.0
    };
    log::info!(
        "FEE DIAGNOSTIC: tx_type={} inputs={} outputs={} carrot={} \
         estimated_weight={} actual_blob_size={} diff={} ({:+.1}%) \
         fee_set={} fee_needed_for_blob={} fee_per_byte={} {}",
        tt,
        n_inputs,
        n_outputs,
        is_carrot,
        estimated_weight,
        weight,
        weight_diff,
        weight_pct,
        actual_fee,
        fee_needed_for_actual,
        fee_per_byte,
        if fee_needed_for_actual > actual_fee { "*** FEE TOO LOW ***" } else { "OK" }
    );

    // 6. Broadcast (unless dry run).
    if !dry_run {
        let send_result = daemon
            .send_raw_transaction_ex(&tx_hex, false, true, asset_type)
            .await
            .map_err(|e| format!("broadcast failed: {e}"))?;

        if send_result.status != "OK" {
            let mut flags = Vec::new();
            if send_result.double_spend {
                flags.push("double_spend");
            }
            if send_result.fee_too_low {
                flags.push("fee_too_low");
            }
            if send_result.invalid_input {
                flags.push("invalid_input");
            }
            if send_result.invalid_output {
                flags.push("invalid_output");
            }
            if send_result.overspend {
                flags.push("overspend");
            }
            if send_result.too_big {
                flags.push("too_big");
            }
            if send_result.sanity_check_failed {
                flags.push("sanity_check_failed");
            }
            if send_result.tx_extra_too_big {
                flags.push("tx_extra_too_big");
            }
            let detail = if !flags.is_empty() {
                flags.join(", ")
            } else if !send_result.reason.is_empty() {
                send_result.reason.clone()
            } else {
                "unknown".to_string()
            };
            return Err(format!(
                "daemon rejected transaction: {} ({}) [est_weight={} actual_weight={} fee={} fee_needed={} fpb={}]",
                send_result.status, detail,
                estimated_weight, weight, actual_fee, fee_needed_for_actual, fee_per_byte
            ));
        }

        // Mark spent outputs in wallet DB.
        for utxo in &selection.selected {
            let _ = wallet.mark_output_spent(&utxo.key_image, &tx_hash);
        }
    }

    Ok(BuiltTx {
        tx_hash,
        fee: actual_fee,
        tx_hex,
        weight,
        estimated_weight: estimated_weight as u64,
        fee_per_byte,
    })
}

fn hex_to_32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex '{hex_str}': {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {} from hex '{hex_str}'", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
