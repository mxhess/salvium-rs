//! Transfer variant commands: transfer, stake, burn, convert, audit,
//! locked_transfer, sweep_all, sweep_below, sweep_single, sweep_unmixable,
//! locked_sweep_all, return_payment, donate.

use super::*;
use crate::tx_common::{self, TxPipeline};

pub async fn transfer(
    ctx: &AppContext,
    address: &str,
    amount_str: &str,
    priority: &str,
    asset_override: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot send from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;
    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    println!("Transfer:");
    println!("  To:     {}", address);
    println!("  Amount: {} {}", format_sal_u64(amount), asset);
    println!("  Format: {:?}", parsed_addr.format);
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_ctx.fee_per_byte);
    println!("  Estimated fee: {} {}", format_sal_u64(est_fee), asset);
    println!();

    let balance = wallet.get_balance(asset, 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + est_fee {
        return Err(format!(
            "insufficient unlocked balance: have {} {}, need {} {}",
            format_sal_u64(unlocked),
            asset,
            format_sal_u64(amount + est_fee),
            asset,
        )
        .into());
    }

    if !tx_common::confirm("Confirm transfer? [y/N] ")? {
        println!("Transfer cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    let keys = wallet.keys();
    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount,
            asset_type: asset.to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!("Transaction submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Fee:     {} {}", format_sal_u64(actual_fee), asset);

    Ok(())
}

pub async fn stake(ctx: &AppContext, amount_str: &str, asset_override: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot stake from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;

    let fee_ctx =
        tx_common::resolve_fee_context(&ctx.pool, salvium_tx::fee::FeePriority::Default).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    println!("Stake:");
    println!("  Amount: {} {}", format_sal_u64(amount), asset);
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_ctx.fee_per_byte);
    println!("  Estimated fee: {} {}", format_sal_u64(est_fee), asset);
    println!();

    let balance = wallet.get_balance(asset, 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + est_fee {
        return Err(format!(
            "insufficient unlocked balance: have {} {}, need {} {}",
            format_sal_u64(unlocked),
            asset,
            format_sal_u64(amount + est_fee),
            asset,
        )
        .into());
    }

    if !tx_common::confirm("Confirm stake? [y/N] ")? {
        println!("Stake cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount,
            asset_type: asset.to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::STAKE)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!("Stake transaction submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Amount:  {} {}", format_sal_u64(amount), asset);
    println!("  Fee:     {} {}", format_sal_u64(actual_fee), asset);

    Ok(())
}

pub async fn burn(
    ctx: &AppContext,
    amount_str: &str,
    priority: &str,
    asset_override: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot burn from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;
    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    println!("Burn:");
    println!("  Amount: {} {}", format_sal_u64(amount), asset);
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_ctx.fee_per_byte);
    println!("  Estimated fee: {} {}", format_sal_u64(est_fee), asset);

    let balance = wallet.get_balance(asset, 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + est_fee {
        return Err(format!(
            "insufficient unlocked balance: have {} {}, need {} {}",
            format_sal_u64(unlocked),
            asset,
            format_sal_u64(amount + est_fee),
            asset,
        )
        .into());
    }

    if !tx_common::confirm("WARNING: Burning tokens is irreversible. Confirm? [y/N] ")? {
        println!("Burn cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::BURN)
        .set_amount_burnt(amount)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!("Burn transaction submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Burnt:   {} {}", format_sal_u64(amount), asset);
    println!("  Fee:     {} {}", format_sal_u64(actual_fee), asset);

    Ok(())
}

pub async fn convert(
    ctx: &AppContext,
    amount_str: &str,
    source_asset: &str,
    dest_asset: &str,
    priority: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot convert from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;
    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let source = if source_asset.is_empty() { &fee_ctx.native_asset } else { source_asset };

    println!("Convert:");
    println!("  Amount: {} {}", format_sal_u64(amount), source);
    println!("  From:   {}", source);
    println!("  To:     {}", dest_asset);
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_ctx.fee_per_byte);
    println!("  Estimated fee: {} {}", format_sal_u64(est_fee), source);

    let balance = wallet.get_balance(source, 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + est_fee {
        return Err(format!(
            "insufficient unlocked {} balance: have {}, need {}",
            source,
            format_sal_u64(unlocked),
            format_sal_u64(amount + est_fee)
        )
        .into());
    }

    if !tx_common::confirm("Confirm conversion? [y/N] ")? {
        println!("Conversion cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        source,
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs, source).await?;

    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount,
            asset_type: dest_asset.to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::CONVERT)
        .set_asset_types(source, dest_asset)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, source).await?;
    println!("Conversion submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Fee:     {} {}", format_sal_u64(actual_fee), source);

    Ok(())
}

pub async fn audit(ctx: &AppContext, priority: &str, asset_override: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot audit from a view-only wallet".into());
    }

    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    // Audit sweeps all funds back to self as a verifiable on-chain proof.
    let balance = wallet.get_balance(asset, 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    let est_fee = salvium_tx::estimate_tx_fee(4, 2, 16, true, 0x04, fee_ctx.fee_per_byte);

    if unlocked <= est_fee {
        return Err("insufficient balance for audit transaction".into());
    }

    let amount = unlocked - est_fee;

    println!("Audit:");
    println!("  Amount: {} {} (sweep to self)", format_sal_u64(amount), asset);
    println!("  Fee:    {} {}", format_sal_u64(est_fee), asset);

    if !tx_common::confirm("Confirm audit transaction? [y/N] ")? {
        println!("Audit cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::All,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount,
            asset_type: asset.to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::AUDIT)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!("Audit transaction submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));

    Ok(())
}

pub async fn locked_transfer(
    ctx: &AppContext,
    address: &str,
    amount_str: &str,
    unlock_time: u64,
    priority: &str,
    asset_override: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot send from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;
    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    println!("Locked Transfer:");
    println!("  To:          {}", address);
    println!("  Amount:      {} {}", format_sal_u64(amount), asset);
    println!("  Unlock time: {}", unlock_time);
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_ctx.fee_per_byte);
    println!("  Estimated fee: {} {}", format_sal_u64(est_fee), asset);

    if !tx_common::confirm("Confirm locked transfer? [y/N] ")? {
        println!("Transfer cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    let keys = wallet.keys();
    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount,
            asset_type: asset.to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_unlock_time(unlock_time)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!("Locked transfer submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Fee:     {} {}", format_sal_u64(actual_fee), asset);

    Ok(())
}

/// Max inputs per sweep TX (matches C++ CARROT_MAX_TX_INPUTS).
const MAX_SWEEP_INPUTS_PER_TX: usize = 64;

/// Sweep `inputs` to `dest_addr` in batches of up to 64 inputs each.
/// Each batch becomes a separate on-chain transaction.
async fn sweep_batched(
    pipeline: &TxPipeline<'_>,
    all_inputs: Vec<tx_common::InputData>,
    parsed_addr: &salvium_types::address::ParsedAddress,
    asset_type: &str,
) -> Result {
    let n_total = all_inputs.len();

    // Split into batches.
    let mut batches: Vec<Vec<tx_common::InputData>> = Vec::new();
    let mut batch = Vec::new();
    for input in all_inputs {
        batch.push(input);
        if batch.len() >= MAX_SWEEP_INPUTS_PER_TX {
            batches.push(std::mem::take(&mut batch));
        }
    }
    if !batch.is_empty() {
        batches.push(batch);
    }

    let n_batches = batches.len();
    if n_batches > 1 {
        println!(
            "Splitting {} inputs into {} transactions (max {} per TX).",
            n_total, n_batches, MAX_SWEEP_INPUTS_PER_TX
        );
    }

    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let mut total_swept = 0u64;
    let mut total_fee = 0u64;

    for (i, batch_inputs) in batches.into_iter().enumerate() {
        let n_inputs = batch_inputs.len();
        let batch_total: u64 = batch_inputs.iter().map(|inp| inp.amount).sum();

        let batch_fee = salvium_tx::estimate_tx_fee(
            n_inputs,
            2,
            salvium_tx::decoy::DEFAULT_RING_SIZE,
            true,
            0x04,
            pipeline.fee_per_byte,
        );

        if batch_total <= batch_fee {
            println!("  Batch {}/{}: skip (dust, fee exceeds total)", i + 1, n_batches);
            continue;
        }

        let sweep_amount = batch_total - batch_fee;

        if n_batches > 1 {
            println!(
                "\n  Batch {}/{}: {} inputs, {} {}",
                i + 1,
                n_batches,
                n_inputs,
                format_sal_u64(sweep_amount),
                asset_type
            );
        }

        let prepared = pipeline.fetch_decoys(&batch_inputs, asset_type).await?;

        let builder = salvium_tx::TransactionBuilder::new()
            .add_inputs(prepared)
            .add_destination(salvium_tx::builder::Destination {
                spend_pubkey: parsed_addr.spend_public_key,
                view_pubkey: parsed_addr.view_public_key,
                amount: sweep_amount,
                asset_type: asset_type.to_string(),
                payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
                is_subaddress,
            })
            .set_fee(batch_fee);

        let result = pipeline.build_sign_submit(builder, asset_type).await?;
        println!("  TX hash: {}", hex::encode(result.tx_hash));
        println!("  Swept:   {} {}", format_sal_u64(sweep_amount), asset_type);
        println!("  Fee:     {} {}", format_sal_u64(batch_fee), asset_type);

        total_swept += sweep_amount;
        total_fee += batch_fee;
    }

    if n_batches > 1 {
        println!(
            "\nSweep complete: {} TX(s), {} {} swept, {} {} total fee",
            n_batches,
            format_sal_u64(total_swept),
            asset_type,
            format_sal_u64(total_fee),
            asset_type
        );
    } else {
        println!("Sweep submitted successfully!");
    }

    Ok(())
}

pub async fn sweep_all(
    ctx: &AppContext,
    address: &str,
    priority: &str,
    asset_override: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    let balance = wallet.get_balance(asset, 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    let est_fee = salvium_tx::estimate_tx_fee(4, 1, 16, true, 0x04, fee_ctx.fee_per_byte);

    if unlocked <= est_fee {
        return Err("insufficient balance for sweep".into());
    }

    let amount = unlocked - est_fee;
    println!("Sweep all:");
    println!("  To:     {}", address);
    println!("  Amount: ~{} {}", format_sal_u64(amount), asset);
    println!("  Fee:    ~{} {} (per batch)", format_sal_u64(est_fee), asset);

    if !tx_common::confirm("Confirm sweep? [y/N] ")? {
        println!("Sweep cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, _) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::All,
    )?;

    sweep_batched(&pipeline, inputs, &parsed_addr, asset).await
}

pub async fn sweep_below(
    ctx: &AppContext,
    address: &str,
    threshold_str: &str,
    priority: &str,
    asset_override: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let threshold = parse_sal_amount(threshold_str)?;
    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    // Get outputs below threshold.
    let query = salvium_crypto::storage::OutputQuery {
        is_spent: Some(false),
        is_frozen: Some(false),
        asset_type: Some(asset.to_string()),
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;
    let below: Vec<_> =
        outputs.iter().filter(|o| o.amount.parse::<u64>().unwrap_or(0) < threshold).collect();

    if below.is_empty() {
        println!("No outputs found below {} {}.", format_sal_u64(threshold), asset);
        return Ok(());
    }

    let total: u64 = below.iter().map(|o| o.amount.parse::<u64>().unwrap_or(0)).sum();
    let est_fee = salvium_tx::estimate_tx_fee(below.len(), 1, 16, true, 0x04, fee_ctx.fee_per_byte);

    if total <= est_fee {
        return Err("total of outputs below threshold doesn't cover the fee".into());
    }

    println!(
        "Sweep below {} {}: {} outputs, total {} {}",
        format_sal_u64(threshold),
        asset,
        below.len(),
        format_sal_u64(total),
        asset,
    );

    if !tx_common::confirm("Confirm sweep? [y/N] ")? {
        println!("Sweep cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, _) = pipeline.select_and_prepare_inputs(
        total - est_fee,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::SmallestFirst,
    )?;

    sweep_batched(&pipeline, inputs, &parsed_addr, asset).await
}

pub async fn sweep_single(
    ctx: &AppContext,
    key_image: &str,
    address: &str,
    priority: &str,
    asset_override: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    let output = wallet
        .get_output(key_image)?
        .ok_or_else(|| format!("output not found for key image: {}", key_image))?;

    let amount: u64 = output.amount.parse().unwrap_or(0);
    let est_fee = salvium_tx::estimate_tx_fee(1, 1, 16, true, 0x04, fee_ctx.fee_per_byte);

    if amount <= est_fee {
        return Err("output amount doesn't cover the fee".into());
    }

    println!("Sweep single output:");
    println!("  Key image: {}", key_image);
    println!("  Amount:    {} {}", format_sal_u64(amount), asset);
    println!("  To:        {}", address);

    if !tx_common::confirm("Confirm? [y/N] ")? {
        println!("Sweep cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount - est_fee,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let sweep_amount = inputs.iter().map(|i| i.amount).sum::<u64>() - actual_fee;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount: sweep_amount,
            asset_type: asset.to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!("Sweep submitted! TX hash: {}", hex::encode(result.tx_hash));

    Ok(())
}

pub async fn sweep_unmixable(ctx: &AppContext, asset_override: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let fee_ctx =
        tx_common::resolve_fee_context(&ctx.pool, salvium_tx::fee::FeePriority::Default).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    // Find outputs with non-zero denomination amounts (pre-RCT or dust).
    let query = salvium_crypto::storage::OutputQuery {
        is_spent: Some(false),
        is_frozen: Some(false),
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;
    let dust_threshold = 1_000_000u64; // 0.001 SAL
    let unmixable: Vec<_> =
        outputs.iter().filter(|o| o.amount.parse::<u64>().unwrap_or(0) < dust_threshold).collect();

    if unmixable.is_empty() {
        println!("No unmixable outputs found.");
        return Ok(());
    }

    let total: u64 = unmixable.iter().map(|o| o.amount.parse::<u64>().unwrap_or(0)).sum();
    println!(
        "Found {} unmixable outputs totalling {} {}",
        unmixable.len(),
        format_sal_u64(total),
        asset
    );

    if !tx_common::confirm("Sweep unmixable outputs to self? [y/N] ")? {
        println!("Cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let est_fee =
        salvium_tx::estimate_tx_fee(unmixable.len(), 1, 16, true, 0x04, fee_ctx.fee_per_byte);

    if total <= est_fee {
        return Err("total of unmixable outputs doesn't cover the fee".into());
    }

    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        total - est_fee,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::SmallestFirst,
    )?;
    let sweep_amount = inputs.iter().map(|i| i.amount).sum::<u64>() - actual_fee;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount: sweep_amount,
            asset_type: asset.to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!(
        "Swept {} unmixable outputs! TX hash: {}",
        unmixable.len(),
        hex::encode(result.tx_hash)
    );

    Ok(())
}

pub async fn locked_sweep_all(
    ctx: &AppContext,
    address: &str,
    unlock_time: u64,
    priority: &str,
    asset_override: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    let balance = wallet.get_balance(asset, 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    let est_fee = salvium_tx::estimate_tx_fee(4, 1, 16, true, 0x04, fee_ctx.fee_per_byte);

    if unlocked <= est_fee {
        return Err("insufficient balance".into());
    }

    let amount = unlocked - est_fee;
    println!("Locked sweep all:");
    println!("  To:          {}", address);
    println!("  Amount:      {} {}", format_sal_u64(amount), asset);
    println!("  Unlock time: {}", unlock_time);

    if !tx_common::confirm("Confirm? [y/N] ")? {
        println!("Cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::All,
    )?;
    let sweep_amount = inputs.iter().map(|i| i.amount).sum::<u64>() - actual_fee;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount: sweep_amount,
            asset_type: asset.to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_unlock_time(unlock_time)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!("Locked sweep submitted! TX hash: {}", hex::encode(result.tx_hash));

    Ok(())
}

pub async fn return_payment(
    ctx: &AppContext,
    tx_hash: &str,
    priority: &str,
    asset_override: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot send from a view-only wallet".into());
    }

    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    // Look up the incoming TX to find the sender's info.
    let query = salvium_crypto::storage::TxQuery {
        is_incoming: Some(true),
        is_outgoing: None,
        is_confirmed: None,
        in_pool: None,
        tx_type: None,
        min_height: None,
        max_height: None,
        tx_hash: Some(tx_hash.to_string()),
    };
    let txs = wallet.get_transfers(&query)?;
    let tx = txs
        .first()
        .ok_or_else(|| format!("no incoming transaction found with hash: {}", tx_hash))?;

    let amount: u64 = tx.incoming_amount.parse().unwrap_or(0);
    if amount == 0 {
        return Err("transaction has no incoming amount to return".into());
    }

    // Derive sender's address from tx_pub_key (for return payment).
    let tx_pub_hex = tx
        .tx_pub_key
        .as_deref()
        .ok_or("transaction has no tx public key — cannot determine return address")?;
    // The user must provide the return address explicitly since we can't
    // reliably derive it from the tx_pub_key alone. For now, use the
    // wallet's own address as a placeholder (in production, the C++ wallet
    // stores the return address in tx extra).
    let return_addr = wallet.cn_address().unwrap_or_default();
    let _ = tx_pub_hex;
    let parsed_addr = salvium_types::address::parse_address(&return_addr)
        .map_err(|e| format!("invalid return address: {}", e))?;

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_ctx.fee_per_byte);

    println!("Return payment:");
    println!("  Original TX: {}", tx_hash);
    println!("  Amount:      {} {}", format_sal_u64(amount), asset);
    println!("  Return to:   {}", return_addr);

    if !tx_common::confirm("Confirm return? [y/N] ")? {
        println!("Cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    let keys = wallet.keys();
    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount,
            asset_type: asset.to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::RETURN)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!("Return payment submitted! TX hash: {}", hex::encode(result.tx_hash));

    Ok(())
}

pub async fn donate(
    ctx: &AppContext,
    amount_str: &str,
    priority: &str,
    asset_override: &str,
) -> Result {
    // Salvium donation address (mainnet).
    let donate_address = "SaLV1DonateXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXaU6oP9";
    transfer(ctx, donate_address, amount_str, priority, asset_override).await
}

pub async fn sweep_account(
    ctx: &AppContext,
    account: u32,
    address: &str,
    priority: &str,
    subaddr_indices: &[u32],
    asset_override: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);
    let fee_ctx = tx_common::resolve_fee_context(&ctx.pool, fee_priority).await?;
    let asset = if asset_override.is_empty() { &fee_ctx.native_asset } else { asset_override };

    // Get outputs for the specific account (and optional subaddress filter).
    let query = salvium_crypto::storage::OutputQuery {
        is_spent: Some(false),
        is_frozen: Some(false),
        asset_type: Some(asset.to_string()),
        tx_type: None,
        account_index: Some(account as i64),
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    };
    let outputs = wallet.get_outputs(&query)?;

    // Filter by subaddress indices if specified.
    let filtered: Vec<_> = if subaddr_indices.is_empty() {
        outputs
    } else {
        outputs
            .into_iter()
            .filter(|o| subaddr_indices.contains(&(o.subaddress_index.minor as u32)))
            .collect()
    };

    if filtered.is_empty() {
        println!("No outputs found in account {}.", account);
        return Ok(());
    }

    let total: u64 = filtered.iter().map(|o| o.amount.parse::<u64>().unwrap_or(0)).sum();
    let est_fee =
        salvium_tx::estimate_tx_fee(filtered.len(), 1, 16, true, 0x04, fee_ctx.fee_per_byte);

    if total <= est_fee {
        return Err("total of outputs in account doesn't cover the fee".into());
    }

    let sweep_amount = total - est_fee;
    println!("Sweep account {}:", account);
    println!("  To:       {}", address);
    println!("  Outputs:  {}", filtered.len());
    println!("  Amount:   {} {}", format_sal_u64(sweep_amount), asset);
    println!("  Fee:      ~{} {}", format_sal_u64(est_fee), asset);

    if !tx_common::confirm("Confirm sweep? [y/N] ")? {
        println!("Sweep cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, _) = pipeline.select_and_prepare_inputs(
        sweep_amount,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::All,
    )?;

    sweep_batched(&pipeline, inputs, &parsed_addr, asset).await
}

pub async fn create_token(
    ctx: &AppContext,
    ticker: &str,
    supply: u64,
    decimals: u64,
    metadata: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot create token from a view-only wallet".into());
    }

    // Validate token params.
    salvium_wallet::validate_create_token_params(ticker, supply, decimals, metadata)?;

    let fee_ctx =
        tx_common::resolve_fee_context(&ctx.pool, salvium_tx::fee::FeePriority::Normal).await?;
    let asset = "SAL1"; // CREATE_TOKEN always uses SAL1

    let cost = salvium_wallet::CREATE_TOKEN_COST;
    println!("Create Token:");
    println!("  Ticker:   {}", ticker);
    println!("  Supply:   {}", supply);
    println!("  Decimals: {}", decimals);
    println!("  Cost:     {} SAL1", format_sal_u64(cost));
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_ctx.fee_per_byte);
    println!("  Est. fee: {} SAL1", format_sal_u64(est_fee));
    println!();

    let balance = wallet.get_balance(asset, 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < cost + est_fee {
        return Err(format!(
            "insufficient balance: have {} SAL1, need {} SAL1",
            format_sal_u64(unlocked),
            format_sal_u64(cost + est_fee),
        )
        .into());
    }

    if !tx_common::confirm("Confirm token creation? [y/N] ")? {
        println!("Token creation cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, &fee_ctx);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        cost,
        est_fee,
        asset,
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs, asset).await?;

    // Build token metadata.
    let token_metadata = salvium_tx::types::TokenMetadata {
        version: 1,
        asset_type: ticker.to_string(),
        token: salvium_tx::types::TokenVariant::Sal(salvium_tx::types::SalToken {
            version: 1,
            supply,
            decimals: decimals as u8,
            metadata: metadata.to_string(),
            url: String::new(),
            signature: [0u8; 32],
        }),
    };

    // Send cost to self (change address).
    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount: cost,
            asset_type: asset.to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::CREATE_TOKEN)
        .set_fee(actual_fee)
        .set_asset_types(asset, asset)
        .set_token_metadata(token_metadata);

    let result = pipeline.build_sign_submit(builder, asset).await?;
    println!("Token created successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Ticker:  {}", ticker);
    println!("  Fee:     {} SAL1", format_sal_u64(actual_fee));

    Ok(())
}
