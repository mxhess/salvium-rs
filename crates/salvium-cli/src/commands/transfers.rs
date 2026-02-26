//! Transfer variant commands: transfer, stake, burn, convert, audit,
//! locked_transfer, sweep_all, sweep_below, sweep_single, sweep_unmixable,
//! locked_sweep_all, return_payment, donate.

use super::*;
use crate::tx_common::{self, TxPipeline};

pub async fn transfer(ctx: &AppContext, address: &str, amount_str: &str, priority: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot send from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;
    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);

    println!("Transfer:");
    println!("  To:     {}", address);
    println!("  Amount: {} SAL", format_sal_u64(amount));
    println!("  Format: {:?}", parsed_addr.format);
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_priority);
    println!("  Estimated fee: {} SAL", format_sal_u64(est_fee));
    println!();

    let balance = wallet.get_balance("SAL", 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + est_fee {
        return Err(format!(
            "insufficient unlocked balance: have {} SAL, need {} SAL",
            format_sal_u64(unlocked),
            format_sal_u64(amount + est_fee)
        )
        .into());
    }

    if !tx_common::confirm("Confirm transfer? [y/N] ")? {
        println!("Transfer cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let keys = wallet.keys();
    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Transaction submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Fee:     {} SAL", format_sal_u64(actual_fee));

    Ok(())
}

pub async fn stake(ctx: &AppContext, amount_str: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot stake from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;

    println!("Stake:");
    println!("  Amount: {} SAL", format_sal_u64(amount));
    println!();

    let fee_priority = salvium_tx::fee::FeePriority::Normal;
    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_priority);
    println!("  Estimated fee: {} SAL", format_sal_u64(est_fee));
    println!();

    let balance = wallet.get_balance("SAL", 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + est_fee {
        return Err(format!(
            "insufficient unlocked balance: have {} SAL, need {} SAL",
            format_sal_u64(unlocked),
            format_sal_u64(amount + est_fee)
        )
        .into());
    }

    if !tx_common::confirm("Confirm stake? [y/N] ")? {
        println!("Stake cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount,
            asset_type: "SAL".to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::STAKE)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Stake transaction submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Amount:  {} SAL", format_sal_u64(amount));
    println!("  Fee:     {} SAL", format_sal_u64(actual_fee));

    Ok(())
}

pub async fn burn(ctx: &AppContext, amount_str: &str, priority: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot burn from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;
    let fee_priority = tx_common::parse_fee_priority(priority);

    println!("Burn:");
    println!("  Amount: {} SAL", format_sal_u64(amount));
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_priority);
    println!("  Estimated fee: {} SAL", format_sal_u64(est_fee));

    let balance = wallet.get_balance("SAL", 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + est_fee {
        return Err(format!(
            "insufficient unlocked balance: have {} SAL, need {} SAL",
            format_sal_u64(unlocked),
            format_sal_u64(amount + est_fee)
        )
        .into());
    }

    if !tx_common::confirm("WARNING: Burning tokens is irreversible. Confirm? [y/N] ")? {
        println!("Burn cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::BURN)
        .set_amount_burnt(amount)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Burn transaction submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Burnt:   {} SAL", format_sal_u64(amount));
    println!("  Fee:     {} SAL", format_sal_u64(actual_fee));

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

    println!("Convert:");
    println!("  Amount: {} {}", format_sal_u64(amount), source_asset);
    println!("  From:   {}", source_asset);
    println!("  To:     {}", dest_asset);
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_priority);
    println!("  Estimated fee: {} {}", format_sal_u64(est_fee), source_asset);

    let balance = wallet.get_balance(source_asset, 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    if unlocked < amount + est_fee {
        return Err(format!(
            "insufficient unlocked {} balance: have {}, need {}",
            source_asset,
            format_sal_u64(unlocked),
            format_sal_u64(amount + est_fee)
        )
        .into());
    }

    if !tx_common::confirm("Confirm conversion? [y/N] ")? {
        println!("Conversion cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        source_asset,
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

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
        .set_asset_types(source_asset, dest_asset)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Conversion submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Fee:     {} {}", format_sal_u64(actual_fee), source_asset);

    Ok(())
}

pub async fn audit(ctx: &AppContext, priority: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot audit from a view-only wallet".into());
    }

    let fee_priority = tx_common::parse_fee_priority(priority);

    // Audit sweeps all funds back to self as a verifiable on-chain proof.
    let balance = wallet.get_balance("SAL", 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    let est_fee = salvium_tx::estimate_tx_fee(4, 2, 16, true, 0x04, fee_priority);

    if unlocked <= est_fee {
        return Err("insufficient balance for audit transaction".into());
    }

    let amount = unlocked - est_fee;

    println!("Audit:");
    println!("  Amount: {} SAL (sweep to self)", format_sal_u64(amount));
    println!("  Fee:    {} SAL", format_sal_u64(est_fee));

    if !tx_common::confirm("Confirm audit transaction? [y/N] ")? {
        println!("Audit cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::All,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount,
            asset_type: "SAL".to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::AUDIT)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
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
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot send from a view-only wallet".into());
    }

    let amount = parse_sal_amount(amount_str)?;
    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);

    println!("Locked Transfer:");
    println!("  To:          {}", address);
    println!("  Amount:      {} SAL", format_sal_u64(amount));
    println!("  Unlock time: {}", unlock_time);
    println!();

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_priority);
    println!("  Estimated fee: {} SAL", format_sal_u64(est_fee));

    if !tx_common::confirm("Confirm locked transfer? [y/N] ")? {
        println!("Transfer cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let keys = wallet.keys();
    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_unlock_time(unlock_time)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Locked transfer submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Fee:     {} SAL", format_sal_u64(actual_fee));

    Ok(())
}

pub async fn sweep_all(ctx: &AppContext, address: &str, priority: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);

    let balance = wallet.get_balance("SAL", 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    let est_fee = salvium_tx::estimate_tx_fee(4, 1, 16, true, 0x04, fee_priority);

    if unlocked <= est_fee {
        return Err("insufficient balance for sweep".into());
    }

    let amount = unlocked - est_fee;
    println!("Sweep all:");
    println!("  To:     {}", address);
    println!("  Amount: {} SAL", format_sal_u64(amount));
    println!("  Fee:    ~{} SAL", format_sal_u64(est_fee));

    if !tx_common::confirm("Confirm sweep? [y/N] ")? {
        println!("Sweep cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::All,
    )?;
    let sweep_amount = inputs.iter().map(|i| i.amount).sum::<u64>() - actual_fee;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    // Sweep: no change output, single destination.
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount: sweep_amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Sweep submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Swept:   {} SAL", format_sal_u64(sweep_amount));
    println!("  Fee:     {} SAL", format_sal_u64(actual_fee));

    Ok(())
}

pub async fn sweep_below(
    ctx: &AppContext,
    address: &str,
    threshold_str: &str,
    priority: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let threshold = parse_sal_amount(threshold_str)?;
    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);

    // Get outputs below threshold.
    let query = salvium_crypto::storage::OutputQuery {
        is_spent: Some(false),
        is_frozen: Some(false),
        asset_type: Some("SAL".to_string()),
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
        println!("No outputs found below {} SAL.", format_sal_u64(threshold));
        return Ok(());
    }

    let total: u64 = below.iter().map(|o| o.amount.parse::<u64>().unwrap_or(0)).sum();
    let est_fee = salvium_tx::estimate_tx_fee(below.len(), 1, 16, true, 0x04, fee_priority);

    if total <= est_fee {
        return Err("total of outputs below threshold doesn't cover the fee".into());
    }

    println!(
        "Sweep below {} SAL: {} outputs, total {} SAL",
        format_sal_u64(threshold),
        below.len(),
        format_sal_u64(total)
    );

    if !tx_common::confirm("Confirm sweep? [y/N] ")? {
        println!("Sweep cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        total - est_fee,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::SmallestFirst,
    )?;
    let sweep_amount = inputs.iter().map(|i| i.amount).sum::<u64>() - actual_fee;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount: sweep_amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Sweep submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Swept:   {} SAL", format_sal_u64(sweep_amount));

    Ok(())
}

pub async fn sweep_single(
    ctx: &AppContext,
    key_image: &str,
    address: &str,
    priority: &str,
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);

    let output = wallet
        .get_output(key_image)?
        .ok_or_else(|| format!("output not found for key image: {}", key_image))?;

    let amount: u64 = output.amount.parse().unwrap_or(0);
    let est_fee = salvium_tx::estimate_tx_fee(1, 1, 16, true, 0x04, fee_priority);

    if amount <= est_fee {
        return Err("output amount doesn't cover the fee".into());
    }

    println!("Sweep single output:");
    println!("  Key image: {}", key_image);
    println!("  Amount:    {} SAL", format_sal_u64(amount));
    println!("  To:        {}", address);

    if !tx_common::confirm("Confirm? [y/N] ")? {
        println!("Sweep cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount - est_fee,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let sweep_amount = inputs.iter().map(|i| i.amount).sum::<u64>() - actual_fee;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount: sweep_amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Sweep submitted! TX hash: {}", hex::encode(result.tx_hash));

    Ok(())
}

pub async fn sweep_unmixable(ctx: &AppContext) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

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
    println!("Found {} unmixable outputs totalling {} SAL", unmixable.len(), format_sal_u64(total));

    if !tx_common::confirm("Sweep unmixable outputs to self? [y/N] ")? {
        println!("Cancelled.");
        return Ok(());
    }

    let fee_priority = salvium_tx::fee::FeePriority::Normal;
    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let est_fee = salvium_tx::estimate_tx_fee(unmixable.len(), 1, 16, true, 0x04, fee_priority);

    if total <= est_fee {
        return Err("total of unmixable outputs doesn't cover the fee".into());
    }

    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        total - est_fee,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::SmallestFirst,
    )?;
    let sweep_amount = inputs.iter().map(|i| i.amount).sum::<u64>() - actual_fee;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let keys = wallet.keys();
    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: keys.carrot.account_spend_pubkey,
            view_pubkey: keys.carrot.account_view_pubkey,
            amount: sweep_amount,
            asset_type: "SAL".to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        })
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
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
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);

    let balance = wallet.get_balance("SAL", 0)?;
    let unlocked: u64 = balance.unlocked_balance.parse().unwrap_or(0);
    let est_fee = salvium_tx::estimate_tx_fee(4, 1, 16, true, 0x04, fee_priority);

    if unlocked <= est_fee {
        return Err("insufficient balance".into());
    }

    let amount = unlocked - est_fee;
    println!("Locked sweep all:");
    println!("  To:          {}", address);
    println!("  Amount:      {} SAL", format_sal_u64(amount));
    println!("  Unlock time: {}", unlock_time);

    if !tx_common::confirm("Confirm? [y/N] ")? {
        println!("Cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::All,
    )?;
    let sweep_amount = inputs.iter().map(|i| i.amount).sum::<u64>() - actual_fee;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount: sweep_amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_unlock_time(unlock_time)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Locked sweep submitted! TX hash: {}", hex::encode(result.tx_hash));

    Ok(())
}

pub async fn return_payment(ctx: &AppContext, tx_hash: &str, priority: &str) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot send from a view-only wallet".into());
    }

    let fee_priority = tx_common::parse_fee_priority(priority);

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

    let est_fee = salvium_tx::estimate_tx_fee(2, 2, 16, true, 0x04, fee_priority);

    println!("Return payment:");
    println!("  Original TX: {}", tx_hash);
    println!("  Amount:      {} SAL", format_sal_u64(amount));
    println!("  Return to:   {}", return_addr);

    if !tx_common::confirm("Confirm return? [y/N] ")? {
        println!("Cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::Default,
    )?;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let keys = wallet.keys();
    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_change_address(keys.carrot.account_spend_pubkey, keys.carrot.account_view_pubkey)
        .set_change_view_balance_secret(keys.carrot.view_balance_secret)
        .set_tx_type(salvium_tx::types::tx_type::RETURN)
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Return payment submitted! TX hash: {}", hex::encode(result.tx_hash));

    Ok(())
}

pub async fn donate(ctx: &AppContext, amount_str: &str, priority: &str) -> Result {
    // Salvium donation address (mainnet).
    let donate_address = "SaLV1DonateXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXaU6oP9";
    transfer(ctx, donate_address, amount_str, priority).await
}

pub async fn sweep_account(
    ctx: &AppContext,
    account: u32,
    address: &str,
    priority: &str,
    subaddr_indices: &[u32],
) -> Result {
    let wallet = open_wallet(ctx)?;

    if !wallet.can_spend() {
        return Err("cannot sweep from a view-only wallet".into());
    }

    let parsed_addr = salvium_types::address::parse_address(address)
        .map_err(|e| format!("invalid destination address: {}", e))?;
    let fee_priority = tx_common::parse_fee_priority(priority);

    // Get outputs for the specific account (and optional subaddress filter).
    let query = salvium_crypto::storage::OutputQuery {
        is_spent: Some(false),
        is_frozen: Some(false),
        asset_type: Some("SAL".to_string()),
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
    let est_fee = salvium_tx::estimate_tx_fee(filtered.len(), 1, 16, true, 0x04, fee_priority);

    if total <= est_fee {
        return Err("total of outputs in account doesn't cover the fee".into());
    }

    let sweep_amount = total - est_fee;
    println!("Sweep account {}:", account);
    println!("  To:       {}", address);
    println!("  Outputs:  {}", filtered.len());
    println!("  Amount:   {} SAL", format_sal_u64(sweep_amount));
    println!("  Fee:      ~{} SAL", format_sal_u64(est_fee));

    if !tx_common::confirm("Confirm sweep? [y/N] ")? {
        println!("Sweep cancelled.");
        return Ok(());
    }

    let pipeline = TxPipeline::new(&wallet, ctx, fee_priority);
    let (inputs, actual_fee) = pipeline.select_and_prepare_inputs(
        sweep_amount,
        est_fee,
        "SAL",
        salvium_wallet::utxo::SelectionStrategy::All,
    )?;
    let final_amount = inputs.iter().map(|i| i.amount).sum::<u64>() - actual_fee;
    let prepared = pipeline.fetch_decoys(&inputs).await?;

    let is_subaddress =
        parsed_addr.address_type == salvium_types::constants::AddressType::Subaddress;

    let builder = salvium_tx::TransactionBuilder::new()
        .add_inputs(prepared)
        .add_destination(salvium_tx::builder::Destination {
            spend_pubkey: parsed_addr.spend_public_key,
            view_pubkey: parsed_addr.view_public_key,
            amount: final_amount,
            asset_type: "SAL".to_string(),
            payment_id: parsed_addr.payment_id.unwrap_or([0u8; 8]),
            is_subaddress,
        })
        .set_fee(actual_fee);

    let result = pipeline.build_sign_submit(builder).await?;
    println!("Sweep submitted successfully!");
    println!("  TX hash: {}", hex::encode(result.tx_hash));
    println!("  Swept:   {} SAL", format_sal_u64(final_amount));
    println!("  Fee:     {} SAL", format_sal_u64(actual_fee));

    Ok(())
}
