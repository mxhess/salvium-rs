//! Shared transaction construction pipeline.
//!
//! Extracts the common UTXO-selection → key-derivation → decoy-fetch → ring-build
//! → sign → submit logic used by transfer, stake, burn, convert, sweep, etc.

use crate::AppContext;
use salvium_rpc::DaemonRpc;
use salvium_wallet::Wallet;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A fully-prepared, signed transaction ready for submission.
#[allow(dead_code)]
pub struct SignedResult {
    pub tx_hash: [u8; 32],
    pub tx_hex: String,
    pub fee: u64,
}

/// Shared pipeline for building, signing, and optionally submitting transactions.
pub struct TxPipeline<'a> {
    pub wallet: &'a Wallet,
    pub daemon: DaemonRpc,
    pub fee_priority: salvium_tx::fee::FeePriority,
}

impl<'a> TxPipeline<'a> {
    pub fn new(
        wallet: &'a Wallet,
        ctx: &AppContext,
        fee_priority: salvium_tx::fee::FeePriority,
    ) -> Self {
        Self { wallet, daemon: DaemonRpc::new(&ctx.daemon_url), fee_priority }
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
            "Selected {} input(s), total {} SAL",
            selection.selected.len(),
            crate::commands::format_sal_u64(selection.total)
        );

        let actual_fee = salvium_tx::estimate_tx_fee(
            selection.selected.len(),
            2,
            salvium_tx::decoy::DEFAULT_RING_SIZE,
            true,
            0x04,
            self.fee_priority,
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
                let commitment = hex_to_32(
                    output.commitment.as_deref().ok_or("CARROT output missing commitment")?,
                )?;
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
                global_index: utxo.global_index,
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
    pub async fn fetch_decoys(
        &self,
        inputs: &[InputData],
    ) -> Result<Vec<salvium_tx::builder::PreparedInput>> {
        println!("Fetching decoy data from daemon...");
        let info = self.daemon.get_info().await?;
        let dist = self.daemon.get_output_distribution(&[0], 0, info.height, true, "").await?;
        let rct_offsets =
            dist.first().ok_or("no output distribution returned from daemon")?.distribution.clone();
        let decoy_selector = salvium_tx::DecoySelector::new(rct_offsets)
            .map_err(|e| format!("decoy selector: {}", e))?;

        let ring_size = salvium_tx::decoy::DEFAULT_RING_SIZE;
        let mut prepared = Vec::new();

        for inp in inputs {
            let (ring_indices, real_pos) = decoy_selector
                .build_ring(inp.global_index, ring_size)
                .map_err(|e| format!("ring build: {}", e))?;

            let requests: Vec<salvium_rpc::daemon::OutputRequest> = ring_indices
                .iter()
                .map(|&idx| salvium_rpc::daemon::OutputRequest { amount: 0, index: idx })
                .collect();
            let outs_info = self.daemon.get_outs(&requests, false, "").await?;

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
                asset_type: "SAL".to_string(),
                global_index: inp.global_index,
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
            .daemon
            .send_raw_transaction(&tx_hex, false)
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
    pub global_index: u64,
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
        "high" => salvium_tx::fee::FeePriority::High,
        "urgent" | "highest" => salvium_tx::fee::FeePriority::Highest,
        _ => salvium_tx::fee::FeePriority::Normal,
    }
}

/// Confirm with the user before proceeding.
pub fn confirm(prompt: &str) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    println!("{}", prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_lowercase() == "y")
}
