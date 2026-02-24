//! Output scanning orchestration.
//!
//! Wraps the low-level CryptoNote and CARROT scanning functions from
//! salvium-crypto into a higher-level API that operates on parsed
//! transaction data.

use crate::keys::WalletKeys;

/// Keys and subaddress maps needed for output scanning.
pub struct ScanContext {
    // CryptoNote scanning.
    pub cn_view_secret: [u8; 32],
    pub cn_spend_secret: Option<[u8; 32]>,
    pub cn_subaddress_map: Vec<([u8; 32], u32, u32)>,

    // CARROT scanning.
    pub carrot_view_incoming: [u8; 32],
    pub carrot_view_balance_secret: [u8; 32],
    pub carrot_account_spend_pubkey: [u8; 32],
    pub carrot_subaddress_map: Vec<([u8; 32], u32, u32)>,

    // CARROT key image computation (full wallet only).
    pub carrot_prove_spend_key: Option<[u8; 32]>,
    pub carrot_generate_image_key: Option<[u8; 32]>,

    /// CARROT generate-address secret (needed for subaddress scalar derivation).
    pub carrot_generate_address_secret: [u8; 32],

    /// Whether CARROT scanning is enabled (keys are non-zero).
    pub carrot_enabled: bool,
}

impl ScanContext {
    /// Build a scan context from wallet keys and subaddress maps.
    pub fn from_keys(
        keys: &WalletKeys,
        cn_subaddrs: Vec<([u8; 32], u32, u32)>,
        carrot_subaddrs: Vec<([u8; 32], u32, u32)>,
    ) -> Self {
        Self {
            cn_view_secret: keys.cn.view_secret_key,
            cn_spend_secret: keys.cn.spend_secret_key,
            cn_subaddress_map: cn_subaddrs,
            carrot_view_incoming: keys.carrot.view_incoming_key,
            carrot_view_balance_secret: keys.carrot.view_balance_secret,
            carrot_account_spend_pubkey: keys.carrot.account_spend_pubkey,
            carrot_subaddress_map: carrot_subaddrs,
            carrot_prove_spend_key: keys.carrot.prove_spend_key,
            carrot_generate_image_key: Some(keys.carrot.generate_image_key),
            carrot_generate_address_secret: keys.carrot.generate_address_secret,
            carrot_enabled: !keys.carrot.is_empty(),
        }
    }
}

/// A single transaction output ready for scanning.
#[derive(Debug, Clone)]
pub struct TxOutput {
    /// Output index within the transaction.
    pub index: u32,
    /// One-time output public key (stealth address).
    pub public_key: [u8; 32],
    /// 1-byte view tag from tagged_key target (for CN fast-reject).
    pub target_view_tag: Option<u8>,
    /// Clear-text amount (non-zero for coinbase, 0 for RCT).
    pub amount: u64,
    /// RCT type (0 = coinbase/non-RCT, 1+ = RCT variant).
    pub rct_type: u8,
    /// ECDH-encrypted amount (8 bytes from ecdhInfo).
    pub ecdh_encrypted_amount: [u8; 8],
    /// Pedersen commitment (outPk entry).
    pub commitment: Option<[u8; 32]>,
    /// 3-byte CARROT view tag (from tx extra).
    pub carrot_view_tag: Option<[u8; 3]>,
    /// CARROT ephemeral X25519 public key (from tx extra).
    pub carrot_ephemeral_pubkey: Option<[u8; 32]>,
    /// Asset type string (e.g. "SAL", "SAL1") from the on-chain output.
    pub asset_type: String,
    /// Per-output unlock time (from output target struct, NOT tx prefix).
    /// CARROT outputs (type 4) always have unlock_time = 0.
    /// For txout_to_key/txout_to_tagged_key, this comes from the output's
    /// own unlock_time field. Falls back to TX prefix unlock_time.
    pub unlock_time: u64,
    /// Encrypted Janus anchor (16 bytes, from CARROT output target).
    pub encrypted_janus_anchor: Option<[u8; 16]>,
}

/// A transaction with all data needed for scanning.
#[derive(Debug)]
pub struct ScanTxData {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Transaction public key (from tx extra).
    pub tx_pub_key: [u8; 32],
    /// Per-output additional public keys (tag 0x04 from tx extra).
    /// Used for per-output CN derivations when present.
    pub additional_pubkeys: Vec<[u8; 32]>,
    /// All outputs in the transaction.
    pub outputs: Vec<TxOutput>,
    /// Whether this is a coinbase (miner) transaction.
    pub is_coinbase: bool,
    /// Block height containing this transaction.
    pub block_height: u64,
    /// First key image from inputs (needed for CARROT input context).
    /// None for coinbase transactions.
    pub first_key_image: Option<[u8; 32]>,
    /// Transaction type (1=miner, 2=protocol, 3=transfer, etc.).
    pub tx_type: u8,
    /// Unlock time from the transaction prefix (0 = no lock).
    pub unlock_time: u64,
}

/// Result of detecting an owned output.
#[derive(Debug, Clone)]
pub struct FoundOutput {
    pub output_index: u32,
    pub amount: u64,
    pub mask: [u8; 32],
    pub key_image: Option<[u8; 32]>,
    pub subaddress_major: u32,
    pub subaddress_minor: u32,
    pub is_carrot: bool,
    pub carrot_shared_secret: Option<[u8; 32]>,
    pub carrot_enote_type: Option<u8>,
    pub output_public_key: [u8; 32],
    pub asset_type: String,
    /// True if matched via the internal (self-send) CARROT scan path.
    pub is_carrot_internal: bool,
}

/// Scan a transaction's outputs for owned ones.
///
/// For outputs with CARROT fields (3-byte view tag + ephemeral pubkey),
/// tries CARROT scanning first; otherwise falls back to CryptoNote.
pub fn scan_transaction(ctx: &ScanContext, tx: &ScanTxData) -> Vec<FoundOutput> {
    let mut found = Vec::new();

    // CryptoNote: compute shared derivation D = 8 * view_secret * tx_pub_key.
    // For CARROT TXs the tx_pub_key is X25519 (not Edwards), so this may
    // fail — that's fine, we only need it for CN outputs.
    let cn_derivation: Option<[u8; 32]> = {
        let derivation_vec =
            salvium_crypto::generate_key_derivation(&tx.tx_pub_key, &ctx.cn_view_secret);
        if derivation_vec.len() == 32 {
            let mut d = [0u8; 32];
            d.copy_from_slice(&derivation_vec);
            Some(d)
        } else {
            None
        }
    };

    // CARROT: compute input context.
    let input_context = if tx.is_coinbase {
        salvium_crypto::make_input_context_coinbase(tx.block_height)
    } else if let Some(ref ki) = tx.first_key_image {
        salvium_crypto::make_input_context_rct(ki)
    } else {
        vec![]
    };

    // Pre-compute per-output CN derivations from additional_pubkeys (tag 0x04).
    // C++ ref: wallet2.cpp uses per-output derivation when additional_pubkeys
    // are present (common for protocol_tx and multi-output pre-CARROT TXs).
    let per_output_derivations: Vec<Option<[u8; 32]>> = tx
        .additional_pubkeys
        .iter()
        .map(|pk| {
            let d = salvium_crypto::generate_key_derivation(pk, &ctx.cn_view_secret);
            if d.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&d);
                Some(arr)
            } else {
                None
            }
        })
        .collect();

    for (out_idx, output) in tx.outputs.iter().enumerate() {
        let is_carrot_output = output.carrot_view_tag.is_some();

        if is_carrot_output {
            // CARROT output: try CARROT scan only (CN derivation is invalid
            // for CARROT since tx_pub_key is X25519).
            if ctx.carrot_enabled && !input_context.is_empty() {
                if let Some(result) =
                    try_carrot_scan(ctx, output, &input_context, tx.is_coinbase)
                {
                    found.push(result);
                }
            }
        } else {
            // Non-CARROT output: try CN scan with shared derivation first.
            let mut cn_found = false;
            if let Some(ref derivation) = cn_derivation {
                if let Some(result) = try_cn_scan(ctx, derivation, output, tx.is_coinbase, tx.tx_type) {
                    found.push(result);
                    cn_found = true;
                }
            }

            // Fix #14: Try per-output derivation from additional_pubkeys.
            // Protocol TXs and multi-output pre-CARROT TXs often use per-output
            // keys (tag 0x04) for derivation instead of the shared tx_pub_key.
            // C++ ref: wallet2.cpp tries both shared and per-output derivations.
            if !cn_found {
                if let Some(Some(ref per_output_deriv)) = per_output_derivations.get(out_idx) {
                    if let Some(result) = try_cn_scan(ctx, per_output_deriv, output, tx.is_coinbase, tx.tx_type) {
                        found.push(result);
                        cn_found = true;
                    }
                }
            }

            // Fall back to CARROT scan for non-CARROT outputs too
            // (in case of misidentification).
            if !cn_found && ctx.carrot_enabled && !input_context.is_empty() {
                if let Some(result) =
                    try_carrot_scan(ctx, output, &input_context, tx.is_coinbase)
                {
                    found.push(result);
                }
            }
        }
    }

    found
}

fn try_cn_scan(
    ctx: &ScanContext,
    derivation: &[u8; 32],
    output: &TxOutput,
    is_coinbase: bool,
    tx_type: u8,
) -> Option<FoundOutput> {
    let rct_type = if is_coinbase { 0 } else { output.rct_type };
    let clear_amount = if is_coinbase && output.amount > 0 {
        Some(output.amount)
    } else {
        None
    };

    // Try with actual output index first.
    let result = salvium_crypto::cn_scan::scan_cryptonote_output(
        &output.public_key,
        derivation,
        output.index,
        output.target_view_tag,
        rct_type,
        clear_amount,
        &output.ecdh_encrypted_amount,
        output.commitment.as_ref(),
        ctx.cn_spend_secret.as_ref(),
        &ctx.cn_view_secret,
        &ctx.cn_subaddress_map,
    ).or_else(|| {
        // Fix #5: PROTOCOL_TX index-0 override.
        // CONVERT/YIELD outputs in PROTOCOL TXs are derived with index 0
        // by the protocol regardless of their actual position in the TX.
        // The view tag and key derivation both use index 0.
        // C++ ref: cryptonote_format_utils.cpp:1526-1531
        if tx_type == 2 && output.index != 0 {
            salvium_crypto::cn_scan::scan_cryptonote_output(
                &output.public_key,
                derivation,
                0, // retry with index 0
                output.target_view_tag,
                rct_type,
                clear_amount,
                &output.ecdh_encrypted_amount,
                output.commitment.as_ref(),
                ctx.cn_spend_secret.as_ref(),
                &ctx.cn_view_secret,
                &ctx.cn_subaddress_map,
            )
        } else {
            None
        }
    })?;

    Some(FoundOutput {
        output_index: output.index,
        amount: result.amount,
        mask: result.mask,
        key_image: result.key_image,
        subaddress_major: result.subaddress_major,
        subaddress_minor: result.subaddress_minor,
        is_carrot: false,
        carrot_shared_secret: None,
        carrot_enote_type: None,
        output_public_key: output.public_key,
        asset_type: output.asset_type.clone(),
        is_carrot_internal: false,
    })
}

fn try_carrot_scan(
    ctx: &ScanContext,
    output: &TxOutput,
    input_context: &[u8],
    is_coinbase: bool,
) -> Option<FoundOutput> {
    let view_tag_3 = output.carrot_view_tag.as_ref()?;
    let d_e = output.carrot_ephemeral_pubkey.as_ref()?;

    let clear_amount = if is_coinbase && output.amount > 0 {
        Some(output.amount)
    } else {
        None
    };

    // Try external scanning (outputs sent TO us).
    if let Some(result) = salvium_crypto::carrot_scan::scan_carrot_output(
        &output.public_key,
        view_tag_3,
        d_e,
        &output.ecdh_encrypted_amount,
        output.commitment.as_ref(),
        &ctx.carrot_view_incoming,
        &ctx.carrot_account_spend_pubkey,
        input_context,
        &ctx.carrot_subaddress_map,
        clear_amount,
    ) {
        // Janus protection: verify the encrypted anchor to reject false positives.
        // C++ ref: scan.cpp try_scan_carrot_enote_external_receiver
        if let Some(ref enc_anchor) = output.encrypted_janus_anchor {
            let is_sub = result.subaddress_major != 0 || result.subaddress_minor != 0;
            if !salvium_crypto::carrot_scan::verify_janus_protection(
                enc_anchor,
                &result.shared_secret,
                &output.public_key,
                d_e,
                input_context,
                &result.address_spend_pubkey,
                is_sub,
                &ctx.carrot_view_incoming,
            ) {
                log::debug!(
                    "Janus protection rejected CARROT external match: out_idx={} amount={}",
                    output.index, result.amount,
                );
                // Fall through to try internal scan
            } else {
                let key_image = compute_carrot_key_image(ctx, &output.public_key, &result);
                return Some(FoundOutput {
                    output_index: output.index,
                    amount: result.amount,
                    mask: result.mask,
                    key_image,
                    subaddress_major: result.subaddress_major,
                    subaddress_minor: result.subaddress_minor,
                    is_carrot: true,
                    carrot_shared_secret: Some(result.shared_secret),
                    carrot_enote_type: Some(result.enote_type),
                    output_public_key: output.public_key,
                    asset_type: output.asset_type.clone(),
                    is_carrot_internal: false,
                });
            }
        } else {
            // No encrypted anchor available (shouldn't happen for CARROT outputs,
            // but accept gracefully for backward compatibility).
            let key_image = compute_carrot_key_image(ctx, &output.public_key, &result);
            return Some(FoundOutput {
                output_index: output.index,
                amount: result.amount,
                mask: result.mask,
                key_image,
                subaddress_major: result.subaddress_major,
                subaddress_minor: result.subaddress_minor,
                is_carrot: true,
                carrot_shared_secret: Some(result.shared_secret),
                carrot_enote_type: Some(result.enote_type),
                output_public_key: output.public_key,
                asset_type: output.asset_type.clone(),
                is_carrot_internal: false,
            });
        }
    }

    // Try internal scanning (self-send: change outputs, etc.).
    if let Some(result) = salvium_crypto::carrot_scan::scan_carrot_internal_output(
        &output.public_key,
        view_tag_3,
        d_e,
        &output.ecdh_encrypted_amount,
        output.commitment.as_ref(),
        &ctx.carrot_view_balance_secret,
        &ctx.carrot_account_spend_pubkey,
        input_context,
        &ctx.carrot_subaddress_map,
        clear_amount,
    ) {
        let key_image = compute_carrot_key_image(ctx, &output.public_key, &result);
        return Some(FoundOutput {
            output_index: output.index,
            amount: result.amount,
            mask: result.mask,
            key_image,
            subaddress_major: result.subaddress_major,
            subaddress_minor: result.subaddress_minor,
            is_carrot: true,
            carrot_shared_secret: Some(result.shared_secret),
            carrot_enote_type: Some(result.enote_type),
            output_public_key: output.public_key,
            asset_type: output.asset_type.clone(),
            is_carrot_internal: true,
        });
    }

    None
}

/// Compute the CARROT key image: KI = x * H_p(Ko).
///
/// For the main address (0,0): x = k_gi + k^o_g
/// For subaddresses:           x = k_gi * k^j_subscal + k^o_g
///
/// The subaddress scalar k^j_subscal is derived from the generate_address_secret,
/// account_spend_pubkey, and the subaddress indices (major, minor).
///
/// Requires prove_spend_key and generate_image_key in the scan context.
/// Returns None for view-only wallets.
fn compute_carrot_key_image(
    ctx: &ScanContext,
    output_pubkey: &[u8; 32],
    result: &salvium_crypto::carrot_scan::CarrotScanResult,
) -> Option<[u8; 32]> {
    // Key image KI = sk_x * H_p(Ko) only needs generate_image_key, not
    // prove_spend_key.  sk_x = adjusted_gik + k^o_g — prove_spend_key is
    // only needed for sk_y (spending).  This allows view-only wallets
    // (which have generate_image_key but not prove_spend_key) to compute
    // key images for spent-output tracking.
    let generate_image_key = ctx.carrot_generate_image_key.as_ref()?;

    // prove_spend_key is only used for sk_y; pass zeros when unavailable.
    let prove_spend_key = ctx.carrot_prove_spend_key
        .as_ref()
        .copied()
        .unwrap_or([0u8; 32]);

    // Compute the commitment from the derived mask and amount.
    let commitment = salvium_crypto::pedersen_commit(
        &result.amount.to_le_bytes(),
        &result.mask,
    );
    let mut commit_32 = [0u8; 32];
    let len = commitment.len().min(32);
    commit_32[..len].copy_from_slice(&commitment[..len]);

    // For subaddresses, multiply the base keys by the subaddress scalar.
    // C++ formula: x = k_gi * k^j_subscal + k^o_g
    //              y = k_ps * k^j_subscal + k^o_t
    // For main address (0,0), k^j_subscal = 1 (identity).
    let (adj_gik, adj_psk) = salvium_crypto::subaddress::carrot_adjust_keys_for_subaddress(
        generate_image_key,
        &prove_spend_key,
        &ctx.carrot_generate_address_secret,
        &ctx.carrot_account_spend_pubkey,
        result.subaddress_major,
        result.subaddress_minor,
    );

    // Derive spend keys with subaddress-adjusted base keys: (sk_x, sk_y).
    let (sk_x, _sk_y) = salvium_crypto::carrot_scan::derive_carrot_spend_keys(
        &adj_psk,
        &adj_gik,
        &result.shared_secret,
        &commit_32,
    );

    // Key image: KI = sk_x * H_p(Ko).
    let ki = salvium_crypto::generate_key_image(output_pubkey, &sk_x);
    if ki.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&ki);
        Some(arr)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_context_from_keys() {
        let keys = WalletKeys::from_seed([42u8; 32], salvium_types::constants::Network::Testnet);
        let ctx = ScanContext::from_keys(&keys, vec![], vec![]);
        assert_eq!(ctx.cn_view_secret, keys.cn.view_secret_key);
        assert!(ctx.cn_spend_secret.is_some());
        assert!(ctx.carrot_enabled);
    }

    #[test]
    fn test_scan_empty_transaction() {
        let keys = WalletKeys::from_seed([42u8; 32], salvium_types::constants::Network::Testnet);
        let ctx = ScanContext::from_keys(&keys, vec![], vec![]);

        let tx = ScanTxData {
            tx_hash: [0u8; 32],
            tx_pub_key: [1u8; 32],
            additional_pubkeys: vec![],
            outputs: vec![],
            is_coinbase: false,
            block_height: 100,
            first_key_image: Some([2u8; 32]),
            tx_type: 3,
            unlock_time: 0,
        };

        let found = scan_transaction(&ctx, &tx);
        assert!(found.is_empty());
    }

    #[test]
    fn test_scan_random_output_not_found() {
        let keys = WalletKeys::from_seed([42u8; 32], salvium_types::constants::Network::Testnet);
        let ctx = ScanContext::from_keys(&keys, vec![], vec![]);

        let tx = ScanTxData {
            tx_hash: [0u8; 32],
            tx_pub_key: [1u8; 32],
            additional_pubkeys: vec![],
            outputs: vec![TxOutput {
                index: 0,
                public_key: [99u8; 32],
                target_view_tag: None,
                amount: 0,
                rct_type: 6,
                ecdh_encrypted_amount: [0u8; 8],
                commitment: Some([0u8; 32]),
                carrot_view_tag: None,
                carrot_ephemeral_pubkey: None,
                asset_type: "SAL".to_string(),
                unlock_time: 0,
                encrypted_janus_anchor: None,
            }],
            is_coinbase: false,
            block_height: 100,
            first_key_image: Some([2u8; 32]),
            tx_type: 3,
            unlock_time: 0,
        };

        // Random output should not match our wallet keys.
        let found = scan_transaction(&ctx, &tx);
        assert!(found.is_empty());
    }
}
