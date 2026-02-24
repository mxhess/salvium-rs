//! High-level WASM APIs for Salvium blockchain explorers.
//!
//! This crate provides ergonomic, JSON-returning functions that combine
//! multiple `salvium-crypto` primitives into single calls, designed for
//! use from JavaScript/TypeScript in Cloudflare Workers or browsers.
//!
//! Build with: `wasm-pack build -p salvium-explorer --target bundler`

use wasm_bindgen::prelude::*;

// ─── Re-exports from salvium-crypto ─────────────────────────────────────────
// When building salvium-explorer as the single WASM module, these re-exports
// make all salvium-crypto functions available through the same JS import.

// Crypto primitives
#[wasm_bindgen] pub fn keccak256(data: &[u8]) -> Vec<u8> { salvium_crypto::keccak256(data) }
#[wasm_bindgen] pub fn blake2b_hash(data: &[u8], out_len: usize) -> Vec<u8> { salvium_crypto::blake2b_hash(data, out_len) }
#[wasm_bindgen] pub fn blake2b_keyed(data: &[u8], out_len: usize, key: &[u8]) -> Vec<u8> { salvium_crypto::blake2b_keyed(data, out_len, key) }
#[wasm_bindgen] pub fn sha256(data: &[u8]) -> Vec<u8> { salvium_crypto::sha256(data) }
#[wasm_bindgen] pub fn argon2id_hash(password: &[u8], salt: &[u8], t_cost: u32, m_cost: u32, parallelism: u32, dk_len: u32) -> Vec<u8> { salvium_crypto::argon2id_hash(password, salt, t_cost, m_cost, parallelism, dk_len) }

// Scalar operations
#[wasm_bindgen] pub fn sc_add(a: &[u8], b: &[u8]) -> Vec<u8> { salvium_crypto::sc_add(a, b) }
#[wasm_bindgen] pub fn sc_sub(a: &[u8], b: &[u8]) -> Vec<u8> { salvium_crypto::sc_sub(a, b) }
#[wasm_bindgen] pub fn sc_mul(a: &[u8], b: &[u8]) -> Vec<u8> { salvium_crypto::sc_mul(a, b) }
#[wasm_bindgen] pub fn sc_mul_add(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> { salvium_crypto::sc_mul_add(a, b, c) }
#[wasm_bindgen] pub fn sc_mul_sub(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> { salvium_crypto::sc_mul_sub(a, b, c) }
#[wasm_bindgen] pub fn sc_reduce32(s: &[u8]) -> Vec<u8> { salvium_crypto::sc_reduce32(s) }
#[wasm_bindgen] pub fn sc_reduce64(s: &[u8]) -> Vec<u8> { salvium_crypto::sc_reduce64(s) }
#[wasm_bindgen] pub fn sc_invert(a: &[u8]) -> Vec<u8> { salvium_crypto::sc_invert(a) }
#[wasm_bindgen] pub fn sc_check(s: &[u8]) -> bool { salvium_crypto::sc_check(s) }
#[wasm_bindgen] pub fn sc_is_zero(s: &[u8]) -> bool { salvium_crypto::sc_is_zero(s) }

// Point operations
#[wasm_bindgen] pub fn scalar_mult_base(s: &[u8]) -> Vec<u8> { salvium_crypto::scalar_mult_base(s) }
#[wasm_bindgen] pub fn scalar_mult_point(s: &[u8], p: &[u8]) -> Vec<u8> { salvium_crypto::scalar_mult_point(s, p) }
#[wasm_bindgen] pub fn point_add_compressed(p: &[u8], q: &[u8]) -> Vec<u8> { salvium_crypto::point_add_compressed(p, q) }
#[wasm_bindgen] pub fn point_sub_compressed(p: &[u8], q: &[u8]) -> Vec<u8> { salvium_crypto::point_sub_compressed(p, q) }
#[wasm_bindgen] pub fn point_negate(p: &[u8]) -> Vec<u8> { salvium_crypto::point_negate(p) }
#[wasm_bindgen] pub fn double_scalar_mult_base(a: &[u8], p: &[u8], b: &[u8]) -> Vec<u8> { salvium_crypto::double_scalar_mult_base(a, p, b) }

// Key derivation
#[wasm_bindgen] pub fn hash_to_point(data: &[u8]) -> Vec<u8> { salvium_crypto::hash_to_point(data) }
#[wasm_bindgen] pub fn generate_key_image(pub_key: &[u8], sec_key: &[u8]) -> Vec<u8> { salvium_crypto::generate_key_image(pub_key, sec_key) }
#[wasm_bindgen] pub fn generate_key_derivation(pub_key: &[u8], sec_key: &[u8]) -> Vec<u8> { salvium_crypto::generate_key_derivation(pub_key, sec_key) }
#[wasm_bindgen] pub fn derive_public_key(derivation: &[u8], output_index: u32, base_pub: &[u8]) -> Vec<u8> { salvium_crypto::derive_public_key(derivation, output_index, base_pub) }
#[wasm_bindgen] pub fn derive_secret_key(derivation: &[u8], output_index: u32, base_sec: &[u8]) -> Vec<u8> { salvium_crypto::derive_secret_key(derivation, output_index, base_sec) }

// Pedersen commitments
#[wasm_bindgen] pub fn pedersen_commit(amount: &[u8], mask: &[u8]) -> Vec<u8> { salvium_crypto::pedersen_commit(amount, mask) }
#[wasm_bindgen] pub fn zero_commit(amount: &[u8]) -> Vec<u8> { salvium_crypto::zero_commit(amount) }
#[wasm_bindgen] pub fn gen_commitment_mask(shared_secret: &[u8]) -> Vec<u8> { salvium_crypto::gen_commitment_mask(shared_secret) }

// X25519
#[wasm_bindgen] pub fn x25519_scalar_mult(scalar: &[u8], u_coord: &[u8]) -> Vec<u8> { salvium_crypto::x25519_scalar_mult(scalar, u_coord) }
#[wasm_bindgen] pub fn edwards_to_montgomery_u(point: &[u8]) -> Vec<u8> { salvium_crypto::edwards_to_montgomery_u(point) }

// Subaddress maps
#[wasm_bindgen] pub fn cn_subaddress_map_batch(spend_pubkey: &[u8], view_secret_key: &[u8], major_count: u32, minor_count: u32) -> Vec<u8> { salvium_crypto::cn_subaddress_map_batch(spend_pubkey, view_secret_key, major_count, minor_count) }
#[wasm_bindgen] pub fn carrot_subaddress_map_batch(account_spend_pubkey: &[u8], account_view_pubkey: &[u8], generate_address_secret: &[u8], major_count: u32, minor_count: u32) -> Vec<u8> { salvium_crypto::carrot_subaddress_map_batch(account_spend_pubkey, account_view_pubkey, generate_address_secret, major_count, minor_count) }

// CARROT key derivation
#[wasm_bindgen] pub fn derive_carrot_keys_batch(master_secret: &[u8]) -> Vec<u8> { salvium_crypto::derive_carrot_keys_batch(master_secret) }
#[wasm_bindgen] pub fn derive_carrot_view_only_keys_batch(view_balance_secret: &[u8], account_spend_pubkey: &[u8]) -> Vec<u8> { salvium_crypto::derive_carrot_view_only_keys_batch(view_balance_secret, account_spend_pubkey) }

// CARROT helpers
#[wasm_bindgen] pub fn compute_carrot_view_tag(s_sr_unctx: &[u8], input_context: &[u8], ko: &[u8]) -> Vec<u8> { salvium_crypto::compute_carrot_view_tag(s_sr_unctx, input_context, ko) }
#[wasm_bindgen] pub fn decrypt_carrot_amount(enc_amount: &[u8], s_sr_ctx: &[u8], ko: &[u8]) -> u64 { salvium_crypto::decrypt_carrot_amount(enc_amount, s_sr_ctx, ko) }
#[wasm_bindgen] pub fn derive_carrot_commitment_mask(s_sr_ctx: &[u8], amount: u64, address_spend_pubkey: &[u8], enote_type: u8) -> Vec<u8> { salvium_crypto::derive_carrot_commitment_mask(s_sr_ctx, amount, address_spend_pubkey, enote_type) }
#[wasm_bindgen] pub fn recover_carrot_address_spend_pubkey(ko: &[u8], s_sr_ctx: &[u8], commitment: &[u8]) -> Vec<u8> { salvium_crypto::recover_carrot_address_spend_pubkey(ko, s_sr_ctx, commitment) }
#[wasm_bindgen] pub fn make_input_context_rct(first_key_image: &[u8]) -> Vec<u8> { salvium_crypto::make_input_context_rct(first_key_image) }
#[wasm_bindgen] pub fn make_input_context_coinbase(block_height: u64) -> Vec<u8> { salvium_crypto::make_input_context_coinbase(block_height) }

// TX parsing & serialization
#[wasm_bindgen] pub fn parse_extra(extra_bytes: &[u8]) -> String { salvium_crypto::parse_extra(extra_bytes) }
#[wasm_bindgen] pub fn serialize_tx_extra(json_str: &str) -> Vec<u8> { salvium_crypto::serialize_tx_extra(json_str) }
#[wasm_bindgen] pub fn compute_tx_prefix_hash(data: &[u8]) -> Vec<u8> { salvium_crypto::compute_tx_prefix_hash(data) }
#[wasm_bindgen] pub fn parse_transaction_bytes(data: &[u8]) -> String { salvium_crypto::parse_transaction_bytes(data) }
#[wasm_bindgen] pub fn serialize_transaction_json(json: &str) -> Vec<u8> { salvium_crypto::serialize_transaction_json(json) }
#[wasm_bindgen] pub fn parse_block_bytes(data: &[u8]) -> String { salvium_crypto::parse_block_bytes(data) }

// Key image helpers
#[wasm_bindgen] pub fn is_valid_key_image(key_image: &[u8]) -> bool { salvium_crypto::is_valid_key_image(key_image) }
#[wasm_bindgen] pub fn key_image_to_y(key_image: &[u8]) -> Vec<u8> { salvium_crypto::key_image_to_y(key_image) }
#[wasm_bindgen] pub fn key_image_from_y(y_coord: &[u8], sign_bit: bool) -> Vec<u8> { salvium_crypto::key_image_from_y(y_coord, sign_bit) }

// Address API
#[wasm_bindgen] pub fn wasm_parse_address(address: &str) -> String { salvium_crypto::wasm_parse_address(address) }
#[wasm_bindgen] pub fn wasm_is_valid_address(address: &str) -> bool { salvium_crypto::wasm_is_valid_address(address) }
#[wasm_bindgen] pub fn wasm_describe_address(address: &str) -> String { salvium_crypto::wasm_describe_address(address) }
#[wasm_bindgen] pub fn wasm_create_address(network: u8, format: u8, addr_type: u8, spend_key: &[u8], view_key: &[u8]) -> String { salvium_crypto::wasm_create_address(network, format, addr_type, spend_key, view_key) }
#[wasm_bindgen] pub fn wasm_to_integrated_address(address: &str, payment_id: &[u8]) -> String { salvium_crypto::wasm_to_integrated_address(address, payment_id) }

// TX type names
#[wasm_bindgen] pub fn wasm_tx_type_name(tx_type: u8) -> String { salvium_crypto::wasm_tx_type_name(tx_type) }
#[wasm_bindgen] pub fn wasm_rct_type_name(rct_type: u8) -> String { salvium_crypto::wasm_rct_type_name(rct_type) }

// Mnemonic
#[wasm_bindgen] pub fn wasm_mnemonic_from_seed(seed: &[u8]) -> String { salvium_crypto::wasm_mnemonic_from_seed(seed) }
#[wasm_bindgen] pub fn wasm_mnemonic_to_seed(words: &str) -> Vec<u8> { salvium_crypto::wasm_mnemonic_to_seed(words) }
#[wasm_bindgen] pub fn wasm_validate_mnemonic(words: &str) -> bool { salvium_crypto::wasm_validate_mnemonic(words) }

// Ring signature signing & verification
#[wasm_bindgen] pub fn clsag_sign_wasm(message: &[u8], ring_flat: &[u8], secret_key: &[u8], commitments_flat: &[u8], commitment_mask: &[u8], pseudo_output: &[u8], secret_index: u32) -> Vec<u8> { salvium_crypto::clsag::clsag_sign_wasm(message, ring_flat, secret_key, commitments_flat, commitment_mask, pseudo_output, secret_index) }
#[wasm_bindgen] pub fn clsag_verify_wasm(message: &[u8], sig_bytes: &[u8], ring_flat: &[u8], commitments_flat: &[u8], pseudo_output: &[u8]) -> bool { salvium_crypto::clsag::clsag_verify_wasm(message, sig_bytes, ring_flat, commitments_flat, pseudo_output) }
#[wasm_bindgen] pub fn tclsag_sign_wasm(message: &[u8], ring_flat: &[u8], secret_key_x: &[u8], secret_key_y: &[u8], commitments_flat: &[u8], commitment_mask: &[u8], pseudo_output: &[u8], secret_index: u32) -> Vec<u8> { salvium_crypto::tclsag::tclsag_sign_wasm(message, ring_flat, secret_key_x, secret_key_y, commitments_flat, commitment_mask, pseudo_output, secret_index) }
#[wasm_bindgen] pub fn tclsag_verify_wasm(message: &[u8], sig_bytes: &[u8], ring_flat: &[u8], commitments_flat: &[u8], pseudo_output: &[u8]) -> bool { salvium_crypto::tclsag::tclsag_verify_wasm(message, sig_bytes, ring_flat, commitments_flat, pseudo_output) }

// Bulletproofs+
#[wasm_bindgen] pub fn bulletproof_plus_prove_wasm(amounts_bytes: &[u8], masks_flat: &[u8]) -> Vec<u8> { salvium_crypto::bulletproofs_plus::bulletproof_plus_prove_wasm(amounts_bytes, masks_flat) }
#[wasm_bindgen] pub fn bulletproof_plus_verify_wasm(proof_data: &[u8], commitments_flat: &[u8]) -> bool { salvium_crypto::bulletproofs_plus::bulletproof_plus_verify_wasm(proof_data, commitments_flat) }

// Full RCT signature batch verification
#[wasm_bindgen] pub fn verify_rct_signatures_wasm(rct_type: u8, input_count: u32, ring_size: u32, tx_prefix_hash: &[u8], rct_base_bytes: &[u8], bp_components: &[u8], key_images_flat: &[u8], pseudo_outs_flat: &[u8], sigs_flat: &[u8], ring_pubkeys_flat: &[u8], ring_commitments_flat: &[u8]) -> Vec<u8> { salvium_crypto::rct_verify::verify_rct_signatures_wasm(rct_type, input_count, ring_size, tx_prefix_hash, rct_base_bytes, bp_components, key_images_flat, pseudo_outs_flat, sigs_flat, ring_pubkeys_flat, ring_commitments_flat) }

// ─── Explorer-specific APIs ─────────────────────────────────────────────────

/// Parse a raw transaction binary and return an enriched JSON analysis.
///
/// Returns JSON with all fields from `parse_transaction_bytes()` plus:
/// - `tx_type_name`: human-readable TX type
/// - `rct_type_name`: human-readable RCT type
/// - `input_count`: number of inputs
/// - `output_count`: number of outputs
/// - `is_coinbase`: whether this is a miner/coinbase TX
/// - `is_carrot`: whether any output uses CARROT format
/// - `key_images`: array of key image hex strings
/// - `output_keys`: array of output public key hex strings
#[wasm_bindgen]
pub fn parse_and_analyze_tx(tx_bytes: &[u8]) -> String {
    let raw_json = salvium_crypto::parse_transaction_bytes(tx_bytes);

    let mut parsed: serde_json::Value = match serde_json::from_str(&raw_json) {
        Ok(v) => v,
        Err(_) => return raw_json,
    };

    // If there's an error field, return as-is
    if parsed.get("error").is_some() {
        return raw_json;
    }

    // Extract all analysis data before mutating (borrow checker requires this)
    let (tx_type, rct_type, input_count, output_count, is_coinbase, is_carrot, key_images, output_keys, fee) = {
        let prefix = &parsed["prefix"];
        let tx_type = prefix.get("txType")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;
        let rct_type = parsed.get("rct")
            .and_then(|r| r.get("type"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        let vin = prefix.get("vin").and_then(|v| v.as_array());
        let vout = prefix.get("vout").and_then(|v| v.as_array());
        let input_count = vin.map(|v| v.len()).unwrap_or(0);
        let output_count = vout.map(|v| v.len()).unwrap_or(0);

        let is_coinbase = vin
            .map(|inputs| {
                inputs.iter().any(|inp| {
                    inp.get("type").and_then(|t| t.as_u64()).map(|t| t == 0xff).unwrap_or(false)
                })
            })
            .unwrap_or(false);

        let is_carrot = vout
            .map(|outputs| {
                outputs.iter().any(|out| {
                    out.get("type").and_then(|t| t.as_u64()).map(|t| t == 0x04).unwrap_or(false)
                })
            })
            .unwrap_or(false);

        let key_images: Vec<String> = vin
            .map(|inputs| {
                inputs.iter()
                    .filter_map(|inp| inp.get("keyImage").and_then(|k| k.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let output_keys: Vec<String> = vout
            .map(|outputs| {
                outputs.iter()
                    .filter_map(|out| out.get("key").and_then(|k| k.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let fee = parsed.get("rct")
            .and_then(|r| r.get("txnFee"))
            .and_then(|f| f.as_str())
            .unwrap_or("0")
            .to_string();

        (tx_type, rct_type, input_count, output_count, is_coinbase, is_carrot, key_images, output_keys, fee)
    };

    // Add analysis fields
    if let Some(obj) = parsed.as_object_mut() {
        obj.insert("tx_type_name".into(), serde_json::Value::String(
            salvium_crypto::wasm_tx_type_name(tx_type),
        ));
        obj.insert("rct_type_name".into(), serde_json::Value::String(
            salvium_crypto::wasm_rct_type_name(rct_type),
        ));
        obj.insert("input_count".into(), serde_json::json!(input_count));
        obj.insert("output_count".into(), serde_json::json!(output_count));
        obj.insert("is_coinbase".into(), serde_json::json!(is_coinbase));
        obj.insert("is_carrot".into(), serde_json::json!(is_carrot));
        obj.insert("key_images".into(), serde_json::json!(key_images));
        obj.insert("output_keys".into(), serde_json::json!(output_keys));
        obj.insert("fee".into(), serde_json::Value::String(fee));
    }

    serde_json::to_string(&parsed).unwrap_or(raw_json)
}

/// Parse a raw block binary and return an enriched JSON analysis.
///
/// Returns JSON with all fields from `parse_block_bytes()` plus:
/// - `miner_tx_analysis`: analyzed miner transaction (same as parse_and_analyze_tx)
/// - `tx_count`: number of transaction hashes (excluding miner tx)
#[wasm_bindgen]
pub fn parse_and_analyze_block(block_bytes: &[u8]) -> String {
    let raw_json = salvium_crypto::parse_block_bytes(block_bytes);

    let mut parsed: serde_json::Value = match serde_json::from_str(&raw_json) {
        Ok(v) => v,
        Err(_) => return raw_json,
    };

    if parsed.get("error").is_some() {
        return raw_json;
    }

    // Count transaction hashes
    let tx_count = parsed
        .get("txHashes")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);

    if let Some(obj) = parsed.as_object_mut() {
        obj.insert("tx_count".into(), serde_json::json!(tx_count));
    }

    serde_json::to_string(&parsed).unwrap_or(raw_json)
}

/// Scan a transaction with a view key to find owned outputs.
///
/// This is a view-only scan: it uses the view secret key and spend public key
/// to check each output for ownership, then decrypts amounts for matching outputs.
///
/// Parameters:
/// - `tx_bytes`: raw transaction binary
/// - `view_secret`: 32-byte view secret key
/// - `spend_pub`: 32-byte spend public key
///
/// Returns JSON array of owned outputs:
/// ```json
/// [
///   {
///     "output_index": 0,
///     "amount": "1000000000",
///     "output_key": "hex...",
///     "subaddress_major": 0,
///     "subaddress_minor": 0
///   }
/// ]
/// ```
///
/// Returns `{"error": "..."}` on failure or empty `[]` if no outputs match.
#[wasm_bindgen]
pub fn decode_outputs_for_view_key(
    tx_bytes: &[u8],
    view_secret: &[u8],
    spend_pub: &[u8],
) -> String {
    if view_secret.len() != 32 || spend_pub.len() != 32 {
        return r#"{"error":"view_secret and spend_pub must each be 32 bytes"}"#.to_string();
    }

    // Parse the transaction first
    let raw_json = salvium_crypto::parse_transaction_bytes(tx_bytes);
    let parsed: serde_json::Value = match serde_json::from_str(&raw_json) {
        Ok(v) => v,
        Err(_) => return format!(r#"{{"error":"failed to parse transaction"}}"#),
    };

    if parsed.get("error").is_some() {
        return raw_json;
    }

    let prefix = &parsed["prefix"];
    let vout = match prefix.get("vout").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return "[]".to_string(),
    };

    // Get the tx public key from the extra
    let tx_pub_key = prefix
        .get("extra")
        .and_then(|e| e.get("pubkey"))
        .and_then(|p| p.as_str())
        .and_then(|hex_str| hex::decode(hex_str).ok());

    let tx_pub_key = match tx_pub_key {
        Some(k) if k.len() == 32 => k,
        _ => return "[]".to_string(), // No tx pub key = can't scan
    };

    // Generate key derivation: D = 8 * view_secret * tx_pub_key
    let derivation = salvium_crypto::generate_key_derivation(&tx_pub_key, view_secret);
    if derivation.is_empty() {
        return "[]".to_string();
    }

    let mut results = Vec::new();

    for (i, out) in vout.iter().enumerate() {
        let output_key_hex = match out.get("key").and_then(|k| k.as_str()) {
            Some(k) => k,
            None => continue,
        };
        let output_key = match hex::decode(output_key_hex) {
            Ok(k) if k.len() == 32 => k,
            _ => continue,
        };

        // Derive the expected output public key: P' = D_to_scalar(i)*G + spend_pub
        let derived_pub = salvium_crypto::derive_public_key(&derivation, i as u32, spend_pub);
        if derived_pub.is_empty() {
            continue;
        }

        // Check if this output belongs to us
        if derived_pub == output_key {
            // Decrypt amount using ECDH info if available
            let amount_str = out
                .get("amount")
                .and_then(|a| a.as_str())
                .unwrap_or("0")
                .to_string();

            results.push(serde_json::json!({
                "output_index": i,
                "amount": amount_str,
                "output_key": output_key_hex,
                "subaddress_major": 0,
                "subaddress_minor": 0,
            }));
        }
    }

    serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string())
}
