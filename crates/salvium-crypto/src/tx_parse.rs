//! Full transaction binary parser.
//!
//! Parses raw Salvium transaction bytes into a JSON string, matching the
//! structure produced by `src/transaction/parsing.js`.
//!
//! Binary fields are hex-encoded strings, amounts are decimal strings,
//! small integers are numbers.

use crate::tx_constants::*;
use crate::tx_format::decode_varint;
use serde_json::{json, Value};

// ─── Cursor ──────────────────────────────────────────────────────────────────

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], String> {
        if self.offset + count > self.data.len() {
            return Err(format!(
                "Unexpected end of data at offset {} (need {} bytes, have {})",
                self.offset,
                count,
                self.remaining()
            ));
        }
        let slice = &self.data[self.offset..self.offset + count];
        self.offset += count;
        Ok(slice)
    }

    fn read_byte(&mut self) -> Result<u8, String> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_varint(&mut self) -> Result<u64, String> {
        match decode_varint(self.data, self.offset) {
            Some((value, bytes_read)) => {
                self.offset += bytes_read;
                Ok(value)
            }
            None => Err(format!(
                "Varint decode failed at offset {}",
                self.offset
            )),
        }
    }

    fn read_u32_le(&mut self) -> Result<u32, String> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64_le(&mut self) -> Result<u64, String> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_string(&mut self) -> Result<String, String> {
        let len = self.read_varint()? as usize;
        if len == 0 {
            return Ok(String::new());
        }
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| format!("Invalid UTF-8 string at offset {}: {}", self.offset - len, e))
    }
}

// ─── Hex helpers ─────────────────────────────────────────────────────────────

fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ─── Transaction Parsing ─────────────────────────────────────────────────────

/// Parse a complete transaction from raw bytes to JSON string.
///
/// Output JSON has the same structure as the JS `parseTransaction()`:
/// ```json
/// {
///   "prefix": { "version": ..., "unlockTime": ..., "vin": [...], "vout": [...], ... },
///   "rct": { "type": ..., "txnFee": "...", "ecdhInfo": [...], ... },
///   "_bytesRead": ...,
///   "_prefixEndOffset": ...
/// }
/// ```
pub fn parse_transaction(data: &[u8]) -> Result<String, String> {
    let mut c = Cursor::new(data);
    let tx = parse_transaction_inner(&mut c)?;
    serde_json::to_string(&tx).map_err(|e| format!("JSON serialization error: {e}"))
}

fn parse_transaction_inner(c: &mut Cursor) -> Result<Value, String> {
    // ─── TX Prefix ───────────────────────────────────────────────────────
    let version = c.read_varint()?;
    let unlock_time = c.read_varint()?;

    // Inputs
    let vin_count = c.read_varint()? as usize;
    let mut vin = Vec::with_capacity(vin_count);
    for _ in 0..vin_count {
        let input_type = c.read_byte()?;
        match input_type {
            TXIN_GEN => {
                let height = c.read_varint()?;
                vin.push(json!({
                    "type": TXIN_GEN,
                    "height": height
                }));
            }
            TXIN_KEY => {
                let amount = c.read_varint()?;
                let asset_type = c.read_string()?;
                let key_offset_count = c.read_varint()? as usize;
                let mut key_offsets = Vec::with_capacity(key_offset_count);
                for _ in 0..key_offset_count {
                    key_offsets.push(c.read_varint()?);
                }
                let key_image = to_hex(c.read_bytes(32)?);
                vin.push(json!({
                    "type": TXIN_KEY,
                    "amount": amount.to_string(),
                    "assetType": asset_type,
                    "keyOffsets": key_offsets,
                    "keyImage": key_image
                }));
            }
            _ => return Err(format!("Unknown input type: {input_type}")),
        }
    }

    // Outputs
    let vout_count = c.read_varint()? as usize;
    let mut vout = Vec::with_capacity(vout_count);
    for _ in 0..vout_count {
        let amount = c.read_varint()?;
        let output_type = c.read_byte()?;
        match output_type {
            TXOUT_KEY => {
                let key = to_hex(c.read_bytes(32)?);
                let asset_type = c.read_string()?;
                let output_unlock_time = c.read_varint()?;
                vout.push(json!({
                    "type": TXOUT_KEY,
                    "amount": amount.to_string(),
                    "key": key,
                    "assetType": asset_type,
                    "unlockTime": output_unlock_time
                }));
            }
            TXOUT_TAGGED_KEY => {
                let key = to_hex(c.read_bytes(32)?);
                let asset_type = c.read_string()?;
                let output_unlock_time = c.read_varint()?;
                let view_tag = c.read_byte()?;
                vout.push(json!({
                    "type": TXOUT_TAGGED_KEY,
                    "amount": amount.to_string(),
                    "key": key,
                    "assetType": asset_type,
                    "unlockTime": output_unlock_time,
                    "viewTag": view_tag
                }));
            }
            TXOUT_CARROT_V1 => {
                let key = to_hex(c.read_bytes(32)?);
                let asset_type = c.read_string()?;
                let view_tag = to_hex(c.read_bytes(3)?);
                let encrypted_janus_anchor = to_hex(c.read_bytes(16)?);
                vout.push(json!({
                    "type": TXOUT_CARROT_V1,
                    "amount": amount.to_string(),
                    "key": key,
                    "assetType": asset_type,
                    "viewTag": view_tag,
                    "encryptedJanusAnchor": encrypted_janus_anchor
                }));
            }
            _ => return Err(format!("Unknown output type: {output_type}")),
        }
    }

    // Extra
    let extra_size = c.read_varint()? as usize;
    let extra_bytes = c.read_bytes(extra_size)?;
    let extra_json_str = crate::tx_format::parse_extra(extra_bytes);
    let extra: Value = serde_json::from_str(&extra_json_str)
        .map_err(|e| format!("Extra parse error: {e}"))?;

    // Salvium-specific prefix fields
    let tx_type = c.read_varint()? as u8;

    let mut amount_burnt = json!("0");
    let mut return_address = Value::Null;
    let mut return_address_list = Value::Null;
    let mut return_address_change_mask = Value::Null;
    let mut return_pubkey = Value::Null;
    let mut source_asset_type = json!("");
    let mut destination_asset_type = json!("");
    let mut amount_slippage_limit = json!("0");
    let mut protocol_tx_data = Value::Null;

    if tx_type != TX_TYPE_UNSET && tx_type != TX_TYPE_PROTOCOL {
        amount_burnt = json!(c.read_varint()?.to_string());

        if tx_type != TX_TYPE_MINER {
            if tx_type == TX_TYPE_TRANSFER && version >= 3 {
                // TRANSFER v3+: return_address_list + change_mask
                let list_count = c.read_varint()? as usize;
                let mut list = Vec::with_capacity(list_count);
                for _ in 0..list_count {
                    list.push(json!(to_hex(c.read_bytes(32)?)));
                }
                return_address_list = json!(list);
                let mask_count = c.read_varint()? as usize;
                return_address_change_mask = json!(to_hex(c.read_bytes(mask_count)?));
            } else if tx_type == TX_TYPE_STAKE && version >= 4 {
                // STAKE v4+: protocol_tx_data
                let ptx_version = c.read_varint()?;
                let ptx_return_addr = to_hex(c.read_bytes(32)?);
                let ptx_return_pubkey = to_hex(c.read_bytes(32)?);
                let ptx_view_tag = to_hex(c.read_bytes(3)?);
                let ptx_anchor_enc = to_hex(c.read_bytes(16)?);
                protocol_tx_data = json!({
                    "version": ptx_version,
                    "return_address": ptx_return_addr,
                    "return_pubkey": ptx_return_pubkey,
                    "return_view_tag": ptx_view_tag,
                    "return_anchor_enc": ptx_anchor_enc
                });
            } else {
                return_address = json!(to_hex(c.read_bytes(32)?));
                return_pubkey = json!(to_hex(c.read_bytes(32)?));
            }

            source_asset_type = json!(c.read_string()?);
            destination_asset_type = json!(c.read_string()?);
            amount_slippage_limit = json!(c.read_varint()?.to_string());
        }
    }

    let prefix = json!({
        "version": version,
        "unlockTime": unlock_time,
        "vin": vin,
        "vout": vout,
        "extra": extra,
        "txType": tx_type,
        "amount_burnt": amount_burnt,
        "return_address": return_address,
        "return_address_list": return_address_list,
        "return_address_change_mask": return_address_change_mask,
        "return_pubkey": return_pubkey,
        "source_asset_type": source_asset_type,
        "destination_asset_type": destination_asset_type,
        "amount_slippage_limit": amount_slippage_limit,
        "protocol_tx_data": protocol_tx_data
    });

    // V1 transactions: no RCT section
    if version == 1 {
        return Ok(json!({
            "prefix": prefix,
            "_bytesRead": c.offset,
            "_prefixEndOffset": c.offset
        }));
    }

    let prefix_end_offset = c.offset;

    // Mixin from first input
    let mixin = if let Some(first) = vin.first() {
        first.get("keyOffsets")
            .and_then(|v| v.as_array())
            .map(|a| a.len().saturating_sub(1))
            .unwrap_or(15)
    } else {
        15
    };

    // ─── RCT Signature ───────────────────────────────────────────────────
    let rct = parse_ringct_signature(c, vin_count, vout_count, mixin)?;

    let bytes_read = c.offset;

    Ok(json!({
        "prefix": prefix,
        "rct": rct,
        "_bytesRead": bytes_read,
        "_prefixEndOffset": prefix_end_offset
    }))
}

// ─── RingCT Parsing ──────────────────────────────────────────────────────────

fn parse_ringct_signature(
    c: &mut Cursor,
    input_count: usize,
    output_count: usize,
    mixin: usize,
) -> Result<Value, String> {
    let rct_type = c.read_byte()?;

    if rct_type == RCT_TYPE_NULL {
        return Ok(json!({ "type": RCT_TYPE_NULL }));
    }

    // Validate type
    if rct_type < RCT_TYPE_BULLETPROOF_PLUS || rct_type > RCT_TYPE_SALVIUM_ONE {
        return Err(format!(
            "Invalid RCT type: {} at offset {}",
            rct_type,
            c.offset - 1
        ));
    }

    // Fee
    let fee = c.read_varint()?;

    // ecdhInfo: 8 bytes per output (compact format for BP+ types)
    let mut ecdh_info = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let amount = to_hex(c.read_bytes(8)?);
        ecdh_info.push(json!({ "amount": amount }));
    }

    // outPk: 32 bytes per output
    let mut out_pk = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        out_pk.push(json!(to_hex(c.read_bytes(32)?)));
    }

    // p_r: Salvium-specific 32 bytes
    let p_r = to_hex(c.read_bytes(32)?);

    let mut rct = json!({
        "type": rct_type,
        "txnFee": fee.to_string(),
        "ecdhInfo": ecdh_info,
        "outPk": out_pk,
        "p_r": p_r
    });

    // salvium_data based on type
    match rct_type {
        RCT_TYPE_SALVIUM_ZERO | RCT_TYPE_SALVIUM_ONE => {
            match parse_salvium_data(c) {
                Ok(sd) => {
                    rct["salvium_data"] = sd;
                }
                Err(e) => {
                    rct["salvium_data_parse_error"] = json!(e);
                    return Ok(rct);
                }
            }
        }
        RCT_TYPE_FULL_PROOFS => {
            // Only pr_proof and sa_proof (2 x 96 bytes)
            let pr_proof = parse_zk_proof(c)?;
            let sa_proof = parse_zk_proof(c)?;
            rct["salvium_data"] = json!({
                "pr_proof": pr_proof,
                "sa_proof": sa_proof
            });
        }
        _ => {}
    }

    // ─── Prunable section ────────────────────────────────────────────────
    if c.remaining() > 0 && rct_type != RCT_TYPE_NULL {
        match parse_rct_sig_prunable(c, rct_type, input_count, output_count, mixin) {
            Ok(prunable) => {
                if let Some(bp) = prunable.get("bulletproofPlus") {
                    rct["bulletproofPlus"] = bp.clone();
                }
                if let Some(clsags) = prunable.get("CLSAGs") {
                    rct["CLSAGs"] = clsags.clone();
                }
                if let Some(tclsags) = prunable.get("TCLSAGs") {
                    rct["TCLSAGs"] = tclsags.clone();
                }
                if let Some(pseudo_outs) = prunable.get("pseudoOuts") {
                    rct["pseudoOuts"] = pseudo_outs.clone();
                }
            }
            Err(e) => {
                rct["prunable_parse_error"] = json!(e);
            }
        }
    }

    Ok(rct)
}

// ─── ZK Proof (3 x 32 bytes = 96 bytes) ─────────────────────────────────────

fn parse_zk_proof(c: &mut Cursor) -> Result<Value, String> {
    let r = to_hex(c.read_bytes(32)?);
    let z1 = to_hex(c.read_bytes(32)?);
    let z2 = to_hex(c.read_bytes(32)?);
    Ok(json!({ "R": r, "z1": z1, "z2": z2 }))
}

// ─── salvium_data_t ──────────────────────────────────────────────────────────

fn parse_salvium_data(c: &mut Cursor) -> Result<Value, String> {
    let salvium_data_type = c.read_varint()?;

    let pr_proof = parse_zk_proof(c)?;
    let sa_proof = parse_zk_proof(c)?;

    let mut result = json!({
        "salvium_data_type": salvium_data_type,
        "pr_proof": pr_proof,
        "sa_proof": sa_proof
    });

    // SalviumZeroAudit (type 1)
    if salvium_data_type == 1 {
        let cz_proof = parse_zk_proof(c)?;
        result["cz_proof"] = cz_proof;

        // input_verification_data
        let input_count = c.read_varint()? as usize;
        let mut ivd = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let a_r = to_hex(c.read_bytes(32)?);
            let amount = c.read_varint()?;
            let idx = c.read_varint()?;
            let origin_tx_type = c.read_varint()? as u8;

            let mut item = json!({
                "aR": a_r,
                "amount": amount.to_string(),
                "i": idx,
                "origin_tx_type": origin_tx_type
            });

            if origin_tx_type != 0 {
                item["aR_stake"] = json!(to_hex(c.read_bytes(32)?));
                item["i_stake"] = json!(c.read_u64_le()?);
            }

            ivd.push(item);
        }
        result["input_verification_data"] = json!(ivd);

        // spend_pubkey
        result["spend_pubkey"] = json!(to_hex(c.read_bytes(32)?));

        // enc_view_privkey_str
        result["enc_view_privkey_str"] = json!(c.read_string()?);
    }

    Ok(result)
}

// ─── RCT Prunable Section ────────────────────────────────────────────────────

fn parse_rct_sig_prunable(
    c: &mut Cursor,
    rct_type: u8,
    input_count: usize,
    _output_count: usize,
    mixin: usize,
) -> Result<Value, String> {
    let mut result = json!({});

    // BulletproofPlus
    if rct_type >= RCT_TYPE_BULLETPROOF_PLUS {
        let nbp = c.read_varint()? as usize;
        if nbp > 1000 {
            return Err(format!("Invalid bulletproofPlus count: {nbp}"));
        }

        let mut bp_proofs = Vec::with_capacity(nbp);
        for _ in 0..nbp {
            let a = to_hex(c.read_bytes(32)?);
            let a1 = to_hex(c.read_bytes(32)?);
            let b = to_hex(c.read_bytes(32)?);
            let r1 = to_hex(c.read_bytes(32)?);
            let s1 = to_hex(c.read_bytes(32)?);
            let d1 = to_hex(c.read_bytes(32)?);

            // L array (varint count)
            let l_count = c.read_varint()? as usize;
            if l_count > 64 {
                return Err(format!("Invalid L array count: {l_count}"));
            }
            let mut l_arr = Vec::with_capacity(l_count);
            for _ in 0..l_count {
                l_arr.push(json!(to_hex(c.read_bytes(32)?)));
            }

            // R array (its own varint count)
            let r_count = c.read_varint()? as usize;
            if r_count > 64 {
                return Err(format!("Invalid R array count: {r_count}"));
            }
            let mut r_arr = Vec::with_capacity(r_count);
            for _ in 0..r_count {
                r_arr.push(json!(to_hex(c.read_bytes(32)?)));
            }

            bp_proofs.push(json!({
                "A": a, "A1": a1, "B": b,
                "r1": r1, "s1": s1, "d1": d1,
                "L": l_arr, "R": r_arr
            }));
        }
        result["bulletproofPlus"] = json!(bp_proofs);
    }

    // CLSAGs / TCLSAGs
    let ring_size = mixin + 1;

    if rct_type == RCT_TYPE_SALVIUM_ONE {
        // TCLSAGs
        let mut tclsags = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let mut sx = Vec::with_capacity(ring_size);
            for _ in 0..ring_size {
                sx.push(json!(to_hex(c.read_bytes(32)?)));
            }
            let mut sy = Vec::with_capacity(ring_size);
            for _ in 0..ring_size {
                sy.push(json!(to_hex(c.read_bytes(32)?)));
            }
            let c1 = to_hex(c.read_bytes(32)?);
            let d = to_hex(c.read_bytes(32)?);
            tclsags.push(json!({ "sx": sx, "sy": sy, "c1": c1, "D": d }));
        }
        result["TCLSAGs"] = json!(tclsags);
    } else if rct_type >= RCT_TYPE_CLSAG {
        // CLSAGs
        let mut clsags = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let mut s = Vec::with_capacity(ring_size);
            for _ in 0..ring_size {
                s.push(json!(to_hex(c.read_bytes(32)?)));
            }
            let c1 = to_hex(c.read_bytes(32)?);
            let d = to_hex(c.read_bytes(32)?);
            clsags.push(json!({ "s": s, "c1": c1, "D": d }));
        }
        result["CLSAGs"] = json!(clsags);
    }

    // pseudoOuts
    if rct_type >= RCT_TYPE_BULLETPROOF_PLUS {
        let mut pseudo_outs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            pseudo_outs.push(json!(to_hex(c.read_bytes(32)?)));
        }
        result["pseudoOuts"] = json!(pseudo_outs);
    }

    Ok(result)
}

// ─── Pricing Record Parsing ──────────────────────────────────────────────────

fn parse_pricing_record(c: &mut Cursor) -> Result<(Value, usize), String> {
    let start = c.offset;

    let pr_version = c.read_varint()?;
    let height = c.read_varint()?;

    // supply_data { sal, vsd }
    let sal = c.read_varint()?;
    let vsd = c.read_varint()?;

    // assets vector
    let assets_count = c.read_varint()? as usize;
    let mut assets = Vec::with_capacity(assets_count);
    for _ in 0..assets_count {
        let asset_type = c.read_string()?;
        let spot_price = c.read_varint()?;
        let ma_price = c.read_varint()?;
        assets.push(json!({
            "assetType": asset_type,
            "spotPrice": spot_price.to_string(),
            "maPrice": ma_price.to_string()
        }));
    }

    let timestamp = c.read_varint()?;

    // signature (vector of bytes)
    let sig_len = c.read_varint()? as usize;
    let signature = if sig_len > 0 {
        to_hex(c.read_bytes(sig_len)?)
    } else {
        String::new()
    };

    let bytes_read = c.offset - start;

    Ok((
        json!({
            "prVersion": pr_version,
            "height": height,
            "supply": { "sal": sal.to_string(), "vsd": vsd.to_string() },
            "assets": assets,
            "timestamp": timestamp,
            "signature": signature
        }),
        bytes_read,
    ))
}

// ─── Block Parsing ───────────────────────────────────────────────────────────

/// Parse a complete block from raw bytes to JSON string.
pub fn parse_block(data: &[u8]) -> Result<String, String> {
    let mut c = Cursor::new(data);

    // Block header
    let major_version = c.read_varint()?;
    let minor_version = c.read_varint()?;
    let timestamp = c.read_varint()?;
    let prev_id = to_hex(c.read_bytes(32)?);
    let nonce = c.read_u32_le()?;

    // Pricing record
    let pricing_record = if major_version >= HF_VERSION_ENABLE_ORACLE {
        let (pr, _) = parse_pricing_record(&mut c)?;
        pr
    } else {
        Value::Null
    };

    // Miner TX
    let miner_tx = parse_transaction_inner(&mut c)?;

    // Protocol TX
    let protocol_tx = parse_transaction_inner(&mut c)?;

    // TX hashes
    let tx_hash_count = c.read_varint()? as usize;
    let mut tx_hashes = Vec::with_capacity(tx_hash_count);
    for _ in 0..tx_hash_count {
        tx_hashes.push(json!(to_hex(c.read_bytes(32)?)));
    }

    let result = json!({
        "header": {
            "majorVersion": major_version,
            "minorVersion": minor_version,
            "timestamp": timestamp,
            "prevId": prev_id,
            "nonce": nonce,
            "pricingRecord": pricing_record
        },
        "minerTx": miner_tx,
        "protocolTx": protocol_tx,
        "txHashes": tx_hashes,
        "_bytesRead": c.offset
    });

    serde_json::to_string(&result).map_err(|e| format!("JSON serialization error: {e}"))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Test helper functions exposed for roundtrip tests in tx_serialize.
#[cfg(test)]
pub(crate) mod tests_helper {
    use crate::tx_constants::*;
    use crate::tx_format::encode_varint;

    pub fn build_minimal_coinbase_tx() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&encode_varint(2));
        data.extend_from_slice(&encode_varint(50));
        data.extend_from_slice(&encode_varint(1));
        data.push(TXIN_GEN);
        data.extend_from_slice(&encode_varint(42));
        data.extend_from_slice(&encode_varint(1));
        data.extend_from_slice(&encode_varint(1000));
        data.push(TXOUT_TAGGED_KEY);
        data.extend_from_slice(&[0xAA; 32]);
        data.extend_from_slice(&encode_varint(3));
        data.extend_from_slice(b"SAL");
        data.extend_from_slice(&encode_varint(0));
        data.push(0x42);
        data.extend_from_slice(&encode_varint(0));
        data.extend_from_slice(&encode_varint(TX_TYPE_MINER as u64));
        data.extend_from_slice(&encode_varint(0));
        data.push(RCT_TYPE_NULL);
        data
    }

    pub fn build_minimal_transfer_tx() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&encode_varint(2));
        data.extend_from_slice(&encode_varint(0));
        data.extend_from_slice(&encode_varint(1));
        data.push(TXIN_KEY);
        data.extend_from_slice(&encode_varint(0));
        data.extend_from_slice(&encode_varint(3));
        data.extend_from_slice(b"SAL");
        data.extend_from_slice(&encode_varint(16));
        for i in 0u64..16 {
            data.extend_from_slice(&encode_varint(i * 100));
        }
        data.extend_from_slice(&[0xBB; 32]);
        data.extend_from_slice(&encode_varint(1));
        data.extend_from_slice(&encode_varint(0));
        data.push(TXOUT_TAGGED_KEY);
        data.extend_from_slice(&[0xCC; 32]);
        data.extend_from_slice(&encode_varint(3));
        data.extend_from_slice(b"SAL");
        data.extend_from_slice(&encode_varint(0));
        data.push(0x99);
        data.extend_from_slice(&encode_varint(33));
        data.push(0x01);
        data.extend_from_slice(&[0xDD; 32]);
        data.extend_from_slice(&encode_varint(TX_TYPE_TRANSFER as u64));
        data.extend_from_slice(&encode_varint(0));
        data.extend_from_slice(&[0x11; 32]);
        data.extend_from_slice(&[0x22; 32]);
        data.extend_from_slice(&encode_varint(3));
        data.extend_from_slice(b"SAL");
        data.extend_from_slice(&encode_varint(3));
        data.extend_from_slice(b"SAL");
        data.extend_from_slice(&encode_varint(0));
        data.push(RCT_TYPE_SALVIUM_ZERO);
        data.extend_from_slice(&encode_varint(50000));
        data.extend_from_slice(&[0xEE; 8]);
        data.extend_from_slice(&[0xFF; 32]);
        data.extend_from_slice(&[0x33; 32]);
        data.extend_from_slice(&encode_varint(0));
        data.extend_from_slice(&[0x44; 96]);
        data.extend_from_slice(&[0x55; 96]);
        data.extend_from_slice(&encode_varint(1));
        data.extend_from_slice(&[0x66; 32]);
        data.extend_from_slice(&[0x67; 32]);
        data.extend_from_slice(&[0x68; 32]);
        data.extend_from_slice(&[0x69; 32]);
        data.extend_from_slice(&[0x6A; 32]);
        data.extend_from_slice(&[0x6B; 32]);
        data.extend_from_slice(&encode_varint(2));
        data.extend_from_slice(&[0x6C; 32]);
        data.extend_from_slice(&[0x6D; 32]);
        data.extend_from_slice(&encode_varint(2));
        data.extend_from_slice(&[0x6E; 32]);
        data.extend_from_slice(&[0x6F; 32]);
        for _ in 0..16 {
            data.extend_from_slice(&[0x70; 32]);
        }
        data.extend_from_slice(&[0x71; 32]);
        data.extend_from_slice(&[0x72; 32]);
        data.extend_from_slice(&[0x73; 32]);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_format::encode_varint;

    /// Build a minimal coinbase TX (v2, 1 gen input, 1 tagged_key output, RCT Null).
    fn build_minimal_coinbase_tx() -> Vec<u8> {
        let mut data = Vec::new();

        // version = 2
        data.extend_from_slice(&encode_varint(2));
        // unlock_time = 50
        data.extend_from_slice(&encode_varint(50));

        // 1 input (gen)
        data.extend_from_slice(&encode_varint(1));
        data.push(TXIN_GEN); // input type
        data.extend_from_slice(&encode_varint(42)); // height

        // 1 output (tagged_key)
        data.extend_from_slice(&encode_varint(1));
        data.extend_from_slice(&encode_varint(1000)); // amount
        data.push(TXOUT_TAGGED_KEY);
        data.extend_from_slice(&[0xAA; 32]); // key
        data.extend_from_slice(&encode_varint(3)); // asset type len
        data.extend_from_slice(b"SAL");
        data.extend_from_slice(&encode_varint(0)); // unlock_time
        data.push(0x42); // view_tag

        // extra (empty)
        data.extend_from_slice(&encode_varint(0));

        // tx_type = MINER (1)
        data.extend_from_slice(&encode_varint(TX_TYPE_MINER as u64));
        // amount_burnt = 0
        data.extend_from_slice(&encode_varint(0));

        // RCT type = Null
        data.push(RCT_TYPE_NULL);

        data
    }

    #[test]
    fn test_parse_minimal_coinbase() {
        let data = build_minimal_coinbase_tx();
        let json_str = parse_transaction(&data).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["prefix"]["version"], 2);
        assert_eq!(parsed["prefix"]["unlockTime"], 50);
        assert_eq!(parsed["prefix"]["txType"], TX_TYPE_MINER);
        assert_eq!(parsed["prefix"]["vin"][0]["type"], TXIN_GEN as u64);
        assert_eq!(parsed["prefix"]["vin"][0]["height"], 42);
        assert_eq!(parsed["prefix"]["vout"][0]["type"], TXOUT_TAGGED_KEY as u64);
        assert_eq!(parsed["prefix"]["vout"][0]["viewTag"], 0x42);
        assert_eq!(parsed["rct"]["type"], RCT_TYPE_NULL);
    }

    /// Build a minimal transfer TX (v2, 1 key input, 1 tagged_key output, RCT BP+, no prunable).
    fn build_minimal_transfer_tx() -> Vec<u8> {
        let mut data = Vec::new();

        // version = 2
        data.extend_from_slice(&encode_varint(2));
        // unlock_time = 0
        data.extend_from_slice(&encode_varint(0));

        // 1 input (key)
        data.extend_from_slice(&encode_varint(1));
        data.push(TXIN_KEY);
        data.extend_from_slice(&encode_varint(0)); // amount
        data.extend_from_slice(&encode_varint(3)); // asset_type len
        data.extend_from_slice(b"SAL");
        data.extend_from_slice(&encode_varint(16)); // 16 key offsets
        for i in 0u64..16 {
            data.extend_from_slice(&encode_varint(i * 100));
        }
        data.extend_from_slice(&[0xBB; 32]); // key image

        // 1 output (tagged_key)
        data.extend_from_slice(&encode_varint(1));
        data.extend_from_slice(&encode_varint(0)); // amount
        data.push(TXOUT_TAGGED_KEY);
        data.extend_from_slice(&[0xCC; 32]); // key
        data.extend_from_slice(&encode_varint(3)); // asset_type len
        data.extend_from_slice(b"SAL");
        data.extend_from_slice(&encode_varint(0)); // unlock_time
        data.push(0x99); // view_tag

        // extra: tag 0x01 + 32-byte pubkey
        data.extend_from_slice(&encode_varint(33));
        data.push(0x01);
        data.extend_from_slice(&[0xDD; 32]);

        // tx_type = TRANSFER (3)
        data.extend_from_slice(&encode_varint(TX_TYPE_TRANSFER as u64));
        // amount_burnt = 0
        data.extend_from_slice(&encode_varint(0));
        // return_address (32 bytes)
        data.extend_from_slice(&[0x11; 32]);
        // return_pubkey (32 bytes)
        data.extend_from_slice(&[0x22; 32]);
        // source_asset_type
        data.extend_from_slice(&encode_varint(3));
        data.extend_from_slice(b"SAL");
        // destination_asset_type
        data.extend_from_slice(&encode_varint(3));
        data.extend_from_slice(b"SAL");
        // amount_slippage_limit
        data.extend_from_slice(&encode_varint(0));

        // RCT type = SalviumZero (8)
        data.push(RCT_TYPE_SALVIUM_ZERO);
        // fee
        data.extend_from_slice(&encode_varint(50000));
        // ecdhInfo: 1 output x 8 bytes
        data.extend_from_slice(&[0xEE; 8]);
        // outPk: 1 output x 32 bytes
        data.extend_from_slice(&[0xFF; 32]);
        // p_r: 32 bytes
        data.extend_from_slice(&[0x33; 32]);

        // salvium_data (type 0 = SalviumZero basic)
        data.extend_from_slice(&encode_varint(0)); // salvium_data_type
        data.extend_from_slice(&[0x44; 96]); // pr_proof
        data.extend_from_slice(&[0x55; 96]); // sa_proof

        // prunable: 1 BP+ proof (minimal)
        data.extend_from_slice(&encode_varint(1)); // nbp
        data.extend_from_slice(&[0x66; 32]); // A
        data.extend_from_slice(&[0x67; 32]); // A1
        data.extend_from_slice(&[0x68; 32]); // B
        data.extend_from_slice(&[0x69; 32]); // r1
        data.extend_from_slice(&[0x6A; 32]); // s1
        data.extend_from_slice(&[0x6B; 32]); // d1
        data.extend_from_slice(&encode_varint(2)); // L count
        data.extend_from_slice(&[0x6C; 32]); // L[0]
        data.extend_from_slice(&[0x6D; 32]); // L[1]
        data.extend_from_slice(&encode_varint(2)); // R count
        data.extend_from_slice(&[0x6E; 32]); // R[0]
        data.extend_from_slice(&[0x6F; 32]); // R[1]

        // CLSAGs (1 input, ring_size = 16)
        for _ in 0..16 {
            data.extend_from_slice(&[0x70; 32]); // s[j]
        }
        data.extend_from_slice(&[0x71; 32]); // c1
        data.extend_from_slice(&[0x72; 32]); // D

        // pseudoOuts (1 input)
        data.extend_from_slice(&[0x73; 32]);

        data
    }

    #[test]
    fn test_parse_minimal_transfer() {
        let data = build_minimal_transfer_tx();
        let json_str = parse_transaction(&data).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["prefix"]["version"], 2);
        assert_eq!(parsed["prefix"]["txType"], TX_TYPE_TRANSFER);
        assert_eq!(parsed["rct"]["type"], RCT_TYPE_SALVIUM_ZERO);
        assert_eq!(parsed["rct"]["txnFee"], "50000");

        // BP+ should have 1 proof with 2 L and 2 R
        let bp = &parsed["rct"]["bulletproofPlus"];
        assert_eq!(bp.as_array().unwrap().len(), 1);
        assert_eq!(bp[0]["L"].as_array().unwrap().len(), 2);
        assert_eq!(bp[0]["R"].as_array().unwrap().len(), 2);

        // CLSAGs
        let clsags = &parsed["rct"]["CLSAGs"];
        assert_eq!(clsags.as_array().unwrap().len(), 1);
        assert_eq!(clsags[0]["s"].as_array().unwrap().len(), 16);

        // pseudoOuts
        assert_eq!(parsed["rct"]["pseudoOuts"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_parse_carrot_v1_output() {
        let mut data = Vec::new();

        // version = 4
        data.extend_from_slice(&encode_varint(4));
        data.extend_from_slice(&encode_varint(0)); // unlock_time

        // 0 inputs
        data.extend_from_slice(&encode_varint(0));

        // 1 output (CARROT_V1)
        data.extend_from_slice(&encode_varint(1));
        data.extend_from_slice(&encode_varint(0)); // amount
        data.push(TXOUT_CARROT_V1);
        data.extend_from_slice(&[0xAA; 32]); // key
        data.extend_from_slice(&encode_varint(4)); // asset type len
        data.extend_from_slice(b"SAL1");
        data.extend_from_slice(&[0xBB; 3]); // view_tag (3 bytes)
        data.extend_from_slice(&[0xCC; 16]); // encrypted_janus_anchor

        // extra (empty)
        data.extend_from_slice(&encode_varint(0));
        // tx_type = UNSET
        data.extend_from_slice(&encode_varint(0));
        // RCT type = Null
        data.push(RCT_TYPE_NULL);

        let json_str = parse_transaction(&data).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        let out = &parsed["prefix"]["vout"][0];
        assert_eq!(out["type"], TXOUT_CARROT_V1 as u64);
        assert_eq!(out["assetType"], "SAL1");
        assert_eq!(out["viewTag"], hex::encode([0xBB; 3]));
        assert_eq!(out["encryptedJanusAnchor"], hex::encode([0xCC; 16]));
    }
}
