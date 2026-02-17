//! Full transaction JSON-to-binary serializer.
//!
//! Mirrors `tx_parse.rs` in reverse — reads a JSON string describing a
//! Salvium transaction and writes the corresponding binary representation.
//!
//! The JSON format matches the output of `tx_parse::parse_transaction()`.

use crate::tx_constants::*;
use crate::tx_format::encode_varint;
use serde_json::Value;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex).map_err(|e| format!("Invalid hex string '{}': {}", hex, e))
}

fn get_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn get_u64(v: &Value, key: &str) -> u64 {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

fn get_u8(v: &Value, key: &str) -> u8 {
    get_u64(v, key) as u8
}

fn get_array<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
}

fn write_varint(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&encode_varint(val));
}

fn write_hex_bytes(buf: &mut Vec<u8>, hex: &str) -> Result<(), String> {
    buf.extend_from_slice(&hex_to_bytes(hex)?);
    Ok(())
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    write_varint(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn write_u64_le(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_le_bytes());
}

// ─── Transaction Serialization ───────────────────────────────────────────────

/// Serialize a complete transaction from JSON string to binary bytes.
///
/// Input JSON format matches the output of `tx_parse::parse_transaction()`.
pub fn serialize_transaction(json_str: &str) -> Result<Vec<u8>, String> {
    let tx: Value =
        serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {e}"))?;
    let mut buf = Vec::with_capacity(4096);

    // 1. TX prefix
    serialize_tx_prefix_inner(&tx, &mut buf)?;

    // 2. RCT base
    if let Some(rct) = tx.get("rct") {
        serialize_rct_base(rct, &mut buf)?;

        let rct_type = get_u8(rct, "type");
        if rct_type != RCT_TYPE_NULL {
            // 3. RCT prunable
            serialize_rct_prunable(rct, rct_type, &mut buf)?;
        }
    }

    Ok(buf)
}

/// Serialize just the transaction prefix from JSON to binary.
pub fn serialize_tx_prefix(json_str: &str) -> Result<Vec<u8>, String> {
    let tx: Value =
        serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {e}"))?;
    let mut buf = Vec::with_capacity(2048);
    serialize_tx_prefix_inner(&tx, &mut buf)?;
    Ok(buf)
}

/// Serialize the RCT base section (type + fee + ecdhInfo + outPk + p_r + salvium_data).
pub fn serialize_rct_base(rct: &Value, buf: &mut Vec<u8>) -> Result<(), String> {
    let rct_type = get_u8(rct, "type");
    buf.push(rct_type);

    if rct_type == RCT_TYPE_NULL {
        return Ok(());
    }

    // Fee
    let fee = get_u64(rct, "txnFee");
    write_varint(buf, fee);

    // ecdhInfo (8 bytes per output)
    for item in get_array(rct, "ecdhInfo") {
        let amount_hex = get_str(item, "amount");
        write_hex_bytes(buf, amount_hex)?;
    }

    // outPk (32 bytes per output)
    for item in get_array(rct, "outPk") {
        let hex = item.as_str().unwrap_or("");
        write_hex_bytes(buf, hex)?;
    }

    // p_r (32 bytes) — Ed25519 identity if missing.
    let p_r = get_str(rct, "p_r");
    if !p_r.is_empty() {
        write_hex_bytes(buf, p_r)?;
    } else {
        // Ed25519 compressed identity point: [0x01, 0x00, ..., 0x00].
        let mut identity = [0u8; 32];
        identity[0] = 0x01;
        buf.extend_from_slice(&identity);
    }

    // salvium_data
    match rct_type {
        RCT_TYPE_SALVIUM_ZERO | RCT_TYPE_SALVIUM_ONE => {
            if let Some(sd) = rct.get("salvium_data") {
                serialize_salvium_data(sd, buf)?;
            }
        }
        RCT_TYPE_FULL_PROOFS => {
            if let Some(sd) = rct.get("salvium_data") {
                serialize_zk_proof(sd.get("pr_proof").unwrap_or(&Value::Null), buf)?;
                serialize_zk_proof(sd.get("sa_proof").unwrap_or(&Value::Null), buf)?;
            }
        }
        _ => {}
    }

    Ok(())
}

// ─── TX Prefix ───────────────────────────────────────────────────────────────

fn serialize_tx_prefix_inner(tx: &Value, buf: &mut Vec<u8>) -> Result<(), String> {
    // The JSON can have prefix as a nested object or be flat
    let prefix = tx.get("prefix").unwrap_or(tx);

    let version = get_u64(prefix, "version");
    write_varint(buf, version);
    write_varint(buf, get_u64(prefix, "unlockTime"));

    // Inputs
    let vin = get_array(prefix, "vin");
    write_varint(buf, vin.len() as u64);
    for input in vin {
        let input_type = get_u8(input, "type");
        match input_type {
            TXIN_GEN => {
                buf.push(TXIN_GEN);
                write_varint(buf, get_u64(input, "height"));
            }
            TXIN_KEY => {
                buf.push(TXIN_KEY);
                write_varint(buf, get_u64(input, "amount"));
                write_string(buf, get_str(input, "assetType"));
                let offsets = get_array(input, "keyOffsets");
                write_varint(buf, offsets.len() as u64);
                for o in offsets {
                    write_varint(buf, o.as_u64().unwrap_or(0));
                }
                write_hex_bytes(buf, get_str(input, "keyImage"))?;
            }
            _ => return Err(format!("Unknown input type: {input_type}")),
        }
    }

    // Outputs
    let vout = get_array(prefix, "vout");
    write_varint(buf, vout.len() as u64);
    for output in vout {
        write_varint(buf, get_u64(output, "amount"));
        let output_type = get_u8(output, "type");
        match output_type {
            TXOUT_KEY => {
                buf.push(TXOUT_KEY);
                write_hex_bytes(buf, get_str(output, "key"))?;
                write_string(buf, get_str(output, "assetType"));
                write_varint(buf, get_u64(output, "unlockTime"));
            }
            TXOUT_TAGGED_KEY => {
                buf.push(TXOUT_TAGGED_KEY);
                write_hex_bytes(buf, get_str(output, "key"))?;
                write_string(buf, get_str(output, "assetType"));
                write_varint(buf, get_u64(output, "unlockTime"));
                buf.push(get_u8(output, "viewTag"));
            }
            TXOUT_CARROT_V1 => {
                buf.push(TXOUT_CARROT_V1);
                write_hex_bytes(buf, get_str(output, "key"))?;
                write_string(buf, get_str(output, "assetType"));
                write_hex_bytes(buf, get_str(output, "viewTag"))?;
                write_hex_bytes(buf, get_str(output, "encryptedJanusAnchor"))?;
            }
            _ => return Err(format!("Unknown output type: {output_type}")),
        }
    }

    // Extra
    if let Some(extra) = prefix.get("extra") {
        // Extra is already a parsed array — serialize via tx_format
        let extra_bytes = serialize_extra_from_parsed(extra)?;
        write_varint(buf, extra_bytes.len() as u64);
        buf.extend_from_slice(&extra_bytes);
    } else {
        write_varint(buf, 0);
    }

    // Salvium-specific prefix fields
    let tx_type = get_u8(prefix, "txType");
    write_varint(buf, tx_type as u64);

    if tx_type != TX_TYPE_UNSET && tx_type != TX_TYPE_PROTOCOL {
        write_varint(buf, get_u64(prefix, "amount_burnt"));

        if tx_type != TX_TYPE_MINER {
            if tx_type == TX_TYPE_TRANSFER && version >= 3 {
                // return_address_list
                let list = get_array(prefix, "return_address_list");
                write_varint(buf, list.len() as u64);
                for addr in list {
                    write_hex_bytes(buf, addr.as_str().unwrap_or(""))?;
                }
                // return_address_change_mask
                let mask = get_str(prefix, "return_address_change_mask");
                if !mask.is_empty() {
                    let mask_bytes = hex_to_bytes(mask)?;
                    write_varint(buf, mask_bytes.len() as u64);
                    buf.extend_from_slice(&mask_bytes);
                } else {
                    write_varint(buf, 0);
                }
            } else if tx_type == TX_TYPE_STAKE && version >= 4 {
                // protocol_tx_data
                if let Some(ptx) = prefix.get("protocol_tx_data") {
                    write_varint(buf, get_u64(ptx, "version"));
                    write_hex_bytes(buf, get_str(ptx, "return_address"))?;
                    write_hex_bytes(buf, get_str(ptx, "return_pubkey"))?;
                    write_hex_bytes(buf, get_str(ptx, "return_view_tag"))?;
                    write_hex_bytes(buf, get_str(ptx, "return_anchor_enc"))?;
                }
            } else {
                // Legacy: return_address + return_pubkey
                let ra = get_str(prefix, "return_address");
                if !ra.is_empty() {
                    write_hex_bytes(buf, ra)?;
                } else {
                    buf.extend_from_slice(&[0u8; 32]);
                }
                let rp = get_str(prefix, "return_pubkey");
                if !rp.is_empty() {
                    write_hex_bytes(buf, rp)?;
                } else {
                    buf.extend_from_slice(&[0u8; 32]);
                }
            }

            // source_asset_type
            write_string(buf, get_str(prefix, "source_asset_type"));
            // destination_asset_type
            write_string(buf, get_str(prefix, "destination_asset_type"));
            // amount_slippage_limit
            write_varint(buf, get_u64(prefix, "amount_slippage_limit"));
        }
    }

    Ok(())
}

// ─── Extra Serialization (from parsed JSON array) ────────────────────────────

fn serialize_extra_from_parsed(extra: &Value) -> Result<Vec<u8>, String> {
    let entries = match extra.as_array() {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };

    if entries.is_empty() {
        return Ok(Vec::new());
    }

    // If the first entry is a number, this is a raw byte array (from builder).
    // Just collect the bytes directly.
    if entries[0].is_number() {
        return Ok(entries
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u8))
            .collect());
    }

    // Structured extra entries (from parse_extra).
    let mut buf = Vec::new();
    for entry in entries {
        let tag = get_u8(entry, "type");
        match tag {
            0x00 => {
                buf.push(0x00);
            }
            0x01 => {
                buf.push(0x01);
                let key = get_str(entry, "key");
                if !key.is_empty() {
                    write_hex_bytes(&mut buf, key)?;
                }
            }
            0x02 => {
                // Nonce: reconstruct from paymentId or raw
                let pid_type = get_str(entry, "paymentIdType");
                if pid_type == "encrypted" {
                    buf.push(0x02);
                    buf.push(9); // nonce length
                    buf.push(0x01); // encrypted PID tag
                    write_hex_bytes(&mut buf, get_str(entry, "paymentId"))?;
                } else if pid_type == "unencrypted" {
                    buf.push(0x02);
                    buf.push(33); // nonce length
                    buf.push(0x00); // unencrypted PID tag
                    write_hex_bytes(&mut buf, get_str(entry, "paymentId"))?;
                } else {
                    let raw = get_str(entry, "raw");
                    if !raw.is_empty() {
                        buf.push(0x02);
                        let raw_bytes = hex_to_bytes(raw)?;
                        buf.push(raw_bytes.len() as u8);
                        buf.extend_from_slice(&raw_bytes);
                    }
                }
            }
            0x04 => {
                buf.push(0x04);
                let keys = get_array(entry, "keys");
                buf.push(keys.len() as u8);
                for k in keys {
                    write_hex_bytes(&mut buf, k.as_str().unwrap_or(""))?;
                }
            }
            _ => {
                // Unknown tags: tag + varint size + data
                buf.push(tag);
                let data = get_str(entry, "data");
                if !data.is_empty() {
                    let data_bytes = hex_to_bytes(data)?;
                    write_varint(&mut buf, data_bytes.len() as u64);
                    buf.extend_from_slice(&data_bytes);
                }
            }
        }
    }

    Ok(buf)
}

// ─── ZK Proof Serialization ─────────────────────────────────────────────────

fn serialize_zk_proof(proof: &Value, buf: &mut Vec<u8>) -> Result<(), String> {
    let r = get_str(proof, "R");
    let z1 = get_str(proof, "z1");
    let z2 = get_str(proof, "z2");
    if r.is_empty() {
        buf.extend_from_slice(&[0u8; 96]);
    } else {
        write_hex_bytes(buf, r)?;
        write_hex_bytes(buf, z1)?;
        write_hex_bytes(buf, z2)?;
    }
    Ok(())
}

// ─── salvium_data_t Serialization ────────────────────────────────────────────

fn serialize_salvium_data(sd: &Value, buf: &mut Vec<u8>) -> Result<(), String> {
    let data_type = get_u64(sd, "salvium_data_type");
    write_varint(buf, data_type);

    serialize_zk_proof(sd.get("pr_proof").unwrap_or(&Value::Null), buf)?;
    serialize_zk_proof(sd.get("sa_proof").unwrap_or(&Value::Null), buf)?;

    // SalviumZeroAudit (type 1)
    if data_type == 1 {
        serialize_zk_proof(sd.get("cz_proof").unwrap_or(&Value::Null), buf)?;

        // input_verification_data
        let ivd = get_array(sd, "input_verification_data");
        write_varint(buf, ivd.len() as u64);
        for item in ivd {
            write_hex_bytes(buf, get_str(item, "aR"))?;
            write_varint(buf, get_u64(item, "amount"));
            write_varint(buf, get_u64(item, "i"));
            let origin = get_u8(item, "origin_tx_type");
            write_varint(buf, origin as u64);
            if origin != 0 {
                write_hex_bytes(buf, get_str(item, "aR_stake"))?;
                write_u64_le(buf, get_u64(item, "i_stake"));
            }
        }

        // spend_pubkey
        let spk = get_str(sd, "spend_pubkey");
        if !spk.is_empty() {
            write_hex_bytes(buf, spk)?;
        } else {
            buf.extend_from_slice(&[0u8; 32]);
        }

        // enc_view_privkey_str
        write_string(buf, get_str(sd, "enc_view_privkey_str"));
    }

    Ok(())
}

// ─── RCT Prunable Serialization ─────────────────────────────────────────────

fn serialize_rct_prunable(rct: &Value, rct_type: u8, buf: &mut Vec<u8>) -> Result<(), String> {
    // BulletproofPlus
    if rct_type >= RCT_TYPE_BULLETPROOF_PLUS {
        let proofs = get_array(rct, "bulletproofPlus");
        write_varint(buf, proofs.len() as u64);
        for proof in proofs {
            write_hex_bytes(buf, get_str(proof, "A"))?;
            write_hex_bytes(buf, get_str(proof, "A1"))?;
            write_hex_bytes(buf, get_str(proof, "B"))?;
            write_hex_bytes(buf, get_str(proof, "r1"))?;
            write_hex_bytes(buf, get_str(proof, "s1"))?;
            write_hex_bytes(buf, get_str(proof, "d1"))?;

            // L array
            let l_arr = get_array(proof, "L");
            write_varint(buf, l_arr.len() as u64);
            for l in l_arr {
                write_hex_bytes(buf, l.as_str().unwrap_or(""))?;
            }

            // R array
            let r_arr = get_array(proof, "R");
            write_varint(buf, r_arr.len() as u64);
            for r in r_arr {
                write_hex_bytes(buf, r.as_str().unwrap_or(""))?;
            }
        }
    }

    // Ring signatures
    if rct_type == RCT_TYPE_SALVIUM_ONE {
        // TCLSAGs
        for sig in get_array(rct, "TCLSAGs") {
            for s in get_array(sig, "sx") {
                write_hex_bytes(buf, s.as_str().unwrap_or(""))?;
            }
            for s in get_array(sig, "sy") {
                write_hex_bytes(buf, s.as_str().unwrap_or(""))?;
            }
            write_hex_bytes(buf, get_str(sig, "c1"))?;
            write_hex_bytes(buf, get_str(sig, "D"))?;
        }
    } else if rct_type >= RCT_TYPE_CLSAG {
        // CLSAGs
        for sig in get_array(rct, "CLSAGs") {
            for s in get_array(sig, "s") {
                write_hex_bytes(buf, s.as_str().unwrap_or(""))?;
            }
            write_hex_bytes(buf, get_str(sig, "c1"))?;
            write_hex_bytes(buf, get_str(sig, "D"))?;
        }
    }

    // pseudoOuts
    if rct_type >= RCT_TYPE_BULLETPROOF_PLUS {
        for po in get_array(rct, "pseudoOuts") {
            write_hex_bytes(buf, po.as_str().unwrap_or(""))?;
        }
    }

    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_parse;

    #[test]
    fn test_roundtrip_coinbase() {
        // Build a minimal coinbase TX
        let original = crate::tx_parse::tests_helper::build_minimal_coinbase_tx();

        // Parse → JSON
        let json = tx_parse::parse_transaction(&original).unwrap();

        // Serialize JSON → binary
        let reserialized = serialize_transaction(&json).unwrap();

        assert_eq!(
            hex::encode(&original),
            hex::encode(&reserialized),
            "Coinbase TX roundtrip failed"
        );
    }

    #[test]
    fn test_roundtrip_transfer() {
        let original = crate::tx_parse::tests_helper::build_minimal_transfer_tx();

        let json = tx_parse::parse_transaction(&original).unwrap();
        let reserialized = serialize_transaction(&json).unwrap();

        assert_eq!(
            hex::encode(&original),
            hex::encode(&reserialized),
            "Transfer TX roundtrip failed"
        );
    }

    /// Roundtrip a real testnet miner TX (v4 CARROT, txout_to_carrot_v1).
    #[test]
    fn test_roundtrip_real_miner_tx() {
        let hex_str = "043c01ffa50a01c4ac84892e04432aa8ffd2cd1d0edb8bbe5c191bf75b3435911f9794edbf15dccaacfb79d96f0453414c318b02fb52bcbcaf26be71a922be126c1e69ab072b013c54483190fbb1bc81c39b4c67e9f2166da31dd0f41049747d86e943bc064d450208000000000000000001908ba1c20b00";
        let original = hex::decode(hex_str).unwrap();

        let json = tx_parse::parse_transaction(&original)
            .expect("Failed to parse real miner TX");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["prefix"]["version"], 4);
        assert_eq!(parsed["prefix"]["txType"], 1); // MINER
        assert_eq!(parsed["prefix"]["vout"][0]["type"], TXOUT_CARROT_V1 as u64);

        let reserialized = serialize_transaction(&json)
            .expect("Failed to re-serialize real miner TX");

        assert_eq!(
            hex_str,
            hex::encode(&reserialized),
            "Real miner TX roundtrip failed"
        );
    }
}
