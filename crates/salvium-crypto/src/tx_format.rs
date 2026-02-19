//! Transaction extra field parsing and serialization.
//!
//! Implements the CryptoNote/Salvium tx_extra format:
//! - Tag 0x00: Padding
//! - Tag 0x01: Shared transaction pubkey (32 bytes)
//! - Tag 0x02: Nonce (1-byte size + data; contains payment ID)
//! - Tag 0x03: Merge mining (varint size + data)
//! - Tag 0x04: Additional per-output pubkeys (1-byte count + 32*N bytes)
//! - Tag 0xDE: Minergate (varint size + data)
//! - Unknown: varint size + data fallback
//!
//! The critical tag 0x01 vs 0x04 selection logic matches C++
//! `store_carrot_ephemeral_pubkeys_to_extra()` from format_utils.cpp:61.

/// Decode a varint (LEB128) from bytes at offset.
/// Returns (value, bytes_read). Max 10 bytes / 70 bits.
pub(crate) fn decode_varint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    loop {
        if offset + i >= data.len() {
            return None;
        }
        let byte = data[offset + i];
        i += 1;
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 70 {
            return None; // overflow
        }
    }
    Some((value, i))
}

/// Encode a u64 value as varint (LEB128).
pub(crate) fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
    buf
}

/// Parse tx_extra field from binary into JSON string.
///
/// Returns a JSON array of objects, each with:
/// - `type`: numeric tag
/// - `tag`: string name
/// - Additional fields depending on tag type
///
/// Keys/data are hex-encoded strings in the JSON output.
pub fn parse_extra(extra_bytes: &[u8]) -> String {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset < extra_bytes.len() {
        let tag = extra_bytes[offset];
        offset += 1;

        match tag {
            0x00 => {
                // Padding: skip consecutive 0x00 bytes
                while offset < extra_bytes.len() && extra_bytes[offset] == 0x00 {
                    offset += 1;
                }
                entries.push(serde_json::json!({
                    "type": 0x00,
                    "tag": "padding"
                }));
            }
            0x01 => {
                // TX_EXTRA_TAG_PUBKEY: 32-byte key
                if offset + 32 > extra_bytes.len() {
                    entries.push(serde_json::json!({
                        "type": 0x01,
                        "tag": "tx_pubkey",
                        "error": "truncated"
                    }));
                    break;
                }
                let key = hex::encode(&extra_bytes[offset..offset + 32]);
                offset += 32;
                entries.push(serde_json::json!({
                    "type": 0x01,
                    "tag": "tx_pubkey",
                    "key": key
                }));
            }
            0x02 => {
                // TX_EXTRA_NONCE: 1-byte size + data
                if offset >= extra_bytes.len() {
                    break;
                }
                let nonce_size = extra_bytes[offset] as usize;
                offset += 1;
                if offset + nonce_size > extra_bytes.len() {
                    entries.push(serde_json::json!({
                        "type": 0x02,
                        "tag": "nonce",
                        "error": "truncated"
                    }));
                    break;
                }
                let nonce = &extra_bytes[offset..offset + nonce_size];
                offset += nonce_size;

                // Parse nonce content
                let nonce_entry = parse_extra_nonce(nonce);
                entries.push(nonce_entry);
            }
            0x03 => {
                // TX_EXTRA_MERGE_MINING_TAG: varint size + data
                match decode_varint(extra_bytes, offset) {
                    Some((size, bytes_read)) => {
                        offset += bytes_read;
                        let size = size as usize;
                        if offset + size > extra_bytes.len() {
                            break;
                        }
                        let data = hex::encode(&extra_bytes[offset..offset + size]);
                        offset += size;
                        entries.push(serde_json::json!({
                            "type": 0x03,
                            "tag": "merge_mining",
                            "data": data
                        }));
                    }
                    None => break,
                }
            }
            0x04 => {
                // TX_EXTRA_TAG_ADDITIONAL_PUBKEYS: 1-byte count + 32*N bytes
                if offset >= extra_bytes.len() {
                    break;
                }
                let count = extra_bytes[offset] as usize;
                offset += 1;
                let mut keys = Vec::with_capacity(count);
                for _ in 0..count {
                    if offset + 32 > extra_bytes.len() {
                        break;
                    }
                    keys.push(hex::encode(&extra_bytes[offset..offset + 32]));
                    offset += 32;
                }
                entries.push(serde_json::json!({
                    "type": 0x04,
                    "tag": "additional_pubkeys",
                    "keys": keys
                }));
            }
            0xDE => {
                // TX_EXTRA_MYSTERIOUS_MINERGATE_TAG: varint size + data
                match decode_varint(extra_bytes, offset) {
                    Some((size, bytes_read)) => {
                        let size = size as usize;
                        if offset + bytes_read + size <= extra_bytes.len() {
                            let data = hex::encode(
                                &extra_bytes[offset + bytes_read..offset + bytes_read + size],
                            );
                            offset += bytes_read + size;
                            entries.push(serde_json::json!({
                                "type": 0xDE,
                                "tag": "minergate",
                                "data": data
                            }));
                        } else {
                            offset = extra_bytes.len();
                        }
                    }
                    None => {
                        offset = extra_bytes.len();
                    }
                }
            }
            _ => {
                // Unknown tag — try varint-length skip
                let mut skipped = false;
                if offset < extra_bytes.len() {
                    if let Some((size, bytes_read)) = decode_varint(extra_bytes, offset) {
                        let size = size as usize;
                        if offset + bytes_read + size <= extra_bytes.len() {
                            let data = hex::encode(
                                &extra_bytes[offset + bytes_read..offset + bytes_read + size],
                            );
                            offset += bytes_read + size;
                            entries.push(serde_json::json!({
                                "type": tag,
                                "tag": "unknown",
                                "data": data
                            }));
                            skipped = true;
                        }
                    }
                }
                if !skipped {
                    entries.push(serde_json::json!({
                        "type": tag,
                        "tag": "unknown",
                        "offset": offset - 1
                    }));
                    offset = extra_bytes.len();
                }
            }
        }
    }

    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

/// Parse nonce content (inner of tag 0x02).
fn parse_extra_nonce(nonce: &[u8]) -> serde_json::Value {
    if nonce.is_empty() {
        return serde_json::json!({
            "type": 0x02,
            "tag": "nonce",
            "raw": hex::encode(nonce)
        });
    }

    match nonce[0] {
        0x00 if nonce.len() == 33 => {
            // Unencrypted payment ID (32 bytes)
            serde_json::json!({
                "type": 0x02,
                "tag": "nonce",
                "paymentIdType": "unencrypted",
                "paymentId": hex::encode(&nonce[1..])
            })
        }
        0x01 if nonce.len() == 9 => {
            // Encrypted payment ID (8 bytes)
            serde_json::json!({
                "type": 0x02,
                "tag": "nonce",
                "paymentIdType": "encrypted",
                "paymentId": hex::encode(&nonce[1..])
            })
        }
        _ => {
            serde_json::json!({
                "type": 0x02,
                "tag": "nonce",
                "raw": hex::encode(nonce)
            })
        }
    }
}

/// Serialize tx_extra from JSON string to binary.
///
/// Input JSON object:
/// - `txPubKey`: hex string (optional, 32-byte shared pubkey)
/// - `additionalPubKeys`: array of hex strings (optional, per-output pubkeys)
/// - `paymentId`: hex string (optional, 8-byte encrypted payment ID)
///
/// Tag selection logic matches C++ store_carrot_ephemeral_pubkeys_to_extra():
/// - 1 output or no additional keys: use tag 0x01 (shared)
/// - 2 outputs with identical D_e: use tag 0x01 (shared)
/// - 2+ outputs with different D_e or 3+ outputs: use tag 0x04 only (no 0x01)
pub fn serialize_tx_extra(json_str: &str) -> Result<Vec<u8>, String> {
    let json: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {e}"))?;

    let mut result = Vec::new();

    // Get additional pubkeys
    let additional_keys: Vec<Vec<u8>> = json
        .get("additionalPubKeys")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().and_then(|s| hex::decode(s).ok()))
                .collect()
        })
        .unwrap_or_default();

    // Determine tag 0x01 vs 0x04
    let mut use_shared = true;
    if additional_keys.len() >= 3 {
        use_shared = false;
    } else if additional_keys.len() == 2 {
        use_shared = additional_keys[0] == additional_keys[1];
    }

    if use_shared {
        // Tag 0x01: shared ephemeral pubkey
        let pubkey = json
            .get("txPubKey")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
            .or_else(|| additional_keys.first().cloned());

        if let Some(pk) = pubkey {
            if pk.len() == 32 {
                result.push(0x01);
                result.extend_from_slice(&pk);
            }
        }
    } else {
        // Tag 0x04: per-output ephemeral pubkeys (no tag 0x01)
        result.push(0x04);
        result.extend_from_slice(&encode_varint(additional_keys.len() as u64));
        for pk in &additional_keys {
            result.extend_from_slice(pk);
        }
    }

    // Tag 0x02: encrypted payment ID
    if let Some(pid_hex) = json.get("paymentId").and_then(|v| v.as_str()) {
        if let Ok(pid) = hex::decode(pid_hex) {
            if pid.len() == 8 {
                result.push(0x02); // nonce tag
                result.push(9); // nonce length: 1 (type) + 8 (pid)
                result.push(0x01); // encrypted payment ID type
                result.extend_from_slice(&pid);
            }
        }
    }

    Ok(result)
}

/// Compute keccak256 hash of raw transaction prefix bytes.
pub fn compute_tx_prefix_hash(data: &[u8]) -> [u8; 32] {
    crate::keccak256_internal(data)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for val in [0u64, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let encoded = encode_varint(val);
            let (decoded, bytes_read) = decode_varint(&encoded, 0).unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {val}");
            assert_eq!(bytes_read, encoded.len());
        }
    }

    #[test]
    fn test_parse_extra_tag_01() {
        // Tag 0x01 + 32-byte key
        let mut extra = vec![0x01];
        extra.extend_from_slice(&[0x42; 32]);
        let json = parse_extra(&extra);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["type"], 0x01);
        assert_eq!(parsed[0]["tag"], "tx_pubkey");
        assert_eq!(parsed[0]["key"], hex::encode([0x42; 32]));
    }

    #[test]
    fn test_parse_extra_tag_04() {
        // Tag 0x04 + 2 pubkeys
        let mut extra = vec![0x04, 2];
        extra.extend_from_slice(&[0xAA; 32]);
        extra.extend_from_slice(&[0xBB; 32]);
        let json = parse_extra(&extra);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["type"], 0x04);
        assert_eq!(parsed[0]["tag"], "additional_pubkeys");
        let keys = parsed[0]["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], hex::encode([0xAA; 32]));
        assert_eq!(keys[1], hex::encode([0xBB; 32]));
    }

    #[test]
    fn test_parse_extra_encrypted_payment_id() {
        // Tag 0x02 + nonce size 9 + encrypted PID (0x01 + 8 bytes)
        let mut extra = vec![0x02, 9, 0x01];
        extra.extend_from_slice(&[0x12; 8]);
        let json = parse_extra(&extra);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["type"], 0x02);
        assert_eq!(parsed[0]["paymentIdType"], "encrypted");
        assert_eq!(parsed[0]["paymentId"], hex::encode([0x12; 8]));
    }

    #[test]
    fn test_parse_extra_combined() {
        // Tag 0x01 + key, then tag 0x02 + encrypted PID
        let mut extra = vec![0x01];
        extra.extend_from_slice(&[0x58; 32]);
        extra.push(0x02);
        extra.push(9);
        extra.push(0x01);
        extra.extend_from_slice(&[0xFF; 8]);
        let json = parse_extra(&extra);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 2);
        assert_eq!(parsed[0]["type"], 0x01);
        assert_eq!(parsed[1]["type"], 0x02);
    }

    #[test]
    fn test_serialize_tx_extra_shared_pubkey() {
        let json = r#"{"txPubKey":"4242424242424242424242424242424242424242424242424242424242424242"}"#;
        let result = serialize_tx_extra(json).unwrap();
        assert_eq!(result[0], 0x01);
        assert_eq!(&result[1..33], &[0x42; 32]);
        assert_eq!(result.len(), 33);
    }

    #[test]
    fn test_serialize_tx_extra_per_output_keys() {
        let json = r#"{"additionalPubKeys":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]}"#;
        let result = serialize_tx_extra(json).unwrap();
        assert_eq!(result[0], 0x04); // tag
        assert_eq!(result[1], 3); // count varint
        assert_eq!(result.len(), 2 + 3 * 32);
    }

    #[test]
    fn test_serialize_tx_extra_two_identical_keys_uses_shared() {
        let key_hex = "4242424242424242424242424242424242424242424242424242424242424242";
        let json = format!(r#"{{"additionalPubKeys":["{key_hex}","{key_hex}"]}}"#);
        let result = serialize_tx_extra(&json).unwrap();
        // 2 identical keys → use shared (tag 0x01)
        assert_eq!(result[0], 0x01);
        assert_eq!(result.len(), 33);
    }

    #[test]
    fn test_serialize_tx_extra_two_different_keys_uses_per_output() {
        let json = r#"{"additionalPubKeys":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}"#;
        let result = serialize_tx_extra(json).unwrap();
        // 2 different keys → use per-output (tag 0x04)
        assert_eq!(result[0], 0x04);
        assert_eq!(result[1], 2); // count
        assert_eq!(result.len(), 2 + 2 * 32);
    }

    #[test]
    fn test_serialize_tx_extra_with_payment_id() {
        let json = r#"{"txPubKey":"4242424242424242424242424242424242424242424242424242424242424242","paymentId":"1234567890abcdef"}"#;
        let result = serialize_tx_extra(json).unwrap();
        // tag 0x01 + 32 bytes + tag 0x02 + size 9 + 0x01 + 8 bytes = 33 + 11 = 44
        assert_eq!(result.len(), 44);
        assert_eq!(result[0], 0x01);
        assert_eq!(result[33], 0x02);
        assert_eq!(result[34], 9);
        assert_eq!(result[35], 0x01);
    }

    #[test]
    fn test_parse_serialize_roundtrip() {
        // Create an extra field, serialize it, parse it back
        let json = r#"{"txPubKey":"4242424242424242424242424242424242424242424242424242424242424242","paymentId":"1234567890abcdef"}"#;
        let serialized = serialize_tx_extra(json).unwrap();
        let parsed_json = parse_extra(&serialized);
        let parsed: serde_json::Value = serde_json::from_str(&parsed_json).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["type"], 0x01);
        assert_eq!(
            arr[0]["key"],
            "4242424242424242424242424242424242424242424242424242424242424242"
        );
        assert_eq!(arr[1]["type"], 0x02);
        assert_eq!(arr[1]["paymentIdType"], "encrypted");
        assert_eq!(arr[1]["paymentId"], "1234567890abcdef");
    }

    #[test]
    fn test_compute_tx_prefix_hash() {
        let data = b"test transaction prefix data";
        let hash = compute_tx_prefix_hash(data);
        let expected = crate::keccak256_internal(data);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_parse_extra_unknown_tag_varint_skip() {
        // Unknown tag 0xAB with varint size 3 + 3 data bytes
        let extra = vec![0xAB, 3, 0x01, 0x02, 0x03];
        let json = parse_extra(&extra);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["type"], 0xAB);
        assert_eq!(parsed[0]["tag"], "unknown");
        assert_eq!(parsed[0]["data"], hex::encode([0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_parse_extra_padding() {
        let extra = vec![0x00, 0x00, 0x00, 0x01];
        // Should parse padding then fail on truncated tag 0x01
        let json = parse_extra(&extra);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(!parsed.as_array().unwrap().is_empty());
        assert_eq!(parsed[0]["type"], 0x00);
        assert_eq!(parsed[0]["tag"], "padding");
    }
}
