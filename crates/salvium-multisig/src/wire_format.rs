//! C++-compatible binary wire format for multisig messages.
//!
//! KEX messages are encoded as: `magic_bytes + base58(epee_binary_blob)`
//! TX sets are encoded as raw Epee portable storage binary (no magic/base58).
//!
//! This matches the C++ `multisig_kex_msg` wire format.

use std::collections::HashMap;

use salvium_rpc::portable_storage::{self, PsValue};
use salvium_types::base58;

use crate::kex::KexMessage;
use crate::schnorr::SchnorrSignature;
use crate::signed_message::{SignedKexMessage, MAGIC_ROUND1, MAGIC_ROUND_N};
use crate::signing::{MultisigClsagContext, PartialClsag, SignerNonces};
use crate::tx_set::{MultisigTxSet, PendingMultisigTx};

// ─── KEX Message Encoding/Decoding ──────────────────────────────────────────

/// Encode a `SignedKexMessage` to the C++ wire format: `magic + base58(epee_blob)`.
pub fn encode_kex_message(msg: &SignedKexMessage) -> String {
    let mut map = HashMap::new();

    // Signing pubkey and signature are always present
    map.insert(
        "signing_pubkey".to_string(),
        PsValue::String(msg.signing_pubkey.to_vec()),
    );
    map.insert(
        "signature".to_string(),
        PsValue::String(msg.signature.to_bytes().to_vec()),
    );

    if msg.inner.round == 1 {
        // Round 1: include msg_privkey (the view key contribution)
        map.insert(
            "msg_privkey".to_string(),
            PsValue::String(msg.msg_privkey.to_vec()),
        );
    } else {
        // Round N: include kex_round and msg_pubkeys
        map.insert(
            "kex_round".to_string(),
            PsValue::Uint32(msg.inner.round as u32),
        );

        let pubkeys: Vec<PsValue> = msg
            .inner
            .keys
            .iter()
            .filter_map(|hex_str| hex::decode(hex_str).ok())
            .map(PsValue::String)
            .collect();
        map.insert("msg_pubkeys".to_string(), PsValue::Array(pubkeys));
    }

    // Serialize to Epee binary, then base58 encode
    let blob = portable_storage::serialize(&map);
    let encoded = base58::encode(&blob);

    // Prepend magic bytes
    let magic = if msg.inner.round == 1 {
        MAGIC_ROUND1
    } else {
        MAGIC_ROUND_N
    };
    let magic_str = std::str::from_utf8(magic).unwrap();
    format!("{}{}", magic_str, encoded)
}

/// Decode a C++ wire format string back to a `SignedKexMessage`.
///
/// Format: `magic + base58(epee_blob)`.
/// The signature is verified as part of decoding — tampered messages are rejected.
///
/// Rejects deprecated V1 messages (C++ `multisig_kex_msg.cpp:216-219`).
pub fn decode_kex_message(wire: &str) -> Result<SignedKexMessage, String> {
    // Reject deprecated V1 messages (C++ multisig_kex_msg.cpp:216-219)
    const MAGIC_V1: &str = "MultisigV1";
    const MAGIC_V1X: &str = "MultisigxV1";
    if wire.starts_with(MAGIC_V1) || wire.starts_with(MAGIC_V1X) {
        return Err("V1 multisig messages are deprecated and not supported".to_string());
    }

    let magic_r1 = std::str::from_utf8(MAGIC_ROUND1).unwrap();
    let magic_rn = std::str::from_utf8(MAGIC_ROUND_N).unwrap();

    let (is_round1, remainder) = if let Some(r) = wire.strip_prefix(magic_r1) {
        (true, r)
    } else if let Some(r) = wire.strip_prefix(magic_rn) {
        (false, r)
    } else {
        return Err("unrecognized magic prefix".to_string());
    };

    // Base58 decode
    let blob = base58::decode(remainder).map_err(|e| format!("base58 decode failed: {}", e))?;

    // Epee deserialize
    let ps = portable_storage::deserialize(&blob)
        .map_err(|e| format!("portable storage deserialize failed: {}", e))?;
    let obj = ps
        .as_object()
        .ok_or_else(|| "expected object at top level".to_string())?;

    // Extract signing_pubkey (32 bytes)
    let signing_pubkey_bytes = obj
        .get("signing_pubkey")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| "missing signing_pubkey".to_string())?;
    if signing_pubkey_bytes.len() != 32 {
        return Err(format!(
            "signing_pubkey: expected 32 bytes, got {}",
            signing_pubkey_bytes.len()
        ));
    }
    let mut signing_pubkey = [0u8; 32];
    signing_pubkey.copy_from_slice(signing_pubkey_bytes);

    // Extract signature (64 bytes)
    let sig_bytes = obj
        .get("signature")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| "missing signature".to_string())?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature: expected 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let signature = SchnorrSignature::from_bytes(&sig_arr);

    let (inner, msg_privkey) = if is_round1 {
        // Round 1: extract msg_privkey
        let privkey_bytes = obj
            .get("msg_privkey")
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| "missing msg_privkey for round 1".to_string())?;
        if privkey_bytes.len() != 32 {
            return Err(format!(
                "msg_privkey: expected 32 bytes, got {}",
                privkey_bytes.len()
            ));
        }
        let mut msg_privkey = [0u8; 32];
        msg_privkey.copy_from_slice(privkey_bytes);

        let kex_msg = KexMessage {
            round: 1,
            signer_index: 0,
            keys: Vec::new(), // Round 1 keys are derived from msg_privkey
            msg_type: crate::constants::MultisigMsgType::KexInit,
        };
        (kex_msg, msg_privkey)
    } else {
        // Round N: extract kex_round and msg_pubkeys
        let round = obj
            .get("kex_round")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "missing kex_round".to_string())? as usize;

        // C++ multisig_kex_msg.cpp:260 — round-N messages must have round > 1
        if round <= 1 {
            return Err("Round-N message must have round > 1".to_string());
        }

        let pubkeys = obj
            .get("msg_pubkeys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "missing msg_pubkeys".to_string())?;

        let keys: Vec<String> = pubkeys
            .iter()
            .filter_map(|v| v.as_bytes().map(hex::encode))
            .collect();

        let kex_msg = KexMessage {
            round,
            signer_index: 0,
            keys,
            msg_type: crate::constants::MultisigMsgType::KexRound,
        };
        let msg_privkey = [0u8; 32]; // Not transmitted in round N
        (kex_msg, msg_privkey)
    };

    // ── Field validation (matches C++ multisig_kex_msg constructor) ──

    // Null signing pubkey check
    if signing_pubkey == [0u8; 32] {
        return Err("signing_pubkey must not be the identity element".to_string());
    }

    // Signature scalar validation: sc_check on both c and s
    if !salvium_crypto::sc_check(&signature.c) {
        return Err("signature.c is not a canonical scalar".to_string());
    }
    if !salvium_crypto::sc_check(&signature.s) {
        return Err("signature.s is not a canonical scalar".to_string());
    }

    // Pubkey must be in the prime-order subgroup
    if !salvium_crypto::is_in_main_subgroup(&signing_pubkey) {
        return Err("signing_pubkey is not in the prime-order subgroup".to_string());
    }

    // Round-N: validate each pubkey in inner.keys
    if !is_round1 {
        for (i, key_hex) in inner.keys.iter().enumerate() {
            let key_bytes =
                hex::decode(key_hex).map_err(|e| format!("key[{}] hex decode failed: {}", i, e))?;
            if key_bytes == [0u8; 32] {
                return Err(format!("key[{}] must not be the identity element", i));
            }
            if !salvium_crypto::is_in_main_subgroup(&key_bytes) {
                return Err(format!("key[{}] is not in the prime-order subgroup", i));
            }
        }
    }

    let signed = SignedKexMessage {
        inner,
        msg_privkey,
        signing_pubkey,
        signature,
    };

    // Verify the Schnorr signature (redundant safety net after field validation)
    signed.verify()?;

    Ok(signed)
}

// ─── TX Set Encoding/Decoding ───────────────────────────────────────────────

/// Encode a `MultisigTxSet` to Epee portable storage binary.
pub fn encode_tx_set(set: &MultisigTxSet) -> Vec<u8> {
    let mut map = HashMap::new();

    map.insert(
        "threshold".to_string(),
        PsValue::Uint32(set.threshold as u32),
    );
    map.insert(
        "signer_count".to_string(),
        PsValue::Uint32(set.signer_count as u32),
    );

    // Signers contributed as array of hex strings
    let signers: Vec<PsValue> = set
        .signers_contributed
        .iter()
        .map(|s| PsValue::String(s.as_bytes().to_vec()))
        .collect();
    map.insert("signers_contributed".to_string(), PsValue::Array(signers));

    // Pending TXs
    let pending: Vec<PsValue> = set.pending_txs.iter().map(encode_pending_tx).collect();
    map.insert("pending_txs".to_string(), PsValue::Array(pending));

    portable_storage::serialize(&map)
}

/// Decode a `MultisigTxSet` from Epee portable storage binary.
pub fn decode_tx_set(data: &[u8]) -> Result<MultisigTxSet, String> {
    let ps =
        portable_storage::deserialize(data).map_err(|e| format!("deserialize failed: {}", e))?;
    let obj = ps
        .as_object()
        .ok_or_else(|| "expected object".to_string())?;

    let threshold = obj.get("threshold").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let signer_count = obj
        .get("signer_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let signers_contributed = obj
        .get("signers_contributed")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let pending_txs = obj
        .get("pending_txs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| decode_pending_tx(v).ok())
                .collect()
        })
        .unwrap_or_default();

    Ok(MultisigTxSet {
        transactions: Vec::new(),
        key_images: Vec::new(),
        pending_txs,
        signers_contributed,
        threshold,
        signer_count,
    })
}

// ─── Helpers: PendingMultisigTx encoding ────────────────────────────────────

fn encode_pending_tx(tx: &PendingMultisigTx) -> PsValue {
    let mut map = HashMap::new();

    map.insert(
        "tx_blob".to_string(),
        PsValue::String(tx.tx_blob.as_bytes().to_vec()),
    );
    map.insert(
        "tx_prefix_hash".to_string(),
        PsValue::String(tx.tx_prefix_hash.as_bytes().to_vec()),
    );
    map.insert("fee".to_string(), PsValue::Uint64(tx.fee));
    map.insert(
        "signing_message".to_string(),
        PsValue::String(tx.signing_message.as_bytes().to_vec()),
    );

    let ki: Vec<PsValue> = tx
        .key_images
        .iter()
        .map(|s| PsValue::String(s.as_bytes().to_vec()))
        .collect();
    map.insert("key_images".to_string(), PsValue::Array(ki));

    // Complex nested structures are JSON-serialized as string blobs
    // to avoid issues with portable_storage's limited nesting support.
    let contexts_json =
        serde_json::to_vec(&tx.signing_contexts).expect("signing_contexts serialization");
    map.insert(
        "signing_contexts".to_string(),
        PsValue::String(contexts_json),
    );

    let nonces_json = serde_json::to_vec(&tx.input_nonces).expect("input_nonces serialization");
    map.insert("input_nonces".to_string(), PsValue::String(nonces_json));

    let partials_json =
        serde_json::to_vec(&tx.input_partials).expect("input_partials serialization");
    map.insert("input_partials".to_string(), PsValue::String(partials_json));

    PsValue::Object(map)
}

fn decode_pending_tx(val: &PsValue) -> Result<PendingMultisigTx, String> {
    let obj = val
        .as_object()
        .ok_or_else(|| "expected object for pending_tx".to_string())?;

    let tx_blob = obj
        .get("tx_blob")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let tx_prefix_hash = obj
        .get("tx_prefix_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let fee = obj.get("fee").and_then(|v| v.as_u64()).unwrap_or(0);
    let signing_message = obj
        .get("signing_message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let key_images = obj
        .get("key_images")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Complex nested structures are JSON-deserialized from string blobs
    let signing_contexts: Vec<MultisigClsagContext> = obj
        .get("signing_contexts")
        .and_then(|v| v.as_bytes())
        .and_then(|b| serde_json::from_slice(b).ok())
        .unwrap_or_default();

    let input_nonces: Vec<Vec<SignerNonces>> = obj
        .get("input_nonces")
        .and_then(|v| v.as_bytes())
        .and_then(|b| serde_json::from_slice(b).ok())
        .unwrap_or_default();

    let input_partials: Vec<Vec<PartialClsag>> = obj
        .get("input_partials")
        .and_then(|v| v.as_bytes())
        .and_then(|b| serde_json::from_slice(b).ok())
        .unwrap_or_default();

    Ok(PendingMultisigTx {
        tx_blob,
        key_images,
        tx_prefix_hash,
        input_nonces,
        input_partials,
        fee,
        destinations: Vec::new(),
        signing_contexts,
        signing_message,
        input_key_offsets: Vec::new(),
        input_z_values: Vec::new(),
        input_y_keys: Vec::new(),
        proposer_signed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MultisigMsgType;
    use crate::signed_message::SignedKexMessage;

    fn make_signing_key() -> [u8; 32] {
        let hash = salvium_crypto::keccak256(b"wire_format_test_key");
        let reduced = salvium_crypto::sc_reduce32(&hash);
        let mut key = [0u8; 32];
        key.copy_from_slice(&reduced);
        key
    }

    #[test]
    fn kex_round1_roundtrip() {
        let privkey = make_signing_key();
        let pk = salvium_crypto::scalar_mult_base(&[1u8; 32]);
        let msg = KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec![hex::encode(&pk), hex::encode(&pk)],
            msg_type: MultisigMsgType::KexInit,
        };
        let signed = SignedKexMessage::create(msg, &privkey).unwrap();
        let wire = encode_kex_message(&signed);

        assert!(wire.starts_with("MultisigxV2R1"));

        let decoded = decode_kex_message(&wire).unwrap();
        assert_eq!(decoded.inner.round, 1);
        assert_eq!(decoded.signing_pubkey, signed.signing_pubkey);
        assert_eq!(decoded.signature, signed.signature);
    }

    #[test]
    fn kex_round_n_roundtrip() {
        let privkey = make_signing_key();
        let pk1 = salvium_crypto::scalar_mult_base(&[2u8; 32]);
        let pk2 = salvium_crypto::scalar_mult_base(&[3u8; 32]);
        let msg = KexMessage {
            round: 3,
            signer_index: 1,
            keys: vec![hex::encode(&pk1), hex::encode(&pk2)],
            msg_type: MultisigMsgType::KexRound,
        };
        let signed = SignedKexMessage::create(msg, &privkey).unwrap();
        let wire = encode_kex_message(&signed);

        assert!(wire.starts_with("MultisigxV2Rn"));

        let decoded = decode_kex_message(&wire).unwrap();
        assert_eq!(decoded.inner.round, 3);
        assert_eq!(decoded.inner.keys.len(), 2);
        assert_eq!(decoded.inner.keys[0], hex::encode(&pk1));
        assert_eq!(decoded.inner.keys[1], hex::encode(&pk2));
    }

    #[test]
    fn reject_wrong_magic() {
        let result = decode_kex_message("BadMagicXXXXXsomedata");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("magic"));
    }

    #[test]
    fn reject_truncated_data() {
        let result = decode_kex_message("MultisigxV2R1");
        assert!(result.is_err());
    }

    #[test]
    fn reject_bad_base58() {
        // 'O', 'I', 'l', '0' are not in CryptoNote base58 alphabet
        let result = decode_kex_message("MultisigxV2R1OOOO0000llll");
        assert!(result.is_err());
    }

    #[test]
    fn tx_set_empty_roundtrip() {
        let set = MultisigTxSet::with_config(2, 3);
        let encoded = encode_tx_set(&set);
        let decoded = decode_tx_set(&encoded).unwrap();

        assert_eq!(decoded.threshold, 2);
        assert_eq!(decoded.signer_count, 3);
        assert!(decoded.pending_txs.is_empty());
    }

    #[test]
    fn tx_set_with_pending_roundtrip() {
        let mut set = MultisigTxSet::with_config(2, 3);
        set.mark_signer_contributed("pk_signer_0");
        set.mark_signer_contributed("pk_signer_1");

        set.add_pending_tx(PendingMultisigTx {
            tx_blob: "deadbeef".to_string(),
            key_images: vec!["aa".repeat(32), "bb".repeat(32)],
            tx_prefix_hash: "cc".repeat(32),
            input_nonces: vec![vec![SignerNonces {
                signer_index: 0,
                secret_nonces: Vec::new(),
                pub_nonces_g: vec!["dd".repeat(32)],
                pub_nonces_hp: vec!["ee".repeat(32)],
                secret_nonces_y: Vec::new(),
                pub_nonces_g_y: Vec::new(),
                pub_nonces_hp_y: Vec::new(),
            }]],
            input_partials: vec![vec![PartialClsag {
                signer_index: 0,
                s_partial: "11".repeat(32),
                c_0: "22".repeat(32),
                sy_partial: Some("33".repeat(32)),
            }]],
            fee: 10_000_000,
            destinations: Vec::new(),
            signing_contexts: vec![MultisigClsagContext {
                ring: vec!["aa".repeat(32), "bb".repeat(32)],
                commitments: vec!["cc".repeat(32)],
                key_image: "dd".repeat(32),
                pseudo_output_commitment: "ee".repeat(32),
                message: "ff".repeat(32),
                real_index: 1,
                use_tclsag: false,
                key_image_y: None,
                commitment_image: None,
                fake_responses: vec!["00".repeat(32), "11".repeat(32)],
            }],
            signing_message: "abcd".to_string(),
            input_key_offsets: Vec::new(),
            input_z_values: Vec::new(),
            input_y_keys: Vec::new(),
            proposer_signed: false,
        });

        let encoded = encode_tx_set(&set);
        let decoded = decode_tx_set(&encoded).unwrap();

        assert_eq!(decoded.threshold, 2);
        assert_eq!(decoded.signer_count, 3);
        assert_eq!(decoded.pending_txs.len(), 1);

        let ptx = &decoded.pending_txs[0];
        assert_eq!(ptx.tx_blob, "deadbeef");
        assert_eq!(ptx.key_images.len(), 2);
        assert_eq!(ptx.fee, 10_000_000);
        assert_eq!(ptx.signing_message, "abcd");
        assert_eq!(ptx.input_nonces.len(), 1);
        assert_eq!(ptx.input_nonces[0].len(), 1);
        assert_eq!(ptx.input_nonces[0][0].signer_index, 0);
        assert_eq!(ptx.input_partials.len(), 1);
        assert_eq!(ptx.input_partials[0][0].sy_partial, Some("33".repeat(32)));
        assert_eq!(ptx.signing_contexts.len(), 1);
        assert_eq!(ptx.signing_contexts[0].real_index, 1);
        assert!(!ptx.signing_contexts[0].use_tclsag);
    }

    #[test]
    fn tx_set_reject_malformed() {
        let result = decode_tx_set(&[0xFF, 0x00, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_v1_magic() {
        let result = decode_kex_message("MultisigV1somedata");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("V1"));

        let result = decode_kex_message("MultisigxV1somedata");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("V1"));
    }

    #[test]
    fn reject_round_n_with_round_1() {
        // Create a valid round-N wire message but manually set round = 1
        let privkey = make_signing_key();
        let pk1 = salvium_crypto::scalar_mult_base(&[2u8; 32]);
        let pk2 = salvium_crypto::scalar_mult_base(&[3u8; 32]);
        let msg = KexMessage {
            round: 3,
            signer_index: 0,
            keys: vec![hex::encode(&pk1), hex::encode(&pk2)],
            msg_type: MultisigMsgType::KexRound,
        };
        let signed = SignedKexMessage::create(msg, &privkey).unwrap();

        // Encode normally, then tamper with the round in the Epee blob
        // Instead, we build a message that has round-N magic but round=1 in the body
        let mut map = std::collections::HashMap::new();
        map.insert(
            "signing_pubkey".to_string(),
            PsValue::String(signed.signing_pubkey.to_vec()),
        );
        map.insert(
            "signature".to_string(),
            PsValue::String(signed.signature.to_bytes().to_vec()),
        );
        map.insert("kex_round".to_string(), PsValue::Uint32(1)); // invalid: round=1 with round-N magic
        let pubkeys: Vec<PsValue> = signed
            .inner
            .keys
            .iter()
            .filter_map(|hex_str| hex::decode(hex_str).ok())
            .map(PsValue::String)
            .collect();
        map.insert("msg_pubkeys".to_string(), PsValue::Array(pubkeys));

        let blob = salvium_rpc::portable_storage::serialize(&map);
        let encoded = salvium_types::base58::encode(&blob);
        let wire = format!("MultisigxV2Rn{}", encoded);

        let result = decode_kex_message(&wire);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("round > 1"));
    }

    #[test]
    fn reject_null_signing_pubkey() {
        // Build a wire message with all-zeros signing_pubkey
        let privkey = make_signing_key();
        let msg = KexMessage {
            round: 1,
            signer_index: 0,
            keys: Vec::new(),
            msg_type: MultisigMsgType::KexInit,
        };
        let signed = SignedKexMessage::create(msg, &privkey).unwrap();

        let mut map = std::collections::HashMap::new();
        map.insert(
            "signing_pubkey".to_string(),
            PsValue::String(vec![0u8; 32]), // null pubkey
        );
        map.insert(
            "signature".to_string(),
            PsValue::String(signed.signature.to_bytes().to_vec()),
        );
        map.insert(
            "msg_privkey".to_string(),
            PsValue::String(signed.msg_privkey.to_vec()),
        );

        let blob = salvium_rpc::portable_storage::serialize(&map);
        let encoded = salvium_types::base58::encode(&blob);
        let wire = format!("MultisigxV2R1{}", encoded);

        let result = decode_kex_message(&wire);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("identity"));
    }
}
