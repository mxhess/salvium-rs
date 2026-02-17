//! Integration tests for expand_transaction + RCT verification pipeline.
//!
//! These tests exercise the public expand_transaction() function from
//! the salvium_crypto crate, verifying key image injection into both
//! CLSAG and TCLSAG JSON signature structures. They mirror the
//! JS test suite in test/expand-transaction.test.js.

use serde_json::json;
use salvium_crypto::rct_verify::expand_transaction;

// =============================================================================
// Helpers
// =============================================================================

/// Build a minimal RCT JSON with CLSAGs in the prunable section.
fn make_clsag_rct_json(count: usize) -> serde_json::Value {
    let sigs: Vec<serde_json::Value> = (0..count)
        .map(|_| json!({
            "s": ["00".repeat(32)],
            "c1": "00".repeat(32),
            "D": "00".repeat(32),
        }))
        .collect();
    json!({
        "p": {
            "CLSAGs": sigs
        }
    })
}

/// Build a minimal RCT JSON with TCLSAGs in the prunable section.
fn make_tclsag_rct_json(count: usize) -> serde_json::Value {
    let sigs: Vec<serde_json::Value> = (0..count)
        .map(|_| json!({
            "sx": ["00".repeat(32)],
            "sy": ["00".repeat(32)],
            "c1": "00".repeat(32),
            "D": "00".repeat(32),
        }))
        .collect();
    json!({
        "p": {
            "TCLSAGs": sigs
        }
    })
}

// =============================================================================
// CLSAG expand tests
// =============================================================================

#[test]
fn expand_clsag_populates_i_fields() {
    let ki1 = [0xAAu8; 32];
    let ki2 = [0xBBu8; 32];
    let mut rct = make_clsag_rct_json(2);

    let result = expand_transaction(&[ki1, ki2], &mut rct);
    assert!(result.is_ok());

    let clsags = rct["p"]["CLSAGs"].as_array().unwrap();
    assert_eq!(clsags[0]["I"].as_str().unwrap(), hex::encode(ki1));
    assert_eq!(clsags[1]["I"].as_str().unwrap(), hex::encode(ki2));
}

#[test]
fn expand_clsag_single_input() {
    let ki = [0xCCu8; 32];
    let mut rct = make_clsag_rct_json(1);

    let result = expand_transaction(&[ki], &mut rct);
    assert!(result.is_ok());
    assert_eq!(
        rct["p"]["CLSAGs"][0]["I"].as_str().unwrap(),
        hex::encode(ki)
    );
}

#[test]
fn expand_clsag_multiple_inputs() {
    let key_images: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
    let mut rct = make_clsag_rct_json(5);

    let result = expand_transaction(&key_images, &mut rct);
    assert!(result.is_ok());

    let clsags = rct["p"]["CLSAGs"].as_array().unwrap();
    for (i, ki) in key_images.iter().enumerate() {
        assert_eq!(
            clsags[i]["I"].as_str().unwrap(),
            hex::encode(ki),
            "key image mismatch at index {}",
            i
        );
    }
}

#[test]
fn expand_clsag_overwrites_existing_i() {
    let old_i = hex::encode([0xFFu8; 32]);
    let mut rct = json!({
        "p": {
            "CLSAGs": [{
                "s": ["00".repeat(32)],
                "c1": "00".repeat(32),
                "D": "00".repeat(32),
                "I": old_i,
            }]
        }
    });

    let new_ki = [0x11u8; 32];
    let result = expand_transaction(&[new_ki], &mut rct);
    assert!(result.is_ok());
    assert_eq!(
        rct["p"]["CLSAGs"][0]["I"].as_str().unwrap(),
        hex::encode(new_ki),
        "existing I field should be overwritten"
    );
}

#[test]
fn expand_clsag_preserves_other_fields() {
    let s_val = "abcd".repeat(16);
    let c1_val = "1234".repeat(16);
    let d_val = "5678".repeat(16);
    let mut rct = json!({
        "p": {
            "CLSAGs": [{
                "s": [s_val],
                "c1": c1_val,
                "D": d_val,
                "extra_field": 42,
            }]
        }
    });

    let ki = [0xEEu8; 32];
    let result = expand_transaction(&[ki], &mut rct);
    assert!(result.is_ok());

    let sig = &rct["p"]["CLSAGs"][0];
    assert_eq!(sig["s"][0].as_str().unwrap(), s_val);
    assert_eq!(sig["c1"].as_str().unwrap(), c1_val);
    assert_eq!(sig["D"].as_str().unwrap(), d_val);
    assert_eq!(sig["extra_field"].as_i64().unwrap(), 42);
    assert_eq!(sig["I"].as_str().unwrap(), hex::encode(ki));
}

// =============================================================================
// TCLSAG expand tests
// =============================================================================

#[test]
fn expand_tclsag_populates_i_fields() {
    let ki1 = [0xAAu8; 32];
    let ki2 = [0xBBu8; 32];
    let mut rct = make_tclsag_rct_json(2);

    let result = expand_transaction(&[ki1, ki2], &mut rct);
    assert!(result.is_ok());

    let tclsags = rct["p"]["TCLSAGs"].as_array().unwrap();
    assert_eq!(tclsags[0]["I"].as_str().unwrap(), hex::encode(ki1));
    assert_eq!(tclsags[1]["I"].as_str().unwrap(), hex::encode(ki2));
}

#[test]
fn expand_tclsag_single_input() {
    let ki = [0x42u8; 32];
    let mut rct = make_tclsag_rct_json(1);

    let result = expand_transaction(&[ki], &mut rct);
    assert!(result.is_ok());
    assert_eq!(
        rct["p"]["TCLSAGs"][0]["I"].as_str().unwrap(),
        hex::encode(ki)
    );
}

// =============================================================================
// Error cases
// =============================================================================

#[test]
fn expand_mismatched_count_clsag() {
    let mut rct = make_clsag_rct_json(3);
    let key_images = [[0xAAu8; 32], [0xBBu8; 32]]; // 2 != 3

    let result = expand_transaction(&key_images, &mut rct);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("count 3 != key image count 2"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn expand_mismatched_count_tclsag() {
    let mut rct = make_tclsag_rct_json(1);
    let key_images = [[0xAAu8; 32], [0xBBu8; 32]]; // 2 != 1

    let result = expand_transaction(&key_images, &mut rct);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("count 1 != key image count 2"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn expand_missing_prunable_section() {
    let key_images = [[0xAAu8; 32]];
    let mut rct = json!({ "type": 5, "fee": 10000 });

    let result = expand_transaction(&key_images, &mut rct);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "missing prunable section");
}

#[test]
fn expand_no_signature_arrays() {
    let key_images = [[0xAAu8; 32]];
    let mut rct = json!({
        "p": {
            "bulletproofPlus": []
        }
    });

    let result = expand_transaction(&key_images, &mut rct);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "no CLSAG or TCLSAG signatures found");
}

#[test]
fn expand_empty_key_images_empty_sigs() {
    let key_images: &[[u8; 32]] = &[];
    let mut rct = make_clsag_rct_json(0);

    let result = expand_transaction(key_images, &mut rct);
    assert!(result.is_ok(), "empty key images with empty sigs should succeed");
}

// =============================================================================
// Alternative key naming ("prunable" instead of "p", "clsags" lowercase)
// =============================================================================

#[test]
fn expand_with_prunable_key() {
    let ki = [0x55u8; 32];
    let mut rct = json!({
        "prunable": {
            "CLSAGs": [{
                "s": [],
                "c1": "00".repeat(32),
                "D": "00".repeat(32),
            }]
        }
    });

    let result = expand_transaction(&[ki], &mut rct);
    assert!(result.is_ok());
    assert_eq!(
        rct["prunable"]["CLSAGs"][0]["I"].as_str().unwrap(),
        hex::encode(ki)
    );
}

#[test]
fn expand_with_lowercase_clsags_key() {
    let ki = [0x66u8; 32];
    let mut rct = json!({
        "p": {
            "clsags": [{
                "s": [],
                "c1": "00".repeat(32),
                "D": "00".repeat(32),
            }]
        }
    });

    let result = expand_transaction(&[ki], &mut rct);
    assert!(result.is_ok());
    assert_eq!(
        rct["p"]["clsags"][0]["I"].as_str().unwrap(),
        hex::encode(ki)
    );
}

#[test]
fn expand_with_lowercase_tclsags_key() {
    let ki = [0x77u8; 32];
    let mut rct = json!({
        "p": {
            "tclsags": [{
                "sx": [],
                "sy": [],
                "c1": "00".repeat(32),
                "D": "00".repeat(32),
            }]
        }
    });

    let result = expand_transaction(&[ki], &mut rct);
    assert!(result.is_ok());
    assert_eq!(
        rct["p"]["tclsags"][0]["I"].as_str().unwrap(),
        hex::encode(ki)
    );
}

// =============================================================================
// Key image hex encoding verification
// =============================================================================

#[test]
fn expand_produces_correct_hex_encoding() {
    // Use a key image with recognizable byte pattern
    let mut ki = [0u8; 32];
    for (i, byte) in ki.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let mut rct = make_clsag_rct_json(1);

    let result = expand_transaction(&[ki], &mut rct);
    assert!(result.is_ok());

    let i_hex = rct["p"]["CLSAGs"][0]["I"].as_str().unwrap();
    assert_eq!(i_hex.len(), 64, "hex-encoded 32-byte key image should be 64 chars");

    // Decode back and compare
    let decoded = hex::decode(i_hex).unwrap();
    assert_eq!(decoded.as_slice(), &ki[..]);
}
