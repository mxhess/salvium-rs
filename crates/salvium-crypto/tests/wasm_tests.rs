//! WASM-bindgen tests for the salvium-crypto WASM API.
//!
//! Run with: wasm-pack test --node -p salvium-crypto
//! Or natively: cargo test --test wasm_tests

use salvium_crypto::*;

#[test]
fn test_parse_address_roundtrip() {
    // Create a testnet CARROT standard address with known keys
    let spend_key = [0x01u8; 32];
    let view_key = [0x02u8; 32];

    let address = wasm_create_address(1, 1, 0, &spend_key, &view_key);
    // Should not be an error JSON
    assert!(
        !address.starts_with('{'),
        "wasm_create_address returned error: {}",
        address
    );

    // Parse it back
    let json = wasm_parse_address(&address);
    assert!(
        !json.contains("\"error\""),
        "wasm_parse_address returned error: {}",
        json
    );

    // Verify fields
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["network"], "testnet");
    assert_eq!(parsed["format"], "carrot");
    assert_eq!(parsed["address_type"], "standard");
    assert_eq!(parsed["spend_public_key"], hex::encode(spend_key));
    assert_eq!(parsed["view_public_key"], hex::encode(view_key));

    // Validate
    assert!(wasm_is_valid_address(&address));

    // Describe
    let desc = wasm_describe_address(&address);
    assert!(desc.contains("Testnet"), "expected 'Testnet' in: {}", desc);
    assert!(desc.contains("CARROT"), "expected 'CARROT' in: {}", desc);
}

#[test]
fn test_address_validation() {
    // Invalid addresses
    assert!(!wasm_is_valid_address(""));
    assert!(!wasm_is_valid_address("not_an_address"));
    assert!(!wasm_is_valid_address("SaLv123456"));

    // Valid: create a mainnet legacy standard address
    let address = wasm_create_address(0, 0, 0, &[0x03u8; 32], &[0x04u8; 32]);
    assert!(!address.starts_with('{'));
    assert!(wasm_is_valid_address(&address));
}

#[test]
fn test_integrated_address() {
    let spend_key = [0x05u8; 32];
    let view_key = [0x06u8; 32];
    let payment_id = [0xAA; 8];

    let standard = wasm_create_address(0, 0, 0, &spend_key, &view_key);
    assert!(!standard.starts_with('{'));

    let integrated = wasm_to_integrated_address(&standard, &payment_id);
    assert!(!integrated.starts_with('{'));
    assert_ne!(standard, integrated);

    // Parse the integrated address and verify payment_id
    let json = wasm_parse_address(&integrated);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["address_type"], "integrated");
    assert_eq!(parsed["payment_id"], hex::encode(payment_id));
}

#[test]
fn test_integrated_address_wrong_payment_id_size() {
    let standard = wasm_create_address(0, 0, 0, &[0x07u8; 32], &[0x08u8; 32]);
    let result = wasm_to_integrated_address(&standard, &[0xBB; 4]);
    assert!(
        result.contains("error"),
        "expected error for 4-byte payment_id"
    );
}

#[test]
fn test_tx_type_names() {
    // All valid codes should return non-empty, non-UNKNOWN names
    let expected = [
        (0, "UNSET"),
        (1, "MINER"),
        (2, "PROTOCOL"),
        (3, "TRANSFER"),
        (4, "CONVERT"),
        (5, "BURN"),
        (6, "STAKE"),
        (7, "RETURN"),
        (8, "AUDIT"),
    ];
    for (code, name) in &expected {
        assert_eq!(
            wasm_tx_type_name(*code),
            *name,
            "tx_type {} should be {}",
            code,
            name
        );
    }

    // Unknown code
    let unknown = wasm_tx_type_name(255);
    assert!(
        unknown.starts_with("UNKNOWN"),
        "255 should be UNKNOWN, got: {}",
        unknown
    );
}

#[test]
fn test_rct_type_names() {
    let expected = [
        (0, "Null"),
        (1, "Full"),
        (2, "Simple"),
        (3, "Bulletproof"),
        (4, "Bulletproof2"),
        (5, "CLSAG"),
        (6, "BulletproofPlus"),
        (7, "FullProofs"),
        (8, "SalviumZero"),
        (9, "SalviumOne"),
    ];
    for (code, name) in &expected {
        assert_eq!(
            wasm_rct_type_name(*code),
            *name,
            "rct_type {} should be {}",
            code,
            name
        );
    }

    let unknown = wasm_rct_type_name(255);
    assert!(unknown.starts_with("UNKNOWN"));
}

#[test]
fn test_keccak256_known_vector() {
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    let hash = keccak256(b"");
    assert_eq!(
        hex::encode(&hash),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );

    // keccak256("abc") known vector
    let hash2 = keccak256(b"abc");
    assert_eq!(hash2.len(), 32);
    assert_ne!(hash, hash2);
}

#[test]
fn test_mnemonic_roundtrip() {
    let seed = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99,
    ];

    let mnemonic = wasm_mnemonic_from_seed(&seed);
    assert!(
        !mnemonic.starts_with('{'),
        "expected mnemonic words, got error: {}",
        mnemonic
    );

    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 25, "mnemonic should have 25 words");

    // Roundtrip
    let recovered = wasm_mnemonic_to_seed(&mnemonic);
    assert_eq!(recovered.len(), 32, "recovered seed should be 32 bytes");
    assert_eq!(recovered, seed.to_vec());

    // Validate
    assert!(wasm_validate_mnemonic(&mnemonic));
}

#[test]
fn test_mnemonic_invalid() {
    assert!(!wasm_validate_mnemonic(""));
    assert!(!wasm_validate_mnemonic("one two three"));
    assert!(wasm_mnemonic_to_seed("invalid").is_empty());
}

#[test]
fn test_mnemonic_from_seed_wrong_length() {
    let result = wasm_mnemonic_from_seed(&[0u8; 16]);
    assert!(result.contains("error"), "expected error for 16-byte seed");
}

#[test]
fn test_parse_transaction_bytes_empty() {
    // Empty input should return an error JSON, not panic
    let result = parse_transaction_bytes(&[]);
    assert!(result.contains("error") || result.contains("Error"));
}

#[test]
fn test_create_address_invalid_params() {
    // Invalid network
    let result = wasm_create_address(99, 0, 0, &[0u8; 32], &[0u8; 32]);
    assert!(result.contains("error"));

    // Invalid format
    let result = wasm_create_address(0, 99, 0, &[0u8; 32], &[0u8; 32]);
    assert!(result.contains("error"));

    // Invalid address type
    let result = wasm_create_address(0, 0, 99, &[0u8; 32], &[0u8; 32]);
    assert!(result.contains("error"));

    // Wrong key length
    let result = wasm_create_address(0, 0, 0, &[0u8; 16], &[0u8; 32]);
    assert!(result.contains("error"));
}
