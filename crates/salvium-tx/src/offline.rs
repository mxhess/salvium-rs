//! Offline signing support for cold-wallet workflows.
//!
//! Provides types and functions for creating, exporting, importing, and
//! validating unsigned/signed transactions as well as key-image and output
//! export files. These allow a view-only (hot) wallet to prepare transactions
//! that are then signed on an air-gapped (cold) device.

use serde::{Deserialize, Serialize};

// ─── Version Constants ──────────────────────────────────────────────────────

/// Format version for unsigned transaction files.
pub const UNSIGNED_TX_VERSION: u32 = 1;

/// Format version for signed transaction files.
pub const SIGNED_TX_VERSION: u32 = 1;

// ─── Unsigned Transaction Types ─────────────────────────────────────────────

/// An unsigned transaction prepared by a view-only wallet for cold signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTx {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
    pub extra: Vec<u8>,
    pub tx_type: u32,
    pub asset_type: String,
    pub ring_size: usize,
}

/// Input for an unsigned transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub key_image: String,
    pub amount: u64,
    pub key_offsets: Vec<u64>,
    pub real_output_index: usize,
    pub real_output_pub_key: String,
}

/// Output for an unsigned transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    pub amount: u64,
    pub destination: String,
    pub is_subaddress: bool,
}

// ─── Signed Transaction Types ───────────────────────────────────────────────

/// A signed transaction ready for broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTx {
    pub version: u32,
    pub tx_hash: String,
    pub tx_blob: String,
    pub tx_key: String,
    pub fee: u64,
    pub tx_type: u32,
    pub asset_type: String,
}

// ─── Key Image / Output Export Types ────────────────────────────────────────

/// Exported key image for view-only wallets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedKeyImage {
    pub key_image: String,
    pub signature: String,
    pub output_index: u64,
    pub amount: u64,
}

/// Exported output for offline signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedOutput {
    pub public_key: String,
    pub key_image: String,
    pub tx_hash: String,
    pub output_index: u64,
    pub amount: u64,
    pub block_height: u64,
    pub asset_type: String,
    pub subaddress_major: u32,
    pub subaddress_minor: u32,
}

// ─── Transaction Summary ────────────────────────────────────────────────────

/// Summary of an unsigned transaction for display purposes.
#[derive(Debug, Clone)]
pub struct TxSummary {
    pub input_count: usize,
    pub output_count: usize,
    pub fee: u64,
    pub total_in: u64,
    pub total_out: u64,
    pub ring_size: usize,
    pub tx_type: u32,
    pub asset_type: String,
}

// ─── Unsigned Transaction Functions ─────────────────────────────────────────

/// Create a new unsigned transaction with the current format version.
pub fn create_unsigned_tx(
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    fee: u64,
    tx_type: u32,
    asset_type: String,
    ring_size: usize,
    extra: Vec<u8>,
) -> UnsignedTx {
    UnsignedTx {
        version: UNSIGNED_TX_VERSION,
        inputs,
        outputs,
        fee,
        extra,
        tx_type,
        asset_type,
        ring_size,
    }
}

/// Deserialize an unsigned transaction from JSON, verifying the version.
pub fn parse_unsigned_tx(json: &str) -> Result<UnsignedTx, String> {
    let tx: UnsignedTx =
        serde_json::from_str(json).map_err(|e| format!("invalid unsigned tx JSON: {}", e))?;
    if tx.version != UNSIGNED_TX_VERSION {
        return Err(format!(
            "unsupported unsigned tx version: expected {}, got {}",
            UNSIGNED_TX_VERSION, tx.version
        ));
    }
    Ok(tx)
}

/// Serialize an unsigned transaction to a JSON string.
pub fn export_unsigned_tx(tx: &UnsignedTx) -> String {
    serde_json::to_string(tx).expect("UnsignedTx serialization should not fail")
}

/// Import an unsigned transaction from a JSON string (alias for `parse_unsigned_tx`).
pub fn import_unsigned_tx(json: &str) -> Result<UnsignedTx, String> {
    parse_unsigned_tx(json)
}

// ─── Signed Transaction Functions ───────────────────────────────────────────

/// Create a new signed transaction with the current format version.
pub fn create_signed_tx(
    tx_hash: String,
    tx_blob: String,
    tx_key: String,
    fee: u64,
    tx_type: u32,
    asset_type: String,
) -> SignedTx {
    SignedTx {
        version: SIGNED_TX_VERSION,
        tx_hash,
        tx_blob,
        tx_key,
        fee,
        tx_type,
        asset_type,
    }
}

/// Deserialize a signed transaction from JSON, verifying the version.
pub fn parse_signed_tx(json: &str) -> Result<SignedTx, String> {
    let tx: SignedTx =
        serde_json::from_str(json).map_err(|e| format!("invalid signed tx JSON: {}", e))?;
    if tx.version != SIGNED_TX_VERSION {
        return Err(format!(
            "unsupported signed tx version: expected {}, got {}",
            SIGNED_TX_VERSION, tx.version
        ));
    }
    Ok(tx)
}

/// Serialize a signed transaction to a JSON string.
pub fn export_signed_tx(tx: &SignedTx) -> String {
    serde_json::to_string(tx).expect("SignedTx serialization should not fail")
}

/// Import a signed transaction from a JSON string (alias for `parse_signed_tx`).
pub fn import_signed_tx(json: &str) -> Result<SignedTx, String> {
    parse_signed_tx(json)
}

// ─── Key Image Export/Import ────────────────────────────────────────────────

/// Serialize a slice of exported key images to a JSON array string.
pub fn export_key_images(images: &[ExportedKeyImage]) -> String {
    serde_json::to_string(images).expect("ExportedKeyImage serialization should not fail")
}

/// Deserialize exported key images from a JSON array string.
pub fn import_key_images(json: &str) -> Result<Vec<ExportedKeyImage>, String> {
    serde_json::from_str(json).map_err(|e| format!("invalid key images JSON: {}", e))
}

// ─── Output Export/Import ───────────────────────────────────────────────────

/// Serialize a slice of exported outputs to a JSON array string.
pub fn export_outputs(outputs: &[ExportedOutput]) -> String {
    serde_json::to_string(outputs).expect("ExportedOutput serialization should not fail")
}

/// Deserialize exported outputs from a JSON array string.
pub fn import_outputs(json: &str) -> Result<Vec<ExportedOutput>, String> {
    serde_json::from_str(json).map_err(|e| format!("invalid outputs JSON: {}", e))
}

// ─── Validation ─────────────────────────────────────────────────────────────

/// Validate an unsigned transaction. Returns `Ok(())` if valid, or a list of
/// errors describing every problem found.
pub fn verify_unsigned_tx(tx: &UnsignedTx) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if tx.inputs.is_empty() {
        errors.push("transaction has no inputs".to_string());
    }

    if tx.outputs.is_empty() {
        errors.push("transaction has no outputs".to_string());
    }

    // Miner transactions (tx_type == 1) can have zero fee.
    if tx.fee == 0 && tx.tx_type != 1 {
        errors.push("fee must be greater than zero for non-miner transactions".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ─── Summary ────────────────────────────────────────────────────────────────

/// Produce a human-readable summary of an unsigned transaction.
pub fn summarize_unsigned_tx(tx: &UnsignedTx) -> TxSummary {
    let total_in: u64 = tx.inputs.iter().map(|i| i.amount).sum();
    let total_out: u64 = tx.outputs.iter().map(|o| o.amount).sum();

    TxSummary {
        input_count: tx.inputs.len(),
        output_count: tx.outputs.len(),
        fee: tx.fee,
        total_in,
        total_out,
        ring_size: tx.ring_size,
        tx_type: tx.tx_type,
        asset_type: tx.asset_type.clone(),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers ----------------------------------------------------------------

    fn sample_input(amount: u64) -> TxInput {
        TxInput {
            key_image: "aa".repeat(32),
            amount,
            key_offsets: vec![100, 200, 300],
            real_output_index: 0,
            real_output_pub_key: "bb".repeat(32),
        }
    }

    fn sample_output(amount: u64) -> TxOutput {
        TxOutput {
            amount,
            destination: "cc".repeat(32),
            is_subaddress: false,
        }
    }

    fn sample_unsigned_tx() -> UnsignedTx {
        create_unsigned_tx(
            vec![sample_input(1_000_000_000)],
            vec![sample_output(900_000_000)],
            100_000_000,
            3, // TRANSFER
            "SAL".to_string(),
            16,
            vec![1, 2, 3, 4],
        )
    }

    fn sample_signed_tx() -> SignedTx {
        create_signed_tx(
            "ab".repeat(32),
            "deadbeef".to_string(),
            "ef".repeat(32),
            100_000_000,
            3,
            "SAL".to_string(),
        )
    }

    // 1. Version constants correct -------------------------------------------

    #[test]
    fn version_constants_correct() {
        assert_eq!(UNSIGNED_TX_VERSION, 1);
        assert_eq!(SIGNED_TX_VERSION, 1);
    }

    // 2. Create and parse unsigned tx round-trip -----------------------------

    #[test]
    fn create_and_parse_unsigned_tx_round_trip() {
        let tx = sample_unsigned_tx();
        let json = serde_json::to_string(&tx).unwrap();
        let parsed = parse_unsigned_tx(&json).unwrap();

        assert_eq!(parsed.version, UNSIGNED_TX_VERSION);
        assert_eq!(parsed.fee, 100_000_000);
        assert_eq!(parsed.inputs.len(), 1);
        assert_eq!(parsed.outputs.len(), 1);
        assert_eq!(parsed.inputs[0].amount, 1_000_000_000);
        assert_eq!(parsed.outputs[0].amount, 900_000_000);
    }

    // 3. Export/import unsigned tx -------------------------------------------

    #[test]
    fn export_import_unsigned_tx() {
        let tx = sample_unsigned_tx();
        let exported = export_unsigned_tx(&tx);
        let imported = import_unsigned_tx(&exported).unwrap();

        assert_eq!(imported.version, tx.version);
        assert_eq!(imported.fee, tx.fee);
        assert_eq!(imported.inputs.len(), tx.inputs.len());
        assert_eq!(imported.outputs.len(), tx.outputs.len());
        assert_eq!(imported.tx_type, tx.tx_type);
        assert_eq!(imported.asset_type, tx.asset_type);
        assert_eq!(imported.ring_size, tx.ring_size);
    }

    // 4. Create and parse signed tx round-trip -------------------------------

    #[test]
    fn create_and_parse_signed_tx_round_trip() {
        let tx = sample_signed_tx();
        let json = serde_json::to_string(&tx).unwrap();
        let parsed = parse_signed_tx(&json).unwrap();

        assert_eq!(parsed.version, SIGNED_TX_VERSION);
        assert_eq!(parsed.tx_hash, tx.tx_hash);
        assert_eq!(parsed.tx_blob, tx.tx_blob);
        assert_eq!(parsed.tx_key, tx.tx_key);
        assert_eq!(parsed.fee, tx.fee);
    }

    // 5. Export/import signed tx ---------------------------------------------

    #[test]
    fn export_import_signed_tx() {
        let tx = sample_signed_tx();
        let exported = export_signed_tx(&tx);
        let imported = import_signed_tx(&exported).unwrap();

        assert_eq!(imported.version, tx.version);
        assert_eq!(imported.tx_hash, tx.tx_hash);
        assert_eq!(imported.tx_blob, tx.tx_blob);
        assert_eq!(imported.tx_key, tx.tx_key);
        assert_eq!(imported.fee, tx.fee);
        assert_eq!(imported.tx_type, tx.tx_type);
        assert_eq!(imported.asset_type, tx.asset_type);
    }

    // 6. Export/import key images preserves all fields -----------------------

    #[test]
    fn export_import_key_images_preserves_all_fields() {
        let images = vec![ExportedKeyImage {
            key_image: "aa".repeat(32),
            signature: "bb".repeat(64),
            output_index: 7,
            amount: 5_000_000_000,
        }];

        let json = export_key_images(&images);
        let imported = import_key_images(&json).unwrap();

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].key_image, images[0].key_image);
        assert_eq!(imported[0].signature, images[0].signature);
        assert_eq!(imported[0].output_index, images[0].output_index);
        assert_eq!(imported[0].amount, images[0].amount);
    }

    // 7. Export/import outputs preserves all fields --------------------------

    #[test]
    fn export_import_outputs_preserves_all_fields() {
        let outputs = vec![ExportedOutput {
            public_key: "aa".repeat(32),
            key_image: "bb".repeat(32),
            tx_hash: "cc".repeat(32),
            output_index: 1,
            amount: 2_000_000_000,
            block_height: 100_000,
            asset_type: "SAL".to_string(),
            subaddress_major: 0,
            subaddress_minor: 5,
        }];

        let json = export_outputs(&outputs);
        let imported = import_outputs(&json).unwrap();

        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].public_key, outputs[0].public_key);
        assert_eq!(imported[0].key_image, outputs[0].key_image);
        assert_eq!(imported[0].tx_hash, outputs[0].tx_hash);
        assert_eq!(imported[0].output_index, outputs[0].output_index);
        assert_eq!(imported[0].amount, outputs[0].amount);
        assert_eq!(imported[0].block_height, outputs[0].block_height);
        assert_eq!(imported[0].asset_type, outputs[0].asset_type);
        assert_eq!(imported[0].subaddress_major, outputs[0].subaddress_major);
        assert_eq!(imported[0].subaddress_minor, outputs[0].subaddress_minor);
    }

    // 8. verify_unsigned_tx passes valid tx ----------------------------------

    #[test]
    fn verify_unsigned_tx_passes_valid_tx() {
        let tx = sample_unsigned_tx();
        assert!(verify_unsigned_tx(&tx).is_ok());
    }

    // 9. verify_unsigned_tx detects missing inputs ---------------------------

    #[test]
    fn verify_unsigned_tx_detects_missing_inputs() {
        let tx = create_unsigned_tx(
            vec![],
            vec![sample_output(900_000_000)],
            100_000_000,
            3,
            "SAL".to_string(),
            16,
            vec![],
        );
        let err = verify_unsigned_tx(&tx).unwrap_err();
        assert!(err.iter().any(|e| e.contains("input")));
    }

    // 10. verify_unsigned_tx detects missing outputs -------------------------

    #[test]
    fn verify_unsigned_tx_detects_missing_outputs() {
        let tx = create_unsigned_tx(
            vec![sample_input(1_000_000_000)],
            vec![],
            100_000_000,
            3,
            "SAL".to_string(),
            16,
            vec![],
        );
        let err = verify_unsigned_tx(&tx).unwrap_err();
        assert!(err.iter().any(|e| e.contains("output")));
    }

    // 11. summarize_unsigned_tx correct counts and totals --------------------

    #[test]
    fn summarize_unsigned_tx_correct_counts_and_totals() {
        let tx = create_unsigned_tx(
            vec![sample_input(1_000_000_000), sample_input(500_000_000)],
            vec![sample_output(900_000_000), sample_output(400_000_000)],
            200_000_000,
            3,
            "SAL".to_string(),
            16,
            vec![],
        );

        let summary = summarize_unsigned_tx(&tx);
        assert_eq!(summary.input_count, 2);
        assert_eq!(summary.output_count, 2);
        assert_eq!(summary.fee, 200_000_000);
        assert_eq!(summary.total_in, 1_500_000_000);
        assert_eq!(summary.total_out, 1_300_000_000);
        assert_eq!(summary.ring_size, 16);
        assert_eq!(summary.tx_type, 3);
        assert_eq!(summary.asset_type, "SAL");
    }

    // 12. Parse invalid JSON returns error -----------------------------------

    #[test]
    fn parse_invalid_json_returns_error() {
        assert!(parse_unsigned_tx("not valid json").is_err());
        assert!(parse_signed_tx("not valid json").is_err());
        assert!(import_key_images("garbage").is_err());
        assert!(import_outputs("garbage").is_err());
    }

    // 13. Parse wrong version returns error ----------------------------------

    #[test]
    fn parse_wrong_version_returns_error() {
        let mut tx = sample_unsigned_tx();
        tx.version = 999;
        let json = serde_json::to_string(&tx).unwrap();
        let err = parse_unsigned_tx(&json).unwrap_err();
        assert!(err.contains("version"));

        let mut stx = sample_signed_tx();
        stx.version = 999;
        let json = serde_json::to_string(&stx).unwrap();
        let err = parse_signed_tx(&json).unwrap_err();
        assert!(err.contains("version"));
    }

    // 14. Multiple key images round-trip -------------------------------------

    #[test]
    fn multiple_key_images_round_trip() {
        let images = vec![
            ExportedKeyImage {
                key_image: "11".repeat(32),
                signature: "22".repeat(64),
                output_index: 0,
                amount: 100,
            },
            ExportedKeyImage {
                key_image: "33".repeat(32),
                signature: "44".repeat(64),
                output_index: 1,
                amount: 200,
            },
            ExportedKeyImage {
                key_image: "55".repeat(32),
                signature: "66".repeat(64),
                output_index: 2,
                amount: 300,
            },
        ];

        let json = export_key_images(&images);
        let imported = import_key_images(&json).unwrap();

        assert_eq!(imported.len(), 3);
        for (orig, imp) in images.iter().zip(imported.iter()) {
            assert_eq!(orig.key_image, imp.key_image);
            assert_eq!(orig.signature, imp.signature);
            assert_eq!(orig.output_index, imp.output_index);
            assert_eq!(orig.amount, imp.amount);
        }
    }

    // 15. Multiple outputs round-trip ----------------------------------------

    #[test]
    fn multiple_outputs_round_trip() {
        let outputs = vec![
            ExportedOutput {
                public_key: "a1".repeat(32),
                key_image: "b1".repeat(32),
                tx_hash: "c1".repeat(32),
                output_index: 0,
                amount: 1_000_000,
                block_height: 10_000,
                asset_type: "SAL".to_string(),
                subaddress_major: 0,
                subaddress_minor: 0,
            },
            ExportedOutput {
                public_key: "a2".repeat(32),
                key_image: "b2".repeat(32),
                tx_hash: "c2".repeat(32),
                output_index: 1,
                amount: 2_000_000,
                block_height: 20_000,
                asset_type: "SAL".to_string(),
                subaddress_major: 0,
                subaddress_minor: 1,
            },
        ];

        let json = export_outputs(&outputs);
        let imported = import_outputs(&json).unwrap();

        assert_eq!(imported.len(), 2);
        for (orig, imp) in outputs.iter().zip(imported.iter()) {
            assert_eq!(orig.public_key, imp.public_key);
            assert_eq!(orig.key_image, imp.key_image);
            assert_eq!(orig.tx_hash, imp.tx_hash);
            assert_eq!(orig.output_index, imp.output_index);
            assert_eq!(orig.amount, imp.amount);
            assert_eq!(orig.block_height, imp.block_height);
            assert_eq!(orig.asset_type, imp.asset_type);
            assert_eq!(orig.subaddress_major, imp.subaddress_major);
            assert_eq!(orig.subaddress_minor, imp.subaddress_minor);
        }
    }

    // 16. Empty inputs/outputs handling --------------------------------------

    #[test]
    fn empty_inputs_and_outputs_handling() {
        // An unsigned tx with no inputs and no outputs should fail verification.
        let tx = create_unsigned_tx(
            vec![],
            vec![],
            100_000_000,
            3,
            "SAL".to_string(),
            16,
            vec![],
        );
        let err = verify_unsigned_tx(&tx).unwrap_err();
        assert!(err.iter().any(|e| e.contains("input")));
        assert!(err.iter().any(|e| e.contains("output")));

        // But serialization should still work fine.
        let json = export_unsigned_tx(&tx);
        let imported = import_unsigned_tx(&json).unwrap();
        assert_eq!(imported.inputs.len(), 0);
        assert_eq!(imported.outputs.len(), 0);

        // Empty key images and outputs export/import.
        let ki_json = export_key_images(&[]);
        let ki = import_key_images(&ki_json).unwrap();
        assert!(ki.is_empty());

        let out_json = export_outputs(&[]);
        let outs = import_outputs(&out_json).unwrap();
        assert!(outs.is_empty());
    }

    // 17. Asset type preservation --------------------------------------------

    #[test]
    fn asset_type_preservation() {
        // Unsigned tx with non-default asset type.
        let tx = create_unsigned_tx(
            vec![sample_input(1_000)],
            vec![sample_output(900)],
            100,
            4, // CONVERT
            "SALV".to_string(),
            16,
            vec![],
        );
        let json = export_unsigned_tx(&tx);
        let imported = import_unsigned_tx(&json).unwrap();
        assert_eq!(imported.asset_type, "SALV");

        // Signed tx.
        let stx = create_signed_tx(
            "ab".repeat(32),
            "beef".to_string(),
            "cd".repeat(32),
            100,
            4,
            "SALV".to_string(),
        );
        let sjson = export_signed_tx(&stx);
        let simported = import_signed_tx(&sjson).unwrap();
        assert_eq!(simported.asset_type, "SALV");

        // Exported outputs.
        let outputs = vec![ExportedOutput {
            public_key: "aa".repeat(32),
            key_image: "bb".repeat(32),
            tx_hash: "cc".repeat(32),
            output_index: 0,
            amount: 1000,
            block_height: 5000,
            asset_type: "SALV".to_string(),
            subaddress_major: 0,
            subaddress_minor: 0,
        }];
        let ojson = export_outputs(&outputs);
        let oimported = import_outputs(&ojson).unwrap();
        assert_eq!(oimported[0].asset_type, "SALV");
    }

    // 18. Ring size preservation ---------------------------------------------

    #[test]
    fn ring_size_preservation() {
        for &ring_size in &[11_usize, 16, 32, 64] {
            let tx = create_unsigned_tx(
                vec![sample_input(1_000)],
                vec![sample_output(900)],
                100,
                3,
                "SAL".to_string(),
                ring_size,
                vec![],
            );

            let json = export_unsigned_tx(&tx);
            let imported = import_unsigned_tx(&json).unwrap();
            assert_eq!(imported.ring_size, ring_size);

            let summary = summarize_unsigned_tx(&imported);
            assert_eq!(summary.ring_size, ring_size);
        }
    }
}
