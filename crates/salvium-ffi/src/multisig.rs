//! FFI bindings for multisig wallet operations.

use std::ffi::{c_char, c_void};

use crate::error::{ffi_try, ffi_try_string};
use crate::handles::{borrow_handle, borrow_handle_mut};
use crate::strings::c_str_to_str;

use salvium_wallet::Wallet;

// =============================================================================
// Multisig Wallet Setup
// =============================================================================

/// Initialize a multisig wallet and return the first KEX message.
///
/// - `handle`: wallet handle (must be a full wallet with spend key)
/// - `threshold`: required number of signers (M)
/// - `signer_count`: total number of signers (N)
///
/// Returns a JSON-encoded KEX message string. Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_multisig_prepare(
    handle: *mut c_void,
    threshold: usize,
    signer_count: usize,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = unsafe { borrow_handle_mut::<Wallet>(handle) }?;
        wallet
            .create_multisig(threshold, signer_count)
            .map_err(|e| e.to_string())
    })
}

/// Process a multisig KEX round with messages from all signers.
///
/// - `handle`: wallet handle (must be a multisig wallet in KEX)
/// - `messages_json`: JSON array of KEX message strings from all signers
///
/// Returns the next round's KEX message JSON, or `"null"` if KEX is complete.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_multisig_make(
    handle: *mut c_void,
    messages_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = unsafe { borrow_handle_mut::<Wallet>(handle) }?;
        let json_str = unsafe { c_str_to_str(messages_json) }?;
        let messages: Vec<String> =
            serde_json::from_str(json_str).map_err(|e| format!("invalid JSON array: {e}"))?;

        match wallet
            .process_multisig_kex(&messages)
            .map_err(|e| e.to_string())?
        {
            Some(msg) => Ok(msg),
            None => Ok("null".to_string()),
        }
    })
}

/// Process subsequent KEX rounds (alias for `salvium_multisig_make`).
///
/// Same parameters and return value as `salvium_multisig_make`.
#[no_mangle]
pub unsafe extern "C" fn salvium_multisig_exchange_keys(
    handle: *mut c_void,
    messages_json: *const c_char,
) -> *mut c_char {
    salvium_multisig_make(handle, messages_json)
}

// =============================================================================
// Multisig Info Export/Import
// =============================================================================

/// Export multisig info (nonces, partial key images) for co-signers.
///
/// Returns hex-encoded info string. Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_multisig_export_info(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = unsafe { borrow_handle::<Wallet>(handle) }?;
        let info = wallet.export_multisig_info().map_err(|e| e.to_string())?;
        Ok(hex::encode(&info))
    })
}

/// Import multisig info from co-signers.
///
/// - `infos_json`: JSON array of hex-encoded info strings
///
/// Returns the number of imported entries, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_multisig_import_info(
    handle: *mut c_void,
    infos_json: *const c_char,
) -> i32 {
    ffi_try(|| {
        let wallet = unsafe { borrow_handle_mut::<Wallet>(handle) }?;
        let json_str = unsafe { c_str_to_str(infos_json) }?;
        let hex_infos: Vec<String> =
            serde_json::from_str(json_str).map_err(|e| format!("invalid JSON array: {e}"))?;

        let infos: Vec<Vec<u8>> = hex_infos
            .iter()
            .map(|h| hex::decode(h).map_err(|e| format!("invalid hex: {e}")))
            .collect::<Result<Vec<_>, _>>()?;

        wallet
            .import_multisig_info(&infos)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
}

// =============================================================================
// Multisig Transaction Signing
// =============================================================================

/// Sign a multisig transaction set.
///
/// - `tx_set_json`: JSON-encoded `MultisigTxSet`
///
/// Returns the updated `MultisigTxSet` JSON with this signer's partial signature added.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_multisig_sign_tx(
    handle: *mut c_void,
    tx_set_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = unsafe { borrow_handle::<Wallet>(handle) }?;
        let json_str = unsafe { c_str_to_str(tx_set_json) }?;
        let mut tx_set: salvium_multisig::tx_set::MultisigTxSet =
            serde_json::from_str(json_str).map_err(|e| format!("invalid tx set JSON: {e}"))?;

        wallet
            .sign_multisig_tx(&mut tx_set)
            .map_err(|e| e.to_string())?;

        serde_json::to_string(&tx_set).map_err(|e| e.to_string())
    })
}

// =============================================================================
// Multisig Status
// =============================================================================

/// Check if the multisig wallet is ready for signing (KEX complete).
///
/// Returns 1 if ready, 0 if not ready, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_multisig_is_ready(handle: *mut c_void) -> i32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let wallet = unsafe { borrow_handle::<Wallet>(handle) }.ok()?;
        let status = wallet.get_multisig_status();
        Some(status.kex_complete)
    }));
    match result {
        Ok(Some(true)) => 1,
        Ok(Some(false)) => 0,
        _ => -1,
    }
}

/// Get the multisig wallet status as JSON.
///
/// Returns JSON with: `is_multisig`, `threshold`, `signer_count`, `kex_complete`,
/// `kex_round`, `multisig_pubkey`.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_multisig_status(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = unsafe { borrow_handle::<Wallet>(handle) }?;
        let status = wallet.get_multisig_status();
        serde_json::to_string(&status).map_err(|e| e.to_string())
    })
}
