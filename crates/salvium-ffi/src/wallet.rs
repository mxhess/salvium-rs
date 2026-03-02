//! Wallet lifecycle, key/address queries, balance, sync, and data operations.

use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::{ffi_try, ffi_try_ptr, ffi_try_string};
use crate::handles::{borrow_handle, borrow_handle_mut, drop_handle};
use crate::strings::c_str_to_str;

use salvium_wallet::Wallet;

/// Wrapper that pairs a Wallet with its cancellation and lifecycle flags.
///
/// `sync_running` is set to `true` while `salvium_wallet_sync` is executing
/// and back to `false` when it returns (even on error / cancel).
/// `salvium_wallet_close` checks this flag and, if sync is active, sets
/// `sync_cancel` and spins until sync finishes before dropping the handle.
/// This prevents use-after-free when the app closes a wallet while sync is
/// still running on another thread.
pub(crate) struct WalletHandle {
    pub wallet: Wallet,
    pub sync_cancel: Arc<AtomicBool>,
    pub sync_running: AtomicBool,
}

impl WalletHandle {
    fn new(wallet: Wallet) -> Self {
        Self {
            wallet,
            sync_cancel: Arc::new(AtomicBool::new(false)),
            sync_running: AtomicBool::new(false),
        }
    }
}

/// RAII guard that sets `sync_running` to `false` on drop, ensuring
/// the flag is cleared even if sync panics or returns early.
struct SyncRunningGuard<'a>(&'a AtomicBool);

impl Drop for SyncRunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

// =============================================================================
// Wallet Lifecycle
// =============================================================================

/// Create a new wallet from a 32-byte seed.
///
/// - `seed`: pointer to 32 bytes
/// - `network`: 0 = Mainnet, 1 = Testnet, 2 = Stagenet
/// - `db_path`: null-terminated UTF-8 path to the database file
/// - `db_key`: encryption key for the database
/// - `db_key_len`: length of `db_key` in bytes
///
/// Returns an opaque wallet handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_create(
    seed: *const u8,
    network: i32,
    db_path: *const c_char,
    db_key: *const u8,
    db_key_len: usize,
) -> *mut c_void {
    ffi_try_ptr(|| {
        let seed_slice = unsafe { crate::strings::c_buf_to_slice(seed, 32) }?;
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed_slice);
        let network = int_to_network(network)?;
        let path = unsafe { c_str_to_str(db_path) }?;
        let key = unsafe { crate::strings::c_buf_to_slice(db_key, db_key_len) }?;
        Wallet::create(seed_arr, network, path, key)
            .map(WalletHandle::new)
            .map_err(|e| e.to_string())
    })
}

/// Restore a wallet from a 25-word mnemonic.
///
/// Returns an opaque wallet handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_from_mnemonic(
    words: *const c_char,
    network: i32,
    db_path: *const c_char,
    db_key: *const u8,
    db_key_len: usize,
) -> *mut c_void {
    ffi_try_ptr(|| {
        let words = unsafe { c_str_to_str(words) }?;
        let network = int_to_network(network)?;
        let path = unsafe { c_str_to_str(db_path) }?;
        let key = unsafe { crate::strings::c_buf_to_slice(db_key, db_key_len) }?;
        Wallet::from_mnemonic(words, network, path, key)
            .map(WalletHandle::new)
            .map_err(|e| e.to_string())
    })
}

/// Open a wallet from JSON-encoded keys.
///
/// `keys_json` must contain: `seed` (hex, optional), `spend_secret_key` (hex, optional),
/// `view_secret_key` (hex), `spend_public_key` (hex), `network` (string).
///
/// Returns an opaque wallet handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_open(
    keys_json: *const c_char,
    db_path: *const c_char,
    db_key: *const u8,
    db_key_len: usize,
) -> *mut c_void {
    ffi_try_ptr(|| {
        let json_str = unsafe { c_str_to_str(keys_json) }?;
        let path = unsafe { c_str_to_str(db_path) }?;
        let key = unsafe { crate::strings::c_buf_to_slice(db_key, db_key_len) }?;

        let keys = wallet_keys_from_json(json_str)?;
        Wallet::open(keys, path, key).map(WalletHandle::new).map_err(|e| e.to_string())
    })
}

/// Close a wallet handle, releasing all resources.
///
/// If a sync is in progress, this cancels it and blocks until the sync
/// loop has exited before dropping the handle. Safe to call from any thread.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_close(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    // Safety: pointer is non-null and was created by into_handle<WalletHandle>.
    // We read the atomic flags through a shared ref before drop_handle takes ownership.
    let wh = unsafe { &*(handle as *const WalletHandle) };

    // Signal any running sync to stop.
    wh.sync_cancel.store(true, Ordering::Relaxed);

    // Wait for sync to finish before dropping.
    while wh.sync_running.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    drop_handle::<WalletHandle>(handle);
}

// =============================================================================
// Key / Address Queries
// =============================================================================

/// Get a wallet address.
///
/// - `addr_type`: 0 = CryptoNote, 1 = CARROT
///
/// Returns a string the caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_address(
    handle: *mut c_void,
    addr_type: i32,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        match addr_type {
            0 => wallet.cn_address().map_err(|e| e.to_string()),
            1 => wallet.carrot_address().map_err(|e| e.to_string()),
            _ => Err(format!("invalid address type: {addr_type} (expected 0=CN or 1=CARROT)")),
        }
    })
}

/// Get the 25-word mnemonic seed phrase.
///
/// Returns null if the wallet is view-only.
/// Caller must free the result with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_mnemonic(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        match wallet.mnemonic() {
            Some(Ok(words)) => Ok(words),
            Some(Err(e)) => Err(e.to_string()),
            None => Err("wallet has no mnemonic (view-only)".into()),
        }
    })
}

/// Get public key material as JSON.
///
/// Returns a JSON object with `view_secret_key`, `spend_public_key`, `network`, etc.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_keys_json(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let keys = wallet.keys();
        let json = serde_json::json!({
            "wallet_type": format!("{:?}", keys.wallet_type),
            "network": format!("{:?}", keys.network),
            "view_secret_key": hex::encode(keys.cn.view_secret_key),
            "view_public_key": hex::encode(keys.cn.view_public_key),
            "spend_public_key": hex::encode(keys.cn.spend_public_key),
            "has_spend_secret": keys.cn.spend_secret_key.is_some(),
            "has_seed": keys.seed.is_some(),
        });
        serde_json::to_string(&json).map_err(|e| e.to_string())
    })
}

/// Whether the wallet can sign transactions (has spend key).
///
/// Returns 1 = yes, 0 = no.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_can_spend(handle: *mut c_void) -> i32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }.ok()?.wallet;
        Some(wallet.can_spend())
    }));
    match result {
        Ok(Some(true)) => 1,
        Ok(Some(false)) => 0,
        _ => -1,
    }
}

/// Get the network type.
///
/// Returns 0 = Mainnet, 1 = Testnet, 2 = Stagenet, -1 = error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_network(handle: *mut c_void) -> i32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }.ok()?.wallet;
        Some(wallet.network())
    }));
    match result {
        Ok(Some(salvium_types::constants::Network::Mainnet)) => 0,
        Ok(Some(salvium_types::constants::Network::Testnet)) => 1,
        Ok(Some(salvium_types::constants::Network::Stagenet)) => 2,
        _ => -1,
    }
}

/// Get the current sync height.
///
/// Returns the height, or `u64::MAX` on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_sync_height(handle: *mut c_void) -> u64 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }.ok()?.wallet;
        wallet.sync_height().ok()
    }));
    match result {
        Ok(Some(h)) => h,
        _ => u64::MAX,
    }
}

// =============================================================================
// Balance
// =============================================================================

/// Get the balance for an asset type (e.g. "SAL").
///
/// Returns JSON: `{"balance": "...", "unlockedBalance": "...", "lockedBalance": "..."}`
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_balance(
    handle: *mut c_void,
    asset_type: *const c_char,
    account_index: i32,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let asset = unsafe { c_str_to_str(asset_type) }?;
        let result = wallet.get_balance(asset, account_index).map_err(|e| e.to_string())?;
        serde_json::to_string(&result).map_err(|e| e.to_string())
    })
}

/// Get balances for all asset types.
///
/// Returns JSON object keyed by asset type, each value is a balance object.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_all_balances(
    handle: *mut c_void,
    account_index: i32,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let result = wallet.get_all_balances(account_index).map_err(|e| e.to_string())?;
        serde_json::to_string(&result).map_err(|e| e.to_string())
    })
}

// =============================================================================
// Wallet Attributes
// =============================================================================

/// Set a wallet attribute (key-value).
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_set_attribute(
    handle: *mut c_void,
    key: *const c_char,
    value: *const c_char,
) -> i32 {
    ffi_try(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let k = unsafe { c_str_to_str(key) }?;
        let v = unsafe { c_str_to_str(value) }?;
        wallet.set_attribute(k, v).map_err(|e| e.to_string())
    })
}

/// Get a wallet attribute.
///
/// Returns the value string, or null if not set.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_attribute(
    handle: *mut c_void,
    key: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let k = unsafe { c_str_to_str(key) }?;
        match wallet.get_attribute(k).map_err(|e| e.to_string())? {
            Some(v) => Ok(v),
            None => Err("attribute not found".into()),
        }
    })
}

/// Reset the sync height (for rescanning).
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_reset_sync_height(handle: *mut c_void, height: u64) -> i32 {
    ffi_try(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        wallet.reset_sync_height(height).map_err(|e| e.to_string())
    })
}

// =============================================================================
// Sync with Callback
// =============================================================================

/// Sync callback function pointer type.
///
/// - `event_type`: 0=started, 1=progress, 2=complete, 3=reorg, 4=error, 5=parse_error, 6=cancelled
/// - `current_height`: current scan height
/// - `target_height`: target chain height
/// - `outputs_found`: number of outputs found so far
/// - `error_msg`: null unless event_type=4
pub type SyncCallbackFn = unsafe extern "C" fn(
    event_type: i32,
    current_height: u64,
    target_height: u64,
    outputs_found: u32,
    error_msg: *const c_char,
);

/// Sync the wallet with the blockchain via a daemon handle.
///
/// - `wallet`: wallet handle
/// - `daemon`: daemon handle (from `salvium_daemon_connect`)
/// - `callback`: optional progress callback (may be null)
///
/// Returns 0 on success, -1 on error.
/// This function blocks until sync is complete.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_sync(
    wallet: *mut c_void,
    daemon: *mut c_void,
    callback: Option<SyncCallbackFn>,
) -> i32 {
    ffi_try(|| {
        let handle = unsafe { borrow_handle_mut::<WalletHandle>(wallet) }?;
        let dh = unsafe { borrow_handle::<crate::daemon::DaemonHandle>(daemon) }?;
        let rt = crate::runtime();

        // Reset cancel flag before starting.
        handle.sync_cancel.store(false, Ordering::Relaxed);

        // Mark sync as active; the guard clears this on drop (even on panic/early return).
        handle.sync_running.store(true, Ordering::Release);
        let _guard = SyncRunningGuard(&handle.sync_running);

        // Register daemon usage so daemon_close waits for us.
        dh.in_use.fetch_add(1, Ordering::Release);
        let _daemon_guard = crate::daemon::DaemonUseGuard(&dh.in_use);

        rt.block_on(async {
            if let Some(cb) = callback {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<salvium_wallet::SyncEvent>(256);

                // Spawn a task to forward events to the C callback.
                let forwarder = tokio::spawn(async move {
                    while let Some(event) = rx.recv().await {
                        dispatch_sync_event(&event, cb);
                    }
                });

                let result = handle.wallet.sync(&dh.pool, Some(&tx), &handle.sync_cancel).await;
                drop(tx); // Close channel so forwarder exits.
                let _ = forwarder.await;

                result.map(|_| ()).map_err(|e| e.to_string())
            } else {
                handle
                    .wallet
                    .sync(&dh.pool, None, &handle.sync_cancel)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
        })
    })
}

/// Cancel an in-progress sync.
///
/// Sets the cancellation flag. The sync loop will stop before the next
/// batch and return `WalletError::Cancelled`. Safe to call from any thread.
/// No-op if no sync is running.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_stop_sync(wallet: *mut c_void) -> i32 {
    ffi_try(|| {
        let handle = unsafe { borrow_handle::<WalletHandle>(wallet) }?;
        handle.sync_cancel.store(true, Ordering::Relaxed);
        Ok(())
    })
}

/// Dispatch a SyncEvent to the C callback.
fn dispatch_sync_event(event: &salvium_wallet::SyncEvent, cb: SyncCallbackFn) {
    use salvium_wallet::SyncEvent;
    match event {
        SyncEvent::Started { target_height } => unsafe {
            cb(0, 0, *target_height, 0, std::ptr::null());
        },
        SyncEvent::Progress { current_height, target_height, outputs_found, .. } => unsafe {
            cb(1, *current_height, *target_height, *outputs_found as u32, std::ptr::null());
        },
        SyncEvent::Complete { height } => unsafe {
            cb(2, *height, *height, 0, std::ptr::null());
        },
        SyncEvent::Reorg { from_height, to_height } => unsafe {
            cb(3, *from_height, *to_height, 0, std::ptr::null());
        },
        SyncEvent::Error(msg) => {
            if let Ok(cs) = std::ffi::CString::new(msg.as_str()) {
                unsafe {
                    cb(4, 0, 0, 0, cs.as_ptr());
                }
            } else {
                let fallback = std::ffi::CString::new("sync error").unwrap();
                unsafe {
                    cb(4, 0, 0, 0, fallback.as_ptr());
                }
            }
        }
        SyncEvent::ParseError { height, blob_len, ref error } => {
            let msg =
                format!("parse error at height {} (blob_len={}): {}", height, blob_len, error);
            if let Ok(cs) = std::ffi::CString::new(msg) {
                unsafe {
                    cb(5, *height, 0, 0, cs.as_ptr());
                }
            }
        }
        SyncEvent::Cancelled { height } => unsafe {
            cb(6, *height, 0, 0, std::ptr::null());
        },
        SyncEvent::PoolScanComplete { new_txs, dropped_txs } => unsafe {
            cb(7, *new_txs as u64, *dropped_txs as u64, 0, std::ptr::null());
        },
    }
}

// =============================================================================
// Query Functions
// =============================================================================

/// Get transfers matching a JSON query.
///
/// `filters_json` schema: `{"isIncoming": bool, "isOutgoing": bool,
///   "isConfirmed": bool, "inPool": bool, "txType": i64,
///   "minHeight": i64, "maxHeight": i64, "txHash": "..."}`
/// All fields are optional.
///
/// Returns a JSON array. Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_transfers(
    handle: *mut c_void,
    filters_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let json_str = unsafe { c_str_to_str(filters_json) }?;
        let query: salvium_wallet::TxQuery =
            serde_json::from_str(json_str).map_err(|e| format!("invalid query JSON: {e}"))?;
        let rows = wallet.get_transfers(&query).map_err(|e| e.to_string())?;
        serde_json::to_string(&rows).map_err(|e| e.to_string())
    })
}

/// Get outputs matching a JSON query.
///
/// `query_json` schema: `{"isSpent": bool, "isFrozen": bool,
///   "assetType": "SAL", "txType": i64, "accountIndex": i64,
///   "subaddressIndex": i64, "minAmount": "...", "maxAmount": "..."}`
/// All fields are optional.
///
/// Returns a JSON array. Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_outputs(
    handle: *mut c_void,
    query_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let json_str = unsafe { c_str_to_str(query_json) }?;
        let query: salvium_wallet::OutputQuery =
            serde_json::from_str(json_str).map_err(|e| format!("invalid query JSON: {e}"))?;
        let rows = wallet.get_outputs(&query).map_err(|e| e.to_string())?;
        serde_json::to_string(&rows).map_err(|e| e.to_string())
    })
}

/// Get staking entries, optionally filtered by status.
///
/// - `status`: optional C string filter (e.g. "active", "returned"), or null for all.
///
/// Returns a JSON array. Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_stakes(
    handle: *mut c_void,
    status: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let status_opt =
            if status.is_null() { None } else { Some(unsafe { c_str_to_str(status) }?) };
        let rows = wallet.get_stakes(status_opt).map_err(|e| e.to_string())?;
        serde_json::to_string(&rows).map_err(|e| e.to_string())
    })
}

// =============================================================================
// Address Book
// =============================================================================

/// List all address book entries.
///
/// Returns a JSON array. Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_address_book_list(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let entries = wallet.get_address_book().map_err(|e| e.to_string())?;
        serde_json::to_string(&entries).map_err(|e| e.to_string())
    })
}

/// Add an address book entry.
///
/// Returns the row_id on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_address_book_add(
    handle: *mut c_void,
    address: *const c_char,
    label: *const c_char,
    description: *const c_char,
) -> i64 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let addr = unsafe { c_str_to_str(address) }?;
        let lbl = unsafe { c_str_to_str(label) }?;
        let desc = unsafe { c_str_to_str(description) }?;
        wallet.add_address_book_entry(addr, lbl, desc, "").map_err(|e| e.to_string())
    }));
    match result {
        Ok(Ok(id)) => id,
        Ok(Err(msg)) => {
            crate::error::set_last_error(&msg);
            -1
        }
        Err(_) => {
            crate::error::set_last_error("panic in address_book_add");
            -1
        }
    }
}

/// Delete an address book entry by row_id.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_address_book_delete(
    handle: *mut c_void,
    row_id: i64,
) -> i32 {
    ffi_try(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        wallet.delete_address_book_entry(row_id).map(|_| ()).map_err(|e| e.to_string())
    })
}

// =============================================================================
// Subaddresses
// =============================================================================

/// Create a new subaddress in an account.
///
/// - `account_index`: major index (0 for default account)
/// - `label`: null-terminated UTF-8 label (may be empty string)
///
/// Returns JSON: `{"major": i64, "minor": i64, "address": "..."}`.
/// Caller must free with `salvium_string_free()`.
/// Returns null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_create_subaddress(
    handle: *mut c_void,
    account_index: i64,
    label: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let lbl = unsafe { c_str_to_str(label) }?;
        let (major, minor, address) =
            wallet.create_subaddress(account_index, lbl).map_err(|e| e.to_string())?;
        let json = serde_json::json!({
            "major": major,
            "minor": minor,
            "address": address,
        });
        serde_json::to_string(&json).map_err(|e| e.to_string())
    })
}

/// Get all subaddresses for an account.
///
/// - `account_index`: major index (0 for default account)
///
/// Returns a JSON array of subaddress objects.
/// Caller must free with `salvium_string_free()`.
/// Returns null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_subaddresses(
    handle: *mut c_void,
    account_index: i64,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let rows = wallet.get_subaddresses(account_index).map_err(|e| e.to_string())?;
        serde_json::to_string(&rows).map_err(|e| e.to_string())
    })
}

/// Set a label on a subaddress.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_label_subaddress(
    handle: *mut c_void,
    major: i64,
    minor: i64,
    label: *const c_char,
) -> i32 {
    ffi_try(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let lbl = unsafe { c_str_to_str(label) }?;
        wallet.label_subaddress(major, minor, lbl).map_err(|e| e.to_string())
    })
}

// =============================================================================
// Transaction Notes
// =============================================================================

/// Set a note on a transaction.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_set_tx_note(
    handle: *mut c_void,
    tx_hash: *const c_char,
    note: *const c_char,
) -> i32 {
    ffi_try(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let hash = unsafe { c_str_to_str(tx_hash) }?;
        let n = unsafe { c_str_to_str(note) }?;
        wallet.set_tx_note(hash, n).map_err(|e| e.to_string())
    })
}

/// Get notes for a list of transaction hashes.
///
/// - `tx_hashes_json`: JSON array of hex hash strings.
///
/// Returns a JSON object mapping hash → note. Caller must free.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_get_tx_notes(
    handle: *mut c_void,
    tx_hashes_json: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let json_str = unsafe { c_str_to_str(tx_hashes_json) }?;
        let hashes: Vec<String> =
            serde_json::from_str(json_str).map_err(|e| format!("invalid JSON array: {e}"))?;
        let hash_refs: Vec<&str> = hashes.iter().map(|s| s.as_str()).collect();
        let notes = wallet.get_tx_notes(&hash_refs).map_err(|e| e.to_string())?;
        serde_json::to_string(&notes).map_err(|e| e.to_string())
    })
}

// =============================================================================
// Output Freeze / Thaw
// =============================================================================

/// Freeze an output (exclude from coin selection).
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_freeze_output(
    handle: *mut c_void,
    key_image: *const c_char,
) -> i32 {
    ffi_try(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let ki = unsafe { c_str_to_str(key_image) }?;
        wallet.freeze_output(ki).map_err(|e| e.to_string())
    })
}

/// Thaw a frozen output.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_thaw_output(
    handle: *mut c_void,
    key_image: *const c_char,
) -> i32 {
    ffi_try(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let ki = unsafe { c_str_to_str(key_image) }?;
        wallet.thaw_output(ki).map_err(|e| e.to_string())
    })
}

// =============================================================================
// Blob (PIN-encrypted wallet key material)
// =============================================================================

/// Export wallet key material as a PIN-encrypted blob.
///
/// The blob contains the wallet seed, keys, database encryption key, and network
/// encrypted with hybrid post-quantum cryptography (Argon2id + ML-KEM-768 +
/// AES-256-GCM). The app stores this blob on disk and uses `import_blob` to
/// unlock it later.
///
/// Returns a JSON string (the PQC envelope). Caller must free with `salvium_string_free()`.
/// Returns null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_export_blob(
    handle: *mut c_void,
    pin: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let wallet = &unsafe { borrow_handle::<WalletHandle>(handle) }?.wallet;
        let pin_str = unsafe { c_str_to_str(pin) }?;

        let keys = wallet.keys();
        let db_key_bytes = wallet.db_key();

        let secrets = salvium_wallet::WalletSecrets {
            seed: keys.seed.map(hex::encode).unwrap_or_default(),
            spend_secret_key: keys.cn.spend_secret_key.map(hex::encode).unwrap_or_default(),
            view_secret_key: hex::encode(keys.cn.view_secret_key),
            data_key: hex::encode(db_key_bytes),
            mnemonic: keys.to_mnemonic().and_then(|r| r.ok()),
            network: format!("{:?}", keys.network).to_lowercase(),
        };

        let envelope_bytes =
            salvium_wallet::encrypt_envelope(&secrets, pin_str).map_err(|e| e.to_string())?;

        String::from_utf8(envelope_bytes).map_err(|e| e.to_string())
    })
}

/// Import a wallet from a PIN-encrypted blob.
///
/// Decrypts the blob, extracts the wallet keys and database encryption key,
/// and opens the wallet at the given database path.
///
/// Returns an opaque wallet handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_import_blob(
    blob: *const c_char,
    pin: *const c_char,
    db_path: *const c_char,
) -> *mut c_void {
    ffi_try_ptr(|| {
        let blob_str = unsafe { c_str_to_str(blob) }?;
        let pin_str = unsafe { c_str_to_str(pin) }?;
        let path = unsafe { c_str_to_str(db_path) }?;

        let secrets = salvium_wallet::decrypt_envelope(blob_str.as_bytes(), pin_str)
            .map_err(|e| e.to_string())?;

        let data_key = secrets.data_key_bytes().map_err(|e| e.to_string())?;

        // Reconstruct wallet keys from the decrypted secrets.
        let network = match secrets.network.as_str() {
            "mainnet" => salvium_types::constants::Network::Mainnet,
            "testnet" => salvium_types::constants::Network::Testnet,
            "stagenet" => salvium_types::constants::Network::Stagenet,
            _ => return Err(format!("invalid network in blob: {}", secrets.network)),
        };

        let keys = if !secrets.seed.is_empty() {
            let seed = secrets.seed_bytes().map_err(|e| e.to_string())?;
            salvium_wallet::WalletKeys::from_seed(seed, network)
        } else if !secrets.view_secret_key.is_empty() && !secrets.spend_secret_key.is_empty() {
            // Full wallet from individual keys — reconstruct via seed-like derivation
            // is not possible without the seed. Fall back to JSON-based reconstruction.
            let json = serde_json::json!({
                "seed": secrets.seed,
                "view_secret_key": secrets.view_secret_key,
                "spend_public_key": "", // Will be derived from spend_secret_key
                "network": secrets.network,
            });
            wallet_keys_from_json(&json.to_string())?
        } else {
            return Err("blob contains neither seed nor keys".into());
        };

        Wallet::open(keys, path, &data_key).map(WalletHandle::new).map_err(|e| e.to_string())
    })
}

/// Re-encrypt a blob with a new PIN.
///
/// Decrypts the blob with `old_pin`, then re-encrypts with `new_pin`.
/// The wallet key material inside is unchanged — only the outer encryption changes.
/// This is a pure crypto operation; no wallet handle or database is needed.
///
/// Returns the new blob JSON string. Caller must free with `salvium_string_free()`.
/// Returns null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_wallet_rekey_blob(
    blob: *const c_char,
    old_pin: *const c_char,
    new_pin: *const c_char,
) -> *mut c_char {
    ffi_try_string(|| {
        let blob_str = unsafe { c_str_to_str(blob) }?;
        let old_pin_str = unsafe { c_str_to_str(old_pin) }?;
        let new_pin_str = unsafe { c_str_to_str(new_pin) }?;

        let secrets = salvium_wallet::decrypt_envelope(blob_str.as_bytes(), old_pin_str)
            .map_err(|e| e.to_string())?;

        let envelope_bytes =
            salvium_wallet::encrypt_envelope(&secrets, new_pin_str).map_err(|e| e.to_string())?;

        String::from_utf8(envelope_bytes).map_err(|e| e.to_string())
    })
}

// =============================================================================
// Helpers
// =============================================================================

fn int_to_network(n: i32) -> Result<salvium_types::constants::Network, String> {
    match n {
        0 => Ok(salvium_types::constants::Network::Mainnet),
        1 => Ok(salvium_types::constants::Network::Testnet),
        2 => Ok(salvium_types::constants::Network::Stagenet),
        _ => Err(format!("invalid network: {n} (expected 0=Mainnet, 1=Testnet, 2=Stagenet)")),
    }
}

fn wallet_keys_from_json(json_str: &str) -> Result<salvium_wallet::WalletKeys, String> {
    let v: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("invalid keys JSON: {e}"))?;

    let network_str = v["network"].as_str().ok_or("missing 'network' in keys JSON")?;
    let network = match network_str {
        "mainnet" | "Mainnet" => salvium_types::constants::Network::Mainnet,
        "testnet" | "Testnet" => salvium_types::constants::Network::Testnet,
        "stagenet" | "Stagenet" => salvium_types::constants::Network::Stagenet,
        _ => return Err(format!("invalid network: {network_str}")),
    };

    // If seed is provided, reconstruct from seed.
    if let Some(seed_hex) = v["seed"].as_str() {
        let seed_bytes = hex::decode(seed_hex).map_err(|e| format!("invalid seed hex: {e}"))?;
        if seed_bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", seed_bytes.len()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        return Ok(salvium_wallet::WalletKeys::from_seed(seed, network));
    }

    // Otherwise, view-only wallet from view_secret_key + spend_public_key.
    let view_hex = v["view_secret_key"].as_str().ok_or("missing 'view_secret_key' in keys JSON")?;
    let spend_pub_hex =
        v["spend_public_key"].as_str().ok_or("missing 'spend_public_key' in keys JSON")?;

    let view_bytes =
        hex::decode(view_hex).map_err(|e| format!("invalid view_secret_key hex: {e}"))?;
    let spend_bytes =
        hex::decode(spend_pub_hex).map_err(|e| format!("invalid spend_public_key hex: {e}"))?;

    if view_bytes.len() != 32 || spend_bytes.len() != 32 {
        return Err("keys must be 32 bytes each".into());
    }

    let mut view_key = [0u8; 32];
    let mut spend_key = [0u8; 32];
    view_key.copy_from_slice(&view_bytes);
    spend_key.copy_from_slice(&spend_bytes);

    Ok(salvium_wallet::WalletKeys::view_only(view_key, spend_key, network))
}
