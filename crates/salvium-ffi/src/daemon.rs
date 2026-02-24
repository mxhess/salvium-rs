//! Daemon RPC handle and query functions.

use std::ffi::{c_char, c_void};

use crate::error::{ffi_try_ptr, ffi_try_string};
use crate::handles::{borrow_handle, drop_handle};
use crate::strings::c_str_to_str;

use salvium_rpc::DaemonRpc;

/// Connect to a daemon RPC endpoint.
///
/// - `url`: null-terminated URL (e.g. "http://127.0.0.1:19081")
///
/// Returns an opaque daemon handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_connect(url: *const c_char) -> *mut c_void {
    ffi_try_ptr(|| {
        let url_str = unsafe { c_str_to_str(url) }?;
        Ok(DaemonRpc::new(url_str))
    })
}

/// Close a daemon handle.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_close(handle: *mut c_void) {
    drop_handle::<DaemonRpc>(handle);
}

/// Get daemon info as JSON.
///
/// Returns a JSON string with height, difficulty, sync status, etc.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_get_info(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let daemon = unsafe { borrow_handle::<DaemonRpc>(handle) }?;
        let rt = crate::runtime();
        let info = rt.block_on(daemon.get_info()).map_err(|e| e.to_string())?;
        serde_json::to_string(&info).map_err(|e| e.to_string())
    })
}

/// Get the current daemon height.
///
/// Returns the height, or `u64::MAX` on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_get_height(handle: *mut c_void) -> u64 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let daemon = unsafe { borrow_handle::<DaemonRpc>(handle) }.ok()?;
        let rt = crate::runtime();
        rt.block_on(daemon.get_height()).ok()
    }));
    match result {
        Ok(Some(h)) => h,
        _ => u64::MAX,
    }
}

/// Check if the daemon is synchronized.
///
/// Returns 1 = yes, 0 = no, -1 = error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_is_synchronized(handle: *mut c_void) -> i32 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let daemon = unsafe { borrow_handle::<DaemonRpc>(handle) }.ok()?;
        let rt = crate::runtime();
        rt.block_on(daemon.is_synchronized()).ok()
    }));
    match result {
        Ok(Some(true)) => 1,
        Ok(Some(false)) => 0,
        _ => -1,
    }
}

/// Get fee estimate as JSON.
///
/// Returns JSON: `{"fee": u64, "quantization_mask": u64, "status": "..."}`
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_get_fee_estimate(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let daemon = unsafe { borrow_handle::<DaemonRpc>(handle) }?;
        let rt = crate::runtime();
        let fee = rt
            .block_on(daemon.get_fee_estimate(0))
            .map_err(|e| e.to_string())?;
        serde_json::to_string(&fee).map_err(|e| e.to_string())
    })
}

/// Get supply info as JSON (circulating, staked, emission).
///
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_get_supply_info(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let daemon = unsafe { borrow_handle::<DaemonRpc>(handle) }?;
        let rt = crate::runtime();
        let info = rt
            .block_on(daemon.get_supply_info())
            .map_err(|e| e.to_string())?;
        serde_json::to_string(&info).map_err(|e| e.to_string())
    })
}

/// Get yield info as JSON (staking rewards).
///
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_get_yield_info(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let daemon = unsafe { borrow_handle::<DaemonRpc>(handle) }?;
        let rt = crate::runtime();
        let info = rt
            .block_on(daemon.get_yield_info())
            .map_err(|e| e.to_string())?;
        serde_json::to_string(&info).map_err(|e| e.to_string())
    })
}
