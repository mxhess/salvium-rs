//! Daemon RPC handle and query functions.

use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::{ffi_try_ptr, ffi_try_string};
use crate::handles::{borrow_handle, drop_handle};
use crate::strings::c_str_to_str;

use salvium_rpc::DaemonRpc;

/// Wrapper that pairs a DaemonRpc with a usage counter.
///
/// `in_use` tracks how many long-running operations (sync) currently hold a
/// reference.  `salvium_daemon_close` waits for `in_use == 0` before dropping,
/// preventing use-after-free when the app closes the daemon while a sync is
/// still running on another thread.
pub(crate) struct DaemonHandle {
    pub daemon: DaemonRpc,
    pub in_use: AtomicUsize,
}

impl DaemonHandle {
    fn new(daemon: DaemonRpc) -> Self {
        Self {
            daemon,
            in_use: AtomicUsize::new(0),
        }
    }
}

/// RAII guard that decrements `in_use` on drop.
pub(crate) struct DaemonUseGuard<'a>(pub &'a AtomicUsize);

impl Drop for DaemonUseGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

/// Connect to a daemon RPC endpoint.
///
/// - `url`: null-terminated URL (e.g. "http://127.0.0.1:19081")
///
/// Returns an opaque daemon handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_connect(url: *const c_char) -> *mut c_void {
    ffi_try_ptr(|| {
        let url_str = unsafe { c_str_to_str(url) }?;
        Ok(DaemonHandle::new(DaemonRpc::new(url_str)))
    })
}

/// Close a daemon handle.
///
/// If the daemon is in use by a sync operation, this blocks until the sync
/// finishes before dropping. Safe to call from any thread.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_close(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    let dh = unsafe { &*(handle as *const DaemonHandle) };

    // Wait for outstanding users (sync) to finish.
    while dh.in_use.load(Ordering::Acquire) > 0 {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    drop_handle::<DaemonHandle>(handle);
}

/// Get daemon info as JSON.
///
/// Returns a JSON string with height, difficulty, sync status, etc.
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_get_info(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let rt = crate::runtime();
        let info = rt
            .block_on(dh.daemon.get_info())
            .map_err(|e| e.to_string())?;
        serde_json::to_string(&info).map_err(|e| e.to_string())
    })
}

/// Get the current daemon height.
///
/// Returns the height, or `u64::MAX` on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_get_height(handle: *mut c_void) -> u64 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }.ok()?;
        let rt = crate::runtime();
        rt.block_on(dh.daemon.get_height()).ok()
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
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }.ok()?;
        let rt = crate::runtime();
        rt.block_on(dh.daemon.is_synchronized()).ok()
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
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let rt = crate::runtime();
        let fee = rt
            .block_on(dh.daemon.get_fee_estimate(0))
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
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let rt = crate::runtime();
        let info = rt
            .block_on(dh.daemon.get_supply_info())
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
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let rt = crate::runtime();
        let info = rt
            .block_on(dh.daemon.get_yield_info())
            .map_err(|e| e.to_string())?;
        serde_json::to_string(&info).map_err(|e| e.to_string())
    })
}
