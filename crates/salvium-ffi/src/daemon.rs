//! Daemon RPC handle and query functions.

use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::{ffi_try, ffi_try_ptr, ffi_try_string};
use crate::handles::{borrow_handle, drop_handle};
use crate::strings::c_str_to_str;

use salvium_rpc::{NodePool, PoolConfig};

/// Wrapper that pairs a NodePool with a usage counter.
///
/// `in_use` tracks how many long-running operations (sync) currently hold a
/// reference.  `salvium_daemon_close` waits for `in_use == 0` before dropping,
/// preventing use-after-free when the app closes the daemon while a sync is
/// still running on another thread.
pub(crate) struct DaemonHandle {
    pub pool: NodePool,
    pub in_use: AtomicUsize,
}

impl DaemonHandle {
    fn new(pool: NodePool) -> Self {
        Self { pool, in_use: AtomicUsize::new(0) }
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
/// Creates a NodePool with seed nodes for the detected network (based on port)
/// plus the provided URL as the primary/active node.
///
/// Returns an opaque daemon handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_connect(url: *const c_char) -> *mut c_void {
    ffi_try_ptr(|| {
        let url_str = unsafe { c_str_to_str(url) }?;
        let network = detect_network_from_url(url_str);
        let pool = NodePool::new(PoolConfig {
            network,
            primary_url: Some(url_str.to_string()),
            ..Default::default()
        });
        Ok(DaemonHandle::new(pool))
    })
}

/// Create a pool with seed nodes for a given network.
///
/// - `network`: 0 = Mainnet, 1 = Testnet, 2 = Stagenet
///
/// Returns an opaque daemon handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_pool_create(network: i32) -> *mut c_void {
    ffi_try_ptr(|| {
        let net = match network {
            0 => salvium_types::constants::Network::Mainnet,
            1 => salvium_types::constants::Network::Testnet,
            2 => salvium_types::constants::Network::Stagenet,
            _ => {
                return Err(format!(
                    "invalid network: {network} (expected 0=Mainnet, 1=Testnet, 2=Stagenet)"
                ))
            }
        };
        let pool = NodePool::new(PoolConfig {
            network: net,
            ..Default::default()
        });
        Ok(DaemonHandle::new(pool))
    })
}

/// Add a user node to the pool.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_add_node(
    handle: *mut c_void,
    url: *const c_char,
) -> i32 {
    ffi_try(|| {
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let url_str = unsafe { c_str_to_str(url) }?;
        let rt = crate::runtime();
        rt.block_on(dh.pool.add_node(url_str));
        Ok(())
    })
}

/// Get the URL of the currently active node.
///
/// Returns a string the caller must free with `salvium_string_free()`.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_active_node(handle: *mut c_void) -> *mut c_char {
    ffi_try_string(|| {
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let rt = crate::runtime();
        Ok(rt.block_on(dh.pool.active_url()))
    })
}

/// Add multiple user nodes to the pool.
///
/// - `urls_json` / `urls_json_len`: UTF-8 JSON array of URL strings,
///   e.g. `["http://node1:19081", "http://node2:19081"]`
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_add_nodes(
    handle: *mut c_void,
    urls_json: *const u8,
    urls_json_len: usize,
) -> i32 {
    ffi_try(|| {
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let json_slice = unsafe { std::slice::from_raw_parts(urls_json, urls_json_len) };
        let json_str = std::str::from_utf8(json_slice).map_err(|e| e.to_string())?;
        let urls: Vec<String> =
            serde_json::from_str(json_str).map_err(|e| format!("invalid URLs JSON: {e}"))?;
        let rt = crate::runtime();
        for url in &urls {
            rt.block_on(dh.pool.add_node(url.trim()));
        }
        Ok(())
    })
}

/// Force a race across all nodes to populate latency data.
///
/// Call once after connecting / adding nodes so that distributed fetch
/// can distribute work effectively. Blocks until all probes complete.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_force_race(handle: *mut c_void) -> i32 {
    ffi_try(|| {
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let rt = crate::runtime();
        rt.block_on(dh.pool.force_race());
        Ok(())
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
        let info = rt.block_on(dh.pool.get_info()).map_err(|e| e.to_string())?;
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
        rt.block_on(dh.pool.get_height()).ok()
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
        rt.block_on(dh.pool.is_synchronized()).ok()
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
        let fee = rt.block_on(dh.pool.get_fee_estimate(0)).map_err(|e| e.to_string())?;
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
        let info = rt.block_on(dh.pool.get_supply_info()).map_err(|e| e.to_string())?;
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
        let info = rt.block_on(dh.pool.get_yield_info()).map_err(|e| e.to_string())?;
        serde_json::to_string(&info).map_err(|e| e.to_string())
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Explorer endpoints
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch blocks by height for explorer use.
///
/// - `heights_json` / `heights_json_len`: UTF-8 JSON array of heights, e.g. `[100, 101, 102]`
/// - `out_buf` / `out_len`: caller-allocated output buffer
///
/// Returns bytes written to `out_buf`, or 0 on error (check `salvium_last_error()`).
///
/// Output JSON: `[{"height":N,"block_blob":"hex...","miner_tx_hash":"...","tx_hashes":["..."]}]`
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_get_blocks_by_height(
    handle: *mut c_void,
    heights_json: *const u8,
    heights_json_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> usize {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<usize, String> {
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let json_slice =
            unsafe { std::slice::from_raw_parts(heights_json, heights_json_len) };
        let json_str = std::str::from_utf8(json_slice).map_err(|e| e.to_string())?;
        let heights: Vec<u64> =
            serde_json::from_str(json_str).map_err(|e| format!("invalid heights JSON: {e}"))?;

        if heights.is_empty() {
            let out = b"[]";
            if out.len() > out_len {
                return Err("output buffer too small".into());
            }
            unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), out_buf, out.len()) };
            return Ok(out.len());
        }

        let rt = crate::runtime();

        // Determine if heights form a contiguous range for distributed fetch.
        let min_h = *heights.iter().min().unwrap();
        let max_h = *heights.iter().max().unwrap();
        let is_contiguous = (max_h - min_h + 1) as usize == heights.len();

        let (headers, bin_blocks) = if is_contiguous && heights.len() > 1 {
            let result = rt
                .block_on(dh.pool.fetch_batch_distributed(min_h, max_h))
                .map_err(|e| e.to_string())?;
            (result.headers, result.bin_blocks)
        } else {
            let (h, b) = rt.block_on(async {
                let h = dh.pool.get_block_headers_range(min_h, max_h).await;
                let b = dh.pool.get_blocks_by_height_bin(&heights).await;
                (h, b)
            });
            (h.map_err(|e| e.to_string())?, b.map_err(|e| e.to_string())?)
        };

        // Build JSON output array.
        let mut entries = Vec::with_capacity(heights.len());
        for (i, height) in heights.iter().enumerate() {
            let header = headers.iter().find(|h| h.height == *height);
            let block_blob_hex = if i < bin_blocks.len() {
                hex::encode(&bin_blocks[i].block)
            } else {
                String::new()
            };
            let miner_tx_hash = header
                .and_then(|h| h.miner_tx_hash.as_deref())
                .unwrap_or("");
            let tx_hashes: Vec<&str> = header
                .and_then(|h| h.extra.get("tx_hashes"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            entries.push(serde_json::json!({
                "height": height,
                "block_blob": block_blob_hex,
                "miner_tx_hash": miner_tx_hash,
                "tx_hashes": tx_hashes,
            }));
        }

        let json_out = serde_json::to_string(&entries).map_err(|e| e.to_string())?;
        let bytes = json_out.as_bytes();
        if bytes.len() > out_len {
            return Err(format!(
                "output buffer too small: need {} bytes, have {}",
                bytes.len(),
                out_len
            ));
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len()) };
        Ok(bytes.len())
    }));

    match result {
        Ok(Ok(n)) => n,
        Ok(Err(msg)) => {
            crate::error::set_last_error(&msg);
            0
        }
        Err(_) => {
            crate::error::set_last_error("panic in salvium_daemon_get_blocks_by_height");
            0
        }
    }
}

/// Fetch transactions by hash for explorer use.
///
/// - `hashes_json` / `hashes_json_len`: UTF-8 JSON array of tx hash strings
/// - `out_buf` / `out_len`: caller-allocated output buffer
///
/// Returns bytes written to `out_buf`, or 0 on error (check `salvium_last_error()`).
///
/// Output JSON: `[{"tx_hash":"...","as_hex":"..."}]`
#[no_mangle]
pub unsafe extern "C" fn salvium_daemon_get_transactions(
    handle: *mut c_void,
    hashes_json: *const u8,
    hashes_json_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> usize {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<usize, String> {
        let dh = unsafe { borrow_handle::<DaemonHandle>(handle) }?;
        let json_slice =
            unsafe { std::slice::from_raw_parts(hashes_json, hashes_json_len) };
        let json_str = std::str::from_utf8(json_slice).map_err(|e| e.to_string())?;
        let hashes: Vec<String> =
            serde_json::from_str(json_str).map_err(|e| format!("invalid hashes JSON: {e}"))?;

        if hashes.is_empty() {
            let out = b"[]";
            if out.len() > out_len {
                return Err("output buffer too small".into());
            }
            unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), out_buf, out.len()) };
            return Ok(out.len());
        }

        let rt = crate::runtime();
        let hash_refs: Vec<&str> = hashes.iter().map(|s| s.as_str()).collect();
        let txs = rt
            .block_on(dh.pool.get_transactions(&hash_refs, false))
            .map_err(|e| e.to_string())?;

        let entries: Vec<serde_json::Value> = txs
            .iter()
            .map(|tx| {
                serde_json::json!({
                    "tx_hash": tx.tx_hash,
                    "as_hex": tx.as_hex,
                })
            })
            .collect();

        let json_out = serde_json::to_string(&entries).map_err(|e| e.to_string())?;
        let bytes = json_out.as_bytes();
        if bytes.len() > out_len {
            return Err(format!(
                "output buffer too small: need {} bytes, have {}",
                bytes.len(),
                out_len
            ));
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len()) };
        Ok(bytes.len())
    }));

    match result {
        Ok(Ok(n)) => n,
        Ok(Err(msg)) => {
            crate::error::set_last_error(&msg);
            0
        }
        Err(_) => {
            crate::error::set_last_error("panic in salvium_daemon_get_transactions");
            0
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Detect network from the port in a daemon URL.
fn detect_network_from_url(url: &str) -> salvium_types::constants::Network {
    use salvium_rpc::ports;
    use salvium_types::constants::Network;

    // Try to extract port from URL.
    if let Some(port_str) = url.rsplit(':').next() {
        // Strip trailing path components.
        let port_str = port_str.split('/').next().unwrap_or(port_str);
        if let Ok(port) = port_str.parse::<u16>() {
            return match port {
                p if p == ports::DAEMON_TESTNET => Network::Testnet,
                p if p == ports::DAEMON_STAGENET => Network::Stagenet,
                _ => Network::Mainnet,
            };
        }
    }
    Network::Mainnet
}
