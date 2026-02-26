//! C ABI wrappers for WASM static library consumption.
//!
//! These functions use the caller-provided buffer pattern: the caller passes
//! `out_buf` / `out_len`, and the function writes a UTF-8 result string into
//! the buffer and returns the number of bytes written (0 on error or null
//! pointers).
//!
//! Intended consumer: Cloudflare Worker linking `libsalvium_crypto.a` directly
//! (no wasm-bindgen / JS glue).

use core::slice;

/// Helper: write `src` into the caller's buffer, truncating if necessary.
/// Returns bytes actually written, or 0 if pointers are null.
unsafe fn write_to_buf(src: &[u8], out_buf: *mut u8, out_len: usize) -> usize {
    if out_buf.is_null() || out_len == 0 {
        return 0;
    }
    let n = src.len().min(out_len);
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), out_buf, n);
    }
    n
}

/// Parse a complete transaction from raw bytes to JSON.
///
/// Writes the JSON string into `out_buf` (up to `out_len` bytes) and returns
/// the number of bytes written. Returns 0 on error or null pointers.
#[no_mangle]
pub unsafe extern "C" fn salvium_parse_transaction_bytes(
    data: *const u8,
    data_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> usize {
    if data.is_null() || data_len == 0 {
        return 0;
    }
    let input = unsafe { slice::from_raw_parts(data, data_len) };
    let json = crate::parse_transaction_bytes(input);
    unsafe { write_to_buf(json.as_bytes(), out_buf, out_len) }
}

/// Parse a complete block from raw bytes to JSON.
///
/// Writes the JSON string into `out_buf` (up to `out_len` bytes) and returns
/// the number of bytes written. Returns 0 on error or null pointers.
#[no_mangle]
pub unsafe extern "C" fn salvium_parse_block_bytes(
    data: *const u8,
    data_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> usize {
    if data.is_null() || data_len == 0 {
        return 0;
    }
    let input = unsafe { slice::from_raw_parts(data, data_len) };
    let json = crate::parse_block_bytes(input);
    unsafe { write_to_buf(json.as_bytes(), out_buf, out_len) }
}

/// Get the human-readable name for a transaction type code.
///
/// Writes the name string into `out_buf` (up to `out_len` bytes) and returns
/// the number of bytes written. Returns 0 on null pointer.
#[no_mangle]
pub unsafe extern "C" fn salvium_tx_type_name(
    tx_type: u32,
    out_buf: *mut u8,
    out_len: usize,
) -> usize {
    let name = crate::wasm_tx_type_name(tx_type as u8);
    unsafe { write_to_buf(name.as_bytes(), out_buf, out_len) }
}
