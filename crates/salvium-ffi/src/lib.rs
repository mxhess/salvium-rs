//! C FFI shim for salvium wallet, daemon, and transaction operations.
//!
//! Provides an opaque handle-based API for mobile/desktop integrations
//! (Flutter, React Native, Swift, Kotlin). Complex types are serialized
//! as JSON strings; errors use thread-local storage.
//!
//! # Safety
//!
//! All `unsafe extern "C"` functions in this crate follow the same contract:
//! - Pointer parameters must be valid (non-null, properly aligned, pointing to
//!   the documented number of bytes or a valid null-terminated C string).
//! - Handle parameters must have been obtained from the corresponding `_create`
//!   / `_connect` function and not yet freed.
//! - The caller owns all input buffers and must free returned strings with
//!   `salvium_string_free()` and handles with the matching `_close()`.
//!
//! # Conventions
//!
//! - Functions returning `i32`: 0 = success, -1 = error
//! - Functions returning `*mut c_char`: null = error
//! - Functions returning `*mut c_void`: null = error (opaque handle)
//! - Caller must call `salvium_string_free()` on returned `*mut c_char`
//! - Caller must call the appropriate `_close()` on returned handles
//! - Check `salvium_last_error()` after any error return

#![allow(clippy::missing_safety_doc)]

pub mod daemon;
pub mod error;
pub mod handles;
pub mod multisig;
pub mod strings;
pub mod transfer;
pub mod wallet;

use std::sync::OnceLock;
use tokio::runtime::Runtime;

/// Global async runtime singleton.
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Get (or lazily create) the singleton tokio runtime.
pub fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("failed to create tokio runtime"))
}

/// Return the Salvium protocol version this library was built against (e.g. `"1.0.7"`).
///
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub extern "C" fn salvium_version() -> *mut std::ffi::c_char {
    let pkg = env!("CARGO_PKG_VERSION"); // e.g. "1.0.7-r012"
    let base = match pkg.split_once('-') {
        Some((base, _)) => base,
        None => pkg,
    };
    match std::ffi::CString::new(base) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Return the library version string derived from the `rXXX` pre-release tag.
///
/// The Cargo version `1.0.7-r012` becomes `"v0.1.2"` — each digit of the
/// three-digit `rXXX` code maps to major.minor.patch.
///
/// Caller must free with `salvium_string_free()`.
#[no_mangle]
pub extern "C" fn salvium_rs_version() -> *mut std::ffi::c_char {
    let pkg = env!("CARGO_PKG_VERSION"); // e.g. "1.0.7-r012"
    let version = match pkg.rsplit_once("-r") {
        Some((_, digits)) if digits.len() == 3 => {
            let d: Vec<u8> = digits.bytes().map(|b| b - b'0').collect();
            format!("v{}.{}.{}", d[0], d[1], d[2])
        }
        _ => pkg.to_string(),
    };
    match std::ffi::CString::new(version) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Explicitly initialize the FFI runtime.
///
/// This is optional — the runtime is lazily created on first use.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn salvium_ffi_init() -> i32 {
    error::ffi_try(|| {
        let _ = runtime();
        Ok(())
    })
}
