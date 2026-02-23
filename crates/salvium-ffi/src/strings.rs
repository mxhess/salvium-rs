//! C string conversion helpers.

use std::ffi::{c_char, CStr, CString};

/// Convert a C string pointer to a Rust `&str`.
///
/// Returns `Err` if the pointer is null or the bytes are not valid UTF-8.
///
/// # Safety
/// The pointer must point to a valid null-terminated C string.
pub unsafe fn c_str_to_str<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null string pointer".into());
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| format!("invalid UTF-8: {e}"))
}

/// Convert a C buffer pointer + length to a Rust `&[u8]`.
///
/// Returns `Err` if the pointer is null.
///
/// # Safety
/// The pointer must point to at least `len` readable bytes.
pub unsafe fn c_buf_to_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], String> {
    if ptr.is_null() {
        return Err("null buffer pointer".into());
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Free a string that was returned by an FFI function.
///
/// The caller must call this for every non-null `*mut c_char` returned by
/// `salvium_wallet_*` functions.
#[no_mangle]
pub unsafe extern "C" fn salvium_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_str_to_str_valid() {
        let cs = CString::new("hello").unwrap();
        let result = unsafe { c_str_to_str(cs.as_ptr()) };
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn test_c_str_to_str_null() {
        let result = unsafe { c_str_to_str(std::ptr::null()) };
        assert!(result.is_err());
    }

    #[test]
    fn test_c_buf_to_slice_valid() {
        let data = [1u8, 2, 3, 4];
        let result = unsafe { c_buf_to_slice(data.as_ptr(), data.len()) };
        assert_eq!(result.unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_c_buf_to_slice_null() {
        let result = unsafe { c_buf_to_slice(std::ptr::null(), 4) };
        assert!(result.is_err());
    }

    #[test]
    fn test_string_free_null_noop() {
        unsafe { salvium_string_free(std::ptr::null_mut()); }
    }

    #[test]
    fn test_string_free_valid() {
        let cs = CString::new("test").unwrap();
        let ptr = cs.into_raw();
        unsafe { salvium_string_free(ptr); }
    }
}
