//! Thread-local error storage and FFI helper macros.
//!
//! Functions return 0 on success, -1 on error. The caller checks
//! `salvium_last_error()` for the message.

use std::cell::RefCell;
use std::ffi::{c_char, c_void, CString};
use std::panic;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Store an error message for the current thread.
pub fn set_last_error(msg: &str) {
    let c =
        CString::new(msg).unwrap_or_else(|_| CString::new("(error contained null byte)").unwrap());
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(c);
    });
}

/// Run a closure that returns `Result<(), String>`.
/// Returns 0 on success, -1 on error (stores message).
/// Also catches panics.
pub fn ffi_try<F>(f: F) -> i32
where
    F: FnOnce() -> Result<(), String> + panic::UnwindSafe,
{
    match panic::catch_unwind(f) {
        Ok(Ok(())) => 0,
        Ok(Err(msg)) => {
            set_last_error(&msg);
            -1
        }
        Err(_) => {
            set_last_error("panic in FFI call");
            -1
        }
    }
}

/// Run a closure that returns `Result<*mut c_char, String>`.
/// Returns the pointer on success, null on error (stores message).
pub fn ffi_try_string<F>(f: F) -> *mut c_char
where
    F: FnOnce() -> Result<String, String> + panic::UnwindSafe,
{
    match panic::catch_unwind(f) {
        Ok(Ok(s)) => match CString::new(s) {
            Ok(cs) => cs.into_raw(),
            Err(e) => {
                set_last_error(&format!("string contained null byte: {e}"));
                std::ptr::null_mut()
            }
        },
        Ok(Err(msg)) => {
            set_last_error(&msg);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic in FFI call");
            std::ptr::null_mut()
        }
    }
}

/// Run a closure that returns `Result<T, String>`.
/// Returns an opaque handle on success, null on error (stores message).
pub fn ffi_try_ptr<T, F>(f: F) -> *mut c_void
where
    F: FnOnce() -> Result<T, String> + panic::UnwindSafe,
{
    match panic::catch_unwind(f) {
        Ok(Ok(val)) => crate::handles::into_handle(val),
        Ok(Err(msg)) => {
            set_last_error(&msg);
            std::ptr::null_mut()
        }
        Err(_) => {
            set_last_error("panic in FFI call");
            std::ptr::null_mut()
        }
    }
}

/// Get the last error message for the current thread.
/// Returns null if no error has occurred.
///
/// The returned pointer is valid until the next FFI call on the same thread.
/// The caller must NOT free this pointer.
#[no_mangle]
pub extern "C" fn salvium_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_ref() {
            Some(cs) => cs.as_ptr(),
            None => std::ptr::null(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_error() {
        set_last_error("test error");
        let ptr = salvium_last_error();
        assert!(!ptr.is_null());
        let msg = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert_eq!(msg.to_str().unwrap(), "test error");
    }

    #[test]
    fn test_ffi_try_success() {
        let result = ffi_try(|| Ok(()));
        assert_eq!(result, 0);
    }

    #[test]
    fn test_ffi_try_error() {
        let result = ffi_try(|| Err("something failed".into()));
        assert_eq!(result, -1);
        let ptr = salvium_last_error();
        let msg = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert_eq!(msg.to_str().unwrap(), "something failed");
    }

    #[test]
    fn test_ffi_try_panic() {
        let result = ffi_try(|| panic!("oh no"));
        assert_eq!(result, -1);
        let ptr = salvium_last_error();
        let msg = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert_eq!(msg.to_str().unwrap(), "panic in FFI call");
    }

    #[test]
    fn test_ffi_try_string_success() {
        let ptr = ffi_try_string(|| Ok("hello".into()));
        assert!(!ptr.is_null());
        let msg = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert_eq!(msg.to_str().unwrap(), "hello");
        // Clean up
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }

    #[test]
    fn test_ffi_try_string_error() {
        let ptr = ffi_try_string(|| Err("bad".into()));
        assert!(ptr.is_null());
    }

    #[test]
    fn test_ffi_try_ptr_success() {
        let ptr = ffi_try_ptr(|| Ok(42u64));
        assert!(!ptr.is_null());
        // Clean up
        crate::handles::drop_handle::<u64>(ptr);
    }

    #[test]
    fn test_ffi_try_ptr_error() {
        let ptr = ffi_try_ptr::<u64, _>(|| Err("fail".into()));
        assert!(ptr.is_null());
    }
}
