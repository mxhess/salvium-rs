//! Opaque handle management.
//!
//! Converts Rust objects to/from `*mut c_void` via `Box::into_raw` / `Box::from_raw`.

use std::ffi::c_void;

/// Move a value onto the heap and return an opaque handle.
pub fn into_handle<T>(val: T) -> *mut c_void {
    Box::into_raw(Box::new(val)) as *mut c_void
}

/// Borrow a reference to the value behind an opaque handle.
///
/// Returns `Err` if the handle is null.
///
/// # Safety
/// The handle must have been created by `into_handle::<T>()` and must not
/// have been freed yet. The caller must ensure exclusive access if `T`
/// is not `Sync`.
pub unsafe fn borrow_handle<'a, T>(handle: *mut c_void) -> Result<&'a T, String> {
    if handle.is_null() {
        return Err("null handle".into());
    }
    Ok(unsafe { &*(handle as *const T) })
}

/// Drop the value behind an opaque handle, freeing its memory.
///
/// No-op if the handle is null.
///
/// # Safety
/// The handle must have been created by `into_handle::<T>()` and must not
/// have been freed before. After this call the handle is invalid.
pub fn drop_handle<T>(handle: *mut c_void) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle as *mut T));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_roundtrip() {
        let val = String::from("hello world");
        let handle = into_handle(val);
        assert!(!handle.is_null());

        let borrowed = unsafe { borrow_handle::<String>(handle) }.unwrap();
        assert_eq!(borrowed, "hello world");

        drop_handle::<String>(handle);
    }

    #[test]
    fn test_null_handle_error() {
        let result = unsafe { borrow_handle::<String>(std::ptr::null_mut()) };
        assert!(result.is_err());
    }

    #[test]
    fn test_drop_null_is_noop() {
        drop_handle::<String>(std::ptr::null_mut());
    }
}
