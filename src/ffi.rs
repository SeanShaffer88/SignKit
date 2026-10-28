//! C ABI surface — everything declared in include/signkit.h.
//! Conventions (house standard):
//! - `*mut c_char` results are caller-owned; free with
//!   `sg_free_string`.
//! - Failures return null and set the thread-local last error
//!   (see `sg_last_error` / `sg_last_error_code`).
//! - Nothing unwinds across the FFI boundary (catch_unwind
//!   everywhere; release profile also sets panic = "abort").
//!
//! There is deliberately no signing export: SignKit inspects
//! and verifies signatures, it does not create them.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::catch_unwind;

use crate::{SgResult, ERR_INTERNAL, ERR_INVALID_ARG, SG_OK};

thread_local! {
    static LAST_ERROR: RefCell<(i32, CString)> =
        RefCell::new((0, CString::new("").unwrap()));
}

pub fn set_error(code: i32, msg: &str) {
    let clean: String = msg.chars().filter(|&c| c != '\0').collect();
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = (
            code,
            CString::new(clean).unwrap_or_else(|_| CString::new("error").unwrap()),
        );
    });
}

fn clear_error() {
    set_error(SG_OK, "");
}

fn out_string(result: SgResult<String>) -> *mut c_char {
    match result {
        Ok(text) => match CString::new(text) {
            Ok(s) => {
                clear_error();
                s.into_raw()
            }
            Err(_) => {
                set_error(ERR_INTERNAL, "result string contained a NUL byte");
                std::ptr::null_mut()
            }
        },
        Err((code, msg)) => {
            set_error(code, &msg);
            std::ptr::null_mut()
        }
    }
}

fn cstr<'a>(ptr: *const c_char, what: &str) -> SgResult<&'a str> {
    if ptr.is_null() {
        return Err((ERR_INVALID_ARG, format!("{what} must not be null")));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| (ERR_INVALID_ARG, format!("{what} must be valid UTF-8")))
}

fn guard<F: FnOnce() -> *mut c_char>(f: F) -> *mut c_char {
    match catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(p) => p,
        Err(_) => {
            set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn sg_version() -> *const c_char {
    static VERSION_C: &[u8] = b"0.1.0\0";
    VERSION_C.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn sg_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().1.as_ptr())
}

#[no_mangle]
pub extern "C" fn sg_last_error_code() -> c_int {
    LAST_ERROR.with(|e| e.borrow().0) as c_int
}

/// # Safety (caller contract): `p` is null or a string this
/// library returned and has not been freed yet. Documented
/// in the header.
#[no_mangle]
pub extern "C" fn sg_free_string(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

#[no_mangle]
pub extern "C" fn sg_inspect(path: *const c_char) -> *mut c_char {
    guard(|| out_string(cstr(path, "path").and_then(crate::inspect_path)))
}

#[no_mangle]
pub extern "C" fn sg_authenticode_hash(path: *const c_char) -> *mut c_char {
    guard(|| out_string(cstr(path, "path").and_then(crate::authenticode_hash_path)))
}

#[no_mangle]
pub extern "C" fn sg_verify(path: *const c_char) -> *mut c_char {
    guard(|| out_string(cstr(path, "path").and_then(crate::verify_path)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn take(p: *mut c_char) -> String {
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
        sg_free_string(p);
        s
    }

    #[test]
    fn ffi_inspect_and_hash_fixture() {
        let dir = std::env::temp_dir().join(format!("signkit-ffi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("app.exe");
        std::fs::write(&f, crate::pe::tests_fixture::unsigned_pe64_exe()).unwrap();
        let path = f.to_string_lossy().to_string();

        let text = take(sg_inspect(cs(&path).as_ptr()));
        let v = crate::json::parse(&text).unwrap();
        assert_eq!(v.get("is_pe").unwrap().as_bool(), Some(true));
        assert_eq!(v.get("pe_kind").unwrap().as_str(), Some("exe"));
        assert_eq!(v.get("bits").unwrap().as_i64(), Some(64));
        assert_eq!(v.get("has_signature").unwrap().as_bool(), Some(false));
        assert_eq!(sg_last_error_code(), 0);

        let hex = take(sg_authenticode_hash(cs(&path).as_ptr()));
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ffi_errors_are_clean() {
        assert!(sg_inspect(std::ptr::null()).is_null());
        assert_eq!(sg_last_error_code(), ERR_INVALID_ARG);
        assert!(sg_inspect(cs("/no/such/file/signkit.exe").as_ptr()).is_null());
        assert_eq!(sg_last_error_code(), crate::ERR_NOT_FOUND);
        sg_free_string(std::ptr::null_mut()); // must be a no-op
    }

    #[cfg(not(windows))]
    #[test]
    fn ffi_verify_not_supported_off_windows() {
        let dir = std::env::temp_dir().join(format!("signkit-ffi-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("app.exe");
        std::fs::write(&f, crate::pe::tests_fixture::unsigned_pe64_exe()).unwrap();
        assert!(sg_verify(cs(&f.to_string_lossy()).as_ptr()).is_null());
        assert_eq!(sg_last_error_code(), crate::ERR_NOT_SUPPORTED);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
