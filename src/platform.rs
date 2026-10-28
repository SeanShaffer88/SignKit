//! Platform layer: the only place Windows APIs are touched.
//! On non-Windows targets verification returns
//! ERR_NOT_SUPPORTED so the pure logic and FFI contract stay
//! testable anywhere.
//!
//! Trust decisions live here and ONLY here: a file is
//! reported "trusted" solely because WinVerifyTrust returned
//! success for it on Windows. Nothing in the PE reader or the
//! hash code can produce that verdict.
//!
//! Every extern block MUST carry #[link(name = "...")] naming
//! its import library. Without it the build fails at LINK
//! time with LNK2019 — check and clippy cannot catch it; CI's
//! real build can.

use crate::{ERR_NOT_SUPPORTED, ERR_PLATFORM};

pub type PResult<T> = Result<T, (i32, String)>;

pub fn not_supported<T>(what: &str) -> PResult<T> {
    Err((
        ERR_NOT_SUPPORTED,
        format!("{what} is only available on Windows"),
    ))
}

/// The outcome of a verification WinVerifyTrust could judge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// "trusted", "unsigned" or "untrusted".
    pub status: &'static str,
    /// The raw WinVerifyTrust return value (an HRESULT).
    pub code: u32,
    /// Plain-words explanation of the verdict.
    pub message: String,
}

// HRESULT codes from WinVerifyTrust / the certificate chain
// engine (values are the unsigned bit patterns).
const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const TRUST_E_SUBJECT_NOT_TRUSTED: u32 = 0x800B_0004;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
const TRUST_E_BAD_DIGEST: u32 = 0x80096010;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_REVOKED: u32 = 0x800B_010C;
const TRUST_E_CERT_SIGNATURE: u32 = 0x80096004;
const TRUST_E_NO_SIGNER_CERT: u32 = 0x80096002;
const TRUST_E_BASIC_CONSTRAINTS: u32 = 0x80096019;

/// Map a raw WinVerifyTrust return value to a verdict.
/// `Ok` for verdicts the caller should report as data
/// (trusted / unsigned / untrusted); `Err` for failures that
/// mean the check itself could not be carried out. Pure, so
/// it compiles (and is tested) on every platform; public
/// because its only caller is the Windows backend, and the
/// mapping table is worth testing (and reading) everywhere.
pub fn map_trust_status(code: u32) -> PResult<VerifyOutcome> {
    match code {
        0 => Ok(VerifyOutcome {
            status: "trusted",
            code,
            message: "WinVerifyTrust verified the signature and its chain".to_string(),
        }),
        TRUST_E_NOSIGNATURE => Ok(VerifyOutcome {
            status: "unsigned",
            code,
            message: "the file has no Authenticode signature".to_string(),
        }),
        TRUST_E_SUBJECT_NOT_TRUSTED
        | TRUST_E_EXPLICIT_DISTRUST
        | TRUST_E_BAD_DIGEST
        | CERT_E_EXPIRED
        | CERT_E_UNTRUSTEDROOT
        | CERT_E_REVOKED
        | TRUST_E_CERT_SIGNATURE
        | TRUST_E_NO_SIGNER_CERT
        | TRUST_E_BASIC_CONSTRAINTS => Ok(VerifyOutcome {
            status: "untrusted",
            code,
            message: format!("WinVerifyTrust rejected the signature (error 0x{code:08X})"),
        }),
        _ => Err((
            ERR_PLATFORM,
            format!("WinVerifyTrust failed with error 0x{code:08X}"),
        )),
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::OsStr;
    use std::os::raw::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
        data1: 0x00AA_C56B,
        data2: 0xCD44,
        data3: 0x11D0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    const WTD_UI_NONE: u32 = 2;
    const WTD_REVOKE_NONE: u32 = 0;
    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_STATEACTION_VERIFY: u32 = 1;
    const WTD_STATEACTION_CLOSE: u32 = 2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    // Layout follows the public Windows SDK (wintrust.h).
    // The union in WINTRUST_DATA is represented by its file
    // pointer member: every union member is pointer-sized.
    #[repr(C)]
    struct WinTrustFileInfo {
        cb_struct: u32,
        file_path: *const u16,
        file_handle: *mut c_void,
        known_subject: *mut Guid,
    }

    #[repr(C)]
    struct WinTrustData {
        cb_struct: u32,
        policy_callback_data: *mut c_void,
        sip_client_data: *mut c_void,
        ui_choice: u32,
        revocation_checks: u32,
        union_choice: u32,
        file_info: *mut WinTrustFileInfo,
        state_action: u32,
        state_data: *mut c_void,
        url_reference: *mut u16,
        prov_flags: u32,
        ui_context: u32,
        signature_settings: *mut c_void,
    }

    #[link(name = "wintrust")]
    extern "system" {
        fn WinVerifyTrust(hwnd: *mut c_void, action_id: *mut Guid, data: *mut c_void) -> i32;
    }

    pub fn verify_file(path: &str) -> PResult<VerifyOutcome> {
        let wide: Vec<u16> = OsStr::new(Path::new(path))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut file_info = WinTrustFileInfo {
            cb_struct: std::mem::size_of::<WinTrustFileInfo>() as u32,
            file_path: wide.as_ptr(),
            file_handle: std::ptr::null_mut(),
            known_subject: std::ptr::null_mut(),
        };
        let mut data = WinTrustData {
            cb_struct: std::mem::size_of::<WinTrustData>() as u32,
            policy_callback_data: std::ptr::null_mut(),
            sip_client_data: std::ptr::null_mut(),
            ui_choice: WTD_UI_NONE,
            revocation_checks: WTD_REVOKE_NONE,
            union_choice: WTD_CHOICE_FILE,
            file_info: &mut file_info,
            state_action: WTD_STATEACTION_VERIFY,
            state_data: std::ptr::null_mut(),
            url_reference: std::ptr::null_mut(),
            prov_flags: 0,
            ui_context: 0,
            signature_settings: std::ptr::null_mut(),
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: file_info and data outlive both calls; the
        // path buffer outlives them too. The second call with
        // WTD_STATEACTION_CLOSE releases the state the first
        // call allocated, as the SDK requires.
        let raw = unsafe {
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action,
                &mut data as *mut WinTrustData as *mut c_void,
            )
        };
        data.state_action = WTD_STATEACTION_CLOSE;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        unsafe {
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action,
                &mut data as *mut WinTrustData as *mut c_void,
            )
        };
        map_trust_status(raw as u32)
    }
}

#[cfg(windows)]
pub fn verify_file(path: &str) -> PResult<VerifyOutcome> {
    win::verify_file(path)
}

#[cfg(not(windows))]
pub fn verify_file(_path: &str) -> PResult<VerifyOutcome> {
    not_supported("Authenticode verification (WinVerifyTrust)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(map_trust_status(0).unwrap().status, "trusted");
        assert_eq!(map_trust_status(0x800B_0100).unwrap().status, "unsigned");
        for code in [0x800B_0004u32, 0x800B_0109, 0x800B_0101, 0x80096010] {
            let out = map_trust_status(code).unwrap();
            assert_eq!(out.status, "untrusted", "code 0x{code:08X}");
            assert!(out.message.contains(&format!("0x{code:08X}")));
        }
        // An unrelated failure is an error, not a verdict.
        let err = map_trust_status(0x8007_0005).unwrap_err();
        assert_eq!(err.0, ERR_PLATFORM);
    }

    /// Windows CI: WinVerifyTrust on a hand-built unsigned PE
    /// must report "unsigned". The only tolerated escape is
    /// ERR_NOT_SUPPORTED, if WinVerifyTrust is somehow
    /// unavailable in the test environment — and the test
    /// prints which path was taken so the log says which.
    #[cfg(windows)]
    #[test]
    fn verify_unsigned_fixture_reports_unsigned() {
        let dir = std::env::temp_dir().join(format!("signkit-winverify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("unsigned.exe");
        std::fs::write(&f, crate::pe::tests_fixture::unsigned_pe64_exe()).unwrap();
        let path = f.to_string_lossy().to_string();
        match crate::verify_path(&path) {
            Ok(text) => {
                let v = crate::json::parse(&text).unwrap();
                assert_eq!(v.get("status").unwrap().as_str(), Some("unsigned"));
                assert_eq!(v.get("code_hex").unwrap().as_str(), Some("0x800B0100"));
                eprintln!("verify path taken: WinVerifyTrust reported unsigned");
            }
            Err((code, msg)) => {
                assert_eq!(
                    code,
                    crate::ERR_NOT_SUPPORTED,
                    "unexpected verify failure: {msg}"
                );
                eprintln!("verify path taken: NOT_SUPPORTED escape ({msg})");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
