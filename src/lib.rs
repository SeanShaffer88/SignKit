//! SignKit — Authenticode inspection and verification
//! helpers for Windows PE files.
//!
//! What it does: read a PE file's structure and signature
//! table (`inspect`), compute the Authenticode image hash
//! (`authenticode_hash`), and — on Windows only — ask
//! WinVerifyTrust whether the signature is actually trusted
//! (`verify`).
//!
//! What it does NOT do: sign files. Signing requires a
//! code-signing certificate, and this kit deliberately ships
//! no signing entry point. There is no `sg_sign` export and
//! nothing in this crate pretends to be one.
//!
//! Module layout (house standard): `pe` is the pure,
//! platform-independent PE reader and hash; `platform` is
//! the only place Windows APIs are touched; `ffi` is the C
//! ABI declared in `include/signkit.h`; `json` and `sha256`
//! are the hand-rolled, zero-dependency family engines.

pub mod ffi;
pub mod json;
pub mod pe;
pub mod platform;
pub mod sha256;

use json::Value;

pub const VERSION: &str = "0.1.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;

// Error codes (mirror include/signkit.h).
pub const SG_OK: i32 = 0;
pub const ERR_INVALID_ARG: i32 = 1;
pub const ERR_NOT_SUPPORTED: i32 = 2;
pub const ERR_NOT_FOUND: i32 = 3;
pub const ERR_ACCESS_DENIED: i32 = 4;
pub const ERR_PLATFORM: i32 = 5;
pub const ERR_INTERNAL: i32 = 6;

/// (code, message) error pair used across the crate.
pub type SgResult<T> = Result<T, (i32, String)>;

/// Escape a string for inclusion inside JSON double quotes.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn read_file(path: &str) -> SgResult<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        let code = match e.kind() {
            std::io::ErrorKind::NotFound => ERR_NOT_FOUND,
            std::io::ErrorKind::PermissionDenied => ERR_ACCESS_DENIED,
            _ => ERR_PLATFORM,
        };
        (code, format!("cannot read '{path}': {e}"))
    })
}

/// `sg_inspect` over a file path: the PE report JSON,
/// including the path it came from.
pub fn inspect_path(path: &str) -> SgResult<String> {
    let data = read_file(path)?;
    let mut v = pe::inspect_bytes(&data)?;
    if let Value::Object(pairs) = &mut v {
        pairs.insert(0, ("path".to_string(), Value::Str(path.to_string())));
    }
    Ok(v.to_json())
}

/// `sg_authenticode_hash` over a file path: the SHA-256
/// Authenticode image hash as lowercase hex.
pub fn authenticode_hash_path(path: &str) -> SgResult<String> {
    let data = read_file(path)?;
    pe::authenticode_hash(&data)
}

/// `sg_verify` over a file path: a JSON verdict
/// `{path, status, code, code_hex, message}` where status is
/// "trusted", "unsigned" or "untrusted". The verdict comes
/// from WinVerifyTrust on Windows; everywhere else this is
/// ERR_NOT_SUPPORTED.
pub fn verify_path(path: &str) -> SgResult<String> {
    if !std::path::Path::new(path).exists() {
        return Err((ERR_NOT_FOUND, format!("no such file: '{path}'")));
    }
    let out = platform::verify_file(path)?;
    let v = json::obj(vec![
        ("path", json::s(path)),
        ("status", json::s(out.status)),
        ("code", json::n(out.code as u64)),
        ("code_hex", json::s(&format!("0x{:08X}", out.code))),
        ("message", json::s(&out.message)),
    ]);
    Ok(v.to_json())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_json() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn missing_file_is_not_found() {
        let p = "/no/such/file/signkit-missing.exe";
        assert_eq!(inspect_path(p).unwrap_err().0, ERR_NOT_FOUND);
        assert_eq!(authenticode_hash_path(p).unwrap_err().0, ERR_NOT_FOUND);
        assert_eq!(verify_path(p).unwrap_err().0, ERR_NOT_FOUND);
    }

    #[cfg(not(windows))]
    #[test]
    fn verify_is_not_supported_off_windows() {
        // An existing file is required to get past the
        // existence check and reach the platform layer.
        let dir = std::env::temp_dir().join(format!("signkit-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.bin");
        std::fs::write(&f, b"MZ").unwrap();
        let err = verify_path(&f.to_string_lossy()).unwrap_err();
        assert_eq!(err.0, ERR_NOT_SUPPORTED);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
