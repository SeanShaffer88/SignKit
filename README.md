# SignKit

## TL;DR

SignKit is a small DLL that answers three questions about a Windows program file (.exe, .dll, .sys): What kind of file is it and does it carry a digital signature? What is the exact fingerprint (the "Authenticode hash") a signature for this file would have to match? And — on Windows — does Windows itself trust the signature? It can look at signatures and check them, **but it cannot sign files**: signing needs a code-signing certificate, and this kit deliberately ships no signing function.

```c
#include "signkit.h"
#include <stdio.h>

int main(void) {
    char *report = sg_inspect("C:/Windows/System32/kernel32.dll");
    printf("%s\n", report);          /* what the file is, signature table or null */
    sg_free_string(report);

    char *verdict = sg_verify("C:/Windows/System32/kernel32.dll");
    if (verdict) {
        printf("%s\n", verdict);     /* {"status":"trusted", ...} */
        sg_free_string(verdict);
    } else {
        printf("verify failed: %s\n", sg_last_error());
    }
    return 0;
}
```

## Key features

- **PE inspection from raw bytes.** `sg_inspect` reads the DOS/COFF/optional headers itself — no Windows APIs — so it works on any platform: PE kind (`exe` / `dll` / `sys` / `unknown`), 32- vs 64-bit, machine type (display name plus the raw code), the raw COFF timestamp, the stored checksum field, section count, overlay size, and the certificate table's location and size.
- **Signature presence, reported honestly.** A signed file reports `cert_table` (file offset + size) and `signer_blob_size` (the WIN_CERTIFICATE payload length). An unsigned file reports `null`s, not zeros dressed up as data.
- **The Authenticode hash, exactly defined.** `sg_authenticode_hash` returns the SHA-256 image hash: every byte hashed except the CheckSum field, the security directory entry itself, and the certificate table; bytes after the certificate table count in whole 8-byte blocks only, per the specification's alignment rule. This is the digest a signature must match — an inspection value, not a trust decision.
- **Trust comes from Windows, or nowhere.** `sg_verify` calls WinVerifyTrust (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, no UI, revocation checks off) and reports `trusted`, `unsigned`, or `untrusted` with the raw error code attached. On non-Windows platforms it fails cleanly with `SG_ERR_NOT_SUPPORTED` instead of guessing.
- **Malformed files are data, not crashes.** Every read is bounds-checked. A truncated or corrupt PE returns a clean error; a file that is not a PE at all reports `{"is_pe":false}` from `sg_inspect`.
- **Zero dependencies.** Hand-rolled PE reader, JSON, and SHA-256; small C ABI; thread-local last-error reporting.

## The API in one screen

| Call | What it does |
|---|---|
| `sg_inspect(path)` | PE report JSON (layout above in the header) |
| `sg_authenticode_hash(path)` | Authenticode image hash as hex SHA-256 |
| `sg_verify(path)` | Verdict JSON: `trusted` / `unsigned` / `untrusted` + raw code |
| `sg_version` / `sg_last_error` / `sg_last_error_code` / `sg_free_string` | Version, thread-local error, string ownership |

There is no `sg_sign`. See the header — it says so too.

## Limitations

- **No signing.** Deliberate: there is no code-signing certificate for this project, and a signing function that cannot produce a trusted signature would be a placeholder. Signing is listed in ROADMAP.md as blocked on a certificate decision.
- **Verification is Windows-only**, because WinVerifyTrust is. Inspection and hashing work anywhere.
- **The whole file is read into memory.** Fine for typical executables; very large installers cost their size in RAM. (ROADMAP item.)
- **The timestamp is reported raw.** COFF TimeDateStamp values are whatever the linker wrote; some linkers write a hash or a fixed value instead of a real time.
- **Catalog-signed files** (`.cat` signatures, common for drivers) carry no embedded certificate table: `sg_inspect` reports them as unsigned, and `sg_verify`'s verdict is whatever WinVerifyTrust decides.
- **Revocation checks are off** in `sg_verify` (documented `WTD_REVOKE_NONE` behaviour); an expired certificate still reports `untrusted`, but a certificate revoked after signing may not be caught.

## Building

```sh
cargo build --release
```

Produces `signkit.dll` / `libsign_kit` (cdylib), an rlib, and a static library from the same crate. The C header is `include/signkit.h`. Rust 1.80+, no dependencies.

## Tests

```sh
cargo test
```

The suite builds PE fixtures byte by byte (unsigned, signed with a fake certificate table, with overlays and post-certificate tails), checks the hash against a second, independently structured implementation, flips bytes in hashed and excluded regions, and feeds every truncation prefix of a fixture through the parser. On Windows, one test asks WinVerifyTrust about an unsigned fixture and expects `unsigned`.
