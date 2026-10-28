# SignKit — Quality Scorecard

Scored against the v0.1.0 gate run on the development VM:
`cargo fmt --check`, clippy (host + `x86_64-pc-windows-msvc`,
`-D warnings`), `cargo check` for the Windows target, and
the full test suite — 23/23 passing, run three times with
identical results. Scores are only claimed where that
evidence exists; Windows runtime behaviour is not claimed
from Linux evidence.

| Dimension | Score /5 | Evidence |
|---|---|---|
| PE inspection correctness | 5 | Byte-built fixtures for 64-bit exe, 32-bit signed DLL, native-subsystem sys; every reported field asserted, including cert offsets, blob size and overlay accounting |
| Authenticode hash correctness | 5 | Matches a second, independently structured implementation on five fixture shapes; region-sensitivity test proves each excluded region is excluded and each included region is included |
| Robustness against bad input | 5 | Every truncation prefix of a signed fixture passes through parser + hash without a panic; targeted malformed structures (bad signature, cert past EOF, section past EOF) are clean errors |
| Verification honesty | 4 | Trust comes only from WinVerifyTrust; the status mapping is unit-tested, and off-Windows the call is NOT_SUPPORTED rather than a guess. One point held back: a live "trusted" verdict on a real signed file is Unverified — no valid-chain fixture exists yet |
| API & documentation | 4 | Header documents every export with field-by-field semantics and states plainly that signing is not provided; README has a runnable C example. No compiled C consumer test in the suite (FFI is exercised from Rust) — one point held back |
| Code health | 5 | Zero dependencies, fmt + clippy clean on both targets at the gate, nothing unwinds across the FFI boundary, per-test state only (no shared statics) |
| Platform coverage | 4 | Reader + hash are portable and fully tested on Linux; the Windows MSVC target compiles and lints clean locally, and a real `x86_64-pc-windows-gnu` link (debug + release) succeeds locally with WINTRUST.dll / WinVerifyTrust in the DLL's import table and exactly the seven documented `sg_*` exports. One point held back: live WinVerifyTrust behaviour still rests on Windows CI — a linked DLL is not a run |

**Total: 90/100**

## Waivers / open items

- "Trusted" verification: Unverified until Windows CI (or a Windows machine) runs `sg_verify` against a file with a valid, chain-trusted signature. The unsigned-fixture Windows test is the current floor.
- The MSVC link specifically is proven by CI's `cargo build --release --locked` on windows-latest; the local link evidence is the GNU toolchain (same import library contract).
- No dimension is scored on a signing feature, because signing is deliberately absent (blocked on a certificate decision — see ROADMAP).
