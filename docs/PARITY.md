# SignKit — Parity (spec vs implementation)

Evidence: the Rust test suite in `src/pe.rs`, `src/ffi.rs`,
`src/platform.rs`, `src/json.rs`, `src/sha256.rs` and
`src/lib.rs` (23 tests, all passing at the v0.1.0 gate, run
three times) plus the header contract in
`include/signkit.h`. "Verified" below means a named test
exercises the behaviour. Windows runtime behaviour is never
claimed from Linux evidence.

| Spec feature | Status | Evidence |
|---|---|---|
| `sg_inspect`: hand-rolled PE reader, works on every platform | Verified | `inspect_unsigned_exe`, `inspect_signed_dll_with_overlay`, `inspect_path_reports_path_and_fields` |
| pe_kind from characteristics/subsystem: exe / dll / sys / unknown | Verified | exe + dll tests above; `inspect_native_subsystem_is_sys` (native subsystem → sys); unknown is the fall-through branch |
| bits 32 / 64 from PE32 / PE32+ magic | Verified | 64-bit exe and 32-bit DLL fixtures |
| machine: display name for common codes + raw value | Verified | `machine` = "x86-64 (AMD64)", `machine_value` = 34404 asserted; i386 fixture covers a second code |
| timestamp: raw COFF TimeDateStamp | Verified | fixture value 0x5E1F3C00 asserted end to end. No ISO string: the family has no shared civil-time conversion yet, so per design the raw value ships alone (ROADMAP item) |
| checksum_field reported as stored | Verified | fixture CheckSum 0xAABBCCDD asserted |
| cert_table {file_offset, size} or null; has_signature | Verified | signed DLL: offset points at a WIN_CERTIFICATE whose dwLength matches; unsigned exe: null + `has_signature:false` |
| signer_blob_size = dwLength − 8 | Verified | signed fixture: 24-byte table → blob 16 |
| overlay_bytes (neither headers, sections, nor cert table) | Verified | signed DLL with 10 overlay bytes between section and cert table asserts 10 |
| sections count | Verified | fixtures assert 1 |
| Not a PE → `{"is_pe":false}`, not an error | Verified | `not_a_pe` |
| Malformed/truncated → clean errors, never panics | Verified | `malformed_structures_are_errors_not_panics`; `every_truncation_prefix_is_handled` runs all prefixes of a signed fixture through parser, inspect and hash |
| `sg_authenticode_hash`: SHA-256 over all bytes except CheckSum field, security directory entry, certificate table; post-cert tail in whole 8-byte blocks | Verified | `hash_matches_independent_reimplementation` (byte-filter + one-shot reference vs streaming range implementation, over unsigned / signed / padded-cert / tail fixtures); `hash_region_sensitivity` (section + stub flips change it; CheckSum + cert blob flips do not; aligned tail byte changes it, unaligned tail byte does not); `hash_unsigned_with_overlay_covers_overlay` |
| Hand-rolled SHA-256 correct | Verified | FIPS known-answer vectors + streaming/one-shot equality at padding boundaries (`sha256` module tests) |
| `sg_verify`: WinVerifyTrust mapping — 0 → trusted; TRUST_E_NOSIGNATURE → unsigned; subject-not-trusted / untrusted-root / expired / revoked / bad-digest family → untrusted with raw code; anything else → SG_ERR_PLATFORM | Partial | The mapping itself is unit-tested on all platforms (`status_mapping`). The live call is compiled and lint-checked for `x86_64-pc-windows-msvc` in the local gate; a Windows test (`verify_unsigned_fixture_reports_unsigned`) asserts an unsigned fixture reports "unsigned" and runs in Windows CI. A "trusted" verdict on a real signed file is **Unverified** — no signed fixture with a valid chain exists in the suite |
| `sg_verify` off Windows → SG_ERR_NOT_SUPPORTED | Verified | `verify_is_not_supported_off_windows`, `ffi_verify_not_supported_off_windows` |
| Revocation off, UI none, GENERIC_VERIFY_V2, state closed after verify | Implemented | `platform::win::verify_file` sets WTD_UI_NONE + WTD_REVOKE_NONE and always issues the WTD_STATEACTION_CLOSE call; exercised only where WinVerifyTrust exists (Windows CI) |
| Signing | **Not provided — by design** | No `sg_sign` export exists; the header, README and ROADMAP state that signing is blocked on a code-signing certificate decision |

## Known gaps (also in README "Limitations")

- Real-world "trusted" verification is Unverified until a properly signed file is tested on Windows.
- Windows link evidence: a local `x86_64-pc-windows-gnu` build (debug + release) links clean; the produced `sign_kit.dll` imports WinVerifyTrust from WINTRUST.dll and exports exactly the seven documented `sg_*` functions (verified with objdump). The MSVC build's link remains Windows CI's to prove.
- Whole file is read into memory; no streaming reader yet.
- Catalog-signed files report no embedded certificate table.
