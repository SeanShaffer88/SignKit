//! Hand-rolled PE (Portable Executable) reader and the
//! Authenticode image hash. Pure byte work: this module runs
//! on every platform and never touches an OS API, so the same
//! code CI exercises on Linux is what reads files on Windows.
//!
//! Robustness rule: every read is bounds-checked and every
//! structural surprise is a clean `Err`, never a panic. A
//! malformed or truncated file is an expected input, not a
//! bug — the test suite feeds every truncation prefix of a
//! fixture through both entry points.

use crate::json::{self, Value};
use crate::sha256::Sha256;
use crate::{SgResult, ERR_INVALID_ARG};

fn malformed<T>(msg: impl Into<String>) -> SgResult<T> {
    Err((ERR_INVALID_ARG, format!("malformed PE: {}", msg.into())))
}

fn u16_at(data: &[u8], off: usize) -> SgResult<u16> {
    let b = data
        .get(off..off + 2)
        .ok_or((ERR_INVALID_ARG, "unexpected end of file".to_string()))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], off: usize) -> SgResult<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or((ERR_INVALID_ARG, "unexpected end of file".to_string()))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The security directory entry: for this one directory the
/// "virtual address" field is a plain file offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertTable {
    pub file_offset: u32,
    pub size: u32,
}

/// Everything `sg_inspect` reports, plus the field offsets
/// the Authenticode hash needs.
#[derive(Clone, Debug)]
pub struct PeInfo {
    pub pe_kind: &'static str,
    pub bits: u32,
    pub machine: u16,
    pub timestamp: u32,
    pub checksum_field: u32,
    pub cert_table: Option<CertTable>,
    /// WIN_CERTIFICATE payload length (`dwLength` minus the
    /// 8-byte header). `None` when there is no certificate.
    pub signer_blob_size: Option<u32>,
    pub overlay_bytes: u64,
    pub sections: u16,
    /// File offset of the CheckSum field (skipped by the hash).
    pub checksum_offset: usize,
    /// File offset of the security directory entry, when the
    /// optional header carries at least 5 directories.
    pub security_entry_offset: Option<usize>,
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x8664 => "x86-64 (AMD64)",
        0x014C => "i386",
        0xAA64 => "ARM64",
        0x01C0 => "ARM",
        0x01C4 => "ARMv7 (Thumb-2)",
        0x0200 => "IA-64",
        0x01F0 => "PowerPC",
        0x0166 => "MIPS (little-endian)",
        0x01A6 => "MIPS16",
        0x01D3 => "AM33",
        0x01F1 => "PowerPC (with FP)",
        0x5032 => "RISC-V (32-bit)",
        0x5064 => "RISC-V (64-bit)",
        _ => "unknown",
    }
}

// COFF characteristics used for pe_kind classification.
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;
// Optional-header subsystem value for native (driver) images.
const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;

/// Parse `data` as a PE image. Returns `Ok(None)` when the
/// file plainly is not a PE (no `MZ` magic). Anything that
/// claims to be one but is structurally broken is `Err`.
pub fn parse_pe(data: &[u8]) -> SgResult<Option<PeInfo>> {
    if data.len() < 2 || &data[0..2] != b"MZ" {
        return Ok(None);
    }
    let pe_off = u32_at(data, 0x3C)? as usize;
    let sig = data
        .get(pe_off..pe_off + 4)
        .ok_or((ERR_INVALID_ARG, "unexpected end of file".to_string()))?;
    if sig != b"PE\0\0" {
        return malformed(format!("no PE signature at offset {pe_off}"));
    }
    let coff = pe_off + 4;
    let machine = u16_at(data, coff)?;
    let sections = u16_at(data, coff + 2)?;
    let timestamp = u32_at(data, coff + 4)?;
    let opt_size = u16_at(data, coff + 16)? as usize;
    let characteristics = u16_at(data, coff + 18)?;
    if opt_size < 2 {
        return malformed("optional header is missing");
    }
    let opt = coff + 20;
    let magic = u16_at(data, opt)?;
    let (bits, num_dirs_off, dirs_off) = match magic {
        0x10B => (32, 92usize, 96usize),
        0x20B => (64, 108usize, 112usize),
        _ => {
            return malformed(format!(
                "unknown optional-header magic 0x{magic:04X} (not PE32/PE32+)"
            ))
        }
    };
    // CheckSum lives at optional-header offset 64 in both formats.
    let checksum_offset = opt + 64;
    let checksum_field = u32_at(data, checksum_offset)?;
    let subsystem = if opt_size >= 70 {
        u16_at(data, opt + 68)?
    } else {
        0
    };
    let num_dirs = if opt_size >= num_dirs_off + 4 {
        u32_at(data, opt + num_dirs_off)?
    } else {
        0
    };
    let security_entry_offset = if num_dirs >= 5 && opt_size >= dirs_off + 40 {
        Some(opt + dirs_off + 32)
    } else {
        None
    };
    let mut cert_table = None;
    let mut signer_blob_size = None;
    if let Some(entry) = security_entry_offset {
        let cert_off = u32_at(data, entry)?;
        let cert_size = u32_at(data, entry + 4)?;
        if cert_off != 0 && cert_size != 0 {
            let cert_end = cert_off as u64 + cert_size as u64;
            if cert_end > data.len() as u64 {
                return malformed(format!(
                    "certificate table at {cert_off} with size {cert_size} extends past end of file ({})",
                    data.len()
                ));
            }
            if cert_size < 8 {
                return malformed(format!(
                    "certificate table size {cert_size} is smaller than a WIN_CERTIFICATE header"
                ));
            }
            let dw_length = u32_at(data, cert_off as usize)?;
            if dw_length < 8 || dw_length > cert_size {
                return malformed(format!(
                    "WIN_CERTIFICATE length {dw_length} does not fit the certificate table size {cert_size}"
                ));
            }
            cert_table = Some(CertTable {
                file_offset: cert_off,
                size: cert_size,
            });
            signer_blob_size = Some(dw_length - 8);
        }
    }

    // Sections: validate raw ranges and find the end of the
    // section data, for the overlay calculation.
    let sec_table = opt + opt_size;
    let mut content_end = sec_table as u64 + sections as u64 * 40;
    for i in 0..sections as usize {
        let sh = sec_table + i * 40;
        let raw_size = u32_at(data, sh + 16)? as u64;
        let raw_ptr = u32_at(data, sh + 20)? as u64;
        if raw_size > 0 {
            let end = raw_ptr + raw_size;
            if end > data.len() as u64 {
                return malformed(format!(
                    "section {i} raw data at {raw_ptr} with size {raw_size} extends past end of file ({})",
                    data.len()
                ));
            }
            content_end = content_end.max(end);
        }
    }
    // Overlay = the bytes that are neither headers, section
    // raw data, nor the certificate table: whatever sits
    // between the last section and the certificate table,
    // plus anything after the table.
    let cert_size = cert_table.map(|c| c.size as u64).unwrap_or(0);
    let overlay_bytes = (data.len() as u64).saturating_sub(content_end + cert_size);

    let pe_kind = if subsystem == IMAGE_SUBSYSTEM_NATIVE {
        "sys"
    } else if characteristics & IMAGE_FILE_DLL != 0 {
        "dll"
    } else if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
        "exe"
    } else {
        "unknown"
    };

    Ok(Some(PeInfo {
        pe_kind,
        bits,
        machine,
        timestamp,
        checksum_field,
        cert_table,
        signer_blob_size,
        overlay_bytes,
        sections,
        checksum_offset,
        security_entry_offset,
    }))
}

/// Build the `sg_inspect` JSON value for raw file bytes.
pub fn inspect_bytes(data: &[u8]) -> SgResult<Value> {
    match parse_pe(data)? {
        None => Ok(json::obj(vec![
            ("is_pe", json::b(false)),
            ("file_size", json::n(data.len() as u64)),
        ])),
        Some(info) => {
            let cert = match info.cert_table {
                Some(c) => json::obj(vec![
                    ("file_offset", json::n(c.file_offset as u64)),
                    ("size", json::n(c.size as u64)),
                ]),
                None => Value::Null,
            };
            let blob = match info.signer_blob_size {
                Some(n) => json::n(n as u64),
                None => Value::Null,
            };
            Ok(json::obj(vec![
                ("is_pe", json::b(true)),
                ("pe_kind", json::s(info.pe_kind)),
                ("bits", json::n(info.bits as u64)),
                ("machine", json::s(machine_name(info.machine))),
                ("machine_value", json::n(info.machine as u64)),
                ("timestamp", json::n(info.timestamp as u64)),
                ("checksum_field", json::n(info.checksum_field as u64)),
                ("has_signature", json::b(info.cert_table.is_some())),
                ("cert_table", cert),
                ("signer_blob_size", blob),
                ("overlay_bytes", json::n(info.overlay_bytes)),
                ("sections", json::n(info.sections as u64)),
                ("file_size", json::n(data.len() as u64)),
            ]))
        }
    }
}

/// The Authenticode image hash (SHA-256 form), exactly as
/// this kit defines it:
///
/// 1. Hash from the start of the file to the CheckSum field.
/// 2. Skip the 4-byte CheckSum field; hash from there to the
///    security directory entry.
/// 3. Skip the 8-byte security directory entry; hash from
///    there to the start of the certificate table, or to end
///    of file when there is none.
/// 4. Extra tail rule: bytes physically after the certificate
///    table (the file length minus the certificate table size
///    leaves them unaccounted) are hashed too, but only in
///    whole 8-byte blocks — a trailing partial block of fewer
///    than 8 bytes is left out, per the alignment rule in the
///    Microsoft PE Authenticode specification.
///
/// `sum_of_bytes_hashed` accounting is tracked alongside, as
/// the spec prescribes. When the optional header carries no
/// security entry at all (fewer than 5 directories), step 3
/// simply continues from after the CheckSum field.
pub fn authenticode_hash(data: &[u8]) -> SgResult<String> {
    let info = match parse_pe(data)? {
        Some(i) => i,
        None => return Err((ERR_INVALID_ARG, "not a PE file (no MZ header)".to_string())),
    };
    let len = data.len();
    let cert_off = info.cert_table.map(|c| c.file_offset as usize);
    let cert_size = info.cert_table.map(|c| c.size as usize).unwrap_or(0);
    let hash_end = cert_off.unwrap_or(len);
    if hash_end > len {
        return malformed("certificate table starts past end of file");
    }

    fn feed_range(
        hasher: &mut Sha256,
        sum: &mut usize,
        data: &[u8],
        start: usize,
        end: usize,
    ) -> SgResult<()> {
        if start > end || end > data.len() {
            return malformed("hash range out of bounds");
        }
        hasher.update(&data[start..end]);
        *sum += end - start;
        Ok(())
    }

    let mut hasher = Sha256::new();
    let mut sum_of_bytes_hashed: usize = 0;
    let cs = info.checksum_offset;
    feed_range(&mut hasher, &mut sum_of_bytes_hashed, data, 0, cs)?;
    match info.security_entry_offset {
        Some(sec) => {
            feed_range(&mut hasher, &mut sum_of_bytes_hashed, data, cs + 4, sec)?;
            if sec + 8 > hash_end {
                return malformed("security directory entry overlaps the certificate table");
            }
            feed_range(
                &mut hasher,
                &mut sum_of_bytes_hashed,
                data,
                sec + 8,
                hash_end,
            )?;
        }
        None => {
            feed_range(
                &mut hasher,
                &mut sum_of_bytes_hashed,
                data,
                cs + 4,
                hash_end,
            )?;
        }
    }

    // Step 4: the extra tail after the certificate table.
    if let Some(off) = cert_off {
        let cert_end = off + cert_size;
        // Bytes the main pass has not accounted for, in the
        // spec's terms: (file length - cert size) - hashed.
        let unaccounted = (len - cert_size).saturating_sub(sum_of_bytes_hashed);
        let physical_tail = len.saturating_sub(cert_end);
        let extra = unaccounted.min(physical_tail);
        let aligned = extra - (extra % 8);
        if aligned > 0 {
            feed_range(
                &mut hasher,
                &mut sum_of_bytes_hashed,
                data,
                cert_end,
                cert_end + aligned,
            )?;
        }
    }

    Ok(hasher.finalize_hex())
}

/// Byte-by-byte PE fixture builder shared by the test
/// modules. Every field the parser reads is written
/// explicitly, so a fixture is a specification of the layout,
/// not a captured binary.
#[cfg(test)]
pub mod tests_fixture {
    fn w16(d: &mut [u8], off: usize, v: u16) {
        d[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn w32(d: &mut [u8], off: usize, v: u32) {
        d[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    pub struct FixtureSpec {
        pub bits64: bool,
        pub machine: u16,
        pub characteristics: u16,
        pub subsystem: u16,
        pub timestamp: u32,
        pub overlay: usize,
        pub cert: bool,
        /// Extra padding bytes inside the certificate table,
        /// beyond the WIN_CERTIFICATE length.
        pub cert_pad: usize,
        /// Bytes physically after the certificate table.
        pub post_cert_tail: usize,
    }

    impl Default for FixtureSpec {
        fn default() -> Self {
            FixtureSpec {
                bits64: true,
                machine: 0x8664,
                characteristics: 0x0022, // executable | large-address-aware
                subsystem: 3,            // Windows CUI
                timestamp: 0x5E1F_3C00,
                overlay: 0,
                cert: false,
                cert_pad: 0,
                post_cert_tail: 0,
            }
        }
    }

    pub fn build(spec: &FixtureSpec) -> Vec<u8> {
        let pe_off = 0x80usize;
        let opt_size = if spec.bits64 { 240 } else { 224 };
        let coff = pe_off + 4;
        let opt = coff + 20;
        let sec_table = opt + opt_size;
        let headers_end = sec_table + 40;
        let raw_ptr = headers_end;
        let raw_size = 16usize;
        let mut data = vec![0u8; raw_ptr + raw_size];
        for i in 0..raw_size {
            data[raw_ptr + i] = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        data[0] = b'M';
        data[1] = b'Z';
        w32(&mut data, 0x3C, pe_off as u32);
        data[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        w16(&mut data, coff, spec.machine);
        w16(&mut data, coff + 2, 1); // one section
        w32(&mut data, coff + 4, spec.timestamp);
        w16(&mut data, coff + 16, opt_size as u16);
        w16(&mut data, coff + 18, spec.characteristics);
        w16(&mut data, opt, if spec.bits64 { 0x20B } else { 0x10B });
        w32(&mut data, opt + 4, raw_size as u32); // SizeOfCode
        w32(&mut data, opt + 32, 0x1000); // SectionAlignment
        w32(&mut data, opt + 36, 0x200); // FileAlignment
        w32(&mut data, opt + 56, 0x2000); // SizeOfImage
        w32(&mut data, opt + 60, headers_end as u32); // SizeOfHeaders
        w32(&mut data, opt + 64, 0xAABB_CCDD); // CheckSum field
        w16(&mut data, opt + 68, spec.subsystem);
        let (nd_off, dirs_off) = if spec.bits64 { (108, 112) } else { (92, 96) };
        w32(&mut data, opt + nd_off, 16); // NumberOfRvaAndSizes
        data[sec_table..sec_table + 5].copy_from_slice(b".text");
        w32(&mut data, sec_table + 8, raw_size as u32); // VirtualSize
        w32(&mut data, sec_table + 12, 0x1000); // VirtualAddress
        w32(&mut data, sec_table + 16, raw_size as u32); // SizeOfRawData
        w32(&mut data, sec_table + 20, raw_ptr as u32); // PointerToRawData
        data.extend(std::iter::repeat(0xEE).take(spec.overlay));
        if spec.cert {
            let cert_off = data.len();
            let blob_len = 16usize;
            let dw_length = (8 + blob_len) as u32;
            let cert_size = dw_length as usize + spec.cert_pad;
            let sec_entry = opt + dirs_off + 32;
            w32(&mut data, sec_entry, cert_off as u32);
            w32(&mut data, sec_entry + 4, cert_size as u32);
            data.extend_from_slice(&dw_length.to_le_bytes());
            data.extend_from_slice(&0x0200u16.to_le_bytes()); // wRevision
            data.extend_from_slice(&0x0002u16.to_le_bytes()); // wCertificateType (PKCS_SIGNED_DATA)
            for i in 0..blob_len {
                data.push(0x40 + i as u8);
            }
            data.extend(std::iter::repeat(0xDD).take(spec.cert_pad));
        }
        data.extend(std::iter::repeat(0x77).take(spec.post_cert_tail));
        data
    }

    pub fn unsigned_pe64_exe() -> Vec<u8> {
        build(&FixtureSpec::default())
    }

    pub fn signed_pe32_dll() -> Vec<u8> {
        build(&FixtureSpec {
            bits64: false,
            machine: 0x014C,
            characteristics: 0x2102, // executable | 32-bit | DLL
            subsystem: 2,            // Windows GUI
            overlay: 10,
            cert: true,
            ..Default::default()
        })
    }

    pub fn signed_pe64_exe_with_tail(tail: usize) -> Vec<u8> {
        build(&FixtureSpec {
            cert: true,
            post_cert_tail: tail,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::tests_fixture::*;
    use super::*;
    use crate::sha256::sha256_hex;

    fn rd32(d: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
    }

    #[test]
    fn inspect_unsigned_exe() {
        let data = unsigned_pe64_exe();
        let info = parse_pe(&data).unwrap().unwrap();
        assert_eq!(info.pe_kind, "exe");
        assert_eq!(info.bits, 64);
        assert_eq!(info.machine, 0x8664);
        assert_eq!(info.timestamp, 0x5E1F_3C00);
        assert_eq!(info.checksum_field, 0xAABB_CCDD);
        assert_eq!(info.cert_table, None);
        assert_eq!(info.signer_blob_size, None);
        assert_eq!(info.overlay_bytes, 0);
        assert_eq!(info.sections, 1);

        let v = inspect_bytes(&data).unwrap();
        assert_eq!(v.get("machine").unwrap().as_str(), Some("x86-64 (AMD64)"));
        assert_eq!(v.get("machine_value").unwrap().as_i64(), Some(0x8664));
        assert_eq!(v.get("has_signature").unwrap().as_bool(), Some(false));
        assert_eq!(v.get("cert_table").unwrap(), &Value::Null);
    }

    #[test]
    fn inspect_signed_dll_with_overlay() {
        let data = signed_pe32_dll();
        let info = parse_pe(&data).unwrap().unwrap();
        assert_eq!(info.pe_kind, "dll");
        assert_eq!(info.bits, 32);
        assert_eq!(info.machine, 0x014C);
        let cert = info.cert_table.unwrap();
        assert_eq!(cert.size, 24); // 8-byte header + 16-byte blob
        assert_eq!(info.signer_blob_size, Some(16));
        // The cert table starts exactly at cert.file_offset:
        assert_eq!(rd32(&data, cert.file_offset as usize), 24);
        // 10 overlay bytes sit between the section data and
        // the certificate table; overlay counts them.
        assert_eq!(info.overlay_bytes, 10);

        let v = inspect_bytes(&data).unwrap();
        assert_eq!(v.get("has_signature").unwrap().as_bool(), Some(true));
        assert_eq!(
            v.get("cert_table").unwrap().get("size").unwrap().as_i64(),
            Some(24)
        );
        assert_eq!(v.get("signer_blob_size").unwrap().as_i64(), Some(16));
    }

    #[test]
    fn inspect_native_subsystem_is_sys() {
        let data = build(&FixtureSpec {
            subsystem: 1,
            ..Default::default()
        });
        let info = parse_pe(&data).unwrap().unwrap();
        assert_eq!(info.pe_kind, "sys");
    }

    #[test]
    fn not_a_pe() {
        assert!(parse_pe(b"hello world, plain text").unwrap().is_none());
        assert!(parse_pe(b"").unwrap().is_none());
        assert!(parse_pe(b"M").unwrap().is_none());
        let v = inspect_bytes(b"hello").unwrap();
        assert_eq!(v.get("is_pe").unwrap().as_bool(), Some(false));
        let err = authenticode_hash(b"hello").unwrap_err();
        assert_eq!(err.0, ERR_INVALID_ARG);
    }

    #[test]
    fn malformed_structures_are_errors_not_panics() {
        // MZ but a bogus signature.
        let mut bad = unsigned_pe64_exe();
        bad[0x80] = b'P';
        bad[0x81] = b'X';
        assert!(parse_pe(&bad).is_err());

        // Certificate table reaching past EOF.
        let mut bad = signed_pe32_dll();
        let pe_off = rd32(&bad, 0x3C) as usize;
        let sec_entry = pe_off + 4 + 20 + 96 + 32; // PE32 dirs at +96
        bad[sec_entry + 4..sec_entry + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_pe(&bad).is_err());

        // Section raw data reaching past EOF.
        let mut bad = unsigned_pe64_exe();
        let sec_table = 0x80 + 4 + 20 + 240;
        bad[sec_table + 16..sec_table + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_pe(&bad).is_err());
    }

    #[test]
    fn every_truncation_prefix_is_handled() {
        let data = signed_pe32_dll();
        for len in 0..=data.len() {
            let prefix = &data[..len];
            // Any result is acceptable (Ok or clean Err); a
            // panic here fails the test.
            let _ = parse_pe(prefix);
            let _ = inspect_bytes(prefix);
            let _ = authenticode_hash(prefix);
        }
    }

    /// Independent re-implementation of the hash for the
    /// tests: instead of streaming ranges into an incremental
    /// hasher like the library, it filters the file byte by
    /// byte through skip predicates and hashes the collected
    /// vector one-shot. Same documented rules, different
    /// structure.
    fn reference_authenticode_hash(data: &[u8]) -> String {
        let pe_off = rd32(data, 0x3C) as usize;
        let opt = pe_off + 4 + 20;
        let magic = u16::from_le_bytes([data[opt], data[opt + 1]]);
        let dirs = opt + if magic == 0x20B { 112 } else { 96 };
        let cs = opt + 64;
        let sec = dirs + 32;
        let cert_off = rd32(data, sec) as usize;
        let cert_size = rd32(data, sec + 4) as usize;
        let cert_end = cert_off + cert_size;
        let tail_len = data.len() - cert_end;
        let tail_aligned = tail_len - (tail_len % 8);
        let mut collected = Vec::new();
        for (i, byte) in data.iter().enumerate() {
            if (cs..cs + 4).contains(&i) {
                continue; // CheckSum field
            }
            if (sec..sec + 8).contains(&i) {
                continue; // security directory entry
            }
            if cert_size > 0 && (cert_off..cert_end).contains(&i) {
                continue; // certificate table
            }
            if cert_size > 0 && i >= cert_end && i - cert_end >= tail_aligned {
                continue; // unaligned remainder of the tail
            }
            collected.push(*byte);
        }
        sha256_hex(&collected)
    }

    #[test]
    fn hash_matches_independent_reimplementation() {
        for data in [
            unsigned_pe64_exe(),
            signed_pe32_dll(),
            signed_pe64_exe_with_tail(13),
            signed_pe64_exe_with_tail(16),
            build(&FixtureSpec {
                cert: true,
                cert_pad: 8,
                overlay: 5,
                ..Default::default()
            }),
        ] {
            assert_eq!(
                authenticode_hash(&data).unwrap(),
                reference_authenticode_hash(&data),
                "fixture of {} bytes",
                data.len()
            );
        }
    }

    #[test]
    fn hash_region_sensitivity() {
        let data = signed_pe64_exe_with_tail(13);
        let base = authenticode_hash(&data).unwrap();
        let pe_off = rd32(&data, 0x3C) as usize;
        let opt = pe_off + 4 + 20;
        let sec = opt + 112 + 32;
        let cs = opt + 64;
        let cert_off = rd32(&data, sec) as usize;
        let headers_end = 0x80 + 4 + 20 + 240 + 40;

        // A byte in the hashed section data changes the hash.
        let mut flipped = data.clone();
        flipped[headers_end] ^= 0xFF;
        assert_ne!(authenticode_hash(&flipped).unwrap(), base);

        // A byte in the DOS stub (hashed header range) changes it.
        let mut flipped = data.clone();
        flipped[10] ^= 0xFF;
        assert_ne!(authenticode_hash(&flipped).unwrap(), base);

        // The CheckSum field is excluded: flipping it changes nothing.
        let mut flipped = data.clone();
        flipped[cs] ^= 0xFF;
        assert_eq!(authenticode_hash(&flipped).unwrap(), base);

        // The certificate blob is excluded.
        let mut flipped = data.clone();
        flipped[cert_off + 10] ^= 0xFF;
        assert_eq!(authenticode_hash(&flipped).unwrap(), base);

        // The aligned part of the post-cert tail is hashed...
        let mut flipped = data.clone();
        flipped[data.len() - 13] ^= 0xFF; // first tail byte
        assert_ne!(authenticode_hash(&flipped).unwrap(), base);

        // ...but the unaligned remainder (last 5 of 13) is not.
        let mut flipped = data.clone();
        flipped[data.len() - 1] ^= 0xFF;
        assert_eq!(authenticode_hash(&flipped).unwrap(), base);
    }

    #[test]
    fn hash_unsigned_with_overlay_covers_overlay() {
        let data = build(&FixtureSpec {
            overlay: 6,
            ..Default::default()
        });
        assert_eq!(
            authenticode_hash(&data).unwrap(),
            reference_authenticode_hash(&data)
        );
        let mut flipped = data.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert_ne!(
            authenticode_hash(&flipped).unwrap(),
            authenticode_hash(&data).unwrap()
        );
    }

    #[test]
    fn inspect_path_reports_path_and_fields() {
        let dir = std::env::temp_dir().join(format!("signkit-inspect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("driver.sys");
        std::fs::write(
            &f,
            build(&FixtureSpec {
                subsystem: 1,
                ..Default::default()
            }),
        )
        .unwrap();
        let path = f.to_string_lossy().to_string();
        let v = crate::json::parse(&crate::inspect_path(&path).unwrap()).unwrap();
        assert_eq!(v.get("path").unwrap().as_str(), Some(path.as_str()));
        assert_eq!(v.get("pe_kind").unwrap().as_str(), Some("sys"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
