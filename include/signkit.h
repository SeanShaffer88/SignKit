/* SignKit.dll — Authenticode inspection and verification
 * helpers for Windows PE files, behind a small C ABI.
 *
 * All strings are UTF-8 and NUL-terminated. char* results
 * are caller-owned: free them with sg_free_string(). On
 * failure a result function returns NULL and the details are
 * in sg_last_error() / sg_last_error_code() (thread-local).
 *
 * SIGNING IS NOT PROVIDED. This library inspects PE files
 * and verifies existing Authenticode signatures. It cannot
 * sign a file: signing requires a code-signing certificate,
 * and SignKit ships no signing entry point. There is no
 * sg_sign — do not look for one, and do not trust any build
 * of this header that claims one exists.
 */
#ifndef SIGNKIT_H
#define SIGNKIT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#if defined(_WIN32) && defined(SG_BUILD)
#define SG_API __declspec(dllexport)
#elif defined(_WIN32)
#define SG_API __declspec(dllimport)
#else
#define SG_API
#endif

/* Result / error codes (sg_last_error_code values). */
#define SG_OK 0
#define SG_ERR_INVALID_ARG 1   /* bad argument, or a malformed PE file */
#define SG_ERR_NOT_SUPPORTED 2 /* needs Windows; called elsewhere */
#define SG_ERR_NOT_FOUND 3     /* the file does not exist */
#define SG_ERR_ACCESS_DENIED 4 /* the file could not be read */
#define SG_ERR_PLATFORM 5      /* OS failure (incl. WinVerifyTrust errors) */
#define SG_ERR_INTERNAL 6      /* internal failure (a caught panic) */

/* Library version string, e.g. "0.1.0". Static storage:
 * do NOT free the returned pointer. */
SG_API const char *sg_version(void);

/* Thread-local message describing the most recent failure
 * on this thread ("" when the last call succeeded). Static
 * storage owned by the library: do NOT free it. */
SG_API const char *sg_last_error(void);

/* Thread-local code for the most recent failure on this
 * thread (SG_OK when the last call succeeded). */
SG_API int sg_last_error_code(void);

/* Free a string returned by sg_inspect, sg_authenticode_hash
 * or sg_verify. NULL is accepted and does nothing. Freeing a
 * pointer this library did not return, or freeing twice, is
 * a caller bug. */
SG_API void sg_free_string(char *p);

/* Inspect a PE file and return a JSON report:
 *   {"path":"...","is_pe":true,"pe_kind":"exe","bits":64,
 *    "machine":"x86-64 (AMD64)","machine_value":34404,
 *    "timestamp":1579105280,"checksum_field":2864434397,
 *    "has_signature":true,
 *    "cert_table":{"file_offset":12345,"size":9876},
 *    "signer_blob_size":9000,"overlay_bytes":0,"sections":6,
 *    "file_size":54321}
 *
 * Field notes:
 * - pe_kind is "exe", "dll", "sys" (native subsystem) or
 *   "unknown", classified from the COFF characteristics and
 *   the optional-header subsystem.
 * - bits is 32 or 64 (PE32 / PE32+).
 * - machine is a display name for common machine codes
 *   (machine_value always carries the raw code).
 * - timestamp is the raw COFF TimeDateStamp (seconds since
 *   the Unix epoch, as stored — linkers may write anything).
 * - checksum_field is the CheckSum value stored in the
 *   optional header (what it claims, not a recomputation).
 * - cert_table is the security directory entry: for this
 *   directory, file_offset is a plain file offset. It is
 *   null when the file is unsigned.
 * - signer_blob_size is the WIN_CERTIFICATE payload length
 *   (dwLength minus its 8-byte header), or null.
 * - overlay_bytes counts bytes that are neither headers,
 *   section raw data, nor the certificate table.
 * - A file that is not a PE at all reports {"is_pe":false,
 *   "file_size":N} and is NOT an error. A file that claims
 *   to be a PE but is malformed or truncated fails with
 *   SG_ERR_INVALID_ARG.
 * Works on every platform (pure byte parsing). */
SG_API char *sg_inspect(const char *path);

/* Compute the Authenticode image hash of a PE file and
 * return it as a 64-character lowercase hex SHA-256 string.
 * The hash covers every byte except the CheckSum field, the
 * security directory entry itself, and the certificate
 * table; bytes after the certificate table are included in
 * whole 8-byte blocks only (the specification's alignment
 * rule). A file that is not a PE fails with
 * SG_ERR_INVALID_ARG.
 *
 * This is an inspection value: it is the digest a signature
 * would have to match, NOT a trust decision. Use sg_verify
 * for trust. */
SG_API char *sg_authenticode_hash(const char *path);

/* Verify a file's Authenticode signature and return a JSON
 * verdict:
 *   {"path":"...","status":"trusted","code":0,
 *    "code_hex":"0x00000000","message":"..."}
 * status is one of:
 * - "trusted":   WinVerifyTrust accepted the signature and
 *                its certificate chain.
 * - "unsigned":  the file carries no signature
 *                (TRUST_E_NOSIGNATURE, 0x800B0100).
 * - "untrusted": a signature exists but was rejected —
 *                signer not trusted, untrusted root, expired
 *                or revoked certificate, digest mismatch and
 *                kin; code / code_hex carry the raw error.
 * Any other WinVerifyTrust failure returns NULL with
 * SG_ERR_PLATFORM. Windows only: elsewhere this fails with
 * SG_ERR_NOT_SUPPORTED. A "trusted" verdict comes only from
 * WinVerifyTrust — no other function in this library makes
 * trust claims. */
SG_API char *sg_verify(const char *path);

#ifdef __cplusplus
}
#endif
#endif
