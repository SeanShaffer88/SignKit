# SignKit — Roadmap

## Blocked

- **Signing (`sg_sign`)** — blocked on a code-signing certificate decision. Certificates cost money and need an owner decision about identity and storage (file vs. token vs. cloud HSM). Until that decision exists, SignKit stays inspect-and-verify only, and the docs keep saying so. When it unblocks, signing goes through the platform crypto APIs (no hand-rolled PKCS#7) and ships with the same honesty rules: if the platform cannot produce the signature, the call fails — it never fakes one.

## Planned

- **ISO-8601 timestamp string** next to the raw COFF TimeDateStamp in `sg_inspect`, once the family shares one civil-time conversion instead of each kit growing its own.
- **Streaming reads for very large files.** `sg_inspect` and `sg_authenticode_hash` currently read the whole file into memory; a seek-based reader would cap memory on multi-GB installers.
- **Signer summary in the inspect report** (subject name / issuer / digest algorithm) by decoding the PKCS#7 blob's certificates on the inspection side — clearly labelled as *what the blob claims*, never as a trust verdict. Trust stays WinVerifyTrust's job.
- **Catalog (`.cat`) awareness**: report when a file is likely catalog-signed so "unsigned" from the embedded-table check is not misread.

## Not planned

- Hand-rolled certificate chain building or revocation checking (WinVerifyTrust already does this correctly).
- Supporting digest algorithms other than SHA-256 for `sg_authenticode_hash` until a real file demands one.
