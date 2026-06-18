---
agent: developer
seq: 1
title: Cert facade code-signing accessors (codeSigning EKU, digitalSignature KU, AIA/CRL-DP presence)
status: done
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade code-signing accessors

## Goal

Add the small set of `Cert` facade accessors the `cabf_cs` lints need. All non-panicking, documented,
returning `Result<_, CertError>`, following the existing accessor style in `cert.rs`.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs`

Does NOT touch `source.rs`, the lint files, `registry.rs`, or the CLI (later tasks).

## What to Do

1. **codeSigning EKU detection** — `pub fn has_code_signing(&self) -> Result<bool, CertError>`:
   `true` iff the EKU view contains OID `1.3.6.1.5.5.7.3.3`. The existing `EkuView.oids` already
   carries every purpose OID, so this mirrors `has_server_auth()` (around `cert.rs:554`). For symmetry
   with `server_auth`/`client_auth`, optionally also add a `code_signing: bool` field to `EkuView`
   (populated in `extended_key_usage()` around `cert.rs:512`). If you add the field, document it.
2. **digitalSignature KU bit** — extend `KeyUsageView` (currently `cert.rs:88`, exposes only
   `key_cert_sign` + `critical`) with `pub digital_signature: bool` (KU bit 0), populated in
   `key_usage()` (around `cert.rs:379`). Document the bit with its RFC 5280 §4.2.1.3 reference.
3. **AIA presence** — `pub fn has_authority_info_access(&self) -> Result<bool, CertError>`: `true` iff
   the Authority Information Access extension is present. Presence only — do NOT enumerate
   accessLocation URIs (that is a deferred follow-up lint). Read via the existing `with_parsed` helper
   and `x509-parser`'s extension API.
4. **CRL-DP presence** — `pub fn has_crl_distribution_points(&self) -> Result<bool, CertError>`:
   `true` iff the CRL Distribution Points extension is present. Presence only.
5. Add `#[cfg(test)] mod tests` cases for the new accessors using existing fixtures where possible
   (e.g. assert `good.pem` / a feature-05 leaf reports `has_code_signing() == false`). The
   code-signing-specific positive cases (codeSigning present, digitalSignature present, AIA/CRL
   present) will be covered by the integration tests in task 04 against the new fixtures; a minimal
   in-file negative assertion here is sufficient.

## Acceptance Criteria

- [ ] `has_code_signing()`, `has_authority_info_access()`, `has_crl_distribution_points()` present and
      documented; all return `Result<_, CertError>` and never panic on cert data.
- [ ] `KeyUsageView` carries a documented `digital_signature` bit.
- [ ] (Optional) `EkuView.code_signing` field added and documented if chosen.
- [ ] Existing `cert.rs` tests still pass; new negative assertions added.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`).

## Notes / Dependencies

- Blocks task 02 (lints) and task 03 (registration / purpose).
- Reuse the existing `with_parsed` pattern; prefer `std`. Document any new crate (none expected).
