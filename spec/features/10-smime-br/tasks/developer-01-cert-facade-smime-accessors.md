---
agent: developer
seq: 1
title: Cert facade accessors for S/MIME BR lints
status: pending
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade accessors for S/MIME BR lints

## Goal

Add the read-only `Cert` facade accessors the `cabf_smime` lints need. Lints must read only through
the facade — nothing parses raw DER inside a lint. Follow the existing accessor style in `cert.rs`
exactly: `with_parsed`, `Result<_, CertError>`, a "# Errors" doc section, non-panicking, and a
`#[cfg(test)] mod tests` exercising each accessor against existing or new fixtures (new S/MIME
fixtures arrive in task 04, so prefer pure/helper-level unit tests here and defer
fixture-dependent assertions to the lints/integration tests where possible).

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs` (extend only — do not edit other crates' files).

This is the ONLY task in feature 10 that touches `cert.rs`.

## What to Do

Add these accessors (mirror the naming/return conventions of `san_dns_names`,
`subject_common_names`, `has_server_auth`, `extended_key_usage`):

1. `san_rfc822_names()` → `Result<Vec<String>, CertError>` — every `rfc822Name` (email) entry in
   the SAN, in encounter order. Empty vec when SAN absent or has none.
2. emailProtection EKU detection — add a `has_email_protection()` →
   `Result<bool, CertError>` predicate (OID `1.3.6.1.5.5.7.3.4`), mirroring `has_server_auth()`.
   Also add an `email_protection: bool` field to `EkuView` (x509-parser already exposes
   `eku.email_protection`; the dotted OID is already emitted in `eku_oid_strings`). Keep `EkuView`
   serde-derive intact.
3. `has_authority_key_identifier()` → `Result<bool, CertError>` — true iff the AKI extension is
   present.
4. CRL Distribution Points:
   - `has_crl_distribution_points()` → `Result<bool, CertError>` — true iff the CRL-DP extension is
     present.
   - `crl_distribution_point_uris()` → `Result<Vec<String>, CertError>` — every `fullName` URI
     (GeneralName::URI) across all distribution points, in encounter order. (Used by the http-scheme
     lint.) If x509-parser does not surface fullName URIs conveniently, reach for `der`/`oid-registry`
     (already present) behind the facade and document any new dependency in `crates/linter/Cargo.toml`.
5. `subject_email_addresses()` → `Result<Vec<String>, CertError>` — every `emailAddress`
   (OID `1.2.840.113549.1.9.1`) RDN value from the subject DN. (Used by the single-email lint.)
6. `subject_country_names()` → `Result<Vec<String>, CertError>` — every `countryName`
   (OID `2.5.4.6`) RDN value from the subject DN, raw (no validation — the lint validates length).

Each accessor: doc comment citing which lint consumes it, a "# Errors" section, non-panicking, and
treats a malformed/duplicated extension as absent rather than surfacing an error (same fail-safe
stance as `extended_key_usage`).

## Acceptance Criteria

- [ ] All six accessor groups present, documented, non-panicking, returning `Result<_, CertError>`.
- [ ] `EkuView` gains an `email_protection` field; `has_email_protection()` predicate added.
- [ ] Style matches existing `cert.rs` accessors (with_parsed, "# Errors", encounter order).
- [ ] Any new crate dependency documented in `crates/linter/Cargo.toml`.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (and with `--features serde`).
- [ ] `cargo fmt --check` clean.

## Notes / Dependencies

- Blocks task 02 (lints) and task 03 (registry/purpose wiring needs nothing new from here, but the
  `auto` resolver in task 03 uses `has_email_protection()`).
- Do NOT add `RuleSource::CabfSmime` here — that lives in `source.rs`, owned by task 02.
