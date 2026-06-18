---
agent: developer
seq: 1
title: Cert facade accessors for the depth-expansion lints
status: pending
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade accessors for the depth-expansion lints

## Goal

Add the new read-only facade accessors/views the feature-12 RFC 5280 and BR lints need. ONE owner of
`cert.rs`. Lints (tasks 02/03) read ONLY through these. Follow the exact style of the existing
accessors: documented, non-panicking (`with_parsed`, treat malformed/absent as `None`/empty), a small
`*View` struct next to the existing ones, and `# Errors` sections.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs` (extend only — do not touch unrelated existing accessors/tests)

Does NOT touch any `lints/`, `registry.rs`, or test/fixture files.

## Steps

Add the following (names indicative; match house style):

1. `authority_key_identifier()` → `Result<Option<AkiView>, CertError>` where
   `AkiView { has_key_identifier: bool, critical: bool }`. `None` when the AKI extension is absent.
   `has_key_identifier` reflects whether the `keyIdentifier` field is present.
   (RFC 5280 §4.2.1.1) — consumed by the AKI lint.
2. `has_subject_key_identifier()` → `Result<bool, CertError>` — true iff the SKI extension is present.
   (RFC 5280 §4.2.1.2) — consumed by both SKI-presence lints.
3. `name_constraints()` → `Result<Option<NameConstraintsView>, CertError>` where
   `NameConstraintsView { critical: bool }`. `None` when absent. (RFC 5280 §4.2.1.10)
4. Extend `EkuView` with `is_empty: bool` — true when the EKU extension carries NO key purposes
   (not `any`, no recognised purposes, and empty `other`). Set it in `extended_key_usage()`.
   (RFC 5280 §4.2.1.12) — consumed by `ext_key_usage_without_bits`.
   - `SanView.is_empty` ALREADY EXISTS — reuse it for `ext_san_no_entries`; no new SAN accessor needed.
   - `BasicConstraintsView` ALREADY exposes `is_ca`, `path_len`, `critical`; `key_usage()` exposes
     `key_cert_sign`. The path-len-improperly-included lint composes these — no new accessor needed.
5. `subject_country_values()` → `Result<Vec<String>, CertError>` — the subject `countryName` (C, OID
   2.5.4.6) attribute values as strings, in order. Empty when no C attribute.
6. `subject_country_is_printable_string()` → `Result<Option<bool>, CertError>` — `None` when no C
   attribute; `Some(true)` when the C attribute value is DER-encoded as PrintableString (tag 0x13),
   `Some(false)` otherwise. Read the ASN.1 tag of the attribute value via `der`/raw bytes (x509-parser
   normalizes the string type away, so this MUST inspect the DER). Document the approach.
   (RFC 5280 Appendix A: `X520countryName ::= PrintableString`)
7. `subject_organizational_unit_count()` → `Result<usize, CertError>` — count of `organizationalUnitName`
   (OU, OID 2.5.4.11) attributes in the subject DN. (BR §7.1.4.2.2)
8. `validity_time_encodings()` → `Result<(TimeEncoding, TimeEncoding), CertError>` for
   `(not_before, not_after)`, where `TimeEncoding { is_utc_time: bool, is_zulu: bool }`. Inspect the
   raw DER of the Validity SEQUENCE: tag 0x17 = UTCTime, 0x18 = GeneralizedTime; `is_zulu` = the
   value's last content byte is `b'Z'`. Use `der`/raw DER. Document the approach.
   (RFC 5280 §4.1.2.5.1) — consumed by `utc_time_not_in_zulu`.
   - If this accessor proves disproportionately hard, it is PRE-APPROVED to cut it and the
     `rfc5280_utc_time_not_in_zulu` lint together (note the cut in the task status and tell the
     architect). It is the lowest-signal item of the RFC subset.

ALREADY-PRESENT accessors to reuse (do NOT re-add): `subject_common_names()`, `san_dns_names()`,
`san_ip_addresses()`, `is_ca()`, `key_usage()`, `basic_constraints()`, `subject_alt_name()`,
`extended_key_usage()`.

## Acceptance Criteria

- [ ] All new accessors/views present, documented (`# Errors`), and non-panicking on absent/malformed
      input (return `None`/empty, never `unwrap`/`panic!`).
- [ ] `EkuView` gains `is_empty`; `extended_key_usage()` populates it.
- [ ] Country-string-type and validity-time-encoding accessors inspect raw DER via `der`; the approach
      is documented in the doc comment.
- [ ] `#[cfg(test)] mod tests` covers each new accessor with at least one positive and one
      absent/negative case (use small embedded PEM/DER or `der`-level unit tests; do NOT depend on the
      not-yet-created feature-12 fixtures).
- [ ] No new crate dependency (use the existing `der`); if one is genuinely needed it is documented.
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean.

## Notes / Dependencies

- Blocks tasks 02 and 03 (both read these accessors).
- The existing `good_cert_*` unit tests must keep passing unchanged — do NOT edit them.
