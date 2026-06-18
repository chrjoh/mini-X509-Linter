---
agent: developer
seq: 2
title: New RFC 5280 expansion lints
status: pending
touches:
  - crates/linter/src/lints/rfc5280/mod.rs
  - crates/linter/src/lints/rfc5280/ca_subject_field_empty.rs
  - crates/linter/src/lints/rfc5280/ext_key_usage_without_bits.rs
  - crates/linter/src/lints/rfc5280/ext_authority_key_identifier_no_key_identifier.rs
  - crates/linter/src/lints/rfc5280/subject_key_identifier_presence.rs
  - crates/linter/src/lints/rfc5280/path_len_constraint_improperly_included.rs
  - crates/linter/src/lints/rfc5280/ext_name_constraints_not_critical.rs
  - crates/linter/src/lints/rfc5280/subject_dn_country_not_printable_string.rs
  - crates/linter/src/lints/rfc5280/ext_san_no_entries.rs
  - crates/linter/src/lints/rfc5280/utc_time_not_in_zulu.rs
depends_on:
  - developer-01-cert-facade-expansion-accessors
---

# Task: New RFC 5280 expansion lints

## Goal

Implement the curated RFC 5280 depth-expansion lints, one small well-commented `Lint` impl per file
(except the two SKI-presence siblings, which share one file), each `RuleSource::Rfc5280`, `rfc5280_*`
id, citing its RFC section, following the exact shape of the existing 6 RFC lints (a pure
`evaluate(...)`/`applies` helper where useful + `#[cfg(test)] mod tests` with a pass and a fail case).

All read ONLY the facade accessors from task 01. **None may fire on the current `good.pem`** — see the
plan's "good.pem Conformance Audit" (each is either PASS or `NotApplicable` on good.pem).

## Files Owned (conflict scope)

- `crates/linter/src/lints/rfc5280/mod.rs` (declare + re-export the new modules; keep existing
  declarations/order intact, append new ones)
- one file per lint (front-matter); `subject_key_identifier_presence.rs` houses BOTH SKI lints.

Does NOT touch `cert.rs` (task 01), `cabf_br/*` (task 03), or `registry.rs` (task 04).

## Steps (each tagged `RuleSource::Rfc5280`)

1. `rfc5280_ca_subject_field_empty` — `applies` = CA-only (`NotApplicable` on leaf via `is_ca()`);
   `check` → `Error` if `subject_is_empty()`. (§4.1.2.6)
2. `rfc5280_ext_key_usage_without_bits` — `applies` = EKU present (`NotApplicable` when
   `extended_key_usage()` is `None`); `check` → `Error` if `EkuView.is_empty`. (§4.2.1.12)
3. `rfc5280_ext_authority_key_identifier_no_key_identifier` — `applies` = AKI present; `check` →
   `Error` if `!AkiView.has_key_identifier`. (§4.2.1.1)
4. `subject_key_identifier_presence.rs` — TWO lints:
   - `rfc5280_ext_subject_key_identifier_missing_ca` — `applies` = CA-only; `check` → `Error` if
     `!has_subject_key_identifier()`. (§4.2.1.2)
   - `rfc5280_ext_subject_key_identifier_missing_sub_cert` — `applies` = non-CA leaf only; `check` →
     `Warn` (SHOULD) if `!has_subject_key_identifier()`. (§4.2.1.2)
5. `rfc5280_path_len_constraint_improperly_included` — `applies` = `basic_constraints().path_len` is
   `Some`; `check` → `Error` unless the cert is a CA with `keyCertSign` (i.e. `is_ca()` AND
   `key_usage().key_cert_sign`). (§4.2.1.9)
6. `rfc5280_ext_name_constraints_not_critical` — `applies` = NameConstraints present; `check` →
   `Error` if not critical. (§4.2.1.10)
7. `rfc5280_subject_dn_country_not_printable_string` — `applies` = `subject_country_is_printable_string()`
   is `Some` (i.e. a C attribute exists); `check` → `Error` if `Some(false)`. (§4.1.2.6 / App. A)
8. `rfc5280_ext_san_no_entries` — `applies` = SAN present; `check` → `Error` if `SanView.is_empty`.
   (§4.2.1.6)
9. `rfc5280_utc_time_not_in_zulu` — `applies` = either validity field `is_utc_time`; `check` → `Error`
   for each UTCTime field whose `is_zulu` is false (may emit up to two findings). (§4.1.2.5.1)
   - If task 01 cut the `validity_time_encodings()` accessor, CUT this lint too and note it.

Each file: doc comment citing the section, `Lint` impl, `#[cfg(test)] mod tests` with at least a pass
and a fail case (fixture-driven integration tests are owned by task 05).

## Acceptance Criteria

- [ ] All shipped RFC lints implemented (9 lint impls across 8 files; SKI file holds 2), each
      `rfc5280_*` id, each citing its section.
- [ ] CA-only / extension-present-only lints return `NotApplicable` correctly.
- [ ] Lints that can fail for multiple reasons return multiple `Finding`s (utc_time over two fields).
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths.
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean.

## Notes / Dependencies

- Depends on task 01. Blocks task 04 (registration references these types).
- Runs in the SAME batch as task 03 (cabf_br lints); the file sets are disjoint.
