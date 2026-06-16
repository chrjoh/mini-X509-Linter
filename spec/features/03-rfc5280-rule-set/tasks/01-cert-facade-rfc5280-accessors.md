---
agent: developer
seq: 1
title: Cert facade accessors for RFC 5280 lints
status: pending
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade accessors for RFC 5280 lints

## Goal

Extend the `Cert` facade with the read-only accessors the six RFC 5280 lints need, so the
lints code against our facade (not `x509-parser`) and reach for `der` only behind it.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs`

This is the single owner of `cert.rs` in feature 03. The lint files (task 02) depend on
the accessors landing first.

## Steps

Add accessors (return owned/borrowed data as appropriate, no panics):

1. `version()` → cert version (v1/v2/v3) as an enum or `u8`.
2. `has_extensions()` → bool (any X.509v3 extensions present).
3. `serial_der_octets()` → the serial as raw big-endian octets (use `der` behind the
   facade for octet length / leading-byte inspection). Provide enough for
   `serial_number_positive`: sign bit and octet count (≤ 20).
4. `validity` accessors already exist (`not_before`/`not_after` from feature 01) — reuse.
5. `basic_constraints()` → `Option<BasicConstraints { is_ca, path_len, critical }>`
   exposing the `cA` flag and the extension's `critical` bit.
6. `key_usage()` → `Option<KeyUsage>` with at least a `key_cert_sign()` predicate and the
   `critical` bit.
7. `subject_is_empty()` → bool (subject DN has no RDNs).
8. `subject_alt_name()` → `Option<SanView { critical, is_empty }>` (full entry
   enumeration can wait for feature 05; here only presence + criticality + emptiness).

Document each accessor; keep them minimal and consistent with the existing style. No new
crate dependencies (use `x509-parser`, `der`, `oid-registry` already present).

## Acceptance Criteria

- [ ] All listed accessors exist, are documented, and return without panicking on missing
      fields (use `Option` where the field may be absent).
- [ ] Serial inspection uses `der` for raw octets, not string parsing.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Blocks task 02 (the lints) and indirectly task 03 (registration).
