---
agent: tester
seq: 4
title: RFC 5280 fixtures + per-lint tests
status: pending
touches:
  - testdata/generate.sh
  - testdata/rfc5280_version_not_v3.pem
  - testdata/rfc5280_serial_number_zero.pem
  - testdata/rfc5280_validity_inverted.pem
  - testdata/rfc5280_ca_bc_not_critical.pem
  - testdata/rfc5280_ca_missing_keycertsign.pem
  - testdata/rfc5280_empty_subject_no_san.pem
  - crates/linter/tests/rfc5280.rs
depends_on:
  - 03-register-rfc5280-lints
---

# Task: RFC 5280 fixtures + per-lint tests

## Goal

One fixture per RFC 5280 lint that violates exactly that rule, plus integration tests
asserting the expected severities. Reuse `good.pem` (must pass all six).

## Files Owned (conflict scope)

- `testdata/generate.sh` (extend the existing script; do not break feature 01/02 fixtures)
- the six `testdata/rfc5280_*.pem` fixtures
- `crates/linter/tests/rfc5280.rs`

## Steps

1. Extend `testdata/generate.sh` to emit one fixture per lint (openssl/rcgen), each
   violating exactly that rule and otherwise valid:
   - `rfc5280_version_not_v3.pem` — extensions present but version v1.
   - `rfc5280_serial_number_zero.pem` — serial = 0 (or negative/over-long variant).
   - `rfc5280_validity_inverted.pem` — `notAfter` <= `notBefore`.
   - `rfc5280_ca_bc_not_critical.pem` — CA cert, BasicConstraints not critical.
   - `rfc5280_ca_missing_keycertsign.pem` — CA cert without `keyCertSign`.
   - `rfc5280_empty_subject_no_san.pem` — empty subject DN, no SAN.
   Commit each generated `.pem`.
2. `crates/linter/tests/rfc5280.rs` (SIFER, Result-assertion conventions):
   - Per lint: load its fixture, run that lint's `check`, assert at least one expected
     `Severity::Error` finding with a relevant message substring.
   - Assert each lint returns empty findings on `good.pem`.
   - Assert CA-only lints report `NotApplicable` on a leaf fixture (e.g. `good.pem` if it
     is a leaf).
   - Run the full `default_registry()` over `good.pem` and assert no `Error`/`Fatal`
     findings from the RFC 5280 source.

## Acceptance Criteria

- [ ] Six fixtures exist, each isolating one violation; `generate.sh` regenerates them.
- [ ] Each lint flags its fixture and passes `good.pem`.
- [ ] CA-only lints are `NotApplicable` on a leaf.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 03 (lints must be registered and the facade/lints in place).
