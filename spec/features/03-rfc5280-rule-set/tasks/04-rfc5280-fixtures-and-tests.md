---
agent: tester
seq: 4
title: RFC 5280 fixtures + per-lint tests
status: done
touches:
  - testdata/generate.sh
  - testdata/good.pem
  - testdata/expired.pem
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

## REQUIRED: Regenerate shared fixtures good.pem and expired.pem (scope conflict from feature 03)

Feature 03 registered six RFC 5280 lints into `default_registry()`, including two CA-only
lints: `rfc5280_basic_constraints_critical_on_ca` and `rfc5280_key_usage_present_when_ca`.
The shared fixtures `testdata/good.pem` and `testdata/expired.pem` (from feature 01) are CA
certificates that LACK a KeyUsage extension, so `rfc5280_key_usage_present_when_ca` now fires
an `Error` on BOTH of them. This breaks the spec requirement (plan.md ~line 49: `good.pem`
must PASS all lints) and breaks three existing CLI integration tests in
`crates/cli/tests/output.rs` (feature 02) that assume good.pem/expired.pem produce no
error-severity findings:

- `text_output::source_rfc5280_on_expired_reports_no_findings`
- `text_output::min_severity_error_on_good_reports_no_findings`
- `text_output::min_severity_error_filters_the_warn_finding_on_expired`

Resolution — this task MUST regenerate the two shared fixtures (via `generate.sh`):

- `testdata/good.pem` — a clean LEAF certificate that passes ALL lints (hygiene + all six
  rfc5280). Make it a leaf (NOT a CA: `basicConstraints CA:FALSE` or absent) with a
  NON-EMPTY subject DN and a SAN, X.509 v3, a small positive serial (<= 20 octets, non-zero),
  a valid validity window (`notBefore` < `notAfter`), and a FAR-FUTURE `notAfter`. As a leaf
  with a non-empty subject, the CA-only lints and `san_present_if_subject_empty` all return
  `NotApplicable`, and the structural lints pass.
- `testdata/expired.pem` — the SAME shape as `good.pem` (clean leaf passing all six rfc5280
  lints) but with `notAfter` in the PAST, so it violates ONLY hygiene `not_expired`. This
  preserves the semantics of every feature 01/02 test using `expired.pem`: it must still
  yield exactly the `not_expired` warn and nothing else.

Regenerating these two MUST keep the existing tests green without editing their source:

- `crates/linter/tests/not_expired.rs` — good loads with no findings; expired loads with one
  warn.
- `crates/linter/tests/registry.rs` — default registry over expired yields the `not_expired`
  warn.
- The three CLI tests above in `crates/cli/tests/output.rs` — must return to
  "OK: no findings" naturally, WITHOUT editing `output.rs`.

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

   Fixture-generation difficulty (IMPORTANT): each of the six violating fixtures must
   violate EXACTLY ONE rule and pass all others. Some malformations cannot be produced by
   openssl directly — e.g. a v1 certificate that still carries extensions, or a serial of
   exactly 0. Where openssl cannot produce the required malformation, use an alternative
   (rcgen, or a hand-crafted / DER-edited certificate). Do NOT ship a fixture that violates
   the wrong rule (or more than one rule) — verify each fixture isolates its single intended
   violation before committing.
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
- [ ] Each violating fixture isolates exactly one rule (no fixture violates the wrong or an
      extra rule); openssl-impossible malformations are produced via rcgen / hand-crafted DER.
- [ ] Each lint flags its fixture and passes `good.pem`.
- [ ] CA-only lints are `NotApplicable` on a leaf.
- [ ] `testdata/good.pem` is regenerated as a clean leaf that passes ALL lints (hygiene +
      all six rfc5280, all CA-only lints `NotApplicable`); `generate.sh` regenerates it.
- [ ] `testdata/expired.pem` is regenerated as the same clean leaf with a past `notAfter`,
      yielding exactly the `not_expired` warn and no other findings; `generate.sh`
      regenerates it.
- [ ] After this task, the FULL `cargo test` suite is green — including the three previously
      failing CLI tests (`source_rfc5280_on_expired_reports_no_findings`,
      `min_severity_error_on_good_reports_no_findings`,
      `min_severity_error_filters_the_warn_finding_on_expired`) — WITHOUT modifying
      `crates/cli/tests/output.rs` or `crates/linter/tests/registry.rs`.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 03 (lints must be registered and the facade/lints in place).
