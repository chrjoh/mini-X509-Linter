---
agent: developer
seq: 2
title: Implement the six RFC 5280 lints
status: done
touches:
  - crates/linter/src/lints/mod.rs
  - crates/linter/src/lints/rfc5280/mod.rs
  - crates/linter/src/lints/rfc5280/version_is_v3.rs
  - crates/linter/src/lints/rfc5280/serial_number_positive.rs
  - crates/linter/src/lints/rfc5280/validity_window.rs
  - crates/linter/src/lints/rfc5280/basic_constraints_critical_on_ca.rs
  - crates/linter/src/lints/rfc5280/key_usage_present_when_ca.rs
  - crates/linter/src/lints/rfc5280/san_present_if_subject_empty.rs
depends_on:
  - 01-cert-facade-rfc5280-accessors
---

# Task: Implement the six RFC 5280 lints

## Goal

Implement the RFC 5280 rule set, one small well-commented `Lint` impl per file, each citing
its RFC 5280 section and using the `rfc5280_*` `lint_id` convention.

## Files Owned (conflict scope)

- `crates/linter/src/lints/mod.rs` (add `pub mod rfc5280;`)
- `crates/linter/src/lints/rfc5280/mod.rs` (module wiring + re-exports)
- one file per lint (listed in front-matter)

Does NOT touch `cert.rs` (task 01) or `registry.rs` (task 03).

## Steps

Implement each lint against the facade accessors from task 01. All tagged
`RuleSource::Rfc5280`.

1. `version_is_v3` — `applies` = `Applies` when `has_extensions()`; `NotApplicable`
   otherwise. `check` → `Error` finding if `version() != v3`. (RFC 5280 §4.1.2.1)
2. `serial_number_positive` — `check` → `Error` if serial is non-positive (sign bit set /
   zero) OR exceeds 20 octets. May emit two distinct findings if both wrong. (§4.1.2.2)
3. `validity_window` (id `rfc5280_validity_not_after_after_not_before`) — `check` →
   `Error` if `not_after() <= not_before()`. (§4.1.2.5)
4. `basic_constraints_critical_on_ca` — `applies` = `Applies` only for CA certs
   (`basic_constraints().is_ca`); `check` → `Error` if BasicConstraints not marked
   critical. (§4.2.1.9)
5. `key_usage_present_when_ca` — `applies` = CA certs only; `check` → `Error` if KeyUsage
   absent or lacks `keyCertSign`. (§4.2.1.3)
6. `san_present_if_subject_empty` — `applies` = `Applies` when `subject_is_empty()`;
   `check` → `Error` if SAN absent, plus a finding if SAN present but not critical.
   (§4.1.2.6 / §4.2.1.6)

Each file: doc comment with the section number, `Lint` impl, and a `#[cfg(test)] mod tests`
with at least a pass and a fail case (fixture-driven integration tests are owned by task 04).

## Acceptance Criteria

- [ ] Six lints implemented, each `rfc5280_*` id, each citing its RFC section.
- [ ] CA-only lints return `NotApplicable` on a leaf.
- [ ] Lints that can fail for multiple reasons return multiple `Finding`s.
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01. Blocks task 03 (registration references these types).
