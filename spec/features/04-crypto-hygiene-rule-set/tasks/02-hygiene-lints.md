---
agent: developer
seq: 2
title: Implement hygiene lints + consolidate not_expired
status: pending
touches:
  - crates/linter/src/lints/hygiene/mod.rs
  - crates/linter/src/lints/hygiene/no_sha1_signature.rs
  - crates/linter/src/lints/hygiene/rsa_key_min_2048.rs
  - crates/linter/src/lints/hygiene/ecdsa_curve_allowlist.rs
depends_on:
  - 01-cert-facade-spki-accessors
---

# Task: Implement hygiene lints + consolidate not_expired

## Goal

Implement the three new crypto-hygiene lints and confirm `not_expired` (from feature 01)
lives in and is exported from the hygiene module. All tagged `RuleSource::Hygiene`,
`hygiene_*` ids.

## Files Owned (conflict scope)

- `crates/linter/src/lints/hygiene/mod.rs` (add new modules; confirm `not_expired` export)
- `crates/linter/src/lints/hygiene/no_sha1_signature.rs`
- `crates/linter/src/lints/hygiene/rsa_key_min_2048.rs`
- `crates/linter/src/lints/hygiene/ecdsa_curve_allowlist.rs`

Does NOT modify `not_expired.rs` (already correct from feature 01) beyond confirming its
`mod`/re-export in `mod.rs`. Does NOT touch `cert.rs` (task 01) or `registry.rs` (task 03).

## Steps

1. `no_sha1_signature` — `applies` = `Applies` always; `check` → `Error` (or `Warn`, pick
   one and document) if the signature algorithm is SHA-1-based. Message names the offending
   algorithm.
2. `rsa_key_min_2048` — `applies` = `Applies` only when `public_key_algorithm()` is RSA
   (`NotApplicable` otherwise); `check` → `Error` if `rsa_modulus_bits() < 2048`. Message
   names the actual bit length.
3. `ecdsa_curve_allowlist` — `applies` = `Applies` only for EC keys; `check` → `Error` if
   the curve is not in {P-256, P-384, P-521}. Message names the offending curve.
4. In `mod.rs`, declare the three new modules, re-export their lint types, and confirm
   `pub mod not_expired;` + its re-export are present (fold the trivial lint into this set).

Each file: doc comment explaining the hygiene rationale, `Lint` impl, and a
`#[cfg(test)] mod tests` with a pass and a fail case.

## Acceptance Criteria

- [ ] Three new hygiene lints implemented with `hygiene_*` ids; `not_expired` confirmed in
      the module and exported.
- [ ] `rsa_key_min_2048` is `NotApplicable` for EC keys; `ecdsa_curve_allowlist` is
      `NotApplicable` for RSA keys.
- [ ] Messages name the offending algorithm / curve / bit length.
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01. Blocks task 03 (registration).
