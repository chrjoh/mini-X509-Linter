---
agent: tester
seq: 4
title: Fixtures (good/expired) + not_expired tests
status: done
touches:
  - testdata/good.pem
  - testdata/expired.pem
  - testdata/generate.sh
  - crates/linter/tests/not_expired.rs
depends_on:
  - 02-cert-facade-and-not-expired-lint
---

# Task: Fixtures (good/expired) + not_expired tests

## Goal

Provide the first test fixtures and an integration test that verifies the `not_expired`
lint and the `Cert` facade against real certificates.

## Files Owned (conflict scope)

- `testdata/good.pem`
- `testdata/expired.pem`
- `testdata/generate.sh`
- `crates/linter/tests/not_expired.rs`

## Steps

1. `testdata/generate.sh` — a small committed script (openssl or rcgen) that regenerates
   the fixtures deterministically. Document required tooling at the top.
   - `good.pem` — a self-signed cert with a far-future `notAfter` (passes `not_expired`).
   - `expired.pem` — a cert with a past `notAfter` (violates `not_expired`).
   - Commit both generated `.pem` files alongside the script.
2. `crates/linter/tests/not_expired.rs` — integration test following SIFER and the
   project testing rules:
   - Group tests in a `mod` per behaviour.
   - Load `expired.pem`, run `NotExpired::check`, assert exactly one `Severity::Warn`
     finding (inspect with `matches!` / direct field assertions).
   - Load `good.pem`, assert `check` returns an empty `Vec`.
   - Assert `Cert::load` returns `Ok` for both (use `.unwrap()` so the `Err` prints on
     failure, per the Result-assertion convention).
   - Add a DER round-trip case if a `.der` fixture is easy to produce (optional).

## Acceptance Criteria

- [ ] `testdata/good.pem` and `testdata/expired.pem` exist and parse via `Cert::load`.
- [ ] `generate.sh` regenerates both fixtures.
- [ ] `cargo test -p linter` passes; tests use `unwrap()`/`unwrap_err()` not
      `assert!(is_ok())`.
- [ ] `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 02 (needs `Cert` + `NotExpired`). The fixtures here are reused/extended
  by later feature test plans.
