---
agent: tester
seq: 4
title: Hygiene fixtures + per-lint tests
status: pending
touches:
  - testdata/generate.sh
  - testdata/hygiene_sha1_signature.pem
  - testdata/hygiene_rsa_1024.pem
  - testdata/hygiene_ecdsa_bad_curve.pem
  - crates/linter/tests/hygiene.rs
depends_on:
  - 03-register-hygiene-lints
---

# Task: Hygiene fixtures + per-lint tests

## Goal

One fixture per new hygiene lint plus integration tests; `expired.pem` (from feature 01)
covers `not_expired`. `good.pem` must pass all hygiene lints.

## Files Owned (conflict scope)

- `testdata/generate.sh` (extend; preserve earlier fixtures)
- `testdata/hygiene_sha1_signature.pem`, `testdata/hygiene_rsa_1024.pem`,
  `testdata/hygiene_ecdsa_bad_curve.pem`
- `crates/linter/tests/hygiene.rs`

## Steps

1. Extend `generate.sh` to emit:
   - `hygiene_sha1_signature.pem` — signed with a SHA-1 algorithm.
   - `hygiene_rsa_1024.pem` — RSA-1024 key.
   - `hygiene_ecdsa_bad_curve.pem` — an EC curve outside {P-256, P-384, P-521}
     (e.g. P-224 or secp256k1, whichever the toolchain can emit).
   Commit each generated `.pem`. (Note: some toolchains restrict weak keys/curves; if a
   fixture cannot be generated, document the limitation in the script and, if needed,
   hand-craft a minimal DER fixture and note its provenance.)
2. `crates/linter/tests/hygiene.rs` (SIFER, Result-assertion conventions):
   - `no_sha1_signature` flags `hygiene_sha1_signature.pem`, passes `good.pem`.
   - `rsa_key_min_2048` flags `hygiene_rsa_1024.pem`; is `NotApplicable` on an EC cert.
   - `ecdsa_curve_allowlist` flags `hygiene_ecdsa_bad_curve.pem`; is `NotApplicable` on an
     RSA cert; passes a P-256 cert (`good.pem` if EC, otherwise add a P-256 fixture).
   - `not_expired` flags `expired.pem`, passes `good.pem` (sanity, consolidated set).
   - Messages name the offending algorithm/curve/bit length (assert substring).

## Acceptance Criteria

- [ ] Three new fixtures exist; `generate.sh` regenerates them (or documents any toolchain
      limitation with a hand-crafted alternative).
- [ ] Each lint flags its fixture and is correctly `NotApplicable` for the wrong key type.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 03.
