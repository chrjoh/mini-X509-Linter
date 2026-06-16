---
agent: tester
seq: 4
title: CA/B Forum BR fixtures + per-lint tests
status: pending
touches:
  - testdata/generate.sh
  - testdata/cabf_br_validity_400_days.pem
  - testdata/cabf_br_cn_not_in_san.pem
  - testdata/cabf_br_internal_san.pem
  - testdata/cabf_br_missing_serverauth.pem
  - crates/linter/tests/cabf_br.rs
depends_on:
  - 03-register-cabf-br-lints
---

# Task: CA/B Forum BR fixtures + per-lint tests

## Goal

One fixture per BR lint isolating its violation, plus integration tests. `good.pem` (a
compliant TLS leaf) must pass all BR lints.

## Files Owned (conflict scope)

- `testdata/generate.sh` (extend; preserve earlier fixtures)
- `testdata/cabf_br_validity_400_days.pem`, `testdata/cabf_br_cn_not_in_san.pem`,
  `testdata/cabf_br_internal_san.pem`, `testdata/cabf_br_missing_serverauth.pem`
- `crates/linter/tests/cabf_br.rs`

## Steps

1. Extend `generate.sh` to emit:
   - `cabf_br_validity_400_days.pem` — leaf with ~400-day validity (>398).
   - `cabf_br_cn_not_in_san.pem` — CN value absent from SAN.
   - `cabf_br_internal_san.pem` — SAN containing an internal name and/or reserved IP
     (e.g. `foo.internal`, `10.0.0.1`).
   - `cabf_br_missing_serverauth.pem` — leaf without the serverAuth EKU.
   Ensure `good.pem` is a compliant TLS leaf (CN in SAN, public name, serverAuth, ≤398d).
   Commit each generated `.pem`.
2. `crates/linter/tests/cabf_br.rs` (SIFER, Result-assertion conventions):
   - Per lint: fixture → ≥1 expected finding with a relevant message substring (the
     offending CN / SAN entry / duration named); `good.pem` → empty findings.
   - `no_internal_names_or_reserved_ip` with multiple bad SAN entries → multiple findings.
   - All four BR lints `NotApplicable` on a CA cert fixture.
   - Optionally exercise `reserved::is_reserved_ip`/`is_internal_name` indirectly via the
     lint (the unit tests for the helper live with task 01).

## Acceptance Criteria

- [ ] Four fixtures exist; `generate.sh` regenerates them; `good.pem` passes all BR lints.
- [ ] Each lint flags its fixture with a descriptive message; multi-entry lint emits
      multiple findings.
- [ ] BR lints `NotApplicable` on a CA cert.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 03.
