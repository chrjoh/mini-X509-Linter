---
agent: tester
seq: 4
title: Code-signing fixtures + cabf_cs integration tests + CLI e2e
status: pending
touches:
  - testdata/generate.sh
  - testdata/cabf_cs_good.pem
  - testdata/cabf_cs_missing_key_usage.pem
  - testdata/cabf_cs_rsa_2048.pem
  - testdata/cabf_cs_ecdsa_bad_curve.pem
  - testdata/cabf_cs_validity_40_months.pem
  - testdata/cabf_cs_validity_500_days.pem
  - testdata/cabf_cs_no_aia.pem
  - testdata/cabf_cs_no_crl.pem
  - crates/linter/tests/cabf_cs.rs
  - crates/cli/tests/output.rs
depends_on:
  - developer-03-register-purpose-and-cli-wiring
---

# Task: Code-signing fixtures + cabf_cs integration tests

## Goal

Add openssl-generated code-signing fixtures (one clean leaf + one violating fixture per lint that has a
through-registry path), write the `cabf_cs` integration tests, and add a CLI `--purpose code-signing` /
`--source cabf_cs` end-to-end test. CRITICAL: do NOT regenerate or modify any existing fixture — the
codeSigning-EKU gate makes all `cabf_cs` lints `NotApplicable` on existing fixtures, so no cascade.

## ⚠️ Fixtures: openssl-generated ONLY — NEVER cert-bar.

## ⚠️ Time-Fragility (read first)

CS leaves use a currently-valid window. `cabf_cs_good.pem` window must be ≤ 460 days AND straddle
"now" (e.g. `2026-06-01 → 2027-06-01`, 365d). It EXPIRES ~2027-06-01; after that `hygiene_not_expired`
fires on the CS fixtures and isolation breaks. Document loudly in `generate.sh`'s header and reference
it in the `cabf_cs.rs` module doc. Regenerate annually. The two validity-violating fixtures must also
straddle now so ONLY their target validity cap fires (not `hygiene_not_expired`).

## Files Owned (conflict scope)

- `testdata/generate.sh` (add CS leaf-extension config + the new fixtures; header note)
- the 8 new `cabf_cs_*.pem`
- `crates/linter/tests/cabf_cs.rs` (new)
- `crates/cli/tests/output.rs` (ADD a cabf_cs/code-signing test; do not alter existing assertions)

Does NOT modify `cert.rs`, `source.rs`, `registry.rs`, `cli/main.rs`, `cli/output.rs`, or any other
existing fixture.

## What to Do

### 1. `generate.sh`

- Add a code-signing leaf-extension config: `extendedKeyUsage = codeSigning`,
  `keyUsage = digitalSignature` (critical as appropriate), `basicConstraints = CA:FALSE`. Default key
  RSA-3072 / SHA-256.
- Add a CS-OK window constant (currently valid, ≤460d), e.g. `CS_OK_NB="20260601000000Z"`,
  `CS_OK_NA="20270601000000Z"` (365d).
- Generate the fixtures (see plan.md Fixtures table):
  - `cabf_cs_good.pem` — codeSigning + digitalSignature + RSA-3072/SHA-256 + CS_OK window + CA:FALSE +
    AIA + CRL-DP present. Clean; passes the full 22-lint registry.
  - `cabf_cs_missing_key_usage.pem` — codeSigning, NO digitalSignature KU (e.g. only keyEncipherment).
  - `cabf_cs_rsa_2048.pem` — codeSigning, RSA-2048 (passes hygiene's ≥2048, fails CS's ≥3072).
  - `cabf_cs_ecdsa_bad_curve.pem` — codeSigning, EC with non-named (explicit) params OR a
    hygiene-permitted-but-CS-disallowed curve; document the exact choice.
  - `cabf_cs_validity_40_months.pem` — codeSigning, ~40-month currently-valid window (>1188d).
  - `cabf_cs_validity_500_days.pem` — codeSigning, 500-day currently-valid window (>460d, ≤39 months).
  - `cabf_cs_no_aia.pem` — codeSigning, clean, NO AIA extension (keep CRL-DP present).
  - `cabf_cs_no_crl.pem` — codeSigning, clean, NO CRL-DP extension (keep AIA present).
  - All EXCEPT their single target deviation must be RFC-5280-/hygiene-clean and currently valid so
    each isolates exactly one CS rule across the full registry.
- Run `bash testdata/generate.sh`; commit every new `.pem`. Do NOT touch existing fixtures.

### 2. `crates/linter/tests/cabf_cs.rs` (new; SIFER, `.unwrap()`/`.unwrap_err()` conventions)

- Per lint with a through-registry fixture: run the default registry on the fixture, assert exactly the
  target `cabf_cs_*` finding fires (Error/Warn per the plan table) with a message substring naming the
  offending value (bit size / curve / duration), and `cabf_cs_good.pem` produces no error/fatal CS
  findings.
- `cabf_cs_validity_40_months.pem`: assert the 39-month Error fires; document that the 460-day Warn
  co-fires (a >39-month cert is necessarily >460 days) and assert that too. Use
  `cabf_cs_validity_500_days.pem` for the 460-day-only isolation (Warn fires, 39-month does NOT).
- `cabf_cs_eku_required`: invoke the lint DIRECTLY (`EkuRequired::new().check(&cert)`) on a
  non-codeSigning leaf (reuse `good.pem` from feature 05) to exercise the fail-closed Error path —
  because a non-codeSigning cert is gated `NotApplicable` and never reaches this lint via the registry.
  Also assert `applies()` is `NotApplicable` on that same non-codeSigning cert. Document why.
- Scoping: all 8 `cabf_cs` lints are `NotApplicable` on a non-codeSigning cert (use `good.pem`); all 8
  `Applies` on `cabf_cs_good.pem`.
- A no-codeSigning cert run through `default_registry().run()` yields 8 `cabf_cs` outcomes all
  `NotApplicable` (confirms no cascade onto existing fixtures).
- Module doc: note the time-fragility window and the codeSigning-gate design.

### 3. `crates/cli/tests/output.rs` (ADD only)

- Add a test that running the CLI with `--purpose code-signing` (or `--source cabf_cs`) on
  `cabf_cs_good.pem` reports the `[cabf_cs]` group with the 8 CS lints (all passed/applicable) and that
  the verbose `purpose:` header renders `code-signing`. Do NOT change any existing assertion or
  constant.

## Acceptance Criteria

- [ ] 8 new openssl-generated CS fixtures added; NO existing fixture modified; `generate.sh` carries
      the time-fragility header note and the CS leaf-extension config.
- [ ] `cabf_cs_good.pem` passes the full 22-lint registry; each violating fixture isolates exactly its
      one CS rule (with the documented 40-month/460-day co-fire exception).
- [ ] `cabf_cs.rs` covers per-lint flag/pass, the direct-call `eku_required` path, scoping
      (NotApplicable on non-codeSigning / Applies on codeSigning), and the no-cascade assertion.
- [ ] CLI e2e for `--purpose code-signing` / `--source cabf_cs` added; existing CLI tests unchanged.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass (also
      `cargo test -p linter --features serde`).

## Notes / Dependencies

- Depends on task 03 (lints registered + purpose + CLI wired).
- If feature 06's golden-file snapshot already exists in `crates/*/tests/`, its regeneration must be
  folded into THIS task (add the snapshot file to `touches`) — see plan.md "Ripple Flag: Feature 06".
  Check for an existing golden snapshot before starting.
