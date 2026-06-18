---
agent: tester
seq: 4
title: PQC fixtures (openssl ML-DSA/SLH-DSA) + pqc integration tests + CLI e2e
status: pending
touches:
  - testdata/generate.sh
  - testdata/pqc_mldsa_good.pem
  - testdata/pqc_slhdsa_good.pem
  - testdata/pqc_unknown_param_set.pem
  - testdata/pqc_spki_params_present.pem
  - testdata/pqc_sig_params_present.pem
  - testdata/pqc_bad_key_length.pem
  - testdata/pqc_bad_key_usage.pem
  - crates/linter/tests/pqc.rs
  - crates/linter/tests/registry.rs
  - crates/cli/tests/output.rs
depends_on:
  - developer-03-register-universal-source-and-cli-wiring
---

# Task: PQC fixtures + pqc integration tests + CLI e2e

## Goal

Add openssl-generated PQC fixtures (a clean ML-DSA leaf + a clean SLH-DSA leaf + one violating fixture
per lint that has a producible deviation), write the `pqc` integration tests, and add a CLI `--source
pqc` end-to-end test. CRITICAL: do NOT regenerate or modify any existing fixture — the PQC-SPKI gate
makes all `pqc` lints `NotApplicable` on existing RSA/EC fixtures, so no cascade.

## ⚠️ Fixtures: openssl-generated ONLY — NEVER cert-bar.

The linter must stay an INDEPENDENT oracle over cert-bar's PQC output. Generate every PQC fixture with
openssl (± documented DER byte-patch for deviations openssl cannot emit natively). Never source a fixture
from the user's cert-bar tool.

## ⚠️ openssl version (read first)

ML-DSA / SLH-DSA generation requires **openssl 3.5+** (verified on 3.6.2). The PQC section of
`generate.sh` MUST `openssl version`-check and fail loudly on an older openssl so a missing-algorithm
error is diagnosable. The two clean PQC leaves MUST be openssl-native (no byte-patching).

## ⚠️ Time-Fragility (read first)

The clean PQC leaves use a currently-valid window straddling "now" (`2026-06-01 → 2027-06-01`, aligned
with the existing `BR_OK` horizon). They EXPIRE ~2027-06-01; after that `hygiene_not_expired` fires on
them and isolation breaks. Document loudly in the PQC section header of `generate.sh` and reference it in
the `pqc.rs` module doc. Regenerate annually. Every violating fixture must also straddle "now" so ONLY
its target PQC rule fires (not `hygiene_not_expired`).

## Files Owned (conflict scope)

- `testdata/generate.sh` (append a SELF-CONTAINED PQC section: ML-DSA/SLH-DSA leaf configs + fixtures +
  the version-check + the fragility header note)
- the 7 new `pqc_*.pem`
- `crates/linter/tests/pqc.rs` (new)
- `crates/linter/tests/registry.rs` (bump the default lint-count assertion to the then-current baseline)
- `crates/cli/tests/output.rs` (ADD a pqc test; do not alter existing assertions)

Does NOT modify `cert.rs`, `source.rs`, `registry.rs` (the lib `src/`), `cli/main.rs`,
`cli/output.rs`, or any other existing fixture.

## What to Do

### 1. `generate.sh` — appended, self-contained PQC section

- `openssl version` guard requiring 3.5+; fail loudly otherwise.
- ML-DSA leaf config: ML-DSA-65 key, params absent, `keyUsage = digitalSignature`,
  `basicConstraints = CA:FALSE`. SLH-DSA leaf config: SLH-DSA-SHA2-128s analogue.
- A PQC-OK window constant straddling "now" (≤ window, currently valid), e.g. reuse/align with `BR_OK`
  (`2026-06-01 → 2027-06-01`).
- Generate the fixtures (see plan.md / test-plan.md Fixtures tables):
  - `pqc_mldsa_good.pem` — clean ML-DSA-65 leaf (openssl-native).
  - `pqc_slhdsa_good.pem` — clean SLH-DSA-SHA2-128s leaf (openssl-native).
  - `pqc_unknown_param_set.pem` — SLH-DSA-arc OID in an unassigned slot (e.g. `.32`) — likely a DER
    byte-patch of an arc digit; document.
  - `pqc_spki_params_present.pem` — ML-DSA key with a present (NULL) SPKI `parameters` field — likely a
    NULL-splice byte-patch; document.
  - `pqc_sig_params_present.pem` — PQC cert with a present signature `parameters` field — likely a
    byte-patch; document.
  - `pqc_bad_key_length.pem` — ML-DSA OID with a public-key length not matching the named set — likely a
    BIT STRING truncate/pad byte-patch; document.
  - `pqc_bad_key_usage.pem` — ML-DSA leaf asserting `keyEncipherment` (openssl config; should be native).
- For ANY deviation openssl cannot produce cleanly and that cannot be reasonably byte-patched, the tester
  decides per fixture: test that lint by **direct lint invocation** on a hand-built `Cert`, OR defer the
  lint+fixture together (pre-approved cut — reconcile the registry/CLI counts and note it). Document the
  decision per fixture in `pqc.rs` and in `generate.sh`.
- Run `bash testdata/generate.sh`; commit every new `.pem`. Do NOT touch existing fixtures. Restore
  tracked fixtures (if perturbed) with `git checkout -- 'testdata/*.pem'` — NEVER `git checkout --
  testdata/` (that would clobber `generate.sh`).

### 2. `crates/linter/tests/pqc.rs` (new; SIFER, `.unwrap()`/`.unwrap_err()` conventions)

- Per lint with a through-registry fixture: run the default registry on the fixture, assert exactly the
  target `pqc_*` finding fires (severity per the plan table) with a message substring naming the
  offending value (parameter set / expected-vs-actual length / KU bit), and both clean leaves produce no
  error/fatal PQC findings.
- `pqc_algorithm_known`: Error on `pqc_unknown_param_set.pem`; the length/family lints produce NO finding
  on it (unknown set has no known length) → isolates exactly `pqc_algorithm_known`.
- `pqc_key_usage_consistency`: assert the `keyEncipherment`-Error on `pqc_bad_key_usage.pem`; exercise
  the Warn paths (EE missing `digitalSignature`; CA missing `keyCertSign`) by direct invocation if a
  clean openssl fixture for each is not producible; document.
- **Scoping:** all PQC lints `NotApplicable` on a non-PQC cert (use `good.pem`); all `Applies` on
  `pqc_mldsa_good.pem` and `pqc_slhdsa_good.pem`.
- **No-cascade (BOTH directions):**
  - `default_registry().run()` on `good.pem` yields 5 (or 6) `pqc` outcomes all `NotApplicable` (empty
    findings) — confirms PQC lints do not touch RSA/EC fixtures.
  - On `pqc_mldsa_good.pem`, the hygiene key-strength lints (`hygiene_rsa_key_min_2048`,
    `hygiene_ecdsa_curve_allowlist`) are `NotApplicable` — confirms a PQC key does not trip RSA/EC
    hygiene checks.
- Module doc: note the time-fragility window, the openssl-version requirement, and the
  universal-source-but-self-gated design.

### 3. `crates/linter/tests/registry.rs` (count bump)

- If this integration test asserts the default total, bump it to the then-current baseline (52 → 57, or
  +6 with the optional lint; 61 → 66 if sibling 11 has landed). State the chosen baseline in a comment.
  No other change; `EXPIRED_*` constants unchanged.

### 4. `crates/cli/tests/output.rs` (ADD only)

- Running the CLI with `--source pqc` on `pqc_mldsa_good.pem` reports the `[pqc]` group with the 5 (or 6)
  PQC lints (all passed/applicable), and the `[pqc]` group renders in the documented `SOURCE_ORDER`
  position (after `[rfc5280]`).
- `--source pqc` on a non-PQC cert (`good.pem`) reports the `[pqc]` group with the PQC lints all
  NotApplicable (universal source filtered in, lints self-gate out — document this interaction).
- Do NOT change any existing assertion or constant.

## Acceptance Criteria

- [ ] 7 new openssl-generated PQC fixtures added (clean ML-DSA + clean SLH-DSA native; deviations via
      documented openssl config / DER byte-patch / direct-invocation-with-deferral); NO existing fixture
      modified; `generate.sh` PQC section carries the version check + fragility header note + per-fixture
      producibility notes.
- [ ] Both clean leaves pass the pqc set; each violating (or direct-invocation) case isolates exactly its
      one PQC rule.
- [ ] `pqc.rs` covers per-lint flag/pass, scoping (NotApplicable on non-PQC / Applies on PQC), and the
      no-cascade assertion in BOTH directions.
- [ ] `registry.rs` integration count bumped to the stated baseline; CLI e2e for `--source pqc` added
      (PQC cert + non-PQC cert cases); existing CLI/registry tests unchanged.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass (also
      `cargo test -p linter --features serde`).

## Notes / Dependencies

- Depends on task 03 (lints registered + universal source + CLI wired).
- If feature 06's golden-file snapshot already exists in `crates/*/tests/`, its regeneration must be
  folded into THIS task (add the snapshot file to `touches`) — see plan.md "Ripple Flag: Feature 06".
  The existing golden fixtures are RSA, so the PQC lints stay NotApplicable on them; only a new `[pqc]`
  bucket + the new PQC fixture rows appear. Check for an existing golden snapshot before starting.
