---
agent: tester
seq: 4
title: BR fixtures + full cross-feature fixture/test regeneration
status: done
touches:
  - testdata/generate.sh
  - testdata/good.pem
  - testdata/expired.pem
  - testdata/rfc5280_serial_number_zero.pem
  - testdata/rfc5280_validity_inverted.pem
  - testdata/rfc5280_empty_subject_no_san.pem
  - testdata/rfc5280_version_not_v3.pem
  - testdata/hygiene_sha1_signature.pem
  - testdata/hygiene_rsa_1024.pem
  - testdata/hygiene_ecdsa_bad_curve.pem
  - testdata/cabf_br_validity_400_days.pem
  - testdata/cabf_br_cn_not_in_san.pem
  - testdata/cabf_br_internal_san.pem
  - testdata/cabf_br_missing_serverauth.pem
  - crates/linter/tests/cabf_br.rs
  - crates/linter/tests/rfc5280.rs
  - crates/linter/tests/hygiene.rs
  - crates/linter/tests/registry.rs
  - crates/cli/tests/output.rs
depends_on:
  - 03-register-cabf-br-lints
---

# Task: BR fixtures + full cross-feature fixture/test regeneration

## Goal

Implement broad-scoping's fixture cascade: regenerate EVERY non-CA leaf fixture so it is
BR-compliant except for its single intended violation, add the four BR per-lint fixtures, write the
BR integration tests, and update the cross-feature test files (constants + module docs) that the
regeneration touches. `good.pem` must pass the full 14-lint registry; `expired.pem` must isolate
ONLY `hygiene_not_expired`; every rfc5280/hygiene fixture must still isolate exactly its one rule.

This task is the OWNER of all shared/cross-feature fixtures and the test files that assert against
them (except `cert.rs`, whose unit-test rewrite is developer task 05).

## ⚠️ Time-Fragility (read first)

BR-compliant leaves use a currently-valid ≤398-day window `2026-06-01 → 2027-06-01` (365d). They
EXPIRE on 2027-06-01; after that, `hygiene_not_expired` fires on every leaf and the isolation tests
fail. Document this loudly in `generate.sh`'s header AND reference it in the test module docs.
Regenerate annually (slide the window forward). See plan.md "Validity-Window Strategy".

## Files Owned (conflict scope)

- `testdata/generate.sh` (rewrite windows + add SAN/EKU to leaves + add four BR fixtures + header note)
- All regenerated leaf `.pem` listed in front-matter + the four new `cabf_br_*.pem`.
- `crates/linter/tests/cabf_br.rs` (new).
- `crates/linter/tests/rfc5280.rs`, `crates/linter/tests/hygiene.rs`,
  `crates/linter/tests/registry.rs`, `crates/cli/tests/output.rs` (constants + module-doc updates).

Does NOT modify `cert.rs` (task 05) or any production `src/` (tasks 01–03).

## Steps

### 1. Rewrite `generate.sh`

- Add window constants: `BR_OK_NB="20260601000000Z"`, `BR_OK_NA="20270601000000Z"` (365d, currently
  valid); past expired window `EXPIRED_NB="20240101000000Z"`, `EXPIRED_NA="20240601000000Z"` (151d);
  400d window `VAL400_NB="20260601000000Z"`, `VAL400_NA="20270706000000Z"`. Keep `FAR_FUTURE_*` only
  for the CA fixtures (BR N/A there).
- Add a reusable leaf extension config carrying `subjectAltName`, `extendedKeyUsage=serverAuth`, and
  `basicConstraints=CA:FALSE`. Parameterise the SAN per fixture (since each leaf's SAN must include
  its own CN as a dNSName).
- Regenerate every non-CA leaf with SAN-including-CN + serverAuth + the appropriate window per the
  plan's "Per-Fixture Target Shape" table:
  - `good.pem`: CN=good.example, SAN DNS:good.example, serverAuth, BR_OK.
  - `expired.pem`: CN=expired.example, SAN DNS:expired.example, serverAuth, EXPIRED window.
  - `rfc5280_serial_number_zero.pem`: serial 0, else BR-compliant, BR_OK.
  - `rfc5280_validity_inverted.pem`: zero-length window at a FUTURE instant (e.g.
    `20270101000000Z` == `20270101000000Z`), serverAuth + SAN-with-CN.
  - `rfc5280_empty_subject_no_san.pem`: empty subject `/`, NO SAN, but serverAuth EKU + BR_OK window.
  - `rfc5280_version_not_v3.pem`: build BR-compliant v3 leaf (serverAuth + SAN-with-CN + BR_OK), then
    patch the DER version byte v3→v1 as today.
  - `hygiene_sha1_signature.pem` / `hygiene_rsa_1024.pem` / `hygiene_ecdsa_bad_curve.pem`: each its
    one hygiene violation; all gain serverAuth + SAN-with-CN + BR_OK.
- Add the four BR fixtures:
  - `cabf_br_validity_400_days.pem`: serverAuth + SAN-with-CN, VAL400 window (400d).
  - `cabf_br_cn_not_in_san.pem`: serverAuth, CN=cn-missing.example, SAN DNS:other.example (omits CN).
  - `cabf_br_internal_san.pem`: serverAuth, CN=public.example, SAN containing DNS:public.example
    (so cn_in_san stays quiet) PLUS DNS:internal.local AND IP:10.0.0.1 (multiple offenders).
  - `cabf_br_missing_serverauth.pem`: SAN-with-CN, EKU present WITHOUT serverAuth (clientAuth only).
- CA fixtures (`rfc5280_ca_bc_not_critical.pem`, `rfc5280_ca_missing_keycertsign.pem`) UNCHANGED.
- Run `bash testdata/generate.sh` and commit every regenerated/new `.pem`.

### 2. `crates/linter/tests/cabf_br.rs` (new; SIFER, Result-assertion conventions)

- Per lint: fixture → ≥1 expected finding with a relevant message substring (offending CN / SAN
  entry / duration); `good.pem` → empty findings.
- `cabf_br_no_internal_names_or_reserved_ip` over `cabf_br_internal_san.pem` → MULTIPLE findings.
- Boundary: 398d passes, the 400d fixture fires (message names the duration).
- All four BR lints `NotApplicable` on a CA cert (`rfc5280_ca_bc_not_critical.pem`).
- A subject with no CN → `cabf_br_cn_in_san` silent (use `rfc5280_empty_subject_no_san.pem`).

### 3. Cross-feature test-file updates

- `crates/linter/tests/registry.rs`: change `EXPIRED_NOT_AFTER` from `1_293_840_000` to
  `1_717_200_000` (2024-06-01). The two expired-isolation tests must still pass unchanged in logic.
- `crates/cli/tests/output.rs`: change `EXPIRED_NOT_AFTER` from `1_293_840_000` to `1_717_200_000`.
  The `(3 passed, 3 not applicable)` rfc5280-group assertion is UNCHANGED (BR is a different source).
- `crates/linter/tests/rfc5280.rs` and `crates/linter/tests/hygiene.rs`: assertion logic UNCHANGED;
  add a one-line module-doc note that BR lints are now in the default registry and the fixtures are
  BR-compliant-except-target (so a future maintainer understands why the fixtures carry SAN/EKU).
  Verify `good_pem_yields_no_error_or_fatal_findings` and the per-fixture isolation tests pass over
  the 14-lint registry.

## Acceptance Criteria

- [ ] All 9 non-CA leaf fixtures regenerated BR-compliant-except-target; 4 new BR fixtures added;
      2 CA fixtures unchanged. `generate.sh` carries the time-fragility header note.
- [ ] `good.pem` passes the full 14-lint registry; `expired.pem` isolates ONLY `hygiene_not_expired`.
- [ ] Every rfc5280/hygiene fixture still isolates exactly its one rule across the 14-lint registry.
- [ ] `EXPIRED_NOT_AFTER` updated to `1_717_200_000` in both `registry.rs` and `cli/output.rs`.
- [ ] `cabf_br.rs` covers per-lint flag/pass, multi-finding, boundary, no-CN, and CA-NotApplicable.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 03 (BR lints registered).
- Runs in the same batch as task 05 (cert.rs unit-test rewrite). The two touch DISJOINT files
  (this task: testdata + tests/* + cli/output.rs; task 05: `cert.rs` only), so there is no conflict.
  Task 05 depends on THIS task because it asserts against the regenerated `good.pem`.
