---
agent: developer
seq: 5
title: Fix stale good.pem CA assertions in cert.rs unit tests
status: done
touches:
  - crates/linter/src/cert.rs
depends_on:
  - 04-rfc5280-fixtures-and-tests
---

# Task: Fix stale good.pem CA assertions in cert.rs unit tests

## Goal

Task 04 regenerated `testdata/good.pem` as a clean LEAF certificate (so it passes all seven
lints and only `expired.pem` violates `not_expired`). The `#[cfg(test)]` unit tests in
`crates/linter/src/cert.rs` (module `tests::rfc5280_accessors`, starting ~line 419) still
assert the OLD shape — that good.pem is a critical CA. Those assertions are now stale and
fail. Update every assertion in the `rfc5280_accessors` module so it reflects the ACTUAL
regenerated good.pem. Tests only — do not change production accessor code unless you discover
a genuine accessor bug.

## Ground Truth (verify before editing)

The regenerated `testdata/good.pem` is a v3 LEAF with:

- `Version: 3` (DER version value `2`)
- `Serial Number: 17` (small, positive, well within 20 octets)
- non-empty subject DN (`CN=good.example`)
- `X509v3 Basic Constraints: CA:FALSE` — and it is **NOT** marked critical
- **NO** SubjectAltName extension
- **NO** KeyUsage extension
- far-future `notAfter` (year 2124)

VERIFY this yourself before editing — read the regenerated good.pem and/or drive the `Cert`
accessors directly (e.g. a scratch print, or `openssl x509 -in testdata/good.pem -noout
-text -ext subjectAltName,basicConstraints,keyUsage`). Assert what is ACTUALLY true, not what
this task or the old test assumed.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs` (the `#[cfg(test)] mod tests::rfc5280_accessors` module only)

This task is the single owner of `cert.rs` in this follow-up batch. Task 06 touches a
different file (`crates/cli/tests/output.rs`), so the two run in parallel.

## Steps

1. Read the current `rfc5280_accessors` module (~lines 419-492) and confirm the ground truth
   above against the regenerated `testdata/good.pem`.
2. Fix `good_cert_is_a_critical_ca` (~line 454), which currently asserts
   `assert!(bc.is_ca)`, `assert!(bc.critical)`, and `assert!(cert.is_ca().unwrap())`. good.pem
   is now a leaf, so this is wrong. Rename it to reflect a leaf (e.g. `good_cert_is_a_leaf`)
   and update the body to assert what is actually true:
   - `basic_constraints()` is `Some` with `is_ca == false` (the regenerated cert carries a
     `CA:FALSE` BasicConstraints extension — confirm whether your accessor surfaces it as
     `Some { is_ca: false, .. }` and assert accordingly; only fall back to `None` if the
     accessor genuinely returns that).
   - the BasicConstraints `critical` bit is `false` (good.pem's BC is not critical — verify).
   - `cert.is_ca().unwrap()` is `false`.
3. Verify `good_cert_has_no_key_usage_or_san` (~line 486). With the regenerated good.pem this
   test SHOULD still pass as written (good.pem has neither KeyUsage nor SAN), but confirm
   against reality. If — and only if — the accessor returns something different from what the
   test asserts, correct the assertion to match the actual cert (e.g. if good.pem turned out
   to carry a SAN, assert `subject_alt_name()` is `Some`). Do not change a passing, correct
   assertion just to match this task's wording.
4. Update any now-inaccurate doc comments — e.g. the `good_cert()` helper docstring (~line
   422) currently says "a v3 CA cert"; correct it to describe a v3 leaf cert.
5. Re-check the remaining tests in the module (`good_cert_is_version_3`,
   `good_cert_has_extensions`, `good_cert_subject_is_not_empty`,
   `good_cert_serial_*`) — they should already match the leaf good.pem; fix any that do not.

## Acceptance Criteria

- [ ] Every assertion in `tests::rfc5280_accessors` reflects the ACTUAL regenerated good.pem
      (leaf, CA:FALSE non-critical, small positive serial, non-empty subject, v3, no SAN/KU).
- [ ] The stale `good_cert_is_a_critical_ca` test is renamed and now asserts good.pem is NOT
      a CA (and that `is_ca()` is `false`).
- [ ] No production accessor code changed (tests-only edit), unless a genuine accessor bug is
      found — in which case document it in the task report.
- [ ] All `cert.rs` unit tests pass: `cargo test -p linter` green.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings` (also with `--features serde`),
      and `cargo fmt --check` all pass.

## Notes / Dependencies

- Depends on task 04 (the regenerated good.pem must be in place before these assertions can
  be corrected).
- Disjoint `touches` from task 06 — safe to run in parallel.
