---
agent: developer
seq: 5
title: Update cert.rs good-fixture unit tests for new SAN/EKU shape
status: done
touches:
  - crates/linter/src/cert.rs
depends_on:
  - 01-cert-facade-san-eku-and-ip-helper
  - 04-cabf-br-fixtures-and-tests
---

# Task: Update cert.rs good-fixture unit tests for new SAN/EKU shape

## Goal

Under broad scoping, `good.pem` is regenerated (task 04) to carry a SAN (DNS:good.example) and the
serverAuth EKU so it stays BR-compliant. The in-file `cert.rs` unit test
`good_cert_has_no_key_usage_or_san` (around line 660) asserts the OLD shape (no SAN, no KeyUsage) and
will now FAIL. Rewrite it to assert the new shape, and verify the other `good_cert` unit tests still
hold.

## Why this is a SEPARATE task from task 01

`cert.rs` is owned by task 01 (facade accessors). Two tasks must not edit `cert.rs` in the same
batch. This task is serialized AFTER task 01 (`depends_on`) and runs in task 04's batch (task 04
touches no `src/` files, so no conflict). It also `depends_on` task 04 because it must assert against
the regenerated `good.pem` bytes.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs` — ONLY the `good_cert` unit tests in the `#[cfg(test)]` module.

## Steps

1. Rewrite `good_cert_has_no_key_usage_or_san` (the assertion `subject_alt_name().is_none()` is now
   false). Rename it to reflect reality, e.g. `good_cert_has_san_with_cn_and_server_auth`, and:
   - assert `cert.subject_alt_name().unwrap().is_some()`;
   - assert the SAN's dNSName entries contain `good.example` (the CN);
   - assert `good.pem` carries the serverAuth EKU (via whichever accessor task 01 added, e.g.
     `cert.has_server_auth().unwrap()` is true);
   - for KeyUsage: assert whatever shape the regenerated fixture actually has. If task 04's
     `good.pem` carries a KeyUsage extension, assert it is `Some`; if serverAuth is carried via EKU
     only with no KeyUsage extension, keep the `key_usage().unwrap().is_none()` assertion and note
     it in a comment. Match the assertion to the committed fixture — do not guess.
2. Verify (and do NOT change) the still-true `good_cert` tests: `good_cert_is_a_leaf`,
   `good_cert_is_version_3`, `good_cert_subject_is_not_empty`, `good_cert_serial_*`, and all
   `spki_accessors` tests (good.pem remains an RSA-2048 / SHA-256 v3 leaf).

## Acceptance Criteria

- [ ] The `good_cert` SAN/EKU unit test reflects the regenerated fixture (SAN present with CN;
      serverAuth present; KeyUsage asserted to match the actual fixture).
- [ ] All other `good_cert` and `spki_accessors` unit tests pass unchanged.
- [ ] `cargo test -p linter` and `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01 (cert.rs facade) and task 04 (regenerated good.pem). Runs in task 04's batch;
  disjoint files (cert.rs) so no conflict with task 04.
