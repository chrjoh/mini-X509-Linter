---
agent: tester
seq: 3
title: PQC fixture + certificate inspection tests
status: pending
touches:
  - testdata/slh_dsa_root_ca.pem
  - crates/cli/tests/inspect.rs
depends_on:
  - 02-cli-info-flag-and-summary-renderer
---

# Task: PQC fixture + certificate inspection tests

## Goal

Commit an in-repo SLH-DSA (post-quantum) root CA fixture and write snapshot + behavioural tests for
the `--info` certificate summary: text and JSON, KeyUsage-bit display correctness, graceful
unknown-algorithm handling, and determinism.

## Files Owned (conflict scope)

- `testdata/slh_dsa_root_ca.pem` (NEW vendored PQC fixture)
- `crates/cli/tests/inspect.rs` (NEW)

These do not overlap any other task's touches.

## PQC fixture provenance (IMPORTANT)

`../cert-bar/certs/slh-dsa-sha2-128s_cert.pem` is OUTSIDE this repository and CANNOT be relied on as a
committed fixture. Commit an in-repo copy as `testdata/slh_dsa_root_ca.pem`:

- Preferred: copy the motivating `slh-dsa-sha2-128s_cert.pem` content into `testdata/` as a vendored
  fixture. It is a self-signed PQC ROOT CA (no private key, no sensitive data). Document its provenance
  in a header comment at the top of `crates/cli/tests/inspect.rs` (what it is, that it is SLH-DSA, and
  that its algorithm OIDs are intentionally unknown to `oid-registry`).
- If a reproducible generator is available in the environment (e.g. `openssl` with an oqs-provider, or
  `rcgen`), prefer adding a regeneration recipe to `testdata/generate.sh` instead; otherwise treat the
  PEM as vendored.

The fixture only needs to PARSE structurally via the `Cert` facade — the point is that its
signature/public-key algorithm OIDs are NOT in `oid-registry`, exercising the graceful-degradation
path. Expected openssl-visible properties to assert against: KeyUsage = `Certificate Sign, CRL Sign`
(NOT critical); BasicConstraints critical `CA:TRUE`; `SAN DNS:SLH-DSA-SHA2-128S Root CA`;
`subject = issuer = CN=SLH-DSA-SHA2-128S Root CA, C=SE, O=NIST PQC SPHINCSplus`.

## Steps

`crates/cli/tests/inspect.rs` (SIFER + Result-assertion conventions; snapshots via `insta`):

1. **Good-cert summary snapshot (text).** Run `mini-x509-lint --info testdata/good.pem` (or call the
   renderer directly); `insta::assert_snapshot!` the summary block. Assert the lint report STILL
   follows the summary (proves `--info` does not suppress linting).
2. **PQC-cert summary snapshot (text).** Same against `testdata/slh_dsa_root_ca.pem`. Assert the
   summary renders without error and that the signature/public-key algorithm shows the raw OID with the
   `(unknown)` label (graceful degradation), NOT a crash or empty field.
3. **KeyUsage-bit display correctness.** Against the PQC CA, assert the summary lists exactly
   `Certificate Sign` and `CRL Sign` and marks KeyUsage as NOT critical. (Pick a fixture/case that
   asserts a richer multi-bit set so bit-mapping is genuinely exercised.)
4. **SAN entry display.** Assert the PQC CA summary shows `DNS:SLH-DSA-SHA2-128S Root CA` and the SAN
   criticality.
5. **BasicConstraints display.** Assert the PQC CA summary shows `CA:TRUE` and critical.
6. **Subject/Issuer DN.** Assert both render as the expected RFC 4514 string for the PQC CA.
7. **JSON envelope.** Run `--info --format json` against `good.pem`; parse the output and assert it is a
   single object with a `summary` object and a `lints` array, and that the `lints` array matches the
   existing feature-02 per-outcome JSON shape (snapshot the `summary` object via `insta`).
8. **Determinism.** Run the text summary twice and assert byte-identical output (no timestamps beyond
   the cert dates).
9. **Default unchanged.** Assert that WITHOUT `--info`, both text and JSON output are unchanged versus a
   baseline (guards the additive contract).

## Acceptance Criteria

- [ ] `testdata/slh_dsa_root_ca.pem` committed in-repo with provenance documented in the test header.
- [ ] Summary snapshots (text) for `good.pem` and the PQC CA are stable and deterministic.
- [ ] Unknown (PQC) algorithm renders the raw OID with a sensible label — no crash, no empty field.
- [ ] KeyUsage display lists every asserted bit by name plus criticality (PQC CA: `Certificate Sign`,
      `CRL Sign`, not critical).
- [ ] SAN entries, BasicConstraints, and subject/issuer DNs render as expected for the PQC CA.
- [ ] `--info --format json` emits `{ "summary": {…}, "lints": [ … ] }`; `lints` matches feature 02.
- [ ] `--info` does NOT suppress the lint report and does not change the exit code.
- [ ] Default (no `--info`) text and JSON output unchanged.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 02 (the `--info` flag and renderer must exist).
- Target the real binary name `mini-x509-lint` (NOT `mini-zlint`).
