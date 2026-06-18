---
agent: tester
seq: 3
title: PQC fixture + certificate inspection tests
status: done
touches:
  - testdata/slh_dsa_root_ca.pem
  - testdata/generate.sh
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

- `testdata/slh_dsa_root_ca.pem` (NEW openssl-generated PQC fixture)
- `testdata/generate.sh` (extend with the PQC recipe)
- `crates/cli/tests/inspect.rs` (NEW)

These do not overlap any other task's touches.

## PQC fixture provenance (IMPORTANT — openssl only, never cert-bar)

**Hard project rule:** all fixtures for this repo are generated with `openssl`, NEVER sourced from the
user's external `cert-bar` tool. The linter is meant to be an INDEPENDENT oracle for cert-bar's output,
so a cert-bar-derived fixture would create a circular validation dependency. `../cert-bar/` is also
outside the repository and must not be relied on. Do NOT vendor `slh-dsa-sha2-128s_cert.pem` from
cert-bar.

Generate `testdata/slh_dsa_root_ca.pem` with openssl 3.6.2 (verified to support SLH-DSA natively) and
add the recipe to `testdata/generate.sh` for reproducibility:

```sh
openssl genpkey -algorithm SLH-DSA-SHA2-128s -out slh.key
openssl req -x509 -new -key slh.key \
  -subj "/CN=SLH-DSA Test Root/C=SE/O=mini-x509-linter testdata" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectAltName=DNS:slh-dsa-test-root" \
  -days 36500 -out testdata/slh_dsa_root_ca.pem
# (the throwaway slh.key is not committed)
```

Document provenance in a header comment at the top of `crates/cli/tests/inspect.rs` (openssl-generated
self-signed SLH-DSA root CA; NOT from cert-bar; algorithm OID `2.16.840.1.101.3.4.3.20`, which may be
unknown to `oid-registry`).

The fixture must PARSE structurally via the `Cert` facade — the point is that its signature/public-key
algorithm may be unknown to `oid-registry`, exercising the graceful-degradation path. Expected
properties to assert against (confirm with `openssl x509 -in testdata/slh_dsa_root_ca.pem -noout -text`
after generating, since the recipe drives them): `Signature Algorithm: SLH-DSA-SHA2-128s`;
KeyUsage = `Certificate Sign, CRL Sign` (critical, per the recipe above); BasicConstraints critical
`CA:TRUE`; `SAN DNS:slh-dsa-test-root`; `subject = issuer = CN=SLH-DSA Test Root, C=SE,
O=mini-x509-linter testdata`.

## Algorithm-name degradation (best-effort name, OID always present)

`signature_algorithm()` (and the public-key algorithm) MUST return the raw OID string when the name is
unknown to `oid-registry`. Whether `oid-registry` 0.8 happens to know the SLH-DSA OID is an
implementation detail — so the test MUST assert on the **OID being present** (always works) and treat
the human-readable name as best-effort (assert it is either the known name OR an `(unknown)`-style
label, not a crash or empty field).

## Steps

`crates/cli/tests/inspect.rs` (SIFER + Result-assertion conventions; snapshots via `insta`):

1. **Good-cert summary snapshot (text).** Run `mini-x509-lint --info testdata/good.pem` (or call the
   renderer directly); `insta::assert_snapshot!` the summary block. Assert the lint report STILL
   follows the summary (proves `--info` does not suppress linting).
2. **PQC-cert summary snapshot (text).** Same against `testdata/slh_dsa_root_ca.pem`. Assert the
   summary renders without error and that the signature/public-key algorithm shows the raw OID (and a
   best-effort name OR an `(unknown)`-style label per the degradation rule above), NOT a crash or empty
   field.
3. **KeyUsage-bit display correctness.** Against the PQC CA, assert the summary lists exactly
   `Certificate Sign` and `CRL Sign` and marks KeyUsage as critical (matching the recipe). (Confirm the
   generated bit set with `openssl x509 -ext keyUsage` and assert the full multi-bit set so bit-mapping
   is genuinely exercised.)
4. **SAN entry display.** Assert the PQC CA summary shows `DNS:slh-dsa-test-root` and the SAN
   criticality.
5. **BasicConstraints display.** Assert the PQC CA summary shows `CA:TRUE` and critical.
6. **Subject/Issuer DN.** Assert both render as the expected RFC 4514 string for the PQC CA
   (`CN=SLH-DSA Test Root,C=SE,O=mini-x509-linter testdata`, subject == issuer for the self-signed root).
7. **JSON envelope.** Run `--info --format json` against `good.pem`; parse the output and assert it is a
   single object with a `summary` object and a `lints` array, and that the `lints` array matches the
   existing feature-02 per-outcome JSON shape (snapshot the `summary` object via `insta`).
8. **Determinism.** Run the text summary twice and assert byte-identical output (no timestamps beyond
   the cert dates).
9. **Default unchanged.** Assert that WITHOUT `--info`, both text and JSON output are unchanged versus a
   baseline (guards the additive contract).

## Acceptance Criteria

- [ ] `testdata/slh_dsa_root_ca.pem` generated with openssl (recipe in `testdata/generate.sh`), NOT
      sourced from cert-bar; provenance documented in the test header.
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
