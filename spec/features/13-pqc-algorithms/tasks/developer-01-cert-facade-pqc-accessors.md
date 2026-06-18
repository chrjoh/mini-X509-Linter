---
agent: developer
seq: 1
title: Cert facade PQC support (PublicKeyAlg ML-DSA/SLH-DSA, params-absent + key-length accessors, KeyUsageView bits)
status: pending
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade PQC accessors

## Goal

Extend the `Cert` facade to recognize ML-DSA / SLH-DSA SPKI algorithms and to expose the read-only
accessors the `pqc` lints need. All non-panicking, documented, returning `Result<_, CertError>` (or a
`Copy`/owned value), following the existing accessor style in `cert.rs`. **Keep existing `Rsa` / `Ec` /
`Other` behavior unchanged** so no current test or fixture breaks.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs`

Does NOT touch `source.rs`, the lint files, `registry.rs`, or the CLI (later tasks).

## What to Do

1. **Extend `PublicKeyAlg`** (currently `cert.rs:163` — `Rsa` / `Ec` / `Other(String)`) to recognize
   PQC. Propose the cleanest shape and document it; the spec's recommendation is either two variants
   `MlDsa(MlDsaParams)` / `SlhDsa(SlhDsaParams)` or a single `Pqc(PqcAlg)` sub-enum, where the carried
   type names the parameter set **or** an "unknown arc member" sentinel. Per plan **option (A)**:
   `public_key_algorithm()` returns the PQC variant for ANY OID under the two arcs
   (`2.16.840.1.101.3.4.3.{17,18,19}` for ML-DSA, `{20..35}` for SLH-DSA), carrying a known parameter
   set when the slot is assigned (`.17`–`.19`, `.20`–`.31`) or the "unknown arc member" form otherwise
   (`.32`–`.35` and any malformed arc member). Keep `Rsa` / `Ec` / `Other` and their match arms
   unchanged.
2. **Recognize the OID arcs in `public_key_algorithm()`** (the `match` at `cert.rs:766`). Add the ML-DSA
   and SLH-DSA arcs; everything else still falls through to `Other(oid)`. Cite FIPS 204 / FIPS 205 + the
   IETF LAMPS X.509 algorithm-identifier profile in the doc comment, with the RFC number marked **TBC**
   (do NOT hard-code an unverified RFC number — see plan "Standards basis"). Re-verify each OID →
   parameter-set mapping against FIPS 204/205 at implementation time.
3. **`spki_algorithm_parameters_present()`** → `Result<bool, CertError>`: `true` iff the SPKI
   `AlgorithmIdentifier.parameters` field is present (present-as-`NULL` counts as present). Read via the
   existing `with_parsed` helper.
4. **`signature_algorithm_parameters_present()`** → `Result<bool, CertError>`: `true` iff the
   certificate **signature** `AlgorithmIdentifier.parameters` field is present.
5. **`public_key_raw_len()`** → `Result<usize, CertError>`: the byte length of the raw subjectPublicKey
   BIT STRING contents (the encoded public key, excluding the unused-bits octet). Document exactly what
   is measured. Used by `pqc_public_key_length`.
6. **Extend `KeyUsageView`** with the bits the KU-consistency lint needs that are not yet exposed:
   `key_encipherment` (bit 2), `key_agreement` (bit 4), `crl_sign` (bit 6), populated in `key_usage()`.
   Confirm `digital_signature` (bit 0) and `key_cert_sign` (bit 5) already exist and reuse them. Document
   each bit with its RFC 5280 §4.2.1.3 bit index.
7. Add `#[cfg(test)] mod tests` for the new behavior using existing fixtures where possible (e.g. assert
   `public_key_algorithm()` is UNCHANGED for `good.pem` (RSA) — a negative regression proving no Rsa/Ec/
   Other shift). The PQC-positive cases (ML-DSA / SLH-DSA recognition, params-absent, key length) are
   covered by the integration tests in task 04 against the new PQC fixtures; a minimal in-file assertion
   for the OID-mapping logic (e.g. a pure helper mapping an OID string to a parameter set) is sufficient
   here.

## Acceptance Criteria

- [ ] `PublicKeyAlg` recognizes ML-DSA and SLH-DSA (including the unknown-arc-member case per option A);
      `Rsa` / `Ec` / `Other` behavior is unchanged.
- [ ] `spki_algorithm_parameters_present()`, `signature_algorithm_parameters_present()`,
      `public_key_raw_len()` present, documented, return `Result<_, CertError>`, never panic on cert data.
- [ ] `KeyUsageView` carries documented `key_encipherment` / `key_agreement` / `crl_sign` bits alongside
      the existing `digital_signature` / `key_cert_sign`.
- [ ] Doc comments cite FIPS 204/205 + the LAMPS X.509 profile with the RFC number marked TBC.
- [ ] Existing `cert.rs` tests still pass; new negative/regression assertions added.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`).

## Notes / Dependencies

- Blocks task 02 (lints) and task 03 (registration / wiring).
- Reuse the existing `with_parsed` pattern; prefer `std`. No new crate expected — document any if
  genuinely necessary.
