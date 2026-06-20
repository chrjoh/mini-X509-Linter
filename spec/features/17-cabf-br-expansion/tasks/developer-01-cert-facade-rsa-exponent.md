---
agent: developer
seq: 1
title: Cert facade accessor for the RSA public exponent
status: done
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade accessor for the RSA public exponent

## Goal

Add the ONE new read-only facade accessor the feature-17 BR lints need:
`rsa_public_exponent()`. ONE owner of `cert.rs`. Lint task (developer-02) reads ONLY through this
accessor (plus existing ones). Follow the exact style of the existing accessors: documented,
non-panicking (treat malformed/absent as `None`), a small `*View` struct next to the existing ones, a
`# Errors` section, and a `#[cfg(test)] mod tests` block.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs` (extend only — do not touch unrelated existing accessors/tests)

Does NOT touch any `lints/`, `registry.rs`, or test/fixture files.

## Steps

1. Add `pub struct RsaExponentView` next to the existing `*View` structs, with documented fields:
   - `is_odd: bool`
   - `at_least_65537: bool` (exponent ≥ 2^16 + 1)
   - `at_most_2_256_minus_1: bool` (exponent ≤ 2^256 − 1)
   Derive `Debug, Clone, Copy, PartialEq, Eq`; add `#[cfg_attr(feature = "serde", derive(Serialize))]`
   only if the neighbouring views do (match the file's convention).

2. Add `pub fn rsa_public_exponent(&self) -> Result<Option<RsaExponentView>, CertError>`:
   - Uses the SAME parsed-public-key path as the existing `rsa_modulus_bits()` (x509-parser's
     `PublicKey::RSA`); for any non-RSA key return `Ok(None)`.
   - Reads the RSA exponent as its big-endian octet slice and computes the three booleans WITHOUT
     parsing into a fixed-width integer (the exponent can be arbitrarily large):
     - `is_odd` = the least-significant octet is odd (last byte AND 1 == 1), with an all-zero / empty
       exponent treated as even.
     - `at_least_65537` = the exponent's numeric value ≥ 65537 (0x01_00_01). Compare via stripped
       leading-zero octet length then lexicographic byte comparison against `[0x01,0x00,0x01]`.
     - `at_most_2_256_minus_1` = the exponent fits in ≤ 32 octets (after stripping leading zeros);
       (2^256 − 1) is exactly 32 0xFF octets, so any value of ≤ 32 significant octets is ≤ 2^256 − 1.
   - Document the byte-arithmetic approach in the doc comment and a `# Errors` section. Non-panicking:
     no `unwrap`/`expect`/`panic!`; malformed key path returns `Ok(None)` or the existing `CertError`
     style used by `rsa_modulus_bits()`.

3. ALREADY-PRESENT accessors to reuse elsewhere (do NOT re-add): `rsa_modulus_bits()`, `key_usage()`,
   `basic_constraints()`, `extended_key_usage()`, `san_entries()`, `subject_alt_name()`,
   `certificate_policy_oids()`, `is_ca()`.

## Acceptance Criteria

- [ ] `rsa_public_exponent()` + `RsaExponentView` present, documented (`# Errors`), non-panicking on
      absent/malformed/non-RSA input (returns `Ok(None)` for non-RSA, never `unwrap`/`panic!`).
- [ ] The three booleans are computed by big-endian byte arithmetic (no fixed-width integer parse);
      the approach is documented.
- [ ] `#[cfg(test)] mod tests` covers: good.pem (exp 65537 → odd, ≥65537, ≤2^256−1 all true), an
      exponent-3 case (odd, NOT ≥65537), and a non-RSA case (`Ok(None)`). Use small embedded byte
      slices or the existing helper that builds `RsaExponentView` from octets; do NOT depend on the
      not-yet-created feature-17 fixtures.
- [ ] No new crate dependency.
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean; existing `good_cert_*`
      unit tests pass UNCHANGED (do not edit them).

## Notes / Dependencies

- Blocks developer-02 (lint `cabf_br_rsa_public_exponent_in_range` reads this accessor).
- This is the ONLY production change to `cert.rs` in this feature.
</content>
