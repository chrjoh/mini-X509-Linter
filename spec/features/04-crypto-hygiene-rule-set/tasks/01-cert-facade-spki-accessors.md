---
agent: developer
seq: 1
title: Cert facade SPKI + signature-algorithm accessors
status: pending
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade SPKI + signature-algorithm accessors

## Goal

Extend the `Cert` facade with the SubjectPublicKeyInfo and signature-algorithm accessors
the hygiene lints need. First feature to touch SPKI parsing.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs`

Sole owner of `cert.rs` in feature 04.

## Steps

Add documented, non-panicking accessors (use `oid-registry` for readable OID names,
`der`/`x509-parser` for structure):

1. `signature_algorithm_oid()` → the signature algorithm OID (and a helper to get a
   human-readable name via `oid-registry`). Enough for `no_sha1_signature` to detect
   SHA-1-based signatures (e.g. `sha1WithRSAEncryption`, `ecdsa-with-SHA1`).
2. `public_key_algorithm()` → an enum like `PublicKeyAlg { Rsa, Ec, Other(oid) }`.
3. `rsa_modulus_bits()` → `Option<u32>` (bit length of the RSA modulus; `None` for
   non-RSA keys).
4. `ec_named_curve()` → `Option<NamedCurve>` or `Option<oid>` identifying the EC curve
   (P-256 / P-384 / P-521 / other); `None` for non-EC keys.

Keep these consistent with the existing facade style. No new crate dependencies.

## Acceptance Criteria

- [ ] Accessors exist, documented, return `Option`/enums without panicking on absent or
      unexpected key types.
- [ ] `rsa_modulus_bits` is `None` for EC keys; `ec_named_curve` is `None` for RSA keys.
- [ ] SHA-1 signature detection is possible from the signature-algorithm accessor.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Blocks task 02 (lints) and task 03 (registration).
