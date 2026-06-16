# Feature: Crypto Hygiene Rule Set

## Overview

Implement the crypto-hygiene lints: signature-algorithm and key-strength checks. This touches SPKI
parsing for the first time. This is plan.md Milestone 4. (`not_expired` already landed in feature 01
as the trivial bootstrap lint and belongs to this set.)

## Requirements

Implement the hygiene lints from plan.md, each tagged `RuleSource::Hygiene`:

- `no_sha1_signature` — flag SHA-1 in the signature algorithm.
- `rsa_key_min_2048` — RSA modulus must be ≥ 2048 bits.
- `ecdsa_curve_allowlist` — restrict to P-256 / P-384 / P-521.
- `not_expired` — informational: `Notice`/`Warn` if already expired (already implemented in
  feature 01; fold it into this rule set's module/registration and ensure consistency).

Each lint:
- Uses `applies()` to scope correctly (e.g. `rsa_key_min_2048` is `NotApplicable` for non-RSA keys;
  `ecdsa_curve_allowlist` is `NotApplicable` for non-ECDSA keys).
- Returns `Vec<Finding>` with a clear message naming the offending algorithm/curve/bit-length.
- Uses `hygiene_*` naming for `lint_id`.

## Architecture

- One file per lint under `crates/linter/src/lints/hygiene/`.
- Add SPKI/algorithm accessors to the `Cert` facade: signature algorithm OID, public key algorithm,
  RSA modulus bit length, ECDSA named curve. Use `oid-registry` for human-readable OID names and
  `der`/`x509-parser` for the structural bits.
- Register the lints in the default registry.

## Changes Overview

**crates/linter/**
- `src/lints/hygiene/mod.rs` — module wiring (include `not_expired` here).
- `src/lints/hygiene/no_sha1_signature.rs`
- `src/lints/hygiene/rsa_key_min_2048.rs`
- `src/lints/hygiene/ecdsa_curve_allowlist.rs`
- `src/lints/hygiene/not_expired.rs` — relocated/confirmed here.
- `src/cert.rs` — SPKI + signature-algorithm accessors.
- `src/registry.rs` — register the hygiene lints.

**testdata/**
- `hygiene_sha1_signature.pem`, `hygiene_rsa_1024.pem`, `hygiene_ecdsa_bad_curve.pem`,
  `expired.pem` (already present from feature 01), plus updates to the regeneration script.

## Dependencies

- None new. Uses `oid-registry`, `der`, `x509-parser` already present.
