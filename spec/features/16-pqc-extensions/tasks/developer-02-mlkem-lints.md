---
agent: developer
seq: 2
title: ML-KEM lints — kem_params table, applies_to_mlkem gate, and the four mlkem_* lints
status: done
touches:
  - crates/linter/src/lints/pqc/mod.rs
  - crates/linter/src/lints/pqc/kem_params.rs
  - crates/linter/src/lints/pqc/mlkem_algorithm_known.rs
  - crates/linter/src/lints/pqc/mlkem_spki_parameters_absent.rs
  - crates/linter/src/lints/pqc/mlkem_public_key_length.rs
  - crates/linter/src/lints/pqc/mlkem_key_usage_consistency.rs
depends_on:
  - developer-01-cert-facade-mlkem-and-keyusage-bits
---

# Task: Implement the ML-KEM (FIPS 203) lints

## Goal

Implement the curated ML-KEM key/cert hygiene rule set — the KEM counterpart to feature 13's ML-DSA /
SLH-DSA signature lints — under the **existing** `RuleSource::Pqc` source. One small file per lint, each
ML-KEM-SPKI-gated, each citing FIPS 203 + the LAMPS ML-KEM X.509 profile (RFC/draft TBC), each
`pqc_mlkem_*` id. House the ML-KEM OID → (parameter-set, encapsulation-key-length) table in a NEW
`pqc/kem_params.rs` (kept separate from the signature `params.rs`, which is NOT touched).

## Scoping (ML-KEM-SPKI-gated — LOAD-BEARING)

Add a shared `applies_to_mlkem(cert)` helper in `pqc/mod.rs` mirroring the existing `applies_to_pqc`:
`Applies` iff `cert.public_key_algorithm()?` is `PublicKeyAlg::MlKem(_)` (any parameter set, **including**
the `PqcParamSet::Unknown` case so `pqc_mlkem_algorithm_known` can fire through the registry), else
`NotApplicable`. On an `Err` reading the SPKI algorithm → **fail closed to `NotApplicable`**. This
self-gate keeps the universal `Pqc` source from cascading onto any non-ML-KEM cert.

## Files Owned (conflict scope)

- `crates/linter/src/lints/pqc/mod.rs` (add `mod kem_params;` + 4 lint module decls + re-exports +
  `applies_to_mlkem`)
- `crates/linter/src/lints/pqc/kem_params.rs` (new)
- the four `mlkem_*` lint files listed in front-matter (new)

Does NOT touch `cert.rs` (dev-01), `pqc/params.rs`, `pqc/key_usage_consistency.rs` (dev-03),
`registry.rs` or the CLI (dev-04). NOTE: `pqc/mod.rs` is edited ONLY by this task in feature 16; the
existing `key_usage_consistency` module declaration is already present from feature 13, so dev-03 needs no
`mod.rs` edit — keep your edits to additive lines.

## What to Do

### 1. `pqc/kem_params.rs` (new)

The auditable ML-KEM OID/parameter-set → encapsulation-key-length table, mirroring `params.rs`:

| Parameter set | Public-key (encapsulation-key) length (bytes) |
|---|---|
| ML-KEM-512  | 800  |
| ML-KEM-768  | 1184 |
| ML-KEM-1024 | 1568 |

Provide a `PqcKemParamInfo { name, public_key_len }` (or reuse a shared shape) + a lookup
`expected_mlkem_public_key_len(param_set: &str) -> Option<usize>` returning `None` for an unknown set
(the "unknown arc member" case has no known length to validate). Include `#[cfg(test)] mod tests`
asserting each entry and the unknown case. ⚠️ Re-verify each triple against FIPS 203 §8 (sizes table) and
the LAMPS ML-KEM registration at implementation time. (The architect verified 1184 for ML-KEM-768 against
an openssl-generated SPKI; confirm the other two.)

### 2. The four lints (all `RuleSource::Pqc`; all ML-KEM-SPKI-gated)

One file each, each with a doc comment citing FIPS 203 + the LAMPS ML-KEM X.509 profile (RFC/draft TBC —
do NOT hard-code an unverified number), a `Lint` impl, and `#[cfg(test)] mod tests`. Mirror the
feature-13 `pqc/*` files' style and the pure-`evaluate()` testability pattern.

1. `pqc_mlkem_algorithm_known` — **Error** if the SPKI OID is an ML-KEM-arc member that does NOT name a
   known parameter set (the `PqcParamSet::Unknown` case). On a known set: no finding. Mirror of
   `pqc_algorithm_known`.
2. `pqc_mlkem_spki_parameters_absent` — **Error** if `cert.spki_algorithm_parameters_present()` is
   `true` (params MUST be absent for ML-KEM per the LAMPS profile). Reuse the existing accessor.
3. `pqc_mlkem_public_key_length` — **Error** if `cert.public_key_raw_len()` does not match the mandated
   length for the named set (from `kem_params.rs`). Message names the parameter set, expected length,
   actual length. On the `Unknown` set: no finding (no known length — leaves the unknown-arc fixture
   isolating `pqc_mlkem_algorithm_known`). Reuse the existing `public_key_raw_len()`.
4. `pqc_mlkem_key_usage_consistency` — read `key_usage()` + `is_ca()`. The **inverse** of the signature
   KU rule (see plan Open Question 2):
   - asserting `digitalSignature` (bit 0) OR `keyCertSign` (bit 5) OR `cRLSign` (bit 6) → **Error**
     (signing bits are actively wrong for a KEM key — one finding per offending bit, each named).
   - an end-entity leaf (not CA) asserting **neither** `keyEncipherment` (bit 2) **nor** `keyAgreement`
     (bit 4) → **Warn** (a KEM EE SHOULD assert at least one). An absent KU extension on an EE yields the
     same Warn.
   - do NOT flag `dataEncipherment` (permitted-but-discouraged — keep conservative; document the
     deliberate omission).
   - the Error signing-bit checks apply regardless of the CA flag; do NOT add a "CA SHOULD assert
     keyCertSign" Warn (that would contradict the forbidden-signing-bit rule). Document the rationale.
   Keep a pure `evaluate(key_usage: Option<KeyUsageView>, is_ca: bool) -> Vec<Finding>` for unit testing.

In `pqc/mod.rs`: add `mod kem_params;`, declare each of the four lint modules, re-export the four lint
types, and add `applies_to_mlkem`.

## Acceptance Criteria

- [ ] `kem_params.rs` carries the audited ML-KEM OID/set → encapsulation-key-length table (800 / 1184 /
      1568) with unit tests, plus the unknown-set `None` case.
- [ ] `applies_to_mlkem` added to `pqc/mod.rs`; `Applies` iff SPKI is `MlKem(_)` (incl. Unknown), else
      `NotApplicable`; SPKI-read `Err` fails closed to `NotApplicable`.
- [ ] Four lints implemented, each `pqc_mlkem_*` id, each `RuleSource::Pqc`, each citing FIPS 203 + LAMPS
      (RFC/draft TBC), each ML-KEM-SPKI-gated via `applies_to_mlkem`.
- [ ] Severities: algorithm_known / spki_params / key_length = Error; key_usage = Error for the signing
      bits, Warn for the missing keyEncipherment/keyAgreement on an EE.
- [ ] All four lints are `NotApplicable` on a non-ML-KEM cert (RSA / EC / ML-DSA / SLH-DSA / Other) and
      `Applies` on an ML-KEM SPKI (including the unknown-arc-member case).
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths; check-path accessor `Err` → empty `Vec`.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`).

## Notes / Dependencies

- Depends on dev-01 (the `MlKem` variant + the existing reused accessors). Blocks dev-04 (registration).
- Runs in parallel with dev-03 (disjoint touches: dev-03 edits only `pqc/key_usage_consistency.rs`).
- Reuse `public_key_raw_len()` and `spki_algorithm_parameters_present()` as-is — no facade change here.
- There is deliberately NO `pqc_mlkem_signature_parameters_absent` lint: an ML-KEM cert's signature
  algorithm is the *issuer's* signing algorithm, not an ML-KEM algorithm (see plan). Do not add one.
