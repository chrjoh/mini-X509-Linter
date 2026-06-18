---
agent: developer
seq: 2
title: Add RuleSource::Pqc and implement the PQC-SPKI-gated pqc lints
status: done
touches:
  - crates/linter/src/source.rs
  - crates/linter/src/lints/mod.rs
  - crates/linter/src/lints/pqc/mod.rs
  - crates/linter/src/lints/pqc/params.rs
  - crates/linter/src/lints/pqc/algorithm_known.rs
  - crates/linter/src/lints/pqc/spki_parameters_absent.rs
  - crates/linter/src/lints/pqc/signature_parameters_absent.rs
  - crates/linter/src/lints/pqc/public_key_length.rs
  - crates/linter/src/lints/pqc/key_usage_consistency.rs
depends_on:
  - developer-01-cert-facade-pqc-accessors
---

# Task: Add RuleSource::Pqc and implement the pqc lints

## Goal

Add the new `RuleSource::Pqc` source and implement the curated PQC signature-algorithm hygiene rule set,
one small file per lint, each PQC-SPKI-gated, each commented with its FIPS 204/205 + LAMPS X.509 basis,
each `pqc_*` id. House the OID → (parameter-set, public-key-length) table in `pqc/params.rs`.

## Scoping (PQC-SPKI-gated — LOAD-BEARING)

Every lint's `applies()` delegates to a shared `applies_to_pqc(cert)` helper (in `pqc/mod.rs`):
`Applies` iff `cert.public_key_algorithm()?` is an ML-DSA or SLH-DSA variant (per plan option A, this
includes the "unknown arc member" case), else `NotApplicable`. On an `Err` reading the SPKI algorithm,
**fail closed to `NotApplicable`** (never manufacture a false positive). This self-gate is what keeps the
universal `Pqc` source from cascading onto any existing RSA/EC fixture. See plan.md "THE KEY DESIGN
DECISION".

## Files Owned (conflict scope)

- `crates/linter/src/source.rs` (add `RuleSource::Pqc`)
- `crates/linter/src/lints/mod.rs` (add `pub mod pqc;`)
- `crates/linter/src/lints/pqc/mod.rs` (declare modules, re-export lint types, shared `applies_to_pqc`)
- `crates/linter/src/lints/pqc/params.rs` (OID → parameter-set + public-key-length table)
- the lint files listed in front-matter

Does NOT touch `cert.rs` (task 01), `registry.rs` or the CLI (task 03).

## What to Do

### 1. `source.rs`

Add `Pqc` to `enum RuleSource` directly **after** `Rfc5280` (grouping the two universal structural
sources). Serde renders `snake_case` → wire string `pqc`. Doc comment: "Post-quantum (ML-DSA / SLH-DSA)
signature-algorithm hygiene and structural checks — a universal, non-CABF source." Update the type-level
doc comment that lists the `--source` vocabulary to include `pqc`.

### 2. `pqc/params.rs`

The auditable OID → (parameter-set name, public-key length in bytes) table from plan.md's OID table
(ML-DSA `.17`–`.19`; SLH-DSA `.20`–`.31`; `.32`–`.35` reserved-but-unassigned). Provide a small lookup
returning the parameter set + mandated public-key length, or the "unknown arc member" outcome. Include
`#[cfg(test)] mod tests` asserting the table entries. ⚠️ Re-verify each OID → set → length triple against
FIPS 204 §4 / FIPS 205 parameter-set tables and the LAMPS registrations at implementation time.

### 3. The lints (all `RuleSource::Pqc`; all PQC-SPKI-gated)

One file each, each with a doc comment citing FIPS 204/205 + the LAMPS X.509 profile (RFC number marked
**TBC** — do NOT hard-code an unverified RFC number), a `Lint` impl, and `#[cfg(test)] mod tests`. Mirror
`crates/linter/src/lints/cabf_cs/` style.

1. `pqc_algorithm_known` — Error if the SPKI OID is an arc member that does NOT name a known parameter
   set (the "unknown arc member" case per the gate). The gate engages on any arc OID, so this lint CAN
   fire through the registry. On a known set: no finding.
2. `pqc_spki_parameters_absent` — Error if `spki_algorithm_parameters_present()` is `true` (params must
   be absent for ML-DSA/SLH-DSA per the LAMPS profile).
3. `pqc_signature_parameters_absent` — Error if `signature_algorithm_parameters_present()` is `true`.
4. `pqc_public_key_length` — Error if `public_key_raw_len()` does not match the mandated length for the
   named parameter set (from `params.rs`). Message names the parameter set, expected length, actual
   length. On the "unknown arc member" case: no finding (no known length to validate — leaves the
   unknown-arc fixture isolating `pqc_algorithm_known`).
5. `pqc_key_usage_consistency` — read `key_usage()` + `is_ca()`. Emit findings (one per offending/missing
   bit, each named):
   - `keyEncipherment` or `keyAgreement` asserted → **Error** (wrong bit for a signature-only key).
   - EE leaf (not CA) NOT asserting `digitalSignature` → **Warn**.
   - CA NOT asserting `keyCertSign` → **Warn**.
   Document the Error-vs-Warn rationale in the file. Absent KU extension on an EE ⇒ the
   `digitalSignature`-missing Warn.

> **Optional 6th lint (`pqc_in_unpermitted_profile`, Notice):** the architect recommends **deferring**
> it (see plan "Future"). Do NOT ship it unless it can be expressed without entangling the purpose
> machinery; if shipped, add `crates/linter/src/lints/pqc/in_unpermitted_profile.rs` to this task's
> touches and reconcile the count in task 03 + the test-plan.

In `pqc/mod.rs` declare each lint module, re-export the lint types, and house `applies_to_pqc`.

## Acceptance Criteria

- [ ] `RuleSource::Pqc` added (serde wire `pqc`, after `Rfc5280`); type-doc updated.
- [ ] `pqc/params.rs` carries the audited OID → set → length table with unit tests.
- [ ] 5 (or 6) lints implemented, each `pqc_*` id, each citing FIPS 204/205 + LAMPS (RFC TBC), each
      PQC-SPKI-gated via the shared `applies_to_pqc` helper.
- [ ] All lints are `NotApplicable` on a non-PQC cert (RSA/EC/Other) and `Applies` on a PQC SPKI
      (including the unknown-arc-member case).
- [ ] Severities match the plan table (algorithm_known / spki_params / sig_params / key_length = Error;
      key_usage = Error for keyEncipherment/keyAgreement, Warn for missing digitalSignature/keyCertSign).
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths; SPKI-read errors fail closed to NotApplicable.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`).

## Notes / Dependencies

- Depends on task 01 (facade accessors). Blocks task 03 (registration / wiring).
- `source.rs` is a SHARED file also edited by sibling features 09/10/11 — see plan.md sequencing warning.
