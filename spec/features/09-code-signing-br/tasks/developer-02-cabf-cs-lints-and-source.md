---
agent: developer
seq: 2
title: Add RuleSource::CabfCs and implement the 8 codeSigning-gated cabf_cs lints
status: pending
touches:
  - crates/linter/src/source.rs
  - crates/linter/src/lints/mod.rs
  - crates/linter/src/lints/cabf_cs/mod.rs
  - crates/linter/src/lints/cabf_cs/eku_required.rs
  - crates/linter/src/lints/cabf_cs/key_usage_required.rs
  - crates/linter/src/lints/cabf_cs/rsa_key_size.rs
  - crates/linter/src/lints/cabf_cs/ecdsa_curve_params.rs
  - crates/linter/src/lints/cabf_cs/validity_period_longer_than_39_months.rs
  - crates/linter/src/lints/cabf_cs/validity_period_longer_than_460_days.rs
  - crates/linter/src/lints/cabf_cs/authority_information_access.rs
  - crates/linter/src/lints/cabf_cs/crl_distribution_points.rs
depends_on:
  - developer-01-cert-facade-cs-accessors
---

# Task: Add RuleSource::CabfCs and implement the 8 cabf_cs lints

## Goal

Add the new `RuleSource::CabfCs` source and implement the curated code-signing rule set, one small file
per lint, each codeSigning-EKU-gated, each commented with its CS BR section, each `cabf_cs_*` id.

## Scoping (codeSigning-EKU-gated — LOAD-BEARING)

Every lint's `applies()` is identical: `Applies` iff `cert.has_code_signing()?` is `true`, else
`NotApplicable`. On a parse error reading the EKU, **fail closed to `NotApplicable`** (do not
manufacture a false positive). This narrow gate is what prevents the feature-05-style fixture cascade:
all existing TLS/generic fixtures are `NotApplicable` for every `cabf_cs` lint. See plan.md "Critical
Design Decision".

## Files Owned (conflict scope)

- `crates/linter/src/source.rs` (add `RuleSource::CabfCs`)
- `crates/linter/src/lints/mod.rs` (add `pub mod cabf_cs;`)
- `crates/linter/src/lints/cabf_cs/mod.rs` (declare lint modules + re-export lint types)
- the 8 lint files listed in front-matter

Does NOT touch `cert.rs` (task 01), `registry.rs` or the CLI (task 03).

## What to Do

### 1. `source.rs`

Add `CabfCs` to `enum RuleSource` after `CabfBr`. Serde renders `snake_case` → wire string `cabf_cs`
(the enum already has `#[serde(rename_all = "snake_case")]`). Add a doc comment:
"CA/Browser Forum Code-Signing Baseline Requirements." Update the type-level doc comment that lists the
CLI `--source` vocabulary to include `cabf_cs`.

### 2. The 8 lints (all `RuleSource::CabfCs`; all codeSigning-gated)

One file each, each with a doc comment citing its CS BR section, a `Lint` impl, and
`#[cfg(test)] mod tests`. Mirror `crates/linter/src/lints/cabf_br/` style.

1. `cabf_cs_eku_required` — `check` → `Error` if `has_code_signing()` is false. NOTE: because the gate
   already requires codeSigning, this `check` cannot fail through the registry path; it is a defensive,
   fail-closed assertion retained for self-description and for direct callers. Document this clearly in
   the file (see plan.md note).
2. `cabf_cs_key_usage_required` — `check` → `Error` if the `digitalSignature` KU bit is not asserted
   (read the new `KeyUsageView.digital_signature`). Absent KU extension ⇒ fire.
3. `cabf_cs_rsa_key_size` — applies further only to RSA keys (use `public_key_algorithm()`); `check` →
   `Error` if `rsa_modulus_bits() < 3072`. Message names the actual bit size. Non-RSA keys: no finding.
4. `cabf_cs_ecdsa_curve_params` — applies further only to EC keys; `check` → `Error` if
   `ec_named_curve()` is `None` (explicit/absent params) or not in the permitted set
   (P-256 = 1.2.840.10045.3.1.7, P-384 = 1.3.132.0.34, P-521 = 1.3.132.0.35). Message names the curve.
5. `cabf_cs_validity_period_longer_than_39_months` — `check` → `Error` if `validity_days() > 1188`
   (39 months). Message names the duration. Document the months→days basis (39 × ~30.5 ≈ 1188; pick
   and document a single fixed day count, e.g. 1188).
6. `cabf_cs_validity_period_longer_than_460_days` — `check` → `Warn` if `validity_days() > 460`.
   Message names the duration. (Severity: Warn — see plan.md table.)
7. `cabf_cs_authority_information_access` — `check` → `Warn` if `has_authority_info_access()` is false.
8. `cabf_cs_crl_distribution_points` — `check` → `Warn` if `has_crl_distribution_points()` is false.

In `cabf_cs/mod.rs` declare each lint module and re-export the lint types (mirror `cabf_br/mod.rs`).

## Acceptance Criteria

- [ ] `RuleSource::CabfCs` added (serde wire `cabf_cs`); type-doc updated.
- [ ] 8 lints implemented, each `cabf_cs_*` id, each citing its CS BR section, each codeSigning-gated.
- [ ] All 8 are `NotApplicable` on a non-codeSigning cert and `Applies` on a codeSigning leaf.
- [ ] Severities match the plan table (eku/key_usage/rsa/ecdsa/39-months = Error; 460-days/aia/crl = Warn).
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths; EKU-read errors fail closed to NotApplicable.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`).

## Notes / Dependencies

- Depends on task 01 (facade accessors). Blocks task 03 (registration / purpose / CLI).
- `source.rs` is a SHARED file also edited by sibling features 10/11 — see plan.md sequencing warning.
