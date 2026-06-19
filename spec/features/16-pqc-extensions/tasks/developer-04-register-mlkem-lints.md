---
agent: developer
seq: 4
title: Register the four ML-KEM lints and reconcile the registry count (66 → 70)
status: done
touches:
  - crates/linter/src/registry.rs
depends_on:
  - developer-02-mlkem-lints
  - developer-03-pqc-sig-keyusage-gap
---

# Task: Register the ML-KEM lints + reconcile counts

## Goal

Register the four new `pqc_mlkem_*` lints in the default registry and reconcile the in-file count/filter
unit tests. NO source-helper change is needed — `RuleSource::Pqc` is already universal and already in
every `*_sources()` helper, the CLI `ALL_SOURCES`, and `output.rs` `SOURCE_ORDER`. NO new `CertPurpose`.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`

Does NOT touch `cert.rs`, the lint files, `source.rs`, or the CLI.

## What to Do

1. In `default_registry_with_now()`, register the four ML-KEM lints by appending them **after** the
   existing five `pqc` lints (`AlgorithmKnown` … `KeyUsageConsistency`) and BEFORE the `cabf_br` block —
   keeping the deterministic registration order the feature-06 golden test relies on:
   ```
   Box::new(pqc::MlkemAlgorithmKnown::new()),
   Box::new(pqc::MlkemSpkiParametersAbsent::new()),
   Box::new(pqc::MlkemPublicKeyLength::new()),
   Box::new(pqc::MlkemKeyUsageConsistency::new()),
   ```
   (Match the actual re-exported type names dev-02 chose.)
2. **Bump the in-file lint-count assertions 66 → 70** (5 existing pqc + 4 new ML-KEM; dev-03 added 0
   lints). Update the assertion at `registry.rs:885-886` (`registry.len()` / `outcomes.len()`) and any
   other in-file count assert. Update the accompanying comment to explain the new baseline
   (66 = pre-feature-16; +4 ML-KEM lints = 70).
3. Update the `pqc` source-filter test: the `[pqc]` source now has **9** lints (5 signature + 4 ML-KEM).
   Find the existing per-source `pqc` filter-count test and bump it 5 → 9. Leave the
   rfc5280 / cabf_br / cabf_cs / cabf_smime / cabf_ev / hygiene filter-count tests unchanged.
4. Confirm (and add a test asserting) that `RuleSource::Pqc` is still present in EVERY purpose's
   `allowed_sources` (the universal-source property) — if such a test already exists from feature 13, it
   needs no change; do NOT duplicate it.
5. NO change to `tls_server_sources()` / `generic_sources()` / `code_signing_sources()` /
   `smime_sources()`, the `auto` resolver, `resolve`, or the `CertPurpose` enum.

## Acceptance Criteria

- [ ] The four `pqc_mlkem_*` lints are registered in `default_registry_with_now()` in the documented
      order (after the five signature `pqc` lints, before `cabf_br`).
- [ ] In-file count asserts bumped 66 → 70 with an explanatory comment.
- [ ] The `pqc` source-filter count bumped 5 → 9; all other source-filter counts unchanged.
- [ ] No `*_sources()` / purpose / resolver change.
- [ ] `cargo test -p linter` and `cargo clippy --all-targets -- -D warnings` clean (also
      `--features serde`).

## Notes / Dependencies

- Depends on dev-02 (the ML-KEM lint types) and dev-03 (the KU-gap extension landed). Blocks tester-05.
- The integration-level count assert in `crates/linter/tests/registry.rs` (if any) is bumped by the
  tester in task 05, NOT here.
