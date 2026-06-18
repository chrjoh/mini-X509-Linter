---
agent: developer
seq: 3
title: Register pqc lints, fold Pqc into ALL purpose source sets (universal source), wire CLI --source/output
status: pending
touches:
  - crates/linter/src/registry.rs
  - crates/cli/src/main.rs
  - crates/cli/src/output.rs
depends_on:
  - developer-02-pqc-lints-and-source
---

# Task: Register pqc lints + universal-source wiring + CLI wiring

## Goal

Wire the 5 (or 6) `pqc` lints into `default_registry()`, fold `RuleSource::Pqc` into **EVERY** purpose's
allowed-source set (the universal-source design — NO new `CertPurpose`), and extend the CLI `--source` /
output ordering to know about `pqc`.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`
- `crates/cli/src/main.rs`
- `crates/cli/src/output.rs`

These are SHARED files also edited by sibling features 09/10/11 — feature 13 is implemented against
whatever baseline exists when it lands and reconciles the final counts/orderings (see plan.md sequencing
warning + the two Ripple Flags). Within feature 13, this is the only task touching these three files.

## What to Do

### 1. `registry.rs` — register lints

Append boxed instances of the 5 (or 6) `pqc` lints in the "add new lints here" section, AFTER the
existing lint blocks (e.g. after `cabf_smime`), in a deterministic order (match the plan table order).
Keep ordering stable for the feature-06 golden test.

### 2. `registry.rs` — universal-source wiring (LOAD-BEARING)

`Pqc` is a UNIVERSAL source, NOT purpose-gated. Add `RuleSource::Pqc` to **ALL** of the per-purpose
source helpers (append at the end of each so existing relative order is untouched):

- `tls_server_sources()` (`registry.rs:162`) → `[Rfc5280, Hygiene, CabfBr, Pqc]`
  (and `..., CabfBr, CabfEv, Pqc` if sibling 11 has landed and folded `CabfEv` here)
- `generic_sources()` (`registry.rs:172`) → `[Rfc5280, Hygiene, Pqc]`
- `code_signing_sources()` (`registry.rs:182`) → `[Rfc5280, Hygiene, CabfCs, Pqc]`
- `smime_sources()` (`registry.rs:192`) → `[Rfc5280, Hygiene, CabfSmime, Pqc]`

**Do NOT add a new `CertPurpose`.** The `CertPurpose` enum, the `auto` resolver, `resolve`,
`auto_decision`, and `auto_sources_from` are UNCHANGED — PQC is not a purpose. Update the `allowed_sources`
doc comment to note that `Pqc` (like `Rfc5280`/`Hygiene`) is in every purpose's set.

### 3. `registry.rs` — unit tests

- `contains_the_known_lints`: bump the lint count + outcome count to the then-current baseline
  (**52 → 57** off current main; **+6** if the optional lint ships; **61 → 66** if sibling 11 has landed
  — STATE the chosen baseline explicitly in a test comment). Add the 5 (or 6) `pqc_*` ids to the expected
  list. `sample_cert()` is RSA/EC (not PQC) so the pqc lints are `NotApplicable` but still produce one
  OUTCOME each → outcome count reflects the bump. Verify `sample_cert()` carries no PQC key.
- Add `pqc_source_filter_runs_exactly_the_pqc_set` mirroring the other source-filter tests:
  `run_filtered(&cert, &[RuleSource::Pqc])` → 5 (or 6) outcomes, all `RuleSource::Pqc`, the `pqc_*` ids,
  none rfc5280_/hygiene_/cabf_*.
- Add **universal-source-membership tests** (the headline property): assert `RuleSource::Pqc` is present
  in `allowed_sources` for `TlsServer`, `Generic`, `CodeSigning`, `Smime` (and for an `auto` resolving
  to each). This is the central new invariant — contrast with `CabfCs`/`CabfSmime` which stay
  single-purpose.
- Leave the existing rfc5280 / cabf_br / cabf_cs / cabf_smime / hygiene filter-count tests and all
  `CertPurpose`/`auto` tests unchanged.

### 4. `crates/cli/src/main.rs`

- `parse_source_token`: add `"pqc" => Ok(RuleSource::Pqc)`; update the error-message list to include
  `pqc`.
- `ALL_SOURCES`: add `RuleSource::Pqc` (keep order consistent with `SOURCE_ORDER` — directly after
  `RuleSource::Rfc5280`).
- **No `CliPurpose` change** (no new purpose).
- Update the `--source` doc strings (module header + the `Args` field doc) to include `pqc`.

### 5. `crates/cli/src/output.rs`

- `SOURCE_ORDER`: add `RuleSource::Pqc` directly after `RuleSource::Rfc5280` (matching the enum
  placement + `ALL_SOURCES`).
- `source_label`: add `RuleSource::Pqc => "pqc"`.

## Acceptance Criteria

- [ ] `default_registry()` includes all 5 (or 6) `pqc` lints in deterministic order.
- [ ] `RuleSource::Pqc` is in ALL four `*_sources()` helpers (tls-server, generic, code-signing, S/MIME);
      NO new `CertPurpose`; `auto`/`resolve` unchanged.
- [ ] CLI accepts `--source pqc`; `source_label` renders `pqc`; `ALL_SOURCES` and `SOURCE_ORDER` include
      `Pqc` in matching position (after `Rfc5280`).
- [ ] Registry unit tests updated (count bumped to the stated baseline, `pqc` filter test,
      universal-source-membership tests for every purpose); existing filter-count / purpose tests
      unchanged.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`).

## Notes / Dependencies

- Depends on task 02. Blocks test task 04.
- ALL of `registry.rs`, `cli/main.rs`, `cli/output.rs` are SHARED with sibling features 09/10/11 —
  feature 13 reconciles the final counts/orderings against the then-current baseline (52 or 61). See the
  two Ripple Flags in plan.md.
