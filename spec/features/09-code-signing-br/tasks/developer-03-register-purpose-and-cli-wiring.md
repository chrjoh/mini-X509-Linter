---
agent: developer
seq: 3
title: Register cabf_cs lints, add CertPurpose::CodeSigning, wire CLI --source/--purpose/output
status: done
touches:
  - crates/linter/src/registry.rs
  - crates/cli/src/main.rs
  - crates/cli/src/output.rs
depends_on:
  - developer-02-cabf-cs-lints-and-source
---

# Task: Register cabf_cs lints + CodeSigning purpose + CLI wiring

## Goal

Wire the 8 `cabf_cs` lints into `default_registry()`, implement the previously-reserved
`CertPurpose::CodeSigning` (mapping + auto resolver), and extend the CLI `--source` / `--purpose` /
output ordering to know about `cabf_cs` and `code-signing`.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`
- `crates/cli/src/main.rs`
- `crates/cli/src/output.rs`

These are SHARED files also edited by sibling features 10/11 — this feature MUST be merged before those
start their edits (see plan.md sequencing warning). Within feature 09, this is the only task touching
these three files.

## What to Do

### 1. `registry.rs` — register lints

Append boxed instances of the 8 `cabf_cs` lints in the "add new lints here" section, AFTER the
`cabf_br` block (`registry.rs:283-286`), in a deterministic order (match the plan table order). Keep
ordering stable for the feature-06 golden test.

### 2. `registry.rs` — `CertPurpose::CodeSigning`

- Add `CodeSigning` to `enum CertPurpose` (currently `Auto`/`TlsServer`/`Generic`, `registry.rs:125`).
  Update its doc comment (the "Future variants" note currently lists CodeSigning as not-yet-implemented
  — change it to implemented; keep Client/Smime listed as future).
- Add `fn code_signing_sources() -> Vec<RuleSource>` mirroring `tls_server_sources()` /
  `generic_sources()`, returning `[RuleSource::Rfc5280, RuleSource::Hygiene, RuleSource::CabfCs]` in a
  fixed order.
- Extend `allowed_sources` (`registry.rs:200`) with a `CodeSigning => code_signing_sources()` arm.
- Extend the `auto` resolver. The decision currently lives in `auto_sources_from(has_server_auth)`
  (`registry.rs:172`) and `resolve` (`registry.rs:221`). Generalize so the precedence is:
  1. codeSigning EKU present → CodeSigning;
  2. else serverAuth EKU present → TlsServer;
  3. else → Generic;
  4. EKU-read `Err(..)` → fail closed to Generic.
  Implement this by reading `cert.has_code_signing()` and `cert.has_server_auth()` (or a single EKU
  read) — codeSigning is checked FIRST. Keep both `allowed_sources(Auto)` and `resolve(Auto)`
  consistent (resolve returns the concrete purpose; allowed_sources returns that purpose's sources).
  Factor the decision into a pure, unit-testable helper (mirror `auto_sources_from`).
- Update in-file unit tests:
  - `contains_the_known_lints`: lint count and outcome count 32 → 40 (off current main after feature
    12; reconcile if a sibling 10/11 lands first); add the 8 `cabf_cs_*` ids to the
    expected list. (NOTE: `sample_cert()` is a self-signed CA with no codeSigning EKU, so the 8 CS
    lints are `NotApplicable` but still produce one OUTCOME each → outcome count is 40 too. Verify
    `sample_cert()` does not assert codeSigning.)
  - Add `cabf_cs_source_filter_runs_exactly_the_cabf_cs_set` mirroring the rfc5280/hygiene/cabf_br
    filter tests: `run_filtered(&cert, &[RuleSource::CabfCs])` → 8 outcomes, all `RuleSource::CabfCs`,
    the 8 ids, none rfc5280_/hygiene_/cabf_br_.
  - Add a purpose test: a CodeSigning purpose (and an `auto` resolving to CodeSigning) yields
    `[Rfc5280, Hygiene, CabfCs]`; document/test the auto precedence (codeSigning beats serverAuth).
    Use the `auto`-decision helper for the precedence unit tests so no fixture is required for the
    pure-logic cases; the fixture-backed end-to-end auto resolution is covered in task 04.
  - Leave the existing rfc5280 (16) / hygiene (4) / cabf_br (12) filter-count tests unchanged.

### 3. `crates/cli/src/main.rs`

- `parse_source_token` (`main.rs:168`): add `"cabf_cs" => Ok(RuleSource::CabfCs)`; update the error
  message list to include `cabf_cs`.
- `ALL_SOURCES` (`main.rs:162`): add `RuleSource::CabfCs` (keep order consistent with `SOURCE_ORDER`).
- `CliPurpose` (`main.rs:97`): add `CodeSigning` variant (clap value `code-signing` — derive via
  `#[value(name = "code-signing")]` or rely on clap's kebab-casing of `CodeSigning`; verify it renders
  as `code-signing`). Update the enum doc (move CodeSigning out of "future/reserved").
- `From<CliPurpose> for CertPurpose` (`main.rs:109`): add `CliPurpose::CodeSigning =>
  CertPurpose::CodeSigning`.
- `purpose_label` (`main.rs:223`): add `CertPurpose::CodeSigning => "code-signing"`.
- Update the `--source` / `--purpose` doc strings (module header `main.rs:12/26` and the `Args` field
  docs `main.rs:133/156`) to include `cabf_cs` / `code-signing`.

### 4. `crates/cli/src/output.rs`

- `SOURCE_ORDER` (`output.rs:22`): add `RuleSource::CabfCs` in a fixed, deterministic position (after
  `CabfBr`). Keep this consistent with `main.rs` `ALL_SOURCES`.
- `source_label` (`output.rs:149`): add `RuleSource::CabfCs => "cabf_cs"`.

## Acceptance Criteria

- [ ] `default_registry()` includes all 8 `cabf_cs` lints in deterministic order.
- [ ] `CertPurpose::CodeSigning` maps to `[Rfc5280, Hygiene, CabfCs]`; `auto` resolves codeSigning
      leaves to CodeSigning, with codeSigning checked before serverAuth and `Err` failing closed to
      Generic.
- [ ] CLI accepts `--source cabf_cs` and `--purpose code-signing`; `purpose_label`/`source_label`
      render the new tokens; `ALL_SOURCES` and `SOURCE_ORDER` include `CabfCs` in matching order.
- [ ] Registry unit tests updated (count 32 → 40 off current main, `cabf_cs` filter test, CodeSigning purpose +
      auto-precedence tests); existing filter-count tests unchanged.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`).

## Notes / Dependencies

- Depends on task 02. Blocks test task 04.
- ALL of `registry.rs`, `cli/main.rs`, `cli/output.rs` are SHARED with sibling features 10/11 —
  sequence those features AFTER this one merges.
