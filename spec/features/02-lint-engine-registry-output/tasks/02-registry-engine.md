---
agent: developer
seq: 2
title: Registry + run engine (no short-circuit) + source filter
status: done
touches:
  - crates/linter/src/registry.rs
  - crates/linter/src/lib.rs
depends_on:
  - 01-serde-on-contract-types
---

# Task: Registry + run engine (no short-circuit) + source filter

## Goal

Turn the loose `Lint` contract into a real engine: a registry that holds all lints and a
`run(&Cert) -> Vec<LintOutcome>` that records `NotApplicable` without calling `check`,
runs every applicable lint, and never short-circuits.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`
- `crates/linter/src/lib.rs`

Depends on task 01 so the `Cargo.toml` serde edits are already in place before lib.rs
re-exports anything serde-aware.

## Steps

1. `crates/linter/src/registry.rs`:
   - `pub struct Registry { lints: Vec<Box<dyn Lint>> }`.
   - `pub fn new() -> Registry` and `pub fn with_lints(...)` constructor helpers.
   - `pub fn default_registry() -> Registry` (or `Registry::default()`) wiring the lints
     that exist today (`NotExpired`). Later features (03–05) append to this constructor —
     keep registration in one obvious place with a clear "add new lints here" comment.
   - `pub fn run(&self, cert: &Cert) -> Vec<LintOutcome>`:
     - For each lint: call `applies()`. If `NotApplicable`, push a `LintOutcome` with
       empty `findings` and `Applicability::NotApplicable` — do NOT call `check()`.
     - If `Applies`, call `check()` and push a `LintOutcome` with the returned findings
       and `Applicability::Applies`.
     - Attach `lint_id` and `source` from the lint to each outcome.
     - Must run **every** lint — no early return on any finding/severity. Document this
       invariant in a comment.
   - `pub fn run_filtered(&self, cert: &Cert, sources: &[RuleSource]) -> Vec<LintOutcome>`
     (or accept an `Option<&[RuleSource]>` where `None` = all) — restrict to selected
     sources *before* running, so unwanted lints are not executed.
2. `crates/linter/src/lib.rs`:
   - `pub mod registry;` and re-export `Registry` + `default_registry`.

## Acceptance Criteria

- [ ] `run` returns one `LintOutcome` per lint considered, with correct `applicability`.
- [ ] `check()` is never called for `NotApplicable` lints (verify via a test lint that
      panics in `check` but reports `NotApplicable` — covered in task 04).
- [ ] `run` never short-circuits: a lint returning findings does not stop others.
- [ ] Source filtering excludes non-selected lints from execution.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01. Blocks tasks 03 (CLI uses the registry) and 04 (engine tests).
