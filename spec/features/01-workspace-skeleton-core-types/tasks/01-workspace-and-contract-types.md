---
agent: developer
seq: 1
title: Workspace skeleton + core contract types
status: done
touches:
  - Cargo.toml
  - crates/linter/Cargo.toml
  - crates/linter/src/lib.rs
  - crates/linter/src/finding.rs
  - crates/linter/src/source.rs
depends_on: []
---

# Task: Workspace skeleton + core contract types

## Goal

Stand up the cargo workspace and the engine-agnostic contract types (`Severity`,
`RuleSource`, `Applicability`, `Finding`, `LintOutcome`, `Lint`) exactly as specified
in plan.md and feature 01's `plan.md`. This is the foundation every later feature builds on.

## Files Owned (conflict scope)

- `Cargo.toml` (workspace root — replace the current single-crate manifest with a `[workspace]`)
- `crates/linter/Cargo.toml`
- `crates/linter/src/lib.rs`
- `crates/linter/src/finding.rs`
- `crates/linter/src/source.rs`

Do NOT touch `crates/linter/src/cert.rs` or the lints module (owned by tasks 02/03).
Note: the existing `src/main.rs` at the repo root should be removed as part of converting
to a workspace — fold that deletion into this task.

## Steps

1. Replace the root `Cargo.toml` with a `[workspace]` manifest listing members
   `crates/linter` and `crates/cli`. Use `resolver = "2"` (or `"3"` for edition 2024).
   Remove the old `[package]`/`src/main.rs` single-crate setup.
2. Create `crates/linter/Cargo.toml`:
   - `[package]` name `linter`, edition matching the workspace.
   - deps (pinned 2026-06-15 to latest stable): `x509-parser = "0.18"` (0.18.1),
     `der = "0.8"` (0.8.0), `oid-registry = "0.8"` (0.8.1 — NOT 0.9, which is a
     pre-release and conflicts with x509-parser's `oid-registry ^0.8.1`),
     `thiserror = "2"` (2.0.x — matches x509-parser's own thiserror ^2.0).
     Note: x509-parser does not use the RustCrypto `der` crate (it uses asn1-rs/der-parser);
     keep `der` only if a lint needs RustCrypto DER parsing directly.
3. `crates/linter/src/source.rs` — `pub enum RuleSource { Rfc5280, CabfBr, Hygiene }`.
   Derive `Debug, Clone, Copy, PartialEq, Eq`. Document each variant.
4. `crates/linter/src/finding.rs`:
   - `pub enum Severity { Notice, Warn, Error, Fatal }` — no `Pass` variant. Derive
     `Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord` (ordering used later by
     `--min-severity` / `--fail-on`; Notice < Warn < Error < Fatal).
   - `pub enum Applicability { Applies, NotApplicable }`.
   - `pub struct Finding { pub severity: Severity, pub message: String }`.
   - `pub struct LintOutcome { pub lint_id: &'static str, pub source: RuleSource,
     pub applicability: Applicability, pub findings: Vec<Finding> }`.
5. `crates/linter/src/lib.rs`:
   - `#![deny(missing_docs)]` crate-level doc comment.
   - `mod` declarations and `pub use` re-exports of the contract types.
   - Define the object-safe `pub trait Lint` with `id()`, `source()`,
     `applies(&Cert) -> Applicability`, `check(&Cert) -> Vec<Finding>`. Document the
     "empty Vec = pass" and "engine only calls check when Applies" invariants.
   - Reference `Cert` from `cert.rs` (module declared here; the type itself is built in task 02).
     Declare `mod cert; pub use cert::Cert;` so the trait can name it.

## Acceptance Criteria

- [ ] `cargo metadata` shows a workspace with `linter` and `cli` members.
- [ ] All contract types match plan.md exactly (no `Pass` variant on `Severity`).
- [ ] `Severity` orders Notice < Warn < Error < Fatal.
- [ ] `Lint` is object-safe (a `Box<dyn Lint>` compiles).
- [ ] Public items documented; `cargo clippy --all-targets -- -D warnings` clean for the linter crate.
- [ ] Old root `src/main.rs` removed.

## Notes / Dependencies

- Blocks tasks 02, 03 (they depend on the module layout and trait defined here).
