---
agent: developer
seq: 1
title: serde derives on contract types (feature-gated)
status: done
touches:
  - crates/linter/src/finding.rs
  - crates/linter/src/source.rs
  - crates/linter/Cargo.toml
depends_on: []
---

# Task: serde derives on contract types (feature-gated)

## Goal

Make the contract types serializable so the CLI can emit JSON, while keeping the core
crate lean by gating `serde` behind a feature.

## Files Owned (conflict scope)

- `crates/linter/src/finding.rs`
- `crates/linter/src/source.rs`
- `crates/linter/Cargo.toml`

This task runs first in feature 02; it must complete before the registry task (which also
edits `Cargo.toml` / lib.rs) to avoid manifest conflicts — see `depends_on` on task 02.

## Steps

1. `crates/linter/Cargo.toml`:
   - Add `serde = { version = "1", features = ["derive"], optional = true }`
     (latest stable 1.0.228, pinned 2026-06-16).
   - Add a `[features]` section with `serde = ["dep:serde"]` (and consider a `default`
     that does NOT enable it, per "keep the core lean").
2. `crates/linter/src/source.rs` — add
   `#[cfg_attr(feature = "serde", derive(serde::Serialize))]` to `RuleSource`. Use
   `#[serde(rename_all = "snake_case")]` so it serializes as `rfc5280` / `cabf_br` /
   `hygiene` (matches the `--source` token spelling).
3. `crates/linter/src/finding.rs` — same `cfg_attr` Serialize derive on `Severity`,
   `Applicability`, `Finding`, and `LintOutcome`.
   - `Severity` → `snake_case` (`notice`/`warn`/`error`/`fatal`).
   - `Applicability` → `snake_case` (`applies`/`not_applicable`).
   - Confirm the **nested** JSON shape: each `LintOutcome` serializes as one object with
     `lint_id`, `source`, `applicability`, and its own `findings` array.

## Acceptance Criteria

- [ ] `cargo build -p linter` (no features) compiles without serde.
- [ ] `cargo build -p linter --features serde` compiles and the types derive `Serialize`.
- [ ] Token spellings match the CLI vocabulary (`rfc5280`, `cabf_br`, `hygiene`,
      `notice`/`warn`/`error`/`fatal`).
- [ ] `cargo clippy --all-targets --features serde -- -D warnings` clean.

## Notes / Dependencies

- No dependency on other feature-02 tasks for code, but it touches `Cargo.toml`, so the
  registry task depends on this one to serialize manifest edits.
