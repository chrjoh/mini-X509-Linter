# Feature: Lint Engine, Registry & Output

## Overview

Turn the loose contract from feature 01 into a real engine: a registry that collects all lints, runs
every applicable one without short-circuiting, and produces both text and JSON output. Add the
`--source` and `--min-severity` filters. This is plan.md Milestone 2.

## Requirements

- A registry in `crates/linter/` that holds all lints (`Vec<Box<dyn Lint>>` to start) and exposes a
  `run(&Cert) -> Vec<LintOutcome>` that:
  - Calls `applies()` for each lint; records `NotApplicable` outcomes (with empty findings) without
    calling `check()`.
  - Calls `check()` for applicable lints and stores the returned findings.
  - **Never short-circuits** — every applicable lint runs, every finding is collected, so a single
    run reports the complete picture (a failure in one lint never suppresses another).
- Filtering, applied by the engine/CLI:
  - `--source <list>` — comma-separated `rfc5280,cabf_br,hygiene` (default: all).
  - `--min-severity <level>` — only surface findings at or above the level (default: `notice`).
- Output formats:
  - `--format text` (default) — human-readable, grouped by `RuleSource`.
  - `--format json` — serde-serialized. The JSON shape is **nested**: one object per `LintOutcome`
    (carrying `lint_id`, `source`, `applicability`) with its own `findings` array. (Confirmed shape.)
- A way to list/aggregate so later features (exit codes, counts) can build on the engine output.

## Architecture

- Registry is the single place lints are wired up; auto-registration (`inventory`/`linkme`) is a
  documented post-v1 stretch, not built here.
- Filtering by `RuleSource` happens before/around `run`; `--min-severity` filters the findings in
  each `LintOutcome` at the reporting boundary so the raw outcomes stay complete.
- Output is a formatter layer over `Vec<LintOutcome>`; `serde` derives live on the contract types
  (gate behind a `serde` feature on the `linter` crate to keep the core lean, or enable directly).
- CLI moves from feature 01's direct single-lint call to driving the registry.

## Changes Overview

**crates/linter/**
- `src/registry.rs` — registry type, lint registration, `run()` (no short-circuit), source filtering.
- `src/finding.rs` — add `serde::Serialize` derives (and the nested-outcome representation).
- `src/lib.rs` — export registry + a constructor that returns the default registry.
- `Cargo.toml` — add `serde` (feature-gated).

**crates/cli/**
- `src/main.rs` — add `--format`, `--source`, `--min-severity` flags (clap).
- `src/output.rs` (new) — text and JSON formatters over `Vec<LintOutcome>`.
- `Cargo.toml` — add `serde_json`.

## Dependencies

- `serde = { version = "1", features = ["derive"] }` (linter, feature-gated)
- `serde_json = "1"` (cli)
