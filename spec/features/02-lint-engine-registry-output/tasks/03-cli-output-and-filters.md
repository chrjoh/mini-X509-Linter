---
agent: developer
seq: 3
title: CLI filters (--format/--source/--min-severity) + formatters
status: done
touches:
  - crates/cli/src/main.rs
  - crates/cli/src/output.rs
  - crates/cli/Cargo.toml
depends_on:
  - 02-registry-engine
---

# Task: CLI filters + text/JSON formatters

## Goal

Drive the registry from the CLI, add the `--format`, `--source`, and `--min-severity`
flags, and produce both text (grouped by `RuleSource`) and nested JSON output.

## Files Owned (conflict scope)

- `crates/cli/src/main.rs`
- `crates/cli/src/output.rs` (new)
- `crates/cli/Cargo.toml`

## Steps

1. `crates/cli/Cargo.toml`:
   - Add `serde_json = "1"` (latest stable 1.0.150, pinned 2026-06-16).
   - Enable the linter `serde` feature: `linter = { path = "../linter", features = ["serde"] }`.
2. `crates/cli/src/main.rs`:
   - Replace the hard-coded single-lint call from feature 01 with `default_registry()`.
   - Add clap flags:
     - `--format <text|json>` (default `text`) — use a clap `ValueEnum`.
     - `--source <list>` — comma-separated `rfc5280,cabf_br,hygiene`; parse into
       `Vec<RuleSource>` (default = all). Reject unknown tokens with a clear error.
     - `--min-severity <level>` (default `notice`) — `ValueEnum` over the severities.
   - Load leaf cert, call `registry.run_filtered(&cert, sources)`.
   - Apply `--min-severity` at the **reporting boundary**: filter findings within each
     outcome for display only; do not mutate the raw outcomes the engine produced.
   - Dispatch to the chosen formatter; exit 0 for now (exit codes arrive in feature 06).
3. `crates/cli/src/output.rs`:
   - `pub fn render_text(outcomes: &[LintOutcome], min: Severity) -> String` — group by
     `RuleSource` (stable, sorted order); list each finding (severity + message).
     Summarize `NotApplicable` lints compactly rather than printing them verbosely.
   - `pub fn render_json(outcomes: &[LintOutcome], min: Severity) -> Result<String>` —
     `serde_json::to_string_pretty` over the (min-severity-filtered) nested outcomes.
   - Keep ordering deterministic so feature 06's golden test is viable.

## Acceptance Criteria

- [ ] `--format json` emits the nested shape (one object per outcome with its own
      `findings` array; `source` as `rfc5280`/`cabf_br`/`hygiene`).
- [ ] `--source rfc5280,hygiene` runs only those sources.
- [ ] `--min-severity warn` hides `notice` findings in both formats.
- [ ] Unknown `--source` / `--format` / `--min-severity` token → clear error, no panic.
- [ ] Output ordering is deterministic.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 02 (needs `default_registry` + `run_filtered`).
