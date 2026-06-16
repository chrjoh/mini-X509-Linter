---
agent: tester
seq: 4
title: Engine + filtering + output tests
status: done
touches:
  - crates/linter/tests/registry.rs
  - crates/cli/tests/output.rs
depends_on:
  - 02-registry-engine
  - 03-cli-output-and-filters
---

# Task: Engine + filtering + output tests

## Goal

Verify the no-short-circuit guarantee, applicability handling, source filtering, and the
text/JSON formatters.

## Files Owned (conflict scope)

- `crates/linter/tests/registry.rs`
- `crates/cli/tests/output.rs`

## Steps

1. `crates/linter/tests/registry.rs` (SIFER, Result-assertion conventions):
   - Define test-only lints (in the test module): one that always `Applies` and returns
     two findings; one that returns `NotApplicable` and **panics** in `check()` (proves
     `check` is not called for non-applicable lints); one that always returns a finding.
   - Assert `run` produces a `LintOutcome` for every lint, with correct `applicability`.
   - Assert the panicking-in-check lint reports `NotApplicable` with empty findings and
     does NOT panic (proves applies-gate).
   - Assert no short-circuit: with multiple finding-producing lints, all outcomes appear.
   - Assert `run_filtered` with a single `RuleSource` excludes other sources.
2. `crates/cli/tests/output.rs`:
   - Build a fixed `Vec<LintOutcome>` and assert `render_text` groups by source and
     contains the expected severity/message lines in deterministic order.
   - Assert `render_json` parses back to the nested shape (parse with `serde_json::Value`
     and inspect `lint_id`/`source`/`findings`).
   - Assert `--min-severity warn` filtering removes notice findings in both renderers.

## Acceptance Criteria

- [ ] Tests prove: every lint yields an outcome, `check` skipped when `NotApplicable`,
      no short-circuit, source filtering works.
- [ ] JSON test confirms nested shape and snake_case source tokens.
- [ ] Tests use `.unwrap()`/`.unwrap_err()` not `assert!(is_ok/err)`.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on tasks 02 and 03.
