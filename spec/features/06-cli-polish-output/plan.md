# Feature: CLI Polish & Output

## Overview

Make the CLI genuinely usable in CI: exit codes driven by `--fail-on`, a polished text formatter with
per-severity counts, the `--chain` flag, a README, and a golden-file test that snapshots the full
registry over `testdata/`. This is plan.md Milestone 6.

## Requirements

- `--fail-on <level>` — exit non-zero if any surfaced finding is at/above the level (default:
  `error`). Drives the process exit code so the tool works in CI / pre-commit hooks.
- Polished `--format text` output: findings grouped by `RuleSource`, plus a summary line with counts
  by severity (e.g. `2 error, 1 warn, 3 notice`). `NotApplicable` lints are summarized, not noisy.
- `--chain` flag — treat multiple inputs / a PEM bundle as a chain; for now parse each cert
  separately and lint each (full chain-aware lints remain a post-v1 stretch). Define the output
  grouping when multiple certs are present.
- Input handling completeness: auto-detect PEM vs DER; a PEM file may contain multiple certs.
- README documenting the CLI surface, exit-code semantics, and example invocations.

## Architecture

- Exit-code logic lives in the CLI, computed from the filtered `Vec<LintOutcome>` (reuse the engine
  output; do not re-run lints).
- The text formatter is extended from feature 02's `output.rs`; counts are derived from outcomes.
- The golden test is owned by the tester (separate test-plan/feature work), but this feature must
  produce **stable, deterministic** output (sorted ordering, no timestamps) so snapshots are viable.

## Changes Overview

**crates/cli/**
- `src/main.rs` — add `--fail-on` and `--chain`; wire exit codes.
- `src/output.rs` — severity counts, grouped text layout, multi-cert/chain rendering.

**workspace root**
- `README.md` — usage, flags, exit codes, examples.

**testdata/**
- A small PEM bundle fixture for `--chain` exercising multiple certs.

## Dependencies

- None new. (`insta` for snapshot testing is introduced by the tester's golden-file test, not here.)
