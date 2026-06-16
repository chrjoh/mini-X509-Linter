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
- `--verbose` / `-v` flag — opt-in per-lint text listing. When set, the `--format text` formatter
  lists **every** lint individually within its source group (its `lint_id` plus a per-lint status
  token) instead of the collapsed `(N passed, M not applicable)` summary. Failing lints still render
  their finding lines exactly as today. The data is already present on every `LintOutcome` returned
  by `Registry::run` (`lint_id`, `applicability`, `findings`), so no engine/linter change is needed.
  Default (flag omitted) behaviour is **unchanged** — the collapsed summary — keeping default CI
  output terse and the verbose listing opt-in. Verbose output must stay deterministic (stable lint
  ordering, no timestamps) so it remains golden-snapshot friendly. `--verbose` affects text only;
  `--format json` already emits every lint with its `lint_id`/`applicability` and is unaffected.
- Input handling completeness: auto-detect PEM vs DER; a PEM file may contain multiple certs.
- README documenting the CLI surface, exit-code semantics, and example invocations.

## Architecture

- Exit-code logic lives in the CLI, computed from the filtered `Vec<LintOutcome>` (reuse the engine
  output; do not re-run lints).
- The text formatter is extended from feature 02's `output.rs`; counts are derived from outcomes.
- Verbose mode is a presentation-only branch inside the text formatter: the same `Vec<LintOutcome>`
  drives both layouts, selected by a `bool` (or small enum) parameter threaded from the `--verbose`
  flag. No second engine run, no new data. Failing-lint rendering is identical in both modes; only the
  passing / NotApplicable lints change from a collapsed count to one labelled line per lint. Status
  tokens and lint ordering are fixed (e.g. sorted by `lint_id` within each source group) for snapshot
  stability.
- The golden test is owned by the tester (separate test-plan/feature work), but this feature must
  produce **stable, deterministic** output (sorted ordering, no timestamps) so snapshots are viable.

## Changes Overview

**crates/cli/**
- `src/main.rs` — add `--fail-on`, `--chain`, and `--verbose`/`-v`; wire exit codes; thread the
  verbose flag into the text formatter.
- `src/output.rs` — severity counts, grouped text layout, multi-cert/chain rendering, and the opt-in
  verbose per-lint listing (default collapsed summary unchanged).

**workspace root**
- `README.md` — usage, flags, exit codes, examples.

**testdata/**
- A small PEM bundle fixture for `--chain` exercising multiple certs.

## Dependencies

- None new. (`insta` for snapshot testing is introduced by the tester's golden-file test, not here.)
