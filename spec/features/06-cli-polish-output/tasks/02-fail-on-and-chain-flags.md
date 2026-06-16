---
agent: developer
seq: 2
title: --fail-on exit codes + --chain flag + multi-cert loading
status: pending
touches:
  - crates/cli/src/main.rs
depends_on:
  - 01-polished-text-formatter
---

# Task: --fail-on exit codes + --chain flag + multi-cert loading

## Goal

Add `--fail-on` (driving the process exit code) and `--chain`, complete PEM-bundle /
multi-cert input handling, and wire the polished formatter so the CLI is CI-ready.

## Files Owned (conflict scope)

- `crates/cli/src/main.rs`

## Steps

1. Add clap flags:
   - `--fail-on <level>` (`ValueEnum`, default `error`) — exit non-zero if any **surfaced**
     finding (after `--min-severity` filtering) is at/above this level.
   - `--chain` — treat multiple inputs / a PEM bundle as a chain.
2. Input handling:
   - Accept `<PATH>...` (multiple paths) and PEM bundles with multiple certs.
   - Without `--chain`: lint the leaf (first cert) only, per plan.md.
   - With `--chain`: parse each cert separately; lint the leaf; render others as chain
     context (full chain-aware lints are post-v1). Use the chain renderer from task 01.
3. Exit code:
   - Compute from the filtered outcomes using `output::severity_counts` (do NOT re-run
     lints). If any surfaced finding `>= --fail-on`, exit non-zero (e.g. 1); else 0.
   - Use a single explicit `std::process::exit(code)` at the end (after all output is
     flushed) — fail-closed semantics, generic error messages, no panic/stack traces.
4. Keep `--format`, `--source`, `--min-severity` (from feature 02) working with the new
   flags.

## Acceptance Criteria

- [ ] `--fail-on error` exits non-zero when an Error/Fatal finding is surfaced, 0 otherwise.
- [ ] `--fail-on` respects `--min-severity` (filtered findings drive the exit code).
- [ ] `--chain` lints the leaf and renders other certs as context.
- [ ] PEM bundle with multiple certs handled; DER auto-detected.
- [ ] Exit code computed from existing outcomes, not a second lint run.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01 (uses `severity_counts` + chain renderer).
