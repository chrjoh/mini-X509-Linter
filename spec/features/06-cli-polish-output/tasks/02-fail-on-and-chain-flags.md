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

# Task: --fail-on exit codes + --chain flag + multi-cert loading + --verbose

## Goal

Add `--fail-on` (driving the process exit code), `--chain`, and `--verbose`/`-v`, complete
PEM-bundle / multi-cert input handling, and wire the polished formatter so the CLI is CI-ready.

## Files Owned (conflict scope)

- `crates/cli/src/main.rs`

## Steps

1. Add clap flags:
   - `--fail-on <level>` (`ValueEnum`, default `error`) — exit non-zero if any **surfaced**
     finding (after `--min-severity` filtering) is at/above this level.
   - `--chain` — treat multiple inputs / a PEM bundle as a chain.
   - `--verbose` (`#[arg(long, short = 'v')]`, a `bool` flag) — opt-in per-lint text listing.
     Confirm no clap short-flag conflict: existing/planned flags (`--format`, `--source`,
     `--min-severity`, `--fail-on`, `--chain`) are all long-only, and clap's auto short flags are
     `-h` (help) and `-V` (uppercase, `--version`); lowercase `-v` is free.
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
5. Thread `--verbose` into the text formatter:
   - Pass the flag into `output::render_text` (and the chain renderer) via the verbosity
     parameter/enum added in task 01. Default (flag omitted) keeps today's collapsed summary.
   - `--verbose` affects `--format text` only; `--format json` is unchanged (it already emits
     every lint). It does **not** affect `--fail-on` / exit-code computation, which stays driven
     by surfaced findings via `severity_counts`.
   - Update the module-level doc comment in `main.rs` to document `--verbose`/`-v` alongside the
     other flags.

## Acceptance Criteria

- [ ] `--fail-on error` exits non-zero when an Error/Fatal finding is surfaced, 0 otherwise.
- [ ] `--fail-on` respects `--min-severity` (filtered findings drive the exit code).
- [ ] `--chain` lints the leaf and renders other certs as context.
- [ ] PEM bundle with multiple certs handled; DER auto-detected.
- [ ] Exit code computed from existing outcomes, not a second lint run.
- [ ] `--verbose`/`-v` switches text output to the per-lint listing; omitting it keeps the
      collapsed summary. The flag does not change JSON output or the exit code.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01 (uses `severity_counts` + chain renderer).
