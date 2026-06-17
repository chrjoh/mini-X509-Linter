---
agent: developer
seq: 2
title: --fail-on exit codes + --chain flag + multi-cert loading
status: pending
touches:
  - crates/cli/src/main.rs
depends_on:
  - 01-polished-text-formatter
  - 05-purpose-resolver
---

# Task: --fail-on exit codes + --chain flag + multi-cert loading + --verbose + --purpose

## Goal

Add `--fail-on` (driving the process exit code), `--chain`, `--verbose`/`-v`, and `--purpose
<auto|tls-server|generic>`, complete PEM-bundle / multi-cert input handling, and wire the polished
formatter so the CLI is CI-ready.

## Files Owned (conflict scope)

- `crates/cli/src/main.rs`

## Steps

1. Add clap flags:
   - `--fail-on <level>` (`ValueEnum`, default `error`) — exit non-zero if any **surfaced**
     finding (after `--min-severity` filtering) is at/above this level.
   - `--chain` — treat multiple inputs / a PEM bundle as a chain.
   - `--verbose` (`#[arg(long, short = 'v')]`, a `bool` flag) — opt-in per-lint text listing.
     Confirm no clap short-flag conflict: existing/planned flags (`--format`, `--source`,
     `--min-severity`, `--fail-on`, `--chain`, `--purpose`) are all long-only, and clap's auto short
     flags are `-h` (help) and `-V` (uppercase, `--version`); lowercase `-v` is free.
   - `--purpose <auto|tls-server|generic>` — a CLI-owned `ValueEnum` (default `Auto`) that scopes
     which lint **sources** apply. Define the enum in `main.rs` (do **not** reuse
     `linter::CertPurpose` directly as the clap type — mirror how `MinSeverity` is a CLI enum mapped
     into the library `Severity`). Shape it so future `client`/`smime`/`code-signing` variants are
     additive; document those as planned-but-unimplemented in the flag/enum doc comment. Provide a
     `From<CliPurpose> for linter::CertPurpose` (or equivalent mapping) so the three shipped variants
     map 1:1.
2. Input handling:
   - Accept `<PATH>...` (multiple paths) and PEM bundles with multiple certs.
   - Without `--chain`: lint the leaf (first cert) only, per plan.md.
   - With `--chain`: parse each cert separately; lint the leaf; render others as chain
     context (full chain-aware lints are post-v1). Use the chain renderer from task 01.
3. `--purpose` source scoping (the effective set passed to `run_filtered`):
   - Map `--purpose` into `linter::CertPurpose` and call its `allowed_sources(&leaf)` resolver
     (added in task 05). For `auto` this resolves per cert from `has_server_auth()` (serverAuth →
     tls-server set, otherwise → generic set; `Err` falls back to generic — handled inside the
     resolver, do not re-implement here).
   - Compute the **effective** source set as the intersection of the purpose-allowed sources and the
     existing `--source` selection (which defaults to all): `effective = allowed ∩ selected`. Pass
     `effective` to `registry.run_filtered(&leaf, &effective)`. Preserve a stable ordering
     (e.g. filter `ALL_SOURCES`/the resolver order by membership) so output stays deterministic. An
     empty intersection (e.g. `--source cabf_br --purpose generic`) correctly runs nothing from that
     source — that is allowed, not an error.
   - With `--chain`, resolve `auto` against the **leaf** (the linted cert), consistent with leaf-only
     linting in v1.
4. Exit code:
   - Compute from the filtered outcomes using `output::severity_counts` (do NOT re-run
     lints). If any surfaced finding `>= --fail-on`, exit non-zero (e.g. 1); else 0.
   - Use a single explicit `std::process::exit(code)` at the end (after all output is
     flushed) — fail-closed semantics, generic error messages, no panic/stack traces.
5. Keep `--format`, `--source`, `--min-severity` (from feature 02) working with the new
   flags.
6. Thread `--verbose` into the text formatter:
   - Pass the flag into `output::render_text` (and the chain renderer) via the verbosity
     parameter/enum added in task 01. Default (flag omitted) keeps today's collapsed summary.
   - `--verbose` affects `--format text` only; `--format json` is unchanged (it already emits
     every lint). It does **not** affect `--fail-on` / exit-code computation, which stays driven
     by surfaced findings via `severity_counts`.
   - When `--verbose` is set, pass the **resolved** purpose to the formatter so it can emit the
     optional deterministic `purpose:` header line (added in task 01). Default (non-verbose) output
     is unchanged.
   - Update the module-level doc comment in `main.rs` to document `--verbose`/`-v` and
     `--purpose` alongside the other flags.

## Acceptance Criteria

- [ ] `--fail-on error` exits non-zero when an Error/Fatal finding is surfaced, 0 otherwise.
- [ ] `--fail-on` respects `--min-severity` (filtered findings drive the exit code).
- [ ] `--chain` lints the leaf and renders other certs as context.
- [ ] PEM bundle with multiple certs handled; DER auto-detected.
- [ ] Exit code computed from existing outcomes, not a second lint run.
- [ ] `--verbose`/`-v` switches text output to the per-lint listing; omitting it keeps the
      collapsed summary. The flag does not change JSON output or the exit code.
- [ ] `--purpose tls-server` runs the CabfBr source; `--purpose generic` skips it; default
      (`auto`/no flag) resolves per cert from serverAuth (run BR on a serverAuth leaf, skip BR on a
      non-serverAuth leaf).
- [ ] Effective source set is `purpose-allowed ∩ --source`; an empty intersection runs nothing from
      that source and is not an error. Default `--purpose` (`auto`) with no `--source` behaves as
      before for serverAuth certs.
- [ ] Purpose-skipped sources are simply not run — no cert-level `NotApplicable` outcomes are
      synthesized for them. Exit code reflects only post-filter findings.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01 (uses `severity_counts` + chain renderer) and task 05 (uses
  `linter::CertPurpose` + `allowed_sources`).
