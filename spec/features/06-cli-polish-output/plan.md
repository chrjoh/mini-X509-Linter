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
- `--purpose <auto|tls-server|generic>` flag — scopes which lint **sources** apply based on the
  certificate's intended purpose, so TLS-server-only rules do not produce false positives on non-TLS
  certs. Default `auto`. Resolves to an allowed `RuleSource` set per the mapping below; the engine then
  runs only lints whose source is in that set (reusing `Registry::run_filtered`). This is a
  CLI/engine-**filtering** layer only: it does **not** change any lint logic, `applies()` rule, or
  fixture, and does **not** alter feature 05's BROAD scoping (which still governs which leaves a
  CabfBr lint examines *once that source is in scope*).
  - **Rationale.** The CA/Browser Forum BR lints (`RuleSource::CabfBr`) are TLS-server-specific.
    Under feature 05's BROAD scoping they apply to every non-CA leaf, so a non-TLS leaf (e.g. a
    keyEncipherment-only or clientAuth cert) that correctly omits the serverAuth EKU still trips
    `cabf_br_ext_key_usage_server_auth_present` — a false positive. `--purpose` lets the user (or the
    `auto` heuristic) declare the cert is not a TLS server, dropping the whole CabfBr source from the
    run so the false positive never surfaces.
  - **Enum (extensible).** Ship `auto`, `tls-server`, `generic` now. Reserve and document — but do
    **not** implement — `client`, `smime`, `code-signing` as planned future values; until their own
    rule sets exist they would behave like `generic`. The clap `ValueEnum` must be shaped so adding
    these later is additive (no breaking rename of the three shipped variants).
  - **Purpose → allowed sources mapping.**
    - `tls-server` → `Rfc5280` + `Hygiene` + `CabfBr` (all current sources).
    - `generic` → `Rfc5280` + `Hygiene` (skip the TLS-server-specific `CabfBr` set).
    - `auto` (default) → resolved **per cert**: if the leaf asserts the serverAuth EKU
      (OID 1.3.6.1.5.5.7.3.1) treat as `tls-server`; otherwise treat as `generic`. A no-EKU or
      non-serverAuth leaf resolves to `generic`, so CabfBr is skipped (the user's encipherment-cert
      case — no false positive). `auto` is a documented **heuristic**; `--purpose tls-server` forces
      the CabfBr set even when serverAuth is absent.
    - (future `client`/`smime`/`code-signing` → `Rfc5280` + `Hygiene` + their own future rule sets;
      until those sets exist they behave like `generic`. Documented, not implemented now.)
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

### `--purpose` filtering layer

- **Resolver lives where the per-cert decision is cheapest.** The engine already exposes
  `Registry::run_filtered(&Cert, sources: &[RuleSource])` and `Cert::has_server_auth() ->
  Result<bool, CertError>` (feature 05). A purpose resolves to a `&[RuleSource]` allowed set, so the
  whole feature reuses the existing `run_filtered` path — no per-lint plumbing.
- **A small linter-crate helper owns the purpose→sources mapping** so the rule is unit-testable and
  not buried in CLI glue. Add a `CertPurpose` enum (or equivalent) plus a resolver in
  `crates/linter/src/registry.rs` (alongside `RuleSource`/`run_filtered`), e.g.
  `fn allowed_sources(purpose, cert) -> Vec<RuleSource>` (or two methods: a static map for the
  explicit variants and a per-cert resolver for `auto`). The CLI maps its `--purpose` `ValueEnum`
  into this linter type and never re-encodes the mapping itself. Adding future purposes touches only
  this one helper.
- **`auto` is resolved per cert, before filtering.** Call `Cert::has_server_auth()` on the leaf;
  `Ok(true)` → `tls-server` set, `Ok(false)` → `generic` set. **Fail-closed for the false-positive
  risk:** on `Err(..)` from `has_server_auth()`, resolve to `generic` (skip CabfBr) so a defensive
  parse failure cannot manufacture a BR false positive; the CLI surfaces the error context only if it
  also fails the overall load (it does not here — a successfully loaded `Cert` re-parsing its own DER
  is theoretically unreachable, so `generic` is the safe default).
- **Composition with `--source` is an intersection.** The effective source set passed to
  `run_filtered` is `(purpose's allowed sources) ∩ (--source selection, default = all)`. So
  `--source cabf_br --purpose generic` runs **nothing** from CabfBr (empty intersection → no findings
  from that source), and `--purpose tls-server --source rfc5280` runs only `rfc5280`. This keeps the
  two flags orthogonal and predictable: `--source` narrows what the user asked for; `--purpose`
  narrows what is applicable to the cert; the run is the overlap. For `auto`, the purpose side is
  resolved per cert first, then intersected.
- **Output behavior for purpose-skipped sources.** Lints in a source dropped by `--purpose` are
  simply **not run** — identical to an unselected `--source`. They do **not** appear as cert-level
  `NotApplicable` outcomes, to avoid conflating "out of profile / not run" with "lint examined the
  cert and reported NotApplicable". This keeps default and verbose text output, JSON, and golden
  snapshots deterministic and uncluttered. When `--verbose` is set, the text formatter **may** emit a
  single deterministic header line noting the active purpose (e.g. `purpose: generic (auto)` showing
  the resolved purpose and whether it came from `auto`); this is the only purpose-driven output
  addition and must stay stable for snapshots. Default (non-verbose) output is unchanged.
- **Exit code is post-filter.** `--fail-on` is computed from the surfaced findings *after* purpose
  filtering (and after `--min-severity`), since skipped sources produce no outcomes at all. No
  separate handling is needed beyond computing the exit code from the already-filtered outcomes.

## Changes Overview

**crates/linter/**
- `src/registry.rs` — add a `CertPurpose` enum and a purpose→`RuleSource`-set resolver (static map
  for `tls-server`/`generic`, per-cert resolution for `auto` via `Cert::has_server_auth()`). Reuses
  the existing `run_filtered`; no lint logic changes. Reserve future `client`/`smime`/`code-signing`
  variants in docs/comments only.

**crates/cli/**
- `src/main.rs` — add `--fail-on`, `--chain`, `--verbose`/`-v`, and `--purpose
  <auto|tls-server|generic>`; map `--purpose` into the linter `CertPurpose`; compute the effective
  source set as `purpose-allowed ∩ --source` (per cert for `auto`) and pass it to `run_filtered`; wire
  exit codes; thread the verbose flag into the text formatter.
- `src/output.rs` — severity counts, grouped text layout, multi-cert/chain rendering, the opt-in
  verbose per-lint listing (default collapsed summary unchanged), and an optional deterministic
  verbose-only `purpose:` header line.

**workspace root**
- `README.md` — usage, flags, exit codes, examples.

**testdata/**
- A small PEM bundle fixture for `--chain` exercising multiple certs.

## Dependencies

- None new. (`insta` for snapshot testing is introduced by the tester's golden-file test, not here.)
