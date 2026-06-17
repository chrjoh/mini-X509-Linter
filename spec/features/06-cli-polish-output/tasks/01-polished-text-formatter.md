---
agent: developer
seq: 1
title: Polished text formatter + chain rendering + counts
status: done
touches:
  - crates/cli/src/output.rs
depends_on: []
---

# Task: Polished text formatter + chain rendering + counts

## Goal

Upgrade the text formatter (from feature 02) to group by `RuleSource`, add a per-severity
summary line, summarize `NotApplicable` lints compactly, render multiple certs / a chain,
add an opt-in verbose per-lint listing, and guarantee deterministic output suitable for
golden snapshots.

## Files Owned (conflict scope)

- `crates/cli/src/output.rs`

Sole owner of `output.rs` in feature 06 (runs before the main.rs task, which only calls
into the new functions). No other feature-06 code task touches this file.

## Steps

1. Extend `render_text`:
   - Findings grouped by `RuleSource`, stable sorted order (source, then lint_id, then
     finding order). No timestamps or other nondeterministic content.
   - A summary line with counts by severity, e.g. `2 error, 1 warn, 3 notice`.
   - `NotApplicable` lints summarized as a count (e.g. `4 not applicable`), not listed
     verbosely.
2. Add a counts helper, e.g.
   `pub fn severity_counts(outcomes: &[LintOutcome], min: Severity) -> SeverityCounts`,
   returning per-severity totals over the surfaced findings. (Reused by the exit-code task.)
3. Add multi-cert / chain rendering:
   - `pub fn render_text_chain(certs: &[CertReport], min: Severity) -> String` (or a
     param to `render_text`) where each entry is labeled (e.g. `Certificate 1 (leaf)`,
     `Certificate 2`). Define the grouping clearly; only the leaf carries lint findings
     in v1, others are chain context. Keep output deterministic.
4. Keep `render_json` consistent (counts can be a top-level field if helpful, but do not
   break the nested per-outcome shape from feature 02).
5. Add an opt-in **verbose** per-lint listing to the text formatter (text only — JSON is
   unaffected; it already emits every lint):
   - Thread a verbosity selector into `render_text` (and `render_text_chain`), e.g. a
     `verbose: bool` parameter or a small `enum Verbosity { Summary, PerLint }`. Keep the
     default path byte-for-byte identical to today's output.
   - **Default (Summary):** unchanged — the collapsed `(N passed, M not applicable)` line per
     source group.
   - **Verbose (PerLint):** within each source group, list **every** lint on its own line with a
     fixed-width status token followed by its `lint_id`, e.g.
     ```
     [rfc5280]
       pass  rfc5280_version_is_v3
       n/a   rfc5280_basic_constraints_critical_on_ca
     ```
     Use stable status tokens — propose `pass` (applicable, no surviving findings) and `n/a`
     (NotApplicable). Failing lints still render their existing finding lines
     (`  <severity> [<lint_id>] <message>`) unchanged; the collapsed summary line is **omitted**
     in verbose mode (the per-lint lines replace it).
   - Order lints deterministically within each group (e.g. sorted by `lint_id`) so the verbose
     listing is golden-snapshot stable. No timestamps or other nondeterministic content.
   - The per-severity summary/counts line behaviour is unchanged by verbosity.
6. Add an **optional, verbose-only** `purpose:` header line so the active scope is visible in verbose
   text output (the `--purpose` flag is wired in task 02; this task only renders it):
   - Accept the resolved purpose as a parameter to `render_text` (and the chain renderer), e.g. a
     small struct/enum value the caller passes. A simple, snapshot-stable rendering is recommended,
     e.g. `purpose: generic (auto)` — the resolved purpose plus, in parentheses, whether it came from
     `auto`; for an explicit `--purpose tls-server` render `purpose: tls-server`.
   - Emit this line **only** in verbose mode; default (non-verbose) output is byte-for-byte
     unchanged. Keep it deterministic (no timestamps, fixed wording) for golden snapshots.
   - This is the only purpose-driven output addition. Purpose-skipped sources are **not** rendered as
     `NotApplicable` — they are simply absent (the CLI passes a smaller source set to the engine), so
     the formatter needs no special handling for them beyond the header line.

## Acceptance Criteria

- [ ] Text output is deterministic (sorted, no timestamps) — golden-snapshot viable.
- [ ] Summary line shows correct per-severity counts.
- [ ] `NotApplicable` lints are summarized, not listed line by line.
- [ ] Multi-cert/chain rendering labels each cert and groups output clearly.
- [ ] Verbose mode lists every lint individually (status token + `lint_id`) within its source
      group, in deterministic (sorted) order; failing-lint finding lines unchanged.
- [ ] Verbose mode omits the collapsed `(N passed, M not applicable)` summary line (replaced by
      the per-lint lines); default (non-verbose) output is byte-for-byte unchanged.
- [ ] Verbose mode emits a deterministic `purpose:` header line reflecting the resolved purpose (and
      `(auto)` when resolved from `auto`); default (non-verbose) output does not include it and is
      byte-for-byte unchanged. No `NotApplicable` outcomes are synthesized for purpose-skipped
      sources.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- No code dependency on other feature-06 tasks; blocks task 02 (main.rs uses
  `severity_counts` and the chain renderer).
