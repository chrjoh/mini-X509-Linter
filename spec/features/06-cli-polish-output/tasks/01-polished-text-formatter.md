---
agent: developer
seq: 1
title: Polished text formatter + chain rendering + counts
status: pending
touches:
  - crates/cli/src/output.rs
depends_on: []
---

# Task: Polished text formatter + chain rendering + counts

## Goal

Upgrade the text formatter (from feature 02) to group by `RuleSource`, add a per-severity
summary line, summarize `NotApplicable` lints compactly, render multiple certs / a chain,
and guarantee deterministic output suitable for golden snapshots.

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

## Acceptance Criteria

- [ ] Text output is deterministic (sorted, no timestamps) — golden-snapshot viable.
- [ ] Summary line shows correct per-severity counts.
- [ ] `NotApplicable` lints are summarized, not listed line by line.
- [ ] Multi-cert/chain rendering labels each cert and groups output clearly.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- No code dependency on other feature-06 tasks; blocks task 02 (main.rs uses
  `severity_counts` and the chain renderer).
