---
agent: tester
seq: 6
title: Regenerate CLI golden snapshots + fix hardcoded count for the 32-lint registry
status: done
touches:
  - crates/cli/tests/snapshots/golden__json_output__good_json.snap
  - crates/cli/tests/snapshots/golden__text_output__good_text.snap
  - crates/cli/tests/snapshots/golden__text_output__cabf_br_validity_400_days_text.snap
  - crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap
  - crates/cli/tests/snapshots/golden__verbose_output__good_verbose_text.snap
  - crates/cli/tests/output.rs
depends_on:
  - tester-05-expansion-fixtures-and-tests
---

# Task: CLI golden-snapshot + count ripple from the 32-lint registry

## Goal

Task 04 grew `default_registry()` from 14 → 32 lints (rfc5280 6→16, cabf_br 4→12). This is a
known, purely-additive ripple into the feature-06 CLI tests, which task 05 correctly flagged but
left untouched (out of its scope). Resolve it here.

## Background (verified by task 05)

The registry change is additive and order-preserving: 10 new `rfc5280_*` rows are inserted after
the existing 6 (before cabf_br), and 8 new `cabf_br_*` rows are appended after the existing 4 — exact
registry order, no existing row reordered or changed. `expired.pem` and `good.pem` are byte-identical
(no fixture regeneration). So every diff below is new lint rows / changed counts only.

## Files Owned

- The 5 golden snapshot files under `crates/cli/tests/snapshots/` listed in `touches`.
- `crates/cli/tests/output.rs` — ONLY the one stale count assertion (see step 2).

## Steps

1. Regenerate the 5 golden snapshots by running the CLI golden test with insta in accept mode, e.g.
   `INSTA_UPDATE=always cargo test -p cli --test golden` (or `cargo insta accept` after a normal
   run). Then **inspect the diff** of each `.snap` to confirm the change is ONLY additive new lint
   rows in registry order (10 new rfc5280, 8 new cabf_br) and updated summary counts — no existing
   row reordered, renamed, or dropped, no timestamps. Do not hand-edit snapshot bodies; let insta
   write them, then verify. Remove any `.snap.new` artifacts.

2. In `crates/cli/tests/output.rs` (~line 133), the test
   `text_output::source_rfc5280_on_expired_reports_no_findings` asserts the rfc5280 group prints
   `(3 passed, 3 not applicable)` on `expired.pem`. With 16 rfc5280 lints this is now
   `(7 passed, 9 not applicable)`. Update the expected string. Verify the new numbers by reasoning
   (or by running) — 16 rfc5280 lints on the expired leaf = 7 passed + 9 not-applicable, 0 findings
   for the rfc5280 source (the test's intent — "no findings" — must still hold). Do not weaken the
   "no findings / no error" intent of the test.

3. Do NOT touch any other file. Do NOT regenerate fixtures or any `src/`.

## Acceptance Criteria

- [ ] All 5 golden snapshots regenerated; diffs confirmed purely additive in registry order.
- [ ] `output.rs` count assertion updated to the correct `(7 passed, 9 not applicable)` (verify the
      exact numbers; reconcile if reality differs and report).
- [ ] `cargo test` (full workspace) green — 0 failures.
- [ ] `cargo test -p linter --features serde`, `cargo clippy --all-targets -- -D warnings`,
      `cargo fmt --check` all pass.

## Notes / Dependencies

- Depends on task 05 (new fixtures + lints fully wired). Pure test-artifact reconciliation; no
  production code, no fixtures.
