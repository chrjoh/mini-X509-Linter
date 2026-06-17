---
agent: tester
seq: 6
title: Retarget not_expired.rs "now" constant for regenerated fixture windows
status: done
touches:
  - crates/linter/tests/not_expired.rs
depends_on:
  - 04-cabf-br-fixtures-and-tests
---

# Task: Retarget not_expired.rs "now" for the regenerated fixture windows

## Goal

A file the feature-05 cross-feature cascade plan missed: `crates/linter/tests/not_expired.rs`
(feature 01) hard-codes `NOW_2100 = 4_102_444_800` (2100-01-01) as a "now" chosen to sit past the
OLD `expired.pem` notAfter (2011) and before the OLD `good.pem` notAfter (2124). Task 04 regenerated
the shared fixtures with much shorter, currently-valid windows, so `NOW_2100` is now past
`good.pem`'s notAfter and the test `good_fixture_yields_no_findings` fails (good.pem is "expired" at
year 2100).

New fixture windows (from task 04 / generate.sh):
- `good.pem`:    notBefore 2026-06-01, notAfter 2027-06-01 (Unix notAfter 1_780_272_000)
- `expired.pem`: notBefore 2024-01-01, notAfter 2024-06-01 (Unix notAfter 1_717_200_000)

## Files Owned

- `crates/linter/tests/not_expired.rs` (test code + module doc only)

## Steps

1. Replace the `NOW_2100` constant with a "now" that sits **inside good.pem's new validity window**
   (strictly between 2026-06-01 and 2027-06-01) AND **past expired.pem's notAfter** (2024-06-01) — any
   instant in good.pem's window satisfies both. E.g. 2026-12-01 (`1_764_547_200`) or similar. Rename
   it accordingly (e.g. `NOW_IN_GOOD_WINDOW`).
2. Update the module doc comment (lines ~11-12) and the constant's doc comment (lines ~23-25) to
   describe the real new windows (good 2026-06-01→2027-06-01; expired 2024-01-01→2024-06-01).
3. Re-verify the other tests in the file remain correct against the new fixtures: `good_fixture_loads`,
   `expired_fixture_loads`, `expired_fixture_yields_one_warn_finding` (expired at the new "now" → one
   Warn), `expired_fixture_passes_when_now_is_before_not_after` (its pinned "now" must be before
   expired.pem's NEW notAfter 2024-06-01 — confirm/adjust if it referenced the old 2011 date),
   `der_input_is_auto_detected_and_loads`, `der_loaded_cert_is_usable_by_a_lint`. Fix any other stale
   date assumption you find; do not weaken assertions.
4. Note the time-fragility: like the other fixtures, this "now" must stay within good.pem's window;
   if good.pem is regenerated with a new window the constant must move too. Add a one-line comment.

## Acceptance Criteria

- [ ] `NOW_*` constant retargeted into good.pem's new window; doc comments corrected.
- [ ] Full `cargo test` is green (0 failures), including this file.
- [ ] `cargo test -p linter --features serde`, `cargo clippy --all-targets -- -D warnings`
      (+ `--features serde`), and `cargo fmt --check` all pass.

## Notes / Dependencies

- Depends on task 04 (regenerated fixtures). This is the last remaining failure after tasks 01-05.
- Only test code; no production `src/` changes.
