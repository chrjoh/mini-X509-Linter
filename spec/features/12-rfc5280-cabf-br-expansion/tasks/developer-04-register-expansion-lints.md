---
agent: developer
seq: 4
title: Register expansion lints + update count/filter unit tests
status: pending
touches:
  - crates/linter/src/registry.rs
depends_on:
  - developer-02-rfc5280-expansion-lints
  - developer-03-cabf-br-expansion-lints
---

# Task: Register expansion lints + update count/filter unit tests

## Goal

Wire the new feature-12 lints into `default_registry()` and update the in-file registry unit tests for
the new counts. NO `source.rs` change, NO `CertPurpose` change — only `default_registry()` and its
tests. Sole owner of `registry.rs`.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`

Does NOT touch `cert.rs`, any `lints/`, `source.rs`, or any fixtures/integration tests.

## Steps

1. In `default_registry()`, **append** the new lints to the END of the appropriate source block,
   preserving the existing order of the current lints (the feature-06 golden test pins order — adding
   at the end of each block extends the snapshot rather than reshuffling existing rows):
   - After the existing 6 rfc5280 lints, add the new rfc5280 lints from task 02 (9 lint impls: the two
     SKI siblings plus the other seven).
   - After the existing 4 cabf_br lints, add the 8 new cabf_br lints from task 03.
   - Hygiene block unchanged.
   - If task 01/02 cut `rfc5280_utc_time_not_in_zulu`, register one fewer rfc5280 lint and adjust the
     counts below by 1 accordingly (note it).
2. Update the in-file unit tests (`#[cfg(test)] mod tests`):
   - `contains_the_known_lints`: total lint count **14 → 24** (`registry.len()` and `outcomes.len()`);
     add the new lint ids to the expected-ids list. (NOTE: `sample_cert()` is a CA, so the new BR lints
     and the leaf-only rfc5280 lints are `NotApplicable` but STILL produce one outcome each, so the
     OUTCOME count equals the lint count = 24.)
   - `rfc5280_source_filter_runs_exactly_the_rfc5280_set`: **6 → 16** outcomes; add the new rfc5280 ids.
   - `cabf_br_source_filter_runs_exactly_the_cabf_br_set`: **4 → 12** outcomes; add the new cabf_br ids;
     assert all are `RuleSource::CabfBr` and none are rfc5280_/hygiene_.
   - `hygiene_source_filter_runs_exactly_the_hygiene_set`: **4 — UNCHANGED.**
   - If a lint was cut, decrement the affected count(s) by 1 and omit its id; note the cut.

## Acceptance Criteria

- [ ] All new lints registered at the END of their source block; existing order untouched.
- [ ] Count test 14 → 24; rfc5280 filter 6 → 16; cabf_br filter 4 → 12; hygiene 4 unchanged (or the
      cut-adjusted variants, documented).
- [ ] All new ids present in the expected-id lists.
- [ ] `cargo test -p linter registry` green; `cargo clippy --all-targets -- -D warnings` and
      `cargo fmt --check` clean.

## Notes / Dependencies

- Depends on tasks 02 and 03. Blocks task 05 (fixtures/integration tests run over the 24-lint registry).
