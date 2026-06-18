---
agent: developer
seq: 3
title: Register EV lints, fold CabfEv into tls-server sources, wire CLI/output
status: pending
touches:
  - crates/linter/src/registry.rs
  - crates/cli/src/main.rs
  - crates/cli/src/output.rs
depends_on:
  - developer-02-cabf-ev-lints
---

# Task: Register EV lints, fold CabfEv into tls-server sources, wire CLI/output

## Goal

Wire the nine EV lints into `default_registry()`, add `RuleSource::CabfEv` to the `tls-server`
allowed-source set (so `auto`/`tls-server` pull in the EV checks), and add the `cabf_ev` token to the
CLI `--source` vocabulary and the text formatter's source ordering/labels.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs` (register lints + `tls_server_sources` + in-file unit tests).
  **NOTE:** this is the library `src/registry.rs`, NOT the integration `tests/registry.rs` (task 04).
- `crates/cli/src/main.rs` (`parse_source_token`, `ALL_SOURCES`, `--source` help text).
- `crates/cli/src/output.rs` (`SOURCE_ORDER`, `source_label`).

All three are **shared with siblings 09/10** — the multi-feature orchestrator must serialize these
edits. See plan.md "Cross-Feature Coordination".

## Steps

1. `registry.rs`:
   - Append boxed instances of the nine EV lints in the "add new lints here" section, AFTER the BR
     lints, in a deterministic order (matters for the feature-06 golden test). Add a `// CA/Browser
     Forum EV lints (feature 11)` comment block mirroring the existing BR block.
   - Update `tls_server_sources()` to `vec![Rfc5280, Hygiene, CabfBr, CabfEv]` (add `CabfEv`). Update
     its doc comment and `generic_sources()` is unchanged. Choose a stable order; EV directly after
     BR keeps downstream output deterministic.
   - Update the in-file `default_registry` unit tests this file owns:
     - `contains_the_known_lints`: bump `registry.len()` / `outcomes.len()` by 9 and add the nine
       `cabf_ev_*` ids to the expected list. (`sample_cert()` is a CA → EV lints are `NotApplicable`
       but still produce one outcome each, so the outcome count still equals the registry length.)
     - Add `cabf_ev_source_filter_runs_exactly_the_cabf_ev_set` mirroring the cabf_br filter test:
       `run_filtered(&cert, &[RuleSource::CabfEv])` → 9 outcomes, all `RuleSource::CabfEv`, the nine
       ids, none `rfc5280_`/`hygiene_`/`cabf_br_`.
     - Update `tls_server_includes_cabf_br` (and the `auto_*` tls-server tests) to also expect
       `CabfEv` in the returned set; keep the assertion order matching the new `tls_server_sources()`.
     - Leave the rfc5280 (16) and hygiene (4) and cabf_br (12) filter-count tests unchanged (baseline after feature 12).
2. `main.rs`:
   - Add `"cabf_ev" => Ok(RuleSource::CabfEv)` to `parse_source_token`; extend the error message's
     expected-list to include `cabf_ev`.
   - Add `RuleSource::CabfEv` to `ALL_SOURCES` (bump the array length; choose the deterministic order
     `Rfc5280, CabfBr, CabfEv, Hygiene`, reconciled with siblings 09/10 at integration).
   - Update the `--source` doc/help comment to list `cabf_ev`.
   - Update the `select_sources` / `effective_sources` unit tests if their expected source vectors now
     include `CabfEv` (the `tls_server_with_all_sources_keeps_all` test must expect the new
     tls-server set ordering).
3. `output.rs`:
   - Add `RuleSource::CabfEv` to `SOURCE_ORDER` (place it after `CabfBr`, before `Hygiene`, matching
     the chosen deterministic order) and to `source_label` (`RuleSource::CabfEv => "cabf_ev"`).

## Acceptance Criteria

- [ ] `default_registry()` includes all nine EV lints in a deterministic order after the BR lints.
- [ ] `tls_server_sources()` includes `CabfEv`; `auto`/`tls-server` therefore run the EV set; the
      tls-server purpose unit tests updated to expect it.
- [ ] `--source cabf_ev` runs exactly the EV set (registry filter test added).
- [ ] `contains_the_known_lints` bumped by 9 with the nine `cabf_ev_*` ids; cabf_br/rfc5280/hygiene
      filter counts unchanged.
- [ ] `main.rs` `parse_source_token` + `ALL_SOURCES` + help text include `cabf_ev`; affected CLI unit
      tests updated.
- [ ] `output.rs` `SOURCE_ORDER` + `source_label` include `CabfEv`.
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` (and `--features serde`) clean.

## Notes / Dependencies

- Depends on task 02. Blocks test task 04.
- The final lint count and `ALL_SOURCES`/`SOURCE_ORDER` ordering depend on siblings 09/10. Whichever
  feature lands last reconciles the total count and the full ordered source list. See plan.md.
