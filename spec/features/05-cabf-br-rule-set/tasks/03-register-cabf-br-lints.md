---
agent: developer
seq: 3
title: Register CA/B Forum BR lints in the default registry
status: done
touches:
  - crates/linter/src/registry.rs
depends_on:
  - 02-cabf-br-lints
---

# Task: Register CA/B Forum BR lints in the default registry

## Goal

Wire the four BR lints into `default_registry()` so they run by default and respond to
`--source cabf_br`.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`

## Steps

1. Append boxed instances of `validity_max_398_days`, `cn_in_san`,
   `no_internal_names_or_reserved_ip`, `ext_key_usage_server_auth_present` in the
   "add new lints here" section.
2. Keep ordering deterministic for the feature 06 golden test.
3. Update the in-file `default_registry` unit tests in `registry.rs` (this task owns the file):
   - `contains_the_known_lints`: change `registry.len()` and `outcomes.len()` from `10` to `14`,
     and add the four `cabf_br_*` ids to the expected-ids list. (`sample_cert()` is a CA, so the
     BR lints are `NotApplicable` but still produce one OUTCOME each → outcome count is also 14.)
   - Add a `cabf_br_source_filter_runs_exactly_the_cabf_br_set` test mirroring the existing
     rfc5280/hygiene filter tests: `run_filtered(&cert, &[RuleSource::CabfBr])` → 4 outcomes, all
     `RuleSource::CabfBr`, containing the four `cabf_br_*` ids, and none of the rfc5280_/hygiene_
     ids.
   - Leave the rfc5280 (6) and hygiene (4) filter-count tests unchanged.

## Acceptance Criteria

- [ ] `default_registry()` includes all four BR lints.
- [ ] `--source cabf_br` runs exactly the BR set.
- [ ] Registration order deterministic.
- [ ] `contains_the_known_lints` updated to 14 lints + the four `cabf_br_*` ids; a
      `cabf_br` source-filter test added.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 02. Blocks test task 04.
