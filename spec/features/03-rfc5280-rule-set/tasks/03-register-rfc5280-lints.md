---
agent: developer
seq: 3
title: Register RFC 5280 lints in the default registry
status: pending
touches:
  - crates/linter/src/registry.rs
depends_on:
  - 02-rfc5280-lints
---

# Task: Register RFC 5280 lints in the default registry

## Goal

Wire the six RFC 5280 lints into `default_registry()` so they run by default and respond to
`--source rfc5280`.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`

Sole owner of `registry.rs` within feature 03 (kept separate from the lint files to avoid a
multi-writer conflict).

## Steps

1. In the "add new lints here" section of `default_registry()`, append boxed instances of
   the six RFC 5280 lints (`version_is_v3`, `serial_number_positive`, `validity_window`,
   `basic_constraints_critical_on_ca`, `key_usage_present_when_ca`,
   `san_present_if_subject_empty`).
2. Keep registration ordering stable/deterministic (matters for the feature 06 golden test).

## Acceptance Criteria

- [ ] `default_registry()` includes all six RFC 5280 lints.
- [ ] `--source rfc5280` runs exactly the RFC 5280 set.
- [ ] Registration order is deterministic.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 02. This is the last code task; test task 04 depends on it.
