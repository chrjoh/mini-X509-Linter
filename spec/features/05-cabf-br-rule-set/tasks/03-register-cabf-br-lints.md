---
agent: developer
seq: 3
title: Register CA/B Forum BR lints in the default registry
status: pending
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

## Acceptance Criteria

- [ ] `default_registry()` includes all four BR lints.
- [ ] `--source cabf_br` runs exactly the BR set.
- [ ] Registration order deterministic.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 02. Blocks test task 04.
