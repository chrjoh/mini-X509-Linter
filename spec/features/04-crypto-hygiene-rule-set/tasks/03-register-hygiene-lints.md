---
agent: developer
seq: 3
title: Register hygiene lints in the default registry
status: done
touches:
  - crates/linter/src/registry.rs
depends_on:
  - 02-hygiene-lints
---

# Task: Register hygiene lints in the default registry

## Goal

Wire the three new hygiene lints into `default_registry()` and confirm `not_expired` is
registered exactly once (it may already be registered from feature 01/02 — avoid a
duplicate).

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`

## Steps

1. Append boxed instances of `no_sha1_signature`, `rsa_key_min_2048`,
   `ecdsa_curve_allowlist` in the "add new lints here" section.
2. Verify `not_expired` appears exactly once in `default_registry()` (it was registered in
   an earlier feature). If consolidating, ensure no duplicate registration.
3. Keep ordering deterministic for the feature 06 golden test.

## Acceptance Criteria

- [ ] All four hygiene lints registered, `not_expired` exactly once.
- [ ] `--source hygiene` runs exactly the hygiene set.
- [ ] Registration order deterministic.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 02. Blocks test task 04.
