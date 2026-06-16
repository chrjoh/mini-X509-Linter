---
agent: tester
seq: 4
title: Golden-file test + exit-code tests + chain fixture
status: pending
touches:
  - testdata/chain_bundle.pem
  - crates/cli/Cargo.toml
  - crates/cli/tests/golden.rs
  - crates/cli/tests/exit_codes.rs
  - crates/cli/tests/snapshots/
depends_on:
  - 03-readme
---

# Task: Golden-file test + exit-code tests + chain fixture

## Goal

Snapshot the full registry over `testdata/` and verify `--fail-on` exit codes and `--chain`
behaviour against the real binary.

## Files Owned (conflict scope)

- `testdata/chain_bundle.pem` (a multi-cert PEM bundle for `--chain`)
- `crates/cli/Cargo.toml` (add `insta` dev-dependency only)
- `crates/cli/tests/golden.rs`
- `crates/cli/tests/exit_codes.rs`
- `crates/cli/tests/snapshots/` (insta snapshots)

## Steps

1. Add `insta` as a `[dev-dependencies]` entry in `crates/cli/Cargo.toml` (snapshot test
   tooling is introduced here, per the feature plan).
2. `testdata/chain_bundle.pem` — concatenate a leaf + an intermediate (reuse existing
   fixtures where possible) to exercise `--chain`.
3. `crates/cli/tests/golden.rs`:
   - Run the registry / formatter over a stable set of `testdata/` fixtures and snapshot
     the **text** output with `insta::assert_snapshot!`. Also snapshot the **JSON** output
     (parse-and-reserialize or `assert_json_snapshot!`) to lock the nested shape.
   - Output must be deterministic (sorted, no timestamps) — if it is not, that is a bug in
     the formatter to report back, not something to paper over in the test.
4. `crates/cli/tests/exit_codes.rs` (drive the built binary, e.g. via
   `assert_cmd`/`std::process::Command`):
   - `--fail-on error` on a cert with an Error finding → non-zero exit.
   - `--fail-on error` on `good.pem` → exit 0.
   - `--fail-on fatal` on a cert with only Error findings → exit 0 (below threshold).
   - `--min-severity` interaction: a finding filtered out below `--min-severity` does not
     trigger `--fail-on`.
   - `--chain chain_bundle.pem` lints the leaf and renders other certs as context; exit
     code reflects only surfaced findings.
   (If `assert_cmd` is preferred over hand-rolled `Command`, add it as a dev-dependency in
   the same `Cargo.toml` edit.)

## Acceptance Criteria

- [ ] Golden text + JSON snapshots committed and stable across runs.
- [ ] Exit-code tests cover the `--fail-on` / `--min-severity` matrix above.
- [ ] `--chain` test confirms leaf-only linting + chain-context rendering.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 03 (and transitively 01/02). Last task in feature 06.
