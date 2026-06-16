# Test Plan: Workspace Skeleton & Core Types

## Scope

Verify the workspace compiles, the contract types match plan.md, the `Cert` facade loads
PEM/DER correctly, and the `not_expired` lint behaves correctly end-to-end through the CLI.

## Conventions

Follow `.claude/rules/rust-testing-core.md`:
- SIFER (Setup / Invoke / Find / Expect / Reset).
- Result assertions: `.unwrap()` / `.unwrap_err()` over `assert!(is_ok())` /
  `assert!(is_err())` so the unexpected value prints on failure.
- Group tests in `#[cfg(test)] mod tests` with nested modules per behaviour.
- Test behaviour and public API, not parser internals.

## Unit Tests (in-crate, `#[cfg(test)]`)

- `Severity` ordering: `Severity::Notice < Severity::Warn < Severity::Error <
  Severity::Fatal`.
- `Lint` object-safety smoke: a `Box<dyn Lint>` can be constructed from `NotExpired`.
- `not_expired.rs` in-file tests: expired → one `Warn`; valid → empty `Vec`.

## Integration Tests (`crates/linter/tests/not_expired.rs`)

- Load `testdata/expired.pem` → `NotExpired::check` returns exactly one `Severity::Warn`.
- Load `testdata/good.pem` → `NotExpired::check` returns empty `Vec`.
- `Cert::load` returns `Ok` for both PEM fixtures.

## Edge Cases

- Empty / non-PEM-non-DER bytes → `Cert::load` returns `Err` (not panic).
- PEM file containing multiple certs → `from_pem` returns all of them; leaf = first.
- File that does not exist → CLI returns a clear `anyhow` error, no panic/stack trace.

## Manual / CLI Verification

- `cargo run -p cli -- testdata/expired.pem` prints the Warn finding.
- `cargo run -p cli -- testdata/good.pem` prints a no-findings line.

## Verification Commands

```
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Exit Criteria

All commands above pass; CLI demonstrates the end-to-end pipe on both fixtures.
