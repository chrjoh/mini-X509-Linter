# Test Plan: CLI Polish & Output

## Scope

Verify `--fail-on` exit codes, the polished text formatter (grouping + per-severity counts
+ NotApplicable summary), the opt-in `--verbose`/`-v` per-lint listing, `--chain` multi-cert
handling, deterministic output, and a golden-file snapshot of the full registry over `testdata/`.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()`. Snapshot
testing via `insta`. CLI behaviour driven against the built binary.

## Fixtures (`testdata/`)

- `chain_bundle.pem` — multi-cert PEM bundle for `--chain`.
- Reuse the full set of per-lint fixtures + `good.pem` from features 01–05 for the golden
  test.

## Snapshot / Golden Tests (`crates/cli/tests/golden.rs`)

- Text output over a stable fixture set — `insta::assert_snapshot!`.
- JSON output — locks the nested per-outcome shape.
- Output must be deterministic: sorted by source/lint_id/finding order, no timestamps.

## Verbose Mode (`--verbose` / `-v`) Tests

- **Per-lint listing (text):** with `--verbose`, the output lists each lint individually under its
  source group, each line showing a status token (`pass` for an applicable lint with no surviving
  findings, `n/a` for NotApplicable) and the `lint_id`. Assert specific known lint_ids appear under
  the correct `[rfc5280]` / `[cabf_br]` / `[hygiene]` group with the expected status. Snapshot via
  `insta::assert_snapshot!`.
- **Failing lints still shown:** in verbose mode, failing-lint finding lines
  (`<severity> [<lint_id>] <message>`) still appear exactly as in default mode.
- **Collapsed summary replaced:** verbose output does **not** contain the
  `(N passed, M not applicable)` summary line; default output (flag omitted) **does**. Assert both
  directions so the unchanged default is guarded.
- **Determinism:** verbose output is byte-stable across two runs (lints sorted, no timestamps),
  i.e. golden-snapshot compatible.
- **JSON unaffected:** `--format json --verbose` produces the same JSON as `--format json` alone
  (the flag is text-only).
- **Exit code unaffected:** `--verbose` does not change the `--fail-on` exit code for the same
  input.

## Exit-Code Tests (`crates/cli/tests/exit_codes.rs`)

- `--fail-on error` + Error finding → non-zero.
- `--fail-on error` + `good.pem` → 0.
- `--fail-on fatal` + only Error findings → 0 (below threshold).
- Finding hidden by `--min-severity` does not trigger `--fail-on`.
- `--chain chain_bundle.pem` → leaf linted, others rendered as context.

## Edge Cases

- Empty findings → summary line shows all-zero counts, exit 0.
- All lints `NotApplicable` → compact summary, exit 0.
- Multiple `<PATH>` args without `--chain` → leaf-only per plan.md (define + test).
- DER input auto-detected alongside PEM.

## Verification Commands

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo insta test   # if using cargo-insta locally; cargo test also runs snapshots
```

## Exit Criteria

Golden snapshots stable; exit-code matrix correct; `--chain` rendering correct; `--verbose`
per-lint listing correct, deterministic, and JSON/exit-code unaffected with default behaviour
unchanged; README matches behaviour; all verification commands pass.
