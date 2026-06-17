# Test Plan: CLI Polish & Output

## Scope

Verify `--fail-on` exit codes, the polished text formatter (grouping + per-severity counts
+ NotApplicable summary), the opt-in `--verbose`/`-v` per-lint listing, `--chain` multi-cert
handling, the `--purpose` source-scoping flag (incl. the BR false-positive fix on non-TLS certs),
deterministic output, and a golden-file snapshot of the full registry over `testdata/`.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()`. Snapshot
testing via `insta`. CLI behaviour driven against the built binary.

## Fixtures (`testdata/`)

- `chain_bundle.pem` — multi-cert PEM bundle for `--chain`.
- `leaf_no_server_auth.pem` — **NEW, required.** A non-TLS leaf WITHOUT the serverAuth EKU (e.g.
  `clientAuth`-only EKU, or `keyEncipherment` keyUsage with no serverAuth), generated with `openssl`
  (NEVER `cert-bar` or fabricated bytes). Needed to exercise the `auto` → `generic` (skip BR) path:
  all current leaf fixtures now carry serverAuth (feature 05 EKU cascade), so none can test the
  skip-BR / no-false-positive case. Owned/added by the tester task that owns `testdata/`.
- Reuse the full set of per-lint fixtures + `good.pem` from features 01–05 for the golden
  test. A serverAuth-bearing leaf from those (e.g. `good.pem`) exercises the `auto` → `tls-server`
  (run BR) path.

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

## Purpose Tests (`crates/cli/tests/purpose.rs`)

Drive the built binary. The `--purpose` flag scopes which lint **sources** run; skipped sources are
**not run** (no findings, and **not** synthesized as `NotApplicable`).

- **tls-server runs BR:** `--purpose tls-server` on a serverAuth leaf → `cabf_br` lints execute
  (BR outcomes present in JSON / the `[cabf_br]` group present in verbose text).
- **generic skips BR:** `--purpose generic` on the same leaf → no `cabf_br` outcomes at all
  (assert the source is absent, not present-as-`NotApplicable`); `rfc5280` + `hygiene` still run.
- **auto, serverAuth present → run BR:** default detection on a serverAuth leaf (e.g. `good.pem`)
  runs the `cabf_br` set.
- **auto, serverAuth absent → skip BR (the false-positive fix):** on `leaf_no_server_auth.pem`,
  `cabf_br_ext_key_usage_server_auth_present` does **not** fire (assert that specific lint_id is
  absent). This is the core regression guard for the non-TLS-cert false positive.
- **default == auto:** invoking with no `--purpose` flag yields identical output and exit code to
  `--purpose auto` for the same input. Assert on at least one serverAuth and one non-serverAuth
  fixture (both directions).
- **forced override:** `--purpose tls-server` on `leaf_no_server_auth.pem` still runs BR (and the
  serverAuth-present lint fires), confirming `auto` is only a heuristic.
- **intersection with `--source`:** `--source cabf_br --purpose generic` runs nothing from BR (empty
  intersection — allowed, not an error); `--purpose tls-server --source rfc5280` runs only `rfc5280`.
- **exit code is post-filter:** `--purpose generic --fail-on error` on `leaf_no_server_auth.pem`
  exits 0 when the only would-be error was the now-skipped BR serverAuth finding (end-to-end proof of
  the fix).
- **verbose purpose header:** `--verbose` emits a deterministic `purpose:` header line reflecting the
  resolved purpose (and `(auto)` when resolved from auto); non-verbose output omits it. Snapshot or
  assert; must be golden-stable.

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
unchanged; `--purpose` scoping correct (tls-server runs BR, generic skips it, auto resolves per cert,
default == auto, intersects with `--source`, exit code post-filter) with the BR false positive on
`leaf_no_server_auth.pem` eliminated; README matches behaviour; all verification commands pass.
