---
agent: tester
seq: 4
title: Golden-file test + exit-code tests + chain fixture
status: pending
touches:
  - testdata/chain_bundle.pem
  - testdata/leaf_no_server_auth.pem
  - crates/cli/Cargo.toml
  - crates/cli/tests/golden.rs
  - crates/cli/tests/exit_codes.rs
  - crates/cli/tests/purpose.rs
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
- `testdata/leaf_no_server_auth.pem` (a non-TLS leaf WITHOUT the serverAuth EKU — see step 5)
- `crates/cli/Cargo.toml` (add `insta` dev-dependency only)
- `crates/cli/tests/golden.rs`
- `crates/cli/tests/exit_codes.rs`
- `crates/cli/tests/purpose.rs` (`--purpose` behaviour against the built binary)
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
   - Add a **`--verbose` text** snapshot over the same fixture set: assert the per-lint listing
     shows each `lint_id` with its `pass` / `n/a` status under the correct source group, that
     failing-lint finding lines still appear, and that the collapsed
     `(N passed, M not applicable)` summary line is **absent** in verbose mode. Snapshot it twice
     (or compare two runs) to confirm determinism (sorted, no timestamps).
   - Add a default-mode assertion that the collapsed `(N passed, M not applicable)` summary is
     still present when `--verbose` is omitted (guards the unchanged default).
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
5. `testdata/leaf_no_server_auth.pem` — a **new** non-TLS leaf fixture WITHOUT the serverAuth EKU,
   needed to exercise the `auto` → `generic` (skip BR) path. **This fixture must be added here**: all
   current leaf fixtures now carry serverAuth (feature 05 EKU cascade), so none can test the
   skip-BR path. Generate it with `openssl` (e.g. a leaf with `extendedKeyUsage = clientAuth` only,
   or `keyUsage = keyEncipherment` with no serverAuth in EKU); a real CA-signed chain is unnecessary
   — a self-signed non-CA leaf that loads as a `Cert` is sufficient. Do **not** hand-edit / use
   `cert-bar` or any fabricated bytes. Keep it minimal and deterministic so snapshots are stable.
6. `crates/cli/tests/purpose.rs` (drive the built binary):
   - `--purpose tls-server` on a serverAuth leaf → `cabf_br` lints run (BR findings/outcomes present
     in JSON, or the `[cabf_br]` group present in verbose text).
   - `--purpose generic` on the same leaf → `cabf_br` lints are **absent** (not run, and **not**
     emitted as `NotApplicable`); rfc5280/hygiene still run.
   - `auto` on a serverAuth leaf → BR runs; `auto` on `testdata/leaf_no_server_auth.pem` → BR is
     skipped (no `cabf_br_ext_key_usage_server_auth_present` false positive). Assert the specific BR
     lint_id is absent in the skip case.
   - **Default == auto:** invoking with no `--purpose` flag produces identical output/exit to
     `--purpose auto` for the same input (assert both directions on at least one serverAuth and one
     non-serverAuth fixture).
   - **Intersection with `--source`:** `--source cabf_br --purpose generic` runs nothing (empty
     intersection, not an error); `--purpose tls-server --source rfc5280` runs only rfc5280.
   - **Exit code post-filter:** `--purpose generic` on `leaf_no_server_auth.pem` with `--fail-on
     error` exits 0 when the only error would have been the (now-skipped) BR serverAuth finding —
     demonstrating the false-positive fix end-to-end.
   - **Verbose purpose header:** `--verbose` emits a deterministic `purpose:` header reflecting the
     resolved purpose (and `(auto)` when from auto); non-verbose output omits it. Snapshot or assert.

## Acceptance Criteria

- [ ] Golden text + JSON snapshots committed and stable across runs.
- [ ] `--verbose` text snapshot lists every lint (`pass`/`n/a` + `lint_id`) under the right
      source group, keeps failing-finding lines, and omits the collapsed summary; default mode
      still shows the collapsed summary. Verbose output is deterministic across runs.
- [ ] Exit-code tests cover the `--fail-on` / `--min-severity` matrix above.
- [ ] `--chain` test confirms leaf-only linting + chain-context rendering.
- [ ] `testdata/leaf_no_server_auth.pem` added via `openssl` (no `cert-bar`/fabricated bytes); a
      non-TLS leaf without serverAuth.
- [ ] `--purpose` tests cover: tls-server runs BR, generic skips BR, auto runs BR on a serverAuth
      leaf and skips BR on `leaf_no_server_auth.pem`, default == auto, `--source` intersection, and
      exit code reflecting post-filter findings (BR false positive gone under generic).
- [ ] Skipped BR source produces no outcomes (not synthesized `NotApplicable`); verbose `purpose:`
      header present only in verbose mode and deterministic.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 03 (and transitively 01/02/05). Last task in feature 06.
