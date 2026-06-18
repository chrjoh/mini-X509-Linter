# Test Plan: Per-Certificate Inspection Under `--chain --info`

## Scope

Verify that `--chain --info` emits a labelled `Certificate Summary` block for EVERY certificate in
the bundle (chain/file order, same labels as the chain lint report), then the chain lint report; that
the `--chain --info --format json` envelope carries a per-cert `summary`; and that all four
invariants hold: single-cert `--info` unchanged, default (no `--info`) output unchanged (text + JSON,
single + chain), exit code unchanged, and graceful degradation for an unsummarizable cert.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()`, behaviour-focused tests
in nested modules. Snapshot testing via `insta`. CLI behaviour driven against the built binary
`mini-x509-lint` (the real `[[bin]]` name; `spec/plan.md`'s `mini-zlint` is outdated). Reuse the
existing `crates/cli/tests/inspect.rs` harness conventions from feature 08.

## Fixtures (`testdata/`)

- **Reuse `testdata/chain_bundle.pem`** — a 2-cert bundle (verified: 2 `BEGIN CERTIFICATE` blocks).
  It exercises both the `Certificate 1 (leaf)` and `Certificate 2` labels. **No new fixture.**
- Reuse `testdata/good.pem` for the single-cert `--info`-unchanged and default-unchanged guards.
- (Only if the review gate asks for a `Certificate 3` label: a new openssl-generated 3-cert bundle,
  tester-owned, never sourced from cert-bar. Default plan does NOT add it.)

## Integration / Snapshot Tests (`crates/cli/tests/inspect.rs`)

1. **`--chain --info` text snapshot (multi-cert).** Run
   `mini-x509-lint --chain --info testdata/chain_bundle.pem`; `insta::assert_snapshot!` the full
   stdout. Assert it contains:
   - a `Certificate 1 (leaf)` label line immediately above a `Certificate Summary` block,
   - a `Certificate 2` label line immediately above a second `Certificate Summary` block,
   - the two summary blocks in chain (file) order,
   - the existing chain lint report below the summaries.
   The snapshot locks the exact layout/whitespace deterministically.

2. **Two summary blocks present (count assertion).** Assert the output contains exactly as many
   `Certificate Summary` headers as certs in the bundle (2 for `chain_bundle.pem`) — proves it is no
   longer leaf-only.

3. **Labels match the chain lint report.** Assert the per-cert summary labels
   (`Certificate 1 (leaf)`, `Certificate 2`) are byte-identical to the labels the chain lint report
   uses (shared-helper contract) — e.g. both appear in the same run's output.

4. **JSON envelope (`--chain --info --format json`).** Run against `chain_bundle.pem`; parse stdout
   and assert the chosen envelope:
   - top-level object with a `certificates` array of length == cert count,
   - each entry has `certificate` (label), `summary` (object), and `outcomes` (array),
   - the `outcomes` array matches the feature-02 per-outcome shape **verbatim** (same keys/nesting as
     the non-`--info` `--chain` JSON for the same input),
   - each `summary` equals the single-cert `build_summary_json` object for that cert.
   Snapshot the `summary` objects (and/or the whole envelope) via `insta`.
   *(If the review gate selects option B, assert the parallel `summaries`/`chain` arrays instead.)*

5. **Single-cert `--info` UNCHANGED.** Run `mini-x509-lint --info testdata/good.pem` (text and
   `--format json`) and assert byte-for-byte identical to the feature-08 baseline (the existing
   `good_info_text` / `good_info_json_summary` snapshots must still match — do NOT regenerate them).

6. **Default UNCHANGED (additive contract).** For both `testdata/good.pem` (single) and
   `testdata/chain_bundle.pem` (`--chain`), assert that WITHOUT `--info`, text AND JSON output are
   byte-for-byte unchanged versus the existing baselines (the golden `chain_bundle_text` snapshot and
   the non-`--info` chain JSON must be untouched).

7. **Exit code unchanged.** For the same `--chain` input, assert the process exit code is identical
   with and without `--info` (and identical to the pre-feature behaviour) — `--info` is additive and
   does not alter `--fail-on` semantics.

8. **Determinism.** Run the `--chain --info` text command twice; assert byte-identical stdout (no
   wall-clock content beyond the certs' own dates).

9. **Graceful degradation (unsummarizable cert in the bundle).** Construct/point at a bundle where
   one entry cannot be fully summarized (e.g. a cert whose accessors degrade), and assert:
   - the run does NOT crash / non-zero-on-panic,
   - the degraded cert's summary block renders `UNAVAILABLE`/`ABSENT` markers (mirroring
     `build_summary`),
   - every OTHER cert's summary block AND the full chain lint report still render.
   If no naturally-degrading multi-cert fixture exists, exercise this at the renderer level (call the
   per-cert summary loop over a bundle including a marker-degrading cert) rather than adding a new PEM
   fixture; document the choice in the test.

## Edge Cases

- A cert in the bundle with NO KeyUsage / NO SAN extension → that block prints the `ABSENT` marker,
  no panic, other blocks unaffected.
- Algorithm unknown to `oid-registry` on a non-leaf cert → raw OID shown in that cert's block (the
  feature-08 degradation path), still per-cert.

## Verification Commands

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Exit Criteria

`--chain --info` text snapshot stable and showing one labelled summary per cert in chain order
followed by the chain lint report; JSON envelope carries a per-cert `summary` with the outcome shape
preserved verbatim; single-cert `--info`, default output (text + JSON, single + chain), and exit code
all confirmed unchanged; graceful degradation verified; all verification commands pass.
