---
agent: tester
seq: 2
title: --chain --info per-cert tests (text snapshot, JSON envelope, invariants)
status: done
touches:
  - crates/cli/tests/inspect.rs
  - crates/cli/tests/snapshots
depends_on:
  - 01-chain-per-cert-summary
---

# Task: `--chain --info` per-cert tests

## Goal

Add tests proving `--chain --info` emits a labelled `Certificate Summary` block per certificate (in
chain order, same labels as the chain lint report) plus the chain lint report; that the
`--chain --info --format json` envelope carries a per-cert `summary`; and that single-cert `--info`,
default output (text + JSON, single + chain), and exit code are all unchanged, with graceful
degradation for an unsummarizable cert.

## Files Owned (conflict scope)

- `crates/cli/tests/inspect.rs` (extend the feature-08 inspect test file)
- `crates/cli/tests/snapshots/` (NEW snapshots for `--chain --info` text + JSON summary)

Disjoint from task 01 (`crates/cli/src/main.rs`). Depends on task 01 (the per-cert path must exist).

## Fixtures

- **Reuse `testdata/chain_bundle.pem`** (2 certs — verified). NO new fixture. Reuse `testdata/good.pem`
  for the single-cert and default-unchanged guards.
- Do NOT regenerate the feature-08 snapshots (`good_info_text`, `slh_dsa_info_text`,
  `good_info_json_summary`) or the golden `chain_bundle_text` snapshot — they must still match
  byte-for-byte (they guard the unchanged single-cert and default paths). If task 01's label
  extraction unexpectedly shifts any of them, you own regenerating, but the expectation is that none
  change.

## Steps (SIFER + Result-assertion conventions; snapshots via `insta`)

1. **`--chain --info` text snapshot.** Run `mini-x509-lint --chain --info testdata/chain_bundle.pem`;
   `insta::assert_snapshot!` the full stdout. Assert presence and order of `Certificate 1 (leaf)` then
   `Certificate 2` label lines, each directly above a `Certificate Summary` block, followed by the
   chain lint report.

2. **One summary per cert (count).** Assert the output contains exactly 2 `Certificate Summary`
   headers for `chain_bundle.pem` — proves it is no longer leaf-only.

3. **Labels match the chain lint report.** Assert the summary labels are byte-identical to the labels
   used in the chain lint report within the same run.

4. **JSON envelope.** Run `--chain --info --format json` over `chain_bundle.pem`; parse stdout and
   assert: top-level object with a `certificates` array of length 2; each entry has `certificate`,
   `summary` (object), `outcomes` (array); each `outcomes` matches the feature-02 per-outcome shape
   verbatim (compare against the non-`--info` `--chain` JSON for the same input); each `summary`
   equals the single-cert `build_summary_json` object for that cert. Snapshot the `summary` objects
   (or the whole envelope) via `insta`. *(If option B was chosen in task 01, assert the parallel
   `summaries`/`chain` arrays instead.)*

5. **Single-cert `--info` unchanged.** Assert `mini-x509-lint --info testdata/good.pem` (text and
   `--format json`) still matches the feature-08 baseline snapshots byte-for-byte.

6. **Default unchanged (additive contract).** For `good.pem` (single) and `chain_bundle.pem`
   (`--chain`), assert WITHOUT `--info` that text AND JSON output are byte-for-byte unchanged versus
   the existing baselines.

7. **Exit code unchanged.** For the `--chain` input, assert the exit code is identical with and
   without `--info`.

8. **Determinism.** Run the `--chain --info` text command twice; assert byte-identical stdout.

9. **Graceful degradation.** Exercise a bundle containing a cert that cannot be fully summarized and
   assert: no panic; the degraded cert's block shows `UNAVAILABLE`/`ABSENT` markers; every other
   cert's summary AND the full chain lint report still render. Prefer the renderer/loop level over
   adding a new PEM fixture; document the approach in the test.

## Acceptance Criteria

- [ ] `--chain --info` text snapshot is stable and shows one labelled summary per cert (chain order)
      then the chain lint report.
- [ ] Exactly one `Certificate Summary` per cert; summary labels match the chain lint report labels.
- [ ] JSON envelope carries a per-cert `summary`; `outcomes` preserved verbatim; `summary` matches
      the single-cert object per cert.
- [ ] Single-cert `--info`, default output (text + JSON, single + chain), and exit code confirmed
      unchanged (feature-08 and golden snapshots untouched).
- [ ] Graceful degradation verified (no panic; markers; other certs + lint report still render).
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 01. Target the real binary name `mini-x509-lint`.
