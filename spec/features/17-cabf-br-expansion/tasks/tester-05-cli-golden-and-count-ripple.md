---
agent: tester
seq: 5
title: Regenerate CLI golden snapshots + fix count ripple for the 82-lint registry
status: done
touches:
  - crates/cli/tests/snapshots/golden__text_output__good_text.snap
  - crates/cli/tests/snapshots/golden__verbose_output__good_verbose_text.snap
  - crates/cli/tests/snapshots/golden__text_output__cabf_br_validity_400_days_text.snap
  - crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap
  - crates/cli/tests/snapshots/golden__json_output__good_json.snap
  - crates/cli/tests/output.rs
depends_on:
  - tester-04-fixtures-and-cabf-br-tests
---

# Task: CLI golden-snapshot + count ripple from the 82-lint registry

## Goal

developer-03 grew `default_registry()` from 70 → 82 lints (cabf_br 12 → 24). This is a known,
near-additive ripple into the CLI golden tests, which tester-04 left untouched (out of its scope).
Resolve it here. Two behavioural twists vs. a pure-additive ripple:
- **good.pem was regenerated** (by tester-04) with a PINNED key + a `certificatePolicies` DV OID, so
  good.pem now PASSES all 12 new lints — its golden snapshots gain 12 PASS rows and NO Warn. Because
  the key is pinned, good.pem's SKI/serial are byte-stable and the `--info` summary does NOT render
  certificatePolicies, so the `inspect__*` snapshots do NOT change (they are NOT in this task's
  `touches` — see below).
- Every OTHER compliant TLS leaf that lacks CertificatePolicies emits a
  `cabf_br_certificate_policies_present` **`Warn`** (and the no-SAN leaf a `cabf_br_san_present` `Warn`),
  so those snapshots gain those `Warn` rows and the per-source summary tuples shift — still additive,
  no row reordered.

## Background (verify against tester-04's results)

The registration is additive and order-preserving: 12 new `cabf_br_*` rows are appended after the
existing 12 (before cabf_ev) — exact registry order, no existing row reordered. Only good.pem's DER
was regenerated (pinned key → byte-stable SKI/serial). So every snapshot diff is: new `cabf_br_*` rows
+ shifted summary counts. For good.pem the 12 new rows are all PASS (no Warn). For other compliant
leaves, one of the new rows is a `cabf_br_certificate_policies_present` `Warn` (plus
`cabf_br_san_present` `Warn` on the no-SAN leaf).

## Files Owned (conflict scope)

- The golden snapshot files listed in `touches` under `crates/cli/tests/snapshots/`.
  - VERIFY the exact set on disk first (`ls crates/cli/tests/snapshots/`). The `inspect__*` snapshots
    should NOT change: good.pem's key is pinned (stable SKI/serial) and the `--info` summary does not
    render certificatePolicies, so `inspect__good_cert_text__good_info_text.snap` and
    `inspect__json_envelope__good_info_json_summary.snap` are expected to be byte-identical. If an
    `inspect__*` snapshot (or any file not in this front-matter) DOES change when you run insta, that
    means good.pem's key was NOT actually pinned (or another out-of-scope file moved) — FLAG it to the
    architect (it likely means tester-04's pinning failed and the accept-churn fallback is in play,
    needing the README `--info` example + these two inspect snapshots widened into scope) rather than
    silently editing an out-of-scope file.
- `crates/cli/tests/output.rs` — ONLY the stale count assertion(s) (see step 2).

## Steps

1. Regenerate the affected golden snapshots by running the CLI golden test with insta in accept mode,
   e.g. `INSTA_UPDATE=always cargo test -p cli --test golden` (or `cargo insta accept` after a normal
   run). Then **inspect every `.snap` diff** to confirm the change is ONLY:
   - appended new `cabf_br_*` rows in registration order (the 12 new ids), and
   - shifted per-source summary counts. For good.pem the 12 new rows are all PASS (no Warn). For other
     compliant leaves the new `Warn` row(s) (`cabf_br_certificate_policies_present`; on the no-SAN leaf
     also `cabf_br_san_present`) appear,
   with NO existing row reordered, renamed, or dropped and no timestamps. The good.pem snapshots must
   show good.pem completely clean (no Warn from the new lints). Do not hand-edit snapshot bodies; let
   insta write them, then verify. Remove any `.snap.new` artifacts.

2. In `crates/cli/tests/output.rs`, update any stale `[cabf_br] (N passed, …)` count assertion. With
   24 cabf_br lints the per-fixture tuple shifts; recompute the exact `(passed, not-applicable,
   warned, failed)` for each asserted fixture by reasoning (or by running) and update the expected
   string(s), preserving each test's intent. Two cases:
   - **good.pem**: it carries certificatePolicies now, so all 12 new lints PASS — good.pem stays
     all-passed/no-warn (its cabf_br tuple is `(24 passed, …)`, NO warned). A "no findings" test on
     good.pem stays a no-findings test.
   - **Other compliant leaves** (no certificatePolicies): `cabf_br_certificate_policies_present` adds a
     `Warn`, so a test that asserted "all passed" on such a leaf becomes "N passed, 1 warned" (the
     no-SAN leaf: 2 warned). Keep the intent that there are no Errors.
   Do NOT weaken any test's intent.

3. Do NOT touch any other file. Do NOT regenerate fixtures or any `src/`.

## Acceptance Criteria

- [ ] All affected golden snapshots regenerated; diffs confirmed additive in registration order (12
      new cabf_br rows + shifted counts; good.pem clean/no-Warn, other compliant leaves +`Warn`(s)); no
      existing row reordered/dropped.
- [ ] `inspect__*` snapshots unchanged (pinned key → stable good.pem SKI/serial; `--info` does not show
      certificatePolicies). If they changed, FLAGGED to the architect (pinning likely failed).
- [ ] `output.rs` count assertion(s) updated to the correct recomputed tuples; good.pem stays
      no-Warn/all-passed; each test's intent preserved.
- [ ] If a snapshot outside the front-matter changes, it was FLAGGED to the architect, not silently
      edited.
- [ ] `cargo test` (full workspace) green — 0 failures.
- [ ] `cargo test -p linter --features serde`, `cargo clippy --all-targets -- -D warnings`,
      `cargo fmt --check` all pass.

## Notes / Dependencies

- Depends on tester-04 (new fixtures + regenerated good.pem + lints fully wired; the 82-lint registry
  exists). Pure test-artifact reconciliation; no production code, no fixtures.
- All 12 lints are kept (no cuts); the cabf_br row count is exactly 24. If tester-04 reports the
  pinned-key fallback was forced, the two `inspect__*` snapshots + README `--info` example need scope
  widening — FLAG the architect before editing them.
</content>
