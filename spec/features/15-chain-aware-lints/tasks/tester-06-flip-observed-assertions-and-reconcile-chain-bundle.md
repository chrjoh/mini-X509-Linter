---
agent: tester
seq: 6
title: Flip the OBSERVED broken-chain assertions to expect the Error + exit 1; reconcile chain_bundle tests/golden; fix flaky from_host validity-nesting
status: done
touches:
  - crates/linter/tests/chain.rs
  - crates/cli/tests/output.rs
  - crates/cli/tests/exit_codes.rs
  - crates/cli/tests/golden.rs
  - crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap
  - crates/cli/tests/from_host.rs
depends_on:
  - developer-05-surface-construction-findings-with-fewer-than-two-links
---

# Task: Flip OBSERVED assertions, reconcile chain_bundle, fix flaky from_host test

This task lands AFTER `developer-05` fixes the engine so a broken chain that
collapses to <2 built links now surfaces its `chain_subject_issuer_dn_match`
Error. Update the tests that currently pin the OLD (buggy) silent-pass behavior,
reconcile the pre-existing `chain_bundle` fixture's tests/golden, and de-flake the
`--from-host` validity-nesting test.

## What to Do

### 1. Flip the engine-level `OBSERVED` assertions (`crates/linter/tests/chain.rs`)

In `mod broken_chain_reporting_gap` (currently ~line 284), the module doc and
these tests assert the bug:

- `run_surfaces_nothing_for_missing_middle_silent_pass` (asserts `reports.is_empty()`
  with the `OBSERVED:` message, ~line 322).
- `dn_mismatch_diagnoses_but_run_is_silent` (asserts `reports.is_empty()`,
  ~line 358).

Flip them to assert the INTENDED behavior:
- `default_chain_registry().run(&load_bundle(CHAIN_MISSING_MIDDLE))` now yields a
  report (non-empty) carrying a `chain_subject_issuer_dn_match` **Error** finding
  (message substring "missing middle link" / "broken chain" / "no issuer").
- Same for `CHAIN_DN_MISMATCH` → a `chain_subject_issuer_dn_match` **Error**
  (message substring "unlinkable" / "does not link" / "no issuer", matching
  whatever `developer-05` emits).
- Keep `build_chain_reports_missing_middle_diagnostic` (it asserts `build_chain`
  itself produces the diagnostic and the collapse to a single position — that
  remains true and is a good regression guard). Update its `chain.links().is_empty()`
  assertion only if `developer-05` changed link construction (it should NOT have —
  the fix is in `run`, not `build_chain`).
- Rename the module from `broken_chain_reporting_gap` to something like
  `broken_chain_reporting` and rewrite the module doc to describe the FIXED
  behavior (remove the "⚠️ THE OBSERVED ENGINE GAP" wording).
- Match the engine's chosen surfacing shape from `developer-05` (synthetic report
  vs construction carrier) — read `crates/linter/src/chain.rs`'s updated `run`
  doc comment first and assert against the actual shape.

### 2. Flip the CLI `OBSERVED` assertions (`crates/cli/tests/output.rs`)

In the chain e2e module (doc ~line 788), flip:
- `chain_dn_mismatch_passes_silently` (~line 926) → rename to e.g.
  `chain_dn_mismatch_surfaces_error_and_fails`: assert the `Chain checks:` section
  renders, contains `error [chain_subject_issuer_dn_match]`, and that
  `--fail-on error` exits non-zero.
- `chain_missing_middle_passes_silently` (~line 954) → rename to e.g.
  `chain_missing_middle_surfaces_error_and_fails`: assert the `Chain checks:`
  section renders the `chain_subject_issuer_dn_match` Error and `--fail-on error`
  exits non-zero.
- Update the module doc (~line 788) to remove the "⚠️ OBSERVED ENGINE GAP"
  paragraph and describe the fixed behavior.
- Match the exact rendered text/label shape `developer-05` chose for link-less
  construction findings (read the updated `output.rs` / run the binary to see the
  real output, then pin it).

### 3. Reconcile the pre-existing `chain_bundle` fixture (the blast radius)

`testdata/chain_bundle.pem` (from spec 06) is **two UNRELATED self-signed certs**
that do not link. Before `developer-05` it collapsed to <2 links and silently
produced no chain section; after the fix it surfaces a `chain_subject_issuer_dn_match`
Error (correct — it is not a single chain). Three places pin the old behavior and
MUST be reconciled:

- `crates/cli/tests/exit_codes.rs`:
  - `chain_bundle_all_pass_exits_zero` (~line 126) asserts exit 0 for
    `--chain chain_bundle.pem` (default `--fail-on error`). It will now exit
    non-zero. **Decide and apply** (architect's guidance: this is the correct new
    behavior): rewrite it to assert a non-zero exit code (and rename, e.g.
    `chain_bundle_unrelated_certs_surface_error`), OR — if you prefer to keep a
    clean all-pass exit-0 regression on a REAL linked chain — repoint it to
    `chain_valid.pem` (a genuinely clean leaf→inter→root chain) and assert exit 0.
    Prefer the latter for the "all pass exits zero" intent, and ADD a separate
    test asserting the unrelated-bundle Error exit. Document the choice in a
    comment.
  - `chain_exit_reflects_only_surfaced_findings` (~line 132) uses
    `chain_bundle.pem` with `--fail-on warn` and asserts exit 0. Same reconciliation:
    repoint to a clean chain for the "no warns" intent, or update the expectation.
- `crates/cli/tests/golden.rs` `chain_bundle_text` (~line 92) + the snapshot
  `crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap`: the
  golden will now gain a `Chain checks:` section with the
  `chain_subject_issuer_dn_match` Error. **Intentionally regenerate** the snapshot
  (e.g. `INSTA_UPDATE=always cargo test -p cli --features fetch chain_bundle_text`
  or `cargo insta accept`) and REVIEW the diff: it must add ONLY the chain section
  (the per-cert blocks above it stay byte-for-byte identical). Confirm no
  single-cert golden changed.
- Check `crates/cli/tests/inspect.rs` (~line 718 references the `chain_bundle_text`
  golden in a comment) — confirm no `--chain --info` assertion on `chain_bundle`
  breaks; update if it does.

If you judge that `chain_bundle.pem` should instead remain a benign two-cert
display fixture and a NEW genuinely-linked fixture should back the golden, that is
acceptable too — but the simplest, spec-consistent path is: unrelated self-signed
certs in a `--chain` bundle correctly surface the structural-integrity Error.
Document whatever you choose.

### 4. De-flake the `--from-host` validity-nesting test (`crates/cli/tests/from_host.rs`)

`leaf_and_intermediate_no_root_fires_issuer_not_in_chain_notice` (~line 376) is
**flaky** and currently FAILS intermittently. `MintedChain::mint()` (~line 102)
issues root, intermediate, and leaf in three sequential `openssl` invocations,
each with `-days 3650` but anchored at successive wall-clock seconds. When the
second ticks over between the intermediate and leaf signings, the leaf's `notAfter`
ends up ~1 second LATER than the intermediate's, so `chain_validity_nested`
correctly fires a **Warn** (subject outlives issuer) — but the test asserts
`!section.contains("warn [")` (~line 412), so it fails.

Fix the FIXTURE timing so the leaf's validity window nests inside the
intermediate's (and the intermediate's inside the root's), deterministically:
- Preferred: pin explicit, nested validity windows on all three certs so the leaf
  ⊆ intermediate ⊆ root regardless of issuance wall-clock. With openssl `x509 -req`
  use `-not_before`/`-not_after` (openssl ≥ 1.1.1 supports these on `x509 -req`;
  if unavailable on the test host, fall back to `-days` chosen so the leaf's window
  is strictly inside the intermediate's — e.g. root `-days 3653`, intermediate
  `-days 3652`, leaf `-days 3650` — giving comfortable nesting margins that absorb
  any per-second drift). Apply the same nesting to the OTHER `mint()`-derived
  servers if they share the issue.
- Keep the windows straddling "now" so the tests stay non-time-fragile (as the
  existing comment at ~line 100 intends).
- Do NOT weaken the assertion to merely tolerate the Warn — the chain links in
  this test are supposed to be sound; the fix is to make the minted chain actually
  nest. Keep the `chain_issuer_not_in_chain` Notice assertion.
- Re-run `cargo test -p cli --features fetch` several times to confirm the test is
  stable (the openssl-dependent tests self-skip when openssl is absent).

### 5. Cross-feature regression

Confirm every existing non-chain test/golden still passes UNCHANGED (the engine
change is confined to the broken-chain surfacing path; the happy-path chain
rendering must be byte-for-byte unchanged). Restore any perturbed tracked fixture
with `git checkout -- 'testdata/*.pem'` (NEVER `git checkout -- testdata/`).

## Acceptance Criteria

- [ ] `crates/linter/tests/chain.rs` broken-chain tests assert the
      `chain_subject_issuer_dn_match` **Error** is surfaced by `run()` for
      missing-middle and DN-mismatch; the `OBSERVED:` wording is gone.
- [ ] `crates/cli/tests/output.rs` asserts the `Chain checks:` section renders the
      Error and `--fail-on error` exits non-zero for both broken bundles; the
      `OBSERVED` wording is gone.
- [ ] The `chain_bundle` exit-code tests and the `chain_bundle_text` golden are
      reconciled with the new behavior (intentionally regenerated; diff reviewed;
      no single-cert golden changed).
- [ ] `leaf_and_intermediate_no_root_fires_issuer_not_in_chain_notice` is
      de-flaked via a properly-nested minted chain and passes reliably across
      repeated runs.
- [ ] All gates green:
      `cargo fmt --check`;
      `cargo clippy --all-targets -- -D warnings`;
      `cargo clippy --all-targets --all-features -- -D warnings`;
      `cargo test`;
      `cargo test -p linter --features verify`;
      `cargo test -p cli --features fetch`;
      `cargo audit`.
- [ ] No `OBSERVED`/gap-pinning assertion remains in the feature-15 test suite.
