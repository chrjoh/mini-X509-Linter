---
agent: developer
seq: 5
title: Surface chain construction findings even when the built chain collapses to <2 links (broken-chain silent-pass bug)
status: done
touches:
  - crates/linter/src/chain.rs
  - crates/cli/src/main.rs
  - crates/cli/src/output.rs
depends_on: []
---

# Task: Fix the broken-chain silent-pass bug

## Background (the bug)

`ChainRegistry::run` (`crates/linter/src/chain.rs`, currently ~line 468) returns
an **empty `Vec<ChainLinkReport>`** whenever the built chain has fewer than two
links:

```rust
let (chain, diagnostics) = build_chain(certs);
let links = chain.links();
if links.is_empty() {
    return Vec::new();          // <-- BUG: drops all construction diagnostics
}
let construction = construction_outcomes(&diagnostics, certs);
// ... construction outcomes are only ever attached to a *link* (leaf/top) ...
```

Construction-driven findings (`chain_subject_issuer_dn_match`,
`chain_not_in_order`, `chain_issuer_not_in_chain`) are only attached to a built
**leaf link** or **top link**. When a genuinely broken set collapses to a single
built position there are **no links**, so `run` returns early and every
construction diagnostic — including the intended `chain_subject_issuer_dn_match`
**Error** for `MissingMiddleLink` / `Unlinkable` / `Cycle` — is silently dropped.

Reproduced end-to-end (the chain section never prints, exit 0 even with
`--fail-on error`):

```
mini-x509-lint --chain testdata/chain_missing_middle.pem --fail-on error   # exits 0, no "Chain checks:"
mini-x509-lint --chain testdata/chain_dn_mismatch.pem    --fail-on error   # exits 0, no "Chain checks:"
```

This also affects the pre-existing `testdata/chain_bundle.pem` (two UNRELATED
self-signed certs that do not link) — it collapses to a single position with an
`Unlinkable` diagnostic that is currently dropped. Once this fix lands, that
bundle WILL surface a `chain_subject_issuer_dn_match` Error. That is the
*correct* behavior (two unrelated self-signed certs presented as a `--chain`
bundle do not form a single chain), and the test/golden reconciliation is the
tester's job in `tester-06` (do NOT touch those tests here).

## What to Do

### 1. Engine: surface construction findings with <2 links (`crates/linter/src/chain.rs`)

Make `ChainRegistry::run` emit the construction-driven findings even when
`chain.links()` is empty (but `certs.len() >= 2`, the existing guard at the top
of `run` stays). Keep the existing behavior for `certs.len() < 2` (return empty —
a lone leaf or empty slice produces no chain output).

Recommended shape (developer finalizes exact representation, keep it
deterministic and snapshot-stable):

- Keep the early `if certs.len() < 2 { return Vec::new(); }` guard.
- After `build_chain`, compute `construction_outcomes(&diagnostics, certs)` as
  today.
- When `links` is **non-empty**, behave exactly as today (leaf-link gets the
  `construction.leaf` outcomes, top-link gets `construction.top`, pairwise lints
  run per link). No change to the happy path or to any existing passing
  snapshot/test for a well-formed chain.
- When `links` **is empty** (a collapsed/broken set with ≥2 input certs), still
  return at least one `ChainLinkReport` carrying the construction outcomes so the
  `chain_subject_issuer_dn_match` Error (and any `chain_not_in_order` /
  `chain_issuer_not_in_chain` Notice) is surfaced and folds into the exit code.
  Because there is no real `(subject, issuer)` link, choose a **deterministic,
  documented** home for these findings. Two acceptable options — pick one and
  document it in the `run` doc comment:
  - **(A) A synthetic chain-level report.** Emit a single `ChainLinkReport` whose
    `subject_index` / `issuer_index` denote "the chain as a whole" (e.g. both set
    to the leaf/`order[0]` index, or a documented sentinel). Carry
    `construction.leaf` + `construction.top` outcomes (which already include the
    `chain_subject_issuer_dn_match` Error). The CLI must render this as a
    chain-level block, NOT as a misleading `Certificate N → Certificate M` link
    (see step 2).
  - **(B) A dedicated construction-level carrier.** If you prefer not to overload
    `ChainLinkReport`, add a small chain-level construction findings vector to the
    engine's return (e.g. change the return to a struct
    `{ links: Vec<ChainLinkReport>, construction: Vec<ChainLinkOutcome> }`, or add
    a separate accessor). This is a larger API change and ripples into the CLI and
    the tester's assertions — only choose it if (A) cannot be made clean. If you
    take this route, keep the existing `Vec<ChainLinkReport>` callers compiling or
    update `crates/cli/src/main.rs` accordingly.
- Whichever option: ensure the result is **deterministic** (stable across runs —
  there is a `running_twice_on_shuffled_input_is_identical`-style determinism
  expectation) and that **construction outcomes are never emitted twice** (don't
  attach them to both a synthetic report AND a real link in any code path).
- Do NOT change `build_chain` itself — its diagnostics are already correct (this
  is confirmed by `crates/linter/tests/chain.rs::broken_chain_reporting_gap`,
  which the tester will repurpose). The fix is purely in how `run` surfaces them.

Update the `ChainRegistry::run` doc comment to describe the <2-links case and the
chosen home for construction findings.

### 2. CLI: render the link-less construction findings (`crates/cli/src/main.rs`, `crates/cli/src/output.rs`)

Today `run_chain` (and `run_from_host`) gate the whole chain section on
`!link_reports.is_empty()` (`crates/cli/src/main.rs` ~line 591:
`let has_chain_section = run_chain_pass && !link_reports.is_empty();`), and the
exit-code fold (~lines 669-674) is gated the same way. After the engine change,
`link_reports` will be non-empty for a broken bundle, so:

- The `Chain checks:` section MUST render for a broken bundle, showing the
  `chain_subject_issuer_dn_match` Error (and any construction Notice).
- The chain findings MUST fold into the `--fail-on` exit code via
  `chain_severity_counts` exactly as for a normal link — verify this happens
  automatically once `link_reports` is non-empty; adjust if your chosen engine
  shape (option B) requires it.
- If you took option (A) with a synthetic report, make the CLI render it as a
  **chain-level** block rather than a bogus `Certificate N → Certificate M` link
  label. In `output::render_chain_section` (and `chain_links_json`), detect the
  synthetic/whole-chain entry (by the documented sentinel) and render its findings
  under the `Chain checks:` header without a misleading link arrow. Keep the
  output deterministic and snapshot-friendly; the tester snapshot-locks the exact
  text in `tester-06`. Coordinate the exact rendering shape so the tester can pin
  it — prefer something like:

  ```text
  Chain checks:
    error [chain_subject_issuer_dn_match] certificate 1 (CN=…) links to no issuer in the presented set (missing middle link / broken chain)
  ```

- **JSON:** the link-less construction findings need a deterministic home in the
  `chain` JSON too. Per the plan's recommendation, surface them so they are not
  lost — either as an entry in the existing flat `chain` array tagged as a
  whole-chain entry, or via the plan's suggested `chain.diagnostics` shape. Keep
  the existing per-link JSON shape for the happy path byte-for-byte unchanged; the
  tester pins the broken-bundle JSON shape.

### 3. Do NOT touch tests/fixtures/goldens

Leave ALL of these to `tester-06` (they are NOT in this task's `touches`):
- `crates/linter/tests/chain.rs` (the `broken_chain_reporting_gap` module and its
  `OBSERVED:` assertions),
- `crates/cli/tests/output.rs` (`chain_dn_mismatch_passes_silently`,
  `chain_missing_middle_passes_silently`),
- `crates/cli/tests/exit_codes.rs` (`chain_bundle_all_pass_exits_zero`,
  `chain_exit_reflects_only_surfaced_findings`),
- `crates/cli/tests/golden.rs` + the `chain_bundle_text` snapshot,
- `testdata/*.pem`, `testdata/generate.sh`.

Your in-FILE `#[cfg(test)] mod tests` inside `crates/linter/src/chain.rs` MAY be
updated to cover the new <2-links surfacing (that file is in your `touches`); do
add an in-file unit test asserting `run()` on a 2-cert unlinkable/missing-middle
set now yields a report carrying the `chain_subject_issuer_dn_match` Error.

## Acceptance Criteria

- [ ] `ChainRegistry::run` returns construction findings for a ≥2-cert set that
      builds to <2 links (no longer returns an empty `Vec` in that case); the
      `< 2` certs guard still returns empty.
- [ ] `chain_subject_issuer_dn_match` **Error** is surfaced for
      `chain_missing_middle.pem`, `chain_dn_mismatch.pem`, and any
      `Unlinkable`/`Cycle` collapsed set; the relevant construction Notices are
      surfaced where applicable.
- [ ] Construction outcomes are emitted exactly once (never duplicated across a
      synthetic report and a real link).
- [ ] The result is deterministic across repeated runs.
- [ ] `mini-x509-lint --chain testdata/chain_missing_middle.pem --fail-on error`
      and `... chain_dn_mismatch.pem --fail-on error` now PRINT a `Chain checks:`
      section AND exit non-zero.
- [ ] The CLI renders the link-less construction findings under `Chain checks:`
      without a misleading `Certificate N → Certificate M` link label; the JSON
      gives them a deterministic, documented home.
- [ ] The happy-path chain rendering (valid/shuffled chains) and its JSON are
      byte-for-byte unchanged.
- [ ] In-file `chain.rs` unit test added covering the <2-links surfacing.
- [ ] `cargo fmt --check` clean.
- [ ] `cargo clippy --all-targets -- -D warnings` and
      `cargo clippy --all-targets --all-features -- -D warnings` clean.
- [ ] `cargo build -p linter` (default, no `verify`) still pulls in NO crypto
      deps.
- [ ] NOTE: workspace `cargo test` will have RED tests after this change (the
      `OBSERVED:` assertions and the `chain_bundle` exit/golden tests still pin the
      OLD behavior). That is expected and is reconciled by `tester-06`. Do NOT
      edit those tests here.
