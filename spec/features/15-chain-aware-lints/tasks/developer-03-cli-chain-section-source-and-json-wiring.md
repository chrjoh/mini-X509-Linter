---
agent: developer
seq: 3
title: CLI enable verify by default + --source chain + chain-section text/JSON wiring over --chain AND --from-host; output SOURCE_ORDER/source_label
status: done
touches:
  - crates/cli/Cargo.toml
  - crates/cli/src/main.rs
  - crates/cli/src/output.rs
depends_on:
  - developer-02-chainlint-trait-registry-source-and-lints
---

# Task: CLI chain-section + --source chain + JSON envelope wiring

## Goal

Surface the chain pass in the CLI over BOTH input shapes that present a real chain:
(1) a `--chain` file bundle, and (2) the `--from-host` presented chain (Refinement 2). Run
`default_chain_registry().run(certs)` when there are ≥2 presented certs AND the `chain` source is
selected; render a dedicated chain-level section (text) after the per-cert reports — for `--from-host`,
after the verdict — and a sibling `chain` array (JSON). Single-cert input, a single-leaf `--from-host`,
and any run with `chain` deselected MUST be byte-for-byte UNCHANGED. Add `chain` to the `--source`
vocabulary and the source ordering. The chain pass builds the chain (order-independent) and may emit the
`chain_not_in_order` / `chain_issuer_not_in_chain` Notices — the CLI renders them via the same helper.

## Files Owned (conflict scope)

- `crates/cli/Cargo.toml`
- `crates/cli/src/main.rs`
- `crates/cli/src/output.rs`

Does NOT touch the linter `src/` or `crates/linter/Cargo.toml` (tasks 01/02) or any test/fixture
(task 04). Note: the chain registry lives in `linter::chain` (`default_chain_registry`), so
`registry.rs` is NOT touched by this feature.

## What to Do

### 0. `crates/cli/Cargo.toml` — enable the linter's `verify` feature by default

Change the linter dependency to enable `verify` alongside `serde`, so `mini-x509-lint --chain` verifies
signatures out of the box (mirrors the existing `serde` enablement):

```toml
linter = { path = "../linter", features = ["serde", "verify"] }
```

No new CLI feature flag is added (verification is on for the binary by default; `--from-host` stays
its own opt-in `fetch` feature, unchanged). A CLI `--no-verify` toggle is an Open Decision, NOT specced
for v1.

### 1. `crates/cli/src/output.rs`

- `SOURCE_ORDER`: append `RuleSource::Chain` (LAST position, matching the enum). Bump the array length.
- `source_label`: add `RuleSource::Chain => "chain"`.
- Add a `render_chain_section(...)` text helper that renders the chain-level block from the
  `Vec<ChainLinkReport>`: a header (e.g. `Chain checks:`), then per link a label line
  `Certificate N (leaf) → Certificate N+1` (built from `subject_index`/`issuer_index` via the CLI's
  `chain_label`, passed in or mirrored), then each surfaced chain finding (respecting `--min-severity`),
  with a documented placeholder for links with no surfaced findings. Mirror `render_text_chain`'s
  style; keep it deterministic and snapshot-friendly. (Alternatively build the label in `main.rs` and
  pass labelled reports in — developer's call; keep rendering in `output.rs` to match existing
  structure.)
- Add a chain-outcomes JSON helper (or reuse the per-outcome serialization) producing each link's
  `{ subject, issuer, outcomes: [ { lint_id, source: "chain", findings } ] }` shape.

### 2. `crates/cli/src/main.rs`

- `parse_source_token`: add `"chain" => Ok(RuleSource::Chain)`; update the error-message source list to
  include `chain`.
- `ALL_SOURCES`: append `RuleSource::Chain` (LAST, consistent with `SOURCE_ORDER`). Bump the length.
- Update the `--source` doc strings (module header + the `Args` field doc) to include `chain` and note
  that it only takes effect under `--chain` with ≥2 certs.
- In `run_chain`:
  - After computing the per-cert reports exactly as today, decide whether to run the chain pass:
    `let run_chain_pass = certs.len() >= 2 && selected.contains(&RuleSource::Chain);` (the chain source
    is purpose-independent — do NOT route it through `effective_sources`, which gates the per-cert
    pass). When true, `let link_reports = linter::default_chain_registry().run(certs);`.
  - **Text:** render the existing per-cert chain report unchanged; when `run_chain_pass`, append
    `output::render_chain_section(...)` (labels from `chain_label`). When not, append nothing (output
    byte-for-byte unchanged).
  - **JSON:** when `run_chain_pass`, emit the `{ "certificates": [...], "chain": [...] }` envelope —
    `certificates` is the EXISTING per-cert array verbatim (reuse `render_chain_json`'s entry shape),
    `chain` is the link array. When NOT (single cert, or chain deselected), emit the existing bare array
    / existing `--info` envelope UNCHANGED.
  - For `--chain --info` JSON (feature 14's `render_chain_info_json`): add a sibling `chain` key
    alongside the existing `certificates` envelope when `run_chain_pass` — keep feature 14's per-cert
    `summary`/`outcomes` shape intact. (This is the intentional, called-out feature-14 reconciliation in
    the Ripple Flag; note it.)
  - **Exit code:** chain findings feed `--fail-on` exactly like per-cert findings. Fold each link's
    findings into the worst-severity computation (mirror the existing per-cert `severity_counts` /
    `exit_code` loop). A chain Error with `--fail-on error` must return the findings exit code.
- Update `run_chain` / the JSON-builder doc comments.

### 2b. `crates/cli/src/main.rs` — `run_from_host` (Refinement 2; `#[cfg(feature = "fetch")]`)

Extend `run_from_host` to run the chain pass over the PRESENTED chain (leaf + intermediates), additive
to the existing leaf lint + `presented_chain` display + `verification:` verdict:

- After the existing leaf lint + verdict, build a `Vec<Cert>` from the presented certs: parse
  `chain.leaf_der` (already done as `leaf`) + each `chain.intermediates_der`. Intermediates that FAIL to
  parse are dropped from the chain `Vec<Cert>` (they still appear in the display `presented_chain` via
  `build_chain_entries`, unchanged) — degrade, never panic.
- `let run_chain_pass = presented.len() >= 2 && selected.contains(&RuleSource::Chain);` When true,
  `let link_reports = default_chain_registry().run(&presented);`.
- **Text:** keep the leaf report, `render_chain_section_text` presented-chain block, and the verdict
  EXACTLY as today; when `run_chain_pass`, append `output::render_chain_section(...)` AFTER the verdict.
  When not (single-leaf, or chain deselected), append nothing — output byte-for-byte unchanged.
- **JSON:** when `run_chain_pass`, add a sibling `"chain"` key to the existing document
  (`{ presented_chain, verification, outcomes }`, plus `summary` under `--info`) — do NOT alter the
  existing keys. When not, the document is unchanged (no `chain` key).
- **Exit code:** fold the chain findings into the existing `severity_counts`/`exit_code` so `--fail-on`
  covers chain findings on the `--from-host` path too.
- The missing-root case is handled inside the chain pass (the top intermediate gets the
  `chain_issuer_not_in_chain` Notice) — no special CLI logic; just render what `run` returns. Update
  `run_from_host`'s doc comment to note the additive chain pass and the trust-vs-lint separation (the
  `verification:` verdict establishes trust to a root; the chain lints verify only the present links).
- Reuse `chain_label` / `output::render_chain_section` — the SAME helpers as the `--chain` path.

### 3. Guard the unchanged paths

- Single-cert `run` (the non-chain entry point) is UNCHANGED — it never builds a chain pass.
- A `--chain` run where `chain` is NOT in `selected` (e.g. `--source rfc5280`) produces NO chain
  section / NO `chain` JSON key — byte-for-byte the same as before this feature for those flag
  combinations.
- A single-leaf `--from-host` run (no intermediates presented) produces NO chain section / NO `chain`
  JSON key — the leaf report + verdict are byte-for-byte unchanged. A `--from-host` run with `chain`
  deselected likewise emits no chain section.

## Acceptance Criteria

- [ ] `crates/cli/Cargo.toml` enables the linter's `verify` feature by default
      (`features = ["serde", "verify"]`), so `mini-x509-lint --chain` / `--from-host` includes
      `chain_signature_valid`.
- [ ] CLI accepts `--source chain`; `source_label` renders `chain`; `ALL_SOURCES` and `SOURCE_ORDER`
      include `Chain` LAST and agree on position; lengths bumped.
- [ ] Chain pass runs when there are ≥2 presented certs + `chain` selected, via `--chain` (file) AND
      `--from-host` (presented chain); otherwise output is byte-for-byte unchanged (text + JSON:
      single-cert file, single-leaf `--from-host`, and chain-deselected).
- [ ] `--from-host` chain section renders AFTER the verdict; the leaf report / `presented_chain` /
      `verification:` bytes above are unchanged; the missing-root top cert shows the
      `chain_issuer_not_in_chain` Notice (not an Error); intermediates that fail to parse are dropped
      from the chain vec but still listed in the display.
- [ ] Text: chain section renders after the per-cert report (links labelled in BUILT order),
      `--min-severity` respected; construction Notices render at their documented home.
- [ ] JSON: `{ "certificates": [...], "chain": [...] }` envelope (file path) / a sibling `chain` key
      added to the `--from-host` document; existing keys verbatim; chain outcomes are
      `{ lint_id, source, findings }`.
- [ ] Chain findings feed the `--fail-on` exit code on BOTH paths.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde` and
      `--features "serde fetch"`); `cargo fmt --check`.

## Notes / Dependencies

- Depends on task 02 (the chain trait/registry/`build_chain`/source + the `verify` feature). Blocks test
  task 04.
- Because the CLI now builds the linter WITH `verify`, the chain section / chain JSON includes
  `chain_signature_valid` (8 chain lints). The `--chain` golden(s) will change (chain section added /
  JSON envelope, including the sig lint + any construction Notices) — that regeneration is OWNED BY THE
  TESTER in task 04, NOT here. Do not edit snapshots in this task.
- The `--from-host` chain wiring lives behind `#[cfg(feature = "fetch")]`; ensure both
  `--features serde` (no fetch) and `--features "serde fetch"` build/clippy clean.
