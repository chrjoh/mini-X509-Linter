# Feature: Per-Certificate Inspection Under `--chain --info`

## Overview

Make `--chain --info` print a labelled certificate **SUMMARY block for EVERY certificate** in the
bundle, not just the leaf. Today `--info` (feature 08) always summarizes only `certs[0]` (the leaf,
by leaf-first PEM convention), even when combined with `--chain`: `run_chain` lints every cert but
renders a single leaf summary (`crates/cli/src/main.rs:504-505`, `let leaf = &certs[0]`). This
feature iterates the bundle and emits one summary per cert — each preceded by the SAME label the
chain lint report already uses (`Certificate 1 (leaf)`, `Certificate 2`, …) — in chain (file) order,
followed by the chain lint report exactly as it renders today.

**This is a small post-milestone UX enhancement, not an engine change.** It adds no `Lint`, touches
no `Registry`, and changes no `Lint`/`Finding`/`LintOutcome` contract. It does NOT add a new `Cert`
facade accessor — feature 08's inspection accessors (`subject_rfc4514`, `issuer_rfc4514`,
`serial_hex`, `signature_algorithm`, `public_key_info`, `key_usage_bits`, `san_entries`) and the
`inspect.rs` renderer (`render_summary_text`, `build_summary`, `build_summary_json`) already exist
and are reused verbatim. The work is purely in the CLI's chain path: loop instead of single-leaf.

### Motivation

Under `--chain`, the user already sees lint findings labelled per certificate, but the `--info`
summary only describes the leaf. To inspect an intermediate's or root's own fields (DN, key usage,
validity, signature algorithm) the user currently has to split the bundle and re-run. Emitting a
labelled summary per cert closes that gap with no new parsing surface.

## Requirements

- **`--chain --info` (text).** Print a SUMMARY block per certificate, each preceded by the SAME
  label the chain lint report uses (`Certificate 1 (leaf)`, `Certificate 2`, `Certificate 3`, …), in
  chain (file) order, then the chain lint report below — exactly as the chain lint report already
  renders. Deterministic, snapshot-friendly, no wall-clock content (cert's own dates only). The
  existing single-leaf `Certificate Summary` block produced by `render_summary_text` is reused
  per-cert; the per-cert chain label is prepended above each block.

- **`--info` WITHOUT `--chain`: UNCHANGED.** The single-cert path still renders one leaf
  `Certificate Summary` block; its output and snapshots are not touched.

- **Default output (no `--info`): byte-for-byte UNCHANGED** for both text and JSON, in both
  single-cert and `--chain` modes. `--info` still does not suppress linting and does not change the
  exit code (which remains driven by `--fail-on` over every cert's surfaced findings, as today).

- **JSON (`--chain --info --format json`).** Emit a **per-cert** summary. The chosen envelope folds
  each cert's `summary` into its existing chain entry alongside its `outcomes` (see *Architecture →
  JSON envelope* and *Open Decisions*). The single-cert `--info --format json` envelope
  `{ "summary": …, "lints": … }` stays unchanged.

- **Unparseable / unsummarizable cert in the bundle.** A cert whose fields cannot be read must
  degrade gracefully (a clear marker) and never crash the run. This is already how
  `build_summary`/`render_summary_text` behave: every accessor `Err` maps to an `UNAVAILABLE` marker
  and absent extensions to an `ABSENT` marker (`crates/cli/src/inspect.rs:228-280`). Per-cert
  iteration must preserve that behaviour for every cert, not just the leaf — no `unwrap`, no
  short-circuit that would drop later certs' summaries.

## Architecture

### Text path (`run_chain`, `crates/cli/src/main.rs`)

`run_chain` already builds `per_cert: Vec<(String /*label*/, Vec<LintOutcome>)>` by iterating
`certs.iter().enumerate()` and computing the label inline (`Certificate 1 (leaf)` for idx 0, else
`Certificate {idx+1}`). The label and the `Cert` are both already in hand during that loop.

- **Extract the label into a shared helper** so the lint loop and the new summary loop produce
  identical labels from a single source of truth — a small free function, e.g.
  `fn chain_label(idx: usize) -> String` in `main.rs` (or a tiny `inspect::chain_label`). The
  existing inline label expression is replaced by a call to it; the chain lint report's labels are
  thus unchanged byte-for-byte.
- **When `info` is set**, build the per-cert summary section by zipping `certs` with their labels:
  for each `(label, cert)` emit `<label>` then `inspect::render_summary_text(cert)`, joined
  deterministically, then a blank-line separator, then the existing chain lint report
  (`output::render_text_chain(...)`). This replaces the current single
  `format!("{summary}\n{report}", summary = inspect::render_summary_text(leaf))` (main.rs:514-520).
- **Layout (see *Per-cert text layout* below).** Each summary block is the existing
  `render_summary_text` output (which begins with its own `Certificate Summary` header line),
  prefixed by the chain label line so the reader can tell which cert it describes.
- The exit-code computation, the lint-report rendering, and the `--info`-is-additive contract are
  untouched.

#### Per-cert text layout (proposed; finalized in the developer task / review gate)

```
Certificate 1 (leaf)
Certificate Summary
  Version:             v3
  Serial:              ...
  ... (existing render_summary_text fields) ...
  Subject Alt Name:    ...

Certificate 2
Certificate Summary
  Version:             v3
  ...
  Subject Alt Name:    ...

<the existing chain lint report, exactly as today>
```

The chain label line sits directly above each existing `Certificate Summary` block; blocks are
separated by a blank line; one blank line separates the last summary block from the chain lint
report. Field order within each block is unchanged (it is whatever `render_summary_text` already
produces). This layout is snapshot-only (no semantic dependency), so the exact separator/whitespace
is the developer's call within the deterministic, snapshot-friendly constraint and is locked by the
tester's snapshot.

### JSON path (`render_chain_info_json`, `crates/cli/src/main.rs`)

Today `render_chain_info_json` (main.rs:583-597) wraps the whole chain in
`{ "summary": <leaf summary>, "lints": <chain array> }` — a single leaf summary. This is replaced by
a per-cert envelope.

**Chosen envelope — fold `summary` into each existing chain entry (RECOMMENDED option A):**

```json
{
  "certificates": [
    {
      "certificate": "Certificate 1 (leaf)",
      "summary":  { ... },
      "outcomes": [ ... ]
    },
    {
      "certificate": "Certificate 2",
      "summary":  { ... },
      "outcomes": [ ... ]
    }
  ]
}
```

Rationale for option A:
- It preserves the existing feature-02 per-outcome shape **verbatim**: each entry keeps its
  `certificate` label and `outcomes` array exactly as `render_chain_json` already emits them
  (main.rs:567-570); we only add a sibling `summary` key. No outcome shape is reshaped.
- It is the least surprising: `--chain --info` is "`--chain` plus a summary per cert", so a summary
  living next to each cert's outcomes mirrors the text layout (label → summary → that cert's lints).
- The `summary` value is exactly `inspect::build_summary_json(cert)` per cert — the same object the
  single-cert path emits — so the two surfaces stay in lockstep.

A top-level object key (`certificates`) wraps the array (rather than a bare array) so the shape is
self-describing and leaves room for future chain-level fields (e.g. a verification verdict) without
another breaking change. (The non-`--info` `--chain` JSON remains the bare array from
`render_chain_json` — unchanged.)

**Alternative — parallel arrays (option B, documented, not chosen):**

```json
{
  "summaries": [ { "certificate": "Certificate 1 (leaf)", "summary": { ... } }, ... ],
  "chain":     [ { "certificate": "Certificate 1 (leaf)", "outcomes": [ ... ] }, ... ]
}
```

Option B keeps `render_chain_json`'s output untouched under a `chain` key and adds a parallel
`summaries` array. It is also non-destructive to the outcome shape, but it duplicates the
`certificate` label across two arrays and forces consumers to join by index/label, which is more
surprising than the co-located option A. Recorded here for the review gate; if the reviewer prefers
B, only the developer JSON-builder task changes.

### Graceful degradation

`build_summary`/`render_summary_text`/`build_summary_json` already never panic or error: each
accessor `Err` becomes an `UNAVAILABLE` marker and each absent extension becomes `ABSENT`/`None`
(`crates/cli/src/inspect.rs:228-280`). Per-cert iteration calls these for every cert, so a cert that
cannot be summarized yields a marker-filled block (text) or a marker-filled object (JSON) while the
other certs' summaries and the full lint report still render. No new degradation code is needed;
the requirement is to NOT introduce any `unwrap`/`?` that would abort the loop.

## Changes Overview

**crates/cli/** *(developer task 01)*
- `src/main.rs` —
  - Extract the per-cert chain label into a shared helper (`chain_label(idx)`), replacing the inline
    label expression in `run_chain`'s lint loop so labels stay a single source of truth.
  - In `run_chain` text branch: when `info`, emit a labelled `render_summary_text` block per cert (in
    chain order) before the chain lint report, instead of the single leaf summary.
  - Replace `render_chain_info_json` with a per-cert builder emitting the chosen envelope
    (`{ "certificates": [ { certificate, summary, outcomes }, … ] }`), reusing
    `inspect::build_summary_json(cert)` per cert and the existing per-outcome shape verbatim.
  - Update the relevant doc comments (`run_chain`, the chain-info JSON builder).
- `src/inspect.rs` — *(only if the shared label helper is placed here)* add a tiny
  `pub fn chain_label(idx: usize) -> String` so both `main.rs` loops share it. Keep touches minimal:
  if the helper lives in `main.rs`, `inspect.rs` is **not** modified at all and the developer task
  drops it from `touches`. No change to any summary renderer, `CertSummary`, or facade accessor.

**Tests** *(tester task 02)*
- `crates/cli/tests/inspect.rs` — add `--chain --info` text snapshot (multi-cert bundle), the per-cert
  JSON envelope test, the single-cert `--info`-unchanged guard, the default-unchanged guard
  (text + JSON, single + chain), the exit-code-unchanged guard, and the graceful-degradation case.
- `crates/cli/tests/snapshots/` — new snapshot(s) for `--chain --info` text and the JSON `summary`
  objects. NO existing inspect snapshot is regenerated, because the current `--chain --info` path is
  not snapshot-tested today (verified: only `good_info_text`, `slh_dsa_info_text`,
  `good_info_json_summary` exist; the golden `chain_bundle_text` is the non-`--info` chain report and
  must stay byte-for-byte unchanged). If, contrary to this, the developer's label extraction shifts
  any existing snapshot, the **tester** owns regenerating it.

## Dependencies

- **None new.** `inspect.rs` (feature 08), `oid-registry`, `serde`/`serde_json`, and `insta` are all
  already wired. No new facade accessor, no new crate.

## Out of Scope (documented)

- **No new `Cert` facade accessor** — feature 08 already provides every accessor the summary needs.
- **No change to single-cert `--info`** behaviour or its snapshots.
- **No change to any non-`--info` output** (text or JSON), single-cert or chain.
- **No new lint, no `Registry`/engine change, no exit-code change.**
- **No new fixture** is required — the tester reuses `testdata/chain_bundle.pem` (2 certs). A 3-cert
  fixture is explicitly avoided unless the review gate decides a third cert is needed to exercise the
  `Certificate 3` label; if so it becomes a tester-owned, openssl-generated fixture (never cert-bar).

## Open Decisions (for the review gate)

1. **JSON envelope shape.** Recommending **option A** (co-located `summary` inside each chain entry,
   wrapped in a top-level `certificates` object). Alternative **option B** (parallel
   `summaries`/`chain` arrays) is documented above. Decision affects only the developer JSON-builder.
2. **Shared-label helper placement.** Recommending a free `chain_label(idx)` in `main.rs` (keeps
   `inspect.rs` untouched, minimizes `touches`). Putting it in `inspect.rs` is the alternative if the
   reviewer prefers the label logic to live next to the renderer.
3. **2-cert vs 3-cert fixture.** Recommending reuse of `chain_bundle.pem` (2 certs) — it already
   exercises both the `(leaf)` and a non-leaf label. A 3-cert fixture is only warranted if the
   reviewer wants the bare `Certificate 3` (non-leaf, non-second) label covered explicitly.
