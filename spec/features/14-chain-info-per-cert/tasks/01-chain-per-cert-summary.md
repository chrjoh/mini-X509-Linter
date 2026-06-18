---
agent: developer
seq: 1
title: Per-cert summary under --chain --info (text + JSON)
status: done
touches:
  - crates/cli/src/main.rs
depends_on: []
---

# Task: Per-cert summary under `--chain --info` (text + JSON)

## Goal

Make `--chain --info` emit a labelled `Certificate Summary` block for EVERY certificate in the
bundle (chain/file order, using the SAME labels as the chain lint report), then the chain lint report
— instead of today's single leaf summary. Also emit a per-cert `summary` in the
`--chain --info --format json` envelope. Reuse feature 08's `inspect.rs` renderer verbatim; add NO
new facade accessor and NO new summary field.

## Files Owned (conflict scope)

- `crates/cli/src/main.rs`

Keep `inspect.rs` UNTOUCHED: place the shared chain-label helper in `main.rs` (see step 1) so this
task does not overlap any `inspect.rs`-touching work. (If you decide the helper belongs in
`inspect.rs`, add it to `touches` and flag it at the review gate — the default is `main.rs`-only.)

## Background (verified)

- `run_chain` (main.rs:476-547) lints every cert into
  `per_cert: Vec<(String /*label*/, Vec<LintOutcome>)>`, computing the label inline:
  `"Certificate 1 (leaf)"` for idx 0, else `format!("Certificate {}", idx + 1)` (main.rs:494-498).
- Text branch currently does `let leaf = &certs[0];` then, when `info`,
  `format!("{summary}\n{report}", summary = inspect::render_summary_text(leaf))` (main.rs:514-520).
- JSON branch calls `render_chain_info_json(leaf, &per_cert, min)` which wraps the chain in
  `{ "summary": <leaf summary>, "lints": <chain array> }` (main.rs:583-597).
- `inspect.rs` already exposes `render_summary_text(&Cert) -> String` (block begins with a
  `Certificate Summary` header line) and `build_summary_json(&Cert) -> serde_json::Value`; both
  degrade gracefully (every accessor `Err` → `UNAVAILABLE`, absent extension → `ABSENT`/`None`,
  inspect.rs:228-280) and never panic.
- `render_chain_json` (main.rs:556-573) emits the per-cert array
  `[ { "certificate": <label>, "outcomes": [...] }, … ]` with the feature-02 outcome shape.

## Steps

1. **Shared label helper.** Add a small free function in `main.rs`, e.g.
   `fn chain_label(idx: usize) -> String` returning `"Certificate 1 (leaf)"` for idx 0 and
   `format!("Certificate {}", idx + 1)` otherwise. Replace the inline label expression in
   `run_chain`'s lint loop (main.rs:494-498) with a call to it, so the chain lint report's labels are
   unchanged byte-for-byte and the summary loop uses the SAME source of truth.

2. **Text branch — per-cert summaries.** When `info` is set, build a summary section by iterating
   `certs.iter().enumerate()`: for each cert emit `chain_label(idx)` on its own line, then
   `inspect::render_summary_text(cert)`, separating blocks by a blank line. Join that section, a
   blank-line separator, and the existing `output::render_text_chain(...)` report. Layout target
   (snapshot-locked by the tester; finalize exact whitespace here):

   ```
   Certificate 1 (leaf)
   Certificate Summary
     Version:             v3
     ... (existing render_summary_text fields) ...

   Certificate 2
   Certificate Summary
     ...

   <existing chain lint report>
   ```

   Remove the now-unused single-leaf summary path; do NOT change `render_text_chain` or
   `render_summary_text`. The non-`info` text branch stays exactly as today.

3. **JSON branch — per-cert summary (chosen envelope, option A).** Replace `render_chain_info_json`
   with a builder that emits:

   ```json
   {
     "certificates": [
       { "certificate": "<label>", "summary": { ... }, "outcomes": [ ... ] },
       ...
     ]
   }
   ```

   For each `(idx, cert)` with its `per_cert` entry: set `certificate` to `chain_label(idx)` (== the
   `per_cert` label), `summary` to `inspect::build_summary_json(cert)`, and `outcomes` to the
   existing per-cert outcome shape (reuse `output::render_json(outcomes, min)` then re-parse, exactly
   as `render_chain_json` does — preserve the feature-02 outcome shape verbatim; do NOT reshape it).
   Wrap the array in a top-level object under the `certificates` key. The non-`info` `--chain` JSON
   path (`render_chain_json`, bare array) stays unchanged.

   *(If the review gate selects option B — parallel `summaries`/`chain` arrays — implement that shape
   instead; only this builder changes. Default is option A.)*

4. **Graceful degradation.** The per-cert loops MUST NOT introduce any `unwrap`/`expect`/`?` that
   could abort on a single bad cert — `render_summary_text`/`build_summary_json` already return a
   marker-filled result for an unsummarizable cert, so every cert (and the full lint report) still
   renders. Preserve that.

5. **Invariants.** Single-cert `--info` path (`render_info_json`, `render_summary_text(leaf)` in the
   non-chain branch) is UNCHANGED. Default (no `--info`) text and JSON output are byte-for-byte
   unchanged in both single and `--chain` modes. `--info` does NOT change the exit code and does NOT
   suppress linting (exit-code computation in `run_chain` is untouched).

6. **Docs.** Update the doc comments on `run_chain` and the chain-info JSON builder to describe the
   per-cert summary and the chosen envelope.

## Acceptance Criteria

- [ ] `--chain --info` (text) prints one labelled `Certificate Summary` block per cert in chain
      order, using the SAME labels as the chain lint report, then the chain lint report below.
- [ ] The chain label is produced by a single shared helper used by BOTH the lint loop and the
      summary loop; the chain lint report's labels are unchanged byte-for-byte.
- [ ] `--chain --info --format json` emits
      `{ "certificates": [ { certificate, summary, outcomes }, … ] }`; `outcomes` matches the
      feature-02 shape verbatim and `summary` equals `build_summary_json` per cert.
- [ ] An unsummarizable cert in the bundle degrades to marker text/JSON; other certs' summaries and
      the full lint report still render; no panic.
- [ ] Single-cert `--info` (text + JSON) is unchanged; default (no `--info`) text + JSON output is
      byte-for-byte unchanged in single and `--chain` modes; exit code unchanged.
- [ ] `inspect.rs` is not modified (helper lives in `main.rs`); no new facade accessor.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- No dependency on other tasks. Target the real binary name `mini-x509-lint`.
- Do not regenerate any feature-08 snapshot; the tester (task 02) owns snapshots.
