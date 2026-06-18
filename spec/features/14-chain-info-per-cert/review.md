# Completeness Review — Feature 14: Per-Certificate Inspection Under `--chain --info`

**Phase 5 (Mandatory Completeness Review)**
**Reviewer:** architect
**Date:** 2026-06-18
**Verdict:** **COMPLETE** ✅

Prior phases: integration review = GO; final verification = READY. This audit independently
re-verifies every requirement, every `touches` file, and every acceptance criterion against the real
code and test outputs, and re-runs all gates.

---

## 1. Requirements (plan.md) — PASS/PARTIAL/FAIL

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| R1 | `--chain --info` (text) prints a labelled `Certificate Summary` block per cert in chain order, using the SAME labels as the chain lint report, then the chain lint report | **PASS** | `main.rs:528-539` loops `certs.iter().enumerate()`, prepends `chain_label(idx)` + `\n` + `inspect::render_summary_text(cert)` per cert, then the existing `report`. Snapshot `inspect__chain_info__chain_bundle_info_text.snap` lines 5-31 show `Certificate 1 (leaf)`/`Certificate 2` each above a `Certificate Summary` block, then the chain report (lines 33-54). Test `chain_info::chain_info_text_snapshot` (inspect.rs:400). |
| R2 | `--info` WITHOUT `--chain`: UNCHANGED single leaf `Certificate Summary`; output/snapshots not touched | **PASS** | Single-cert branch `main.rs:416-441` is unmodified (`format!("{summary}\n{lint_report}", summary = inspect::render_summary_text(leaf))`). Feature-08 snapshots `good_info_text`, `good_info_json_summary`, `slh_dsa_info_text` show no git diff; tests `good_cert_text::*`, `json_envelope::*` (31-test inspect suite) all pass. Guard test `chain_info::single_cert_info_is_unchanged_by_this_feature` (inspect.rs:684). |
| R3 | Default output (no `--info`): byte-for-byte UNCHANGED (text + JSON, single + chain); `--info` does not suppress linting nor change exit code | **PASS** | Non-info text/JSON branches unchanged (`main.rs:426-428, 435-439, 547`). Golden `golden__text_output__chain_bundle_text.snap` shows **no git diff**. Guards: `default_unchanged::*`, `chain_info::chain_without_info_emits_no_summary_block` (inspect.rs:716). Lint report still rendered when info set (`report` built first at `main.rs:527` then prefixed). |
| R4 | JSON `--chain --info --format json` emits per-cert summary folded into each chain entry (option A) | **PASS** | `render_chain_info_json` (`main.rs:610-631`) emits `{ "certificates": [ { certificate, summary, outcomes }, … ] }`. Snapshot `inspect__chain_info__chain_bundle_info_json_summaries.snap`. Tests `json_envelope_has_certificates_array_with_summary_and_outcomes` (inspect.rs:511), `json_summaries_snapshot` (659). Single-cert `{summary, lints}` envelope (`render_info_json`, `main.rs:460-473`) untouched. |
| R5 | Unparseable / unsummarizable cert degrades gracefully (markers), never crashes; per-cert iteration preserves this for every cert | **PASS** | Loops use no `unwrap`/`expect`/`?` over cert fields; rely on `inspect::render_summary_text`/`build_summary_json` marker behaviour (reused verbatim). Test `chain_info::absent_extensions_render_per_cert_markers_without_dropping_certs` (inspect.rs:776): both `(not present)` ABSENT markers render in one run and the full chain lint report still follows (inspect.rs:814). |

---

## 2. Task `touches` files — coverage

| Task | `touches` entry | Status | Evidence |
|------|-----------------|--------|----------|
| 01 (impl) | `crates/cli/src/main.rs` | **PASS** | Only production file changed (`git status`: ` M crates/cli/src/main.rs`). Contains `chain_label`, per-cert text loop, `render_chain_info_json` per-cert envelope. |
| 01 (impl) | `crates/cli/src/inspect.rs` — must stay UNTOUCHED (helper in main.rs) | **PASS** | `inspect.rs` is untracked from feature 08 and shows **no diff**; helper lives in `main.rs:481-487`. No new facade accessor (`crates/linter/src/cert.rs` diff is pre-existing feature-08 work, not this feature). |
| 02 (tests) | `crates/cli/tests/inspect.rs` | **PASS** | `chain_info` module (inspect.rs:385-816) adds the new tests; suite = 31 passed. |
| 02 (tests) | `crates/cli/tests/snapshots` | **PASS** | 2 new snapshots present (`chain_bundle_info_text.snap`, `chain_bundle_info_json_summaries.snap`, both 17:09). No existing snapshot regenerated. |

---

## 3. Task 01 Acceptance Criteria

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 01-A | `--chain --info` text: one labelled summary per cert in chain order, same labels, then chain report | **PASS** | `main.rs:528-539`; text snapshot lines 5-54. |
| 01-B | Chain label from a single shared helper used by BOTH loops; chain report labels unchanged byte-for-byte | **PASS** | `chain_label` (`main.rs:481-487`) called in lint loop (`main.rs:515`), text summary loop (`main.rs:533`), and JSON via `per_cert` label. Golden chain snapshot unchanged → labels byte-identical. Test `each_label_sits_directly_above_its_summary_block` (inspect.rs:425). |
| 01-C | JSON `{ certificates: [{certificate, summary, outcomes}] }`; outcomes verbatim feature-02; summary == `build_summary_json` per cert | **PASS** | `render_chain_info_json` reuses `output::render_json` then re-parses (`main.rs:619-625`), identical mechanism to `render_chain_json`. Test `json_outcomes_match_non_info_chain_verbatim` (inspect.rs:563) asserts `env_entry["outcomes"] == bare_entry["outcomes"]`; `json_per_cert_summary_matches_single_cert_summary_shape` (619). |
| 01-D | Unsummarizable cert degrades to markers; others + lint report still render; no panic | **PASS** | See R5; test inspect.rs:776. |
| 01-E | Single-cert `--info` (text+JSON) unchanged; default text+JSON byte-for-byte unchanged single + chain; exit code unchanged | **PASS** | See R2/R3; exit-code logic `main.rs:553-565` untouched. Tests `info_does_not_change_the_chain_exit_code` (inspect.rs:746), `default_unchanged::*`. |
| 01-F | `inspect.rs` not modified; no new facade accessor | **PASS** | See §2; helper in `main.rs`. |
| 01-G | `cargo test`, clippy `-D warnings`, `fmt --check` pass | **PASS** | See §5 gates. |

---

## 4. Task 02 Acceptance Criteria

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 02-A | `--chain --info` text snapshot stable; one labelled summary per cert (chain order) then chain report | **PASS** | `chain_info_text_snapshot` (inspect.rs:400) + snapshot file. |
| 02-B | Exactly one `Certificate Summary` per cert; labels match chain report | **PASS** | `one_summary_block_per_certificate` (inspect.rs:413), `each_label_sits_directly_above_its_summary_block` (425), `both_subject_dns_appear_in_their_summaries` (453). |
| 02-C | JSON envelope carries per-cert `summary`; outcomes verbatim; summary matches single-cert object per cert | **PASS** | inspect.rs:511, 563, 619, 659. |
| 02-D | Single-cert `--info`, default (text+JSON, single+chain), exit code unchanged (feature-08 + golden snapshots untouched) | **PASS** | `single_cert_info_is_unchanged_by_this_feature` (684), `chain_without_info_emits_no_summary_block` (716), `info_does_not_change_the_chain_exit_code` (746); golden + feature-08 snapshots no diff. |
| 02-E | Graceful degradation verified (no panic; markers; other certs + lint report render) | **PASS** | inspect.rs:776-814. |
| 02-F | `cargo test`, clippy `-D warnings`, `fmt --check` pass | **PASS** | See §5. |

Determinism additionally locked: `chain_info_text_is_byte_identical_across_runs` (inspect.rs:764).

---

## 5. Gate Results

| Gate | Result |
|------|--------|
| `cargo fmt --check` | **PASS** (exit 0) |
| `cargo clippy --all-targets -- -D warnings` | **PASS** (exit 0) |
| `cargo clippy --all-targets --features fetch -- -D warnings` | **PASS** (exit 0) |
| `cargo test` (full workspace) | **PASS** — cli unit 52, exit_codes 12, golden 8, **inspect 31**, output 20, purpose 15, save 0; fetch 29 + handshake 6 + validation 14; linter 482 + rule suites (cabf_br 48, cabf_cs 14, cabf_ev 26, cabf_smime 17, hygiene 11, not_expired 8, pqc 12, registry 39, rfc5280 39, registry-mod 11) + main 39; all 0 failed |
| `cargo test -p cli --features fetch` | **PASS** — 66 + 12 + 8 + **31** + 20 + 15 + 8; 0 failed |

---

## 6. Targeted Confirmations

- **Option-A JSON with verbatim feature-02 outcomes** — CONFIRMED. `render_chain_info_json`
  (`main.rs:610-631`) re-parses `output::render_json` output (same path as `render_chain_json`);
  test `json_outcomes_match_non_info_chain_verbatim` asserts equality against the bare `--chain` JSON.
- **Shared `chain_label` used by both loops** — CONFIRMED. Single definition `main.rs:481-487`;
  call sites `main.rs:515` (lint), `main.rs:533` (text summary); JSON reuses the `per_cert` label
  which itself comes from `chain_label`.
- **4 invariants** — CONFIRMED: single `--info` unchanged (R2), default unchanged (R3), `--chain`
  without `--info` unchanged (R3 / inspect.rs:716), exit code unchanged (`main.rs:553-565`,
  inspect.rs:746).
- **Golden `chain_bundle_text` unchanged** — CONFIRMED (no git diff on the tracked golden snapshot).
- **2 new snapshots meaningful + deterministic** — CONFIRMED. Both contain only the certs' own dates
  (`Jun 1 2026`, `Jan 1 2026`, etc.), no wall-clock content; layout fully captured.
- **Production change confined to `main.rs`; `inspect.rs` untouched** — CONFIRMED (git status: only
  `crates/cli/src/main.rs` modified for this feature; `inspect.rs` no diff).

---

## 7. Spec Artifacts

| Artifact | Status |
|----------|--------|
| `spec/features/14-chain-info-per-cert/plan.md` | Present ✅ |
| `spec/features/14-chain-info-per-cert/test-plan.md` | Present ✅ |
| `spec/features/14-chain-info-per-cert/tasks/01-chain-per-cert-summary.md` (status: done) | Present ✅ |
| `spec/features/14-chain-info-per-cert/tasks/02-chain-info-tests.md` (status: done) | Present ✅ |
| `design.md` | N/A — CLI feature, no UI |
| `ui-test-report.md` | N/A — CLI feature, no UI |

---

## 8. Verdict

**COMPLETE.** Every requirement, every `touches` file, and every acceptance criterion across both
task files maps to PASS with concrete code/test evidence. All five gates are green. No gaps; no
follow-up task required.
