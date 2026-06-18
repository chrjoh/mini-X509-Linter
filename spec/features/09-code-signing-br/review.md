# Phase 5 — Mandatory Completeness Review: Feature 09 (Code-Signing BR)

**Reviewer:** architect (orchestration gate)
**Date:** 2026-06-18
**Verdict:** **COMPLETE** — all requirements, touches, and acceptance criteria PASS; all quality gates green; GAP-1 confirmed closed. No open gaps.

---

## 1. Quality Gate Results

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --check` | **PASS** (exit 0, no diff) |
| Lint | `cargo clippy --all-targets -- -D warnings` | **PASS** (exit 0, `Finished` clean) |
| Tests (workspace) | `cargo test` | **PASS** (exit 0; all suites green) |
| Tests (serde) | `cargo test -p linter --features serde` | **PASS** (exit 0; lib 280 passed, cabf_cs 14, cabf_br 48, hygiene 11, not_expired 8, registry 10, rfc5280 39) |

### Per-suite test counts (cargo test)

- linter lib unit tests: 280 passed (includes registry 40-lint count + `cabf_cs` filter + CodeSigning purpose + auto-precedence tests, and per-lint `#[cfg(test)]` modules)
- `tests/cabf_cs.rs`: **14 passed** (new integration suite)
- `tests/cabf_br.rs`: 48, `tests/hygiene.rs`: 11, `tests/not_expired.rs`: 8, `tests/rfc5280.rs`: 39, `tests/registry.rs`: 10 — all unchanged, all green (no-cascade proven)
- CLI: `tests/output.rs` 15, `tests/golden.rs` 8, `tests/purpose.rs` 15, `tests/exit_codes.rs` 12, `main.rs` unit 39 — all green

---

## 2. Per-Requirement Verification (plan.md)

| Requirement | Status | Evidence |
|---|---|---|
| 8 `cabf_cs_*` lint files, one per lint | **PASS** | `crates/linter/src/lints/cabf_cs/` contains eku_required, key_usage_required, rsa_key_size, ecdsa_curve_params, validity_period_longer_than_39_months, validity_period_longer_than_460_days, authority_information_access, crl_distribution_points (+ mod.rs) |
| `RuleSource::CabfCs` (wire `cabf_cs`, after CabfBr) | **PASS** | `source.rs:23` `CabfCs`; type-doc `source.rs:13` lists `cabf_cs`; serde snake_case verified by serde test pass |
| `CertPurpose::CodeSigning` + `code_signing_sources()` `[Rfc5280, Hygiene, CabfCs]` | **PASS** | `registry.rs:142` variant; `registry.rs:175-177` helper; mapping asserted `registry.rs:1012` |
| `auto` precedence: codeSigning→CS first, else serverAuth→TLS, else Generic, Err→Generic (fail-closed) | **PASS** | `auto_purpose_from` `registry.rs:196-207` (codeSigning checked first, `Err`/false falls through to Generic); unit tests `registry.rs:980-1054` incl. both-EKU and Err-fail-closed cases |
| CLI `--source cabf_cs` wiring + `ALL_SOURCES` | **PASS** | `main.rs:184` parse arm; `main.rs:169-172` `ALL_SOURCES` includes `CabfCs`; error string `main.rs:187` lists `cabf_cs` |
| CLI `--purpose code-signing` + `From` + `purpose_label` | **PASS** | `main.rs:107` `CliPurpose::CodeSigning`; `main.rs:118` From arm; `main.rs:241` label `"code-signing"`; doc strings `main.rs:13,26,31,138` updated |
| `SOURCE_ORDER` placement (after CabfBr) + `source_label` | **PASS** | `output.rs:22-27` = `[Rfc5280, CabfBr, CabfCs, Hygiene]`; `source_label` `output.rs:157` → `"cabf_cs"` (matches `ALL_SOURCES` order) |
| Register 8 lints after cabf_br block, deterministic order | **PASS** | `registry.rs:371-378` boxes all 8 in plan-table order |
| Count test 32→40 | **PASS** | `registry.rs:712-713` `registry.len()==40` and `outcomes.len()==40` |
| `cabf_cs` source-filter test (8 outcomes, all CabfCs) | **PASS** | `registry.rs:874-901` `cabf_cs_source_filter_runs_exactly_the_cabf_cs_set` |
| No-cascade (all 8 NotApplicable on existing fixtures; existing suites unedited) | **PASS** | rfc5280/hygiene/cabf_br/not_expired/registry suites pass with no edits; `cabf_cs.rs` no-cascade test green; `git status` shows no existing `.pem` modified |
| `generate.sh` CS recipe (GAP-1) | **PASS** | see §4 |
| README/docs | **N/A → PASS** | plan.md does not require a README change; CLI in-source doc strings updated (`main.rs:13,26,31`); doc count refs corrected (no stale 22/32 in source) |

### Per-lint detail (severity + facade)

| Lint | Severity (impl) | Plan | Status |
|---|---|---|---|
| eku_required | Error (`eku_required.rs:51`) | Error | PASS |
| key_usage_required | Error (`key_usage_required.rs:36`) | Error | PASS |
| rsa_key_size (<3072) | Error (`rsa_key_size.rs:37`) | Error | PASS |
| ecdsa_curve_params | Error (`ecdsa_curve_params.rs:64,73`) | Error | PASS |
| validity_..._39_months (>1188d) | Error (`...39_months.rs:47`) | Error | PASS |
| validity_..._460_days | Warn (`...460_days.rs:41`) | Warn | PASS |
| authority_information_access | Warn (`authority_information_access.rs:38`) | Warn | PASS |
| crl_distribution_points | Warn (`crl_distribution_points.rs:38`) | Warn | PASS |

`eku_required` fail-closed `check()` confirmed: `Ok(false)`→Error, `Err(_)`→empty (`eku_required.rs:72-78`), with direct-call test `eku_required.rs:122-130` and `applies()==NotApplicable` test `eku_required.rs:113-120`.

---

## 3. Per-Task `touches` + Acceptance Criteria

### developer-01 (cert.rs accessors) — **PASS**
- `has_code_signing()` `cert.rs:633`; `has_authority_info_access()` `cert.rs:837`; `has_crl_distribution_points()` `cert.rs:865` — all `Result<bool, CertError>`.
- `KeyUsageView.digital_signature` `cert.rs:94`, populated `cert.rs:440`.
- `EkuView.code_signing` (optional, chosen) `cert.rs:138`, populated `cert.rs:580`.
- Negative unit tests `cert.rs:1575-1610` (good.pem reports false for codeSigning/AIA/CRL-DP).
- clippy clean (gate §1).

### developer-02 (source.rs + 8 lints + lints/mod.rs) — **PASS**
- All 9 `touches` files present (8 lint files + mod.rs; `source.rs`, `lints/mod.rs:8`).
- `RuleSource::CabfCs` added; 8 lints implemented, each codeSigning-gated via `applies_to_code_signing` (shared in `cabf_cs/mod.rs`); ids `cabf_cs_*`; severities per table.
- NotApplicable/Applies behavior asserted in `cabf_cs.rs` scoping tests; clippy clean.

### developer-03 (registry.rs + cli/main.rs + cli/output.rs) — **PASS**
- All 3 `touches` modified; all acceptance criteria mapped above (count 40, filter test, purpose+auto tests, CLI tokens, SOURCE_ORDER/labels); existing filter-count tests unchanged.

### tester-04 (fixtures + cabf_cs.rs + cli/output.rs) — **PASS**
- 8 new `cabf_cs_*.pem` present (untracked, to be committed in final commit); no existing fixture modified (`git status`).
- `crates/linter/tests/cabf_cs.rs` (14 tests) covers per-lint flag/pass, direct-call eku_required, scoping, no-cascade, 40-month co-fire + 500-day isolation, time-fragility module doc.
- CLI e2e ADDED in `output.rs:422-567` (`code_signing_output` mod: verbose purpose header, `[cabf_cs]` group, `--source cabf_cs` text + JSON 8-outcome proof); existing assertions unchanged.
- **Note (non-blocking):** `crates/cli/tests/golden.rs` was also regenerated (now references `cabf_cs`, 8 golden tests pass) per the plan's Feature-06 Ripple Flag. This file was not in tester-04's declared `touches` list — a minor process deviation, not a functional gap; the regeneration is correct and the snapshot is green. Recorded for traceability only.

### tester-05 (generate.sh CS recipe restoration — GAP-1 fix) — **PASS** — see §4.

---

## 4. GAP-1 Re-Verification (generate.sh code-signing recipe)

**CLOSED.** `testdata/generate.sh` contains a complete code-signing section:
- Time-fragility header note `generate.sh:13` and section note `generate.sh:739-749` (CS fixtures expire ~2027-06-01; regenerate annually).
- CS leaf-extension config: `extendedKeyUsage=codeSigning` `generate.sh:781`; CS_OK window `CS_OK_NB=20260601000000Z` / `CS_OK_NA=20270601000000Z` `generate.sh:810-811`.
- All 8 fixtures regenerated: `cabf_cs_good` `:826`, `cabf_cs_missing_key_usage` `:833`, `cabf_cs_rsa_2048` `:839`, `cabf_cs_ecdsa_bad_curve` (explicit EC params) `:847`, `cabf_cs_validity_40_months` `:854`, `cabf_cs_validity_500_days` `:860`, `cabf_cs_no_aia` `:867`, `cabf_cs_no_crl` `:875`.

`git status` shows only `testdata/generate.sh` modified among tracked testdata; no committed `.pem` byte-changed (tester-05 acceptance criterion met).

---

## 5. Spec Artifact Presence

| Artifact | Present |
|---|---|
| `plan.md` | YES |
| `test-plan.md` | YES |
| `tasks/developer-01..03`, `tester-04`, `tester-05` | YES (5 files, all `status: done`) |
| `design.md` | N/A — non-UI library/CLI feature |
| `ui-test-report.md` | N/A — no UI |
| `review.md` | this file |

---

## 6. Verdict

**COMPLETE.** Every plan.md requirement, every task `touches` entry, and every acceptance criterion is implemented and verified against the real code; all four quality gates are green; the no-cascade property holds (existing suites pass unedited, no existing fixture changed); GAP-1 is confirmed closed. The only observation is a non-blocking traceability note that `cli/tests/golden.rs` was regenerated outside tester-04's declared `touches` (correct per the Ripple Flag, snapshot green). **No follow-up task files created.** Feature 09 is DONE pending the feature's final commit of the 8 untracked fixtures + new source/test files.
