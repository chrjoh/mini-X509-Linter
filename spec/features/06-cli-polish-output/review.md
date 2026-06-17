# Phase 5 Completeness Review — Feature 06: CLI Polish & Output

**Reviewer:** architect
**Date:** 2026-06-17
**Verdict: COMPLETE**

Scope: final completeness gate for `spec/features/06-cli-polish-output/`. Every
requirement in `plan.md`, every file in every task's `touches` list, and every
acceptance criterion across tasks 01–05 was verified against the real code and
test artifacts, and all quality gates were run.

---

## 1. Quality Gate Results

| Gate | Result | Notes |
|------|--------|-------|
| `cargo fmt --check` | **PASS** (exit 0) | No formatting drift. |
| `cargo clippy --all-targets -- -D warnings` | **PASS** (exit 0) | Clean. |
| `cargo clippy --all-targets --features serde -- -D warnings` | **PASS** (exit 0) | `serde` is a real linter-crate feature (`crates/linter/Cargo.toml:20-23`). |
| `cargo test` | **PASS** (exit 0) | See per-suite counts below. |
| `cargo test -p linter --features serde` | **PASS** (exit 0) | 136 + 18 + 11 + 8 + 10 + 16 = 199 tests, 0 failed. |

(No TUI in this feature.)

### `cargo test` per-suite counts (default features)

| Suite | Passed |
|-------|--------|
| `cli` unit (`src/main.rs`) | 39 |
| `cli` `tests/exit_codes.rs` | 12 |
| `cli` `tests/golden.rs` | 8 |
| `cli` `tests/output.rs` (feature 02 e2e, still green) | 12 |
| `cli` `tests/purpose.rs` | 15 |
| `linter` unit (`src/lib.rs`) | 136 |
| `linter` `tests/cabf_br.rs` | 18 |
| `linter` `tests/hygiene.rs` | 11 |
| `linter` `tests/not_expired.rs` | 8 |
| `linter` `tests/registry.rs` | 10 |
| `linter` `tests/rfc5280.rs` | 16 |
| doc-tests | 0 |
| **Total** | **285 passed, 0 failed, 0 ignored** |

---

## 2. Requirement → Evidence Map

| Requirement (plan.md) | Status | Evidence |
|-----------------------|--------|----------|
| `--fail-on <level>` drives exit code (default `error`, at/above level) | **PASS** | `crates/cli/src/main.rs:144-145` (flag, default `Error`), `exit_code()` `main.rs:406-418`, computed from filtered outcomes `main.rs:313-314`. Tests: `exit_codes.rs::fail_on::*` (good=0, error→1, fatal-threshold→0, warn→1). |
| Polished `--format text`: grouped by `RuleSource` + per-severity summary line; NotApplicable summarized not noisy | **PASS** | `output.rs::render_group_block` (fixed `SOURCE_ORDER` `output.rs:22-23`), `SeverityCounts::summary_line` `output.rs:101-120`, collapsed `(N passed, M not applicable)` `output.rs:315-317`. Unit tests `output.rs::render_text::*`, `severity_counts::*`. |
| `--chain` flag — parse/lint each cert, defined multi-cert grouping | **PASS** | `main.rs:148-149` flag, `run_chain` `main.rs:320-374` (per-cert labels "Certificate 1 (leaf)" / "Certificate N"), `render_text_chain` `output.rs:398-428`. Snapshot `golden__text_output__chain_bundle_text.snap` shows two labelled blocks. Tests: `exit_codes.rs::chain::*`, `golden.rs::chain_bundle_text`. |
| `--verbose`/`-v` — opt-in per-lint listing (status token + lint_id), default collapsed unchanged, deterministic, JSON unaffected | **PASS** | `main.rs:153-154` (`short = 'v'`), threaded as `Verbosity::PerLint` `main.rs:273-277`; `render_group_per_lint` `output.rs:325-361` (sorted by `lint_id`, `pass`/`n/a` tokens). Snapshot `golden__verbose_output__good_verbose_text.snap`. Tests: `golden.rs::verbose_is_deterministic_across_runs`, `default_mode_keeps_collapsed_summary`, `json_unaffected_by_verbose`. |
| `--purpose <auto\|tls-server\|generic>` source scoping (default auto) | **PASS** | CLI enum `CliPurpose` `main.rs:96-107`, `From<CliPurpose> for CertPurpose` `main.rs:109-117`, resolver `registry.rs::CertPurpose::allowed_sources` `registry.rs:200-206`. |
| Purpose mapping: tls-server→Rfc5280+Hygiene+CabfBr; generic→Rfc5280+Hygiene; auto per-cert via serverAuth | **PASS** | `tls_server_sources()` `registry.rs:148-150`, `generic_sources()` `registry.rs:158-160`, `auto_sources_from()` `registry.rs:172-177`. Unit tests `registry.rs::cert_purpose::*`. |
| auto fail-closed on `has_server_auth()` `Err` → generic (no manufactured BR false positive) | **PASS** | `auto_sources_from` `registry.rs:175` (`Ok(false) \| Err(_) => generic`). Test `registry.rs::auto_fails_closed_to_generic_on_error`. |
| Composition with `--source` = intersection (incl. empty intersection allowed) | **PASS** | `effective_sources()` `main.rs:210-220`. Unit tests `main.rs::effective_sources::*` (intersection, empty intersection). E2E `purpose.rs::source_intersection::*`. |
| auto resolved per cert, before filtering; chain resolves per cert | **PASS** | `run_chain` resolves `effective_sources(purpose, cert, ...)` per cert `main.rs:341`. Chain snapshot: Certificate 2 (CA, no serverAuth) has no `[cabf_br]` group. |
| Purpose-skipped sources NOT run and NOT synthesized as NotApplicable | **PASS** | Skipped sources simply absent from `run_filtered` input; no synthesis path exists. Tests `purpose.rs::generic_skips_br::generic_omits_cabf_br_group`, `generic_skips_br_in_json`. |
| Exit code is post-filter (purpose + min-severity) | **PASS** | `severity_counts` over filtered outcomes drives `exit_code` `main.rs:313-314`, `364-368`. Test `purpose.rs::auto_resolution::auto_skips_br_exit_code_is_zero`. |
| Verbose-only `purpose:` header (resolved + `(auto)`); non-verbose omits it | **PASS** | `PurposeHeader`/`push_purpose_header` `output.rs:55-72,172-177`, built in `build_purpose_header` `main.rs:236-245`. Tests `purpose.rs::verbose_purpose_header::*`, snapshot first line `purpose: tls-server (auto)`. |
| Input handling: auto-detect PEM vs DER; PEM may hold multiple certs | **PASS** | `load_certs` → `Cert::load` `main.rs:426-437`. Multi-cert exercised by `chain_bundle.pem`. |
| Future `client`/`smime`/`code-signing` reserved (documented, not implemented; additive) | **PASS** | Doc comments `registry.rs:117-123`, `main.rs:90-95`; not added as variants. |
| README documenting CLI surface, exit-code semantics, examples | **PASS** | `README.md` (12.4 KB): flag table `README.md:62-68`, exit codes `README.md:89-94`, `--purpose` model `README.md:106-140`, examples incl. `--verbose` `README.md:239+`, chain `README.md:294+`. |
| Golden/deterministic snapshot test over `testdata/` | **PASS** | `crates/cli/tests/golden.rs` + 5 committed `.snap` files; `insta = { version = "1", features = ["json"] }` `crates/cli/Cargo.toml:23`. |
| No new production deps; `insta` dev-dep only | **PASS** | `insta` is `[dev-dependencies]` only; no production dep added. |

---

## 3. Task-by-Task Acceptance Criteria

### Task 01 — Polished text formatter (`crates/cli/src/output.rs`)
| Criterion | Status | Evidence |
|-----------|--------|----------|
| Deterministic text (sorted, no timestamps) | PASS | `SOURCE_ORDER` `output.rs:22`, per-lint sort `output.rs:333`. `golden.rs::verbose_is_deterministic_across_runs`. |
| Summary line correct per-severity counts | PASS | `severity_counts`/`summary_line` + tests `output.rs:595-666`. |
| NotApplicable summarized not line-by-line | PASS | `render_group_summary` count `output.rs:315-317`; test `counts_not_applicable_compactly`. |
| Multi-cert/chain rendering labelled + grouped | PASS | `render_text_chain` + `CertReport` `output.rs:371-428`; chain snapshot. |
| Verbose lists every lint (token + id), sorted; failing lines unchanged | PASS | `render_group_per_lint` `output.rs:325-361`; tests `verbose_lists_every_lint_sorted`, `verbose_keeps_failing_finding_lines`. |
| Verbose omits collapsed summary; default byte-for-byte unchanged | PASS | `render_text` back-compat path `output.rs:206-208`; test `summary_mode_group_body_matches_render_text`. |
| Verbose `purpose:` header; default omits it; no NA synthesis | PASS | tests `purpose_header_only_in_verbose`, `explicit_purpose_omits_auto_marker`. |
| clippy clean | PASS | Gate 2. |

### Task 02 — flags + exit codes + wiring (`crates/cli/src/main.rs`)
| Criterion | Status | Evidence |
|-----------|--------|----------|
| `--fail-on error` non-zero on Error/Fatal, 0 otherwise | PASS | `exit_code` + `exit_codes.rs::fail_on::*`. |
| `--fail-on` respects `--min-severity` | PASS | `exit_codes.rs::min_severity_interaction::*`. |
| `--chain` lints leaf + renders others as context | PASS | `run_chain` + chain snapshot/tests. |
| PEM bundle multi-cert; DER auto-detected | PASS | `load_certs`/`Cert::load`; `chain_bundle.pem`. |
| Exit code from existing outcomes (no re-run) | PASS | `severity_counts` over already-run `outcomes` `main.rs:313`. |
| `--verbose`/`-v` switches text only; no JSON/exit-code change | PASS | `json_unaffected_by_verbose`; verbose not fed into `exit_code`. |
| `--purpose` tls-server runs BR / generic skips / auto per-cert | PASS | `purpose.rs::{tls_server_runs_br,generic_skips_br,auto_resolution}`. |
| Effective set = purpose ∩ `--source`; empty intersection not an error | PASS | `effective_sources` tests + `purpose.rs::source_intersection::*`. |
| Skipped sources not run / no NA synthesis; exit reflects post-filter | PASS | `generic_skips_br_in_json`; `auto_skips_br_exit_code_is_zero`. |
| clippy clean | PASS | Gate 2. |

### Task 03 — README (`README.md`)
| Criterion | Status | Evidence |
|-----------|--------|----------|
| Documents every v1 flag (incl. `--purpose`), exit codes, ≥2 examples | PASS | flag table + multiple example blocks. |
| Examples match actual binary name + flag spellings | PASS | uses `mini-x509-lint` throughout (`README.md:30-33,46,55,100+`), matches `[[bin]] name` `crates/cli/Cargo.toml:7`. |
| No broken/contradictory claims vs CLI | PASS | Exit-code, intersection, auto-heuristic wording all match code. |

### Task 04 — golden/exit/purpose tests + fixtures (tester)
| Criterion | Status | Evidence |
|-----------|--------|----------|
| Golden text + JSON snapshots committed & stable | PASS | 5 `.snap` in `crates/cli/tests/snapshots/`; tests green. |
| Verbose snapshot lists lints + keeps failing lines + omits collapsed; default keeps collapsed; deterministic | PASS | `good_verbose_text.snap`, `default_mode_keeps_collapsed_summary`, determinism test. |
| Exit-code matrix covered | PASS | `exit_codes.rs` (12 tests). |
| `--chain` leaf-only lint + chain-context rendering | PASS | chain snapshot + `exit_codes.rs::chain`. |
| `leaf_no_server_auth.pem` via openssl (no fabricated bytes) | PASS | fixture present (1164 B); recipe documented `purpose.rs:10-19` (openssl 3.6.2, clientAuth-only). |
| `--purpose` coverage (tls-server/generic/auto both ways/default==auto/intersection/post-filter exit) | PASS | `purpose.rs` (15 tests) covers all listed cases incl. the BR false-positive guard `auto_skips_br_on_non_server_auth_leaf`. |
| Skipped BR no outcomes; verbose header only in verbose & deterministic | PASS | `generic_skips_br_in_json`, `verbose_purpose_header::*`. |
| `cargo test` / clippy / fmt pass | PASS | All gates. |

### Task 05 — CertPurpose resolver (`crates/linter/src/registry.rs`)
| Criterion | Status | Evidence |
|-----------|--------|----------|
| `CertPurpose` with Auto/TlsServer/Generic; future variants doc-only | PASS | `registry.rs:124-141` + doc `117-123`. |
| Resolver returns documented sets | PASS | `allowed_sources` `registry.rs:200-206`; tests `tls_server_includes_cabf_br`, `generic_omits_cabf_br`. |
| Auto per-cert via `has_server_auth`; `Err`→generic | PASS | `auto_sources_from` + tests `auto_on_*`, `auto_fails_closed_to_generic_on_error`. |
| Stable/deterministic source ordering | PASS | fixed vecs `registry.rs:149,159`; asserted in tests. |
| Exported from crate root alongside `RuleSource` | PASS | `pub use registry::{CertPurpose, ...}` `crates/linter/src/lib.rs:32`. |
| Unit tests cover all four cases without new testdata files | PASS | `registry.rs::cert_purpose` mod uses `sample_cert`/`good.pem` + `auto_sources_from` helper. |
| No lint logic / applies / fixture changes; feature 05 BROAD scoping untouched | PASS | Only additive enum + resolver; engine/lints unchanged. |
| clippy clean | PASS | Gate 2. |

---

## 4. Known Notes (each judged)

| # | Note | Judgement |
|---|------|-----------|
| (a) | Task 02 added `#[allow(dead_code)]` to `render_text` in `output.rs` (task 01's file) — `render_text` became unused by the binary once it switched to `render_text_opts`. | **Note / acceptable.** `output.rs` is a binary module, so `pub` does not suppress dead-code warnings; the back-compat entry point is retained and exercised by its own unit tests (`output.rs:487-593`). Documented inline `output.rs:200-205`. Not a defect. |
| (b) | Task 05 added a `CertPurpose` re-export to `lib.rs` beyond its `registry.rs` touch. | **Note / acceptable.** Required for `use linter::CertPurpose;` in the CLI and explicitly mandated by task 05 step 5 / its acceptance criterion ("exported from the crate root alongside `RuleSource`"). Matches the existing `pub use` pattern. Not scope creep. |
| (c) | Chain-mode JSON shape (`{certificate, outcomes}` per cert, alphabetized keys via `serde_json::json!`) differs from single-cert JSON (struct-order keys). | **Note / cosmetic, not a defect.** Output is deterministic and golden-locked (`render_chain_json` `main.rs:383-400`). Key ordering differs only because `serde_json::Value` maps sort keys; cheap future fix = `serde_json` `preserve_order` feature if ever desired. Does not affect correctness or any acceptance criterion. |
| (d) | CLI accepts a single `<PATH>` + PEM-bundle multi-cert rather than multiple positional path args. | **Note / not a gap.** Satisfies plan.md ("a PEM file may contain multiple certs") and is documented in README (`--chain`, "every certificate in a PEM bundle"). The test-plan "Multiple `<PATH>` args" edge case is covered by the documented bundle behaviour. Acceptable. |
| (e) | Binary is `mini-x509-lint` while `CLAUDE.md` still says `mini-zlint`. | **Note / pre-existing doc inconsistency, NOT a feature-06 defect.** The user chose to leave the stale reference this round. Only remaining occurrence: `CLAUDE.md:4`. The root `plan.md` no longer exists (project plan referenced in CLAUDE.md is absent at repo root). README correctly uses `mini-x509-lint` everywhere; the binary name (`crates/cli/Cargo.toml:7`) and all feature-06 artifacts are consistent. Recorded as a known doc inconsistency to fix in a future docs pass. |

No note rises to FAIL or PARTIAL; all are acceptable/cosmetic.

---

## 5. Verdict

**COMPLETE.**

All plan.md requirements, all `touches` files across tasks 01–05, and every
acceptance criterion are implemented and verified against the real code and
committed test artifacts. All five quality gates pass (fmt, clippy ×2, test ×2;
285 default tests + 199 serde-feature linter tests, 0 failures). The known notes
(a)–(e) are acceptable or cosmetic and do not block the feature. No follow-up
tasks are required.

The single cross-cutting doc nit worth tracking outside this feature: `CLAUDE.md:4`
still says `mini-zlint` (the user opted to leave it this round) — a documentation
cleanup item, not a feature-06 gap.
