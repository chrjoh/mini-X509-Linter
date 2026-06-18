# Completeness Review — Feature 10: CA/Browser Forum S/MIME Baseline Requirements

**Phase 5 (Mandatory Completeness Review) — the DONE gate.**

- Reviewer: architect
- Date: 2026-06-18
- Inputs re-read: `plan.md`, `test-plan.md`, all 4 task files (developer-01..03, tester-04, all `status: done`).
- Prior phases: Integration review = GO; Final verification = READY.

## Top-Level Verdict: **COMPLETE**

All 12 lints, the new `RuleSource::CabfSmime`, `CertPurpose::Smime` + `auto` precedence, the CLI
`--source`/`--purpose` wiring, `SOURCE_ORDER` placement, registry count/filter test updates, the
no-cascade EKU gate, and the appended `generate.sh` S/MIME recipe are all implemented, tested, and
green. The feature-09 `generate.sh` CS recipe was preserved (no recurrence of the feature-09 gap).

One **doc-only** inaccuracy was found (`test-plan.md` line 68 still says "outcome count == 44"; the
implemented — and correct — assertion is `52`). It does **not** affect code, tests, or any gate, so
the feature is COMPLETE. A non-blocking follow-up task (`tester-05`) is filed to correct the stale
spec note. No production-code or test-code gap exists.

---

## Quality Gates

| Gate | Command | Result |
|------|---------|--------|
| Format | `cargo fmt --check` | **PASS** (exit 0, no diff) |
| Lint | `cargo clippy --all-targets -- -D warnings` | **PASS** (exit 0, clean) |
| Tests | `cargo test` (full workspace) | **PASS** — 595 tests, 0 failed (lib 358, cabf_smime 17, cabf_br 48, cabf_cs 14, hygiene 11, not_expired 8, registry 10, rfc5280 39, cli main 40, exit_codes 12, golden 8, output 15, purpose 15) |
| Serde | `cargo test -p linter --features serde` | **PASS** — lib 358 + all integration suites green, 0 failed |
| Recipe | `bash testdata/generate.sh` | **PASS** (exit 0) — regenerates all 12 `cabf_smime_*.pem` |

---

## Per-Requirement Verification (plan.md Requirements + Changes Overview)

### The 12 S/MIME lints (plan.md §Requirements table)

All 12 lint files exist under `crates/linter/src/lints/cabf_smime/`, each `cabf_smime_*`, each
EKU-gated via the shared `applies_to_smime_leaf`, each registered in `default_registry()`
(registry.rs:430-441) and asserted in `contains_the_known_lints` (registry.rs:821-832).

| # | lint_id | Severity | Evidence | Status |
|---|---------|----------|----------|--------|
| 1 | `cabf_smime_san_present` | Error | `san_present.rs`; reg registry.rs:430; integ test `san_present` cabf_smime.rs:212 | PASS |
| 2 | `cabf_smime_san_not_critical` | Warn | `san_not_critical.rs`; reg :431; integ `san_not_critical` cabf_smime.rs:233 | PASS |
| 3 | `cabf_smime_email_in_san` | Error | `email_in_san.rs` (per-CN multi-finding, domain case-insensitive); reg :432; integ :254 | PASS |
| 4 | `cabf_smime_single_email_subject` | Error | `single_email_subject.rs`; reg :433; integ :275 | PASS |
| 5 | `cabf_smime_key_usage_present` | Error | `key_usage_present.rs`; reg :434; integ :296 | PASS |
| 6 | `cabf_smime_key_usage_critical` | Warn | `key_usage_critical.rs` (silent when KU absent); reg :435; integ :317 | PASS |
| 7 | `cabf_smime_eku_email_protection_present` | Error | `eku_email_protection_present.rs` defensive `evaluate(bool)` + unit tests (passes when present, fires when absent); reg :436 | PASS |
| 8 | `cabf_smime_eku_no_server_auth` | Error | `eku_no_server_auth.rs`; reg :437; integ :338 (fixture `eku_server_auth`) | PASS |
| 9 | `cabf_smime_authority_key_identifier_present` | Error | `authority_key_identifier_present.rs`; reg :438; integ :362 | PASS |
| 10 | `cabf_smime_crl_distribution_points_present` | Error | `crl_distribution_points_present.rs`; reg :439; integ :384 | PASS |
| 11 | `cabf_smime_crl_distribution_points_http` | Error | `crl_distribution_points_http.rs` (per-URI multi-finding); reg :440; integ :406 | PASS |
| 12 | `cabf_smime_subject_country_valid` | Error | `subject_country_valid.rs` (per-value multi-finding); reg :441; integ :431 | PASS |

### Core wiring requirements

| Requirement | Evidence | Status |
|-------------|----------|--------|
| `RuleSource::CabfSmime` (serde wire `cabf_smime`) | source.rs:26 + `#[serde(rename_all="snake_case")]` source.rs:16; doc lists vocabulary source.rs:12 | PASS |
| EKU gate `applies_to_smime_leaf` (emailProtection AND not CA; fail-closed to NotApplicable) | cabf_smime/mod.rs:92-97 | PASS |
| `CertPurpose::Smime` promoted, `[Rfc5280, Hygiene, CabfSmime]` | registry.rs:149 (Smime variant), `smime_sources()` registry.rs:192-198, `allowed_sources`/`resolve` :289/:321 | PASS |
| `auto` precedence codeSigning → serverAuth → emailProtection → Generic | `auto_purpose_from` registry.rs:220-232; tests `auto_on_email_protection_leaf_resolves_to_smime` :1234, `auto_server_auth_beats_email_protection` :1255, `auto_code_signing_beats_email_protection` :1269, `auto_email_protection_err_fails_closed_to_generic` :1279 | PASS |
| serverAuth wins over emailProtection (multipurpose) | `auto_server_auth_beats_email_protection` registry.rs:1255-1266; documented cabf_smime/mod.rs:31-38 | PASS |
| CLI `--source cabf_smime` | main.rs:193 (`parse_source_token`), error msg :196, `ALL_SOURCES` :176-181; test `parses_cabf_smime_source` :491 | PASS |
| CLI `--purpose smime` | `CliPurpose::Smime` main.rs:112, `From` map :125, `purpose_label` :251, help text :26-31; test `cli_purpose_conversion` :533 | PASS |
| `SOURCE_ORDER` placement `[Rfc5280, CabfBr, CabfCs, CabfSmime, Hygiene]` | output.rs:22-28; `source_label` carries `cabf_smime` | PASS |
| Registry count 40 → 52 | `contains_the_known_lints` registry.rs:776-777 (`len()==52`, `outcomes.len()==52`) | PASS |
| `cabf_smime` source-filter test (12 outcomes, all CabfSmime, no other prefixes) | `cabf_smime_source_filter_runs_exactly_the_cabf_smime_set` registry.rs:986-1021 | PASS |
| Other filter counts unchanged: rfc5280=16, hygiene=4, cabf_br=12, cabf_cs=8 | registry.rs:850, :892, :922, :961 | PASS |
| No-cascade: smime NotApplicable on all pre-existing fixtures | `no_cascade_all_twelve_smime_lints_not_applicable_on_a_non_smime_leaf` cabf_smime.rs:528 (good.pem + CA fixture); existing rfc5280/hygiene/cabf_br/registry/golden suites unchanged & green | PASS |
| `generate.sh` S/MIME recipe (all 12 fixtures, emailProtection, time-fragility note) | generate.sh:878-... ; 12 distinct `cabf_smime_*.pem`; `bash testdata/generate.sh` regenerates all 12; CS recipe (5 cabf_cs fixtures) preserved | PASS |

### cert.rs facade accessors (task 01)

| Accessor | Evidence | Status |
|----------|----------|--------|
| `san_rfc822_names()` | cert.rs:529 | PASS |
| `EkuView.email_protection` field | cert.rs:142, populated :614 | PASS |
| `has_email_protection()` | cert.rs:687 | PASS |
| `has_authority_key_identifier()` | cert.rs:865 | PASS |
| `has_crl_distribution_points()` | cert.rs:936 | PASS |
| `crl_distribution_point_uris()` | cert.rs:969 | PASS |
| `subject_email_addresses()` | cert.rs:1067 | PASS |
| `subject_country_names()` | cert.rs:1050 | PASS |
| No new crate dependency (implementable with x509-parser) | no Cargo.toml change required; clippy/test clean | PASS |

---

## Per-Task Acceptance Criteria

### developer-01 (cert.rs facade) — `touches: crates/linter/src/cert.rs`

- [x] All six accessor groups present, documented, non-panicking, `Result<_, CertError>` — cert.rs:529/687/865/936/969/1050/1067
- [x] `EkuView.email_protection` field + `has_email_protection()` — cert.rs:142, :687
- [x] Style matches existing accessors (with_parsed, "# Errors", encounter order)
- [x] No new crate dependency required (Cargo.toml unchanged)
- [x] clippy clean (incl. `--features serde`) / fmt clean — gates PASS

### developer-02 (lints + source) — `touches: source.rs, lints/mod.rs, cabf_smime/*` (14 files)

- [x] `RuleSource::CabfSmime` serializes to `cabf_smime` — source.rs:26
- [x] All 12 lints implemented, each `cabf_smime_*`, each citing its S/MIME BR § — lint file doc headers
- [x] Every lint EKU-gated via shared `applies_to_smime_leaf` — cabf_smime/mod.rs:92
- [x] Multi-violation lints emit one finding per offending entry — email_in_san / crl_distribution_points_http / subject_country_valid
- [x] No `unwrap`/`expect`/`panic!` on cert paths; accessor `Err` handled — fail policy mod.rs:40-52
- [x] clippy clean (incl. `--features serde`) — gate PASS
- [x] All 14 `touches` files present on disk — verified

### developer-03 (registry + purpose + CLI) — `touches: registry.rs, cli/main.rs, cli/output.rs`

- [x] `default_registry()` includes all 12 cabf_smime lints in deterministic order — registry.rs:430-441
- [x] `--source cabf_smime` runs exactly the smime set; `--purpose smime` → `[Rfc5280, Hygiene, CabfSmime]` — main.rs:193, registry.rs:192/289
- [x] `auto` resolves emailProtection-only → Smime; serverAuth wins; fail-closed Err — registry.rs:1234/1255/1279
- [x] `contains_the_known_lints` + smime source-filter + `Smime` purpose tests added/passing; other counts unchanged — registry.rs:776/986/1206
- [x] CLI `SOURCE_ORDER`/`ALL_SOURCES`/`source_label`/`CliPurpose` carry `cabf_smime`/`smime` — output.rs:22, main.rs:176/112/251
- [x] `cargo test` / clippy / fmt pass — gates PASS

### tester-04 (fixtures + tests) — `touches: generate.sh, 12 .pem, tests/cabf_smime.rs`

- [x] 13 new openssl fixtures listed (1 clean + 11 violating present on disk = 12 files; lint 7 has no fixture by design); NO existing fixture changed; `generate.sh` gains S/MIME section with time-fragility note — generate.sh:878
- [x] `cabf_smime_good.pem` passes full registry (no Error/Fatal); each violating fixture isolates exactly its one rule — cabf_smime.rs:148/452
- [x] EKU gate keeps every smime lint NotApplicable on good.pem (TLS leaf) and a CA fixture — cabf_smime.rs:528
- [x] Feature-03/04/05 isolation + feature-06 golden pass UNCHANGED (verified, not edited) — rfc5280/hygiene/cabf_br/golden suites green
- [x] `cargo test` / clippy (incl. serde) / fmt / `bash testdata/generate.sh` all pass — gates PASS

> Fixture-count note: the `touches` list enumerates 12 `.pem` files (good + 11 violating). The
> plan/test-plan prose says "13 new fixtures" but the design explicitly gives lint 7 NO fixture, so
> the correct on-disk count is 12. All 12 are present and openssl-generated by the appended recipe.
> No gap — the "13" is prose rounding, the implementation matches the (12-file) `touches` list.

---

## Spec Artifacts

| Artifact | Present | Note |
|----------|---------|------|
| `plan.md` | YES | Requirements + Changes Overview complete |
| `test-plan.md` | YES | One stale count note (see Gaps) |
| `tasks/developer-01-cert-facade-smime-accessors.md` | YES | status: done |
| `tasks/developer-02-cabf-smime-lints-and-source.md` | YES | status: done |
| `tasks/developer-03-register-purpose-and-cli-wiring.md` | YES | status: done |
| `tasks/tester-04-fixtures-and-tests.md` | YES | status: done |
| `design.md` | N/A | Correctly absent — non-UI feature |
| `ui-test-report.md` | N/A | Correctly absent — non-UI feature |

---

## Gaps Found

### G1 (PARTIAL — doc-only, non-blocking): stale outcome-count note in test-plan.md

- **Location:** `spec/features/10-smime-br/test-plan.md` line 68 — "outcome count == 44".
- **Reality:** the implemented (and correct) assertion is `outcomes.len() == 52`
  (registry.rs:777). The engine never short-circuits — `sample_cert()` produces one outcome per
  registered lint regardless of applicability, so the outcome count equals the registry length (52),
  not 44. The "== 44" predates the final count reconciliation and was missed when the other stale
  refs were corrected.
- **Impact:** none on code, tests, or any quality gate. The implementation is correct; only the
  spec note is wrong, so it could mislead a future maintainer.
- **Disposition:** NOT hand-fixed (per gate protocol). Follow-up task filed:
  `tasks/tester-05-fix-stale-outcome-count-note.md`.

No PARTIAL/FAIL exists in any production-code, test-code, fixture, or build artifact. G1 is a
documentation correction only and does not hold the feature open as INCOMPLETE.

---

## Conclusion

**VERDICT: COMPLETE.** Every plan.md requirement, every `touches` file, and every task acceptance
criterion is implemented and verified against the real code; all four quality gates are green; the
`generate.sh` S/MIME recipe regenerates all 12 fixtures and the feature-09 CS recipe is intact. The
single finding (G1) is a doc-only stale count in test-plan.md, recorded as a non-blocking follow-up
(`tester-05`).
