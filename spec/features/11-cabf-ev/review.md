# Completeness Review — Feature 11: CA/Browser Forum Extended Validation (EV)

**Phase 5 — Mandatory Completeness Review (the DONE gate)**
**Date:** 2026-06-18
**Reviewer:** architect
**Verdict:** ✅ **COMPLETE** — no open gaps.

All four task files (`developer-01..03`, `tester-04`) are `status: done`. Every plan
requirement, every `touches` file, and every acceptance criterion is verified against the real
code and test output below. All four quality gates pass. Spec artifacts are present;
`design.md` / `ui-test-report.md` are correctly N/A (non-UI feature).

---

## 1. Quality Gates

| Gate | Command | Result |
|------|---------|--------|
| Format | `cargo fmt --check` | ✅ PASS (exit 0, no diff) |
| Lint | `cargo clippy --all-targets -- -D warnings` | ✅ PASS (exit 0) |
| Tests (workspace) | `cargo test` | ✅ PASS (exit 0) |
| Tests (serde) | `cargo test -p linter --features serde` | ✅ PASS (exit 0) |

Key per-binary test results: `tests/cabf_ev.rs` **26 passed**; `tests/registry.rs` **11 passed**;
`crates/cli/tests/golden.rs` **8 passed**; serde-feature linter lib **414 passed**;
`rfc5280.rs` 39, `cabf_br`/`cabf_cs`/`cabf_smime`/`hygiene` all green. 0 failed / 0 ignored across
the workspace.

---

## 2. Per-Requirement Verification (plan.md)

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| R1 | 9 EV lints, all `cabf_ev_*`, `RuleSource::CabfEv`, `Severity::Error` | ✅ PASS | 9 lint files in `crates/linter/src/lints/cabf_ev/`; ids extracted match plan exactly; all 9 use `RuleSource::CabfEv` and `Severity::Error` (grep counts = 9/9); each cites its EVG § in doc + message |
| R2 | `RuleSource::CabfEv` variant (serde `cabf_ev`) + doc | ✅ PASS | `source.rs:25` `CabfEv`; `source.rs:13` doc lists `cabf_ev` vocabulary |
| R3 | EV-policy-OID allowlist (`EV_POLICY_OIDS`), incl. `2.23.140.1.1` + test OID `1.3.6.1.4.1.99999.1.1` | ✅ PASS | `cabf_ev/policy.rs:40-49`; entries cited per-CA; "necessarily incomplete" maintenance note (lines 11-20); unit tests assert reserved + test OID present, DV OID `2.23.140.1.2.1` absent |
| R4 | `is_ev_scope` = serverAuth && a policy OID in allowlist; fail-closed on `Err` | ✅ PASS | `cabf_ev/mod.rs:79-88` (`matches!(has_server_auth(), Ok(true))`, `Err(_) => false`); `applies_to_ev` at `mod.rs:95-101` |
| R5 | Fold `CabfEv` into `tls-server`, **NO** new `CertPurpose` | ✅ PASS | `registry.rs:173-179` `tls_server_sources()` returns `[Rfc5280, Hygiene, CabfBr, CabfEv]`; no `ev` purpose added (no new `CertPurpose` variant in source.rs) |
| R6 | `auto` pulls EV for free on serverAuth leaf | ✅ PASS | `registry.rs:265,303` `TlsServer => tls_server_sources()`; CLI test `effective_sources(TlsServer,...)` expects `CabfEv` (`main.rs:553-560`) |
| R7 | CLI `--source cabf_ev` wiring | ✅ PASS | `main.rs:193` `"cabf_ev" => Ok(RuleSource::CabfEv)`; `main.rs:176-179` `ALL_SOURCES` (len 6) includes `CabfEv`; help text `main.rs:13,145,198` |
| R8 | `SOURCE_ORDER` placement `[Rfc5280, CabfBr, CabfEv, CabfCs, CabfSmime, Hygiene]` | ✅ PASS | `output.rs:22-28` exact order; `source_label` `output.rs:159` `CabfEv => "cabf_ev"` |
| R9 | Registry count / filter test updates | ✅ PASS | `src/registry.rs:809-810` total 61; per-source filters: rfc5280=16 (`:892`), hygiene=4 (`:934`), cabf_br=12 (`:964`), cabf_ev=9 (`:1003`), cabf_cs=8 (`:1042`), cabf_smime=12 (`:1079`) → 4+16+12+9+8+12 = 61 ✓ |
| R10 | No-cascade: EV N/A on all existing fixtures | ✅ PASS | `cabf_ev/mod.rs` test `good_pem_is_not_in_ev_scope`; integration `all_ev_lints_not_applicable_on_non_ev_good_leaf` + `..._on_ca_cert`; existing rfc5280/cabf_br/hygiene isolation suites unchanged & green |
| R11 | generate.sh EV recipe | ✅ PASS | `testdata/generate.sh` feature-11 section (from line 879): test OID, EV subject DN, 8.8.8.8 IP note, two-rule validity note, references shared time-fragility header (no divergent warning). `bash testdata/generate.sh` exits 0 and reproduces all 10 `cabf_ev_*.pem`; regenerated set passes all 26 EV + 11 registry tests |
| R12 | Golden snapshots regenerated (additive, all-NA group shown) | ✅ PASS | 5 snapshots updated; `good_text.snap:9-10` shows `[cabf_ev] (0 passed, 9 not applicable)`; verbose lists all 9 `n/a cabf_ev_*`; json/chain/validity-400 snapshots reference cabf_ev. `golden.rs` 8 tests pass; doc comment updated (`golden.rs:16,30`) |
| R13 | `cabf_ev_validity_400_days` documented two-rule case | ✅ PASS | `cabf_ev.rs:466` `validity_400_fixture_trips_both_br_and_ev_validity_rules` asserts exactly `{cabf_br_validity_max_398_days, cabf_ev_validity_max_398_days}` and no other rule |
| R14 | `cabf_ev_san_ip` uses 8.8.8.8 (192.0.2.10 trips BR reserved-IP) | ✅ PASS | `generate.sh:917-923` documents the 8.8.8.8 choice; integration isolation test confirms single-rule isolation for `cabf_ev_san_ip.pem` |

---

## 3. Per-Acceptance-Criterion Verification

### developer-01 — Cert facade EV accessors (`crates/linter/src/cert.rs`)

| AC | Status | Evidence |
|----|--------|----------|
| All 7 accessors present, each documented with OID + consuming lint | ✅ PASS | `certificate_policy_oids` (`:1168`, OID 2.5.29.32), `subject_organization_names` (`:1197`, 2.5.4.10), `subject_business_category` (`:1215`, 2.5.4.15), `subject_jurisdiction_country` (`:1235`, 1.3.6.1.4.1.311.60.2.1.3), `subject_serial_numbers` (`:1260`, 2.5.4.5), `subject_organization_identifiers` (`:1279`, 2.5.4.97), `san_wildcard_dns_names` (`:1298`); DRY helper `subject_attribute_values` (`:1143`) |
| `subject_serial_numbers` doc distinguishes subject-DN attr from cert serial | ✅ PASS | `cert.rs:1261-1262` explicit comment "the subject DN attribute, NOT the [certificate serial]" |
| All return `Result<_, CertError>`; no panic on cert data paths | ✅ PASS | signatures all `-> Result<Vec<String>, CertError>`; clippy clean confirms no unwrap/expect lints |
| Unit tests cover non-EV/empty cases against `good.pem` | ✅ PASS | `cert.rs:2053-2108` six tests asserting empty on good.pem (policies, org, businessCategory, jurisdiction, serial, orgId, wildcard) |
| clippy clean (incl. `--features serde`) | ✅ PASS | gate §1 |

### developer-02 — Nine EV lints, allowlist, `RuleSource::CabfEv`

| AC | Status | Evidence |
|----|--------|----------|
| `RuleSource::CabfEv` added (serde `cabf_ev`), doc updated | ✅ PASS | R2 |
| Nine `cabf_ev_*` lints, each citing EVG § | ✅ PASS | R1; EVG citations grepped per file (§9.2.1/.2.2/.2.4/.2.6/.2.8/§9.4) |
| All self-scope via `applies_to_ev`; non-EV leaf N/A for all nine | ✅ PASS | 9/9 files reference `applies_to_ev` (grep); `mod.rs:95-101`; R4/R10 |
| Allowlist present, cited, incl. `2.23.140.1.1` + test OID, incomplete note + tests | ✅ PASS | R3 |
| Multi-violation lints emit one finding per offender | ✅ PASS | `not_wildcard`, `san_no_ip_address`, `business_category_invalid` iterate per-entry; integration tests `flags_wildcard_san_entry_and_names_it` etc. + multi-finding unit tests |
| No unwrap/expect/panic on cert data paths | ✅ PASS | clippy clean; `mod.rs` fail-closed `Err(_) => false` |
| clippy clean (incl. serde) | ✅ PASS | gate §1 |

### developer-03 — Register + wire `CabfEv`

| AC | Status | Evidence |
|----|--------|----------|
| `default_registry()` includes 9 EV lints after BR, deterministic order | ✅ PASS | `registry.rs:435-443` nine boxed EV lints after the BR block |
| `tls_server_sources()` includes `CabfEv`; tls-server purpose tests updated | ✅ PASS | `registry.rs:173-179`; doc `:281`; CLI `effective_sources` test `main.rs:553-560` |
| `--source cabf_ev` runs exactly the EV set (filter test added) | ✅ PASS | `registry.rs:992-1003` `cabf_ev_source_filter_runs_exactly_the_cabf_ev_set` → 9 outcomes, all `CabfEv`, nine ids |
| `contains_the_known_lints` bumped by 9; other filter counts unchanged | ✅ PASS | `registry.rs:809-810` total 61; nine ids `:846-854`; rfc5280/hygiene/cabf_br counts unchanged (R9) |
| `main.rs` token + ALL_SOURCES + help include `cabf_ev`; CLI tests updated | ✅ PASS | R7; `main.rs:477,553-560` tests |
| `output.rs` SOURCE_ORDER + source_label include `CabfEv` | ✅ PASS | R8 |
| `cargo test` + clippy (incl. serde) clean | ✅ PASS | gate §1 |

### tester-04 — EV fixtures + integration tests + count bump

| AC | Status | Evidence |
|----|--------|----------|
| Ten EV `.pem` fixtures (1 control + 9 per-lint), openssl-generated; no existing regenerated; generate.sh references shared header | ✅ PASS | 10 `cabf_ev_*.pem` present; `generate.sh` regenerates all 10 (exit 0); EV section references shared time-fragility header (`:881-888`); 8.8.8.8 documented |
| `cabf_ev_good.pem` passes full registry; all EV N/A on good.pem + CA; Applies on EV good | ✅ PASS | `cabf_ev.rs:406` `ev_good_yields_no_error_or_fatal_findings`; `:337` N/A on good.pem; `:359` N/A on CA; `:380` Applies on EV good |
| Each per-lint EV fixture isolates exactly one rule (validity-400 the two-rule exception) | ✅ PASS | `cabf_ev.rs:428` `each_single_rule_ev_fixture_isolates_exactly_one_violation`; `:466` two-rule validity test |
| `tests/registry.rs` count bumped by 9; expired constant/tests unchanged | ✅ PASS | `tests/registry.rs:382` total 61; `EXPIRED_NOT_AFTER` (`:47`) unchanged |
| `cargo test`, clippy, fmt pass | ✅ PASS | gate §1 |

---

## 4. `touches` File Verification

Every file in all four tasks' `touches` lists exists and carries the intended change:

- `crates/linter/src/cert.rs` — 7 accessors + helper + tests ✓
- `crates/linter/src/source.rs` — `CabfEv` variant ✓
- `crates/linter/src/lints/mod.rs` — `pub mod cabf_ev;` (module compiles, re-exported) ✓
- `crates/linter/src/lints/cabf_ev/{mod,policy + 9 lints}.rs` — all 11 files present ✓
- `crates/linter/src/registry.rs` — registration + tls_server_sources + unit tests ✓
- `crates/cli/src/main.rs`, `crates/cli/src/output.rs` — CLI/output wiring ✓
- `testdata/generate.sh` + 10 `cabf_ev_*.pem` — present, regenerable ✓
- `crates/linter/tests/cabf_ev.rs` (26 tests), `crates/linter/tests/registry.rs` (count 61) ✓
- 5 golden snapshots + `crates/cli/tests/golden.rs` — additive, doc updated ✓

---

## 5. Cross-Feature Reconciliation (siblings 09/10)

The shared-file reconciliation landed consistently with sibling features 09 (`CabfCs`) and 10
(`CabfSmime`):

- Final registry count **61** = 4 hygiene + 16 rfc5280 + 12 cabf_br + 9 cabf_ev + 8 cabf_cs +
  12 cabf_smime, asserted identically in `src/registry.rs:809` and `tests/registry.rs:382`.
- `SOURCE_ORDER` / `ALL_SOURCES` carry the full deterministic list `[Rfc5280, CabfBr, CabfEv,
  CabfCs, CabfSmime, Hygiene]` (output.rs:22-28, main.rs:176-181) — EV directly after BR as
  specified.
- `tls_server_sources()` contains `CabfEv` only (09/10 are not tls-server purposes), as required.

---

## 6. Spec Artifacts

| Artifact | Present? |
|----------|----------|
| `plan.md` | ✅ |
| `test-plan.md` | ✅ |
| `tasks/developer-01..03`, `tasks/tester-04` | ✅ (all 4, status: done) |
| `design.md` | N/A — non-UI feature (correctly absent) |
| `ui-test-report.md` | N/A — non-UI feature (correctly absent) |

---

## 7. Verdict

# ✅ COMPLETE

Every plan requirement, `touches` file, and acceptance criterion is PASS with concrete evidence.
All four quality gates are green. generate.sh reproduces all 10 EV fixtures and the regenerated
set passes the full EV + registry suites. The 5 golden snapshots are additive (the all-NA
`[cabf_ev]` group renders on TLS certs by design). No PARTIAL or FAIL findings — no follow-up
task created.

**Open gaps:** none.
