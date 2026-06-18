# Completeness Review — Feature 13: PQC Algorithms (ML-DSA + SLH-DSA)

**Phase 5 — Mandatory Completeness Review (gate: DONE?)**
**Date:** 2026-06-18
**Reviewer:** architect
**Verdict:** ✅ **COMPLETE** — no open gaps.

Baseline reconciled: sibling 11 (`cabf_ev`) had landed, so the pre-PQC baseline was **61** lints
with sources `[Rfc5280, CabfBr, CabfEv, CabfCs, CabfSmime, Hygiene]`. Feature 13 adds 5 `pqc` lints and
inserts `Pqc` right after `Rfc5280` → **66** lints, sources
`[Rfc5280, Pqc, CabfBr, CabfEv, CabfCs, CabfSmime, Hygiene]`. The optional 6th lint
(`pqc_in_unpermitted_profile`) was deferred per the architect's recommendation.

---

## 1. Quality Gates

| Gate | Result | Evidence |
|---|---|---|
| `cargo fmt --check` | ✅ PASS | exit 0, no output |
| `cargo clippy --all-targets -- -D warnings` | ✅ PASS | exit 0, "Finished `dev` profile" |
| `cargo test` (full workspace) | ✅ PASS | exit 0; all suites green incl. `pqc.rs` 12/12, in-file `registry` lint suite 39/39 |
| `cargo test -p linter --features serde` | ✅ PASS | exit 0; 39/39 |
| `cargo test --test pqc -p linter` | ✅ PASS | 12 passed; 0 failed |

---

## 2. Per-Requirement Audit (plan.md)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| R1 | 5 PQC lints (`pqc_algorithm_known`, `pqc_spki_parameters_absent`, `pqc_signature_parameters_absent`, `pqc_public_key_length`, `pqc_key_usage_consistency`) | ✅ PASS | `crates/linter/src/lints/pqc/{algorithm_known,spki_parameters_absent,signature_parameters_absent,public_key_length,key_usage_consistency}.rs`; ids confirmed via grep |
| R2 | `RuleSource::Pqc` (serde wire `pqc`, after `Rfc5280`) | ✅ PASS | `source.rs:25` (`Pqc` directly after `Rfc5280:19`); doc lists vocabulary incl. `pqc` |
| R3 | `PublicKeyAlg` extended with `MlDsa`/`SlhDsa(PqcParamSet)`; Rsa/Ec/Other unchanged | ✅ PASS | `cert.rs:185-201` variants; `cert.rs:842-845` match keeps Rsa/Ec, falls through to `Other`; regression test `cert.rs:1940,2348` good.pem still Rsa |
| R4 | `PqcParamSet::Known` / `Unknown` (option A gate-on-arc) | ✅ PASS | `cert.rs:220`; `classify_pqc_oid` `cert.rs:1522-1557` returns variant for any arc member, `Unknown` for `.32`–`.35`/malformed |
| R5 | Accessors `spki_algorithm_parameters_present` / `signature_algorithm_parameters_present` / `public_key_raw_len` → `Result<_, CertError>` | ✅ PASS | `cert.rs:865, 884, 903`; all via `with_parsed`, documented, no panic |
| R6 | `KeyUsageView` bits `key_encipherment` / `key_agreement` / `crl_sign` (+ existing `digital_signature` / `key_cert_sign`) | ✅ PASS | `cert.rs:94,98,102,105,108`; populated `cert.rs:503-507` |
| R7 | Universal source: `Pqc` in ALL 4 `*_sources()` helpers | ✅ PASS | `registry.rs:181` (tls_server), `:197` (generic), `:211` (code_signing), `:228` (smime) |
| R8 | NO new `CertPurpose`; `auto`/`resolve` unchanged | ✅ PASS | `registry.rs:282-287, 327-330` unchanged purpose dispatch; no new enum variant |
| R9 | CLI `--source pqc` wiring | ✅ PASS | `main.rs:194` parse token, `:201` error list, `:13,146` doc strings, `:179` `ALL_SOURCES` |
| R10 | `SOURCE_ORDER` placement (after `Rfc5280`) + `source_label` | ✅ PASS | `output.rs:24` `Pqc` after `Rfc5280`, `:159` label `"pqc"`; `ALL_SOURCES` (main.rs:177) and `SOURCE_ORDER` (output.rs:22) match exactly |
| R11 | Count/filter test updates (61 → 66) | ✅ PASS | `registry.rs:851-852` (`66`), `tests/registry.rs:369-382` (`66` with documented breakdown); per-purpose membership + `pqc_source_filter` tests present |
| R12 | `params.rs` FIPS sizes | ✅ PASS | `params.rs:44-108`: ML-DSA 1312/1952/2592 (FIPS 204 Tbl 2), SLH-DSA 32/48/64 (FIPS 205 Tbl 8); 15 named sets; unit tests `:131-181` |
| R13 | No-cascade both directions | ✅ PASS | `pqc.rs::no_cascade::raw_run_on_rsa_good_has_all_pqc_outcomes_not_applicable` + `raw_run_on_pqc_leaf_leaves_rsa_ec_hygiene_not_applicable` (both pass) |
| R14 | `generate.sh` PQC recipe (7 fixtures) | ✅ PASS | `generate.sh:878-1133`: openssl 3.5+ guard (`:948`), oracle/fragility headers, all 7 `wrote` lines |
| R15 | Golden regeneration (additive only) | ✅ PASS | 5 snapshots regenerated; `good_text.snap` diff shows ONLY `[pqc] (0 passed, 5 not applicable)` inserted; existing rows unchanged in outcome |
| R16 | Deferred 6th lint documented as Future | ✅ PASS | plan.md:160, 177, 423; `in_unpermitted_profile.rs` absent (correctly not shipped) |

---

## 3. Per-Task Acceptance-Criteria Audit

### developer-01 — cert facade (status: done) — ✅ ALL PASS
- PublicKeyAlg recognizes ML-DSA/SLH-DSA incl. unknown-arc; Rsa/Ec/Other unchanged → `cert.rs:185-201, 842-845`, regression test `:2348`.
- 3 accessors present, documented, `Result<_, CertError>`, no panic → `cert.rs:865, 884, 903`.
- KeyUsageView carries documented new bits → `cert.rs:94-108`.
- Doc comments cite FIPS 204/205 + LAMPS (RFC TBC) → `cert.rs:821-826, 857-859, 877-878`.
- Existing tests pass + new regression assertions added → full + serde suites green.
- clippy clean (incl. serde) → gate PASS.

### developer-02 — RuleSource::Pqc + lints (status: done) — ✅ ALL PASS
- `RuleSource::Pqc` after `Rfc5280`, type-doc updated → `source.rs:13, 25`.
- `params.rs` audited table + unit tests → `params.rs:44-181`.
- 5 lints, each `pqc_*`, each FIPS/LAMPS-cited, each gated via `applies_to_pqc` → 5 files + `mod.rs:75-81`.
- NotApplicable on non-PQC, Applies on PQC incl. unknown-arc → `mod.rs:77-79`; `pqc.rs::scoping` tests.
- Severities match table → Error ×4 lints; key_usage Error (keyEnc/keyAgree `:57,66`) + Warn (missing digSig/keyCertSign `:80,90`).
- Fail-closed to NotApplicable on SPKI read Err → `mod.rs:79`.
- clippy clean → gate PASS.

### developer-03 — register + universal source + CLI (status: done) — ✅ ALL PASS
- `default_registry()` includes 5 pqc lints, deterministic order → `registry.rs:438-441` block, ids at `:876-880`.
- `Pqc` in all 4 helpers; no new CertPurpose; auto/resolve unchanged → `registry.rs:181,197,211,228`.
- CLI accepts `--source pqc`; label renders; ALL_SOURCES/SOURCE_ORDER aligned → `main.rs:177-185,194`; `output.rs:22-30,159`.
- Registry unit tests: count 66, pqc filter, universal-membership for every purpose; existing tests unchanged → `registry.rs:851,973,1216-1510`.
- clippy clean → gate PASS.

### tester-04 — fixtures + tests (status: done) — ✅ ALL PASS
- 7 openssl-generated fixtures present (2 native clean leaves + bad_key_usage native + 4 DER byte-patches), no existing fixture modified → `ls testdata/pqc_*.pem`; `git status` shows only new `pqc_*.pem` untracked.
- generate.sh PQC section: version check + fragility header + per-fixture producibility notes → `generate.sh:878-1133`.
- Both clean leaves pass; each violating case isolates one rule → `pqc.rs::clean_leaves` + `::per_lint_isolation` (5 isolation tests pass).
- pqc.rs covers per-lint flag/pass, scoping, no-cascade both directions → 12/12 tests pass.
- registry.rs integration count bumped to 66; CLI e2e `--source pqc` added; existing tests unchanged → `tests/registry.rs:382`; `cli/tests/output.rs` modified additively.
- cargo test / clippy / fmt / serde all pass → gates PASS.

---

## 4. Spec Artifacts

| Artifact | Status |
|---|---|
| `plan.md` | ✅ present |
| `test-plan.md` | ✅ present |
| `tasks/developer-01..03`, `tester-04` | ✅ present, all status: done |
| `design.md` | ✅ N/A (non-UI feature) — correctly absent |
| `ui-test-report.md` | ✅ N/A (non-UI feature) — correctly absent |

---

## 5. Targeted Confirmations

- **Deferred 6th lint** (`pqc_in_unpermitted_profile`): correctly NOT shipped; documented as Future
  (plan.md:160/177/423). Not an open gap.
- **developer-01 KeyUsageView test-literal edits** in `cabf_cs/key_usage_required.rs`,
  `cabf_smime/key_usage_critical.rs`, `cabf_smime/key_usage_present.rs`: each is +3 lines, all inside
  `#[cfg(test)] mod tests` (cfg marker at lines 67/68; struct literal in the `ku()` test helper). These
  were mechanically required because `KeyUsageView` gained 3 fields — **test-only and benign**. No
  production behavior change.
- **No-cascade**: zero existing fixtures regenerated; only new `pqc_*.pem` are untracked. Golden
  snapshots are additive (new `[pqc]` bucket only; existing rows unchanged in outcome).
- **SOURCE_ORDER ↔ ALL_SOURCES** agreement verified literally identical.

---

## Top-Level Verdict: ✅ COMPLETE

All 16 plan requirements, all 4 task `touches` lists, all acceptance criteria across the 4 task files,
and all 4 quality gates verified PASS against the real code and live test output. The universal-but-
self-gated design is implemented and proven (no-cascade both directions). The deferred optional lint is
documented as Future, not an open gap. **No follow-up task created — feature is DONE.**
