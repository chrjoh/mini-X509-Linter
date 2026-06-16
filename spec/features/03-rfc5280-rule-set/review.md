# Phase 5 Completeness Review — Feature 03: RFC 5280 Rule Set

**Reviewer:** architect
**Date:** 2026-06-16
**Scope:** `spec/features/03-rfc5280-rule-set/` (tasks 01–06)
**Inputs:** plan.md (Requirements + Changes Overview), test-plan.md, tasks 01–06 Acceptance Criteria
**Prior gates:** integration review = INTEGRATION CLEAN; tester verification = VERIFIED (116/116)

---

## TOP-LEVEL VERDICT: **COMPLETE**

All six RFC 5280 lints are implemented, scoped, registered, fixture-backed, and tested.
Every plan.md requirement and every acceptance criterion across tasks 01–06 maps to PASS.
All five quality gates are green. One non-blocking cosmetic observation (PARTIAL) is recorded
below; it is not a plan.md requirement and does not gate completion. No follow-up tasks created.

---

## 1. Quality Gate Results

| Gate | Result | Evidence |
|------|--------|----------|
| `cargo fmt --check` | **PASS** | exit 0, no diff |
| `cargo clippy --all-targets -- -D warnings` | **PASS** | exit 0, Finished clean |
| `cargo clippy --all-targets --features serde -- -D warnings` | **PASS** | exit 0, Finished clean |
| `cargo test` | **PASS** | 116 passed / 0 failed (see breakdown) |
| `cargo test -p linter --features serde` | **PASS** | 90 passed / 0 failed (linter only, serde on) |

### `cargo test` breakdown (116 total)

| Suite | Passed |
|-------|--------|
| cli `unittests src/main.rs` | 14 |
| cli `tests/output.rs` | 12 |
| linter `unittests src/lib.rs` | 57 |
| linter `tests/not_expired.rs` | 8 |
| linter `tests/registry.rs` | 9 |
| linter `tests/rfc5280.rs` | 16 |
| **Total** | **116** |

(No TUI in this feature — none expected or run.)

---

## 2. Requirement Mapping (plan.md)

### 2.1 The six lints (each tagged `RuleSource::Rfc5280`)

| Requirement | Verdict | Evidence |
|-------------|---------|----------|
| `version_is_v3` — v3 required when extensions present | **PASS** | `version_is_v3.rs:25-70`; id `rfc5280_version_is_v3` (:27); §4.1.2.1 cited (:1-6); `check` emits Error when `has_extensions() && version != 2` (:44-69) |
| `serial_number_positive` — positive, ≤20 octets | **PASS** | `serial_number_positive.rs:33-84`; id (:64); §4.1.2.2 cited (:1-10); emits up to 2 Findings (zero/negative + overlong) via pure `evaluate` (:33-61) |
| `validity_not_after_after_not_before` | **PASS** | `validity_window.rs:25-64`; id `rfc5280_validity_not_after_after_not_before` (:26); §4.1.2.5 cited (:1-9); Error when `not_after <= not_before` (:50-63) |
| `basic_constraints_critical_on_ca` | **PASS** | `basic_constraints_critical_on_ca.rs:23-62`; id (:24); §4.2.1.9 cited (:1-7); CA-scoped via `applies` (:32-40); Error when BC not critical (:51-61) |
| `key_usage_present_when_ca` — keyCertSign required | **PASS** | `key_usage_present_when_ca.rs:23-65`; id (:24); §4.2.1.3 cited (:1-7); CA-scoped (:32-39); Error when KU absent or lacks keyCertSign (:49-64) |
| `san_present_if_subject_empty` — SAN required + critical | **PASS** | `san_present_if_subject_empty.rs:26-69`; id (:27); §4.1.2.6/§4.2.1.6 cited (:1-10); empty-subject-scoped (:35-43); Error when SAN absent OR present-but-not-critical (:53-67) |

### 2.2 Cross-cutting lint requirements

| Requirement | Verdict | Evidence |
|-------------|---------|----------|
| Each declares scope via `applies()` (CA-only → NotApplicable on leaf) | **PASS** | BC/KU map `is_ca()` Ok(true)→Applies else NotApplicable; SAN maps `subject_is_empty()`; integration `not_applicable_on_leaf` tests pass (`tests/rfc5280.rs:182,214,246`) |
| Returns `Vec<Finding>` — empty pass; multi-finding allowed | **PASS** | serial emits 2 findings (`flags_both_zero_and_overlong`, `serial_number_positive.rs:163-171`); all `check` return `Vec<Finding>` |
| Comment cites RFC 5280 section | **PASS** | Every lint's module doc-comment cites its § (see 2.1) |
| Stable `rfc5280_*` lint_id convention | **PASS** | All six ids prefixed `rfc5280_`; asserted in `has_correct_id_and_source` per file and in registry `default_registry::contains_the_known_lints` |

### 2.3 Architecture / scoping / facade

| Requirement | Verdict | Evidence |
|-------------|---------|----------|
| One file per lint under `lints/rfc5280/` | **PASS** | 6 lint files + `mod.rs` present (`crates/linter/src/lints/rfc5280/`) |
| Lints read only through `Cert` facade | **PASS** | Every lint imports `crate::cert::Cert` and calls facade accessors only; no `x509_parser`/`der` import in any lint file |
| `der` used behind facade for raw serial | **PASS** | `cert.rs:239-262` `serial_der_octets`/`serial_summary` inspect raw octets; lints consume `SerialSummary` only |
| Registered in default constructor | **PASS** | `registry.rs:129-145` `default_registry()` boxes all six in deterministic order |

### 2.4 Fixtures (testdata/)

| Requirement | Verdict | Evidence |
|-------------|---------|----------|
| One fixture per lint violating exactly that rule | **PASS** | 6 `rfc5280_*.pem` present; `each_fixture_isolates_exactly_one_rfc5280_violation` (`tests/rfc5280.rs:288-331`) asserts exactly one lint fires per fixture through the full registry — **authoritative isolation proof**, passes |
| `good.pem` passes all six | **PASS** | `good_pem_yields_no_error_or_fatal_findings` (`tests/rfc5280.rs:264-282`) passes; regenerated as clean leaf (CN=good.example, serial 17, CA:FALSE, v3, far-future) |
| Regeneration script present | **PASS** | `testdata/generate.sh` (8190 B, executable) covers all 8 outputs incl. DER version-byte patch for v1-with-extensions (`generate.sh:176-177`) |

---

## 3. Acceptance Criteria by Task

### Task 01 — Cert facade accessors (`crates/linter/src/cert.rs`)
| Criterion | Verdict | Evidence |
|-----------|---------|----------|
| All listed accessors exist, documented, no-panic (Option for absent) | **PASS** | `version` (:209), `has_extensions` (:222), `serial_der_octets` (:239), `serial_summary` (:255), `not_before/after` (:185/195), `basic_constraints`→`Option<BasicConstraintsView>` (:275), `is_ca` (:296), `key_usage`→`Option<KeyUsageView>` (:310), `subject_is_empty` (:329), `subject_alt_name`→`Option<SanView>` (:344); all return `Result`, no panics on data paths |
| Serial inspection uses `der` for raw octets | **PASS** | `serial_der_octets` uses `raw_serial()` (:240); `serial_summary` derives sign/zero/len from octets (:255-262) |
| clippy clean | **PASS** | gate 2/3 above |

### Task 02 — The six lints (lint files + `lints/mod.rs` + `rfc5280/mod.rs`)
| Criterion | Verdict | Evidence |
|-----------|---------|----------|
| Six lints, each `rfc5280_*` id, each cites RFC section | **PASS** | §2.1 |
| CA-only lints NotApplicable on a leaf | **PASS** | `tests/rfc5280.rs:182-190, 214-222` pass |
| Multi-reason lints return multiple Findings | **PASS** | serial `evaluate` + `flags_both_zero_and_overlong`; SAN absent-vs-not-critical paths |
| No `unwrap`/`expect`/`panic!` on cert data paths | **PASS** | All `check`/`applies` use `match ... Err(_) => ...` fail-policy (module doc `rfc5280/mod.rs:8-17`); `unwrap`/`expect` appear only inside `#[cfg(test)]` |
| clippy clean | **PASS** | gate above |

### Task 03 — Registry registration (`crates/linter/src/registry.rs`)
| Criterion | Verdict | Evidence |
|-----------|---------|----------|
| `default_registry()` includes all six | **PASS** | `registry.rs:138-143`; asserted `contains_the_known_lints` (:463-490), `len()==7` |
| `--source rfc5280` runs exactly the RFC 5280 set | **PASS** | `rfc5280_source_filter_runs_exactly_the_rfc5280_set` (:492-519) asserts 6 outcomes, all Rfc5280, no hygiene |
| Registration order deterministic | **PASS** | Fixed `vec![...]` order (:135-143); CLI golden-style test `(3 passed, 3 not applicable)` stable |
| clippy clean | **PASS** | gate above |

### Task 04 — Fixtures + per-lint tests (tester)
| Criterion | Verdict | Evidence |
|-----------|---------|----------|
| Six fixtures exist; `generate.sh` regenerates them | **PASS** | `testdata/` listing + `generate.sh:118-177` |
| Each fixture isolates exactly one rule (openssl-impossible via patched DER) | **PASS** | `each_fixture_isolates_exactly_one_rfc5280_violation` passes; v1-with-extensions made by DER version-byte patch (`generate.sh:176-177`) |
| Each lint flags its fixture and passes `good.pem` | **PASS** | per-lint `flags_*` + `passes_for_good_leaf` tests (`tests/rfc5280.rs:64-255`) |
| CA-only lints NotApplicable on a leaf | **PASS** | `tests/rfc5280.rs:182,214` |
| `good.pem` regenerated as clean leaf passing ALL lints | **PASS** | `good_pem_yields_no_error_or_fatal_findings` passes; `generate.sh:110-111` |
| `expired.pem` regenerated: same leaf, past notAfter, only `not_expired` warn | **PASS** | `generate.sh:113-114`; `not_expired.rs` (8) + `registry.rs` (9) green unmodified |
| Full `cargo test` green incl. the 3 previously-failing CLI tests, without editing output.rs/registry.rs | **PASS** | 116/116; the three CLI tests pass (one relaxed in task 06 by design, not editing registry.rs) |
| `cargo test` / clippy / fmt pass | **PASS** | gates above |

> Note: AC criterion "without modifying `crates/cli/tests/output.rs`" for `source_rfc5280_on_expired_reports_no_findings` was reassigned to task 06 as a deliberate, reviewed scope split (the assertion was a stale exact-match, not a fixture problem). The other two CLI tests returned to green purely via the regenerated fixtures. This is consistent with the task-06 plan and does not constitute a gap.

### Task 05 — Fix stale `good.pem` CA assertions in `cert.rs` unit tests (developer)
| Criterion | Verdict | Evidence |
|-----------|---------|----------|
| Every assertion in `tests::rfc5280_accessors` reflects regenerated leaf good.pem | **PASS** | module `cert.rs:419-491`; v3 (:431), has-extensions (:440), subject not empty (:447), serial positive ≤20 (:468), no KU/SAN (:489) |
| Stale `good_cert_is_a_critical_ca` renamed; asserts NOT a CA | **PASS** | renamed `good_cert_is_a_leaf` (:454) asserts `!bc.is_ca` (:459) and `!cert.is_ca().unwrap()` (:464) |
| No production accessor code changed (tests-only) | **PASS** | accessor bodies (:209-348) unchanged; edits confined to test module |
| `cargo test -p linter` green | **PASS** | 57 unit + integration green |
| test/clippy(+serde)/fmt pass | **PASS** | gates above |

### Task 06 — Relax stale exact-match CLI test (tester, `crates/cli/tests/output.rs`)
| Criterion | Verdict | Evidence |
|-----------|---------|----------|
| Test passes via `.contains("OK: no findings")` (no exact-match) | **PASS** | `output.rs:133` |
| Still verifies meaningful output (header/summary present) | **PASS** | `output.rs:125` `[rfc5280]`, `:129` `(3 passed, 3 not applicable)` |
| No production code changed; no other test weakened | **PASS** | only this test's assertions changed; sibling tests intact |
| `cargo test` fully green | **PASS** | 116/116 |
| clippy(+serde)/fmt pass | **PASS** | gates above |

---

## 4. Non-Blocking Observation (carried from integration review) — **PARTIAL / NOTE**

**Finding:** Three in-file `#[cfg(test)]` modules embed a **CA-certificate** DER blob under
misleading constant names that suggest a leaf:

- `lints/rfc5280/version_is_v3.rs:78` — `GOOD_PEM` (the blob is a critical CA:TRUE cert)
- `lints/rfc5280/serial_number_positive.rs:91` — `GOOD_PEM` (same CA blob)
- `lints/rfc5280/validity_window.rs:72` — `GOOD_PEM` (same CA blob)
- `lints/rfc5280/san_present_if_subject_empty.rs:78` — `NON_EMPTY_SUBJECT_PEM` (same CA blob)

(The sibling constants `GOOD_CA_PEM` in `basic_constraints_critical_on_ca.rs:70` and
`CA_NO_KEY_USAGE_PEM` in `key_usage_present_when_ca.rs:74` are **accurately** named.)

**Severity:** cosmetic naming clarity only. **Owner:** task 02.

**Why it does not block:**
- Every assertion made against the embedded cert is *accurate for that cert* (it is v3, has a
  positive short serial, a valid validity window, a non-empty subject, and `applies` is always
  `Applies` for those three lints) and all such tests pass.
- It is not a plan.md requirement — plan.md mandates one committed `testdata/` fixture per lint,
  which is satisfied. These in-file constants are auxiliary smoke tests.
- The **authoritative** pass/leaf and one-violation-per-fixture guarantees come from
  `crates/linter/tests/rfc5280.rs` using the real committed fixtures
  (`good_pem_yields_no_error_or_fatal_findings`, `each_fixture_isolates_exactly_one_rfc5280_violation`),
  both passing.

**Disposition:** recorded as PARTIAL/NOTE, not FAIL. No follow-up task required for completion.
If desired later, a trivial rename (`GOOD_PEM` → `CA_WITH_EXTENSIONS_PEM`, `NON_EMPTY_SUBJECT_PEM`
documented as a CA) would close it — purely optional polish.

---

## 5. Follow-up Tasks

None. Feature is COMPLETE; no gaps require remediation.
