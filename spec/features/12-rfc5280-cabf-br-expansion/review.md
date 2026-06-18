# Completeness Review (Phase 5) — Feature 12: RFC 5280 & CA/Browser Forum BR Depth Expansion

**Date:** 2026-06-18
**Reviewer:** architect (mandatory completeness gate)
**Verdict:** **COMPLETE** — no open gaps.

This gate audits every requirement in `plan.md`, every file in each task's `touches` list, and
every acceptance criterion across all six task files (developer-01..04, tester-05, tester-06) against
the real code and live test output. Evidence is cited as `file:line`, test name, or command output.

---

## 1. Quality Gates (live results)

| Gate | Result | Evidence |
|---|---|---|
| `cargo fmt --check` | PASS | exit 0, no diff |
| `cargo clippy --all-targets -- -D warnings` | PASS | `Finished dev profile`, exit 0 |
| `cargo test` (full workspace) | PASS | all binaries `0 failed` (see tally below) |
| `cargo test -p linter --features serde` | PASS | linter lib 226 passed; cabf_br 48; hygiene 11; not_expired 8; registry 10; rfc5280 39 — `0 failed` |

**Full-workspace `cargo test` tally (all `0 failed`):**
- cli `mini_x509_lint` unit: 39
- cli `tests/exit_codes.rs`: 12
- cli `tests/golden.rs`: 8
- cli `tests/output.rs`: 12
- cli `tests/purpose.rs`: 15
- linter lib unit: 226
- linter `tests/cabf_br.rs`: 48
- linter `tests/hygiene.rs`: 11
- linter `tests/not_expired.rs`: 8
- linter `tests/registry.rs`: 10
- linter `tests/rfc5280.rs`: 39

All cross-feature regression suites (hygiene, registry, not_expired, CLI output) pass **unchanged**,
confirming the central invariant: **no existing fixture was regenerated**.

---

## 2. Requirements Audit (plan.md)

### 2.1 New RFC 5280 lints (10 shipped; item 1 deliberately cut)

| Lint (id) | Status | Evidence |
|---|---|---|
| `rfc5280_basic_constraints_not_critical` (item 1) | PASS (cut, as designed) | Documented cut in plan §Cuts; not registered (duplicate of existing `BasicConstraintsCriticalOnCa`) |
| `rfc5280_ca_subject_field_empty` | PASS | `lints/rfc5280/ca_subject_field_empty.rs`; registered `registry.rs:CaSubjectFieldEmpty::new()` |
| `rfc5280_ext_key_usage_without_bits` | PASS | `ext_key_usage_without_bits.rs`; `ExtKeyUsageWithoutBits::new()`; reads `EkuView.is_empty` |
| `rfc5280_ext_authority_key_identifier_no_key_identifier` | PASS | `ext_authority_key_identifier_no_key_identifier.rs`; test `flags_aki_without_key_identifier` ok |
| `rfc5280_ext_subject_key_identifier_missing_ca` | PASS | `subject_key_identifier_presence.rs`; tests `flags_ca_without_subject_key_identifier`, `not_applicable_on_leaf` ok |
| `rfc5280_ext_subject_key_identifier_missing_sub_cert` | PASS | same file; `warns_for_leaf_without_subject_key_identifier`, `not_applicable_on_ca` ok; **Warn** confirmed |
| `rfc5280_path_len_constraint_improperly_included` | PASS | `path_len_constraint_improperly_included.rs`; tests `flags_path_len_on_non_ca_leaf`, `not_applicable_when_path_len_absent` ok |
| `rfc5280_ext_name_constraints_not_critical` | PASS | `ext_name_constraints_not_critical.rs`; `flags_non_critical_name_constraints` ok |
| `rfc5280_subject_dn_country_not_printable_string` | PASS | `subject_dn_country_not_printable_string.rs`; `flags_country_encoded_as_utf8_string`, `not_applicable_when_no_country_attribute` ok |
| `rfc5280_ext_san_no_entries` | PASS | `ext_san_no_entries.rs`; `flags_san_with_zero_general_names`, `passes_for_good_leaf_with_one_entry` ok |
| `rfc5280_utc_time_not_in_zulu` | PASS (shipped, not cut) | `utc_time_not_in_zulu.rs`; `flags_utc_time_in_offset_form`, `passes_for_good_leaf_in_zulu` ok |

All 10 shipped lints registered after the original 6 in `default_registry()` (`registry.rs` block,
"RFC 5280 depth-expansion lints (feature 12)"), order appended not reshuffled. The pre-approved
`utc_time` cut was **not needed** — the lint shipped.

### 2.2 New CA/Browser Forum BR lints (8 shipped)

| Lint (id) | Status | Evidence |
|---|---|---|
| `cabf_br_dnsname_underscore_in_sld` | PASS | `dnsname_syntax.rs` (DnsnameUnderscoreInSld); registered |
| `cabf_br_dnsname_bad_character_in_label` | PASS | `dnsname_syntax.rs` (DnsnameBadCharacterInLabel); registered |
| `cabf_br_dnsname_label_too_long` | PASS | `dnsname_syntax.rs` (DnsnameLabelTooLong); registered |
| `cabf_br_dnsname_wildcard_left_of_public_suffix` | PASS | `dnsname_syntax.rs:221-245`; conservative two-label `*.<single-label>` rule, NO PSL, limitation documented in docstring |
| `cabf_br_organizational_unit_name_prohibited` | PASS | `organizational_unit_name_prohibited.rs`; uses `subject_organizational_unit_count()` |
| `cabf_br_subject_contains_reserved_ip` | PASS | `subject_contains_reserved_ip.rs`; reuses `reserved.rs` on CN values |
| `cabf_br_extra_subject_common_names` | PASS | `extra_subject_common_names.rs`; `subject_common_names().len() > 1` |
| `cabf_br_subject_country_not_iso` | PASS | `subject_country_not_iso.rs`; in-module alpha-2 allowlist, no crate |

All 8 registered after the original 4 (`registry.rs` block "CA/Browser Forum BR depth-expansion lints
(feature 12)"). All broad-scoped (`NotApplicable` on CA), verified by `cabf_br.rs` 48 tests passing
including CA-NotApplicable cases.

### 2.3 Facade accessors (cert.rs)

| Accessor / View | Status | Evidence |
|---|---|---|
| `authority_key_identifier()` → `Option<AkiView>` | PASS | `cert.rs:751`; `struct AkiView` at `cert.rs:183` |
| `has_subject_key_identifier()` | PASS | `cert.rs:779` |
| `name_constraints()` → `Option<NameConstraintsView>` | PASS | `cert.rs:806`; `struct NameConstraintsView` at `cert.rs:197` |
| `EkuView.is_empty` + `eku_is_empty()` | PASS | populated `cert.rs:570`; helper `cert.rs:1005`; `mod eku_is_empty` tests `cert.rs:1474` (any/other/empty cases) |
| Reuse `SanView.is_empty` | PASS | `cert.rs:469` populates; no new SAN accessor (as specified) |
| `subject_country_values()` → `Vec<String>` | PASS | `cert.rs:828` |
| `subject_country_is_printable_string()` → `Option<bool>` (DER tag 0x13) | PASS | `cert.rs:855`; inspects `attr_value().tag().0 == TAG_NUM_PRINTABLE_STRING` directly on DER |
| `subject_organizational_unit_count()` → `usize` | PASS | `cert.rs:878` |
| `validity_time_encodings()` → `(TimeEncoding, TimeEncoding)` (DER tags 0x17/0x18 + trailing `Z`) | PASS | `cert.rs:902`; `read_time()` `cert.rs:1075` checks `is_utc_time` via tag and `is_zulu` via `content.last() == Some(&b'Z')`; `struct TimeEncoding` `cert.rs:210`; 4 unit tests `cert.rs:1573-1612` |

Both non-trivial DER accessors (country PrintableString, validity time-encoding) inspect raw ASN.1
tags as the task required, with documented approach. No `unwrap`/`panic!` on cert-data paths
(returns `CertError::Der` / `None` / empty).

### 2.4 Constraints

| Constraint | Status | Evidence |
|---|---|---|
| Count/filter test updates (32 / 16 / 12 / 4) | PASS | `registry.rs:643-644` total=32; `:697` rfc5280=16; `:769` cabf_br=12; `:739` hygiene=4; tests green |
| No new dependency | PASS | `crates/linter/Cargo.toml` deps = x509-parser 0.18, der 0.8, oid-registry 0.8, thiserror 2, serde (optional, pre-existing). No additions. ISO-3166 allowlist and wildcard rule are in-module, no crate |
| No existing-fixture regeneration | PASS | All regression suites (hygiene 11, registry 10, not_expired 8, CLI output 12) pass unchanged; brief confirms good.pem/expired.pem byte-identical; `generate.sh` modified only to ADD 18 new recipes |
| Golden-snapshot reconciliation | PASS | 5 CLI snapshots present under `crates/cli/tests/snapshots/`; cli `tests/golden.rs` 8 passed; feature-06 golden in linter suite green |
| `source.rs` / `CertPurpose` / engine unchanged | PASS | only `default_registry()` appended; no new RuleSource/CertPurpose |
| CLI count ripple `(3 passed, 3 not applicable)` → `(7 passed, 9 not applicable)` | PASS | `crates/cli/tests/output.rs:133`; test passes |

---

## 3. Task `touches` + Acceptance-Criteria Audit

### developer-01 (cert.rs) — status done
- `touches: crates/linter/src/cert.rs` — PASS (all 7 accessors + 3 views + EkuView extension present; see §2.3).
- AC: all accessors documented/non-panicking — PASS. EkuView gains is_empty — PASS. DER inspection documented — PASS. `#[cfg(test)]` positive+negative per accessor — PASS (lib unit 226 incl. `eku_is_empty`, `read_time`, country, etc.). No new dep — PASS. clippy/fmt clean — PASS.

### developer-02 (rfc5280 lints) — status done
- `touches`: mod.rs + 9 lint files — PASS, all 9 files present in `lints/rfc5280/` (see §2.1).
- AC: 9 impls across 8 files (SKI file holds 2) — PASS. CA-only/ext-present NotApplicable — PASS (`not_applicable_*` tests). Multi-finding (utc_time two fields) — PASS (impl emits per-field). No panic — PASS. clippy/fmt — PASS.

### developer-03 (cabf_br lints) — status done
- `touches`: mod.rs + dnsname_syntax.rs + 4 single files — PASS (see §2.2).
- AC: 8 impls, cabf_br_ ids, BR citations — PASS. Broad-scoped — PASS. Multi-entry findings — PASS. No new dep (in-module ISO/PSL) — PASS. No panic — PASS. clippy/fmt — PASS. reserved.rs reused not modified — PASS.

### developer-04 (registry.rs) — status done
- `touches: crates/linter/src/registry.rs` — PASS.
- AC: appended at end of each block, order untouched — PASS (`default_registry()` body). Counts 32/16/12/4 — PASS (`registry.rs:643,697,769,739`). New ids in expected lists — PASS (filter tests green). clippy/fmt — PASS.
- NOTE: task body text says "14 → 24" (stale); actual shipped registry is **32**, and the in-file assertions correctly read 32/16/12/4. The stale "24" in the task prose was superseded by tester-06 and the corrected count; the implementation is correct. Non-blocking documentation drift only.

### tester-05 (fixtures + tests) — status done
- `touches`: generate.sh + 18 `.pem` + rfc5280.rs + cabf_br.rs — PASS. All 18 fixtures present in `testdata/`; rfc5280.rs (39) and cabf_br.rs (48) green.
- AC: 18 fixtures, each isolating its rule — PASS (`each_new_rfc5280_fixture_isolates_exactly_one_violation` ok; cabf_br isolation green). SKI-sub-cert asserts Warn — PASS. Existing isolation unchanged — PASS. Golden regenerated — PASS. all gates + generate.sh — PASS. cn_reserved_ip exception documented in test — PASS (fixture present, two-rule approach).
- NOTE: same stale "24-lint registry" prose in task body; the live registry is 32 and tests assert against it correctly.

### tester-06 (CLI golden + count ripple) — status done
- `touches`: 5 snapshot files + output.rs — PASS. All 5 snapshots present; output.rs:133 updated to `(7 passed, 9 not applicable)`.
- AC: snapshots regenerated additively — PASS (cli golden 8 passed). output.rs count `(7 passed, 9 not applicable)` — PASS. full `cargo test` green — PASS. serde/clippy/fmt — PASS.

---

## 4. Spec Artifacts

| Artifact | Present |
|---|---|
| `plan.md` | YES |
| `test-plan.md` | YES |
| `tasks/developer-01..04`, `tester-05`, `tester-06` (6 files) | YES |
| `review.md` (this file) | YES |
| `design.md` | N/A — not expected for this feature |
| `ui-test-report.md` | N/A — **this is a non-UI library/CLI feature**; no UI artifacts are expected or required |

---

## 5. Gaps

**None.** Every requirement, every `touches` file, and every acceptance criterion maps to PASS with
concrete evidence. No PARTIAL/FAIL items; no follow-up task files created.

Two non-blocking observations (documentation drift only, code is correct):
- developer-04 and tester-05 task bodies contain stale "14 → 24" / "24-lint registry" prose. The
  actual shipped registry is **32**, and all live assertions (`registry.rs`, CLI count, golden) are
  correct at 32/16/12/4. tester-06 and the corrected docs already reconcile this. No code impact.

---

## Verdict: **COMPLETE**
