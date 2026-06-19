# Feature 16 — PQC extensions: Phase 3 Integration Review

Reviewer: architect. Verdict: **INTEGRATION OK**. No follow-up tasks created.

> The Phase 5 formal completeness audit is appended at the bottom of this file
> ("Phase 5 — Formal Completeness Audit"). Top-level feature verdict: **COMPLETE**.

## Quality gates (all green)

| Gate | Result |
|------|--------|
| `cargo fmt --check` | PASS (exit 0) |
| `cargo clippy --all-targets -- -D warnings` | PASS (exit 0) |
| `cargo test` (workspace) | PASS — all suites 0 failed (linter unit 581, pqc 21, registry 11, cli inspect 31, cli output 33, cli golden 8, etc.) |
| `cargo test -p linter --features serde` | PASS — 0 failed |

## Out-of-touches edits — adjudication

The orchestrator note referenced `crates/cli/tests/inspect.rs`; the actual edited artifacts are the three inspect **snapshot** files (the `.rs` source was not touched).

- `inspect__good_cert_text__good_info_text.snap`
- `inspect__chain_info__chain_bundle_info_text.snap`
- `inspect__slh_dsa_ca_text__slh_dsa_info_text.snap`

These three are NOT in tester-05's declared `touches` → genuine out-of-touches edits.

Diff content is exactly the expected `[pqc]` n/a-slot growth from the 4 new ML-KEM lints:
- non-PQC certs: `[pqc] (0 passed, 5 not applicable)` → `(0 passed, 9 not applicable)`
- SLH-DSA CA: `[pqc] (5 passed, 0 not applicable)` → `(5 passed, 4 not applicable)`
- plus insta dropping the cosmetic `assertion_line:` header.

No outcome flipped; every cert still reports `OK: no findings`.

**Adjudication: acceptable necessary integration edit, noted as task-hygiene.** Any registry change shifts the per-cert n/a counts in every text/inspect snapshot, so these snapshot updates were unavoidable once the 4 ML-KEM lints registered. The tester correctly updated the parallel `golden__*` snapshots (which WERE in touches, including `chain_bundle`); the three `inspect__*` snapshots are the same class of change and should have been added to tester-05's `touches`. Minor hygiene gap only — no behavioural risk, no re-dispatch warranted.

Note: the `cabf_cs` / `cabf_smime` key_usage `.rs` test-helper edits (new `data_encipherment`/`encipher_only`/`decipher_only` struct fields) were correctly pre-declared in developer-01's `touches` — not out of scope.

## Recipe parity (testdata/generate.sh)

All 5 committed fixtures have a reproducing recipe (basename present in generate.sh): good, unknown_param_set, spki_params_present, bad_key_length, bad_key_usage. generate.sh diff is additions only (+268, 0 deletions).

## No fixture cascade

`git status` / `git diff --stat testdata/`: only the 5 new `pqc_mlkem_*.pem` (untracked) added and generate.sh extended. No pre-existing fixture's bytes changed. `good.pem` runs clean (`OK: no findings`). `pqc_mldsa_good.pem` and `pqc_slhdsa_good.pem` remain clean.

## Self-gating / no code cascade

- 4 ML-KEM lints fire only on `MlKem(_)`: confirmed via runs — they sit in the n/a slot for RSA/EC/ML-DSA/SLH-DSA, and each ML-KEM deviation fixture isolates exactly one `pqc_mlkem_*` error.
- Part-3 (`pqc_key_usage_consistency` now also Errors on dataEncipherment/encipherOnly/decipherOnly) is purely additive on a key already passing the PQC-signature gate. Across all non-mlkem fixtures, only the pre-existing `pqc_bad_key_usage.pem` (intentional ML-DSA deviation) triggers it. No RSA/EC/clean fixture gained an Error/Fatal.

## chain.rs unused-const concern (earlier batch)

Resolved. `CHAIN_PQC_VALID` defined (chain.rs:74) and used (chain.rs:708). `clippy --all-targets -D warnings` clean.

## Count reconciliation

Authoritative per-cert count is **70** (4 hygiene + 16 rfc5280 + 12 cabf_br + 9 cabf_ev + 8 cabf_cs + 12 cabf_smime + **9 pqc**), asserted in registry.rs tests. The only `66`/`61` occurrences are in an explanatory history comment in `registry.rs` ("pre-feature-16 total was 66") — intentional, not stale. No stale `52` / `5 pqc` assertions remain.

---

# Phase 5 — Formal Completeness Audit

Reviewer: architect (orchestrator). Audit date: 2026-06-19.
Method: re-verified every requirement, acceptance criterion, and `touches` file
against the implemented code (Read/Grep at `file:line`), re-ran the gates, and
inspected the committed fixtures with `openssl x509`.

## Gate re-run (all green)

| Gate | Result |
|------|--------|
| `cargo fmt --check` | PASS (exit 0) |
| `cargo clippy --all-targets -- -D warnings` | PASS (exit 0) |
| `cargo test` (workspace) | PASS — every suite 0 failed (linter unit 581, pqc integration 21, registry integration 11, cli output 33, cli inspect 31, cli golden 8, …) |
| `cargo test -p linter --features serde` | PASS — 0 failed (570 unit + suites); the new `PublicKeyAlg::MlKem` variant serialises under the existing derive |

## Requirement / acceptance-criterion → status

### Part 1 — ML-KEM key/cert recognition (dev-01)

| Item | Status | Evidence |
|------|--------|----------|
| `PublicKeyAlg::MlKem(PqcParamSet)` variant added | PASS | `cert.rs:229` |
| `MLKEM_ARC_PREFIX = "2.16.840.1.101.3.4.4."` (kems arc) | PASS | `cert.rs:2119` |
| `classify_mlkem_oid` — `.1/.2/.3` → ML-KEM-512/768/1024 Known; other arc members → Unknown; non-arc → None | PASS | `cert.rs:2140-2167` (slot match 1/2/3; `.contains('.')`/non-numeric/other slot → `Unknown`); tests `cert.rs:3229-3289` |
| Does NOT overload `classify_pqc_oid` (separate sibling fn) | PASS | `classify_pqc_oid` at `cert.rs:2058` keyed on `...3.4.3.`; distinct fn |
| Wired into `public_key_algorithm()` after `classify_pqc_oid` fallthrough | PASS | `cert.rs:981-982` (`classify_pqc_oid(other).or_else(|| classify_mlkem_oid(other))`) |
| Rsa/Ec/MlDsa/SlhDsa/Other unchanged | PASS | match arms unchanged; full suite green; `good.pem` RSA regression assertion in classifier tests |
| Clean fixture classified ML-KEM-768 by openssl | PASS | `openssl x509 -in testdata/pqc_mlkem_good.pem -text` → `Public Key Algorithm: ML-KEM-768` |

### Part 1 — KEM lints + kem_params (dev-02)

| Item | Status | Evidence |
|------|--------|----------|
| `kem_params.rs` table: ML-KEM-512=800, 768=1184, 1024=1568; `expected_mlkem_public_key_len` returns None for unknown | PASS | `kem_params.rs:45-54,65`; tests `kem_params.rs:76-98` |
| `applies_to_mlkem` gate — Applies iff `MlKem(_)` (incl. Unknown), else NotApplicable, Err fails closed | PASS | `pqc/mod.rs:103-110` (`Ok(_) | Err(_) => NotApplicable`) |
| `pqc_mlkem_algorithm_known` — Error on Unknown arc member; id/source/gate | PASS | id `mlkem_algorithm_known.rs:58`, `RuleSource::Pqc:62`, `Severity::Error:47`, gate `:66` |
| `pqc_mlkem_spki_parameters_absent` — Error when SPKI params present | PASS | id `:50`, `RuleSource::Pqc:54`, `Severity::Error:37`, gate `:58` |
| `pqc_mlkem_public_key_length` — Error on length mismatch, names set/expected/actual | PASS | id `:74`, `RuleSource::Pqc:78`, `Severity::Error:63`, gate `:82` |
| `pqc_mlkem_key_usage_consistency` — Error on digitalSignature/keyCertSign/cRLSign; Warn EE missing keyEnc/keyAgree; dataEncipherment NOT flagged; signing-Error regardless of CA | PASS | `mlkem_key_usage_consistency.rs:63-103` (3 Error bits `:64,72,80`; Warn `:91-102` EE-only; no dataEncipherment branch); id `:110`, source `:114`, gate `:118` |
| No `pqc_mlkem_signature_parameters_absent` lint (intentional) | PASS | absent by design (plan §"No ML-KEM signature-parameters-absent lint"); only 4 mlkem_*.rs files exist |
| All 4 lints NotApplicable on non-ML-KEM, Applies on ML-KEM (incl. Unknown) | PASS | `applies_to_mlkem` semantics + `pqc.rs` scoping tests `scoping::*`, `clean_leaves::*` |

### Part 3 — `pqc_key_usage_consistency` gap (dev-03)

| Item | Status | Evidence |
|------|--------|----------|
| Errors on `data_encipherment` (bit 3), `encipher_only` (bit 7), `decipher_only` (bit 8) | PASS | `key_usage_consistency.rs:67-99` (each pushes `Severity::Error`) |
| id/source/gate unchanged; no new lint added | PASS | id/source/`applies_to_pqc` unchanged; registry total +4 (ML-KEM only), part-3 adds 0 |
| Unit tests per bit + multi-finding | PASS | `errors_on_data_encipherment` `:221`, `errors_on_encipher_only` `:233`, `errors_on_decipher_only` `:245`, multi-finding `:288` |
| `KeyUsageView` 3 new bool fields populated from x509-parser | PASS | `cert.rs:104,119,123` (struct), `:635,639,640` (populated in `key_usage()`), `:1771,1775,1776` (alt construction site) |
| 4 existing test-helper literals updated | PASS | cabf_cs/cabf_smime helper sites compile; full suite green (dev-01 `touches`) |

### Registry (dev-04)

| Item | Status | Evidence |
|------|--------|----------|
| 4 ML-KEM lints registered after 5 signature pqc lints, before cabf_br | PASS | `registry.rs:491-494` (immediately after `:479-483`) |
| In-file count 66 → 70 | PASS | `registry.rs:899-900` (`len()==70`, `outcomes==70`); baseline comment `:889-892` |
| pqc bucket 5 → 9; all 9 ids listed | PASS | `registry.rs:924-932` and filter test `:1043-1051`; filter test `pqc_source_filter_runs_exactly_the_pqc_set` `:1025` |
| Integration count 66 → 70 | PASS | `tests/registry.rs:392-393` (`len()==70`); authoritative-count comment `:376-380` (9 pqc) |
| No source-helper / purpose / resolver change | PASS | only `registry.rs` in dev-04 `touches`; `RuleSource::Pqc` already universal |

### Fixtures + tests (tester-05)

| Item | Status | Evidence |
|------|--------|----------|
| 5 `pqc_mlkem_*.pem` committed | PASS | `testdata/pqc_mlkem_{good,unknown_param_set,spki_params_present,bad_key_length,bad_key_usage}.pem` |
| Clean leaf openssl-native (no byte-patch) | PASS | `openssl x509` reads `ML-KEM-768`, `CA:FALSE`, critical Key Usage |
| Recipe parity in generate.sh (all 5 basenames present) | PASS | 21 matches across the 5 basenames; section at `generate.sh:1556+` |
| generate.sh: openssl 3.5+ guard, force_pubkey recipe, byte-patch-invalidates-signature caveat, fragility header | PASS | version guard `generate.sh` ML-KEM section (`MLKEM_OPENSSL_*` ~1641+), recipe header (`-force_pubkey`), caveat ("CA signature no longer verifies … acceptable: structural checker") |
| No fixture cascade (no existing fixture regenerated) | PASS | `git status`/`git diff --stat testdata/` — only 5 new pem + generate.sh additions; `good.pem`/`pqc_mldsa_good`/`pqc_slhdsa_good` clean (Phase-3 record) |
| Named per-lint isolation tests exist & pass | PASS | `pqc.rs`: `mlkem_good_passes_all_mlkem_lints:199`, `..._isolates_mlkem_algorithm_known:322`, `..._spki_parameters_absent:334`, `..._public_key_length:347`, `..._key_usage_consistency:361` |
| Part-3 integration (dataEncipherment via registry) | PASS | `pqc.rs:503 data_encipherment_on_signature_key_errors_through_registry`; bits 7/8 unit-covered (documented in test-plan §Gaps 1) |
| No-cascade both directions incl. no spurious cabf_br | PASS | `pqc.rs:642 raw_run_on_mlkem_leaf_leaves_rsa_ec_hygiene_not_applicable`, `:670 clean_mlkem_leaf_under_resolved_purpose_trips_no_finding` |
| CLI `--source pqc` e2e (ML-KEM + non-PQC) | PASS | `cli/tests/output.rs:834,889,922,742,781` (mlkem_good, default_run, bad_key_usage, non_pqc, json nine outcomes) |
| Golden/inspect snapshots regenerated (only `[pqc]` slot growth) | PASS | Phase-3 record §"Out-of-touches edits" — 3 golden + 3 inspect snaps, `5→9` n/a, no flipped outcome |

## Composite PQC — scoped-out user decision (NOT a gap)

Composite PQC + classical (sigs/KEM) was **deliberately deferred** at the
Phase-1.5 escalation gate, confirmed acceptable by the user. Rationale (plan
Open Question 1): stock OpenSSL 3.6.2 cannot mint a composite SPKI/cert and the
IETF composite drafts carry provisional OIDs, so there is no openssl-native or
honest byte-patch fixture path under the "OpenSSL-only, never cert-bar,
recipe-parity" constraint. It is reserved in plan.md §"Future" with concrete
blockers, not silently dropped. **This is a scope decision, not an incomplete
requirement.**

## Open gaps

None. The two items under test-plan §"Gaps / Deviations" are pre-approved,
documented deviations, not open work:
1. Part-3 bits 7/8 (encipherOnly/decipherOnly) integration — covered at unit
   level (dev-03 `:233,:245`); the representative bit-3 path is integration-
   covered. No committed openssl fixture asserts bits 7/8 (openssl follows the
   LAMPS profile), and the touch budget adds none. Acceptable.
2. The 3 `inspect__*` snapshots were out-of-`touches` but a necessary,
   behaviour-neutral integration edit (per-cert n/a count shift from registering
   4 lints). Adjudicated acceptable in the Phase-3 record. Task-hygiene only.

## Top-level verdict

**COMPLETE**

Every requirement, every acceptance criterion, and every file in every task's
`touches` list is implemented and verified with concrete evidence; all four
gates (fmt, clippy, test, serde) are green; composite is a confirmed scope cut,
not a gap. No follow-up task files created.
