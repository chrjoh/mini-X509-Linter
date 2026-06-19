# Phase 5 — Completeness Review: Feature 15 (Chain-Aware Lints)

**Date:** 2026-06-19
**Reviewer:** architect (orchestrator gate)
**Verdict:** **COMPLETE** (one trivial documentation nit tracked as a follow-up; not gating)

This gate re-verifies every requirement in `plan.md`, every acceptance criterion across
all 6 task files (developer-01/02/03/05, tester-04/06 — all `status: done`), the resolved
Phase-3 broken-chain bug, and all quality gates against the real code + test outputs.

---

## 1. Quality Gates (all green)

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --check` | **PASS** (exit 0) |
| Clippy (all) | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **PASS** (exit 0) |
| Tests (default) | `cargo test` | **PASS** — all suites ok, 0 failed (lib 539 + chain integ 32 etc.; CLI suites incl. golden, from_host gated) |
| Linter + verify | `cargo test -p linter --features verify` | **PASS** — lib 539, `tests/chain.rs` 32, all other integ green; 0 failed |
| CLI + fetch | `cargo test -p cli --features fetch` | **PASS** — incl. `from_host.rs` 8 tests, 0 failed |
| Supply chain | `cargo audit` | **PASS** (exit 0) — 1134 advisories loaded, 136 deps scanned, **no vulnerabilities**; no advisory hits `ring` / `fips204` / `fips205` |

**Feature-gating property (dependency containment), independently verified:**
- `cargo tree -p linter -e normal` (default) → **NO** `ring`/`fips204`/`fips205`/`aws-lc`. Core crate stays dependency-light. **PASS**
- `cargo tree -p linter --features verify -e normal` → `fips204 v0.4.6`, `fips205 v0.4.1`, `ring v0.17.14` (versions match the plan's pins). **PASS**

---

## 2. Spec Artifacts

| Artifact | Present | Note |
|---|---|---|
| `plan.md` | ✅ | 926 lines, full spec + Open Decisions + Ripple Flag + Sequencing |
| `test-plan.md` | ✅ | full fixtures table, 4 load-bearing properties, exit criteria |
| `tasks/developer-01…` | ✅ | cert facade accessors |
| `tasks/developer-02…` | ✅ | trait/registry/build_chain/source/lints/verify |
| `tasks/developer-03…` | ✅ | CLI wiring |
| `tasks/developer-05…` | ✅ | broken-chain surfacing fix |
| `tasks/tester-04…` | ✅ | fixtures + tests + golden regen |
| `tasks/tester-06…` | ✅ | flip OBSERVED + reconcile chain_bundle + de-flake |
| `design.md` | N/A (correct) | no UI — no design artifact required |
| `ui-test-report.md` | N/A (correct) | CLI + library only, no UI |

---

## 3. Per-Requirement Verification (plan.md → code)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| R1 | `ChainLint` trait: ordered-pair, object-safe, deterministic, network-free, panic-free; per-cert `Lint`/`Registry`/`default_registry` UNCHANGED | **PASS** | `chain.rs:61-99` trait (`id`/`source`/`check`/`check_with_depth`/`is_construction_driven`); `lib.rs:64-79` `Lint` trait untouched; `registry.rs` not in any task `touches` |
| R2 | `RuleSource::Chain` (serde `chain`), at END of enum, NOT folded into `*_sources()` | **PASS** | `source.rs:47` `Chain` last after `Hygiene`; `source.rs:16` `rename_all="snake_case"`; per-cert filter-count tests unchanged (`registry.rs` 11 tests green) |
| R3 | Chain pass runs only on ≥2 presented certs via `--chain` OR `--from-host`; single-cert/default byte-for-byte unchanged | **PASS** | `chain.rs:515-518` `run` returns empty for `<2`; CLI `main.rs:599` (`--chain`) + `main.rs:893` (`--from-host`) gate `certs.len()>=2 && selected.contains(Chain)`; `run`/`empty_for_*` unit tests |
| R4 | Chain is BUILT (order-independent): DN + AKI/SKI linkage, disorder→Notice, broken→Error/Warn, missing-root→Notice, deterministic tie-breaks | **PASS** | `build_chain` `chain.rs:326-453`; `is_issued_by` `:250-268` (Name-DER + AKI/SKI confirm); tie-breaks by ascending index `:344-374`; tests `shuffled_chain_is_reordered_with_disorder_notice`, `running_twice_on_shuffled_input_is_identical` |
| R5 | Findings attach to a link labelled `Certificate N → Certificate N+1` in BUILT order | **PASS** | `ChainLinkReport.subject_index/issuer_index` original-input indices `chain.rs:143-153`; CLI builds labels via `render_chain_section`/`chain_label` (`main.rs:634`) |
| R6 | Five structural lints dependency-free, always registered | **PASS** | `lints/chain/{subject_issuer_dn_match,not_in_order,issuer_not_in_chain,aki_ski_match,issuer_is_ca,path_len_respected,validity_nested}.rs`; `default_chain_registry` `chain.rs:737-745` registers 7 unconditionally |
| R7 | `chain_signature_valid` behind `verify`; 8th lint when on, absent when off; CLI default-on | **PASS** | `chain.rs:747-748` `#[cfg(feature="verify")]` push; `Cargo.toml:40` `verify` feature; `cli/Cargo.toml` enables `["serde","verify"]`; registry tests assert 7/8 |
| R8 | Sig-verify fail-OPEN: fail→Error, success→pass, unsupported→Notice | **PASS** | `subject_signature.rs:77-86` Verified→`[]`, Failed→Error, Unsupported→Notice; `verify.rs:42-49,73-139` fail-open `Unsupported` on unknown OID / unparseable SPKI |
| R9 | Graceful degradation: accessor `Err` → no finding, never panic/abort | **PASS** | `is_issued_by`/`is_self_signed` `let-else → false`; each link lint degrades on `Err` (verified in lint files + `chain.rs` graceful-degradation integ test) |
| R10 | 8 cert.rs raw-bytes accessors, `Result<_,CertError>`, non-panicking, feature-independent | **PASS** | `cert.rs:1797/1815/1835/1865/1893/1910/895/1934` for subject/issuer name DER, SKI/AKI bytes, tbs_der, signature_value_bytes, `signature_algorithm_oid`→`String` (documented non-borrowing choice), issuer_spki_bytes; all plain methods (pass under default + verify) |
| R11 | `verify` module isolates all crypto; OID→backend dispatch unit-testable | **PASS** | `verify.rs:36` `use ring::signature`; `:176` PQC dispatch to fips204/fips205; `VerifyOutcome` enum `:42-49`; in-file dispatch tests |
| R12 | `--from-host` presented chain runs the pass after the verdict; root-absent→Notice; trust-vs-lint separation | **PASS** | `run_from_host` `main.rs:893-895`; doc `:794` notes root-absent Notice + intermediates-fail-to-parse dropped; `from_host.rs` tests incl. `verdict_invalid_while_chain_lints_pass` |
| R13 | Chain findings fold into exit code | **PASS** (re-verified e2e) | `--chain chain_missing_middle.pem --fail-on error` → **exit 1**; `chain_valid.pem` → **exit 0**; `chain_severity_counts` fold in `main.rs` |
| R14 | JSON `{ certificates, chain }` envelope; per-cert path + default output unchanged | **PASS** | e2e: broken-chain JSON top-level keys `['certificates','chain']`, `chain` is a list; single-cert JSON unchanged (output.rs tests) |
| R15 | openssl-only fixtures (classical + PQC + broken + bad-signature + shuffled) | **PASS** | 13 `testdata/chain_*.pem` present incl. `chain_classical_valid`, `chain_pqc_valid`, `chain_bad_signature`, `chain_unsupported_sig_alg`, `chain_shuffled`, `chain_missing_middle`; generated via `generate.sh` (openssl), in-file unit fixtures under `src/chain_testdata/` |

---

## 4. Resolved Phase-3 Gap (broken-chain silent-pass) — fix evidence

**Bug (Phase-3 NO-GO):** `ChainRegistry::run` returned an empty `Vec` whenever the built
chain collapsed to `<2` links, silently dropping construction diagnostics (incl. the
`chain_subject_issuer_dn_match` Error). Exit 0 even with `--fail-on error`.

**Fix (developer-05), verified in code + e2e:**
- `chain.rs:515-539` — `run` keeps the `<2 certs` early-return but, when `certs.len()>=2`
  and the built order has no links, emits ONE **chain-level** `ChainLinkReport`
  (`subject_index == issuer_index == CHAIN_LEVEL_INDEX`, `chain.rs:129`) carrying
  `construction.leaf + construction.top` outcomes exactly once (no duplication).
- `ChainLinkReport::is_chain_level()` `chain.rs:162-164`; CLI renders it under a
  `(whole chain)` heading WITHOUT a misleading link arrow.
- In-file unit tests: `missing_middle_two_cert_set_surfaces_dn_match_error`,
  `unlinkable_two_cert_set_surfaces_dn_match_error`, `broken_set_run_is_deterministic`,
  `well_formed_chain_emits_no_chain_level_report` (happy path unchanged).

**Independent end-to-end re-verification (this gate):**
```
$ mini-x509-lint --chain testdata/chain_missing_middle.pem --fail-on error
... Chain checks: / (whole chain) /
  error [chain_subject_issuer_dn_match] ... (unlinkable / extra certificate)
  error [chain_subject_issuer_dn_match] ... (missing middle link / broken chain)
EXIT=1                                        ← was exit 0 (the bug)

$ mini-x509-lint --chain testdata/chain_valid.pem --fail-on error
EXIT=0   (Chain checks: section present)       ← clean positive control
```
JSON broken-chain shape: `{ "certificates":[…], "chain":[ {outcomes:[…]} ] }` — chain-level
construction findings given a deterministic home in the `chain` array. **GAP RESOLVED.**

**tester-06 reconciliation, verified:**
- Golden `golden__text_output__chain_bundle_text.snap:28-30` now carries `Chain checks:` /
  `(whole chain)` / the `chain_subject_issuer_dn_match` Error (per-cert bytes above unchanged).
- OBSERVED/gap-pinning assertions flipped (no `OBSERVED` wording remains; suites green).
- `chain_bundle.pem` reconciled as the broken-bundle exit-1 case; `chain_valid.pem` is the
  clean exit-0 positive control.
- from_host validity-nesting de-flaked (`from_host.rs` 8 tests pass deterministically).

---

## 5. Per-Task Acceptance-Criteria Roll-up

| Task | Criteria | Status |
|---|---|---|
| developer-01 (8 accessors) | all 7 criteria | **PASS** — accessors present, `None`-not-`Err` for absent SKI/AKI, self-signed `subject==issuer` DER test, feature-independent, existing accessors intact, clippy clean |
| developer-02 (trait/registry/build_chain/source/7 lints/verify) | all 8 criteria | **PASS** — types in `chain.rs` re-exported from `lib.rs`; build_chain linkage + diagnostics; `Chain` last; per-cert path unchanged; 7 always-on lints + RFC cites; `verify` feature + `verify.rs`/`subject_signature.rs` gated; 7/8 counts asserted; gates clean |
| developer-03 (CLI wiring) | all 8 criteria | **PASS** — `cli/Cargo.toml` `["serde","verify"]`; `--source chain`, `SOURCE_ORDER`/`ALL_SOURCES` Chain last; pass over `--chain` + `--from-host`; root-absent Notice; JSON envelope; exit-code fold; clippy/fmt clean |
| developer-05 (broken-chain fix) | all 12 criteria | **PASS** — see §4; `run` surfaces `<2`-link construction findings once, deterministic, chain-level render, JSON home, happy path unchanged, default build no crypto deps, in-file test added |
| tester-04 (fixtures/tests/golden) | all 8 criteria | **PASS** — 13 openssl fixtures; order-independence + root-absent proven; clean/classical/PQC pass, bad-sig Error, unsupported Notice; `chain.rs` 32 tests; CLI e2e + `from_host.rs`; golden regen; audit recorded |
| tester-06 (flip/reconcile/de-flake) | all 6 criteria | **PASS** — OBSERVED flipped, chain_bundle reconciled, golden regenerated, from_host de-flaked, all listed gates green, no gap-pinning assertion remains |

---

## 6. Noted Deviations (all acceptable, documented)

1. **In-file unit-test fixtures live in `crates/linter/src/chain_testdata/`** (`link_leaf.pem`,
   `link_inter.pem`, `link_root.pem`, `link_stray.pem`), consumed by `chain.rs`'s
   `#[cfg(test)]` module via `include_bytes!`. openssl-generated, independent of cert-bar —
   consistent with the "openssl-only oracle" rule. Acceptable: keeps the unit tests
   self-contained without depending on the workspace `testdata/` integration fixtures.
2. **`from_host.rs` mints chains with openssl `s_server`-style issuance** (root/intermediate/leaf
   via sequential `openssl` invocations) rather than rcgen; tests self-skip when openssl is
   absent. Acceptable and matches the hermetic-server intent.
3. **Cross-feature touch of feature-14 `inspect.rs` + its snapshots** — `inspect.rs:383-467`
   and `inspect__chain_info__*` snapshots were updated because feature-14's `--chain --info`
   path also runs over `chain_bundle.pem`, which now correctly surfaces the
   `chain_subject_issuer_dn_match` Error under `(whole chain)`. This was a NECESSARY
   reconciliation (the pre-feature snapshots pinned `chain_bundle` as all-pass). Within the
   intentional-golden-churn boundary; no single-cert golden changed.

---

## 7. Documentation Gap (non-gating; follow-up created)

The plan's **Ripple Flag** said the README still states "no chain-aware lints". Verified at
this gate: `README.md:401-402` ("linted independently — there are no chain-aware lints") and
`README.md:518-522` (Scope bullet: "no chain-aware lints: no path-building, no issuer/subject
linkage checks, and no signature verification against the issuer") are now FALSE — contradicted
by the shipped feature.

This is a trivial documentation nit, explicitly deferred out of the code/test tasks by the
Ripple Flag and noted in tester-04's Notes. Per the gate rules it is NOT hand-fixed; a tiny
follow-up doc task was created:
`spec/features/15-chain-aware-lints/tasks/developer-07-readme-scope-note-flip.md`
(`status: pending`, touches `README.md` only). It does not block the COMPLETE verdict —
every code/test requirement and quality gate passes.

---

## 8. Verdict

**COMPLETE.**

All 15 plan requirements PASS; all 6 task files' acceptance criteria PASS; the Phase-3
broken-chain silent-pass bug is RESOLVED and independently re-verified end-to-end (broken
chain → exit 1 with the `(whole chain)` chain-level report; clean chain → exit 0). Every
quality gate is green: `cargo fmt --check`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings`, `cargo test`, `cargo test -p linter --features verify`,
`cargo test -p cli --features fetch`, and `cargo audit`. The default `linter` build pulls in
no crypto dependencies; `verify` pins `ring 0.17.14` / `fips204 0.4.6` / `fips205 0.4.1`.

The only outstanding item is a one-line README Scope-note flip, tracked as the pending
follow-up `developer-07` — a documentation nit, not a functional gap.
