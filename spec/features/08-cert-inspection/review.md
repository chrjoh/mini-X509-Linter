# Completeness Review — Feature 08: Certificate Inspection (`--info`)

**Phase 5 (Mandatory Completeness Review).** This gate decides whether feature 08 is DONE.

- **Verdict: COMPLETE**
- **Open gaps: none**
- Reviewer: architect
- Inputs re-read: `plan.md`, `test-plan.md`, all 3 task files (status `done`), and the live code under `crates/linter/src/cert.rs`, `crates/cli/src/inspect.rs`, `crates/cli/src/main.rs`, `crates/cli/tests/inspect.rs`, `testdata/`.

---

## 1. Per-requirement verification (from `plan.md` §Requirements)

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| R1 | `--info` flag: long-only, no short alias | **PASS** | `crates/cli/src/main.rs:231` `#[arg(long)] info: bool` — no `short`. Clap auto `-h`/`-V` only; no collision. |
| R2 | When set, print summary block for the leaf, then **still run + print** the lint report | **PASS** | `main.rs:407-446` (single), `:501-516` (chain), `:701-712` (from-host) all render summary then append the existing lint report. Test `good_cert_text::info_does_not_suppress_the_lint_report` (inspect.rs:106) asserts `[rfc5280]` + `OK: no findings` follow the summary; SLH-DSA snapshot lines 19-26 show the lint report after the summary. |
| R3 | `--info` does not change the exit code | **PASS** | No exit-code path touched in `run`; exit code stays `--fail-on`-driven. Test `default_unchanged::info_does_not_change_the_exit_code` (inspect.rs:346) asserts `with`/`without` status codes are equal and `Some(0)`. |
| R4 | Default behaviour (flag omitted) byte-for-byte unchanged (text + JSON) | **PASS** | `main.rs` guards every branch on `if args.info` / `if info`; the `else` arms are the original code verbatim. Tests `default_unchanged::default_text_has_no_summary_block` (inspect.rs:324) and `default_json_is_a_bare_lint_array` (inspect.rs:334). Pre-existing `golden__*.snap` files unmodified (git status: untracked = only new `inspect__*` snaps). |
| R5 | No clap conflict with `--format`/`--source`/`--min-severity`/feature-06 flags; claims no short flag | **PASS** | `info: bool` is long-only; `cargo build`/clippy compile clean; all 17 inspect tests + 66 main.rs unit tests pass. |
| R6.1 | Summary field 1 — Version (`v3`) | **PASS** | `inspect.rs:221` `version_label` (0→v1..2→v3); snapshot `Version: v3` (slh snap line 7; json `"version":"v3"`). |
| R6.2 | Field 2 — Serial, hex, uppercase, stable format | **PASS** | `cert.rs:1642 serial_hex` → uppercase colon-separated (`format!("{b:02X}")`); snapshot `Serial: 01:2D`; unit test `good_cert_serial_hex_is_uppercase_colon_separated` (cert.rs). |
| R6.3 | Field 3 — Subject DN (RFC 4514) | **PASS** | `cert.rs:1605 subject_rfc4514` via `to_string_with_registry`; snapshot `CN=SLH-DSA Test Root, C=SE, O=mini-x509-linter testdata`; test `subject_equals_issuer_for_self_signed_root` (inspect.rs:239). |
| R6.4 | Field 4 — Issuer DN (RFC 4514) | **PASS** | `cert.rs:1622 issuer_rfc4514`; snapshot issuer line 10; same test. |
| R6.5 | Field 5 — Validity (cert's own dates, no wall-clock) | **PASS** | `inspect.rs:247-256` uses `not_before()`/`not_after()` only; slh snap `Jan 1 00:00:00 2026 → 2126`; determinism test (inspect.rs:368). |
| R6.6 | Field 6 — Signature algorithm name if known, else raw OID + `(unknown)` label | **PASS** | `cert.rs:1661 signature_algorithm` (OID always; name best-effort); `inspect.rs:98 AlgorithmDisplay::render` → `name (oid)` or `oid (unknown)`. Unit test `unknown_name_shows_raw_oid_with_label` (inspect.rs:550). |
| R6.7 | Field 7 — Public key alg/params, size/curve when available, graceful unknown | **PASS** | `cert.rs:1685 public_key_info` (key_bits via `key_size()`, 0→None; curve via `ec_named_curve`); json snap shows RSA `key_bits:2048`; slh snap shows PQC with no size (graceful). |
| R6.8 | Field 8 — BasicConstraints: CA bool, pathLen, critical | **PASS** | `inspect.rs:142 BasicConstraintsDisplay::render` (`CA:<bool>`, optional `pathlen:`, criticality); slh snap `CA:true (critical)`; test `basic_constraints_shows_ca_true_critical` (inspect.rs:219). |
| R6.9 | Field 9 — KeyUsage: **every** asserted bit by name + critical | **PASS** | `cert.rs:1727 key_usage_bits` exposes all 9 bits + critical; `inspect.rs:404 key_usage_names` maps all 9 in RFC bit order; slh snap `Certificate Sign, CRL Sign (critical)`; test `key_usage_lists_exactly_cert_sign_and_crl_sign_critical` (inspect.rs:186) also asserts the 7 unasserted bits are absent. |
| R6.10 | Field 10 — SAN: each entry (type+value) + critical | **PASS** | `cert.rs:1761 san_entries` + `general_name_view` (cert.rs:1812, all 10 GeneralName variants); `inspect.rs:194 SanDisplay::render`; slh snap `DNS:slh-dsa-test-root (not critical)`; test `san_entry_present` (inspect.rs:229). |
| R7 | PQC-friendliness: `signature_algorithm()` returns raw OID when name unknown; degrade gracefully; never error/panic/omit; test asserts on OID presence | **PASS** | `cert.rs:1665` `oid_name(...).or_else(|| pqc_name_for_oid(...))` — OID always set, name best-effort. `pqc_name_for_oid` (cert.rs:1799) reuses feature-13 `classify_pqc_oid`. Test `signature_algorithm_shows_oid_and_enriched_name` (inspect.rs:148) asserts OID presence (load-bearing) + enriched name + never `(unavailable)`. |
| R8 | Determinism: fixed field order, no extra timestamps, snapshot-testable | **PASS** | `inspect.rs:431 render_summary_text` fixed order; 3 `insta` snapshots committed; tests `has_stable_field_order` (inspect.rs:493), `is_deterministic` (inspect.rs:528), `text_summary_is_byte_identical_across_runs` (inspect.rs:368). |
| R9 | JSON: `--info --format json` → `{ "summary": {…}, "lints": [ … ] }`; lints shape preserved verbatim | **PASS** | `main.rs:446 render_info_json` (single), `:572 render_chain_info_json` (chain), `:712` (from-host adds `summary` key). Tests `info_json_has_summary_and_lints_keys` (inspect.rs:258), `lints_array_matches_bare_feature_02_shape` (inspect.rs:279) asserts `env["lints"] == bare` verbatim + the 4 per-outcome keys. JSON summary snapshot committed. |

---

## 2. Per-task `touches` + acceptance-criteria verification

### Task 01 — Cert facade inspection accessors (`crates/linter/src/cert.rs`) — status: done

`touches: [crates/linter/src/cert.rs]` — file modified; diff is **521 insertions, 0 deletions** (purely additive).

| Acceptance criterion | Status | Evidence |
|----------------------|--------|----------|
| All listed accessors + view structs exist, documented (`///` + `# Errors`), owned returns only | **PASS** | `subject_rfc4514`/`issuer_rfc4514`/`serial_hex`/`signature_algorithm`/`public_key_info`/`key_usage_bits`/`san_entries` (cert.rs:1605-1776), all return owned `String`/`Vec`/owned structs; structs `AlgorithmId`/`PublicKeyInfo`/`KeyUsageBits`/`SanEntries`/`GeneralNameView` (cert.rs:301-391) with `///` + `# Errors`. |
| `key_usage_bits` exposes ALL nine bits + critical | **PASS** | `KeyUsageBits` (cert.rs:339-361) has all 9 bits + `critical`; populated at cert.rs:1731-1742. |
| `san_entries` → one owned `GeneralNameView` per entry, stable kind/value | **PASS** | cert.rs:1761; `general_name_view` (cert.rs:1812) covers all 10 variants. |
| `signature_algorithm`/`public_key_info` return raw OID + `name=None` for unknown; never error/panic on PQC | **PASS** | cert.rs:1665, 1691 OID always; PQC enrichment best-effort; `Unknown` slot → `None`. |
| New structs derive `Serialize` only under `serde` feature | **PASS** | `#[cfg_attr(feature = "serde", derive(Serialize))]` on each (cert.rs:302, 319, 338, 370, 385). |
| No new crate dependencies | **PASS** | `git diff crates/linter/Cargo.toml` empty (not in changed-files list); reuses `oid-registry`/`x509-parser`. |
| `#[cfg(test)]` unit tests for new accessors against good.pem | **PASS** | `mod feature08_inspection_accessors` — 7 tests pass (subject/issuer/serial_hex/signature_algorithm/public_key_info/key_usage_bits/san_entries). |
| `cargo test` / `clippy -D warnings` / `fmt --check` pass | **PASS** | See §4 gate results. |

### Task 02 — `--info` flag + summary renderer (`crates/cli/src/inspect.rs` NEW, `crates/cli/src/main.rs`) — status: done

`touches: [crates/cli/src/inspect.rs, crates/cli/src/main.rs]` — `inspect.rs` created; `main.rs` modified (131 ins / 13 del; all deletions are `if/else`-wrapping of original arms, original behaviour preserved in `else`).

| Acceptance criterion | Status | Evidence |
|----------------------|--------|----------|
| `--info` prints summary, then still runs + prints lint report | **PASS** | R2 above. |
| Long-only, no short alias, no clap conflict; omitting it = byte-for-byte unchanged (text + JSON) | **PASS** | R1, R4, R5. |
| Exact stable field order; no extra timestamps | **PASS** | R8; `render_summary_text` (inspect.rs:431-476). |
| KeyUsage lists every asserted bit + criticality; SAN every entry + criticality | **PASS** | R6.9, R6.10. |
| Unknown (PQC) sig/pubkey alg render raw OID + label, never error/panic | **PASS** | R7; `AlgorithmDisplay::render` (inspect.rs:98). |
| `--info --format json` → `{summary, lints}`; lints matches feature 02 exactly | **PASS** | R9. |
| `--info` does not alter exit code | **PASS** | R3. |
| `cargo test` / `clippy -D warnings` / `fmt --check` pass | **PASS** | §4. |

### Task 03 — PQC fixture + inspection tests (`testdata/slh_dsa_root_ca.pem`, `testdata/generate.sh`, `crates/cli/tests/inspect.rs`) — status: done

`touches` all present: `slh_dsa_root_ca.pem` (new, 11267 bytes), `generate.sh` (modified, +42/−0), `crates/cli/tests/inspect.rs` (new) + 3 `insta` snapshots.

| Acceptance criterion | Status | Evidence |
|----------------------|--------|----------|
| Fixture openssl-generated (recipe in generate.sh), NOT cert-bar; provenance in test header | **PASS** | generate.sh adds `openssl genpkey -algorithm SLH-DSA-SHA2-128s` + `req -x509` with the exact addext recipe; test header inspect.rs:12-31 documents openssl/NOT-cert-bar + OID `2.16.840.1.101.3.4.3.20`. |
| Text summary snapshots for good.pem + PQC CA stable/deterministic | **PASS** | `inspect__good_cert_text__good_info_text.snap`, `inspect__slh_dsa_ca_text__slh_dsa_info_text.snap` committed; determinism test passes. |
| Unknown (PQC) algorithm renders raw OID + sensible label, no crash/empty | **PASS** | R7; OID-presence assertion (inspect.rs:157), never-`(unavailable)` assertion (inspect.rs:168). |
| KeyUsage lists every asserted bit + criticality (PQC CA: Cert Sign, CRL Sign) | **PASS** | R6.9; inspect.rs:186 also asserts unasserted bits absent. |
| SAN, BasicConstraints, subject/issuer DN render as expected for PQC CA | **PASS** | inspect.rs:219/229/239; snapshot lines 9-17. |
| `--info --format json` → `{summary, lints}`; lints matches feature 02 | **PASS** | R9. |
| `--info` does NOT suppress lint report, does not change exit code | **PASS** | R2, R3. |
| Default (no `--info`) text + JSON unchanged | **PASS** | R4. |
| `cargo test` / `clippy -D warnings` / `fmt --check` pass | **PASS** | §4. |

**Fixture properties (from committed snapshot, openssl recipe-driven):** pinned serial `01:2D`, fixed validity `Jan 1 2026 → Jan 1 2126`, `CA:true (critical)`, `Certificate Sign, CRL Sign (critical)`, `DNS:slh-dsa-test-root`, subject == issuer. All match the plan/test-plan expectations.

---

## 3. Spec artifacts present

| Artifact | Status |
|----------|--------|
| `spec/features/08-cert-inspection/plan.md` | **PRESENT** |
| `spec/features/08-cert-inspection/test-plan.md` | **PRESENT** (two stale lines — SAN value + `(unknown)`-label description — already corrected in prior phase) |
| `tasks/01-cert-facade-inspection-accessors.md` | **PRESENT** (status: done) |
| `tasks/02-cli-info-flag-and-summary-renderer.md` | **PRESENT** (status: done) |
| `tasks/03-pqc-fixture-and-inspect-tests.md` | **PRESENT** (status: done) |
| `design.md` | **N/A — correct** (CLI feature, no UI; no design doc warranted) |
| `ui-test-report.md` | **N/A — correct** (no UI surface) |

---

## 4. Quality-gate results

| Gate | Command | Result |
|------|---------|--------|
| Format | `cargo fmt --check` | **PASS** (exit 0) |
| Clippy (default) | `cargo clippy --all-targets -- -D warnings` | **PASS** (exit 0) |
| Clippy (fetch) | `cargo clippy -p cli --all-targets --features fetch -- -D warnings` | **PASS** (exit 0, forced rebuild — `fetch` is a `cli`-crate feature, so `-p cli` is the correct scope) |
| Tests (workspace) | `cargo test` | **PASS** — 0 failed across all suites. Inspect: 17 integration + 12 src-unit + 7 feature08 cert.rs accessor tests. Linter lib: 482 passed. |
| Tests (cli + fetch) | `cargo test -p cli --features fetch` | **PASS** — main.rs 66, exit_codes 12, golden 8, inspect 17, output 20, purpose 15, save 8; 0 failed. |

---

## 5. Architecture-invariant confirmations

| Invariant | Status | Evidence |
|-----------|--------|----------|
| `KeyUsageView` / `SanView` UNMODIFIED (cert.rs diff additive) | **CONFIRMED** | `git diff --numstat crates/linter/src/cert.rs` = `521 0` (zero deletions); removed-line scan empty. New `KeyUsageBits` / `SanEntries` added ALONGSIDE the untouched lint views. |
| Default output unchanged + golden snapshots untouched | **CONFIRMED** | `golden__*.snap` not in git-changed set; only new `inspect__*.snap` are untracked additions. Default-unchanged tests pass. |
| SLH-DSA fixture openssl-generated + no existing fixture regenerated | **CONFIRMED** | Only `slh_dsa_root_ca.pem` is new in `testdata/`; `generate.sh` diff is +42/−0 (additive recipe); no other `.pem` modified. Recipe uses `openssl genpkey/req -x509`, never cert-bar. |
| PQC name enrichment present (reuses feature-13 classification) | **CONFIRMED** | `pqc_name_for_oid` (cert.rs:1799) → `classify_pqc_oid` (feature 13); snapshot shows `SLH-DSA-SHA2-128s (2.16.840.1.101.3.4.3.20)` for both signature + public key. |
| No engine change (Registry / Lint trait / default_registry untouched) | **CONFIRMED** | No registry/source/finding files in the changed-files set; 482 linter tests + golden tests unchanged and passing. |

---

## 6. Verdict

**COMPLETE.** Every `plan.md` requirement (R1–R9, including all 10 summary fields), every file in each task's `touches` list, and every acceptance criterion across tasks 01–03 maps to **PASS** with concrete code/test evidence. All five quality gates pass. All architecture invariants hold. Spec artifacts are present; `design.md`/`ui-test-report.md` are correctly N/A for a UI-less CLI feature.

**Open gaps: none.** No follow-up task files created.
