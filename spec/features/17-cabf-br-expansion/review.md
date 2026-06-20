# Feature 17 — cabf_br expansion: Integration & Completeness Review

**Verdict: COMPLETE**

Reviewer: architect. Date: 2026-06-20. All five tasks (developer-01..03, tester-04,
tester-05) report `status: done`. This is the workflow-ending gate.

---

## 1. Gate results (verbatim)

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --check` | `=== FMT EXIT: 0 ===` (no output) |
| Clippy | `cargo clippy --all-targets -- -D warnings` | `Finished dev profile ...` / `=== CLIPPY EXIT: 0 ===` |
| Tests (workspace) | `cargo test` | all suites `ok`, `0 failed`; `=== TEST EXIT: 0 ===` |
| Tests (serde) | `cargo test -p linter --features serde` | lib `636 passed; 0 failed`, `cabf_br.rs 93 passed`, all suites `ok`; `=== SERDE EXIT: 0 ===` |

Key per-suite counts from `cargo test`: linter lib `647 passed`, `tests/cabf_br.rs 93 passed`,
`tests/registry.rs 11 passed`, cli `tests/golden.rs 8`, `tests/inspect.rs 31`, `tests/output.rs 33`.
All green.

---

## 2. Requirement / acceptance-criterion → evidence matrix

| Requirement / AC | Status | Evidence |
|---|---|---|
| All 12 new `cabf_br_*` lints shipped (none cut), broad-scoped | **PASS** | `registry.rs:519-530` registers all 12 `Box::new(cabf_br::...)`; verbose CLI lists all 12 new rows (`--verbose good.pem`) |
| Severities: lints 7/8/12 = Warn, rest = Error | **PASS** | Per-fixture finding dump: `san_present`, `certificate_policies_present`, `basic_constraints_present` emit `warn`; the other 9 emit `error` (see §3) |
| ONE new facade accessor `rsa_public_exponent()` + `RsaExponentView`; others reuse existing | **PASS** | `cert.rs:1110 fn rsa_public_exponent`, `cert.rs:287 struct RsaExponentView` with `is_odd`/`at_least_65537`/`at_most_2_256_minus_1`; `# Errors` doc at `cert.rs:1097` |
| good.pem regenerated ONCE, PINNED key + DV OID, finding-free; SKI/serial byte-stable | **PASS** | `openssl` SKI `80:31:B9:6A:1E:A6:B8:88:63:FC:6C:BF:58:97:4F:67:6D:CD:E0:83`, `serial=11` (hex 17); CLI text/json/verbose = "OK: no findings", `[cabf_br] (24 passed, 0 not applicable)`; `testdata/keys/good.key` committed; `generate.sh:165 GOOD_KEY`, `:286-291` certificatePolicies DV OID |
| good.pem finding-free across all 12 (lints 8/9 positive passes, no Warn) | **PASS** | verbose: `pass cabf_br_certificate_policies_present`, `pass cabf_br_certificate_policies_reserved_oid`, all 24 rows `pass`; json `findings: []` everywhere |
| `inspect__*` snapshots + README `--info` good.pem example unchanged (SKI stable) | **PASS** | `inspect__good_cert_text` + `inspect__json_envelope` both carry SKI `80:31:B9:6A...`; README:370 `--info` good.pem example carries `80:31:B9:6A...`; both equal the actual fixture SKI |
| No OTHER existing fixture's DER regenerated; only additive Warn(s) | **PASS** (see §6 caveat) | Snapshots reconciled to current fixtures; the only additive non-Error on policies-free leaves is `cabf_br_certificate_policies_present` Warn (asserted in `internal_san_fixture_yields_two_error_findings_from_one_lint`, `cabf_br.rs:1387`) |
| `cabf_br_missing_serverauth.pem` reconciled as documented two-rule co-fire | **PASS** | `cabf_br.rs:1479 missing_serverauth_fixture_trips_both_serverauth_rules` asserts `[server_auth_present, server_auth_required]` |
| Registry counts: total 70→82, cabf_br 12→24, others unchanged | **PASS** | `registry.rs:918-919 assert_eq!(... 82)`, `:1133 assert_eq!(outcomes.len(), 24)`, `:1206/:1244/:1285` other source filters; `tests/registry.rs:393-394 assert_eq!(... 82)`; CLI `[cabf_br] (24 passed...)` |
| 12 new openssl fixtures, recipe parity in generate.sh, each isolating its rule | **PASS** | all 12 `testdata/cabf_br_*.pem` present + `keys/good.key`; each has a `generate.sh` recipe (see §5); isolation asserted in `cabf_br.rs:1406` |
| 2 documented intentional co-fires asserted as multi-finding (not isolation) | **PASS** | `cabf_br.rs:1444 leaf_path_len_fixture_trips_both_br_and_rfc_path_len_rules`; `:1463 eku_no_server_auth_fixture_trips_both_serverauth_rules` |
| All affected golden snapshots additive/order-preserving; inspect unchanged; output.rs counts | **PASS** | `golden__verbose_output__good_verbose_text.snap` = 24 cabf_br rows; `good_text` summary `(24 passed, 0 not applicable)`; inspect SKI stable; `golden.rs`/`output.rs` green |
| `cargo test` / `clippy` / `fmt --check` clean | **PASS** | §1 |

---

## 3. Per-fixture outcome verification (raw full-registry findings, `--now 1796083200`)

Each of the 12 new lints fires on exactly its deviation fixture. The additive
`cabf_br_certificate_policies_present` Warn on policies-free new fixtures is expected (plan §C)
and is keyed out by the Error-severity isolation helper `firing_error_lints`.

| Fixture | Findings observed | Verdict |
|---|---|---|
| `cabf_br_ku_cert_sign.pem` | error `..._cert_sign_prohibited` (+ policies Warn) | PASS — isolates lint 1 |
| `cabf_br_ku_crl_sign.pem` | error `..._crl_sign_prohibited` (+ policies Warn) | PASS — isolates lint 2 |
| `cabf_br_leaf_path_len.pem` | error `cabf_br_...path_len_prohibited` + error `rfc5280_path_len_constraint_improperly_included` (+ policies Warn) | PASS — **documented co-fire** |
| `cabf_br_eku_any.pem` | error `cabf_br_ext_key_usage_any_prohibited` (+ policies Warn) | PASS — isolates lint 4 |
| `cabf_br_eku_no_server_auth.pem` | (full registry) error `server_auth_present` + error `server_auth_required` | PASS — **documented co-fire** (see §3a) |
| `cabf_br_san_email_entry.pem` | 2× error `cabf_br_san_dns_or_ip_only` (one per offending entry) (+ policies Warn) | PASS — isolates lint 6, multi-finding |
| `cabf_br_no_san.pem` | warn `cabf_br_san_present` (+ policies Warn) | PASS — isolates lint 7 (Warn) |
| `cabf_br_no_policies.pem` | warn `cabf_br_certificate_policies_present` | PASS — isolates lint 8 (Warn) |
| `cabf_br_policies_no_reserved.pem` | error `cabf_br_certificate_policies_reserved_oid` | PASS — isolates lint 9 |
| `cabf_br_rsa_mod_not_oct.pem` | error `cabf_br_rsa_modulus_bits_multiple_of_8` (+ policies Warn) | PASS — isolates lint 10 |
| `cabf_br_rsa_exp_3.pem` | error `cabf_br_rsa_public_exponent_in_range` (+ policies Warn) | PASS — isolates lint 11 |
| `cabf_br_no_basic_constraints.pem` | warn `cabf_br_basic_constraints_present` (+ policies Warn) | PASS — isolates lint 12 (Warn) |

No pre-existing clean fixture gained an unexpected Error: the registry isolation tests
(`each_fixture_isolates_exactly_one_rfc5280_violation`, `each_new_single_error_rule_fixture_isolates_exactly_one_violation`,
`internal_san_fixture_yields_two_error_findings_from_one_lint`) are all green, and good.pem yields
no Error/Fatal (`good_pem_yields_no_error_or_fatal_findings`, green in 3 suites).

### 3a. Note on the two co-fire fixtures under the CLI default purpose

The CLI's auto purpose-detection classifies `cabf_br_eku_no_server_auth.pem` (EKU = clientAuth only)
as not-tls-server, so the CLI run drops the entire `cabf_br` block (29 outcomes, no cabf_br) and
reports "no findings". This is **correct and expected**: the plan's isolation contract is "across the
FULL 82-lint registry", which the integration tests exercise via the raw
`default_registry_with_now(Some(TEST_NOW))` oracle (`cabf_br.rs:1463`), where the two-rule co-fire is
asserted and green. The purpose-gating is an orthogonal CLI layer and not a feature-17 concern. NOT a
gap.

---

## 4. Adjudication of out-of-`touches` edits

### tester-04 edits outside its `touches`

1. **`crates/linter/src/cert.rs` — `good_cert_carries_only_the_cabf_dv_reserved_policy_oid` (cert.rs:3257).**
   The prior test asserted good.pem had NO certificate-policy OIDs — a false premise after the
   *mandated* good.pem regeneration that adds the DV OID. The test now asserts
   `certificate_policy_oids().unwrap() == vec!["2.23.140.1.2.1"]`. **Acceptable.** It is a unit test of
   the new fixture state (not production code), correct, minimal, behaviour-neutral. Without it the
   suite would falsely fail. **Task-hygiene note:** this is production-crate test code outside
   tester-04's declared `touches`; ideally a developer task would own cert.rs edits, but the change is
   purely a consequence of the regen that tester-04 owns, so co-locating it was pragmatic.

2. **`clippy::manual_contains` fixes in developer-02's
   `cabf_br/ext_key_usage_any_prohibited.rs` + `ext_key_usage_server_auth_required.rs` test helpers.**
   Confirmed these are in test/helper code (e.g. `oids.contains(&"1.3.6.1.5.5.7.3.1")` style). They
   are **needed for the `-D warnings` gate** and are behaviour-neutral (membership test, identical
   semantics). **Acceptable.** **Task-hygiene note:** they touch developer-02's files; clippy churn on
   another task's source is a known seam — acceptable here because the gate would otherwise be red and
   the change is mechanical.

### tester-05 edits (documented accept-churn fallback surface)

`exit_codes.rs`, `inspect.rs`, `golden.rs`, the two good.pem `inspect__*` snapshots, and README. Each
diff is explained solely by the +12 cabf_br rows / good.pem SKI churn (`1D:33:53:BC` → `80:31:B9:6A`)
/ the full-regen SKI churn — confirmed: good.pem inspect snapshots carry the new SKI `80:31:B9:6A...`
matching the live fixture; README:370 good.pem `--info` carries the same; the verbose golden carries
exactly 24 cabf_br rows; the non-verbose summary reads `(24 passed, 0 not applicable)`. No outcome
flip. **Acceptable** — this is the planned snapshot reconciliation; all snapshot suites are green.

---

## 5. Recipe parity (generate.sh)

Every committed new artifact has a reproducing recipe: all 12 `testdata/cabf_br_*.pem` (each grep-hit
in `generate.sh`), `testdata/good.pem` (signed from the pinned key, certificatePolicies DV OID added
at `generate.sh:286-291`), and `testdata/keys/good.key` (pinned; `generate.sh:165 GOOD_KEY`, with a
documented one-time `openssl genrsa -out testdata/keys/good.key 2048` mint recipe at `:162/:168`).
PASS.

---

## 6. Known fragility (NOT a feature-17 gap) — full-regen churn

`generate.sh:152-153` re-rolls the shared non-good `$KEY` (`mktemp` + `openssl genrsa`) on every run;
only `GOOD_KEY` is pinned. Consequence: **re-running `generate.sh` will re-churn every non-good
fixture's SKI/signature bytes**, breaking SKI-bearing snapshots (notably
`inspect__slh_dsa_ca_text__slh_dsa_info_text.snap`, SKI `AB:2E:29:C6...`) and the README SLH-DSA
`--info` example again.

Current state is **internally consistent**: the tree is fresh/committed (355 tracked files), all
snapshots were reconciled to the on-disk fixtures, and the linter integration tests — the
authoritative per-fixture oracle — are green. Spot-verified: the slh_dsa inspect snapshot SKI
`AB:2E:29:C6...` equals the live `slh_dsa_root_ca.pem` SKI, and the README SLH-DSA `--info` example
(README:397-398, `AB:2E:29:C6...`) matches the live fixture exactly. Consistency confirmed.

**Recommendation (future work, do NOT implement in feature 17):** pin ALL fixture keys (commit fixed
PEMs under `testdata/keys/` and have `generate.sh` read them instead of re-rolling via `mktemp`), so
re-running `generate.sh` is byte-deterministic and never silently breaks SKI-bearing snapshots or the
README. This mirrors the good.pem pinning already done here.

---

## 7. Count / composite sanity

Target is **12 new lints** (user-approved; no AIA, no push to 15). All three sources of truth agree:
plan.md (count "settled at 12", total 70→82, cabf_br 12→24), `registry.rs` (82 / 24 assertions at
`:918-919`, `:1133`), and `tests/registry.rs` (82 at `:393-394`). Other source filters
(rfc5280/hygiene/pqc/cabf_ev/cabf_cs/cabf_smime) unchanged. PASS.

---

## Final verdict: COMPLETE

All 12 lints shipped at the correct severities with the single new accessor; good.pem is finding-free
with a pinned key and stable SKI (`80:31:B9:6A...`)/serial (17); every new lint fires on exactly its
fixture and the two documented co-fires are asserted as multi-finding; registry counts reconcile to
82/24 across plan, code, and tests; recipe parity holds; all four gates are green. The out-of-touches
edits are correct, minimal, and behaviour-neutral (task-hygiene notes only). The full-regen churn is
recorded as a known fragility with an all-fixture-key-pinning recommendation — not a feature-17 gap.
No follow-up tasks required.
