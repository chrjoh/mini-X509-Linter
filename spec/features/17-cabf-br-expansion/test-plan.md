# Test Plan: Feature 17 — CA/Browser Forum BR expansion (12 new cabf_br lints)

## Scope

Fixtures + linter integration tests for the twelve new `cabf_br_*` lints added in
feature 17 (registry now 82 lints total; `cabf_br` bucket 24). Covers: one
openssl-generated deviation fixture per new lint, the regenerated finding-free
`good.pem` (pinned key + DV reserved policy OID), per-lint flag/pass tests,
multi-finding and `Warn`-severity cases, CA `NotApplicable`, full-registry
isolation (incl. the two documented intentional co-fires), and reconciliation of
the cascade onto rfc5280 / registry / cabf_ev integration suites.

CLI golden snapshots, `output.rs` count strings, the two `inspect__*` snapshots,
and the README `--info` example are tester-05's scope (see "Handoff to tester-05").

## Acceptance Criteria (from plan / task)

- [x] `good.pem` regenerated ONCE with a PINNED key (`testdata/keys/good.key`,
      committed) + a `certificatePolicies` DV OID `2.23.140.1.2.1`; finding-free
      across all 12 new lints (lints 8/9 are positive passes).
- [~] SKI byte-stable: **NOT achievable** — the original good.pem private key was
      never committed (old `generate.sh` used a `mktemp` key), so the original SKI
      `1D:33:53:BC…` is unreproducible. The new pinned key yields SKI
      `80:31:B9:6A:1E:A6:B8:88:63:FC:6C:BF:58:97:4F:67:6D:CD:E0:83`. This is the
      plan's documented accept-churn FALLBACK; FLAGGED for tester-05 + architect
      (see "Handoff"). Serial stays `17` (=`11` hex).
- [x] 12 new openssl-generated fixtures (recipe parity in `generate.sh`), each
      isolating exactly its one new rule across the 82-lint registry except the two
      documented intentional co-fires.
- [x] Per-new-lint flag/pass tests; `Warn` lints assert `Warn` severity;
      multi-finding case for `san_dns_or_ip_only`; all 12 `NotApplicable` on a CA.
- [x] good.pem asserted to emit NO finding from any new lint (no Warn, no Error)
      and to PASS lints 8 and 9 explicitly.
- [x] `cabf_br_missing_serverauth.pem` isolation reconciled to a documented
      two-rule assertion (lints 5 + existing serverAuth);
      `rfc5280_empty_subject_no_san.pem` isolation still holds (Error-keyed).
- [x] `cargo test` (linter crate), `cargo clippy --all-targets -- -D warnings`,
      `cargo fmt --check`, and `bash testdata/generate.sh` all pass cleanly.

## Fixtures Added (recipe parity in testdata/generate.sh)

| Fixture | New lint isolated | Severity | Notes |
|---|---|---|---|
| `cabf_br_ku_cert_sign.pem` | subscriber_key_usage_cert_sign_prohibited | Error | KU keyCertSign on CA:FALSE leaf |
| `cabf_br_ku_crl_sign.pem` | subscriber_key_usage_crl_sign_prohibited | Error | KU cRLSign on CA:FALSE leaf |
| `cabf_br_leaf_path_len.pem` | subscriber_basic_constraints_path_len_prohibited | Error | **2-rule co-fire** w/ rfc5280_path_len_constraint_improperly_included |
| `cabf_br_eku_any.pem` | ext_key_usage_any_prohibited | Error | EKU serverAuth + anyExtendedKeyUsage |
| `cabf_br_eku_no_server_auth.pem` | ext_key_usage_server_auth_required | Error | **2-rule co-fire** w/ existing ext_key_usage_server_auth_present |
| `cabf_br_san_email_entry.pem` | san_dns_or_ip_only | Error | SAN DNS:<cn> + email + URI → **two findings** |
| `cabf_br_no_san.pem` | san_present | **Warn** | /O= subject (no CN, so cn_in_san quiet); no SAN |
| `cabf_br_no_policies.pem` | certificate_policies_present | **Warn** | no CertificatePolicies |
| `cabf_br_policies_no_reserved.pem` | certificate_policies_reserved_oid | Error | policies w/ non-reserved OID 1.3.6.1.4.1.99999.1 |
| `cabf_br_rsa_mod_not_oct.pem` | rsa_modulus_bits_multiple_of_8 | Error | DER-patched 2055/2054-bit modulus (≥2048, not octet-aligned) |
| `cabf_br_rsa_exp_3.pem` | rsa_public_exponent_in_range | Error | RSA-2048 exponent 3 |
| `cabf_br_no_basic_constraints.pem` | basic_constraints_present | **Warn** | no BasicConstraints |

Plus `good.pem` regenerated (pinned key + DV reserved policy OID) and
`testdata/keys/good.key` committed (pinned RSA-2048 key for good.pem only).

All fixtures use the `BR_OK` window (2026-06-01 → 2027-06-01), bracketing
TEST_NOW = 1_796_083_200. Every fixture has a reproducing recipe in
`generate.sh`; openssl-only (no cert-bar). `cabf_br_rsa_mod_not_oct.pem` and the
country/utctime precedents use length-recomputing DER patches.

### Additive Warn on every non-good leaf

Under broad BR scoping, every non-CA leaf lacking a CertificatePolicies extension
gains an additive `cabf_br_certificate_policies_present` **Warn**. Only `good.pem`
(regenerated to carry policies) is exempt. This never adds a second *Error* to any
fixture, so all Error-keyed isolation tests hold; the additive Warn is explicitly
asserted where a test counts Warns.

## Test Cases (crates/linter/tests/cabf_br.rs)

### Per-lint flag/pass + CA-NotApplicable (one nested module per new lint)
For each new lint: deviation fixture → expected finding (correct severity + message
substring); `good.pem` → no finding; CA fixture → `NotApplicable`.

- Error lints assert `assert_error_mentions`; Warn lints
  (`san_present`, `certificate_policies_present`, `basic_constraints_present`)
  assert `assert_warn_mentions` (Warn severity, no Error).
- `san_dns_or_ip_only`: **multi-finding** — two prohibited entries → two Errors.
- `certificate_policies_reserved_oid`: silent when policies absent (uses
  `cabf_br_no_policies.pem`).
- `feature_17_lints_ca_scoping::all_twelve_new_br_lints_not_applicable_on_ca`.

### Full-registry isolation (mod default_registry_isolation)
- `each_new_single_error_rule_fixture_isolates_exactly_one_violation` (7 fixtures).
- `leaf_path_len_fixture_trips_both_br_and_rfc_path_len_rules` (documented 2-rule).
- `eku_no_server_auth_fixture_trips_both_serverauth_rules` (documented 2-rule).
- `missing_serverauth_fixture_trips_both_serverauth_rules` (reconciled existing
  fixture to the same 2-rule pair — lint 5 KEPT).
- `feature_17_warn_only_fixtures_fire_no_error_and_their_warns` (no-san,
  no-policies, no-basic-constraints).
- `good_pem_yields_no_finding_at_all` (no Error AND no Warn).
- `good_pem_passes_certificate_policies_lints_8_and_9` (positive passes documented).

## Cascade Reconciliations (authorized scope expansion)

- `crates/linter/tests/registry.rs`: total count 70 → 82;
  `expired_fixture_isolates_only_the_not_expired_finding` reconciled — expired.pem
  now surfaces the expiry Warn + the additive BR policies Warn, still NO Error
  (plan Cascade §B; expired.pem NOT regenerated).
- `crates/linter/tests/rfc5280.rs`: path-len-on-leaf excluded from the strict
  one-rule loop + asserted as a 2-rule case; eku-empty fixture now also trips the
  new serverAuth-required lint (3-rule raw-registry case); ski-missing-sub-cert now
  has two Warns (target + additive policies).
- `crates/linter/tests/cabf_ev.rs`: every EV fixture carries a non-reserved EV
  marker policy OID, so it correctly co-fires `cabf_br_certificate_policies_reserved_oid`
  (genuine new finding, NOT an EV-fixture defect). The good/each-fixture/validity-400
  EV isolation tests reconciled to include that BR Error (EV fixtures NOT
  regenerated — out of feature-17 scope).
- `crates/linter/src/cert.rs` (1 unit test, out of touches but required for the
  build): `good_cert_has_no_certificate_policy_oids` → renamed/updated to assert
  good.pem carries ONLY the DV reserved OID `2.23.140.1.2.1` (direct consequence of
  the mandated good.pem regeneration). FLAGGED below.
- `crates/linter/src/lints/cabf_br/ext_key_usage_{any_prohibited,server_auth_required}.rs`
  (2 one-line `#[cfg(test)]` helper fixes for `clippy::manual_contains`,
  behaviour-neutral; developer-02 files, out of touches). FLAGGED below.

## Handoff to tester-05 (CLI scope — still failing after this task, EXPECTED)

`crates/cli/tests/`:
- `golden.rs` (5): good text/verbose/json, chain_bundle text, cabf_br_validity_400
  text — gain 12 cabf_br rows / Warn rows.
- `inspect.rs` (6): incl. `good_cert_text::info_summary_then_lint_report_snapshot`
  and `json_envelope::summary_object_snapshot` — these MOVE because the good.pem
  **SKI churned** (`1D:33:53:BC…` → `80:31:B9:6A…`), the accept-churn FALLBACK.
- `exit_codes.rs` (1): `chain::chain_exit_reflects_only_surfaced_findings`.
- `output.rs`: passed in this run, but any `[cabf_br] (N …)` count strings should
  be re-audited by tester-05.
- README.md `--info` good.pem SKI example (line ~370) must move to `80:31:B9:6A…`.

**SCOPE-WIDENING FLAG:** the two `inspect__*` snapshots + README SKI were expected
to be UNCHANGED under the pinned-key path; they DO move here because the original
key is unrecoverable. tester-05's `touches` must be widened to include them (per
the plan's accept-churn fallback).

## Coverage Goals

- All 12 new `cabf_br_*` lints: flag + pass + CA-NotApplicable + full-registry
  isolation. (Achieved.)
- good.pem: completely finding-free across the 82-lint registry. (Achieved.)
