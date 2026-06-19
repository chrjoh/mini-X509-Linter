# Test Plan: PQC Extensions — ML-KEM lints + part-3 KeyUsage gap

## Scope

Verification for feature 16 (tester task 05): the four `pqc_mlkem_*` lints
(ML-KEM / FIPS 203 key-establishment), the part-3 extension of
`pqc_key_usage_consistency` (dataEncipherment / encipherOnly / decipherOnly Errors
on a PQC signature key), and reconciliation of the registry count (66 → 70),
CLI `--source pqc` output, and the feature-06 golden + inspect snapshots.

All fixtures are openssl-generated (never cert-bar); the clean ML-KEM leaf is
openssl-native via `x509 -req -force_pubkey`; deviations are documented DER
byte-patches. Tests pin the clock to `TEST_NOW = 1_796_083_200` (2026-12-01).

## Acceptance Criteria (from spec / task)

- [x] 5 openssl-generated ML-KEM fixtures; clean leaf native; deviations documented;
      no existing fixture modified; `generate.sh` ML-KEM section carries the openssl
      version check, fragility header, per-fixture producibility notes, and the
      byte-patch-invalidates-signature caveat.
- [x] Clean leaf passes all 4 ML-KEM lints; each deviation isolates exactly one rule.
- [x] `pqc.rs` covers per-ML-KEM-lint flag/pass; part-3 dataEncipherment Error on a
      PQC signature key end-to-end; scoping (N/A on non-ML-KEM incl. ML-DSA, Applies
      on ML-KEM); no-cascade both directions incl. no spurious cabf_br on the clean
      KEM leaf.
- [x] `registry.rs` integration count bumped 66 → 70; CLI `--source pqc` e2e added
      (ML-KEM cert + non-PQC cert); existing CLI/registry tests reconciled (5 → 9).
- [x] Golden + inspect snapshots regenerated only where content changed; diff reviewed
      (only `[pqc]` slot growth; no flipped outcome).
- [x] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
      and `cargo test -p linter --features serde` all pass.

## Fixtures (testdata/, recipe in testdata/generate.sh)

| Fixture | Producibility | Isolates |
|---|---|---|
| `pqc_mlkem_good.pem` | openssl-native (`-force_pubkey`) | none (clean; passes all 4) |
| `pqc_mlkem_unknown_param_set.pem` | DER patch: SPKI OID arc `.2`→`.4` | `pqc_mlkem_algorithm_known` (Error) |
| `pqc_mlkem_spki_params_present.pem` | DER patch: NULL spliced into SPKI AlgId | `pqc_mlkem_spki_parameters_absent` (Error) |
| `pqc_mlkem_bad_key_length.pem` | DER patch: BIT STRING 1184→1183 | `pqc_mlkem_public_key_length` (Error) |
| `pqc_mlkem_bad_key_usage.pem` | openssl-native (`digitalSignature,keyEncipherment` KU) | `pqc_mlkem_key_usage_consistency` (Error) |

Byte-patched fixtures break the issuer signature; acceptable for a structural linter
that never verifies signatures. Clean + bad-KU leaves verify against the ML-DSA CA.

## Test Cases

### Integration — `crates/linter/tests/pqc.rs` (21 tests)

| Test | Description | Expected |
|---|---|---|
| `clean_leaves::mlkem_good_passes_all_mlkem_lints` | ML-KEM leaf, pqc-filtered | 4 ML-KEM Apply + pass, 5 signature N/A, 0 findings |
| `clean_leaves::{mldsa,slhdsa}_good_passes_all_pqc_lints` | signature leaves | 5 sig Apply, 4 ML-KEM N/A, 0 findings |
| `per_lint_isolation::mlkem_unknown_param_set_isolates_mlkem_algorithm_known` | unknown arc `.4` | exactly 1 Error naming the OID |
| `per_lint_isolation::mlkem_spki_params_present_isolates_mlkem_spki_parameters_absent` | NULL params | exactly 1 Error |
| `per_lint_isolation::mlkem_bad_key_length_isolates_mlkem_public_key_length` | 1183-byte key | exactly 1 Error naming 1184/1183 |
| `per_lint_isolation::mlkem_bad_key_usage_isolates_mlkem_key_usage_consistency` | digitalSignature bit | exactly 1 Error naming digitalSignature |
| `per_lint_isolation::*` (signature, retained) | feature-13 deviations | unchanged, each isolates its lint |
| `scoping::mlkem_lints_apply_on_mlkem_leaf_signature_lints_do_not` | ML-KEM leaf | 4 ML-KEM Apply, 5 sig N/A |
| `scoping::signature_lints_apply_on_signature_pqc_leaves_mlkem_lints_do_not` | ML-DSA/SLH-DSA | inverse |
| `scoping::all_pqc_lints_not_applicable_on_rsa_leaf` | good.pem | all 9 N/A |
| `key_usage_part3::key_encipherment_on_signature_key_errors_through_registry` | `pqc_bad_key_usage.pem` | Error via registry |
| `key_usage_part3::data_encipherment_on_signature_key_errors_through_registry` | in-memory KU patch (bit 3) | exactly 1 Error naming dataEncipherment |
| `no_cascade::raw_run_on_rsa_good_has_all_pqc_outcomes_not_applicable` | RSA good, full registry | 9 pqc outcomes all N/A |
| `no_cascade::raw_run_on_mlkem_leaf_leaves_rsa_ec_hygiene_not_applicable` | ML-KEM leaf | RSA/EC hygiene lints N/A |
| `no_cascade::clean_mlkem_leaf_under_resolved_purpose_trips_no_finding` | Auto purpose | resolves `[Rfc5280,Pqc,Hygiene]`, 0 findings, no cabf_br |
| `no_cascade::raw_run_on_mldsa_good_surfaces_no_pqc_finding` | ML-DSA, full registry | no pqc finding |

### Integration — `crates/linter/tests/registry.rs`

| Test | Expected |
|---|---|
| `default_registry_has_the_expected_total_lint_count` | `registry.len() == 70`, `outcomes.len() == 70` |

### CLI e2e — `crates/cli/tests/output.rs`

| Test | Expected |
|---|---|
| `source_pqc_on_mlkem_good_runs_only_the_pqc_group` | `[pqc]` only; 4 ML-KEM `pass`, 5 sig `n/a`; no findings |
| `default_run_on_mlkem_good_renders_pqc_group_after_rfc5280` | `[pqc]` after `[rfc5280]`; no findings |
| `source_pqc_on_mlkem_bad_key_usage_reports_the_error` | `pqc_mlkem_key_usage_consistency` Error naming digitalSignature |
| `source_pqc_json_emits_nine_pqc_outcomes_on_mldsa_leaf` | 9 outcomes; 5 applies, 4 not_applicable |
| `source_pqc_on_mldsa_good_runs_only_the_pqc_group` (updated) | 5 sig `pass`, 4 ML-KEM `n/a` |
| `source_pqc_on_non_pqc_cert_lists_all_lints_not_applicable` | all 9 `n/a` on good.pem |

### Snapshots regenerated (only `[pqc]` slot growth; no flipped outcome)

- `golden__{text,verbose,json}` for `good.pem`, `cabf_br_validity_400_days.pem`,
  `chain_bundle.pem`: `[pqc] (0 passed, 5→9 not applicable)`; verbose +4 `n/a`
  rows; JSON +4 `not_applicable` outcomes.
- `inspect__{good_cert_text, chain_info, slh_dsa_ca_text}` (out-of-touches ripple,
  see Gaps): RSA `[pqc] 5→9 n/a`; SLH-DSA `[pqc] (5 passed, 0→4 not applicable)`.

## Edge Cases

- Unknown ML-KEM arc member (`.4`) → only `pqc_mlkem_algorithm_known` fires; the
  length lint stays silent (no known length for an unknown set).
- ML-KEM bad-KU fixture asserts `digitalSignature` AND `keyEncipherment` so the
  missing-encryption-bit Warn is suppressed → single Error, clean isolation.
- Clean ML-KEM leaf is a generic (no serverAuth) leaf → resolves to generic
  purpose, so serverAuth-scoped cabf_br lints are not even in the run.
- CN == SAN on the clean leaf so cabf_br_cn_in_san stays quiet even if forced.

## Coverage Goals / Notes

- All 4 ML-KEM lints + the part-3 lint covered at both unit (dev-02/03) and
  integration level. Part-3 bits 7/8 (encipherOnly/decipherOnly) are unit-covered
  (dev-03); the integration test covers bit 3 (dataEncipherment) end-to-end via an
  in-memory length-preserving KU BIT STRING patch (no new committed fixture).

## Gaps / Deviations

1. **Part-3 bits 7/8 integration:** `encipherOnly`/`decipherOnly` are not asserted
   on any committed openssl ML-DSA fixture (openssl follows the LAMPS profile and
   the 5-fixture touch budget adds none). They are unit-covered in dev-03;
   integration covers the representative bit-3 path via an in-memory DER patch.
2. **inspect.rs snapshots (out-of-touches):** the 3 `--info` snapshots
   (`good_cert_text`, `chain_info`, `slh_dsa_ca_text`) embed the per-cert lint
   report and therefore gained the 4 ML-KEM `[pqc]` n/a slots. They were NOT in the
   task `touches` but `cargo test` cannot pass without them. Regenerated; the diff
   is purely the expected `[pqc]` slot growth (no flipped outcome). Flagged for
   integration review.
