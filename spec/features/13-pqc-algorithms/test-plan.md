# Test Plan: Post-Quantum Signature-Algorithm Hygiene Rule Set

## Scope

Verify the ~5 PQC-SPKI-gated `pqc` lints, the new facade work (`PublicKeyAlg` ML-DSA/SLH-DSA
recognition, `spki_algorithm_parameters_present`, `signature_algorithm_parameters_present`,
`public_key_raw_len`, the new `KeyUsageView` bits), the new **universal** `RuleSource::Pqc` source and
its membership in EVERY purpose's allowed-source set, and the CLI `--source pqc` wiring.

**Two load-bearing properties (each is itself a test objective):**

1. **Universal-source membership:** `RuleSource::Pqc` is in `allowed_sources` for tls-server, generic,
   code-signing, and S/MIME purposes (and the `auto`-resolved equivalents) — NOT purpose-gated.
2. **No cascade:** every `pqc` lint is `NotApplicable` on every existing (RSA/EC) fixture because each
   lint self-gates on a PQC SPKI OID. Consequently NO existing fixture is regenerated and every existing
   isolation/invariant suite stays untouched. The symmetric counterpart also holds: the hygiene
   key-strength lints (`hygiene_rsa_key_min_2048`, `hygiene_ecdsa_curve_allowlist`) are `NotApplicable`
   on a PQC key, so they do NOT fire on the new PQC fixtures.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()`, behaviour-focused tests
grouped per lint in nested modules. Fixtures openssl-generated only; never hand-author cert bytes beyond
targeted DER byte-patching (and only where the tester documents that openssl cannot produce the
deviation natively).

## ⚠️ openssl version requirement

ML-DSA / SLH-DSA fixture generation requires **openssl 3.5+** (verified on 3.6.2). The PQC section of
`generate.sh` MUST version-check and fail loudly on an older openssl so a missing-algorithm error is
diagnosable. The two clean PQC leaves MUST be openssl-native (no byte-patching).

## ⚠️ Time-Fragility

`pqc_mldsa_good.pem` and `pqc_slhdsa_good.pem` use a currently-valid window straddling "now"
(`2026-06-01 → 2027-06-01`, aligned with the existing `BR_OK` horizon). They expire ~2027-06-01, after
which `hygiene_not_expired` fires on them and isolation breaks. Regenerate annually (slide forward).
`generate.sh`'s PQC section header documents this; `pqc.rs`'s module doc references it so a flood of
`not_expired` failures is diagnosable. Every violating PQC fixture must also straddle "now".

## Fixtures (`testdata/`) — all openssl-generated (± documented DER byte-patch), NEVER cert-bar

| Fixture | shape | isolates |
|---|---|---|
| `pqc_mldsa_good.pem` | ML-DSA-65, params absent, correct length, digitalSignature KU, CA:FALSE, currently-valid | nothing in the pqc set (clean positive control) |
| `pqc_slhdsa_good.pem` | SLH-DSA-SHA2-128s, params absent, correct length, digitalSignature KU, CA:FALSE, currently-valid | nothing in the pqc set (clean positive control) |
| `pqc_unknown_param_set.pem` | SLH-DSA-arc OID in an unassigned slot (e.g. `.32`) | `pqc_algorithm_known` (Error) |
| `pqc_spki_params_present.pem` | ML-DSA key with a present (NULL) SPKI `parameters` field | `pqc_spki_parameters_absent` (Error) |
| `pqc_sig_params_present.pem` | PQC cert whose signature AlgorithmIdentifier has a present `parameters` field | `pqc_signature_parameters_absent` (Error) |
| `pqc_bad_key_length.pem` | ML-DSA OID with a public-key byte length not matching the named set | `pqc_public_key_length` (Error) |
| `pqc_bad_key_usage.pem` | ML-DSA leaf asserting `keyEncipherment` | `pqc_key_usage_consistency` (Error) |

Producibility caveats (tester owns the decision, like prior features):

- `pqc_unknown_param_set`, `pqc_spki_params_present`, `pqc_sig_params_present`, `pqc_bad_key_length` are
  deviations openssl will NOT emit normally (openssl follows the LAMPS profile). Per fixture the tester
  decides: producible via openssl config, via openssl + targeted DER byte-patch (OID arc digit flip,
  NULL-splice into the AlgorithmIdentifier, BIT STRING truncate/pad), OR not cleanly producible. For a
  non-producible deviation: test the lint by **direct lint invocation** on a hand-built `Cert` where
  feasible, OR defer the lint+fixture together (pre-approved cut, reconcile counts). Document per fixture
  in `pqc.rs` and `generate.sh`.
- `pqc_unknown_param_set.pem` is the through-registry fixture for `pqc_algorithm_known` only under the
  arc-gate (plan option A). If option B is chosen, test that lint by direct invocation and drop/adjust
  the fixture.

## Unit Tests (in-file, owned by the developer tasks — listed for coverage tracking)

### `cert.rs` (task 01)

- `public_key_algorithm()` returns the ML-DSA variant for `2.16.840.1.101.3.4.3.{17,18,19}` and the
  SLH-DSA variant for the `{20..31}` known slots, with the correct parameter-set identity; an arc OID in
  an unassigned slot (`.32`) returns the "unknown arc member" form (per plan option A).
- `public_key_algorithm()` is UNCHANGED for RSA (`1.2.840.113549.1.1.1`), EC (`1.2.840.10045.2.1`), and
  an unrelated `Other` OID (negative regression — proves no Rsa/Ec/Other behavior shift).
- `spki_algorithm_parameters_present()` true on a fixture with present params, false on absent.
- `signature_algorithm_parameters_present()` true/false analogues.
- `public_key_raw_len()` reports the expected byte length on a PQC fixture (and documents what it
  measures — the BIT STRING value excluding the unused-bits octet).
- `KeyUsageView` exposes `key_encipherment` / `key_agreement` / `crl_sign` correctly (positive +
  absent), alongside the existing `digital_signature` / `key_cert_sign`.

### `registry.rs` (task 03)

- `contains_the_known_lints`: lint count and outcome count bumped 61 → 66 (5 pqc lints; sibling 11
  cabf_ev had landed before this feature); the 5 `pqc_*` ids present.
- `pqc_source_filter_runs_exactly_the_pqc_set`: `run_filtered(&cert, &[RuleSource::Pqc])` → 5
  outcomes, all `RuleSource::Pqc`, the `pqc_*` ids, none rfc5280_/hygiene_/cabf_*.
- **Universal-source membership** (the headline property): `allowed_sources` for `TlsServer`, `Generic`,
  `CodeSigning`, `Smime` (and an `auto` resolving to each) ALL include `RuleSource::Pqc`. Assert
  explicitly for every purpose. (Contrast: `CabfCs` is only in code-signing, `CabfSmime` only in S/MIME
  — those existing assertions remain unchanged.)
- Existing rfc5280 / cabf_br / cabf_cs / cabf_smime / hygiene filter counts UNCHANGED.
- No new `CertPurpose`: the `CertPurpose` enum / `auto` resolver / `resolve` tests are unchanged.
- `sample_cert()` is RSA/EC (not PQC), so the `pqc` lints are `NotApplicable` but still produce one
  OUTCOME each → outcome count reflects the bump. Confirm `sample_cert()` carries no PQC key.

## Integration Tests (`crates/linter/tests/pqc.rs`)

- Per lint with a through-registry fixture: run the default registry on the fixture, assert exactly the
  target `pqc_*` finding fires (severity per the plan table) with a message substring naming the
  offending value (parameter set / expected-vs-actual length / KU bit), and both clean PQC leaves
  produce no error/fatal PQC findings.
- `pqc_algorithm_known`: on `pqc_unknown_param_set.pem` the Error fires; on the two clean leaves it
  passes; the other length/family lints produce NO finding on the unknown-arc fixture (the unknown set
  has no known length to validate) so it isolates exactly `pqc_algorithm_known`.
- `pqc_key_usage_consistency`: the `keyEncipherment`-on-signature-key Error fires on `pqc_bad_key_usage`;
  document and (where a fixture exists) assert the Warn paths (EE missing `digitalSignature`; CA missing
  `keyCertSign`) — these may be exercised by direct invocation if a clean openssl fixture for each Warn
  case is not producible.
- **Scoping:** all PQC lints are `NotApplicable` on a non-PQC cert (use `good.pem`); all PQC lints
  `Applies` on `pqc_mldsa_good.pem` and `pqc_slhdsa_good.pem`.
- **No-cascade (load-bearing):** `default_registry().run()` on `good.pem` yields 5 `pqc` outcomes
  all `NotApplicable` with empty findings. Symmetrically: on `pqc_mldsa_good.pem`, the hygiene
  key-strength lints (`hygiene_rsa_key_min_2048`, `hygiene_ecdsa_curve_allowlist`) are `NotApplicable`
  (PQC key is neither RSA nor EC) — assert this so the PQC key does not trip the RSA/EC hygiene checks.
- Module doc: note the time-fragility window, the openssl-version requirement, and the
  universal-source-but-self-gated design.

## CLI E2E (`crates/cli/tests/output.rs`, ADD only)

- `--source pqc` on `pqc_mldsa_good.pem` → `[pqc]` group with the 5 PQC lints, all
  applicable/passed. Confirm the `[pqc]` group renders in the documented `SOURCE_ORDER` position
  (after `[rfc5280]`).
- `--source pqc` on a non-PQC cert (`good.pem`) → the `[pqc]` group shows the PQC lints all
  NotApplicable (universal source is filtered in, lints self-gate out).
- A default (all-source) run on `pqc_mldsa_good.pem` shows the `[pqc]` group alongside the existing
  groups, and the existing groups behave as before. Do NOT change any existing assertion or constant.

## Cross-Feature Regression (must still pass UNCHANGED — proves no cascade)

- `crates/linter/tests/rfc5280.rs`, `hygiene.rs`, `registry.rs` (existing assertions), `not_expired.rs`,
  `cabf_br.rs`, `cabf_cs.rs`, `cabf_smime.rs` — all existing isolation/invariant tests pass with NO edits
  (the PQC lints are NotApplicable on every existing fixture). The `EXPIRED_*` constants are NOT changed.
- `cli/tests/output.rs` existing tests pass unchanged.
- The only edit to a pre-existing test file is the additive `--source pqc` test in `cli/tests/output.rs`
  and the count bump in `crates/linter/tests/registry.rs` (if that integration test asserts the total).

## Edge Cases

- OID exactly at each known slot (`.17`–`.19`, `.20`–`.31`) → recognized; an arc OID at an unassigned
  slot (`.32`–`.35`) → `pqc_algorithm_known` fires; a near-miss OID just outside the arc → `Other`
  (gate NotApplicable, no PQC lint runs).
- Public-key length exactly the mandated value passes `pqc_public_key_length`; one byte short/long fails
  (message names expected vs actual).
- `parameters` present-as-NULL vs present-as-other-value both count as "present" (Error) for the two
  parameters-absent lints; truly absent passes.
- KU: a PQC signature key asserting only `digitalSignature` passes; asserting `keyEncipherment` or
  `keyAgreement` → Error; an EE with no KU at all → the `digitalSignature`-missing Warn (documented).
- `--source pqc` forces the PQC set even on a non-PQC leaf — but the gated lints then report
  NotApplicable (forcing the source does not bypass the per-lint SPKI gate; document this interaction,
  mirroring the `--source cabf_cs` interaction in feature 09).

## Verification Commands

```
cargo test
cargo test -p linter --features serde
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features serde -- -D warnings
cargo fmt --check
openssl version            # must be 3.5+ for the PQC fixtures
bash testdata/generate.sh
```

## Exit Criteria

The 5 `pqc` lints + facade work + the universal `RuleSource::Pqc` source + CLI wiring are
validated; the universal-source-membership property is proven (Pqc in every purpose's allowed-sources);
the PQC-SPKI-gate scoping is confirmed; both clean PQC leaves pass the pqc set; each violating (or
direct-invocation) case isolates its one PQC rule; the no-cascade property is proven in BOTH directions
(PQC lints NotApplicable on RSA/EC fixtures; hygiene RSA/EC lints NotApplicable on PQC fixtures);
registry/CLI unit + e2e tests pass; no existing fixture is regenerated; all verification commands green.
