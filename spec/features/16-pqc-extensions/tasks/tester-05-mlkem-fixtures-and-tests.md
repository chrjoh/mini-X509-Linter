---
agent: tester
seq: 5
title: ML-KEM fixtures (openssl -force_pubkey) + ML-KEM integration tests + part-3 tests + CLI e2e + count/golden reconciliation
status: done
touches:
  - testdata/generate.sh
  - testdata/pqc_mlkem_good.pem
  - testdata/pqc_mlkem_unknown_param_set.pem
  - testdata/pqc_mlkem_spki_params_present.pem
  - testdata/pqc_mlkem_bad_key_length.pem
  - testdata/pqc_mlkem_bad_key_usage.pem
  - crates/linter/tests/pqc.rs
  - crates/linter/tests/registry.rs
  - crates/cli/tests/output.rs
  - crates/cli/tests/golden.rs
  - crates/cli/tests/snapshots/golden__text_output__good_text.snap
  - crates/cli/tests/snapshots/golden__json_output__good_json.snap
  - crates/cli/tests/snapshots/golden__verbose_output__good_verbose_text.snap
  - crates/cli/tests/snapshots/golden__text_output__cabf_br_validity_400_days_text.snap
  - crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap
depends_on:
  - developer-04-register-mlkem-lints
---

# Task: ML-KEM fixtures + integration tests + part-3 coverage + reconciliation

## Goal

Add openssl-generated ML-KEM fixtures (a clean ML-KEM leaf + one violating fixture per ML-KEM lint that
has a producible deviation), write the ML-KEM integration tests, add integration coverage for the part-3
`pqc_key_usage_consistency` extension, add a CLI `--source pqc` e2e for an ML-KEM cert, and reconcile the
integration registry count + the feature-06 golden snapshots. CRITICAL: do NOT regenerate or modify any
existing fixture — the ML-KEM-SPKI gate makes all four `pqc_mlkem_*` lints `NotApplicable` on every
existing RSA/EC/ML-DSA/SLH-DSA fixture, so no cascade.

## ⚠️ Fixtures: openssl-generated ONLY — NEVER cert-bar.

The linter must stay an INDEPENDENT oracle. Generate every ML-KEM fixture with openssl (± documented DER
byte-patch / direct-invocation for deviations openssl cannot emit natively). Never source a fixture from
the user's cert-bar tool. Every committed fixture MUST have a reproducing recipe in `generate.sh`.

## ⚠️ openssl ML-KEM cert recipe (verified by the architect — read first)

ML-KEM keys CANNOT self-sign or sign their own CSR. The verified native path (OpenSSL 3.6.2):

```sh
# 1. ML-DSA CA (signer) — reuse/align with the feature-13 PQC CA if one exists.
openssl genpkey -algorithm ML-DSA-65 -out ca.key
openssl req -new -x509 -key ca.key -subj "/CN=mlkem-test-ca" -days <window> -out ca.pem
# 2. ML-KEM leaf key + its public key (PEM, for -force_pubkey).
openssl genpkey -algorithm ML-KEM-768 -out mlkem.key
openssl pkey -in mlkem.key -pubout -out mlkem.pub.pem
# 3. A dummy CSR signed by the CA key; the ML-KEM key only appears as the FORCED SPKI.
openssl req -new -key ca.key -subj "/CN=mlkem-leaf" -out dummy.csr
openssl x509 -req -in dummy.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -force_pubkey mlkem.pub.pem -extfile mlkem_ext.cnf -extensions v3 \
  -days <window> -out pqc_mlkem_good.pem
# mlkem_ext.cnf [v3]: basicConstraints = critical,CA:FALSE ; keyUsage = critical,keyEncipherment
```

The result is a valid cert with `Public Key Algorithm: ML-KEM-768` and absent SPKI params (architect
verified). Require **openssl 3.5+**; `openssl version`-guard the section and fail loudly on older.

## ⚠️ Time-fragility (read first)

Use a fixed validity window bracketing **TEST_NOW = 2026-12-01** (`default_registry_with_now(Some(1_796_083_200))`
/ CLI `--now 1796083200`), aligned with the feature-13 PQC fixtures' `BR_OK` horizon. Document the expiry
in the `generate.sh` ML-KEM section header and reference it in the test module doc; regenerate annually.
Every fixture (clean and violating) must bracket TEST_NOW so ONLY its target ML-KEM rule fires (not
`hygiene_not_expired`).

## Files Owned (conflict scope)

- `testdata/generate.sh` (append a SELF-CONTAINED ML-KEM section)
- the 5 new `pqc_mlkem_*.pem`
- `crates/linter/tests/pqc.rs` (extend — the existing feature-13 PQC integration test; add ML-KEM cases +
  the part-3 cases here so the PQC integration suite stays in one file)
- `crates/linter/tests/registry.rs` (bump the integration count assert 66 → 70 at lines ~376/389-391)
- `crates/cli/tests/output.rs` (ADD a `--source pqc` ML-KEM case; do not alter existing assertions)
- `crates/cli/tests/golden.rs` + the listed golden snapshots (regenerate ONLY if the snapshot content
  actually changes — see step 5)

Does NOT modify the lib `src/` (cert.rs, source.rs, registry.rs, the lints) or the CLI `src/`.

## What to Do

### 1. `generate.sh` — appended, self-contained ML-KEM section

- `openssl version` guard requiring 3.5+; fail loudly.
- The `-force_pubkey` recipe above; reuse a feature-13 PQC ML-DSA CA if present, else mint one in-section.
- A validity window bracketing TEST_NOW (align with `BR_OK`).
- Generate the fixtures:
  - `pqc_mlkem_good.pem` — clean ML-KEM-768 leaf, `keyEncipherment` KU, CA:FALSE. **openssl-native, no
    byte-patching.**
  - `pqc_mlkem_bad_key_usage.pem` — ML-KEM leaf with `keyUsage = digitalSignature` (wrong bit for a KEM
    key) — likely openssl-native via the `-extfile` extensions.
  - `pqc_mlkem_unknown_param_set.pem` — ML-KEM-arc OID in an unassigned slot (e.g. `.4`) — DER byte-patch
    of an arc digit; document.
  - `pqc_mlkem_spki_params_present.pem` — ML-KEM key with a present (NULL) SPKI `parameters` field — DER
    NULL-splice byte-patch; document.
  - `pqc_mlkem_bad_key_length.pem` — ML-KEM OID with an encapsulation-key length not matching the named
    set — DER BIT STRING truncate/pad byte-patch; document. NOTE: byte-patching the SPKI invalidates the
    issuer signature — acceptable (the linter does not verify signatures; it lints structure). State this
    caveat in the recipe.
- For ANY deviation that cannot be byte-patched cleanly, test that lint by **direct lint invocation** on a
  hand-built `Cert`, OR defer the lint+fixture together (pre-approved cut — reconcile the registry/CLI
  counts and note it). Document the decision per fixture in `pqc.rs` and `generate.sh`.
- Run `bash testdata/generate.sh`; commit every new `.pem`. Restore tracked fixtures (if perturbed) with
  `git checkout -- 'testdata/*.pem'` — NEVER `git checkout -- testdata/`.

### 2. `crates/linter/tests/pqc.rs` — extend (SIFER, `.unwrap()`/`.unwrap_err()` conventions)

- **ML-KEM per-lint:** run `default_registry_with_now(Some(1_796_083_200))` on each fixture; assert
  exactly the target `pqc_mlkem_*` finding fires (severity per the plan table) with a message substring
  naming the offending value (parameter set / expected-vs-actual length / KU bit), and the clean leaf
  produces no error/fatal ML-KEM findings.
- `pqc_mlkem_algorithm_known`: Error on `pqc_mlkem_unknown_param_set.pem`; the length lint produces NO
  finding on it (unknown set has no known length) → isolates exactly `pqc_mlkem_algorithm_known`.
- `pqc_mlkem_key_usage_consistency`: assert the signing-bit Error on `pqc_mlkem_bad_key_usage.pem`;
  exercise the Warn path (EE asserting neither keyEncipherment nor keyAgreement) by direct invocation if
  a clean openssl fixture is not producible; document.
- **Part-3 coverage:** add a test asserting `pqc_key_usage_consistency` now flags `dataEncipherment` /
  `encipherOnly` / `decipherOnly` on a PQC **signature** key. If no openssl-native fixture asserts those
  bits on an ML-DSA key, cover via direct lint invocation on a hand-built `Cert` (or extend the existing
  feature-13 `pqc_bad_key_usage.pem` analysis) — document the approach.
- **Scoping:** all four ML-KEM lints `NotApplicable` on a non-ML-KEM cert (use `good.pem` AND
  `pqc_mldsa_good.pem` to prove ML-KEM lints do not fire on a PQC *signature* key); all four `Applies` on
  `pqc_mlkem_good.pem`.
- **No-cascade (BOTH directions):**
  - `default_registry_with_now(...).run()` on `good.pem` yields the four ML-KEM outcomes all
    `NotApplicable`.
  - On `pqc_mlkem_good.pem`: the hygiene key-strength lints (`hygiene_rsa_key_min_2048`,
    `hygiene_ecdsa_curve_allowlist`) are `NotApplicable`; the feature-13 signature `pqc_*` lints are
    `NotApplicable` (an ML-KEM key is not a signature key); and NO spurious `cabf_br_*` finding fires
    (the clean ML-KEM leaf is a generic, no-serverAuth leaf) — the cross-source no-cascade assertion from
    plan Open Question 3.
- Module doc: note the time-fragility window, the openssl-version requirement, the `-force_pubkey` recipe,
  and the universal-source-but-self-gated design.

### 3. `crates/linter/tests/registry.rs` (integration count bump)

- Bump the default-total assertion **66 → 70** (lines ~376 comment + 389-391 asserts). Update the
  authoritative-count comment (4 hygiene + 16 rfc5280 + 9 pqc + … = 70). `EXPIRED_*` constants unchanged.

### 4. `crates/cli/tests/output.rs` (ADD only)

- `mini-zlint --source pqc --now 1796083200 pqc_mlkem_good.pem` reports the `[pqc]` group with all 9 PQC
  lints (5 signature NotApplicable on a KEM key, 4 ML-KEM applicable/passed), in the documented
  `SOURCE_ORDER` position (after `[rfc5280]`).
- `--source pqc` on a non-PQC cert (`good.pem`) reports the `[pqc]` group with all 9 lints NotApplicable
  (universal source filtered in, lints self-gate out).
- Do NOT change any existing assertion or constant.

### 5. Feature-06 golden snapshots

- The existing golden fixtures are RSA, so the four new ML-KEM lints stay `NotApplicable` on them
  (self-gate) — the per-cert `[pqc]` grouping for those fixtures gains 4 NotApplicable slots, which MAY
  change a verbose/grouped snapshot's content. Run `cargo test -p mini-zlint` (or the golden harness)
  and, if (and only if) a snapshot's content changed, regenerate it via the project's snapshot-update
  flow and review the diff to confirm ONLY the expected `[pqc]` slots / new ML-KEM rows changed (no
  existing outcome flipped). If no snapshot changed, drop the snapshot files from the committed diff.
- Check whether any inspect snapshot (e.g. `inspect__slh_dsa_ca_text`) needs a sibling for ML-KEM; the
  brief does not require an ML-KEM inspect fixture, so do NOT add one unless a golden run demands it.

## Acceptance Criteria

- [ ] 5 new openssl-generated ML-KEM fixtures (clean leaf openssl-native via `-force_pubkey`; deviations
      via documented openssl config / DER byte-patch / direct-invocation-with-deferral); NO existing
      fixture modified; `generate.sh` ML-KEM section carries the version check + fragility header +
      per-fixture producibility notes + the byte-patch-invalidates-signature caveat.
- [ ] The clean leaf passes the ML-KEM set; each violating (or direct-invocation) case isolates exactly
      its one ML-KEM rule.
- [ ] `pqc.rs` covers: per-ML-KEM-lint flag/pass; the part-3 dataEncipherment/encipherOnly/decipherOnly
      Errors on a PQC signature key; scoping (NotApplicable on non-ML-KEM incl. ML-DSA / Applies on
      ML-KEM); and the no-cascade assertion in BOTH directions incl. no spurious cabf_br on the clean KEM
      leaf.
- [ ] `registry.rs` integration count bumped 66 → 70; CLI e2e for `--source pqc` added (ML-KEM cert +
      non-PQC cert cases); existing CLI/registry tests unchanged.
- [ ] Golden snapshots regenerated only if content changed, with the diff reviewed (no flipped outcomes).
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass (also
      `cargo test -p linter --features serde`).

## Notes / Dependencies

- Depends on dev-04 (the four ML-KEM lints registered + universal source already wired).
- The architect verified the `-force_pubkey` recipe and the ML-KEM-768 encapsulation-key length (1184) on
  OpenSSL 3.6.2 at planning time; re-confirm ML-KEM-512 (800) and ML-KEM-1024 (1568) if you mint those.
