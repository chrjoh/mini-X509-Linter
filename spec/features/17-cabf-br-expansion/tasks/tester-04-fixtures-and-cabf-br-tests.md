---
agent: tester
seq: 4
title: Feature-17 fixtures + per-lint/isolation cabf_br tests
status: done
touches:
  - testdata/generate.sh
  - testdata/keys/good.key
  - testdata/good.pem
  - testdata/cabf_br_ku_cert_sign.pem
  - testdata/cabf_br_ku_crl_sign.pem
  - testdata/cabf_br_leaf_path_len.pem
  - testdata/cabf_br_eku_any.pem
  - testdata/cabf_br_eku_no_server_auth.pem
  - testdata/cabf_br_san_email_entry.pem
  - testdata/cabf_br_no_san.pem
  - testdata/cabf_br_no_policies.pem
  - testdata/cabf_br_policies_no_reserved.pem
  - testdata/cabf_br_rsa_mod_not_oct.pem
  - testdata/cabf_br_rsa_exp_3.pem
  - testdata/cabf_br_no_basic_constraints.pem
  - crates/linter/tests/cabf_br.rs
depends_on:
  - developer-03-register-expansion-lints
---

# Task: Feature-17 fixtures + per-lint/isolation cabf_br tests

## Goal

Regenerate `good.pem` ONCE (pinned key + a `certificatePolicies` DV OID) so it is BR-compliant and
finding-free, add ONE openssl-generated violating fixture per new lint, write per-lint flag/pass tests,
extend the existing isolation tests to the new fixtures, and verify the OTHER existing fixtures'
isolation tests still pass. **good.pem is the ONLY existing fixture regenerated** (and its key is
pinned so SKI/serial stay byte-stable); all other existing fixtures are untouched.

## Time / clock (pinned — load-bearing)

New leaf fixtures reuse the existing `BR_OK` window (2026-06-01 → 2027-06-01) and share feature 05's
annual expiry chore. Linter tests use `default_registry_with_now(Some(TEST_NOW))` with
TEST_NOW = 1_796_083_200 (2026-12-01). No dynamic dates.

## Files Owned (conflict scope)

- `testdata/generate.sh` (ADD the new fixtures; ADD the pinned-key + certificatePolicies handling for
  good.pem; do NOT alter OTHER existing recipes or windows).
- `testdata/keys/good.key` (NEW committed pinned RSA-2048 key for good.pem).
- `testdata/good.pem` (REGENERATED once — pinned key + certificatePolicies DV OID).
- The 12 new `.pem` listed in front-matter.
- `crates/linter/tests/cabf_br.rs` (extend with new cases).

Does NOT modify `cert.rs`, `registry.rs`, any `src/lints/`, any OTHER existing fixture `.pem`, or any
CLI snapshot (those ripple in tester-05).

## Steps

### 0. Regenerate good.pem with a PINNED key + certificatePolicies (load-bearing — do this FIRST)

good.pem must become BR-compliant so the new CertificatePolicies lints (8/9) PASS on it and good.pem
stays completely finding-free. Do this with MINIMAL, byte-deterministic churn by **pinning good.pem's
RSA key** (the preferred approach in the plan's "good.pem regeneration strategy"):

1. Generate ONCE and COMMIT a fixed RSA-2048 key at `testdata/keys/good.key`
   (`openssl genrsa -out testdata/keys/good.key 2048`). Commit it; it must NOT be re-rolled on future
   `generate.sh` runs.
2. In `generate.sh`, sign good.pem from that pinned key instead of the shared re-rolled `$KEY`. good.pem
   is self-signed, so a dedicated `-signkey testdata/keys/good.key` (a `GOOD_KEY="$HERE/keys/good.key"`)
   affects no other fixture. Keep the existing serial (`-set_serial 17`), the `BR_OK` window
   (2026-06-01 → 2027-06-01, bracketing TEST_NOW = 1_796_083_200), RSA-2048/SHA-256, CA:FALSE,
   serverAuth, and SAN `DNS:good.example.com`.
3. ADD `certificatePolicies=2.23.140.1.2.1` (the CABF DV reserved OID) to good.pem's extension config
   (`EXT_GOOD` / its `make_leaf_ext` block — add the line; if `make_leaf_ext` is reused by other
   fixtures, set the policies line on good.pem's ext file specifically so OTHER leaves are unaffected).
   openssl only; recipe parity in `generate.sh`.
4. Run `bash testdata/generate.sh` and confirm with `openssl x509 -in testdata/good.pem -noout -text`:
   the `X509v3 Certificate Policies: Policy: 2.23.140.1.2.1` extension is present, and the
   SubjectKeyIdentifier still reads `1D:33:53:BC:F1:E7:31:96:F9:67:D2:FC:72:0A:F0:96:7D:2F:4C:13` and
   the serial is still `17` (0x11). **If the SKI/serial changed, the key was not actually pinned —
   STOP and fix the pinning** (the whole point is byte-stable SKI/serial so the two `inspect__*`
   snapshots and the README `--info` example do NOT move).

> FALLBACK (only if pinning genuinely cannot work): accept the re-rolled SKI. You must then FLAG the
> architect, because the two `inspect__*` snapshots
> (`inspect__good_cert_text__good_info_text.snap`, `inspect__json_envelope__good_info_json_summary.snap`)
> and the README `--info` good.pem SKI example fall OUTSIDE this task's `touches` and are tester-05's
> scope (which would need widening). cert.rs has NO hardcoded good.pem SKI assertion, so nothing in
> cert.rs needs editing in either branch. **Prefer pinning** — it keeps churn to the lint-report
> snapshots only.

### 1. Add fixtures to `generate.sh` (openssl only; byte-patch only where noted)

Add one violating fixture per new lint, each isolating EXACTLY its one new rule across the FULL 82-lint
registry AND firing no OLD rule, EXCEPT the two documented intentional co-fires. Reuse the existing
`make_leaf_ext`/`sign_csr` helpers and the `BR_OK` window. Public names use `*.example.com`. Keep a
compliant `DNS:<cn>` SAN entry on every leaf so `cabf_br_cn_in_san` stays quiet, and ensure no name is
internal/reserved (so `cabf_br_no_internal_names_or_reserved_ip` stays quiet) and labels stay LDH/short
unless that is the target. Use the plan's Fixture Strategy table for shapes:

- `cabf_br_ku_cert_sign.pem` — KeyUsage with `keyCertSign`, CA:FALSE.
- `cabf_br_ku_crl_sign.pem` — KeyUsage with `cRLSign`, CA:FALSE.
- `cabf_br_leaf_path_len.pem` — BasicConstraints CA:FALSE with `pathlen:0`. If openssl refuses pathlen
  with CA:FALSE, byte-patch or use an explicit ext file. **Intentional two-rule co-fire** with the
  feature-12 `rfc5280_path_len_constraint_improperly_included` — assert BOTH and exclude from the
  strict exactly-one-rule loop (document it).
- `cabf_br_eku_any.pem` — EKU = `serverAuth, anyExtendedKeyUsage`.
- `cabf_br_eku_no_server_auth.pem` — EKU = `clientAuth` only. See §3 below for the overlap decision.
- `cabf_br_san_email_entry.pem` — SAN = `DNS:<cn>` + `email:a@example.com`.
- `cabf_br_no_san.pem` — NO SAN, non-empty subject DN, else compliant. (Confirm `cabf_br_san_present`
  fires `Warn`; confirm no rfc5280 SAN rule fires — `rfc5280_san_present_if_subject_empty` only fires
  on an EMPTY subject.)
- `cabf_br_no_policies.pem` — NO CertificatePolicies, else compliant. (Fires `cabf_br_certificate_policies_present`
  `Warn`. NOTE good.pem does NOT fire this `Warn` — it now carries a `certificatePolicies` DV OID; this
  dedicated no-policies fixture is what asserts the `Warn` cleanly.)
- `cabf_br_policies_no_reserved.pem` — CertificatePolicies present with a single non-reserved OID
  (e.g. `1.3.6.1.4.1.99999.1`).
- `cabf_br_rsa_mod_not_oct.pem` — RSA key whose modulus bit length is not a multiple of 8. openssl
  RSA keygen produces byte-aligned moduli; byte-patching the modulus is acceptable if it yields a
  structurally parseable cert. If a non-octet modulus genuinely cannot be minted, FLAG the architect
  for an alternative recipe — lint 10 is NOT cut (all 12 lints are kept).
- `cabf_br_rsa_exp_3.pem` — RSA-2048 key with public exponent 3 (`-pkeyopt rsa_keygen_pubexp:3`).
- `cabf_br_no_basic_constraints.pem` — NO BasicConstraints extension, else compliant. (Fires
  `cabf_br_basic_constraints_present` `Warn`; audit it trips no rfc5280 rule.)

Run `bash testdata/generate.sh` and commit every new `.pem` with recipe-parity in `generate.sh`.

### 2. `crates/linter/tests/cabf_br.rs` — per-lint flag/pass + multi-finding + CA-NotApplicable

- Per new lint: its fixture → expected finding(s) (correct severity + a relevant message substring);
  `good.pem` → **no finding at all from any of the 12 new lints** (no Error AND no Warn). Assert
  explicitly that good.pem passes lints 8 and 9 (CertificatePolicies present + reserved DV OID present),
  so the regeneration is documented, not silent.
- `cabf_br_san_dns_or_ip_only`: a SAN with two non-DNS/IP entries → multiple `Finding`s.
- `Warn`-severity lints (`san_present`, `certificate_policies_present`, `basic_constraints_present`):
  assert the finding severity is `Warn`, not `Error`.
- All 12 new BR lints `NotApplicable` on a CA cert (use an existing CA fixture, e.g.
  `rfc5280_ca_bc_not_critical.pem`).

### 3. Existing-fixture cascade audit (verify; only good.pem is regenerated) — load-bearing

- Confirm the existing `each_fixture_isolates_exactly_one_*` / per-fixture isolation tests key on
  **Error/Fatal severity** (not total finding count). If they key on count, reconcile that ONE
  assertion (documented) — do NOT regenerate the fixture.
- `rfc5280_empty_subject_no_san.pem`: now gains a `cabf_br_san_present` `Warn`. Verify its single-Error
  isolation test still holds (Warn-keyed-out). If it keys on total count, reconcile that ONE assertion
  (documented). Lint 7 is KEPT (Phase-1.5 decision 1) — do NOT cut it; do NOT regenerate the fixture.
- `cabf_br_missing_serverauth.pem` (EKU present without serverAuth): lint 5
  (`ext_key_usage_server_auth_required`) is KEPT (Phase-1.5 decision 2). This fixture CO-FIRES the
  existing `cabf_br_ext_key_usage_server_auth_present` AND lint 5 (both Error). SETTLED RESOLUTION
  (implement, do not re-decide): make lint 5's own `cabf_br_eku_no_server_auth.pem` the single-rule
  isolating fixture, and reconcile `cabf_br_missing_serverauth.pem`'s isolation test to a **documented
  two-rule assertion** that asserts the TWO related serverAuth rules co-fire (feature-12
  underscore/bad-char precedent). Lint 5 is NOT cut.
- good.pem now PASSES lint 8 (it carries `certificatePolicies`), so it emits NO `Warn`. Every OTHER
  compliant leaf that lacks CertificatePolicies still emits a `cabf_br_certificate_policies_present`
  `Warn` — that does not break any single-Error isolation test, but DOES change golden snapshots
  (tester-05 owns those).

### 4. Isolation coverage for the new fixtures

- Extend the BR isolation coverage so each new fixture fires exactly its one new rule across the
  82-lint registry (and no OLD rule), with the two documented exceptions: `cabf_br_leaf_path_len.pem`
  (two-rule: BR + RFC path-len) and `cabf_br_eku_no_server_auth.pem` (two-rule: existing + new
  serverAuth — lint 5 is kept). The `Warn`-only fixtures (`cabf_br_no_san.pem`, `cabf_br_no_policies.pem`,
  `cabf_br_no_basic_constraints.pem`) fire exactly their one new `Warn` and no Error.

### 5. Regression verification (verify only)

- `crates/linter/tests/hygiene.rs`, `crates/linter/tests/rfc5280.rs`,
  `crates/linter/tests/registry.rs`: must still pass. The only expected interaction is the additive
  `Warn`s on compliant leaves; if any EXISTING fixture's Error-set changes, STOP and FLAG (it means a
  lint mis-shaped).

## Acceptance Criteria

- [ ] good.pem regenerated with a PINNED key (`testdata/keys/good.key`, committed) + a
      `certificatePolicies` DV OID `2.23.140.1.2.1`. SKI still
      `1D:33:53:BC:F1:E7:31:96:F9:67:D2:FC:72:0A:F0:96:7D:2F:4C:13` and serial still `17` (verified via
      `openssl x509 -text`); if either changed, the key was not pinned — fix it.
- [ ] 12 new openssl-generated fixtures added (recipe-parity in `generate.sh`), each isolating exactly
      its one new rule across the 82-lint registry, except the two documented intentional co-fires; NO
      existing fixture OTHER than good.pem regenerated.
- [ ] Per-new-lint flag/pass tests in `cabf_br.rs`; `Warn` lints assert `Warn` severity; multi-finding
      case for `san_dns_or_ip_only`; all 12 `NotApplicable` on a CA.
- [ ] good.pem asserted to emit NO finding from any of the 12 new lints (no Warn, no Error), and to
      PASS lints 8 and 9 (policies present + reserved DV OID present).
- [ ] `cabf_br_missing_serverauth.pem` isolation test reconciled to a documented two-rule assertion
      (lints 5 + existing serverAuth), and `rfc5280_empty_subject_no_san.pem` isolation test still holds
      (Warn-keyed or reconciled). No lint cut; no fixture other than good.pem regenerated.
- [ ] `cargo test` (linter crate), `cargo clippy --all-targets -- -D warnings`,
      `cargo fmt --check`, and `bash testdata/generate.sh` all pass cleanly.
- [ ] If `cabf_br_leaf_path_len.pem` or `cabf_br_rsa_mod_not_oct.pem` cannot be minted (even
      byte-patched), FLAG the architect for an alternative recipe — the lint is NOT cut, nothing faked.
- [ ] If the pinned-key approach fails and the SKI re-rolls, FLAG the architect (the two `inspect__*`
      snapshots + README `--info` example fall outside this task's scope and tester-05 must be widened).

## Notes / Dependencies

- Depends on developer-03 (the 82-lint registry exists). Blocks tester-05 (CLI golden/count ripple).
- Sole owner of fixtures + `crates/linter/tests/cabf_br.rs`. CLI snapshots are tester-05's scope — if a
  CLI snapshot or `output.rs` count needs changing, FLAG it for tester-05 (do not edit it here).
</content>
