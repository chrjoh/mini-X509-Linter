# Test Plan: CA/Browser Forum S/MIME BR Rule Set

## Scope

Verify the ~12 EKU-gated `cabf_smime` lints, the new `RuleSource::CabfSmime`, the new
`CertPurpose::Smime` and its `auto` resolution, and the CLI wiring (`--source cabf_smime`,
`--purpose smime`, output ordering). Prove the cascade-avoidance design: every smime lint is
`NotApplicable` on all pre-existing fixtures, so NO existing fixture or cross-feature test is
changed.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER; `.unwrap()`/`.unwrap_err()` over
`assert!(is_ok/is_err)`; behaviour-focused tests grouped per lint in nested modules. One fixture per
lint that violates exactly that rule; `cabf_smime_good.pem` passes them all.

## ⚠️ Time-Fragility

S/MIME leaf fixtures use a currently-valid window aligned with feature 05 (`2026-06-01 →
2027-06-01`, 365d). They EXPIRE 2027-06-01; after that `hygiene_not_expired` fires on them and the
isolation tests fail. `generate.sh`'s appended S/MIME section and the `cabf_smime.rs` module doc
must say so. Regenerate annually (slide the window forward).

## Fixtures (`testdata/`) — all NEW, openssl-generated, NEVER cert-bar

Each asserts `emailProtection` EKU (so it stays in scope) and is otherwise rfc5280 + hygiene clean
(RSA-2048/SHA-256, v3, positive serial, 365d currently-valid).

- `cabf_smime_good.pem` — clean S/MIME leaf: emailProtection EKU, SAN rfc822Name = email-shaped CN,
  KeyUsage present + critical, AKI present, CRL DP http URI, single subject emailAddress, country
  `US`. Passes the full registry.
- `cabf_smime_no_san.pem` → `cabf_smime_san_present`
- `cabf_smime_san_critical.pem` → `cabf_smime_san_not_critical`
- `cabf_smime_cn_email_not_in_san.pem` → `cabf_smime_email_in_san`
- `cabf_smime_two_email_subject.pem` → `cabf_smime_single_email_subject`
- `cabf_smime_no_key_usage.pem` → `cabf_smime_key_usage_present`
- `cabf_smime_key_usage_not_critical.pem` → `cabf_smime_key_usage_critical`
- `cabf_smime_eku_server_auth.pem` → `cabf_smime_eku_no_server_auth`
- `cabf_smime_no_aki.pem` → `cabf_smime_authority_key_identifier_present`
- `cabf_smime_no_crl_dp.pem` → `cabf_smime_crl_distribution_points_present`
- `cabf_smime_crl_dp_ldap.pem` → `cabf_smime_crl_distribution_points_http`
- `cabf_smime_bad_country.pem` → `cabf_smime_subject_country_valid`

(`cabf_smime_eku_email_protection_present` has no fixture — it cannot fire under the gate; covered by
a developer `check()`-level unit test on the defensive path.)

## Unit Tests (in `cert.rs`, developer task 01)

- `san_rfc822_names`, `subject_email_addresses`, `subject_country_names`,
  `crl_distribution_point_uris`: return the expected values from the clean S/MIME fixture and empty
  vecs when the relevant extension/RDN is absent.
- `has_email_protection`, `has_authority_key_identifier`, `has_crl_distribution_points`: true on the
  clean S/MIME fixture, false on a fixture lacking each.
- `EkuView.email_protection` set correctly.

## Unit Tests (per lint file, developer task 02)

- A factored `evaluate(...)` pure-decision helper per lint, tested with plain inputs (pass + fire
  cases), mirroring `cabf_br/ext_key_usage_server_auth_present.rs`.
- `applies()` returns `Applies` on an emailProtection leaf and `NotApplicable` on a CA / a
  non-emailProtection leaf (the EKU gate).
- `id()` / `source()` correct (`cabf_smime_*`, `RuleSource::CabfSmime`).

## Registry / Purpose Unit Tests (developer task 03, in `registry.rs`)

- `contains_the_known_lints`: count 32 → 44 off current main (12 smime lints); add the twelve
  `cabf_smime_*` ids. `sample_cert()` is a CA without emailProtection ⇒ smime lints NotApplicable
  but still one outcome each ⇒ outcome count == 44.
- `cabf_smime_source_filter_runs_exactly_the_cabf_smime_set`: 12 outcomes, all `CabfSmime`, the
  twelve ids, none from `rfc5280_`/`hygiene_`/`cabf_br_`.
- `Smime` purpose: `allowed_sources == [Rfc5280, Hygiene, CabfSmime]`; `resolve`/`allowed_sources`
  consistency; `auto` on an emailProtection-only leaf resolves to `Smime`; serverAuth wins when both
  EKUs present; `Err` fails closed to generic. Use the `auto_*_from(...)` pure helpers so no extra
  fixture is required for the decision branches.
- Existing rfc5280 (16) / hygiene (4) / cabf_br (12) filter counts UNCHANGED (baseline after feature 12).

## CLI Unit Tests (developer task 03)

- `select_sources` accepts `cabf_smime` (single and in a comma list); rejects unknown tokens still.
- `cli_purpose_conversion` maps `Smime → CertPurpose::Smime`.
- `effective_sources`: `--purpose smime` keeps `cabf_smime`, drops `cabf_br`; intersection with
  `--source` honoured.
- `output.rs` `SOURCE_ORDER`/`source_label` carry `cabf_smime` (a group-order assertion if present).

## Integration Tests (`crates/linter/tests/cabf_smime.rs`)

- Per lint: its fixture flagged with a relevant message at the expected severity; `cabf_smime_good`
  passes it.
- `cabf_smime_good.pem` over `default_registry().run()` → no Error/Fatal from any source.
- Each violating fixture isolates EXACTLY its one rule across the full registry
  (`firing == vec![expected]`).
- Multi-finding where applicable (one finding per offending CN / URI / country).
- **Cascade-avoidance proof:** every `cabf_smime` lint is `NotApplicable` on `good.pem` (TLS leaf,
  no emailProtection) and on `rfc5280_ca_bc_not_critical.pem` (CA).

## Cross-Feature Regression (must pass UNCHANGED — do NOT edit)

The EKU gate guarantees these stay green with only added `NotApplicable` outcomes:

- `crates/linter/tests/rfc5280.rs`, `hygiene.rs`, `cabf_br.rs` isolation tests.
- `crates/linter/tests/registry.rs` expired invariants.
- `crates/cli/tests/output.rs` (the feature-06 golden / source-group assertions): adding a
  `cabf_smime` group to `SOURCE_ORDER` MUST NOT change the rendered output for certs that have zero
  cabf_smime outcomes in scope (an empty group is skipped by `render_group_block`). Verify the
  existing golden assertions still hold; if a golden snapshot enumerates groups, confirm an empty
  smime group does not appear. If it does change, that is a wiring bug to report, not a snapshot to
  bless.

## Edge Cases

- Email match policy: domain part case-insensitive (document + test); local-part policy documented.
- Subject with no CN / no email CN → `email_in_san` silent.
- Subject with no country → `subject_country_valid` silent.
- No CRL DP → `crl_distribution_points_http` silent (only the presence lint fires).
- KeyUsage absent → `key_usage_critical` silent (only the presence lint fires).
- A cert with BOTH emailProtection and serverAuth: in scope for smime, `eku_no_server_auth` fires;
  under `auto` it resolves to `TlsServer` (serverAuth precedence) — confirm both behaviours.

## Verification Commands

```
cargo test
cargo test -p linter --features serde
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features serde -- -D warnings
cargo fmt --check
bash testdata/generate.sh
```

## Exit Criteria

All ~12 smime lints validated against dedicated fixtures and the clean leaf; EKU-gated scoping
confirmed (NotApplicable on all pre-existing fixtures); each violating fixture isolates exactly its
one rule across the 26-lint registry; registry count/filter + `Smime` purpose + `auto` resolver
tests pass; CLI `--source cabf_smime` / `--purpose smime` work; NO existing fixture or cross-feature
test changed; all verification commands pass.
