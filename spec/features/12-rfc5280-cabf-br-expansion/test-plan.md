# Test Plan: RFC 5280 & CA/Browser Forum BR Depth Expansion

## Scope

Verify the new feature-12 lints added to the EXISTING `RuleSource::Rfc5280` (10 lints) and
`RuleSource::CabfBr` (8 lints) sources. No new RuleSource/CertPurpose, no engine change. RFC lints
scope per their nature (universal / CA-only / extension-present-only); BR lints use feature 05's BROAD
scoping (`NotApplicable` on CA, `Applies` on every non-CA leaf, NOT EKU-gated).

**Central invariant: NO existing fixture is regenerated.** Every new lint either PASSes or is
`NotApplicable` on the current `good.pem` and all existing leaf fixtures (verified in plan's "good.pem
Conformance Audit"). The test suite must confirm this — the existing isolation/invariant tests pass
UNCHANGED over the grown 24-lint registry.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()`, behaviour-focused tests
grouped per lint in nested modules. One openssl-generated fixture per new lint; never hand-author cert
bytes beyond DER byte-patching.

## Registry counts (after expansion)

- Total: 14 → **24** (`registry.len()`, `outcomes.len()` on a CA sample cert).
- rfc5280 filter: 6 → **16**. cabf_br filter: 4 → **12**. hygiene: **4** (unchanged).
- (Adjust by −1 per any pre-approved cut, e.g. `rfc5280_utc_time_not_in_zulu`, with the cut documented.)

## New fixtures (`testdata/`, all openssl-generated)

RFC: `rfc5280_ca_subject_empty.pem`, `rfc5280_eku_empty.pem`, `rfc5280_aki_no_keyid.pem`,
`rfc5280_ski_missing_ca.pem`, `rfc5280_ski_missing_sub_cert.pem`, `rfc5280_path_len_on_leaf.pem`,
`rfc5280_name_constraints_not_critical.pem`, `rfc5280_country_not_printable.pem`,
`rfc5280_san_empty.pem`, `rfc5280_utctime_not_zulu.pem`.

BR: `cabf_br_dnsname_underscore.pem`, `cabf_br_dnsname_bad_char.pem`,
`cabf_br_dnsname_label_too_long.pem`, `cabf_br_dnsname_bare_wildcard.pem`, `cabf_br_ou_present.pem`,
`cabf_br_cn_reserved_ip.pem`, `cabf_br_two_common_names.pem`, `cabf_br_country_not_iso.pem`.

Each is BR-compliant-except-its-one-target (or a CA where the lint is CA-only), reusing the existing
`BR_OK` / CA windows. Existing fixtures are UNCHANGED.

## Unit Tests (in-file, owned by the developer tasks — listed for coverage tracking)

- `cert.rs` (task 01): each new accessor — positive + absent/negative case (AKI present/absent,
  SKI present/absent, NameConstraints critical/absent, EKU empty/non-empty, country
  printable/non-printable/absent, OU count, validity time-encoding UTCTime-Zulu vs not).
- Each new lint file (tasks 02/03): a pass and a fail case, plus `applies()` scoping
  (CA-only / extension-present / broad).

## Integration Tests

### `crates/linter/tests/rfc5280.rs` (extend)

- Per new RFC lint: fixture → ≥1 finding (severity + message substring); `good.pem` → no rfc5280
  Error/Fatal.
- `rfc5280_ext_subject_key_identifier_missing_sub_cert` asserts `Warn` (SHOULD), not `Error`.
- CA-only new lints (`ca_subject_field_empty`, `ski_missing_ca`, and `path_len_improperly_included`
  when applied to a leaf) report the correct `applies()` result.
- Extend `each_fixture_isolates_exactly_one_rfc5280_violation` to the new rfc5280 fixtures: each fires
  exactly its one rule across the 24-lint registry and no BR rule.

### `crates/linter/tests/cabf_br.rs` (extend)

- Per new BR lint: fixture flagged with a descriptive message; `good.pem` passes (no BR findings).
- Multi-finding cases (several bad-char SAN names → several findings).
- All new BR lints `NotApplicable` on a CA cert.
- `subject_country_not_iso`: no-country cert silent; bad-country fixture flagged.
- `dnsname_wildcard_left_of_public_suffix`: `*.com` flagged; `*.example.com` (multi-label) NOT flagged
  (conservative rule); confirm with a small positive/negative pair.
- Extend BR isolation coverage to the new BR fixtures.

### `cabf_br_cn_reserved_ip.pem` exception (document the chosen approach)

The CN is an IP, and `cabf_br_cn_in_san` requires the CN in SAN, which also trips the existing
SAN-reserved-IP lint. This fixture cannot be perfectly single-rule. The tester picks and DOCUMENTS:
(a) accept a two-rule fixture and assert BOTH reserved-IP rules fire (excluding it from the strict
one-rule isolation loop), or (b) construct a genuinely single-rule variant if achievable. State the
choice in the test.

## Golden Snapshot (feature 06)

- Regenerate to include the 24-lint outcomes. Existing rows unchanged in order; new rows appended.
- If regeneration would touch a file outside the tester task's `touches`, FLAG to the architect.

## Cross-Feature Regression (verify UNCHANGED — must NOT need edits)

- `crates/linter/tests/hygiene.rs`, `crates/linter/tests/registry.rs`, `crates/cli/tests/output.rs`:
  pass unchanged. `EXPIRED_NOT_AFTER` constants and the `(3 passed, 3 not applicable)` rfc5280-group
  assertion are untouched (no existing fixture/window/encoding changed). If any of these needs a
  change, an existing fixture was inadvertently affected — STOP and FLAG; do NOT paper over it.

## Edge Cases

- EKU present-but-empty vs EKU with `any` only (the latter is NOT "without bits").
- AKI present with keyIdentifier (pass) vs AKI present without it (fail) vs AKI absent (NotApplicable).
- Path-len on a proper CA-with-keyCertSign (pass) vs on a leaf (fail).
- DNS label exactly 63 octets (pass) vs 64 (fail) — boundary.
- Country `US` (pass), `XX` (pass), `ZZ`/`USA` (fail), absent (silent).
- Multiple CNs: exactly 1 (pass), 2 (fail with count in message).
- UTCTime ending in `Z` (pass) vs offset form (fail); GeneralizedTime path is out of scope (cut).

## Verification Commands

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
bash testdata/generate.sh
```

## Exit Criteria

All new RFC + BR lints validated against dedicated openssl fixtures; scoping correct (universal /
CA-only / extension-present / broad-leaf); each new fixture isolates exactly its one new rule across
the 24-lint registry (with the one documented `cabf_br_cn_reserved_ip` exception); NO existing fixture
regenerated and all existing isolation/invariant tests pass UNCHANGED; registry count/filter unit
tests updated (24 / 16 / 12 / 4); golden snapshot regenerated; verification commands pass. Any
pre-approved cut (utctime/path-len/country) is documented, not silently faked.
