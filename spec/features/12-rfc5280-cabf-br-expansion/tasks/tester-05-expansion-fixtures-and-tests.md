---
agent: tester
seq: 5
title: Expansion fixtures + per-lint/isolation tests + golden snapshot
status: pending
touches:
  - testdata/generate.sh
  - testdata/rfc5280_ca_subject_empty.pem
  - testdata/rfc5280_eku_empty.pem
  - testdata/rfc5280_aki_no_keyid.pem
  - testdata/rfc5280_ski_missing_ca.pem
  - testdata/rfc5280_ski_missing_sub_cert.pem
  - testdata/rfc5280_path_len_on_leaf.pem
  - testdata/rfc5280_name_constraints_not_critical.pem
  - testdata/rfc5280_country_not_printable.pem
  - testdata/rfc5280_san_empty.pem
  - testdata/rfc5280_utctime_not_zulu.pem
  - testdata/cabf_br_dnsname_underscore.pem
  - testdata/cabf_br_dnsname_bad_char.pem
  - testdata/cabf_br_dnsname_label_too_long.pem
  - testdata/cabf_br_dnsname_bare_wildcard.pem
  - testdata/cabf_br_ou_present.pem
  - testdata/cabf_br_cn_reserved_ip.pem
  - testdata/cabf_br_two_common_names.pem
  - testdata/cabf_br_country_not_iso.pem
  - crates/linter/tests/rfc5280.rs
  - crates/linter/tests/cabf_br.rs
depends_on:
  - developer-04-register-expansion-lints
---

# Task: Expansion fixtures + per-lint/isolation tests + golden snapshot

## Goal

Add ONE openssl-generated violating fixture per new lint, write per-lint flag/pass tests, extend the
existing isolation tests to the new fixtures, and regenerate the feature-06 golden snapshot for the
24-lint registry. **No existing fixture is regenerated** (see plan's good.pem Conformance Audit) — only
NEW fixtures are added. Verify the existing isolation/invariant tests still pass UNCHANGED.

## ⚠️ Time-Fragility (inherited)

New leaf fixtures reuse the existing `BR_OK` window (2026-06-01 → 2027-06-01). They share feature 05's
annual expiry chore (regenerate before 2027-06-01). `generate.sh` already documents this; new fixtures
reuse the existing constants — no new dating note needed beyond reusing `BR_OK_*`/CA windows.

## Files Owned (conflict scope)

- `testdata/generate.sh` (ADD the new fixtures; do NOT alter the existing fixture recipes or windows).
- The 18 new `.pem` listed in front-matter.
- `crates/linter/tests/rfc5280.rs`, `crates/linter/tests/cabf_br.rs` (extend with new cases).
- The feature-06 golden snapshot file (regenerate it). NOTE: that snapshot lives under the feature-06
  test directory; if regenerating it requires editing a file not in this front-matter, FLAG it to the
  architect rather than silently editing an out-of-scope file.

Does NOT modify `cert.rs`, `registry.rs`, any `src/lints/`, or the existing fixture `.pem`.

## Steps

### 1. Add fixtures to `generate.sh` (openssl only; never hand-author cert bytes beyond byte-patching)

Add one violating fixture per new lint, each isolating EXACTLY its one new rule across the FULL 24-lint
registry AND firing no OLD rule. Use the plan's "Fixture Strategy" table for shapes. Reuse the existing
`make_leaf_ext`/`sign_csr` helpers and `BR_OK`/CA windows. Public names use `*.example.com` (per the
existing reserved-name note) unless the target requires otherwise.

- RFC: `rfc5280_ca_subject_empty.pem` (CA, empty subject), `rfc5280_eku_empty.pem` (EKU present but
  empty), `rfc5280_aki_no_keyid.pem` (AKI without keyIdentifier), `rfc5280_ski_missing_ca.pem`
  (CA, no SKI), `rfc5280_ski_missing_sub_cert.pem` (leaf, no SKI, else compliant → only the Warn),
  `rfc5280_path_len_on_leaf.pem` (pathlen with CA:FALSE), `rfc5280_name_constraints_not_critical.pem`
  (NameConstraints present, not critical), `rfc5280_country_not_printable.pem` (subject C as
  UTF8String/IA5String), `rfc5280_san_empty.pem` (SAN present, zero entries), `rfc5280_utctime_not_zulu.pem`
  (UTCTime not ending in Z).
- BR: `cabf_br_dnsname_underscore.pem` (`DNS:foo_bar.example.com` + compliant CN-in-SAN),
  `cabf_br_dnsname_bad_char.pem` (illegal char in a label), `cabf_br_dnsname_label_too_long.pem`
  (64-octet label), `cabf_br_dnsname_bare_wildcard.pem` (`DNS:*.com`), `cabf_br_ou_present.pem`
  (subject has an OU), `cabf_br_cn_reserved_ip.pem` (CN=`10.0.0.1`), `cabf_br_two_common_names.pem`
  (two CN attributes, both in SAN), `cabf_br_country_not_iso.pem` (C=`ZZ` or `USA`).

Isolation caveats to honor (each fixture must fire ONLY its one new rule, and NO existing rule):
- DNS-syntax fixtures: keep a separate compliant `DNS:<cn>` entry so `cabf_br_cn_in_san` stays quiet;
  ensure the bad name is not internal/reserved (so `cabf_br_no_internal_names_or_reserved_ip` stays
  quiet) and not over-long unless that is the target.
- `cabf_br_dnsname_bare_wildcard.pem`: confirm `reserved.rs::is_internal_name` does NOT classify
  `*.com` as internal; give it a normal compliant CN present in SAN.
- `cabf_br_cn_reserved_ip.pem`: the CN is an IP, so `cabf_br_cn_in_san` requires that IP in SAN, which
  also trips the existing SAN-reserved-IP lint. This fixture CANNOT be perfectly single-rule. CHOOSE
  and DOCUMENT one approach: (a) accept a two-rule fixture and assert BOTH the new CN-reserved-IP rule
  and the existing SAN-reserved-IP rule fire (and exclude this fixture from the strict
  exactly-one-rule isolation loop, asserting its two-rule set explicitly), OR (b) construct it so only
  the CN-reserved-IP rule fires if achievable. Document the decision in the test.
- `rfc5280_country_not_printable.pem` / `rfc5280_utctime_not_zulu.pem`: if openssl cannot emit the
  non-PrintableString country / non-Zulu UTCTime, byte-patch the DER (as the existing version-byte
  patch does) or use an explicit ext/config. If genuinely not producible, FLAG it; for utctime the
  lint cut is pre-approved (coordinate with task 01/02).
- `rfc5280_path_len_on_leaf.pem`: if openssl refuses `pathlen` with CA:FALSE, byte-patch or use an
  explicit ext file; if not producible, FLAG it (lint+fixture cut together, pre-approved).
- CA fixtures here (`rfc5280_ca_subject_empty.pem`, `rfc5280_ski_missing_ca.pem`): BR lints are
  `NotApplicable` (CA), so they isolate only their one rfc5280 rule.

Run `bash testdata/generate.sh` and commit every new `.pem`.

### 2. `crates/linter/tests/rfc5280.rs` (extend)

- Per new RFC lint: its fixture → ≥1 expected finding (severity + relevant message substring);
  `good.pem` → no rfc5280 Error/Fatal (unchanged).
- Extend `each_fixture_isolates_exactly_one_rfc5280_violation` (or add a sibling) to cover the new
  rfc5280 fixtures: each fires exactly its one rule across the 24-lint registry and no BR rule.
- SKI-missing-sub-cert fixture asserts a `Warn` (SHOULD), not `Error`.

### 3. `crates/linter/tests/cabf_br.rs` (extend)

- Per new BR lint: its fixture flagged with a descriptive message; `good.pem` passes (no BR findings).
- Multi-finding cases where applicable (e.g. a SAN with several bad-char names).
- All new BR lints `NotApplicable` on a CA cert (use `rfc5280_ca_bc_not_critical.pem` or
  `rfc5280_ca_subject_empty.pem`).
- `cabf_br_subject_country_not_iso`: no-country cert → silent; bad-country fixture → flagged.
- Extend the BR isolation coverage to the new BR fixtures (each fires exactly its one rule, with the
  documented `cabf_br_cn_reserved_ip.pem` exception).

### 4. Golden snapshot (feature 06)

- Regenerate the golden snapshot so it includes the new lint outcomes (24 lints). Confirm the existing
  rows are unchanged in order and only new rows are appended. If regeneration touches an out-of-scope
  file, FLAG to the architect.

### 5. Regression verification (no edits expected — verify only)

- `crates/linter/tests/hygiene.rs`, `crates/linter/tests/registry.rs`, `crates/cli/tests/output.rs`:
  must still pass UNCHANGED (no existing fixture/window/encoding changed, so the `EXPIRED_NOT_AFTER`
  constants and the `(3 passed, 3 not applicable)` rfc5280-group assertion are untouched). If any of
  these needs a change, that means an existing fixture was inadvertently affected — STOP and FLAG.

## Acceptance Criteria

- [ ] 18 new openssl-generated fixtures added (10 rfc5280 + 8 BR), each isolating exactly its one new
      rule across the 24-lint registry (with the one documented `cabf_br_cn_reserved_ip` exception);
      NO existing fixture regenerated.
- [ ] Per-new-lint flag/pass tests in `rfc5280.rs` and `cabf_br.rs`; SKI-sub-cert asserts `Warn`.
- [ ] Isolation coverage extended to the new fixtures; existing isolation/invariant tests pass
      UNCHANGED.
- [ ] Golden snapshot regenerated for the 24-lint registry (existing rows unchanged, new rows appended).
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, and
      `bash testdata/generate.sh` all pass cleanly.
- [ ] Any non-producible fixture (utctime/country/path-len) FLAGGED with its pre-approved lint cut, not
      silently faked.

## Notes / Dependencies

- Depends on task 04 (lints registered; the 24-lint registry exists).
- This is the sole owner of fixtures and integration tests; production `src/` is owned by tasks 01–04.
