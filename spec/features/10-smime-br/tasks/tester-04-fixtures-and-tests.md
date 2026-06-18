---
agent: tester
seq: 4
title: S/MIME fixtures + integration tests
status: done
touches:
  - testdata/generate.sh
  - testdata/cabf_smime_good.pem
  - testdata/cabf_smime_no_san.pem
  - testdata/cabf_smime_san_critical.pem
  - testdata/cabf_smime_cn_email_not_in_san.pem
  - testdata/cabf_smime_two_email_subject.pem
  - testdata/cabf_smime_no_key_usage.pem
  - testdata/cabf_smime_key_usage_not_critical.pem
  - testdata/cabf_smime_eku_server_auth.pem
  - testdata/cabf_smime_no_aki.pem
  - testdata/cabf_smime_no_crl_dp.pem
  - testdata/cabf_smime_crl_dp_ldap.pem
  - testdata/cabf_smime_bad_country.pem
  - crates/linter/tests/cabf_smime.rs
depends_on:
  - developer-03-register-purpose-and-cli-wiring
---

# Task: S/MIME fixtures + integration tests

## Goal

Add the NEW S/MIME fixtures (openssl-generated, NEVER cert-bar) and the integration tests proving
each `cabf_smime` lint isolates exactly its one rule (within the cabf_smime source via
run_filtered([CabfSmime])), the clean leaf passes the cabf_smime set, and the EKU gate keeps every
smime lint `NotApplicable` on pre-existing fixtures (so NO existing fixture is regenerated).

## Files Owned (conflict scope)

- `testdata/generate.sh` (APPEND a new S/MIME section only — do NOT alter existing generation).
- The thirteen new `cabf_smime_*.pem` fixtures (front-matter list).
- `crates/linter/tests/cabf_smime.rs` (new).

Does NOT modify any `src/`, any existing fixture, or any other test file. The cascade-avoidance EKU
gate (plan.md) means the feature-03/04/05 isolation tests and the feature-06 golden test stay green
WITHOUT edits here — verify that, do not change them.

## ⚠️ Time-Fragility (read first)

S/MIME leaf fixtures must be currently valid so `hygiene_not_expired` passes. Use a fixed
currently-valid window (align with feature 05's `2026-06-01 → 2027-06-01`, 365d). These fixtures
EXPIRE on 2027-06-01; after that `hygiene_not_expired` fires on them. Document this loudly in the
appended `generate.sh` section header AND reference it in the `cabf_smime.rs` module doc, and
regenerate annually (slide the window forward).

## Steps

### 1. Append an S/MIME section to `generate.sh`

Generate (openssl only) a clean S/MIME leaf and one per-lint violating fixture. Every fixture MUST
assert the `emailProtection` EKU (OID `1.3.6.1.5.5.7.3.4`) so it stays in scope; each violating
fixture breaks EXACTLY one rule and passes the others (and passes rfc5280 + hygiene: RSA-2048/
SHA-256, v3, positive serial, currently-valid window).

- `cabf_smime_good.pem` — emailProtection EKU; SAN with `rfc822Name` (email) matching an
  email-shaped subject CN (e.g. CN/email `user@example.com`); KeyUsage present + critical
  (digitalSignature, keyEncipherment); AKI present; CRL DP with an `http://` URI; exactly one
  subject emailAddress; subject country `US` (valid 2-letter); 365d currently-valid window. Passes
  the entire smime set.
- `cabf_smime_no_san.pem` — no SAN (or SAN without any rfc822Name) → lint 1.
- `cabf_smime_san_critical.pem` — SAN marked critical, non-empty subject → lint 2.
- `cabf_smime_cn_email_not_in_san.pem` — email-shaped CN (e.g. `cn-only@example.com`) absent from
  the SAN's rfc822Names (SAN carries a different email) → lint 3.
- `cabf_smime_two_email_subject.pem` — two `emailAddress` RDNs in the subject → lint 4.
- `cabf_smime_no_key_usage.pem` — KeyUsage extension absent → lint 5.
- `cabf_smime_key_usage_not_critical.pem` — KeyUsage present but NOT critical → lint 6.
- `cabf_smime_eku_server_auth.pem` — EKU asserts BOTH emailProtection AND serverAuth → lint 8.
- `cabf_smime_no_aki.pem` — AKI extension absent → lint 9.
- `cabf_smime_no_crl_dp.pem` — CRL DP extension absent → lint 10.
- `cabf_smime_crl_dp_ldap.pem` — CRL DP fullName URI uses `ldap://` (non-http scheme) → lint 11.
- `cabf_smime_bad_country.pem` — subject country `USA` (3 letters) → lint 12.

(Lint 7, `cabf_smime_eku_email_protection_present`, has no fixture: a cert lacking emailProtection
is NotApplicable and cannot fire normally; it is covered by the developer's `check()`-level unit
test on the defensive path. Note this in the test module doc.)

Run `bash testdata/generate.sh` and commit every new `.pem`.

### 2. `crates/linter/tests/cabf_smime.rs` (new; SIFER, `.unwrap()`/`.unwrap_err()` conventions)

- Per lint: its fixture → ≥1 expected finding with a relevant message substring (offending CN / URI
  / country / duration), at the expected severity (Error vs Warn per the plan table);
  `cabf_smime_good.pem` → empty findings for that lint.
- `cabf_smime_good.pem` over the full `default_registry().run()` → no Error/Fatal findings from ANY
  source (it is rfc5280 + hygiene + smime clean; cabf_br lints are NotApplicable because it is not a
  serverAuth leaf — confirm).
- Multi-finding case: a fixture (or the `cn_email_not_in_san` / `crl_dp_ldap`) yields one finding
  per offending entry where applicable.
- EKU-gate isolation (cascade-avoidance proof): EVERY `cabf_smime` lint is `NotApplicable` on a
  pre-existing non-S/MIME fixture — assert against `good.pem` (the TLS leaf from feature 05, no
  emailProtection) and against a CA fixture (`rfc5280_ca_bc_not_critical.pem`). This is the test
  that documents why no existing fixture needed regeneration.
- Each S/MIME violating fixture isolates EXACTLY its one rule across the full registry (mirror
  `each_fixture_isolates_exactly_one_*_violation` from rfc5280/hygiene/cabf_br): collect firing
  lint ids and assert it equals the single expected id.

### 3. Verify (do NOT edit) cross-feature green-ness

Confirm the feature-03/04/05 isolation tests, the good/expired invariants, and the feature-06
golden test still pass unchanged — the EKU gate guarantees this. If any fails, the gate is wrong;
report it rather than editing those tests.

## Acceptance Criteria

- [ ] 13 new openssl-generated S/MIME fixtures (1 clean + 12 violating) added; NO existing fixture
      changed; `generate.sh` gains an appended S/MIME section with the time-fragility note.
- [ ] `cabf_smime_good.pem` passes the full registry (no Error/Fatal); each violating fixture
      isolates exactly its one rule.
- [ ] `cabf_smime.rs` proves the EKU gate keeps every smime lint NotApplicable on `good.pem` (TLS
      leaf) and on a CA fixture.
- [ ] Feature-03/04/05 isolation + feature-06 golden tests pass UNCHANGED (verified, not edited).
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings` (and `--features serde`),
      `cargo fmt --check`, `bash testdata/generate.sh` all pass.

## Notes / Dependencies

- Depends on task 03 (lints registered, source/purpose/CLI wired).
- See `spec/features/10-smime-br/test-plan.md` for the full strategy.
