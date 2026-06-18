# Test Plan: CA/Browser Forum Extended Validation (EV) Rule Set

## Scope

Verify the nine self-scoped EV lints (`cabf_ev_organization_name_missing`,
`cabf_ev_business_category_missing`, `cabf_ev_business_category_invalid`,
`cabf_ev_jurisdiction_country_missing`, `cabf_ev_serial_number_missing`, `cabf_ev_not_wildcard`,
`cabf_ev_san_no_ip_address`, `cabf_ev_validity_max_398_days`, `cabf_ev_organization_id_present`), the
new `Cert` facade accessors, the `EV_POLICY_OIDS` allowlist + `is_ev_scope` gating, and the additive
source wiring (`RuleSource::CabfEv`, tls-server inclusion, `--source cabf_ev`, output ordering).

**Self-scoping (load-bearing):** an EV lint is `NotApplicable` unless the cert is in EV scope
(`serverAuth` + a recognized EV policy OID). Non-EV leaves (incl. `good.pem`) and CA certs are N/A for
all nine. This means **no existing fixture is regenerated** and no feature-03/04/05 isolation test
changes — the only cross-feature edit is the additive lint count in `tests/registry.rs`.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()` on `Result`,
behaviour-focused tests grouped per lint in nested `mod` blocks. Prefer a pure `evaluate(...)` helper
per lint (mirroring `cabf_br/cn_in_san.rs`) so logic is unit-testable without a fixture.

## ⚠️ Time-fragility

EV fixtures reuse the existing `BR_OK` window (`2026-06-01 → 2027-06-01`) and the 400-day window
(`2026-06-01 → 2027-07-06`). They EXPIRE in 2027; after that `hygiene_not_expired` fires on every EV
leaf and the EV isolation tests fail wholesale. This is the SAME chore already documented in
`generate.sh`'s header — the EV section references it; do not add a divergent warning. The `cabf_ev.rs`
module doc references it too. Regenerate `testdata/` annually before 2027-06-01.

## Fixtures (`testdata/`) — openssl-generated only, NO regeneration of existing fixtures

A clean EV leaf = `serverAuth` + test EV policy OID `1.3.6.1.4.1.99999.1.1` in `certificatePolicies` +
EV subject fields (`businessCategory=Private Organization`, `jurisdictionOfIncorporationCountryName=US`,
`organizationName`, subject `serialNumber`, `countryName=US`, `organizationIdentifier`) + non-wildcard,
IP-free SAN whose dNSName = CN + `BR_OK` window.

- `cabf_ev_good.pem` — clean EV control; passes the entire registry.
- `cabf_ev_org_name_missing.pem` — no `organizationName`.
- `cabf_ev_business_category_missing.pem` — no `businessCategory`.
- `cabf_ev_business_category_invalid.pem` — `businessCategory=Sole Proprietor`.
- `cabf_ev_jurisdiction_country_missing.pem` — no `jurisdictionOfIncorporationCountryName`.
- `cabf_ev_serial_number_missing.pem` — no subject `serialNumber` attribute.
- `cabf_ev_wildcard_san.pem` — SAN `*.ev.example.com` (CN matches a non-wildcard SAN entry).
- `cabf_ev_san_ip.pem` — SAN includes public `IP:192.0.2.10` (RFC 5737) + CN dNSName.
- `cabf_ev_validity_400_days.pem` — 400d window, else clean (two-rule exception: BR + EV validity).
- `cabf_ev_org_id_missing.pem` — no `organizationIdentifier`.

Negative control (reuse, no new fixture): `good.pem` (non-EV TLS leaf) — all EV lints N/A.
CA control (reuse): `rfc5280_ca_bc_not_critical.pem` — all EV lints N/A.

## Unit Tests (`cert.rs`, developer task 01)

- `certificate_policy_oids()`: empty on `good.pem` (no `certificatePolicies`); the EV-cert positive
  case is covered by the integration tests against the EV fixtures.
- EV subject accessors (`subject_organization_names`, `subject_business_category`,
  `subject_jurisdiction_country`, `subject_serial_numbers`, `subject_organization_identifiers`): empty
  on `good.pem`.
- `san_wildcard_dns_names()`: empty on `good.pem` (its SAN dNSName is non-wildcard).
- Doc/behaviour: `subject_serial_numbers()` reads the subject-DN `serialNumber` (2.5.4.5), NOT the
  certificate serial — assert it differs from `serial_summary` on a fixture that has both.

## Unit Tests (`cabf_ev/policy.rs`, developer task 02)

- `EV_POLICY_OIDS` contains `2.23.140.1.1` (CA/B Forum reserved) and `1.3.6.1.4.1.99999.1.1` (test).
- An arbitrary DV/OV policy OID (e.g. `2.23.140.1.2.1` domain-validated) is NOT in the allowlist.

## Unit Tests (per-lint, developer task 02)

Each lint's `#[cfg(test)] mod tests` covers, via its pure `evaluate(...)` helper where possible:

- pass case (requirement satisfied) → empty findings.
- fail case (requirement violated) → ≥1 `Severity::Error` finding whose message names the
  missing attribute / offending value / wildcard / IP / duration.
- multi-finding cases for `not_wildcard`, `san_no_ip_address`, `business_category_invalid`.
- `validity_max_398_days`: boundary 398 passes, 399/400 fires (message names duration).
- `id()` / `source()` correct (`cabf_ev_*`, `RuleSource::CabfEv`).

## Integration Tests (`crates/linter/tests/cabf_ev.rs`)

- **Per-lint flag/pass:** each per-lint fixture is flagged by its EV lint (descriptive message);
  `cabf_ev_good.pem` passes that lint.
- **Positive control:** `cabf_ev_good.pem` over the full `default_registry()` → no error/fatal
  findings (every EV lint applies and passes; BR/RFC/hygiene pass).
- **Isolation:** each per-lint EV fixture over the full registry surfaces exactly its one EV rule
  (BR/RFC/hygiene stay quiet). `cabf_ev_validity_400_days.pem` is the documented exception: exactly
  two findings (`cabf_br_validity_max_398_days` + `cabf_ev_validity_max_398_days`), no other rule.
- **Self-scoping (N/A):** every `cabf_ev_*` lint is `NotApplicable` on `good.pem` (non-EV TLS leaf)
  and on `rfc5280_ca_bc_not_critical.pem` (CA).
- **Self-scoping (Applies):** every `cabf_ev_*` lint `Applies` on `cabf_ev_good.pem` (in EV scope).
- **Fail-closed scope:** documented — `is_ev_scope` returns false on `Err` (covered via the lint
  `applies` returning `NotApplicable`; no malformed fixture required).

## Registry / Wiring Tests

- `crates/linter/src/registry.rs` (developer task 03, in-file unit tests):
  - `contains_the_known_lints`: count bumped by 9; the nine `cabf_ev_*` ids present.
  - `cabf_ev_source_filter_runs_exactly_the_cabf_ev_set`: 9 outcomes, all `RuleSource::CabfEv`, the
    nine ids, none `rfc5280_`/`hygiene_`/`cabf_br_`.
  - `tls_server_includes_cabf_br`-style tests updated to also expect `CabfEv`; `auto`-on-serverAuth
    tests expect the new tls-server set. rfc5280 (6) / hygiene (4) / cabf_br (4) filter counts
    unchanged.
- `crates/cli/src/main.rs` (developer task 03, in-file unit tests):
  - `parse_source_token("cabf_ev")` → `RuleSource::CabfEv`; unknown-token error lists `cabf_ev`.
  - `select_sources` / `effective_sources` expectations updated for the new `ALL_SOURCES` /
    tls-server ordering.
- `crates/linter/tests/registry.rs` (tester task 04): default lint-count assertion bumped by 9;
  `EXPIRED_NOT_AFTER` and expired-isolation tests UNCHANGED.

## Cross-Feature Regression (must still pass — EV adds no cascade)

- `crates/linter/tests/rfc5280.rs`, `hygiene.rs`, `cabf_br.rs`: assertion logic UNCHANGED — EV lints
  are N/A on every existing fixture, so isolation/`good_pem` invariants hold. Verify green over the
  larger registry.
- `crates/cli/tests/output.rs`: the rfc5280-group `(N passed, M not applicable)` assertions are
  unaffected by EV (different source); verify no change is needed beyond what task 03's source wiring
  introduces (EV is a new group in `SOURCE_ORDER`, but it only renders when EV outcomes are present).

## Cross-Feature Coordination (siblings 09/10)

`source.rs`, `registry.rs`, `cli/main.rs`, `cli/output.rs`, and `tests/registry.rs` are shared with
features 09 (`CabfCs`) and 10 (`CabfSmime`). The final lint count, `ALL_SOURCES`, and `SOURCE_ORDER`
must reconcile across all three — the last feature to land sets the authoritative count and the full
ordered source list (`Rfc5280, CabfBr, CabfEv, CabfCs, CabfSmime, Hygiene`). The EV tests assert EV's
own contribution; the integration owner re-checks the totals.

## Edge Cases

- A non-EV TLS leaf that asserts an UNRECOGNIZED policy OID is NOT in EV scope (the allowlist gates
  it) → all EV lints N/A. (Conceptually verified by `good.pem` having no EV OID; if a fixture with a
  non-EV OID is cheap to add, assert it too.)
- `businessCategory` present but valid → `business_category_invalid` passes; present and invalid →
  fires; absent → only `business_category_missing` fires (not `_invalid`).
- Multiple wildcard SAN entries → one `not_wildcard` finding each.
- Multiple SAN IPs → one `san_no_ip_address` finding each.
- 398-day EV cert passes the validity lint; 400-day fires both EV and BR validity lints.

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

All nine EV lints + the EV-policy-OID allowlist + `is_ev_scope` self-gating validated; EV fixtures
isolate exactly their one rule (validity-400 the documented two-rule exception); `cabf_ev_good.pem`
passes the full registry; every EV lint is N/A on non-EV leaves and CA certs and `Applies` on EV
certs; no existing fixture regenerated and no feature-03/04/05 isolation test changed; the additive
source wiring (registry count, tls-server set, `--source cabf_ev`, `SOURCE_ORDER`/`source_label`)
verified; verification commands pass.
