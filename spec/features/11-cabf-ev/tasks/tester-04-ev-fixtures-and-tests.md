---
agent: tester
seq: 4
title: EV fixtures (openssl-only) + EV integration tests + registry count bump
status: done
touches:
  - testdata/generate.sh
  - testdata/cabf_ev_good.pem
  - testdata/cabf_ev_org_name_missing.pem
  - testdata/cabf_ev_business_category_missing.pem
  - testdata/cabf_ev_business_category_invalid.pem
  - testdata/cabf_ev_jurisdiction_country_missing.pem
  - testdata/cabf_ev_serial_number_missing.pem
  - testdata/cabf_ev_wildcard_san.pem
  - testdata/cabf_ev_san_ip.pem
  - testdata/cabf_ev_validity_400_days.pem
  - testdata/cabf_ev_org_id_missing.pem
  - crates/linter/tests/cabf_ev.rs
  - crates/linter/tests/registry.rs
  - crates/cli/tests/golden.rs
  - crates/cli/tests/snapshots/golden__text_output__good_text.snap
  - crates/cli/tests/snapshots/golden__text_output__cabf_br_validity_400_days_text.snap
  - crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap
  - crates/cli/tests/snapshots/golden__json_output__good_json.snap
  - crates/cli/tests/snapshots/golden__verbose_output__good_verbose_text.snap
depends_on:
  - developer-03-register-and-wire-cabf-ev
---

# Task: EV fixtures (openssl-only) + EV integration tests + registry count bump

## Goal

Add the openssl-generated EV fixtures, write the EV integration tests, and bump the default
lint-count assertion in `tests/registry.rs`. EV's self-scoping means **NO existing fixture is
regenerated** and **no existing cross-feature test changes** beyond the additive lint count — verify
that `good.pem` stays a non-EV leaf (all `cabf_ev_*` lints `NotApplicable` on it).

## ⚠️ Time-fragility (reuse the existing header — do NOT add a divergent one)

EV fixtures reuse the existing `BR_OK` window (`2026-06-01 → 2027-06-01`, 365d) and the 400-day window
(`2026-06-01 → 2027-07-06`), so they carry the same annual-regeneration chore already documented in
`generate.sh`'s header. The EV section of `generate.sh` MUST reference that existing header note
(point to it), not introduce a second warning. The `cabf_ev.rs` module doc should reference it too,
mirroring `cabf_br.rs`.

## Fixtures (openssl-generated ONLY — never cert-bar)

A clean EV leaf = `serverAuth` EKU + the test EV policy OID `1.3.6.1.4.1.99999.1.1` in
`certificatePolicies` + EV subject fields (`businessCategory=Private Organization`,
`jurisdictionOfIncorporationCountryName=US` (OID 1.3.6.1.4.1.311.60.2.1.3),
`organizationName`, subject `serialNumber` (registration number), `countryName=US`,
`organizationIdentifier`) + a non-wildcard, IP-free SAN whose dNSName equals the CN + a `BR_OK`
window. Each per-lint fixture is this clean EV leaf with EXACTLY ONE EV requirement broken.

- `cabf_ev_good.pem` — fully clean EV leaf; passes the entire registry (every EV lint applies and
  passes; BR/RFC/hygiene pass). The positive EV control.
- `cabf_ev_org_name_missing.pem` — omit `organizationName` (keep CN+SAN so `cn_in_san` stays quiet).
- `cabf_ev_business_category_missing.pem` — omit `businessCategory`.
- `cabf_ev_business_category_invalid.pem` — `businessCategory=Sole Proprietor` (not a permitted value).
- `cabf_ev_jurisdiction_country_missing.pem` — omit `jurisdictionOfIncorporationCountryName`.
- `cabf_ev_serial_number_missing.pem` — omit the subject `serialNumber` attribute (certificate serial
  stays positive so RFC `serial_number_positive` stays quiet).
- `cabf_ev_wildcard_san.pem` — SAN dNSName `*.ev.example.com` (wildcard); CN matches a non-wildcard
  SAN entry so `cn_in_san` stays quiet.
- `cabf_ev_san_ip.pem` — SAN includes a genuinely public, routable IP `IP:8.8.8.8` plus the CN as a
  dNSName. (NOTE: the originally-suggested RFC 5737 `192.0.2.10` was found to trip the broad
  `cabf_br_no_internal_names_or_reserved_ip` lint — the linter classifies RFC 5737 documentation
  ranges as reserved — so a public IP is used to keep this a single-rule fixture.)
- `cabf_ev_validity_400_days.pem` — 400-day window (`2026-06-01 → 2027-07-06`), else clean.
  **Documented exception:** a 400-day EV leaf fires BOTH `cabf_ev_validity_max_398_days` AND
  `cabf_br_validity_max_398_days` (both ceilings are 398d). The test for this fixture asserts both
  fire and that no OTHER rule does (it is the one fixture that intentionally isolates two rules — one
  per source).
- `cabf_ev_org_id_missing.pem` — omit `organizationIdentifier`.

Build EV fixtures via an openssl extension config carrying `extendedKeyUsage=serverAuth`,
`certificatePolicies=1.3.6.1.4.1.99999.1.1`, `basicConstraints=CA:FALSE`, and the parameterized SAN;
EV subject fields go in the subject DN (`-subj`/config). Run `bash testdata/generate.sh` and commit
every new `.pem`. The two existing CA fixtures and all feature-03/04/05 leaves are UNCHANGED.

## `crates/linter/tests/cabf_ev.rs` (new; SIFER, Result-assertion conventions)

- Per lint: its fixture flagged with a descriptive message (names the missing attribute / offending
  value / wildcard entry / IP / duration); `cabf_ev_good.pem` → that lint passes.
- `cabf_ev_good.pem` over the FULL `default_registry()` → no error/fatal findings (the positive EV
  control passes everything).
- Scoping: every `cabf_ev_*` lint is `NotApplicable` on `good.pem` (non-EV TLS leaf, no EV policy
  OID) AND on a CA cert (`rfc5280_ca_bc_not_critical.pem`).
- Scoping: every `cabf_ev_*` lint `Applies` on `cabf_ev_good.pem` (in EV scope).
- `cabf_ev_not_wildcard` / `cabf_ev_san_no_ip_address` / `cabf_ev_business_category_invalid` —
  multi-finding cases where applicable.
- `cabf_ev_validity_max_398_days`: 400d fixture fires (message names duration); boundary 398 passes.
- `cabf_ev_validity_400_days.pem` over the full registry → exactly two findings (BR + EV validity),
  no other rule fires (documented two-rule exception).
- Each per-lint fixture over the full registry isolates exactly its one EV rule (plus the documented
  validity exception), confirming the BR/RFC/hygiene lints stay quiet on EV fixtures.

## `crates/linter/tests/registry.rs` (count bump only)

- Bump the default-registry lint-count assertion by 9 (the nine EV lints). The `EXPIRED_NOT_AFTER`
  constant and the expired-isolation tests are UNCHANGED (EV adds no fixture cascade).
- **Cross-feature note:** if siblings 09/10 also bump this count, the final number must reconcile
  across all three features — the last feature to land sets the authoritative count. Coordinate at
  integration (see plan.md "Cross-Feature Coordination").

## Acceptance Criteria

- [ ] Ten EV `.pem` fixtures added (1 clean control + 9 per-lint), openssl-generated; NO existing
      fixture regenerated; `generate.sh` EV section references the existing fragility header.
- [ ] `cabf_ev_good.pem` passes the full registry; every `cabf_ev_*` lint is N/A on `good.pem` and on
      a CA cert, and `Applies` on `cabf_ev_good.pem`.
- [ ] Each per-lint EV fixture isolates exactly its one EV rule (validity-400 is the documented
      two-rule exception).
- [ ] `tests/registry.rs` count bumped by 9; expired constant/tests unchanged.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 03 (EV lints registered + wired).
- Touches `crates/linter/tests/registry.rs` (the INTEGRATION test file), which is distinct from the
  library `src/registry.rs` owned by task 03 — no intra-feature conflict. The count assertion is the
  cross-feature reconciliation point with siblings 09/10.
