# Feature: CA/Browser Forum Extended Validation (EV) Rule Set

## Overview

Implement the CA/Browser Forum **Extended Validation (EV) Guidelines** lints — the stricter
identity-assurance profile layered on top of the Baseline Requirements (BR). EV certificates carry
verified legal-entity identity in the subject DN (organization, jurisdiction, business category,
registration number, serial number) and a recognized **EV certificate policy OID**. This feature adds
a new `RuleSource::CabfEv` rule set and a curated, high-signal subset of the EV-specific checks,
following the same "one small file per lint, commented with its EV Guidelines section" shape as the
RFC 5280 (feature 03) and BR (feature 05) rule sets.

This is plan-of-record Milestone 5's natural extension (the BR set is feature 05; EV is the strict
sub-profile of the same TLS-server world). It is drafted **in parallel** with sibling features 09
(`CabfCs` / code-signing) and 10 (`CabfSmime` / S/MIME), so the shared files
(`source.rs`, `registry.rs`, `output.rs`, `main.rs`) must be sequenced against those features — see
"Cross-Feature Coordination (siblings 09/10)".

## THE KEY DESIGN DECISION: EV is a self-scoping sub-profile of `tls-server`, not a new purpose

EV is **not** identified by an EKU. A leaf is "EV" because it asserts a recognized **EV certificate
policy OID** in its `certificatePolicies` extension, on top of being a normal `serverAuth` TLS leaf.
This drives the entire design, and is the most important decision in this spec:

### Decided approach (recommended, chosen): no new `--purpose`; EV self-scopes under `tls-server`

We do **NOT** add an `ev` `CertPurpose`. Instead:

1. Add a new source `RuleSource::CabfEv` and fold it into the **existing** `tls-server` allowed-source
   set. The tls-server set becomes `[Rfc5280, Hygiene, CabfBr, CabfEv]` (today it is
   `[Rfc5280, Hygiene, CabfBr]`). Because `CertPurpose::Auto` already resolves a `serverAuth` leaf to
   `tls-server`, **`auto` pulls in `CabfEv` for free** for any TLS leaf — no CLI changes are required
   for users to get EV checks on EV certs.
2. Each EV lint **self-gates in `applies()`**: it returns `NotApplicable` unless the cert is "in EV
   scope" (see "EV-scope detection" below). A non-EV TLS leaf therefore sees every `cabf_ev_*` lint as
   `NotApplicable` — **no cascade on existing fixtures** (`good.pem` is a non-EV TLS leaf, so all EV
   lints are N/A on it and it still passes the registry). An EV cert sees them `Applies`.

This is the same self-scoping pattern the BR lints already use for CA-vs-leaf (`applies_to_leaf`),
generalized to "is this an EV cert?". It keeps the CLI surface unchanged, keeps `--source` orthogonal
(`--source cabf_ev` runs exactly the EV set, filtered before applicability like every other source),
and means the cross-feature blast radius is limited to **one line** in the tls-server source set plus
the new source registration.

### Why not a separate `ev` purpose

A separate `--purpose ev` would (a) force users to know a cert is EV before linting it (defeating the
point — the linter should *detect* EV), (b) duplicate the entire tls-server source set, and (c) split
the EV checks off from the BR checks that EV certs must *also* satisfy. Self-scoping keeps EV strictly
additive to the existing tls-server profile, which is exactly the real-world relationship (EV ⊂ BR ⊂
RFC 5280). Rejected in favor of the self-scoping sub-profile.

## EV-scope detection (the EV-policy-OID allowlist)

An EV lint applies only to an EV cert. Real EV detection depends on the **issuing CA's** policy OID:
each CA mints EV certs under its own CA-specific `certificatePolicies` OID, and browsers/zlint
maintain an **allowlist** mapping those OIDs to "this is EV". There is no single universal EV OID
(the CA/Browser Forum reserved `2.23.140.1.1` as the *EV* policy identifier, but many CAs still assert
their own legacy CA-specific OID instead, sometimes in addition).

### Decided approach: a curated, documented EV-policy-OID allowlist constant, made testable

- Add a small, **auditable** `EV_POLICY_OIDS` constant list in the linter (one module, each OID
  commented with the CA/source it represents), consulted by the shared `is_ev_scope()` helper. This is
  the auditable, zlint-style choice. **It is necessarily incomplete** — real EV detection tracks the
  issuing CA, and CAs add OIDs over time. Document this loudly, exactly like the reserved-IP list in
  `lints/cabf_br/reserved.rs` needs occasional maintenance.
- The list **MUST** include the CA/Browser Forum reserved EV identifier `2.23.140.1.1`, plus a small
  set of well-known CA EV OIDs (documented, illustrative — not exhaustive), plus a **dedicated test OID
  `1.3.6.1.4.1.99999.1.1`** reserved for fixtures so the openssl-generated EV fixtures fall in scope.
  (Using a private-enterprise-arc test OID keeps the fixtures self-contained and avoids implying any
  real CA relationship.)

### Testability note (resolve here)

The EV fixtures must be **in scope** for the EV lints, which means the test EV policy OID must be in
`EV_POLICY_OIDS`. Two options were considered:

- **(chosen) Allowlist-with-test-OID:** `is_ev_scope()` = `has_server_auth() && any policy OID present
  is in EV_POLICY_OIDS`. Fixtures assert the dedicated test OID `1.3.6.1.4.1.99999.1.1`. This keeps
  `applies()` honest (a non-EV TLS leaf with an *unrecognized* policy OID is correctly N/A) while
  staying fully testable with openssl-only fixtures.
- (rejected) "any policy OID present + serverAuth" as the scope: simpler and trivially testable, but it
  mis-classifies every DV/OV cert that asserts *any* policy OID (almost all of them) as EV, producing
  mass false positives. Not used.

`is_ev_scope()` is **fail-closed**: if `certificate_policy_oids()` or `has_server_auth()` returns
`Err`, treat as not-EV → `NotApplicable` (a parse failure must never manufacture an EV finding). This
mirrors the BR `applies_to_leaf` and the `auto_sources_from` fail-closed stance.

## Curated lint subset (~9 lints, all `RuleSource::CabfEv`, `cabf_ev_*`, self-scoped to EV)

From the zlint EV menu, this high-signal subset is chosen (each cites the relevant EV Guidelines
section in its doc comment). Severity is `Error` for the structural/identity requirements (an EV cert
that violates them is mis-issued) and `Error` for the validity ceiling, matching how BR treats its own
mandatory fields:

1. `cabf_ev_organization_name_missing` — EV subject MUST include `organizationName` → `Error`. (EVG
   §9.2.1)
2. `cabf_ev_business_category_missing` — EV subject MUST include `businessCategory` → `Error`. (EVG
   §9.2.4)
3. `cabf_ev_business_category_invalid` — `businessCategory`, when present, MUST be one of the three
   permitted values: `Private Organization`, `Government Entity`, `Business Entity` (EVG §9.2.4) →
   `Error`. Message names the offending value. (covers zlint `lint_ev_invalid_business_category`)
4. `cabf_ev_jurisdiction_country_missing` — EV subject MUST include
   `jurisdictionOfIncorporationCountryName` (OID `1.3.6.1.4.1.311.60.2.1.3`) → `Error`. (EVG §9.2.4)
   (covers zlint `lint_ev_country_name_missing` for the jurisdiction country)
5. `cabf_ev_serial_number_missing` — EV subject MUST include the `serialNumber` attribute (the
   registration/incorporation number, distinct from the certificate serial) → `Error`. (EVG §9.2.6)
6. `cabf_ev_not_wildcard` — an EV cert MUST NOT contain a wildcard (`*.`) name in its SAN dNSName
   entries → `Error`, one finding per offending wildcard entry. (EVG §9.2.2 / BR wildcard prohibition
   for EV) (covers zlint `lint_ev_not_wildcard`)
7. `cabf_ev_san_no_ip_address` — an EV cert MUST NOT contain an `iPAddress` in its SAN → `Error`, one
   finding per offending IP. (EVG §9.2.2) (covers zlint `lint_ev_san_ip_address_present`)
8. `cabf_ev_validity_max_398_days` — EV cert validity window MUST NOT exceed 398 days → `Error`,
   message names the actual duration. (EVG §9.4 / current EV validity ceiling) (covers zlint
   `lint_ev_valid_time_too_long`)
9. `cabf_ev_organization_id_present` — EV subject SHOULD/MUST carry an `organizationIdentifier`
   (OID `2.5.4.97`) once required; flag its **absence** → `Error`. (EVG §9.2.8) (covers zlint
   `lint_ev_organization_id_missing`)

Deliberately **deferred** from the menu (documented so a future feature can pick them up): the
`orgid`-consistency / `orgid` registration-scheme lints (`lint_orgid_inconsistent_subj_and_ext`,
`lint_invalid_orgid_reg_scheme`) require cross-referencing the subject DN against the CA/Browser Forum
`cabfOrganizationIdentifier` *extension* (OID `2.23.140.3.1`) and parsing the registration-scheme
syntax — a larger, separable effort. `lint_extra_subject_attribs` and
`lint_onion_subject_validity_time_too_large` are niche and out of scope for v1 of the EV set. Noting
them keeps this subset focused and high-signal.

Each lint:
- Tagged `RuleSource::CabfEv`; `applies()` delegates to the shared `applies_to_ev(cert)` helper
  (`Applies` iff `is_ev_scope(cert)`, else `NotApplicable`, fail-closed on `Err`).
- Returns `Vec<Finding>` naming the offending value/entry/duration.
- Carries a doc comment with the EV Guidelines section it enforces.
- Uses `cabf_ev_*` naming for `lint_id`.

## Architecture

- One small file per lint under `crates/linter/src/lints/cabf_ev/`, plus `cabf_ev/mod.rs` declaring
  the modules, the shared `applies_to_ev` / `is_ev_scope` helpers, and the `EV_POLICY_OIDS` allowlist
  (the allowlist may live in a dedicated `cabf_ev/policy.rs` submodule for auditability, mirroring how
  `cabf_br/reserved.rs` isolates the reserved-range list).
- Reuse existing `Cert` facade accessors where possible (`san_dns_names`, `san_ip_addresses`,
  `validity_days`, `subject_common_names`, `has_server_auth`, `is_ca`). Add the **new** accessors the
  EV identity/policy checks need (see "Facade accessors" / task 01).
- Register the EV lints in `default_registry()` after the BR lints (deterministic order for the
  feature 06 golden test).
- Wire `RuleSource::CabfEv` into the `tls-server` allowed-source set in `registry.rs`, the `--source`
  token parser + `ALL_SOURCES` in `main.rs`, and the `SOURCE_ORDER` + `source_label` in `output.rs`.

## EV-scope self-gating ⇒ NO cascade on existing fixtures (critical)

Because every EV lint is `NotApplicable` unless `is_ev_scope(cert)` is true, and the only certs in EV
scope are those asserting an `EV_POLICY_OIDS` OID:

- `good.pem` is a non-EV TLS leaf (no EV policy OID) → all `cabf_ev_*` lints are `NotApplicable` on it.
  **It still passes the registry.** No regeneration of `good.pem` or any existing fixture.
- Every existing BR/RFC/hygiene fixture is likewise non-EV → EV lints N/A → their isolation tests are
  unaffected. **No existing fixture is regenerated.** This feature only **adds** new EV fixtures.

This is the deliberate advantage of self-scoping over the BR feature's broad scoping (which forced the
feature-05 fixture cascade). EV adds zero cross-feature fixture churn.

## Facade accessors (task 01, in `cert.rs`)

New, documented, non-panicking (`Result<_, CertError>`) accessors:

- `certificate_policy_oids() -> Result<Vec<String>, CertError>` — the policy OIDs from the
  `certificatePolicies` extension (OID `2.5.29.32`) in dotted form, empty `Vec` when absent. Consumed
  by `is_ev_scope()`.
- `subject_organization_names() -> Result<Vec<String>, CertError>` — `organizationName` (O,
  OID `2.5.4.10`) values. (`organization_name_missing`)
- `subject_business_category() -> Result<Vec<String>, CertError>` — `businessCategory`
  (OID `2.5.4.15`) values. (`business_category_missing` / `_invalid`)
- `subject_jurisdiction_country() -> Result<Vec<String>, CertError>` —
  `jurisdictionOfIncorporationCountryName` (OID `1.3.6.1.4.1.311.60.2.1.3`) values.
  (`jurisdiction_country_missing`)
- `subject_serial_numbers() -> Result<Vec<String>, CertError>` — the subject DN `serialNumber`
  attribute (OID `2.5.4.5`) values — distinct from the certificate serial (`serial_summary`). Document
  the distinction clearly. (`serial_number_missing`)
- `subject_organization_identifiers() -> Result<Vec<String>, CertError>` — `organizationIdentifier`
  (OID `2.5.4.97`) values. (`organization_id_present`)
- `san_has_wildcard()` / reuse `san_dns_names()` + a small wildcard predicate — wildcard SAN dNSName
  detection (an entry beginning with `*.`). Prefer adding a documented `san_wildcard_dns_names() ->
  Result<Vec<String>, CertError>` returning only the wildcard entries, so `not_wildcard` can name each
  offender. (`not_wildcard`)

Reuse for EV without new accessors: `san_ip_addresses()` (`san_no_ip_address`), `validity_days()`
(`validity_max_398_days`), `has_server_auth()` + `certificate_policy_oids()` (`is_ev_scope`).

Generic subject-attribute reading: prefer a single internal helper in `cert.rs` that pulls all RDN
attribute values for a given OID (the CN reader `subject_common_names` already does this for
`2.5.4.3`); the new accessors can each delegate to it, keeping the facade DRY and auditable. Document
which OID each accessor reads.

## Changes Overview

**crates/linter/ (production code — developer tasks 01-03)**
- `src/cert.rs` — the new subject-attribute + policy-OID + wildcard-SAN accessors (task 01).
- `src/lints/cabf_ev/mod.rs` — module declarations, re-exports, `applies_to_ev` / `is_ev_scope`
  helpers (task 02).
- `src/lints/cabf_ev/policy.rs` — the `EV_POLICY_OIDS` allowlist (each OID cited), with unit tests
  (task 02; created here to keep the lint files conflict-free).
- `src/lints/cabf_ev/organization_name_missing.rs`
- `src/lints/cabf_ev/business_category_missing.rs`
- `src/lints/cabf_ev/business_category_invalid.rs`
- `src/lints/cabf_ev/jurisdiction_country_missing.rs`
- `src/lints/cabf_ev/serial_number_missing.rs`
- `src/lints/cabf_ev/not_wildcard.rs`
- `src/lints/cabf_ev/san_no_ip_address.rs`
- `src/lints/cabf_ev/validity_max_398_days.rs`
- `src/lints/cabf_ev/organization_id_present.rs`
- `src/lints/mod.rs` — add `pub mod cabf_ev;` (task 02).
- `src/source.rs` — add `RuleSource::CabfEv` (serde `cabf_ev`); update the doc comment listing the
  serde vocabulary (task 02, shared with siblings 09/10 — sequence).
- `src/registry.rs` — register the nine EV lints in `default_registry()`; add `CabfEv` to the
  `tls_server_sources()` set; update the in-file `default_registry` count/filter unit tests (add a
  `cabf_ev` source-filter test; bump the lint count and the `tls_server_includes_cabf_br` test to also
  expect `CabfEv`) (task 03, shared with siblings 09/10 — sequence).

**crates/cli/ (production code — developer task 03)**
- `src/main.rs` — add `cabf_ev` to `parse_source_token` and to `ALL_SOURCES`; update the `--source`
  help text (task 03, shared with siblings 09/10 — sequence).
- `src/output.rs` — add `RuleSource::CabfEv` to `SOURCE_ORDER` and `source_label` (task 03, shared
  with siblings 09/10 — sequence).

**testdata/ + tests (tester — task 04)**
- `testdata/generate.sh` — add an EV leaf-extension config (serverAuth + `certificatePolicies` with
  the test EV OID + EV subject fields) and the new EV fixtures; keep the existing fragility header and
  reuse the `BR_OK` window (EV validity ceiling is also 398 days). NO existing fixture regenerated.
- New EV fixtures (openssl-generated only; see "Fixtures").
- `crates/linter/tests/cabf_ev.rs` — the EV integration tests (new).
- `crates/linter/tests/registry.rs` — bump the default lint count to reflect the nine EV lints; the
  EXPIRED constant is unchanged. (Shared with siblings 09/10 — if 09/10 also bump the count, sequence
  this file so the final count is consistent; see coordination note.)

## Fixtures (openssl-generated ONLY — never cert-bar)

A clean EV leaf carries: `serverAuth` EKU + the test EV policy OID `1.3.6.1.4.1.99999.1.1` in
`certificatePolicies` + the EV subject fields (`businessCategory=Private Organization`,
`jurisdictionOfIncorporationCountryName` e.g. `US`, `organizationName`, `serialNumber` (registration
number), `countryName`, `organizationIdentifier`) + a non-wildcard, IP-free SAN whose dNSName equals
the CN + a `BR_OK` (≤398d, currently-valid) window. Each per-lint violating fixture is this clean EV
leaf with **exactly one** EV requirement omitted or broken, so it isolates exactly one `cabf_ev_*`
rule across the full registry (and passes RFC 5280 + hygiene + BR).

- `cabf_ev_good.pem` — fully clean EV leaf; passes the entire registry (every EV lint applies and
  passes; BR/RFC/hygiene pass). The positive EV control.
- `cabf_ev_org_name_missing.pem` — omits `organizationName`. (CN/SAN still present so BR `cn_in_san`
  stays quiet.)
- `cabf_ev_business_category_missing.pem` — omits `businessCategory`.
- `cabf_ev_business_category_invalid.pem` — `businessCategory=Sole Proprietor` (not one of the three
  permitted values).
- `cabf_ev_jurisdiction_country_missing.pem` — omits `jurisdictionOfIncorporationCountryName`.
- `cabf_ev_serial_number_missing.pem` — omits the subject `serialNumber` attribute (certificate serial
  is still positive so RFC `serial_number_positive` stays quiet).
- `cabf_ev_wildcard_san.pem` — SAN dNSName `*.ev.example.com` (wildcard); CN matches a non-wildcard
  SAN entry so `cn_in_san` stays quiet.
- `cabf_ev_san_ip.pem` — SAN includes an `iPAddress` (a **public** documentation IP, e.g.
  `IP:192.0.2.10` from RFC 5737, so BR `no_internal_names_or_reserved_ip` stays quiet) plus the CN as
  a dNSName.
- `cabf_ev_validity_400_days.pem` — EV leaf with a 400-day window (`2026-06-01 → 2027-07-06`, same
  horizon as `cabf_br_validity_400_days`), else clean. Isolates `cabf_ev_validity_max_398_days`.
  Note: a 400-day EV leaf also fires `cabf_br_validity_max_398_days` (both ceilings are 398d) — so this
  fixture is the documented exception that fires **two** rules (one BR, one EV). Document this in the
  test; assert both fire and that no *other* rule does. (Alternatively, split into a generic 400d test
  asserting the EV rule fires and accept the BR co-fire.)
- `cabf_ev_org_id_missing.pem` — omits `organizationIdentifier`.
- (negative control, reuse) `good.pem` — existing non-EV TLS leaf; assert every `cabf_ev_*` lint is
  `NotApplicable` on it (no EV policy OID). No new fixture, no regeneration.

### Time-fragility

EV fixtures reuse the `BR_OK` window (`2026-06-01 → 2027-06-01`) and the 400-day window, so they carry
the **same** annual-regeneration chore documented in `generate.sh`'s header. The EV section of
`generate.sh` must reference that existing header note (do not add a second, divergent warning). The
`cabf_ev.rs` test module doc should reference it too, mirroring `cabf_br.rs`.

## Cross-Feature Coordination (siblings 09/10) — load-bearing

Features 09 (`CabfCs`/code-signing) and 10 (`CabfSmime`/S/MIME) are drafted in parallel and add their
own `RuleSource` variants + lints. They edit the **same shared files** this feature does:

- `crates/linter/src/source.rs` (each adds a `RuleSource` variant)
- `crates/linter/src/registry.rs` (each registers lints + may touch the purpose→source mapping + the
  count/filter unit tests)
- `crates/cli/src/main.rs` (`parse_source_token`, `ALL_SOURCES`, help text)
- `crates/cli/src/output.rs` (`SOURCE_ORDER`, `source_label`)
- `crates/linter/tests/registry.rs` (default lint-count assertion)

**These cannot be edited concurrently across features.** When the three features are implemented, the
shared-file edits MUST be serialized (one feature's implementation merges, then the next rebases). For
this feature's *internal* sequencing, tasks 02 and 03 own the shared files and run strictly after the
self-contained lint work; the architect orchestrating the multi-feature batch must additionally
serialize feature 11's task 02/03 against features 09/10's equivalents. Specifically:

- The final `default_registry().len()` and the `registry.rs` count assertion depend on how many lints
  09/10 + 11 collectively add. Whichever feature lands last reconciles the count. Task 03's count
  update is written to be re-checked at integration.
- `tls_server_sources()` must include `CabfEv` (this feature) and is unaffected by 09/10 (code-signing
  and S/MIME are NOT tls-server purposes — they fold into their own future purposes or `generic`,
  per the existing `CertPurpose` "future variants" doc). Confirm 09/10 do not also edit
  `tls_server_sources()`; if they do, reconcile.
- `SOURCE_ORDER` / `source_label` / `parse_source_token` / `ALL_SOURCES` must list all new sources;
  the last feature to land reconciles the full ordered list. Choose a deterministic order:
  `Rfc5280, CabfBr, CabfEv, CabfCs, CabfSmime, Hygiene` (EV directly after BR, since EV ⊂ BR), to keep
  the feature-06 golden output stable.

## Dependencies

None new. All EV attribute reading is via `x509-parser`'s existing RDN iteration (the same path
`subject_common_names()` already uses); policy-OID reading via `x509-parser`'s `certificate_policies()`
extension accessor. No new crate is required; if one is genuinely needed for an OID lookup, document it
and add it to `crates/linter/Cargo.toml`.

## Sequencing (batches, intra-feature)

- Batch A: task 01 (`cert.rs` facade accessors). depends_on: none.
- Batch B: task 02 (EV lints + `cabf_ev/` module + `policy.rs` allowlist + `lints/mod.rs` +
  `source.rs` `CabfEv`). depends_on: task 01.
- Batch C: task 03 (registry registration + `tls_server_sources` update + count/filter unit tests +
  `main.rs` + `output.rs` wiring). depends_on: task 02.
- Batch D: task 04 (EV fixtures + `generate.sh` EV section + `cabf_ev.rs` integration tests +
  `registry.rs` count bump). depends_on: task 03.

`cert.rs` is touched only by task 01. `source.rs` only by task 02. `registry.rs` is touched by task 03
(registration + lib unit tests) and task 04 (integration `tests/registry.rs` is a *different* file —
no conflict; the lib `src/registry.rs` is task 03 only). `main.rs`/`output.rs` only by task 03. The
lint files + `policy.rs` only by task 02. All `touches` lists are disjoint within a batch.

## Ripple Flag: none for existing fixtures

Unlike feature 05, EV's self-scoping means **no existing fixture or cross-feature test changes**
(`good.pem` stays as-is; EV lints are N/A on it). The only shared-file edits are the additive source
wiring, which is the cross-feature 09/10 coordination above — not a fixture cascade.
