---
agent: developer
seq: 2
title: Implement the nine CA/B Forum EV lints, EV-policy-OID allowlist, and RuleSource::CabfEv
status: done
touches:
  - crates/linter/src/source.rs
  - crates/linter/src/lints/mod.rs
  - crates/linter/src/lints/cabf_ev/mod.rs
  - crates/linter/src/lints/cabf_ev/policy.rs
  - crates/linter/src/lints/cabf_ev/organization_name_missing.rs
  - crates/linter/src/lints/cabf_ev/business_category_missing.rs
  - crates/linter/src/lints/cabf_ev/business_category_invalid.rs
  - crates/linter/src/lints/cabf_ev/jurisdiction_country_missing.rs
  - crates/linter/src/lints/cabf_ev/serial_number_missing.rs
  - crates/linter/src/lints/cabf_ev/not_wildcard.rs
  - crates/linter/src/lints/cabf_ev/san_no_ip_address.rs
  - crates/linter/src/lints/cabf_ev/validity_max_398_days.rs
  - crates/linter/src/lints/cabf_ev/organization_id_present.rs
depends_on:
  - developer-01-cert-facade-ev-accessors
---

# Task: Implement the nine CA/B Forum EV lints, EV-policy-OID allowlist, and RuleSource::CabfEv

## Goal

Add the new `RuleSource::CabfEv` and implement the curated EV rule set, one small file per lint, each
commented with its EV Guidelines section, each `cabf_ev_*`, all **self-scoped to EV certs** via a
shared `applies_to_ev` helper that consults a curated, documented EV-policy-OID allowlist.

## EV-scope self-gating (load-bearing — see plan.md "EV-scope detection")

`is_ev_scope(cert)` = `cert.has_server_auth()? == true` AND at least one of
`cert.certificate_policy_oids()?` is in the `EV_POLICY_OIDS` allowlist. Each lint's `applies()`
delegates to `applies_to_ev(cert)`: `Applies` iff `is_ev_scope(cert)`, else `NotApplicable`.
**Fail-closed:** if either accessor returns `Err`, treat as not-EV → `NotApplicable` (a parse failure
must never manufacture an EV finding). This mirrors `cabf_br::applies_to_leaf` and
`registry::auto_sources_from`.

A non-EV TLS leaf (e.g. `good.pem`, which has serverAuth but no EV policy OID) is therefore
`NotApplicable` for every EV lint — no cascade on existing fixtures.

## Files Owned (conflict scope)

- `crates/linter/src/source.rs` — add the `CabfEv` variant (serde `cabf_ev`); update the doc comment
  listing the serde `--source` vocabulary. **Shared with siblings 09/10 — sequence at integration.**
- `crates/linter/src/lints/mod.rs` — add `pub mod cabf_ev;`.
- `crates/linter/src/lints/cabf_ev/mod.rs` — module declarations + re-exports + `applies_to_ev` /
  `is_ev_scope` helpers.
- `crates/linter/src/lints/cabf_ev/policy.rs` — the `EV_POLICY_OIDS` allowlist (created here so the
  lint files stay conflict-free).
- the nine lint files (listed in front-matter).

Does NOT modify `cert.rs` (task 01) or `registry.rs` / `main.rs` / `output.rs` (task 03).

## Steps

1. `source.rs`: add `RuleSource::CabfEv`, serde `cabf_ev`. Keep the variant ordering/doc consistent
   with the existing `Rfc5280, CabfBr, Hygiene` block; document it as the CA/Browser Forum Extended
   Validation Guidelines.
2. `cabf_ev/policy.rs`: a `pub const EV_POLICY_OIDS: &[&str]` (or a documented function) listing the
   recognized EV policy OIDs, **each entry commented** with the CA/source it represents. MUST include:
   - `2.23.140.1.1` — CA/Browser Forum reserved EV policy identifier.
   - a small set of well-known CA EV OIDs (documented as illustrative, NOT exhaustive).
   - `1.3.6.1.4.1.99999.1.1` — dedicated TEST OID for fixtures (commented as test-only, private arc).
   Add a module doc note (mirroring `cabf_br/reserved.rs`) that this list is **necessarily incomplete**
   — real EV detection tracks the issuing CA and needs occasional maintenance. Add `#[cfg(test)] mod
   tests` asserting membership (e.g. `2.23.140.1.1` and the test OID are present; an arbitrary DV OID
   is absent).
3. `cabf_ev/mod.rs`: declare each lint module + `pub mod policy;`, re-export the lint types, and
   implement `is_ev_scope(cert: &Cert) -> bool` + `applies_to_ev(cert: &Cert) -> Applicability` with
   the fail-closed policy above. Document the module's scoping + fail policy (mirror `cabf_br/mod.rs`).
4. Implement the nine lints (all `RuleSource::CabfEv`; `applies` → `applies_to_ev`):
   - `cabf_ev_organization_name_missing` — `Error` if `subject_organization_names()` is empty. (EVG §9.2.1)
   - `cabf_ev_business_category_missing` — `Error` if `subject_business_category()` is empty. (EVG §9.2.4)
   - `cabf_ev_business_category_invalid` — for each present `businessCategory` value not in
     {`Private Organization`, `Government Entity`, `Business Entity`} → `Error` naming the value. (EVG §9.2.4)
   - `cabf_ev_jurisdiction_country_missing` — `Error` if `subject_jurisdiction_country()` is empty. (EVG §9.2.4)
   - `cabf_ev_serial_number_missing` — `Error` if `subject_serial_numbers()` is empty. (EVG §9.2.6)
   - `cabf_ev_not_wildcard` — `Error` per `san_wildcard_dns_names()` entry, naming it. (EVG §9.2.2)
   - `cabf_ev_san_no_ip_address` — `Error` per `san_ip_addresses()` entry, naming it. (EVG §9.2.2)
   - `cabf_ev_validity_max_398_days` — `Error` if `validity_days() > 398`, message naming the
     duration; boundary 398 passes, 399 fires. (EVG §9.4)
   - `cabf_ev_organization_id_present` — `Error` if `subject_organization_identifiers()` is empty
     (flag the absence). (EVG §9.2.8)
   Each lint file: doc comment with the EVG section, `Lint` impl, and a `#[cfg(test)] mod tests` with
   pass/fail cases. Prefer a pure `evaluate(...)` helper taking plain values (mirror `cabf_br/cn_in_san.rs`)
   so the logic is unit-testable without a fixture. Follow the fail policy: an accessor `Err` in
   `check` returns an empty `Vec` (never fabricate a pass or spurious failure).

## Acceptance Criteria

- [ ] `RuleSource::CabfEv` added (serde `cabf_ev`), doc updated.
- [ ] Nine `cabf_ev_*` lints implemented, each citing its EVG section.
- [ ] All self-scope via `applies_to_ev`: `Applies` iff `is_ev_scope`, `NotApplicable` otherwise,
      fail-closed on `Err`. A non-EV TLS leaf is `NotApplicable` for all nine.
- [ ] `EV_POLICY_OIDS` allowlist present, each OID cited, includes `2.23.140.1.1` + the test OID,
      with a "necessarily incomplete" maintenance note and unit tests.
- [ ] Multi-violation lints (`not_wildcard`, `san_no_ip_address`, `business_category_invalid`) emit
      one finding per offending entry/value.
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (and with `--features serde`).

## Notes / Dependencies

- Depends on task 01 (facade accessors). Blocks task 03 (registration/wiring).
- `source.rs` is shared with siblings 09/10 (each adds a `RuleSource` variant) — the multi-feature
  orchestrator must serialize this edit against theirs. See plan.md "Cross-Feature Coordination".
