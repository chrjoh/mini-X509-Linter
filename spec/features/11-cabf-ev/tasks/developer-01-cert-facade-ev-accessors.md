---
agent: developer
seq: 1
title: Cert facade EV subject-attribute, policy-OID, and wildcard-SAN accessors
status: done
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade EV subject-attribute, policy-OID, and wildcard-SAN accessors

## Goal

Add the `Cert` facade accessors the EV lints and the `is_ev_scope()` helper need: the
`certificatePolicies` policy OIDs, the EV subject-DN identity attributes, and wildcard-SAN
detection. All documented and non-panicking (`Result<_, CertError>`), following the existing
accessor style in `cert.rs` (see `subject_common_names`, `san_dns_names`, `san_ip_addresses`,
`validity_days`).

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs` (extend only — do not touch any other file)

## Steps

1. Add a small internal helper that returns all subject-DN attribute values for a given attribute
   OID (the `subject_common_names` accessor already does this for `2.5.4.3`; generalize so the new
   accessors delegate to one place). Keep it DRY and auditable; document which OID each public
   accessor reads.
2. Public accessors (each documented with the OID it reads and the EV lint that consumes it):
   - `certificate_policy_oids() -> Result<Vec<String>, CertError>` — policy OIDs from the
     `certificatePolicies` extension (OID `2.5.29.32`), dotted form, in encounter order; empty `Vec`
     when the extension is absent. Use `x509-parser`'s `certificate_policies()` accessor; treat a
     malformed/absent extension as an empty list (do not surface as `Err`).
   - `subject_organization_names()` — `organizationName` (O, OID `2.5.4.10`).
   - `subject_business_category()` — `businessCategory` (OID `2.5.4.15`).
   - `subject_jurisdiction_country()` — `jurisdictionOfIncorporationCountryName`
     (OID `1.3.6.1.4.1.311.60.2.1.3`).
   - `subject_serial_numbers()` — the subject DN `serialNumber` attribute (OID `2.5.4.5`).
     **Document clearly** that this is the subject DN attribute (the EV registration/incorporation
     number), distinct from the *certificate* serial number surfaced by `serial_summary`.
   - `subject_organization_identifiers()` — `organizationIdentifier` (OID `2.5.4.97`).
   - `san_wildcard_dns_names() -> Result<Vec<String>, CertError>` — the SAN dNSName entries that
     begin with `*.` (wildcard names), in encounter order; empty `Vec` when none. Reuse the existing
     SAN dNSName parsing path (mirror `san_dns_names`).
3. Add `#[cfg(test)] mod` unit tests for the new accessors against `testdata/good.pem` (a non-EV
   leaf: assert `certificate_policy_oids()` and the EV subject attributes are empty/absent, and
   `san_wildcard_dns_names()` is empty). EV-cert-positive coverage comes from the EV fixtures in task
   04; for now assert the non-EV/empty cases so this task has no fixture dependency.

## Acceptance Criteria

- [ ] All seven accessors present, each documented with the OID it reads and the consuming EV lint.
- [ ] `subject_serial_numbers()` doc explicitly distinguishes the subject-DN `serialNumber` attribute
      from the certificate serial number.
- [ ] All return `Result<_, CertError>`; no `unwrap`/`expect`/`panic!` on cert data paths.
- [ ] Unit tests cover the non-EV/empty cases against `good.pem`.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (and with `--features serde`).

## Notes / Dependencies

- Blocks task 02 (lints) and indirectly tasks 03/04.
- `cert.rs` is owned ONLY by this task in this feature; no other task edits it.
