---
agent: developer
seq: 2
title: New CA/Browser Forum BR expansion lints (feature 17)
status: done
touches:
  - crates/linter/src/lints/cabf_br/mod.rs
  - crates/linter/src/lints/cabf_br/subscriber_key_usage_prohibited.rs
  - crates/linter/src/lints/cabf_br/subscriber_basic_constraints_path_len_prohibited.rs
  - crates/linter/src/lints/cabf_br/ext_key_usage_any_prohibited.rs
  - crates/linter/src/lints/cabf_br/ext_key_usage_server_auth_required.rs
  - crates/linter/src/lints/cabf_br/san_dns_or_ip_only.rs
  - crates/linter/src/lints/cabf_br/san_present.rs
  - crates/linter/src/lints/cabf_br/certificate_policies.rs
  - crates/linter/src/lints/cabf_br/rsa_modulus_bits_multiple_of_8.rs
  - crates/linter/src/lints/cabf_br/rsa_public_exponent_in_range.rs
  - crates/linter/src/lints/cabf_br/basic_constraints_present.rs
depends_on:
  - developer-01-cert-facade-rsa-exponent
---

# Task: New CA/Browser Forum BR expansion lints (feature 17)

## Goal

Implement the 12 curated BR depth-expansion lints, each `RuleSource::CabfBr`, `cabf_br_*` id, citing
its BR section, following the exact shape of the existing BR lints (e.g.
`organizational_unit_name_prohibited.rs`, `subject_country_not_iso.rs`). **BROAD scoping
(load-bearing):** every lint reuses the existing `applies_to_leaf(cert)` helper in `mod.rs` —
`applies = if cert.is_ca() { NotApplicable } else { Applies }`. Every non-CA leaf is in scope, NOT
EKU-gated; CA certs are `NotApplicable`.

All read ONLY facade accessors (developer-01's new `rsa_public_exponent()` + existing ones). **None may
fire an Error on `good.pem` or any existing leaf fixture** — see the plan's "good.pem Conformance
Audit". Three lints (7, 8, 12) are `Warn` severity by deliberate cascade design. **good.pem is being
regenerated (by tester-04) to carry a `certificatePolicies` DV OID `2.23.140.1.2.1`, so lints 8 and 9
must PASS on it — good.pem ends up finding-free across all 12 new lints (no Warn, no Error).** Implement
lints 8 and 9 against the facade so a leaf carrying `certificatePolicies` with the DV reserved OID
passes BOTH (lint 8: policies present; lint 9: a reserved OID present). Do NOT introduce any finding
that fires on the regenerated good.pem.

## Files Owned (conflict scope)

- `crates/linter/src/lints/cabf_br/mod.rs` (declare + re-export new modules; keep existing
  declarations/order intact, append new ones; do NOT modify the `applies_to_leaf` helper signature).
- One file per lint (front-matter), EXCEPT two sibling-pair files:
  - `subscriber_key_usage_prohibited.rs` houses BOTH the `keyCertSign` and `cRLSign` lints.
  - `certificate_policies.rs` houses BOTH the policies-present and policies-reserved-oid lints.

Does NOT touch `cert.rs` (developer-01), `reserved.rs` (reuse if needed, do not modify), or
`registry.rs` (developer-03).

## Steps (each tagged `RuleSource::CabfBr`, broad-scoped via `applies_to_leaf`)

In `subscriber_key_usage_prohibited.rs` (read `key_usage()`; skip/no-finding when KeyUsage absent):
1. `cabf_br_subscriber_key_usage_cert_sign_prohibited` — `Error` if `KeyUsageView.key_cert_sign`.
   (BR §7.1.2.7 subscriber KeyUsage; `keyCertSign` is CA-only.)
2. `cabf_br_subscriber_key_usage_crl_sign_prohibited` — `Error` if `KeyUsageView.crl_sign`.
   (Same clause; `cRLSign` is CA-only.)

Separate files:
3. `cabf_br_subscriber_basic_constraints_path_len_prohibited` — `Error` if `basic_constraints()`
   yields a view with `path_len.is_some()`. (BR §7.1.2.7 / RFC 5280 §4.2.1.9.) Skip when no
   BasicConstraints. (Intentionally co-fires the feature-12 RFC sibling; that is the tester's concern.)
4. `cabf_br_ext_key_usage_any_prohibited` — `Error` if `extended_key_usage()` view's `oids` contains
   the `anyExtendedKeyUsage` OID `2.5.29.37.0` (in-module `const`). (BR §7.1.2.7.6.) Skip when no EKU.
5. `cabf_br_ext_key_usage_server_auth_required` — `Error` if the EKU extension IS present but
   `EkuView.server_auth` is false. (BR §7.1.2.7.6.) Skip (no finding) when EKU is ABSENT — this is
   what distinguishes it from the existing `cabf_br_ext_key_usage_server_auth_present` (which flags the
   absent/no-serverAuth case). Document the distinction in the docstring. **Lint 5 is KEPT** — its
   intentional co-fire with the existing lint on `cabf_br_missing_serverauth.pem` is reconciled by
   tester-04 as a documented two-rule assertion; no developer action beyond the distinct surface.
6. `cabf_br_san_dns_or_ip_only` — for each `san_entries()` entry whose `GeneralNameView.kind` is not
   `"DNS"` or `"IP"`, emit one `Error` naming the entry kind/value. (BR §7.1.2.7.12.) Skip when SAN
   absent.
7. `cabf_br_san_present` — `Warn` if `subject_alt_name()` is `None` (SAN extension absent).
   (BR §7.1.2.7.12.) **Severity `Warn` (load-bearing — see plan Cascade-Management §A).**
8. `cabf_br_certificate_policies_present` — `Warn` if `certificate_policy_oids()` is empty (no
   CertificatePolicies). (BR §7.1.2.7.9.) **Severity `Warn`** (defence-in-depth for policies-free
   leaves). good.pem is regenerated to carry `certificatePolicies`, so this lint **PASSES on good.pem**
   (no finding).
9. `cabf_br_certificate_policies_reserved_oid` — when `certificate_policy_oids()` is NON-empty,
   `Error` if NONE of the reserved CABF OIDs `2.23.140.1.2.1` (DV) / `.2.2` (OV) / `.2.3` (IV)
   (in-module `const` list) is present. (BR §7.1.6.1.) Skip (no finding) when CertificatePolicies is
   ABSENT. good.pem carries the DV OID `2.23.140.1.2.1`, so this lint **PASSES on good.pem** (positive
   pass: policies present AND a reserved OID present).
10. `cabf_br_rsa_modulus_bits_multiple_of_8` — `Error` if `rsa_modulus_bits()` is `Some(bits)` with
    `bits % 8 != 0`. (BR §6.1.6.) `None` (non-RSA) ⇒ no finding.
11. `cabf_br_rsa_public_exponent_in_range` — read developer-01's `rsa_public_exponent()`; `Error` if
    the view is `Some` and NOT (`is_odd && at_least_65537 && at_most_2_256_minus_1`). (BR §6.1.6.)
    `None` (non-RSA) ⇒ no finding.
12. `cabf_br_basic_constraints_present` — `Warn` if `basic_constraints()` is `None` (no
    BasicConstraints extension). (BR §7.1.2.7.8.) **Severity `Warn`** (defence-in-depth; good.pem
    PASSES — it has BasicConstraints).

Each file: doc comment citing the BR section + the broad-scoping note + the fail-policy note (copy the
style from the existing cabf_br lints), a pure `evaluate(...)` helper where it clarifies the decision,
the `Lint` impl with `applies = applies_to_leaf`, and `#[cfg(test)] mod tests` with at least a pass and
a fail case (fixture-driven integration tests are owned by tester-04). Where a lint can flag several
entries (lint 6), return multiple `Finding`s.

## No cuts (Phase-1.5 — count settled at 12)

All 12 lints are KEPT (Phase-1.5 decisions 1 & 2). Do NOT cut any lint. The two cascade interactions
that earlier flirted with cuts are now settled and owned by tester-04, not the developer:
- Lint 5 co-fire with the existing serverAuth lint → documented two-rule assertion (tester-04).
- Lints 7/8/12 `Warn` severity → reconciled in test assertions / golden snapshots; good.pem is
  regenerated so lint 8 PASSES on it. No developer-side cut.

## Acceptance Criteria

- [ ] All 12 BR lints implemented (none cut), each `cabf_br_*` id, each citing its BR section.
- [ ] Every lint broad-scoped via `applies_to_leaf`: `NotApplicable` on a CA, `Applies` on every
      non-CA leaf (NOT EKU-gated).
- [ ] Severities: lints 7, 8, 12 = `Warn`; lints 1–6, 9, 10, 11 = `Error`.
- [ ] Multi-entry lint 6 returns multiple `Finding`s where applicable.
- [ ] No new crate dependency; reserved-policy OIDs and the `anyEKU` OID are in-module `const`s and
      documented.
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths; accessor `Err` in `check` → empty `Vec`.
- [ ] No finding (Error OR Warn) fires on the regenerated good.pem; lints 8 and 9 PASS on a leaf
      carrying `certificatePolicies` with the DV reserved OID `2.23.140.1.2.1`.
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean; existing tests pass.

## Notes / Dependencies

- Depends on developer-01 (lint 11 reads `rsa_public_exponent()`). Blocks developer-03 (registration
  references these types).
- Reuse the existing `crates/linter/src/lints/cabf_br/reserved.rs` if relevant — do not modify it.
</content>
