---
agent: developer
seq: 3
title: New CA/Browser Forum BR expansion lints
status: pending
touches:
  - crates/linter/src/lints/cabf_br/mod.rs
  - crates/linter/src/lints/cabf_br/dnsname_syntax.rs
  - crates/linter/src/lints/cabf_br/organizational_unit_name_prohibited.rs
  - crates/linter/src/lints/cabf_br/subject_contains_reserved_ip.rs
  - crates/linter/src/lints/cabf_br/extra_subject_common_names.rs
  - crates/linter/src/lints/cabf_br/subject_country_not_iso.rs
depends_on:
  - developer-01-cert-facade-expansion-accessors
---

# Task: New CA/Browser Forum BR expansion lints

## Goal

Implement the curated BR depth-expansion lints, each `RuleSource::CabfBr`, `cabf_br_*` id, citing its
BR section, following the exact shape of the existing 4 BR lints. **BROAD scoping (load-bearing):**
`applies = if cert.is_ca() { NotApplicable } else { Applies }` for every lint — every non-CA leaf is in
scope, NOT EKU-gated; CA certs are `NotApplicable`. Reuse `reserved.rs` where relevant.

All read ONLY facade accessors (task 01 + existing). **None may fire on the current `good.pem`** — see
the plan's "good.pem Conformance Audit" (each PASSes good.pem). This is what avoids re-triggering the
feature-05 shared-fixture cascade; do NOT introduce a check that fires on good.pem or any existing
leaf fixture.

## Files Owned (conflict scope)

- `crates/linter/src/lints/cabf_br/mod.rs` (declare + re-export new modules; keep existing
  declarations/order intact, append new ones)
- `dnsname_syntax.rs` houses FOUR lints (the three label-syntax checks + the bare-wildcard check),
  all of which operate on `san_dns_names()`.
- one file each for the remaining four lints (front-matter).

Does NOT touch `cert.rs` (task 01), `rfc5280/*` (task 02), `reserved.rs` (already exists; reuse it,
do not modify), or `registry.rs` (task 04).

## Steps (each tagged `RuleSource::CabfBr`, broad-scoped)

In `dnsname_syntax.rs` (iterate `san_dns_names()`; one finding per offending name, message names it):
1. `cabf_br_dnsname_underscore_in_sld` — `Error` if any label contains `_`. (BR §7.1.4.2 / §3.2.2.4)
2. `cabf_br_dnsname_bad_character_in_label` — `Error` if any label has a non-LDH char (allow `*` only
   as a whole leftmost label for wildcards; everything else letters/digits/hyphen). (BR §7.1.4.2)
3. `cabf_br_dnsname_label_too_long` — `Error` if any DNS label exceeds 63 octets. (BR §7.1.4.2)
4. `cabf_br_dnsname_wildcard_left_of_public_suffix` — `Error` for a bare wildcard `*.<single-label>`
   (exactly two labels, first is `*`). Conservative: do NOT flag multi-label wildcards like
   `*.example.com`; NO PSL dependency. Document the limitation in the docstring. (BR §3.2.2.6)

Separate files:
5. `cabf_br_organizational_unit_name_prohibited` — `Error` if `subject_organizational_unit_count() > 0`.
   (BR §7.1.4.2.2)
6. `cabf_br_subject_contains_reserved_ip` — for each `subject_common_names()` value that parses as an
   `IpAddr`, `Error` if `reserved::is_reserved_ip(&ip)`. (BR §4.2.2) — distinct from the existing
   SAN-based `cabf_br_no_internal_names_or_reserved_ip`.
7. `cabf_br_extra_subject_common_names` — `Error` if `subject_common_names().len() > 1` (message names
   the count). (BR §7.1.4.2.2)
8. `cabf_br_subject_country_not_iso` — for each `subject_country_values()` entry, `Error` if it is not
   a 2-letter ISO 3166-1 alpha-2 code (allow `XX`). No country attribute ⇒ no finding. Use a small
   in-module alpha-2 allowlist (no crate); document the source/choice. (BR §7.1.4.2.2)

Each file: doc comment citing the BR section, `Lint` impl with broad `applies`, `#[cfg(test)] mod tests`
with a pass and a fail case (fixture-driven integration tests are owned by task 05). Where a lint can
flag several entries, return multiple `Finding`s.

## Acceptance Criteria

- [ ] All 8 shipped BR lints implemented, each `cabf_br_*` id, each citing its BR section.
- [ ] Every lint broad-scoped: `NotApplicable` on a CA, `Applies` on every non-CA leaf (NOT EKU-gated).
- [ ] Multi-entry lints (dnsname_*, reserved-ip, country) return multiple `Finding`s where applicable.
- [ ] No new crate dependency; the ISO/PSL handling is in-module and documented.
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths.
- [ ] `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean.

## Notes / Dependencies

- Depends on task 01. Blocks task 04 (registration references these types).
- Runs in the SAME batch as task 02 (rfc5280 lints); the file sets are disjoint.
- Reuse the existing `crates/linter/src/lints/cabf_br/reserved.rs` — do not modify it.
