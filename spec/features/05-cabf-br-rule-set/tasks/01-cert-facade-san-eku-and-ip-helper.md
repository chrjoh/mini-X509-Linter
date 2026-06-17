---
agent: developer
seq: 1
title: Cert facade SAN/EKU accessors + reserved-IP/name helper
status: done
touches:
  - crates/linter/src/cert.rs
  - crates/linter/src/lints/cabf_br/reserved.rs
depends_on: []
---

# Task: Cert facade SAN/EKU accessors + reserved-IP/name helper

## Goal

Add the SAN entry enumeration and EKU accessors the BR lints need, plus a small, auditable
helper module that classifies internal/reserved names and reserved IP ranges (kept in one
place so the rule is reviewable).

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs` (extend with SAN entry enumeration + EKU accessors)
- `crates/linter/src/lints/cabf_br/reserved.rs` (new helper module — owned here so the
  lint files in task 02 stay free of conflict)

## Steps

1. `cert.rs` accessors (documented, non-panicking):
   - `san_dns_names()` → `Vec<String>` of dNSName entries.
   - `san_ip_addresses()` → `Vec<IpAddr>` of iPAddress entries (use `std::net::IpAddr`).
   - `subject_common_names()` → `Vec<String>` of CN values from the subject DN.
   - `ext_key_usage_oids()` → `Option<Vec<oid>>` and a `has_server_auth()` predicate
     (serverAuth EKU OID 1.3.6.1.5.5.7.3.1).
   - `validity_days()` → duration in days between `not_before` and `not_after` (for the
     398-day rule). Reuse the existing validity accessors.
   - An `is_ca()` predicate so BR lints can scope to leaves. **Broad scoping:** BR lints apply to
     EVERY non-CA leaf (NOT EKU-gated), so the scoping predicate the lints need is simply "is this a
     CA?". `is_ca()` must be robust: a cert with no BasicConstraints (or CA:FALSE) is a non-CA leaf.
2. `lints/cabf_br/reserved.rs`:
   - `pub fn is_reserved_ip(ip: &IpAddr) -> bool` — classify private, loopback,
     link-local, unspecified, multicast, documentation, and other reserved ranges. Prefer
     `std::net::Ipv4Addr`/`Ipv6Addr` predicates; keep the range list in this one module,
     each entry commented with its RFC (e.g. RFC 1918, RFC 5737).
   - `pub fn is_internal_name(name: &str) -> bool` — classify internal/non-resolvable
     names (e.g. `.local`, `.internal`, single-label hostnames, reserved TLDs). Document
     the policy; keep it small and auditable.
   - Add `#[cfg(test)] mod tests` for the classifiers (clear true/false cases).
   - Wire `pub mod reserved;` into `lints/cabf_br/mod.rs` — but that file is owned by
     task 02; to avoid a conflict, this task creates `reserved.rs` only, and task 02
     declares the module. (If `mod.rs` does not yet exist, task 02 creates it and declares
     `pub mod reserved;`.)

Prefer `std`; if a crate is genuinely needed for IP classification, document it and add it
to `crates/linter/Cargo.toml` (note the addition explicitly per the plan).

## Acceptance Criteria

- [ ] SAN dNSName/iPAddress enumeration, CN enumeration, EKU accessors, and validity-days
      helper all present and documented.
- [ ] `reserved.rs` classifiers cover private/loopback/link-local/reserved ranges, each
      cited with its RFC, with unit tests.
- [ ] Prefer `std`; any added crate is documented.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Blocks task 02 (lints) and task 03 (registration).
- `cert.rs` is ALSO edited by task 05 (the `good_cert` unit-test rewrite). Task 05 is in a LATER
  batch and `depends_on` this task, so the two never edit `cert.rs` concurrently. Do not touch the
  `good_cert_has_no_key_usage_or_san` test here — that is task 05's job.
