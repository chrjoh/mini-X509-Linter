---
agent: developer
seq: 2
title: Implement the four CA/B Forum BR lints
status: pending
touches:
  - crates/linter/src/lints/mod.rs
  - crates/linter/src/lints/cabf_br/mod.rs
  - crates/linter/src/lints/cabf_br/validity_max_398_days.rs
  - crates/linter/src/lints/cabf_br/cn_in_san.rs
  - crates/linter/src/lints/cabf_br/no_internal_names_or_reserved_ip.rs
  - crates/linter/src/lints/cabf_br/ext_key_usage_server_auth_present.rs
depends_on:
  - 01-cert-facade-san-eku-and-ip-helper
---

# Task: Implement the four CA/B Forum BR lints

## Goal

Implement the BR rule set, one small file per lint, each commented with its BR section
number, `cabf_br_*` id, all scoped to TLS leaf certs.

## Files Owned (conflict scope)

- `crates/linter/src/lints/mod.rs` (add `pub mod cabf_br;`)
- `crates/linter/src/lints/cabf_br/mod.rs` (declare lint modules + `pub mod reserved;`)
- the four lint files (listed in front-matter)

Does NOT modify `cert.rs` or `reserved.rs` (task 01) or `registry.rs` (task 03).

## Steps

All tagged `RuleSource::CabfBr`; `applies` returns `NotApplicable` for CA certs (these
target TLS leaves).

1. `validity_max_398_days` — `check` → `Error`/`Warn` if `validity_days() > 398`. Message
   names the actual duration. (BR §6.3.2)
2. `cn_in_san` — `check` → `Error` for each subject CN value not present in
   `san_dns_names()`/`san_ip_addresses()`. May emit multiple findings (one per offending
   CN). (BR §7.1.4.2)
3. `no_internal_names_or_reserved_ip` — `check` → `Error` for each SAN entry that is an
   internal name (`reserved::is_internal_name`) or a reserved IP
   (`reserved::is_reserved_ip`). One finding per offending entry, naming it. (BR §7.1.4.2 /
   §4.2.2)
4. `ext_key_usage_server_auth_present` — `check` → `Error`/`Warn` if `has_server_auth()`
   is false. (BR §7.1.2.7)

In `cabf_br/mod.rs` declare each lint module + `pub mod reserved;`, and re-export the lint
types. Each lint file: doc comment with the BR section, `Lint` impl, and a
`#[cfg(test)] mod tests` with pass/fail cases.

## Acceptance Criteria

- [ ] Four lints implemented, each `cabf_br_*` id, each citing its BR section.
- [ ] All are `NotApplicable` on CA certs.
- [ ] Multi-violation lints (`cn_in_san`, `no_internal_names_or_reserved_ip`) emit one
      finding per offending entry.
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01. Blocks task 03 (registration).
