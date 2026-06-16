# Feature: CA/Browser Forum BR Rule Set

## Overview

Implement the web-PKI–specific Baseline Requirements lints. This is where most ambiguity lives, so
each lint stays small and is commented with its BR section number. This is plan.md Milestone 5.

## Requirements

Implement the CA/B Forum BR lints from plan.md, each tagged `RuleSource::CabfBr`:

- `validity_max_398_days` — leaf TLS certs must be ≤ 398 days.
- `cn_in_san` — any subject CN value must also appear in the SAN.
- `no_internal_names_or_reserved_ip` — reject internal/reserved names and reserved IPs in the SAN.
- `ext_key_usage_server_auth_present` — TLS leaf certs should carry the `serverAuth` EKU.

Each lint:
- Scopes via `applies()` (these target TLS **leaf** certs; CA certs are `NotApplicable`).
- Returns `Vec<Finding>` with messages that name the specific SAN entry / CN / duration at fault.
- Carries a comment with the BR section number it enforces.
- Uses `cabf_br_*` naming for `lint_id`.

## Architecture

- One small file per lint under `crates/linter/src/lints/cabf_br/`.
- Reuse the SAN / subject / EKU / validity accessors added in features 03–04; add any missing ones to
  the `Cert` facade (e.g. helpers to enumerate SAN dNSName / iPAddress entries, classify reserved IP
  ranges, and read EKU OIDs).
- "Internal/reserved" name and IP classification should be a small, well-documented helper so the
  rule is auditable; keep the reserved-range list in one place.
- Register the lints in the default registry.

## Changes Overview

**crates/linter/**
- `src/lints/cabf_br/mod.rs`
- `src/lints/cabf_br/validity_max_398_days.rs`
- `src/lints/cabf_br/cn_in_san.rs`
- `src/lints/cabf_br/no_internal_names_or_reserved_ip.rs`
- `src/lints/cabf_br/ext_key_usage_server_auth_present.rs`
- `src/cert.rs` — SAN entry enumeration, EKU accessors, IP classification helper (or a small
  dedicated module).
- `src/registry.rs` — register the BR lints.

**testdata/**
- One fixture per lint (e.g. `cabf_br_validity_400_days.pem`, `cabf_br_cn_not_in_san.pem`,
  `cabf_br_internal_san.pem`, `cabf_br_missing_serverauth.pem`), plus regeneration-script updates.

## Dependencies

- None new. May lean on `std::net`/`ipaddress`-style logic for reserved-range checks; prefer std
  where possible and document any added crate.
