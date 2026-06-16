# Feature: RFC 5280 Rule Set

## Overview

Implement the first real rule set: the RFC 5280 structural lints. Each is a small, well-commented
`Lint` impl with a dedicated fixture certificate under `testdata/`. This is plan.md Milestone 3.

## Requirements

Implement the RFC 5280 lints listed in plan.md, each tagged `RuleSource::Rfc5280`:

- `version_is_v3` — if extensions are present, the cert version must be v3.
- `serial_number_positive` — serial must be a positive integer, ≤ 20 octets.
- `validity_not_after_after_not_before` — `notAfter` must be later than `notBefore`.
- `basic_constraints_critical_on_ca` — CA certs must mark BasicConstraints critical.
- `key_usage_present_when_ca` — CA certs must have `keyCertSign` in KeyUsage.
- `san_present_if_subject_empty` — an empty subject DN requires a SAN, marked critical.

Each lint:
- Declares scope via `applies()` (e.g. CA-only lints return `NotApplicable` on a leaf).
- Returns `Vec<Finding>` — empty for pass; may return more than one finding where a rule genuinely
  fails for several distinct reasons.
- Carries a comment citing the relevant RFC 5280 section.
- Uses a stable `lint_id` following the `rfc5280_*` naming convention.

## Architecture

- One file per lint (or small grouped files) under `crates/linter/src/lints/rfc5280/`.
- Lints read only through the `Cert` facade; if `x509-parser` doesn't surface something (e.g. raw
  serial octet length), reach for `der` behind the facade rather than in the lint.
- Register each new lint in the registry's default constructor (from feature 02).

## Changes Overview

**crates/linter/**
- `src/lints/rfc5280/mod.rs` — module wiring.
- `src/lints/rfc5280/version_is_v3.rs`
- `src/lints/rfc5280/serial_number_positive.rs`
- `src/lints/rfc5280/validity_window.rs` (`validity_not_after_after_not_before`)
- `src/lints/rfc5280/basic_constraints_critical_on_ca.rs`
- `src/lints/rfc5280/key_usage_present_when_ca.rs`
- `src/lints/rfc5280/san_present_if_subject_empty.rs`
- `src/cert.rs` — extend the facade with any accessors these lints need (extensions, basic
  constraints, key usage, subject DN emptiness, SAN + criticality).
- `src/registry.rs` — register the new lints.

**testdata/**
- One fixture cert per lint that violates exactly that rule, named after the lint
  (e.g. `rfc5280_serial_number_zero.pem`), plus the existing `good.pem` passing them all.
- A regeneration script (`testdata/generate.sh` or similar) using `openssl`/`rcgen`.

## Dependencies

- None new beyond feature 01/02. `der` (already present) may be used for low-level serial inspection.
