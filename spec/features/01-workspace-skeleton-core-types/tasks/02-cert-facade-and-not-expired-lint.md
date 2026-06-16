---
agent: developer
seq: 2
title: Cert facade + not_expired lint
status: done
touches:
  - crates/linter/src/cert.rs
  - crates/linter/src/lints/mod.rs
  - crates/linter/src/lints/hygiene/mod.rs
  - crates/linter/src/lints/hygiene/not_expired.rs
depends_on:
  - 01-workspace-and-contract-types
---

# Task: Cert facade + not_expired lint

## Goal

Build the `Cert` parsing facade over `x509-parser` and the trivial bootstrap lint
`not_expired` (hygiene) that exercises the `Lint` contract end-to-end.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs`
- `crates/linter/src/lints/mod.rs`
- `crates/linter/src/lints/hygiene/mod.rs`
- `crates/linter/src/lints/hygiene/not_expired.rs`

Must NOT modify `lib.rs` beyond what task 01 already wired (the `mod cert;` and
`mod lints;` declarations). If a `mod lints;` line is missing, coordinate — but task 01
declares `mod cert`; add `mod lints;` there is owned by task 01. Keep `lib.rs` edits out
of this task; if `mod lints;` is needed, request task 01 add it (it is listed in task 01's lib.rs work implicitly via module wiring).

## Steps

1. `crates/linter/src/cert.rs`:
   - `pub struct Cert` that **owns its backing DER bytes** and exposes a parsed view, so
     callers get a self-contained value (no leaking `x509-parser` lifetimes). A common
     pattern: store `der: Vec<u8>` and re-parse on access, or use a self-referential-safe
     approach (owning the bytes + parsing in accessor methods is acceptable and simplest).
   - `pub fn from_der(bytes: &[u8]) -> Result<Cert, CertError>`.
   - `pub fn from_pem(bytes: &[u8]) -> Result<Vec<Cert>, CertError>` (a PEM may hold many).
   - `pub fn load(bytes: &[u8]) -> Result<Vec<Cert>, CertError>` — auto-detect PEM vs DER
     (PEM begins with `-----BEGIN`).
   - Accessor needed now: validity window — `not_before()` and `not_after()` returning a
     time type (`x509-parser`'s `ASN1Time` or convert to `OffsetDateTime`). Keep accessors
     minimal; later features extend this file.
   - `#[derive(thiserror::Error)] pub enum CertError` for parse failures (generic messages;
     no panics, no `unwrap` on parse paths).
2. `crates/linter/src/lints/mod.rs` — declare `pub mod hygiene;`.
3. `crates/linter/src/lints/hygiene/mod.rs` — declare `pub mod not_expired;` and re-export
   the lint type.
4. `crates/linter/src/lints/hygiene/not_expired.rs`:
   - `pub struct NotExpired;` implementing `Lint`.
   - `id()` → `"hygiene_not_expired"`; `source()` → `RuleSource::Hygiene`.
   - `applies()` → always `Applies`.
   - `check()` → compare `not_after()` to now; if expired, return one `Finding`
     (`Severity::Warn`, message naming the expiry date). Empty `Vec` otherwise.
   - Cite that this is informational hygiene, not an RFC 5280 hard fail.
   - Add a `#[cfg(test)] mod tests` covering an expired and a not-expired case using
     constructed/loaded certs (the dedicated fixture-based unit test may also be added by
     the tester; a minimal in-file test here is fine).

## Acceptance Criteria

- [ ] `Cert::load` correctly auto-detects PEM and DER inputs.
- [ ] `Cert` owns its bytes — no borrowed lifetime escapes the facade.
- [ ] `NotExpired` implements `Lint`; returns one `Warn` finding for an expired cert,
      empty for a valid one.
- [ ] No `unwrap`/`expect`/`panic!` on parse or check paths.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01 (contract types + trait + `mod cert;`/`mod lints;` wiring in lib.rs).
