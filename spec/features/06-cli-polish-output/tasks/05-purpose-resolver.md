---
agent: developer
seq: 5
title: CertPurpose enum + purpose→RuleSource resolver (linter crate)
status: pending
touches:
  - crates/linter/src/registry.rs
depends_on: []
---

# Task: CertPurpose enum + purpose→RuleSource resolver (linter crate)

## Goal

Add the certificate-purpose abstraction to the **linter** crate so the CLI can scope which lint
sources run without re-encoding the mapping itself. A purpose resolves to an allowed set of
`RuleSource`s; the CLI then reuses the existing `Registry::run_filtered(&Cert, &[RuleSource])` to run
only those sources. This is a **filtering** layer — no lint logic, `applies()` rule, or fixture
changes, and feature 05's BROAD scoping is untouched.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`

Sole owner of `registry.rs` in feature 06. No CLI task touches this file. This task is independent
of task 01 (different crate/file) and may run in the same parallel batch; it **blocks** task 02
(`main.rs` maps `--purpose` into this type and calls the resolver).

## Steps

1. Add a `CertPurpose` enum next to `RuleSource` / `run_filtered`:
   - Shipped variants: `Auto`, `TlsServer`, `Generic`.
   - Reserve `Client`, `Smime`, `CodeSigning` as **planned future** values — document them in a doc
     comment only; do **not** add them as variants now (keep the enum minimal but note the intended
     extension so adding them later is additive).
   - Derive the usual `Debug, Clone, Copy, PartialEq, Eq`. Do **not** add a clap `ValueEnum` derive
     here — the CLI owns its own flag vocabulary and maps into this type (mirrors how `MinSeverity`
     in `main.rs` is decoupled from `linter::Severity`).
2. Implement the purpose → allowed-sources resolver. Recommended shape:
   `pub fn allowed_sources(self, cert: &Cert) -> Vec<RuleSource>` on `CertPurpose`, with the mapping:
   - `TlsServer` → `[Rfc5280, Hygiene, CabfBr]` (all current sources).
   - `Generic`   → `[Rfc5280, Hygiene]` (skip the TLS-server-specific `CabfBr` set).
   - `Auto`      → resolved **per cert**: call `cert.has_server_auth()`; `Ok(true)` → same set as
     `TlsServer`, `Ok(false)` → same set as `Generic`. **Fail closed for the false-positive risk:**
     on `Err(..)` resolve to the `Generic` set (skip `CabfBr`) so a defensive parse failure cannot
     manufacture a BR false positive. Do not panic or propagate the error from this resolver.
   - Keep the `TlsServer` / `Generic` arms re-using a single static helper so the sets stay in sync
     (e.g. `Auto`-resolved-to-tls-server and explicit `TlsServer` return the identical slice/vec).
3. Document on the resolver: `auto` is a documented **heuristic**; `--purpose tls-server` (handled in
   the CLI) forces the `CabfBr` set even when serverAuth is absent. Note that ordering of the returned
   sources should be stable (e.g. always `Rfc5280, Hygiene, CabfBr`) so downstream output stays
   deterministic.
4. Add `#[cfg(test)]` unit tests in the same file:
   - `TlsServer.allowed_sources(..)` contains `CabfBr`; `Generic.allowed_sources(..)` does not.
   - `Auto` on a serverAuth leaf → contains `CabfBr`; `Auto` on a non-serverAuth leaf → omits
     `CabfBr`. (Build minimal `Cert` fixtures the way existing `registry.rs` tests do — reuse the
     crate's existing test helpers / fixtures; do **not** add new files to `testdata/`.)
5. Export `CertPurpose` from the crate root if `RuleSource` is exported there, so the CLI can
   `use linter::CertPurpose;` (match the existing `pub use` pattern for `RuleSource`).

## Acceptance Criteria

- [ ] `CertPurpose` enum exists with `Auto`, `TlsServer`, `Generic`; future variants documented only.
- [ ] Resolver returns the documented allowed-source sets for each variant.
- [ ] `Auto` resolves per cert from `has_server_auth()`; `Err(..)` falls back to the `Generic` set.
- [ ] Returned source ordering is stable/deterministic.
- [ ] `CertPurpose` is exported from the crate root alongside `RuleSource`.
- [ ] Unit tests cover tls-server/generic/auto(serverAuth)/auto(non-serverAuth) without new
      `testdata/` files.
- [ ] No lint logic, `applies()`, or fixture changes; feature 05 BROAD scoping untouched.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- No code dependency on other feature-06 tasks; blocks task 02 (main.rs uses `CertPurpose` +
  `allowed_sources`). Can run in the same batch as task 01 (disjoint files/crates).
