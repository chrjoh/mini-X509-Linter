# Feature: Workspace Skeleton & Core Types

## Overview

Stand up the cargo workspace and the type contract every lint codes against, then prove the
pipeline end-to-end with a single trivial lint. After this feature, `mini-x509-lint <PATH>` can load a
PEM/DER certificate and print one finding. This is plan.md Milestone 1 plus the "Core types" contract.

## Requirements

- A cargo workspace with two crates to start: `crates/linter/` (library) and `crates/cli/` (binary
  named `mini-x509-lint`). The `fetch` crate is added later in feature 07.
- A `Cert` facade in the `linter` crate: a thin wrapper over `x509-parser`'s parsed certificate so
  lints code against our type, not the parser's, leaving room to swap the parser later.
- The core contract types, exactly as specified in plan.md:
  - `enum Severity { Notice, Warn, Error, Fatal }` — no `Pass` variant; "passed" = empty findings.
  - `enum RuleSource { Rfc5280, CabfBr, Hygiene }`
  - `enum Applicability { Applies, NotApplicable }`
  - `struct Finding { severity: Severity, message: String }` — one specific problem; a lint may
    return several.
  - `struct LintOutcome { lint_id: &'static str, source: RuleSource, applicability: Applicability,
    findings: Vec<Finding> }` — engine-attached identity; empty findings + `Applies` = pass.
  - `trait Lint { id(); source(); applies(&Cert) -> Applicability; check(&Cert) -> Vec<Finding> }`
    where an empty `Vec` means pass and the engine only calls `check` when `applies == Applies`.
- One trivial lint to exercise the contract: `not_expired` (hygiene) — emits a `Notice`/`Warn`
  finding if the cert is already expired, empty otherwise.
- CLI input loading: read a file path, auto-detect PEM vs DER, parse into a `Cert`, run the single
  lint, and print the finding(s) as text. Just enough to show the full pipe working.

## Architecture

- `linter` crate owns parsing facade + the contract; it has **no network code** and no CLI concerns.
- `Cert` borrows from the parsed DER/`x509-parser` structures; keep lifetimes contained behind the
  facade (own the backing bytes in `Cert` so callers get a self-contained value).
- The `Lint` trait is object-safe so the engine (feature 02) can hold `Vec<Box<dyn Lint>>`.
- CLI is a thin shell: load → (hard-coded list of one lint for now) → format. The registry abstraction
  arrives in feature 02; here a direct call is acceptable to keep the milestone small.

## Changes Overview

**crates/linter/**
- `Cargo.toml` — deps: `x509-parser`, `der`, `oid-registry`, `thiserror`.
- `src/lib.rs` — module wiring, re-exports of the public contract.
- `src/cert.rs` — `Cert` facade over `x509-parser` (load-from-PEM, load-from-DER, accessors used by
  `not_expired`: validity window).
- `src/finding.rs` — `Severity`, `Finding`, `LintOutcome`.
- `src/source.rs` — `RuleSource`.
- `src/lints/mod.rs`, `src/lints/hygiene/not_expired.rs` — the trivial lint + the `Lint` trait if not
  placed in `lib.rs`.

**crates/cli/**
- `Cargo.toml` — deps: `linter` (path), `clap`, `anyhow`.
- `src/main.rs` — accept `<PATH>`, load, run the one lint, print findings.

**workspace root**
- `Cargo.toml` — `[workspace]` members.

**testdata/**
- `good.pem` — a certificate that passes `not_expired`.
- `expired.pem` — a certificate that violates `not_expired` (fixture for the unit test).

## Dependencies

Versions pinned to current latest stable releases on 2026-06-15 (verified against crates.io).

- `x509-parser = "0.18"` (linter) — latest stable 0.18.1
- `der = "0.8"` (linter) — latest stable 0.8.0
- `oid-registry = "0.8"` (linter) — latest stable 0.8.1 (NOT 0.9; see note)
- `thiserror = "2"` (linter) — latest stable 2.0.x (see note)
- `clap = { version = "4", features = ["derive"] }` (cli) — latest stable 4.6.1
- `anyhow = "1"` (cli) — latest stable 1.0.102

### Compatibility notes (x509-parser / der / oid-registry coupling)

- `x509-parser 0.18.1` transitively pins `oid-registry ^0.8.1`. The newest `oid-registry`
  on crates.io is `0.9.0-beta.1`, a pre-release; pinning `oid-registry = "0.9"` would
  conflict with x509-parser and is also a beta. We therefore pin `oid-registry = "0.8"`
  (resolves to 0.8.1) to stay on the same major that x509-parser requires.
- `x509-parser 0.18.1` does **not** depend on the RustCrypto `der` crate. Its ASN.1
  backend is the `asn1-rs` / `der-parser` family (`asn1-rs ^0.7`, `der-parser ^10`). The
  `der = "0.8"` listed here is the independent RustCrypto `der` crate and is **not**
  version-coupled with x509-parser. If the lints in later features do not end up needing
  RustCrypto `der` directly, this dependency can be dropped; keep it only if a lint parses
  DER structures outside the x509-parser facade.
- `thiserror` is bumped from `1` to `2` to match x509-parser's own `thiserror ^2.0`
  requirement, avoiding two parallel `thiserror` majors in the dependency tree.
