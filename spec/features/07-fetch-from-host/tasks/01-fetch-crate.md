---
agent: developer
seq: 1
title: Standalone fetch crate — blocking handshake + verify verdict
status: pending
touches:
  - crates/fetch/Cargo.toml
  - crates/fetch/src/lib.rs
  - Cargo.toml
depends_on: []
---

# Task: Standalone fetch crate — blocking handshake + verify verdict

## Goal

Create `crates/fetch/`: a standalone, network-capable crate that performs a blocking TLS
handshake, captures the presented chain (even if untrusted/expired) via an accept-any
verifier, and separately produces a verification verdict against a root store. It must NOT
depend on `linter`.

## Files Owned (conflict scope)

- `crates/fetch/Cargo.toml` (new)
- `crates/fetch/src/lib.rs` (new)
- `Cargo.toml` (workspace root — add `crates/fetch` to members)

## Steps

1. `crates/fetch/Cargo.toml`:
   - deps (pin current): `rustls = "0.23"`, `rustls-pki-types = "1"`, `webpki-roots = "1"`,
     `thiserror = "1"`.
   - `[features]` with a `fetch` feature gating the network capability per the plan
     (decide whether the crate's network code is always-on within the crate but the CLI
     gates it; the plan asks for a `fetch` feature — implement it on the CLI side, and
     mirror a feature here if it cleanly gates the rustls deps).
2. `crates/fetch/src/lib.rs`:
   - Public API: `pub fn fetch_chain(target: &Target, sni: Option<&str>, timeout: Duration)
     -> Result<FetchedChain, FetchError>`.
   - `pub struct FetchedChain { pub leaf_der: Vec<u8>, pub intermediates_der: Vec<Vec<u8>>,
     pub verdict: VerificationVerdict }`.
   - `pub enum VerificationVerdict { Valid, Invalid { reason: String } }`.
   - `Target` parsing/validation helper:
     - Enforce `host[:port]` shape; default port 443; restrict to a sane port range
       (1–65535, reject 0).
     - Classify host as hostname vs IP address.
     - Behind a flag/option, refuse private/loopback/link-local targets (SSRF guard) —
       expose this as a parameter so the CLI can surface it.
   - SNI rules: hostname → derive SNI by default (overridable); IP → SNI required, return
     a clear `FetchError` if missing.
   - Handshake: blocking `rustls` over `std::net::TcpStream` with the timeout applied to
     connect + handshake. Use an accept-any verifier that records the presented certs.
     // SECURITY: this accept-any verifier exists ONLY to capture the presented chain for
     extraction; it must never be reused for trust decisions. Keep it private to this crate.
   - Verification: a SEPARATE pass using a real `WebPkiServerVerifier` + `webpki-roots`
     root store, producing the `VerificationVerdict` (valid / why it failed). A failed
     verdict must NOT prevent returning the captured chain.
   - `#[derive(thiserror::Error)] pub enum FetchError` for connect/handshake/timeout/
     parse/validation failures, with generic messages (no internal detail leakage).
   - Fail-closed verification: any error in the verify pass → `Invalid { reason }`, never
     silently treated as valid.

Follow `.claude/rules/rust-secure-coding.md` and the OWASP A04 TLS guidance: the only
deliberate verification bypass is the documented capture verifier, scoped to extraction.

## Acceptance Criteria

- [ ] `crates/fetch` builds standalone and does NOT depend on `linter`.
- [ ] `fetch_chain` returns leaf + intermediates + a separate verdict; a bad cert still
      yields the chain plus an `Invalid { reason }`.
- [ ] Accept-any verifier is private, documented with `// SECURITY:`, used only for capture.
- [ ] Host validation (shape, port range, optional SSRF guard) and SNI rules (IP requires
      `--sni`) implemented; clear generic errors.
- [ ] Timeout applies to connect + handshake.
- [ ] `cargo clippy --all-targets -- -D warnings` clean for the crate.

## Notes / Dependencies

- Independent of the CLI tasks except via the workspace `Cargo.toml` edit (shared with
  task 02). To avoid a manifest conflict, this task owns the workspace `members` edit;
  task 02 does NOT touch root `Cargo.toml`.
- Blocks tasks 02 and 04.
