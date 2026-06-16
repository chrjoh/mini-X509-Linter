---
agent: tester
seq: 4
title: Fetch tests against a hermetic local TLS server
status: pending
touches:
  - crates/fetch/Cargo.toml
  - crates/fetch/tests/handshake.rs
  - crates/fetch/tests/validation.rs
depends_on:
  - 02-cli-from-host-wiring
---

# Task: Fetch tests against a hermetic local TLS server

## Goal

Test the `fetch` crate offline and deterministically: stand up a local `rustls` server with
a known cert, fetch from it, and assert the captured chain and verdict. Also unit-test host
validation and SNI rules.

## Files Owned (conflict scope)

- `crates/fetch/Cargo.toml` (add `[dev-dependencies]` only — e.g. a rustls server-side
  dep and `rcgen` for an in-test cert)
- `crates/fetch/tests/handshake.rs`
- `crates/fetch/tests/validation.rs`

## Steps

1. `crates/fetch/Cargo.toml` — add dev-deps needed for a local TLS server fixture
   (e.g. `rcgen` to mint a test cert; rustls server config). Keep these dev-only.
2. `crates/fetch/tests/handshake.rs` (SIFER, Result-assertion conventions):
   - Spawn a blocking `rustls` TLS server on `127.0.0.1:0` (ephemeral port) with a known
     self-signed cert, on a background thread. Tear it down at test end.
   - `fetch_chain` against it (with `--sni`/SNI supplied since it's an IP/loopback target,
     and the SSRF guard disabled for the test) → assert the captured `leaf_der` matches the
     server's cert.
   - Assert the verdict is `Invalid { reason }` for the self-signed cert (not in the root
     store) — proving capture succeeds even when verification fails.
   - Assert intermediates are captured if the server presents any.
3. `crates/fetch/tests/validation.rs`:
   - Host parsing: `host`, `host:443`, `host:8443` accepted; port 0 / out-of-range / bad
     shape rejected with the right `FetchError`.
   - SNI rule: IP target without SNI → error; hostname derives SNI.
   - SSRF guard (when enabled): loopback/private target refused; (when disabled) allowed.
   - Timeout: a connect to an unroutable/blackhole address returns a timeout error within
     the budget (keep this test fast and hermetic; prefer a non-listening local port that
     refuses quickly, or skip if it can't be made deterministic — document the choice).

Tests must be hermetic (no real network) so CI stays offline.

## Acceptance Criteria

- [ ] Handshake test runs fully offline against a local rustls server; captured leaf
      matches the served cert.
- [ ] Verdict is `Invalid` for the untrusted self-signed test cert, while the chain is
      still captured.
- [ ] Validation tests cover host shape, port range, SNI rules, and the SSRF guard.
- [ ] `cargo test -p fetch`, `cargo clippy --all-targets -- -D warnings`,
      `cargo fmt --check` pass; no network access required.

## Notes / Dependencies

- Depends on task 02 (crate API stable). CLI-level `--from-host` smoke testing may reuse
  the same local server if convenient, but the core coverage lives in the `fetch` crate.
