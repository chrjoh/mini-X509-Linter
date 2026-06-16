# Feature: Fetch Certificate From Host (`--from-host`)

## Overview

Add a new input source: fetch a certificate directly from a live host over a TLS handshake, instead
of reading a file. Only the leaf is linted; the intermediates the server presents are displayed and
the chain is verified, with the verdict shown alongside. This is plan.md Milestone 7. Fetching lives
in its own standalone crate so the `linter` crate stays network-free.

## Requirements

- New standalone crate `crates/fetch/` that performs a **blocking** TLS handshake (no async runtime —
  we must have the cert in hand before linting proceeds) and returns the presented chain plus a
  separate verification verdict. It does **not** depend on `linter`.
- CLI flags (per plan.md CLI surface):
  - `--from-host <host[:port]>` — fetch via TLS instead of reading a file (default port 443).
  - `--sni <name>` — override/supply the SNI.
  - `--timeout <secs>` — connection/handshake timeout (default 10).
  - `<PATH>...` and `--from-host` are **mutually exclusive** input sources.
- Chain extraction **as presented**: capture the leaf + intermediates even if the cert is
  expired/self-signed/untrusted, using a custom verifier that records the certs and lets the
  handshake proceed. Document it with a `// SECURITY:` comment; keep it inside the `fetch` crate and
  never reuse it for anything but extraction. Gate the whole capability behind a `fetch` cargo feature.
- Chain **verification** still performed and **reported**: validate the presented chain against a
  root store (e.g. `webpki-roots`, or the OS trust store) and display the verdict (`valid` / why it
  failed) alongside the displayed chain. Leaf lint findings and the chain verdict are two distinct
  things in the output.
- **Only the leaf is linted** — the leaf flows into the same engine; intermediates are displayed as
  chain context, not linted.
- **SNI handling:**
  - Host is a hostname → derive SNI from it by default; `--sni` overrides.
  - Host is an IP address → SNI cannot be deduced; `--sni` is **required**, error clearly if missing.
- Host validation before connecting: enforce `host[:port]` shape, restrict to a sane port range, and
  (optionally, behind a flag) refuse private/loopback/link-local targets to limit SSRF-style misuse.
  Surface a clear generic error on connect/handshake/timeout failure.
- This is the seam where future TLS-version / cipher-suite reporting plugs in (post-v1; out of scope
  here).

## Architecture

- `crates/fetch/` exposes something like `fetch_chain(target, sni, timeout) -> FetchedChain` where
  `FetchedChain` holds the DER-encoded leaf, the intermediates, and a `VerificationVerdict`.
- Blocking `rustls` over `std::net::TcpStream`; the custom accept-any verifier captures certs.
  Verification is a separate pass (real `WebPkiServerVerifier` + root store) so a bad cert still
  yields the chain plus a "why it failed" verdict.
- The CLI wires `fetch` → `linter`: take the leaf DER from `fetch`, build a `Cert`, run the registry;
  render the chain + verdict via the formatter from features 02/06.
- All `rustls`/network deps belong to `crates/fetch` and the CLI's `fetch` feature — never `linter`.

## Changes Overview

**crates/fetch/** (new)
- `Cargo.toml` — `rustls`, `rustls-pki-types`, `webpki-roots`.
- `src/lib.rs` — blocking handshake, accept-any capture verifier (`// SECURITY:`), separate
  verification pass, host parsing/validation, SNI derivation rules, timeout handling, error type.

**crates/cli/**
- `Cargo.toml` — add `fetch` (path) under a `fetch` feature; declare the feature.
- `src/main.rs` — `--from-host`, `--sni`, `--timeout`; enforce mutual exclusion with `<PATH>`;
  lint only the leaf.
- `src/output.rs` — render the presented chain and the verification verdict alongside lint findings.

**workspace root**
- `Cargo.toml` — add the `fetch` crate to workspace members.
- `README.md` — document `--from-host`, SNI rules, the `fetch` feature flag, and the verification
  verdict in output.

## Dependencies

(In the `fetch` crate, behind the `fetch` feature.)

- `rustls = "0.23"`
- `rustls-pki-types = "1"`
- `webpki-roots = "1"` (or an OS-trust verifier alternative)
