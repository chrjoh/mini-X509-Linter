---
agent: developer
seq: 3
title: CLI skeleton — load, run one lint, print
status: done
touches:
  - crates/cli/Cargo.toml
  - crates/cli/src/main.rs
depends_on:
  - 01-workspace-and-contract-types
  - 02-cert-facade-and-not-expired-lint
---

# Task: CLI skeleton — load, run one lint, print

## Goal

A thin `mini-x509-lint` binary that takes `<PATH>`, loads the cert(s) via the `Cert`
facade, runs the single `not_expired` lint against the leaf, and prints findings as text.
Proves the full pipe end-to-end (Milestone 1).

## Files Owned (conflict scope)

- `crates/cli/Cargo.toml`
- `crates/cli/src/main.rs`

## Steps

1. `crates/cli/Cargo.toml`:
   - `[package]` name `cli`, `[[bin]]` name `mini-x509-lint`.
   - deps (pinned 2026-06-15 to latest stable): `linter` (path = `../linter`),
     `clap = { version = "4", features = ["derive"] }` (4.6.1), `anyhow = "1"` (1.0.102).
2. `crates/cli/src/main.rs`:
   - clap `derive` struct with a positional `path: PathBuf`. (Richer flags arrive in
     features 02/06 — keep this minimal.)
   - Read the file, call `Cert::load`, take the **leaf** (first cert) as the lint target.
     If no certs parse, return a clear `anyhow` error.
   - Build a hard-coded list of one lint (`NotExpired`) — registry comes in feature 02.
   - Call `applies()`; if `Applies`, call `check()`; print each `Finding` as a text line
     (severity + message). If no findings, print a short "no findings" line.
   - Use `anyhow` for error handling; no `unwrap`/`expect` on IO or parse paths; generic
     error messages to the user, no stack traces.

## Acceptance Criteria

- [ ] `cargo run -p cli -- <path-to-expired.pem>` prints the not_expired Warn finding.
- [ ] `cargo run -p cli -- <path-to-good.pem>` prints a no-findings line.
- [ ] Missing/unreadable/unparseable file yields a clear non-panicking error.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Notes / Dependencies

- Depends on tasks 01 + 02 (needs the contract, `Cert`, and `NotExpired`).
