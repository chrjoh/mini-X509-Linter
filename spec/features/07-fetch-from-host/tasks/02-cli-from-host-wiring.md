---
agent: developer
seq: 2
title: CLI --from-host wiring + chain/verdict rendering
status: pending
touches:
  - crates/cli/Cargo.toml
  - crates/cli/src/main.rs
  - crates/cli/src/output.rs
depends_on:
  - 01-fetch-crate
---

# Task: CLI --from-host wiring + chain/verdict rendering

## Goal

Wire the `fetch` crate into the CLI behind a `fetch` feature: add `--from-host`, `--sni`,
`--timeout`; enforce mutual exclusion with `<PATH>`; lint only the leaf; render the
presented chain and the verification verdict alongside lint findings.

## Files Owned (conflict scope)

- `crates/cli/Cargo.toml`
- `crates/cli/src/main.rs`
- `crates/cli/src/output.rs`

Does NOT touch root `Cargo.toml` (task 01 owns the workspace `members` edit).

## Steps

1. `crates/cli/Cargo.toml`:
   - Add `fetch = { path = "../fetch", optional = true }`.
   - Declare a `[features]` `fetch = ["dep:fetch"]` so network code is opt-in.
2. `crates/cli/src/main.rs`:
   - Add clap flags: `--from-host <host[:port]>`, `--sni <name>`, `--timeout <secs>`
     (default 10). Gate the `--from-host` path behind `#[cfg(feature = "fetch")]`; when the
     feature is off, `--from-host` should produce a clear "built without fetch support"
     error rather than silently doing nothing.
   - Enforce that `<PATH>...` and `--from-host` are **mutually exclusive** (clap group or
     explicit check) with a clear error if both/neither given.
   - On `--from-host`: validate the target, apply SNI rules (IP requires `--sni`), call
     `fetch::fetch_chain`. Build a `Cert` from the leaf DER and run the registry on the
     **leaf only**. Pass intermediates + verdict to the renderer.
   - Surface connect/handshake/timeout failures as clear generic `anyhow` errors.
3. `crates/cli/src/output.rs`:
   - Render the presented chain (leaf + intermediates as context) and the
     `VerificationVerdict` (valid / why it failed) as a distinct section, clearly separate
     from the leaf's lint findings. Support both text and JSON. Keep output deterministic.

## Acceptance Criteria

- [ ] `--from-host example.com` (with feature on) fetches, lints the leaf, prints chain +
      verdict + findings.
- [ ] `<PATH>` and `--from-host` are mutually exclusive with a clear error.
- [ ] IP host without `--sni` → clear error; hostname derives SNI by default.
- [ ] Built without the `fetch` feature, `--from-host` errors clearly; file linting still
      works.
- [ ] Verdict and lint findings are visibly distinct in both text and JSON.
- [ ] `cargo clippy --all-targets --features fetch -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01. Blocks the test task 04 (which exercises the wired CLI).
