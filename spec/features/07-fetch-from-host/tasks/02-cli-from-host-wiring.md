---
agent: developer
seq: 2
title: CLI --from-host wiring + chain/verdict rendering + --save
status: done
touches:
  - crates/cli/Cargo.toml
  - crates/cli/src/main.rs
  - crates/cli/src/output.rs
  - crates/cli/src/save.rs
depends_on:
  - 01-fetch-crate
---

# Task: CLI --from-host wiring + chain/verdict rendering + --save

## Goal

Wire the `fetch` crate into the CLI behind a `fetch` feature: add `--from-host`, `--sni`,
`--timeout`; enforce mutual exclusion with `<PATH>`; lint only the leaf; render the
presented chain and the verification verdict alongside lint findings. Also add the optional
`--save <path>` / `--force` capability that writes the full presented chain to disk as a PEM
bundle.

## Files Owned (conflict scope)

- `crates/cli/Cargo.toml`
- `crates/cli/src/main.rs`
- `crates/cli/src/output.rs`
- `crates/cli/src/save.rs` (new — DER→PEM bundle writer for `--save`; alternatively fold into
  `output.rs` if cleaner, but it stays within this task's conflict scope either way)

Does NOT touch root `Cargo.toml` (task 01 owns the workspace `members` edit).

## Steps

1. `crates/cli/Cargo.toml`:
   - Add `fetch = { path = "../fetch", optional = true }`.
   - Declare a `[features]` `fetch = ["dep:fetch"]` so network code is opt-in.
2. `crates/cli/src/main.rs`:
   - Add clap flags: `--from-host <host[:port]>`, `--sni <name>`, `--timeout <secs>`
     (default 10), `--save <path>`, `--force`. Gate the `--from-host` path behind
     `#[cfg(feature = "fetch")]`; when the feature is off, `--from-host` should produce a
     clear "built without fetch support" error rather than silently doing nothing.
   - Enforce that `<PATH>...` and `--from-host` are **mutually exclusive** (clap group or
     explicit check) with a clear error if both/neither given.
   - Reject `--save` (and `--force`) when `--from-host` is absent — i.e. with a `<PATH>` file
     input or no input — with a clear message (saving a cert read from a file is pointless).
   - On `--from-host`: validate the target, apply SNI rules (IP requires `--sni`), call
     `fetch::fetch_chain`. Build a `Cert` from the leaf DER and run the registry on the
     **leaf only**. Pass intermediates + verdict to the renderer.
   - When `--save <path>` is set: write the **full presented chain** (leaf +
     intermediates, presentation order) as a PEM bundle to `<path>` after the fetch. The save
     happens **regardless of the verification verdict** and is **independent of linting** —
     linting still proceeds normally. Overwrite policy: refuse to overwrite an existing
     `<path>` unless `--force` is given; the parent directory must already exist (do not
     create it). On any write failure, surface a clear **generic** `anyhow` error and exit
     non-zero. Pipeline order: fetch → save → lint → render.
   - Surface connect/handshake/timeout failures as clear generic `anyhow` errors.
3. `crates/cli/src/save.rs` (or `output.rs`):
   - Encode the captured DER chain as a PEM bundle: base64 each DER cert, wrap in
     `-----BEGIN CERTIFICATE-----`/`-----END CERTIFICATE-----` at 64-char lines, concatenate
     in presentation order (leaf first). Reuse any existing workspace base64/PEM facility;
     otherwise hand-roll the wrap (no new crate dependency). Content is the captured DER with
     **no transformation**.
   - Write the bundle with `0o644` permissions (certs are public). Honor the refuse-overwrite
     /`--force` policy and the "parent dir must exist" rule; map IO errors to a generic error.
   - Optionally emit a deterministic `saved presented chain to <path>` confirmation on
     **stderr** (outside any stdout golden-snapshot scope) so it cannot break a future golden.
4. `crates/cli/src/output.rs`:
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
- [ ] `--save <path>` with `--from-host` writes the full presented chain (leaf +
      intermediates) as a PEM bundle that re-lints via `<PATH>`; linting still proceeds.
- [ ] `--save` (or `--force`) without `--from-host` is a clear error.
- [ ] `--save` refuses to overwrite an existing file unless `--force` is given; with `--force`
      it overwrites. Missing parent directory and other write failures → clear generic error,
      non-zero exit. Saved file uses `0o644`.
- [ ] Save happens regardless of the verification verdict (expired/self-signed chains still
      saved).
- [ ] `cargo clippy --all-targets --features fetch -- -D warnings` clean.

## Notes / Dependencies

- Depends on task 01. Blocks the test task 04 (which exercises the wired CLI).
