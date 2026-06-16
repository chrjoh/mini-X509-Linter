---
agent: developer
seq: 2
title: --info flag + certificate summary renderer
status: pending
touches:
  - crates/cli/src/inspect.rs
  - crates/cli/src/main.rs
depends_on:
  - 01-cert-facade-inspection-accessors
---

# Task: --info flag + certificate summary renderer

## Goal

Add a `--info` flag and a deterministic certificate **summary block** renderer. When `--info` is set,
the CLI prints the summary for the leaf, then **still runs and prints the lint report** as today.
`--info` does not suppress linting and does not change the exit code.

## Files Owned (conflict scope)

- `crates/cli/src/inspect.rs` (NEW — the summary renderer; kept separate from `output.rs` so feature
  08 does not overlap feature 06's lint formatter)
- `crates/cli/src/main.rs` (flag + wiring)

These two files do not overlap any other feature's task touches. (Feature 06 owns `output.rs`; this
task deliberately avoids it.)

## Steps

### `crates/cli/src/inspect.rs` (NEW)

1. Add `pub fn render_summary_text(cert: &Cert) -> String` — a deterministic, stable-field-order text
   block built from the facade inspection accessors (task 01). Field order MUST be:
   version, serial (hex), subject DN, issuer DN, notBefore, notAfter, signature algorithm, public key,
   BasicConstraints, KeyUsage, SubjectAltName.
   - **Signature algorithm:** show `name` if known, else the raw OID with a `(unknown)` label.
   - **Public key:** show algorithm name/OID plus size/curve when available; degrade gracefully.
   - **KeyUsage:** list **every** asserted bit by name (e.g. `Certificate Sign, CRL Sign`) and append
     the criticality (e.g. `(not critical)`); print a clear marker when the extension is absent.
   - **SubjectAltName:** one line/segment per entry (`DNS:…`, `IP:…`, etc.) plus criticality; clear
     marker when absent.
   - No timestamps beyond the cert's own dates; no nondeterministic content.
2. Add `pub fn render_summary_json(cert: &Cert) -> Result<CertSummary>` (or a function returning the
   serializable struct) — build an owned, `Serialize`-able `CertSummary` struct mirroring the text
   fields, so `main.rs` can fold it into the JSON envelope. Define `CertSummary` here in `inspect.rs`.
3. Add `#[cfg(test)]` unit tests for the field ordering and the unknown-algorithm rendering shape (the
   PQC fixture snapshot lives in the tester's task 03).

### `crates/cli/src/main.rs`

4. Add the clap flag: `#[arg(long)] info: bool`. Long-only, NO short alias (avoids any clash with the
   auto `-h`/`-V` and feature 06's planned `-v`). Confirm against existing flags `--format`,
   `--source`, `--min-severity` — no conflict.
5. Wire the new module (`mod inspect;`).
6. In `run`: when `args.info` is set, render the summary BEFORE the lint report:
   - `--format text`: print `inspect::render_summary_text(&leaf)` first, then a blank-line separator,
     then the existing lint text report.
   - `--format json`: emit a single top-level object `{ "summary": {…}, "lints": [ … ] }` where
     `summary` is the serialized `CertSummary` and `lints` is the existing nested per-outcome JSON
     shape from feature 02 (preserved verbatim — do not change the per-outcome shape). When `--info` is
     NOT set with `--format json`, output is unchanged (the bare lint JSON as today).
7. `--info` does NOT change the exit code and does NOT suppress linting. Default behaviour (flag
   omitted) is byte-for-byte unchanged for both formats.
8. Update the module-level doc comment in `main.rs` to document `--info` alongside the other flags.

## Acceptance Criteria

- [ ] `--info` prints the summary block, then still runs and prints the lint report.
- [ ] `--info` is long-only with no short alias and no clap conflict; omitting it leaves output
      byte-for-byte unchanged (both text and JSON).
- [ ] Summary text has the exact stable field order listed above; no timestamps beyond the cert dates.
- [ ] KeyUsage lists every asserted bit plus criticality; SAN lists every entry plus criticality.
- [ ] Unknown (PQC) signature/public-key algorithms render the raw OID with a sensible label, never
      erroring or panicking.
- [ ] `--info --format json` emits `{ "summary": {…}, "lints": [ … ] }`; the `lints` shape matches
      feature 02 exactly.
- [ ] `--info` does not alter the exit code.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 01 (uses the facade inspection accessors).
- Target the real binary name `mini-x509-lint` (NOT `mini-zlint`) in any doc/help text.
