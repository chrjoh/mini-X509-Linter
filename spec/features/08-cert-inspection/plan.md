# Feature: Certificate Inspection (`--info`)

## Overview

Add a certificate **inspection** mode: a `--info` flag that prints a deterministic SUMMARY block
of the certificate's own fields (version, serial, subject/issuer DN, validity, signature algorithm,
public key, BasicConstraints, KeyUsage bits, SAN entries) alongside the existing lint report.

**This is a NEW feature beyond the original `spec/plan.md` — a post-milestone inspection/UX
enhancement, not a change to the lint engine.** It does not add, remove, or alter any `Lint`, the
`Registry`, or the `Lint`/`Finding`/`LintOutcome` contract. It only (a) extends the read-only `Cert`
facade with display-oriented accessors and (b) adds a CLI rendering path. The engine still lints the
leaf exactly as before; `--info` is purely additive display.

### Motivation

Today the CLI only prints lint findings derived from `LintOutcome`; there is no way to display the
certificate's *own* values. Users want to **see** certificate fields — especially the full KeyUsage
bit set — not just a pass/fail verdict.

The concrete driving example is a self-signed **SLH-DSA (SPHINCS+) post-quantum root CA**. `openssl`
shows it as: `KeyUsage = Certificate Sign, CRL Sign` (NOT critical); `BasicConstraints` critical
`CA:TRUE`; `SAN DNS:SLH-DSA-SHA2-128S Root CA`; `subject = issuer = CN=SLH-DSA-SHA2-128S Root CA, C=SE,
O=NIST PQC SPHINCSplus`. The linter parses it fine structurally (reports OK) but cannot display any of
these values. The signature/public-key algorithm OID is **unknown to `oid-registry`** (SLH-DSA is too
new), so the summary must degrade gracefully and show the raw OID rather than failing.

## Requirements

- **`--info` flag.** A new long-only clap flag (no short alias). When set, the CLI prints a
  certificate **summary block** for the leaf, then **still runs and prints the lint report** below it.
  `--info` does not suppress linting and does not change the exit code (which remains driven by
  `--fail-on` / surfaced findings). Default behaviour (flag omitted) is byte-for-byte unchanged.
- **No clap conflict.** `--info` is long-only and does not collide with existing flags
  (`--format`, `--source`, `--min-severity` from feature 02) or planned feature 06 flags
  (`--fail-on`, `--chain`, `--verbose`/`-v`). It claims no short flag, so it cannot clash with the
  auto `-h`/`-V` or feature 06's `-v`.
- **Summary fields (stable order):**
  1. Version (e.g. `v3`).
  2. Serial — hex string (uppercase, colon-separated or plain; pick one and keep it stable).
  3. Subject DN — RFC 4514 string.
  4. Issuer DN — RFC 4514 string.
  5. Validity — `notBefore` / `notAfter` (the cert's own dates; no wall-clock timestamps).
  6. Signature algorithm — human-readable name via `oid-registry` if known, else the raw OID string
     with a sensible `(unknown)` label.
  7. Public key — algorithm/parameters if reasonably available (algorithm name or OID, plus size/curve
     when the parser exposes it); degrade gracefully when unknown.
  8. BasicConstraints — `CA` boolean, `pathLenConstraint` (if present), and `critical` bit.
  9. KeyUsage — **every** asserted bit by name, plus whether the extension is `critical`.
  10. SubjectAltName — each entry (type + value), plus the `critical` bit.
- **PQC-friendliness (explicit requirement).** The signature and public-key algorithms may be UNKNOWN
  to `oid-registry` (e.g. SLH-DSA). The summary MUST degrade gracefully — display the raw dotted OID
  string and a sensible label — and MUST NOT error, panic, or omit the field. This is exercised by a
  dedicated test against the committed SLH-DSA fixture.
- **Determinism.** Output has a fixed field order and contains no timestamps beyond the cert's own
  dates, so it is snapshot-testable with `insta`.
- **JSON (`--info --format json`).** When `--info` is combined with `--format json`, emit a structured
  cert-summary object **in addition to** the existing lint JSON, under a clearly named key (e.g. a
  top-level object `{ "summary": { … }, "lints": [ … ] }`, or a separate `summary` field — define the
  exact shape in the formatter task). The summary is a separate serializable struct. See *Open
  Decisions* for scope.

## Architecture

- **Library (`crates/linter`).** Extend the `Cert` facade in `crates/linter/src/cert.rs` with
  display-oriented, **owned-return** accessors. The facade re-parses on each call inside `with_parsed`,
  whose closure may NOT leak borrows from the parsed cert — so every new accessor returns owned data
  (`String`, `Vec<…>`, small owned `#[derive(Clone)]` view structs), never a reference into the parsed
  certificate. Name lookups reuse `oid-registry` (already a dependency). The new view structs gain
  `#[cfg_attr(feature = "serde", derive(Serialize))]` so the CLI can serialize them for JSON, matching
  how the existing contract types are feature-gated.
- **CLI (`crates/cli`).** A `--info` flag in `crates/cli/src/main.rs` and a dedicated summary renderer
  in a NEW file `crates/cli/src/inspect.rs`. Keeping the renderer in its own module avoids any
  `touches` overlap with feature 06's `crates/cli/src/output.rs` (the lint formatter), so features 06
  and 08 can be developed/merged independently. `main.rs` calls `inspect::render_summary_text` (or
  `…_json`) before the existing lint render path.
- **No engine change.** `Registry`, the `Lint` trait, and `default_registry()` are untouched.

## Changes Overview

**crates/linter/** *(owned by developer task 01)*
- `src/cert.rs` — add inspection accessors and their owned view structs (see task 01 for exact names
  and return types). Feature-gate `Serialize` on the new structs behind the existing `serde` feature.

**crates/cli/** *(owned by developer task 02)*
- `src/inspect.rs` — NEW. Renders the certificate summary block as text and as a JSON object from the
  `Cert` facade accessors. Deterministic, stable field order.
- `src/main.rs` — add the `--info` flag; when set, render the summary (text or JSON per `--format`)
  before the lint report; wire the new module. Update the module-level doc comment.

**testdata/** *(owned by tester task 03)*
- `slh_dsa_root_ca.pem` — NEW committed PQC fixture (a self-signed SLH-DSA root CA). See *Open
  Decisions* for provenance; the fixture MUST be committed in-repo (the motivating
  `../cert-bar/certs/slh-dsa-sha2-128s_cert.pem` is OUTSIDE the repo and cannot be relied on).
- A regeneration note appended to `testdata/generate.sh` only if the fixture is reproducibly
  generatable; otherwise the committed PEM is treated as a vendored fixture with provenance documented
  in the test (see task 03).

**Tests** *(owned by tester task 03)*
- `crates/cli/tests/inspect.rs` — NEW. Snapshot + behavioural tests for the summary (text and JSON),
  KeyUsage-bit display, graceful unknown-algorithm handling, and determinism.

## Dependencies

- **None new.** `oid-registry` 0.8 is already a `linter` dependency (used for algorithm-name lookup);
  `serde`/`serde_json` are already wired (linter `serde` feature, CLI `serde_json`). `insta` for
  snapshots is introduced by the tester's test task, consistent with feature 06.

## Open Decisions (made by the architect)

1. **Flag interaction.** `--info` prints the summary block **and then** the lint report; it does not
   replace linting and does not affect the exit code. Rationale: inspection is additive; suppressing
   lints would surprise CI users and complicate exit-code semantics. (If a future "summary-only" mode
   is wanted, add it as a separate flag later.)
2. **JSON scope.** JSON of the summary is **in scope** (not deferred). Combining `--info --format json`
   emits a single top-level object `{ "summary": {…}, "lints": [ … ] }`. This is achievable without
   complicating the facade because the new view structs are plain owned data with feature-gated
   `Serialize`. The exact JSON envelope is finalized in task 02; the nested per-outcome lint shape from
   feature 02 is preserved verbatim under the `lints` key.
3. **PQC fixture provenance.** `../cert-bar/` is OUTSIDE this repo and cannot be a committed fixture.
   The tester (task 03) MUST commit an in-repo `testdata/slh_dsa_root_ca.pem`. Preferred source: copy
   the motivating `slh-dsa-sha2-128s_cert.pem` content into `testdata/` as a vendored fixture and
   document its provenance in a header comment in the test file (the cert is a self-signed PQC root, so
   it carries no private data of concern). If a reproducible generator (e.g. an `openssl`/oqs-provider
   recipe) is available in the environment, prefer adding it to `generate.sh`; otherwise treat the PEM
   as vendored. The fixture only needs to PARSE structurally — its algorithm OIDs being unknown to
   `oid-registry` is the whole point.
4. **Binary-name note.** `spec/plan.md` calls the binary `mini-zlint`, but the actual `[[bin]]` name
   in `crates/cli/Cargo.toml` is **`mini-x509-lint`**. Tests and docs in this feature MUST target the
   real binary name `mini-x509-lint`.
