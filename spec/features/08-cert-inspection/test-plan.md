# Test Plan: Certificate Inspection (`--info`)

## Scope

Verify the `--info` certificate summary: deterministic text block (stable field order, no timestamps),
full KeyUsage-bit display, SAN entry display, BasicConstraints, subject/issuer DNs, the structured
JSON envelope (`{ "summary": …, "lints": … }`), graceful handling of algorithms unknown to
`oid-registry` (PQC / SLH-DSA), and that `--info` is purely additive (does not suppress linting or
change the exit code).

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()`, behaviour-focused tests
in nested modules. Snapshot testing via `insta`. CLI behaviour driven against the built binary
(`mini-x509-lint` — the real `[[bin]]` name; `spec/plan.md`'s `mini-zlint` is outdated).

## Fixtures (`testdata/`)

- `slh_dsa_root_ca.pem` — NEW vendored self-signed SLH-DSA (SPHINCS+) post-quantum root CA. Provenance
  documented in the test header (copied from the external `cert-bar` motivating cert; OIDs intentionally
  unknown to `oid-registry`). Expected: KeyUsage `Certificate Sign, CRL Sign` (not critical);
  BasicConstraints critical `CA:TRUE`; `SAN DNS:SLH-DSA-SHA2-128S Root CA`;
  `subject = issuer = CN=SLH-DSA-SHA2-128S Root CA, C=SE, O=NIST PQC SPHINCSplus`.
- Reuse `good.pem` (clean leaf from feature 03) for the baseline summary snapshot.

## Unit Tests (`crates/linter/src/cert.rs`, `#[cfg(test)]`)

Owned by developer task 01, alongside the new accessors:
- New inspection accessors against `good.pem`: `subject_rfc4514`, `issuer_rfc4514`, `serial_hex`,
  `signature_algorithm`, `public_key_info`, `key_usage_bits`, `san_entries` — return owned data,
  no panics, sensible values.

## Integration / Snapshot Tests (`crates/cli/tests/inspect.rs`)

- **Text summary snapshot** for `good.pem` and the PQC CA — `insta::assert_snapshot!`, stable order.
- **Lint report still present** after the summary when `--info` is set (additive, not a replacement).
- **KeyUsage bits:** PQC CA lists exactly `Certificate Sign` + `CRL Sign`, marked not critical;
  a multi-bit case exercises the full bit mapping.
- **SAN entries:** `DNS:SLH-DSA-SHA2-128S Root CA` plus criticality rendered.
- **BasicConstraints:** `CA:TRUE` + critical rendered for the PQC CA.
- **Subject/Issuer DN:** expected RFC 4514 strings.
- **Unknown-algorithm degradation:** PQC signature/public-key algorithm shows the raw dotted OID with a
  sensible `(unknown)` label — no crash, no empty field.
- **JSON envelope:** `--info --format json` over `good.pem` parses to a single object with a `summary`
  object and a `lints` array; the `lints` array matches the feature-02 per-outcome shape verbatim;
  snapshot the `summary` object.
- **Determinism:** two consecutive text-summary runs are byte-identical.
- **Default unchanged:** without `--info`, text and JSON output are byte-for-byte unchanged versus a
  baseline (both formats), guarding the additive contract.
- **Exit code unaffected:** `--info` does not change the `--fail-on`/exit-code outcome for the same
  input.

## Edge Cases

- Cert with NO KeyUsage / NO SAN extension → summary prints a clear "absent" marker, no panic.
- Cert with an empty subject DN → `subject_rfc4514` renders an empty/`""` DN deterministically.
- Algorithm known to `oid-registry` (e.g. `good.pem`'s) → name shown; PQC unknown → raw OID shown.

## Verification Commands

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo insta test   # if using cargo-insta locally; cargo test also runs snapshots
```

## Exit Criteria

Summary snapshots (text + JSON) stable and deterministic; KeyUsage/SAN/BasicConstraints/DN display
correct on both `good.pem` and the PQC CA; unknown-algorithm degradation verified against the committed
SLH-DSA fixture; `--info` confirmed additive (lints still run, exit code unchanged, default output
unchanged); all verification commands pass.
