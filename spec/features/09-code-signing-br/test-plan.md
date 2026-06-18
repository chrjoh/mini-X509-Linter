# Test Plan: CA/Browser Forum Code-Signing BR Rule Set

## Scope

Verify the 8 codeSigning-EKU-gated `cabf_cs` lints, the new facade accessors (`has_code_signing`,
`KeyUsageView.digital_signature`, `has_authority_info_access`, `has_crl_distribution_points`), the new
`RuleSource::CabfCs` source, the `CertPurpose::CodeSigning` purpose + `auto` precedence, and the CLI
`--source cabf_cs` / `--purpose code-signing` wiring.

**Gate (load-bearing):** every `cabf_cs` lint is `NotApplicable` unless the cert asserts the
`codeSigning` EKU (OID 1.3.6.1.5.5.7.3.3). Consequently NO existing fixture is regenerated and the
feature-03/04/05 isolation suites stay untouched. Confirming this no-cascade property is itself a test
objective.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()`, behaviour-focused tests
grouped per lint.

## ⚠️ Time-Fragility

`cabf_cs_good.pem` uses a currently-valid ≤460-day window (`2026-06-01 → 2027-06-01`, 365d). It expires
~2027-06-01, after which `hygiene_not_expired` fires on the CS fixtures and isolation breaks.
Regenerate annually (slide forward). `generate.sh` documents this; `cabf_cs.rs` module doc references
it so a flood of `not_expired` failures is diagnosable. The two validity-violating fixtures must also
straddle "now".

## Fixtures (`testdata/`) — all openssl-generated, NEVER cert-bar; all assert codeSigning EKU

| Fixture | shape | isolates |
|---|---|---|
| `cabf_cs_good.pem` | codeSigning + digitalSignature + RSA-3072/SHA-256 + ≤460d valid + CA:FALSE + AIA + CRL-DP | nothing (clean, passes 22-lint registry) |
| `cabf_cs_missing_key_usage.pem` | codeSigning, no digitalSignature KU | `cabf_cs_key_usage_required` (Error) |
| `cabf_cs_rsa_2048.pem` | codeSigning, RSA-2048 | `cabf_cs_rsa_key_size` (Error) |
| `cabf_cs_ecdsa_bad_curve.pem` | codeSigning, EC explicit/disallowed curve | `cabf_cs_ecdsa_curve_params` (Error) |
| `cabf_cs_validity_40_months.pem` | codeSigning, ~40-month window | `cabf_cs_validity_period_longer_than_39_months` (Error) + 460-day Warn co-fires |
| `cabf_cs_validity_500_days.pem` | codeSigning, 500-day window | `cabf_cs_validity_period_longer_than_460_days` (Warn) only |
| `cabf_cs_no_aia.pem` | codeSigning, no AIA | `cabf_cs_authority_information_access` (Warn) |
| `cabf_cs_no_crl.pem` | codeSigning, no CRL-DP | `cabf_cs_crl_distribution_points` (Warn) |

No dedicated fixture for `cabf_cs_eku_required` (its violating cert would be gated out); tested by
direct lint invocation on a non-codeSigning leaf.

## Unit Tests (`cert.rs`, developer task 01)

- `has_code_signing()` is `false` on `good.pem` (serverAuth, no codeSigning); `true` on a codeSigning
  leaf (covered by integration tests against `cabf_cs_good.pem`).
- `KeyUsageView.digital_signature` reads the bit correctly (negative case on a fixture without it).
- `has_authority_info_access()` / `has_crl_distribution_points()` presence true/false.

## Unit Tests (`registry.rs`, developer task 03)

- `contains_the_known_lints`: 22 lints / 22 outcomes; the 8 `cabf_cs_*` ids present.
- `cabf_cs_source_filter_runs_exactly_the_cabf_cs_set`: 8 outcomes, all `RuleSource::CabfCs`, the 8
  ids, none rfc5280_/hygiene_/cabf_br_.
- CodeSigning purpose → `[Rfc5280, Hygiene, CabfCs]`.
- `auto` precedence (pure-helper tests, no fixture): codeSigning present → CodeSigning (even if
  serverAuth also present); serverAuth only → TlsServer; neither → Generic; EKU-read `Err` → Generic
  (fail closed).
- Existing rfc5280 (16) / hygiene (4) / cabf_br (12) filter counts UNCHANGED (baseline after feature 12).

## Integration Tests (`crates/linter/tests/cabf_cs.rs`)

- Per lint: its fixture flagged with a descriptive message (bit size / curve / duration); severity
  matches the table; `cabf_cs_good.pem` passes.
- `cabf_cs_validity_40_months`: 39-month Error fires; 460-day Warn co-fires (documented); use
  `..._500_days` for the 460-day-only isolation.
- `cabf_cs_eku_required`: invoked directly on a non-codeSigning leaf (`good.pem`) → Error (fail-closed
  path); `applies()` NotApplicable on the same cert.
- Scoping: all 8 NotApplicable on `good.pem`; all 8 Applies on `cabf_cs_good.pem`.
- No-cascade: `default_registry().run()` on `good.pem` yields 8 `cabf_cs` outcomes all NotApplicable
  with empty findings.

## CLI E2E (`crates/cli/tests/output.rs`, ADD only)

- `--purpose code-signing` (or `--source cabf_cs`) on `cabf_cs_good.pem` → `[cabf_cs]` group with the 8
  CS lints, all applicable/passed; verbose `purpose:` header renders `code-signing`.
- Existing CLI assertions and constants UNCHANGED.

## Cross-Feature Regression (must still pass UNCHANGED — proves no cascade)

- `crates/linter/tests/rfc5280.rs`, `hygiene.rs`, `registry.rs`, `not_expired.rs`,
  `cabf_br.rs` — all existing isolation/invariant tests pass with NO edits (the CS lints are
  NotApplicable on every existing fixture). `EXPIRED_NOT_AFTER` constants are NOT changed.
- `cli/tests/output.rs` existing tests pass unchanged.

## Edge Cases

- A cert asserting BOTH codeSigning and serverAuth: `auto` resolves to CodeSigning (precedence).
- RSA exactly 3072 passes; 3071/2048 fail. EC P-256/384/521 (named params) pass; explicit params fail.
- Validity exactly 1188 days passes the 39-month lint; 1189 fails. Exactly 460 days passes the 460-day
  lint; 461 fails (Warn).
- `--purpose code-signing` forces the CS set even if the leaf lacks codeSigning — but the gated lints
  then report NotApplicable (forcing the source does not bypass the per-lint EKU gate; document this
  interaction).

## Verification Commands

```
cargo test
cargo test -p linter --features serde
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features serde -- -D warnings
cargo fmt --check
bash testdata/generate.sh
```

## Exit Criteria

All 8 `cabf_cs` lints + accessors + source + CodeSigning purpose + CLI wiring validated; codeSigning-gate
scoping confirmed; the clean CS fixture passes the 22-lint registry; each violating fixture isolates its
one CS rule (with the documented 40-month/460-day co-fire); the no-cascade property is proven (existing
suites pass unedited); registry/CLI unit + e2e tests pass; all verification commands green.
