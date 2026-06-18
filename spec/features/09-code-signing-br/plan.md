# Feature: CA/Browser Forum Code-Signing Baseline Requirements Rule Set

## Overview

Add a curated subset of the CA/Browser Forum **Code-Signing Baseline Requirements** (CS BR) as a new
lint source, `RuleSource::CabfCs`. Code-signing certificates are a distinct PKI profile from TLS
server certificates: they assert the `codeSigning` EKU (OID `1.3.6.1.5.5.7.3.3`) and are governed by
their own validity, key-strength, and revocation-pointer rules. This feature wires in:

- a new `RuleSource::CabfCs` source (wire string `cabf_cs`, lint-id prefix `cabf_cs_*`);
- a new, EKU-gated rule set of 8 lints under `crates/linter/src/lints/cabf_cs/`;
- the previously-reserved `CertPurpose::CodeSigning` purpose, including the `auto` resolver and the
  CLI `--purpose code-signing` value;
- new openssl-generated fixtures (a clean code-signing leaf + one violating fixture per lint).

This is plan.md Milestone-adjacent work (a sibling rule set to feature 05's TLS BR set). We deliberately
port only a **high-signal subset** of zlint's `lint_cs_*` menu — the rules implementable with the
existing `Cert` facade plus two modest new accessors — rather than the full catalogue.

## Critical Design Decision: codeSigning-EKU `applies()`-Scoping (avoids a shared-fixture cascade)

Feature 05 took **broad scoping** for the TLS BR lints (every non-CA leaf is in scope), which forced a
**full regeneration of every existing leaf fixture** and rippled through the feature-03/04 isolation
tests and the `EXPIRED_NOT_AFTER` constants. That cascade was expensive and is documented at length in
`spec/features/05-cabf-br-rule-set/plan.md`.

**This feature deliberately does NOT repeat that.** Every `cabf_cs` lint's `applies()` returns
`NotApplicable` unless the certificate **asserts the `codeSigning` EKU (OID `1.3.6.1.5.5.7.3.3`)**:

```text
applies(cert) = if cert.has_code_signing()? { Applies } else { NotApplicable }
```

### Consequences (the whole point of this scoping)

- Under `default_registry().run()`, all 8 `cabf_cs` lints are `NotApplicable` on **every existing
  TLS / generic leaf fixture** (`good.pem`, `expired.pem`, all `rfc5280_*`, all `hygiene_*`, the two
  `cabf_br_*`-shape leaves) — none of those assert `codeSigning`.
- Therefore **NO existing fixture is regenerated**, the feature-03/04/05 isolation tests stay green
  untouched, and the `EXPIRED_NOT_AFTER` constants are NOT changed.
- This feature adds **only its own new fixtures**: one clean code-signing leaf plus one violating
  fixture per lint. Each new fixture asserts `codeSigning` so the `cabf_cs` lints engage on it, and is
  otherwise RFC-5280-/hygiene-clean so it isolates exactly its one CS violation.

This narrow EKU-gate is the explicit anti-pattern fix for the feature-05-style cascade.

## Curated Lint Subset (8 lints; all `cabf_cs_*`; all codeSigning-EKU-gated)

Curated from the zlint `lint_cs_*` menu. We pick the 8 implementable with our facade + two modest new
accessors (AIA presence, CRL-DP presence). Each lint carries a doc comment with the CS BR section it
enforces and a `#[cfg(test)] mod tests`.

| Lint id | What it enforces | Severity | Facade used | zlint analogue |
|---|---|---|---|---|
| `cabf_cs_eku_required` | the `codeSigning` EKU (1.3.6.1.5.5.7.3.3) is present | Error | `has_code_signing()` (gate is always true here, so this lint also checks the EKU is the *only*/expected purpose path is out of scope — see note) | `lint_cs_eku_required` |
| `cabf_cs_key_usage_required` | the `digitalSignature` KU bit is asserted | Error | `key_usage()` → new `digital_signature` bit | `lint_cs_key_usage_required` |
| `cabf_cs_rsa_key_size` | RSA keys are ≥ 3072 bits | Error | `public_key_algorithm()` + `rsa_modulus_bits()` | `lint_cs_rsa_key_size` |
| `cabf_cs_ecdsa_curve_params` | EC keys use a permitted named curve (P-256 / P-384 / P-521) with named-curve params | Error | `public_key_algorithm()` + `ec_named_curve()` | `lint_cs_ecdsa_curve_params` |
| `cabf_cs_validity_period_longer_than_39_months` | validity window ≤ 39 months (1188 days) | Error | `validity_days()` | `lint_cs_validity_period_longer_than_39_months` |
| `cabf_cs_validity_period_longer_than_460_days` | validity window ≤ 460 days | Warn | `validity_days()` | `lint_cs_validity_period_longer_than_460_days` |
| `cabf_cs_authority_information_access` | an AIA extension is present (CA Issuers / OCSP pointers expected) | Warn | new `has_authority_info_access()` | `lint_cs_authority_information_access` |
| `cabf_cs_crl_distribution_points` | a CRL Distribution Points extension is present | Warn | new `has_crl_distribution_points()` | `lint_cs_crl_distribution_points` |

### Why this subset and not the rest of the menu

- **EKU presence** (`cabf_cs_eku_required`) and **KU** (`cabf_cs_key_usage_required`) are the
  defining shape checks and are trivially backed by the existing EKU view + a one-bit KU addition.
- **Key strength** (`cabf_cs_rsa_key_size` at ≥3072, distinct from hygiene's ≥2048; and
  `cabf_cs_ecdsa_curve_params`) reuses the SPKI accessors already built for the hygiene set.
- **Two validity caps** (39 months and 460 days) reuse `validity_days()`; both are pure arithmetic on
  the existing accessor and demonstrate the Error/Warn split.
- **AIA + CRL-DP presence** are the two revocation-pointer rules; they need only a *presence*
  predicate, so they justify exactly two small new facade accessors and no DER walking of the entry
  contents.
- **Deferred (NOT ported):** `lint_cs_aia_missing_ca_issuers_http_url`, `lint_cs_aia_ocsp_not_http`,
  `lint_cs_allowed_signature_algorithm`, `lint_cs_prohibited_subject`. These require enumerating AIA
  accessLocation URI schemes, a signature-algorithm allowlist beyond hygiene's SHA-1 check, or subject
  DN field-by-field policy — each a larger accessor surface than this first CS slice warrants. They are
  candidates for a follow-up CS feature. The two AIA/CRL *presence* lints we keep are the gateway that
  later URI-scheme lints would build on.

> Note on `cabf_cs_eku_required`: because every `cabf_cs` lint's `applies()` is already gated on the
> codeSigning EKU being present, the lint can never *fail* on a cert that reaches its `check()` via the
> normal registry path — by construction such a cert has codeSigning. This lint is retained because
> (a) under `--purpose code-signing` the CS set is the *declared intent*, and a forced run still wants
> the explicit assertion documented, and (b) it keeps the rule set self-describing and mirrors zlint.
> Its `check()` re-reads `has_code_signing()` and emits an Error if absent (a defensive, fail-closed
> path that also covers a future caller running the lint outside the gate). Document this reasoning in
> the lint file. The dedicated violating fixture for this lint is therefore the *only* new fixture that
> must reach the lint without codeSigning — which it cannot do through the gate; see the Fixtures
> section for how its test invokes the lint directly rather than through the registry.

## Architecture

- One small file per lint under `crates/linter/src/lints/cabf_cs/`, plus `cabf_cs/mod.rs` declaring
  the modules and re-exporting the lint types. Mirror the layout of `crates/linter/src/lints/cabf_br/`.
- New source variant `RuleSource::CabfCs` in `crates/linter/src/source.rs` (serde `snake_case` →
  `cabf_cs`), placed after `CabfBr`.
- New facade accessors in `crates/linter/src/cert.rs`:
  - `has_code_signing()` — `true` iff the EKU view contains OID `1.3.6.1.5.5.7.3.3`. (The existing
    `EkuView.oids` already carries every purpose OID, so this is a small predicate; optionally add a
    `code_signing: bool` field to `EkuView` mirroring `server_auth`/`client_auth` for symmetry.)
  - extend `KeyUsageView` with a `digital_signature: bool` bit (currently only `key_cert_sign` is
    exposed) for `cabf_cs_key_usage_required`.
  - `has_authority_info_access()` — presence predicate for the AIA extension.
  - `has_crl_distribution_points()` — presence predicate for the CRL-DP extension.
  - Reuse existing `rsa_modulus_bits()`, `ec_named_curve()`, `public_key_algorithm()`,
    `validity_days()` as-is.
- New purpose `CertPurpose::CodeSigning` in `crates/linter/src/registry.rs`:
  - mapping: `CodeSigning -> [Rfc5280, Hygiene, CabfCs]` (a dedicated `code_signing_sources()` helper
    mirroring `tls_server_sources()` / `generic_sources()`, with a fixed, deterministic order).
  - `auto` resolver precedence (document explicitly): the leaf's EKU is consulted once.
    1. if the leaf asserts the `codeSigning` EKU → `CodeSigning`;
    2. else if the leaf asserts the `serverAuth` EKU → `TlsServer`;
    3. else → `Generic`;
    4. on a parse error reading the EKU → **fail closed** to `Generic` (never manufacture a CS or BR
       false positive), matching feature 05's `auto_sources_from` error policy.
    The existing serverAuth→tls-server and else→generic rules are unchanged; codeSigning is checked
    *first* so a cert that (unusually) asserts both EKUs is treated as code-signing.
- CLI wiring in `crates/cli/src/main.rs`:
  - add `cabf_cs` to the `--source` token parser and `ALL_SOURCES`;
  - add `CliPurpose::CodeSigning` (clap value `code-signing`) and its `From<CliPurpose>` arm; update
    the `--purpose` and `--source` doc strings and the error message in `parse_source_token`;
  - add a `purpose_label` arm for `CertPurpose::CodeSigning` → `"code-signing"`.
- CLI output in `crates/cli/src/output.rs`:
  - add `RuleSource::CabfCs` to `SOURCE_ORDER` (after `CabfBr`, before/relative to `Hygiene` — keep a
    fixed deterministic order; the feature-06 golden test pins ordering, see Ripple Flag);
  - add a `source_label` arm → `"cabf_cs"`.
- Register the 8 lints in `default_registry()` after the `cabf_br` block, in a deterministic order.

## ⚠️ SHARED-FILE / SEQUENCING WARNING (sibling features 10 & 11)

This feature edits files that sibling rule-set features **10** and **11** (being drafted in parallel)
also edit:

- `crates/linter/src/source.rs` (each adds a `RuleSource` variant)
- `crates/linter/src/registry.rs` (each adds a `CertPurpose` variant + registers lints)
- `crates/cli/src/main.rs` (each extends `--source` / `--purpose` / `ALL_SOURCES`)
- `crates/cli/src/output.rs` (each extends `SOURCE_ORDER` + `source_label`)

**These features MUST be implemented SEQUENTIALLY, not run in parallel.** Two features editing the
same `enum RuleSource` / `enum CertPurpose` / `SOURCE_ORDER` / `parse_source_token` concurrently will
conflict on every one of these four files. The orchestrator scheduling features 09/10/11 must serialize
them (09 fully merged before 10 starts the shared-file edits, etc.). Within feature 09, the task
`depends_on` graph already serializes its own touches of these files.

## Changes Overview

**crates/linter/ (production code — developer tasks 01–03)**
- `src/cert.rs` — new accessors: `has_code_signing()`, `has_authority_info_access()`,
  `has_crl_distribution_points()`; extend `KeyUsageView` with `digital_signature`; optionally extend
  `EkuView` with `code_signing`. (task 01)
- `src/source.rs` — add `RuleSource::CabfCs` (serde `cabf_cs`). (task 02)
- `src/lints/mod.rs` — `pub mod cabf_cs;`. (task 02)
- `src/lints/cabf_cs/mod.rs` + the 8 lint files. (task 02)
- `src/registry.rs` — register the 8 lints; add `CertPurpose::CodeSigning` +
  `code_signing_sources()`; extend `allowed_sources`/`resolve`/`auto` precedence; update in-file unit
  tests (lint count 14 → 22; add a `cabf_cs` source-filter test; add a CodeSigning purpose test).
  (task 03)

**crates/cli/ (production code — developer task 03)**
- `src/main.rs` — `--source cabf_cs` token + `ALL_SOURCES`; `CliPurpose::CodeSigning`
  (`code-signing`) + `From` arm; `purpose_label` arm; doc/error-string updates. (task 03)
- `src/output.rs` — `SOURCE_ORDER` + `source_label` for `CabfCs`. (task 03)

**testdata/ + tests (tester — task 04)**
- `testdata/generate.sh` — add a code-signing leaf-extension config (codeSigning EKU +
  digitalSignature KU + appropriate key size + currently-valid window) and the new fixtures.
- New fixtures (openssl-generated only — NEVER cert-bar): see Fixtures section.
- New integration tests `crates/linter/tests/cabf_cs.rs`.
- Possibly a CLI `--purpose code-signing` / `--source cabf_cs` e2e test in `crates/cli/tests/output.rs`
  (see test-plan).

## Fixtures (openssl-generated ONLY — never cert-bar)

A **clean code-signing leaf** = `codeSigning` EKU + `digitalSignature` KU + RSA-3072 (or P-256) +
`SHA-256` + `CA:FALSE` + a **currently-valid** window that is **≤ 460 days** (so both validity lints
pass). One **violating fixture per lint**, each breaking exactly one CS rule while remaining otherwise
clean and asserting `codeSigning` (so the gate engages).

| Fixture | shape | single intended violation |
|---|---|---|
| `cabf_cs_good.pem` | codeSigning + digitalSignature + RSA-3072/SHA-256 + ≤460d currently-valid + CA:FALSE | NONE (clean; passes the whole 22-lint registry) |
| `cabf_cs_missing_key_usage.pem` | codeSigning EKU, NO digitalSignature KU (e.g. KU with only `keyEncipherment`, or no KU) | `cabf_cs_key_usage_required` |
| `cabf_cs_rsa_2048.pem` | codeSigning, RSA-2048 (≥ hygiene's 2048 so hygiene passes; < CS's 3072) | `cabf_cs_rsa_key_size` |
| `cabf_cs_ecdsa_bad_curve.pem` | codeSigning, EC on a non-allowlisted-but-hygiene-permitted curve, OR P-256 with explicit (non-named) params | `cabf_cs_ecdsa_curve_params` |
| `cabf_cs_validity_40_months.pem` | codeSigning, ~40-month window (> 39 months / 1188d), currently valid | `cabf_cs_validity_period_longer_than_39_months` (also trips the 460-day Warn — see note) |
| `cabf_cs_validity_500_days.pem` | codeSigning, 500-day window (> 460d, ≤ 39 months), currently valid | `cabf_cs_validity_period_longer_than_460_days` only |
| `cabf_cs_no_aia.pem` | codeSigning, clean, but NO AIA extension | `cabf_cs_authority_information_access` |
| `cabf_cs_no_crl.pem` | codeSigning, clean, but NO CRL-DP extension | `cabf_cs_crl_distribution_points` |

Notes / caveats:

- **`cabf_cs_eku_required` has no dedicated through-the-registry violating fixture.** A cert without
  codeSigning is `NotApplicable` (gated out), so it can never reach this lint's `check()` via
  `registry.run()`. Its test invokes the lint *directly* (`lint.check(&cert)`) on a non-codeSigning
  leaf (reuse `good.pem` from feature 05, which has serverAuth/no codeSigning) to exercise the
  fail-closed Error path. Document this in the test. No new fixture needed for it.
- **`cabf_cs_good.pem` window:** must be currently valid AND ≤ 460 days. Use the same "straddle now"
  discipline as feature 05's `BR_OK` window. As of drafting (2026-06), e.g.
  `notBefore = 2026-06-01`, `notAfter = 2027-06-01` (365d) satisfies both validity caps and is
  currently valid. **TIME-FRAGILITY:** like feature 05, this window expires (here ~2027-06-01); after
  that, `hygiene_not_expired` fires on the CS fixtures. Document loudly in `generate.sh`; regenerate
  annually. The two validity-violating fixtures (`..._40_months`, `..._500_days`) must also straddle
  "now" so only their target validity cap fires and not `hygiene_not_expired`.
- **`cabf_cs_validity_40_months.pem`:** 40 months > both 39 months and 460 days, so it would trip
  BOTH validity lints. To keep "exactly one CS violation" the test for `..._40_months` asserts the
  39-month lint fires; the 460-day Warn co-firing is expected and documented (a >39-month cert is
  necessarily >460 days). Use `..._500_days` for the 460-day-only isolation. State this in the test.
- **`cabf_cs_ecdsa_bad_curve.pem`:** the cleanest isolation is a P-256 key encoded with *explicit*
  curve parameters (so `ec_named_curve()` returns `None`), or a curve permitted by hygiene's
  allowlist but not by CS. Choose whichever openssl can produce deterministically; document the choice.
- All CS fixtures must pass the rfc5280 + hygiene lints (v3, positive serial, valid validity ordering,
  RSA ≥2048 / permitted hygiene curve, SHA-256, currently valid) so each isolates exactly its one CS
  rule across the full registry — EXCEPT the deliberate single-rule deviation.

## Dependencies

- None new. AIA / CRL-DP presence and codeSigning EKU detection are all available through
  `x509-parser`'s extension API already used by `cert.rs`; prefer reading via the existing
  `with_parsed` helper. Document any crate if one proves genuinely necessary.

## Sequencing (batches)

- **Batch A:** task 01 (cert.rs accessors). [`crates/linter/src/cert.rs`]
- **Batch B:** task 02 (source.rs + lint files + lints/mod.rs). depends_on 01.
- **Batch C:** task 03 (registry.rs register + CertPurpose::CodeSigning + CLI main.rs/output.rs
  wiring). depends_on 02.
- **Batch D:** task 04 (fixtures + cabf_cs.rs tests + optional CLI e2e). depends_on 03.

Within feature 09 these are strictly serial because tasks 02 and 03 both touch shared registry/CLI
files in dependency order. No two tasks in this feature share a `touches` file within the same batch.

## Ripple Flag: Feature 06 golden test

Feature 06's golden-file test (plan.md Milestone 6) snapshots the output of running all lints over
`testdata/`. Adding 8 lints + a new `cabf_cs` source group + new `testdata/` fixtures changes:
- the lint count (14 → 22) and the per-source grouping in any golden snapshot;
- `SOURCE_ORDER` now includes `cabf_cs`, so grouped text/JSON output gains a `[cabf_cs]` section.

**Action (flag only — do NOT edit feature 06 here):** when feature 06's golden test exists/regenerates,
it must include the new `cabf_cs` group and the new CS fixtures. If feature 06 is already implemented
when this feature lands, its golden snapshot must be regenerated as part of task 04 (add the snapshot
file to task 04's `touches` and note it). Verify whether `crates/*/tests/` contains a golden snapshot
before implementing; if present, fold its regeneration into task 04.

## Ripple Flag: Feature 08 cert-inspection

Feature 08's inspection summary may enumerate EKU purposes; the new `EkuView.code_signing` field (if
added) and the CS fixtures are additive and should not break feature 08, but if feature 08 snapshots an
EKU summary, confirm the new field does not alter existing snapshots. Flag only.
