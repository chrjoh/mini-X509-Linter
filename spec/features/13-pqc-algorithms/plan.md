# Feature: Post-Quantum Signature-Algorithm Hygiene & Structural Rule Set

## Overview

Add a curated **post-quantum cryptography (PQC) signature-algorithm hygiene** rule set as a new lint
source, `RuleSource::Pqc`. The rule set covers the two NIST-standardized PQC **signature** families an
X.509 certificate can carry in its `SubjectPublicKeyInfo` (SPKI) and signature `AlgorithmIdentifier`:

- **ML-DSA** (Module-Lattice Digital Signature Algorithm) — NIST FIPS 204 — parameter sets ML-DSA-44 /
  ML-DSA-65 / ML-DSA-87.
- **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm) — NIST FIPS 205 — the 12 parameter
  sets in the `2.16.840.1.101.3.4.3.{20..35}` arc.

These lints are **algorithm hygiene and structural** checks: they verify that a PQC key/signature is
encoded the way the IETF LAMPS X.509 algorithm-identifier profiles for ML-DSA and SLH-DSA require
(absent `parameters`, correct public-key length for the named parameter set, KeyUsage consistency for a
signature key) and that the OID names a known parameter set. They are **not** CA/Browser Forum
Baseline-Requirements checks (the BR currently permit only RSA/ECDSA for public TLS issuance — see
"Architecture / Why a new non-CABF source").

This feature wires in:

- a new `RuleSource::Pqc` source (wire string `pqc`, lint-id prefix `pqc_*`) — a **universal** source,
  NOT a purpose-gated one (see "THE KEY DESIGN DECISION");
- a small set of PQC-SPKI-gated lints (~6) under `crates/linter/src/lints/pqc/`;
- modest read-only facade work in `cert.rs`: recognize the ML-DSA / SLH-DSA OID arcs in
  `public_key_algorithm()`, and add the accessors the lints need (SPKI / signature `parameters`-absent
  predicates, raw public-key byte length);
- new openssl-generated fixtures (a clean ML-DSA leaf + a clean SLH-DSA leaf + one violating fixture per
  lint that has a producible deviation).

We deliberately port a **high-signal subset** — the structural/hygiene checks implementable with the
existing `Cert` facade plus a few modest new accessors — rather than attempting a full PQC profile.

## Standards basis (RFC numbers flagged where unconfirmed)

- **NIST FIPS 204** — Module-Lattice-Based Digital Signature Standard (ML-DSA). Defines the three
  parameter sets and their public-key sizes.
- **NIST FIPS 205** — Stateless Hash-Based Digital Signature Standard (SLH-DSA). Defines the 12
  parameter sets and their public-key sizes.
- **IETF LAMPS X.509 algorithm-identifier profiles for ML-DSA and SLH-DSA** — these define the X.509
  SPKI and signature OIDs and the encoding rules (notably that the `AlgorithmIdentifier.parameters`
  field MUST be **absent**, and the public-key encoding). As of drafting (early 2026) these are recent
  RFCs / late-stage drafts.
  - ⚠️ **CONFIRM BEFORE CITING IN CODE:** the exact RFC numbers (commonly referenced as the
    "ML-DSA in X.509" and "SLH-DSA in X.509" LAMPS documents; sometimes cited together with the
    composite-signature draft). Do **not** hard-code a specific RFC number in a lint doc comment until
    the developer verifies the published number. Until confirmed, doc comments should cite
    "FIPS 204 / FIPS 205 + the IETF LAMPS ML-DSA/SLH-DSA X.509 algorithm-identifier profile
    (RFC number TBC)".
- **OID arcs** — the NIST `2.16.840.1.101.3.4.3` "sigAlgs" arc. Full table below.

### OID → parameter-set table (bake this into the spec; lints consult it)

ML-DSA (FIPS 204):

| OID | Parameter set | Public-key length (bytes) |
|---|---|---|
| `2.16.840.1.101.3.4.3.17` | ML-DSA-44 | 1312 |
| `2.16.840.1.101.3.4.3.18` | ML-DSA-65 | 1952 |
| `2.16.840.1.101.3.4.3.19` | ML-DSA-87 | 2592 |

SLH-DSA (FIPS 205) — the `2.16.840.1.101.3.4.3.{20..35}` arc, 12 parameter sets (small `s` and fast
`f` variants of each hash/size combination):

| OID | Parameter set | Public-key length (bytes) |
|---|---|---|
| `2.16.840.1.101.3.4.3.20` | SLH-DSA-SHA2-128s  | 32 |
| `2.16.840.1.101.3.4.3.21` | SLH-DSA-SHA2-128f  | 32 |
| `2.16.840.1.101.3.4.3.22` | SLH-DSA-SHA2-192s  | 48 |
| `2.16.840.1.101.3.4.3.23` | SLH-DSA-SHA2-192f  | 48 |
| `2.16.840.1.101.3.4.3.24` | SLH-DSA-SHA2-256s  | 64 |
| `2.16.840.1.101.3.4.3.25` | SLH-DSA-SHA2-256f  | 64 |
| `2.16.840.1.101.3.4.3.26` | SLH-DSA-SHAKE-128s | 32 |
| `2.16.840.1.101.3.4.3.27` | SLH-DSA-SHAKE-128f | 32 |
| `2.16.840.1.101.3.4.3.28` | SLH-DSA-SHAKE-192s | 48 |
| `2.16.840.1.101.3.4.3.29` | SLH-DSA-SHAKE-192f | 48 |
| `2.16.840.1.101.3.4.3.30` | SLH-DSA-SHAKE-256s | 64 |
| `2.16.840.1.101.3.4.3.31` | SLH-DSA-SHAKE-256f | 64 |

> The arc reserves `2.16.840.1.101.3.4.3.{20..35}` (16 slots) for SLH-DSA. FIPS 205 defines **12**
> parameter sets, which map to `.20`–`.31` above. Slots `.32`–`.35` exist in the reserved span but are
> **not** assigned to a published FIPS 205 parameter set; an OID landing in the SLH-DSA arc but outside
> the known 12 is exactly what `pqc_algorithm_known` flags (see lint table).
> ⚠️ The developer MUST re-verify each OID → parameter-set → public-key-length triple against FIPS 204 §4
> and FIPS 205 (parameter-set tables) and the IETF LAMPS registrations at implementation time; the table
> above is the spec's working set and the lengths are the load-bearing values for `pqc_public_key_length`.

## THE KEY DESIGN DECISION: `Pqc` is a UNIVERSAL source, NOT purpose-gated

This is the single most important property of the feature and the central correctness invariant.

Unlike `cabf_cs` (code-signing), `cabf_smime` (S/MIME), and the pending `cabf_ev` (EV) sources — each of
which is **purpose-specific** and folded only into its own purpose's allowed-source set — the `Pqc`
source must behave like `Rfc5280` and `Hygiene`: it is in **every** purpose's allowed-source set.

**Rationale:** a PQC public key can appear in a TLS-server cert, a code-signing cert, an S/MIME cert, or
a generic cert. The algorithm-encoding hygiene rules (parameters-absent, key length, KU consistency) are
true regardless of the certificate's purpose. Gating `Pqc` to one purpose would silently skip PQC
hygiene on certs resolved to a different purpose.

### Wiring (load-bearing)

`Pqc` MUST be added to ALL of the existing per-purpose source helpers in `registry.rs`:

- `tls_server_sources()` → `[Rfc5280, Hygiene, CabfBr, Pqc]`
- `generic_sources()` → `[Rfc5280, Hygiene, Pqc]`
- `code_signing_sources()` → `[Rfc5280, Hygiene, CabfCs, Pqc]`
- `smime_sources()` → `[Rfc5280, Hygiene, CabfSmime, Pqc]`
- (and the `tls_server`-derived / `auto` paths inherit this for free, since `auto` resolves to one of
  the above concrete purposes)

If sibling feature 11 (`cabf_ev`) has landed when feature 13 is implemented, `cabf_ev` is *also* folded
into `tls_server_sources()` — that does not change feature 13's wiring (we still add `Pqc` to every
helper), but it changes the baseline counts (see "Ripple Flag: sibling-11 reconciliation").

### Self-gating ⇒ ZERO cascade on existing RSA/EC fixtures (the central correctness property)

Although `Pqc` is universal (so every PQC lint is *filtered in* for every cert), each PQC lint
**self-gates in `applies()`**: it returns `NotApplicable` unless the cert's SPKI algorithm is a
recognized ML-DSA or SLH-DSA OID. A non-PQC cert (RSA, EC, or any `Other`) therefore sees every `pqc_*`
lint as `NotApplicable`.

```text
applies(cert) = match cert.public_key_algorithm()? {
    PublicKeyAlg::MlDsa(_) | PublicKeyAlg::SlhDsa(_) => Applies,   // (shape per task 01)
    _ /* Rsa | Ec | Other */                         => NotApplicable,
}
// on an Err reading the SPKI algorithm → fail closed to NotApplicable
```

Consequences (the whole point of the universal-but-self-gated design):

- Under `default_registry().run()`, every `pqc` lint is `NotApplicable` on **every existing fixture**
  (`good.pem`, `expired.pem`, all `rfc5280_*`, all `hygiene_*`, all `cabf_br_*`, `cabf_cs_*`,
  `cabf_smime_*`, the CA fixtures) — none of those carry a PQC key.
- Therefore **NO existing fixture is regenerated**, every existing isolation/invariant suite stays green
  untouched, and the `EXPIRED_*` constants are NOT changed.
- This feature adds **only its own new PQC fixtures**. Each new fixture carries a PQC key (so the gate
  engages) and is otherwise RFC-5280-/hygiene-clean so it isolates exactly its one PQC deviation.

This mirrors how features 09–12 achieved no-cascade via `applies()` (the EKU gate in 09/10, the
EV-policy gate in 11, the extension-present / CA-only / good.pem-passes audit in 12). The novelty here is
that the *source* is universal while the *lints* still self-gate — universality affects only which
filter buckets the lints appear in, never which fixtures they fire on.

## Curated lint subset (~6 lints; all `pqc_*`; all PQC-SPKI-gated)

Each lint is `RuleSource::Pqc`, gated on the SPKI algorithm being ML-DSA/SLH-DSA, one small file (or a
shared file for sibling rules), a doc comment citing FIPS 204/205 + the LAMPS X.509 profile (RFC TBC),
and a `#[cfg(test)] mod tests`.

| Lint id | What it enforces | Severity | Facade used | Notes |
|---|---|---|---|---|
| `pqc_algorithm_known` | the SPKI OID lies in the ML-DSA/SLH-DSA arc AND names a *known* parameter set (not an unassigned slot e.g. `.32`–`.35`, and not a malformed arc member) | Error | `public_key_algorithm()` (the `MlDsa`/`SlhDsa` variant must carry a known parameter set) | The gate engages on any arc OID; this lint distinguishes a *recognized* set from an arc OID that is reserved-but-unassigned. See gate/lint interaction note. |
| `pqc_spki_parameters_absent` | the SPKI `AlgorithmIdentifier.parameters` field MUST be **absent** (not present, not `NULL`) | Error | new `spki_algorithm_parameters_present()` | LAMPS profile requires absent params for ML-DSA/SLH-DSA. |
| `pqc_signature_parameters_absent` | the certificate **signature** `AlgorithmIdentifier.parameters` field MUST be absent | Error | new `signature_algorithm_parameters_present()` | Self-gated on the SPKI being PQC (the signature alg is typically the same family for a self-issued/leaf example). See note. |
| `pqc_public_key_length` | the raw public-key byte length matches the length mandated for the named parameter set (per the OID table) | Error | `public_key_algorithm()` + new `public_key_raw_len()` | Message names the parameter set, expected length, and actual length. |
| `pqc_key_usage_consistency` | a PQC **signature** key MUST NOT assert `keyEncipherment` or `keyAgreement`; an EE leaf SHOULD assert `digitalSignature`; a CA SHOULD assert `keyCertSign`/`cRLSign` | mixed (see below) | `key_usage()` → `KeyUsageView` (needs `key_encipherment`, `key_agreement`, `digital_signature`, `key_cert_sign`, `crl_sign` bits), `is_ca()` | Severity split documented below. |
| `pqc_in_unpermitted_profile` *(optional / Future)* | advisory Notice when a PQC key appears in a profile that does not yet permit PQC (e.g. a `serverAuth` leaf, since the CABF BR do not yet allow PQC for public TLS) | Notice | `public_key_algorithm()` + `has_server_auth()` | **Ships only if cleanly expressible without entangling the purpose machinery.** Otherwise deferred to Future — see "Future" subsection. The architect's recommendation: **defer** it for v1 (it overlaps purpose intent and risks confusing the universal-source design); ship the 5 structural lints first. |

### Severity decisions

- `pqc_algorithm_known`, `pqc_spki_parameters_absent`, `pqc_signature_parameters_absent`,
  `pqc_public_key_length` → **Error**. These are hard encoding requirements of the LAMPS profile; a cert
  that violates them is malformed / non-interoperable.
- `pqc_key_usage_consistency` → **mixed, documented per bit:**
  - asserting `keyEncipherment` or `keyAgreement` on a PQC **signature** key → **Error** (these bits are
    semantically wrong for a signature-only algorithm — a verifier would mis-use the key).
  - EE leaf NOT asserting `digitalSignature` → **Warn** (a SHOULD; some valid configurations omit it).
  - CA NOT asserting `keyCertSign` → **Warn** (a SHOULD-shaped expectation; keep it Warn to avoid
    false-positives on unusual-but-valid CA KU sets).
  - Document the rationale (Error for the actively-wrong bits, Warn for the absent-recommended bits) in
    the lint file. One `check()` may emit multiple findings (one per offending/missing bit), each named.
- `pqc_in_unpermitted_profile` (if shipped) → **Notice**.

> Final lint count for the registry/CLI bumps: **5** if `pqc_in_unpermitted_profile` is deferred
> (recommended), **6** if it ships. The plan is written for **5**; if the developer ships the optional
> 6th, reconcile the count in task 03 and the test-plan accordingly. State the chosen number explicitly
> at implementation time.

### Gate vs `pqc_algorithm_known` interaction (resolve here)

The `applies()` gate must engage on a cert that carries a PQC-*arc* OID even when that OID is a
reserved-but-unassigned slot (`.32`–`.35`) or otherwise not a known parameter set — otherwise
`pqc_algorithm_known` could never fire through the registry path (the unknown-OID cert would be gated
out). Two clean options; **the spec chooses option (A)**:

- **(A, chosen) Gate on the arc, name the set in the variant.** `public_key_algorithm()` returns the
  ML-DSA/SLH-DSA variant for *any* OID under the two arcs, with the parameter-set identity carried as an
  enum-or-`Option` inside the variant (a known set, or "unknown arc member"). `applies()` = `Applies`
  for any arc member. `pqc_algorithm_known` then fires Error when the variant's parameter set is the
  "unknown arc member" case. Every other PQC lint that needs a length/family treats "unknown arc member"
  as: no finding (it cannot validate a length it does not know) — so the unknown-OID fixture isolates
  exactly `pqc_algorithm_known`.
- (B, rejected) Gate strictly on known sets; test `pqc_algorithm_known` by direct lint invocation only.
  Rejected because it makes the lint untestable through the registry and weakens the gate's coverage of
  arc-but-unknown OIDs.

The developer finalizes the exact variant shape (task 01) and documents the chosen gate semantics.

### Why this subset and not more

- **Parameter-set recognition + length** are the defining structural checks and are backed directly by
  the OID table + a raw-key-length accessor.
- **Two `parameters`-absent lints** (SPKI + signature) are the single most-cited LAMPS encoding
  requirement for these algorithms and need only small presence predicates.
- **KU consistency** is the one semantic check that distinguishes a signature key from an encryption key
  and reuses the existing `KeyUsageView` plus a few additional bits.
- **Deferred (NOT ported):** signature-algorithm/SPKI-algorithm *agreement* checks (cert signed with a
  different family than its key), composite-PQC structural rules, ML-KEM key-encipherment-only rules,
  and the unpermitted-profile advisory (see "Future"). Each needs either out-of-scope algorithm families
  or a larger accessor surface than this first PQC slice warrants.

## Architecture

- One small file per lint under `crates/linter/src/lints/pqc/`, plus `pqc/mod.rs` declaring the modules,
  re-exporting the lint types, and housing the shared `applies_to_pqc(cert)` helper and the
  OID → (parameter-set, public-key-length) table (the table may live in a dedicated `pqc/params.rs`
  submodule for auditability, mirroring how `cabf_br/reserved.rs` and `cabf_ev/policy.rs` isolate their
  data tables). Mirror the layout of `crates/linter/src/lints/cabf_cs/`.
- New source variant `RuleSource::Pqc` in `crates/linter/src/source.rs` (serde `snake_case` → `pqc`).
  Placement in the enum: adjacent to the other universal sources — recommended directly **after**
  `Rfc5280` (so the enum reads `Rfc5280, Pqc, CabfBr, ...`) OR just before `Hygiene`; the spec picks
  **right after `Rfc5280`** to group the two cross-purpose structural sources together. Keep the enum
  order, `SOURCE_ORDER`, and `ALL_SOURCES` mutually consistent (see CLI section).
- New facade work in `crates/linter/src/cert.rs` (task 01):
  - **Extend `PublicKeyAlg`** to recognize PQC. Proposed cleanest shape (developer finalizes):
    add two variants `MlDsa(MlDsaParams)` and `SlhDsa(SlhDsaParams)` — OR a single `Pqc(PqcAlg)`
    sub-enum — where the carried type identifies the parameter set (a known set, or an "unknown arc
    member" sentinel per option (A) above). **Keep the existing `Rsa` / `Ec` / `Other(String)` variants
    and their behavior unchanged** so no current test or fixture breaks (an existing PQC-in-`Other` test,
    if any, is the only thing that could shift — the developer checks for and updates any such in-file
    test in `cert.rs`'s own `#[cfg(test)]`).
  - Recognize the ML-DSA (`2.16.840.1.101.3.4.3.{17,18,19}`) and SLH-DSA
    (`2.16.840.1.101.3.4.3.{20..35}`) OID arcs in `public_key_algorithm()` (currently the `match` at
    `cert.rs:766` buckets them into `Other`).
  - `spki_algorithm_parameters_present() -> Result<bool, CertError>` — `true` iff the SPKI
    `AlgorithmIdentifier.parameters` field is present (present-and-`NULL` counts as present). Read via
    the existing `with_parsed` helper. (Consumed by `pqc_spki_parameters_absent`.)
  - `signature_algorithm_parameters_present() -> Result<bool, CertError>` — `true` iff the certificate
    signature `AlgorithmIdentifier.parameters` field is present. (Consumed by
    `pqc_signature_parameters_absent`.)
  - `public_key_raw_len() -> Result<usize, CertError>` — the byte length of the raw subjectPublicKey
    BIT STRING contents (the encoded public key) for non-RSA/EC keys. Document exactly what is measured
    (the public-key octets the LAMPS profile defines as the SPKI public key for ML-DSA/SLH-DSA — i.e.
    the BIT STRING value, excluding the unused-bits octet). (Consumed by `pqc_public_key_length`.)
  - **Extend `KeyUsageView`** with the bits the KU-consistency lint needs that are not yet exposed:
    `key_encipherment` (bit 2), `key_agreement` (bit 4), `crl_sign` (bit 6). (`digital_signature`,
    `key_cert_sign` already exist; confirm and reuse.) Document each bit with its RFC 5280 §4.2.1.3 bit
    index. (Consumed by `pqc_key_usage_consistency`.) Reuse existing `is_ca()`.
  - All accessors return `Result<_, CertError>`, never panic on cert data, follow the existing accessor
    style.
- New source wiring in `crates/linter/src/registry.rs` (task 03):
  - Register the 5 (or 6) `pqc` lints in `default_registry()` after the `cabf_smime` block (or wherever
    keeps the deterministic order with the golden test — append at the end of the existing lint list, in
    a fixed order).
  - **Add `RuleSource::Pqc` to ALL of `tls_server_sources()`, `generic_sources()`,
    `code_signing_sources()`, `smime_sources()`** (the universal-source wiring above). Keep each
    helper's order fixed and deterministic; append `Pqc` at the end of each so existing relative order is
    untouched.
  - **No new `CertPurpose`.** PQC is not a purpose; it is a universal source. The `auto` resolver,
    `resolve`, and the `CertPurpose` enum are **unchanged**.
  - Update the in-file unit tests: bump the lint count (52 → 57 off the current baseline, or +6 if the
    optional lint ships; reconcile to 61-baseline if sibling 11 has landed — see Ripple Flag); add a
    `pqc` source-filter test; add tests asserting `Pqc` is present in *every* purpose's
    `allowed_sources` (the universal-source property is itself a test objective). Leave the existing
    rfc5280/cabf_br/cabf_cs/cabf_smime/hygiene filter-count tests unchanged.
- CLI wiring in `crates/cli/src/main.rs` (task 03):
  - add `"pqc" => Ok(RuleSource::Pqc)` to `parse_source_token`; add `RuleSource::Pqc` to `ALL_SOURCES`
    (keep order consistent with `SOURCE_ORDER`); update the `--source` doc string and the
    `parse_source_token` error-message list to include `pqc`.
  - **No `CliPurpose` change** (no new purpose).
- CLI output in `crates/cli/src/output.rs` (task 03):
  - add `RuleSource::Pqc` to `SOURCE_ORDER` in a fixed position — recommended directly after
    `RuleSource::Rfc5280` (matching the enum placement and grouping the two universal structural sources)
    — and add a `source_label` arm → `"pqc"`. `ALL_SOURCES` (main.rs) and `SOURCE_ORDER` (output.rs)
    MUST agree on the position.

## ⚠️ SHARED-FILE / SEQUENCING WARNING (siblings 09/10/11)

This feature edits files that sibling rule-set features **09/10/11** also edit:

- `crates/linter/src/source.rs` (each adds a `RuleSource` variant)
- `crates/linter/src/registry.rs` (each registers lints; 09/10/11 add a purpose or fold a source into a
  purpose set; this feature folds `Pqc` into ALL purpose sets)
- `crates/cli/src/main.rs` (`--source` / `ALL_SOURCES` / help text)
- `crates/cli/src/output.rs` (`SOURCE_ORDER` / `source_label`)

**These features MUST be implemented SEQUENTIALLY, not run in parallel.** Feature 13 is the latest in the
series; it MUST be implemented against whatever baseline exists when it lands, and it reconciles the
final counts and ordered source lists. The current baseline is **52 lints** with sources
`[Rfc5280, CabfBr, CabfCs, CabfSmime, Hygiene]` (feature 11 not yet implemented). If feature 11 lands
first, the baseline becomes **61** (52 + 9 EV lints) with `CabfEv` inserted before `CabfCs` — see the
sibling-11 Ripple Flag. Within feature 13, the task `depends_on` graph serializes its own touches of the
shared files.

## Changes Overview

**crates/linter/ (production code — developer tasks 01–03)**
- `src/cert.rs` — extend `PublicKeyAlg` with ML-DSA/SLH-DSA recognition; recognize the OID arcs in
  `public_key_algorithm()`; add `spki_algorithm_parameters_present()`,
  `signature_algorithm_parameters_present()`, `public_key_raw_len()`; extend `KeyUsageView` with
  `key_encipherment` / `key_agreement` / `crl_sign` bits. Keep Rsa/Ec/Other behavior unchanged.
  (task 01)
- `src/source.rs` — add `RuleSource::Pqc` (serde `pqc`), after `Rfc5280`; update the type-doc listing
  the `--source` vocabulary. (task 02)
- `src/lints/mod.rs` — `pub mod pqc;`. (task 02)
- `src/lints/pqc/mod.rs` — module declarations + re-exports + shared `applies_to_pqc` helper. (task 02)
- `src/lints/pqc/params.rs` — the OID → (parameter-set name, public-key length) table, with unit tests.
  (task 02; isolated for auditability and to keep lint files conflict-free.)
- `src/lints/pqc/algorithm_known.rs` (task 02)
- `src/lints/pqc/spki_parameters_absent.rs` (task 02)
- `src/lints/pqc/signature_parameters_absent.rs` (task 02)
- `src/lints/pqc/public_key_length.rs` (task 02)
- `src/lints/pqc/key_usage_consistency.rs` (task 02)
- (optional) `src/lints/pqc/in_unpermitted_profile.rs` — only if the optional advisory lint ships
  (recommended deferred). (task 02)
- `src/registry.rs` — register the 5 (or 6) `pqc` lints; add `Pqc` to ALL four `*_sources()` helpers;
  update in-file count/filter unit tests + the universal-source-membership tests. NO `CertPurpose`
  change. (task 03)

**crates/cli/ (production code — developer task 03)**
- `src/main.rs` — `--source pqc` token + `ALL_SOURCES`; doc/error-string updates. No purpose change.
  (task 03)
- `src/output.rs` — `SOURCE_ORDER` + `source_label` for `Pqc`. (task 03)

**testdata/ + tests (tester — task 04)**
- `testdata/generate.sh` — append a SELF-CONTAINED PQC section (ML-DSA / SLH-DSA leaf-extension configs +
  the new fixtures). Requires openssl 3.5+ / 3.6.2 (native ML-DSA / SLH-DSA). NO existing fixture
  regenerated.
- New fixtures (openssl-generated only — NEVER cert-bar): see Fixtures section.
- New integration tests `crates/linter/tests/pqc.rs`.
- A CLI `--source pqc` e2e test in `crates/cli/tests/output.rs` (ADD only).
- Registry count bump in `crates/linter/tests/registry.rs` if that integration test asserts the total
  (reconcile to the then-current baseline).

## Fixtures (openssl-generated ONLY — never cert-bar)

⚠️ **openssl version:** ML-DSA and SLH-DSA key/cert generation requires **openssl 3.5+** (verified
working on 3.6.2). The PQC section of `generate.sh` MUST document the minimum version and fail loudly
(version check) if run on an older openssl, so a missing-algorithm failure is diagnosable rather than
silent.

⚠️ **Fixtures must remain the independent oracle.** Generate ALL PQC fixtures with openssl, NEVER source
them from the user's `cert-bar` tool — the linter must stay an independent checker over cert-bar's PQC
output.

A **clean ML-DSA leaf** = ML-DSA-65 SPKI (params absent) + ML-DSA-65 signature (params absent) + correct
public-key length + `digitalSignature` KU (no `keyEncipherment`/`keyAgreement`) + `CA:FALSE` + a
**currently-valid** window aligned with the existing `BR_OK` horizon (`2026-06-01 → 2027-06-01`). A
**clean SLH-DSA leaf** = the SLH-DSA analogue (e.g. SLH-DSA-SHA2-128s). One **violating fixture per lint
that has a producible deviation**, each breaking exactly one PQC rule while remaining otherwise clean and
carrying a PQC key (so the gate engages).

| Fixture | shape | single intended violation |
|---|---|---|
| `pqc_mldsa_good.pem` | ML-DSA-65, params absent, correct length, digitalSignature KU, CA:FALSE, currently-valid | NONE in the pqc set (clean) |
| `pqc_slhdsa_good.pem` | SLH-DSA-SHA2-128s, params absent, correct length, digitalSignature KU, CA:FALSE, currently-valid | NONE in the pqc set (clean) |
| `pqc_unknown_param_set.pem` | SPKI OID in the SLH-DSA arc but an unassigned slot (e.g. `.32`) | `pqc_algorithm_known` |
| `pqc_spki_params_present.pem` | ML-DSA key with a present (NULL) SPKI `parameters` field | `pqc_spki_parameters_absent` |
| `pqc_sig_params_present.pem` | PQC cert whose signature `AlgorithmIdentifier` carries a present `parameters` field | `pqc_signature_parameters_absent` |
| `pqc_bad_key_length.pem` | ML-DSA OID but a public-key byte length that does not match the named set | `pqc_public_key_length` |
| `pqc_bad_key_usage.pem` | ML-DSA leaf asserting `keyEncipherment` (wrong bit for a signature key) | `pqc_key_usage_consistency` (Error path) |

Notes / caveats (the tester owns producibility decisions, like prior features):

- **openssl may not cleanly produce every deviation.** Several violating fixtures (`spki_params_present`,
  `sig_params_present`, `bad_key_length`, `unknown_param_set`) require encodings openssl will **not**
  emit normally — openssl follows the LAMPS profile (absent params, correct length, valid OID). The
  tester MUST decide, per fixture, whether it is producible via openssl config, via openssl + targeted
  **DER byte-patching** (e.g. flipping an OID arc digit, splicing a NULL into the AlgorithmIdentifier,
  truncating/padding the BIT STRING), or **not cleanly producible** at all. For any deviation that
  cannot be produced cleanly, the tester:
  - tests that lint by **direct lint invocation** on a hand-constructed `Cert` where feasible, OR
  - flags the lint+fixture as **deferred together** (noted, pre-approved like feature 12's pre-approved
    cuts), reducing the shipped lint count by one and reconciling the registry/CLI counts.
  Document the chosen approach per fixture in the test and in `generate.sh`. The two clean fixtures
  (`pqc_mldsa_good`, `pqc_slhdsa_good`) MUST be openssl-native (no patching).
- **`pqc_unknown_param_set.pem`** is the through-registry fixture for `pqc_algorithm_known` ONLY because
  the gate is on the arc, not the known set (option (A) above). If the developer ships option (B)
  instead, this lint is tested by direct invocation and the fixture may be dropped — reconcile.
- **Time-fragility:** the two clean PQC leaves use a currently-valid window straddling "now"
  (`2026-06-01 → 2027-06-01`, aligned with `BR_OK`). They EXPIRE ~2027-06-01, after which
  `hygiene_not_expired` fires on them and isolation breaks. Document loudly in `generate.sh`'s PQC
  section header and reference it in the `pqc.rs` module doc; regenerate annually. Any violating fixture
  must also straddle "now" so ONLY its target PQC rule fires (not `hygiene_not_expired`).
- **All PQC fixtures must pass the rfc5280 + hygiene lints** (v3, positive serial, valid validity
  ordering, currently valid) EXCEPT their single deliberate PQC deviation. Note: the hygiene key-strength
  lints (`hygiene_rsa_key_min_2048`, `hygiene_ecdsa_curve_allowlist`) are `applies()`-scoped to RSA / EC
  keys respectively, so they are `NotApplicable` on a PQC key and do NOT fire on the PQC fixtures —
  confirm this in the no-cascade test (it is the symmetric counterpart to the PQC gate).
- **No existing fixture is regenerated.** Restore tracked fixtures with
  `git checkout -- 'testdata/*.pem'` (the quoted glob — NEVER `git checkout -- testdata/` which would
  also clobber `generate.sh`). The `generate.sh` PQC section is appended and self-contained so it does
  not perturb the existing fixture-generation recipes.

## Dependencies

**None new expected.** The OID-arc recognition and the `AlgorithmIdentifier.parameters`-presence /
public-key-length reads are all available through `x509-parser` / `der` (already dependencies) via the
existing `with_parsed` helper — `public_key_algorithm()` already reaches `c.public_key().algorithm`, and
the `parameters` field and raw BIT STRING are reachable on the same parsed structures. The OID →
parameter-set → length table is a small in-module constant (no crate). If the developer finds a new crate
genuinely necessary, it MUST be documented and justified in the task and added to
`crates/linter/Cargo.toml` (and `cargo audit`-checked per CLAUDE.md).

## Future (explicitly out of scope for this feature — reserved, not specced)

Documented here, like the other features reserve future variants, so a later feature can pick them up
deliberately. These are **NOT** specced or implemented by feature 13:

- **ML-KEM (FIPS 203)** — the key-encapsulation (encryption) PQC family. Its X.509 keys are
  encryption-only (`keyEncipherment`), with a different KU-consistency rule (the *inverse* of the
  signature rule here). It needs its own OID arc recognition and its own length table. Reserved.
- **Composite PQC + classical** (e.g. composite ML-DSA + ECDSA / RSA signatures and keys) — the IETF
  LAMPS composite drafts define hybrid AlgorithmIdentifiers with their own OIDs and structural rules
  (the public key / signature is a SEQUENCE of two component keys/signatures). Larger structural surface;
  reserved.
- **Stateful hash-based signatures (LMS/HSS — RFC 8554; XMSS/XMSS^MT — RFC 8391)** — these are stateful
  and have NIST SP 800-208 / RFC profiles distinct from SLH-DSA (which is *stateless*). They are out of
  scope; reserved.
- **`pqc_in_unpermitted_profile`** advisory Notice (the optional 6th lint) — deferred unless it can be
  expressed without entangling the purpose machinery. Reserved as a follow-up.
- **Signature/SPKI algorithm-agreement** lints (cert signed by a different family than its own key) —
  reserved.

## Ripple Flag: Feature 06 golden test

Feature 06's golden-file test snapshots the output of running all lints over `testdata/`. Adding the
`pqc` lints + a new `[pqc]` source group + new PQC fixtures changes:
- the lint count and the per-source grouping in any golden snapshot;
- `SOURCE_ORDER` now includes `pqc`, so grouped text/JSON output gains a `[pqc]` section.

**BUT the existing golden fixtures are RSA**, and the PQC lints are `NotApplicable` on them (self-gate),
so the existing golden rows do not change in *outcome* — only the new `[pqc]` source bucket appears (with
all existing fixtures NotApplicable) and the new PQC fixtures add rows. **Action (flag only — do NOT edit
feature 06 here):** if feature 06's golden snapshot exists when feature 13 lands, fold its regeneration
into the tester task (add the snapshot file to task 04's `touches` and note it). Verify whether
`crates/*/tests/` contains a golden snapshot before implementing; if present, regenerate as part of
task 04.

## Ripple Flag: sibling-11 (cabf_ev) count / SOURCE_ORDER reconciliation

Feature 11 (`cabf_ev`) is NOT yet implemented as of drafting. Feature 13's counts and ordered source
lists MUST be reconciled against whatever baseline exists when 13 is implemented:

- **If 11 has NOT landed (current state):** baseline = **52 lints**, sources
  `[Rfc5280, CabfBr, CabfCs, CabfSmime, Hygiene]`. After feature 13: **57** (or 58 with the optional
  lint). Enum / `SOURCE_ORDER` / `ALL_SOURCES` become `[Rfc5280, Pqc, CabfBr, CabfCs, CabfSmime,
  Hygiene]`.
- **If 11 HAS landed:** baseline = **61 lints**, sources include `CabfEv` (inserted before `CabfCs`, per
  feature 11's chosen order `Rfc5280, CabfBr, CabfEv, CabfCs, CabfSmime, Hygiene`). After feature 13:
  **66** (or 67). Place `Pqc` right after `Rfc5280` →
  `[Rfc5280, Pqc, CabfBr, CabfEv, CabfCs, CabfSmime, Hygiene]`.

The implementer reconciles the exact lint count, the `default_registry().len()` assertion, the
per-source filter counts, the enum order, `SOURCE_ORDER`, and `ALL_SOURCES` at integration time, and
states the chosen baseline explicitly in the registry unit-test update. Whichever feature lands last
owns the final count.

## Sequencing (batches)

- **Batch A:** task 01 (`cert.rs`: `PublicKeyAlg` extension + OID-arc recognition + the three new
  accessors + `KeyUsageView` bit additions). [`crates/linter/src/cert.rs`]
- **Batch B:** task 02 (`source.rs` `RuleSource::Pqc` + `lints/mod.rs` + `pqc/` module + `params.rs` +
  the 5 (or 6) lint files). depends_on 01.
- **Batch C:** task 03 (`registry.rs` register + universal `*_sources()` wiring + count/filter +
  universal-membership unit tests; `cli/main.rs` + `cli/output.rs` wiring). depends_on 02.
- **Batch D:** task 04 (PQC fixtures + `generate.sh` PQC section + `pqc.rs` tests + CLI e2e +
  `tests/registry.rs` count bump). depends_on 03.

> Conflict audit: `cert.rs` touched only by task 01. `source.rs` + `lints/mod.rs` + `pqc/*` only by
> task 02. `registry.rs` + `cli/main.rs` + `cli/output.rs` only by task 03. `testdata/` + `tests/*` only
> by task 04. No two tasks in this feature share a `touches` file within the same batch; the chain is
> strictly serial because 02 and 03 depend on prior shared-file edits in order.
