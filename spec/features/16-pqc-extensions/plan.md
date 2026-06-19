# Feature: PQC Extensions — ML-KEM Key/Cert Lints, Composite Feasibility, and PQC-Signature KeyUsage Gap

## Overview

Feature 13 shipped the post-quantum **signature** hygiene rule set (ML-DSA / SLH-DSA) under the
universal `RuleSource::Pqc` source. Feature 16 extends that PQC family in three directions:

1. **ML-KEM (FIPS 203) key/cert lints** — the **key-establishment (KEM)** counterpart to feature 13's
   signature lints. ML-KEM keys are *encryption-only*; their KeyUsage consistency rule is the **inverse**
   of the signature rule (`keyEncipherment` / `keyAgreement` permitted; `digitalSignature` / `keyCertSign`
   / `cRLSign` forbidden). New lints: SPKI parameters absent, mandated public-key length, recognised
   parameter set, and KEM KeyUsage consistency.

2. **Composite PQC + classical (signatures / KEM)** — `draft-ietf-lamps-pq-composite-sigs` /
   `-kem`. **RESOLVED: deferred to the backlog.** Stock OpenSSL 3.6.2 cannot emit a composite SPKI (see
   "Open Question 1 — RESOLVED"), so there is no openssl-native fixture path and the IETF drafts carry
   provisional, churning OIDs. Feature 16 ships parts 1 + 3 now and reserves composite for a later
   feature (recorded in "Future").

3. **Close the `pqc_key_usage_consistency` gap** — the existing PQC *signature* KU lint today flags only
   `keyEncipherment` / `keyAgreement` as Error bits. Extend it to also flag **`dataEncipherment`** (bit 3),
   **`encipherOnly`** (bit 7), and **`decipherOnly`** (bit 8) on a PQC signature key. These are likewise
   semantically wrong for a signature-only algorithm (a verifier honouring them would mis-use the key).

This feature reuses the **existing** `RuleSource::Pqc` (already universal and already wired into every
purpose helper, the CLI `--source` vocabulary, and the `[pqc]` output bucket). **No new source, no new
CLI/output wiring, no new purpose.** The only shared-file ripple is the registry lint count + `cert.rs`
(the `KeyUsageView` extension and a new ML-KEM OID arc).

## Standards basis (RFC / draft numbers flagged where unconfirmed)

- **NIST FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM). Defines the
  three parameter sets and their **encapsulation-key** sizes.
- **IETF LAMPS ML-KEM in X.509** — the algorithm-identifier profile defining the ML-KEM SPKI OIDs and
  encoding rules (notably `AlgorithmIdentifier.parameters` MUST be **absent**, and the public key is the
  raw encapsulation key in the SPKI BIT STRING). ⚠️ **CONFIRM the exact RFC/draft number before citing in
  code.** Until confirmed, doc comments cite "FIPS 203 + the IETF LAMPS ML-KEM X.509 algorithm-identifier
  profile (RFC/draft number TBC)" — mirroring feature 13's ML-DSA/SLH-DSA convention.
- **RFC 5280 §4.2.1.3** — Key Usage bit semantics (the bit indices for `dataEncipherment` bit 3,
  `encipherOnly` bit 7, `decipherOnly` bit 8, plus the existing `digitalSignature` bit 0,
  `keyEncipherment` bit 2, `keyAgreement` bit 4, `keyCertSign` bit 5, `cRLSign` bit 6).
- **OID arc** — the NIST `2.16.840.1.101.3.4.4` **"kems" arc** (distinct from the `...3.4.3` "sigAlgs"
  arc feature 13 uses). **Verified against the installed OpenSSL 3.6.2 `list -kem-algorithms`:**

### ML-KEM OID → parameter-set → encapsulation-key length table (verified)

| OID | Parameter set | Public-key (encapsulation-key) length (bytes) |
|---|---|---|
| `2.16.840.1.101.3.4.4.1` | ML-KEM-512  | 800  |
| `2.16.840.1.101.3.4.4.2` | ML-KEM-768  | 1184 |
| `2.16.840.1.101.3.4.4.3` | ML-KEM-1024 | 1568 |

> Verified by the architect at planning time: `openssl list -kem-algorithms` lists exactly these three
> OIDs (`id-alg-ml-kem-512/768/1024`); a generated ML-KEM-768 SPKI BIT STRING has 1185 content octets =
> 1 unused-bits octet + **1184** raw key octets, matching the table and confirming
> `Cert::public_key_raw_len()` (which excludes the unused-bits octet — see "Architecture / Reuse")
> measures the right value. The developer MUST still re-verify each triple against FIPS 203 §8 (sizes
> table) and the LAMPS registration at implementation time; the lengths are the load-bearing value for
> `pqc_mlkem_public_key_length`.

## Open questions — RESOLVED in this plan

### Open Question 1 — Composite feasibility & scope → RESOLVED: **defer composite**

Architect investigation (OpenSSL 3.6.2): `openssl list -signature-algorithms` and `list -kem-algorithms`
list **no** composite algorithms; `genpkey -algorithm MLDSA65-ECDSA-P256-SHA512` (and the
`id-MLDSA65-ECDSA-P256` form) fail with `unsupported`. Stock OpenSSL therefore **cannot mint a composite
SPKI or composite-signed cert at all.** The composite drafts also still carry provisional OIDs.

The hard constraint "fixtures: OpenSSL only, never cert-bar" means there is **no honest openssl-native or
byte-patch path** to a representative composite fixture without hand-crafting the entire composite SPKI
SEQUENCE-of-two-component-keys structure in DER from scratch — a large, low-confidence surface against a
moving draft.

**Recommendation (chosen): defer composite entirely to the backlog** (option (c) in the brief). Ship
parts 1 (ML-KEM) + 3 (KU gap) now. Composite is reserved in "Future" with the concrete blockers noted so
a later feature can pick it up once (a) OpenSSL gains composite support or (b) the drafts reach RFC with
stable OIDs. **This is the one item flagged to the user at the Phase 1.5 gate** (see "Escalations").

### Open Question 2 — KEM KeyUsage policy (precise) → RESOLVED

For an ML-KEM certificate (a KEM / key-establishment key), mirror feature 13's signature rule inverted,
with the same Error-vs-Warn split:

- **Permitted / expected bits:** `keyEncipherment` (bit 2) and `keyAgreement` (bit 4). (ML-KEM is used
  for key establishment; both spellings appear in practice across profiles.)
- **Forbidden bits → Error** (actively-wrong for a KEM key — a verifier honouring them would mis-use the
  key for an operation it cannot perform): `digitalSignature` (bit 0), `keyCertSign` (bit 5),
  `cRLSign` (bit 6), and the data-/content-signing-adjacent `nonRepudiation`/`contentCommitment` is NOT
  forbidden here (out of scope — KEM keys neither sign nor are forbidden it; we keep the set to the
  clearly-wrong signing bits). `dataEncipherment` (bit 3) is **permitted-but-discouraged**: it is a
  legacy bulk-encryption bit, not how ML-KEM is used; we do **not** flag it (avoid false positives), to
  keep the lint conservative — documented in the lint file.
- **Recommended-present bit → Warn:** an end-entity ML-KEM leaf SHOULD assert at least one of
  `keyEncipherment` / `keyAgreement`; if it asserts **neither** (or the KU extension is absent on an EE)
  → **Warn** (a SHOULD, not a MUST — some valid configs differ).
- **CA case:** an ML-KEM key in a CA cert is unusual (a CA signs; a KEM key cannot). We keep this simple:
  the forbidden signing bits (`keyCertSign`/`cRLSign`/`digitalSignature`) Error regardless of CA flag;
  no separate "CA SHOULD assert keyCertSign" Warn (that would contradict the forbidden-signing-bit rule).

Severity split mirrors feature 13: **Error** for the actively-wrong signing bits, **Warn** for the
absent-recommended encryption bit. One `check()` may emit multiple findings, each named.

### Open Question 3 — Is ML-KEM a new universal-source set, or does it need gating nuance? → RESOLVED

ML-KEM lints reuse the **existing universal `RuleSource::Pqc`** (no new source). Each ML-KEM lint
self-gates in `applies()` on the SPKI algorithm being the new `PublicKeyAlg::MlKem(_)` variant (the
mirror of feature 13's `applies_to_pqc`). A KEM EE is never a TLS *signature* leaf, but it CAN legitimately
carry `serverAuth`-adjacent EKUs in some hybrid profiles; the existing purpose model handles this without
spurious findings because:

- `Pqc` is a separate self-gating pass, so the ML-KEM lints fire only on ML-KEM SPKIs.
- The clean ML-KEM fixture is a **generic** leaf (no `serverAuth` EKU, `CA:FALSE`), so `cabf_br`
  serverAuth/KU lints stay `NotApplicable` on it (CABF BR lints gate on serverAuth scope). The tester
  MUST add a no-cross-source-cascade assertion confirming the clean ML-KEM fixture trips **only** its
  intended PQC outcomes (no spurious `cabf_br_*` / `hygiene_*` findings) — the symmetric counterpart to
  feature 13's no-cascade test. Note: the hygiene key-strength lints (`hygiene_rsa_key_min_2048`,
  `hygiene_ecdsa_curve_allowlist`) are RSA/EC-scoped and stay `NotApplicable` on an ML-KEM key.

### Open Question 4 — `KeyUsageView` extension shape → RESOLVED

Add three plain `bool` fields to the existing `KeyUsageView` struct (`crates/linter/src/cert.rs:91`):
`data_encipherment` (bit 3), `encipher_only` (bit 7), `decipher_only` (bit 8), each documented with its
RFC 5280 §4.2.1.3 bit index. Populate them in the single `key_usage()` constructor
(`cert.rs:602`) via x509-parser 0.18's `data_encipherment()` / `encipher_only()` / `decipher_only()`
accessors (**verified present** in the installed x509-parser 0.18.1).

`KeyUsageView` is constructed in exactly ONE place (`Cert::key_usage()`, cert.rs:602) and is `Copy`. Its
consumers (each builds a `KeyUsageView` literal in its `#[cfg(test)]` helper, which must add the 3 new
fields):

- `crates/linter/src/lints/pqc/key_usage_consistency.rs` (the part-3 lint — also reads the new fields)
- `crates/linter/src/lints/cabf_cs/key_usage_required.rs` (test helper only)
- `crates/linter/src/lints/cabf_smime/key_usage_critical.rs` (test helper only)
- `crates/linter/src/lints/cabf_smime/key_usage_present.rs` (test helper only)
- the new `crates/linter/src/lints/pqc/mlkem_key_usage_consistency.rs` (reads the new fields)

Because the struct gains fields, every literal-construction site (production constructor + the 4 existing
test helpers) MUST be updated in the **same task** that extends the struct, or the crate will not compile.
**This is why the `KeyUsageView` extension is its own early foundation task (dev-01) that all lint tasks
depend on**, and dev-01 touches the test-helper sites in the cabf_cs / cabf_smime lint files (additive:
just the new struct fields in the `ku()` helpers — no behaviour change). See the Conflict Audit.

## Architecture

### Reuse (no change needed — confirmed)

- **`RuleSource::Pqc`** already exists, is universal, and is already in `tls_server_sources()`,
  `generic_sources()`, `code_signing_sources()`, `smime_sources()`, the CLI `ALL_SOURCES`,
  `parse_source_token`, and `output.rs` `SOURCE_ORDER` / `source_label`. **No source/CLI/output edits.**
- **`Cert::public_key_raw_len()`** (cert.rs:1005) already returns `subject_public_key.data.len()` — the
  BIT STRING content excluding the unused-bits octet — which is exactly the ML-KEM encapsulation-key byte
  length (verified 1184 for ML-KEM-768). **Reused as-is for `pqc_mlkem_public_key_length`.**
- **`Cert::spki_algorithm_parameters_present()`** (cert.rs:967) already reports SPKI params presence.
  **Reused as-is for `pqc_mlkem_spki_parameters_absent`.**
- **The `applies_to_pqc` pattern** (pqc/mod.rs:75) is the template for a new `applies_to_mlkem` gate.

### New facade work in `crates/linter/src/cert.rs` (dev-01)

1. **Add `PublicKeyAlg::MlKem(PqcParamSet)`** variant (alongside `MlDsa` / `SlhDsa`; cert.rs:185).
   Reuse the existing `PqcParamSet { Known(&'static str), Unknown(String) }` enum unchanged.
2. **Add a second OID-arc classifier.** Do **NOT** overload `classify_pqc_oid` (the sigAlgs arc). Add a
   sibling `classify_mlkem_oid(dotted) -> Option<PublicKeyAlg>` keyed on a new
   `MLKEM_ARC_PREFIX = "2.16.840.1.101.3.4.4."` recognising `.1` → ML-KEM-512, `.2` → ML-KEM-768,
   `.3` → ML-KEM-1024 (single-component suffix only; anything else in the arc → `PqcParamSet::Unknown`
   per option (A), so a future `pqc_mlkem_algorithm_known` can fire through the registry). Wire it into
   `public_key_algorithm()` (cert.rs:937) after the existing `classify_pqc_oid` fallthrough:
   `classify_pqc_oid(other).or_else(|| classify_mlkem_oid(other)).unwrap_or_else(|| Other(...))`.
3. **Extend `KeyUsageView`** with `data_encipherment` (bit 3), `encipher_only` (bit 7),
   `decipher_only` (bit 8); populate in `key_usage()`; update the 4 existing test-helper literals
   (additive). See Open Question 4.
4. Add `#[cfg(test)] mod tests` for `classify_mlkem_oid` (mirror the existing `classify_pqc_oid` tests:
   known slots, unknown-arc-member `.4` / `.0`, non-arc OIDs, malformed). Assert `good.pem` (RSA) is
   unchanged.

### New lints in `crates/linter/src/lints/pqc/` (dev-02)

A KEM parameter table + a shared ML-KEM gate + four ML-KEM lints, mirroring feature 13's structure. The
KEM length table lives in a **new `pqc/kem_params.rs`** (kept separate from the signature `params.rs` for
auditability and to keep the dev-02 / dev-03 touches disjoint per the conflict rules — `params.rs` is NOT
touched by feature 16).

`pqc/mod.rs` gains: a `mod kem_params;`, the four new `mod` declarations + re-exports, and a new shared
`applies_to_mlkem(cert)` helper (`Applies` iff `public_key_algorithm()? == MlKem(_)`, else
`NotApplicable`; `Err` → fail closed to `NotApplicable`).

| Lint id | What it enforces | Severity | Facade used | Notes |
|---|---|---|---|---|
| `pqc_mlkem_algorithm_known` | the SPKI OID is in the ML-KEM arc AND names a known parameter set (not an unassigned arc slot) | Error | `public_key_algorithm()` (`MlKem` variant carries `Known` vs `Unknown`) | Gate fires on any arc member (option A); this lint flags the `Unknown` case. Mirror of `pqc_algorithm_known`. |
| `pqc_mlkem_spki_parameters_absent` | the SPKI `AlgorithmIdentifier.parameters` MUST be absent | Error | `spki_algorithm_parameters_present()` (reused) | LAMPS ML-KEM profile requires absent params. Mirror of `pqc_spki_parameters_absent`. |
| `pqc_mlkem_public_key_length` | the raw encapsulation-key byte length matches the mandated length for the named set | Error | `public_key_algorithm()` + `public_key_raw_len()` (reused) + `kem_params.rs` | Message names the parameter set, expected length, actual length. `Unknown` set → no finding (isolates `pqc_mlkem_algorithm_known`). |
| `pqc_mlkem_key_usage_consistency` | a KEM key MUST NOT assert signing bits (`digitalSignature` / `keyCertSign` / `cRLSign` → Error); EE SHOULD assert `keyEncipherment` or `keyAgreement` (neither → Warn) | mixed | `key_usage()` + `is_ca()` | Inverse of `pqc_key_usage_consistency`. See Open Question 2 for the exact bit policy. |

> **No ML-KEM signature-parameters-absent lint:** an ML-KEM cert's *signature* algorithm is the **issuer's
> signing algorithm** (e.g. the ML-DSA CA), not an ML-KEM algorithm — so the signature-params-absent rule
> belongs to the signing family, not the KEM family. The existing `pqc_signature_parameters_absent` (gated
> on the SPKI being a *signature* PQC key) does not apply to an ML-KEM SPKI, and we deliberately add no
> KEM analogue. Documented in the feature so the absence is intentional, not an oversight.

### Part 3 — extend `pqc_key_usage_consistency` (dev-03)

In `crates/linter/src/lints/pqc/key_usage_consistency.rs`, extend the pure `evaluate()` to also push an
**Error** finding when the (signature-key) `KeyUsageView` asserts `data_encipherment` (bit 3),
`encipher_only` (bit 7), or `decipher_only` (bit 8) — same rationale as the existing
`keyEncipherment`/`keyAgreement` Errors (these bits are meaningless/wrong for a signature-only key). Each
finding is named with its bit. Update the file's doc comment and add `#[cfg(test)] mod tests` cases
(including a multi-finding case). The lint id, source, and gate are unchanged.

### Registry (dev-04)

Register the **four** new ML-KEM lints in `default_registry_with_now()` (append after the existing five
`pqc` lints, keeping the deterministic order the feature-06 golden test relies on). No source-helper
change (Pqc already universal). Bump the in-file count assertions **66 → 70** (5 existing pqc + 4 new
ML-KEM; parts 3 adds NO new lint — it only adds findings to an existing lint). Add a `pqc` source-filter
test confirming the new lints are filtered into every purpose. Reconcile any per-source `[pqc]` filter
count.

## Changes Overview

**crates/linter/ (production code — developer tasks 01–04)**

- `src/cert.rs` — add `PublicKeyAlg::MlKem(PqcParamSet)`; add `MLKEM_ARC_PREFIX` + `classify_mlkem_oid`
  + wire into `public_key_algorithm()`; extend `KeyUsageView` with `data_encipherment` / `encipher_only`
  / `decipher_only` and populate in `key_usage()`; classifier unit tests. (dev-01)
- `src/lints/cabf_cs/key_usage_required.rs` — additive: add the 3 new fields to the test `ku()` helper
  literal (no behaviour change). (dev-01 — same task as the struct change so the crate compiles)
- `src/lints/cabf_smime/key_usage_critical.rs` — additive test-helper field update. (dev-01)
- `src/lints/cabf_smime/key_usage_present.rs` — additive test-helper field update. (dev-01)
- `src/lints/pqc/mod.rs` — add `mod kem_params;` + the 4 ML-KEM lint module decls + re-exports + the
  shared `applies_to_mlkem` helper. (dev-02)
- `src/lints/pqc/kem_params.rs` — new ML-KEM OID/parameter-set → encapsulation-key-length table + lookup
  + unit tests. (dev-02)
- `src/lints/pqc/mlkem_algorithm_known.rs` — new. (dev-02)
- `src/lints/pqc/mlkem_spki_parameters_absent.rs` — new. (dev-02)
- `src/lints/pqc/mlkem_public_key_length.rs` — new. (dev-02)
- `src/lints/pqc/mlkem_key_usage_consistency.rs` — new. (dev-02)
- `src/lints/pqc/key_usage_consistency.rs` — part 3: extend `evaluate()` + doc + tests. (dev-03)
- `src/registry.rs` — register the 4 ML-KEM lints; bump count 66 → 70; update count/filter unit tests.
  (dev-04)

**crates/cli/ — NO production change.** `RuleSource::Pqc` already fully wired (main.rs / output.rs). The
CLI e2e for `--source pqc` on an ML-KEM cert is a tester ADD only.

**testdata/ + tests (tester — task 05)**

- `testdata/generate.sh` — append a SELF-CONTAINED ML-KEM section (the `-force_pubkey` recipe + the new
  fixtures + the version-check + the time-fragility header note). NO existing fixture regenerated.
- New ML-KEM fixtures (openssl-generated only — NEVER cert-bar): see Fixtures section.
- New integration tests `crates/linter/tests/pqc_mlkem.rs` (or extend `crates/linter/tests/pqc.rs` — the
  tester decides; if extending, it is a shared-file edit owned solely by the tester task).
- A CLI `--source pqc` e2e for an ML-KEM cert in `crates/cli/tests/output.rs` (ADD only).
- Registry count bump in `crates/linter/tests/registry.rs` if it asserts the total (66 → 70).
- Feature-06 golden snapshots: the existing golden fixtures are RSA, so the 4 new ML-KEM lints stay
  `NotApplicable` on them (self-gate) — only a new ML-KEM fixture row + the 4 extra `[pqc]` lint slots in
  any per-cert grouping change. If golden snapshots exist, regenerate them in THIS task (add to
  `touches`). Verify before implementing.

## Fixtures (openssl-generated ONLY — never cert-bar)

⚠️ **openssl capability finding (verified by the architect, OpenSSL 3.6.2):**

- ML-KEM key generation: **native** (`openssl genpkey -algorithm ML-KEM-768`).
- ML-KEM **certificate** issuance: ML-KEM keys CANNOT self-sign or sign their own CSR
  (`operation not supported for this keytype`). The working native path is: an **ML-DSA CA** signs a cert
  whose SPKI is substituted with the ML-KEM public key via **`openssl x509 -req ... -force_pubkey
  mlkem.pub.pem`** (verified: produces a valid cert with `Public Key Algorithm: ML-KEM-768` and the
  configured `Key Usage`). The dummy CSR is signed with the CA's own ML-DSA key; the ML-KEM key only ever
  appears as the forced SPKI. The clean ML-KEM fixture is therefore **openssl-native (no byte-patching)**.
- Minimum openssl: **3.5+** (verified on 3.6.2). The ML-KEM section of `generate.sh` MUST `openssl
  version`-check and fail loudly on an older openssl, mirroring the feature-13 PQC section.
- **Composite: NOT producible** by stock OpenSSL (see Open Question 1) — no composite fixtures in this
  feature.

⚠️ **Fixtures must remain the independent oracle.** Generate ALL ML-KEM fixtures with openssl, NEVER from
the user's cert-bar tool. Every committed fixture MUST have a reproducing recipe in `testdata/generate.sh`
(recipe-parity is mandatory — the `git checkout testdata/` churn trap has silently dropped recipes before;
restore with the quoted glob `git checkout -- 'testdata/*.pem'`, NEVER `git checkout -- testdata/`).

⚠️ **Pinned test clock & fixed validity windows.** Tests use `default_registry_with_now(Some(1_796_083_200))`
(TEST_NOW = 2026-12-01) / CLI `--now 1796083200`. New fixtures use a fixed validity window bracketing
TEST_NOW (align with the existing `BR_OK` horizon used by the feature-13 PQC fixtures). Document the
expiry and regenerate annually.

A **clean ML-KEM leaf** = ML-KEM-768 SPKI (params absent) + ML-DSA CA signature + correct encapsulation-key
length + `keyEncipherment` KU (no signing bits) + `CA:FALSE` + a validity window bracketing TEST_NOW.

| Fixture | shape | single intended violation |
|---|---|---|
| `pqc_mlkem_good.pem` | ML-KEM-768, params absent, correct length, `keyEncipherment` KU, CA:FALSE, valid | NONE (clean) — openssl-native |
| `pqc_mlkem_unknown_param_set.pem` | SPKI OID in the ML-KEM arc but an unassigned slot (e.g. `.4`) | `pqc_mlkem_algorithm_known` |
| `pqc_mlkem_spki_params_present.pem` | ML-KEM key with a present (NULL) SPKI `parameters` field | `pqc_mlkem_spki_parameters_absent` |
| `pqc_mlkem_bad_key_length.pem` | ML-KEM OID but an encapsulation-key length not matching the named set | `pqc_mlkem_public_key_length` |
| `pqc_mlkem_bad_key_usage.pem` | ML-KEM leaf asserting `digitalSignature` (wrong bit for a KEM key) | `pqc_mlkem_key_usage_consistency` (Error path) |

Producibility (the tester owns the per-fixture decision, like prior features):

- `pqc_mlkem_good.pem` — **openssl-native** (`-force_pubkey`); MUST NOT be byte-patched.
- `pqc_mlkem_bad_key_usage.pem` — likely **openssl-native** (set `keyUsage = digitalSignature` in the
  `-extfile` extensions; the SPKI is still ML-KEM via `-force_pubkey`).
- `pqc_mlkem_unknown_param_set.pem`, `pqc_mlkem_spki_params_present.pem`, `pqc_mlkem_bad_key_length.pem`
  — openssl follows the LAMPS profile (valid OID, absent params, correct length), so these require a
  documented **DER byte-patch** (flip an arc digit; splice a NULL into the SPKI AlgorithmIdentifier;
  truncate/pad the BIT STRING) OR, where a clean patch is infeasible, test the lint by **direct lint
  invocation** on a hand-built `Cert` (and, if truly unproducible, defer the lint+fixture together as a
  pre-approved cut, reconciling the registry/CLI counts). Document the choice per fixture in the test and
  in `generate.sh`. NOTE: byte-patching the BIT STRING length changes the SPKI but the cert is signed by
  the CA over the TBSCertificate — the patch must target the fixture's encoded bytes directly, accepting
  that the issuer signature no longer verifies (acceptable: the linter does not verify signatures; it
  lints structure). State this caveat in the recipe.

- **No fixture cascade.** All ML-KEM lints self-gate on `PublicKeyAlg::MlKem`, so they stay
  `NotApplicable` on every existing RSA/EC/ML-DSA/SLH-DSA fixture (adding zero regeneration pressure).
  The part-3 change adds findings only on a cert that already triggers `pqc_key_usage_consistency` (a PQC
  *signature* key) AND asserts one of the new bits — it cannot fire on existing clean fixtures (the
  feature-13 `pqc_mldsa_good` / `pqc_slhdsa_good` leaves assert only `digitalSignature`). The tester MUST
  confirm both directions in the no-cascade test.

## Dependencies

**None new.** The ML-KEM OID-arc recognition reuses the existing `with_parsed` / OID-string path; the
encapsulation-key length reuses the existing `public_key_raw_len()`; the SPKI params predicate reuses the
existing `spki_algorithm_parameters_present()`; the three new KeyUsage bits use x509-parser 0.18's
`data_encipherment()` / `encipher_only()` / `decipher_only()` (verified present in the installed
0.18.1). The KEM length table is a small in-module constant. If the developer finds a new crate genuinely
necessary, it MUST be documented, justified in the task, added to `crates/linter/Cargo.toml`, and
`cargo audit`-checked (CLAUDE.md).

## Registry count delta

- Baseline (post-feature-13/15): **66** lints.
- Feature 16 adds **4** ML-KEM lints. Part 3 adds **0** lints (extends an existing one).
- **New total: 70.** Update `registry.rs` in-file asserts (66 → 70), the
  `crates/linter/tests/registry.rs` integration count (if it asserts the total), and any per-`[pqc]`
  filter count (5 → 9 pqc lints).

## Quality gates

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings` (also `cargo test -p linter --features serde` — the new
  `PublicKeyAlg::MlKem` variant must serialise under the existing `serde` derive)
- `cargo test`

## Escalations (Phase 1.5 gate — flag to the user)

1. **Composite PQC+classical is deferred to the backlog** (Open Question 1). Reason: stock OpenSSL 3.6.2
   cannot mint a composite SPKI/cert, and the IETF composite drafts still carry provisional OIDs, so
   there is no honest openssl-native or byte-patch fixture path that respects the "OpenSSL-only, never
   cert-bar, recipe-parity" constraint. The plan ships parts 1 (ML-KEM) + 3 (KU gap) and reserves
   composite in "Future". **Confirm this scope cut is acceptable before implementation.**

All other open questions are resolved within this plan and do not require the user.

## Future (explicitly out of scope — reserved, not specced)

- **Composite PQC + classical signatures / KEM** (`draft-ietf-lamps-pq-composite-sigs` / `-kem`) —
  blocked on (a) OpenSSL composite support or a stable hand-crafted DER recipe and (b) the drafts
  reaching RFC with non-provisional OIDs. The composite SPKI/signature is a SEQUENCE of two component
  keys/signatures; a future feature adds a composite OID arc classifier, a `composite_algorithm_known`
  lint, and (if feasible) component-consistency lints. Reserved.
- **`pqc_mlkem_algorithm_known` reserved-slot coverage** is handled (option A gate), but a richer
  ML-KEM-in-CA policy lint (a KEM key in a CA cert is structurally odd) is reserved.
- **Hybrid TLS named-group / non-X.509 PQC usages** — out of scope (this linter is X.509-only).

## Sequencing (batches)

- **Batch A:** dev-01 (`cert.rs`: `MlKem` variant + `classify_mlkem_oid` + `KeyUsageView` 3 bits;
  additive test-helper updates in the 3 cabf lint files). depends_on: none.
- **Batch B:** dev-02 (`pqc/mod.rs` + `pqc/kem_params.rs` + the 4 `mlkem_*` lint files) AND dev-03
  (`pqc/key_usage_consistency.rs` part-3 extension) — **disjoint touches**, so they CAN run in parallel.
  Both depend_on dev-01.
- **Batch C:** dev-04 (`registry.rs` register + count/filter tests). depends_on dev-02 (needs the lint
  types re-exported) AND dev-03 (count is verified after both land; dev-03 adds 0 lints but the registry
  test asserts behaviour stability).
- **Batch D:** tester-05 (ML-KEM fixtures + `generate.sh` + integration tests + CLI e2e + registry
  integration count + golden regen). depends_on dev-04.

### Conflict Audit

- `cert.rs` — dev-01 only.
- `cabf_cs/key_usage_required.rs`, `cabf_smime/key_usage_critical.rs`, `cabf_smime/key_usage_present.rs`
  — dev-01 only (additive test-helper field updates, bundled with the struct change).
- `pqc/mod.rs` — dev-02 only. `pqc/kem_params.rs` + the 4 `mlkem_*.rs` — dev-02 only.
- `pqc/key_usage_consistency.rs` — dev-03 only. (Disjoint from dev-02's `pqc/mod.rs`? dev-02 edits
  `pqc/mod.rs` to add module decls; dev-03 edits `pqc/key_usage_consistency.rs`. These are different
  files → disjoint. The `key_usage_consistency` module is ALREADY declared in `mod.rs` from feature 13,
  so dev-03 needs no `mod.rs` edit. ✓ parallel-safe.)
- `registry.rs` — dev-04 only.
- `testdata/*`, `crates/linter/tests/*`, `crates/cli/tests/*` — tester-05 only.
- No two tasks in the same batch share a `touches` file. dev-02 ∥ dev-03 verified disjoint above.
