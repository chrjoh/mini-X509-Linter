---
agent: developer
seq: 2
title: ChainLint trait + chain pass/registry + build_chain construction + RuleSource::Chain + 7 always-on chain lints + verify module + chain_signature_valid + verify feature
status: done
touches:
  - crates/linter/Cargo.toml
  - crates/linter/src/lib.rs
  - crates/linter/src/source.rs
  - crates/linter/src/chain.rs
  - crates/linter/src/lints/mod.rs
  - crates/linter/src/lints/chain/mod.rs
  - crates/linter/src/lints/chain/subject_issuer_dn_match.rs
  - crates/linter/src/lints/chain/not_in_order.rs
  - crates/linter/src/lints/chain/issuer_not_in_chain.rs
  - crates/linter/src/lints/chain/aki_ski_match.rs
  - crates/linter/src/lints/chain/issuer_is_ca.rs
  - crates/linter/src/lints/chain/path_len_respected.rs
  - crates/linter/src/lints/chain/validity_nested.rs
  - crates/linter/src/lints/chain/subject_signature.rs
  - crates/linter/src/lints/chain/verify.rs
depends_on:
  - developer-01-cert-facade-raw-bytes-accessors
---

# Task: ChainLint trait, chain pass/registry, build_chain construction, Chain source, 7 always-on chain lints, the verify module + chain_signature_valid, and the verify feature

## Goal

Add the linter's first cross-certificate reasoning, kept ENTIRELY ADDITIVE so the existing per-cert
`Lint` / `Registry` / `default_registry()` path is byte-for-byte unchanged. Introduce a `ChainLint`
trait + a separate chain pass + a **`build_chain` construction/normalization step** (order-independent)
+ a new `RuleSource::Chain` source + the 7 always-registered dependency-free chain lints (2
construction-driven: the REDEFINED `chain_subject_issuer_dn_match` structural-integrity verdict +
`chain_not_in_order` Notice; plus `chain_issuer_not_in_chain` Notice; plus 4 structural link lints:
AKI/SKI, issuer-is-CA, path-len, validity-nested) + an 8th cryptographic lint `chain_signature_valid`
(behind a new `verify` cargo feature, implemented via an isolated `verify` module using
`ring`/`fips204`/`fips205`).

## Files Owned (conflict scope)

- `crates/linter/Cargo.toml` (add the `verify` feature + `ring`/`fips204`/`fips205` optional deps)
- `crates/linter/src/lib.rs` (declare/re-export the chain trait + types; `Lint` path unchanged)
- `crates/linter/src/source.rs` (add `RuleSource::Chain`)
- `crates/linter/src/chain.rs` (NEW — chain trait, registry, report/outcome types, the chain-pass walk)
- `crates/linter/src/lints/mod.rs` (`pub mod chain;`)
- `crates/linter/src/lints/chain/*` (the module + 7 always-on lint files — incl. `not_in_order.rs` and
  `issuer_not_in_chain.rs` — + `verify.rs` + `subject_signature.rs`)

Does NOT touch `cert.rs` (task 01), `registry.rs` / `cli/*` (task 03), or `finding.rs`.
**Decision (per plan Open Decision 5): the chain trait, `ChainRegistry`, `default_chain_registry()`,
`ChainLinkReport`, and `ChainLinkOutcome` all live in the NEW `src/chain.rs`** — this keeps `registry.rs`
and `finding.rs` entirely out of this feature's scope on the linter side and isolates the chain pass.
`lib.rs` only `mod chain;` + re-exports them.

## What to Do

### 0. `crates/linter/Cargo.toml` — the `verify` feature + crypto deps

Add the optional crypto deps and a `verify` feature gating them (NO openssl/aws-lc, NO cmake):

```toml
[dependencies]
ring    = { version = "0.17", optional = true }  # classical RSA/ECDSA/Ed25519 (already in workspace via fetch)
fips204 = { version = "0.4",  optional = true }  # ML-DSA  (FIPS 204), pure Rust, pre-1.0
fips205 = { version = "0.4",  optional = true }  # SLH-DSA (FIPS 205), pure Rust, pre-1.0

[features]
verify = ["dep:ring", "dep:fips204", "dep:fips205"]
```

- Pin `ring` to the version already resolved in the workspace `Cargo.lock` (used by `fetch`/`rcgen`);
  caret-pin `fips204`/`fips205` as `"0.4"`. Verified on crates.io: `fips204 = "0.4.6"`,
  `fips205 = "0.4.1"`.
- Keep `verify` OFF by default (the core crate stays dependency-light); the CLI enables it (task 03).
- Run `cargo audit` after adding (A03); flag advisories.

### 1. `source.rs` — new source

Add `RuleSource::Chain` (serde `snake_case` → `chain`) at the **END** of the enum, after `Hygiene`, so
it reads `[Rfc5280, Pqc, CabfBr, CabfEv, CabfCs, CabfSmime, Hygiene, Chain]`. Update the type-doc
`--source` vocabulary listing to include `chain`. Document that `chain` is the only cross-certificate
source and only surfaces under `--chain` with ≥2 certs.

### 2. `src/chain.rs` — the chain pass

- `pub trait ChainLint` (object-safe, deterministic, network-free, panic-free):
  - `fn id(&self) -> &'static str;`
  - `fn source(&self) -> RuleSource;` (always `RuleSource::Chain`)
  - `fn check(&self, subject: &Cert, issuer: &Cert) -> Vec<Finding>;` — empty Vec = link passes (the
    established "empty = pass" convention; a lint that cannot evaluate a link returns empty —
    "pass-by-vacuity"). Reuse the existing `Finding` / `Severity` verbatim. **No `Applicability`** in
    the chain pass (documented rationale in plan.md).
  - For `chain_path_len_respected`, the lint needs the issuer's depth in the chain. Provide this
    cleanly WITHOUT making the trait non-pairwise: pass the issuer's chain index to the lint via the
    engine. Recommended shape: add a second trait method with a default impl, OR carry the index in a
    small context arg, e.g. `fn check_with_depth(&self, subject, issuer, issuer_index: usize) ->
    Vec<Finding> { self.check(subject, issuer) }` and have only `path_len_respected` override it. The
    developer finalizes the exact signature; keep the trait object-safe and keep the common case
    (`check`) the one-line shape every other lint implements. Document the chosen approach.
- `pub struct ChainLinkOutcome { pub lint_id: &'static str, pub source: RuleSource, pub findings:
  Vec<Finding> }` (derive `Debug, Clone, PartialEq, Eq`; `Serialize` under the `serde` feature,
  rendering `{ lint_id, source, findings }` — NO `applicability`).
- `pub struct ChainLinkReport { pub subject_index: usize, pub issuer_index: usize, pub outcomes:
  Vec<ChainLinkOutcome> }` (same derives; the engine stays label-free — the CLI builds
  `Certificate N → Certificate N+1` from the indices).
- **`build_chain(&[Cert]) -> (OrderedChain, Vec<ConstructionDiagnostic>)`** (Refinement 1) — the
  construction/normalization step, called by `run` BEFORE the pairwise walk:
  - **Linkage rule:** cert A is issued by cert B iff `A.issuer_name_der() == B.subject_name_der()`
    (byte-exact, task 01). When BOTH `A.authority_key_id_bytes()` and `B.subject_key_id_bytes()` are
    `Some`, they MUST also be equal (disambiguates several certs sharing a Name DER). When either is
    absent, Name-DER match alone stands. Any accessor `Err` → that cert yields no candidate edge
    (degrade, never panic).
  - **Algorithm (deterministic):** (1) compute candidate issuers per cert (excluding self, except a
    self-signed top recognized as the anchor); (2) the leaf is the cert no other cert links to; (3) walk
    leaf→issuer→…→top following the confirmed edge; (4) **stable tie-breaks by ascending ORIGINAL input
    index** — never map-iteration/hash order.
  - **`ConstructionDiagnostic` enum** covering: `Disorder` (complete chain, wrong input order →
    `chain_not_in_order` Notice), `MissingMiddleLink` / `Unlinkable` / `Cycle`
    (→ `chain_subject_issuer_dn_match` Error), `Fork` (>1 candidate issuer → `chain_subject_issuer_dn_match`
    Warn, after the lowest-index tie-break), `MissingTopIssuer` (root absent → `chain_issuer_not_in_chain`
    Notice). Document each failure mode in the `build_chain` doc comment.
  - The `OrderedChain` carries the built leaf→top order (indices into the input slice) so the engine and
    CLI can map back to `Certificate N` labels.
- `pub struct ChainRegistry { lints: Vec<Box<dyn ChainLint>> }` with:
  - `pub fn run(&self, certs: &[Cert]) -> Vec<ChainLinkReport>` — returns EMPTY for `certs.len() < 2`;
    otherwise calls `build_chain`, maps the construction diagnostics → construction-level findings
    (`chain_subject_issuer_dn_match`, `chain_not_in_order`, `chain_issuer_not_in_chain`), then for the
    built order's N-1 adjacent links runs the pairwise link lints, producing one link report per built
    link (`subject_index`/`issuer_index` are indices into the BUILT order; record enough to recover the
    original `Certificate N` label deterministically). Construction findings attach at their documented
    home (the developer finalizes: a chain-level slot, or on the relevant cert/link — keep
    snapshot-stable; see plan Open Decisions 11/14).
- `pub fn default_chain_registry() -> ChainRegistry` — registers the 7 always-on chain lints (the 2
  construction-driven lints + `chain_issuer_not_in_chain` + the 4 structural link lints, in the plan
  table order) and `chain_signature_valid` under `#[cfg(feature = "verify")]` LAST. So the registry holds
  **7 without `verify`, 8 with `verify`**. (Construction-driven lints may be registry entries whose
  findings the engine injects from `build_chain` diagnostics — see plan Open Decision 11; keep them
  counted and ordered.)
- `#[cfg(test)] mod tests`: 7 lints present by default (assert no `chain_signature_valid` without
  `verify`); `#[cfg(feature = "verify")]` assertion that the 8th is present and is `RuleSource::Chain`;
  all `RuleSource::Chain`; `run` empty for 0/1 cert. **`build_chain` tests:** already-ordered chain →
  built order == input + no `chain_not_in_order`; shuffled chain → reordered + exactly
  `chain_not_in_order`; missing-middle → Error; fork → Warn with the deterministic lowest-index pick;
  cycle → Error and terminates; missing-top → `chain_issuer_not_in_chain` Notice; AKI/SKI disambiguation
  picks the AKI-matching issuer; running twice on the same shuffled input is byte-identical.

### 3. `lib.rs`

- `pub mod chain;` and re-export `ChainLint`, `ChainRegistry`, `default_chain_registry`,
  `ChainLinkReport`, `ChainLinkOutcome` (and the construction types — `build_chain` /
  `ConstructionDiagnostic` / `OrderedChain` — if they need to be public for the CLI/tests; keep internal
  ones `pub(crate)`). Keep the existing `Lint` trait, `Registry`, `default_registry`, and all current
  re-exports UNCHANGED. Extend the crate-level doc to mention the separate chain pass + the order-
  independent construction step.

### 4. `src/lints/mod.rs` + `src/lints/chain/mod.rs`

- `pub mod chain;` in `lints/mod.rs`.
- `lints/chain/mod.rs`: declarations + re-exports of the 7 always-on chain-lint types
  (unconditional — the 2 construction lints + `issuer_not_in_chain` + the 4 link lints), PLUS
  `#[cfg(feature = "verify")] pub mod verify;` and `#[cfg(feature = "verify")] pub mod subject_signature;`
  with the conditional re-export of the `chain_signature_valid` lint type. Optionally a small shared
  helper module (keep small).

### 5. The 7 always-registered chain lints (one small file each, doc comment cites the RFC 5280 clause, `#[cfg(test)]`)

**Construction-driven (sourced from `build_chain` diagnostics — see §2):**

| File | id | reports | Severity |
|---|---|---|---|
| `subject_issuer_dn_match.rs` *(REDEFINED)* | `chain_subject_issuer_dn_match` | structural-integrity verdict: missing-middle-link / unlinkable-extra / cycle (Error), fork (Warn). NOT the old file-adjacent DN compare. | Error / Warn |
| `not_in_order.rs` *(NEW)* | `chain_not_in_order` | Notice: complete chain but input order differed; reordered for analysis. Message: "certificates were not in leaf-to-root order; reordered for analysis". | Notice |
| `issuer_not_in_chain.rs` *(NEW)* | `chain_issuer_not_in_chain` | Notice on the top cert: its issuer (root) is absent. Message: "issuer (e.g. root) not present in the presented chain; trust to a root is verified separately by the connection verdict". | Notice |

**Pairwise link lints (over the BUILT adjacent `(subject, issuer)` links):**

| File | id | enforces (subject → issuer link) | Severity | pass-by-vacuity |
|---|---|---|---|---|
| `aki_ski_match.rs` | `chain_aki_ski_match` | when `subject.authority_key_id_bytes()` is `Some` AND `issuer.subject_key_id_bytes()` is `Some`, the two MUST be equal (§4.2.1.1) | Error | subject has no AKI keyId OR issuer has no SKI |
| `issuer_is_ca.rs` | `chain_issuer_is_ca` | issuer `basic_constraints().is_ca` AND `key_usage().key_cert_sign` (§4.2.1.9/§4.2.1.3) | Error | never (Err → no finding) |
| `path_len_respected.rs` | `chain_path_len_respected` | intermediate CAs below a CA's position MUST NOT exceed its `pathLenConstraint` (§4.2.1.9) — uses the issuer index from the engine | Error | issuer not a CA, or no `pathLenConstraint` |
| `validity_nested.rs` | `chain_validity_nested` | `issuer.not_before() <= subject.not_before()` AND `subject.not_after() <= issuer.not_after()` | Warn | never (Err reading a bound → no finding) |
| `subject_signature.rs` *(`#[cfg(feature = "verify")]`, see §6)* | `chain_signature_valid` | subject signature over `tbs_der()` verifies against `issuer.issuer_spki_bytes()` (§4.1.1.3) | Error (fail) / Notice (unsupported) | accessor `Err` → no finding |

- Each lint message names the offending value (the mismatched DN summary / keyid hex / non-CA issuer /
  pathLen value + actual depth / the validity bound). For the DN/keyid lints, do NOT dump raw bytes in
  the message — render a short hex/`subject_rfc4514`-style summary for human readability while the
  COMPARISON uses the raw bytes.
- All comparisons / reads degrade gracefully: any accessor `Err` → no finding for that link (never
  panic, never abort the pass). Document the degradation per lint.
- `chain_validity_nested` is clock-independent: it compares the two certs' own `ASN1Time` bounds, never
  "now".

### 6. The verify module + `chain_signature_valid` (BOTH `#[cfg(feature = "verify")]`)

#### `src/lints/chain/verify.rs` — isolated crypto dispatch (contains ALL crypto-crate usage)

- Expose a pure function returning a small enum, e.g.:
  ```text
  pub(crate) enum VerifyOutcome { Verified, Failed, Unsupported }
  pub(crate) fn verify_signature(
      sig_alg_oid: &Oid, tbs_der: &[u8], signature: &[u8], issuer_spki: &[u8],
  ) -> VerifyOutcome
  ```
  (adapt the OID type to whatever `signature_algorithm_oid()` returns from task 01.)
- Map the signature-algorithm OID → backend per the supported matrix:
  - **`ring`** — RSA PKCS#1 v1.5 + SHA-256/384/512; ECDSA P-256+SHA-256, P-384+SHA-384; Ed25519.
  - **`fips204`** — ML-DSA-44/65/87 (FIPS 204).
  - **`fips205`** — SLH-DSA SHA2 + SHAKE variants (FIPS 205).
- Any OID NOT in the matrix → `VerifyOutcome::Unsupported` (fail-OPEN — NEVER `Failed` for an algorithm
  we cannot check). Confirm against the chosen crate versions whether RSA-PSS / ECDSA P-521 are
  verifiable via `ring`; if not, they map to `Unsupported`. Document the final supported set.
- Be panic-free: malformed/truncated inputs (bad spki, wrong-length signature) → `Failed` or
  `Unsupported` (document which), never a panic.
- `#[cfg(test)] mod tests`: supported OID dispatches; a known-good triple → `Verified`; a corrupted
  signature → `Failed`; an unknown OID → `Unsupported`. Pull bytes from committed fixtures (task 04) or
  small in-file vectors — do NOT hand-author key material.

#### `src/lints/chain/subject_signature.rs` — the `chain_signature_valid` lint (thin)

- A `ChainLint` (id `chain_signature_valid`, `RuleSource::Chain`). In `check(subject, issuer)`:
  read `subject.tbs_der()`, `subject.signature_value_bytes()`, `subject.signature_algorithm_oid()`,
  and `issuer.issuer_spki_bytes()`; any `Err` → return empty (graceful degradation, no finding).
- Call `verify::verify_signature(...)` and map:
  - `Verified` → `vec![]` (pass);
  - `Failed` → one `Finding { Error, "signature does not verify against the issuer's public key" }`
    (include a short alg/OID hint, NOT raw bytes);
  - `Unsupported` → one `Finding { Notice, "signature not verified: unsupported algorithm <oid>" }`.
- Doc comment cites RFC 5280 §4.1.1.3 and states clearly this is signature verification ONLY (not
  trust/path validation, not revocation). Note the `fips204`/`fips205` pre-1.0/unaudited maturity caveat
  (acceptable for a verifier over PUBLIC cert data).
- **Self-signed root self-link (Open Decision 8):** if implementing, verify a self-signed root's own
  signature by treating it as its own issuer for the top link; keep it deterministic. If it adds
  non-trivial engine complexity, omit it for v1 and leave a `// TODO` + note.
- `#[cfg(test)] mod tests`: with `verify` on, a valid (classical) triple passes; a corrupted one →
  Error; an unsupported OID → Notice. (Cross-cert fixtures land in task 04.)

## Acceptance Criteria

- [ ] `ChainLint` trait + `ChainRegistry` + `default_chain_registry()` + `build_chain` +
      `ChainLinkReport` / `ChainLinkOutcome` live in `src/chain.rs`, re-exported from `lib.rs`;
      object-safe; deterministic.
- [ ] `build_chain` links by Name-DER (+ AKI/SKI disambiguation), reorders shuffled bundles
      deterministically (stable input-index tie-breaks), and emits the disorder / missing-middle /
      unlinkable / fork / cycle / missing-top diagnostics; documented failure modes; never panics.
- [ ] `RuleSource::Chain` added at the END of the enum (serde `chain`); type-doc updated.
- [ ] The existing `Lint` trait, `Registry`, `default_registry`, `*_sources()` helpers, `finding.rs`,
      and ALL per-cert paths are UNCHANGED.
- [ ] All 7 always-on chain lints implemented (the redefined `chain_subject_issuer_dn_match`,
      `chain_not_in_order`, `chain_issuer_not_in_chain`, + the 4 link lints), `RuleSource::Chain`,
      deterministic registration order, each with a doc comment citing its RFC 5280 clause and a
      `#[cfg(test)] mod tests`. The redefined `chain_subject_issuer_dn_match` reflects the
      structural-integrity verdict, NOT the old file-adjacent compare.
- [ ] `verify` cargo feature added gating `ring`/`fips204`/`fips205`; `verify.rs` (OID→backend dispatch,
      `VerifyOutcome`, panic-free, fail-open on unknown OID) and `subject_signature.rs`
      (`chain_signature_valid`: Verified→pass, Failed→Error, Unsupported→Notice) both
      `#[cfg(feature = "verify")]`; `default_chain_registry()` registers the 8th only under `verify`.
- [ ] Registry holds 7 lints without `verify`, 8 with `verify` (both asserted).
- [ ] `run` returns empty for <2 certs; builds the chain then reports over the BUILT order; mere disorder
      yields only `chain_not_in_order`; missing root yields only `chain_issuer_not_in_chain`;
      pass-by-vacuity rules honored.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde` and
      `--features "serde verify"`); `cargo fmt --check`; `cargo audit` run on the new deps.

## Notes / Dependencies

- Depends on task 01's accessors (incl. the TBS/signature/SPKI/OID ones). Blocks task 03 (CLI wiring)
  and task 04 (tests).
- New crates `ring` + `fips204` + `fips205` — ALL pure-Rust, NO openssl/aws-lc, NO cmake — behind the
  `verify` feature only. `cargo audit` them (A03). The 7 always-on lints + `build_chain` + the chain engine remain
  dependency-free; verification is strictly additive and feature-gated.
- Keep the chain pass entirely separate from the per-cert engine — the additive design is the central
  correctness property (task 04 tests it). Keep ALL crypto in `verify.rs` so the deps are contained.
