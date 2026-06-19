# Feature: Chain-Aware Lints (leaf → issuer → root structural checks)

## Overview

Add the linter's first **chain-aware** lints: rules that reason ACROSS the certificates in a chain
(a leaf, its intermediate(s), and the root) instead of inspecting a single certificate in isolation.
Today **every** lint is per-cert: the `Lint` trait sees exactly one `Cert`, and the CLI's `--chain`
mode (feature 14) parses a PEM bundle into a `Vec<Cert>` and lints **each cert independently** in
`run_chain` (`crates/cli/src/main.rs`), labelling them `Certificate 1 (leaf)`, `Certificate 2`, ….
There are currently NO lints that look at more than one certificate; the README's
[Scope & limitations] calls this out as a deliberate non-goal ("Each certificate is linted
independently … there are no chain-aware lints", `README.md:401`,`:518`). **This feature flips that
non-goal** for a curated set of *structural* chain checks.

This feature wires in:

- a new **`ChainLint`** trait + a separate **chain pass** that runs over the ordered chain, kept
  entirely **additive** so the existing per-cert `Lint` / `Registry` path is UNCHANGED;
- a **chain-construction / normalization step** (`build_chain`) that, BEFORE the pairwise lint pass,
  links each cert to its issuer by byte-exact issuer/subject Name-DER matching (confirmed by AKI/SKI
  when both present) and produces an ordered leaf→…→top sequence — so a complete-but-shuffled bundle is
  reordered (a **Notice**, `chain_not_in_order`) rather than throwing false Errors, while genuinely
  broken sets (missing middle link, unlinkable/extra cert, fork, cycle) are reported as Error/Warn;
- a new **`RuleSource::Chain`** source (wire string `chain`, lint-id prefix `chain_*`) — a NEW source
  so `--source chain` grouping stays clean and the existing per-cert filter counts are untouched;
- a curated set of **6** chain lints under `crates/linter/src/lints/chain/`: **5 dependency-free
  structural** checks plus **1 cryptographic signature-verification** check
  (`chain_signature_valid`);
- modest read-only facade work in `cert.rs`: the **raw AKI keyIdentifier bytes**, the **raw SKI
  bytes**, **raw subject/issuer name DER** accessors (for byte-exact matching), and the **raw TBS
  DER**, **signature value bytes + signature-algorithm OID**, and **issuer SubjectPublicKeyInfo /
  public-key bytes** (for signature verification) — current accessors are only booleans/presence and
  lossy string DNs;
- a small isolated **`verify` module** (`crates/linter/src/lints/chain/verify.rs`) that maps a
  signature-algorithm OID to the right pure-Rust backend (`ring` for classical, `fips204`/`fips205`
  for PQC) and returns `Verified | Failed | Unsupported`;
- a new optional **`verify` cargo feature** on `crates/linter` that gates `chain_signature_valid` and
  its crypto dependencies — **enabled by default by the CLI** so `mini-x509-lint --chain` verifies out
  of the box, while library users can opt out to keep a dependency-light build;
- CLI/output wiring so chain lints surface as a dedicated chain-level section (text) and a top-level
  `chain` array (JSON), running over **BOTH** input shapes that present a real chain: a `--chain` file
  bundle (≥2 certs) AND the **`--from-host` presented chain** (leaf + intermediates the `fetch` crate
  captures) — the `[chain]` section / chain JSON appears for `--from-host` too, after the leaf report
  and the connection verdict;
- new openssl-generated chain fixtures (a clean valid chain + one violating chain per structural lint,
  plus a valid classical chain, a valid PQC chain, a bad-signature chain, and — if expressible — an
  unsupported-algorithm case).

**Signature verification is INCLUDED in this feature** using a **pure-Rust** crypto stack (NO
openssl / aws-lc, NO cmake): `ring` for classical (RSA / ECDSA / Ed25519, already in the workspace via
`crates/fetch`) and the pure-Rust `fips204` (ML-DSA / FIPS 204) + `fips205` (SLH-DSA / FIPS 205) crates
for PQC. The verification lint and its crypto deps sit behind the `verify` cargo feature so the default
*library* build stays dependency-light; the **CLI enables `verify` by default**. This is **signature
verification only** — NOT trust/path validation, NOT revocation.

## Requirements

- **A `ChainLint` trait** sees the ordered chain (or an adjacent subject→issuer pair) and returns
  findings attached to a link. Object-safe, deterministic, network-free, panic-free. The existing
  per-cert `Lint` trait, `Registry`, and `default_registry()` path are byte-for-byte UNCHANGED.

- **A new `RuleSource::Chain`** (serde `chain`). Chain lints are **structural / purpose-independent**:
  they run under all purposes and are NOT folded into the per-purpose `*_sources()` helpers (those
  gate the *per-cert* pass). The `--source chain` token, `SOURCE_ORDER`, and `ALL_SOURCES` learn the
  new source; the per-cert filter counts are untouched.

- **Chain lints run on a real chain** — when there are ≥2 presented certs. Two entry points feed the
  chain pass: a `--chain` PEM bundle (file input), AND the `--from-host` presented chain (leaf +
  intermediates captured by `fetch`). On single-cert input (one-cert file, or a host that presents only
  a leaf), and on any default (no `--chain`, no `--from-host`) single-cert file run, the chain pass does
  not execute and output is byte-for-byte UNCHANGED (text and JSON).

- **The chain is BUILT, not assumed.** Before the pairwise lint pass, a `build_chain(&[Cert])` step
  links each cert to its in-bundle issuer by byte-exact issuer/subject Name-DER match (confirmed by
  AKI/SKI when both present) and emits an ordered leaf→…→top sequence plus construction diagnostics.
  Mere disorder (a complete chain in the wrong file order) is a **Notice** (`chain_not_in_order`), not
  an Error: the link checks then run over the REORDERED chain so disorder alone produces no false
  Errors. A genuinely broken set (missing middle link, unlinkable/extra cert, fork, cycle) is reported
  as Error/Warn. A missing issuer at the TOP (the root simply absent — normal for `--from-host`) is NOT
  an error; it is a **Notice** (`chain_issuer_not_in_chain`). The construction is deterministic (stable
  tie-breaks) so output and snapshots are stable.

- **Findings attach to a link**, labelled by the adjacent pair, e.g. `Certificate 1 → Certificate 2`
  (subject → alleged issuer), reusing the same `Certificate N` numbering the per-cert chain report
  already uses (`chain_label`, `crates/cli/src/main.rs:481`). The labels follow the BUILT order, not
  the raw input order (the `chain_not_in_order` Notice records that a reordering occurred).

- **Five structural lints stay dependency-free.** The five structural chain lints are implementable
  with the existing `Cert` facade plus the new raw-bytes accessors (task 01) — no crypto crate. They
  are always registered, independent of the `verify` feature.

- **One signature-verification lint behind the `verify` feature.** `chain_signature_valid` verifies
  each link's signature against the issuer's public key using a pure-Rust crypto stack
  (`ring` + `fips204` + `fips205`). It is gated by the `verify` cargo feature: when `verify` is OFF the
  lint is simply NOT registered (the other seven are unaffected); when ON it is the 8th chain lint. The
  CLI enables `verify` by default.

- **Signature-verification policy is fail-OPEN on unsupported algorithms.** Verify FAILS → `Error`;
  verify SUCCEEDS → pass (empty findings); algorithm not in the supported matrix → `Notice` (never a
  false `Error` for an algorithm we cannot check). See *Architecture → `chain_signature_valid`*.

- **Graceful degradation.** Any accessor `Err` on any cert in the chain must degrade to "cannot
  evaluate this link" (no finding, or a single documented Notice) — never a panic and never an
  aborted chain pass. For `chain_signature_valid`, an accessor `Err` (missing TBS/signature/SPKI bytes)
  degrades to no finding, exactly like the structural lints.

## Architecture

### The chain-pass engine extension (additive; the per-cert path is untouched)

Today a lint is `Lint { id, source, applies(&Cert), check(&Cert) -> Vec<Finding> }`, run by
`Registry::run` / `run_filtered`. Chain reasoning does not fit that shape (it needs ≥2 certs), and we
must NOT perturb the existing path. The chosen design is a **separate trait + separate pass**:

```text
/// A rule that reasons across adjacent links of an ordered certificate chain.
pub trait ChainLint {
    fn id(&self) -> &'static str;          // stable, e.g. "chain_subject_issuer_dn_match"
    fn source(&self) -> RuleSource;        // always RuleSource::Chain
    /// Evaluate `subject` against its alleged issuer. Empty Vec = link passes.
    fn check(&self, subject: &Cert, issuer: &Cert) -> Vec<Finding>;
}
```

**Per-adjacent-pair shape (RECOMMENDED, chosen).** Each chain lint inspects ONE adjacent
`(subject, issuer)` pair. The engine walks the ordered chain `[c0 (leaf), c1, …, cN (root)]` and, for
each adjacent pair `(ci, ci+1)`, runs every chain lint, producing a `ChainLinkReport` per link. This
keeps each lint trivially testable (two certs in, findings out), keeps the trait object-safe and
deterministic, and matches every v1 lint (all are pairwise). A whole-chain `check(&[Cert])` shape was
considered and **rejected for v1** (only `chain_path_len_respected` is arguably non-pairwise, and it
is expressible pairwise by tracking depth in the engine — see that lint's note). The trait is reserved
as a documented Future if a genuinely non-pairwise rule (e.g. name-constraints propagation) is added.

- **Reuse `Finding`/`Severity` verbatim** — chain findings ARE `Finding`s (severity + message), so
  the whole text/JSON severity machinery (`--min-severity`, `--fail-on`, severity counts) works
  unchanged. No new finding type is needed for the *body*; only the *link attachment* is new.

- **A `ChainLinkOutcome`** (mirroring `LintOutcome`) attaches a lint's identity + findings to a link.
  Proposed (developer finalizes exact field names):

  ```text
  pub struct ChainLinkOutcome { lint_id: &'static str, source: RuleSource, findings: Vec<Finding> }
  ```

  There is **no `Applicability`** in the chain pass: a chain lint that has nothing to say returns an
  empty `Vec<Finding>` (the established "empty = pass" convention). A lint that cannot meaningfully
  evaluate a link (e.g. the subject has no AKI for `chain_aki_ski_match`) ALSO returns empty — it is a
  pass-by-vacuity, documented per lint. (Rationale: adding `Applicability` to the chain pass would
  duplicate machinery for no surfaced benefit, since chain lints self-skip by returning empty.)

- **A `ChainRegistry` + `default_chain_registry()`** alongside `default_registry()`, holding
  `Vec<Box<dyn ChainLint>>`. It exposes one entry point:

  ```text
  pub fn run(&self, chain: &[Cert]) -> Vec<ChainLinkReport>
  // where ChainLinkReport = { subject_index: usize, issuer_index: usize, outcomes: Vec<ChainLinkOutcome> }
  ```

  `run` returns an EMPTY vec for a chain of < 2 certs (no links). For N certs it produces N-1 link
  reports in chain order. A `run_filtered(&chain, &[RuleSource])` is **NOT needed** in v1 (only one
  chain source exists); the CLI filters at the source level before deciding to run the chain pass.
  This is documented as a Future extension point.

- **Chain construction precedes the lint pass (order-independent).** The chain pass NO LONGER assumes
  leaf-first input. Before running the pairwise lints, the engine BUILDS the ordered chain from the
  presented certs (see *Chain construction / normalization* below), then runs the link checks over the
  built order. This makes the pass order-independent: a complete-but-shuffled bundle is reordered and
  linted clean (only a `chain_not_in_order` Notice), instead of throwing false Errors from comparing
  non-adjacent file pairs. Genuinely broken sets surface as construction diagnostics → Error/Warn.

### Chain construction / normalization (`build_chain`)

A `build_chain(&[Cert]) -> (OrderedChain, Vec<ConstructionDiagnostic>)` helper lives in the chain
module (`src/chain.rs`) and is consumed by the chain pass before the pairwise walk. The per-cert path
is untouched.

**Linkage rule.** Cert *A* is issued by cert *B* iff `A.issuer_name_der() == B.subject_name_der()`
(byte-exact RFC 5280 §4.1.2.4/§4.1.2.6 Name match), using task-01's `issuer_name_der` /
`subject_name_der`. When BOTH `A.authority_key_id_bytes()` and `B.subject_key_id_bytes()` are present,
they MUST also be equal for the link to be confirmed (this DISAMBIGUATES when several certs share a
Name DER — e.g. cross-signed/rolled-over CAs). When either AKI or SKI is absent, the Name-DER match
alone stands (pass-by-vacuity, matching `chain_aki_ski_match`). Any accessor `Err` → that cert
contributes no candidate edge (degrade, never panic).

**Algorithm (deterministic).**
1. For each cert, compute its candidate issuers among the OTHER certs by the linkage rule above
   (excluding a cert as its own issuer EXCEPT for a self-signed top — subject DN == issuer DN with AKI
   absent or == own SKI — which is recognized as the chain anchor, not a cycle).
2. Identify the **leaf**: the cert that is not an issuer of any other cert in the set (no other cert
   links to it). If several qualify (a fork at the bottom) or none (a cycle), record the corresponding
   diagnostic (below).
3. Walk leaf → issuer → issuer …, following the single confirmed edge at each step, until a cert has no
   in-bundle issuer (the top). Produce the ordered sequence leaf→…→top.
4. **Stable tie-breaks (determinism):** when construction must choose among otherwise-equal candidates
   (e.g. a fork, or two unlinked certs), break ties by ascending ORIGINAL input index; never by
   content hashing or map iteration order. Document the tie-break so snapshots are stable.

**Diagnostics from construction → findings / severity policy.** `build_chain` returns a
`Vec<ConstructionDiagnostic>` that the chain pass maps to `Finding`s on the appropriate link or cert:

| Construction outcome | Meaning | Lint id | Severity |
|---|---|---|---|
| **Disorder only** | the certs DO form one linear chain, but the input order differed; reordered for analysis | `chain_not_in_order` | **Notice** |
| **Missing middle link** | a NON-top cert whose issuer is not in the bundle (a hole in the middle of the path) | `chain_subject_issuer_dn_match` | **Error** |
| **Unlinkable / extra cert** | a cert that belongs to no position in the single chain (doesn't link in or out) | `chain_subject_issuer_dn_match` | **Error** |
| **Fork** | a cert with >1 candidate issuer in the bundle (ambiguous) — pick deterministically (lowest input index) and proceed | `chain_subject_issuer_dn_match` | **Warn** |
| **Cycle** | the linkage edges form a loop (no leaf / no top) | `chain_subject_issuer_dn_match` | **Error** |
| **Missing issuer at the TOP** | the top cert's issuer is simply absent (e.g. the root, not bundled) | `chain_issuer_not_in_chain` | **Notice** (see Refinement 2; NOT an error) |

The construction diagnostics are surfaced THROUGH the chain lints (not a separate finding type):
`chain_subject_issuer_dn_match` is REPURPOSED to be the structural-integrity verdict (see below) and
`chain_not_in_order` / `chain_issuer_not_in_chain` are the two new Notice lints. After construction, the
five link-level lints (AKI/SKI, issuer-is-CA, path-len, validity-nested, signature-valid) run over the
BUILT adjacent links exactly as before.

**Failure modes are documented in the `build_chain` doc + the README.** The construction is the only
new whole-set reasoning; the per-link lints remain pairwise over the built order.

#### Reconciling `chain_subject_issuer_dn_match`

Its OLD meaning ("adjacent FILE pairs have matching subject/issuer DNs") no longer fits once we build
by DN — comparing arbitrary file-adjacent pairs is exactly the false-Error source Refinement 1 removes.
It is **REDEFINED** as the chain's STRUCTURAL-INTEGRITY verdict produced by construction: *"every cert
links to exactly one issuer in the set and the certs form a single linear chain."* It fires **Error**
on a missing middle link / unlinkable-extra cert / cycle, **Warn** on a fork (ambiguous, after
deterministic tie-break), and passes (empty) when the set forms one clean chain (whether or not it was
in order — mere disorder is the separate `chain_not_in_order` Notice, and a merely-absent root is the
separate `chain_issuer_not_in_chain` Notice). It no longer fires merely because the input was shuffled.
Document the redefinition in the lint's doc comment and the README.

- **No-network / determinism.** The chain pass touches only the parsed certs already in memory; no
  I/O, no clock (chain lints compare cert-intrinsic fields and each other, not "now"). `chain_validity_nested`
  compares the two certs' own validity windows, not wall-clock — keeping the chain report
  snapshot-stable. Deterministic iteration: links in BUILT chain order, lints in registration order.
  **Construction is deterministic too:** stable tie-breaks (ascending input index), no map-iteration- or
  hash-dependent ordering, so the built order — and therefore the link labels and snapshots — are
  reproducible across runs.

### Findings attach to a link

The CLI labels each link `Certificate N → Certificate N+1` using the SAME `chain_label` numbering
the per-cert report uses (so `Certificate 1 (leaf) → Certificate 2`, then `Certificate 2 →
Certificate 3`, …). The link label is built in the CLI from the `subject_index` / `issuer_index` in
each `ChainLinkReport`; the engine stays label-free (it only knows indices), keeping presentation in
the CLI exactly as the per-cert path does.

### The new `chain` source and where it sits

`RuleSource::Chain` (serde `chain`) is added to `crates/linter/src/source.rs`. **Placement:** at the
**END** of the enum, after `Hygiene`, so the enum reads
`[Rfc5280, Pqc, CabfBr, CabfEv, CabfCs, CabfSmime, Hygiene, Chain]`. Rationale: `chain` is
categorically different from the per-cert sources (it is the only cross-certificate source and only
appears under `--chain`), so it reads naturally last and the existing relative order of the seven
per-cert sources is untouched. `SOURCE_ORDER` (output.rs) and `ALL_SOURCES` (main.rs) get `Chain`
appended in the same last position; `source_label` gains `Chain => "chain"`; `parse_source_token`
gains `"chain" => Ok(RuleSource::Chain)`.

- **Chain is NOT in the per-purpose `*_sources()` helpers.** Those helpers gate the *per-cert* pass.
  `Chain` is purpose-independent and lives in a *separate pass*, so folding it into `tls_server_sources()`
  etc. would be meaningless (the per-cert engine would try to run a chain lint over one cert). The
  per-cert filter-count unit tests are therefore UNCHANGED. This is the key structural difference from
  feature 13's universal `Pqc` (which IS a per-cert source folded into every purpose set).

- **`--source` interaction.** `--source chain` selects only the chain pass; `--source rfc5280`
  selects only that per-cert source and runs NO chain pass; a default run (all sources) runs both the
  per-cert pass per cert AND, when `--chain` + ≥2 certs, the chain pass. When `--source` is given
  WITHOUT `chain`, the chain pass is suppressed even under `--chain` (the user filtered chain out).
  Document this in the `--source` help and the test-plan.

### `chain_signature_valid` — cryptographic signature verification (pure-Rust, behind `verify`)

Verifying a cert's signature against its issuer's public key is the highest-value chain check. This
feature INCLUDES it, implemented with a **pure-Rust** crypto stack (NO openssl / aws-lc, NO cmake):

- **classical (RSA / ECDSA / Ed25519)** via `ring` — already in the workspace via `crates/fetch`
  (rustls' `ring` provider) and `rcgen`; `ring` builds with cc/asm but no cmake;
- **PQC (ML-DSA / SLH-DSA)** via the pure-Rust `fips204 = "0.4"` (ML-DSA / FIPS 204) and
  `fips205 = "0.4"` (SLH-DSA / FIPS 205) crates.

(Verified on crates.io: `ring`, `fips204 = "0.4.6"`, `fips205 = "0.4.1"` exist. Caret-pin `"0.4"` to
match workspace convention.)

**The lint (pairwise like the other chain lints).** For each `(subject, issuer)` link, verify the
subject cert's signature over its raw TBS DER bytes against the issuer's public key:

- **Verify FAILS → `Error`** — message "signature does not verify against the issuer's public key"
  (a forged / mismatched / corrupted link).
- **Verify SUCCEEDS → pass** (empty findings).
- **Algorithm not supported by the verifier → `Notice`** — message
  "signature not verified: unsupported algorithm \<oid\>". This is **fail-OPEN**: we NEVER raise a
  false `Error` for an algorithm we cannot check.
- Any accessor `Err` (missing TBS / signature / SPKI bytes) → no finding (graceful degradation, like
  the structural lints).

**Supported-algorithm matrix (decides Error/pass vs the Notice fail-open path):**

| Family | Algorithms | Backend |
|---|---|---|
| RSA PKCS#1 v1.5 | + SHA-256 / SHA-384 / SHA-512 | `ring` |
| ECDSA | P-256 + SHA-256, P-384 + SHA-384 | `ring` |
| EdDSA | Ed25519 | `ring` |
| ML-DSA | ML-DSA-44 / 65 / 87 (FIPS 204) | `fips204` |
| SLH-DSA | SHA2 + SHAKE variants (FIPS 205) | `fips205` |

Notes on the matrix (developer confirms against the chosen crate versions):
- **RSA-PSS** and **ECDSA P-521** may not be cleanly verifiable via `ring` (P-521 in particular is
  outside `ring`'s `ECDSA_*` set) — any such algorithm falls to the **Notice / fail-open** path rather
  than an `Error`. Confirm and document each.
- The OID → backend mapping is the single source of truth for what is "supported" vs "Notice"; an OID
  the mapping does not recognize is always the Notice path.

**Self-signed roots.** The pairwise model verifies `(subject, issuer)` links. A self-signed root's own
self-signature CAN be checked by treating the root as its own issuer for the top of the chain
(`verify(root.tbs, root.signature, root.spki)`). **Recommendation: include it if cheap** — when the
top cert is self-signed (subject DN == issuer DN, AKI absent or == own SKI), evaluate one extra
self-link so a root with a corrupted self-signature is caught. The engine already produces N-1 adjacent
links for an N-cert chain; the self-link is the root being its own issuer. Developer finalizes whether
this is an extra synthetic link or simply that the top adjacent link's issuer (the root) is verified
against itself — keep it deterministic and snapshot-stable. If it adds non-trivial engine complexity,
leave it out of v1 and note it as a small follow-up.

**Scope.** `chain_signature_valid` is signature verification ONLY — it does NOT do trust-anchor / path
validation, does NOT check revocation, does NOT build or reorder the chain. It answers exactly: "does
this cert's signature verify against the public key of the cert presented as its issuer?"

#### `verify` cargo feature — DECISION (default-on vs opt-in)

Adding `ring` + `fips204` + `fips205` to the previously crypto-free `crates/linter` is significant, so
the verification lint and its deps sit behind a new optional cargo feature on the linter crate
(proposed name: **`verify`**). When `verify` is OFF, `chain_signature_valid` is NOT registered in
`default_chain_registry()` (the other seven chain lints are unaffected); when ON, it is the 8th
chain lint.

**The decision — which is the default?**

- **Library default OFF (opt-in), CLI enables it ON by default — RECOMMENDED.** Mirrors how
  `--from-host` is opt-in via the `fetch` feature: `crates/linter`'s default build stays
  dependency-light (`x509-parser` / `der` / `oid-registry` only — no crypto), so library consumers who
  only want structural lints pay nothing. The **CLI** depends on the linter with
  `features = ["verify"]` (exactly as it already does for `serde`), so `mini-x509-lint --chain`
  verifies signatures out of the box — the headline behavior for the end-user binary. Library users
  who want verification opt in with `--features verify`.

  *Trade-off:* the default `cargo test -p linter` (no `verify`) registers 7 chain lints; the
  golden-snapshot / CLI behavior (which builds with `verify`) registers 8. The chain-lint **count** and
  any chain golden therefore depend on the active feature set — this must be reconciled in the registry
  unit tests (assert 7 without `verify`, 8 with `verify`) and the CLI goldens (generated WITH `verify`).

- *Alternative — `verify` default-ON for the library too.* Treats verification as a core linter value;
  simpler (one count everywhere). Rejected as the default because it forces the crypto stack onto every
  library consumer and breaks the "core crate is dependency-light" precedent the `serde` and `fetch`
  features established. (Reviewer may flip this — it is Open Decision 7.)

**Documented consequence:** the default-build chain-lint set and the golden snapshots depend on this
choice. Tasks 02/03/04 are written for the recommended option (library opt-in, CLI default-on).

### Curated chain-lint set (8; all `chain_*`; all `RuleSource::Chain`)

The set is now **two construction-level lints** (driven by `build_chain`, reasoning over the whole set)
plus **five pairwise link lints** (each inspecting one adjacent `(subject, issuer)` pair of the BUILT
order) plus the **one cryptographic** pairwise lint (`chain_signature_valid`, behind `verify`). Each is
one small file under `crates/linter/src/lints/chain/`, with a doc comment citing the RFC 5280 clause and
a `#[cfg(test)] mod tests`. "Pass-by-vacuity" = the lint returns empty findings when its precondition is
absent (documented per lint). The construction lints + four structural link lints are always registered;
`chain_signature_valid` is registered ONLY when the `verify` feature is on.

**Construction-driven lints (whole-set; emitted from `build_chain` diagnostics):**

| Lint id | What it reports | Severity | Pass when |
|---|---|---|---|
| `chain_subject_issuer_dn_match` *(REDEFINED — see reconciliation above)* | structural integrity: every cert links to exactly one issuer in the set and the certs form a single linear chain. Fires on a **missing middle link** / **unlinkable-extra cert** / **cycle** (Error) or a **fork** (Warn, after deterministic tie-break). | **Error** / **Warn** | the set forms one clean chain (whether or not in order; a merely-absent root is the separate Notice) |
| `chain_not_in_order` *(NEW Notice)* | the certs DO form one linear chain but the input order differed; they were reordered for analysis. Informational — NOT an error. Message: "certificates were not in leaf-to-root order; reordered for analysis". | **Notice** | the input was already in leaf→top order |
| `chain_issuer_not_in_chain` *(NEW Notice)* | the top cert's issuer (e.g. the root) is not present in the presented set. NOT an error: for `--from-host` the root lives in the trust store and trust is checked by the connection verdict. Message: "issuer (e.g. root) not present in the presented chain; trust to a root is verified separately by the connection verdict". | **Notice** | the top cert is self-signed (it is its own anchor) OR its issuer IS in the set |

**Pairwise link lints (over the BUILT adjacent `(subject, issuer)` links):**

| Lint id | What it enforces (on each `subject → issuer` link) | Severity | Facade used | Pass-by-vacuity when |
|---|---|---|---|---|
| `chain_aki_ski_match` | when the subject carries an AKI **keyIdentifier** AND the issuer carries an **SKI**, the two byte strings MUST be equal (RFC 5280 §4.2.1.1: AKI SHOULD match the issuer's SKI). | **Error** (see severity note) | new `authority_key_id_bytes()`, `subject_key_id_bytes()` | the subject has no AKI keyIdentifier, OR the issuer has no SKI (cannot compare) |
| `chain_issuer_is_ca` | the issuer cert MUST be a CA: basicConstraints `cA=TRUE` AND keyUsage asserts `keyCertSign` (RFC 5280 §4.2.1.9 / §4.2.1.3). An EE cert cannot issue. | **Error** | `basic_constraints()` (`is_ca`), `key_usage()` (`key_cert_sign`) | never — every issuer is checked (an `Err` → no finding + degradation) |
| `chain_path_len_respected` | the number of non-self-issued intermediate CAs **between** a CA's subordinate and the leaf MUST NOT exceed that CA's `pathLenConstraint` (RFC 5280 §4.2.1.9). | **Error** | `basic_constraints()` (`path_len`) + engine-supplied link depth | the issuer is not a CA, or has no `pathLenConstraint` (unconstrained) |
| `chain_validity_nested` | the subject cert's validity window SHOULD fall within the issuer's validity window (`issuer.not_before ≤ subject.not_before` and `subject.not_after ≤ issuer.not_after`). A cert valid beyond its issuer is a deployment smell, not strictly an RFC 5280 MUST. | **Warn** (see severity note) | `not_before()`, `not_after()` (ASN1Time, Copy) | never (an `Err` reading either bound → no finding + degradation) |
| `chain_signature_valid` *(only with `verify` feature)* | the subject cert's signature over its TBS DER MUST verify against the issuer's public key (§4.1.1.3). Verify FAILS → **Error**; SUCCEEDS → pass; unsupported algorithm → **Notice** (fail-open). | **Error** / **Notice** (see policy) | new `tbs_der()`, `signature_value_bytes()`, `signature_algorithm_oid()`, `issuer_spki_bytes()`; the `verify` module | accessor `Err` → no finding; unsupported alg → Notice (not a pass, not an Error) |

Optional / considered and **deferred** (see *Future*):
- `chain_root_is_self_signed` / `chain_leaf_not_self_issued` — sanity checks on the chain endpoints.
  Recommended **deferred**: they are endpoint (not pairwise-link) checks that complicate the clean
  pairwise model, and the value overlaps `chain_subject_issuer_dn_match` (a self-signed root is a link
  where subject==issuer at the top). Reserved.

**Final v1 count: 8 chain lints** — 2 construction-driven (`chain_subject_issuer_dn_match` redefined +
`chain_not_in_order`) + `chain_issuer_not_in_chain` + 4 structural link lints (AKI/SKI, issuer-is-CA,
path-len, validity-nested) = **7 always-registered**, plus `chain_signature_valid` (registered only with
the `verify` feature). The registry count is therefore **7 without `verify`, 8 with `verify`**
(reconciled in the registry unit tests and the CLI goldens, which build with `verify`).

> Note on "construction-driven" registration: `chain_not_in_order`, `chain_issuer_not_in_chain`, and the
> redefined `chain_subject_issuer_dn_match` are sourced from `build_chain`'s diagnostics rather than from
> a pairwise `check(subject, issuer)`. They are still `RuleSource::Chain` lints with stable `chain_*` ids
> and still counted in the registry; the developer finalizes whether they are represented as registry
> entries with a no-op pairwise `check` (their findings injected by the engine from the diagnostics) or
> as a distinct construction-lint shape — keep them counted, ordered deterministically, and attached to
> the correct cert/link. See Open Decision 11.

#### Severity notes (resolved here)

- `chain_subject_issuer_dn_match` (REDEFINED) → **Error** for a missing-middle-link / unlinkable-extra /
  cycle (the set does not form a real single chain — a verifier would reject it), **Warn** for a fork
  (ambiguous: >1 candidate issuer; the engine picks deterministically and proceeds, but flags the
  ambiguity). `chain_issuer_is_ca`, `chain_path_len_respected` → **Error**. These are hard
  chain-construction violations: the presented chain does not validate as a real issuance path.
- `chain_not_in_order` → **Notice**. Pure disorder is not a defect of the certificates — the chain is
  complete and valid; only the FILE/presentation order differed. A Notice records that a reorder
  happened (so the link labels follow the built order) without penalizing a correct-but-shuffled bundle.
- `chain_issuer_not_in_chain` → **Notice**. A top cert whose issuer (the root) is simply absent is
  NORMAL — especially for `--from-host`, where the root is in the client trust store and trust is
  established by the connection verdict, not by the lints. Never an Error.
- `chain_aki_ski_match` → **Error**. RFC 5280 §4.2.1.1 phrases the AKI/SKI relationship as a SHOULD,
  but a *present* AKI keyIdentifier that does NOT match the issuer's *present* SKI is a strong signal
  the wrong issuer is presented (or the bundle is mis-ordered) — i.e. a near-certain broken chain, so
  Error. The pass-by-vacuity rule (no AKI or no SKI → no finding) keeps it from firing on legitimately
  AKI-less or SKI-less certs. (If the reviewer prefers Warn, that is a one-line change — recorded as an
  Open Decision.)
- `chain_validity_nested` → **Warn**. This is a deployment smell (a cert outliving its issuer), not an
  RFC 5280 MUST. Warn avoids false-positives on legitimately-structured chains where a long-lived root
  reissues. (Reviewer may prefer Notice — Open Decision.)
- `chain_signature_valid` → **Error** on a verify failure (a signature that does not check against the
  presented issuer's key is a broken/forged link a TLS client would reject), **Notice** on an
  unsupported algorithm (fail-open — we make no claim about an algorithm our backends cannot verify),
  pass on success.

#### `chain_signature_valid` verify-module placement (resolve here)

The OID → backend dispatch and the `ring` / `fips204` / `fips205` calls live in a small isolated module
`crates/linter/src/lints/chain/verify.rs` (a `verify` submodule of `lints::chain`). It exposes a pure
function returning a `VerifyOutcome` enum, e.g.:

```text
pub(crate) enum VerifyOutcome { Verified, Failed, Unsupported }
pub(crate) fn verify_signature(
    sig_alg_oid: &Oid, tbs_der: &[u8], signature: &[u8], issuer_spki: &[u8],
) -> VerifyOutcome
```

Keeping all crypto in this one module (a) contains the `ring` / `fips204` / `fips205` deps to a single
`#[cfg(feature = "verify")]` file, (b) makes the OID → backend mapping independently unit-testable
(supported OID → dispatches; unknown OID → `Unsupported`), and (c) keeps `subject_signature.rs` (the
`chain_signature_valid` lint file) a thin translator: read the four accessors, call `verify_signature`,
map `Verified → []`, `Failed → [Error]`, `Unsupported → [Notice]`. The whole module + lint file are
`#[cfg(feature = "verify")]`. Document that `fips204`/`fips205` are pre-1.0 / generally unaudited —
acceptable for a verifier reasoning over PUBLIC certificate data, not for protecting secrets.

#### `chain_path_len_respected` depth note (resolve here)

`pathLenConstraint` limits the number of non-self-issued intermediate CAs that may follow in the path.
Expressed pairwise: for the link `(subject, issuer)` where `issuer` is a CA with
`pathLen = k`, the engine supplies the issuer's **depth below the leaf** (number of links between this
issuer and `c0`); the lint flags Error when the count of intermediate CAs that must appear *below*
this CA (derivable from the issuer's position in the ordered chain) exceeds `k`. The engine passes the
issuer's chain index to the lint (the only piece of whole-chain context any v1 lint needs), so the
lint stays pairwise while having the one integer it needs. The developer finalizes the exact depth
arithmetic against RFC 5280 §4.2.1.9 (the leaf is not counted; self-issued CAs do not count toward the
limit) and documents it. *Alternative considered:* a whole-chain `check(&[Cert])` for this one lint —
rejected to keep one uniform pairwise trait; the single integer is sufficient.

### Running the chain pass on the `--from-host` presented chain

The chain pass runs over **two** input shapes, since both present a real chain:

1. a **`--chain` file bundle** (≥2 certs) — the original wiring; and
2. the **`--from-host` presented chain** — the leaf + intermediates the `fetch` crate already captures.

For `--from-host`, `run_from_host` currently parses ONLY the leaf and builds display-only entries from
`chain.intermediates_der`. Refinement 2 extends it: after the existing leaf lint + verdict, parse the
presented certs (leaf + intermediates) into a `Vec<Cert>`, run `build_chain` + the chain pass over them,
and append the `[chain]` section (text) / `chain` array (JSON) — placed AFTER the leaf report and the
`verification:` verdict. The existing per-cert leaf linting and the `verification: valid/invalid`
verdict stay EXACTLY as they are; the chain section is purely additive. Intermediates that fail to parse
are simply not contributed to the chain `Vec<Cert>` (they still appear in the display `presented_chain`
as today) — degrade, never panic.

**Root-absent handling (the key point).** Servers usually present leaf + intermediates but NOT the root
(the client has it in its trust store); some do send it. The pairwise checks only cover links PRESENT in
the bundle, so a missing root at the top is **NOT an Error** — the top intermediate simply has no
in-bundle issuer to verify against. Construction handles this as the "missing issuer at the TOP" case
and emits a **Notice** on the top cert: `chain_issuer_not_in_chain` — *"issuer (e.g. root) not present
in the presented chain; trust to a root is verified separately by the connection verdict."* This Notice
is emitted for the file-bundle case too (a `--chain` bundle that omits its root), so the behavior is
uniform across both entry points.

**Trust-anchor validation is OUT of scope for the lints.** The chain lints verify only the LINKS that
are present (DN linkage, AKI/SKI, issuer-is-CA, path-len, validity nesting, and — with `verify` —
signatures). They do NOT validate trust to a root / trust anchor. For `--from-host` that trust decision
is ALREADY covered by the existing `verification: valid/invalid` verdict (webpki-roots, produced by the
`fetch` crate). The plan must make this separation explicit: *connection verdict = trust to a root;
chain lints = structural + cryptographic soundness of the presented links.* Document this in the README
and the `--from-host` help.

**Feature gating under `--from-host`.** `chain_signature_valid` stays behind the `verify` feature, and
the CLI enables `verify` by default (prior decision), so a default `mini-x509-lint --from-host` run
ALSO signature-verifies the present links. The missing-root top link gets the
`chain_issuer_not_in_chain` Notice, NOT an Error.

**Single-cert `--from-host` (server presents only a leaf).** No links → the chain pass produces
nothing. RECOMMENDED: emit NOTHING for the chain section in this case (no link exists, so even the
issuer-not-in-chain Notice is not surfaced on the lone leaf — there is nothing to lint). The leaf is
still linted per-cert and the verdict still shown, exactly as today. Default / no-`--chain` single-cert
FILE input behavior is likewise unchanged.

### CLI / output

Chain lints surface in a **dedicated chain-level section AFTER the per-cert reports** (for
`--from-host`, after the leaf report AND the verdict), when there are ≥2 presented certs AND the chain
source is selected (default, or explicit `--source chain`). For file input this means `--chain` with
`certs.len() >= 2`; for `--from-host` it means the presented chain has ≥2 certs (leaf + ≥1
intermediate). `chain_signature_valid` reports through the SAME `[chain]` section / chain JSON array as
the structural lints — no new output shape. When the CLI is built with `verify` (the default),
its `[chain]` block and chain JSON simply include one more lint id; when built without `verify`, the
lint is absent and the section shows only the 7 always-registered chain lints.

- **Text.** After the existing per-cert chain lint report (`output::render_text_chain`) — and, for
  `--from-host`, after the verdict — append a chain-level block. Construction-level findings
  (`chain_not_in_order` once for the whole chain; `chain_issuer_not_in_chain` on the top cert) render
  first, then the per-link findings over the BUILT order, e.g. for a complete-but-shuffled bundle:

  ```text
  <existing per-cert chain report, byte-for-byte unchanged>

  Chain checks:
    [chain] chain_not_in_order: notice: certificates were not in leaf-to-root order; reordered for analysis
  Certificate 1 (leaf) → Certificate 2
    (no findings)
  Certificate 2 → Certificate 3
    (no findings)
    [chain] chain_issuer_not_in_chain: notice: issuer (e.g. root) not present in the presented chain; trust to a root is verified separately by the connection verdict
  ```

  And for a genuinely broken set (missing middle link):

  ```text
  Chain checks:
    [chain] chain_subject_issuer_dn_match: error: certificate "CN=…" links to no issuer in the presented set (broken chain)
  ```

  The exact header text / indentation / "no findings" rendering, and whether the construction Notices
  render under the header or attached to a specific cert label, are the developer's call within the
  deterministic, snapshot-friendly constraint and locked by the tester's snapshot. The `--min-severity`
  filter applies to chain findings exactly as to per-cert findings (so `--min-severity warn` hides the
  two Notices); a link with no surfaced findings renders a documented placeholder (or is omitted —
  developer's call, snapshot-locked). The CLI builds link labels from the BUILT order's
  `subject_index`/`issuer_index`, NOT the raw input order.

- **JSON.** Add a **top-level `chain` array** alongside the existing per-cert structure, preserving
  the feature-02 per-outcome shape and the feature-14 envelope. For a plain `--chain` JSON run (today
  a bare array from `render_chain_json`), wrap it so the chain findings have a home WITHOUT breaking
  the existing per-cert shape. RECOMMENDED envelope (Open Decision below):

  ```json
  {
    "certificates": [ { "certificate": "Certificate 1 (leaf)", "outcomes": [ … ] }, … ],
    "chain": [
      {
        "subject": "Certificate 1 (leaf)",
        "issuer":  "Certificate 2",
        "outcomes": [ { "lint_id": "chain_subject_issuer_dn_match", "source": "chain", "findings": [ … ] }, … ]
      }
    ]
  }
  ```

  This means the plain `--chain` JSON changes from a bare top-level array to
  `{ "certificates": [...], "chain": [...] }` **only when the chain pass runs** (≥2 certs and chain
  source selected). See *Ripple Flag* and *Open Decisions* — this is a deliberate, called-out JSON
  shape change for `--chain` JSON, and any `--chain` JSON golden must be intentionally regenerated by
  the tester. Single-cert JSON and `--chain --info` JSON (feature 14) reuse the same approach: a
  sibling `chain` key alongside the existing `certificates` envelope. The chain `outcomes` reuse the
  exact `LintOutcome`-shaped object (sans `applicability`, which the chain pass does not carry — the
  serialized chain outcome is `{ lint_id, source, findings }`).

  **Construction-level findings in JSON.** `chain_not_in_order` (one per chain) and
  `chain_issuer_not_in_chain` (on the top cert) attach to the chain as a whole rather than to a single
  `(subject, issuer)` link. The developer chooses a deterministic home — RECOMMENDED: a top-level
  `chain.diagnostics` (or `chain.construction`) array sibling to the per-link `chain.links`, e.g.
  `{ "certificates": [...], "chain": { "diagnostics": [ … ], "links": [ … ] } }`, OR keep the flat
  `chain: [...]` link array and surface the construction findings on the relevant link/cert entry — the
  developer finalizes the exact shape and the tester snapshot-locks it. Keep it snapshot-stable.

  **`--from-host` JSON.** The existing `--from-host` JSON document
  (`{ presented_chain, verification, outcomes }`, or with `summary` under `--info`) gains a sibling
  `chain` key (same shape as above) when the presented chain has ≥2 certs and the chain source is
  selected. The existing `presented_chain` / `verification` / `outcomes` keys are UNCHANGED; the `chain`
  key is purely additive. A single-leaf `--from-host` JSON document is unchanged (no `chain` key).

- **Determinism / unchanged paths.** Single-cert file input and any run WITHOUT `--chain` /
  `--from-host` produce byte-for-byte UNCHANGED text and JSON (the chain pass never executes). A
  single-leaf `--from-host` run (no intermediates presented) likewise emits no chain section. A
  `--from-host` run that presents leaf + intermediates gains the additive chain section AFTER the verdict
  — the leaf report, `presented_chain` display, and `verification:` verdict bytes above it are
  unchanged. Existing golden snapshots for single-cert and the per-cert chain report MUST NOT change
  EXCEPT a `--chain` golden that the tester intentionally regenerates to include the new chain section
  (called out in the Ripple Flag). `--from-host` is tested via the hermetic local TLS server (feature
  07's `TestServer`), not via a golden, since the presented certs are minted per-test.

## Changes Overview

**crates/linter/ (production code — developer tasks 01–03)**
- `src/cert.rs` *(task 01)* — add the raw-bytes accessors (name DER + SKI/AKI octets for structural
  matching; TBS DER + signature value + signature-alg OID + issuer SPKI for signature verification),
  all `Result<_, CertError>`, non-panicking, reusing the `with_parsed` pattern:
  - `subject_name_der() -> Result<Vec<u8>, CertError>` — the DER encoding of the subject Name (the
    raw RDNSequence bytes), for byte-exact name matching.
  - `issuer_name_der() -> Result<Vec<u8>, CertError>` — the DER encoding of the issuer Name.
  - `subject_key_id_bytes() -> Result<Option<Vec<u8>>, CertError>` — the raw SKI keyIdentifier octets,
    `None` when the SKI extension is absent.
  - `authority_key_id_bytes() -> Result<Option<Vec<u8>>, CertError>` — the raw AKI keyIdentifier
    octets, `None` when AKI is absent or carries no keyIdentifier field.
  - `tbs_der() -> Result<Vec<u8>, CertError>` — the raw DER of the tbsCertificate (the exact bytes the
    signature is computed over; x509-parser exposes `tbs_certificate` raw bytes).
  - `signature_value_bytes() -> Result<Vec<u8>, CertError>` — the signature value octets
    (`signature_value`), i.e. the BIT STRING contents.
  - `signature_algorithm_oid() -> Result<Oid, CertError>` (or an owned/`String` OID — developer
    chooses a non-borrowing, non-panicking shape) — the OID of the outer signatureAlgorithm, for the
    verify module's backend dispatch.
  - `issuer_spki_bytes() -> Result<Vec<u8>, CertError>` — the raw SubjectPublicKeyInfo / public-key
    bytes of THIS cert (the issuer's, when called on the issuer cert), in the form the verifier needs
    (the developer decides: full SPKI DER vs the raw public-key BIT STRING contents — document which,
    and ensure the verify module consumes the matching form; for `ring` the raw key bytes per algorithm,
    for `fips204`/`fips205` the encoded public key). x509-parser exposes `subject_pki`.
  - Keep all existing accessors (incl. `AkiView` / `has_subject_key_identifier` / `subject_rfc4514` /
    `issuer_rfc4514` / `basic_constraints` / `key_usage` / `not_before` / `not_after`) UNCHANGED. The
    new accessors are ADDITIVE and feature-independent (plain `Cert` methods — they expose bytes; only
    the verify *lint* is feature-gated). Add `#[cfg(test)] mod tests` for the new accessors (present vs
    absent, non-empty bytes, OID value via existing fixtures).
- `src/lib.rs` *(task 02)* — declare and re-export the `ChainLint` trait, `ChainLinkOutcome`,
  `ChainLinkReport` (and `ChainRegistry` / `default_chain_registry` re-export). Keep the existing
  `Lint` trait + re-exports unchanged.
- `src/source.rs` *(task 02)* — add `RuleSource::Chain` (serde `chain`) at the END of the enum
  (after `Hygiene`); update the type-doc `--source` vocabulary listing.
- `src/finding.rs` *(task 02; only if `ChainLinkOutcome` lives here)* — add `ChainLinkOutcome`
  (and `ChainLinkReport` if co-located). Alternatively these live in a new `src/chain.rs` (developer's
  call; keep `touches` minimal — see Sequencing). `Finding` / `Severity` / `LintOutcome` UNCHANGED.
- `src/chain.rs` *(task 02; NEW, recommended home for the chain trait + registry + construction)* —
  `ChainLint`, `ChainRegistry`, `default_chain_registry()`, `ChainLinkReport`, `ChainLinkOutcome`, the
  **`build_chain(&[Cert]) -> (OrderedChain, Vec<ConstructionDiagnostic>)` helper** (DN/AKI-SKI linkage,
  deterministic leaf→top walk, stable tie-breaks, the diagnostic enum for disorder / missing-middle /
  unlinkable / fork / cycle / missing-top), and the chain-pass walk that BUILDS the order, maps
  construction diagnostics → findings (`chain_subject_issuer_dn_match` Error/Warn, `chain_not_in_order`
  Notice, `chain_issuer_not_in_chain` Notice), THEN runs the pairwise link lints over the built order.
  (If the trait must live in `lib.rs` for re-export ergonomics, the registry + report types + `build_chain`
  live here; the developer finalizes placement and keeps it conflict-free.)
- `src/lints/mod.rs` *(task 02)* — `pub mod chain;`.
- `src/lints/chain/mod.rs` *(task 02)* — module declarations + re-exports of the construction lints + the
  4 structural link-lint types (unconditional); see below for the `#[cfg(feature = "verify")]`
  verify/signature modules.
- `src/lints/chain/subject_issuer_dn_match.rs` *(task 02; REDEFINED)* — the structural-integrity verdict
  driven by `build_chain` (Error on missing-middle/unlinkable/cycle, Warn on fork), NOT the old
  file-adjacent DN compare.
- `src/lints/chain/not_in_order.rs` *(task 02; NEW Notice)* — `chain_not_in_order`: Notice when the set
  forms a complete chain but the input order differed (reordered for analysis).
- `src/lints/chain/issuer_not_in_chain.rs` *(task 02; NEW Notice)* — `chain_issuer_not_in_chain`: Notice
  on the top cert when its issuer (the root) is absent from the presented set.
- `src/lints/chain/aki_ski_match.rs` *(task 02)*
- `src/lints/chain/issuer_is_ca.rs` *(task 02)*
- `src/lints/chain/path_len_respected.rs` *(task 02)*
- `src/lints/chain/validity_nested.rs` *(task 02)*
- `src/lints/chain/subject_signature.rs` *(task 02; NEW, `#[cfg(feature = "verify")]`)* — the
  `chain_signature_valid` lint: reads `tbs_der` / `signature_value_bytes` / `signature_algorithm_oid`
  from the subject and `issuer_spki_bytes` from the issuer, calls `verify::verify_signature`, maps
  `Verified → []` / `Failed → [Error]` / `Unsupported → [Notice]`.
- `src/lints/chain/verify.rs` *(task 02; NEW, `#[cfg(feature = "verify")]`)* — the isolated crypto
  module: OID → backend dispatch (`ring` / `fips204` / `fips205`) returning `VerifyOutcome`. Contains
  ALL crypto-crate usage; unit-tested for OID mapping (supported → dispatch, unknown → `Unsupported`).
- `Cargo.toml` *(task 02)* — add the `verify` feature gating `ring` + `fips204` + `fips205` (caret-pin
  `"0.4"`); the 7 always-registered lints + the new accessors are unaffected when `verify` is off.
- `src/lints/chain/mod.rs` *(task 02)* — `#[cfg(feature = "verify")] pub mod verify;` and
  `#[cfg(feature = "verify")] pub mod subject_signature;` plus the conditional re-export of the lint
  type; the 7 always-registered modules (2 construction + `issuer_not_in_chain` + 4 link lints) are
  unconditional.
- `src/chain.rs` *(task 02)* — `default_chain_registry()` registers the 7 always-on chain lints (the 2
  construction lints, `chain_issuer_not_in_chain`, and the 4 structural link lints) and
  `chain_signature_valid` under `#[cfg(feature = "verify")]` (so the registry holds 7 without `verify`, 8
  with it). The registry/run machinery is otherwise feature-independent.
- `src/registry.rs` — **NOT touched by this feature.** `default_chain_registry()` lives in
  `src/chain.rs` (Open Decision 5), so the per-cert `default_registry()`, the `*_sources()` helpers, and
  the per-cert filter-count unit tests are entirely untouched. Chain-registry unit tests live in
  `chain.rs` (7 lints without `verify`, 8 with `verify`; all `RuleSource::Chain`; `build_chain` +
  `run` over a clean chain produce no Error/Warn; disorder → only `chain_not_in_order`; `< 2` certs →
  empty).

**crates/cli/ (production code — developer task 03)**
- `Cargo.toml` *(task 03)* — enable the linter's `verify` feature by default for the CLI:
  `linter = { path = "../linter", features = ["serde", "verify"] }` (mirrors the existing `serde`
  enablement). This is what makes `mini-x509-lint --chain` verify signatures out of the box. No new CLI
  feature flag is needed (verification is on for the binary by default); a CLI `--no-verify` toggle is
  an Open Decision (not specced for v1 — the lint already self-skips unsupported algorithms).
- `src/main.rs` — `parse_source_token`: add `"chain" => Ok(RuleSource::Chain)`; `ALL_SOURCES`: append
  `RuleSource::Chain`; update `--source` doc/error strings. In `run_chain` (file `--chain` path): when
  `certs.len() >= 2` AND the chain source is selected, run `default_chain_registry().run(certs)` and
  render the chain section (text) / `chain` array (JSON). Build link labels from the BUILT order's
  indices via the existing `chain_label`. Guard so single-cert and chain-source-deselected runs are
  byte-for-byte unchanged. Update `render_chain_json` / `render_chain_info_json` to emit the
  `{ certificates, chain }` envelope when the chain pass produced reports (and the bare array / existing
  envelope otherwise).
- `src/main.rs` *(Refinement 2 — `run_from_host`, `#[cfg(feature = "fetch")]`)* — after the existing
  leaf lint + `presented_chain` display + `verification:` verdict, parse the presented certs (leaf +
  `chain.intermediates_der`) into a `Vec<Cert>` (intermediates that fail to parse are dropped from the
  chain `Vec<Cert>` but still appear in the display `presented_chain`, as today). When that vec has ≥2
  certs AND the chain source is selected, run `default_chain_registry().run(&presented)` and append the
  chain section (text, after the verdict) / a sibling `chain` key (JSON, alongside the existing
  `presented_chain`/`verification`/`outcomes`/`summary` keys). Fold chain findings into the existing
  `severity_counts`/`exit_code` so `--fail-on` covers them. A single-leaf presented chain (no
  intermediates) → no chain section, output unchanged. Reuse `chain_label`/`render_chain_section`; do NOT
  alter the existing leaf/verdict rendering. Update `run_from_host`'s doc comment to note the additive
  chain pass and the trust-vs-lint separation (the verdict = trust; chain lints = present-link soundness).
- `src/output.rs` — `SOURCE_ORDER`: append `RuleSource::Chain` (last); `source_label`:
  `RuleSource::Chain => "chain"`. Add a `render_chain_section` (text) helper for the chain-level block
  (mirroring `render_text_chain`'s style; renders construction Notices + per-link findings) and a
  chain-outcomes JSON helper, OR build these inline in `main.rs` (developer's call; keep `output.rs` the
  home for rendering to match existing structure). The SAME helpers serve both the `--chain` file path
  and the `--from-host` path.

**testdata/ + tests (tester — task 04)**
- `testdata/generate.sh` — append a SELF-CONTAINED chain section: a clean leaf→intermediate→root chain
  (all structural chain lints pass) + one violating chain per structural lint, PLUS the
  signature-verification fixtures: a valid **classical** chain (RSA/ECDSA, every link verifies), a valid
  **PQC** chain (e.g. ML-DSA root → ML-DSA intermediate → leaf — openssl 3.6.2 can generate these,
  exercising the fips204/fips205 path), a **bad-signature** chain (DER-patch one signature byte, or a
  cert signed by a different key than its named issuer) → `chain_signature_valid` Error, and (if
  expressible) an **unsupported-algorithm** case → Notice. Reuse `testdata/chain_bundle.pem` (2 certs)
  where it fits; mint new multi-cert chain fixtures otherwise. Align all validity windows with the
  existing `BR_OK` horizon (`2026-06-01 → 2027-06-01`) to avoid `hygiene_not_expired` cross-fire and
  for snapshot stability. The tester owns the producibility of the bad-signature fixture (openssl-native
  mismatched-key issuance vs documented single-byte DER patch). `cargo audit` MUST be run after the new
  crypto deps land (A03 supply-chain).
- New fixtures (openssl-generated only — NEVER cert-bar): see Fixtures section in `test-plan.md`. This
  now ALSO includes an **unordered/shuffled bundle** (a complete chain in non-leaf-first order → only
  `chain_not_in_order` Notice, all link checks still pass) and a **broken** set (missing-middle-link
  and/or fork → `chain_subject_issuer_dn_match` Error/Warn).
- `crates/linter/tests/chain.rs` (new) — chain-lint integration tests, including `build_chain`
  construction cases (clean-ordered, shuffled→reordered, missing-middle, fork, cycle, missing-top) and
  the two new Notice lints.
- `crates/cli/tests/output.rs` (ADD a `--chain` chain-section test + a `--source chain` test + the
  unordered-bundle case + a broken-bundle case).
- `crates/cli/tests/inspect.rs` OR a new `crates/cli/tests/from_host.rs` *(Refinement 2)* — a
  `--from-host` presented-chain test using feature 07's hermetic local TLS `TestServer` (present
  leaf+intermediate WITHOUT the root): assert the `[chain]` section appears after the verdict, the
  present link checks pass, and the top intermediate gets the `chain_issuer_not_in_chain` Notice. The
  tester chooses the file (reuse the existing fetch-feature test harness pattern); if a new test file is
  added it is in task 04's `touches`.
- A `--chain` text/JSON golden (intentionally added/regenerated to include the chain section — the
  ONLY golden churn this feature permits; see Ripple Flag). `--from-host` is verified via the hermetic
  server, not a golden.
- `crates/linter/tests/registry.rs` — NO per-cert count change (chain lints are not in
  `default_registry()`); optionally add a `default_chain_registry()` count assertion (7 / 8).

## Dependencies

**The 7 always-registered lints (incl. `build_chain` construction) + the new accessors add no
dependency.** They read fields already reachable through `x509-parser` / `der` (already dependencies)
via the existing `with_parsed` helper: raw subject/issuer Name DER, raw SKI/AKI keyIdentifier octets,
raw TBS DER, signature value + algorithm OID, issuer SPKI bytes, basicConstraints, keyUsage, and
validity bounds are all on the parsed structures (the new accessors merely surface bytes already
present). Chain construction reuses the same Name-DER + AKI/SKI accessors — no new dependency.

**New crypto dependencies — on `crates/linter`, behind the `verify` feature (off by default):**

```toml
[dependencies]
# Pure-Rust crypto for chain_signature_valid (feature = "verify"). NO openssl/aws-lc, NO cmake.
ring    = { version = "0.17", optional = true }  # classical: RSA / ECDSA / Ed25519
                                                 # (already in the workspace via crates/fetch)
fips204 = { version = "0.4",  optional = true }  # ML-DSA  (FIPS 204) — pure Rust, pre-1.0
fips205 = { version = "0.4",  optional = true }  # SLH-DSA (FIPS 205) — pure Rust, pre-1.0

[features]
verify = ["dep:ring", "dep:fips204", "dep:fips205"]
```

- Caret-pin `"0.4"` for `fips204`/`fips205` to match workspace convention; pin `ring` to the version
  already resolved in `Cargo.lock` (workspace uses it via `fetch`/`rcgen`). Verified on crates.io:
  `ring`, `fips204 = "0.4.6"`, `fips205 = "0.4.1"`.
- When `verify` is OFF (the linter default), NONE of these are compiled and `chain_signature_valid` is
  not registered — the core crate stays dependency-light.
- **The CLI enables `verify` by default** (`features = ["serde", "verify"]` in `crates/cli/Cargo.toml`),
  so the binary verifies out of the box.
- **`cargo audit` MUST be run** after adding these (A03 supply-chain). `fips204`/`fips205` are pre-1.0
  and generally unaudited — acceptable for a verifier over PUBLIC certificate data, not for protecting
  secrets; document the maturity caveat.

## Open Decisions (for the review gate)

1. **`verify` cargo feature default — library opt-in + CLI default-on (recommended) vs library
   default-on.** Recommending the linter's `verify` feature default-OFF (core crate stays
   dependency-light) with the **CLI enabling it by default** (binary verifies out of the box) — mirrors
   the `fetch` opt-in / `serde` enablement precedents. Consequence: 7 chain lints without `verify`, 8
   with it; registry tests assert both, CLI goldens build WITH `verify`. (Reviewer may flip to
   library-default-on — Open Decision 7.)
2. **`chain_aki_ski_match` severity — Error (recommended) vs Warn.** Recommending **Error** (a present
   AKI not matching a present SKI is a near-certain wrong/mis-ordered issuer), with pass-by-vacuity when
   either id is absent.
3. **`chain_validity_nested` severity — Warn (recommended) vs Notice.** Recommending **Warn**.
4. **JSON envelope for chain findings.** Recommending the sibling top-level `chain` array alongside the
   existing `certificates` envelope (`{ "certificates": [...], "chain": [...] }`), accepting that plain
   `--chain` JSON moves from a bare array to this object **when the chain pass runs**. Alternative: keep
   `render_chain_json`'s bare array and emit chain findings as a separate adjacent document — rejected
   (two documents is more surprising than one self-describing object).
5. **Chain trait/registry home — new `src/chain.rs` (recommended) vs `lib.rs` + `registry.rs`.**
   Recommending a dedicated `src/chain.rs` so the chain pass is isolated and `registry.rs` /
   `default_registry()` stay entirely untouched. Affects only which file task 02/03 touch (kept
   conflict-free either way).
6. **Optional endpoint lints (`chain_root_is_self_signed` / `chain_leaf_not_self_issued`).**
   Recommending **defer** (breaks the clean pairwise model; overlaps DN-match). Reserved.
7. **`verify` default-ON for the library too?** Treats verification as a core linter value (one count
   everywhere) at the cost of forcing the crypto stack on every library consumer. Recommending **NO**
   (keep it CLI-only-default) — see Open Decision 1.
8. **Self-signed root self-signature check.** Recommending **include if cheap** — verify a self-signed
   root's own signature by treating it as its own issuer for the top link, so a corrupted root
   self-signature is caught. Leave out of v1 only if it adds non-trivial engine complexity.
9. **ECDSA P-521 / RSA-PSS coverage.** These may fall to the Notice/fail-open path if `ring` cannot
   verify them cleanly. Recommending the fail-open Notice for any algorithm the backends cannot check;
   the developer confirms the exact supported set against the chosen crate versions and documents it.
10. **CLI `--no-verify` toggle.** Not specced for v1 (the lint self-skips unsupported algorithms and
    only adds a Notice/Error, never blocks). Reserved if users want to suppress the crypto pass.
11. **Representation of the construction-driven lints (Refinement 1).** `chain_subject_issuer_dn_match`
    (redefined), `chain_not_in_order`, and `chain_issuer_not_in_chain` are sourced from `build_chain`
    diagnostics, not a pairwise `check(subject, issuer)`. Recommending they remain registry entries with
    stable `chain_*` ids (counted in the 7/8 total), with the engine injecting their findings from the
    diagnostics — vs modelling construction as a separate non-lint step. The developer finalizes the
    exact shape; either way they are counted, deterministically ordered, and attached to the right
    cert/link.
12. **Fork severity (Refinement 1).** A cert with >1 candidate issuer in the bundle (ambiguous chain).
    Recommending **Warn** (the engine still picks deterministically by lowest input index and proceeds),
    vs Error. Reviewer may prefer Error if an ambiguous chain should hard-fail.
13. **Single-leaf `--from-host` chain output (Refinement 2).** Recommending the chain section emits
    **nothing** when the server presents only a leaf (no link to lint), vs surfacing a lone
    `chain_issuer_not_in_chain` Notice on the leaf. Recommending nothing (there is no link).
14. **Construction-finding home in JSON (Refinement 1).** Whole-chain findings (`chain_not_in_order`,
    `chain_issuer_not_in_chain`, structural-integrity errors) attach to the chain, not a single link.
    Recommending a `chain.diagnostics`/`chain.construction` sibling to the per-link array (or surfacing
    on the relevant cert entry) — developer finalizes; tester snapshot-locks.

## Future (explicitly out of scope — reserved, not specced)

- **RSA-PSS / ECDSA P-521 / additional signature algorithms** in `chain_signature_valid` — v1 covers
  the matrix above; any algorithm the `ring`/`fips204`/`fips205` backends cannot verify is reported via
  the Notice fail-open path. Broadening the verifiable set (e.g. RSA-PSS, P-521, composite PQC+classical
  signatures) is reserved.
- **Whole-chain `ChainLint::check(&[Cert])`** shape — reserved for a genuinely non-pairwise rule (e.g.
  name-constraints propagation down the path, RFC 5280 §4.2.1.10; policy-constraints / policy-mapping
  processing, §4.2.1.11–§6.1). v1's trait is pairwise; this is an additive trait method or sibling
  trait when needed.
- **Chain *building / ordering*** — v1 NOW reconstructs the issuance order from an unordered bundle via
  `build_chain` (Refinement 1): linear leaf→top linkage by DN + AKI/SKI, with deterministic tie-breaks
  and the disorder/missing-middle/fork/cycle/missing-top diagnostics. Still RESERVED: **AIA-fetching**
  missing intermediates (network), reconstructing **branched/cross-signed** PKI graphs (v1 produces ONE
  linear chain and flags forks rather than exploring all paths), and full trust-anchor **path
  validation** (RFC 5280 §6.1) — trust is the connection verdict's job, not the lints'.
- **Endpoint sanity lints** (`chain_root_is_self_signed`, `chain_leaf_not_self_issued`) — reserved
  (Open Decision 6).
- **EKU chaining / basic-constraints CA depth beyond pathLen** and other §6.1 path-validation steps —
  reserved.

## Ripple Flag: golden snapshots + README Scope note

- **Golden snapshots.** Feature 06's golden test snapshots CLI output over `testdata/`. The chain pass
  runs over file `--chain` bundles (≥2 certs) AND the `--from-host` presented chain (≥2 certs) — but the
  goldens only exercise the FILE path (`--from-host` has no golden; it is tested via the hermetic local
  TLS server, which mints certs per-run). So for the goldens:
  - All single-cert goldens (`good_text`, `good_json`, `good_verbose_text`, the per-cert source-group
    snapshots) are **byte-for-byte UNCHANGED** (no chain pass).
  - The existing **`--chain` text golden** (`golden__text_output__chain_bundle_text.snap`) WILL gain
    the new "Chain checks:" section, and any `--chain` **JSON** golden moves to the
    `{ certificates, chain }` envelope. Because the CLI builds with `verify` by default, these goldens
    include `chain_signature_valid` alongside the 7 always-registered lints — they must be generated with the
    CLI's default feature set (`verify` on). These are the ONLY snapshots this feature changes, and the
    **tester** owns regenerating them (add them to task 04's `touches`). Verify exactly which `--chain`
    goldens exist before regenerating; do NOT touch single-cert goldens. (Action: flag only — do NOT
    edit feature 06 here.)
- **README Scope note.** This feature **flips** the README non-goal "Each certificate is linted
  independently … there are no chain-aware lints" (`README.md:401`,`:518`). The README MUST be updated
  to describe: the new chain-aware lints and the `chain` source; that the chain is BUILT/normalized
  (order-independent) so shuffled-but-complete bundles are reordered (Notice) not rejected; that chain
  lints run on BOTH `--chain` file bundles and the `--from-host` presented chain; and the explicit
  trust-vs-lint separation (the `--from-host` `verification:` verdict establishes trust to a root via
  webpki-roots; the chain lints only verify the LINKS that are present, and a merely-absent root is a
  Notice, never an Error). (Action: flag only — the README edit is a documentation task folded into the
  integration step / a doc task, NOT into this code spec's production-code tasks. Note it here so it is
  not forgotten at the review gate.)

## Sequencing (batches)

- **Batch A:** task 01 (`cert.rs`: the raw-bytes accessors — name DER, SKI/AKI octets, TBS DER,
  signature value + algorithm OID, issuer SPKI — + in-file tests).
  [`crates/linter/src/cert.rs`]
- **Batch B:** task 02 (`ChainLint` trait + `ChainRegistry`/`default_chain_registry` + the `build_chain`
  construction/normalization step + `RuleSource::Chain` + the 7 always-registered chain lints (2
  construction-driven incl. the redefined `chain_subject_issuer_dn_match` + `chain_not_in_order` +
  `chain_issuer_not_in_chain` + 4 structural link lints) + the `verify` module + `chain_signature_valid`
  + the `verify` cargo feature/deps). depends_on 01.
  [`crates/linter/src/lib.rs`, `src/source.rs`, `src/chain.rs`, `src/lints/mod.rs`,
  `src/lints/chain/*` (incl. `not_in_order.rs`, `issuer_not_in_chain.rs`, `verify.rs`,
  `subject_signature.rs`), `crates/linter/Cargo.toml`]
- **Batch C:** task 03 (CLI/output wiring: `--source chain`, the chain section, the JSON envelope,
  running the chain pass on BOTH `--chain` file bundles AND the `--from-host` presented chain with the
  root-absent Notice, and enabling the linter's `verify` feature by default in the CLI manifest).
  depends_on 02.
  [`crates/cli/Cargo.toml`, `crates/cli/src/main.rs`, `crates/cli/src/output.rs`]
- **Batch D:** task 04 (openssl chain fixtures incl. classical/PQC/bad-signature/unsupported + an
  **unordered/shuffled bundle** + a **broken** bundle (missing-middle/fork) + `generate.sh` chain
  section + `chain.rs` tests (incl. `build_chain` construction cases) + CLI e2e + a `--from-host`
  presented-chain test via the hermetic local TLS server (root-absent Notice) + the `--chain` golden
  regeneration + `cargo audit`). depends_on 03.
  [`testdata/*`, `crates/linter/tests/chain.rs`, `crates/cli/tests/output.rs`, the `--from-host` test
  file, the `--chain` golden snap]

> Conflict audit: `cert.rs` touched only by task 01. `lib.rs` / `source.rs` / `chain.rs` /
> `lints/mod.rs` / `lints/chain/*` (incl. the new `not_in_order.rs` + `issuer_not_in_chain.rs`) /
> `crates/linter/Cargo.toml` only by task 02. `crates/cli/Cargo.toml` / `cli/main.rs` (incl.
> `run_from_host`, Refinement 2) / `cli/output.rs` only by task 03. `testdata/*` (incl.
> `chain_shuffled.pem` + `chain_missing_middle.pem`) + `crates/linter/tests/chain.rs` +
> `crates/cli/tests/output.rs` + the new `crates/cli/tests/from_host.rs` + the golden snap only by task
> 04. `registry.rs` and `finding.rs` are NOT touched by any task (the chain trait/registry/`build_chain`
> live in `chain.rs`). No two tasks share a `touches` file; the chain is strictly serial because 02
> builds on 01's accessors, 03 wires 02's trait/registry/`build_chain`/feature into BOTH the `--chain`
> and `--from-host` paths, and 04 tests 03's CLI surface. Mirrors the 12/13 dependency chain.
