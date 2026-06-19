# Test Plan: Chain-Aware Lints

## Scope

Verify the **8** `chain` lints — 7 always-registered (2 construction-driven:
`chain_subject_issuer_dn_match` (redefined structural-integrity verdict) + `chain_not_in_order` Notice;
plus `chain_issuer_not_in_chain` Notice; plus 4 structural link lints: AKI/SKI, issuer-is-CA, path-len,
validity-nested) + `chain_signature_valid` (cryptographic, behind the `verify` feature) — the new
`ChainLint` trait + chain pass + `ChainRegistry` / `default_chain_registry()`, the **`build_chain`
construction/normalization step** (order-independent leaf→top linkage by DN + AKI/SKI, with the
disorder/missing-middle/unlinkable/fork/cycle/missing-top diagnostics), the new `cert.rs` raw-bytes
accessors (`subject_name_der`, `issuer_name_der`, `subject_key_id_bytes`, `authority_key_id_bytes`,
`tbs_der`, `signature_value_bytes`, `signature_algorithm_oid`, `issuer_spki_bytes`), the isolated
`verify` module (OID → `ring`/`fips204`/`fips205` dispatch), the `verify` cargo feature, the new
`RuleSource::Chain` source, and the CLI chain-section + `--source chain` + JSON envelope wiring over
BOTH `--chain` file bundles AND the `--from-host` presented chain.

**Feature-gating property (load-bearing).** With the linter's `verify` feature OFF,
`default_chain_registry()` holds 7 chain lints and `chain_signature_valid` is absent; with `verify` ON,
it holds 8. The CLI builds with `verify` ON by default, so CLI e2e + goldens see all 8. Tests must
assert BOTH counts (`cargo test -p linter` for 7; `cargo test -p linter --features verify` for 8).

**Four load-bearing properties (each is itself a test objective):**

1. **Additive engine — per-cert path UNCHANGED.** `default_registry()`, the per-cert `Lint` pass, the
   per-purpose `*_sources()` helpers, and ALL existing per-cert filter-count tests are unchanged. The
   chain pass is a separate `default_chain_registry()` over a separate `ChainLint` trait.
2. **Chain pass runs ONLY on a real chain.** It executes only when there are ≥2 presented certs AND the
   `chain` source is selected — via `--chain` (file bundle) OR `--from-host` (presented chain).
   Single-cert input (one-cert file, or a single-leaf `--from-host`) and any default (no `--chain` /
   `--from-host`) run produce byte-for-byte UNCHANGED output (text + JSON); the chain pass never
   executes.
3. **Order-independence + deterministic construction.** `build_chain` reorders a complete-but-shuffled
   bundle so the link checks pass (only a `chain_not_in_order` Notice fires); a genuinely broken set
   (missing-middle / unlinkable / fork / cycle) surfaces via `chain_subject_issuer_dn_match`
   Error/Warn; a merely-absent root is a `chain_issuer_not_in_chain` Notice, never an Error.
   Construction is deterministic (stable tie-breaks by input index) so the built order, labels, and
   snapshots are reproducible.
4. **No clock dependence / determinism.** Chain lints compare cert-intrinsic fields and each other,
   never "now" (`chain_validity_nested` compares the two certs' own windows). The chain report is
   snapshot-stable; link order is BUILT chain order, lint order is registration order.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()`, behaviour-focused tests
grouped per lint in nested modules. Fixtures openssl-generated only; never cert-bar; never hand-author
cert bytes beyond targeted DER byte-patching where the tester documents openssl cannot produce the
deviation natively.

## ⚠️ Fixtures: openssl-generated ONLY — NEVER cert-bar

Generate every chain fixture with openssl so the linter stays an INDEPENDENT oracle. Reuse
`testdata/chain_bundle.pem` (2 certs) where it fits; mint new chain fixtures otherwise.

## ⚠️ Time-Fragility

All chain fixtures use validity windows aligned with the existing `BR_OK` horizon
(`2026-06-01 → 2027-06-01`, except `chain_validity_not_nested` which deliberately gives the subject a
window extending past the issuer's). They EXPIRE ~2027-06-01; after that `hygiene_not_expired` fires in
the per-cert pass and any per-cert assertions on these fixtures break. Document loudly in the chain
section header of `generate.sh` and reference it in `chain.rs`'s module doc. Regenerate annually.
**The chain lints themselves are clock-independent**, but per-cert assertions in the same test files
are not — keep chain-lint assertions separate from any per-cert "currently valid" assertion.

## Fixtures (`testdata/`) — all openssl-generated, NEVER cert-bar

A **clean valid chain** = leaf → intermediate (CA, keyCertSign, pathLen sufficient) → root
(self-signed CA), in leaf-first order, where `build_chain` finds it already ordered (NO
`chain_not_in_order`) and every link satisfies all four STRUCTURAL link lints: AKI matches issuer SKI,
each issuer is a CA with keyCertSign, pathLen respected, validity nested — and the redefined
`chain_subject_issuer_dn_match` passes (one clean single chain). If the bundle includes its self-signed
root, no `chain_issuer_not_in_chain` Notice fires (the top is its own anchor); if it omits the root, the
Notice fires on the top intermediate. (If reused as a `chain_signature_valid` positive control too, it
must also use a supported
signature algorithm so verification passes — see the classical/PQC controls below.)

| Fixture | shape | isolates (chain lint) |
|---|---|---|
| `chain_valid.pem` (or reuse `chain_bundle.pem` if it already satisfies all link lints) | clean leaf→intermediate→root, in leaf-first order, all links pass all chain lints, BR_OK windows | nothing in the chain set (clean positive control); note a bundle that OMITS the root → `chain_issuer_not_in_chain` Notice on the top intermediate |
| `chain_shuffled.pem` *(NEW, Refinement 1)* | the SAME complete chain as `chain_valid.pem` but in a non-leaf-first file order (e.g. root, leaf, intermediate) | `chain_not_in_order` (**Notice** only) — `build_chain` reorders, all link checks still pass, NO Error/Warn |
| `chain_missing_middle.pem` *(NEW, Refinement 1)* | leaf + root only (the intermediate that links them is absent), so the leaf's issuer is not in the set | `chain_subject_issuer_dn_match` (**Error** — broken chain, missing middle link) |
| `chain_dn_mismatch.pem` | leaf whose **issuer** DN does not equal the intermediate's **subject** DN (e.g. intermediate re-minted with a different subject) — under the redefined lint this is an unlinkable/missing-issuer set | `chain_subject_issuer_dn_match` (Error) |
| `chain_aki_ski_mismatch.pem` | leaf carrying an AKI keyIdentifier that does NOT equal the intermediate's SKI (both present, differing bytes) | `chain_aki_ski_match` (Error) |
| `chain_issuer_not_ca.pem` | leaf "issued" by a cert that is NOT a CA (basicConstraints CA:FALSE or no keyCertSign) | `chain_issuer_is_ca` (Error) |
| `chain_path_len_exceeded.pem` | a CA with `pathLenConstraint = 0` that nonetheless has an intermediate CA below it (≥1 intermediate where 0 allowed) | `chain_path_len_respected` (Error) |
| `chain_validity_not_nested.pem` | leaf whose `notAfter` extends beyond its issuer's `notAfter` (subject outlives issuer) | `chain_validity_nested` (Warn) |
| `chain_classical_valid.pem` | valid classical chain (RSA and/or ECDSA), every link signature verifies | `chain_signature_valid` pass via `ring` (positive control) |
| `chain_pqc_valid.pem` | valid PQC chain: ML-DSA root → ML-DSA intermediate → leaf (openssl 3.6.2-generated) | `chain_signature_valid` pass via `fips204`/`fips205` (PQC positive control) |
| `chain_bad_signature.pem` | a link whose signature does NOT verify against its named issuer's key (DER-patch one signature byte, OR a cert signed by a different key than the named issuer) | `chain_signature_valid` (Error) |
| `chain_unsupported_sig_alg.pem` *(if expressible)* | a link signed with an algorithm outside the supported matrix (e.g. RSA-PSS or P-521 if `ring` cannot verify it) | `chain_signature_valid` (Notice — fail-open) |

Producibility caveats (tester owns the decision, like prior features):

- **`chain_shuffled.pem`** is trivially openssl-native: concatenate the SAME three PEMs as the clean
  control in a non-leaf-first order (e.g. root, then leaf, then intermediate). It needs NO separate
  issuance — it is a reordered concatenation of `chain_valid.pem`'s certs. Assert that `build_chain`
  reorders it, only `chain_not_in_order` (Notice) fires, and NO link lint reports Error/Warn.
- **`chain_missing_middle.pem`** = the clean control's leaf + root PEMs concatenated WITHOUT the
  intermediate (openssl-native, no patching). Assert `chain_subject_issuer_dn_match` Error.
- **Fork / cycle construction cases** are best covered by **direct `build_chain` invocation** on
  hand-loaded `Cert`s rather than committed PEM fixtures (a fork needs two certs sharing a subject DN
  that both plausibly issue the leaf; a cycle is not normally producible by openssl). Reuse
  cross-signed-shaped certs if available, otherwise construct the candidate sets in-test and assert the
  fork → Warn (with the deterministic lowest-input-index tie-break) and cycle → Error. Document that no
  PEM fixture is committed for these.
- **`chain_dn_mismatch`, `chain_aki_ski_mismatch`, `chain_path_len_exceeded`** require minting a chain
  whose links deliberately disagree — produced by generating the certs with mismatched
  subjects/keyids/pathLen in `generate.sh` (openssl config + separate issuance steps), NOT by
  byte-patching where avoidable. Where openssl will not cleanly emit a mismatch (e.g. forcing an AKI
  that differs from the real issuer SKI may require a custom AKI value), the tester decides per fixture:
  openssl config, openssl + targeted DER byte-patch (documented), OR test that lint by **direct
  `ChainLint::check(subject, issuer)` invocation** on two hand-loaded `Cert`s. Document per fixture in
  `chain.rs` and `generate.sh`.
- **`chain_aki_ski_match` pass-by-vacuity** cases (subject without AKI keyIdentifier; issuer without
  SKI) are tested by direct `check` invocation on certs lacking those extensions (reuse an existing
  AKI-less / SKI-less fixture if one exists) — assert NO finding.
- **`chain_path_len_exceeded`** needs ≥3 certs (root with pathLen=0 → intermediate CA → leaf) so an
  intermediate exists below the constrained CA. Mint a 3-cert chain.
- The clean control (`chain_valid.pem` / reused `chain_bundle.pem`) MUST be openssl-native (no
  patching). If `chain_bundle.pem` already satisfies all the link lints (and is leaf-first so no
  `chain_not_in_order` fires), reuse it and add NO new clean fixture; verify this first. (Note: if it is
  reused as the `chain_signature_valid`
  positive control too, confirm openssl produced it with an algorithm in the supported matrix — RSA or
  ECDSA P-256/P-384 — so it is a `Verified` pass, not a `Notice`.)
- **`chain_classical_valid` / `chain_pqc_valid`** are openssl-native positive controls (no patching).
  The PQC chain requires openssl 3.6.2 (ML-DSA support); document the openssl version in the chain
  section header. If the build/test host lacks ML-DSA-capable openssl, the tester may instead exercise
  the fips204/fips205 path by **direct `verify::verify_signature` / `ChainLint::check` invocation** on a
  committed PQC fixture and document that the regeneration step needs openssl 3.6.2.
- **`chain_bad_signature`** (tester owns producibility): preferred is openssl-native — issue the subject
  with a key that does NOT match the named issuer's SPKI (so the signature genuinely fails). Where that
  is awkward, a documented single-byte DER patch of one link's signature value is acceptable (restore
  with `git checkout -- 'testdata/*.pem'`, never the whole dir). Either way assert `chain_signature_valid`
  fires **Error** on exactly the patched/mismatched link.
- **`chain_unsupported_sig_alg`** is best-effort: if openssl can mint a chain using an algorithm the
  backends cannot verify (e.g. RSA-PSS or ECDSA P-521, pending the developer's confirmed matrix), use
  it to assert the **Notice** fail-open path; otherwise cover the Notice path by direct
  `verify::verify_signature` invocation with an unknown/unsupported OID and document that no openssl
  fixture is committed for it.
- Run **`cargo audit`** after the `verify` deps land (A03); record the result. Flag if any advisory hits
  `ring` / `fips204` / `fips205`.

## Unit Tests (in-file, owned by the developer tasks — listed for coverage tracking)

### `cert.rs` (task 01)

- `subject_name_der()` / `issuer_name_der()` return non-empty DER; for a self-signed cert (root)
  subject_name_der == issuer_name_der; for the leaf, `leaf.issuer_name_der()` ==
  `intermediate.subject_name_der()` on a real chain (the byte-exact match the lint relies on).
- `subject_key_id_bytes()` returns `Some(bytes)` when SKI present, `None` when absent.
- `authority_key_id_bytes()` returns `Some(bytes)` when AKI keyIdentifier present, `None` when AKI
  absent OR AKI present-but-no-keyIdentifier (e.g. AKI carrying only authorityCertIssuer).
- On a real chain, `leaf.authority_key_id_bytes()` == `intermediate.subject_key_id_bytes()` (positive
  control proving the byte match).
- `tbs_der()` / `signature_value_bytes()` / `issuer_spki_bytes()` return non-empty bytes for a normal
  cert; `signature_algorithm_oid()` returns the expected OID for a known fixture (e.g. the RSA-SHA256 or
  ECDSA fixture). These accessors are feature-INDEPENDENT (plain `Cert` methods) — assert they compile
  and work in BOTH the default build and `--features verify`.
- Existing accessors unchanged (negative regression: `good.pem` behavior unchanged).

### chain trait / registry / construction (task 02; `src/chain.rs`)

- `default_chain_registry()` holds exactly **7** chain lints WITHOUT `verify`, and **8** WITH
  `--features verify` (the 8th is `chain_signature_valid`); all `source() == RuleSource::Chain`, with the
  documented `chain_*` ids (incl. `chain_subject_issuer_dn_match`, `chain_not_in_order`,
  `chain_issuer_not_in_chain`), in deterministic registration order. Assert both counts under the two
  feature sets (`#[cfg(feature = "verify")]`-gated assertion for the 8th).
- `ChainRegistry::run(chain)` returns an EMPTY vec for `chain.len() < 2` (0 and 1 cert).
- For an N-cert chain it returns N-1 `ChainLinkReport`s in BUILT chain order, plus the construction-level
  findings (`chain_not_in_order`, `chain_issuer_not_in_chain`, structural-integrity verdict) surfaced at
  their documented home. `RuleSource::Chain` serializes to `"chain"` (serde feature).
- **`build_chain` construction unit tests:**
  - Clean, already-ordered chain → built order == input order, NO `chain_not_in_order`, structural
    verdict passes.
  - Shuffled-but-complete chain → built order is leaf→top regardless of input order; exactly
    `chain_not_in_order` (Notice) fires; the link lints over the built order all pass.
  - Missing middle link → `chain_subject_issuer_dn_match` Error; no panic.
  - Unlinkable / extra cert → `chain_subject_issuer_dn_match` Error.
  - Fork (cert with >1 candidate issuer) → `chain_subject_issuer_dn_match` Warn; the engine picks the
    lowest-input-index candidate DETERMINISTICALLY (assert the chosen edge is stable across runs).
  - Cycle → `chain_subject_issuer_dn_match` Error; terminates (no infinite loop).
  - Missing top issuer (root absent) → `chain_issuer_not_in_chain` Notice on the top cert; NOT an Error.
  - AKI/SKI disambiguation: two certs share a subject DN but only one matches the leaf's AKI → the
    AKI-matching one is chosen as issuer (assert).
  - Determinism: running `build_chain` twice on the same shuffled input yields byte-identical ordering
    and diagnostics.

### verify module (task 02; `src/lints/chain/verify.rs`, `#[cfg(feature = "verify")]`)

- OID → backend dispatch: each supported OID (RSA-SHA256/384/512, ECDSA P-256/P-384, Ed25519,
  ML-DSA-44/65/87, SLH-DSA variants) routes to its backend; a known-good (tbs, signature, spki) triple
  yields `Verified`; a corrupted signature yields `Failed`.
- An unknown / out-of-matrix OID yields `Unsupported` (never `Failed`) — the fail-open contract.
- Malformed inputs (truncated spki / wrong-length signature) do NOT panic — they yield `Failed` or
  `Unsupported` (developer documents which; the lint then degrades, never panics).
- These can be exercised with bytes pulled from the committed classical/PQC fixtures (so no key material
  is hand-authored).

### `registry.rs` (NOT touched by this feature)

- The chain registry lives in `chain.rs`, so `registry.rs` is untouched. The per-cert
  `default_registry()` count and ALL per-cert filter-count tests are UNCHANGED (chain lints are NOT in
  the per-cert registry). The additive-design assertion that `default_registry()` contains NO `chain_*`
  id lives in `crates/linter/tests/chain.rs` (see below), not in a registry.rs edit. The chain-registry
  count assertions (7 without `verify`, 8 with) live in `chain.rs` too.

## Integration Tests (`crates/linter/tests/chain.rs`)

- **Per lint, through `default_chain_registry().run`:** load the violating chain fixture, run the chain
  pass, assert exactly the target `chain_*` finding fires at the documented severity on the expected
  link (with a message substring naming the offending value — the mismatched DN/keyid, the non-CA
  issuer, the pathLen, the validity bound), and that the clean chain produces NO error/warn chain
  findings.
- **Per-link attachment:** assert the finding is attached to the correct `(subject_index, issuer_index)`
  link (e.g. on a 3-cert path-len fixture, the violation is on the root→intermediate or
  intermediate→leaf link as designed).
- **Construction / order-independence (Refinement 1):**
  - **`chain_not_in_order`:** on `chain_shuffled.pem`, exactly the `chain_not_in_order` **Notice** fires
    and ALL link lints pass over the reordered chain (NO Error/Warn from mere disorder); on the
    already-ordered clean chain it does NOT fire.
  - **`chain_subject_issuer_dn_match` (redefined):** **Error** on `chain_missing_middle.pem` (leaf's
    issuer absent) and on `chain_dn_mismatch.pem` (unlinkable set); **Warn** on a fork (direct
    `build_chain` invocation — assert the deterministic lowest-input-index pick); **Error** on a cycle
    (direct invocation, terminates); **pass** on the clean chain (one linear chain, whether ordered or
    shuffled).
  - **`chain_issuer_not_in_chain`:** **Notice** on the top intermediate when the bundle omits the root;
    does NOT fire when a self-signed root is present (top is its own anchor). NEVER an Error.
- **Link lints run over the BUILT order:** on `chain_shuffled.pem`, assert the link findings (or
  absence thereof) attach to the reordered `(subject_index, issuer_index)` links, not the raw input
  positions.
- **`chain_aki_ski_match`:** Error on `chain_aki_ski_mismatch`; pass-by-vacuity (NO finding) when the
  subject has no AKI keyIdentifier OR the issuer has no SKI (direct `check` invocation on such certs).
- **`chain_issuer_is_ca`:** Error on `chain_issuer_not_ca`; pass on the clean chain. Exercise both the
  `cA=FALSE` path and the `cA=TRUE`-but-no-`keyCertSign` path (direct invocation if a fixture for each
  is not separately producible; document).
- **`chain_path_len_respected`:** Error on `chain_path_len_exceeded` (pathLen=0 CA with an intermediate
  below it); pass on the clean chain; pass-by-vacuity when the issuer has no `pathLenConstraint`
  (unconstrained) — direct invocation.
- **`chain_validity_nested`:** Warn on `chain_validity_not_nested` (subject outlives issuer); pass on
  the clean chain (subject window within issuer window). Clock-independent — assert it does NOT depend
  on "now" (the fixture windows are fixed).
- **`chain_signature_valid`** *(gated `#[cfg(feature = "verify")]`)*: **pass** on `chain_classical_valid`
  (every link verifies via `ring`) and on `chain_pqc_valid` (via `fips204`/`fips205`); **Error** on
  `chain_bad_signature` on exactly the broken link, message mentions "signature does not verify";
  **Notice** on the unsupported-algorithm case (fixture or direct `verify_signature` with an unknown
  OID), message "signature not verified: unsupported algorithm". With `verify` OFF, assert
  `chain_signature_valid` is NOT in the registry (no such finding can fire). Self-signed root self-link:
  if implemented (Open Decision 8), assert a clean self-signed root verifies and a corrupted
  self-signature is caught.
- **Chain length gating:** `default_chain_registry().run(&certs[..1])` (single cert) → empty; an empty
  slice → empty.
- **Graceful degradation:** a chain where one cert cannot yield a needed accessor value degrades to no
  finding on that link, never panics, and the other links still report (direct invocation with a
  deliberately truncated/odd cert if feasible; otherwise document the degradation path is covered by
  the accessor `Err` arm).
- Module doc: note the time-fragility window, the openssl-only fixtures, and the
  additive-separate-pass design.

## CLI E2E (`crates/cli/tests/output.rs`, ADD only)

- **`--chain` default run on the clean chain** → the existing per-cert chain report renders UNCHANGED,
  followed by the new "Chain checks:" section showing each link with no findings (or the documented
  placeholder). The CLI is built with `verify` by default, so `chain_signature_valid` participates
  (passing on a valid chain). The per-cert report bytes above the chain section are unchanged.
- **`--chain` on `chain_bad_signature.pem`** → the chain section shows the `chain_signature_valid`
  **Error** on the broken link; `--fail-on error` returns the findings exit code.
- **`--chain` on a violating chain** (e.g. `chain_dn_mismatch.pem`) → the chain section shows the
  `chain_subject_issuer_dn_match` Error on the offending link; `--fail-on error` returns the
  findings exit code (chain findings feed the exit code exactly like per-cert findings — assert).
- **`--source chain` on the clean chain** → ONLY the chain section renders (the per-cert pass is
  filtered out); the `[chain]`/"Chain checks:" block is present.
- **`--source rfc5280` (no chain) under `--chain`** → NO chain section (chain source deselected), and
  the per-cert report is unchanged. Document this suppression.
- **Single-cert input (no `--chain`)** → NO chain section; output byte-for-byte unchanged.
- **JSON `--chain` on the clean chain** → the `{ "certificates": [...], "chain": [...] }` envelope; the
  `certificates` array matches the existing per-cert shape verbatim; the `chain` array carries one entry
  per link with `subject`, `issuer`, and `outcomes` (`{ lint_id, source: "chain", findings }`).
- **JSON single-cert** → unchanged (no `chain` key).
- **`--chain` on `chain_shuffled.pem`** → the chain section shows the `chain_not_in_order` Notice and the
  links rendered in BUILT (leaf→top) order, all passing; `--min-severity warn` hides the Notice.
- **`--chain` on `chain_missing_middle.pem`** → the chain section shows the `chain_subject_issuer_dn_match`
  Error; `--fail-on error` returns the findings exit code.
- Do NOT change any existing assertion or constant beyond the intentionally-regenerated `--chain`
  golden (below).

## CLI E2E — `--from-host` presented chain (Refinement 2; hermetic local TLS server)

Use feature 07's hermetic local TLS server harness (`crates/fetch/tests/handshake.rs`'s `TestServer`
pattern — a `rustls` server on an ephemeral `127.0.0.1` port, background thread, presenting a configured
cert chain). These tests require the `fetch` feature (and run with the CLI's default `verify`). The
server can present **leaf + intermediate WITHOUT the root** (the realistic case). The tester chooses the
file (`crates/cli/tests/inspect.rs` or a new `crates/cli/tests/from_host.rs`).

- **`--from-host` presenting leaf + intermediate (no root)** → after the existing leaf report,
  `presented_chain` display, and `verification:` verdict (all UNCHANGED), the `[chain]` section appears:
  the present leaf→intermediate link checks pass (incl. `chain_signature_valid` via `ring`, since the
  CLI builds with `verify`), and the top intermediate carries the **`chain_issuer_not_in_chain`**
  Notice (root absent). Assert the Notice is NOT an Error and the leaf/verdict bytes above are unchanged.
- **`--from-host` presenting leaf + intermediate + root** → the chain section's links all pass and NO
  `chain_issuer_not_in_chain` Notice (the self-signed root is its own anchor).
- **`--from-host` presenting a single leaf only** → NO chain section (no link to lint); the leaf report +
  verdict are unchanged (byte-for-byte vs the pre-feature behavior for that server).
- **`--from-host` JSON** (leaf + intermediate, no root) → the document gains a sibling `chain` key
  alongside the unchanged `presented_chain` / `verification` / `outcomes` (and `summary` under `--info`)
  keys; the `chain` carries the link outcomes + the `chain_issuer_not_in_chain` construction Notice at
  its documented home. A single-leaf `--from-host` JSON has NO `chain` key.
- **Trust-vs-lint separation:** a server whose chain links are all sound but whose root is untrusted
  yields `verification: invalid` (the connection verdict) WHILE the chain lints pass (the present links
  are sound) — assert both independently, demonstrating the lints do not duplicate trust validation.
- Since the presented certs are minted per-test (rcgen, like feature 07), these use direct assertions on
  stdout, NOT goldens.

## Golden Regeneration (the ONLY permitted golden churn — tester-owned)

- The existing `--chain` text golden (`crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap`)
  gains the "Chain checks:" section — regenerate it intentionally and review the diff (it must add ONLY
  the chain section; the per-cert report bytes above must be identical).
- Any `--chain` JSON golden moves to the `{ certificates, chain }` envelope — regenerate intentionally.
- **All single-cert goldens** (`good_text`, `good_json`, `good_verbose_text`, source-group snapshots)
  MUST remain byte-for-byte unchanged — verify the diff touches no single-cert snapshot. Restore
  tracked fixtures (if perturbed) with `git checkout -- 'testdata/*.pem'` — NEVER `git checkout --
  testdata/` (that would clobber `generate.sh`).

## Cross-Feature Regression (must still pass UNCHANGED — proves the additive design)

- `crates/linter/tests/rfc5280.rs`, `hygiene.rs`, `not_expired.rs`, `cabf_br.rs`, `cabf_cs.rs`,
  `cabf_smime.rs`, `pqc.rs`, and the per-cert assertions in `registry.rs` — all pass with NO edits (the
  chain pass is a separate registry that the per-cert path never invokes).
- `cli/tests/output.rs` existing tests and all single-cert goldens pass unchanged.
- `crates/cli/tests/inspect.rs` (feature 14 `--chain --info`) — verify the chain section does NOT
  disturb the `--info` summary blocks; if `--chain --info` JSON now also carries a sibling `chain`
  array, that is an intentional, called-out addition (reconcile with feature 14's envelope and
  regenerate that snapshot if one exists — tester-owned, noted).

## Edge Cases

- 0-cert and 1-cert chains → chain pass returns empty; no chain section; no JSON `chain` key.
- A self-signed single root presented alone (1 cert) → no chain pass (needs ≥2).
- A root presented as the top of a chain (subject==issuer at the top link) → `build_chain` recognizes it
  as the self-signed anchor (NOT a cycle); the engine evaluates the N-1 adjacent pairs of the BUILT order
  (a 3-cert chain has 2 links, leaf→int and int→root). No `chain_issuer_not_in_chain` Notice (the root
  is its own issuer).
- A complete chain in SHUFFLED file order → `build_chain` reorders it; only `chain_not_in_order` (Notice)
  fires; link checks run over the built order and pass. (The pre-refinement false-Error case is gone.)
- A bundle missing its root at the top → `chain_issuer_not_in_chain` Notice on the top cert, never an
  Error. Uniform across `--chain` files and `--from-host`.
- AKI present but carrying only authorityCertIssuer/Serial (no keyIdentifier) → `authority_key_id_bytes`
  returns `None` → `chain_aki_ski_match` pass-by-vacuity.
- Issuer with `pathLen` absent (unconstrained) → `chain_path_len_respected` pass-by-vacuity regardless
  of depth.
- `--source chain` on a single-cert input → no chain section (still needs ≥2 certs); the per-cert pass
  is filtered out, so the output is the (possibly empty) selected-source per-cert report only —
  document this combination.

## Verification Commands

```
cargo test                                                # workspace (CLI builds linter with verify)
cargo test -p cli --features fetch                         # incl. --from-host presented-chain tests (Refinement 2)
cargo test -p linter                                      # linter WITHOUT verify → 7 chain lints
cargo test -p linter --features serde                     # serde shape
cargo test -p linter --features verify                    # WITH verify → 8 chain lints (sig-verify)
cargo test -p linter --features "serde verify"            # both
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features serde -- -D warnings
cargo clippy --all-targets --features "serde verify" -- -D warnings
cargo fmt --check
cargo audit                                               # A03 supply-chain on ring/fips204/fips205
openssl version                                           # PQC fixtures need openssl >= 3.6.2 (ML-DSA)
bash testdata/generate.sh
```

## Exit Criteria

The 8 `chain` lints (7 always-registered, incl. the `build_chain` construction lints +
`chain_signature_valid`) + the `ChainLint` trait + chain pass + `build_chain` construction/normalization
+ `default_chain_registry()` + the 8 `cert.rs` accessors + the `verify` module + the `verify` cargo
feature + the `RuleSource::Chain` source + CLI chain-section / `--source chain` / JSON envelope over BOTH
`--chain` files AND the `--from-host` presented chain are validated; the additive-design property is
proven (per-cert path and all existing per-cert tests/goldens UNCHANGED); the feature-gating property is
proven (7 chain lints without `verify`, 8 with); the chain-pass-only-on-real-chain property is proven (no
chain section/key for single-cert or non-`--chain`/non-`--from-host` runs);
**order-independence is proven** (a shuffled-but-complete bundle reorders → only `chain_not_in_order`
Notice + all link checks pass; a missing-middle/fork/cycle set surfaces `chain_subject_issuer_dn_match`
Error/Warn; construction is deterministic); **root-absent handling is proven** (a bundle/host missing its
root → `chain_issuer_not_in_chain` Notice, never an Error); the `--from-host` presented chain runs the
chain pass after the verdict with the trust-vs-lint separation demonstrated; the clean chain passes all
link lints; classical and PQC chains pass `chain_signature_valid` and the bad-signature chain fires its
Error on the correct link; the unsupported-algorithm case is a Notice (fail-open), never a false Error;
each violating chain isolates exactly its one chain rule on the correct link; pass-by-vacuity cases
produce no finding; the `--chain` golden is intentionally regenerated (with `verify` on) with ONLY the
chain section added; no single-cert fixture or golden is changed; `cargo audit` is clean (or advisories
recorded) on the new crypto deps; all verification commands green.
