---
agent: tester
seq: 4
title: openssl chain fixtures + chain integration tests + CLI e2e + --chain golden regen
status: done
touches:
  - testdata/generate.sh
  - testdata/chain_valid.pem
  - testdata/chain_shuffled.pem
  - testdata/chain_missing_middle.pem
  - testdata/chain_dn_mismatch.pem
  - testdata/chain_aki_ski_mismatch.pem
  - testdata/chain_issuer_not_ca.pem
  - testdata/chain_path_len_exceeded.pem
  - testdata/chain_validity_not_nested.pem
  - testdata/chain_classical_valid.pem
  - testdata/chain_pqc_valid.pem
  - testdata/chain_bad_signature.pem
  - testdata/chain_unsupported_sig_alg.pem
  - crates/linter/tests/chain.rs
  - crates/cli/tests/output.rs
  - crates/cli/tests/from_host.rs
  - crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap
depends_on:
  - developer-03-cli-chain-section-source-and-json-wiring
---

# Task: chain fixtures + chain integration tests + CLI e2e + golden regen

## Goal

Add openssl-generated chain fixtures (a clean valid chain + an **unordered/shuffled** bundle + a
**broken** missing-middle bundle + one violating chain per structural lint, PLUS
classical/PQC/bad-signature/unsupported-algorithm fixtures for `chain_signature_valid`), write the
`chain` integration tests (incl. `build_chain` construction cases + the two new Notice lints + the
verify lint gated `#[cfg(feature = "verify")]`), add CLI `--chain` chain-section + `--source chain` e2e
tests AND a `--from-host` presented-chain test via feature 07's hermetic local TLS server (Refinement 2),
run `cargo audit` on the new crypto deps, and intentionally regenerate ONLY the `--chain` golden(s) to
include the new chain section (which, because the CLI builds with `verify`, includes
`chain_signature_valid`). CRITICAL: the chain pass is a SEPARATE registry that the per-cert path never
invokes, so NO existing single-cert fixture or golden changes, and ALL existing per-cert tests stay green
untouched.

## ⚠️ Fixtures: openssl-generated ONLY — NEVER cert-bar.

The linter must stay an INDEPENDENT oracle. Generate every chain fixture with openssl (± documented DER
byte-patch / direct-`check`-invocation for deviations openssl cannot emit natively). Reuse
`testdata/chain_bundle.pem` (2 certs) for the clean control IF it already satisfies all the chain
lints — verify first; if so, drop `chain_valid.pem` from `touches` and reuse `chain_bundle.pem`.

## ⚠️ Time-Fragility (read first)

All chain fixtures use BR_OK-aligned windows (`2026-06-01 → 2027-06-01`), EXCEPT
`chain_validity_not_nested.pem` which deliberately gives the subject a window extending past the
issuer's. They expire ~2027-06-01; after that `hygiene_not_expired` fires in the per-cert pass and any
per-cert assertions on these fixtures break. Document loudly in the chain section header of
`generate.sh` and reference it in `chain.rs`'s module doc. The chain lints themselves are
clock-independent — keep chain-lint assertions separate from any per-cert "currently valid" assertion.
Regenerate annually.

## Files Owned (conflict scope)

- `testdata/generate.sh` (append a SELF-CONTAINED chain section + the fragility header)
- the new `chain_*.pem` (incl. `chain_shuffled.pem` + `chain_missing_middle.pem`; fewer if
  `chain_bundle.pem` is reused for the clean control)
- `crates/linter/tests/chain.rs` (new)
- `crates/cli/tests/output.rs` (ADD chain tests; do not alter existing assertions)
- `crates/cli/tests/from_host.rs` (NEW — `--from-host` presented-chain tests via the hermetic local TLS
  server; `#[cfg(feature = "fetch")]`)
- `crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap` (intentional regen — chain
  section added; per-cert bytes above MUST be identical)

Does NOT modify `cert.rs`, `source.rs`, `chain.rs`, `lib.rs`, `registry.rs`, `cli/main.rs`,
`cli/output.rs`, or any single-cert fixture/golden.

## What to Do

### 1. `generate.sh` — appended, self-contained chain section

- A fragility header note + BR_OK-aligned window constant.
- Clean chain: leaf → intermediate (CA, keyCertSign, sufficient pathLen, AKI=intermediate-SKI) → root
  (self-signed CA), in leaf-first order. Every link passes all link lints; `build_chain` finds it already
  ordered (no `chain_not_in_order`). Reuse `chain_bundle.pem` if it already qualifies (verify with the
  implemented lints); else mint `chain_valid.pem` (openssl-native, no patch).
- **Construction fixtures (Refinement 1):**
  - `chain_shuffled.pem` — the SAME certs as the clean chain, concatenated in a non-leaf-first order
    (e.g. root, leaf, intermediate). Openssl-native, no separate issuance — just a reordered concat.
    → only `chain_not_in_order` Notice, all link checks pass.
  - `chain_missing_middle.pem` — the clean chain's leaf + root only (intermediate omitted). Openssl-
    native concat. → `chain_subject_issuer_dn_match` Error.
  - Fork / cycle: cover by **direct `build_chain` invocation** in `chain.rs` (no committed PEM; openssl
    won't mint a cycle, and a fork needs contrived shared-DN certs). Document.
- One violating chain per structural (link) lint (see test-plan.md Fixtures table):
  - `chain_dn_mismatch.pem` — leaf's issuer DN ≠ intermediate's subject DN.
  - `chain_aki_ski_mismatch.pem` — leaf AKI keyId present but ≠ intermediate SKI (both present).
  - `chain_issuer_not_ca.pem` — issuer is CA:FALSE or lacks keyCertSign.
  - `chain_path_len_exceeded.pem` — 3-cert chain: root pathLen=0 → intermediate CA → leaf.
  - `chain_validity_not_nested.pem` — leaf notAfter beyond issuer notAfter.
- Signature-verification fixtures (`chain_signature_valid`):
  - `chain_classical_valid.pem` — valid RSA/ECDSA chain, every link verifies (positive control, `ring`).
  - `chain_pqc_valid.pem` — ML-DSA root → ML-DSA intermediate → leaf, openssl 3.6.2 (exercises
    fips204/fips205). Document the openssl >= 3.6.2 requirement in the chain header; if the host lacks
    it, cover the PQC path by direct `verify::verify_signature`/`ChainLint::check` invocation on a
    committed fixture and note the regeneration prerequisite.
  - `chain_bad_signature.pem` — a link whose signature does NOT verify against its named issuer
    (preferred: openssl-native mismatched-key issuance; acceptable: documented single-byte DER patch of
    one signature value). Asserts `chain_signature_valid` **Error** on the broken link.
  - `chain_unsupported_sig_alg.pem` *(if expressible)* — a link using an algorithm outside the supported
    matrix (e.g. RSA-PSS / P-521, pending the developer's confirmed matrix) → `chain_signature_valid`
    **Notice**. If not cleanly producible, cover the Notice path by direct `verify_signature` with an
    unknown OID and skip committing this fixture (document).
- For any deviation openssl cannot produce cleanly (e.g. forcing a non-matching AKI), the tester decides
  per fixture: openssl config, openssl + targeted DER byte-patch (documented), OR test that lint by
  **direct `ChainLint::check(subject, issuer)` invocation** on two hand-loaded `Cert`s. Document the
  decision per fixture in `chain.rs` and `generate.sh`.
- Run `bash testdata/generate.sh`; commit every new `.pem`. Restore tracked fixtures (if perturbed)
  with `git checkout -- 'testdata/*.pem'` — NEVER `git checkout -- testdata/` (that clobbers
  `generate.sh`).

### 2. `crates/linter/tests/chain.rs` (new; SIFER, `.unwrap()`/`.unwrap_err()`)

- Per lint, through `default_chain_registry().run`: load the violating chain, assert exactly the target
  `chain_*` finding fires at the documented severity ON THE EXPECTED LINK (`subject_index`/`issuer_index`),
  message names the offending value; the clean chain produces no error/warn chain findings.
- **Construction / order-independence (Refinement 1):**
  - `chain_not_in_order`: on `chain_shuffled.pem`, exactly the Notice fires; the link lints over the
    REORDERED chain all pass (NO Error/Warn from disorder). On the already-ordered clean chain it does
    NOT fire. Assert link findings attach to the BUILT-order link indices.
  - `chain_subject_issuer_dn_match` (REDEFINED): Error on `chain_missing_middle.pem` and
    `chain_dn_mismatch.pem`; **Warn** on a fork (direct `build_chain` invocation — assert the
    deterministic lowest-input-index pick); **Error** on a cycle (direct invocation, terminates);
    passes on the clean chain.
  - `chain_issuer_not_in_chain`: Notice on the top cert when the bundle omits the root; does NOT fire
    when a self-signed root is present.
  - Determinism: `build_chain` on the same shuffled input twice → identical order + diagnostics.
- `chain_issuer_is_ca` (Error on issuer_not_ca;
  exercise both CA:FALSE and no-keyCertSign — direct invocation if needed),
  `chain_path_len_respected` (Error on path_len_exceeded; pass-by-vacuity when issuer has no pathLen —
  direct invocation), `chain_validity_nested` (Warn on validity_not_nested; clock-independent).
- `chain_aki_ski_match`: Error on aki_ski_mismatch; pass-by-vacuity (NO finding) when subject lacks AKI
  keyId OR issuer lacks SKI (direct invocation on such certs).
- `chain_signature_valid` *(`#[cfg(feature = "verify")]` test module/asserts)*: **pass** on
  `chain_classical_valid` and `chain_pqc_valid`; **Error** on `chain_bad_signature` on the broken link
  (message mentions "signature does not verify"); **Notice** on the unsupported-algorithm case (fixture
  or direct `verify::verify_signature` with an unknown OID). Also assert that WITHOUT `verify`,
  `default_chain_registry()` has no `chain_signature_valid` (gate the sig-verify asserts behind
  `#[cfg(feature = "verify")]` and add a `#[cfg(not(feature = "verify"))]` count assertion of 7; a
  `#[cfg(feature = "verify")]` count assertion of 8).
- Chain-length gating: `run` on a single cert / empty slice → empty (no link reports).
- Graceful degradation: a link where an accessor errors degrades to no finding, never panics, other
  links still report.
- **Additive-design assertions:** `default_registry()` (per-cert) contains NO `chain_*` id; running the
  per-cert registry over a chain fixture yields ONLY per-cert outcomes (no chain findings). The chain
  pass is reachable only via `default_chain_registry()`.
- Module doc: time-fragility window, openssl-only fixtures, additive-separate-pass design.

### 3. `crates/cli/tests/output.rs` (ADD only)

- `--chain` default run on the clean chain → existing per-cert report UNCHANGED, then the "Chain checks:"
  section (all links pass / documented placeholder). Assert the per-cert bytes above are unchanged.
- `--chain` on `chain_dn_mismatch.pem` → chain section shows the Error on the offending link;
  `--fail-on error` returns the findings exit code (assert exit code).
- `--chain` on `chain_bad_signature.pem` → chain section shows the `chain_signature_valid` **Error** on
  the broken link; `--fail-on error` returns the findings exit code (the CLI builds with `verify`).
- `--chain` on `chain_shuffled.pem` → chain section shows the `chain_not_in_order` Notice and links in
  BUILT order, all passing; `--min-severity warn` hides the Notice; no Error/Warn.
- `--chain` on `chain_missing_middle.pem` → chain section shows the `chain_subject_issuer_dn_match`
  Error; `--fail-on error` returns the findings exit code.
- `--source chain` on the clean chain → ONLY the chain section (per-cert pass filtered out).
- `--source rfc5280` under `--chain` → NO chain section (chain deselected); per-cert report unchanged.
- Single-cert input (no `--chain`) → NO chain section; output unchanged.
- JSON `--chain` on the clean chain → `{ "certificates": [...], "chain": [...] }`; `certificates`
  matches the existing per-cert shape verbatim; `chain` carries the link outcomes + construction findings
  with `source: "chain"`. JSON single-cert → unchanged (no `chain` key).
- Do NOT change any existing assertion or constant.

### 3b. `crates/cli/tests/from_host.rs` (NEW; Refinement 2; `#[cfg(feature = "fetch")]`)

Use feature 07's hermetic local TLS server (`crates/fetch/tests/handshake.rs`'s `TestServer` pattern:
a `rustls` server on an ephemeral `127.0.0.1` port, background thread, presenting a configured chain
minted with `rcgen`). Build/run with `--features "fetch"` (and the CLI's default `verify`). Cases:

- **Server presents leaf + intermediate (NO root)** → after the leaf report + `presented_chain` +
  `verification:` verdict (UNCHANGED), the `[chain]` section appears: the present link passes (incl.
  `chain_signature_valid` via `ring`), and the top intermediate carries the `chain_issuer_not_in_chain`
  Notice. Assert it is a Notice, NOT an Error, and the bytes above the chain section are unchanged.
- **Server presents leaf + intermediate + root** → links pass; NO `chain_issuer_not_in_chain` Notice.
- **Server presents a single leaf only** → NO chain section; leaf report + verdict unchanged.
- **JSON (leaf + intermediate, no root)** → the document gains a sibling `chain` key alongside the
  unchanged `presented_chain`/`verification`/`outcomes` (and `summary` under `--info`); the `chain`
  carries the link outcome + the `chain_issuer_not_in_chain` Notice. Single-leaf JSON → no `chain` key.
- **Trust-vs-lint separation:** a server whose links are sound but whose root is untrusted →
  `verification: invalid` WHILE the chain lints pass. Assert both independently.
- These use direct stdout assertions (certs minted per-test), NOT goldens.

### 4. Golden regeneration (the ONLY permitted golden churn)

- Regenerate `golden__text_output__chain_bundle_text.snap` intentionally to include the "Chain checks:"
  section. REVIEW the diff: it must add ONLY the chain section; the per-cert report bytes above must be
  byte-for-byte identical.
- If a `--chain` JSON golden exists, regenerate it to the `{ certificates, chain }` envelope (add it to
  `touches`). Verify which `--chain` goldens exist before regenerating.
- **Verify the diff touches NO single-cert golden** (`good_text`, `good_json`, `good_verbose_text`, the
  source-group snapshots). If feature 14's `--chain --info` snapshot exists and now carries a sibling
  `chain` array, regenerate it intentionally too (add to `touches`) and reconcile with feature 14's
  envelope — note this in the test.

## Acceptance Criteria

- [ ] openssl-generated chain fixtures added: the clean chain + `chain_shuffled.pem` +
      `chain_missing_middle.pem` + the structural-link violating chains + classical/PQC/bad-signature
      (+ unsupported-alg if expressible) for sig-verify (clean controls openssl-native; deviations via
      documented openssl config / DER byte-patch / direct-invocation); NO single-cert fixture modified;
      `generate.sh` chain section carries the fragility header, the openssl >= 3.6.2 (ML-DSA) note, and
      per-fixture producibility notes.
- [ ] Order-independence proven: `chain_shuffled.pem` → only `chain_not_in_order` Notice + all link
      checks pass over the reordered chain; `chain_missing_middle.pem` (+ fork/cycle via direct
      invocation) → `chain_subject_issuer_dn_match` Error/Warn; construction is deterministic.
- [ ] Root-absent proven: a bundle/host missing its root → `chain_issuer_not_in_chain` Notice, never an
      Error.
- [ ] The clean chain passes all link lints; the classical and PQC chains pass `chain_signature_valid`;
      the bad-signature chain fires its Error on the correct link; the unsupported-alg case is a Notice
      (fail-open). Each violating chain isolates exactly its one chain rule on the correct link;
      pass-by-vacuity cases produce no finding.
- [ ] `chain.rs` covers per-lint flag/pass, the `build_chain` construction cases (ordered/shuffled/
      missing-middle/fork/cycle/missing-top/AKI-SKI-disambiguation/determinism), the two new Notice
      lints, per-link attachment over the BUILT order, length gating, graceful degradation, the sig-verify
      cases (gated `#[cfg(feature = "verify")]`, with `#[cfg(not(feature = "verify"))]` count-of-7 and
      `#[cfg(feature = "verify")]` count-of-8 assertions), and the additive-design assertions (no
      `chain_*` in `default_registry()`).
- [ ] CLI e2e (`output.rs`): `--chain` chain-section (incl. `chain_signature_valid`), the shuffled +
      missing-middle cases, `--source chain`, chain-deselected suppression, single-cert unchanged, JSON
      envelope, the bad-signature Error, and the chain `--fail-on` exit code — all added; existing
      assertions unchanged.
- [ ] `from_host.rs` (Refinement 2): `--from-host` presented-chain tests via the hermetic local TLS
      server — leaf+intermediate (root-absent Notice), leaf+intermediate+root (no Notice), single-leaf
      (no chain section), JSON sibling `chain` key, and the trust-vs-lint separation.
- [ ] The `--chain` text golden regenerated (CLI build = `verify` on) with ONLY the chain section added;
      no single-cert golden changed.
- [ ] `cargo test`, `cargo test -p cli --features fetch`, `cargo test -p linter --features verify`,
      `cargo test -p linter --features serde`, `cargo clippy --all-targets --features "serde verify"
      -- -D warnings`, `cargo fmt --check`, and `cargo audit` (on `ring`/`fips204`/`fips205`) all
      pass / recorded.

## Notes / Dependencies

- Depends on task 03 (CLI wired). This is the last task in the feature.
- README Scope-note update (flipping the "no chain-aware lints" non-goal, and noting pure-Rust
  signature verification) is a documentation step flagged in plan.md's Ripple Flag — coordinate at the
  review gate; it is NOT part of this test task's `touches`.
- The crypto deps (`ring`/`fips204`/`fips205`) are added in task 02 behind the `verify` feature; this
  task RUNS `cargo audit` to confirm no advisories (A03) and records the result. PQC fixtures need
  openssl >= 3.6.2.
