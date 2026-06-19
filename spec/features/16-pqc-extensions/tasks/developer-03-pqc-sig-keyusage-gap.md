---
agent: developer
seq: 3
title: Close pqc_key_usage_consistency gap — flag dataEncipherment / encipherOnly / decipherOnly on a PQC signature key
status: done
touches:
  - crates/linter/src/lints/pqc/key_usage_consistency.rs
depends_on:
  - developer-01-cert-facade-mlkem-and-keyusage-bits
---

# Task: Extend pqc_key_usage_consistency with the three additional encryption bits

## Goal

The existing `pqc_key_usage_consistency` lint (feature 13) flags only `keyEncipherment` (bit 2) and
`keyAgreement` (bit 4) as Error bits on a PQC **signature** key. Extend it to ALSO flag
`dataEncipherment` (bit 3), `encipherOnly` (bit 7), and `decipherOnly` (bit 8) as Error — these are
likewise semantically wrong for a signature-only algorithm (a verifier honouring them would mis-use the
key). The lint id, source, gate, and the existing Warn paths are unchanged. This task adds NO new lint
(the registry count is unaffected by this task).

## Files Owned (conflict scope)

- `crates/linter/src/lints/pqc/key_usage_consistency.rs`

Does NOT touch `cert.rs` (dev-01 — the `KeyUsageView` bits already exist by the time this runs),
`pqc/mod.rs` or the ML-KEM lints (dev-02), `registry.rs` or the CLI (dev-04). The
`key_usage_consistency` module is already declared in `pqc/mod.rs` from feature 13, so NO `mod.rs` edit
is needed.

## What to Do

1. In the pure `evaluate(key_usage: Option<KeyUsageView>, is_ca: bool)` function, inside the existing
   `if let Some(ku) = key_usage { ... }` block (where `keyEncipherment` / `keyAgreement` are already
   checked), add three more **Error** findings, one per bit, each with a distinct named message citing
   RFC 5280 §4.2.1.3 and the bit index:
   - `ku.data_encipherment` (bit 3) asserted → Error.
   - `ku.encipher_only` (bit 7) asserted → Error.
   - `ku.decipher_only` (bit 8) asserted → Error.
   Keep messages consistent in tone with the existing `keyEncipherment` / `keyAgreement` messages
   ("... is asserted on an ML-DSA / SLH-DSA signature key, which cannot perform ...").
2. Update the lint's module doc comment (the `//!` block) to list all five forbidden encryption-class
   bits (`keyEncipherment`, `keyAgreement`, `dataEncipherment`, `encipherOnly`, `decipherOnly`) and the
   rationale (actively-wrong bits for a signature-only key → Error), leaving the existing Warn paths
   (EE missing `digitalSignature`; CA missing `keyCertSign`) documented as-is.
3. Update the `#[cfg(test)] mod tests` `ku()` helper to construct the new fields (the helper currently
   takes `digital_signature, key_encipherment, key_agreement, key_cert_sign`; extend it so the new bits
   are settable — either add parameters or set sensible defaults and add focused test cases). Add tests:
   - one Error each for `dataEncipherment`, `encipherOnly`, `decipherOnly` asserted alone.
   - a multi-finding case asserting several forbidden bits at once on an EE that also omits
     `digitalSignature` (assert the exact Error count + the single Warn).
   - confirm the existing clean-EE / clean-CA pass cases still produce no findings with the new fields
     `false`.

## Acceptance Criteria

- [ ] `evaluate()` emits an Error finding (one per bit, each named) when `dataEncipherment`,
      `encipherOnly`, or `decipherOnly` is asserted on a PQC signature key.
- [ ] The lint id (`pqc_key_usage_consistency`), source (`RuleSource::Pqc`), gate (`applies_to_pqc`), and
      the existing Warn paths are unchanged; NO new lint is added.
- [ ] Module doc lists all five forbidden encryption-class bits with the Error rationale.
- [ ] New unit tests cover each new bit individually and a multi-finding case; existing pass cases still
      pass.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`).

## Notes / Dependencies

- Depends on dev-01 (the `KeyUsageView.data_encipherment` / `encipher_only` / `decipher_only` fields).
- Runs in parallel with dev-02 (disjoint files). Blocks dev-04 only in the sense that the registry test
  is verified after both lint tasks land.
