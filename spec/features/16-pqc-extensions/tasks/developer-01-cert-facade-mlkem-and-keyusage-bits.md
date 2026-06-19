---
agent: developer
seq: 1
title: Cert facade — PublicKeyAlg::MlKem + classify_mlkem_oid + KeyUsageView dataEncipherment/encipherOnly/decipherOnly bits
status: done
touches:
  - crates/linter/src/cert.rs
  - crates/linter/src/lints/cabf_cs/key_usage_required.rs
  - crates/linter/src/lints/cabf_smime/key_usage_critical.rs
  - crates/linter/src/lints/cabf_smime/key_usage_present.rs
depends_on: []
---

# Task: Cert facade ML-KEM recognition + KeyUsageView bit extension

## Goal

Extend the `Cert` facade to recognise the ML-KEM (FIPS 203) SPKI OID arc and to expose three additional
Key Usage bits. All non-panicking, documented, returning the existing accessor types. **Keep existing
`Rsa` / `Ec` / `MlDsa` / `SlhDsa` / `Other` behaviour unchanged** so no current test or fixture breaks.

Because `KeyUsageView` gains fields, every literal-construction site must be updated in THIS task or the
crate will not compile — that is why the cabf_cs / cabf_smime test-helper updates are bundled here.

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs`
- `crates/linter/src/lints/cabf_cs/key_usage_required.rs` (test `ku()` helper literal — additive only)
- `crates/linter/src/lints/cabf_smime/key_usage_critical.rs` (test `ku()` helper literal — additive only)
- `crates/linter/src/lints/cabf_smime/key_usage_present.rs` (test `ku()` helper literal — additive only)

Does NOT touch `pqc/mod.rs`, the ML-KEM lint files, `pqc/key_usage_consistency.rs`, `registry.rs`, or the
CLI (later tasks).

## What to Do

1. **Add `PublicKeyAlg::MlKem(PqcParamSet)`** to the enum (`cert.rs:185`), alongside `MlDsa` / `SlhDsa`.
   Reuse the existing `PqcParamSet { Known(&'static str), Unknown(String) }` enum unchanged. Doc-comment
   it citing **FIPS 203 + the IETF LAMPS ML-KEM X.509 algorithm-identifier profile (RFC/draft number
   TBC)** — do NOT hard-code an unverified RFC number. Note that it is the KEM (encryption-only)
   counterpart to the `MlDsa` / `SlhDsa` signature variants.
2. **Add a second OID-arc classifier — do NOT overload `classify_pqc_oid`** (which keys on the
   `2.16.840.1.101.3.4.3.` sigAlgs arc). Add:
   - `const MLKEM_ARC_PREFIX: &str = "2.16.840.1.101.3.4.4.";` (the NIST "kems" arc).
   - `fn classify_mlkem_oid(dotted: &str) -> Option<PublicKeyAlg>` mirroring `classify_pqc_oid`'s shape
     (single-component suffix only; `.1` → `ML-KEM-512`, `.2` → `ML-KEM-768`, `.3` → `ML-KEM-1024`;
     any other arc member, including `.0` / `.4`+ and multi-component suffixes that still fall under the
     arc, → `PqcParamSet::Unknown(dotted)` so a future `pqc_mlkem_algorithm_known` can fire — per the
     plan's option (A)). Anything outside the arc → `None`.
3. **Wire `classify_mlkem_oid` into `public_key_algorithm()`** (`cert.rs:937`). After the existing
   `classify_pqc_oid(other)` attempt, chain the ML-KEM classifier before the `Other` fallback, e.g.:
   `classify_pqc_oid(other).or_else(|| classify_mlkem_oid(other)).unwrap_or_else(|| Other(other.to_string()))`.
   Keep `Rsa` / `Ec` and the existing match arms unchanged.
4. **Extend `KeyUsageView`** (`cert.rs:91`) with three documented `bool` fields:
   - `data_encipherment` — RFC 5280 §4.2.1.3 bit 3.
   - `encipher_only` — RFC 5280 §4.2.1.3 bit 7.
   - `decipher_only` — RFC 5280 §4.2.1.3 bit 8.
   Document each with its bit index and note they are consumed by `pqc_key_usage_consistency` (a PQC
   *signature* key MUST NOT assert them) and by `pqc_mlkem_key_usage_consistency`.
5. **Populate the new fields in `key_usage()`** (`cert.rs:602`) via x509-parser 0.18's
   `ext.value.data_encipherment()` / `.encipher_only()` / `.decipher_only()` (verified present in the
   installed x509-parser 0.18.1).
6. **Update the four `KeyUsageView` literal sites** to add the three new fields (additive, no behaviour
   change): the production constructor in `key_usage()` (step 5) and the `#[cfg(test)] ku()` helpers in
   `cabf_cs/key_usage_required.rs`, `cabf_smime/key_usage_critical.rs`, `cabf_smime/key_usage_present.rs`.
   Set the new fields to `false` in each test helper (those lints do not exercise the new bits).
   NOTE: `pqc/key_usage_consistency.rs`'s own `ku()` helper is updated by dev-03, NOT here — that file is
   out of this task's scope.
7. Add `#[cfg(test)] mod tests` for `classify_mlkem_oid` mirroring the existing `classify_pqc_oid` tests:
   `.1` → ML-KEM-512 Known, `.2` → ML-KEM-768, `.3` → ML-KEM-1024; `.0` / `.4` → Unknown arc member;
   a non-arc OID (`1.2.840.113549.1.1.1`) → `None`; a multi-component / malformed suffix → handled per
   step 2. Add a regression assertion that `good.pem` (RSA) `public_key_algorithm()` is unchanged.

## Acceptance Criteria

- [ ] `PublicKeyAlg::MlKem(PqcParamSet)` added; `Rsa` / `Ec` / `MlDsa` / `SlhDsa` / `Other` behaviour
      unchanged.
- [ ] `classify_mlkem_oid` recognises `2.16.840.1.101.3.4.4.{1,2,3}` as Known ML-KEM-512/768/1024 and
      other arc members as `Unknown`; it does NOT overload `classify_pqc_oid`.
- [ ] `public_key_algorithm()` returns `MlKem(_)` for an ML-KEM SPKI and is otherwise unchanged.
- [ ] `KeyUsageView` carries documented `data_encipherment` (bit 3), `encipher_only` (bit 7),
      `decipher_only` (bit 8) fields, populated in `key_usage()`.
- [ ] All four `KeyUsageView` literal sites compile with the new fields (production + 3 cabf test helpers).
- [ ] New `classify_mlkem_oid` unit tests + the `good.pem` regression assertion pass.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`: the new `MlKem` variant
      serialises under the existing `serde` derive).

## Notes / Dependencies

- Blocks dev-02 (ML-KEM lints), dev-03 (part-3 KU extension), dev-04 (registry).
- Reuse the existing `with_parsed` pattern and the existing `classify_pqc_oid` / `slh_dsa_param_set_name`
  style. No new crate expected — document any if genuinely necessary.
- The existing `public_key_raw_len()` (cert.rs:1005) and `spki_algorithm_parameters_present()`
  (cert.rs:967) already work for ML-KEM and need NO change — do not modify them.
