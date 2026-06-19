---
agent: developer
seq: 1
title: Cert facade raw-bytes accessors (name DER, SKI/AKI octets, TBS DER, signature value + alg OID, issuer SPKI)
status: done
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade raw-bytes accessors for chain matching

## Goal

Add the read-only raw-bytes accessors the chain lints need: byte-exact matching (the structural link
lints AND the `build_chain` construction step, which links by issuer/subject Name DER + AKI/SKI) AND
signature verification (`chain_signature_valid`). The current facade exposes only
booleans/presence for AKI/SKI (`AkiView.has_key_identifier`, `has_subject_key_identifier`) and lossy
string DNs (`subject_rfc4514`, `issuer_rfc4514`) — none of which support byte-exact comparison or
expose the TBS / signature / SPKI bytes the verifier needs. All new accessors are non-panicking,
documented, return `Result<_, CertError>`, and reuse the existing `with_parsed` pattern. They are plain
`Cert` methods (NOT feature-gated) — only the verify *lint* (task 02) is behind the `verify` feature;
the accessors merely surface bytes already present so they compile in every feature configuration. **Keep every existing accessor
and view (`AkiView`, `BasicConstraintsView`, `KeyUsageView`, `subject_rfc4514`, `issuer_rfc4514`,
`basic_constraints`, `key_usage`, `not_before`, `not_after`, `has_subject_key_identifier`,
`authority_key_identifier`) UNCHANGED.**

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs`

Does NOT touch `lib.rs`, `source.rs`, the lint files, `registry.rs`, `chain.rs`, or the CLI (later
tasks).

## What to Do

1. **`subject_name_der() -> Result<Vec<u8>, CertError>`** — the DER encoding of the subject `Name`
   (the raw RDNSequence bytes, as they appear in the certificate), for byte-exact RFC 5280 §4.1.2.6
   name matching. Document exactly what is returned (the DER of the Name structure). Reuse
   `with_parsed`; reach the subject via the parsed certificate's tbsCertificate.

2. **`issuer_name_der() -> Result<Vec<u8>, CertError>`** — the DER encoding of the issuer `Name`
   (RFC 5280 §4.1.2.4). Same shape as above.

   > The chain lint `chain_subject_issuer_dn_match` compares `subject.issuer_name_der()` against
   > `issuer.subject_name_der()` byte-for-byte. Ensure both return the SAME encoding for the same
   > logical Name (so a self-signed root's `subject_name_der() == issuer_name_der()`); add an in-file
   > test asserting that on an existing self-signed CA fixture.

3. **`subject_key_id_bytes() -> Result<Option<Vec<u8>>, CertError>`** — the raw Subject Key Identifier
   keyIdentifier octets, `Some(bytes)` when the SKI extension is present, `None` when absent. Document
   that this is the keyIdentifier OCTET STRING contents (not the extension wrapper).

4. **`authority_key_id_bytes() -> Result<Option<Vec<u8>>, CertError>`** — the raw Authority Key
   Identifier keyIdentifier octets, `Some(bytes)` when AKI is present AND carries a keyIdentifier
   field, `None` when AKI is absent OR present-but-with-no-keyIdentifier (e.g. AKI carrying only
   authorityCertIssuer/authorityCertSerialNumber). Document this. (This is the byte counterpart of the
   existing `AkiView.has_key_identifier` boolean — keep `AkiView` unchanged.)

5. **`tbs_der() -> Result<Vec<u8>, CertError>`** — the raw DER of the tbsCertificate (the exact bytes
   the signature is computed over). x509-parser exposes the tbsCertificate's raw bytes; return an owned
   `Vec<u8>`. Document that these are the bytes a verifier hashes/verifies over.

6. **`signature_value_bytes() -> Result<Vec<u8>, CertError>`** — the outer signature value octets
   (`signature_value`, the BIT STRING contents). Owned `Vec<u8>`.

7. **`signature_algorithm_oid() -> Result<Oid, CertError>`** (or an owned/`String` OID — pick a
   non-borrowing, non-panicking shape; if returning the x509-parser/oid-registry `Oid` causes lifetime
   friction, return an owned representation) — the OID of the OUTER signatureAlgorithm, used by the
   verify module (task 02) to dispatch to the right crypto backend.

8. **`issuer_spki_bytes() -> Result<Vec<u8>, CertError>`** — the SubjectPublicKeyInfo / public-key
   bytes of THIS cert (named `issuer_spki_bytes` because the chain lint calls it on the issuer cert).
   Decide and DOCUMENT which form you return — full SPKI DER vs the raw public-key BIT STRING contents
   — and keep it consistent with what task 02's verify module consumes (`ring` wants the raw key bytes
   per algorithm; `fips204`/`fips205` want the encoded public key). x509-parser exposes `subject_pki`.
   If two forms are genuinely needed, expose the one most directly useful and let the verify module
   re-derive; document the choice.

9. Add `#[cfg(test)] mod tests` for the new accessors using existing fixtures:
   - present vs absent for SKI/AKI keyIdentifier;
   - non-empty DER for subject/issuer names;
   - self-signed CA fixture: `subject_name_der() == issuer_name_der()`;
   - non-empty `tbs_der()`, `signature_value_bytes()`, `issuer_spki_bytes()`; `signature_algorithm_oid()`
     returns the expected OID on a known fixture (e.g. the RSA-SHA256 or ECDSA fixture);
   - a positive regression that `good.pem`'s existing accessor behavior is unchanged.
   The cross-cert positive controls (leaf.issuer_name_der == intermediate.subject_name_der;
   leaf.authority_key_id_bytes == intermediate.subject_key_id_bytes) and the end-to-end verify of
   tbs/signature/spki are covered by the integration tests in task 04 against the chain fixtures.

## Acceptance Criteria

- [ ] `subject_name_der`, `issuer_name_der`, `subject_key_id_bytes`, `authority_key_id_bytes`,
      `tbs_der`, `signature_value_bytes`, `signature_algorithm_oid`, `issuer_spki_bytes` present,
      documented, return `Result<_, CertError>`, never panic on cert data.
- [ ] `subject_key_id_bytes` / `authority_key_id_bytes` return `None` (not `Err`) when the respective
      extension / keyIdentifier field is absent.
- [ ] Self-signed cert: `subject_name_der() == issuer_name_der()` (in-file test).
- [ ] `tbs_der` / `signature_value_bytes` / `issuer_spki_bytes` non-empty; `signature_algorithm_oid`
      returns the expected OID on a known fixture; the chosen `issuer_spki_bytes` form is documented.
- [ ] All accessors are plain (non-feature-gated) `Cert` methods — compile and pass in the default
      build AND under `--features verify`.
- [ ] All existing `cert.rs` accessors and views are unchanged; existing `cert.rs` tests still pass.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (also `--features serde`).

## Notes / Dependencies

- Blocks task 02 (chain lints + verify module) and task 03 (CLI wiring).
- Reuse the existing `with_parsed` pattern; prefer `std`. No new crate in THIS task — the crypto deps
  (`ring`/`fips204`/`fips205`) are added in task 02 behind the `verify` feature; these accessors only
  surface bytes already reachable through `x509-parser` / `der` (Name DER, keyIdentifier octets, raw
  TBS, signature value, signature-alg OID, SubjectPublicKeyInfo).
