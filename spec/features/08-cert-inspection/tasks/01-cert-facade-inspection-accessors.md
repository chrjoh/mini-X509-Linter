---
agent: developer
seq: 1
title: Cert facade inspection accessors
status: done
touches:
  - crates/linter/src/cert.rs
depends_on: []
---

# Task: Cert facade inspection accessors

## Goal

Extend the `Cert` facade with display-oriented, **owned-return** accessors so the CLI can render a
certificate summary block from our facade (not directly from `x509-parser`). The existing facade is
INSUFFICIENT for inspection: it exposes only `key_cert_sign` (not the full KeyUsage bit set), no
displayable DNs, no displayable serial, no signature/public-key algorithm, and only SAN
emptiness/criticality (not the entries).

## Files Owned (conflict scope)

- `crates/linter/src/cert.rs`

Sole owner of `cert.rs` in feature 08. The CLI task (task 02) depends on these accessors landing
first.

## Owned-return constraint (IMPORTANT)

All accessors go through `with_parsed`, whose closure may NOT leak references into the parsed
`X509Certificate` (its lifetime is local to the call). Every new accessor MUST return **owned** data:
`String`, `Vec<…>`, or small owned view structs (`#[derive(Debug, Clone)]`). Never return a borrow
into the parsed cert. Each accessor returns `Result<…, CertError>` (or `Result<Option<…>, CertError>`
where the field may be absent), matching the existing accessors' style, and must not panic on missing
or malformed fields (use `Option`, never `unwrap`).

## Steps

Add the following accessors and their supporting owned view structs (propose these names/types; keep
them documented and consistent with the existing facade style). Feature-gate `Serialize` on the new
structs behind the existing `serde` feature so the CLI can serialize them (mirror how the contract
types do it):

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
```

1. `subject_rfc4514(&self) -> Result<String, CertError>` — the subject DN as an RFC 4514 string.
2. `issuer_rfc4514(&self) -> Result<String, CertError>` — the issuer DN as an RFC 4514 string.
3. `serial_hex(&self) -> Result<String, CertError>` — the serial as an uppercase hex string (derive
   from `serial_der_octets`; pick a stable formatting — e.g. colon-separated pairs — and document it).
4. `signature_algorithm(&self) -> Result<AlgorithmId, CertError>` where
   `AlgorithmId { oid: String, name: Option<String> }`. `oid` is the dotted-decimal OID string;
   `name` is the human-readable name from `oid-registry` if known, else `None` (PQC OIDs like SLH-DSA
   will be `None` — this is expected and MUST NOT error).
5. `public_key_info(&self) -> Result<PublicKeyInfo, CertError>` where
   `PublicKeyInfo { algorithm: AlgorithmId, key_bits: Option<usize>, curve: Option<String> }` (or a
   similar small owned struct). Populate `key_bits`/`curve` only when the parser reasonably exposes
   them; leave `None` otherwise. Must degrade gracefully for unknown (PQC) key algorithms.
6. `key_usage_bits(&self) -> Result<Option<KeyUsageBits>, CertError>` where `KeyUsageBits` carries the
   **full** set of KeyUsage bits as booleans plus the `critical` bit:
   `digital_signature`, `non_repudiation` (content commitment), `key_encipherment`,
   `data_encipherment`, `key_agreement`, `key_cert_sign`, `crl_sign`, `encipher_only`,
   `decipher_only`, and `critical`. `None` when the extension is absent. (The existing `KeyUsageView`
   stays as-is for the lints; add this richer struct alongside it.)
7. `san_entries(&self) -> Result<Option<SanEntries>, CertError>` where `SanEntries` carries the
   `critical` bit and `entries: Vec<GeneralNameView>`, and
   `GeneralNameView { kind: String, value: String }` — one owned entry per general name (e.g.
   `kind = "DNS"`, `value = "example.com"`; `kind = "IP"`, etc.). Render IPs/other variants as stable
   display strings. `None` when the extension is absent. (The existing `SanView` stays as-is for the
   lints.)

Reuse `oid-registry` (already a dependency) for OID-name lookup. Do NOT add new crate dependencies.
Place the new structs in `cert.rs` (no new file — keeps the touch minimal). Document each item with
`///` per `#[deny(missing_docs)]`, including an `# Errors` section.

## Acceptance Criteria

- [ ] All listed accessors and view structs exist, are documented (`///` + `# Errors`), and return
      owned data only (no borrowed lifetime escapes `with_parsed`).
- [ ] `key_usage_bits` exposes ALL nine KeyUsage bits plus `critical`.
- [ ] `san_entries` returns one owned `GeneralNameView` per SAN entry with a stable `kind`/`value`.
- [ ] `signature_algorithm` and `public_key_info` return the raw OID string and set `name`/details to
      `None` for algorithms unknown to `oid-registry` — never erroring or panicking on PQC OIDs.
- [ ] New view structs derive `Serialize` only under the `serde` feature (no unconditional serde dep).
- [ ] No new crate dependencies added.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` pass.

## Notes / Dependencies

- Blocks task 02 (the CLI summary renderer) and indirectly task 03 (tests).
- Add focused `#[cfg(test)]` unit tests in `cert.rs` against `testdata/good.pem` for the new
  accessors (mirroring the existing `rfc5280_accessors` test module). PQC-specific assertions live in
  task 03 against the committed SLH-DSA fixture.
