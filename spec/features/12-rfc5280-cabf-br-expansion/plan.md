# Feature: RFC 5280 & CA/Browser Forum BR Depth Expansion

## Overview

Features 03 and 05 shipped a deliberately small first pass of each rule set (6 RFC 5280 lints,
4 CA/Browser Forum BR lints). This feature **deepens both existing rule sets** with a curated set of
additional high-signal lints, inspired by the zlint menu, that our `x509-parser` + `der` facade can
support with modest new accessors.

**This feature adds lints to the EXISTING `RuleSource::Rfc5280` and `RuleSource::CabfBr` sources.**
There is **NO new `RuleSource`** and **NO new `CertPurpose`** — that keeps `source.rs` and the purpose
mapping untouched. The new RFC lints run universally (like the existing 6); the new BR lints run under
the existing tls-server purpose mapping (like the existing 4). The only registry change is appending
the new lints to `default_registry()` (so the lint count grows) and updating the in-file count/filter
unit tests.

This is a depth expansion, not an architectural change. The engine, traits, `source.rs`,
`CertPurpose`, CLI wiring, output formatting, and golden-file mechanics are all unchanged.

## Requirements

### New RFC 5280 lints (curated subset — 10 lints, all `RuleSource::Rfc5280`)

Scoping mirrors the existing 6: universal where the rule is universal; `applies()` returns
`NotApplicable` where the rule is structurally inapplicable (CA-only rules on a leaf, or
extension-present-only rules when the extension is absent). **None of these may fire on the current
`good.pem`** (see "Fixture Strategy" — confirmed against good.pem's actual extension set).

1. `rfc5280_basic_constraints_not_critical` — if BasicConstraints is present **and `cA = TRUE`**, it
   MUST be marked critical → `Error`. (RFC 5280 §4.2.1.9)
   - NOTE: this overlaps the existing `rfc5280_basic_constraints_critical_on_ca`. **CUT to avoid a
     duplicate rule** — see "Cuts". (Listed here only to record the deliberate cut.)
2. `rfc5280_ca_subject_field_empty` — a CA certificate MUST have a non-empty subject DN → `Error`.
   `applies()` = CA-only (`NotApplicable` on a leaf). (RFC 5280 §4.1.2.6)
3. `rfc5280_ext_key_usage_without_bits` — if the EKU extension is present it MUST contain at least one
   KeyPurposeId → `Error`. `applies()` = EKU present (`NotApplicable` when absent). (RFC 5280 §4.2.1.12)
4. `rfc5280_ext_authority_key_identifier_no_key_identifier` — if the AKI extension is present it MUST
   contain a `keyIdentifier` field (the BR/RFC norm for non-self-signed certs) → `Error`. `applies()`
   = AKI present (`NotApplicable` when absent). (RFC 5280 §4.2.1.1)
5. `rfc5280_ext_subject_key_identifier_missing_ca` — a CA certificate MUST include a SubjectKeyIdentifier
   extension → `Error`. `applies()` = CA-only. (RFC 5280 §4.2.1.2)
6. `rfc5280_ext_subject_key_identifier_missing_sub_cert` — a sub-certificate (non-CA leaf) SHOULD
   include a SubjectKeyIdentifier extension → `Warn`. `applies()` = non-CA leaf only.
   (RFC 5280 §4.2.1.2)
7. `rfc5280_path_len_constraint_improperly_included` — `pathLenConstraint` is present but the cert is
   NOT a CA with `keyCertSign`, which is the only context where it is meaningful → `Error`.
   `applies()` = `pathLenConstraint` present. (RFC 5280 §4.2.1.9)
8. `rfc5280_ext_name_constraints_not_critical` — if the NameConstraints extension is present it MUST be
   marked critical → `Error`. `applies()` = NameConstraints present. (RFC 5280 §4.2.1.10)
9. `rfc5280_subject_dn_country_not_printable_string` — a subject `countryName` (C) attribute MUST be
   encoded as PrintableString → `Error`. `applies()` = subject has a `countryName` attribute.
   (RFC 5280 §4.1.2.6 / Appendix A — `X520countryName ::= PrintableString`)
10. `rfc5280_ext_san_no_entries` — if the SAN extension is present it MUST contain at least one
    GeneralName → `Error`. `applies()` = SAN present. (RFC 5280 §4.2.1.6)
11. `rfc5280_utc_time_not_in_zulu` — a `UTCTime` validity field MUST end in `Z` (Zulu) and use the
    `YYMMDDHHMMSSZ` form → `Error`. `applies()` = either validity field is encoded as UTCTime.
    (RFC 5280 §4.1.2.5.1)

> That is 10 shipped RFC lints (items 2–11; item 1 is cut). See "Cuts" for the candidates dropped and
> why.

### New CA/Browser Forum BR lints (curated subset — 8 lints, all `RuleSource::CabfBr`)

**Scoping mirrors the existing 4 BR lints (feature 05's BROAD scoping):** `applies()` =
`if cert.is_ca() { NotApplicable } else { Applies }` — every non-CA leaf is in scope, NOT EKU-gated;
CA certs are `NotApplicable`. This is load-bearing and honored throughout.

**Critical constraint (zero existing-fixture regeneration):** Under broad scoping, every new BR lint
runs on the current `good.pem` and on all 9 existing non-CA leaf fixtures. To avoid re-triggering the
feature-05 shared-fixture cascade, **every new BR lint below is chosen so that the current `good.pem`
(and the other compliant leaves) already PASSES it.** No existing fixture is regenerated. (See
"good.pem Conformance Audit" for the per-lint confirmation.)

1. `cabf_br_dnsname_underscore_in_sld` — a SAN `dNSName` MUST NOT contain an underscore in any label
   → `Error` (one finding per offending name). (BR §7.1.4.2 / §3.2.2.4)
2. `cabf_br_dnsname_bad_character_in_label` — a SAN `dNSName` label MUST contain only LDH characters
   (letters, digits, hyphen) → `Error` (one finding per offending name). (BR §7.1.4.2)
3. `cabf_br_dnsname_label_too_long` — no `dNSName` DNS label may exceed 63 octets → `Error` (one
   finding per offending name). (BR §7.1.4.2 / RFC 1035 §2.3.4)
4. `cabf_br_dnsname_wildcard_left_of_public_suffix` — a wildcard `dNSName` of the bare form `*.<tld>`
   (wildcard immediately left of a public suffix, e.g. `*.com`) is prohibited → `Error`.
   `applies()` per broad scoping; the check is over each wildcard SAN entry. (BR §3.2.2.6)
   - Public-suffix handling is intentionally **conservative**: flag only the unambiguous single-label
     case `*.<single-label>` (e.g. `*.com`, `*.local`). A full PSL is out of scope — see
     "Public-Suffix Scope" and the accessor note.
5. `cabf_br_organizational_unit_name_prohibited` — the subject DN MUST NOT contain an
   `organizationalUnitName` (OU) attribute → `Error`. (BR §7.1.4.2.2, OU prohibited since 2022-09-01)
6. `cabf_br_subject_contains_reserved_ip` — a subject **CN** that parses as an IP address MUST NOT be
   a reserved/internal IP → `Error`. Reuses the existing `reserved.rs` classifier. (BR §4.2.2)
   - This complements the existing `cabf_br_no_internal_names_or_reserved_ip` (which checks **SAN**
     entries); this one checks the **CN** value. Distinct surface, distinct fixture.
7. `cabf_br_extra_subject_common_names` — the subject DN MUST contain **at most one** `commonName`
   attribute → `Error` (message names the count). (BR §7.1.4.2.2)
8. `cabf_br_subject_country_not_iso` — if a subject `countryName` (C) is present it MUST be a 2-letter
   ISO 3166-1 alpha-2 code (or the explicitly-allowed `XX`) → `Error`. `applies()` per broad scoping;
   the check is skipped (no finding) when no country attribute is present. (BR §7.1.4.2.2)

> That is 8 shipped BR lints. The remaining candidates were cut — see "Cuts".

## good.pem Conformance Audit (why NO existing fixture is regenerated)

The current `good.pem` (verified via `openssl x509 -text`) is an RSA-2048/SHA-256 v3 **leaf** with
exactly these extensions:
- BasicConstraints `CA:FALSE` (not critical)
- ExtendedKeyUsage = serverAuth (not critical, **has** a key-purpose bit)
- SubjectAlternativeName = `DNS:good.example.com` (one short, LDH-only, non-wildcard label)
- SubjectKeyIdentifier present
- **NO** AuthorityKeyIdentifier, **NO** KeyUsage, **NO** NameConstraints, **NO** pathLenConstraint,
  **NO** CertificatePolicies, **NO** subject countryName, **NO** OU, **single** CN
- validity encoded as `UTCTime` ending in `Z` (Zulu), window 2026-06-01 → 2027-06-01

Per-new-lint result on `good.pem`:

| New lint | good.pem result | Why |
|---|---|---|
| rfc5280_ca_subject_field_empty | NotApplicable | leaf (not CA) |
| rfc5280_ext_key_usage_without_bits | PASS | EKU has serverAuth bit |
| rfc5280_ext_authority_key_identifier_no_key_identifier | NotApplicable | no AKI |
| rfc5280_ext_subject_key_identifier_missing_ca | NotApplicable | leaf |
| rfc5280_ext_subject_key_identifier_missing_sub_cert | PASS | leaf HAS SKI |
| rfc5280_path_len_constraint_improperly_included | NotApplicable | no pathLen |
| rfc5280_ext_name_constraints_not_critical | NotApplicable | no NameConstraints |
| rfc5280_subject_dn_country_not_printable_string | NotApplicable | no country attr |
| rfc5280_ext_san_no_entries | PASS | SAN has one entry |
| rfc5280_utc_time_not_in_zulu | PASS | UTCTime ends in Z |
| cabf_br_dnsname_underscore_in_sld | PASS | `good.example.com` has no `_` |
| cabf_br_dnsname_bad_character_in_label | PASS | LDH-only labels |
| cabf_br_dnsname_label_too_long | PASS | all labels < 64 octets |
| cabf_br_dnsname_wildcard_left_of_public_suffix | PASS | not a wildcard SAN |
| cabf_br_organizational_unit_name_prohibited | PASS | no OU |
| cabf_br_subject_contains_reserved_ip | PASS | CN is a DNS name, not an IP |
| cabf_br_extra_subject_common_names | PASS | exactly one CN |
| cabf_br_subject_country_not_iso | PASS | no country attr → no finding |

**Conclusion: NO existing fixture (good.pem, expired.pem, the 6 rfc5280, the 3 hygiene, the 4 cabf_br,
the 2 CA) needs regeneration.** Every new lint either passes the existing leaves or is `NotApplicable`
to them. Each new lint gets its OWN new violating fixture (see Fixture Strategy). This is the
deliberate "option (a)" from the brief: choose additions good.pem already satisfies.

> One residual risk to confirm in the tester task, NOT a regeneration: the existing `each_fixture_*`
> isolation tests assert "exactly one rule fires across the FULL registry." Adding lints grows the
> registry, but since every new lint passes / is NotApplicable on the existing fixtures, those fixtures
> still fire exactly their one original rule. The isolation assertions therefore remain TRUE without
> editing the existing fixtures. The tester task verifies this explicitly.

## Cuts (candidates dropped, with reasons)

These zlint-menu candidates were considered and **deliberately excluded** from the shipped subset:

- `lint_basic_constraints_not_critical` (RFC) — **duplicate** of the existing
  `rfc5280_basic_constraints_critical_on_ca`. Cut to avoid two lints enforcing the same rule.
- `lint_ext_key_usage_not_critical` (RFC) — EKU criticality is a SHOULD with many legitimate
  exceptions; low signal and noisy. Cut.
- `lint_ext_duplicate_extension` (RFC) — `x509-parser` already errors / de-duplicates on duplicate
  extension OIDs, and crafting a fixture with a genuine duplicate extension is awkward with openssl
  (needs hand DER surgery). Accessor cost is disproportionate. **Cut.**
- `lint_serial_number_longer_than_20_octets` (RFC) — **already covered**: the existing
  `rfc5280_serial_number_positive` emits a distinct finding when `octet_len > 20` (see
  `serial_number_positive.rs` `MAX_SERIAL_OCTETS`). Cut as duplicate.
- `lint_path_len_constraint_zero_or_less` (RFC) — `pathLenConstraint` is a DER `INTEGER` and our facade
  surfaces it as `Option<u32>` (already unsigned/non-negative — see `BasicConstraintsView.path_len`),
  so "zero or less" is not representable without a new signed-DER path. The *improperly-included* check
  (item 7) is the higher-signal, facade-supportable sibling; we ship that and **cut** zero-or-less.
- `lint_generalized_time_not_in_zulu` (RFC) — RFC 5280 requires dates ≥ 2050 to use GeneralizedTime;
  all our fixtures are pre-2050 (UTCTime). A GeneralizedTime fixture needs a > 2050 window, which is
  fine, but the *non-Zulu* violating encoding requires hand DER surgery (openssl always emits Zulu).
  We ship the UTCTime-Zulu check (item 11, same surgery difficulty but the common case) and **cut** the
  generalized-time variant to keep the fixture surgery to one lint. Documented as a future addition.
- `lint_key_usage_and_extended_key_usage_inconsistent` (RFC) — the KU/EKU consistency matrix is large
  and policy-laden; high false-positive risk for a first depth pass. Cut.
- `lint_ext_cert_policy_duplicate` (RFC) and `lint_ext_san_empty_name` / `lint_ext_san_dns_name_too_long`
  (RFC) — `san_dns_name_too_long` is **shipped as the BR variant** (`cabf_br_dnsname_label_too_long`,
  higher signal under BR). The RFC `cert_policy_duplicate` and `san_empty_name` are lower-signal and
  need extra accessors (policy OID enumeration; per-GeneralName empty detection); **cut** for this pass.
- `lint_rsa_mod_less_than_2048_bits` (BR) — **already covered** by the hygiene lint
  `hygiene_rsa_key_min_2048`. The BR-scoped variant would only differ in `RuleSource`/scoping; the rule
  itself is identical and already enforced. Cut to avoid a redundant second implementation of the same
  modulus check. (If BR-specific reporting is ever wanted, revisit.)
- `lint_sub_cert_aia_does_not_contain_ocsp_url` (BR) — requires AIA accessLocation enumeration (a new
  accessor) AND the current `good.pem` has **no AIA**, so a broadly-scoped version would FIRE on
  good.pem → would force regenerating good.pem (adding an AIA with an OCSP URL). That violates the
  "no existing-fixture regeneration" constraint. **Cut** (would re-trigger the cascade).
- `lint_sub_cert_eku_server_auth_client_auth_missing` (BR) — overlaps the existing
  `cabf_br_ext_key_usage_server_auth_present`; the clientAuth half is not a hard BR requirement. Cut.
- `lint_ext_san_missing` (BR) — good.pem HAS a SAN so it would pass, BUT
  `rfc5280_empty_subject_no_san.pem` deliberately has NO SAN; a broadly-scoped "SAN missing" BR lint
  would FIRE on that existing fixture, breaking its isolation test → regeneration. **Cut** (would
  re-trigger the cascade). The SAN-presence concern is already partly covered by
  `rfc5280_san_present_if_subject_empty`.
- `lint_sub_cert_certificate_policies_missing` (BR) — good.pem has **no** CertificatePolicies, so a
  broadly-scoped version FIRES on good.pem → regeneration. **Cut** (would re-trigger the cascade).
- `lint_cab_ov_requires_org` (BR) — OV-specific (depends on policy-OID profiling we do not model). Cut.

> Every cut driven by the cascade (`aia_ocsp`, `san_missing`, `policies_missing`) is recorded here so a
> future feature that is willing to own a good.pem regeneration can pick them up deliberately.

## Architecture

- **No `source.rs` change. No `CertPurpose` change. No engine/trait change.**
- New RFC lints: one small file per lint under `crates/linter/src/lints/rfc5280/`, each
  `RuleSource::Rfc5280`, `rfc5280_*` id, citing its RFC section, following the exact shape of the
  existing 6 (pure `evaluate(...)` helper where useful + `#[cfg(test)] mod tests`).
- New BR lints: one small file per lint under `crates/linter/src/lints/cabf_br/`, each
  `RuleSource::CabfBr`, `cabf_br_*` id, citing its BR section, broad-scoped via
  `applies = if is_ca { NotApplicable } else { Applies }`, reusing `reserved.rs` where relevant.
- New facade accessors live in `cert.rs` (one task owns the file). New views are added next to the
  existing `*View` structs. Lints read ONLY through the facade.
- Registered by appending to `default_registry()` AFTER the existing lints, preserving the existing
  deterministic order (the feature-06 golden test pins order — new lints go at the end of each
  source's block so existing ordering is untouched and the golden snapshot extends rather than
  reshuffles). The golden snapshot regeneration is owned by the tester task.

### Facade accessors needed (grouped in the cert.rs task)

| Accessor (new) | Lints that consume it |
|---|---|
| `authority_key_identifier()` → `Option<AkiView { has_key_identifier: bool, critical: bool }>` | rfc5280_ext_authority_key_identifier_no_key_identifier |
| `has_subject_key_identifier()` → `bool` | rfc5280_ext_subject_key_identifier_missing_ca, ..._missing_sub_cert |
| `name_constraints()` → `Option<NameConstraintsView { critical: bool }>` | rfc5280_ext_name_constraints_not_critical |
| `extended_key_usage()` extension — extend `EkuView` with `is_empty: bool` (no key-purpose bits AND no `other` OIDs AND not `any`) | rfc5280_ext_key_usage_without_bits |
| `subject_alt_name()` view — add `entry_count`/reuse existing `is_empty` (already present on `SanView`) | rfc5280_ext_san_no_entries (reuse existing `SanView.is_empty`) |
| `basic_constraints()` — already exposes `path_len: Option<u32>` and `is_ca`; pair with `key_usage()` for keyCertSign | rfc5280_path_len_constraint_improperly_included |
| `subject_country_values()` → `Vec<String>` (countryName attribute values) | cabf_br_subject_country_not_iso |
| `subject_country_is_printable_string()` → `Option<bool>` (None if no country attr; needs `der` to read the ASN.1 tag of the C attribute value) | rfc5280_subject_dn_country_not_printable_string |
| `subject_organizational_unit_count()` → `usize` (count of OU attributes) | cabf_br_organizational_unit_name_prohibited |
| `subject_common_names()` — ALREADY EXISTS (count > 1 ⇒ extra; first value ⇒ IP parse) | cabf_br_extra_subject_common_names, cabf_br_subject_contains_reserved_ip |
| `san_dns_names()` — ALREADY EXISTS (underscore/LDH/label-length/wildcard checks operate on these strings) | cabf_br_dnsname_* (all four) |
| `validity_time_encodings()` → `(TimeEncoding, TimeEncoding)` where `TimeEncoding { is_utc_time: bool, is_zulu: bool }` (needs `der`/raw bytes to see the ASN.1 time tag + trailing `Z`) | rfc5280_utc_time_not_in_zulu |

Notes on accessor difficulty / cuts:
- The **country PrintableString** and **validity time-encoding** accessors require dropping to `der`
  / raw DER to inspect ASN.1 tags (x509-parser normalizes these away). They are the two non-trivial
  accessors; both are scoped to read a single tag byte and are documented in the task. If the
  time-encoding accessor proves disproportionately hard at implementation time, the developer is
  authorized to cut `rfc5280_utc_time_not_in_zulu` (and its fixture) and note it — it is the lowest of
  the RFC subset in signal. (Recorded so the cut is pre-approved, not a surprise.)
- The **public-suffix** check for the wildcard lint uses NO PSL crate — see Public-Suffix Scope.

### Public-Suffix Scope (wildcard lint)

`cabf_br_dnsname_wildcard_left_of_public_suffix` deliberately does NOT depend on a Public Suffix List.
It flags only the unambiguous bare-wildcard form: a `dNSName` of exactly two labels whose first label
is `*` (e.g. `*.com`, `*.local`, `*.xyz`). Multi-label wildcards like `*.example.com` are NOT flagged
(they are not "immediately left of a public suffix" under this conservative rule). This keeps the lint
dependency-free and false-positive-safe; the docstring states the limitation explicitly.

## Changes Overview

**crates/linter/ (production — developer tasks)**
- `src/cert.rs` — new accessors/views listed above (ONE owner; task 01).
- `src/lints/rfc5280/mod.rs` — declare + re-export the new RFC lint modules (task 02).
- `src/lints/rfc5280/ca_subject_field_empty.rs` (task 02)
- `src/lints/rfc5280/ext_key_usage_without_bits.rs` (task 02)
- `src/lints/rfc5280/ext_authority_key_identifier_no_key_identifier.rs` (task 02)
- `src/lints/rfc5280/subject_key_identifier_presence.rs` — houses BOTH
  `rfc5280_ext_subject_key_identifier_missing_ca` and `..._missing_sub_cert` (sibling rules, one file)
  (task 02)
- `src/lints/rfc5280/path_len_constraint_improperly_included.rs` (task 02)
- `src/lints/rfc5280/ext_name_constraints_not_critical.rs` (task 02)
- `src/lints/rfc5280/subject_dn_country_not_printable_string.rs` (task 02)
- `src/lints/rfc5280/ext_san_no_entries.rs` (task 02)
- `src/lints/rfc5280/utc_time_not_in_zulu.rs` (task 02)
- `src/lints/cabf_br/mod.rs` — declare + re-export the new BR lint modules (task 03)
- `src/lints/cabf_br/dnsname_syntax.rs` — houses the three label-syntax lints
  (`dnsname_underscore_in_sld`, `dnsname_bad_character_in_label`, `dnsname_label_too_long`) +
  `dnsname_wildcard_left_of_public_suffix` (all operate on `san_dns_names()`) (task 03)
- `src/lints/cabf_br/organizational_unit_name_prohibited.rs` (task 03)
- `src/lints/cabf_br/subject_contains_reserved_ip.rs` (task 03)
- `src/lints/cabf_br/extra_subject_common_names.rs` (task 03)
- `src/lints/cabf_br/subject_country_not_iso.rs` (task 03)
- `src/registry.rs` — append new lints to `default_registry()`; update the in-file count test
  (14 → 24), the rfc5280 filter test (6 → 16), the cabf_br filter test (4 → 12); hygiene filter (4)
  unchanged (task 04)

**testdata/ (tester — task 05)**
- `generate.sh` — add one openssl-generated violating fixture per new lint (see Fixture Strategy).
- New fixtures (one per shipped lint, each isolating exactly its rule across the FULL 24-lint
  registry): see Fixture Strategy table for the list and shape.
- Existing fixtures UNCHANGED (no regeneration).

**crates/linter/tests/ + crates/cli/tests/ (tester — task 05)**
- `crates/linter/tests/rfc5280.rs` — per-new-lint flag/pass + extend the isolation test to the new
  rfc5280 fixtures.
- `crates/linter/tests/cabf_br.rs` — per-new-lint flag/pass + multi-finding cases + CA-NotApplicable +
  extend isolation to the new BR fixtures.
- Golden snapshot test (feature 06) — regenerate the snapshot to include the new lint outcomes
  (the snapshot file lives under the feature-06 test; tester owns the regeneration).
- Existing isolation/invariant tests for the OLD fixtures must still pass UNCHANGED in logic (verify;
  no constant changes expected since no window/encoding of existing fixtures changes).

## Fixture Strategy (openssl-generated only; one per new lint)

All fixtures are non-CA leaves UNLESS the lint is CA-only. BR-compliant leaves reuse the existing
`BR_OK` window (2026-06-01 → 2027-06-01) and `make_leaf_ext` pattern so they pass everything except
their one target. CA fixtures reuse the CA window/shape. **Same annual time-fragility as feature 05**
applies to every new leaf fixture — `generate.sh` already documents it; the new fixtures inherit
`BR_OK`/CA windows and need no new dating note beyond reusing the constants.

| New fixture (lint) | shape / single intended violation |
|---|---|
| `rfc5280_ca_subject_empty.pem` (ca_subject_field_empty) | CA cert, empty subject DN; CA window |
| `rfc5280_eku_empty.pem` (ext_key_usage_without_bits) | leaf, EKU extension present but empty (no purposes) |
| `rfc5280_aki_no_keyid.pem` (aki_no_key_identifier) | leaf, AKI present carrying only authorityCertIssuer/Serial, NO keyIdentifier |
| `rfc5280_ski_missing_ca.pem` (ski_missing_ca) | CA cert, no SubjectKeyIdentifier (openssl: omit SKI) |
| `rfc5280_ski_missing_sub_cert.pem` (ski_missing_sub_cert) | leaf, no SubjectKeyIdentifier (omit SKI); else BR-compliant → only the SHOULD/Warn fires |
| `rfc5280_path_len_on_leaf.pem` (path_len_improperly_included) | leaf with `pathlen` set but CA:FALSE (improper) |
| `rfc5280_name_constraints_not_critical.pem` (name_constraints_not_critical) | cert with NameConstraints present but NOT critical |
| `rfc5280_country_not_printable.pem` (country_not_printable_string) | leaf, subject C encoded as UTF8String/IA5String not PrintableString |
| `rfc5280_san_empty.pem` (ext_san_no_entries) | leaf, SAN extension present but with zero GeneralNames |
| `rfc5280_utctime_not_zulu.pem` (utc_time_not_in_zulu) | leaf, UTCTime validity NOT ending in Z (offset form) |
| `cabf_br_dnsname_underscore.pem` (dnsname_underscore_in_sld) | leaf, SAN `DNS:foo_bar.example.com`, CN in SAN to keep cn_in_san quiet |
| `cabf_br_dnsname_bad_char.pem` (dnsname_bad_character_in_label) | leaf, SAN `DNS:foo!bar.example.com` (illegal char) |
| `cabf_br_dnsname_label_too_long.pem` (dnsname_label_too_long) | leaf, SAN with a 64-octet label |
| `cabf_br_dnsname_bare_wildcard.pem` (dnsname_wildcard_left_of_public_suffix) | leaf, SAN `DNS:*.com` |
| `cabf_br_ou_present.pem` (organizational_unit_name_prohibited) | leaf, subject contains an OU attribute |
| `cabf_br_cn_reserved_ip.pem` (subject_contains_reserved_ip) | leaf, CN=`10.0.0.1` (reserved IP), SAN with that IP so SAN lint also predictable — but isolate: see note |
| `cabf_br_two_common_names.pem` (extra_subject_common_names) | leaf, subject with two CN attributes (both in SAN to keep cn_in_san quiet) |
| `cabf_br_country_not_iso.pem` (subject_country_not_iso) | leaf, subject C=`ZZ`/`USA` (not a valid alpha-2) |

> Fixture isolation caveats the tester must mind (each fixture fires EXACTLY its one new rule across
> the full 24-lint registry, and no OLD rule):
> - Several DNS-syntax fixtures put an illegal character in a SAN dNSName. The illegal name must NOT
>   also be the CN-in-SAN matcher — keep a separate compliant `DNS:<cn>` entry so `cabf_br_cn_in_san`
>   stays quiet, and ensure the bad name is not an internal/reserved name (so
>   `cabf_br_no_internal_names_or_reserved_ip` stays quiet) and not too long unless that is the target.
> - `cabf_br_dnsname_bare_wildcard.pem` (`*.com`): `*.com` is a single public label; confirm
>   `reserved.rs::is_internal_name` does NOT classify `*.com` as internal (it should not — `com` is
>   public). The CN should be a normal compliant name present in SAN.
> - `cabf_br_cn_reserved_ip.pem`: the target is the CN-reserved-IP rule. To keep the *existing*
>   `cabf_br_cn_in_san` quiet, put the CN value (`10.0.0.1`) in the SAN as an iPAddress — but that
>   makes the *existing* `cabf_br_no_internal_names_or_reserved_ip` fire too (reserved IP in SAN),
>   breaking single-rule isolation. RESOLUTION: give this fixture a SAN with a compliant public
>   dNSName equal to a CN-like name is impossible (CN is an IP). Instead, scope the test as
>   "fires the CN-reserved-IP rule" and ASSERT it co-fires with the SAN-reserved-IP rule, documenting
>   that this fixture intentionally trips TWO related reserved-IP rules (CN + SAN). The tester should
>   either (a) accept a two-rule fixture here and assert both, or (b) build the CN as an IP with NO
>   SAN iPAddress entry — but BR/`cn_in_san` requires the CN in SAN, so (a) is cleaner. **Document the
>   chosen approach in the test.** This is the one fixture that cannot be perfectly single-rule;
>   tester owns the decision and documents it.
> - `rfc5280_path_len_on_leaf.pem`: openssl may refuse `pathlen` with CA:FALSE via config; if so, the
>   tester byte-patches or uses an explicit ext file. If genuinely not producible with openssl, the
>   tester flags it and the lint+fixture are cut together (noted, pre-approved like the time-encoding
>   cut).

## Dependencies

**None new.** Everything is supported by the already-present `x509-parser`, `der`, and `oid-registry`.
The country-PrintableString and UTCTime-Zulu accessors use `der` (already a dependency) to read raw
ASN.1 tags. The wildcard lint uses no PSL crate (conservative single-label rule). The ISO-3166 check
uses a small in-module allowlist of alpha-2 codes (no crate) — or, if the developer prefers, a minimal
hand-maintained set; document the choice in the lint. No `Cargo.toml` change is expected; if the
developer finds one genuinely necessary, it must be documented and justified in the task.

## Sequencing (batches)

- **Batch A:** task 01 (cert.rs accessors/views).
- **Batch B:** task 02 (new rfc5280 lint files) AND task 03 (new cabf_br lint files) — DISJOINT file
  sets (rfc5280/* vs cabf_br/*), both depend on task 01, so they run in parallel.
- **Batch C:** task 04 (registry.rs registration + count/filter unit-test updates) — depends on 02 and
  03 (references the new lint types).
- **Batch D:** task 05 (fixtures + integration tests + golden snapshot regeneration) — depends on 04.

> Conflict audit: `cert.rs` is touched only by task 01. `lints/rfc5280/*` only by task 02.
> `lints/cabf_br/*` only by task 03. `registry.rs` only by task 04. `testdata/` + `tests/*` only by
> task 05. No two tasks in the same batch share a file. Tasks 02 and 03 are the only same-batch pair
> and their `touches` are fully disjoint.
