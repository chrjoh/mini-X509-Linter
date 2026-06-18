# Feature: CA/Browser Forum S/MIME Baseline Requirements Rule Set

## Overview

Add a fourth rule set: the CA/Browser Forum **S/MIME Baseline Requirements** (S/MIME BR),
enforcing the structurally-checkable requirements that apply to email-protection (S/MIME)
end-entity certificates. This is the email-PKI counterpart to feature 05 (TLS-server BR) and a
sibling of feature 09 (code-signing BR) and feature 11. It introduces a new
[`RuleSource::CabfSmime`] source, a new [`CertPurpose::Smime`] (promoting the long-reserved
variant), a curated subset of ~12 S/MIME lints, and new openssl-generated fixtures — without
regenerating any existing fixture.

S/MIME BR defines human-validation tiers (Mailbox / Organization / Sponsor / Individual) and three
generations (legacy / multipurpose / strict). Those tiers turn on facts a linter cannot observe
(how the CA validated the subject), so **this feature deliberately ports only the structurally
checkable rules** — the ones we can decide from the encoded certificate via the `Cert` facade. The
validation-tier and generation rules are explicitly out of scope.

## The Cascade-Avoidance Decision (CRITICAL — load-bearing, honored throughout)

Feature 05 (TLS BR) chose **broad scoping** (every non-CA leaf is in scope), which forced a
project-wide regeneration of every leaf fixture and lockstep edits to multiple test files. This
feature deliberately does **NOT** repeat that.

**Every `cabf_smime_*` lint's `applies()` returns `NotApplicable` unless the certificate asserts the
`emailProtection` EKU purpose (OID `1.3.6.1.5.5.7.3.4`).** Concretely:

```text
if cert has emailProtection EKU { Applies } else { NotApplicable }
```

(CA certs are also `NotApplicable`: a CA cert is not an S/MIME end-entity. The gate is
"emailProtection EKU present AND not a CA".)

### Why this matters

- Under `default_registry().run()`, every `cabf_smime_*` lint is `NotApplicable` on **all existing
  fixtures** — the TLS/leaf/CA fixtures from features 03/04/05 do not carry the `emailProtection`
  EKU. So:
  - **No existing fixture is regenerated.** `good.pem`, `expired.pem`, every `rfc5280_*`,
    `hygiene_*`, and `cabf_br_*` fixture is untouched.
  - The feature-03/04/05 isolation tests (`each_fixture_isolates_exactly_one_*_violation`),
    the good/expired invariants, and the feature-06 golden test stay green — the only change to
    their world is N additional `NotApplicable` outcomes per cert (the new lints), which the
    existing assertions tolerate by construction (they assert on *firing* findings, not on the raw
    outcome count, except `default_registry::contains_the_known_lints`, which this feature updates
    deliberately).
- This feature therefore adds **only its own new fixtures**: one clean S/MIME leaf plus one
  per-lint violating fixture. This is the explicit design that prevents a feature-05-style cascade.

## Requirements

Implement the following S/MIME BR lints, each tagged [`RuleSource::CabfSmime`], `cabf_smime_*` id,
**EKU-gated** as above, each carrying a comment citing its S/MIME BR section.

| # | lint_id | Rule it enforces | Severity | S/MIME BR § |
|---|---------|------------------|----------|-------------|
| 1 | `cabf_smime_san_present` | SAN extension MUST be present and contain ≥1 `rfc822Name` (email) | Error | §7.1.2.3 (SAN) |
| 2 | `cabf_smime_san_not_critical` | SAN SHOULD NOT be marked critical when the subject DN is non-empty | Warn | §7.1.2.3 |
| 3 | `cabf_smime_email_in_san` | every subject CN that is an email address MUST also appear as an `rfc822Name` in the SAN | Error | §7.1.4.2.1 |
| 4 | `cabf_smime_single_email_subject` | the subject DN MUST carry at most one `emailAddress` (RDN) attribute | Error | §7.1.4.2.1 |
| 5 | `cabf_smime_key_usage_present` | the KeyUsage extension MUST be present | Error | §7.1.2.3 |
| 6 | `cabf_smime_key_usage_critical` | KeyUsage SHOULD be marked critical | Warn | §7.1.2.3 |
| 7 | `cabf_smime_eku_email_protection_present` | EKU MUST assert `emailProtection` (OID `1.3.6.1.5.5.7.3.4`) | Error | §7.1.2.3 (EKU) |
| 8 | `cabf_smime_eku_no_server_auth` | an S/MIME EKU MUST NOT also assert `serverAuth` (no TLS-server multipurpose) | Error | §7.1.2.3 |
| 9 | `cabf_smime_authority_key_identifier_present` | the Authority Key Identifier extension MUST be present | Error | §7.1.2.3 |
| 10 | `cabf_smime_crl_distribution_points_present` | a Subscriber cert MUST carry a CRL Distribution Points extension | Error | §7.1.2.3 |
| 11 | `cabf_smime_crl_distribution_points_http` | every CRL DP `fullName` URI MUST use the `http`/`https` scheme | Error | §7.1.2.3 |
| 12 | `cabf_smime_subject_country_valid` | if a subject `countryName` is present it MUST be a 2-letter (ISO 3166-1 alpha-2 shaped) value | Error | §7.1.4.2 |

Each lint:
- Scopes via `applies()` → `Applies` only when the cert asserts `emailProtection` EKU and is not a
  CA; `NotApplicable` otherwise (see the cascade-avoidance decision).
- Returns `Vec<Finding>` — empty for pass; may return more than one finding (e.g. multiple CNs not
  in SAN, multiple non-http CRL URIs).
- Carries a comment citing its S/MIME BR section number.
- Uses a stable `cabf_smime_*` `lint_id`.

### Rationale for the curated subset (zlint menu trim)

The zlint S/MIME menu has ~36 lints. We pick the ~12 above because each is decidable from the
encoded certificate with our facade (or a modest new accessor). We deliberately **exclude**:

- Validation-tier rules (Mailbox/Organization/Sponsor/Individual) and legacy/multipurpose/strict
  *generation* distinctions — they depend on out-of-band CA validation state the cert does not
  encode (`smime_strict_eku_check` / `smime_legacy_multipurpose_eku_check`,
  `lint_commonname_mailbox_validated`, `lint_cabf_policy_missing` tier semantics).
- `lint_qc_statements_not_critical` / `lint_subject_dir_attr` — niche extensions not present on our
  facade; left for a later iteration to keep this feature tight.
- `lint_rsa_key_usage_strict` / `lint_ecpublickey_key_usages` — key-type-specific KeyUsage bit
  matrices; the generic `cabf_smime_key_usage_present` covers the high-signal case for v1.

> Lint 7 (`cabf_smime_eku_email_protection_present`) is, by construction, always satisfied for any
> cert that reaches `check()` (because `applies()` already required the emailProtection EKU). It is
> retained as an explicit, self-documenting rule so the rule set reads completely against S/MIME BR
> §7.1.2.3, and so its presence is asserted (rather than silently assumed) — it functions as a
> guard that fires only on the defensive `Err` path. Task 02 must document this and NOT make it
> redundant with the gate; alternatively the developer MAY drop it if the reviewer prefers 11 lints,
> but the default is to ship it. (Decision recorded so siblings stay consistent.)

## Architecture

- New module tree `crates/linter/src/lints/cabf_smime/`, one small file per lint, mirroring
  `lints/cabf_br/`. A shared `applies_to_smime_leaf(cert)` helper in `cabf_smime/mod.rs` implements
  the EKU gate once (emailProtection present AND not CA), so every lint's `applies()` is uniform and
  auditable — exactly as `cabf_br/mod.rs::applies_to_leaf` does for BR.
- New source `RuleSource::CabfSmime` in `source.rs` (serde wire string `cabf_smime`).
- New purpose `CertPurpose::Smime` in `registry.rs` (promoting the reserved variant), mapping to
  `[Rfc5280, Hygiene, CabfSmime]`. The `auto` resolver is extended to detect the emailProtection EKU.
- Lints read only through the `Cert` facade. The facade is extended (task 01) with the email-SAN,
  emailProtection-EKU, AKI, CRL-DP, subject-emailAddress, and subject-country accessors the subset
  needs; nothing is read raw inside a lint.

### `auto` resolver precedence (documented, shared with siblings 09/11)

`CertPurpose::Auto` currently resolves serverAuth → TlsServer, else → Generic. With this feature and
its siblings, the leaf-EKU resolution order is:

1. `serverAuth` (OID `…3.1`) present → `TlsServer`.
2. else `codeSigning` (OID `…3.3`) present → `CodeSigning` (added by feature 09).
3. else `emailProtection` (OID `…3.4`) present → `Smime` (added by THIS feature).
4. else → `Generic`.

This precedence is **prescribed** so 05/09/10/11 stay mutually consistent. A cert that asserts both
serverAuth and emailProtection resolves to `TlsServer` (serverAuth wins) — but note lint 8
(`cabf_smime_eku_no_server_auth`) will still flag such a cert *if* it is also linted under the
`CabfSmime` source (e.g. `--source cabf_smime` or `--purpose smime`), which is the intended
multipurpose-abuse signal. Document this interaction in task 02 and task 03.

> SHARED-FILE / SEQUENCING NOTE: `source.rs`, `registry.rs`, `crates/cli/src/main.rs`, and
> `crates/cli/src/output.rs` are ALSO edited by sibling features 09 (code-signing) and 11. The
> `auto` resolver, the `SOURCE_ORDER` / `ALL_SOURCES` arrays, the `--source` token list, the
> `--purpose` ValueEnum, and the registry source-filter unit tests are all common ground. **These
> features must be implemented SEQUENCED, not concurrently**, and whichever lands later must rebase
> onto the resolver/enum shape the earlier one created (extending, never overwriting). This plan
> describes feature 10's slice; the implementer must reconcile with the then-current state of those
> four files.

## Changes Overview

**crates/linter/ (production code — developer tasks 01-03)**

- `src/cert.rs` — extend the facade (task 01): email-SAN (`san_rfc822_names()`), emailProtection
  detection (`has_email_protection()` and/or an `email_protection` field on `EkuView`), Authority
  Key Identifier presence (`has_authority_key_identifier()`), CRL Distribution Points
  (`crl_distribution_point_uris()` → `Vec<String>` of fullName URIs, plus a "present" signal),
  subject `emailAddress` enumeration (`subject_email_addresses()`), and subject `countryName`
  enumeration (`subject_country_names()`).
- `src/source.rs` — add `RuleSource::CabfSmime` (serde `cabf_smime`).
- `src/lints/mod.rs` — `pub mod cabf_smime;`.
- `src/lints/cabf_smime/mod.rs` — module wiring + `applies_to_smime_leaf` helper + re-exports.
- `src/lints/cabf_smime/san_present.rs`
- `src/lints/cabf_smime/san_not_critical.rs`
- `src/lints/cabf_smime/email_in_san.rs`
- `src/lints/cabf_smime/single_email_subject.rs`
- `src/lints/cabf_smime/key_usage_present.rs`
- `src/lints/cabf_smime/key_usage_critical.rs`
- `src/lints/cabf_smime/eku_email_protection_present.rs`
- `src/lints/cabf_smime/eku_no_server_auth.rs`
- `src/lints/cabf_smime/authority_key_identifier_present.rs`
- `src/lints/cabf_smime/crl_distribution_points_present.rs`
- `src/lints/cabf_smime/crl_distribution_points_http.rs`
- `src/lints/cabf_smime/subject_country_valid.rs`
- `src/registry.rs` — register the ~12 lints (after the `cabf_br` block, deterministic order); add
  `CertPurpose::Smime` + its `smime_sources()` helper + extend the `auto` resolver
  (`auto_sources_from` / `resolve`); update the in-file unit tests (lint count 14 → 26; add a
  `cabf_smime` source-filter test; add `Smime` purpose tests).

**crates/cli/ (production code — developer task 03)**

- `src/main.rs` — add `cabf_smime` to `parse_source_token` and the error message; add `CabfSmime`
  to `ALL_SOURCES`; add `Smime` to the `CliPurpose` ValueEnum + the `From<CliPurpose>` mapping +
  the doc comment; update affected unit tests.
- `src/output.rs` — add `RuleSource::CabfSmime` to `SOURCE_ORDER` and to `source_label`
  (`"cabf_smime"`).

**testdata/ (tester — task 04) — NEW fixtures only, openssl-generated, NEVER cert-bar**

- `cabf_smime_good.pem` — a clean S/MIME leaf: `emailProtection` EKU, a SAN with an `rfc822Name`
  (email) that matches any email-shaped subject CN, KeyUsage present + critical
  (digitalSignature / keyEncipherment), AKI present, a CRL DP with an `http` URI, single subject
  emailAddress, valid 2-letter country, currently-valid validity. Passes the entire `cabf_smime`
  set (and rfc5280 + hygiene).
- One per-lint violating fixture, each breaking exactly one `cabf_smime` rule while still asserting
  `emailProtection` (so it stays in scope) and passing the others:
  - `cabf_smime_no_san.pem` (no SAN / no rfc822Name) → lint 1
  - `cabf_smime_san_critical.pem` (SAN marked critical, non-empty subject) → lint 2
  - `cabf_smime_cn_email_not_in_san.pem` (email-shaped CN absent from SAN) → lint 3
  - `cabf_smime_two_email_subject.pem` (two subject emailAddress RDNs) → lint 4
  - `cabf_smime_no_key_usage.pem` (KeyUsage absent) → lint 5
  - `cabf_smime_key_usage_not_critical.pem` (KeyUsage present, non-critical) → lint 6
  - `cabf_smime_eku_server_auth.pem` (emailProtection + serverAuth both) → lint 8
  - `cabf_smime_no_aki.pem` (AKI absent) → lint 9
  - `cabf_smime_no_crl_dp.pem` (CRL DP absent) → lint 10
  - `cabf_smime_crl_dp_ldap.pem` (CRL DP with an `ldap://` URI) → lint 11
  - `cabf_smime_bad_country.pem` (subject country = `USA`, 3 letters) → lint 12
  - (lint 7 has no dedicated violating fixture: a cert without emailProtection is `NotApplicable`,
    so it cannot fire under normal scoping; cover lint 7 with a `check()`-level unit test on the
    defensive `Err` path, per task 02.)
- New integration test `crates/linter/tests/cabf_smime.rs`.
- `testdata/generate.sh` — APPEND a new S/MIME section generating the above. Do NOT alter the
  existing TLS/leaf/CA generation. Mind validity-window time-fragility exactly as feature 05: use a
  currently-valid window and document an annual regeneration chore in the appended section header.

> NO existing fixture is regenerated by this feature. The cascade-avoidance design (EKU gate)
> guarantees the new lints are `NotApplicable` on every pre-existing fixture.

## Time-Fragility (same class as feature 05)

The new S/MIME fixtures must be **currently valid** so `hygiene_not_expired` passes. Use a fixed,
currently-valid window (e.g. the same `2026-06-01 → 2027-06-01` horizon feature 05 uses for its
`BR_OK_*` leaves) and document loudly in the appended `generate.sh` section that these fixtures
EXPIRE on that date and MUST be regenerated annually (slide the window forward). The
`cabf_smime.rs` module doc should reference this so a future flood of `not_expired` failures is
diagnosable.

## Sequencing (batches)

- Batch A: task 01 (cert.rs facade accessors). No dependency.
- Batch B: task 02 (cabf_smime lints + `RuleSource::CabfSmime` in `source.rs` + `lints/mod.rs`
  wiring). Depends on 01.
- Batch C: task 03 (registry registration + `CertPurpose::Smime` + `--purpose`/`auto`/`--source`
  wiring in registry.rs + cli/main.rs + cli/output.rs + their unit-test updates). Depends on 02.
- Batch D: task 04 (new fixtures + `cabf_smime.rs` integration tests + generate.sh append).
  Depends on 03.

Conflict-freedom: each task owns a disjoint `touches` set within this feature. `cert.rs` is owned
only by task 01; `source.rs` + the lint files only by task 02; `registry.rs` + the two cli files
only by task 03; testdata + tests only by task 04. `depends_on` links them in a strict chain, so no
two run concurrently. (Cross-FEATURE conflicts with siblings 09/11 on the shared files are handled
by the cross-feature sequencing note above, outside this task graph.)

## Dependencies

- None new expected. The facade accessors should be implementable with the existing `x509-parser`
  (it already surfaces SAN GeneralNames incl. rfc822Name, EKU purposes incl. emailProtection,
  AuthorityKeyIdentifier, and CRLDistributionPoints). If `x509-parser` does not surface a CRL-DP
  fullName URI conveniently, reach for `der`/`oid-registry` (already present) behind the facade —
  document any addition in `crates/linter/Cargo.toml`. Subject country / emailAddress come from the
  subject `X509Name` RDN iteration already used by `subject_common_names()`.
