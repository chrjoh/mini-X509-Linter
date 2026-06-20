# Feature: CA/Browser Forum Baseline Requirements expansion (feature 17)

## Overview

Features 05 and 12 shipped 12 CA/Browser Forum Baseline Requirements (BR) lints under
`RuleSource::CabfBr`. This feature **deepens the `cabf_br` source only** with a curated set of
**12 NEW structurally-decidable BR lints** (count settled at 12 — no AIA lints, no push to 15),
inspired by the zlint menu, that our `x509-parser` + `der` facade already supports (or supports with
one small new accessor).

> **Phase-1.5 decisions folded in (2026-06-20):**
> 1. **All 12 lints are kept.** The count is settled at 12; no AIA lints are added and there is no
>    push to 15.
> 2. **Lint 5 (`cabf_br_ext_key_usage_server_auth_required`) is kept.** Its two-rule co-fire with the
>    existing `cabf_br_ext_key_usage_server_auth_present` on `cabf_br_missing_serverauth.pem` is
>    reconciled by the tester as a documented two-rule assertion (NOT a cut) — see Cascade-Management §B.
> 3. **`good.pem` is made BR-compliant** by adding a `certificatePolicies` extension carrying the
>    reserved CABF **DV** policy OID `2.23.140.1.2.1`. This turns lints 8
>    (`certificate_policies_present`) and 9 (`certificate_policies_reserved_oid`) into **POSITIVE
>    passes** on good.pem, so good.pem **PASSES all 12 new lints with NO Warn** and stays completely
>    finding-free. To keep this byte-deterministic, good.pem's RSA key is **PINNED** (committed
>    `testdata/keys/good.key`) so its SKI / serial / signature bytes stay stable and ONLY the
>    `certificatePolicies` extension is added — see "good.pem regeneration strategy". The previously
>    "open question" Warn on good.pem is therefore resolved: good.pem has zero findings.

**Scope is `cabf_br` ONLY.** EV / code-signing / S/MIME are separate existing/future features and are
NOT touched. There is **NO new `RuleSource`** and **NO new `CertPurpose`** — `source.rs` and the
purpose mapping are untouched. The new lints run under the existing `tls-server` purpose mapping and,
per the feature-05 BROAD-scoping decision, apply to **every non-CA leaf** (EKU-gated only where the
rule itself requires it). The only registry change is appending the new lints to `default_registry()`
(growing the count) and updating the in-file count/filter unit tests.

This is a depth expansion, not an architectural change. The engine, traits, `source.rs`,
`CertPurpose`, CLI wiring, and output formatting are all unchanged. The golden snapshots and the
in-file registry counts ripple additively (see "Cascade-Management Strategy").

"Structurally-decidable" means checkable from the **encoded certificate alone**. This linter is
**offline**: NO network, NO CA / validation-state, NO revocation, NO trust-store. Every zlint BR rule
that needs out-of-band state is OUT of scope and is enumerated in "Cuts (out of scope / cascade)".

## Requirements

### New CA/Browser Forum BR lints (curated subset — 12 lints, all `RuleSource::CabfBr`)

**Scoping mirrors the existing 12 BR lints (feature 05's BROAD scoping):** every lint reuses the
shared `applies_to_leaf(cert)` helper in `cabf_br/mod.rs`, i.e.
`if cert.is_ca() { NotApplicable } else { Applies }` — every non-CA leaf is in scope, NOT EKU-gated;
CA certs are `NotApplicable`. This is load-bearing and honored throughout.

**Critical constraint (one targeted regeneration: good.pem only):** Under broad scoping, every new BR
lint runs on `good.pem` and on all existing non-CA leaf fixtures. Eleven of the twelve new lints are
shaped so the current leaves already PASS them (or are `NotApplicable`). The single exception is the
CertificatePolicies pair (lints 8/9): rather than ship lint 8 as a `Warn` that fires on a
policies-free good.pem (the earlier "option (a)"), **good.pem is regenerated once** to ADD a
`certificatePolicies` extension carrying the reserved CABF **DV** OID `2.23.140.1.2.1`. This makes
good.pem genuinely BR-compliant: lint 8 PASSES (policies present) and lint 9 PASSES (a reserved OID is
present). good.pem ends up **finding-free across all 12 new lints**. No OTHER existing fixture is
regenerated. To keep the good.pem regeneration byte-minimal, its RSA key is **pinned** — see "good.pem
regeneration strategy". The per-lint confirmation is in the "good.pem Conformance Audit".

Verified `good.pem` extension set **after regeneration**: RSA-2048/exp-65537 v3 **leaf** (key PINNED,
SKI/serial unchanged), BasicConstraints `CA:FALSE` (non-critical), ExtendedKeyUsage = `serverAuth`
only (non-critical), SubjectAlternativeName = `DNS:good.example.com` (one short LDH non-wildcard
label), **CertificatePolicies = `2.23.140.1.2.1` (DV, non-critical) — NEW**, SubjectKeyIdentifier
present, single CN; **NO** KeyUsage, **NO** AuthorityInfoAccess, **NO** pathLenConstraint, **NO**
NameConstraints, **NO** subject countryName, **NO** OU.

1. `cabf_br_subscriber_key_usage_cert_sign_prohibited` — a subscriber (non-CA leaf) certificate MUST
   NOT assert the `keyCertSign` KeyUsage bit (bit 5) → `Error`. (BR §7.1.2.7.x — subscriber
   certificate KeyUsage; `keyCertSign` is a CA-only bit, RFC 5280 §4.2.1.3.) `applies()` = broad
   leaf. Check is skipped (no finding) when no KeyUsage extension is present. Accessor: existing
   `key_usage()` → `KeyUsageView.key_cert_sign`.
   - good.pem: PASS (no KeyUsage extension → nothing to flag).

2. `cabf_br_subscriber_key_usage_crl_sign_prohibited` — a subscriber certificate MUST NOT assert the
   `cRLSign` KeyUsage bit (bit 6) → `Error`. (Same clause; `cRLSign` is a CA-only bit.) `applies()` =
   broad leaf; skipped when no KeyUsage extension. Accessor: existing `key_usage()` →
   `KeyUsageView.crl_sign`.
   - good.pem: PASS (no KeyUsage extension).
   - Housed in the SAME file as lint 1 (`subscriber_key_usage_prohibited.rs`); sibling rules, one file.

3. `cabf_br_subscriber_basic_constraints_path_len_prohibited` — a subscriber certificate MUST NOT
   include a `pathLenConstraint` in BasicConstraints (it is meaningful only for a CA) → `Error`.
   (BR §7.1.2.7.x / §7.1.2.4; RFC 5280 §4.2.1.9 — `pathLenConstraint` only with `cA=TRUE` and
   `keyCertSign`.) `applies()` = broad leaf. Accessor: existing `basic_constraints()` →
   `BasicConstraintsView.path_len.is_some()`.
   - good.pem: PASS (no pathLenConstraint).
   - NOTE: complements feature-12's `rfc5280_path_len_constraint_improperly_included` (RFC source,
     fires whenever path_len present on a non-CA-with-keyCertSign). This is the **BR-scoped** sibling
     (broad leaf scoping, `cabf_br_*` id, BR clause). They will CO-FIRE on the same path-len-on-leaf
     fixture by construction — the tester documents the two-rule co-fire (see Fixture Strategy). This
     is an intentional dual-source finding, like the feature-12 underscore/bad-char co-fire.

4. `cabf_br_ext_key_usage_any_prohibited` — a subscriber TLS certificate MUST NOT assert
   `anyExtendedKeyUsage` (OID `2.5.29.37.0`) in its EKU → `Error`. (BR §7.1.2.7.6 — the subscriber
   EKU MUST contain `id-kp-serverAuth` and MAY contain `id-kp-clientAuth`; `anyExtendedKeyUsage` is
   prohibited.) `applies()` = broad leaf. Accessor: existing `extended_key_usage()` →
   `EkuView.oids` contains `"2.5.29.37.0"`. Skipped (no finding) when no EKU extension present.
   - good.pem: PASS (EKU = serverAuth only; no `any`).

5. `cabf_br_ext_key_usage_server_auth_required` — a subscriber TLS certificate's EKU, **when
   present**, MUST include `id-kp-serverAuth` (OID `1.3.6.1.5.5.7.3.1`) → `Error`. (BR §7.1.2.7.6.)
   `applies()` = broad leaf. Accessor: existing `extended_key_usage()` → `EkuView.server_auth`.
   Check is skipped (no finding) when the EKU extension is ABSENT — this is what keeps it distinct
   from the existing `cabf_br_ext_key_usage_server_auth_present` (which flags the **absent-EKU**
   case). This new lint flags the **EKU-present-but-no-serverAuth** case (e.g. an EKU asserting only
   `clientAuth`). Distinct surface, distinct fixture.
   - good.pem: PASS (EKU present and has serverAuth).
   - OVERLAP CHECK (RESOLVED — lint 5 is KEPT): the existing `cabf_br_ext_key_usage_server_auth_present`
     fires when no serverAuth purpose is asserted at all. The existing BR fixture
     `cabf_br_missing_serverauth.pem` (EKU present WITHOUT serverAuth) therefore CO-FIRES both the
     existing lint and this new one. Per Phase-1.5 decision 2, lint 5 is **NOT cut**. Resolution:
     lint 5's OWN new fixture `cabf_br_eku_no_server_auth.pem` is the single-rule isolating fixture,
     and the existing `cabf_br_missing_serverauth.pem` isolation test is **reconciled to a documented
     two-rule assertion** (it asserts the TWO related serverAuth rules co-fire), following the
     feature-12 underscore/bad-char two-rule precedent. The tester owns this reconciliation and
     documents it. See "Cascade-Management Strategy §B".

6. `cabf_br_san_dns_or_ip_only` — every Subject Alternative Name entry of a subscriber TLS
   certificate MUST be a `dNSName` or `iPAddress` GeneralName; other GeneralName types
   (`rfc822Name`, `URI`, `directoryName`, `otherName`, etc.) are prohibited → `Error` (one finding
   per offending entry, naming the entry kind). (BR §7.1.2.7.12 — subjectAltName extension contents.)
   `applies()` = broad leaf. Accessor: existing `san_entries()` → iterate `SanEntries.entries`, flag
   any `GeneralNameView.kind` not in `{"DNS","IP"}`. Skipped (no finding) when SAN absent.
   - good.pem: PASS (single DNS entry).

7. `cabf_br_san_present` — a subscriber TLS certificate MUST include a SubjectAlternativeName
   extension → `Warn`. (BR §7.1.2.7.12 — SAN MUST be present.) `applies()` = broad leaf. Accessor:
   existing `subject_alt_name()` → `None` ⇒ finding. **Severity is `Warn` (not `Error`)** so that the
   existing fixture `rfc5280_empty_subject_no_san.pem` (a deliberate no-SAN leaf) does not gain a NEW
   **Error** that would break its single-Error isolation test. See "Cascade-Management Strategy" for
   why `Warn` is the safe severity and how the tester reconciles that fixture's isolation assertion.
   - good.pem: PASS (SAN present).
   - CASCADE NOTE: this is the one lint that FIRES on an existing fixture (`rfc5280_empty_subject_no_san.pem`).
     It is included deliberately as a `Warn` (not an `Error`) precisely so the existing fixture's
     isolation tests, which assert exactly one *Error/Fatal*, are not broken. The tester MUST verify
     that the existing fixture's isolation test keys on Error-severity (not on total finding count);
     if it keys on total finding count, the tester reconciles that ONE assertion (documented, no
     fixture regeneration). Lint 7 is KEPT (Phase-1.5 decision 1 — all 12 lints settled); the `Warn`
     severity makes this reconciliation purely a test-assertion update, never a fixture regeneration
     or a cut.

8. `cabf_br_certificate_policies_present` — a subscriber TLS certificate MUST include a
   CertificatePolicies extension → `Warn`. (BR §7.1.2.7.9.) `applies()` = broad leaf. Accessor:
   existing `certificate_policy_oids()` → empty ⇒ finding. **Severity `Warn`** (defence-in-depth for
   any other policies-free leaf; the canonical good.pem now PASSES because it carries
   `certificatePolicies`).
   - good.pem: **PASS** — after the Phase-1.5 regeneration, good.pem carries a `certificatePolicies`
     extension (DV OID `2.23.140.1.2.1`), so this lint produces NO finding. good.pem stays completely
     finding-free. (Earlier draft had this firing a `Warn` on good.pem; that is superseded by the
     good.pem regeneration — Phase-1.5 decision 3.)

9. `cabf_br_certificate_policies_reserved_oid` — **when** the CertificatePolicies extension is
   present, it MUST assert at least one CA/Browser Forum reserved policy OID: domain-validated
   `2.23.140.1.2.1`, organization-validated `2.23.140.1.2.2`, or individual-validated
   `2.23.140.1.2.3` → `Error`. (BR §7.1.6.1 / §7.1.2.7.9.) `applies()` = broad leaf. Accessor:
   existing `certificate_policy_oids()`. Skipped (no finding) when CertificatePolicies is ABSENT.
   Fires only when a policies extension exists but lists none of the three reserved OIDs.
   - good.pem: **PASS** — after regeneration good.pem carries the reserved DV OID `2.23.140.1.2.1`, so
     this is a POSITIVE pass (policies present AND a reserved OID present). (Earlier draft passed by
     being "not evaluated"; now it passes affirmatively.)

10. `cabf_br_rsa_modulus_bits_multiple_of_8` — an RSA subscriber key's modulus bit length MUST be a
    multiple of 8 (a whole number of octets) → `Error`. (BR §6.1.6.) `applies()` = broad leaf.
    Accessor: existing `rsa_modulus_bits()` → `Some(bits)` with `bits % 8 != 0` ⇒ finding; `None`
    (non-RSA key) ⇒ no finding. Distinct from `hygiene_rsa_key_min_2048` (which checks the floor, not
    the octet-alignment).
    - good.pem: PASS (2048 is a multiple of 8).

11. `cabf_br_rsa_public_exponent_in_range` — an RSA subscriber key's public exponent MUST be odd and
    in the range `[2^16 + 1, 2^256 − 1]` (i.e. ≥ 65537 and odd) → `Error`. (BR §6.1.6.) `applies()` =
    broad leaf. Accessor: **NEW** `rsa_public_exponent()` → `Result<Option<RsaExponentView>, _>`
    exposing the exponent as raw big-endian octets (or a small struct with `is_odd: bool`,
    `at_least_65537: bool`, `at_most_2_256_minus_1: bool` computed from the octets); `None` for a
    non-RSA key ⇒ no finding. The exponent can be arbitrarily large, so it is compared via
    byte-length / leading-byte arithmetic, not by parsing into a fixed integer. See "Facade accessor
    needed".
    - good.pem: PASS (exponent 65537 = 0x010001, odd, in range).

12. `cabf_br_basic_constraints_present` — a subscriber TLS certificate MUST include a
    BasicConstraints extension (with `cA = FALSE`) → `Warn`. (BR §7.1.2.7.8.) `applies()` = broad
    leaf. Accessor: existing `basic_constraints()` → `None` ⇒ finding. good.pem HAS BasicConstraints
    (`CA:FALSE`), so it PASSES. **Severity `Warn`** as defence-in-depth in case any existing leaf
    fixture lacks BasicConstraints (the tester audits all existing leaves; if any lacks BC and the
    severity must be Error to be meaningful, that fixture interaction is reconciled — see
    Cascade-Management Strategy).
    - good.pem: PASS (BasicConstraints present, CA:FALSE).

> That is **12 shipped BR lints** (count settled — Phase-1.5 decision 1; 11 reuse existing accessors,
> lint 11 needs ONE new accessor). Lints 7, 8, 12 are `Warn` severity by deliberate cascade design;
> lints 1–6, 9, 10, 11 are `Error`. All 12 are KEPT — see "Cuts" for the menu candidates that were
> never in scope (out-of-scope offline, duplicate). good.pem PASSES all 12 (no Warn) after its
> Phase-1.5 regeneration.

## good.pem Conformance Audit (good.pem is finding-free; only good.pem is regenerated)

Per-new-lint result on the current `good.pem` (verified via `openssl x509 -in testdata/good.pem
-noout -text`):

| New lint | good.pem result | Why |
|---|---|---|
| cabf_br_subscriber_key_usage_cert_sign_prohibited | PASS | no KeyUsage extension |
| cabf_br_subscriber_key_usage_crl_sign_prohibited | PASS | no KeyUsage extension |
| cabf_br_subscriber_basic_constraints_path_len_prohibited | PASS | no pathLenConstraint |
| cabf_br_ext_key_usage_any_prohibited | PASS | EKU = serverAuth only |
| cabf_br_ext_key_usage_server_auth_required | PASS | EKU present and has serverAuth |
| cabf_br_san_dns_or_ip_only | PASS | single DNS entry |
| cabf_br_san_present | PASS | SAN present |
| cabf_br_certificate_policies_present | **PASS** | CertificatePolicies present (DV OID `2.23.140.1.2.1`) — ADDED by Phase-1.5 regeneration |
| cabf_br_certificate_policies_reserved_oid | **PASS** | reserved DV OID `2.23.140.1.2.1` present (positive pass) |
| cabf_br_rsa_modulus_bits_multiple_of_8 | PASS | 2048 is a multiple of 8 |
| cabf_br_rsa_public_exponent_in_range | PASS | exponent 65537, odd, in range |
| cabf_br_basic_constraints_present | PASS | BasicConstraints present |

**Conclusion:** `good.pem` is the ONLY fixture regenerated, and its RSA key is **pinned** so its SKI,
serial, and signature bytes stay byte-stable — ONLY the `certificatePolicies` extension is added. All
twelve new lints PASS (or are `NotApplicable`) on every existing leaf; **good.pem is completely
finding-free** across all 12 (no Warn, no Error). No other fixture's DER changes. Because the
`--info` summary block does NOT render `certificatePolicies` AND the key is pinned, the two
`inspect__*` snapshots and the README `--info` example do NOT change. The good.pem golden *lint-report*
snapshots still change additively (the 12 new `cabf_br_*` rows + shifted summary counts, all passing),
which tester-05 owns.

## good.pem regeneration strategy (PINNED KEY — minimal, deterministic churn)

good.pem is regenerated ONCE to add a `certificatePolicies` extension carrying the reserved CABF DV
OID `2.23.140.1.2.1`. The naive way (re-running `testdata/generate.sh` as-is) would re-roll the shared
`$KEY` (`openssl genrsa` into a `mktemp`), which would change good.pem's **SKI**, and the signature
bytes — rippling into the two `inspect__*` snapshots (the SKI hex in `inspect__good_cert_text` and
`inspect__json_envelope`), the README `--info` example (SKI `1D:33:53:BC:…`), and any byte-sensitive
snapshot. The serial is already fixed (`sign_csr` passes `-set_serial 17`), so only the key-derived
bytes are at risk.

**CHOSEN APPROACH: pin good.pem's RSA key (preferred).** Commit a fixed RSA-2048 private key at
`testdata/keys/good.key` and sign good.pem from it so the SKI / signature stay byte-stable and ONLY
the `certificatePolicies` extension changes. Concretely in `generate.sh`:
- Add a committed `testdata/keys/good.key` (a fixed RSA-2048 PEM; the developer/tester generates it
  ONCE, commits it, and `generate.sh` reads it rather than re-rolling).
- good.pem is signed with that pinned key (a dedicated `GOOD_KEY="$HERE/keys/good.key"` used as the
  `-signkey` for good.pem only; the other leaves keep using the existing re-rolled `$KEY`). good.pem
  is self-signed, so a dedicated key affects no other fixture.
- Add the `certificatePolicies=2.23.140.1.2.1` line to good.pem's extension config (the
  `make_leaf_ext`/`EXT_GOOD` block), keeping the `BR_OK` window (2026-06-01 → 2027-06-01) bracketing
  TEST_NOW, RSA-2048/SHA-256, CA:FALSE, serverAuth, SAN DNS=CN — openssl only, recipe parity.

**Why pinning beats accept-churn:** with the key pinned, the SKI (`1D:33:53:BC:…`) and serial (`17`,
shown as `11` in the summary — hex) are byte-stable, so the two `inspect__*` snapshots and the README
`--info` example need **no change at all**. The only good.pem snapshots that move are the lint-report
golden snapshots, which move anyway because of the +12 lints — that ripple is already owned by
tester-05. Net: pinning removes 3 files (2 inspect snapshots + README SKI) and any cert.rs SKI
assertion from the churn surface.

**FALLBACK (accept-churn) — only if pinning proves impractical.** If a fixed `good.key` cannot be made
to work (it should — it is a plain committed PEM), the tester accepts the re-rolled SKI and MUST then
also update, in tester-05's scope: the two `inspect__*` snapshots
(`inspect__good_cert_text__good_info_text.snap`, `inspect__json_envelope__good_info_json_summary.snap`),
the README `--info` good.pem SKI example (README.md ~line 370 + the JSON `subject_key_id` ~line 405
region), and any cert.rs SKI assertion (NOTE: cert.rs currently has NO hardcoded good.pem SKI
assertion — its `good_cert_*` tests are structural — so nothing in cert.rs needs editing in either
branch). The pinned-key approach is PREFERRED precisely to avoid widening the snapshot/README churn.

The chosen approach (pinned key) is made explicit in tester-04's `touches` (it adds
`testdata/keys/good.key` and regenerates `testdata/good.pem`) and Acceptance Criteria.

## Cascade-Management Strategy (THE #1 RISK)

`cabf_br` runs on EVERY TLS leaf fixture, so each new lint must be cascade-audited. The strategy is:

### A. Severity-shaping to protect existing single-Error isolation tests
The existing `each_fixture_isolates_exactly_one_*` tests (and the per-fixture isolation tests) assert
that a deviation fixture fires **exactly one Error/Fatal-severity rule** across the FULL registry.
New lints that would otherwise add an Error on an existing fixture are shipped as `Warn`
(lints 7, 8, 12), so they never add a second *Error* to any existing fixture. The tester MUST confirm
the existing isolation tests key on **Error/Fatal severity** (not on total finding count). If any
isolation test keys on total finding count, that ONE assertion is reconciled (documented), NOT the
fixture. NOTE: after the good.pem regeneration, NO new lint produces any finding on good.pem (lint 8
now PASSES on good.pem), so the only `Warn`-on-an-existing-fixture interaction left is
`cabf_br_san_present` on the no-SAN leaf (§B).

### B. Existing fixtures that interact with the new lints (audit; only good.pem is regenerated)
- `good.pem`: **regenerated once** (pinned key) to ADD `certificatePolicies` (DV OID). It now PASSES
  all 12 new lints with NO finding (lints 8/9 are positive passes). No `Warn` on good.pem. See
  "good.pem regeneration strategy".
- Every OTHER compliant leaf (e.g. `expired.pem` and the rfc5280/hygiene leaves that lack
  CertificatePolicies): gains ONE `Warn` from `cabf_br_certificate_policies_present`. Additive golden
  ripple only; these fixtures are NOT regenerated. (Their golden/inspect output is owned by tester-05
  where applicable.)
- `rfc5280_empty_subject_no_san.pem` (no-SAN leaf): gains a `Warn` from `cabf_br_san_present`.
  Because it is a `Warn`, the existing single-Error isolation test for this fixture is preserved IF it
  keys on Error severity. Tester verifies; if it keys on count, reconcile that one assertion (do NOT
  regenerate; do NOT cut — all 12 lints are kept per Phase-1.5 decision 1).
- `cabf_br_missing_serverauth.pem` (EKU present without serverAuth): lint 5 is KEPT (Phase-1.5
  decision 2). This fixture CO-FIRES the existing `cabf_br_ext_key_usage_server_auth_present` AND the
  new lint 5 (both Error). RESOLUTION (settled, not optional): lint 5's NEW fixture
  `cabf_br_eku_no_server_auth.pem` is the single-rule isolating fixture; the existing
  `cabf_br_missing_serverauth.pem` isolation test is **reconciled to a documented two-rule assertion**
  (asserts the TWO related serverAuth rules co-fire), following the feature-12 underscore/bad-char
  precedent. The tester implements and documents this; lint 5 is NOT cut.
- Existing path-len / KeyUsage CA fixtures: BR lints are `NotApplicable` on a CA, so unaffected.

### C. Golden-snapshot reconciliation list (owned by the tester, additive only)
The registry grows **70 → 82** lints (cabf_br 12 → 24). Every TLS-leaf golden snapshot extends with
the 12 new `cabf_br_*` rows in registration order (appended after the existing cabf_br block) and the
per-source summary counts shift. For good.pem all 12 new rows are PASSES (no Warn). For compliant
leaves OTHER than good.pem, one of the new rows is a `cabf_br_certificate_policies_present` `Warn`
(those leaves were not given a policies extension); the no-SAN leaf also shows a `cabf_br_san_present`
`Warn`. The lint-report snapshots to regenerate (insta accept, then diff-verify additive):
- `crates/cli/tests/snapshots/golden__text_output__good_text.snap` (good.pem: +12 PASS rows, no Warn)
- `crates/cli/tests/snapshots/golden__verbose_output__good_verbose_text.snap`
- `crates/cli/tests/snapshots/golden__text_output__cabf_br_validity_400_days_text.snap`
- `crates/cli/tests/snapshots/golden__text_output__chain_bundle_text.snap`
- `crates/cli/tests/snapshots/golden__json_output__good_json.snap`
- (any other `golden__*` snapshot whose body lists per-lint cabf_br rows — tester enumerates the full
  set by running `cargo insta test` and inspecting which `.snap` files change.)

**inspect snapshots and README do NOT move (pinned key).** Because good.pem's key is pinned, its SKI
and serial are byte-stable, and the `--info` summary block does NOT render `certificatePolicies`. So
`inspect__good_cert_text__good_info_text.snap`, `inspect__json_envelope__good_info_json_summary.snap`,
and the README `--info` good.pem example (SKI `1D:33:53:BC:…`) are **unchanged** and are NOT in
tester-05's `touches`. If the tester is FORCED onto the accept-churn fallback (pinning failed), these
three move and the tester must FLAG it to the architect to widen tester-05's `touches` before editing
them. The README `[rfc5280] (7 passed, 9 not applicable)` illustrative count line is rfc5280-only and
does not change (cabf_br is a separate block).

### D. In-file registry count reconciliation (owned by task: registry)
- `registry.rs` total-count test: `70 → 82`.
- `registry.rs` `cabf_br` source-filter test: `12 → 24`, and the expected-ids list extended with the
  12 new ids.
- `registry.rs` total-registry expected-ids list extended with the 12 new ids.
- rfc5280 (16), hygiene (4), pqc (9), cabf_ev (9), cabf_cs (8), cabf_smime (12) filters UNCHANGED.

### E. CLI count-assertion ripple (owned by the golden/count tester task)
Any `crates/cli/tests/output.rs` assertion of the form `[cabf_br] (N passed, …)` shifts by +12 (minus
any new `Warn`/`Error` findings on that fixture). The tester recomputes the exact
`(passed, not-applicable, warned, failed)` tuple per fixture and updates the stale strings, preserving
each test's intent.

## Fixture Strategy (openssl-generated only; one per new lint)

In addition to the 12 new fixtures, **good.pem is regenerated once** (pinned key, +`certificatePolicies`
DV OID — see "good.pem regeneration strategy"); it remains a clean BR-compliant leaf that passes
everything. All new fixtures are non-CA leaves (BR lints are NotApplicable on CAs). BR-compliant leaves
reuse the existing `BR_OK` window (2026-06-01 → 2027-06-01) and `make_leaf_ext`/`sign_csr` helpers in
`testdata/generate.sh` so they pass everything except their one (or documented co-firing) target.
**Same annual time-fragility as feature 05** — the new leaves inherit `BR_OK` and need no new dating
note. Pinned test clock: TEST_NOW = 1_796_083_200 (2026-12-01); linter tests use
`default_registry_with_now(Some(TEST_NOW))`, CLI tests pass `--now 1796083200`. No dynamic dates.

Each fixture must fire EXACTLY its one new rule across the FULL 82-lint registry (and no OLD rule),
EXCEPT the documented intentional co-fires.

| New fixture (lint) | shape / intended violation | co-fire note |
|---|---|---|
| `cabf_br_ku_cert_sign.pem` (subscriber_key_usage_cert_sign_prohibited) | leaf, KeyUsage asserts `keyCertSign` (+ digitalSignature to stay realistic), CA:FALSE | isolates this rule |
| `cabf_br_ku_crl_sign.pem` (subscriber_key_usage_crl_sign_prohibited) | leaf, KeyUsage asserts `cRLSign`, CA:FALSE | isolates this rule |
| `cabf_br_leaf_path_len.pem` (subscriber_basic_constraints_path_len_prohibited) | leaf, BasicConstraints CA:FALSE with `pathlen:0` (byte-patch if openssl refuses) | **co-fires** feature-12 `rfc5280_path_len_constraint_improperly_included` by construction — assert both (documented two-rule fixture) |
| `cabf_br_eku_any.pem` (ext_key_usage_any_prohibited) | leaf, EKU = `serverAuth, anyExtendedKeyUsage` | isolates this rule (serverAuth kept so server-auth lints stay quiet) |
| `cabf_br_eku_no_server_auth.pem` (ext_key_usage_server_auth_required) | leaf, EKU = `clientAuth` only (present, no serverAuth) | **co-fires** existing `cabf_br_ext_key_usage_server_auth_present` — assert BOTH (documented two-rule fixture). Lint 5 is KEPT; this is its single-rule-vs-existing isolating fixture and the existing `cabf_br_missing_serverauth.pem` test is reconciled to the same two-rule assertion. |
| `cabf_br_san_email_entry.pem` (san_dns_or_ip_only) | leaf, SAN = `DNS:<cn>` + `email:a@example.com` | isolates this rule (compliant DNS-CN keeps cn_in_san quiet) |
| `cabf_br_no_san.pem` (san_present, `Warn`) | leaf, NO SAN; subject DN non-empty; else compliant | NOTE: a no-SAN leaf with a non-empty subject DN must not trip rfc5280 SAN rules; verify against `rfc5280_san_present_if_subject_empty` (only fires on EMPTY subject) — distinct |
| `cabf_br_no_policies.pem` (certificate_policies_present, `Warn`) | leaf, NO CertificatePolicies; else compliant | good.pem ALSO fires this `Warn`; the dedicated fixture asserts the `Warn` in isolation |
| `cabf_br_policies_no_reserved.pem` (certificate_policies_reserved_oid) | leaf, CertificatePolicies present with a single non-reserved OID (e.g. `1.3.6.1.4.1.99999.1`) | isolates this rule (policies present, none reserved) |
| `cabf_br_rsa_mod_not_oct.pem` (rsa_modulus_bits_multiple_of_8) | leaf, RSA key whose modulus bit length is not a multiple of 8 (e.g. 2047/2049-bit key, or byte-patch) | likely needs a non-standard key size — tester FLAGS to the architect for an alternative recipe if openssl cannot mint one; lint is NOT cut |
| `cabf_br_rsa_exp_3.pem` (rsa_public_exponent_in_range) | leaf, RSA key with public exponent 3 (`-pkeyopt rsa_keygen_pubexp:3`), 2048-bit, else compliant | isolates this rule (exp 3 < 65537) |
| `cabf_br_no_basic_constraints.pem` (basic_constraints_present, `Warn`) | leaf, NO BasicConstraints extension; else compliant | tester audits that omitting BC does not trip an rfc5280 rule; if BC omission interacts, reconcile the test assertion (lint is NOT cut) |

> Fixture isolation caveats the tester must mind (all 12 lints are KEPT — these are fixture-producibility
> notes, NOT lint-cut contingencies):
> - `cabf_br_leaf_path_len.pem`: openssl may refuse `pathlen` with `CA:FALSE`. If so, byte-patch the
>   DER (as the existing version-byte patch does) or use an explicit ext file. The lint stands
>   regardless; if the fixture is genuinely impossible to mint, the tester FLAGS it to the architect to
>   choose an alternative fixture recipe — the lint is NOT cut.
> - `cabf_br_rsa_mod_not_oct.pem`: a modulus whose bit length is not a multiple of 8 is unusual;
>   openssl RSA keygen produces byte-aligned moduli. The tester may need a deliberately odd-sized key
>   or a byte-patched modulus. If not cleanly producible, FLAG it to the architect for an alternative
>   recipe — the lint is NOT cut.
> - `cabf_br_eku_no_server_auth.pem` and `cabf_br_no_san.pem`: see Cascade-Management §B — these
>   touch existing fixtures' isolation tests; tester implements the settled reconciliations (documented
>   two-rule assertion for the serverAuth pair; Warn-keyed-out for the no-SAN leaf).
> - All DNS/SAN fixtures: keep a compliant `DNS:<cn>` entry so `cabf_br_cn_in_san` stays quiet, ensure
>   no bad name is internal/reserved (so `cabf_br_no_internal_names_or_reserved_ip` stays quiet), and
>   keep labels LDH/short unless that is the explicit target.

## Architecture

- **No `source.rs` change. No `CertPurpose` change. No engine/trait change.**
- New BR lints: one small file per lint (or per sibling pair) under
  `crates/linter/src/lints/cabf_br/`, each `RuleSource::CabfBr`, `cabf_br_*` id, citing its BR
  section, broad-scoped via the existing `applies_to_leaf` helper, reusing existing facade accessors
  (and `reserved.rs` if relevant). Each file follows the existing shape: a pure `evaluate(...)` helper
  + `#[cfg(test)] mod tests` with a pass and a fail case (fixture-driven integration tests owned by
  the tester).
- The ONE new facade accessor lives in `cert.rs` (one owner). Lints read ONLY through the facade.
- Registered by appending to `default_registry()` AFTER the existing cabf_br block, preserving the
  deterministic order (the golden test pins order — new lints go at the END of the cabf_br block so
  existing ordering is untouched and snapshots extend rather than reshuffle).
- Fail policy (mirrors existing cabf_br): accessor `Err` in `applies` → `NotApplicable`; accessor
  `Err` in `check` → empty `Vec`; no `unwrap`/`expect`/`panic!` on cert data paths.

### Facade accessor needed (ONE new accessor — grouped in the cert.rs task)

| Accessor (new) | Lint that consumes it |
|---|---|
| `rsa_public_exponent()` → `Result<Option<RsaExponentView>, CertError>` where `RsaExponentView { is_odd: bool, at_least_65537: bool, at_most_2_256_minus_1: bool }` (computed from the RSA exponent's big-endian octets via `x509-parser`'s parsed RSA public key; `None` for a non-RSA key). Documented `# Errors`; non-panicking. | cabf_br_rsa_public_exponent_in_range |

ALREADY-PRESENT accessors reused by the other 11 lints (do NOT re-add): `key_usage()`
(`KeyUsageView.key_cert_sign`/`.crl_sign`), `basic_constraints()`
(`BasicConstraintsView.path_len`/presence), `extended_key_usage()`
(`EkuView.oids`/`.server_auth`), `san_entries()` (`SanEntries.entries[].kind`), `subject_alt_name()`
(presence), `certificate_policy_oids()`, `rsa_modulus_bits()`, `is_ca()`.

> Reserved CABF policy OIDs (`2.23.140.1.2.{1,2,3}`) are an in-module `const` list in lint 9's file
> (no crate). The `anyExtendedKeyUsage` OID `2.5.29.37.0` is an in-module `const` in lint 4's file.

## Changes Overview

**crates/linter/ (production — developer tasks)**
- `src/cert.rs` — ONE new accessor `rsa_public_exponent()` + `RsaExponentView` (task: developer-01).
- `src/lints/cabf_br/mod.rs` — declare + re-export the new lint modules (task: developer-02).
- `src/lints/cabf_br/subscriber_key_usage_prohibited.rs` — houses BOTH
  `cabf_br_subscriber_key_usage_cert_sign_prohibited` and `..._crl_sign_prohibited` (task: developer-02).
- `src/lints/cabf_br/subscriber_basic_constraints_path_len_prohibited.rs` (task: developer-02).
- `src/lints/cabf_br/ext_key_usage_any_prohibited.rs` (task: developer-02).
- `src/lints/cabf_br/ext_key_usage_server_auth_required.rs` (task: developer-02).
- `src/lints/cabf_br/san_dns_or_ip_only.rs` (task: developer-02).
- `src/lints/cabf_br/san_present.rs` (task: developer-02).
- `src/lints/cabf_br/certificate_policies.rs` — houses BOTH `cabf_br_certificate_policies_present`
  and `cabf_br_certificate_policies_reserved_oid` (sibling rules, one file) (task: developer-02).
- `src/lints/cabf_br/rsa_modulus_bits_multiple_of_8.rs` (task: developer-02).
- `src/lints/cabf_br/rsa_public_exponent_in_range.rs` (task: developer-02).
- `src/lints/cabf_br/basic_constraints_present.rs` (task: developer-02).
- `src/registry.rs` — append the 12 new lints to `default_registry()`; update the in-file total count
  (70 → 82), the cabf_br filter test (12 → 24) + expected-ids list, and the total expected-ids list
  (task: developer-03).

**testdata/ (tester — task: tester-04)**
- `keys/good.key` — NEW committed pinned RSA-2048 key for good.pem (byte-stable SKI/serial).
- `generate.sh` — sign good.pem from the pinned key and ADD `certificatePolicies=2.23.140.1.2.1` to
  good.pem's extension config; add one openssl-generated violating fixture per new lint (see Fixture
  Strategy).
- `good.pem` — REGENERATED once (pinned key + certificatePolicies DV OID); stays finding-free.
- 12 new fixtures (one per lint), each isolating exactly its one new rule across the 82-lint registry
  (with the two documented intentional co-fires: path-len-on-leaf + the EKU-serverAuth pair).
- All OTHER existing fixtures UNCHANGED (no regeneration).

**crates/linter/tests/ (tester — task: tester-04)**
- `crates/linter/tests/cabf_br.rs` — per-new-lint flag/pass + multi-finding cases + CA-NotApplicable +
  extend isolation to the new fixtures; document the two intentional two-rule co-fires; verify the
  existing fixtures' isolation tests still hold (Error-severity keyed).

**crates/cli/tests/ (tester — task: tester-05)**
- Regenerate every affected `golden__*` lint-report snapshot for the 82-lint registry (additive).
  good.pem's snapshots gain 12 PASS rows (no Warn); other compliant leaves gain a
  `cabf_br_certificate_policies_present` `Warn` row.
- The `inspect__*` snapshots do NOT change (pinned key → stable SKI/serial; `--info` does not render
  certificatePolicies). They are NOT in tester-05's `touches`. If the accept-churn fallback is forced,
  the tester FLAGS the architect to widen scope before touching them.
- `crates/cli/tests/output.rs` — update any stale `[cabf_br] (N …)` count assertions, preserving
  intent.

## Dependencies

**None new.** Everything is supported by the already-present `x509-parser`, `der`, and `oid-registry`.
The new `rsa_public_exponent()` accessor uses `x509-parser`'s already-parsed RSA public key (the same
path `rsa_modulus_bits()` uses). The reserved-policy-OID and `anyExtendedKeyUsage` OID checks use
small in-module `const` lists (no crate). No `Cargo.toml` change is expected; if the developer finds
one genuinely necessary it must be documented and justified in the task.

## Cuts (candidates dropped, with reasons)

### Out of scope — needs out-of-band / network / validation state (offline linter)
- `lint_sub_cert_aia_marked_critical` / AIA contents (OCSP URI present, caIssuers URI present,
  http-scheme) — **explicitly out of scope per Phase-1.5 decision 1 (no AIA lints).** Additionally:
  AIA accessLocation URI enumeration is not in the facade (only `has_authority_info_access()` exists),
  so these would need a new URI-enumeration accessor, and good.pem has no AIA (good.pem's Phase-1.5
  regeneration adds ONLY `certificatePolicies`, not AIA). The OCSP-reachability semantics also lean
  toward validation state. **Out of scope** (decision 1 + accessor cost + state-leaning) — deferred to
  a future feature willing to own an AIA accessor.
- `lint_ocsp_url_responds` / `lint_crl_distribution_point_reachable` / any revocation-liveness check —
  network. **Out of scope (offline linter).**
- `lint_cert_chains_to_trusted_root` / path-building / `lint_ca_signature_valid` — trust-store /
  validation state. **Out of scope.**
- `lint_sct_present` / CT-log inclusion — requires CT-log state / embedded SCT semantics beyond pure
  structural decidability for the BR-required count; **Cut** (state-leaning, low offline signal).

### Duplicate / already covered
- `lint_rsa_mod_less_than_2048_bits` (BR) — already covered by `hygiene_rsa_key_min_2048`. We ship the
  octet-alignment + exponent-range checks (lints 10, 11) which are NOT covered. **Cut** (the floor
  check is duplicate).
- `lint_basic_constraints_path_len_present` overlap with feature-12
  `rfc5280_path_len_constraint_improperly_included` — we deliberately ship the BR-scoped sibling
  (lint 3) and let the two CO-FIRE (documented), rather than cutting; this is recorded under lint 3,
  not a cut.
- `lint_ext_san_dns_name_too_long` / underscore / bad-char / wildcard (BR) — **already shipped** in
  feature 12 (`cabf_br_dnsname_*`). **Cut** (duplicate).
- `lint_subject_country_not_iso`, `lint_organizational_unit_name_prohibited`,
  `lint_extra_subject_common_names`, `lint_cn_in_san`, `lint_internal_names_or_reserved_ip` — **already
  shipped** (features 05/12). **Cut** (duplicate).

### Shipped as Warn to stay cascade-safe (all KEPT — no cuts)
- `cabf_br_san_present` (lint 7), `cabf_br_certificate_policies_present` (lint 8),
  `cabf_br_basic_constraints_present` (lint 12) — kept as **`Warn`** precisely so they do not add an
  Error to any existing fixture. Per Phase-1.5 decision 3, good.pem is regenerated to carry
  `certificatePolicies`, so lint 8 now PASSES on good.pem (no Warn) and good.pem is finding-free.
  Lints 7 and 12 do not fire on good.pem (it has SAN and BasicConstraints). All three are KEPT.
- `cabf_br_ext_key_usage_server_auth_required` (lint 5) — KEPT (Phase-1.5 decision 2). Its co-fire with
  the existing `cabf_br_ext_key_usage_server_auth_present` on `cabf_br_missing_serverauth.pem` is
  reconciled as a documented two-rule assertion (feature-12 precedent), NOT a cut.
- `lint_subscriber_validity_serial_entropy` / `lint_serial_not_random` — serial-entropy heuristics
  have high false-positive risk and are not cleanly decidable without statistical assumptions.
  **Out of scope** per the brief (never one of the 12).

### Policy-laden / high false-positive
- `lint_key_usage_and_extended_key_usage_inconsistent` — large policy matrix; high FP risk for a first
  pass. **Cut.**
- `lint_cab_dv_conflicts_with_locality` / OV-vs-DV subject-attribute profiling — depends on policy-OID
  profiling we do not model (and overlaps the EV feature). **Cut.**

## Sequencing (batches)

- **Batch A:** `developer-01` (cert.rs — `rsa_public_exponent()` accessor + view). `depends_on: []`.
- **Batch B:** `developer-02` (the 11 new cabf_br lint files + mod.rs wiring). `depends_on:
  developer-01` (lint 11 reads the new accessor; the others read existing accessors). Single owner of
  `lints/cabf_br/*` (except `reserved.rs`, reused not modified).
- **Batch C:** `developer-03` (registry.rs registration + count/filter unit-test updates).
  `depends_on: developer-02` (references the new lint types).
- **Batch D:** `tester-04` (fixtures + `crates/linter/tests/cabf_br.rs` per-lint/isolation tests).
  `depends_on: developer-03` (the 82-lint registry exists).
- **Batch E:** `tester-05` (CLI golden snapshots + `output.rs` count ripple). `depends_on: tester-04`.

> Conflict audit: `cert.rs` only by developer-01. `lints/cabf_br/*` only by developer-02.
> `registry.rs` only by developer-03. `testdata/*` + `crates/linter/tests/cabf_br.rs` only by
> tester-04. `crates/cli/tests/*` only by tester-05. No two tasks in the same batch share a file; each
> batch has a single task, so all `touches` lists are trivially disjoint within a batch.

## Acceptance Criteria (feature-level)

- [ ] All 12 new `cabf_br_*` lints shipped (count settled — none cut), each citing its BR clause, each
      broad-scoped via `applies_to_leaf`.
- [ ] Severities: lints 7, 8, 12 = `Warn`; the rest = `Error`.
- [ ] ONE new facade accessor (`rsa_public_exponent()`); all other lints reuse existing accessors.
- [ ] `good.pem` regenerated ONCE with a PINNED key (`testdata/keys/good.key`) + a
      `certificatePolicies` DV OID `2.23.140.1.2.1`; good.pem is finding-free across all 12 new lints
      (lints 8/9 are positive passes, no Warn). SKI/serial byte-stable → `inspect__*` snapshots and the
      README `--info` example unchanged.
- [ ] No OTHER existing fixture's DER regenerated; the only behavioural change to other compliant
      leaves is the additive `Warn` from `cabf_br_certificate_policies_present` (and `cabf_br_san_present`
      on the no-SAN leaf), reconciled in golden snapshots, breaking no single-Error isolation test.
- [ ] The `cabf_br_missing_serverauth.pem` two-rule co-fire (lints 5 + existing serverAuth lint) is
      reconciled as a documented two-rule assertion (not a cut).
- [ ] registry counts reconciled (total 70 → 82; cabf_br 12 → 24); other source filters unchanged.
- [ ] 12 new openssl-generated fixtures (recipe-parity in `generate.sh`), each isolating its one new
      rule except the two documented intentional co-fires.
- [ ] All affected `golden__*` lint-report snapshots regenerated (additive, order-preserving);
      `inspect__*` snapshots unchanged (pinned key); `output.rs` counts updated.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, and
      `bash testdata/generate.sh` all pass cleanly.
- [ ] If `cabf_br_leaf_path_len.pem` or `cabf_br_rsa_mod_not_oct.pem` is not producible via openssl
      (even byte-patched), FLAG it to the architect for an alternative recipe — the lint is NOT cut.
</content>
</invoke>
