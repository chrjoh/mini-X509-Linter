# Feature: CA/Browser Forum BR Rule Set

## Overview

Implement the web-PKI–specific Baseline Requirements lints. This is where most ambiguity lives, so
each lint stays small and is commented with its BR section number. This is plan.md Milestone 5.

## Scoping Decision (BROAD — load-bearing, honored throughout this spec)

The four BR lints use **BROAD scoping**: they apply to **every non-CA leaf certificate**,
regardless of EKU. They are **NOT EKU-gated** — a leaf without `serverAuth` is still in scope (it is
flagged by `cabf_br_ext_key_usage_server_auth_present`, not skipped). **CA certs remain
`NotApplicable`** for all four BR lints.

`applies()` for each BR lint is therefore: `if cert.is_ca() { NotApplicable } else { Applies }`.

### Rationale

- A linter that only checks certs which already declare `serverAuth` would silently ignore the most
  dangerous case: a TLS-intended leaf that *forgot* `serverAuth`. Broad scoping makes the missing-EKU
  lint meaningful.
- It keeps `applies()` trivial and uniform across all four lints (no per-lint EKU pre-gate), which is
  easier to audit and reason about.
- It matches the project's "report every finding, never short-circuit" philosophy.

### Accepted cost (the cross-feature cascade)

Under broad scoping, **every existing non-CA leaf fixture is now in scope for all four BR lints**.
The current leaf fixtures have a 100-year validity window and no SAN/EKU, so they would trip
`validity_max_398_days`, `cn_in_san` (CN present, SAN absent), and `ext_key_usage_server_auth_present`
simultaneously. That breaks the "exactly one rule fires" isolation tests in features 03 and 04 and
the good/expired invariants. The resolution (below) regenerates **all** non-CA leaf fixtures to be
BR-compliant except for their single intended violation. See "Cross-Feature Fixture & Test
Regeneration Plan".

## The Four BR Lints (broad-scoped; CA ⇒ NotApplicable)

- `cabf_br_validity_max_398_days` — non-CA leaf whose validity window (`notAfter − notBefore`) is
  **> 398 days** → `Error`. Message names the actual duration. (BR §6.3.2)
- `cabf_br_cn_in_san` — non-CA leaf whose subject CN value is **not present in the SAN** → `Error`
  (one finding per offending CN, naming it). If the subject has **no CN**, there is nothing to
  require → no finding. (BR §7.1.4.2)
- `cabf_br_no_internal_names_or_reserved_ip` — non-CA leaf whose SAN contains an **internal/reserved
  name or reserved IP** → `Error` (one finding per offending entry, naming it). (BR §7.1.4.2 /
  §4.2.2)
- `cabf_br_ext_key_usage_server_auth_present` — non-CA leaf **lacking the `serverAuth` EKU**
  (OID 1.3.6.1.5.5.7.3.1) → `Error`. (BR §7.1.2.7)

Each lint:
- Scopes via `applies()` → `NotApplicable` for CA certs, `Applies` for every non-CA leaf.
- Returns `Vec<Finding>` with messages that name the specific SAN entry / CN / duration at fault.
- Carries a comment with the BR section number it enforces.
- Uses `cabf_br_*` naming for `lint_id`.

## Architecture

- One small file per lint under `crates/linter/src/lints/cabf_br/`.
- Reuse the SAN / subject / EKU / validity accessors added in features 03–04; add any missing ones to
  the `Cert` facade (SAN dNSName/iPAddress enumeration, CN enumeration, EKU OID reading +
  `has_server_auth()`, `validity_days()`, `is_ca()`).
- "Internal/reserved" name and IP classification lives in a single, well-documented helper
  (`lints/cabf_br/reserved.rs`) so the rule is auditable; the reserved-range list lives in one place.
- Register the lints in the default registry (after the rfc5280 + hygiene lints, for a deterministic
  order the feature-06 golden test can pin).

## Validity-Window Strategy for BR-Compliant Leaf Fixtures (time-fragility warning)

Every non-CA leaf fixture must now carry a validity window that is BOTH **≤ 398 days** AND
**currently valid** (`notAfter` in the future) so `hygiene_not_expired` still passes and
`cabf_br_validity_max_398_days` does not fire. The old fixed `2024-01-01 → 2124-01-01` (100 years)
violates the 398-day rule and must go.

**Chosen window for currently-valid BR-compliant leaves: `notBefore = 2026-06-01`,
`notAfter = 2027-06-01` (365 days).** As of today (2026-06-16) this is currently valid and ≤ 398
days. We deliberately do NOT use a window starting `2025-06-01` (it would already be expired) — the
window must straddle "now".

**Implementation in `generate.sh`:** introduce a new pair of constants, e.g.

```
BR_OK_NB="20260601000000Z"   # currently valid, <=398d window
BR_OK_NA="20270601000000Z"
```

and use them for all currently-valid BR-compliant leaves. Keep the existing far-future window
(`FAR_FUTURE_*`) ONLY where the fixture intentionally violates `validity_max_398_days` is NOT the
goal AND the fixture is a CA (CA fixtures are out of BR scope, so their window is irrelevant to BR).
For non-CA leaf fixtures whose target violation is something OTHER than validity, use `BR_OK_*`.

> ⚠️ **TIME-FRAGILITY WARNING (accepted cost of broad scoping).** The `BR_OK_*` window expires on
> **2027-06-01**. After that date, every BR-compliant leaf fixture becomes expired, which will make
> `hygiene_not_expired` fire on `good.pem` and on every per-rule fixture — breaking the isolation
> tests wholesale. **These fixtures MUST be regenerated (slide the window forward) at least annually,
> before 2027-06-01.** This fragility is inherent to combining "currently valid" with "≤ 398 days":
> a short window cannot also be far-future. `generate.sh` must document this loudly in its header, and
> the test files should reference it so a future maintainer who sees a flood of `not_expired` failures
> knows the cause. (An alternative — relative `openssl -days 365` dating — makes the *checked-in*
> bytes non-deterministic across regenerations but self-healing on regen; we keep fixed dates for
> reproducibility and accept the annual-regen chore. Document both options in `generate.sh`.)

`expired.pem` is the deliberate exception: it must remain expired (violating only
`hygiene_not_expired`) while passing all BR lints. Give it a **past** ≤ 398-day window, e.g.
`notBefore = 2024-01-01`, `notAfter = 2024-06-01` (151 days). 151 ≤ 398 so `validity_max_398_days`
passes; the window is in the past so `not_expired` fires; serverAuth + SAN-with-CN keep the other BR
lints quiet.

> Note: `expired.pem`'s `notAfter` is asserted by Unix-seconds constants in two test files
> (`crates/linter/tests/registry.rs` `EXPIRED_NOT_AFTER` and `crates/cli/tests/output.rs`
> `EXPIRED_NOT_AFTER`, both currently `1_293_840_000` = 2011-01-01). Changing the window to
> `2024-06-01` changes that constant to **`1_717_200_000`** (2024-06-01T00:00:00Z). Both test files
> must be updated in lockstep with the fixture. This is part of the regeneration task's scope.

## Per-Fixture BR-Fire Matrix (BEFORE the fix — current shapes under broad scoping)

All current non-CA leaf fixtures share: 100-year window (2024→2124, except the two special ones),
non-empty subject with a CN, NO SAN, NO EKU. Under broad scoping that means each currently trips
THREE BR lints (validity, cn_in_san, missing serverauth). The table shows which of the 4 BR lints
fire on each fixture **as it exists today**:

| Fixture | is_ca | validity_max_398 | cn_in_san | internal/reserved | missing_serverauth | BR lints firing |
|---|---|---|---|---|---|---|
| good.pem | no | FIRE (100y) | FIRE (CN, no SAN) | pass (no SAN) | FIRE (no EKU) | 3 |
| expired.pem | no | FIRE (100y past 2010→2011 is 1y… see note) | FIRE | pass | FIRE | 3 |
| rfc5280_serial_number_zero | no | FIRE (100y) | FIRE | pass | FIRE | 3 |
| rfc5280_validity_inverted | no | pass (0-len window ≤398) | FIRE | pass | FIRE | 2 |
| rfc5280_empty_subject_no_san | no | FIRE (100y) | pass (no CN) | pass (no SAN) | FIRE | 2 |
| rfc5280_version_not_v3 | no | FIRE (100y) | FIRE | pass | FIRE | 3 |
| hygiene_sha1_signature | no | FIRE (100y) | FIRE | pass | FIRE | 3 |
| hygiene_rsa_1024 | no | FIRE (100y) | FIRE | pass | FIRE | 3 |
| hygiene_ecdsa_bad_curve | no | FIRE (100y) | FIRE | pass | FIRE | 3 |
| rfc5280_ca_bc_not_critical | **yes** | N/A | N/A | N/A | N/A | 0 (CA) |
| rfc5280_ca_missing_keycertsign | **yes** | N/A | N/A | N/A | N/A | 0 (CA) |

Notes on edge fixtures:
- `expired.pem` currently uses `2010-01-01 → 2011-01-01` (≈365d). Under broad scoping that is ≤398,
  so `validity_max_398_days` would actually NOT fire on the *current* expired.pem — but `cn_in_san`
  and `missing_serverauth` would, breaking its "isolates only not_expired" guarantee. Either way it
  must be regenerated.
- `rfc5280_validity_inverted` has a zero-length window (`notAfter == notBefore`), which is ≤398, so
  `validity_max_398_days` does not fire on it; but `cn_in_san` + `missing_serverauth` still would.
- `rfc5280_empty_subject_no_san` has no CN, so `cn_in_san` does not fire (nothing to require), and no
  SAN so `internal/reserved` does not fire; but validity + missing_serverauth would.
- The two CA fixtures are correctly `NotApplicable` for all four BR lints — confirmed, no change.

**Conclusion:** every non-CA leaf fixture (9 of them) breaks at least one isolation/invariant test
under broad scoping and must be regenerated to be BR-compliant except for its single target rule.

## Per-Fixture Target Shape (AFTER the fix — what each fixture must become)

All non-CA leaf fixtures gain: `serverAuth` EKU, a SAN whose dNSName entries include the subject CN,
no internal/reserved SAN entries, and a `BR_OK_*` (currently-valid, ≤398d) window — EXCEPT where the
fixture's single target violation requires deviating from exactly one of those.

| Fixture | window | SAN | EKU | other | single intended violation |
|---|---|---|---|---|---|
| good.pem | BR_OK (365d) | DNS:good.example (= CN) | serverAuth | RSA-2048/SHA-256, CA:FALSE | NONE (clean) |
| expired.pem | PAST 2024-01-01→2024-06-01 (151d) | DNS:expired.example (= CN) | serverAuth | — | `hygiene_not_expired` |
| rfc5280_serial_number_zero | BR_OK | DNS = CN | serverAuth | serial 0 | `rfc5280_serial_number_positive` |
| rfc5280_validity_inverted | zero-len, FAR-FUTURE-but-≤398… see note | DNS = CN | serverAuth | notAfter == notBefore | `rfc5280_validity_not_after_after_not_before` |
| rfc5280_empty_subject_no_san | BR_OK | **none** (target) | serverAuth | empty subject DN | `rfc5280_san_present_if_subject_empty` |
| rfc5280_version_not_v3 | BR_OK | DNS = CN | serverAuth | DER version byte patched v3→v1 | `rfc5280_version_is_v3` |
| hygiene_sha1_signature | BR_OK | DNS = CN | serverAuth | RSA-2048 signed SHA-1 | `hygiene_no_sha1_signature` |
| hygiene_rsa_1024 | BR_OK | DNS = CN | serverAuth | RSA-1024 / SHA-256 | `hygiene_rsa_key_min_2048` |
| hygiene_ecdsa_bad_curve | BR_OK | DNS = CN | serverAuth | EC secp224r1 / SHA-256 | `hygiene_ecdsa_curve_allowlist` |
| rfc5280_ca_bc_not_critical | (CA — BR N/A) | (CA non-empty subj) | — | CA, BC not critical | `rfc5280_basic_constraints_critical_on_ca` |
| rfc5280_ca_missing_keycertsign | (CA — BR N/A) | (CA non-empty subj) | — | CA, no keyCertSign | `rfc5280_key_usage_present_when_ca` |

Important per-fixture caveats:

- **`rfc5280_validity_inverted`**: its window must be a **zero-length** window (notAfter ==
  notBefore) to violate `validity_not_after_after_not_before`, AND that point must be in the future
  so `not_expired` passes, AND the zero-length span is ≤398 so `validity_max_398_days` passes. A
  single near-future instant works, e.g. `notBefore = notAfter = 2027-01-01`. (Do NOT use 2120 —
  that is fine for not_expired but irrelevant; any future instant works. Keep it future-of-now.)
  This fixture is also time-fragile in the same way (it must stay future-of-now), but its zero-length
  window means it never trips the 398-day rule regardless. It still needs SAN+EKU added so cn_in_san
  and missing_serverauth stay quiet.
- **`rfc5280_empty_subject_no_san`**: deliberately has NO SAN and an empty subject. With no CN,
  `cn_in_san` is silent (nothing required). With no SAN, `no_internal_names_or_reserved_ip` is
  silent. It STILL needs the `serverAuth` EKU added (broad scoping: a non-CA leaf without serverAuth
  fires `ext_key_usage_server_auth_present`) and a `BR_OK` window. So its added pieces are EKU +
  BR_OK window only — NOT a SAN.
- **`expired.pem`**: past ≤398d window + serverAuth + SAN-with-CN, so ONLY `not_expired` fires.

## The Dedicated BR-Violating Fixtures (one per BR lint)

Each is a non-CA leaf that is BR-compliant EXCEPT its one target violation, and passes all rfc5280 +
hygiene lints (BR_OK window unless the target is validity; RSA-2048/SHA-256; v3; positive serial;
CA:FALSE):

| Fixture | window | SAN | EKU | single intended violation |
|---|---|---|---|---|
| cabf_br_validity_400_days | **400d**, currently valid (e.g. 2026-06-01→2027-07-06) | DNS = CN | serverAuth | `cabf_br_validity_max_398_days` |
| cabf_br_cn_not_in_san | BR_OK | DNS that **omits** the CN (e.g. CN=cn-missing.example, SAN DNS:other.example) | serverAuth | `cabf_br_cn_in_san` |
| cabf_br_internal_san | BR_OK | SAN with an internal name AND/OR reserved IP (e.g. DNS:internal.local + IP:10.0.0.1), CN present in SAN as a public name so cn_in_san stays quiet | serverAuth | `cabf_br_no_internal_names_or_reserved_ip` |
| cabf_br_missing_serverauth | BR_OK | DNS = CN | EKU present but **without serverAuth** (e.g. clientAuth only) | `cabf_br_ext_key_usage_server_auth_present` |

Caveats:
- `cabf_br_validity_400_days`: 400 days > 398 (fires validity) but must be currently valid so
  `not_expired` passes. `2026-06-01 → 2027-07-06` is 400 days and straddles now. Same annual
  time-fragility as `BR_OK`, slightly longer horizon. Document it.
- `cabf_br_internal_san`: put a public name equal to the CN in the SAN so `cn_in_san` does NOT fire;
  the internal/reserved entry is the *additional* SAN entry that the target lint flags. For the
  "multiple findings" edge case, include both an internal name and a reserved IP.
- `cabf_br_missing_serverauth`: it must carry an EKU extension that lacks serverAuth (e.g. clientAuth
  only) — NOT a cert with no EKU at all, so the test asserts the "EKU present but serverAuth absent"
  path. (An entirely-absent EKU would also fire the lint; either is acceptable, but clientAuth-only
  is the clearer, more realistic isolation.)

## Changes Overview

**crates/linter/ (production code — developer tasks 01–03)**
- `src/lints/cabf_br/mod.rs`
- `src/lints/cabf_br/validity_max_398_days.rs`
- `src/lints/cabf_br/cn_in_san.rs`
- `src/lints/cabf_br/no_internal_names_or_reserved_ip.rs`
- `src/lints/cabf_br/ext_key_usage_server_auth_present.rs`
- `src/lints/cabf_br/reserved.rs` (internal/reserved name + reserved-IP classifier)
- `src/lints/mod.rs` — `pub mod cabf_br;`
- `src/cert.rs` — SAN entry enumeration, CN enumeration, EKU accessors + `has_server_auth()`,
  `validity_days()`, `is_ca()`.
- `src/registry.rs` — register the four BR lints; update the in-file `default_registry` count/filter
  unit tests (10→14; add a `cabf_br` source-filter test).

**crates/linter/src/cert.rs unit tests (developer — see follow-up task 05)**
- `good_cert_has_no_key_usage_or_san` becomes FALSE once good.pem gains a SAN + KeyUsage; this test
  must be rewritten to assert the new shape (SAN present with DNS = CN; KeyUsage present if added).
  `good_cert_is_a_leaf`, `good_cert_is_version_3`, `good_cert_subject_is_not_empty`, the serial and
  SPKI tests stay true (good.pem is still an RSA-2048/SHA-256 v3 leaf).
- NOTE: `cert.rs` is owned by developer task 01 (facade accessors). To avoid two tasks editing
  `cert.rs` in the same batch, the unit-test fix is a **separate, later developer task (05)** that
  `depends_on` both the facade task (01) and the fixture regeneration (04). See task list.

**Cross-feature test files (tester — folded into task 04, the fixture regeneration owner)**
- `crates/linter/tests/rfc5280.rs` — `good_pem_yields_no_error_or_fatal_findings` and
  `each_fixture_isolates_exactly_one_rfc5280_violation` now run over a 14-lint registry; the
  isolation assertion (`firing == vec![expected]`) still holds IFF the fixtures are BR-compliant.
  No assertion text changes are strictly required if regeneration is correct, but the module doc
  comment should note BR is now in the registry, and the fixtures are the load-bearing change.
- `crates/linter/tests/hygiene.rs` — same: `each_hygiene_fixture_isolates_exactly_one_violation`
  and `good_pem_yields_no_error_or_fatal_findings` must still pass over the 14-lint registry given
  BR-compliant fixtures.
- `crates/linter/tests/registry.rs` — `EXPIRED_NOT_AFTER` constant changes to `1_717_200_000`
  (2024-06-01); `default_registry_flags_expired_fixture_with_warn` and
  `expired_fixture_isolates_only_the_not_expired_finding` must still pass (expired.pem stays
  isolated to not_expired given the new BR-compliant-but-past shape).
- `crates/cli/tests/output.rs` — `EXPIRED_NOT_AFTER` constant changes to `1_717_200_000`; the
  `source_rfc5280_on_expired_reports_no_findings` test asserts `(3 passed, 3 not applicable)` for the
  rfc5280 group — that count is unaffected by BR (different source) and stays as-is. The text/JSON
  prefix assertions (`certificate expired: notAfter is <EXPIRED_NOT_AFTER>`) track the constant.

**testdata/ (tester — task 04)**
- `generate.sh` — rewritten windows (BR_OK + past expired + 400d), SAN + serverAuth EKU added to all
  non-CA leaves, plus the four new BR fixtures; loud time-fragility header note.
- Regenerate ALL committed leaf `.pem`: `good.pem`, `expired.pem`, `rfc5280_serial_number_zero.pem`,
  `rfc5280_validity_inverted.pem`, `rfc5280_empty_subject_no_san.pem`, `rfc5280_version_not_v3.pem`,
  `hygiene_sha1_signature.pem`, `hygiene_rsa_1024.pem`, `hygiene_ecdsa_bad_curve.pem`.
- New: `cabf_br_validity_400_days.pem`, `cabf_br_cn_not_in_san.pem`, `cabf_br_internal_san.pem`,
  `cabf_br_missing_serverauth.pem`.
- The two CA fixtures (`rfc5280_ca_bc_not_critical.pem`, `rfc5280_ca_missing_keycertsign.pem`) are
  unchanged (BR N/A).
- New BR integration tests: `crates/linter/tests/cabf_br.rs`.

## Cross-Feature Fixture & Test Regeneration Plan (summary)

1. `generate.sh` regenerates all 9 non-CA leaf fixtures as BR-compliant-except-target (developer-free;
   tester task 04).
2. `registry.rs` + `cli/output.rs` `EXPIRED_NOT_AFTER` → `1_717_200_000` (tester task 04, since it
   owns the expired.pem reshape and those constants are coupled to the fixture).
3. `registry.rs` in-file unit tests: lint count 10→14, add `cabf_br` filter test (developer task 03,
   which already owns `registry.rs`).
4. `cert.rs` unit test `good_cert_has_no_key_usage_or_san` rewritten (developer task 05, serialized
   after task 01 to avoid a same-batch `cert.rs` conflict).

## Sequencing (batches)

- Batch A: task 01 (cert.rs facade + reserved.rs).
- Batch B: task 02 (lint files; depends on 01).
- Batch C: task 03 (registry.rs register + count/filter unit-test updates; depends on 02).
- Batch D: task 04 (generate.sh + all fixtures + cross-feature test-file updates + cabf_br.rs;
  depends on 03) AND task 05 (cert.rs unit-test rewrite; depends on 01 and 04). Task 05 and task 04
  touch DISJOINT files (05 → `cert.rs`; 04 → testdata + tests/* + cli/output.rs), so they may run in
  the same batch. Task 05 depends on 04 only because it needs the regenerated `good.pem` to assert
  against; if preferred, run 04 then 05 strictly sequentially.

> Conflict note: `cert.rs` is touched by BOTH task 01 (facade) and task 05 (unit-test rewrite). They
> are in different batches (01 in A, 05 in D) and linked via `depends_on`, so they never run
> concurrently. `registry.rs` is touched only by task 03.

## Dependencies

- None new. May lean on `std::net` for reserved-range checks; prefer std where possible and document
  any added crate.

## Ripple Flag: Feature 08 (cert-inspection) spec must be revisited

Feature 08's spec/test-plan assume `good.pem` is a clean leaf with **NO SAN and NO KeyUsage**:
- `spec/features/08-cert-inspection/test-plan.md` line ~26 reuses `good.pem` for the baseline summary
  snapshot, line ~57 tests "Cert with NO KeyUsage / NO SAN extension → summary prints a clear
  'absent' marker", and lines ~31/46 snapshot `good.pem`'s summary + JSON envelope.
- After this feature, `good.pem` **HAS a SAN (DNS:good.example) and the serverAuth EKU** (and a
  KeyUsage extension if the developer adds one to carry serverAuth cleanly). The "absent marker"
  edge case can no longer use `good.pem`; the good.pem summary snapshot will show SAN + EKU lines.

**Action (do NOT edit feature 08 here — flag only):** when feature 08 is planned/implemented, it must
either (a) use a different, deliberately bare fixture for the NO-SAN/NO-KeyUsage "absent marker" case,
and (b) regenerate its `good.pem` summary snapshots to include the SAN/EKU lines. This note exists so
feature 08's architect revisits those assumptions.
