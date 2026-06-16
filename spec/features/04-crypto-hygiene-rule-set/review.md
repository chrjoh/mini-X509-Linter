# Phase 5 Completeness Review — Feature 04: Crypto Hygiene Rule Set

**Reviewer:** architect
**Date:** 2026-06-16
**Scope:** `spec/features/04-crypto-hygiene-rule-set/` (tasks 01–04)
**Prior gates:** Integration review = INTEGRATION CLEAN; tester verification = VERIFIED (160 tests).

---

## Verdict: COMPLETE

Every plan.md requirement, every file in every task's `touches` list, and every
acceptance criterion across tasks 01–04 is implemented in real code and covered by
passing tests. All five quality gates are green. No follow-up tasks required.

---

## Quality Gate Results

| Gate | Result | Evidence |
|------|--------|----------|
| `cargo fmt --check` | PASS | exit 0, no diff |
| `cargo clippy --all-targets -- -D warnings` | PASS | exit 0, `Finished` clean |
| `cargo clippy --all-targets --features serde -- -D warnings` | PASS | exit 0, `Finished` clean |
| `cargo test` | PASS | **160 passed; 0 failed** across all targets |
| `cargo test -p linter --features serde` | PASS | **134 passed; 0 failed** (linter crate w/ serde) |

`cargo test` per-target counts: main 14, output 12, linter lib 89, hygiene 11,
not_expired 8, registry 10, rfc5280 16, doctests 0 = 160.

---

## Requirement Mapping

| Requirement (plan.md) | Status | Evidence |
|------------------------|--------|----------|
| `no_sha1_signature` lint — flag SHA-1 in signature algorithm | PASS | `no_sha1_signature.rs:57-98`; id `hygiene_no_sha1_signature` (:59), `RuleSource::Hygiene` (:63), `Severity::Error` (:92); message names algorithm (:93). Integration: `hygiene.rs:67-81` flags `sha1WithRSAEncryption`, `:84-91` passes good.pem. |
| `rsa_key_min_2048` lint — RSA modulus ≥ 2048 bits | PASS | `rsa_key_min_2048.rs:48-75`; id (:50), `MIN_RSA_BITS=2048` (:16), message names bit length (:40-42). Integration: `hygiene.rs:97-111` flags 1024 (substring "1024"), `:113-120` passes good.pem. |
| `ecdsa_curve_allowlist` lint — restrict to P-256/384/521 | PASS | `ecdsa_curve_allowlist.rs:79-107`; allowlist OIDs (:29-33), id (:81), message names curve (:67). Integration: `hygiene.rs:137-154` flags secp224r1 (OID 1.3.132.0.33). |
| `not_expired` — folded into hygiene set & consistent | PASS | `not_expired.rs:79` id `hygiene_not_expired`, `RuleSource::Hygiene` (:83), `Severity::Warn` (:101). Declared/re-exported in `hygiene/mod.rs:9,14`. Registered exactly once `registry.rs:139`. |
| SPKI / signature accessors on `Cert` facade | PASS | `cert.rs`: `signature_algorithm_oid` (:412), `signature_algorithm_name` (:428), `public_key_algorithm`→`PublicKeyAlg` (:442), `rsa_modulus_bits`→`Option<u32>` (:466), `ec_named_curve`→`Option<NamedCurve>` (:485). Uses `oid-registry`/`oid2sn` (:511-513), `der`/`x509-parser` structure. No new deps. |
| `applies()` scoping (NotApplicable for wrong key type) | PASS | `rsa_key_min_2048.rs:57-64` Applies only for RSA; `ecdsa_curve_allowlist.rs:88-95` Applies only for EC; `no_sha1_signature.rs:66-70` always Applies. Integration NotApplicable cases: `hygiene.rs:122-131, 156-188`. |
| Fixtures created + regeneration script | PASS | `testdata/hygiene_sha1_signature.pem`, `hygiene_rsa_1024.pem`, `hygiene_ecdsa_bad_curve.pem` all present; `generate.sh:225-245` emits all three with documented algorithms/curves. |
| Registration in default registry (10 lints) | PASS | `registry.rs:134-152` (4 hygiene + 6 rfc5280); `registry.rs:479` asserts `len()==10`; `--source hygiene` runs exactly 4 (`registry.rs:535-559`). |

---

## Acceptance Criteria Mapping

### Task 01 — Cert facade SPKI accessors (`cert.rs`)

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Accessors exist, documented, return Option/enums without panicking | PASS | `cert.rs:412,428,442,466,485` — all return `Result<...>`/`Option`; no `unwrap`/`panic` on cert paths (`with_parsed` returns `Err` defensively, :216-219). |
| `rsa_modulus_bits` None for EC; `ec_named_curve` None for RSA | PASS | `rsa_modulus_bits` matches only `PublicKey::RSA` else None (:467-470); `ec_named_curve` early-returns None for non-EC OID (:489-491). Unit tests `cert.rs:699-715`. |
| SHA-1 detection possible from signature-algorithm accessor | PASS | `signature_algorithm_oid` (:412) + known-OID doc (:404-406); consumed by `no_sha1_signature`. |
| `cargo clippy --all-targets -- -D warnings` clean | PASS | gate green. |

### Task 02 — Hygiene lints + consolidate not_expired

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Three new lints with `hygiene_*` ids; not_expired confirmed/exported | PASS | ids `hygiene_no_sha1_signature` / `hygiene_rsa_key_min_2048` / `hygiene_ecdsa_curve_allowlist`; `mod.rs:7-15` declares + re-exports all four incl. not_expired. |
| `rsa_key_min_2048` NotApplicable for EC; `ecdsa_curve_allowlist` NotApplicable for RSA | PASS | `rsa_key_min_2048.rs:57-64`; `ecdsa_curve_allowlist.rs:88-95`. Integration `hygiene.rs:122-131,156-165`. |
| Messages name offending algorithm/curve/bit length | PASS | `no_sha1_signature.rs:93`, `rsa_key_min_2048.rs:40-42`, `ecdsa_curve_allowlist.rs:67`. Asserted via substring `hygiene.rs:80,110,153`. |
| No unwrap/expect/panic on cert data paths | PASS | All three `check`/`applies` match on `Result` and fail safe (`no_sha1_signature.rs:77-80`, `rsa_key_min_2048.rs:70-73`, `ecdsa_curve_allowlist.rs:102-105`). |
| clippy clean | PASS | gate green. |

### Task 03 — Register hygiene lints (`registry.rs`)

| Criterion | Status | Evidence |
|-----------|--------|----------|
| All four hygiene lints registered, not_expired exactly once | PASS | `registry.rs:139-142`; single `NotExpired::new()` at :139. |
| `--source hygiene` runs exactly the hygiene set | PASS | `registry.rs:535-559` asserts 4 hygiene, 0 rfc5280. |
| Registration order deterministic | PASS | Fixed `vec![...]` order with golden-test comment (:137-144). |
| clippy clean | PASS | gate green. |

### Task 04 — Fixtures + tests (`generate.sh`, 3 fixtures, `hygiene.rs`)

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Three new fixtures exist; generate.sh regenerates (or documents limitation) | PASS | Fixtures present (`ls testdata/`); `generate.sh:225-245` emits each with inline provenance (SHA-1 via openssl 3.6.2 default provider, RSA-1024, secp224r1). |
| Each lint flags its fixture and is NotApplicable for wrong key type | PASS | `hygiene.rs:64-92,94-132,134-189`; full-registry isolation `hygiene.rs:198-227`. |
| `cargo test`, clippy, `cargo fmt --check` pass | PASS | all gates green. |

---

## Test-Plan Coverage (`test-plan.md`)

| Test-plan item | Status | Evidence |
|----------------|--------|----------|
| `no_sha1_signature` flags SHA-1, passes good.pem | PASS | `hygiene.rs:67-91` |
| `rsa_key_min_2048` flags RSA-1024, NotApplicable on EC | PASS | `hygiene.rs:97-131` |
| `ecdsa_curve_allowlist` flags non-allowlisted, NotApplicable on RSA, passes P-256 | PARTIAL (see note a) | flag + NotApplicable in `hygiene.rs:137-188`; P-256 PASS covered by helper unit test `ecdsa_curve_allowlist.rs:151-153`, not a real EC cert fixture. |
| `not_expired` flags expired.pem, passes good.pem | PASS | `tests/not_expired.rs:92-120`; consolidated-set exclusivity `registry.rs:404` (`expired_fixture_isolates_only_the_not_expired_finding`). |
| Edge: non-RSA/non-EC → both key lints NotApplicable, no panic | PASS | `applies()` `_ => NotApplicable` arms (`rsa_key_min_2048.rs:62`, `ecdsa_curve_allowlist.rs:93`); `PublicKeyAlg::Other` returned, not error (`cert.rs:450`). |
| Edge: SHA-2 signature passes | PASS | `no_sha1_signature.rs:132-134`, `hygiene.rs:84-91`. |
| Edge: curve toolchain limitation documented in generate.sh | PASS | `generate.sh:225-245` provenance comments. |

---

## Non-Blocking Notes (judged)

**(a) ECDSA allowlisted-curve PASS path — PARTIAL (not FAIL).**
The P-256/384/521 PASS path is verified by a unit test on the pure decision helper
`evaluate(Some(curve(OID_P256, ...)))` (`ecdsa_curve_allowlist.rs:147-153`,
`is_allowlisted_oid` :130-145), not by a real allowlisted-EC certificate fixture. No
such fixture exists, and adding one is outside the tester's task-04 scope. **plan.md
does not require an allowlisted-EC fixture** (Changes Overview lists only the three
"bad" hygiene fixtures + reuse of good.pem/expired.pem). The accessor path that would
read a real curve is independently exercised by the secp224r1 fixture
(`hygiene.rs:137-154`), so OID extraction itself is integration-covered. Judged
PARTIAL/note — does not block COMPLETE.

**(b) good.pem / expired.pem (and rfc5280 fixtures) show as modified in git — note (not FAIL).**
`git status` shows `expired.pem`, `good.pem`, and the six `rfc5280_*.pem` fixtures as
modified, and the three new `hygiene_*.pem` as untracked. Cause: `generate.sh` was
re-run with fresh random keys. The regenerated certs are semantically identical (same
algorithms — RSA-2048 / SHA-256 for good.pem; same validity windows, subjects, and
intended single-rule violations). All regression tests are green (160/160), behavior
unchanged. The scope is slightly broader than originally noted (the rfc5280 fixtures
also re-rolled), but the same reasoning applies and no test depends on byte-stable key
material. Judged note — does not block COMPLETE.

---

## Conclusion

All requirements, touched files, and acceptance criteria across tasks 01–04 are
implemented and test-covered. All five quality gates pass. The two known items are
correctly non-blocking: (a) is not a plan.md requirement and the PASS path is
unit-tested; (b) is cosmetic git churn with unchanged semantics and green tests.

**FINAL VERDICT: COMPLETE.**
