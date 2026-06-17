# Phase 5 Completeness Review: CA/Browser Forum BR Rule Set (feature 05)

**Reviewer:** architect (final gate)
**Date:** 2026-06-16
**Scope reviewed:** `spec/features/05-cabf-br-rule-set/plan.md`, `test-plan.md`, tasks 01-06
(Acceptance Criteria), against the real code + committed test artifacts.

---

## TOP-LEVEL VERDICT: **COMPLETE**

All requirements, all files in every task `touches` list, and all acceptance criteria are
implemented and verified against the real code. All five quality gates pass (218 tests, clippy
clean with and without `serde`, fmt clean). No follow-up tasks required.

---

## Quality Gate Results

| Gate | Result | Evidence |
|---|---|---|
| `cargo fmt --check` | **PASS** | exit 0, no diff |
| `cargo clippy --all-targets -- -D warnings` | **PASS** | exit 0, `Finished` clean |
| `cargo clippy --all-targets --features serde -- -D warnings` | **PASS** | exit 0, `Finished` clean |
| `cargo test` | **PASS** | **218 passed; 0 failed** (sum across all binaries) |
| `cargo test -p linter --features serde` | **PASS** | linter lib 129 + cabf_br 18 + hygiene 11 + not_expired 8 + registry 10 + rfc5280 16 = 192, 0 failed |

Per-binary counts (`cargo test`):
- `mini_x509_lint` (cli unit): 14
- `cli tests/output.rs`: 12
- `linter` lib unit: 129
- `linter tests/cabf_br.rs`: 18
- `linter tests/hygiene.rs`: 11
- `linter tests/not_expired.rs`: 8
- `linter tests/registry.rs`: 10
- `linter tests/rfc5280.rs`: 16

---

## Requirements → Status

### R1. The four BR lints (broad-scoped; CA ⇒ NotApplicable) — **PASS**

| Lint | id | BR § | scoping | Evidence |
|---|---|---|---|---|
| `cabf_br_validity_max_398_days` | yes | §6.3.2 | `is_ca` ⇒ NotApplicable | `validity_max_398_days.rs:51` (id), `:40` (msg names duration), `:58/:120` (applies/NotApplicable) |
| `cabf_br_cn_in_san` | yes | §7.1.4.2.2 | same | `cn_in_san.rs:84` (id), `:62` (msg), `:91` (applies) |
| `cabf_br_no_internal_names_or_reserved_ip` | yes | §7.1.4.2 / §4.2.2 | same | `no_internal_names_or_reserved_ip.rs:68` (id), `:43/:56` (per-entry msgs), `:75/:158` (applies) |
| `cabf_br_ext_key_usage_server_auth_present` | yes | §7.1.2.7 | same | `ext_key_usage_server_auth_present.rs:49` (id), `:40` (msg + OID), `:56/:108` (applies) |

Each lint file carries a doc comment with the BR section number and is broad-scoped
(`NotApplicable` for CA, `Applies` for every non-CA leaf, not EKU-gated). Confirmed by
`cabf_br.rs::scoping::all_four_br_lints_apply_on_a_non_ca_leaf` and
`...all_four_br_lints_not_applicable_on_ca`.

### R2. Broad scoping (load-bearing) — **PASS**

`applies()` is uniform: `NotApplicable` iff `cert.is_ca()`. Not EKU-gated — a leaf without
serverAuth is flagged by `ext_key_usage_server_auth_present`, not skipped. Verified in all four
lint files and in `cabf_br.rs` scoping tests.

### R3. Reserved-IP / internal-name helper — **PASS**

`crates/linter/src/lints/cabf_br/reserved.rs` present. `is_reserved_ip` (`:45`) and
`is_internal_name` (`:141`) each fully RFC-cited in one auditable module (RFC 1918, 1122, 3927,
6598, 5737, 2544, 5771, 8190, 1112, 4291, 4193, 3849, 6761, 6762, 7686, 8375). `#[cfg(test)] mod
tests` at `:164` covers private/loopback/link-local/documentation/CGNAT/benchmarking/future-use IPv4,
IPv6 ranges, and internal-name true/false cases. Prefers `std::net` predicates; no new crate added.

### R4. SAN / EKU / CN / validity / is_ca accessors on the Cert facade — **PASS**

`crates/linter/src/cert.rs`: `is_ca` (`:365`), `san_dns_names` (`:437`), `san_ip_addresses` (`:464`),
`subject_common_names` (`:491`), `ext_key_usage_oids` (`:539`), `has_server_auth` (`:554`),
`validity_days` (`:573`). All return `Result<_, CertError>` (non-panicking).

### R5. Fixtures (4 new BR + 9 regenerated leaves + 2 unchanged CA + generate.sh) — **PASS**

All 15 `.pem` + `generate.sh` present in `testdata/`. Verified shapes via openssl:

- `good.pem`: 2026-06-01→2027-06-01 (365d), CN=good.example.com, SAN DNS=good.example.com, serverAuth.
- `expired.pem`: 2024-01-01→2024-06-01 (151d) — notAfter Unix = 1_717_200_000.
- `cabf_br_validity_400_days.pem`: 2026-06-01→2027-07-06 (400d), serverAuth, SAN=CN.
- `cabf_br_cn_not_in_san.pem`: CN=cn-missing.example.com, SAN DNS:other.example.com (omits CN), serverAuth.
- `cabf_br_internal_san.pem`: CN=public.example.com in SAN + DNS:internal.local + IP:10.0.0.1, serverAuth (multiple offenders).
- `cabf_br_missing_serverauth.pem`: clientAuth-only EKU (present but no serverAuth), SAN=CN.

`generate.sh` carries the loud TIME-FRAGILITY header (`:13`) and the window constants
`BR_OK_NB/NA`, `EXPIRED_NB/NA`, `VAL400_NB/NA` (`:157-168`).

### R6. Registration (10 → 14 lints, deterministic order, source filter) — **PASS**

`registry.rs:154-157` registers the four BR lints after rfc5280+hygiene (deterministic order for the
feature-06 golden test). Unit tests updated: `registry.len()==14` and `outcomes.len()==14` (`:489-490`);
`cabf_br_source_filter_runs_exactly_the_cabf_br_set` (`:576`) asserts 4 outcomes, all
`RuleSource::CabfBr`, the four ids, none rfc5280_/hygiene_. rfc5280 (6) + hygiene (4) filter counts
unchanged (`:525`, `:557`).

### R7. Cross-feature cascade — **PASS**

- `EXPIRED_NOT_AFTER = 1_717_200_000` in both `tests/registry.rs:47` and `cli/tests/output.rs:35`.
- `not_expired.rs` retargeted: `NOW_IN_GOOD_WINDOW = 1_796_083_200` (`:29`) = 2026-12-01, which is
  strictly inside good.pem's real window (notBefore 2026-06-01 = 1_780_272_000, notAfter 2027-06-01 =
  1_811_808_000) and past expired.pem's notAfter (2024-06-01). See NOTE-NOW below.
- `cert.rs` good-fixture test rewritten to `good_cert_has_san_and_server_auth_but_no_key_usage`
  (`:900`), asserting SAN DNS=good.example.com=CN; other good_cert tests (`:842/:858/:865`) unchanged.
- `rfc5280.rs` (`:21`) and `hygiene.rs` (`:25`) carry the 14-lint / BR-compliant-except-target module
  doc note; isolation assertions unchanged and passing.
- expired-isolation tests pass: `registry.rs:374,409`; cli `(3 passed, 3 not applicable)` at
  `output.rs:133`.

---

## Acceptance Criteria → Status (per task)

**Task 01** (cert facade + reserved.rs): all 4 ACs **PASS** — accessors present & documented (R4);
reserved classifiers RFC-cited with tests (R3); std-only, no crate added; clippy clean.

**Task 02** (four lints): all 5 ACs **PASS** — four `cabf_br_*` lints, each citing BR section;
NotApplicable on CA / Applies on every non-CA leaf; `cn_in_san` & `no_internal_names_or_reserved_ip`
emit one finding per offending entry (verified: `internal_san_fixture_yields_two_findings_from_one_lint`,
`cabf_br.rs:346`); no unwrap/expect/panic on cert data paths; clippy clean.

**Task 03** (registry): all 5 ACs **PASS** — four BR lints in `default_registry()`; `--source cabf_br`
runs exactly the BR set; deterministic order; `contains_the_known_lints` at 14 + four ids; cabf_br
filter test added; clippy clean.

**Task 04** (fixtures + cross-feature tests): all 6 ACs **PASS** — 9 leaves regenerated, 4 BR fixtures
added, 2 CA unchanged, fragility header present; `good.pem` passes the full 14-lint registry
(`rfc5280.rs`/`hygiene.rs` good_pem tests green); `expired.pem` isolates only `hygiene_not_expired`
(`registry.rs:409`); every rfc5280/hygiene fixture isolates exactly one rule; `EXPIRED_NOT_AFTER`
updated in both files; `cabf_br.rs` covers flag/pass, multi-finding, boundary, no-CN, CA-NotApplicable;
test/clippy/fmt pass.

**Task 05** (cert.rs good-fixture test): all 3 ACs **PASS** — test reflects regenerated fixture (SAN
present with CN, serverAuth present, KeyUsage absent and named so in the test); other good_cert/spki
tests pass unchanged; `cargo test -p linter` + clippy clean.

**Task 06** (not_expired.rs now-constant): all 3 ACs **PASS** — `NOW_IN_GOOD_WINDOW` retargeted into
good.pem's window with corrected docs; full `cargo test` green; serde test + clippy (both) + fmt pass.

---

## Known Notes (each judged)

**NOTE-TIME-FRAGILITY — PARTIAL/note (accepted cost, NOT a defect).**
All non-CA leaf fixtures use a currently-valid ≤398-day window expiring 2027-06-01
(`cabf_br_validity_400_days` expires 2027-07-06). After those dates `hygiene_not_expired` fires on
every leaf and the isolation suite fails wholesale. This is the inherent cost of combining "currently
valid" with "≤398 days" — a short window cannot also be far-future. Documented loudly in
`generate.sh:13` header and referenced in the rfc5280/hygiene/cabf_br/not_expired test module docs, so
a future maintainer seeing a flood of `not_expired` failures can diagnose it. **Action required before
2027-06-01:** slide the windows forward and regenerate. Accepted, not blocking.

**NOTE-RESERVED-EXAMPLE — PARTIAL/note (documented, intentional).**
`reserved.rs` classifies `.example` as RFC 6761 special-use/reserved, so fixtures use public
`*.example.com` names (e.g. `good.example.com`) rather than `*.example`. The plan's earlier prose
sometimes wrote `good.example`; the committed fixtures and tests consistently use `good.example.com`,
and the cert.rs/cabf_br tests assert that exact string. Internally consistent; documented. Not a defect.

**NOTE-NOW-CONSTANT — note (value-correction confirmed correct).**
Task 06's inline comment labeled good.pem's notAfter as `1_780_272_000`; that value is actually
good.pem's *notBefore* (2026-06-01). The real notAfter is `1_811_808_000` (2027-06-01). The committed
constant `NOW_IN_GOOD_WINDOW = 1_796_083_200` (2026-12-01) is correctly strictly inside
[notBefore, notAfter] and past expired.pem's notAfter. This is the "follow-up value-correction"
referenced in the task status — verified correct against the real fixture bytes. Not a defect.

**NOTE-NO-CLI-E2E — PARTIAL/note (criterion satisfied at the specified level).**
There is no CLI-level `--source cabf_br` end-to-end test. The relevant acceptance criterion (task 03)
specifies a *registry-level* filter test, which exists and passes
(`cabf_br_source_filter_runs_exactly_the_cabf_br_set`, `registry.rs:576`). The CLI already wires
sources generically and has rfc5280-source CLI coverage in `cli/tests/output.rs`. No criterion in this
feature requires a CLI cabf_br e2e test, so this is not a gap for feature 05. Optional future
enhancement only.

**NOTE-FEATURE-08-RIPPLE — flag only (do NOT edit feature 08).**
`good.pem` now has a SAN (DNS:good.example.com) + serverAuth EKU, which invalidates feature 08's
planned "no SAN / no KeyUsage" inspection edge case and its `good.pem` summary/JSON snapshots
(plan.md "Ripple Flag" section; feature-08 test-plan ~lines 26/31/46/57). When feature 08 runs, its
architect MUST (a) use a different deliberately-bare fixture for the NO-SAN/NO-KeyUsage "absent marker"
case, and (b) regenerate good.pem snapshots to include the SAN/EKU lines. **Not actioned here by
design.**

---

## Conclusion

Every requirement, every `touches` file, and every acceptance criterion across tasks 01-06 maps to
PASS (with the five notes above judged as accepted/documented notes, none rising to FAIL). All five
quality gates are green at 218 tests.

**VERDICT: COMPLETE.** No follow-up tasks created.
