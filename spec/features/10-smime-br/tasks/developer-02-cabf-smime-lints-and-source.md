---
agent: developer
seq: 2
title: Implement the cabf_smime lints + RuleSource::CabfSmime
status: pending
touches:
  - crates/linter/src/source.rs
  - crates/linter/src/lints/mod.rs
  - crates/linter/src/lints/cabf_smime/mod.rs
  - crates/linter/src/lints/cabf_smime/san_present.rs
  - crates/linter/src/lints/cabf_smime/san_not_critical.rs
  - crates/linter/src/lints/cabf_smime/email_in_san.rs
  - crates/linter/src/lints/cabf_smime/single_email_subject.rs
  - crates/linter/src/lints/cabf_smime/key_usage_present.rs
  - crates/linter/src/lints/cabf_smime/key_usage_critical.rs
  - crates/linter/src/lints/cabf_smime/eku_email_protection_present.rs
  - crates/linter/src/lints/cabf_smime/eku_no_server_auth.rs
  - crates/linter/src/lints/cabf_smime/authority_key_identifier_present.rs
  - crates/linter/src/lints/cabf_smime/crl_distribution_points_present.rs
  - crates/linter/src/lints/cabf_smime/crl_distribution_points_http.rs
  - crates/linter/src/lints/cabf_smime/subject_country_valid.rs
depends_on:
  - developer-01-cert-facade-smime-accessors
---

# Task: Implement the cabf_smime lints + RuleSource::CabfSmime

## Goal

Add `RuleSource::CabfSmime` and implement the ~12 S/MIME BR lints, one small file per lint, each
EKU-gated, `cabf_smime_*` id, each commented with its S/MIME BR section. Mirror `lints/cabf_br/`
exactly in shape.

## Files Owned (conflict scope)

- `crates/linter/src/source.rs` (add the `CabfSmime` variant only).
- `crates/linter/src/lints/mod.rs` (add `pub mod cabf_smime;`).
- `crates/linter/src/lints/cabf_smime/mod.rs` (new) + the twelve lint files (front-matter list).

Does NOT touch `cert.rs` (task 01), `registry.rs`, or the cli files (task 03).

## Scoping (EKU-GATED — load-bearing, see plan.md "Cascade-Avoidance Decision")

Every lint's `applies()` is identical and delegates to a single shared helper in
`cabf_smime/mod.rs`:

```text
fn applies_to_smime_leaf(cert) -> Applicability {
    // Applies iff: not a CA AND emailProtection EKU present.
    // Fail-safe: any accessor Err -> NotApplicable.
}
```

This guarantees the lints are `NotApplicable` on every pre-existing fixture (none carry
emailProtection), so NO existing fixture is regenerated. Use `cert.is_ca()` and
`cert.has_email_protection()` (added in task 01).

## Steps

1. `source.rs`: add `CabfSmime` to `RuleSource` with a doc comment ("CA/Browser Forum S/MIME
   Baseline Requirements for email-protection certificates."). It must serialize (serde feature) to
   the snake_case wire string `cabf_smime` — the existing `#[serde(rename_all = "snake_case")]`
   handles this; verify. Update the enum's doc comment that lists the wire vocabulary.
2. `lints/mod.rs`: add `pub mod cabf_smime;`.
3. `cabf_smime/mod.rs`: module doc (scoping policy + fail policy, mirroring `cabf_br/mod.rs`),
   `mod`/`pub use` for each lint, and the shared `applies_to_smime_leaf` helper.
4. Implement each lint per the plan.md table (fail policy: accessor `Err` in `check` → empty `Vec`;
   accessor `Err` in `applies` → `NotApplicable`; no `unwrap`/`expect`/`panic!` on cert paths):
   - `cabf_smime_san_present` (Error) — fire if SAN absent or has zero `rfc822Name`. (§7.1.2.3)
   - `cabf_smime_san_not_critical` (Warn) — fire if SAN is critical and subject DN is non-empty.
     (§7.1.2.3)
   - `cabf_smime_email_in_san` (Error) — for each subject CN that is email-shaped (contains `@`),
     fire if it is not present (case-insensitive on the domain part — document the chosen policy) in
     `san_rfc822_names()`. One finding per offending CN, naming it. Non-email CNs are ignored.
     (§7.1.4.2.1)
   - `cabf_smime_single_email_subject` (Error) — fire if `subject_email_addresses().len() > 1`.
     (§7.1.4.2.1)
   - `cabf_smime_key_usage_present` (Error) — fire if KeyUsage extension absent
     (`cert.key_usage()? is None`). (§7.1.2.3)
   - `cabf_smime_key_usage_critical` (Warn) — fire if KeyUsage present but not critical. If KeyUsage
     absent, emit nothing (that is lint 5's concern). (§7.1.2.3)
   - `cabf_smime_eku_email_protection_present` (Error) — fire only on the defensive
     `has_email_protection()` `Err` path / `Ok(false)` (which is unreachable under the gate). See
     plan.md note: this lint reads complete against §7.1.2.3 and acts as a guard. Document that the
     gate already requires emailProtection so the firing path is the defensive one. (§7.1.2.3)
   - `cabf_smime_eku_no_server_auth` (Error) — fire if the cert ALSO asserts `serverAuth`
     (`has_server_auth()`), i.e. forbidden TLS-server multipurpose. (§7.1.2.3)
   - `cabf_smime_authority_key_identifier_present` (Error) — fire if
     `has_authority_key_identifier()` is false. (§7.1.2.3)
   - `cabf_smime_crl_distribution_points_present` (Error) — fire if `has_crl_distribution_points()`
     is false. (§7.1.2.3)
   - `cabf_smime_crl_distribution_points_http` (Error) — for each URI in
     `crl_distribution_point_uris()` whose scheme is not `http`/`https`, fire (one finding per
     offending URI, naming it). If no CRL DP present, emit nothing (lint 10's concern). (§7.1.2.3)
   - `cabf_smime_subject_country_valid` (Error) — for each `subject_country_names()` value that is
     not exactly 2 ASCII letters, fire (one finding per offending value, naming it). If no country
     present, emit nothing (country is optional). (§7.1.4.2)
5. Each lint file: doc comment with S/MIME BR section, `Lint` impl, and a `#[cfg(test)] mod tests`
   with pass/fail unit cases. Where a fixture is needed, use a `load_fixture` helper like
   `cabf_br`'s; the S/MIME fixtures land in task 04, so prefer pure-decision helper unit tests
   (factor an `evaluate(...)` fn like `cabf_br/ext_key_usage_server_auth_present.rs`) for the
   firing logic and add only minimal fixture-backed `applies()` tests (which task 04 will satisfy).

## Acceptance Criteria

- [ ] `RuleSource::CabfSmime` added; serializes to `cabf_smime`.
- [ ] All ~12 lints implemented, each `cabf_smime_*`, each citing its S/MIME BR section.
- [ ] Every lint EKU-gated via the shared `applies_to_smime_leaf` (NotApplicable unless
      emailProtection present and not CA).
- [ ] Multi-violation lints emit one finding per offending entry.
- [ ] No `unwrap`/`expect`/`panic!` on cert data paths; accessor `Err` handled explicitly.
- [ ] `cargo clippy --all-targets -- -D warnings` clean (and `--features serde`).

## Notes / Dependencies

- Depends on task 01 (facade accessors). Blocks task 03 (registration/purpose wiring).
- Do NOT register the lints or add the purpose here — that is task 03.
