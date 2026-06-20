---
agent: developer
seq: 3
title: Register the feature-17 BR lints + reconcile registry counts
status: done
touches:
  - crates/linter/src/registry.rs
depends_on:
  - developer-02-cabf-br-expansion-lints
---

# Task: Register the feature-17 BR lints + reconcile registry counts

## Goal

Append the 12 new `cabf_br` lints to `default_registry()` AFTER the existing cabf_br block (preserving
the deterministic registration order so golden snapshots extend rather than reshuffle), and update the
in-file count/filter unit tests. ONE owner of `registry.rs`.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs` (the `default_registry()` builder + its in-file `#[cfg(test)]` tests)

Does NOT touch `cert.rs`, any `lints/`, or any integration test / fixture / snapshot file.

## Steps

1. In `default_registry()`, append the 12 new lints at the END of the cabf_br block (after
   `cabf_br::SubjectCountryNotIso::new()`, before the cabf_ev block), in this order:
   - `cabf_br::SubscriberKeyUsageCertSignProhibited::new()`
   - `cabf_br::SubscriberKeyUsageCrlSignProhibited::new()`
   - `cabf_br::SubscriberBasicConstraintsPathLenProhibited::new()`
   - `cabf_br::ExtKeyUsageAnyProhibited::new()`
   - `cabf_br::ExtKeyUsageServerAuthRequired::new()`
   - `cabf_br::SanDnsOrIpOnly::new()`
   - `cabf_br::SanPresent::new()`
   - `cabf_br::CertificatePoliciesPresent::new()`
   - `cabf_br::CertificatePoliciesReservedOid::new()`
   - `cabf_br::RsaModulusBitsMultipleOf8::new()`
   - `cabf_br::RsaPublicExponentInRange::new()`
   - `cabf_br::BasicConstraintsPresent::new()`
   (Use the exact type names exported by developer-02's `mod.rs`; verify against that file. All 12 are
   registered — Phase-1.5 decision 1, no cuts.)

2. Update the in-file unit tests:
   - Total-count test: `assert_eq!(registry.len(), 70)` → `82` (both the `registry.len()` and the
     `outcomes.len()` assertions in that test).
   - Total-registry expected-ids list: add the 12 new `cabf_br_*` ids.
   - `cabf_br_source_filter_runs_exactly_the_cabf_br_set`: `assert_eq!(outcomes.len(), 12)` → `24`,
     update the doc comment ("twelve" → "twenty-four"), and extend the expected-ids list with the 12
     new ids.
   - Leave the rfc5280 (16), pqc (9), hygiene (4), cabf_ev (9), cabf_cs (8), cabf_smime (12) filter
     tests UNCHANGED.

3. Verify the registration order matches the plan's lint table so the downstream golden snapshots
   extend in this exact order.

## Acceptance Criteria

- [ ] All 12 new cabf_br lints registered at the end of the cabf_br block in the specified order (none
      cut — Phase-1.5 decision 1).
- [ ] Total count test 70 → 82; cabf_br filter test 12 → 24; both expected-ids lists extended.
- [ ] Other source-filter tests unchanged.
- [ ] `cargo test -p linter` (the in-file registry tests) green; `cargo clippy --all-targets -- -D
      warnings` and `cargo fmt --check` clean.

## Notes / Dependencies

- Depends on developer-02 (references the new lint types). Blocks tester-04 (the 82-lint registry must
  exist before fixtures are isolation-tested).
- All 12 lints are kept (Phase-1.5 decision 1); the counts are fixed at total 82 / cabf_br 24.
</content>
