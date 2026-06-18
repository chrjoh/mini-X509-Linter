---
agent: developer
seq: 3
title: Register cabf_smime lints + CertPurpose::Smime + CLI wiring
status: done
touches:
  - crates/linter/src/registry.rs
  - crates/cli/src/main.rs
  - crates/cli/src/output.rs
depends_on:
  - developer-02-cabf-smime-lints-and-source
---

# Task: Register cabf_smime lints + CertPurpose::Smime + CLI wiring

## Goal

Wire the S/MIME rule set into the default registry, promote `CertPurpose::Smime`, extend the `auto`
resolver and the CLI (`--source cabf_smime`, `--purpose smime`, output `SOURCE_ORDER`), and update
the affected unit tests.

## Files Owned (conflict scope)

- `crates/linter/src/registry.rs`
- `crates/cli/src/main.rs`
- `crates/cli/src/output.rs`

> CROSS-FEATURE WARNING: these three files are ALSO edited by sibling features 09 (code-signing) and
> 11. The `auto` resolver, `ALL_SOURCES`, `SOURCE_ORDER`, the `--source` token list, the
> `--purpose` ValueEnum, and the source-filter unit tests are common ground. Implement SEQUENCED
> with 09/11 (not concurrently). If 09 has already landed `CertPurpose::CodeSigning` and its
> resolver branch, EXTEND that shape (add the emailProtection branch after codeSigning per the
> precedence in plan.md); do not overwrite it. Reconcile lint/outcome counts in
> `contains_the_known_lints` against the then-current registry length.

## Steps

### registry.rs

1. In `default_registry()`, append boxed instances of all ~12 `cabf_smime` lints AFTER the
   `cabf_br` block, in a deterministic order (the feature-06 golden test pins ordering — keep it
   stable and grouped).
2. Promote `CertPurpose::Smime` (remove it from the "Future variants" doc note; document it as
   shipped). Add a `smime_sources()` helper returning `vec![Rfc5280, Hygiene, CabfSmime]` (stable
   order), mirroring `tls_server_sources()`/`generic_sources()`. Wire it into `allowed_sources` and
   `resolve` for `CertPurpose::Smime`.
3. Extend the `auto` resolver per plan.md precedence: serverAuth → TlsServer; else codeSigning →
   CodeSigning (feature 09, if present); else emailProtection → Smime; else Generic. The pure
   decision helper (`auto_sources_from` and/or a new resolver) must take whatever signals it needs
   (e.g. `Result<bool, CertError>` for serverAuth AND emailProtection) so the branches stay
   unit-testable without fixtures — match the existing fail-closed style (`Err` never manufactures a
   source-specific false positive). Add `auto_*` unit tests for the new emailProtection branch
   (Ok(true) → smime set; the serverAuth-wins precedence; Err → generic/fail-closed).
4. Update in-file unit tests:
   - `contains_the_known_lints`: registry length 40 → 52 off current main (12 smime lints; feature 09
     already landed; reconcile again if sibling 11 lands first), outcome count likewise,
     and add the twelve `cabf_smime_*` ids to the
     expected list. Note `sample_cert()` is a CA with no emailProtection, so the smime lints are
     `NotApplicable` but still produce one outcome each → outcome count == registry length.
   - Add `cabf_smime_source_filter_runs_exactly_the_cabf_smime_set` mirroring the rfc5280/hygiene/
     cabf_br filter tests (12 outcomes, all `RuleSource::CabfSmime`, the twelve ids, none from other
     prefixes).
   - Add `CertPurpose::Smime` tests: `smime_includes_cabf_smime` (allowed_sources ==
     `[Rfc5280, Hygiene, CabfSmime]`), and `resolve`/`allowed_sources` consistency. The existing
     rfc5280 (16), hygiene (4), cabf_br (12) filter-count tests are UNCHANGED (baseline after feature 12).

### crates/cli/src/main.rs

5. `parse_source_token`: add `"cabf_smime" => Ok(RuleSource::CabfSmime)` and update the error
   message's accepted-values list.
6. `ALL_SOURCES`: add `RuleSource::CabfSmime` (keep the array consistent with `SOURCE_ORDER`).
7. `CliPurpose`: add a `Smime` variant (ValueEnum token `smime`); update the `From<CliPurpose>` map
   (`Smime => CertPurpose::Smime`), the `purpose_label` (`Smime => "smime"`), the doc comment
   (remove `smime` from "reserved/not implemented"; it is now shipped), and the module/flag help
   text listing `--source`/`--purpose` values.
8. Update affected unit tests (`select_sources` accepting `cabf_smime`; `cli_purpose_conversion`
   mapping `Smime`; any `effective_sources` test that enumerates the full source set).

### crates/cli/src/output.rs

9. `SOURCE_ORDER`: add `RuleSource::CabfSmime` (choose a fixed position consistent with `main.rs`
   `ALL_SOURCES`; document the chosen order — e.g. after `CabfBr`). `source_label`: add
   `RuleSource::CabfSmime => "cabf_smime"`. The `SOURCE_ORDER` array length grows from 3.

## Acceptance Criteria

- [ ] `default_registry()` includes all ~12 cabf_smime lints in deterministic order.
- [ ] `--source cabf_smime` runs exactly the smime set; `--purpose smime` maps to
      `[Rfc5280, Hygiene, CabfSmime]`.
- [ ] `auto` resolves an emailProtection-only leaf to `Smime` (serverAuth still wins when both
      present), with fail-closed `Err` behaviour; new resolver unit tests pass.
- [ ] `contains_the_known_lints` + a `cabf_smime` source-filter test + `Smime` purpose tests added
      and passing; other source-filter counts unchanged.
- [ ] CLI `SOURCE_ORDER`/`ALL_SOURCES`/`source_label`/`CliPurpose` all carry `cabf_smime`/`smime`.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings` (and `--features serde`),
      `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 02. Blocks test task 04.
- Reconcile with siblings 09/11 on the four shared files (see cross-feature warning).
