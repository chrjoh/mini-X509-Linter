---
agent: developer
seq: 7
title: Flip the README "no chain-aware lints" Scope note now that feature 15 shipped
status: done
touches:
  - README.md
depends_on:
  - tester-06-flip-observed-assertions-and-reconcile-chain-bundle
---

# Task: Update the README Scope note for chain-aware lints

## Background

Feature 15 shipped the linter's first chain-aware lints, the `chain` source, the
`build_chain` order-independent construction step, and pure-Rust signature
verification (`chain_signature_valid`, on by default in the CLI). The README still
contains the now-FALSE non-goal statements that feature 15's Ripple Flag flagged
for update:

- `README.md:401-402` — "Each certificate is linted **independently** — there are
  no chain-aware lints (see [Scope & limitations])."
- `README.md:518-522` (Scope & limitations bullet) — "**Each certificate is linted
  independently.** `--chain` parses and lints every certificate in a bundle
  separately — there are **no chain-aware lints**: no path-building, no
  issuer/subject linkage checks, and no signature verification against the issuer."

Both statements are contradicted by the shipped behavior (verified at the review
gate: `--chain chain_missing_middle.pem --fail-on error` exits 1 with a
`chain_subject_issuer_dn_match` Error under a `(whole chain)` heading; the clean
chain runs all 8 chain lints incl. `chain_signature_valid`).

This is a DOCUMENTATION-only change (no code/tests). It was intentionally deferred
out of the code/test tasks per the plan's Ripple Flag.

## What to Do

Update `README.md` so the Scope note reflects the shipped feature. Per the plan's
Ripple Flag, the README MUST now describe:

1. The new chain-aware lints and the `chain` source (the `chain_*` lint family;
   `--source chain`).
2. That the chain is BUILT/normalized (order-independent): a shuffled-but-complete
   bundle is reordered (a `chain_not_in_order` **Notice**), not rejected.
3. That chain lints run on BOTH `--chain` file bundles (≥2 certs) AND the
   `--from-host` presented chain.
4. The explicit trust-vs-lint separation: the `--from-host` `verification:` verdict
   establishes trust to a root (webpki-roots, via `rustls`); the chain lints only
   verify the LINKS that are present, and a merely-absent root is a
   `chain_issuer_not_in_chain` **Notice**, never an Error.
5. That signature verification (`chain_signature_valid`) is pure-Rust
   (`ring` + `fips204`/`fips205`), behind the linter's `verify` feature, enabled by
   default in the CLI; an unsupported signature algorithm is a fail-open **Notice**,
   never a false Error.

Replace the line 401-402 cross-reference and the line 518-522 Scope bullet with
accurate text. Keep the rest of the Scope section (CABF subset, PQC-coverage,
out-of-scope path-validation/AIA/revocation) intact — full RFC 5280 §6.1 path
validation, AIA-fetching, and revocation remain out of scope and should still be
listed as such.

## Acceptance Criteria

- [ ] No remaining "no chain-aware lints" / "linted independently … no chain-aware"
      statement in `README.md`.
- [ ] The Scope section accurately describes: the chain source/lints, the
      order-independent `build_chain` normalization, the `--chain` + `--from-host`
      coverage, the trust-vs-lint separation, and the `verify`-gated pure-Rust
      signature verification with its fail-open Notice policy.
- [ ] Out-of-scope items still listed: full §6.1 path validation, AIA-fetching,
      revocation, cross-signed graph exploration.
- [ ] Documentation-only: no change under `crates/*/src/`, `tests/`, or `testdata/`.

## Notes / Dependencies

- This is the README documentation step explicitly deferred by feature 15's Ripple
  Flag and noted in `tester-04`'s Notes. It is the ONLY remaining gap from the
  Phase 5 completeness review; everything else passed.
