---
agent: tester
seq: 5
title: Fix stale outcome-count note in test-plan.md
status: done
touches:
  - spec/features/10-smime-br/test-plan.md
depends_on:
  - tester-04-fixtures-and-tests
---

# Task: Fix stale outcome-count note in test-plan.md

## Context

The Phase-5 completeness review (`spec/features/10-smime-br/review.md`, gap G1) found a doc-only
inaccuracy. This is a documentation correction only — NO code, test, or fixture changes.

## What to Do

In `spec/features/10-smime-br/test-plan.md`, the `contains_the_known_lints` bullet (around line 66-68)
currently reads:

> `sample_cert()` is a CA without emailProtection ⇒ smime lints NotApplicable but still one outcome
> each ⇒ outcome count == 44.

This contradicts the implemented (and correct) assertion. The engine never short-circuits: every
registered lint yields exactly one outcome regardless of applicability, so for the 52-lint registry
the outcome count equals the registry length, **52**, not 44. The shipped test asserts
`outcomes.len() == 52` (`crates/linter/src/registry.rs`, `contains_the_known_lints`,
`assert_eq!(outcomes.len(), 52)`).

1. Change `outcome count == 44` to `outcome count == 52` so the test-plan matches the registry length
   (one outcome per lint; NotApplicable still counts).
2. Skim the surrounding lines for any other "44" / "26" / "32 → 44" remnants in this file and
   reconcile them to the 52-lint reality if found (the review only confirmed line 68; double-check the
   whole file).

## Acceptance Criteria

- [ ] `test-plan.md` no longer states `outcome count == 44`; it states `== 52` (matching
      `registry.rs::contains_the_known_lints`).
- [ ] No other stale lint/outcome counts remain in `test-plan.md`.
- [ ] No source, test, or fixture files are touched (doc-only change).

## Notes

- Non-blocking: feature 10 is COMPLETE per the review; this only corrects spec drift so a future
  maintainer is not misled.
