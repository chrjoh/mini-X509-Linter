---
agent: tester
seq: 6
title: Relax stale exact-match CLI test for rfc5280 on expired.pem
status: done
touches:
  - crates/cli/tests/output.rs
depends_on:
  - 04-rfc5280-fixtures-and-tests
---

# Task: Relax stale exact-match CLI test for rfc5280 on expired.pem

## Goal

The CLI integration test
`text_output::source_rfc5280_on_expired_reports_no_findings`
(`crates/cli/tests/output.rs`, ~line 101) asserts EXACT stdout equality:

```rust
assert_eq!(stdout, "OK: no findings\n");
```

This only ever passed in feature 02 because no rfc5280 lints were registered then (the source
group was empty, so no header printed). Feature 03 registered six rfc5280 lints, so
`--source rfc5280 expired.pem` now correctly prints a non-empty source group. The ACTUAL,
verified output is:

```
[rfc5280]
  (3 passed, 3 not applicable)
OK: no findings
```

(expired.pem under rfc5280 has 3 applicable passing lints + 3 not-applicable lints, and zero
findings — the `not_expired` warn belongs to the hygiene source, not rfc5280.)

The `render_text` formatter is behaving CORRECTLY by design: a non-empty source group prints
a `[source]` header and a `(N passed, M not applicable)` summary. The TEST assertion is
stale, not the code. The sibling tests `min_severity_error_on_good_reports_no_findings` and
`min_severity_error_filters_the_warn_finding_on_expired` (~lines 124, 147) already use
`stdout.contains("OK: no findings")` — match that established pattern.

## Files Owned (conflict scope)

- `crates/cli/tests/output.rs` (the `source_rfc5280_on_expired_reports_no_findings` test only)

This task is the single owner of `output.rs` in this follow-up batch. Task 05 touches
`crates/linter/src/cert.rs`, so the two run in parallel.

## Steps

1. In `source_rfc5280_on_expired_reports_no_findings` (~line 101), replace the stale
   `assert_eq!(stdout, "OK: no findings\n");` (~line 118) with a `.contains` assertion
   consistent with the sibling `min_severity_error_*` tests:
   - `assert!(stdout.contains("OK: no findings"), ...)` with a helpful failure message that
     includes the actual stdout.
2. To keep the test meaningful (it should still verify the rfc5280 group renders), ALSO
   assert the group header/summary is present, e.g.:
   - `assert!(stdout.contains("[rfc5280]"), ...)`
   - `assert!(stdout.contains("not applicable"), ...)` (or the exact
     `(3 passed, 3 not applicable)` summary line — verify the exact string against the binary
     before hard-coding the counts).
   Verify the actual output first (e.g.
   `cargo run -p cli --bin mini-x509-lint -- --source rfc5280 testdata/expired.pem`) and
   assert strings that genuinely appear.
3. Update the test's `// Expect:` comment so it no longer claims "no hygiene group" / exact
   match — describe the real expectation (rfc5280 group renders, summary shows all-passing /
   not-applicable, no findings).
4. Do NOT change `render_text` or any production code. Do NOT weaken any other test in the
   file — only this one assertion changes.

## Acceptance Criteria

- [ ] `source_rfc5280_on_expired_reports_no_findings` passes via a `.contains("OK: no
      findings")` assertion (no longer exact-match).
- [ ] The test still verifies meaningful output (rfc5280 group header and/or
      passed/not-applicable summary present).
- [ ] No production code changed; no other test weakened.
- [ ] `cargo test` is FULLY green.
- [ ] `cargo clippy --all-targets -- -D warnings` (also with `--features serde`) and
      `cargo fmt --check` pass.

## Notes / Dependencies

- Depends on task 04 (the rfc5280 lints must be registered for this output shape to exist).
- Disjoint `touches` from task 05 — safe to run in parallel.
