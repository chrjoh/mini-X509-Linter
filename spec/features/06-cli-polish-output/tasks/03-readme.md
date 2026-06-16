---
agent: developer
seq: 3
title: README — usage, flags, exit codes, examples
status: pending
touches:
  - README.md
depends_on:
  - 02-fail-on-and-chain-flags
---

# Task: README — usage, flags, exit codes, examples

## Goal

Document the CLI surface so the tool is usable from the README alone.

## Files Owned (conflict scope)

- `README.md` (workspace root)

## Steps

Write `README.md` covering:
1. What the tool is (a from-scratch X.509 linter; rule sets RFC 5280, CA/B BR, hygiene).
2. Build/install (`cargo build`, binary name `mini-x509-lint`).
3. CLI surface: `<PATH>...`, `--format text|json`, `--source rfc5280,cabf_br,hygiene`,
   `--min-severity`, `--fail-on`, `--chain`, `--verbose`/`-v`. (Document `--from-host`/`--sni`/
   `--timeout` only as "added in the fetch feature" or leave a placeholder; that lands in
   feature 07.) Note that `--verbose` lists every lint (pass/n/a + `lint_id`) in text mode and is
   opt-in; default output stays terse.
4. Exit-code semantics: driven by `--fail-on` (0 = clean, non-zero = a finding at/above
   the threshold was surfaced). Show a CI / pre-commit usage example.
5. Example invocations with sample output (text + JSON, plus one `--verbose` text example showing
   the per-lint listing).
6. A note on the report-everything / no-short-circuit behaviour and severity meanings.

## Acceptance Criteria

- [ ] README documents every v1 flag, exit-code semantics, and at least two examples.
- [ ] Examples match the actual binary name and flag spellings.
- [ ] No broken/contradictory claims vs the implemented CLI.

## Notes / Dependencies

- Depends on task 02 so documented flags/exit codes match the final CLI. Feature 07 will
  extend the README with `--from-host`.
