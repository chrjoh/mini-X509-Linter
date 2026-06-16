# Test Plan: Lint Engine, Registry & Output

## Scope

Verify the registry runs every applicable lint without short-circuiting, records
`NotApplicable` without calling `check`, filters by `RuleSource`, applies `--min-severity`
at the reporting boundary, and renders both text (grouped by source) and nested JSON.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()` over
`assert!(is_ok/err)`, behaviour-focused tests grouped in nested `mod`s.

## Unit / Integration Tests

### Engine (`crates/linter/tests/registry.rs`)
- Every lint considered yields exactly one `LintOutcome` with correct `applicability`.
- A lint that panics in `check()` but reports `NotApplicable` must NOT panic — proves the
  applies-gate.
- No short-circuit: multiple finding-producing lints all surface their outcomes.
- `run_filtered` with one `RuleSource` excludes lints of other sources from execution.

### Output (`crates/cli/tests/output.rs`)
- `render_text` groups by `RuleSource` in deterministic, sorted order; `NotApplicable`
  lints summarized, not noisy.
- `render_json` produces the nested shape: one object per outcome carrying `lint_id`,
  `source`, `applicability`, and its own `findings` array. Source tokens are snake_case
  (`rfc5280`, `cabf_br`, `hygiene`).
- `--min-severity warn` removes `notice` findings in both renderers while leaving raw
  outcomes intact.

## Edge Cases

- Empty `Vec<LintOutcome>` renders cleanly (text + JSON).
- All lints `NotApplicable` → text shows a compact summary, JSON shows empty findings.
- Unknown `--source` / `--format` / `--min-severity` token → clear CLI error, no panic.
- `--source` with duplicate tokens handled gracefully.

## Verification Commands

```
cargo test
cargo build -p linter            # no serde
cargo build -p linter --features serde
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Exit Criteria

No-short-circuit and applies-gate proven by tests; JSON nested shape confirmed; filtering
correct; all verification commands pass.
