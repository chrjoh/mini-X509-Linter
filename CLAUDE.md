# mini-X509-Linter

A from-scratch X.509 certificate linter in Rust (inspired by zlint). A cargo workspace with a
`linter` library crate, a standalone `fetch` crate (TLS retrieval), and a `mini-zlint` CLI binary.
See `plan.md` for the full project plan. No UI.

- Build/test: `cargo test`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format check: `cargo fmt --check`
- security check added libs with: `cargo audit`

## Multi-Agent Workflow

This project supports a multi-agent workflow with specialized roles:

| Agent | Role | Outputs |
|-------|------|---------|
| **architect** | Plans features, creates specs and task files, delegates and coordinates | `spec/features/XX/plan.md`, `spec/features/XX/tasks/` |
| **developer** | Implements code and unit tests | `crates/*/src/`, `tests/` |
| **tester** | Creates test plans, writes integration tests, verifies | `spec/features/XX/test-plan.md`, `tests/` |

### Usage

Invoke individual agents:
```
@architect Plan a feature for: <description>
@developer Implement the feature from spec/features/XX-name/plan.md
@tester Write tests for spec/features/XX-name/plan.md
```

Run the full orchestrated workflow:
```
/orchestrate-workflow <feature description>
```

### How It Works

1. **Architect** reads requirements, researches the codebase, creates a spec (`plan.md`) and task files (`tasks/`)
2. **Developer** and **Tester** are dispatched in conflict-free batches per task files
3. **Architect** reviews integration and resolves conflicts
4. **Tester** runs final verification

### Agent Configuration

- Agent definitions: `.claude/agents/<role>/SKILL.md`
- Workflow skill: `.claude/skills/orchestrate-workflow/SKILL.md`
- Coding standards: `.claude/rules/`
- Feature specs: `spec/features/XX-name/plan.md`
- Task files: `spec/features/XX-name/tasks/`
- Test plans: `spec/features/XX-name/test-plan.md`
