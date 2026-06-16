# Test Plan: Fetch Certificate From Host (`--from-host`)

## Scope

Verify the standalone `fetch` crate: blocking handshake, accept-any chain capture, a
separate verification verdict, host validation, SNI rules, timeout handling, and the CLI
wiring (mutual exclusion, leaf-only linting, chain + verdict rendering). All tests are
hermetic (offline) using a local `rustls` server fixture.

## Conventions

Per `.claude/rules/rust-testing-core.md`: SIFER, `.unwrap()`/`.unwrap_err()`. Per
`.claude/rules/rust-secure-coding.md` + OWASP A04: the accept-any verifier is the only
deliberate bypass, scoped to capture; verification is a separate real pass and fails closed.

## Crate Tests (`crates/fetch/tests/`)

### handshake.rs (local rustls server, ephemeral 127.0.0.1 port)
- Captured `leaf_der` matches the served cert.
- Verdict is `Invalid { reason }` for an untrusted self-signed test cert — chain still
  captured (capture succeeds independent of verification).
- Intermediates captured when the server presents them.

### validation.rs
- Host shape: `host`, `host:443`, `host:8443` accepted; port 0 / out-of-range / malformed
  rejected with the correct `FetchError`.
- SNI: IP target without `--sni` → error; hostname derives SNI by default; `--sni`
  overrides.
- SSRF guard: enabled → loopback/private refused; disabled → allowed.
- Timeout applies to connect + handshake (kept deterministic/fast).

## CLI Tests (optional smoke, reuse local server)

- `<PATH>` and `--from-host` mutually exclusive → clear error if both/neither.
- `--from-host` (feature on) lints the leaf only; renders chain context + verdict distinct
  from findings, in text and JSON.
- Built without the `fetch` feature → `--from-host` errors clearly; file linting unaffected.

## Edge Cases

- Self-signed / expired / untrusted server cert → chain captured, verdict explains failure.
- IP literal host, both with and without `--sni`.
- Connection refused / unreachable → clear generic error, no panic/stack trace.
- Server presenting only a leaf (no intermediates).

## Verification Commands

```
cargo test -p fetch
cargo test --features fetch
cargo clippy --all-targets --features fetch -- -D warnings
cargo fmt --check
cargo audit            # network deps added — check advisories
```

## Exit Criteria

`fetch` crate is offline-testable; capture works regardless of verdict; verdict is a real
separate pass that fails closed; CLI wiring (mutual exclusion, leaf-only, distinct verdict)
verified; all verification commands pass with no network access.
