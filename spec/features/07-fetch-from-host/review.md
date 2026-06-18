# Completeness Review — Feature 07: Fetch Certificate From Host (`--from-host`) + `--save`

**Phase 5 — Mandatory Completeness Review (gate).**
**Reviewer:** architect
**Date:** 2026-06-18

## Top-Level Verdict: **COMPLETE**

Every plan requirement, every task `touches` file, and every acceptance criterion is
implemented in the real code and backed by passing tests. All seven quality gates pass;
`cargo audit` is clean. Architecture invariants (linter network-free, opt-in CLI feature,
ring provider, private fail-closed capture verifier) all hold. **No open gaps; no follow-up
tasks created.**

---

## 1. Per-Requirement Verification (from `plan.md`)

| # | Requirement | Status | Evidence |
|---|-------------|--------|----------|
| R1 | New standalone `crates/fetch/`, blocking handshake, returns chain + separate verdict, does **not** depend on `linter` | **PASS** | `crates/fetch/Cargo.toml` deps = rustls/rustls-pki-types/webpki-roots/thiserror only (no `linter`). `fetch_chain` is blocking over `std::net::TcpStream` (`lib.rs:325-378`, `338` `connect_timeout`, `409` `drive_handshake`). |
| R2 | `--from-host <host[:port]>` (default 443) | **PASS** | `main.rs:152-154` flag; `DEFAULT_PORT=443` (`lib.rs:38`), applied in `split_host_port` (`lib.rs:204,229`). |
| R3 | `--sni <name>` override/supply | **PASS** | `main.rs:159-161`; `resolve_sni` override logic `lib.rs:263-272`. |
| R4 | `--timeout <secs>` (default 10) | **PASS** | `main.rs:164-166` `default_value_t = 10`; applied to connect (`lib.rs:338`) and read/write (`lib.rs:346-348`). |
| R5 | `<PATH>` and `--from-host` mutually exclusive | **PASS** | `run_from_host` rejects both (`main.rs:538-540`); test `save.rs` covers no-input/file-input error paths; CLI smoke verified. |
| R6 | `--save <path>` optional; error if used without `--from-host` | **PASS** | `main.rs:366-368` bail "`--save is only valid with --from-host`"; tests `no_server_needed::save_without_from_host_errors`, `save_with_no_input_at_all_errors`. |
| R7 | `--force` optional; error if without `--save` | **PASS** | `main.rs:369-371` (no `--from-host`) and `main.rs:542-544` (`--force` w/o `--save`); test `force_without_from_host_errors`. |
| R8 | Chain captured as presented even if untrusted/expired/self-signed; documented `// SECURITY:`; private; never reused | **PASS** | Private `mod capture` → `pub(crate) struct CaptureVerifier` (`lib.rs:558`), not exported. 4× `// SECURITY:` notes (`lib.rs`). Capture proven independent of verdict: `handshake.rs::verdict_is_invalid_for_untrusted_self_signed`. |
| R9 | Gate capability behind a `fetch` cargo feature | **PASS** | CLI `fetch = ["dep:fetch"]`, dep `optional = true` (`crates/cli/Cargo.toml`); all `--from-host`/save code `#[cfg(feature = "fetch")]`. `cargo tree -p cli` (default) shows **no** rustls/fetch/ring/webpki. |
| R10 | Separate real verification pass + verdict reported | **PASS** | `verify_chain` uses real `WebPkiServerVerifier` + `webpki_roots::TLS_SERVER_ROOTS` (`lib.rs:449-484`), distinct from capture. Rendered as `verification: ...` (`output.rs:496-508`) / JSON `verification` key (`output.rs:512-539`). |
| R11 | Only the leaf is linted; intermediates displayed as context | **PASS** | `Cert::from_der(&chain.leaf_der)` then `registry.run_filtered(&leaf, ...)` (`main.rs:589-595`); intermediates only feed `build_chain_entries` display (`main.rs:597-598, 636-654`). |
| R12 | SNI: hostname derives by default; IP requires `--sni` (clear error) | **PASS** | `resolve_sni` (`lib.rs:263-272`): `Ip + None → SniRequiredForIp`. CLI pre-checks (`main.rs:556-560`). Tests `sni_rules::*`, `handshake::ip_target_without_sni_errors_before_connecting`. |
| R13 | Host validation: shape, sane port range; optional SSRF guard; generic connect/handshake/timeout errors | **PASS** | `Target::parse`/`split_host_port`/`parse_port` (port 1..=65535, reject 0) `lib.rs:158-243`; `is_blocked_address` + `--block-private` (`lib.rs:276-301`, `main.rs:171-173,565`). All `FetchError` messages generic (`lib.rs:45-94`, test `error_messages`). |
| R14 | Save = full presented chain (leaf + intermediates, presentation order) | **PASS** | `save_chain(path, leaf_der, intermediates_der, force)` → `encode_chain_pem` leaf-first (`save.rs:80-86, 104`). Test `encode_chain_pem::round_trips_leaf_and_intermediates_in_order`. |
| R15 | Format = PEM bundle, concatenated BEGIN/END blocks, re-lintable via `<PATH>` | **PASS** | `der_to_pem_block` (`save.rs:65-76`). Round-trip CLI test `server_backed::save_writes_pem_bundle_and_round_trips` asserts identical leaf findings on re-lint. |
| R16 | Capture-as-presented: save regardless of verdict; save & lint independent | **PASS** | Save sits before lint, ungated by verdict (`main.rs:577-586`); lint always proceeds. Test `save_happens_regardless_of_invalid_verdict`. |
| R17 | Overwrite policy: refuse unless `--force`; parent dir must already exist | **PASS** | `save.rs:110-127`; tests `refuses_to_overwrite_without_force`, `overwrites_with_force`, `errors_when_parent_directory_missing`; CLI `refuses_overwrite_without_force_then_succeeds_with_force`. |
| R18 | IO safety: generic error + non-zero exit on write failure; `0o644` | **PASS** | Generic `anyhow` errors (`save.rs:111,123,131`), `main` exits FAILURE (`main.rs:327-332`); `0o644` set (`save.rs:134-139`), test `sets_0o644_permissions`; CLI `write_to_missing_parent_dir_is_generic_error_nonzero` asserts non-zero + no `panicked`. |
| R19 | README documents the full surface | **PASS** | README §Fetching from a host + flag table (lines 85-90, 352-475): all flags, feature flag, SNI rules, mutual exclusion, verdict-vs-findings, security note, `--save`/`--force`, examples. |
| Dep | `rustls 0.23`, `rustls-pki-types 1`, `webpki-roots 1`; **no new dep for `--save`** | **PASS** | Versions match `crates/fetch/Cargo.toml`. PEM base64 hand-rolled in `save.rs` (RFC4648, no new crate); CLI dep tree adds nothing for save. thiserror bumped to `2` (workspace convention). |

---

## 2. Per-Task `touches` + Acceptance-Criteria Verification

### Task 01 — Standalone fetch crate (status: done)

**Touches:** `crates/fetch/Cargo.toml` ✓, `crates/fetch/src/lib.rs` ✓, root `Cargo.toml` ✓ (members include `crates/fetch`).

| AC | Status | Evidence |
|----|--------|----------|
| Builds standalone, no `linter` dep | **PASS** | `cargo test -p fetch` builds clean; manifest has no `linter`. |
| `fetch_chain` returns leaf + intermediates + verdict; bad cert still yields chain + `Invalid` | **PASS** | `FetchedChain` struct (`lib.rs:117-124`); `handshake.rs` capture+Invalid tests. |
| Accept-any verifier private, `// SECURITY:`, capture-only | **PASS** | `pub(crate)` in private `mod capture` (`lib.rs:536-558`); `// SECURITY:` ×4. |
| Host validation + SSRF guard + SNI rules; generic errors | **PASS** | See R12/R13; 29 in-crate unit tests pass. |
| Timeout on connect + handshake | **PASS** | `lib.rs:338,346-348`; `timeout::refused_connection_returns_within_budget`. |
| Clippy clean | **PASS** | `cargo clippy --all-targets` exit 0. |

### Task 02 — CLI wiring + chain/verdict render + `--save` (status: done)

**Touches:** `crates/cli/Cargo.toml` ✓, `crates/cli/src/main.rs` ✓, `crates/cli/src/output.rs` ✓, `crates/cli/src/save.rs` ✓ (new). Does **not** touch root `Cargo.toml` ✓.

| AC | Status | Evidence |
|----|--------|----------|
| `--from-host` (feature on) fetches, lints leaf, prints chain + verdict + findings | **PASS** | `run_from_host` (`main.rs:526-629`); test `fetch_lints_leaf_and_prints_verdict`. |
| `<PATH>` / `--from-host` mutually exclusive, clear error | **PASS** | `main.rs:538-540`. |
| IP without `--sni` → error; hostname derives SNI | **PASS** | `main.rs:556-560`. |
| Built w/o `fetch`, `--from-host` errors clearly; file linting works | **PASS** | Flags `#[cfg(feature="fetch")]`; `load_input_certs` no-fetch branch message "rebuild with --features fetch" (`main.rs:687-692`); default `cargo test` (no fetch in cli) passes. |
| Verdict vs findings visibly distinct, text + JSON | **PASS** | Text `presented chain:`/`verification:` block before findings (`output.rs:496-508`); JSON top-level `presented_chain`/`verification`/`outcomes` keys (`main.rs:615-620`); tests `chain_section::*`. |
| `--save` writes full chain PEM bundle, re-lints; linting still proceeds | **PASS** | `save_writes_pem_bundle_and_round_trips`. |
| `--save`/`--force` without `--from-host` errors | **PASS** | `main.rs:366-371`; tests `no_server_needed::*`. |
| Refuse overwrite w/o `--force`; with `--force` overwrites; missing parent/write failure → generic + non-zero; `0o644` | **PASS** | `refuses_overwrite_without_force_then_succeeds_with_force`, `write_to_missing_parent_dir_is_generic_error_nonzero`, `sets_0o644_permissions`. |
| Save regardless of verdict | **PASS** | `save_happens_regardless_of_invalid_verdict`. |
| `clippy --all-targets --features fetch` clean | **PASS** | `cargo clippy --all-targets -p cli --features fetch -- -D warnings` exit 0. |

### Task 03 — README (status: done)

**Touches:** `README.md` ✓.

| AC | Status | Evidence |
|----|--------|----------|
| Documents all flags, feature flag, SNI rules, mutual exclusion, verdict-vs-findings | **PASS** | README flag table 85-90; §372-413. |
| Documents `--save`/`--force`: PEM bundle, only with `--from-host`, refuse-overwrite, re-lintable | **PASS** | README §414-432. |
| ≥1 `--from-host` example and ≥1 `--save` example | **PASS** | §391-411 (from-host), §432-465 (save + force). |
| Consistent with implemented behaviour | **PASS** | Stderr confirmation, `verification: invalid: <reason>`, `--block-private` all match code. Stale "3 sources" corrected to **7 sources / 66 lints** (README:131). |

### Task 04 — Hermetic tests + `--save` coverage (status: done)

**Touches:** `crates/fetch/Cargo.toml` (dev-deps) ✓ (`rcgen` ring-only), `crates/fetch/tests/handshake.rs` ✓, `crates/fetch/tests/validation.rs` ✓, `crates/cli/tests/save.rs` ✓ (new).

| AC | Status | Evidence |
|----|--------|----------|
| Handshake test fully offline vs local rustls server; captured leaf matches served cert | **PASS** | `handshake.rs` rcgen+rustls in-process ephemeral 127.0.0.1; `captures_self_signed_leaf_der`. |
| Verdict `Invalid` for untrusted self-signed while chain captured | **PASS** | `verdict_is_invalid_for_untrusted_self_signed`. |
| Validation: host shape, port range, SNI rules, SSRF guard | **PASS** | `validation.rs` 14 tests pass. |
| `--save` writes re-lintable full-chain bundle; round-trip same findings | **PASS** | `save_writes_pem_bundle_and_round_trips`. |
| `--save`/`--force` w/o `--from-host` errors; overwrite policy; missing-parent generic + non-zero; save regardless of verdict | **PASS** | `save.rs` 8 tests pass (openssl present — server-backed ran, did not skip). |
| All verification commands pass; no network | **PASS** | See §3. CLI save tests use local `openssl s_server`; fetch tests use in-process rustls. Hermetic. |

---

## 3. Quality Gate Results

| Gate | Result |
|------|--------|
| `cargo fmt --check` | **PASS** (exit 0) |
| `cargo clippy --all-targets -- -D warnings` | **PASS** (exit 0) |
| `cargo clippy --all-targets -p cli --features fetch -- -D warnings` | **PASS** (exit 0) |
| `cargo test` (full workspace, default) | **PASS** — all suites green incl. linter (39) + fetch crate; 0 failed |
| `cargo test -p fetch` | **PASS** — unit 29, handshake 6, validation 14; 0 failed |
| `cargo test -p cli --features fetch` | **PASS** — output 20, purpose 15, save 8 (5 server-backed ran); 0 failed |
| `cargo audit` | **PASS** — 122 deps scanned, 0 vulnerabilities, 0 warnings (exit 0) |

---

## 4. Architecture-Invariant Confirmations

- **linter is network-free:** `crates/linter/Cargo.toml` has no rustls/webpki/ring; deps are
  x509-parser/der/oid-registry/thiserror/serde(opt). **CONFIRMED.**
- **Default `cli` build has no rustls/fetch:** `cargo tree -p cli` (default) returns none of
  rustls/fetch/ring/webpki. `fetch` dep is `optional` behind `fetch = ["dep:fetch"]`.
  **CONFIRMED.**
- **rustls uses `ring` (no aws-lc/cmake):** `crates/fetch/Cargo.toml` rustls with
  `default-features=false, features=["ring","std","tls12"]`; `Cargo.lock` contains `ring`,
  `rustls`, `webpki-roots`, `rcgen` and **no** `aws-lc-rs` / `aws-lc-sys` / `cmake`.
  **CONFIRMED.**
- **Capture verifier private + `// SECURITY:` + fail-closed verdict:** `CaptureVerifier` is
  `pub(crate)` inside a private `mod capture`, never re-exported; 4× `// SECURITY:` notes;
  `verify_chain` is fail-closed (any builder/verify error → `Invalid { reason }`, `lib.rs:449-484`).
  **CONFIRMED.**

---

## 5. Spec Artifacts

| Artifact | Present | Note |
|----------|---------|------|
| `plan.md` | ✓ | Requirements + Changes Overview incl. `--save`. |
| `test-plan.md` | ✓ | Scope, crate + CLI + `--save` coverage. |
| `tasks/01-fetch-crate.md` | ✓ | status: done. |
| `tasks/02-cli-from-host-wiring.md` | ✓ | status: done. |
| `tasks/03-readme-from-host.md` | ✓ | status: done. |
| `tasks/04-fetch-tests-local-server.md` | ✓ | status: done. |
| `design.md` | N/A | Correctly absent — CLI/library feature, no UI design surface. |
| `ui-test-report.md` | N/A | Correctly absent — no UI. |

---

## 6. cargo audit Summary

`Scanning Cargo.lock for vulnerabilities (122 crate dependencies)` → **0 vulnerabilities,
0 warnings, exit 0.** Network deps added by this feature (rustls/ring/webpki-roots/rcgen)
introduce no advisories. The `ring` provider choice keeps the C/cmake `aws-lc-sys` toolchain
out of the tree.

---

## 7. Open Gaps & Follow-Ups

**None.** All criteria PASS. No PARTIAL/FAIL items; no follow-up task files created.

**Gate decision: COMPLETE — feature 07 is DONE.**
