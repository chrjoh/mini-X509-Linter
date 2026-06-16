# Mini X.509 Linter — Project Plan

A from-scratch X.509 certificate linter in Rust, inspired by [zlint](https://github.com/zmap/zlint).
Given a certificate (or a chain), it runs a set of independent checks and reports
findings as `pass` / `notice` / `warn` / `error` / `fatal`, grouped by the rule set
they belong to.

## Goals

- Learn the guts of X.509 / PKI by encoding the rules, not just consuming a cert library.
- Produce a genuinely useful CLI you can point at a `.pem`/`.der` and get a verdict.
- Keep the lint engine reusable as a library so the CLI is a thin shell over it.

## Non-goals (for v1)

- Building/validating full chains against a trust store as a general lint over arbitrary file inputs
  (that's a separate tool — keep a hook for it).
  - Exception: for `--from-host`, we *do* verify the chain the server presents and display the
    verdict (see below). This is a display-only check tied to the live connection, not a lint, and
    not offered for file inputs in v1.
- Revocation network fetching (OCSP/CRL/AIA). Parse and check what's in the cert; defer revocation.
  - Note: fetching a cert *from a host* over a TLS handshake (see below) is in scope — it's input
    acquisition, not revocation checking. The two are kept separate.
- Being bug-for-bug compatible with zlint. Borrow its structure and naming ideas, not its code.

## Approach decisions

- **Parsing:** build on `x509-parser` + `der` rather than hand-rolling DER. Focus effort on lint
  rules, not ASN.1 decoding. (Leave room to swap in a custom parser later if curiosity strikes.)
- **Rule sets targeted first:** RFC 5280, CA/Browser Forum Baseline Requirements (BR), and a
  crypto-hygiene set (weak algos/keys).
- **Shape:** a `linter` library crate + a thin `mini-zlint` CLI binary (cargo workspace), plus a
  small standalone `fetch` crate for TLS retrieval (kept separate so the linter stays network-free).
- **Inputs:** in addition to local `.pem`/`.der` files, support fetching the certificate directly
  from a live host over a TLS handshake (`--from-host host:port`). Only the **leaf** is linted; the
  intermediates the server presents are displayed (so the user sees the full response) and the chain
  is verified, with the verdict shown alongside. Fetching is purely an input source and stays
  decoupled from the lint rules — it lives in its own crate.
- **Synchronous fetch:** the handshake is a single blocking step (we must have the cert in hand
  before linting can proceed), so use blocking `rustls` over `std::net::TcpStream` — no async runtime.

## Crate layout

```
mini-zlint/
├── Cargo.toml            # workspace
├── plan.md
├── crates/
│   ├── linter/           # library: parsing facade + lint engine + rules (no network)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── cert.rs        # thin wrapper over x509-parser's parsed cert
│   │   │   ├── finding.rs     # Severity, Finding, LintResult types
│   │   │   ├── registry.rs    # collects all lints, runs them, filters by source
│   │   │   ├── source.rs      # RuleSource enum: Rfc5280, CabfBr, Hygiene
│   │   │   └── lints/
│   │   │       ├── mod.rs
│   │   │       ├── rfc5280/   # one file per lint (or small grouped files)
│   │   │       ├── cabf_br/
│   │   │       └── hygiene/
│   │   └── Cargo.toml
│   ├── fetch/            # small standalone crate: TLS handshake → presented chain + verify verdict
│   │   ├── src/lib.rs        # blocking rustls; no dependency on `linter`
│   │   └── Cargo.toml
│   └── cli/              # binary: arg parsing, input loading, output formatting
│       ├── src/main.rs       # wires `fetch` → `linter`; depends on both
│       └── Cargo.toml
└── testdata/             # sample certs: good, and one-bad-thing-each
```

## Core types (the contract every lint codes against)

```rust
// A Finding always describes a real problem, so there's no `Pass` variant —
// "passed" is represented by an empty `Vec<Finding>`.
pub enum Severity { Notice, Warn, Error, Fatal }

pub enum RuleSource { Rfc5280, CabfBr, Hygiene }

pub enum Applicability { Applies, NotApplicable } // e.g. a CA-only lint on a leaf

/// One specific problem a lint found. A single lint may return several.
pub struct Finding {
    pub severity: Severity,   // how bad THIS problem is
    pub message: String,      // human-readable detail of THIS problem
}

/// What the engine records per lint (it attaches id/source/applicability).
pub struct LintOutcome {
    pub lint_id: &'static str,        // e.g. "rfc5280_subject_empty_san_required"
    pub source: RuleSource,
    pub applicability: Applicability,
    pub findings: Vec<Finding>,       // empty + Applies => the lint passed
}

/// Every lint implements this. Engine handles applicability + result collection.
pub trait Lint {
    fn id(&self) -> &'static str;
    fn source(&self) -> RuleSource;
    fn applies(&self, c: &Cert) -> Applicability;
    /// Return EVERY problem found; empty `Vec` means pass. The engine only calls
    /// this when `applies()` == `Applies`, and annotates each result with id/source.
    fn check(&self, c: &Cert) -> Vec<Finding>;
}
```

Design notes:
- `applies()` lets each lint declare its scope (CA vs leaf, has-extension, etc.) so the engine
  can report `NotApplicable` instead of forcing every lint to special-case it.
- Lints are registered in `registry.rs` (a simple `Vec<Box<dyn Lint>>` to start; can move to
  `inventory`/linkme later for auto-registration if the list grows).
- Filtering by `RuleSource` lets the CLI do `--source rfc5280,hygiene`.
- **Report everything, never short-circuit.** The engine runs *every* applicable lint and collects
  *all* findings — a failure in one lint never stops the others. Because `check()` returns
  `Vec<Finding>`, a single rule can also report several distinct problems at once (e.g. KeyUsage
  wrong *and* BasicConstraints missing), each with its own severity and message. The report lists
  every finding so the user sees the complete picture, not just the first problem.

## CLI surface (v1)

```
mini-zlint <PATH>... [options]

  --format text|json        default: text
  --source <list>           comma-sep: rfc5280,cabf_br,hygiene (default: all)
  --min-severity <level>    only show findings at/above this (default: notice)
  --fail-on <level>         exit non-zero if any finding >= level (default: error)
  --chain                   treat multiple inputs / a bundle as a chain (parse each separately for now)
  --from-host <host[:port]> fetch the cert via a TLS handshake instead of reading a file
                            (default port 443; --sni <name> to override the SNI)
  --timeout <secs>          connection/handshake timeout for --from-host (default: 10)
```

Input handling: auto-detect PEM vs DER; a PEM file may contain multiple certs. `<PATH>...` and
`--from-host` are mutually-exclusive input sources. File inputs yield a list of certs; a host yields
the full chain the server presents. **Only the leaf is ever linted** — for a host that's the
server's end-entity cert; for a file that's the first cert. Any remaining certs are treated as chain
context (displayed, not linted).
Exit code driven by `--fail-on` so it's usable in CI / pre-commit hooks.

### Fetching from a host (`--from-host`)

- Open a TCP connection and perform a **blocking** TLS handshake (no async runtime — we wait for the
  cert before doing anything else). Capture the leaf + any intermediates the server sends.
- We want the chain *as presented* even if it's expired/self-signed/untrusted, so the handshake uses
  a custom verifier that records the presented certs and lets the handshake proceed regardless. This
  is a deliberate, scoped exception to "always verify" — document it with a `// SECURITY:` comment,
  keep it inside the `fetch` crate, and never reuse it for anything but chain extraction.
- **Chain verification is still performed and reported.** Separately from extraction, validate the
  presented chain against a root store (e.g. `webpki-roots`, or the OS trust store) and display the
  verdict (`valid` / why it failed) alongside the displayed chain. The leaf's lint findings and the
  chain's verification verdict are two distinct things in the output.
- **SNI handling:**
  - If the host is a **hostname**, derive SNI from it by default; `--sni <name>` overrides.
  - If the host is an **IP address**, SNI cannot be deduced — `--sni <name>` is **required**; error
    out with a clear message if it's missing.
- Validate the user-supplied host before connecting: enforce `host[:port]` shape (default port 443),
  restrict to a sane port range, and (optionally) refuse private/loopback/link-local targets behind a
  flag to keep the tool from being pointed at internal infra (SSRF-style misuse). Surface a clear
  generic error on connect/handshake/timeout failure.
- This is the seam where the future TLS-version / cipher-suite reporting plugs in (see stretch ideas).

## Initial lint backlog

Start with ~3 per source to prove the engine end-to-end, then expand.

**RFC 5280**
- `version_is_v3` — extensions present ⇒ version must be v3.
- `serial_number_positive` — serial must be a positive integer, ≤ 20 octets.
- `validity_not_after_after_not_before` — notAfter must be later than notBefore.
- `basic_constraints_critical_on_ca` — CA certs must mark BasicConstraints critical.
- `key_usage_present_when_ca` — CA certs must have keyCertSign in KeyUsage.
- `san_present_if_subject_empty` — empty subject DN ⇒ SAN must exist and be critical.

**CA/B Forum BR**
- `validity_max_398_days` — leaf TLS certs ≤ 398 days.
- `cn_in_san` — any subject CN value must also appear in SAN.
- `no_internal_names_or_reserved_ip` — reject internal/reserved names in SAN.
- `ext_key_usage_server_auth_present` — TLS leaf should have serverAuth EKU.

**Crypto hygiene**
- `no_sha1_signature` — flag SHA-1 in the signature algorithm.
- `rsa_key_min_2048` — RSA modulus ≥ 2048 bits.
- `ecdsa_curve_allowlist` — restrict to P-256/P-384/P-521.
- `not_expired` — informational: notice/warn if already expired.

## Milestones

1. **Skeleton compiles.** Workspace, types, a single trivial lint (`not_expired`), and a CLI
   that loads a PEM and prints one finding. End-to-end pipe working.
2. **Engine + registry.** Trait, registry, applicability, `--source` and `--min-severity`
   filtering. JSON output via `serde`.
3. **RFC 5280 set.** Implement the listed lints, each with a fixture cert in `testdata/`.
4. **Hygiene set.** Signature-algo and key-strength checks (touches SPKI parsing).
5. **CA/B BR set.** The web-PKI specific rules; this is where most ambiguity lives — keep
   each lint small and well-commented with the BR section number.
6. **Polish.** `--fail-on` exit codes, nice text formatter (counts by severity), README,
   and a golden-file test that runs all lints over `testdata/` and snapshots the output.
7. **Fetch from host.** Standalone `fetch` crate: blocking TLS handshake → extract presented chain
   (accept-any verifier) + verify chain against a root store for a separate verdict. CLI wires it in:
   lint only the leaf, display the full chain and the verification verdict. SNI rules (derive from
   hostname; required for IPs), host validation, timeouts, generic error handling. Test against a
   local TLS server fixture (a `rustls` server with a known cert) so it's hermetic and offline in CI.

## Dependencies (starting set)

```toml
x509-parser = "0.18"   # cert + extension parsing
der          = "0.8"   # low-level DER when x509-parser doesn't expose something
oid-registry = "0.8"   # human-readable OIDs (pairs with x509-parser)
clap         = { version = "4", features = ["derive"] }
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
anyhow       = "1"     # CLI-level error handling
thiserror    = "1"     # library error types

# --from-host — lives in the standalone `fetch` crate (blocking, no async runtime)
rustls          = "0.23"  # blocking TLS handshake over std::net::TcpStream
rustls-pki-types = "1"    # CertificateDer and friends
webpki-roots    = "1"     # root store for chain verification (or swap for an OS-trust verifier)
```
*(Pin to whatever is current when you start — check crates.io.)*

## Testing strategy

- One fixture cert per lint under `testdata/`, named after the lint, that violates exactly
  that rule (plus a `good.pem` that should pass everything). Generate them with `openssl` or
  `rcgen` and commit a small script that regenerates them.
- Unit test per lint: load fixture, assert the expected `Severity`.
- Integration/golden test: run the full registry over `testdata/`, snapshot JSON output.

## Stretch ideas (post-v1)

- Auto-registration of lints (`inventory`/`linkme`) so adding a file is enough.
- A `--list-lints` command that prints id/source/description.
- Chain-aware lints (path length, name constraints) once single-cert lints are solid.
- Swap `x509-parser` for a hand-rolled DER parser behind the same `Cert` facade — the original
  learning goal, made safe by the existing test suite.
- Revocation: parse CRLDP/AIA and (optionally, behind a flag) fetch + check.

### Host-connection reporting (post `--from-host`)

Once `--from-host` lands, extend the handshake to report on the *connection* itself, not just the
cert. These are properties of the live endpoint, so they live alongside the fetch code and surface
as their own report section (or a new `RuleSource`/lint category for TLS-config hygiene):

- **Negotiated/supported TLS versions.** Report the version negotiated, and (stretch) probe which
  versions the host accepts by attempting handshakes pinned to each (TLS 1.0–1.3). Flag deprecated
  versions (1.0/1.1) as a finding.
- **Cipher suites** *(future requirement — can slip to a later version).* Report the negotiated
  suite and, ideally, enumerate the host's accepted suites; flag weak/legacy suites (RC4, 3DES,
  non-AEAD, export). Enumeration likely needs lower-level control than `rustls` exposes by default,
  so this may want a dedicated probe path — scope it when we get there.
