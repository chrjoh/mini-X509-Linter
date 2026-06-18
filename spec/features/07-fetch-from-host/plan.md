# Feature: Fetch Certificate From Host (`--from-host`)

## Overview

Add a new input source: fetch a certificate directly from a live host over a TLS handshake, instead
of reading a file. Only the leaf is linted; the intermediates the server presents are displayed and
the chain is verified, with the verdict shown alongside. This is plan.md Milestone 7. Fetching lives
in its own standalone crate so the `linter` crate stays network-free.

## Requirements

- New standalone crate `crates/fetch/` that performs a **blocking** TLS handshake (no async runtime —
  we must have the cert in hand before linting proceeds) and returns the presented chain plus a
  separate verification verdict. It does **not** depend on `linter`.
- CLI flags (per plan.md CLI surface):
  - `--from-host <host[:port]>` — fetch via TLS instead of reading a file (default port 443).
  - `--sni <name>` — override/supply the SNI.
  - `--timeout <secs>` — connection/handshake timeout (default 10).
  - `<PATH>...` and `--from-host` are **mutually exclusive** input sources.
  - `--save <path>` — **optional**: also write the fetched certificate(s) to disk. Only
    meaningful with `--from-host`; using `--save` without `--from-host` (i.e. with a `<PATH>`
    file input, or with no input) is an **error** with a clear message (saving a cert read
    from a file is pointless). (Considered alias: `--out <path>`; chose `--save` for clarity.)
  - `--force` — **optional**: allow `--save` to overwrite an existing file. Default policy is
    to **refuse to overwrite** an existing file unless `--force` is given (safer "look before
    you overwrite" default). (Considered alternative: plain overwrite with no `--force`; left
    for the user to confirm at the review gate.)
- Chain extraction **as presented**: capture the leaf + intermediates even if the cert is
  expired/self-signed/untrusted, using a custom verifier that records the certs and lets the
  handshake proceed. Document it with a `// SECURITY:` comment; keep it inside the `fetch` crate and
  never reuse it for anything but extraction. Gate the whole capability behind a `fetch` cargo feature.
- Chain **verification** still performed and **reported**: validate the presented chain against a
  root store (e.g. `webpki-roots`, or the OS trust store) and display the verdict (`valid` / why it
  failed) alongside the displayed chain. Leaf lint findings and the chain verdict are two distinct
  things in the output.
- **Only the leaf is linted** — the leaf flows into the same engine; intermediates are displayed as
  chain context, not linted.
- **SNI handling:**
  - Host is a hostname → derive SNI from it by default; `--sni` overrides.
  - Host is an IP address → SNI cannot be deduced; `--sni` is **required**, error clearly if missing.
- Host validation before connecting: enforce `host[:port]` shape, restrict to a sane port range, and
  (optionally, behind a flag) refuse private/loopback/link-local targets to limit SSRF-style misuse.
  Surface a clear generic error on connect/handshake/timeout failure.
- **Saving the fetched chain (`--save`):**
  - **What is saved:** the **full presented chain as captured** — leaf + intermediates, in
    presentation order — not just the leaf (most useful for archiving / diffing).
    (Considered alternative: leaf-only.)
  - **Format:** a **PEM bundle** — concatenated `-----BEGIN CERTIFICATE-----` blocks, one per
    cert in presentation order. PEM is the portable, openssl-friendly, multi-cert format, and
    the linter already auto-detects/reads multi-cert PEM, so a saved file can be **re-linted
    later** via the normal `<PATH>` input. (Considered alternative: DER — rejected because a
    single DER file cannot hold a multi-cert bundle.)
  - **Capture-as-presented:** the save happens **regardless of the verification verdict**
    (even expired/self-signed/untrusted chains), consistent with the existing fetch capture
    design. Saving and linting are **independent**: linting still proceeds normally and the
    save is a side effect.
  - **Overwrite policy:** refuse to overwrite an existing file unless `--force` is given (see
    `--force` above). The parent directory **must already exist** (we do not create it).
  - **IO / safety:** on any write failure surface a clear **generic** error (no internal
    detail leakage) and a **non-zero exit**. File permissions `0o644` are fine — certs are
    public, not secret; do not over-engineer this.
- This is the seam where future TLS-version / cipher-suite reporting plugs in (post-v1; out of scope
  here).

## Architecture

- `crates/fetch/` exposes something like `fetch_chain(target, sni, timeout) -> FetchedChain` where
  `FetchedChain` holds the DER-encoded leaf, the intermediates, and a `VerificationVerdict`.
- Blocking `rustls` over `std::net::TcpStream`; the custom accept-any verifier captures certs.
  Verification is a separate pass (real `WebPkiServerVerifier` + root store) so a bad cert still
  yields the chain plus a "why it failed" verdict.
- The CLI wires `fetch` → `linter`: take the leaf DER from `fetch`, build a `Cert`, run the registry;
  render the chain + verdict via the formatter from features 02/06.
- All `rustls`/network deps belong to `crates/fetch` and the CLI's `fetch` feature — never `linter`.

### Saving the presented chain (`--save`)

- **Pipeline order:** fetch → (if `--save`) write the chain to `<path>` → lint the leaf →
  render the chain + verdict + findings as today. The save sits **between** capture and lint,
  but does not gate linting: a save failure is its own error path, and a successful save does
  not alter the lint/render flow.
- **Where the PEM encoding lives:** the `fetch` crate returns DER; the DER→PEM encoding for
  `--save` lives in the **CLI** (it owns output), keeping `fetch` focused on the handshake.
  (Considered alternative: a small helper in `crates/fetch`; rejected to keep `fetch` lean.)
- **Encoding:** each captured DER cert is base64-encoded and wrapped in
  `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` at 64-char lines, concatenated
  in presentation order (leaf first). Reuse whatever base64/PEM facility already exists in the
  workspace; otherwise hand-roll the wrap (it is trivial — no new crate dependency expected).
- **Save-confirmation line:** optionally emit a deterministic confirmation (e.g.
  `saved presented chain to <path>`). Spec it as **stderr** (or otherwise outside any golden
  snapshot scope) so it never breaks a future stdout golden test.
- **Security:** `--save` writes attacker-influenced bytes (the remote presents the chain) to a
  **user-chosen** path — no path-traversal risk beyond what the user types. The content is
  exactly the captured DER re-encoded as PEM, with **no transformation**. Refuse-to-overwrite
  (`--force` to override) avoids clobbering an existing file by accident.

## Changes Overview

**crates/fetch/** (new)
- `Cargo.toml` — `rustls`, `rustls-pki-types`, `webpki-roots`.
- `src/lib.rs` — blocking handshake, accept-any capture verifier (`// SECURITY:`), separate
  verification pass, host parsing/validation, SNI derivation rules, timeout handling, error type.

**crates/cli/**
- `Cargo.toml` — add `fetch` (path) under a `fetch` feature; declare the feature.
- `src/main.rs` — `--from-host`, `--sni`, `--timeout`, `--save`, `--force`; enforce mutual
  exclusion with `<PATH>`; reject `--save`/`--force` when `--from-host` is absent; lint only
  the leaf; when `--save` is set, write the presented chain (after fetch, before/around lint)
  honoring the refuse-without-`--force` overwrite policy.
- `src/output.rs` (or a small `src/save.rs` writer) — render the presented chain and the
  verification verdict alongside lint findings; encode the captured DER chain as a PEM bundle
  and write it (0o644), plus the optional `saved presented chain to <path>` confirmation line
  (on stderr / outside golden scope).

**workspace root**
- `Cargo.toml` — add the `fetch` crate to workspace members.
- `README.md` — document `--from-host`, SNI rules, the `fetch` feature flag, the verification
  verdict in output, and `--save`/`--force` (PEM bundle of the full presented chain, only with
  `--from-host`, refuse-overwrite-without-`--force`, re-lintable via `<PATH>`).

## Dependencies

(In the `fetch` crate, behind the `fetch` feature.)

- `rustls = "0.23"`
- `rustls-pki-types = "1"`
- `webpki-roots = "1"` (or an OS-trust verifier alternative)

**No new dependency expected for `--save`.** PEM encoding is trivial base64 + line wrapping;
reuse whatever base64/PEM facility already exists in the workspace, otherwise hand-roll the
wrap. If a tiny encoder must be pulled, flag it at the review gate rather than adding it
silently.
