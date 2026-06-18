---
agent: developer
seq: 3
title: README — document --from-host, SNI, fetch feature, verdict
status: done
touches:
  - README.md
depends_on:
  - 02-cli-from-host-wiring
---

# Task: README — document --from-host, SNI, fetch feature, verdict

## Goal

Extend the README (created in feature 06) to document the live-fetch capability.

## Files Owned (conflict scope)

- `README.md`

## Steps

Add a "Fetching from a host" section covering:
1. `--from-host <host[:port]>` (default port 443), `--sni <name>`, `--timeout <secs>`.
2. The `fetch` cargo feature: how to build with it
   (`cargo build -p cli --features fetch`) and that file linting works without it.
3. Mutual exclusivity of `<PATH>` and `--from-host`.
4. SNI rules: derived from a hostname by default; **required** for IP targets.
5. That only the **leaf** is linted; intermediates are displayed as chain context.
6. The verification verdict (`valid` / why it failed) shown alongside, and that it is
   distinct from lint findings.
7. A brief security note: the handshake uses an accept-any verifier solely to capture the
   presented chain (so untrusted/expired certs can still be inspected); the verdict is a
   separate, real verification pass.
8. `--save <path>` / `--force`: write the **full presented chain** (leaf + intermediates) to
   disk as a **PEM bundle**. Only valid with `--from-host` (error otherwise). Refuses to
   overwrite an existing file unless `--force`; parent directory must already exist. The saved
   bundle is **re-lintable** via the normal `<PATH>` input. Save happens regardless of the
   verification verdict; saving and linting are independent.
9. Example invocation(s) with sample output, including a `--from-host ... --save out.pem`
   example.

## Acceptance Criteria

- [ ] README documents all flags (`--from-host`, `--sni`, `--timeout`, `--save`, `--force`),
      the feature flag, SNI rules, mutual exclusion, and the verdict-vs-findings distinction.
- [ ] Documents `--save`/`--force`: PEM bundle of the full presented chain, only with
      `--from-host`, refuse-overwrite-without-`--force`, re-lintable via `<PATH>`.
- [ ] Includes at least one `--from-host` example and one `--save` example.
- [ ] Consistent with the implemented CLI behaviour.

## Notes / Dependencies

- Depends on task 02 so documentation matches behaviour.
