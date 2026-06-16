---
agent: developer
seq: 3
title: README — document --from-host, SNI, fetch feature, verdict
status: pending
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
8. Example invocation(s) with sample output.

## Acceptance Criteria

- [ ] README documents all three flags, the feature flag, SNI rules, mutual exclusion, and
      the verdict-vs-findings distinction.
- [ ] Includes at least one `--from-host` example.
- [ ] Consistent with the implemented CLI behaviour.

## Notes / Dependencies

- Depends on task 02 so documentation matches behaviour.
