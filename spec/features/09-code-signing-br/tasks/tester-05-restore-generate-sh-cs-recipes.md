---
agent: tester
seq: 5
title: Restore the code-signing fixture recipes in generate.sh (lost to churn-cleanup)
status: done
touches:
  - testdata/generate.sh
depends_on:
  - tester-04-fixtures-and-tests
---

# Task: Restore the code-signing fixture recipes in testdata/generate.sh

## Goal

The 8 `testdata/cabf_cs_*.pem` fixtures are committed, but `testdata/generate.sh` contains ZERO
code-signing content — the recipe block added in task 04 was wiped when the churn-cleanup step ran
`git checkout testdata/` (which reverted `generate.sh` along with the re-rolled `.pem` keys). The CS
fixtures have a HARD 2027 expiry (time-fragility, documented in `crates/linter/tests/cabf_cs.rs`), so
there must be a runnable recipe to regenerate them. Add it back.

## Files Owned (conflict scope)

- `testdata/generate.sh` ONLY. Do NOT modify any `.pem` (the 8 CS fixtures are already committed and
  must stay byte-stable) or any other file.

## What to Do

1. Add a code-signing section to `generate.sh` (follow the existing style/structure of the feature-12
   and cabf_br sections) that regenerates all 8 CS fixtures:
   - A code-signing leaf-extension config: `extendedKeyUsage = codeSigning`,
     `keyUsage = digitalSignature` (critical as appropriate), `basicConstraints = CA:FALSE`,
     `subjectKeyIdentifier = hash`, non-empty CN, NO SAN. Default key RSA-3072 / SHA-256.
   - A CS-OK window constant (currently valid, ≤460d, straddles now): `2026-06-01 → 2027-06-01` (365d).
   - The 8 recipes, matching the committed fixtures' shapes:
     - `cabf_cs_good.pem` — RSA-3072, critical digitalSignature KU, AIA + CRL-DP present, CS_OK window.
     - `cabf_cs_missing_key_usage.pem` — KU asserts only keyEncipherment (no digitalSignature).
     - `cabf_cs_rsa_2048.pem` — RSA-2048.
     - `cabf_cs_ecdsa_bad_curve.pem` — EC P-256 with EXPLICIT (non-named) params
       (`openssl ecparam -param_enc explicit`) so `ec_named_curve()` returns None.
     - `cabf_cs_validity_40_months.pem` — ~40-month window straddling now (>1188d), e.g.
       2024-06-01 → 2027-10-01.
     - `cabf_cs_validity_500_days.pem` — 500-day window straddling now (>460d, ≤39mo), e.g.
       2026-02-01 → 2027-06-16.
     - `cabf_cs_no_aia.pem` — clean, NO AIA (keep CRL-DP).
     - `cabf_cs_no_crl.pem` — clean, NO CRL-DP (keep AIA).
   - Carry the TIME-FRAGILITY note (CS fixtures expire ~2027-06-01; regenerate annually) loudly in the
     section header, consistent with how `cabf_cs.rs` documents it.

2. **Verify the recipe runs without re-churning committed fixtures:** run `bash testdata/generate.sh`,
   confirm it produces all 8 CS fixtures with no error and that each new lint still fires correctly,
   THEN `git checkout -- testdata/*.pem` to discard the freshly re-rolled bytes (random keys) so the
   committed `.pem` files stay byte-stable. The ONLY tracked change you leave is `generate.sh`. Confirm
   with `git status` that exactly `testdata/generate.sh` is modified and no `.pem` differs.

3. Re-run the suite to confirm nothing regressed: `cargo test` must stay green against the unchanged
   committed fixtures (you did not change any `.pem`).

## Acceptance Criteria

- [ ] `generate.sh` contains a runnable code-signing section regenerating all 8 `cabf_cs_*.pem` with
      the correct shapes + the time-fragility header note.
- [ ] `git status` shows ONLY `testdata/generate.sh` modified; no `.pem` byte change.
- [ ] `bash testdata/generate.sh` runs clean and emits the 8 CS fixtures.
- [ ] `cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`,
      `cargo test -p linter --features serde` all pass.

## Notes / Dependencies

- Depends on task 04 (fixtures committed). Pure regeneration-recipe restoration; no `.pem`, no `src/`,
  no other test file.
