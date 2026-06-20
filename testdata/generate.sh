#!/usr/bin/env bash
#
# Regenerates the certificate fixtures used by the linter test suite.
#
# Required tooling:
#   - openssl 3.5+ (tested with OpenSSL 3.6.2; 3.5+ needed for ML-DSA / SLH-DSA)
#   - bash, dd, xxd, python3 (for the byte-patched fixtures)
#
# Usage:
#   ./testdata/generate.sh
#
# ============================================================================
# FIXED VALIDITY DATES — NOT TIME-FRAGILE (the test suite pins the clock)
# ============================================================================
# Feature 05 (CA/Browser Forum BR lints) introduced BROAD scoping: the four BR
# lints apply to EVERY non-CA leaf. One of them, cabf_br_validity_max_398_days,
# requires a leaf's validity window to be BOTH <= 398 days AND currently valid
# (notAfter in the future). A short window cannot also be far-future, so the
# BR-compliant leaves below use a fixed, <=398-day window:
#
#     BR_OK:  2026-06-01  ->  2027-06-01   (365 days)
#
# These leaves expire on 2027-06-01 in WALL-CLOCK terms, but that does NOT make
# the fixtures time-fragile: the test suite pins the reference clock to a fixed
# instant inside every window (via `--now <RFC3339>` on the CLI and
# `default_registry_with_now(...)` in the library), so hygiene_not_expired
# evaluates against that pinned "now" — never against the machine clock. The
# fixtures therefore do NOT need annual regeneration; the fixed dates exist only
# for byte-reproducibility (so a regen produces the same windows/serials).
#
# The cabf_br_validity_400_days fixture uses 2026-06-01 -> 2027-07-06 (400 days)
# to isolate cabf_br_validity_max_398_days against the same pinned clock.
#
# Two dating strategies were considered:
#   (a) Fixed dates (chosen here): the committed bytes are reproducible across
#       regenerations, and the pinned test clock makes them clock-independent.
#   (b) Relative dates (openssl -days 365): self-healing on regen (always
#       relative to "now"), but the committed bytes drift every regeneration,
#       making fixture diffs noisy and the checked-in window non-deterministic,
#       and the pinned-clock tests would then need recomputed reference instants.
# We keep fixed dates for reproducibility; the pinned clock removes the old
# annual-regen chore entirely.
# ============================================================================
#
# Output (written next to this script):
#
#   Shared fixtures (used across features 01–05):
#     - good.pem     clean BR-compliant LEAF cert that PASSES every shipped lint
#                    (all 14: 4 hygiene + 6 rfc5280 + 4 cabf_br). RSA-2048 /
#                    SHA-256, CA:FALSE, serverAuth EKU, SAN DNS = CN, BR_OK
#                    window.
#     - expired.pem  same BR-compliant leaf shape but with a PAST <=398d window
#                    (2024-01-01 -> 2024-06-01, 151d), so it violates ONLY
#                    hygiene_not_expired. notAfter == 2024-06-01 == Unix
#                    1_717_200_000 (asserted by EXPIRED_NOT_AFTER constants in
#                    crates/linter/tests/registry.rs and crates/cli/tests/output.rs).
#
#   Under BROAD BR scoping every non-CA leaf is in scope for all four BR lints,
#   so every leaf fixture is now built BR-COMPLIANT-EXCEPT-ITS-ONE-TARGET: it
#   gains serverAuth EKU, a SAN whose dNSName entries include the subject CN,
#   no internal/reserved SAN entries, and a BR_OK window — except where the
#   single target violation forces deviating from exactly one of those.
#
#   NOTE ON NAMES: the reserved-name classifier (lints/cabf_br/reserved.rs)
#   treats .example / .test / .local / .internal / single-label names as
#   internal/reserved. So BR-compliant leaf SANs MUST use a genuinely public
#   FQDN. We use *.example.com (TLD "com" is public; the name does NOT end in a
#   reserved suffix), which keeps cabf_br_no_internal_names_or_reserved_ip quiet.
#
#   One fixture per RFC 5280 lint, each violating EXACTLY that rule and passing
#   all other lints across the full 14-lint registry:
#     - rfc5280_version_not_v3.pem         BR-compliant v3 leaf, version byte
#                                          patched v3 -> v1.
#     - rfc5280_serial_number_zero.pem     serial == 0, else BR-compliant.
#     - rfc5280_validity_inverted.pem      notAfter == notBefore at a FUTURE
#                                          instant (zero-length window: <=398d so
#                                          BR validity passes, future so
#                                          not_expired passes). serverAuth + SAN.
#     - rfc5280_ca_bc_not_critical.pem     CA, BasicConstraints not critical
#                                          (keyUsage has keyCertSign). CA => BR
#                                          N/A, so UNCHANGED from feature 03.
#     - rfc5280_ca_missing_keycertsign.pem CA, BasicConstraints critical, but
#                                          keyUsage lacks keyCertSign. CA => BR
#                                          N/A, UNCHANGED.
#     - rfc5280_empty_subject_no_san.pem   empty subject DN, NO SAN (target), but
#                                          serverAuth EKU + BR_OK window ADDED.
#                                          No CN => cn_in_san silent; no SAN =>
#                                          internal-name lint silent; serverAuth
#                                          present => EKU lint silent. Isolates
#                                          ONLY san_present_if_subject_empty.
#
#   One fixture per crypto-hygiene lint (feature 04), each a BR-compliant leaf
#   (serverAuth + SAN-with-CN + BR_OK) that violates EXACTLY its one hygiene rule:
#     - hygiene_sha1_signature.pem   RSA-2048 key, SIGNED WITH SHA-1.
#     - hygiene_rsa_1024.pem         RSA-1024 key, SHA-256 signature.
#     - hygiene_ecdsa_bad_curve.pem  EC key on secp224r1 (named curve outside
#                                    {P-256,P-384,P-521}), SHA-256 signature.
#
#   One fixture per CA/Browser Forum BR lint (feature 05), each a BR-compliant
#   leaf EXCEPT its one target violation:
#     - cabf_br_validity_400_days.pem    400d window (2026-06-01 -> 2027-07-06),
#                                        currently valid. Violates ONLY
#                                        cabf_br_validity_max_398_days.
#     - cabf_br_cn_not_in_san.pem        CN=cn-missing.example.com but SAN lists
#                                        only DNS:other.example.com (omits the
#                                        CN). Violates ONLY cabf_br_cn_in_san.
#     - cabf_br_internal_san.pem         CN=public.example.com present in SAN as a
#                                        public name (cn_in_san quiet) PLUS
#                                        DNS:internal.local AND IP:10.0.0.1.
#                                        Violates ONLY
#                                        cabf_br_no_internal_names_or_reserved_ip
#                                        (with MULTIPLE findings).
#     - cabf_br_missing_serverauth.pem   SAN-with-CN, EKU present WITHOUT
#                                        serverAuth (clientAuth only). Violates
#                                        ONLY cabf_br_ext_key_usage_server_auth_present.
#
# Design notes
# ------------
# * All non-CA leaves carry basicConstraints=CA:FALSE, extendedKeyUsage with
#   serverAuth (unless the fixture's target is the missing-serverAuth rule), and
#   a SAN whose dNSName matches the subject CN (unless the target requires
#   otherwise). This keeps the BR lints quiet on every leaf except for its single
#   intended violation.
#
# * The two CA fixtures carry a non-empty subject (SAN lint N/A), a valid
#   validity window / serial / version, and are NotApplicable for all four BR
#   lints (CA => out of BR scope), so they keep their original far-future window
#   and are UNCHANGED from feature 03.
#
# * Two malformations cannot be produced by openssl directly and are made by
#   construction:
#     - serial == 0: `openssl x509 -req -set_serial 0`.
#     - v1 cert that still CARRIES extensions: openssl always emits v3 when
#       extensions are present, so we build a normal v3 cert and patch the single
#       DER version byte (the INTEGER inside the `[0] EXPLICIT` wrapper) from
#       0x02 (v3) to 0x00 (v1). The certificate's extensions TLV is left intact,
#       producing the otherwise-impossible "v1 with extensions" shape. The
#       signature no longer matches, which is irrelevant: the linter only parses
#       structure, it does not verify signatures.
#
# Determinism: each fixture embeds a freshly generated RSA/EC key, so exact bytes
# differ per run. What the tests rely on is stable: validity windows, serials,
# subject presence, CA-ness, SAN/EKU contents, and extension criticality.
# Regenerate only when you intend to refresh the committed fixtures; CI consumes
# the committed .pem files.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# A single shared key keeps the script fast; fixtures are self-signed and we do
# not rely on key uniqueness across fixtures.
KEY="$(mktemp)"
openssl genrsa -out "$KEY" 2048 2>/dev/null

# good.pem's key is PINNED (feature 17): a fixed, committed RSA-2048 key at
# testdata/keys/good.key. good.pem is signed from THIS key (not the re-rolled
# $KEY above), so good.pem's SubjectKeyIdentifier / serial / signature bytes are
# byte-stable across regenerations and ONLY the certificatePolicies extension
# added in feature 17 changes good.pem. good.pem is self-signed, so a dedicated
# key affects no other fixture. The key was generated ONCE and committed; it must
# NOT be re-rolled here. If it is ever missing, recreate it ONCE with
#   openssl genrsa -out testdata/keys/good.key 2048
# and commit it (do NOT regenerate it on subsequent runs — that would re-roll the
# SKI/signature and defeat the pin).
GOOD_KEY="$HERE/keys/good.key"
if [[ ! -f "$GOOD_KEY" ]]; then
  echo "ERROR: pinned good.pem key missing: $GOOD_KEY" >&2
  echo "       create it ONCE with: openssl genrsa -out $GOOD_KEY 2048" >&2
  echo "       then commit it (it must NOT be re-rolled on regen)." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Validity windows (UTC, openssl 1.1.1+/3.x flags).
# ---------------------------------------------------------------------------
# BR_OK: currently valid AND <=398 days (365d). Used by every BR-compliant leaf
# whose target violation is NOT validity. EXPIRES 2027-06-01 — see the
# time-fragility warning at the top of this file.
BR_OK_NB="20260601000000Z"
BR_OK_NA="20270601000000Z"

# EXPIRED: a PAST <=398-day window (151d). Used by expired.pem so it isolates
# ONLY hygiene_not_expired. notAfter 2024-06-01 == Unix 1_717_200_000.
EXPIRED_NB="20240101000000Z"
EXPIRED_NA="20240601000000Z"

# VAL400: currently valid but 400 days (> 398). Used by cabf_br_validity_400_days
# to fire ONLY cabf_br_validity_max_398_days. Also time-fragile (later horizon).
VAL400_NB="20260601000000Z"
VAL400_NA="20270706000000Z"

# INVERTED: a zero-length window (notAfter == notBefore) at a FUTURE instant.
# <=398d so BR validity passes; future so not_expired passes; equal bounds so
# rfc5280_validity_not_after_after_not_before fires. Future-of-now; also slide it
# forward if it ever falls into the past.
INVERTED_INSTANT="20270101000000Z"

# FAR_FUTURE: retained ONLY for the two CA fixtures (CA => BR N/A, so the 398-day
# rule never applies to them and a far-future window is fine).
FAR_FUTURE_NB="20240101000000Z"
FAR_FUTURE_NA="21240101000000Z" # 2124 — comfortably past any test "now".

# ---------------------------------------------------------------------------
# Extension config builders.
# ---------------------------------------------------------------------------
# make_leaf_ext <out_extfile> <san_spec>
#
# Writes a leaf extension config (CA:FALSE + serverAuth EKU + the given SAN).
# $san_spec is an openssl subjectAltName value, e.g. "DNS:good.example.com" or
# "DNS:a.example.com,IP:10.0.0.1". Pass "" to omit the SAN entirely.
make_leaf_ext() {
  local out="$1" san_spec="$2"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'extendedKeyUsage=serverAuth\n'
    if [[ -n "$san_spec" ]]; then
      printf 'subjectAltName=%s\n' "$san_spec"
    fi
  } >"$out"
}

# sign_csr <out.pem> <subject> <serial> <not_before> <not_after> <extfile|"">
#
# Self-signs a CSR built from $KEY (RSA-2048, SHA-256) with explicit serial /
# validity / extensions.
sign_csr() {
  local out="$1" subj="$2" serial="$3" nb="$4" na="$5" extfile="$6"
  local csr
  csr="$(mktemp)"
  openssl req -new -key "$KEY" -subj "$subj" -out "$csr" 2>/dev/null

  local args=(
    x509 -req -in "$csr" -signkey "$KEY" -out "$out"
    -set_serial "$serial" -not_before "$nb" -not_after "$na" -sha256
  )
  if [[ -n "$extfile" ]]; then
    args+=(-extfile "$extfile")
  fi
  openssl "${args[@]}" 2>/dev/null
  rm -f "$csr"
  echo "wrote $out"
}

# --- reusable extension configs --------------------------------------------
EXT_TMPS=()
new_ext() {
  local t
  t="$(mktemp)"
  EXT_TMPS+=("$t")
  echo "$t"
}

# CA fixtures (unchanged from feature 03).
EXT_CA_BC_NONCRIT="$(new_ext)"
printf 'basicConstraints=CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$EXT_CA_BC_NONCRIT"
EXT_CA_NO_KCS="$(new_ext)"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,cRLSign\n' >"$EXT_CA_NO_KCS"

# Hygiene keys.
HYG_RSA2048_KEY="$(mktemp)"
HYG_RSA1024_KEY="$(mktemp)"
HYG_EC_KEY="$(mktemp)"

# Code-signing keys (feature 09). One RSA-3072 key is shared across the six
# RSA-3072 CS fixtures (their SubjectKeyIdentifier is therefore identical, which
# is fine — the CS lints do not assert SKI uniqueness across fixtures). A
# separate RSA-2048 key drives cabf_cs_rsa_2048, and an EXPLICIT-curve EC key
# (P-256 params encoded inline, no named-curve OID) drives the bad-curve fixture.
CS_RSA3072_KEY="$(mktemp)"
CS_RSA2048_KEY="$(mktemp)"
CS_EC_KEY="$(mktemp)"

cleanup() {
  rm -f "$KEY" "$HYG_RSA2048_KEY" "$HYG_RSA1024_KEY" "$HYG_EC_KEY" \
    "$CS_RSA3072_KEY" "$CS_RSA2048_KEY" "$CS_EC_KEY" "${EXT_TMPS[@]}"
}
trap cleanup EXIT

# ===========================================================================
# Shared fixtures
# ===========================================================================

# good.pem: clean BR-compliant leaf — v3, CN=good.example.com, SAN DNS = CN,
# serverAuth, CA:FALSE, RSA-2048/SHA-256, BR_OK window. Passes every shipped lint.
#
# Feature 17: good.pem now ALSO carries a certificatePolicies extension with the
# CABF reserved DV policy OID 2.23.140.1.2.1, so the new
# cabf_br_certificate_policies_present (lint 8) and
# cabf_br_certificate_policies_reserved_oid (lint 9) lints are POSITIVE passes and
# good.pem stays completely finding-free. good.pem is signed from the PINNED
# $GOOD_KEY (not the re-rolled $KEY) so its SKI/serial/signature are byte-stable
# and only this certificatePolicies line moves good.pem's bytes.
EXT_GOOD="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:good.example.com\n'
  printf 'certificatePolicies=2.23.140.1.2.1\n'
} >"$EXT_GOOD"
GOOD_CSR="$(mktemp)"
openssl req -new -key "$GOOD_KEY" -subj "/CN=good.example.com" -out "$GOOD_CSR" 2>/dev/null
openssl x509 -req -in "$GOOD_CSR" -signkey "$GOOD_KEY" -out "$HERE/good.pem" \
  -set_serial 17 -not_before "$BR_OK_NB" -not_after "$BR_OK_NA" -sha256 \
  -extfile "$EXT_GOOD" 2>/dev/null
rm -f "$GOOD_CSR"
echo "wrote $HERE/good.pem (PINNED key + certificatePolicies DV OID 2.23.140.1.2.1)"

# expired.pem: BR-compliant leaf shape but PAST <=398d window — isolates ONLY
# hygiene_not_expired.
EXT_EXPIRED="$(new_ext)"
make_leaf_ext "$EXT_EXPIRED" "DNS:expired.example.com"
sign_csr "$HERE/expired.pem" "/CN=expired.example.com" 17 "$EXPIRED_NB" "$EXPIRED_NA" "$EXT_EXPIRED"

# ===========================================================================
# RFC 5280 per-lint violating fixtures
# ===========================================================================

# serial_number_positive: serial 0, otherwise BR-compliant leaf.
EXT_SERIAL="$(new_ext)"
make_leaf_ext "$EXT_SERIAL" "DNS:serial-zero.example.com"
sign_csr "$HERE/rfc5280_serial_number_zero.pem" "/CN=serial-zero.example.com" 0 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_SERIAL"

# validity_not_after_after_not_before: zero-length window (notAfter == notBefore)
# at a FUTURE instant. openssl refuses a strictly inverted window but accepts an
# equal pair; the lint requires notAfter STRICTLY later than notBefore, so an
# equal pair violates it. Future instant => not_expired passes; zero span <=398
# => BR validity passes. serverAuth + SAN-with-CN keep the other BR lints quiet.
EXT_INVERTED="$(new_ext)"
make_leaf_ext "$EXT_INVERTED" "DNS:inverted.example.com"
sign_csr "$HERE/rfc5280_validity_inverted.pem" "/CN=inverted.example.com" 21 \
  "$INVERTED_INSTANT" "$INVERTED_INSTANT" "$EXT_INVERTED"

# basic_constraints_critical_on_ca: CA cert, BasicConstraints NOT critical, but
# keyUsage carries keyCertSign. CA => all four BR lints N/A. UNCHANGED.
sign_csr "$HERE/rfc5280_ca_bc_not_critical.pem" "/CN=ca-bc-noncrit.example" 18 \
  "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_CA_BC_NONCRIT"

# key_usage_present_when_ca: CA cert, BasicConstraints critical CA:TRUE, keyUsage
# present WITHOUT keyCertSign. CA => BR N/A. UNCHANGED.
sign_csr "$HERE/rfc5280_ca_missing_keycertsign.pem" "/CN=ca-no-kcs.example" 19 \
  "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_CA_NO_KCS"

# san_present_if_subject_empty: empty subject DN, NO SAN (target), but serverAuth
# EKU + BR_OK window ADDED. No CN => cn_in_san silent; no SAN => internal-name
# lint silent; serverAuth present => EKU lint silent. Isolates ONLY this rule.
EXT_EMPTY="$(new_ext)"
make_leaf_ext "$EXT_EMPTY" "" # CA:FALSE + serverAuth, no SAN
sign_csr "$HERE/rfc5280_empty_subject_no_san.pem" "/" 20 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_EMPTY"

# version_is_v3: build a BR-compliant v3 leaf, then patch the DER version byte
# from v3 (0x02) to v1 (0x00). openssl cannot emit "v1 with extensions" directly.
EXT_VERSION="$(new_ext)"
make_leaf_ext "$EXT_VERSION" "DNS:version-v1.example.com"
V3_TMP="$(mktemp)"
DER_TMP="$(mktemp)"
sign_csr "$V3_TMP" "/CN=version-v1.example.com" 22 "$BR_OK_NB" "$BR_OK_NA" "$EXT_VERSION"
openssl x509 -in "$V3_TMP" -outform DER -out "$DER_TMP"

# Locate the version field. DER layout at the start of a Certificate:
#   30 LL                      SEQUENCE (Certificate)
#     30 LL                    SEQUENCE (TBSCertificate)
#       A0 03 02 01 NN         [0] EXPLICIT { INTEGER version }
# We find the "A0 03 02 01" prefix and flip the following value byte to 0x00.
patch_version_to_v1() {
  local der="$1"
  local hex
  hex="$(xxd -p -l 32 "$der" | tr -d '\n')"
  local marker="a003020102"
  local idx="${hex%%"$marker"*}"
  if [[ "$idx" == "$hex" ]]; then
    echo "ERROR: version marker a003020102 not found in $der" >&2
    exit 1
  fi
  local byte_off=$(((${#idx} / 2) + 4))
  printf '\x00' | dd of="$der" bs=1 seek="$byte_off" count=1 conv=notrunc 2>/dev/null
}

patch_version_to_v1 "$DER_TMP"
openssl x509 -inform DER -in "$DER_TMP" -outform PEM -out "$HERE/rfc5280_version_not_v3.pem"
echo "wrote $HERE/rfc5280_version_not_v3.pem (version byte patched v3 -> v1)"
rm -f "$V3_TMP" "$DER_TMP"

# ===========================================================================
# Crypto-hygiene per-lint violating fixtures (feature 04)
# ===========================================================================
#
# Each is a BR-compliant leaf (serverAuth + SAN-with-CN + BR_OK window) that
# violates EXACTLY its one hygiene rule. They carry their own key/digest, so they
# inline the signing step.

# sign_leaf_with <out.pem> <key> <subject> <serial> <digest> <extfile>
sign_leaf_with() {
  local out="$1" key="$2" subj="$3" serial="$4" digest="$5" extfile="$6"
  local csr
  csr="$(mktemp)"
  openssl req -new -key "$key" -subj "$subj" -out "$csr" 2>/dev/null
  openssl x509 -req -in "$csr" -signkey "$key" -out "$out" \
    -set_serial "$serial" -not_before "$BR_OK_NB" -not_after "$BR_OK_NA" \
    "-$digest" -extfile "$extfile" 2>/dev/null
  rm -f "$csr"
  echo "wrote $out"
}

# hygiene_no_sha1_signature: RSA-2048 key but SIGNED WITH SHA-1.
EXT_SHA1="$(new_ext)"
make_leaf_ext "$EXT_SHA1" "DNS:sha1-sig.example.com"
openssl genrsa -out "$HYG_RSA2048_KEY" 2048 2>/dev/null
sign_leaf_with "$HERE/hygiene_sha1_signature.pem" "$HYG_RSA2048_KEY" \
  "/CN=sha1-sig.example.com" 30 sha1 "$EXT_SHA1"

# hygiene_rsa_key_min_2048: RSA-1024 key, SHA-256 signature.
EXT_RSA1024="$(new_ext)"
make_leaf_ext "$EXT_RSA1024" "DNS:rsa-1024.example.com"
openssl genrsa -out "$HYG_RSA1024_KEY" 1024 2>/dev/null
sign_leaf_with "$HERE/hygiene_rsa_1024.pem" "$HYG_RSA1024_KEY" \
  "/CN=rsa-1024.example.com" 31 sha256 "$EXT_RSA1024"

# hygiene_ecdsa_curve_allowlist: EC key on secp224r1 (NIST P-224), SHA-256 sig.
EXT_ECDSA="$(new_ext)"
make_leaf_ext "$EXT_ECDSA" "DNS:ec-bad-curve.example.com"
openssl ecparam -name secp224r1 -genkey -noout -out "$HYG_EC_KEY" 2>/dev/null
sign_leaf_with "$HERE/hygiene_ecdsa_bad_curve.pem" "$HYG_EC_KEY" \
  "/CN=ec-bad-curve.example.com" 32 sha256 "$EXT_ECDSA"

# ===========================================================================
# CA/Browser Forum BR per-lint violating fixtures (feature 05)
# ===========================================================================
#
# Each is a BR-compliant leaf EXCEPT its one target BR violation, and passes all
# rfc5280 + hygiene lints (RSA-2048/SHA-256, v3, positive serial, CA:FALSE).

# cabf_br_validity_max_398_days: 400d currently-valid window. serverAuth + SAN.
EXT_VAL400="$(new_ext)"
make_leaf_ext "$EXT_VAL400" "DNS:validity-400.example.com"
sign_csr "$HERE/cabf_br_validity_400_days.pem" "/CN=validity-400.example.com" 40 \
  "$VAL400_NB" "$VAL400_NA" "$EXT_VAL400"

# cabf_br_cn_in_san: CN present but ABSENT from the SAN (SAN lists a different
# public name). serverAuth + BR_OK. Isolates ONLY cabf_br_cn_in_san.
EXT_CNMISS="$(new_ext)"
make_leaf_ext "$EXT_CNMISS" "DNS:other.example.com"
sign_csr "$HERE/cabf_br_cn_not_in_san.pem" "/CN=cn-missing.example.com" 41 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_CNMISS"

# cabf_br_no_internal_names_or_reserved_ip: CN=public.example.com IS in the SAN
# as a public name (cn_in_san quiet) PLUS an internal name AND a reserved IP, so
# the target lint fires with MULTIPLE findings.
EXT_INTERNAL="$(new_ext)"
make_leaf_ext "$EXT_INTERNAL" "DNS:public.example.com,DNS:internal.local,IP:10.0.0.1"
sign_csr "$HERE/cabf_br_internal_san.pem" "/CN=public.example.com" 42 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_INTERNAL"

# cabf_br_ext_key_usage_server_auth_present: EKU PRESENT but WITHOUT serverAuth
# (clientAuth only). SAN-with-CN + BR_OK keep the other BR lints quiet.
EXT_NOSA="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=clientAuth\n'
  printf 'subjectAltName=DNS:no-serverauth.example.com\n'
} >"$EXT_NOSA"
sign_csr "$HERE/cabf_br_missing_serverauth.pem" "/CN=no-serverauth.example.com" 43 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_NOSA"

# ===========================================================================
# Feature 12: RFC 5280 depth-expansion per-lint violating fixtures
# ===========================================================================
#
# The registry now ships 32 lints (4 hygiene + 16 rfc5280 + 12 cabf_br). Each
# fixture below violates EXACTLY its one NEW rule across the FULL 32-lint
# registry and fires no OLD rule under the purpose-gated engine, EXCEPT four
# fixtures with an INHERENT, documented overlap when the lints are run through
# the RAW (non-purpose-gated) `default_registry().run()` used by the isolation
# tests (see the per-fixture notes and the integration tests):
#   - rfc5280_eku_empty.pem  (an empty EKU asserts no serverAuth, so the broad
#     cabf_br_ext_key_usage_server_auth_present co-fires under the raw registry;
#     the purpose-gated engine resolves this non-serverAuth leaf to Generic and
#     never runs the BR sources)
#   - cabf_br_dnsname_underscore.pem  (underscore is also a non-LDH character,
#     so the bad-character lint co-fires by construction)
#   - cabf_br_dnsname_bare_wildcard.pem  (`*.com` strips to the single label
#     `com`, which reserved.rs::is_internal_name classifies as internal, so the
#     internal-name lint co-fires by construction)
#   - cabf_br_cn_reserved_ip.pem  (an IP CN must appear in the SAN to satisfy
#     cabf_br_cn_in_san, which trips the existing SAN-reserved-IP lint too)
#
# Leaf fixtures reuse BR_OK; CA fixtures reuse the FAR_FUTURE window.
# Time-fragility is inherited from feature 05 (see the warning at the top).

# rfc5280_ca_subject_field_empty: CA cert with an EMPTY subject DN. To isolate
# ONLY this rule the CA carries critical BasicConstraints + keyCertSign (so the
# CA structural lints pass), a hash SKI (so ski_missing_ca passes), and a
# CRITICAL SAN (RFC 5280 requires the SAN critical when the subject is empty, so
# san_present_if_subject_empty passes). CA => all BR lints NotApplicable.
EXT_CA_SUBJ_EMPTY="$(new_ext)"
{
  printf 'basicConstraints=critical,CA:TRUE\n'
  printf 'keyUsage=critical,keyCertSign,cRLSign\n'
  printf 'subjectKeyIdentifier=hash\n'
  printf 'subjectAltName=critical,DNS:ca-empty.example.com\n'
} >"$EXT_CA_SUBJ_EMPTY"
sign_csr "$HERE/rfc5280_ca_subject_empty.pem" "/" 60 \
  "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_CA_SUBJ_EMPTY"

# rfc5280_ext_key_usage_without_bits: leaf with an EKU extension present but
# EMPTY (a zero-length KeyPurposeId SEQUENCE). openssl refuses an empty
# extendedKeyUsage value, so the extension is injected as raw DER: the EKU OID
# (2.5.29.37) carrying the DER bytes 30 00 (SEQUENCE, length 0). An empty EKU
# asserts no serverAuth (see the inherent-overlap note above).
EXT_EKU_EMPTY="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'subjectAltName=DNS:eku-empty.example.com\n'
  printf '2.5.29.37=DER:30:00\n'
} >"$EXT_EKU_EMPTY"
sign_csr "$HERE/rfc5280_eku_empty.pem" "/CN=eku-empty.example.com" 61 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_EKU_EMPTY"

# rfc5280_aki_no_keyid: leaf whose AuthorityKeyIdentifier carries only
# authorityCertIssuer (the issuer DirName) and the serial, with NO keyIdentifier
# field. openssl's `authorityKeyIdentifier=issuer:always` emits exactly that.
EXT_AKI_NO_KEYID="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:aki-no-keyid.example.com\n'
  printf 'authorityKeyIdentifier=issuer:always\n'
} >"$EXT_AKI_NO_KEYID"
sign_csr "$HERE/rfc5280_aki_no_keyid.pem" "/CN=aki-no-keyid.example.com" 62 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_AKI_NO_KEYID"

# rfc5280_ski_missing_ca: CA cert (critical BC + keyCertSign, non-empty subject)
# with NO SubjectKeyIdentifier. openssl 3.x auto-adds a hash SKI, so we suppress
# it explicitly with `subjectKeyIdentifier=none`. CA => all BR lints N/A.
EXT_SKI_MISSING_CA="$(new_ext)"
{
  printf 'basicConstraints=critical,CA:TRUE\n'
  printf 'keyUsage=critical,keyCertSign,cRLSign\n'
  printf 'subjectKeyIdentifier=none\n'
} >"$EXT_SKI_MISSING_CA"
sign_csr "$HERE/rfc5280_ski_missing_ca.pem" "/CN=ski-missing-ca.example" 63 \
  "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_SKI_MISSING_CA"

# rfc5280_ski_missing_sub_cert: BR-compliant leaf with NO SubjectKeyIdentifier
# (suppressed via `subjectKeyIdentifier=none`). This is a SHOULD, so the only
# finding is a WARN. Everything else passes.
EXT_SKI_MISSING_SUB="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:ski-sub.example.com\n'
  printf 'subjectKeyIdentifier=none\n'
} >"$EXT_SKI_MISSING_SUB"
sign_csr "$HERE/rfc5280_ski_missing_sub_cert.pem" "/CN=ski-sub.example.com" 64 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_SKI_MISSING_SUB"

# rfc5280_path_len_on_leaf: leaf with a pathLenConstraint set while CA:FALSE —
# pathLen is only meaningful on a keyCertSign CA, so this is improper. openssl
# accepts `CA:FALSE,pathlen:0` directly.
EXT_PATHLEN_LEAF="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE,pathlen:0\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:pathlen-leaf.example.com\n'
} >"$EXT_PATHLEN_LEAF"
sign_csr "$HERE/rfc5280_path_len_on_leaf.pem" "/CN=pathlen-leaf.example.com" 65 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_PATHLEN_LEAF"

# rfc5280_name_constraints_not_critical: leaf carrying a NameConstraints
# extension that is NOT marked critical (RFC 5280 requires it critical). openssl
# emits NameConstraints non-critical by default.
EXT_NC="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:nameconstraints.example.com\n'
  printf 'nameConstraints=permitted;DNS:.example.com\n'
} >"$EXT_NC"
sign_csr "$HERE/rfc5280_name_constraints_not_critical.pem" \
  "/CN=nameconstraints.example.com" 66 "$BR_OK_NB" "$BR_OK_NA" "$EXT_NC"

# rfc5280_country_not_printable: leaf whose subject countryName is encoded as a
# UTF8String instead of the RFC-mandated PrintableString. openssl always emits
# countryName as PrintableString (tag 0x13), so we BYTE-PATCH the SUBJECT
# country value's tag byte from 0x13 (PrintableString) to 0x0c (UTF8String). The
# value "US" is valid UTF-8, so the cert still parses; only the tag changes. The
# patch targets the SECOND occurrence of the TLV `13 02 55 53` ("US") in the DER
# (the first is the self-signed ISSUER country, the second is the SUBJECT
# country). This length-preserving patch breaks the signature, which is fine —
# the linter parses structure, it does not verify signatures.
EXT_COUNTRY="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:country-utf8.example.com\n'
} >"$EXT_COUNTRY"
COUNTRY_V3="$(mktemp)"
COUNTRY_DER="$(mktemp)"
sign_csr "$COUNTRY_V3" "/C=US/CN=country-utf8.example.com" 67 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_COUNTRY"
openssl x509 -in "$COUNTRY_V3" -outform DER -out "$COUNTRY_DER"
python3 - "$COUNTRY_DER" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
pat = bytes.fromhex("13025553")  # PrintableString, len 2, "US"
first = data.find(pat)
second = data.find(pat, first + 1)
if first < 0 or second < 0:
    sys.exit("ERROR: could not find both issuer+subject country TLVs to patch")
data[second] = 0x0C  # UTF8String tag on the SUBJECT country value
open(path, "wb").write(data)
PY
openssl x509 -inform DER -in "$COUNTRY_DER" -outform PEM \
  -out "$HERE/rfc5280_country_not_printable.pem"
echo "wrote $HERE/rfc5280_country_not_printable.pem (subject C tag patched PrintableString -> UTF8String)"
rm -f "$COUNTRY_V3" "$COUNTRY_DER"

# rfc5280_san_empty: leaf whose SubjectAltName extension is PRESENT but contains
# ZERO GeneralNames. openssl's `subjectAltName=email:copy` with a subject that
# has no email yields an empty SAN. The subject uses /O= (no CN) so cn_in_san
# stays silent, and the subject is non-empty so san_present_if_subject_empty
# stays N/A.
EXT_SAN_EMPTY="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=email:copy\n'
} >"$EXT_SAN_EMPTY"
sign_csr "$HERE/rfc5280_san_empty.pem" "/O=SAN Empty Org" 68 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_SAN_EMPTY"

# rfc5280_utctime_not_zulu: leaf whose notBefore UTCTime is in the OFFSET form
# "YYMMDDHHMMSS+0000" instead of Zulu "YYMMDDHHMMSSZ". openssl always emits the
# Zulu form, so we rewrite the notBefore UTCTime in the DER from the 13-byte
# "260601000000Z" to the 17-byte "260601000000+0000" and fix the three nested
# length headers (Validity SEQUENCE — short form, TBSCertificate SEQUENCE and the
# outer Certificate SEQUENCE — both two-byte long form). x509-parser accepts the
# offset form; the lint flags it because it does not end in 'Z'. Signature is
# intentionally invalidated (irrelevant to a structural linter).
EXT_UTCTIME="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:utctime.example.com\n'
} >"$EXT_UTCTIME"
UTC_V3="$(mktemp)"
UTC_DER="$(mktemp)"
sign_csr "$UTC_V3" "/CN=utctime.example.com" 69 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_UTCTIME"
openssl x509 -in "$UTC_V3" -outform DER -out "$UTC_DER"
python3 - "$UTC_DER" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())

# notBefore UTCTime: tag 0x17, length 0x0d (13), content "260601000000Z".
i = data.find(bytes.fromhex("170d") + b"260601000000Z")
if i < 0:
    sys.exit("ERROR: could not locate notBefore UTCTime to patch")
old_tlv_len = 2 + 13
new_tlv = b"\x17\x11" + b"260601000000+0000"  # tag, len 17, offset-form content
data = bytearray(data[:i] + new_tlv + data[i + old_tlv_len:])
delta = len(new_tlv) - old_tlv_len  # +4

# Fix outer Certificate SEQUENCE length (30 82 hi lo at offset 0).
if not (data[0] == 0x30 and data[1] == 0x82):
    sys.exit("ERROR: unexpected Certificate SEQUENCE header")
cert_len = ((data[2] << 8) | data[3]) + delta
data[2] = (cert_len >> 8) & 0xFF
data[3] = cert_len & 0xFF

# Fix TBSCertificate SEQUENCE length (30 82 hi lo at offset 4).
if not (data[4] == 0x30 and data[5] == 0x82):
    sys.exit("ERROR: unexpected TBSCertificate SEQUENCE header")
tbs_len = ((data[6] << 8) | data[7]) + delta
data[6] = (tbs_len >> 8) & 0xFF
data[7] = tbs_len & 0xFF

# Fix Validity SEQUENCE length (short-form 30 LL immediately before notBefore).
j = data.find(b"\x17\x11" + b"260601000000+0000")
val_hdr = j - 2
if data[val_hdr] != 0x30:
    sys.exit("ERROR: unexpected Validity SEQUENCE header")
data[val_hdr + 1] = data[val_hdr + 1] + delta

open(path, "wb").write(data)
PY
openssl x509 -inform DER -in "$UTC_DER" -outform PEM \
  -out "$HERE/rfc5280_utctime_not_zulu.pem"
echo "wrote $HERE/rfc5280_utctime_not_zulu.pem (notBefore UTCTime rewritten to offset form)"
rm -f "$UTC_V3" "$UTC_DER"

# ===========================================================================
# Feature 12: CA/Browser Forum BR depth-expansion per-lint violating fixtures
# ===========================================================================
#
# All are BR-compliant leaves EXCEPT their one target violation (plus the three
# documented inherent two-rule overlaps noted at the top of the feature-12
# section). Each carries serverAuth EKU + a compliant public SAN dNSName + the
# BR_OK window so the other lints stay quiet.

# cabf_br_dnsname_underscore: SAN with a compliant DNS:<cn> plus the offending
# DNS:foo_bar.example.com. NOTE (inherent two-rule): an underscore is also a
# non-LDH character, so cabf_br_dnsname_bad_character_in_label co-fires on the
# same name by construction. There is no underscore name the LDH check passes,
# so this fixture intentionally trips BOTH dNSName-syntax rules; the integration
# test asserts that exact pair.
EXT_DNS_USCORE="$(new_ext)"
make_leaf_ext "$EXT_DNS_USCORE" "DNS:underscore.example.com,DNS:foo_bar.example.com"
sign_csr "$HERE/cabf_br_dnsname_underscore.pem" "/CN=underscore.example.com" 70 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_DNS_USCORE"

# cabf_br_dnsname_bad_char: SAN with a compliant DNS:<cn> plus DNS:foo!bar...
# ('!' is a non-LDH character, but NOT an underscore, so only the bad-character
# rule fires).
EXT_DNS_BADCHAR="$(new_ext)"
make_leaf_ext "$EXT_DNS_BADCHAR" "DNS:badchar.example.com,DNS:foo!bar.example.com"
sign_csr "$HERE/cabf_br_dnsname_bad_char.pem" "/CN=badchar.example.com" 71 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_DNS_BADCHAR"

# cabf_br_dnsname_label_too_long: SAN with a compliant DNS:<cn> plus a name whose
# leftmost label is 64 octets (> the 63-octet DNS limit). The label is all 'a's
# (LDH), so ONLY the label-too-long rule fires.
LONG_LABEL="$(python3 -c 'print("a" * 64)')"
EXT_DNS_TOOLONG="$(new_ext)"
make_leaf_ext "$EXT_DNS_TOOLONG" "DNS:toolong.example.com,DNS:${LONG_LABEL}.example.com"
sign_csr "$HERE/cabf_br_dnsname_label_too_long.pem" "/CN=toolong.example.com" 72 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_DNS_TOOLONG"

# cabf_br_dnsname_bare_wildcard: SAN with a compliant DNS:<cn> plus the bare
# wildcard DNS:*.com. NOTE (inherent two-rule): reserved.rs::is_internal_name
# strips the leading "*." and judges "com" as a single-label name => internal,
# so cabf_br_no_internal_names_or_reserved_ip co-fires by construction. Any bare
# wildcard "*.<tld>" reduces to a single label, so the overlap is unavoidable;
# the integration test asserts that exact pair.
EXT_DNS_WILDCARD="$(new_ext)"
make_leaf_ext "$EXT_DNS_WILDCARD" "DNS:wildcard.example.com,DNS:*.com"
sign_csr "$HERE/cabf_br_dnsname_bare_wildcard.pem" "/CN=wildcard.example.com" 73 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_DNS_WILDCARD"

# cabf_br_ou_present: BR-compliant leaf whose subject carries a prohibited
# organizationalUnitName (OU) attribute.
EXT_OU="$(new_ext)"
make_leaf_ext "$EXT_OU" "DNS:ou.example.com"
sign_csr "$HERE/cabf_br_ou_present.pem" "/OU=Engineering/CN=ou.example.com" 74 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_OU"

# cabf_br_cn_reserved_ip: subject CN is the reserved IP 10.0.0.1, present in the
# SAN as IP:10.0.0.1 so cabf_br_cn_in_san stays quiet. NOTE (inherent two-rule,
# pre-documented in the plan): putting the reserved IP in the SAN to satisfy
# cn_in_san necessarily trips the existing cabf_br_no_internal_names_or_reserved_ip
# (SAN reserved IP). This fixture intentionally trips BOTH reserved-IP rules
# (CN + SAN); the integration test asserts that exact pair.
EXT_CN_IP="$(new_ext)"
make_leaf_ext "$EXT_CN_IP" "IP:10.0.0.1"
sign_csr "$HERE/cabf_br_cn_reserved_ip.pem" "/CN=10.0.0.1" 75 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_CN_IP"

# cabf_br_two_common_names: subject carries TWO commonName attributes, both
# present in the SAN so cn_in_san stays quiet — ONLY the extra-CN rule fires.
EXT_TWO_CN="$(new_ext)"
make_leaf_ext "$EXT_TWO_CN" "DNS:cn-first.example.com,DNS:cn-second.example.com"
sign_csr "$HERE/cabf_br_two_common_names.pem" \
  "/CN=cn-first.example.com/CN=cn-second.example.com" 76 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_TWO_CN"

# cabf_br_country_not_iso: BR-compliant leaf whose subject countryName is "ZZ",
# which is a valid-length but not-assigned ISO 3166-1 alpha-2 code. ("ZZ" is NOT
# the explicitly-allowed "XX".)
EXT_COUNTRY_ISO="$(new_ext)"
make_leaf_ext "$EXT_COUNTRY_ISO" "DNS:country-iso.example.com"
sign_csr "$HERE/cabf_br_country_not_iso.pem" "/C=ZZ/CN=country-iso.example.com" 77 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_COUNTRY_ISO"

# ===========================================================================
# Feature 17: CA/Browser Forum BR depth-expansion per-lint violating fixtures
# ===========================================================================
#
# Twelve more BR lints (the registry now ships 82 lints overall; cabf_br holds
# 24). Each fixture below is a BR-compliant leaf EXCEPT its one NEW target rule
# and fires no OLD rule across the FULL 82-lint registry, with TWO documented
# intentional co-fires (asserted as two-rule cases in crates/linter/tests/cabf_br.rs):
#   - cabf_br_leaf_path_len.pem  (a pathLenConstraint on a CA:FALSE leaf trips
#     BOTH the new BR-scoped cabf_br_subscriber_basic_constraints_path_len_prohibited
#     AND the feature-12 rfc5280_path_len_constraint_improperly_included by
#     construction — pathLen on a non-CA-with-keyCertSign leaf is improper under
#     both sources)
#   - cabf_br_eku_no_server_auth.pem  (an EKU asserting clientAuth only trips BOTH
#     the new cabf_br_ext_key_usage_server_auth_required AND the existing
#     cabf_br_ext_key_usage_server_auth_present — no serverAuth purpose is asserted)
#
# All leaves reuse the BR_OK window, RSA-2048/SHA-256, CA:FALSE, a compliant
# public DNS:<cn> SAN entry (so cabf_br_cn_in_san stays quiet and the names are
# not internal/reserved), unless the single target forces deviating from exactly
# one of those. Serials 80..91.

# cabf_br_subscriber_key_usage_cert_sign_prohibited: leaf KeyUsage asserts
# keyCertSign (a CA-only bit) alongside digitalSignature. CA:FALSE keeps it a
# subscriber cert; serverAuth + compliant SAN keep the other BR lints quiet.
EXT_KU_CERTSIGN="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:ku-cert-sign.example.com\n'
  printf 'keyUsage=digitalSignature,keyCertSign\n'
} >"$EXT_KU_CERTSIGN"
sign_csr "$HERE/cabf_br_ku_cert_sign.pem" "/CN=ku-cert-sign.example.com" 80 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_KU_CERTSIGN"

# cabf_br_subscriber_key_usage_crl_sign_prohibited: leaf KeyUsage asserts cRLSign
# (a CA-only bit) alongside digitalSignature. CA:FALSE.
EXT_KU_CRLSIGN="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:ku-crl-sign.example.com\n'
  printf 'keyUsage=digitalSignature,cRLSign\n'
} >"$EXT_KU_CRLSIGN"
sign_csr "$HERE/cabf_br_ku_crl_sign.pem" "/CN=ku-crl-sign.example.com" 81 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_KU_CRLSIGN"

# cabf_br_subscriber_basic_constraints_path_len_prohibited: leaf with a
# pathLenConstraint while CA:FALSE — meaningful only on a keyCertSign CA, so it is
# improper on a subscriber. openssl accepts CA:FALSE,pathlen:0 directly. DOCUMENTED
# two-rule co-fire: this also trips the feature-12
# rfc5280_path_len_constraint_improperly_included by construction (pathLen on a
# non-CA-with-keyCertSign leaf is improper under both the BR and RFC sources). The
# integration test asserts that exact pair.
EXT_LEAF_PATHLEN="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE,pathlen:0\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:leaf-path-len.example.com\n'
} >"$EXT_LEAF_PATHLEN"
sign_csr "$HERE/cabf_br_leaf_path_len.pem" "/CN=leaf-path-len.example.com" 82 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_LEAF_PATHLEN"

# cabf_br_ext_key_usage_any_prohibited: EKU = serverAuth + anyExtendedKeyUsage
# (the prohibited 2.5.29.37.0). serverAuth kept so the server-auth lints stay
# quiet; only the any-EKU rule fires.
EXT_EKU_ANY="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth,anyExtendedKeyUsage\n'
  printf 'subjectAltName=DNS:eku-any.example.com\n'
} >"$EXT_EKU_ANY"
sign_csr "$HERE/cabf_br_eku_any.pem" "/CN=eku-any.example.com" 83 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_EKU_ANY"

# cabf_br_ext_key_usage_server_auth_required: EKU present (clientAuth only) with NO
# serverAuth. DOCUMENTED two-rule co-fire: this fixture also trips the EXISTING
# cabf_br_ext_key_usage_server_auth_present (no serverAuth purpose is asserted), so
# the integration test asserts that exact pair. This is lint 5's
# single-rule-vs-existing isolating fixture (the existing cabf_br_missing_serverauth.pem
# isolation test is reconciled to the same two-rule assertion).
EXT_EKU_NOSA="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=clientAuth\n'
  printf 'subjectAltName=DNS:eku-no-server-auth.example.com\n'
} >"$EXT_EKU_NOSA"
sign_csr "$HERE/cabf_br_eku_no_server_auth.pem" "/CN=eku-no-server-auth.example.com" 84 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_EKU_NOSA"

# cabf_br_san_dns_or_ip_only: SAN = compliant DNS:<cn> + TWO prohibited entries (a
# rfc822Name and a URI). Only the DNS-or-IP-only rule fires (the DNS:<cn> keeps
# cn_in_san quiet), but it yields TWO findings (one per offending entry) — the
# multi-finding case. The reserved.rs classifier is not tripped: example.com is a
# public name and neither prohibited entry is a dNSName/iPAddress it inspects.
EXT_SAN_EMAIL="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:san-email.example.com,email:a@example.com,URI:https://san.example.com/\n'
} >"$EXT_SAN_EMAIL"
sign_csr "$HERE/cabf_br_san_email_entry.pem" "/CN=san-email.example.com" 85 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_SAN_EMAIL"

# cabf_br_san_present (Warn): leaf with NO SAN but a NON-EMPTY subject DN, else
# compliant. cabf_br_san_present fires a Warn; rfc5280_san_present_if_subject_empty
# stays quiet because the subject is non-empty. The subject uses /O= (NO CN) so
# cabf_br_cn_in_san stays quiet — a CN with no SAN would otherwise trip cn_in_san
# (the CN cannot be present in a non-existent SAN). serverAuth kept so the
# server-auth lints stay quiet. This fixture fires EXACTLY one new Warn and no
# Error across the full registry.
EXT_NO_SAN="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
} >"$EXT_NO_SAN"
sign_csr "$HERE/cabf_br_no_san.pem" "/O=No SAN Org" 86 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_NO_SAN"

# cabf_br_certificate_policies_present (Warn): leaf with NO CertificatePolicies
# extension, else compliant. Fires a Warn from cabf_br_certificate_policies_present.
# (good.pem now CARRIES certificatePolicies, so this dedicated fixture is what
# asserts the Warn cleanly; cabf_br_certificate_policies_reserved_oid stays quiet
# because the extension is ABSENT.)
EXT_NO_POLICIES="$(new_ext)"
make_leaf_ext "$EXT_NO_POLICIES" "DNS:no-policies.example.com"
sign_csr "$HERE/cabf_br_no_policies.pem" "/CN=no-policies.example.com" 87 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_NO_POLICIES"

# cabf_br_certificate_policies_reserved_oid: CertificatePolicies PRESENT with a
# single NON-reserved OID (1.3.6.1.4.1.99999.1). cabf_br_certificate_policies_present
# stays quiet (the extension is present); only the reserved-OID rule fires.
EXT_POLICIES_NORES="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:policies-no-reserved.example.com\n'
  printf 'certificatePolicies=1.3.6.1.4.1.99999.1\n'
} >"$EXT_POLICIES_NORES"
sign_csr "$HERE/cabf_br_policies_no_reserved.pem" "/CN=policies-no-reserved.example.com" 88 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_POLICIES_NORES"

# cabf_br_rsa_modulus_bits_multiple_of_8: an RSA modulus whose bit length is NOT a
# multiple of 8. openssl RSA keygen always yields byte-aligned moduli (the top
# octet has its high bit set, so an N-bit key has exactly N significant bits), so
# the non-octet-aligned modulus is produced by a DER patch: mint a 2056-bit key,
# CLEAR the high bit of the modulus's most-significant content octet AND drop the
# now-redundant 0x00 DER sign octet (x509-parser requires minimal INTEGER
# encoding, so the sign octet must be removed once the top bit is clear). That
# yields a strictly-minimal 2055-bit modulus INTEGER (2055 % 8 == 7 != 0). The
# removal shortens the INTEGER by one octet, so every enclosing definite-length
# header (the RSAPublicKey SEQUENCE, the subjectPublicKey BIT STRING, the
# SubjectPublicKeyInfo SEQUENCE, the TBSCertificate SEQUENCE, and the outer
# Certificate SEQUENCE) is recomputed via an ancestor-length walk. 2056 (not 2048)
# is chosen so the patched length 2055 stays >= 2048 and the floor lint
# hygiene_rsa_key_min_2048 (2048-bit minimum) stays quiet — ONLY the
# octet-alignment lint fires. The signature no longer matches, which is irrelevant
# — the linter parses structure, it does not verify signatures.
BR_RSA_MOD_KEY="$(mktemp)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2056 -out "$BR_RSA_MOD_KEY" 2>/dev/null
EXT_RSA_MOD="$(new_ext)"
make_leaf_ext "$EXT_RSA_MOD" "DNS:rsa-mod-not-oct.example.com"
BR_RSA_MOD_CSR="$(mktemp)"
BR_RSA_MOD_V3="$(mktemp)"
BR_RSA_MOD_DER="$(mktemp)"
openssl req -new -key "$BR_RSA_MOD_KEY" -subj "/CN=rsa-mod-not-oct.example.com" \
  -out "$BR_RSA_MOD_CSR" 2>/dev/null
openssl x509 -req -in "$BR_RSA_MOD_CSR" -signkey "$BR_RSA_MOD_KEY" \
  -out "$BR_RSA_MOD_V3" \
  -set_serial 89 -not_before "$BR_OK_NB" -not_after "$BR_OK_NA" -sha256 \
  -extfile "$EXT_RSA_MOD" 2>/dev/null
openssl x509 -in "$BR_RSA_MOD_V3" -outform DER -out "$BR_RSA_MOD_DER"
python3 - "$BR_RSA_MOD_DER" <<'PY'
import sys

def read_len(b, i):
    f = b[i]; i += 1
    if f < 0x80:
        return f, i
    n = f & 0x7f
    return int.from_bytes(b[i:i + n], 'big'), i + n

path = sys.argv[1]
orig = bytearray(open(path, "rb").read())
# 2056-bit modulus => 258 content octets (1 sign zero + 257 value octets),
# encoded as INTEGER tag 02, length 0x82 0x01 0x02, then 0x00 sign octet, then the
# 0xNN top value octet (high bit set).
marker = bytes.fromhex("0282010200")  # 02 82 01 02 00
i = orig.find(marker)
if i < 0:
    sys.exit("ERROR: could not locate 2056-bit RSA modulus INTEGER to patch")
int_tag = i                 # offset of the INTEGER tag (0x02)
sign_off = i + len(marker) - 1   # offset of the 0x00 sign octet
msb_off = sign_off + 1           # the true most-significant value octet
if orig[msb_off] & 0x80 == 0:
    sys.exit("ERROR: modulus top octet high bit already clear; unexpected key shape")

# Clear the high bit (2056 -> 2055 significant bits), then DELETE the now-redundant
# 0x00 sign octet so the INTEGER is minimally encoded (x509-parser requires this).
patched_msb = orig[msb_off] & 0x7F
vstart = sign_off  # the byte we will remove

# Find every enclosing ancestor header whose content range contains vstart. We
# recurse into CONSTRUCTED nodes and, specially, into the subjectPublicKey BIT
# STRING (tag 0x03, primitive) whose content is "unused-bits octet (0x00) followed
# by the DER-encoded RSAPublicKey SEQUENCE". Every such ancestor's definite length
# shrinks by one octet when the sign byte is removed.
ancestors = []

def rec(start, end):
    j = start
    while j < end:
        tag = orig[j]
        ln, c = read_len(orig, j + 1)
        e = c + ln
        if c <= vstart < e:
            if tag & 0x20:  # constructed (SEQUENCE / SET / explicit tags)
                ancestors.append(j)
                rec(c, e)
            elif tag == 0x03:  # BIT STRING: descend past the unused-bits octet
                ancestors.append(j)
                rec(c + 1, e)
        j = e

rec(0, len(orig))

delta = -1  # we remove exactly one octet (the sign byte)

# Build the new buffer: copy through, replacing the MSB value and dropping the
# sign octet. Order in memory: ... 02 82 01 02 | 00(sign) | NN(msb) ...
# Remove the sign octet (at sign_off) and write the patched MSB in its place.
data = bytearray(orig[:sign_off] + bytes([patched_msb]) + orig[msb_off + 1:])

def bump(b, hdr):
    f = b[hdr + 1]
    if f < 0x80:
        b[hdr + 1] = (f + delta) & 0xff
    else:
        n = f & 0x7f
        v = int.from_bytes(b[hdr + 2:hdr + 2 + n], 'big') + delta
        b[hdr + 2:hdr + 2 + n] = v.to_bytes(n, 'big')

# The INTEGER's own definite length (0x82 0x01 0x02 -> 0x82 0x01 0x01).
bump(data, int_tag)
# Every constructed ancestor (SEQUENCEs / BIT STRING) shrinks by one octet too.
for a in sorted(set(ancestors)):
    bump(data, a)

open(path, "wb").write(data)
PY
openssl x509 -inform DER -in "$BR_RSA_MOD_DER" -outform PEM \
  -out "$HERE/cabf_br_rsa_mod_not_oct.pem"
echo "wrote $HERE/cabf_br_rsa_mod_not_oct.pem (RSA modulus -> 2055 bits, not octet-aligned)"
rm -f "$BR_RSA_MOD_CSR" "$BR_RSA_MOD_V3" "$BR_RSA_MOD_DER" "$BR_RSA_MOD_KEY"

# cabf_br_rsa_public_exponent_in_range: RSA-2048 key with public exponent 3
# (< 65537), else compliant. Only the exponent-range rule fires.
BR_RSA_EXP_KEY="$(mktemp)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3 \
  -out "$BR_RSA_EXP_KEY" 2>/dev/null
EXT_RSA_EXP="$(new_ext)"
make_leaf_ext "$EXT_RSA_EXP" "DNS:rsa-exp-3.example.com"
BR_RSA_EXP_CSR="$(mktemp)"
openssl req -new -key "$BR_RSA_EXP_KEY" -subj "/CN=rsa-exp-3.example.com" \
  -out "$BR_RSA_EXP_CSR" 2>/dev/null
openssl x509 -req -in "$BR_RSA_EXP_CSR" -signkey "$BR_RSA_EXP_KEY" \
  -out "$HERE/cabf_br_rsa_exp_3.pem" \
  -set_serial 90 -not_before "$BR_OK_NB" -not_after "$BR_OK_NA" -sha256 \
  -extfile "$EXT_RSA_EXP" 2>/dev/null
rm -f "$BR_RSA_EXP_CSR" "$BR_RSA_EXP_KEY"
echo "wrote $HERE/cabf_br_rsa_exp_3.pem (RSA-2048, public exponent 3)"

# cabf_br_basic_constraints_present (Warn): leaf with NO BasicConstraints
# extension, else compliant. Fires a Warn from cabf_br_basic_constraints_present.
# Omitting BasicConstraints trips no rfc5280 rule (the RFC BC rules apply to CAs;
# a leaf without BC is structurally fine). serverAuth + SAN keep the rest quiet.
EXT_NO_BC="$(new_ext)"
{
  printf 'extendedKeyUsage=serverAuth\n'
  printf 'subjectAltName=DNS:no-basic-constraints.example.com\n'
} >"$EXT_NO_BC"
sign_csr "$HERE/cabf_br_no_basic_constraints.pem" "/CN=no-basic-constraints.example.com" 91 \
  "$BR_OK_NB" "$BR_OK_NA" "$EXT_NO_BC"

# ===========================================================================
# Feature 10: CA/Browser Forum S/MIME Baseline Requirements fixtures
# ===========================================================================
# The twelve cabf_smime_*.pem fixtures exercise the emailProtection-gated S/MIME
# lint source. Each is a SELF-SIGNED (subject == issuer) RSA-2048 / SHA-256 leaf
# that is S/MIME-compliant EXCEPT its one target violation. Shared shape:
#   - subject DN = /C=US/CN=<...>/emailAddress=user@example.com (stored order
#     C, CN, emailAddress)
#   - basicConstraints = CA:FALSE
#   - extendedKeyUsage = emailProtection
#   - keyUsage = critical, digitalSignature + keyEncipherment
#   - subjectKeyIdentifier = hash; authorityKeyIdentifier = keyid (== SKI, since
#     self-signed)
#   - crlDistributionPoints = URI:http://crl.example.com/smime.crl
#   - subjectAltName = email:user@example.com
# Extension order as emitted: BC, EKU, KU, SKI, AKI, CRL-DP, SAN.
#
# Shape was determined by `openssl x509 -text` over each committed fixture; the
# self-signed-with-keyid AKI and the per-fixture deviation each fixture's name
# encodes were read directly from the committed bytes.
#
# Fixed dates: all twelve use the BR_OK window (clock pinned by the test suite,
# see the header note) so hygiene_not_expired stays quiet against the pinned now.
#
# Serials: good=100, no_san=101, san_critical=102, cn_email_not_in_san=103,
# two_email_subject=104, no_key_usage=105, key_usage_not_critical=106,
# eku_server_auth=108, no_aki=109, no_crl_dp=110, crl_dp_ldap=111,
# bad_country=112 (serial 107 is intentionally unused — matches the committed set).
#
# bad_country is the ONE DER-byte-patched S/MIME fixture: openssl rejects a
# 3-character countryName via -subj (PrintableString maxsize=2), so a C=US
# self-signed cert is built and the SUBJECT countryName value is rewritten in the
# DER from "US" (13 02 55 53) to "USA" (13 03 55 53 41), recomputing every
# enclosing definite-length header. The ISSUER country stays "US" (only the first
# of the two country TLVs is left unpatched), so subject=C=USA / issuer=C=US,
# exactly as in the committed fixture. The length-changing patch invalidates the
# signature, which is irrelevant to a structural linter.

# One RSA-2048 key shared across all twelve S/MIME fixtures (their SKI is
# therefore identical — the S/MIME lints do not assert SKI uniqueness).
SMIME_KEY="$(mktemp)"
openssl genrsa -out "$SMIME_KEY" 2048 2>/dev/null

# make_smime_ext <out> <ku> <crl_dp|""> <san_line|""> [eku_override]
#
# Writes an S/MIME leaf extension config in the canonical extension order
# (BC, EKU, KU, SKI, AKI, CRL-DP, SAN). $ku is the keyUsage value (set "" to omit
# the KU extension entirely). $crl_dp is a full crlDistributionPoints value (e.g.
# "URI:http://...") or "" to omit CRL-DP. $san_line is a full subjectAltName value
# (e.g. "email:user@example.com" or "critical,email:user@example.com") or "" to
# omit the SAN. $5 (optional) overrides the extendedKeyUsage VALUE in its normal
# slot (default "emailProtection").
make_smime_ext() {
  local out="$1" ku="$2" crl="$3" san="$4" eku="${5:-emailProtection}"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'extendedKeyUsage=%s\n' "$eku"
    if [[ -n "$ku" ]]; then
      printf 'keyUsage=%s\n' "$ku"
    fi
    printf 'subjectKeyIdentifier=hash\n'
    printf 'authorityKeyIdentifier=keyid:always\n'
    if [[ -n "$crl" ]]; then
      printf 'crlDistributionPoints=%s\n' "$crl"
    fi
    if [[ -n "$san" ]]; then
      printf 'subjectAltName=%s\n' "$san"
    fi
  } >"$out"
}

# sign_smime <out.pem> <subject> <serial> <extfile>
#
# Self-signs an S/MIME CSR built from $SMIME_KEY (RSA-2048, SHA-256) with the
# BR_OK window. Self-signed so AKI keyid == SKI.
sign_smime() {
  local out="$1" subj="$2" serial="$3" extfile="$4"
  local csr
  csr="$(mktemp)"
  openssl req -new -key "$SMIME_KEY" -subj "$subj" -out "$csr" 2>/dev/null
  openssl x509 -req -in "$csr" -signkey "$SMIME_KEY" -out "$out" \
    -set_serial "$serial" -not_before "$BR_OK_NB" -not_after "$BR_OK_NA" -sha256 \
    -extfile "$extfile" 2>/dev/null
  rm -f "$csr"
  echo "wrote $out"
}

SMIME_CRL="URI:http://crl.example.com/smime.crl"
SMIME_KU="critical,digitalSignature,keyEncipherment"

# cabf_smime_good: clean S/MIME leaf, passes every S/MIME lint.
EXT_SM_GOOD="$(new_ext)"
make_smime_ext "$EXT_SM_GOOD" "$SMIME_KU" "$SMIME_CRL" "email:user@example.com"
sign_smime "$HERE/cabf_smime_good.pem" "/C=US/CN=user@example.com/emailAddress=user@example.com" \
  100 "$EXT_SM_GOOD"

# cabf_smime_no_san: SAN omitted entirely.
EXT_SM_NOSAN="$(new_ext)"
make_smime_ext "$EXT_SM_NOSAN" "$SMIME_KU" "$SMIME_CRL" ""
sign_smime "$HERE/cabf_smime_no_san.pem" "/C=US/CN=No San User/emailAddress=user@example.com" \
  101 "$EXT_SM_NOSAN"

# cabf_smime_san_critical: SAN marked critical.
EXT_SM_SANCRIT="$(new_ext)"
make_smime_ext "$EXT_SM_SANCRIT" "$SMIME_KU" "$SMIME_CRL" "critical,email:user@example.com"
sign_smime "$HERE/cabf_smime_san_critical.pem" "/C=US/CN=user@example.com/emailAddress=user@example.com" \
  102 "$EXT_SM_SANCRIT"

# cabf_smime_cn_email_not_in_san: CN is an email (cn-only@) absent from the SAN
# (SAN lists a DIFFERENT address other@).
EXT_SM_CNNOTIN="$(new_ext)"
make_smime_ext "$EXT_SM_CNNOTIN" "$SMIME_KU" "$SMIME_CRL" "email:other@example.com"
sign_smime "$HERE/cabf_smime_cn_email_not_in_san.pem" \
  "/C=US/CN=cn-only@example.com/emailAddress=user@example.com" 103 "$EXT_SM_CNNOTIN"

# cabf_smime_two_email_subject: subject carries TWO emailAddress RDNs.
EXT_SM_TWOEMAIL="$(new_ext)"
make_smime_ext "$EXT_SM_TWOEMAIL" "$SMIME_KU" "$SMIME_CRL" "email:user@example.com"
sign_smime "$HERE/cabf_smime_two_email_subject.pem" \
  "/C=US/CN=Two Email User/emailAddress=user@example.com/emailAddress=second@example.com" \
  104 "$EXT_SM_TWOEMAIL"

# cabf_smime_no_key_usage: KU extension omitted entirely.
EXT_SM_NOKU="$(new_ext)"
make_smime_ext "$EXT_SM_NOKU" "" "$SMIME_CRL" "email:user@example.com"
sign_smime "$HERE/cabf_smime_no_key_usage.pem" "/C=US/CN=No KU User/emailAddress=user@example.com" \
  105 "$EXT_SM_NOKU"

# cabf_smime_key_usage_not_critical: KU present but NOT critical.
EXT_SM_KUNONCRIT="$(new_ext)"
make_smime_ext "$EXT_SM_KUNONCRIT" "digitalSignature,keyEncipherment" "$SMIME_CRL" "email:user@example.com"
sign_smime "$HERE/cabf_smime_key_usage_not_critical.pem" \
  "/C=US/CN=KU NonCrit User/emailAddress=user@example.com" 106 "$EXT_SM_KUNONCRIT"

# cabf_smime_eku_server_auth: EKU adds serverAuth alongside emailProtection
# (prohibited for S/MIME), kept in the canonical EKU slot via the override.
EXT_SM_EKUSA="$(new_ext)"
make_smime_ext "$EXT_SM_EKUSA" "$SMIME_KU" "$SMIME_CRL" "email:user@example.com" \
  "emailProtection,serverAuth"
sign_smime "$HERE/cabf_smime_eku_server_auth.pem" \
  "/C=US/CN=Server Auth User/emailAddress=user@example.com" 108 "$EXT_SM_EKUSA"

# cabf_smime_no_aki: AuthorityKeyIdentifier omitted. Built via the extra-line
# slot so the default AKI line is replaced by the EKU line ONLY.
EXT_SM_NOAKI="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=emailProtection\n'
  printf 'keyUsage=%s\n' "$SMIME_KU"
  printf 'subjectKeyIdentifier=hash\n'
  printf 'crlDistributionPoints=%s\n' "$SMIME_CRL"
  printf 'subjectAltName=email:user@example.com\n'
} >"$EXT_SM_NOAKI"
sign_smime "$HERE/cabf_smime_no_aki.pem" "/C=US/CN=No AKI User/emailAddress=user@example.com" \
  109 "$EXT_SM_NOAKI"

# cabf_smime_no_crl_dp: CRL distribution points omitted.
EXT_SM_NOCRL="$(new_ext)"
make_smime_ext "$EXT_SM_NOCRL" "$SMIME_KU" "" "email:user@example.com"
sign_smime "$HERE/cabf_smime_no_crl_dp.pem" "/C=US/CN=No CRL User/emailAddress=user@example.com" \
  110 "$EXT_SM_NOCRL"

# cabf_smime_crl_dp_ldap: CRL-DP uses an ldap:// URI instead of http://.
EXT_SM_CRLLDAP="$(new_ext)"
make_smime_ext "$EXT_SM_CRLLDAP" "$SMIME_KU" "URI:ldap://crl.example.com/smime.crl" "email:user@example.com"
sign_smime "$HERE/cabf_smime_crl_dp_ldap.pem" "/C=US/CN=Ldap Crl User/emailAddress=user@example.com" \
  111 "$EXT_SM_CRLLDAP"

# cabf_smime_bad_country: subject countryName "USA" (3 chars). openssl rejects
# C=USA via -subj, so build a C=US self-signed cert and DER-patch the SUBJECT
# country value US -> USA (issuer left as US), recomputing enclosing lengths.
EXT_SM_BADC="$(new_ext)"
make_smime_ext "$EXT_SM_BADC" "$SMIME_KU" "$SMIME_CRL" "email:user@example.com"
SM_BADC_V3="$(mktemp)"
SM_BADC_DER="$(mktemp)"
sign_smime "$SM_BADC_V3" "/C=US/CN=Bad Country User/emailAddress=user@example.com" 112 "$EXT_SM_BADC"
openssl x509 -in "$SM_BADC_V3" -outform DER -out "$SM_BADC_DER"
python3 - "$SM_BADC_DER" <<'PY'
import sys

def read_len(b, i):
    f = b[i]; i += 1
    if f < 0x80:
        return f, i
    n = f & 0x7f
    return int.from_bytes(b[i:i + n], 'big'), i + n

path = sys.argv[1]
orig = bytearray(open(path, 'rb').read())
pat = bytes.fromhex("13025553")  # PrintableString, len 2, "US"
first = orig.find(pat)
second = orig.find(pat, first + 1)
if first < 0 or second < 0:
    sys.exit("ERROR: could not find both issuer+subject country TLVs to patch")
vstart = second  # patch the SUBJECT country (second occurrence); leave ISSUER "US".

# Collect every CONSTRUCTED ancestor header whose content range contains vstart.
ancestors = []

def rec(start, end):
    i = start
    while i < end:
        tag = orig[i]
        ln, c = read_len(orig, i + 1)
        e = c + ln
        if c <= vstart < e:
            if tag & 0x20:  # constructed
                ancestors.append(i)
                rec(c, e)
        i = e

rec(0, len(orig))

# Splice "US" -> "USA": 13 02 55 53 -> 13 03 55 53 41 (+1 byte).
delta = 1
data = bytearray(orig[:vstart] + bytes.fromhex("1303555341") + orig[vstart + 4:])

def bump(b, i):
    f = b[i + 1]
    if f < 0x80:
        b[i + 1] = (f + delta) & 0xff
    else:
        n = f & 0x7f
        v = int.from_bytes(b[i + 2:i + 2 + n], 'big') + delta
        b[i + 2:i + 2 + n] = v.to_bytes(n, 'big')

for a in sorted(set(ancestors)):
    bump(data, a)
open(path, 'wb').write(data)
PY
openssl x509 -inform DER -in "$SM_BADC_DER" -outform PEM -out "$HERE/cabf_smime_bad_country.pem"
echo "wrote $HERE/cabf_smime_bad_country.pem (subject countryName patched US -> USA)"
rm -f "$SM_BADC_V3" "$SM_BADC_DER"

# ===========================================================================
# Feature 11: CA/Browser Forum EXTENDED VALIDATION (EV) fixtures
# ===========================================================================
# The ten cabf_ev_*.pem fixtures exercise the EV-policy-gated lint source. Each
# is a SELF-SIGNED (subject == issuer) RSA-2048 / SHA-256 serverAuth leaf that is
# EV-compliant EXCEPT its one target violation. Shared shape:
#   - subject DN (stored order): C=US, jurisdictionCountryName=US
#     (1.3.6.1.4.1.311.60.2.1.3), businessCategory=Private Organization,
#     O=Example EV Inc, serialNumber=REG-12345,
#     organizationIdentifier=NTRUS-12345, CN=ev.example.com
#   - basicConstraints = CA:FALSE
#   - extendedKeyUsage = serverAuth
#   - certificatePolicies = the EV marker OID 1.3.6.1.4.1.99999.1.1
#   - subjectAltName = DNS:ev.example.com
#   - subjectKeyIdentifier = hash; NO AKI, NO CRL-DP.
# Extension order as emitted: BC, EKU, certPolicies, SAN, SKI.
#
# Shape was determined by `openssl x509 -text -nameopt multiline` over each
# committed fixture: the stored DN attribute order, the EV policy OID, the
# serverAuth EKU, the absence of AKI/CRL-DP, and the per-fixture deviation each
# fixture's name encodes were all read from the committed bytes.
#
# Fixed dates: nine use the BR_OK window; cabf_ev_validity_400_days uses VAL400
# (2026-06-01 -> 2027-07-06). Clock pinned by the test suite (see header note).
#
# Serials: good=110, org_name_missing=111, business_category_missing=112,
# business_category_invalid=113, jurisdiction_country_missing=114,
# serial_number_missing=115, wildcard_san=116, san_ip=117, validity_400_days=118,
# org_id_missing=119.

# One RSA-2048 key shared across all ten EV fixtures.
EV_KEY="$(mktemp)"
openssl genrsa -out "$EV_KEY" 2048 2>/dev/null

# The EV marker policy OID. The EV lint source self-gates on this OID being
# present in certificatePolicies.
EV_POLICY_OID="1.3.6.1.4.1.99999.1.1"

# make_ev_ext <out> <san_line>
#
# Writes an EV serverAuth leaf extension config with the EV policy OID. $san_line
# is a full subjectAltName value (e.g. "DNS:ev.example.com").
make_ev_ext() {
  local out="$1" san="$2"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'extendedKeyUsage=serverAuth\n'
    printf 'certificatePolicies=%s\n' "$EV_POLICY_OID"
    printf 'subjectAltName=%s\n' "$san"
    printf 'subjectKeyIdentifier=hash\n'
  } >"$out"
}

# sign_ev <out.pem> <subject> <serial> <not_before> <not_after> <extfile>
#
# Self-signs an EV CSR built from $EV_KEY (RSA-2048, SHA-256).
sign_ev() {
  local out="$1" subj="$2" serial="$3" nb="$4" na="$5" extfile="$6"
  local csr
  csr="$(mktemp)"
  openssl req -new -key "$EV_KEY" -subj "$subj" -out "$csr" 2>/dev/null
  openssl x509 -req -in "$csr" -signkey "$EV_KEY" -out "$out" \
    -set_serial "$serial" -not_before "$nb" -not_after "$na" -sha256 \
    -extfile "$extfile" 2>/dev/null
  rm -f "$csr"
  echo "wrote $out"
}

# Full EV subject DN building blocks (subject is passed as a single -subj string;
# openssl emits them in the order written, which matches the committed fixtures).
EV_C="/C=US"
EV_JC="/jurisdictionC=US"
EV_BC="/businessCategory=Private Organization"
EV_O="/O=Example EV Inc"
EV_SN="/serialNumber=REG-12345"
EV_OI="/organizationIdentifier=NTRUS-12345"
EV_CN="/CN=ev.example.com"

EV_SAN="DNS:ev.example.com"

# cabf_ev_good: full EV subject + EV policy + serverAuth. Passes every EV lint.
EXT_EV_GOOD="$(new_ext)"
make_ev_ext "$EXT_EV_GOOD" "$EV_SAN"
sign_ev "$HERE/cabf_ev_good.pem" "${EV_C}${EV_JC}${EV_BC}${EV_O}${EV_SN}${EV_OI}${EV_CN}" \
  110 "$BR_OK_NB" "$BR_OK_NA" "$EXT_EV_GOOD"

# cabf_ev_org_name_missing: organizationName (O) omitted.
EXT_EV_NOORG="$(new_ext)"
make_ev_ext "$EXT_EV_NOORG" "$EV_SAN"
sign_ev "$HERE/cabf_ev_org_name_missing.pem" "${EV_C}${EV_JC}${EV_BC}${EV_SN}${EV_OI}${EV_CN}" \
  111 "$BR_OK_NB" "$BR_OK_NA" "$EXT_EV_NOORG"

# cabf_ev_business_category_missing: businessCategory omitted.
EXT_EV_NOBC="$(new_ext)"
make_ev_ext "$EXT_EV_NOBC" "$EV_SAN"
sign_ev "$HERE/cabf_ev_business_category_missing.pem" "${EV_C}${EV_JC}${EV_O}${EV_SN}${EV_OI}${EV_CN}" \
  112 "$BR_OK_NB" "$BR_OK_NA" "$EXT_EV_NOBC"

# cabf_ev_business_category_invalid: businessCategory = "Sole Proprietor" (not one
# of the four EV-permitted values).
EXT_EV_BADBC="$(new_ext)"
make_ev_ext "$EXT_EV_BADBC" "$EV_SAN"
sign_ev "$HERE/cabf_ev_business_category_invalid.pem" \
  "${EV_C}${EV_JC}/businessCategory=Sole Proprietor${EV_O}${EV_SN}${EV_OI}${EV_CN}" \
  113 "$BR_OK_NB" "$BR_OK_NA" "$EXT_EV_BADBC"

# cabf_ev_jurisdiction_country_missing: jurisdictionCountryName omitted.
EXT_EV_NOJC="$(new_ext)"
make_ev_ext "$EXT_EV_NOJC" "$EV_SAN"
sign_ev "$HERE/cabf_ev_jurisdiction_country_missing.pem" "${EV_C}${EV_BC}${EV_O}${EV_SN}${EV_OI}${EV_CN}" \
  114 "$BR_OK_NB" "$BR_OK_NA" "$EXT_EV_NOJC"

# cabf_ev_serial_number_missing: subject serialNumber attribute omitted.
EXT_EV_NOSN="$(new_ext)"
make_ev_ext "$EXT_EV_NOSN" "$EV_SAN"
sign_ev "$HERE/cabf_ev_serial_number_missing.pem" "${EV_C}${EV_JC}${EV_BC}${EV_O}${EV_OI}${EV_CN}" \
  115 "$BR_OK_NB" "$BR_OK_NA" "$EXT_EV_NOSN"

# cabf_ev_wildcard_san: SAN adds a wildcard DNS:*.ev.example.com (prohibited for EV).
EXT_EV_WILD="$(new_ext)"
make_ev_ext "$EXT_EV_WILD" "DNS:ev.example.com,DNS:*.ev.example.com"
sign_ev "$HERE/cabf_ev_wildcard_san.pem" "${EV_C}${EV_JC}${EV_BC}${EV_O}${EV_SN}${EV_OI}${EV_CN}" \
  116 "$BR_OK_NB" "$BR_OK_NA" "$EXT_EV_WILD"

# cabf_ev_san_ip: SAN adds IP:8.8.8.8 (an IP address is prohibited for EV). NOTE:
# 8.8.8.8 is a PUBLIC routable address (NOT a reserved-range IP like 192.0.2.10),
# so it trips the EV no-IP-SAN rule WITHOUT also tripping any reserved-IP lint.
EXT_EV_IP="$(new_ext)"
make_ev_ext "$EXT_EV_IP" "DNS:ev.example.com,IP:8.8.8.8"
sign_ev "$HERE/cabf_ev_san_ip.pem" "${EV_C}${EV_JC}${EV_BC}${EV_O}${EV_SN}${EV_OI}${EV_CN}" \
  117 "$BR_OK_NB" "$BR_OK_NA" "$EXT_EV_IP"

# cabf_ev_validity_400_days: VAL400 window (2026-06-01 -> 2027-07-06, > the EV
# validity ceiling). Otherwise EV-compliant.
EXT_EV_VAL400="$(new_ext)"
make_ev_ext "$EXT_EV_VAL400" "$EV_SAN"
sign_ev "$HERE/cabf_ev_validity_400_days.pem" "${EV_C}${EV_JC}${EV_BC}${EV_O}${EV_SN}${EV_OI}${EV_CN}" \
  118 "$VAL400_NB" "$VAL400_NA" "$EXT_EV_VAL400"

# cabf_ev_org_id_missing: organizationIdentifier omitted.
EXT_EV_NOOI="$(new_ext)"
make_ev_ext "$EXT_EV_NOOI" "$EV_SAN"
sign_ev "$HERE/cabf_ev_org_id_missing.pem" "${EV_C}${EV_JC}${EV_BC}${EV_O}${EV_SN}${EV_CN}" \
  119 "$BR_OK_NB" "$BR_OK_NA" "$EXT_EV_NOOI"

# ===========================================================================
# leaf_no_server_auth.pem — clientAuth-only leaf (purpose-resolution tests)
# ===========================================================================
# Used by crates/cli/tests/purpose.rs: a self-signed non-CA leaf, RSA-2048 /
# SHA-256, v3, that carries extendedKeyUsage=clientAuth (NO serverAuth), a SAN
# whose dNSName == CN, and an SKI. Because it resolves to a non-serverAuth
# purpose, it must NOT trip any cabf_br lint under the purpose-gated engine.
#
# Shape (from `openssl x509 -text`): serial 51, CN=no-server-auth.example.com,
# VAL400 window (2026-06-01 -> 2027-07-06), CA:FALSE, EKU clientAuth, SKI hash,
# SAN DNS:no-server-auth.example.com, no KU, no AKI. Its own RSA-2048 key.
LNSA_KEY="$(mktemp)"
openssl genrsa -out "$LNSA_KEY" 2048 2>/dev/null
EXT_LNSA="$(new_ext)"
{
  printf 'basicConstraints=CA:FALSE\n'
  printf 'extendedKeyUsage=clientAuth\n'
  printf 'subjectAltName=DNS:no-server-auth.example.com\n'
  printf 'subjectKeyIdentifier=hash\n'
} >"$EXT_LNSA"
LNSA_CSR="$(mktemp)"
openssl req -new -key "$LNSA_KEY" -subj "/CN=no-server-auth.example.com" -out "$LNSA_CSR" 2>/dev/null
openssl x509 -req -in "$LNSA_CSR" -signkey "$LNSA_KEY" -out "$HERE/leaf_no_server_auth.pem" \
  -set_serial 51 -not_before "$VAL400_NB" -not_after "$VAL400_NA" -sha256 \
  -extfile "$EXT_LNSA" 2>/dev/null
echo "wrote $HERE/leaf_no_server_auth.pem (clientAuth-only leaf)"
rm -f "$LNSA_CSR"

cleanup_feature_10_11() {
  rm -f "$SMIME_KEY" "$EV_KEY" "$LNSA_KEY"
}
cleanup_feature_10_11

# ===========================================================================
# Feature 09: CA/Browser Forum CODE-SIGNING Baseline Requirements fixtures
# ===========================================================================
# FIXED DATES — NOT TIME-FRAGILE (the test suite pins the clock).
# ---------------------------------------------------------------------------
# The eight cabf_cs_*.pem fixtures use fixed windows chosen so that, against the
# PINNED reference clock, hygiene_not_expired stays quiet (notAfter after the
# pinned "now"). The non-validity fixtures use the CS_OK window
# 2026-06-01 -> 2027-06-01 (365d, <=460d). The two validity-violating fixtures
# bracket the pinned "now":
#     cabf_cs_validity_40_months  2024-06-01 -> 2027-10-01  (~40 months, >1188d)
#     cabf_cs_validity_500_days   2026-02-01 -> 2027-06-16  (500d, >460d, <=39mo)
# Because the cabf_cs isolation tests (crates/linter/tests/cabf_cs.rs) pin the
# reference clock to a fixed instant inside the CS windows, hygiene_not_expired
# is evaluated against that pinned "now" — not the wall clock — so these fixtures
# do NOT need annual regeneration. The fixed dates are kept for byte-reproducibility.
#
# Scoping note: the CS lints are NARROW (codeSigning-EKU-gated). Every CS leaf
# carries extendedKeyUsage=codeSigning, keyUsage=digitalSignature (critical),
# CA:FALSE, a hash SubjectKeyIdentifier, a non-empty CN, and NO SAN. They
# deliberately do NOT carry serverAuth, so under the raw registry the broad
# cabf_br_ext_key_usage_server_auth_present co-fires — that is the false positive
# `--purpose code-signing` suppresses, not a fixture defect (see cabf_cs.rs).
#
# Each fixture is otherwise CS-compliant EXCEPT its one target violation. Default
# key RSA-3072 / SHA-256. AIA = OCSP + CA Issuers; CRL-DP = one HTTP URI.

# Fresh keys for the CS section.
openssl genrsa -out "$CS_RSA3072_KEY" 3072 2>/dev/null
openssl genrsa -out "$CS_RSA2048_KEY" 2048 2>/dev/null
# Explicit (non-named) curve params so ec_named_curve() returns None: encode the
# P-256 parameters inline rather than by curve OID.
openssl ecparam -name prime256v1 -param_enc explicit -genkey -noout \
  -out "$CS_EC_KEY" 2>/dev/null

# make_cs_ext <out_extfile> <aia:0|1> <crl:0|1> [ku_override]
#
# Writes a code-signing leaf extension config: CA:FALSE, codeSigning EKU, a hash
# SubjectKeyIdentifier, and keyUsage=critical,digitalSignature (overridable via
# $4). NO SAN. AIA (OCSP + CA Issuers) and CRL-DP are each emitted only when the
# corresponding flag is 1.
make_cs_ext() {
  local out="$1" want_aia="$2" want_crl="$3" ku="${4:-critical,digitalSignature}"
  {
    printf 'basicConstraints=CA:FALSE\n'
    printf 'extendedKeyUsage=codeSigning\n'
    printf 'keyUsage=%s\n' "$ku"
    printf 'subjectKeyIdentifier=hash\n'
    if [[ "$want_aia" == "1" ]]; then
      printf 'authorityInfoAccess=OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://ca.example.com/ca.crt\n'
    fi
    if [[ "$want_crl" == "1" ]]; then
      printf 'crlDistributionPoints=URI:http://crl.example.com/cs.crl\n'
    fi
  } >"$out"
}

# sign_cs <out.pem> <key> <subject> <serial> <not_before> <not_after> <extfile>
#
# Self-signs a CS CSR built from the given key with SHA-256.
sign_cs() {
  local out="$1" key="$2" subj="$3" serial="$4" nb="$5" na="$6" extfile="$7"
  local csr
  csr="$(mktemp)"
  openssl req -new -key "$key" -subj "$subj" -out "$csr" 2>/dev/null
  openssl x509 -req -in "$csr" -signkey "$key" -out "$out" \
    -set_serial "$serial" -not_before "$nb" -not_after "$na" -sha256 \
    -extfile "$extfile" 2>/dev/null
  rm -f "$csr"
  echo "wrote $out"
}

# CS_OK: currently valid AND <=460d (365d). Used by every CS fixture whose target
# violation is NOT validity. EXPIRES 2027-06-01 — see the warning above.
CS_OK_NB="20260601000000Z"
CS_OK_NA="20270601000000Z"

# CS_40M: ~40-month window (>1188d) straddling now. notAfter in the future so
# not_expired stays quiet; only the CS validity-period lint fires.
CS_40M_NB="20240601000000Z"
CS_40M_NA="20271001000000Z"

# CS_500D: 500-day window (>460d, <=39 months) straddling now.
CS_500D_NB="20260201000000Z"
CS_500D_NA="20270616000000Z"

# cabf_cs_good: clean CS leaf — RSA-3072, critical digitalSignature KU, AIA +
# CRL-DP present, CS_OK window. Passes every CS lint.
EXT_CS_GOOD="$(new_ext)"
make_cs_ext "$EXT_CS_GOOD" 1 1
sign_cs "$HERE/cabf_cs_good.pem" "$CS_RSA3072_KEY" "/CN=cs-good.example.com" 90 \
  "$CS_OK_NB" "$CS_OK_NA" "$EXT_CS_GOOD"

# cabf_cs_missing_key_usage: KU asserts only keyEncipherment (NO digitalSignature)
# — violates the CS digitalSignature-required rule. Everything else CS-compliant.
EXT_CS_NOKU="$(new_ext)"
make_cs_ext "$EXT_CS_NOKU" 1 1 "critical,keyEncipherment"
sign_cs "$HERE/cabf_cs_missing_key_usage.pem" "$CS_RSA3072_KEY" \
  "/CN=cs-no-ku.example.com" 91 "$CS_OK_NB" "$CS_OK_NA" "$EXT_CS_NOKU"

# cabf_cs_rsa_2048: RSA-2048 key (< the CS 3072-bit minimum). Otherwise clean.
EXT_CS_RSA2048="$(new_ext)"
make_cs_ext "$EXT_CS_RSA2048" 1 1
sign_cs "$HERE/cabf_cs_rsa_2048.pem" "$CS_RSA2048_KEY" \
  "/CN=cs-rsa-2048.example.com" 92 "$CS_OK_NB" "$CS_OK_NA" "$EXT_CS_RSA2048"

# cabf_cs_ecdsa_bad_curve: EC P-256 key with EXPLICIT (non-named) params, so
# ec_named_curve() returns None and the CS curve-allowlist lint fires. Otherwise
# clean (AIA + CRL-DP, CS_OK window).
EXT_CS_EC="$(new_ext)"
make_cs_ext "$EXT_CS_EC" 1 1
sign_cs "$HERE/cabf_cs_ecdsa_bad_curve.pem" "$CS_EC_KEY" \
  "/CN=cs-ec-explicit.example.com" 93 "$CS_OK_NB" "$CS_OK_NA" "$EXT_CS_EC"

# cabf_cs_validity_40_months: ~40-month window straddling now (>1188d). Violates
# ONLY the CS validity-period lint.
EXT_CS_40M="$(new_ext)"
make_cs_ext "$EXT_CS_40M" 1 1
sign_cs "$HERE/cabf_cs_validity_40_months.pem" "$CS_RSA3072_KEY" \
  "/CN=cs-validity-40m.example.com" 94 "$CS_40M_NB" "$CS_40M_NA" "$EXT_CS_40M"

# cabf_cs_validity_500_days: 500-day window straddling now (>460d, <=39 months).
EXT_CS_500D="$(new_ext)"
make_cs_ext "$EXT_CS_500D" 1 1
sign_cs "$HERE/cabf_cs_validity_500_days.pem" "$CS_RSA3072_KEY" \
  "/CN=cs-validity-500d.example.com" 95 "$CS_500D_NB" "$CS_500D_NA" "$EXT_CS_500D"

# cabf_cs_no_aia: clean CS leaf with NO AIA (CRL-DP kept). Violates ONLY the CS
# AIA-required lint.
EXT_CS_NOAIA="$(new_ext)"
make_cs_ext "$EXT_CS_NOAIA" 0 1
sign_cs "$HERE/cabf_cs_no_aia.pem" "$CS_RSA3072_KEY" \
  "/CN=cs-no-aia.example.com" 96 "$CS_OK_NB" "$CS_OK_NA" "$EXT_CS_NOAIA"

# cabf_cs_no_crl: clean CS leaf with NO CRL-DP (AIA kept). Violates ONLY the CS
# CRL-DP-required lint.
EXT_CS_NOCRL="$(new_ext)"
make_cs_ext "$EXT_CS_NOCRL" 1 0
sign_cs "$HERE/cabf_cs_no_crl.pem" "$CS_RSA3072_KEY" \
  "/CN=cs-no-crl.example.com" 97 "$CS_OK_NB" "$CS_OK_NA" "$EXT_CS_NOCRL"

# ===========================================================================
# Feature 13 — POST-QUANTUM (ML-DSA / SLH-DSA) FIXTURES
# ===========================================================================
#
# These exercise the universal `pqc` lint source (RuleSource::Pqc). Each pqc
# lint self-gates on the SPKI algorithm being an ML-DSA / SLH-DSA arc member, so
# these are the ONLY fixtures that engage the gate — every existing RSA/EC
# fixture stays NotApplicable for all five pqc lints (the no-cascade property).
#
# ⚠️  openssl 3.5+ REQUIRED (verified on 3.6.2). ML-DSA / SLH-DSA key and cert
#     generation is native in openssl 3.5+. The version is checked below and the
#     script aborts loudly on an older openssl so a missing-algorithm failure is
#     diagnosable rather than silent.
#
# ⚠️  INDEPENDENT-ORACLE RULE: every PQC fixture is generated with openssl,
#     NEVER with the user's cert-bar tool. The linter must remain an independent
#     checker over cert-bar's PQC output.
#
# ℹ️  FIXED DATES — NOT TIME-FRAGILE: the two clean PQC leaves (and every
#     violating PQC leaf) use the BR_OK window (2026-06-01 -> 2027-06-01) so that,
#     against the PINNED reference clock used by the pqc.rs isolation tests, ONLY
#     the single intended pqc rule fires (not hygiene_not_expired). Because the
#     clock is pinned (not the wall clock), these fixtures do NOT need annual
#     regeneration; the fixed window is kept for byte-reproducibility.
#
# Fixtures produced (7):
#   - pqc_mldsa_good.pem        clean ML-DSA-65 leaf (openssl-native). Passes all
#                               five pqc lints: params absent, 1952-byte key,
#                               digitalSignature-only KU, CA:FALSE.
#   - pqc_slhdsa_good.pem       clean SLH-DSA-SHA2-128s leaf (openssl-native).
#                               Passes all five pqc lints: params absent, 32-byte
#                               key, digitalSignature-only KU, CA:FALSE.
#   - pqc_bad_key_usage.pem     ML-DSA-65 leaf asserting keyEncipherment
#                               (openssl-native config). Violates ONLY
#                               pqc_key_usage_consistency (Error path).
#   - pqc_spki_params_present.pem   DER BYTE-PATCH of pqc_mldsa_good: a NULL
#                               (05 00) is spliced into the SPKI
#                               AlgorithmIdentifier after the OID and all
#                               enclosing SEQUENCE lengths recomputed. openssl
#                               follows the LAMPS profile and will not emit a
#                               present parameters field, so this requires a
#                               patch. Violates ONLY pqc_spki_parameters_absent.
#   - pqc_sig_params_present.pem    DER BYTE-PATCH of pqc_mldsa_good: a NULL is
#                               spliced into the OUTER Certificate.signatureAlgorithm
#                               (the field x509-parser exposes as
#                               signature_algorithm) and lengths recomputed.
#                               Patch-only for the same reason. Violates ONLY
#                               pqc_signature_parameters_absent.
#   - pqc_bad_key_length.pem    DER BYTE-PATCH of pqc_mldsa_good: one byte is
#                               dropped from the end of the SPKI subjectPublicKey
#                               BIT STRING (1952 -> 1951) and lengths recomputed.
#                               This also breaks the signature, which is
#                               irrelevant to a structural linter (it never
#                               verifies signatures). Patch-only. Violates ONLY
#                               pqc_public_key_length.
#   - pqc_unknown_param_set.pem DER BYTE-PATCH of pqc_slhdsa_good: the final arc
#                               byte of the SPKI OID is flipped from .20 (0x14,
#                               SLH-DSA-SHA2-128s) to .32 (0x20), an
#                               UNASSIGNED slot in the SLH-DSA arc. This is a
#                               length-preserving single-byte flip (no length
#                               recomputation). The gate still engages (arc
#                               member), the length lint stays silent (no known
#                               length for an unknown set). Violates ONLY
#                               pqc_algorithm_known.
#
# The four byte-patched fixtures are produced by an in-script Python3 DER helper
# (PQC_DERLIB below) that re-encodes the lengths of every enclosing SEQUENCE so
# the resulting certificate still parses. This mirrors the byte-patch approach
# used for rfc5280_version_not_v3 / rfc5280_country_not_printable above.

# openssl 3.5+ guard (ML-DSA / SLH-DSA are native only on 3.5+).
PQC_OPENSSL_VER="$(openssl version | awk '{print $2}')"
PQC_OPENSSL_MAJOR="${PQC_OPENSSL_VER%%.*}"
PQC_OPENSSL_REST="${PQC_OPENSSL_VER#*.}"
PQC_OPENSSL_MINOR="${PQC_OPENSSL_REST%%.*}"
if [[ "$PQC_OPENSSL_MAJOR" -lt 3 ]] ||
  { [[ "$PQC_OPENSSL_MAJOR" -eq 3 ]] && [[ "$PQC_OPENSSL_MINOR" -lt 5 ]]; }; then
  echo "ERROR: the PQC fixtures require openssl 3.5+ for native ML-DSA / SLH-DSA;" >&2
  echo "       found openssl $PQC_OPENSSL_VER. Upgrade openssl and re-run." >&2
  exit 1
fi

# Reusable in-script Python3 DER toolkit for the four byte-patched PQC fixtures.
# Walks the certificate's TLV tree, replaces a sub-range, and re-encodes the
# lengths of all enclosing SEQUENCEs so the output still parses.
PQC_DERLIB="$(mktemp /tmp/pqc_derlib.XXXXXX.py)"
cat >"$PQC_DERLIB" <<'PYEOF'
"""Minimal DER toolkit for the PQC fixture byte-patchers (length-recomputing)."""

def read_len(b, i):
    first = b[i]; i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7f
    return int.from_bytes(b[i:i + n], 'big'), i + n


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(out)]) + out


class Node:
    def __init__(self, buf, start):
        self.buf = buf
        self.start = start
        self.tag = buf[start]
        self.length, self.content = read_len(buf, start + 1)
        self.end = self.content + self.length

    def children(self):
        res, i = [], self.content
        while i < self.end:
            c = Node(self.buf, i)
            res.append(c)
            i = c.end
        return res


def reencode(tag, content):
    return bytes([tag]) + enc_len(len(content)) + content


def cert_parts(der):
    root = Node(der, 0)
    tbs, sigalg, sigval = root.children()
    return root, tbs, sigalg, sigval


def rebuild_cert(new_tbs_content, sigalg, sigval):
    tbs = reencode(0x30, new_tbs_content)
    a = sigalg.buf[sigalg.start:sigalg.end]
    v = sigval.buf[sigval.start:sigval.end]
    return reencode(0x30, tbs + a + v)
PYEOF

# --- clean ML-DSA-65 leaf (openssl-native) ---------------------------------
PQC_MLDSA_KEY="$(mktemp)"
openssl genpkey -algorithm ML-DSA-65 -out "$PQC_MLDSA_KEY" >/dev/null 2>&1
PQC_MLDSA_CNF="$(mktemp)"
cat >"$PQC_MLDSA_CNF" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = pqc-mldsa.example.com
[v3]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectAltName = DNS:pqc-mldsa.example.com
EOF
openssl req -new -x509 -key "$PQC_MLDSA_KEY" -out "$HERE/pqc_mldsa_good.pem" \
  -config "$PQC_MLDSA_CNF" -set_serial 200 \
  -not_before 20260601000000Z -not_after 20270601000000Z >/dev/null 2>&1
echo "wrote $HERE/pqc_mldsa_good.pem (clean ML-DSA-65 leaf, openssl-native)"

# --- clean SLH-DSA-SHA2-128s leaf (openssl-native) -------------------------
PQC_SLHDSA_KEY="$(mktemp)"
openssl genpkey -algorithm SLH-DSA-SHA2-128s -out "$PQC_SLHDSA_KEY" >/dev/null 2>&1
PQC_SLHDSA_CNF="$(mktemp)"
sed 's/pqc-mldsa/pqc-slhdsa/g' "$PQC_MLDSA_CNF" >"$PQC_SLHDSA_CNF"
openssl req -new -x509 -key "$PQC_SLHDSA_KEY" -out "$HERE/pqc_slhdsa_good.pem" \
  -config "$PQC_SLHDSA_CNF" -set_serial 201 \
  -not_before 20260601000000Z -not_after 20270601000000Z >/dev/null 2>&1
echo "wrote $HERE/pqc_slhdsa_good.pem (clean SLH-DSA-SHA2-128s leaf, openssl-native)"

# --- pqc_bad_key_usage: ML-DSA-65 leaf asserting keyEncipherment (native) --
PQC_BADKU_CNF="$(mktemp)"
sed 's/keyUsage = critical,digitalSignature/keyUsage = critical,digitalSignature,keyEncipherment/' \
  "$PQC_MLDSA_CNF" >"$PQC_BADKU_CNF"
openssl req -new -x509 -key "$PQC_MLDSA_KEY" -out "$HERE/pqc_bad_key_usage.pem" \
  -config "$PQC_BADKU_CNF" -set_serial 202 \
  -not_before 20260601000000Z -not_after 20270601000000Z >/dev/null 2>&1
echo "wrote $HERE/pqc_bad_key_usage.pem (ML-DSA-65 leaf with keyEncipherment KU, native)"

# --- DER-patched fixtures (openssl will not emit these deviations natively) -
PQC_MLDSA_DER="$(mktemp)"
PQC_SLHDSA_DER="$(mktemp)"
openssl x509 -in "$HERE/pqc_mldsa_good.pem" -outform DER -out "$PQC_MLDSA_DER"
openssl x509 -in "$HERE/pqc_slhdsa_good.pem" -outform DER -out "$PQC_SLHDSA_DER"

# pqc_spki_params_present: splice a NULL into the SPKI AlgorithmIdentifier.
PQC_PATCH_OUT="$(mktemp)"
python3 - "$PQC_DERLIB" "$PQC_MLDSA_DER" "$PQC_PATCH_OUT" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("derlib", sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
der = bytearray(open(sys.argv[2], 'rb').read())
_, tbs, sigalg, sigval = d.cert_parts(der)
spki = tbs.children()[6]
algid, bitstr = spki.children()
oid = algid.children()[0]
new_algid = d.reencode(0x30, der[algid.content:oid.end] + bytes([0x05, 0x00]))
new_spki = d.reencode(0x30, new_algid + der[bitstr.start:bitstr.end])
new_tbs = der[tbs.content:spki.start] + new_spki + der[spki.end:tbs.end]
open(sys.argv[3], 'wb').write(d.rebuild_cert(new_tbs, sigalg, sigval))
PY
openssl x509 -inform DER -in "$PQC_PATCH_OUT" -outform PEM \
  -out "$HERE/pqc_spki_params_present.pem"
echo "wrote $HERE/pqc_spki_params_present.pem (SPKI AlgorithmIdentifier NULL spliced in)"

# pqc_sig_params_present: splice a NULL into the OUTER signatureAlgorithm.
python3 - "$PQC_DERLIB" "$PQC_MLDSA_DER" "$PQC_PATCH_OUT" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("derlib", sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
der = bytearray(open(sys.argv[2], 'rb').read())
_, tbs, sigalg, sigval = d.cert_parts(der)
oid = sigalg.children()[0]
new_sigalg = d.reencode(0x30, der[sigalg.content:oid.end] + bytes([0x05, 0x00]))
out = d.reencode(0x30, der[tbs.start:tbs.end] + new_sigalg + der[sigval.start:sigval.end])
open(sys.argv[3], 'wb').write(out)
PY
openssl x509 -inform DER -in "$PQC_PATCH_OUT" -outform PEM \
  -out "$HERE/pqc_sig_params_present.pem"
echo "wrote $HERE/pqc_sig_params_present.pem (outer signatureAlgorithm NULL spliced in)"

# pqc_bad_key_length: drop one byte from the SPKI public-key BIT STRING.
python3 - "$PQC_DERLIB" "$PQC_MLDSA_DER" "$PQC_PATCH_OUT" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("derlib", sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
der = bytearray(open(sys.argv[2], 'rb').read())
_, tbs, sigalg, sigval = d.cert_parts(der)
spki = tbs.children()[6]
algid, bitstr = spki.children()
bs = der[bitstr.content:bitstr.end]
assert bs[0] == 0x00, "expected 0 unused bits in the BIT STRING"
new_bitstr = d.reencode(0x03, bs[:-1])          # drop one trailing key byte (1952 -> 1951)
new_spki = d.reencode(0x30, der[algid.start:algid.end] + new_bitstr)
new_tbs = der[tbs.content:spki.start] + new_spki + der[spki.end:tbs.end]
open(sys.argv[3], 'wb').write(d.rebuild_cert(new_tbs, sigalg, sigval))
PY
openssl x509 -inform DER -in "$PQC_PATCH_OUT" -outform PEM \
  -out "$HERE/pqc_bad_key_length.pem"
echo "wrote $HERE/pqc_bad_key_length.pem (SPKI public key truncated 1952 -> 1951 bytes)"

# pqc_unknown_param_set: flip the SPKI OID arc byte .20 -> .32 (unassigned slot).
python3 - "$PQC_DERLIB" "$PQC_SLHDSA_DER" "$PQC_PATCH_OUT" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("derlib", sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
der = bytearray(open(sys.argv[2], 'rb').read())
_, tbs, _sigalg, _sigval = d.cert_parts(der)
spki = tbs.children()[6]
oid = spki.children()[0].children()[0]
last = oid.end - 1
assert der[last] == 0x14, "expected SLH-DSA-SHA2-128s SPKI arc byte .20 (0x14)"
der[last] = 0x20                                # .20 -> .32 (unassigned SLH-DSA slot)
open(sys.argv[3], 'wb').write(der)
PY
openssl x509 -inform DER -in "$PQC_PATCH_OUT" -outform PEM \
  -out "$HERE/pqc_unknown_param_set.pem"
echo "wrote $HERE/pqc_unknown_param_set.pem (SPKI OID arc .20 -> .32, unassigned slot)"

rm -f "$PQC_DERLIB" "$PQC_MLDSA_KEY" "$PQC_MLDSA_CNF" "$PQC_SLHDSA_KEY" \
  "$PQC_SLHDSA_CNF" "$PQC_BADKU_CNF" "$PQC_MLDSA_DER" "$PQC_SLHDSA_DER" \
  "$PQC_PATCH_OUT"

# ===========================================================================
# Feature 16 — POST-QUANTUM ML-KEM (FIPS 203) KEY/CERT FIXTURES
# ===========================================================================
#
# These exercise the four feature-16 `pqc_mlkem_*` lints (still under the
# universal RuleSource::Pqc). Each ML-KEM lint self-gates on the SPKI algorithm
# being an ML-KEM "kems"-arc member (PublicKeyAlg::MlKem), so these are the ONLY
# fixtures that engage that gate — every existing RSA/EC/ML-DSA/SLH-DSA fixture
# stays NotApplicable for all four ML-KEM lints (the no-cascade property), and
# the five feature-13 *signature* lints stay NotApplicable on these ML-KEM keys.
#
# ⚠️  openssl 3.5+ REQUIRED (verified on 3.6.2). Re-uses the PQC version guard
#     above (this section runs after it). ML-KEM key generation is native; an
#     ML-KEM cert is minted by an ML-DSA CA via `x509 -req -force_pubkey` (see
#     below), since ML-KEM keys CANNOT self-sign or sign their own CSR.
#
# ⚠️  -force_pubkey RECIPE (architect-verified, OpenSSL 3.6.2): ML-KEM keys are
#     key-establishment only and cannot produce a signature, so neither
#     `req -x509` (self-sign) nor signing a CSR works. The working native path:
#       1. an ML-DSA CA (signer) self-signs a CA cert;
#       2. an ML-KEM-768 key is generated and its public key exported (PEM);
#       3. a DUMMY CSR is signed with the CA's own ML-DSA key; the ML-KEM public
#          key is substituted as the certificate SPKI via `-force_pubkey`.
#     The result is a valid cert with `Public Key Algorithm: ML-KEM-768` and an
#     ABSENT SPKI parameters field (LAMPS profile). The clean leaf is therefore
#     openssl-native (NO byte-patching). The CA's ML-DSA private key is throwaway
#     and not committed; only the leaf fixtures are kept.
#
# ℹ️  FIXED DATES — NOT TIME-FRAGILE: every ML-KEM leaf uses the BR_OK window
#     (2026-06-01 -> 2027-06-01). The pqc-filtered isolation runs are
#     clock-independent; the full-registry no-cascade runs pin the clock to
#     TEST_NOW = 1796083200 (2026-12-01) via default_registry_with_now(...) /
#     CLI --now 1796083200, so hygiene_not_expired never trips. The clean leaf's
#     subject CN == its SAN DNS (pqc-mlkem.example.com) so that EVEN under a
#     forced cabf_br run the leaf trips no cabf_br_cn_in_san. Because the clock is
#     pinned, these fixtures do NOT need annual regeneration; the fixed window is
#     kept for byte-reproducibility.
#
# ML-KEM-768 encapsulation-key length = 1184 bytes (FIPS 203 §8; the SPKI BIT
# STRING content is 1185 octets = 1 unused-bits octet + 1184 raw key octets).
#
# Fixtures produced (5):
#   - pqc_mlkem_good.pem            clean ML-KEM-768 leaf (openssl-native via
#                                   -force_pubkey): params absent, 1184-byte key,
#                                   keyEncipherment KU, CA:FALSE. Passes all 4
#                                   ML-KEM lints. NO byte-patching.
#   - pqc_mlkem_bad_key_usage.pem   ML-KEM-768 leaf asserting
#                                   digitalSignature + keyEncipherment KU
#                                   (openssl-native config). The forbidden
#                                   signing bit Errors; keyEncipherment suppresses
#                                   the missing-encryption-bit Warn, so this
#                                   isolates EXACTLY pqc_mlkem_key_usage_consistency
#                                   (one Error finding).
#   - pqc_mlkem_unknown_param_set.pem   DER BYTE-PATCH of pqc_mlkem_good: the final
#                                   SPKI OID arc byte is flipped .2 (0x02,
#                                   ML-KEM-768) -> .4 (0x04), an UNASSIGNED slot in
#                                   the ML-KEM "kems" arc. Length-preserving single
#                                   byte flip (no length recomputation). The gate
#                                   still engages (arc member); the length lint
#                                   stays silent (no known length for an unknown
#                                   set). Violates ONLY pqc_mlkem_algorithm_known.
#   - pqc_mlkem_spki_params_present.pem  DER BYTE-PATCH of pqc_mlkem_good: a NULL
#                                   (05 00) is spliced into the SPKI
#                                   AlgorithmIdentifier after the OID and all
#                                   enclosing SEQUENCE lengths recomputed. openssl
#                                   follows the LAMPS profile (absent params) so
#                                   this requires a patch. Violates ONLY
#                                   pqc_mlkem_spki_parameters_absent.
#   - pqc_mlkem_bad_key_length.pem  DER BYTE-PATCH of pqc_mlkem_good: one byte is
#                                   dropped from the end of the SPKI
#                                   subjectPublicKey BIT STRING (1184 -> 1183) and
#                                   lengths recomputed. Violates ONLY
#                                   pqc_mlkem_public_key_length.
#
# ⚠️  BYTE-PATCH CAVEAT: the three DER-patched ML-KEM fixtures alter the SPKI,
#     which is covered by the issuer's signature over the TBSCertificate — so the
#     CA signature no longer verifies on those three. This is acceptable: the
#     linter is a STRUCTURAL checker and never verifies certificate signatures.
#     (The ML-KEM lints all gate on / read structure, not signatures.) The clean
#     leaf and the bad-KU leaf are NOT patched and verify against the CA.
#
# Re-uses the PQC_DERLIB helper pattern; a local copy is created here so this
# section is self-contained (the feature-13 copy was already rm'd above).

# openssl 3.5+ guard (ML-KEM is native only on 3.5+); same check as the PQC
# section, repeated so this block is self-contained if reordered.
MLKEM_OPENSSL_VER="$(openssl version | awk '{print $2}')"
MLKEM_OPENSSL_MAJOR="${MLKEM_OPENSSL_VER%%.*}"
MLKEM_OPENSSL_REST="${MLKEM_OPENSSL_VER#*.}"
MLKEM_OPENSSL_MINOR="${MLKEM_OPENSSL_REST%%.*}"
if [[ "$MLKEM_OPENSSL_MAJOR" -lt 3 ]] ||
  { [[ "$MLKEM_OPENSSL_MAJOR" -eq 3 ]] && [[ "$MLKEM_OPENSSL_MINOR" -lt 5 ]]; }; then
  echo "ERROR: the ML-KEM fixtures require openssl 3.5+ for native ML-KEM / ML-DSA;" >&2
  echo "       found openssl $MLKEM_OPENSSL_VER. Upgrade openssl and re-run." >&2
  exit 1
fi

# Local DER toolkit (length-recomputing) for the three ML-KEM byte-patches.
MLKEM_DERLIB="$(mktemp /tmp/mlkem_derlib.XXXXXX.py)"
cat >"$MLKEM_DERLIB" <<'PYEOF'
"""Minimal DER toolkit for the ML-KEM fixture byte-patchers (length-recomputing)."""

def read_len(b, i):
    first = b[i]; i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7f
    return int.from_bytes(b[i:i + n], 'big'), i + n


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(out)]) + out


class Node:
    def __init__(self, buf, start):
        self.buf = buf
        self.start = start
        self.tag = buf[start]
        self.length, self.content = read_len(buf, start + 1)
        self.end = self.content + self.length

    def children(self):
        res, i = [], self.content
        while i < self.end:
            c = Node(self.buf, i)
            res.append(c)
            i = c.end
        return res


def reencode(tag, content):
    return bytes([tag]) + enc_len(len(content)) + content


def cert_parts(der):
    root = Node(der, 0)
    tbs, sigalg, sigval = root.children()
    return root, tbs, sigalg, sigval


def rebuild_cert(new_tbs_content, sigalg, sigval):
    tbs = reencode(0x30, new_tbs_content)
    a = sigalg.buf[sigalg.start:sigalg.end]
    v = sigval.buf[sigval.start:sigval.end]
    return reencode(0x30, tbs + a + v)


def spki_node(der):
    """Return the SubjectPublicKeyInfo node of a v3 cert (tbs child index 6:
    version[0], serial, sigalg, issuer, validity, subject, SPKI, ...)."""
    _, tbs, _, _ = cert_parts(der)
    return tbs.children()[6]
PYEOF

MLKEM_WORK="$(mktemp -d)"
MK() { printf '%s/%s' "$MLKEM_WORK" "$1"; }

# 1. ML-DSA CA (signer). Self-signed; never committed.
openssl genpkey -algorithm ML-DSA-65 -out "$(MK ca.key)" >/dev/null 2>&1
openssl req -new -x509 -key "$(MK ca.key)" -subj "/CN=mlkem-test-ca" \
  -not_before 20260601000000Z -not_after 20270601000000Z -out "$(MK ca.pem)" >/dev/null 2>&1

# 2. ML-KEM-768 leaf key + exported public key.
openssl genpkey -algorithm ML-KEM-768 -out "$(MK mlkem.key)" >/dev/null 2>&1
openssl pkey -in "$(MK mlkem.key)" -pubout -out "$(MK mlkem.pub.pem)" >/dev/null 2>&1

# 3. Dummy CSR signed by the CA's ML-DSA key (CN == SAN so cabf_br_cn_in_san stays
#    quiet even under a forced cabf_br run).
openssl req -new -key "$(MK ca.key)" -subj "/CN=pqc-mlkem.example.com" \
  -out "$(MK dummy.csr)" >/dev/null 2>&1

# clean leaf ext: keyEncipherment KU, CA:FALSE, SAN == CN.
cat >"$(MK ext_good.cnf)" <<'EOF'
[v3]
basicConstraints = critical,CA:FALSE
keyUsage = critical,keyEncipherment
subjectAltName = DNS:pqc-mlkem.example.com
EOF

# --- pqc_mlkem_good.pem (openssl-native, -force_pubkey) ---------------------
openssl x509 -req -in "$(MK dummy.csr)" -CA "$(MK ca.pem)" -CAkey "$(MK ca.key)" \
  -force_pubkey "$(MK mlkem.pub.pem)" -extfile "$(MK ext_good.cnf)" -extensions v3 \
  -set_serial 210 -not_before 20260601000000Z -not_after 20270601000000Z \
  -out "$HERE/pqc_mlkem_good.pem" >/dev/null 2>&1
echo "wrote $HERE/pqc_mlkem_good.pem (clean ML-KEM-768 leaf, openssl-native -force_pubkey)"

# --- pqc_mlkem_bad_key_usage.pem (openssl-native config) -------------------
# digitalSignature (forbidden signing bit -> Error) + keyEncipherment (so the
# missing-encryption Warn is suppressed; isolates exactly one Error).
cat >"$(MK ext_badku.cnf)" <<'EOF'
[v3]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
subjectAltName = DNS:pqc-mlkem.example.com
EOF
openssl x509 -req -in "$(MK dummy.csr)" -CA "$(MK ca.pem)" -CAkey "$(MK ca.key)" \
  -force_pubkey "$(MK mlkem.pub.pem)" -extfile "$(MK ext_badku.cnf)" -extensions v3 \
  -set_serial 214 -not_before 20260601000000Z -not_after 20270601000000Z \
  -out "$HERE/pqc_mlkem_bad_key_usage.pem" >/dev/null 2>&1
echo "wrote $HERE/pqc_mlkem_bad_key_usage.pem (ML-KEM-768 leaf with digitalSignature KU, native)"

# --- DER-patched ML-KEM fixtures (openssl will not emit these natively) -----
openssl x509 -in "$HERE/pqc_mlkem_good.pem" -outform DER -out "$(MK good.der)" >/dev/null 2>&1

# pqc_mlkem_unknown_param_set: flip the SPKI OID arc byte .2 -> .4 (unassigned).
python3 - "$MLKEM_DERLIB" "$(MK good.der)" "$(MK unknown.der)" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("derlib", sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
der = bytearray(open(sys.argv[2], 'rb').read())
spki = d.spki_node(der)
oid = spki.children()[0].children()[0]
last = oid.end - 1
assert der[last] == 0x02, "expected ML-KEM-768 SPKI arc byte .2 (0x02)"
der[last] = 0x04                                # .2 -> .4 (unassigned ML-KEM slot)
open(sys.argv[3], 'wb').write(der)
PY
openssl x509 -inform DER -in "$(MK unknown.der)" -outform PEM \
  -out "$HERE/pqc_mlkem_unknown_param_set.pem"
echo "wrote $HERE/pqc_mlkem_unknown_param_set.pem (SPKI OID arc .2 -> .4, unassigned slot)"

# pqc_mlkem_spki_params_present: splice a NULL into the SPKI AlgorithmIdentifier.
python3 - "$MLKEM_DERLIB" "$(MK good.der)" "$(MK params.der)" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("derlib", sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
der = bytearray(open(sys.argv[2], 'rb').read())
_, tbs, sigalg, sigval = d.cert_parts(der)
spki = d.spki_node(der)
algid, bitstr = spki.children()
oid = algid.children()[0]
new_algid = d.reencode(0x30, der[algid.content:oid.end] + bytes([0x05, 0x00]))
new_spki = d.reencode(0x30, new_algid + der[bitstr.start:bitstr.end])
new_tbs = der[tbs.content:spki.start] + new_spki + der[spki.end:tbs.end]
open(sys.argv[3], 'wb').write(d.rebuild_cert(new_tbs, sigalg, sigval))
PY
openssl x509 -inform DER -in "$(MK params.der)" -outform PEM \
  -out "$HERE/pqc_mlkem_spki_params_present.pem"
echo "wrote $HERE/pqc_mlkem_spki_params_present.pem (SPKI AlgorithmIdentifier NULL spliced in)"

# pqc_mlkem_bad_key_length: drop one byte from the SPKI public-key BIT STRING.
python3 - "$MLKEM_DERLIB" "$(MK good.der)" "$(MK badlen.der)" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("derlib", sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
der = bytearray(open(sys.argv[2], 'rb').read())
_, tbs, sigalg, sigval = d.cert_parts(der)
spki = d.spki_node(der)
algid, bitstr = spki.children()
bs = der[bitstr.content:bitstr.end]
assert bs[0] == 0x00, "expected 0 unused bits in the BIT STRING"
new_bitstr = d.reencode(0x03, bs[:-1])          # drop one trailing key byte (1184 -> 1183)
new_spki = d.reencode(0x30, der[algid.start:algid.end] + new_bitstr)
new_tbs = der[tbs.content:spki.start] + new_spki + der[spki.end:tbs.end]
open(sys.argv[3], 'wb').write(d.rebuild_cert(new_tbs, sigalg, sigval))
PY
openssl x509 -inform DER -in "$(MK badlen.der)" -outform PEM \
  -out "$HERE/pqc_mlkem_bad_key_length.pem"
echo "wrote $HERE/pqc_mlkem_bad_key_length.pem (SPKI public key truncated 1184 -> 1183 bytes)"

# Throwaway CA key / CSR / configs / DER scratch are not committed.
rm -rf "$MLKEM_WORK"
rm -f "$MLKEM_DERLIB"

# ============================================================================
# Feature 08 (certificate inspection / `--info`) — SLH-DSA root CA fixture
# ============================================================================
# Self-contained section. Generates `slh_dsa_root_ca.pem`: a self-signed
# SLH-DSA-SHA2-128s (SPHINCS+) POST-QUANTUM ROOT CA, used by the `--info`
# inspection tests (crates/cli/tests/inspect.rs).
#
# WHY a distinct fixture: feature 13 already ships `pqc_slhdsa_good.pem`, but
# that is an SLH-DSA *leaf* with no KeyUsage extension. The inspection tests
# need a cert that carries a KeyUsage extension with MULTIPLE bits set (plus
# critical) so the summary's KeyUsage-bit display is genuinely exercised — hence
# a fresh ROOT CA here.
#
# PROVENANCE (HARD PROJECT RULE): generated with openssl 3.6.2 (which supports
# SLH-DSA natively), NEVER sourced from the user's external `cert-bar` tool. The
# linter must remain an INDEPENDENT oracle for cert-bar's output, so a
# cert-bar-derived fixture would create a circular validation dependency.
#
# Exercises in the summary: a PQC signature/public-key algorithm (OID
# 2.16.840.1.101.3.4.3.20 — not known to oid-registry, but the linter enriches
# it to the name "SLH-DSA-SHA2-128s" via the feature-13 classification);
# KeyUsage PRESENT with keyCertSign + cRLSign + critical; BasicConstraints
# CA:TRUE critical; a SAN; and subject == issuer (self-signed root).
#
# DETERMINISM: a fixed serial (301) and a fixed, long validity window
# (2026-01-01 -> 2126-01-01) are pinned so the committed fixture — and therefore
# the `--info` snapshot — is reproducible. The summary shows only the cert's own
# dates (never wall-clock time), so the snapshot stays stable.
SLH_CA_KEY="$(mktemp)"
openssl genpkey -algorithm SLH-DSA-SHA2-128s -out "$SLH_CA_KEY" >/dev/null 2>&1
openssl req -x509 -new -key "$SLH_CA_KEY" \
  -subj "/CN=SLH-DSA Test Root/C=SE/O=mini-x509-linter testdata" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectAltName=DNS:slh-dsa-test-root" \
  -set_serial 301 \
  -not_before 20260101000000Z -not_after 21260101000000Z \
  -out "$HERE/slh_dsa_root_ca.pem" >/dev/null 2>&1
echo "wrote $HERE/slh_dsa_root_ca.pem (self-signed SLH-DSA-SHA2-128s root CA, openssl-native)"
# The throwaway private key is not committed.
rm -f "$SLH_CA_KEY"

# ============================================================================
# Feature 15 (chain-aware lints) — leaf -> intermediate -> root chain fixtures
# ============================================================================
# Self-contained section. Generates every `chain_*.pem` fixture the chain-aware
# lint tests consume (crates/linter/tests/chain.rs, crates/cli/tests/output.rs).
# Each fixture is a REAL linked chain (leaf actually issued by an intermediate
# actually issued by a self-signed root) unless noted otherwise.
#
# PROVENANCE (HARD PROJECT RULE): openssl 3.6.2 ONLY, NEVER the user's external
# cert-bar tool — the linter must stay an INDEPENDENT oracle. The PQC chain
# (chain_pqc_valid.pem) needs openssl >= 3.6.2 (ML-DSA support); if the host
# lacks it that one fixture cannot be regenerated (the others are classical).
#
# ℹ️ FIXED DATES — NOT TIME-FRAGILE: all chain fixtures use the BR_OK-aligned
#     window 2026-06-01 -> 2027-06-01
# EXCEPT chain_validity_not_nested.pem, whose LEAF deliberately runs to
# 2027-09-01 (past the issuer's notAfter) to trip chain_validity_nested. The
# per-cert pass over these fixtures evaluates hygiene_not_expired against the
# PINNED reference clock (not the wall clock), and the chain LINTS themselves are
# clock-independent, so these fixtures do NOT need annual regeneration; the fixed
# windows are kept for byte-reproducibility.
#
# DETERMINISM: fixed serials (4xx) and fixed validity windows are pinned so the
# committed bytes are reproducible. (RSA/EC keys are random, so the exact bytes
# still differ per regen — but the linter assertions key off cert STRUCTURE, not
# fixed bytes, and there is no committed chain golden that pins these bytes; the
# only --chain golden is chain_bundle.pem, two UNRELATED self-signed certs that
# produce 0 chain links and therefore no chain section.)
#
# PER-FIXTURE PRODUCIBILITY NOTES:
#   - chain_valid / chain_classical_valid / chain_pqc_valid: openssl-native real
#     chains; every chain lint passes (sig verifies via ring / fips204).
#   - chain_shuffled: the SAME three chain_valid certs re-concatenated in
#     non-leaf-first order (root, leaf, inter). No separate issuance → only
#     chain_not_in_order (Notice) fires; build_chain reorders it.
#   - chain_missing_middle: chain_valid's leaf + root only (intermediate omitted).
#   - chain_dn_mismatch: leaf (issued by 'inter') bundled with a DIFFERENT-subject
#     intermediate + root, so the leaf links to nothing.
#   - chain_aki_ski_mismatch: a 2-cert bundle (leaf3 + the real 'inter'). leaf3 is
#     issued by inter3, a SAME-SUBJECT-DN but DIFFERENT-KEY intermediate, so the
#     leaf's AKI keyId != inter's SKI. NB: because build_chain's linkage rule ALSO
#     requires AKI==SKI when both present, the leaf does NOT link to inter through
#     the engine — so chain_aki_ski_match is exercised by DIRECT check(subject,
#     issuer) invocation on the two loaded certs (see chain.rs).
#   - chain_issuer_not_ca: leaf issued by a CA:FALSE cert ('notca'), + root.
#   - chain_path_len_exceeded: root pathlen:0 -> intermediate CA -> leaf (an
#     intermediate CA appears below a pathlen:0 CA).
#   - chain_validity_not_nested: leaf notAfter (2027-09-01) beyond its issuer's.
#   - chain_bad_signature: a real leaf issued by 'inter' whose signature value has
#     its LAST DER byte XOR 0xFF, so it does not verify -> chain_signature_valid
#     Error on that link (DER byte-patch, openssl cannot emit a bad self-signature
#     natively).
#   - chain_unsupported_sig_alg: a P-521 / ecdsa-with-SHA512 chain. ring's
#     supported matrix excludes P-521, so the verifier returns Unsupported ->
#     chain_signature_valid Notice (fail-open), never an Error.

CHAIN_WORK="$(mktemp -d)"
CW() { printf '%s/%s' "$CHAIN_WORK" "$1"; }
CHAIN_NB=20260601000000Z
CHAIN_NA=20270601000000Z

# ---- Real RSA chain: root -> intermediate (pathlen:0) -> leaf -----------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW root.key)" >/dev/null 2>&1
openssl req -x509 -new -key "$(CW root.key)" -sha256 \
  -subj "/CN=mini-x509 chain test root/C=SE/O=mini-x509-linter testdata" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -addext "authorityKeyIdentifier=keyid" \
  -set_serial 401 -not_before $CHAIN_NB -not_after $CHAIN_NA \
  -out "$(CW root.pem)" >/dev/null 2>&1

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW inter.key)" >/dev/null 2>&1
openssl req -new -key "$(CW inter.key)" \
  -subj "/CN=mini-x509 chain test intermediate/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW inter.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW inter.ext)"
openssl x509 -req -in "$(CW inter.csr)" -CA "$(CW root.pem)" -CAkey "$(CW root.key)" \
  -set_serial 402 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW inter.ext)" \
  -sha256 -out "$(CW inter.pem)" >/dev/null 2>&1

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW leaf.key)" >/dev/null 2>&1
openssl req -new -key "$(CW leaf.key)" \
  -subj "/CN=chain-leaf.example.com/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW leaf.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:chain-leaf.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW leaf.ext)"
openssl x509 -req -in "$(CW leaf.csr)" -CA "$(CW inter.pem)" -CAkey "$(CW inter.key)" \
  -set_serial 403 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW leaf.ext)" \
  -sha256 -out "$(CW leaf.pem)" >/dev/null 2>&1

cat "$(CW leaf.pem)" "$(CW inter.pem)" "$(CW root.pem)" > "$HERE/chain_valid.pem"
echo "wrote $HERE/chain_valid.pem (RSA leaf -> intermediate -> root, all chain lints pass)"

# chain_shuffled: same three certs, non-leaf-first order (root, leaf, inter).
cat "$(CW root.pem)" "$(CW leaf.pem)" "$(CW inter.pem)" > "$HERE/chain_shuffled.pem"
echo "wrote $HERE/chain_shuffled.pem (reordered -> chain_not_in_order Notice only)"

# chain_missing_middle: leaf + root only (intermediate absent).
cat "$(CW leaf.pem)" "$(CW root.pem)" > "$HERE/chain_missing_middle.pem"
echo "wrote $HERE/chain_missing_middle.pem (leaf + root, intermediate omitted)"

# ---- chain_dn_mismatch: leaf bundled with a different-subject intermediate ----
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW inter2.key)" >/dev/null 2>&1
openssl req -new -key "$(CW inter2.key)" \
  -subj "/CN=mini-x509 DIFFERENT intermediate/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW inter2.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW inter2.ext)"
openssl x509 -req -in "$(CW inter2.csr)" -CA "$(CW root.pem)" -CAkey "$(CW root.key)" \
  -set_serial 422 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW inter2.ext)" \
  -sha256 -out "$(CW inter2.pem)" >/dev/null 2>&1
cat "$(CW leaf.pem)" "$(CW inter2.pem)" "$(CW root.pem)" > "$HERE/chain_dn_mismatch.pem"
echo "wrote $HERE/chain_dn_mismatch.pem (leaf's issuer DN matches no bundled cert)"

# ---- chain_aki_ski_mismatch: same-DN, different-key intermediate -------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW inter3.key)" >/dev/null 2>&1
openssl req -new -key "$(CW inter3.key)" \
  -subj "/CN=mini-x509 chain test intermediate/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW inter3.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW inter3.ext)"
openssl x509 -req -in "$(CW inter3.csr)" -CA "$(CW root.pem)" -CAkey "$(CW root.key)" \
  -set_serial 442 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW inter3.ext)" \
  -sha256 -out "$(CW inter3.pem)" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW leaf3.key)" >/dev/null 2>&1
openssl req -new -key "$(CW leaf3.key)" \
  -subj "/CN=aki-mismatch-leaf.example.com/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW leaf3.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:aki-mismatch-leaf.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW leaf3.ext)"
openssl x509 -req -in "$(CW leaf3.csr)" -CA "$(CW inter3.pem)" -CAkey "$(CW inter3.key)" \
  -set_serial 443 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW leaf3.ext)" \
  -sha256 -out "$(CW leaf3.pem)" >/dev/null 2>&1
# 2-cert bundle for DIRECT-invocation testing: leaf3 (AKI=inter3 SKI) + real inter.
cat "$(CW leaf3.pem)" "$(CW inter.pem)" > "$HERE/chain_aki_ski_mismatch.pem"
echo "wrote $HERE/chain_aki_ski_mismatch.pem (leaf AKI keyId != issuer SKI; direct-invocation)"

# ---- chain_issuer_not_ca: leaf issued by a CA:FALSE cert ---------------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW notca.key)" >/dev/null 2>&1
openssl req -new -key "$(CW notca.key)" \
  -subj "/CN=mini-x509 not-a-ca issuer/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW notca.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW notca.ext)"
openssl x509 -req -in "$(CW notca.csr)" -CA "$(CW root.pem)" -CAkey "$(CW root.key)" \
  -set_serial 432 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW notca.ext)" \
  -sha256 -out "$(CW notca.pem)" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW leaf2.key)" >/dev/null 2>&1
openssl req -new -key "$(CW leaf2.key)" \
  -subj "/CN=leaf-under-nonca.example.com/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW leaf2.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:leaf-under-nonca.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW leaf2.ext)"
openssl x509 -req -in "$(CW leaf2.csr)" -CA "$(CW notca.pem)" -CAkey "$(CW notca.key)" \
  -set_serial 433 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW leaf2.ext)" \
  -sha256 -out "$(CW leaf2.pem)" >/dev/null 2>&1
cat "$(CW leaf2.pem)" "$(CW notca.pem)" "$(CW root.pem)" > "$HERE/chain_issuer_not_ca.pem"
echo "wrote $HERE/chain_issuer_not_ca.pem (issuer is CA:FALSE)"

# ---- chain_path_len_exceeded: pathlen:0 root -> intermediate CA -> leaf ------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW plroot.key)" >/dev/null 2>&1
openssl req -x509 -new -key "$(CW plroot.key)" -sha256 \
  -subj "/CN=mini-x509 pathlen0 root/C=SE/O=mini-x509-linter testdata" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -addext "authorityKeyIdentifier=keyid" \
  -set_serial 451 -not_before $CHAIN_NB -not_after $CHAIN_NA \
  -out "$(CW plroot.pem)" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW plinter.key)" >/dev/null 2>&1
openssl req -new -key "$(CW plinter.key)" \
  -subj "/CN=mini-x509 pathlen test intermediate/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW plinter.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW plinter.ext)"
openssl x509 -req -in "$(CW plinter.csr)" -CA "$(CW plroot.pem)" -CAkey "$(CW plroot.key)" \
  -set_serial 452 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW plinter.ext)" \
  -sha256 -out "$(CW plinter.pem)" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW plleaf.key)" >/dev/null 2>&1
openssl req -new -key "$(CW plleaf.key)" \
  -subj "/CN=pathlen-leaf.example.com/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW plleaf.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pathlen-leaf.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW plleaf.ext)"
openssl x509 -req -in "$(CW plleaf.csr)" -CA "$(CW plinter.pem)" -CAkey "$(CW plinter.key)" \
  -set_serial 453 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW plleaf.ext)" \
  -sha256 -out "$(CW plleaf.pem)" >/dev/null 2>&1
cat "$(CW plleaf.pem)" "$(CW plinter.pem)" "$(CW plroot.pem)" > "$HERE/chain_path_len_exceeded.pem"
echo "wrote $HERE/chain_path_len_exceeded.pem (pathlen:0 CA with an intermediate below)"

# ---- chain_validity_not_nested: leaf notAfter beyond issuer notAfter ---------
LEAF_LATE_NA=20270901000000Z
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW vnleaf.key)" >/dev/null 2>&1
openssl req -new -key "$(CW vnleaf.key)" \
  -subj "/CN=validity-not-nested-leaf.example.com/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW vnleaf.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:validity-not-nested-leaf.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW vnleaf.ext)"
openssl x509 -req -in "$(CW vnleaf.csr)" -CA "$(CW inter.pem)" -CAkey "$(CW inter.key)" \
  -set_serial 463 -not_before $CHAIN_NB -not_after $LEAF_LATE_NA -extfile "$(CW vnleaf.ext)" \
  -sha256 -out "$(CW vnleaf.pem)" >/dev/null 2>&1
cat "$(CW vnleaf.pem)" "$(CW inter.pem)" "$(CW root.pem)" > "$HERE/chain_validity_not_nested.pem"
echo "wrote $HERE/chain_validity_not_nested.pem (leaf outlives issuer; notAfter $LEAF_LATE_NA)"

# ---- chain_classical_valid: ECDSA P-256 chain (positive control via ring) ----
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$(CW ecroot.key)" >/dev/null 2>&1
openssl req -x509 -new -key "$(CW ecroot.key)" -sha256 \
  -subj "/CN=mini-x509 ecdsa chain root/C=SE" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -addext "authorityKeyIdentifier=keyid" \
  -set_serial 411 -not_before $CHAIN_NB -not_after $CHAIN_NA -out "$(CW ecroot.pem)" >/dev/null 2>&1
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$(CW ecinter.key)" >/dev/null 2>&1
openssl req -new -key "$(CW ecinter.key)" -subj "/CN=mini-x509 ecdsa chain intermediate/C=SE" -out "$(CW ecinter.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW ecinter.ext)"
openssl x509 -req -in "$(CW ecinter.csr)" -CA "$(CW ecroot.pem)" -CAkey "$(CW ecroot.key)" \
  -set_serial 412 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW ecinter.ext)" -sha256 -out "$(CW ecinter.pem)" >/dev/null 2>&1
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$(CW ecleaf.key)" >/dev/null 2>&1
openssl req -new -key "$(CW ecleaf.key)" -subj "/CN=ecdsa-leaf.example.com/C=SE" -out "$(CW ecleaf.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:ecdsa-leaf.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW ecleaf.ext)"
openssl x509 -req -in "$(CW ecleaf.csr)" -CA "$(CW ecinter.pem)" -CAkey "$(CW ecinter.key)" \
  -set_serial 413 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW ecleaf.ext)" -sha256 -out "$(CW ecleaf.pem)" >/dev/null 2>&1
cat "$(CW ecleaf.pem)" "$(CW ecinter.pem)" "$(CW ecroot.pem)" > "$HERE/chain_classical_valid.pem"
echo "wrote $HERE/chain_classical_valid.pem (ECDSA P-256 chain; verifies via ring)"

# ---- chain_pqc_valid: ML-DSA-65 chain (requires openssl >= 3.6.2) ------------
openssl genpkey -algorithm ML-DSA-65 -out "$(CW pqroot.key)" >/dev/null 2>&1
openssl req -x509 -new -key "$(CW pqroot.key)" \
  -subj "/CN=mini-x509 ML-DSA chain root/C=SE/O=mini-x509-linter testdata" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -addext "authorityKeyIdentifier=keyid" \
  -set_serial 481 -not_before $CHAIN_NB -not_after $CHAIN_NA -out "$(CW pqroot.pem)" >/dev/null 2>&1
openssl genpkey -algorithm ML-DSA-65 -out "$(CW pqinter.key)" >/dev/null 2>&1
openssl req -new -key "$(CW pqinter.key)" -subj "/CN=mini-x509 ML-DSA chain intermediate/C=SE/O=mini-x509-linter testdata" -out "$(CW pqinter.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW pqinter.ext)"
openssl x509 -req -in "$(CW pqinter.csr)" -CA "$(CW pqroot.pem)" -CAkey "$(CW pqroot.key)" \
  -set_serial 482 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW pqinter.ext)" -out "$(CW pqinter.pem)" >/dev/null 2>&1
openssl genpkey -algorithm ML-DSA-65 -out "$(CW pqleaf.key)" >/dev/null 2>&1
openssl req -new -key "$(CW pqleaf.key)" -subj "/CN=mldsa-leaf.example.com/C=SE/O=mini-x509-linter testdata" -out "$(CW pqleaf.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:mldsa-leaf.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW pqleaf.ext)"
openssl x509 -req -in "$(CW pqleaf.csr)" -CA "$(CW pqinter.pem)" -CAkey "$(CW pqinter.key)" \
  -set_serial 483 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW pqleaf.ext)" -out "$(CW pqleaf.pem)" >/dev/null 2>&1
cat "$(CW pqleaf.pem)" "$(CW pqinter.pem)" "$(CW pqroot.pem)" > "$HERE/chain_pqc_valid.pem"
echo "wrote $HERE/chain_pqc_valid.pem (ML-DSA-65 chain; verifies via fips204; needs openssl >= 3.6.2)"

# ---- chain_bad_signature: DER-patch the last byte of a real leaf signature ---
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW bsleaf.key)" >/dev/null 2>&1
openssl req -new -key "$(CW bsleaf.key)" \
  -subj "/CN=bad-signature-leaf.example.com/C=SE/O=mini-x509-linter testdata" \
  -out "$(CW bsleaf.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:bad-signature-leaf.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW bsleaf.ext)"
openssl x509 -req -in "$(CW bsleaf.csr)" -CA "$(CW inter.pem)" -CAkey "$(CW inter.key)" \
  -set_serial 473 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW bsleaf.ext)" \
  -sha256 -out "$(CW bsleaf.pem)" >/dev/null 2>&1
openssl x509 -in "$(CW bsleaf.pem)" -outform DER -out "$(CW bsleaf.der)" >/dev/null 2>&1
python3 - "$(CW bsleaf.der)" "$(CW bsleaf_patched.der)" <<'PY'
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
data[-1] ^= 0xFF   # corrupt the last signature byte so verification fails
open(sys.argv[2], 'wb').write(data)
PY
openssl x509 -inform DER -in "$(CW bsleaf_patched.der)" -outform PEM -out "$(CW bsleaf_patched.pem)" >/dev/null 2>&1
cat "$(CW bsleaf_patched.pem)" "$(CW inter.pem)" "$(CW root.pem)" > "$HERE/chain_bad_signature.pem"
echo "wrote $HERE/chain_bad_signature.pem (leaf signature last byte XOR 0xFF -> chain_signature_valid Error)"

# ---- chain_unsupported_sig_alg: P-521 / ecdsa-with-SHA512 chain --------------
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$(CW p5root.key)" >/dev/null 2>&1
openssl req -x509 -new -key "$(CW p5root.key)" -sha512 \
  -subj "/CN=mini-x509 P-521 chain root/C=SE/O=mini-x509-linter testdata" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -addext "authorityKeyIdentifier=keyid" \
  -set_serial 491 -not_before $CHAIN_NB -not_after $CHAIN_NA -out "$(CW p5root.pem)" >/dev/null 2>&1
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$(CW p5inter.key)" >/dev/null 2>&1
openssl req -new -key "$(CW p5inter.key)" -subj "/CN=mini-x509 P-521 chain intermediate/C=SE/O=mini-x509-linter testdata" -out "$(CW p5inter.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW p5inter.ext)"
openssl x509 -req -in "$(CW p5inter.csr)" -CA "$(CW p5root.pem)" -CAkey "$(CW p5root.key)" \
  -set_serial 492 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW p5inter.ext)" -sha512 -out "$(CW p5inter.pem)" >/dev/null 2>&1
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$(CW p5leaf.key)" >/dev/null 2>&1
openssl req -new -key "$(CW p5leaf.key)" -subj "/CN=p521-leaf.example.com/C=SE/O=mini-x509-linter testdata" -out "$(CW p5leaf.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:p521-leaf.example.com\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW p5leaf.ext)"
openssl x509 -req -in "$(CW p5leaf.csr)" -CA "$(CW p5inter.pem)" -CAkey "$(CW p5inter.key)" \
  -set_serial 493 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW p5leaf.ext)" -sha512 -out "$(CW p5leaf.pem)" >/dev/null 2>&1
cat "$(CW p5leaf.pem)" "$(CW p5inter.pem)" "$(CW p5root.pem)" > "$HERE/chain_unsupported_sig_alg.pem"
echo "wrote $HERE/chain_unsupported_sig_alg.pem (P-521 / ecdsa-with-SHA512 -> chain_signature_valid Notice, fail-open)"

# ===========================================================================
# Feature 15 link chain: crates/linter/src/chain_testdata/{link_*}.pem
# ===========================================================================
# The chain-link unit tests `include_bytes!` these four fixtures from
# crates/linter/src/chain_testdata/ (NOT testdata/), so they are written there.
# They form a REAL linked, signature-verifying chain plus one unrelated stray CA:
#   - link_root.pem   (serial 1) self-signed CN=Chain Link Root CA, critical
#                     CA:TRUE, KU keyCertSign+cRLSign, SKI hash, AKI keyid (==SKI).
#   - link_inter.pem  (serial 2) issued by root, critical CA:TRUE pathlen:0, KU
#                     keyCertSign+cRLSign, SKI hash, AKI = root keyid.
#   - link_leaf.pem   (serial 3) issued by inter, critical CA:FALSE, KU
#                     digitalSignature+keyEncipherment, EKU serverAuth, SKI hash,
#                     AKI = inter keyid, SAN DNS:link-leaf.example.com.
#   - link_stray.pem  (serial 9) self-signed CN=Unrelated Stray CA, critical
#                     CA:TRUE, KU keyCertSign ONLY (no cRLSign), SKI hash, AKI
#                     keyid (==SKI). Links to nothing in the test chain.
# All four use the BR_OK-aligned CHAIN window (2026-06-01 -> 2027-06-01). Shape
# read from `openssl x509 -text` over each committed fixture (serials, the leaf's
# AKI==inter SKI linkage, and the stray's keyCertSign-only KU).
LINK_DIR="$HERE/../crates/linter/src/chain_testdata"

# link_root: self-signed root CA.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW link_root.key)" >/dev/null 2>&1
openssl req -x509 -new -key "$(CW link_root.key)" -sha256 \
  -subj "/CN=Chain Link Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -addext "authorityKeyIdentifier=keyid" \
  -set_serial 1 -not_before $CHAIN_NB -not_after $CHAIN_NA \
  -out "$LINK_DIR/link_root.pem" >/dev/null 2>&1
echo "wrote $LINK_DIR/link_root.pem (self-signed Chain Link Root CA)"

# link_inter: intermediate CA (pathlen:0) issued by link_root.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW link_inter.key)" >/dev/null 2>&1
openssl req -new -key "$(CW link_inter.key)" -subj "/CN=Chain Link Intermediate CA" \
  -out "$(CW link_inter.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$(CW link_inter.ext)"
openssl x509 -req -in "$(CW link_inter.csr)" -CA "$LINK_DIR/link_root.pem" -CAkey "$(CW link_root.key)" \
  -set_serial 2 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW link_inter.ext)" \
  -sha256 -out "$LINK_DIR/link_inter.pem" >/dev/null 2>&1
echo "wrote $LINK_DIR/link_inter.pem (intermediate CA issued by link_root)"

# link_leaf: serverAuth leaf issued by link_inter.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW link_leaf.key)" >/dev/null 2>&1
openssl req -new -key "$(CW link_leaf.key)" -subj "/CN=link-leaf.example.com" \
  -out "$(CW link_leaf.csr)" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\nsubjectAltName=DNS:link-leaf.example.com\n' > "$(CW link_leaf.ext)"
openssl x509 -req -in "$(CW link_leaf.csr)" -CA "$LINK_DIR/link_inter.pem" -CAkey "$(CW link_inter.key)" \
  -set_serial 3 -not_before $CHAIN_NB -not_after $CHAIN_NA -extfile "$(CW link_leaf.ext)" \
  -sha256 -out "$LINK_DIR/link_leaf.pem" >/dev/null 2>&1
echo "wrote $LINK_DIR/link_leaf.pem (serverAuth leaf issued by link_inter)"

# link_stray: unrelated self-signed CA with keyCertSign-ONLY key usage.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(CW link_stray.key)" >/dev/null 2>&1
openssl req -x509 -new -key "$(CW link_stray.key)" -sha256 \
  -subj "/CN=Unrelated Stray CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" \
  -addext "subjectKeyIdentifier=hash" -addext "authorityKeyIdentifier=keyid" \
  -set_serial 9 -not_before $CHAIN_NB -not_after $CHAIN_NA \
  -out "$LINK_DIR/link_stray.pem" >/dev/null 2>&1
echo "wrote $LINK_DIR/link_stray.pem (unrelated self-signed stray CA, keyCertSign only)"

# Throwaway keys/CSRs/configs are not committed.
rm -rf "$CHAIN_WORK"
