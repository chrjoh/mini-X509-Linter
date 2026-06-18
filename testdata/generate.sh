#!/usr/bin/env bash
#
# Regenerates the certificate fixtures used by the linter test suite.
#
# Required tooling:
#   - openssl 3.x (tested with OpenSSL 3.6.2)
#   - bash, dd, xxd (for the one byte-patched fixture)
#
# Usage:
#   ./testdata/generate.sh
#
# ============================================================================
# ⚠️  TIME-FRAGILITY WARNING — READ BEFORE TOUCHING THESE FIXTURES  ⚠️
# ============================================================================
# Feature 05 (CA/Browser Forum BR lints) introduced BROAD scoping: the four BR
# lints apply to EVERY non-CA leaf. One of them, cabf_br_validity_max_398_days,
# requires a leaf's validity window to be BOTH <= 398 days AND currently valid
# (notAfter in the future). A short window cannot also be far-future, so the
# BR-compliant leaves below use a fixed, currently-valid <=398-day window:
#
#     BR_OK:  2026-06-01  ->  2027-06-01   (365 days)
#
# These leaves EXPIRE on 2027-06-01. After that date hygiene_not_expired fires
# on good.pem and on every per-rule leaf fixture, breaking the "exactly one rule
# fires" isolation tests WHOLESALE (a flood of not_expired failures).
#
#   >>> REGENERATE ANNUALLY (slide the windows forward) BEFORE 2027-06-01. <<<
#
# The cabf_br_validity_400_days fixture uses 2026-06-01 -> 2027-07-06 (400 days,
# also currently valid) and has a slightly later horizon, but the same chore.
#
# Two dating strategies were considered:
#   (a) Fixed dates (chosen here): the committed bytes are reproducible across
#       regenerations, but require the annual manual slide above.
#   (b) Relative dates (openssl -days 365): self-healing on regen (always
#       relative to "now"), but the committed bytes drift every regeneration,
#       making fixture diffs noisy and the checked-in window non-deterministic.
# We keep fixed dates for reproducibility and accept the annual-regen chore.
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
# serverAuth, CA:FALSE, RSA-2048/SHA-256, BR_OK window. Passes all 14 lints.
EXT_GOOD="$(new_ext)"
make_leaf_ext "$EXT_GOOD" "DNS:good.example.com"
sign_csr "$HERE/good.pem" "/CN=good.example.com" 17 "$BR_OK_NB" "$BR_OK_NA" "$EXT_GOOD"

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
# ⚠️  Feature 09: CA/Browser Forum CODE-SIGNING Baseline Requirements fixtures
# ===========================================================================
# ⚠️  TIME-FRAGILITY — READ ME — these fixtures EXPIRE ~2027-06-01.  ⚠️
# ---------------------------------------------------------------------------
# The eight cabf_cs_*.pem fixtures use currently-valid windows so that
# hygiene_not_expired stays quiet (notAfter in the future). The non-validity
# fixtures use the CS_OK window 2026-06-01 -> 2027-06-01 (365d, <=460d). The two
# validity-violating fixtures straddle "now":
#     cabf_cs_validity_40_months  2024-06-01 -> 2027-10-01  (~40 months, >1188d)
#     cabf_cs_validity_500_days   2026-02-01 -> 2027-06-16  (500d, >460d, <=39mo)
# ALL of them EXPIRE in 2027. After 2027-06-01 (and 2027-10-01 for the 40-month
# fixture) hygiene_not_expired fires on the CS fixtures and the cabf_cs isolation
# tests (crates/linter/tests/cabf_cs.rs) break wholesale.
#
#   >>> REGENERATE ANNUALLY (slide the CS windows forward) BEFORE 2027-06-01. <<<
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
