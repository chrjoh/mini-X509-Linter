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
# Output (written next to this script):
#
#   Shared fixtures (used across features 01/02/03):
#     - good.pem     clean LEAF cert that PASSES every shipped lint.
#     - expired.pem  same clean leaf shape but with a PAST notAfter, so it
#                    violates ONLY hygiene `not_expired`.
#
#   One fixture per RFC 5280 lint, each violating EXACTLY that rule and passing
#   all other RFC 5280 lints (plus `not_expired`, via a far-future notAfter):
#     - rfc5280_version_not_v3.pem         extensions present but version v1.
#     - rfc5280_serial_number_zero.pem     serial == 0.
#     - rfc5280_validity_inverted.pem      notAfter <= notBefore.
#     - rfc5280_ca_bc_not_critical.pem     CA, BasicConstraints not critical
#                                          (but keyUsage has keyCertSign).
#     - rfc5280_ca_missing_keycertsign.pem CA, BasicConstraints critical, but
#                                          keyUsage lacks keyCertSign.
#     - rfc5280_empty_subject_no_san.pem   empty subject DN, no SAN, non-CA leaf.
#
#   One fixture per NEW crypto-hygiene lint (feature 04), each a clean leaf that
#   violates EXACTLY its one hygiene rule and passes everything else (the six RFC
#   5280 lints, `not_expired`, and the other two hygiene lints):
#     - hygiene_sha1_signature.pem   RSA-2048 key but SIGNED WITH SHA-1, so the
#                                    signature algorithm is sha1WithRSAEncryption.
#                                    Violates ONLY hygiene_no_sha1_signature.
#     - hygiene_rsa_1024.pem         RSA-1024 key, SHA-256 signature. Violates
#                                    ONLY hygiene_rsa_key_min_2048.
#     - hygiene_ecdsa_bad_curve.pem  EC key on secp224r1 (a NAMED curve outside
#                                    {P-256,P-384,P-521}), SHA-256 signature.
#                                    Violates ONLY hygiene_ecdsa_curve_allowlist.
#
# Design notes
# ------------
# * good.pem / expired.pem are LEAF certs (basicConstraints CA:FALSE) with a
#   non-empty subject and NO SAN. As a non-CA with a populated subject the two
#   CA-only lints (`basic_constraints_critical_on_ca`, `key_usage_present_when_ca`)
#   and `san_present_if_subject_empty` all return NotApplicable, while the
#   structural lints (version, serial, validity) pass. This keeps the certs clean
#   under the full default registry.
#
# * Each violating fixture is otherwise a clean leaf/CA so it isolates a single
#   rule. The CA fixtures carry a non-empty subject (SAN lint N/A) and a valid
#   validity window / serial / version; the empty-subject fixture is a non-CA
#   leaf (CA lints N/A) and otherwise valid.
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
# Determinism: each fixture embeds a freshly generated RSA key, so exact bytes
# differ per run. What the tests rely on is stable: validity windows, serials,
# subject presence, CA-ness, and extension criticality. Regenerate only when you
# intend to refresh the committed fixtures; CI consumes the committed .pem files.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# A single shared key keeps the script fast; fixtures are self-signed and we do
# not rely on key uniqueness across fixtures.
KEY="$(mktemp)"
trap 'rm -f "$KEY"' EXIT
openssl genrsa -out "$KEY" 2048 2>/dev/null

# Far-future and past validity windows (UTC, openssl 1.1.1+/3.x flags).
FAR_FUTURE_NB="20240101000000Z"
FAR_FUTURE_NA="21240101000000Z" # 2124 — comfortably past any test "now".
PAST_NB="20100101000000Z"
PAST_NA="20110101000000Z"

# sign_csr <out.pem> <subject> <serial> <not_before> <not_after> <extfile|"">
#
# Self-signs a CSR built from $KEY with explicit serial / validity / extensions.
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

# Reusable extension config snippets.
EXT_LEAF="$(mktemp)"
printf 'basicConstraints=CA:FALSE\n' >"$EXT_LEAF"

EXT_CA_BC_NONCRIT="$(mktemp)"
printf 'basicConstraints=CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$EXT_CA_BC_NONCRIT"

EXT_CA_NO_KCS="$(mktemp)"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,cRLSign\n' >"$EXT_CA_NO_KCS"

trap 'rm -f "$KEY" "$EXT_LEAF" "$EXT_CA_BC_NONCRIT" "$EXT_CA_NO_KCS"' EXIT

# --- Shared fixtures -------------------------------------------------------

# good.pem: clean leaf — v3, non-empty subject, no SAN, CA:FALSE, far future.
sign_csr "$HERE/good.pem"    "/CN=good.example"    17 "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_LEAF"

# expired.pem: same leaf shape, past notAfter — violates ONLY not_expired.
sign_csr "$HERE/expired.pem" "/CN=expired.example" 17 "$PAST_NB"       "$PAST_NA"       "$EXT_LEAF"

# --- RFC 5280 per-lint violating fixtures ---------------------------------

# serial_number_positive: serial 0, otherwise clean leaf.
sign_csr "$HERE/rfc5280_serial_number_zero.pem" "/CN=serial-zero.example" 0 \
  "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_LEAF"

# validity_not_after_after_not_before: notAfter <= notBefore. openssl refuses to
# emit a strictly inverted window ("end date before start date"), but it DOES
# accept an empty (zero-length) window where notAfter == notBefore. The lint
# requires notAfter to be STRICTLY later than notBefore, so an equal pair is a
# valid violation of the rule. Both bounds are far-future (2120), so not_expired
# still passes. Otherwise a clean leaf.
sign_csr "$HERE/rfc5280_validity_inverted.pem" "/CN=inverted.example" 21 \
  "21200101000000Z" "21200101000000Z" "$EXT_LEAF"

# basic_constraints_critical_on_ca: CA cert, BasicConstraints NOT critical, but
# keyUsage carries keyCertSign so key_usage_present_when_ca passes.
sign_csr "$HERE/rfc5280_ca_bc_not_critical.pem" "/CN=ca-bc-noncrit.example" 18 \
  "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_CA_BC_NONCRIT"

# key_usage_present_when_ca: CA cert, BasicConstraints critical CA:TRUE, keyUsage
# present WITHOUT keyCertSign.
sign_csr "$HERE/rfc5280_ca_missing_keycertsign.pem" "/CN=ca-no-kcs.example" 19 \
  "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_CA_NO_KCS"

# san_present_if_subject_empty: empty subject DN, no SAN, non-CA leaf.
sign_csr "$HERE/rfc5280_empty_subject_no_san.pem" "/" 20 \
  "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_LEAF"

# version_is_v3: build a clean v3 leaf with extensions, then patch the DER
# version byte from v3 (0x02) to v1 (0x00). openssl cannot emit "v1 with
# extensions" directly, so we do it by construction (see header notes).
V3_TMP="$(mktemp)"
DER_TMP="$(mktemp)"
sign_csr "$V3_TMP" "/CN=version-v1.example" 22 "$FAR_FUTURE_NB" "$FAR_FUTURE_NA" "$EXT_LEAF"
openssl x509 -in "$V3_TMP" -outform DER -out "$DER_TMP"

# Locate the version field. DER layout at the start of a Certificate:
#   30 LL                      SEQUENCE (Certificate)
#     30 LL                    SEQUENCE (TBSCertificate)
#       A0 03 02 01 NN         [0] EXPLICIT { INTEGER version }
# We find the "A0 03 02 01" prefix and flip the following value byte to 0x00.
# Search within the first 32 bytes, where the version field always lives.
patch_version_to_v1() {
  local der="$1"
  local hex
  hex="$(xxd -p -l 32 "$der" | tr -d '\n')"
  # Offset (in hex-string chars) of the marker "a003020102".
  local marker="a003020102"
  local idx="${hex%%"$marker"*}"
  if [[ "$idx" == "$hex" ]]; then
    echo "ERROR: version marker a003020102 not found in $der" >&2
    exit 1
  fi
  # Byte offset of the value (the 0x02 after a0 03 02 01) = chars-before/2 + 4.
  local byte_off=$(((${#idx} / 2) + 4))
  printf '\x00' | dd of="$der" bs=1 seek="$byte_off" count=1 conv=notrunc 2>/dev/null
}

patch_version_to_v1 "$DER_TMP"
openssl x509 -inform DER -in "$DER_TMP" -outform PEM -out "$HERE/rfc5280_version_not_v3.pem"
echo "wrote $HERE/rfc5280_version_not_v3.pem (version byte patched v3 -> v1)"
rm -f "$V3_TMP" "$DER_TMP"

# --- Crypto-hygiene per-lint violating fixtures (feature 04) ---------------
#
# These three reuse the same clean-leaf shape (CA:FALSE via $EXT_LEAF, non-empty
# subject, no SAN, v3, small positive serial, far-future validity) so each
# isolates a SINGLE hygiene rule across the WHOLE registry. They cannot reuse the
# shared $KEY / sign_csr helper unchanged because each needs a specific key or
# digest, so they carry their own keys and inline the signing step in the same
# style. All temp keys are cleaned up on exit alongside the earlier ones.

HYG_RSA2048_KEY="$(mktemp)"
HYG_RSA1024_KEY="$(mktemp)"
HYG_EC_KEY="$(mktemp)"
trap 'rm -f "$KEY" "$EXT_LEAF" "$EXT_CA_BC_NONCRIT" "$EXT_CA_NO_KCS" \
      "$HYG_RSA2048_KEY" "$HYG_RSA1024_KEY" "$HYG_EC_KEY"' EXIT

# sign_leaf_with <out.pem> <key> <subject> <serial> <digest>
#
# Self-signs a clean leaf ($EXT_LEAF, far-future validity) from an explicit key
# with an explicit signature digest. A hygiene-specific variant of sign_csr: it
# parameterises BOTH the signing key and the digest (sign_csr hardcodes the
# shared RSA-2048 key and -sha256), which is exactly what these fixtures need.
sign_leaf_with() {
  local out="$1" key="$2" subj="$3" serial="$4" digest="$5"
  local csr
  csr="$(mktemp)"
  openssl req -new -key "$key" -subj "$subj" -out "$csr" 2>/dev/null
  openssl x509 -req -in "$csr" -signkey "$key" -out "$out" \
    -set_serial "$serial" -not_before "$FAR_FUTURE_NB" -not_after "$FAR_FUTURE_NA" \
    "-$digest" -extfile "$EXT_LEAF" 2>/dev/null
  rm -f "$csr"
  echo "wrote $out"
}

# hygiene_no_sha1_signature: RSA-2048 key (so rsa_key_min_2048 passes; non-EC so
# ecdsa_curve_allowlist is N/A) but SIGNED WITH SHA-1, yielding signature
# algorithm sha1WithRSAEncryption (OID 1.2.840.113549.1.1.5). openssl 3.6.2's
# default provider still permits RSA-SHA1 signing, so `-sha1` works directly.
openssl genrsa -out "$HYG_RSA2048_KEY" 2048 2>/dev/null
sign_leaf_with "$HERE/hygiene_sha1_signature.pem" "$HYG_RSA2048_KEY" \
  "/CN=sha1-sig.example" 30 sha1

# hygiene_rsa_key_min_2048: RSA-1024 key (below the 2048-bit floor) with a
# SHA-256 signature (so no_sha1_signature passes; non-EC so ecdsa lint is N/A).
openssl genrsa -out "$HYG_RSA1024_KEY" 1024 2>/dev/null
sign_leaf_with "$HERE/hygiene_rsa_1024.pem" "$HYG_RSA1024_KEY" \
  "/CN=rsa-1024.example" 31 sha256

# hygiene_ecdsa_curve_allowlist: EC key on secp224r1 (NIST P-224, OID
# 1.3.132.0.33) — a recognised NAMED curve that is NOT on the {P-256,P-384,P-521}
# allowlist, so the lint fires on the "not allowlisted" path (not the
# fail-closed "no named curve" path). Signed ecdsa-with-SHA256, so the SHA-1 lint
# passes; an EC key makes rsa_key_min_2048 N/A.
openssl ecparam -name secp224r1 -genkey -noout -out "$HYG_EC_KEY" 2>/dev/null
sign_leaf_with "$HERE/hygiene_ecdsa_bad_curve.pem" "$HYG_EC_KEY" \
  "/CN=ec-bad-curve.example" 32 sha256
