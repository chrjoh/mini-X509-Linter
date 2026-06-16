#!/usr/bin/env bash
#
# Regenerates the shared certificate fixtures used by the linter test suite.
#
# Required tooling:
#   - openssl 3.x (tested with OpenSSL 3.6.2)
#   - bash
#
# Usage:
#   ./testdata/generate.sh
#
# Output (written next to this script):
#   - good.pem     self-signed cert with a far-future notAfter (passes not_expired)
#   - expired.pem  self-signed cert whose notAfter is in the past (fails not_expired)
#
# Notes on determinism:
#   The certificates embed freshly generated RSA keys and pseudo-random serial
#   numbers, so the exact bytes differ on every run. What IS stable and is what
#   the tests rely on is the *validity window*:
#     - good.pem    notBefore = 2024-01-01, notAfter = 2124-01-01 (100 years)
#     - expired.pem notBefore = 2010-01-01, notAfter = 2011-01-01 (long past)
#   Regenerate only when you intend to refresh the committed fixtures; the
#   committed .pem files are what CI consumes, the script documents how they were
#   produced.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

gen() {
  # gen <out.pem> <not_before YYYYMMDDHHMMSSZ> <not_after YYYYMMDDHHMMSSZ> <CN>
  local out="$1" not_before="$2" not_after="$3" cn="$4"
  local key
  key="$(mktemp)"

  openssl genrsa -out "$key" 2048 2>/dev/null

  # -not_before / -not_after pin an explicit validity window (openssl 1.1.1+/3.x).
  openssl req -new -x509 \
    -key "$key" \
    -out "$out" \
    -subj "/CN=${cn}" \
    -not_before "$not_before" \
    -not_after "$not_after" \
    -sha256

  rm -f "$key"
  echo "wrote $out  (notBefore=$not_before notAfter=$not_after)"
}

gen "$HERE/good.pem"    "20240101000000Z" "21240101000000Z" "good.example"
gen "$HERE/expired.pem" "20100101000000Z" "20110101000000Z" "expired.example"
