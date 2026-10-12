#!/usr/bin/env bash
# Checks the cosign hashes pinned in scripts/cosign.env against the
# cosign_checksums.txt published with that cosign release.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091 # plain KEY=value pins
. "$HERE/cosign.env"

sums="$(curl --proto '=https' --tlsv1.2 -fsSL "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign_checksums.txt")"
status=0
for os in linux darwin; do
  for arch in amd64 arm64; do
    var="COSIGN_SHA256_$(printf '%s_%s' "$os" "$arch" | tr '[:lower:]' '[:upper:]')"
    want="$(awk -v name="cosign-$os-$arch" '$2 == name { print $1 }' <<<"$sums")"
    if [[ -n "$want" && "$want" == "${!var}" ]]; then
      echo "ok   cosign-$os-$arch"
    else
      echo "FAIL $var=${!var}, cosign_checksums.txt has ${want:-nothing}" >&2
      status=1
    fi
  done
done
exit "$status"
