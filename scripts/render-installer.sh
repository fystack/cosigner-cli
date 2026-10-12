#!/usr/bin/env bash
# Renders install.sh for one release from scripts/install.sh.tmpl, pinning the
# SHA-256 of every binary and its Sigstore bundle, plus the bootstrap cosign
# from scripts/cosign.env. Runs in the release workflow after the binaries are
# signed, so the bundles exist.
#
#   scripts/render-installer.sh vX.Y.Z COMMIT DIST_DIR   # writes DIST_DIR/install.sh
set -euo pipefail

VERSION="${1:?usage: render-installer.sh vX.Y.Z COMMIT DIST_DIR}"
COMMIT="${2:?commit required}"
DIST="${3:?dist directory required}"
BASE_URL="${BASE_URL:-https://cosigner.fystack.io}"
REPOSITORY="${REPOSITORY:-fystack/cosigner-cli}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid version: $VERSION" >&2; exit 1; }
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "commit must be a full 40-character SHA: $COMMIT" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi
}

values=(
  "VERSION=$VERSION"
  "COMMIT=$COMMIT"
  "BASE_URL=$BASE_URL"
  "REPOSITORY=$REPOSITORY"
)
while IFS= read -r line; do
  [[ "$line" =~ ^COSIGN_[A-Z0-9_]+=.+$ ]] && values+=("$line")
done < "$HERE/cosign.env"
for os in linux darwin; do
  for arch in amd64 arm64; do
    asset="$DIST/cosigner-cli-$os-$arch"
    for file in "$asset" "$asset.sigstore.json"; do
      [[ -s "$file" ]] || { echo "missing $file" >&2; exit 1; }
    done
    key="$(printf '%s_%s' "$os" "$arch" | tr '[:lower:]' '[:upper:]')"
    values+=("SHA256_$key=$(sha256 "$asset")" "BUNDLE_SHA256_$key=$(sha256 "$asset.sigstore.json")")
  done
done

script="$(cat "$HERE/install.sh.tmpl")"
for pair in "${values[@]}"; do
  script="${script//@@${pair%%=*}@@/${pair#*=}}"
done
if leftover="$(grep -o '@@[A-Z0-9_]*@@' <<<"$script" | sort -u)" && [[ -n "$leftover" ]]; then
  echo "no value for: $leftover" >&2
  exit 1
fi
printf '%s\n' "$script" > "$DIST/install.sh"
echo "rendered $DIST/install.sh for $VERSION"
