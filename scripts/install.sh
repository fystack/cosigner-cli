#!/usr/bin/env bash
set -euo pipefail

# Explicit versions only. The destination is a new binary-only directory.
VERSION="${1:?Usage: install.sh vX.Y.Z /absolute/new/install/directory}"
INSTALL_DIR="${2:?Supply a new install directory}"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid release version" >&2; exit 1; }
[[ "$INSTALL_DIR" = /* ]] || { echo "Install directory must be absolute" >&2; exit 1; }
[[ ! -e "$INSTALL_DIR" && ! -L "$INSTALL_DIR" ]] || { echo "Install directory exists" >&2; exit 1; }
command -v cosign >/dev/null || { echo "Install Cosign first; see https://docs.sigstore.dev/cosign/system_config/installation/" >&2; exit 1; }
case "$(uname -s)" in Linux) TARGET_OS=linux ;; Darwin) TARGET_OS=darwin ;; *) echo "Linux or macOS required" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) TARGET_ARCH=amd64 ;; arm64|aarch64) TARGET_ARCH=arm64 ;; *) echo "amd64 or arm64 required" >&2; exit 1 ;; esac
REPOSITORY="fystack/cosigner-cli"
ASSET="cosigner-cli-$TARGET_OS-$TARGET_ARCH"
TASK_TEMP="$(mktemp -d)"
trap 'rm -rf -- "$TASK_TEMP"' EXIT
BASE="https://github.com/$REPOSITORY/releases/download/$VERSION"
curl --fail --silent --show-error --location "$BASE/$ASSET" --output "$TASK_TEMP/$ASSET"
curl --fail --silent --show-error --location "$BASE/$ASSET.sigstore.json" --output "$TASK_TEMP/$ASSET.sigstore.json"
cosign verify-blob "$TASK_TEMP/$ASSET" --bundle "$TASK_TEMP/$ASSET.sigstore.json" \
  --certificate-identity "https://github.com/$REPOSITORY/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
mkdir -m 0700 "$INSTALL_DIR"
install -m 0755 "$TASK_TEMP/$ASSET" "$INSTALL_DIR/cosigner-cli"
echo "Installed verified CLI: $INSTALL_DIR/cosigner-cli"
