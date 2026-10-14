#!/usr/bin/env bash
# shellcheck disable=SC2016 # docker stubs and dash -c bodies are single-quoted on purpose
# Renders install.sh with placeholder release files, lints it, and runs its
# Docker checks under dash against stub docker commands.
#
#   scripts/test-installer.sh        # needs dash; shellcheck is used when installed
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
DASH="$(command -v dash)" || { echo "dash is required (apt-get install dash / brew install dash)" >&2; exit 1; }

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- render ------------------------------------------------------------------
mkdir "$WORK/dist"
for os in linux darwin; do
  for arch in amd64 arm64; do
    echo "binary $os $arch" > "$WORK/dist/cosigner-cli-$os-$arch"
    echo "bundle $os $arch" > "$WORK/dist/cosigner-cli-$os-$arch.sigstore.json"
  done
done
"$HERE/render-installer.sh" v9.9.9 0123456789abcdef0123456789abcdef01234567 "$WORK/dist" >/dev/null
INSTALLER="$WORK/dist/install.sh"
grep -q '@@' "$INSTALLER" && fail "unrendered placeholder in install.sh"
grep -qx 'VERSION="v9.9.9"' "$INSTALLER" || fail "VERSION not rendered"
want="$(cd "$WORK/dist" && { sha256sum cosigner-cli-linux-amd64 2>/dev/null || shasum -a 256 cosigner-cli-linux-amd64; } | cut -d ' ' -f 1)"
grep -qx "SHA256_LINUX_AMD64=\"$want\"" "$INSTALLER" || fail "binary SHA-256 not pinned"
echo "ok   render"

# --- lint ----------------------------------------------------------------------
if command -v shellcheck >/dev/null; then
  shellcheck -s sh "$INSTALLER"
  shellcheck "$HERE"/*.sh
  echo "ok   shellcheck"
else
  echo "skip shellcheck (not installed)"
fi
dash -n "$INSTALLER"
dash "$INSTALLER" --help 2>/dev/null || fail "--help failed under dash"
dash "$INSTALLER" --bogus 2>/dev/null && fail "unknown option accepted"
echo "ok   dash"

# --- Docker checks -------------------------------------------------------------
# Everything but the final `main "$@"`, so the functions can be called directly.
sed '$d' "$INSTALLER" > "$WORK/functions.sh"
# A PATH with only the tools check_docker needs, so a real docker never leaks in.
mkdir "$WORK/tools"
for tool in grep tr id sort cat; do ln -s "$(command -v "$tool")" "$WORK/tools/$tool"; done

scenario() { # name docker-stub-body expected-regex... (prefix ! to forbid)
  local name="$1" body="$2" bin="$WORK/bin-$1" out pattern
  shift 2
  mkdir "$bin"
  cp -P "$WORK"/tools/* "$bin/"
  if [[ -n "$body" ]]; then printf '#!/bin/sh\n%s\n' "$body" > "$bin/docker"; chmod +x "$bin/docker"; fi
  [[ "$name" == standalone ]] && { printf '#!/bin/sh\nexit 0\n' > "$bin/docker-compose"; chmod +x "$bin/docker-compose"; }
  out="$(PATH="$bin" "$DASH" -c '. "$1"; WARNINGS=0; OS=linux; check_docker; echo "warnings=$WARNINGS"' _ "$WORK/functions.sh" 2>&1)"
  for pattern in "$@"; do
    if [[ "$pattern" == !* ]]; then
      grep -Eq -- "${pattern#!}" <<<"$out" && fail "$name: unexpected /${pattern#!}/ in:"$'\n'"$out"
    else
      grep -Eq -- "$pattern" <<<"$out" || fail "$name: missing /$pattern/ in:"$'\n'"$out"
    fi
  done
  echo "ok   docker: $name"
}

healthy='case "$1 $2" in "info "*) exit 0;; "version --format") echo 29.1.3;; "compose version") echo 2.40.3+ds1-0ubuntu1;; esac'
scenario healthy "$healthy" 'docker compose 2\.40\.3\+ds1-0ubuntu1' 'daemon is reachable' 'warnings=0'
scenario compose-v5 \
  'case "$1 $2" in "info "*) exit 0;; "version --format") echo 29.5.2;; "compose version") echo v5.5.1;; esac' \
  'docker compose v5\.5\.1' 'warnings=0'
scenario permission \
  'case "$1" in info) echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1;; compose) echo 2.29.1;; esac' \
  'no permission to use Docker|docker group, but this login session' '!daemon is reachable'
scenario daemon-down \
  'case "$1" in info) echo "Cannot connect to the Docker daemon. Is the docker daemon running?" >&2; exit 1;; compose) echo 2.29.1;; esac' \
  'daemon is not running' 'systemctl enable --now docker'
scenario too-old \
  'case "$1 $2" in "info "*) exit 0;; "version --format") echo 19.03.13-ce;; "compose version") echo 1.29.2;; esac' \
  'Compose 1\.29\.2 is too old' 'Engine 19\.03\.13-ce is too old' 'warnings=2'
scenario no-compose \
  'case "$1" in info) exit 0;; version) echo 24.0.7;; compose) echo "unknown command" >&2; exit 1;; esac' \
  'Compose v2 is missing' 'warnings=1'
scenario standalone \
  'case "$1" in info) exit 0;; version) echo 24.0.7;; compose) exit 1;; esac' \
  'standalone docker-compose' 'warnings=1'
scenario no-docker '' 'Docker is not installed' 'warnings=1'

# --- version_ge ----------------------------------------------------------------
check_version() { # have want expect(yes|no)
  local got=no
  dash -c '. "$1"; version_ge "$2" "$3"' _ "$WORK/functions.sh" "$1" "$2" && got=yes
  [[ "$got" == "$3" ]] || fail "version_ge $1 $2: got $got, want $3"
}
check_version 2.40.3+ds1-0ubuntu1 2.0 yes
check_version v5.5.1 2.0 yes
check_version 1.29.2 2.0 no
check_version 20.10.24+dfsg1 20.10 yes
check_version 20.9.1 20.10 no
check_version 29.1.3 20.10 yes
echo "ok   version_ge"

# --- detect_platform picks each platform's own pins --------------------------------
for pair in Linux:x86_64:linux:amd64 Linux:aarch64:linux:arm64 Darwin:x86_64:darwin:amd64 Darwin:arm64:darwin:arm64; do
  IFS=: read -r kernel machine os arch <<<"$pair"
  bin="$WORK/uname-$kernel-$machine"
  mkdir "$bin"
  printf '#!/bin/sh\ncase "$1" in -s) echo %s;; -m) echo %s;; esac\n' "$kernel" "$machine" > "$bin/uname"
  printf '#!/bin/sh\necho 0\n' > "$bin/sysctl" # not under Rosetta
  chmod +x "$bin/uname" "$bin/sysctl"
  got="$(PATH="$bin:$PATH" "$DASH" -c '. "$1"; detect_platform; echo "$CLI_SHA256 $BUNDLE_SHA256 $COSIGN_SHA256"' _ "$WORK/functions.sh")"
  key="$(printf '%s_%s' "$os" "$arch" | tr '[:lower:]' '[:upper:]')"
  want="$(sed -n "s/^SHA256_$key=\"\(.*\)\"$/\1/p; s/^BUNDLE_SHA256_$key=\"\(.*\)\"$/\1/p; s/^COSIGN_SHA256_$key=\"\(.*\)\"$/\1/p" "$INSTALLER" | tr '\n' ' ')"
  [[ "$got " == "$want" ]] || fail "detect_platform $kernel/$machine: got '$got', want '$want'"
done
echo "ok   detect_platform"

# --- --version hands over only to a signed installer -----------------------------
# Stub curl serves another release's installer that leaves a marker when it runs;
# stub cosign accepts or rejects its signature.
handover() { # name verify-exit-code expect(ran|refused)
  local bin="$WORK/handover-$1" mark="$WORK/handover-$1.ran" out status=0
  mkdir "$bin" "$bin-dir"
  cat > "$bin/curl" <<'EOF'
#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in --output) out="$2"; shift 2 ;; *) url="$1"; shift ;; esac
done
case "$url" in
  */v1.0.0/install.sh) printf '#!/bin/sh\ntouch "$HANDOVER_MARK"\n' > "$out" ;;
  */v1.0.0/install.sh.sigstore.json) echo '{}' > "$out" ;;
  *) exit 22 ;;
esac
EOF
  printf '#!/bin/sh\ncase "$1" in version) echo "GitVersion: v3.1.3";; verify-blob) exit %s;; esac\n' "$2" > "$bin/cosign"
  chmod +x "$bin/curl" "$bin/cosign"
  out="$(PATH="$bin:$PATH" HANDOVER_MARK="$mark" COSIGNER_INSTALL_DIR="$bin-dir" \
    "$DASH" "$INSTALLER" --version v1.0.0 --skip-docker-check 2>&1)" || status=$?
  case "$3" in
    ran) [[ $status -eq 0 && -e "$mark" ]] || fail "handover $1: signed installer did not run (status $status):"$'\n'"$out" ;;
    refused) [[ $status -ne 0 && ! -e "$mark" ]] || fail "handover $1: unsigned installer ran (status $status):"$'\n'"$out" ;;
  esac
  echo "ok   handover: $1"
}
handover signed 0 ran
handover unsigned 1 refused

echo "installer tests passed"
