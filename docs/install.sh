#!/bin/sh
# Installs zoneblick from a GitHub release.
#
#   curl -fsSL https://zoneblick.com/install.sh | sh
#
# What it does:
#   1. Downloads the release binary for this system and checks its SHA-256.
#      When the GitHub CLI (gh) is installed and signed in, it also checks
#      the build provenance: a signed statement that the file was built by
#      the project's release workflow.
#   2. Installs it to /usr/local/bin (or --prefix DIR/bin).
#   3. On Linux with systemd, when run as root: creates a `zoneblick` user,
#      a starter config in /etc/zoneblick, a data directory in
#      /var/lib/zoneblick and a systemd service, and starts the service.
#
# Options (after `sh -s --` when piping):
#   --version vX.Y.Z   install this release instead of the newest
#   --prefix DIR       install the binary to DIR/bin (default /usr/local)
#   --no-service       do not set up the systemd service
#   --require-attestation
#                      stop unless the build provenance could be verified
#
# Nothing is changed outside the paths above. Existing config is never
# overwritten.

set -eu

# Everything runs from main, called on the last line, so that a download
# cut off half way runs nothing at all.
main() {

REPO="cschweda/zoneblick"
VERSION="${ZONEBLICK_VERSION:-}"
PREFIX="${ZONEBLICK_PREFIX:-/usr/local}"
SERVICE="auto"
ATTEST="auto"

say() { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || fail "--version needs a value"; VERSION="$2"; shift 2 ;;
    --prefix) [ $# -ge 2 ] || fail "--prefix needs a value"; PREFIX="$2"; shift 2 ;;
    --no-service) SERVICE="no"; shift ;;
    --require-attestation) ATTEST="require"; shift ;;
    -h|--help) sed -n '2,25p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # fetch URL FILE
  if have curl; then curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
  elif have wget; then wget -q --https-only "$1" -O "$2"
  else fail "curl or wget is needed"
  fi
}

have tar || fail "tar is needed"

os=$(uname -s)
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  aarch64|arm64) arch="aarch64" ;;
  *) fail "no release binary for the $arch processor; build from source instead: https://github.com/$REPO#build-from-source" ;;
esac
case "$os" in
  Linux) target="$arch-unknown-linux-musl" ;;
  Darwin) target="$arch-apple-darwin" ;;
  *) fail "this script supports Linux and macOS; on Windows see https://github.com/$REPO#install" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

ASKED_VERSION="$VERSION"
if [ -z "$VERSION" ]; then
  # The newest release, pre-releases included.
  fetch "https://api.github.com/repos/$REPO/releases?per_page=1" "$tmp/releases.json"
  VERSION=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp/releases.json" | head -n 1)
  [ -n "$VERSION" ] || fail "could not find the newest release; pass --version vX.Y.Z"
fi
case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac

name="zoneblick-$VERSION-$target"
base="https://github.com/$REPO/releases/download/$VERSION"
say "Downloading zoneblick $VERSION for $target"
fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz" || fail "download failed: $base/$name.tar.gz"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "download failed: $base/SHA256SUMS"

expected=$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | awk '{print $1}')
[ -n "$expected" ] || fail "no checksum for $name.tar.gz in SHA256SUMS"
if have sha256sum; then actual=$(sha256sum "$tmp/$name.tar.gz" | awk '{print $1}')
elif have shasum; then actual=$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{print $1}')
else fail "sha256sum or shasum is needed to verify the download"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for $name.tar.gz; nothing was installed"
say "Checksum verified"

# The checksum file comes from the same release as the binary, so it only
# shows that the download is whole. The attestation shows where the file
# was built: by this project's release workflow, from the tag asked for.
# These releases were made before attestations and have none; the list is
# exact, so that no other version number can switch the check off.
UNATTESTED=" v0.1.0 v0.1.1 v0.2.0 v0.3.0 v0.4.0 v0.5.0 v0.6.0 v0.6.1 v0.7.0 v0.8.0 v0.9.0 v0.10.0 v0.11.0 v0.12.0 v0.12.1 v0.12.2 "
case "$UNATTESTED" in
  *" $VERSION "*)
    [ "$ATTEST" != "require" ] \
      || fail "$VERSION was released before build provenance was recorded; nothing was installed"
    # The newest release is always attested. If "newest" came out as one
    # of the old ones, the answer about releases is not to be trusted.
    [ -n "$ASKED_VERSION" ] \
      || fail "the newest release was reported as $VERSION, which is older than it should be; pass --version to install it anyway"
    say "Warning: $VERSION has no build provenance to check; only its checksum was verified"
    ;;
  *)
    if have gh && gh auth status >/dev/null 2>&1; then
      gh attestation verify "$tmp/$name.tar.gz" --repo "$REPO" \
        --signer-workflow "$REPO/.github/workflows/release.yml" \
        --source-ref "refs/tags/$VERSION" >/dev/null 2>"$tmp/attest.err" \
        || fail "the build provenance of $name.tar.gz does not verify; nothing was installed ($(head -n 1 "$tmp/attest.err"))"
      say "Build provenance verified"
    elif [ "$ATTEST" = "require" ]; then
      fail "--require-attestation needs the GitHub CLI (gh), signed in; nothing was installed"
    else
      say "Warning: build provenance not checked (needs the GitHub CLI, gh, signed in); only the checksum was verified"
    fi
    ;;
esac

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"

# Use sudo only when the target directory is not writable.
SUDO=""
mkdir -p "$PREFIX/bin" 2>/dev/null || true
if [ ! -w "$PREFIX/bin" ]; then
  have sudo || fail "$PREFIX/bin is not writable; run as root or pass --prefix"
  SUDO="sudo"
fi
$SUDO mkdir -p "$PREFIX/bin"
$SUDO install -m 755 "$tmp/$name/zoneblick" "$PREFIX/bin/zoneblick"
say "Installed $PREFIX/bin/zoneblick"

setup_service() {
  if ! id zoneblick >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/zoneblick --shell /usr/sbin/nologin zoneblick
  fi
  mkdir -p /etc/zoneblick /var/lib/zoneblick
  chown zoneblick:zoneblick /var/lib/zoneblick
  chmod 700 /var/lib/zoneblick

  if [ ! -e /etc/zoneblick/zoneblick.toml ]; then
    cat > /etc/zoneblick/zoneblick.toml <<'CONFIG'
# zoneblick configuration. After editing: systemctl restart zoneblick
# Reference: https://github.com/cschweda/zoneblick#configuration

[server]
# The API and web UI listen here. Keep it on localhost and put a reverse
# proxy with TLS in front for remote access.
bind = "127.0.0.1:8053"
data_dir = "/var/lib/zoneblick"
# The API and the web UI always ask for a token. Leave this out and the
# daemon makes one on its first start, in /var/lib/zoneblick/api-token:
#   sudo cat /var/lib/zoneblick/api-token
# To choose your own, store only its hash here:
#   TOKEN=$(openssl rand -hex 32); echo "$TOKEN"; printf '%s' "$TOKEN" | zoneblick token
# token_sha256 = ""

[schedule]
every = "1h"
max_qps_per_server = 5

# Add one [[zone]] block per zone you control.
# [[zone]]
# name = "example.org"
# seeds = ["www", "mail"]
# ignore = ["_acme-challenge.*"]

# [alerts.webhook]
# url = "https://example.org/hooks/zoneblick"

# [alerts.ntfy]
# url = "https://ntfy.sh/your-topic"

# [alerts.email]
# to = "ops@example.org"
# from = "zoneblick@example.org"
# smtp_host = "smtp.example.org"
# username = "zoneblick"
# password_file = "/etc/zoneblick/smtp-password"
CONFIG
    chown root:zoneblick /etc/zoneblick/zoneblick.toml
    chmod 640 /etc/zoneblick/zoneblick.toml
    say "Wrote /etc/zoneblick/zoneblick.toml"
  else
    say "Kept the existing /etc/zoneblick/zoneblick.toml"
  fi

  cat > /etc/systemd/system/zoneblick.service <<UNIT
[Unit]
Description=zoneblick DNS zone watchdog
Documentation=https://zoneblick.com
After=network-online.target
Wants=network-online.target

[Service]
User=zoneblick
Group=zoneblick
ExecStart=$PREFIX/bin/zoneblick serve --config /etc/zoneblick/zoneblick.toml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/zoneblick

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now zoneblick >/dev/null 2>&1 || true
  say "Service zoneblick is installed and started"
  say ""
  say "Next: add your zones to /etc/zoneblick/zoneblick.toml, then"
  say "  systemctl restart zoneblick"
  say "The web UI is at http://127.0.0.1:8053 on this machine. It asks for"
  say "the API token, which the service made on its first start:"
  say "  sudo cat /var/lib/zoneblick/api-token"
}

if [ "$SERVICE" = "auto" ] && [ "$os" = "Linux" ] && [ -d /run/systemd/system ] && have systemctl; then
  if [ "$(id -u)" -eq 0 ]; then
    setup_service
  else
    say ""
    say "The binary is installed. To also set up the systemd service, run this script as root."
  fi
fi

say ""
say "Try it:  zoneblick check example.org"
}

main "$@"
