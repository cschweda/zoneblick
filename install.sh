#!/bin/sh
# Installs zoneblick from a GitHub release.
#
#   curl -fsSL https://zoneblick.com/install.sh | sh
#
# What it does:
#   1. Downloads the release binary for this system and checks its SHA-256.
#   2. Installs it to /usr/local/bin (or --prefix DIR/bin).
#   3. On Linux with systemd, when run as root: creates a `zoneblick` user,
#      a starter config in /etc/zoneblick, a data directory in
#      /var/lib/zoneblick and a systemd service, and starts the service.
#
# Options (after `sh -s --` when piping):
#   --version vX.Y.Z   install this release instead of the newest
#   --prefix DIR       install the binary to DIR/bin (default /usr/local)
#   --no-service       do not set up the systemd service
#
# Nothing is changed outside the paths above. Existing config is never
# overwritten.

set -eu

REPO="cschweda/zoneblick"
VERSION="${ZONEBLICK_VERSION:-}"
PREFIX="${ZONEBLICK_PREFIX:-/usr/local}"
SERVICE="auto"

say() { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || fail "--version needs a value"; VERSION="$2"; shift 2 ;;
    --prefix) [ $# -ge 2 ] || fail "--prefix needs a value"; PREFIX="$2"; shift 2 ;;
    --no-service) SERVICE="no"; shift ;;
    -h|--help) sed -n '2,22p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # fetch URL FILE
  if have curl; then curl -fsSL "$1" -o "$2"
  elif have wget; then wget -q "$1" -O "$2"
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
# Needed before binding to anything but localhost. Make one with:
#   zoneblick token "$(openssl rand -hex 32)"
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
  say "The web UI is at http://127.0.0.1:8053 on this machine."
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
