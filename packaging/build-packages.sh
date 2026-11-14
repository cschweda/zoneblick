#!/bin/sh
# Builds the .deb and .rpm packages from a built Linux binary.
#
#   packaging/build-packages.sh VERSION ARCH BINARY OUTDIR
#
# VERSION is like 0.12.0 or v0.12.0; ARCH is x86_64 or aarch64. Needs
# dpkg-deb and rpmbuild. Both packages install the same files as the
# install script: the binary, the systemd unit, and a starter config in
# /etc/zoneblick that an upgrade never overwrites.

set -eu

[ $# -eq 4 ] || { echo "usage: $0 VERSION ARCH BINARY OUTDIR" >&2; exit 1; }
version="${1#v}"
arch="$2"
binary="$3"
out="$4"
case "$arch" in
  x86_64) deb_arch="amd64" ;;
  aarch64) deb_arch="arm64" ;;
  *) echo "$0: unknown architecture $arch" >&2; exit 1 ;;
esac

here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# The files both packages install.
stage="$work/stage"
mkdir -p "$stage/usr/bin" "$stage/usr/lib/systemd/system" "$stage/etc/zoneblick" \
  "$stage/usr/share/doc/zoneblick"
install -m 755 "$binary" "$stage/usr/bin/zoneblick"
grep -v '^#' "$here/zoneblick.service" | sed 's#/usr/local/bin/zoneblick#/usr/bin/zoneblick#' \
  > "$stage/usr/lib/systemd/system/zoneblick.service"
# The starter config is the one in the install script.
sed -n "/<<'CONFIG'\$/,/^CONFIG\$/p" "$root/install.sh" | sed '1d;$d' \
  > "$stage/etc/zoneblick/zoneblick.toml"
[ -s "$stage/etc/zoneblick/zoneblick.toml" ] || { echo "$0: no starter config found" >&2; exit 1; }
chmod 640 "$stage/etc/zoneblick/zoneblick.toml"
for doc in README.md LICENSE-MIT LICENSE-APACHE THIRD-PARTY.md; do
  install -m 644 "$root/$doc" "$stage/usr/share/doc/zoneblick/$doc"
done

cat > "$work/postinst" <<'SCRIPT'
if ! id zoneblick >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/zoneblick --shell /usr/sbin/nologin zoneblick
fi
mkdir -p /var/lib/zoneblick
chown zoneblick:zoneblick /var/lib/zoneblick
chmod 700 /var/lib/zoneblick
chown root:zoneblick /etc/zoneblick/zoneblick.toml
chmod 640 /etc/zoneblick/zoneblick.toml
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  if systemctl is-enabled zoneblick >/dev/null 2>&1; then
    systemctl try-restart zoneblick || true
  else
    systemctl enable --now zoneblick >/dev/null 2>&1 || true
  fi
fi
SCRIPT
cat > "$work/prerm" <<'SCRIPT'
if [ -d /run/systemd/system ]; then
  systemctl disable --now zoneblick >/dev/null 2>&1 || true
fi
SCRIPT

description="zoneblick checks DNS zones from the root, asks every authoritative
 nameserver directly, stores each run and reports what changed. It runs
 as a command or as a daemon with a web UI and alerts."

# ---- .deb
deb="$work/deb"
mkdir -p "$deb/DEBIAN"
cp -a "$stage/." "$deb/"
cat > "$deb/DEBIAN/control" <<CONTROL
Package: zoneblick
Version: $version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: zoneblick <noreply@zoneblick.com>
Homepage: https://zoneblick.com
Description: A self-hosted DNS zone watchdog
 $description
CONTROL
echo "/etc/zoneblick/zoneblick.toml" > "$deb/DEBIAN/conffiles"
{ echo '#!/bin/sh'; echo 'set -e'; cat "$work/postinst"; } > "$deb/DEBIAN/postinst"
{
  echo '#!/bin/sh'; echo 'set -e'
  echo 'if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then'
  cat "$work/prerm"
  echo 'fi'
} > "$deb/DEBIAN/prerm"
chmod 755 "$deb/DEBIAN/postinst" "$deb/DEBIAN/prerm"
dpkg-deb --build --root-owner-group "$deb" "$out/zoneblick_${version}_${deb_arch}.deb" >/dev/null
echo "built $out/zoneblick_${version}_${deb_arch}.deb"

# ---- .rpm
rpm="$work/rpm"
mkdir -p "$rpm/SPECS"
cat > "$rpm/SPECS/zoneblick.spec" <<SPEC
Name: zoneblick
Version: $version
Release: 1
Summary: A self-hosted DNS zone watchdog
License: MIT OR Apache-2.0
URL: https://zoneblick.com
AutoReqProv: no
Requires(pre): shadow-utils

%global debug_package %{nil}
%global __os_install_post %{nil}
%define _build_id_links none

%description
$description

%install
mkdir -p %{buildroot}
cp -a $stage/. %{buildroot}/

%files
%attr(0755, root, root) /usr/bin/zoneblick
%attr(0644, root, root) /usr/lib/systemd/system/zoneblick.service
%dir /etc/zoneblick
%config(noreplace) %attr(0640, root, root) /etc/zoneblick/zoneblick.toml
/usr/share/doc/zoneblick

%post
$(cat "$work/postinst")

%preun
if [ "\$1" = "0" ]; then
$(cat "$work/prerm")
fi
SPEC
rpmbuild -bb --quiet --target "$arch" --define "_topdir $rpm" "$rpm/SPECS/zoneblick.spec"
cp "$rpm/RPMS/$arch/zoneblick-$version-1.$arch.rpm" "$out/"
echo "built $out/zoneblick-$version-1.$arch.rpm"
