#!/bin/sh
# Writes the Homebrew formula for a release to standard output.
#
#   packaging/formula.sh VERSION SHA256SUMS > Formula/zoneblick.rb
#
# VERSION is like v0.12.0; SHA256SUMS is the file published with the
# release. The formula installs the release binaries; nothing is compiled.

set -eu

[ $# -eq 2 ] || { echo "usage: $0 VERSION SHA256SUMS" >&2; exit 1; }
tag="$1"
case "$tag" in v*) ;; *) tag="v$tag" ;; esac
sums="$2"

sum() {
  value=$(grep " zoneblick-$tag-$1.tar.gz\$" "$sums" | awk '{print $1}')
  [ -n "$value" ] || { echo "$0: no checksum for $1 in $sums" >&2; exit 1; }
  printf '%s' "$value"
}

base="https://github.com/cschweda/zoneblick/releases/download/$tag/zoneblick-$tag"
mac_arm=$(sum aarch64-apple-darwin)
mac_intel=$(sum x86_64-apple-darwin)
linux_arm=$(sum aarch64-unknown-linux-musl)
linux_intel=$(sum x86_64-unknown-linux-musl)

cat <<FORMULA
# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "${tag#v}"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "$base-aarch64-apple-darwin.tar.gz"
      sha256 "$mac_arm"
    end
    on_intel do
      url "$base-x86_64-apple-darwin.tar.gz"
      sha256 "$mac_intel"
    end
  end

  on_linux do
    on_arm do
      url "$base-aarch64-unknown-linux-musl.tar.gz"
      sha256 "$linux_arm"
    end
    on_intel do
      url "$base-x86_64-unknown-linux-musl.tar.gz"
      sha256 "$linux_intel"
    end
  end

  def install
    bin.install "zoneblick"
    doc.install "README.md", "THIRD-PARTY.md"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/zoneblick --version")
  end
end
FORMULA
