# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "0.11.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.11.0/zoneblick-v0.11.0-aarch64-apple-darwin.tar.gz"
      sha256 "b9670b1ef7c31078970d2a4a23d1639640888c237dc6d074551f41968871d35d"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.11.0/zoneblick-v0.11.0-x86_64-apple-darwin.tar.gz"
      sha256 "14702b92b9e5c6edb8edafcf3456d42f3e39519524bf710a8786944693585409"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.11.0/zoneblick-v0.11.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "da81712fbf8bf1b01c6d04d9af2e51dc874a8b900ce37ffe6b024aa538bda237"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.11.0/zoneblick-v0.11.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "d5695529ef8148da090d7214fd79ad9f5a2d0965c8f0ac2dc01a643526b817c4"
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
