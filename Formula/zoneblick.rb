# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "0.14.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.14.0/zoneblick-v0.14.0-aarch64-apple-darwin.tar.gz"
      sha256 "90de88eda36019851fff139062bbb17069820db1d0375c2c31077ea5e23de788"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.14.0/zoneblick-v0.14.0-x86_64-apple-darwin.tar.gz"
      sha256 "d70f7d08495a641b49df0c495e369b6a7a1bd91641f611b2b74f7c364340978f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.14.0/zoneblick-v0.14.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "e729a17ed8d42850a1edd4f7a8da972ff7e2b1242b16ffd751c7c364a82b2c72"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.14.0/zoneblick-v0.14.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "7a8e28b0b3a5c6e4cbeeefeeb556cc018a7dc14b14ba24eace8533c68343523f"
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
