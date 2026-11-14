# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "0.12.1"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.1/zoneblick-v0.12.1-aarch64-apple-darwin.tar.gz"
      sha256 "ec9077e3abfbfb22c82fb838972424e40bc1541d8b1fed9b5272e8a01f3f5331"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.1/zoneblick-v0.12.1-x86_64-apple-darwin.tar.gz"
      sha256 "278379ca5e35dff60070a9b7ecb7f9c1d16acef300c0c2e858aee2d3e192ef42"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.1/zoneblick-v0.12.1-aarch64-unknown-linux-musl.tar.gz"
      sha256 "b559702390773833b73822d90a2efabc42bdfda1d7ec0deaea8c3807985a8faa"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.1/zoneblick-v0.12.1-x86_64-unknown-linux-musl.tar.gz"
      sha256 "f77c604672d1b5863bc41e8fa4b3b2e88a71d1a8176e78c6a3cdf0cd0a86b028"
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
