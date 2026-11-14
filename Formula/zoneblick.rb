# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "0.15.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.15.0/zoneblick-v0.15.0-aarch64-apple-darwin.tar.gz"
      sha256 "8d89c6f76b3ef724e002178fbc8e9b0e68846e6f52e0b96a35a95d45527febe1"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.15.0/zoneblick-v0.15.0-x86_64-apple-darwin.tar.gz"
      sha256 "fef2baabc062aae3b7cfef82402bb3bda6996425654f6befac4b19aad50f0997"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.15.0/zoneblick-v0.15.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "5c075506fb71454a6117e3e827953937a697fd68ff32c1ee88cd6adf1e119de4"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.15.0/zoneblick-v0.15.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "9dd6e320aaf8971533d1f355e338f1ac69818aa39f1cc6a0363acb3a54013c27"
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
