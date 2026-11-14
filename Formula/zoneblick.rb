# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "0.12.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.0/zoneblick-v0.12.0-aarch64-apple-darwin.tar.gz"
      sha256 "2f45897dd4218468e8dfa83f8518277cc39367e423dc8945952c48fa64b1429f"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.0/zoneblick-v0.12.0-x86_64-apple-darwin.tar.gz"
      sha256 "2febbe06fc90c75d2d9b67b667b3cee1c5984aa3fc4d4af824810172be57fb64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.0/zoneblick-v0.12.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "d604609f254ed6cfcdb272413c76662ce2d190ebc4b58d173ddbd5e8d9bcad08"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.0/zoneblick-v0.12.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "2c20f418f30c177eac9f11737e57ded742582441620f62e3948fd50a5c4b3680"
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
