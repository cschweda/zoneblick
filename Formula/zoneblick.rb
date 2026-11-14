# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "0.13.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.13.0/zoneblick-v0.13.0-aarch64-apple-darwin.tar.gz"
      sha256 "393927a36da40bb521e7e96558647dde5be2aaf90c8d8b679a27c2b070fc649b"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.13.0/zoneblick-v0.13.0-x86_64-apple-darwin.tar.gz"
      sha256 "d4a446dada8ccab2f671ab6e26bdeea86e4379863b37de126a26a9e7ccd569d0"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.13.0/zoneblick-v0.13.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "90f1e04746558251ebb47c52c7dbda8a67df0737cb9598afba24fa71281655f2"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.13.0/zoneblick-v0.13.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "02dd9df1cfff48245a6c1cbf600cce5e6939451eed7909d534b4b81021f7f4ed"
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
