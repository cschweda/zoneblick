# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "0.12.2"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.2/zoneblick-v0.12.2-aarch64-apple-darwin.tar.gz"
      sha256 "c3a792904ee18716221179ad7cf1ffc8be71519b2503fd9ce15f9a5cb672050b"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.2/zoneblick-v0.12.2-x86_64-apple-darwin.tar.gz"
      sha256 "5eaa7bffee320d6ea2b2cc6c72a2a294e71a470e7709caeef274634ed5afaeba"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.2/zoneblick-v0.12.2-aarch64-unknown-linux-musl.tar.gz"
      sha256 "e46a9954c2c24da77dd832e0cbd068624f37c0cf2270b71b9e9600962727e6b2"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.12.2/zoneblick-v0.12.2-x86_64-unknown-linux-musl.tar.gz"
      sha256 "e85328ad595c4b3207a96a4de8a06d7551862d75686af50b06538db49097ea95"
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
