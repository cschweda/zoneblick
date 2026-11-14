# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "0.13.1"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.13.1/zoneblick-v0.13.1-aarch64-apple-darwin.tar.gz"
      sha256 "93ad8b9da05369e426b2b21f09dbd7e4214b1251d35a54d64d6dbd7c792cb6c7"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.13.1/zoneblick-v0.13.1-x86_64-apple-darwin.tar.gz"
      sha256 "0ebe5ca70f32709237ab75ad40b4155d9e6f560719e51bfe8ecac09188070f7d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.13.1/zoneblick-v0.13.1-aarch64-unknown-linux-musl.tar.gz"
      sha256 "7ecc4453bc022c1c48bd9c24d904902f4fe3c36b8ba33b4734ed7bb50c030db3"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.13.1/zoneblick-v0.13.1-x86_64-unknown-linux-musl.tar.gz"
      sha256 "92236120923887bd37e90a1d6c9a1728613fdf06b6c1915da1c7c3425a3f2870"
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
