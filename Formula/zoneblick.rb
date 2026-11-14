# Written by packaging/formula.sh when a release is published.
class Zoneblick < Formula
  desc "Self-hosted DNS zone watchdog"
  homepage "https://zoneblick.com"
  version "0.15.1"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.15.1/zoneblick-v0.15.1-aarch64-apple-darwin.tar.gz"
      sha256 "0f0a1ee614dd52486af74ee8a64d515648cf9799ac9aa1d24edd1a7718c7b166"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.15.1/zoneblick-v0.15.1-x86_64-apple-darwin.tar.gz"
      sha256 "606f4e03bc460fcea3575a522c6176e67e59bd922037c6b9e7ddea27f8b33585"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.15.1/zoneblick-v0.15.1-aarch64-unknown-linux-musl.tar.gz"
      sha256 "3e878e1fd0a21846b6593e504b223ae0063405e7c250cdb5e360ffd080906ace"
    end
    on_intel do
      url "https://github.com/cschweda/zoneblick/releases/download/v0.15.1/zoneblick-v0.15.1-x86_64-unknown-linux-musl.tar.gz"
      sha256 "44a207822264199c16ff747a42d664c2f8b77ff07fb7e7b48abdf0583f9d4ca1"
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
