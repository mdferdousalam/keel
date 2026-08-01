# Homebrew formula for the Bitting CLI and agent.
#
# Lives in a tap (`mdferdousalam/homebrew-bitting`) rather than homebrew-core, which has notability
# requirements a new project does not meet. Copied there on release; kept here so it is
# reviewed alongside the code it installs.
#
# Homebrew is the *primary* macOS channel on purpose: `brew` does not apply the quarantine
# attribute, so Gatekeeper's "damaged app" dialog never appears — which matters because Bitting
# ships without a paid Developer ID. See packaging/README.md.
class Bitting < Formula
  desc "Local-first password manager with no server, no account, and no telemetry"
  homepage "https://github.com/mdferdousalam/bitting"
  license "AGPL-3.0-or-later"
  version "0.0.0-unreleased"

  # The **source** archive, not the binary tarball. `install` below runs `cargo install
  # --path crates/...`, which needs the crate tree; this used to point at
  # `bitting-<version>-macos-universal.tar.gz`, which contains four compiled binaries and no
  # source, so the build would have failed on a missing path the moment anyone ran it.
  #
  # The binary tarball still exists on the release for people who want a direct download —
  # it is simply not what a build-from-source formula consumes.
  #
  # Filled in at release. Left obviously invalid rather than as a plausible-looking
  # placeholder: a wrong-but-real-shaped hash is a hash somebody might not check.
  url "https://github.com/mdferdousalam/bitting/archive/refs/tags/v#{version}.tar.gz"
  sha256 "REPLACE_WITH_THE_PUBLISHED_SHA256"

  depends_on "rust" => :build

  def install
    # Built from source in the tap rather than installed from a bottle, so the thing a user
    # runs is built from the lockfile in the tag they asked for.
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/bitting-cli"
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/bitting-agent"
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/bitting-mcp"
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/bitting-native-host"
    doc.install "README.md", "LICENSE", "docs/threat-model.md"
  end

  def caveats
    <<~EOS
      Bitting stores your vault in one encrypted file. Create it with:

        bitting init

      Nothing starts automatically. Any Bitting command starts the agent on demand, and the
      agent exits when it has been idle and locked.

      To fill passwords in a browser, run:

        bitting setup-browser --extension-id <ID>

      Bitting is distributed without a paid Apple Developer ID. Installing through Homebrew
      avoids Gatekeeper entirely; a downloaded .dmg would need a right-click → Open.
    EOS
  end

  test do
    assert_match "bitting", shell_output("#{bin}/bitting --version")
    # `verify-release` needs no vault and no agent, so it is the one command that can be
    # exercised in a sandboxed test.
    assert_match(/refus|no signing keys|signature/i,
                 shell_output("#{bin}/bitting verify-release #{testpath} 2>&1", 1))
  end
end
