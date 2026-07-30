# Homebrew formula for the Keel CLI and agent.
#
# Lives in a tap (`keel-vault/homebrew-keel`) rather than homebrew-core, which has notability
# requirements a new project does not meet. Copied there on release; kept here so it is
# reviewed alongside the code it installs.
#
# Homebrew is the *primary* macOS channel on purpose: `brew` does not apply the quarantine
# attribute, so Gatekeeper's "damaged app" dialog never appears — which matters because Keel
# ships without a paid Developer ID. See packaging/README.md.
class Keel < Formula
  desc "Local-first password manager with no server, no account, and no telemetry"
  homepage "https://github.com/keel-vault/keel"
  license "GPL-3.0-or-later"
  version "0.0.0-unreleased"

  # Filled in at release. Left obviously invalid rather than as a plausible-looking
  # placeholder: a wrong-but-real-shaped hash is a hash somebody might not check.
  url "https://github.com/keel-vault/keel/releases/download/v#{version}/keel-#{version}-macos-universal.tar.gz"
  sha256 "REPLACE_WITH_THE_PUBLISHED_SHA256"

  depends_on "rust" => :build

  def install
    # Built from source in the tap rather than installed from a bottle, so the thing a user
    # runs is built from the lockfile in the tag they asked for.
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/keel-cli"
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/keel-agent"
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/keel-mcp"
    system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/keel-native-host"
    doc.install "README.md", "LICENSE", "docs/threat-model.md"
  end

  def caveats
    <<~EOS
      Keel stores your vault in one encrypted file. Create it with:

        keel init

      Nothing starts automatically. Any Keel command starts the agent on demand, and the
      agent exits when it has been idle and locked.

      To fill passwords in a browser, run:

        keel setup-browser --extension-id <ID>

      Keel is distributed without a paid Apple Developer ID. Installing through Homebrew
      avoids Gatekeeper entirely; a downloaded .dmg would need a right-click → Open.
    EOS
  end

  test do
    assert_match "keel", shell_output("#{bin}/keel --version")
    # `verify-release` needs no vault and no agent, so it is the one command that can be
    # exercised in a sandboxed test.
    assert_match(/refus|no signing keys|signature/i,
                 shell_output("#{bin}/keel verify-release #{testpath} 2>&1", 1))
  end
end
