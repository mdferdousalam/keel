# Packaging

Bitting is distributed **without paid code-signing certificates**. That is a deliberate
constraint, and it shapes this directory: the strategy is to route users through channels
where OS gatekeeping does not apply, and to be honest about the ones where it does.

The integrity story does not depend on a certificate. Releases are reproducible on Linux and
signed offline with two independent algorithms (Ed25519 and ML-DSA-65), and
`bitting verify-release` requires **both**. A purchased certificate would improve first-run UX and
would not improve integrity — a compromised CI pipeline can be handed a certificate, and cannot
be handed an offline key. That framing belongs in the release notes, not in an apology.

## Per-platform

| Channel | Gatekeeping | Notes |
|---|---|---|
| **Homebrew tap** (macOS) | None | `brew` downloads are not browser-quarantined, so Gatekeeper's "damaged app" dialog never appears. The primary macOS channel. |
| **curl install script** (macOS/Linux CLI) | None | The quarantine attribute is applied by browsers, not by `curl`. Quarantine-free by construction. |
| **`.dmg`** (macOS) | Yes | Ad-hoc signed, which is free and **mandatory** — unsigned arm64 binaries will not execute at all on Apple Silicon. Users must right-click → Open once. |
| **Scoop bucket** (Windows) | None | Scoop downloads via PowerShell and verifies hashes, so SmartScreen's browser-download reputation check does not fire. The primary Windows channel. |
| **winget** (Windows) | Partial | Community repo listing with hash verification. |
| **portable `.zip`** (Windows) | Minimal | Extract and run. Far less friction than an installer. |
| **`.deb` / `.rpm` / AppImage** (Linux) | None | Built with `nfpm`. Linux is the smoothest platform because nothing gatekeeps. |
| **AUR** (Arch) | None | `bitting` builds from source with a committed lockfile; `bitting-bin` uses the release artifact. |
| **`cargo install bitting-cli`** | None | Builds from source. Always available. |

## What the release actually produces

`release.yml` builds five targets and publishes these as a draft:

| Asset | Channel it feeds |
|---|---|
| `bitting-<v>-macos-universal.tar.gz` | direct download (both Apple architectures, `lipo`'d and ad-hoc signed) |
| `bitting-<v>-{aarch64,x86_64}-apple-darwin.tar.gz` | per-architecture direct download |
| `bitting-<v>-{x86_64,aarch64}-unknown-linux-musl.tar.gz` | direct download, and the input to the packages below |
| `bitting_<v>_{amd64,arm64}.deb`, `.rpm` | apt / dnf, built by `nfpm` from `nfpm.yaml` |
| `SHA256SUMS`, SBOM, provenance | verification |

Every archive contains all four binaries — `bitting`, `bitting-agent`, `bitting-mcp`,
`bitting-native-host` — which is the set `nfpm.yaml` and `PKGBUILD` install. That agreement is
load-bearing and was briefly untrue: the archive step shipped only the first two while the
packages referenced all four.

**Windows is built but not published.** `x86_64-pc-windows-gnu` is the reproducibility
reference target and its build proves the code compiles, but the agent has no named-pipe
transport, so `Transport::bind` returns `Unsupported` and every command fails at the transport
layer. A Windows package would install a binary where `bitting init` cannot work.
`scoop-bitting.json` is parked until that lands. No arm64 Windows target exists at all.

## What is here and what is not

The manifests in this directory are **templates**. Every one of them needs a real release —
a tag, published artifacts, and their SHA-256 sums — before it can be filled in, and none has
been exercised against a real download because no release exists yet. They are written now so
that cutting the first release is a matter of substituting hashes rather than designing a
distribution strategy under time pressure.

Two of them describe a build from source, not from the binary tarball — `homebrew-bitting.rb`
and `PKGBUILD` both compile against the committed lockfile — so their `url` is the GitHub
source archive for the tag. The Homebrew formula pointed at the binary tarball until the first
release was prepared, which would have failed on a missing `crates/` directory.

Nothing here is signed, because the signing keys do not exist. Generating them is a maintainer
ceremony on an offline machine, described in `SECURITY.md`, and doing it inside a development
session would defeat its entire purpose: the value of that key is precisely that it has never
been on a networked machine.
