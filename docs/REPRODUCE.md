# Reproducing a Keel build

A signature proves the maintainer signed those bytes. It does not prove those bytes came from
the published source. Rebuilding is what closes that gap, and it is the only check that does
not require trusting the maintainer at all.

## What is claimed, and what is not

Overclaiming reproducibility damages trust more than scoping it does, so the scope is exact:

| Target | Reproducible | Notes |
|---|---|---|
| `x86_64-unknown-linux-musl` | **Yes, byte for byte** | The reference target |
| `aarch64-unknown-linux-musl` | **Yes, byte for byte** | |
| `x86_64-pc-windows-gnu` | **Yes, byte for byte** | Why the GNU toolchain is used for the reference build |
| `x86_64-pc-windows-msvc` | No | MSVC embeds timestamps and non-deterministic PDB signatures |
| `*-apple-darwin` (signed) | No | `codesign` embeds a timestamp |
| `*-apple-darwin` (unsigned) | **Yes** | Hash published in `UNSIGNED-HASHES` |

The Linux `musl` claim is not aspirational. Every release build runs the deterministic targets
**twice, in independent CI jobs**, and fails if the outputs differ. Claiming reproducibility
without testing it is how a project finds out from a user that its builds have not been
reproducible for a year.

## Rebuilding

```sh
git clone https://github.com/keel-vault/keel
cd keel
git checkout v1.0.0          # the tag you are checking

export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
export TZ=UTC
export LC_ALL=C
export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME/.cargo=/cargo"

rustup target add x86_64-unknown-linux-musl
cargo build --locked --profile release-repro \
  --target x86_64-unknown-linux-musl -p keel-cli -p keel-agent

sha256sum target/x86_64-unknown-linux-musl/release-repro/keel \
          target/x86_64-unknown-linux-musl/release-repro/keel-agent
```

Compare those hashes against the published `SHA256SUMS`. `--locked` is not optional: without
it Cargo may resolve a different dependency version and produce a legitimately different
binary.

## Why each environment variable is needed

Each one removes a specific way the output could depend on *where* it was built rather than
*what* was built:

- **`SOURCE_DATE_EPOCH`** — build tooling embeds timestamps. Pinning it to the commit date
  makes them a function of the source.
- **`--remap-path-prefix`** — panic messages and debug info contain absolute source paths, so
  without this the output depends on your home directory. This also keeps the maintainer's
  directory layout out of shipped binaries.
- **`TZ=UTC`, `LC_ALL=C`** — any date or number formatted during the build would otherwise
  vary by locale.
- **The pinned toolchain** in `rust-toolchain.toml` — a different compiler version produces
  different code. Cargo honours it automatically; do not override it.

## Comparing macOS artifacts

`codesign` embeds a timestamp, so a signed Mach-O binary cannot be byte-identical between
builds. Two options:

**Compare the unsigned hash.** Releases include an `UNSIGNED-HASHES` file recorded before
signing. Build locally without signing and compare against that.

**Strip the signature and compare.** Also works, with the caveat that `codesign
--remove-signature` does not always restore the exact pre-signing bytes:

```sh
cp keel keel-stripped
codesign --remove-signature keel-stripped
shasum -a 256 keel-stripped
```

Keel is ad-hoc signed rather than notarized because the project has no paid Apple Developer
ID. Ad-hoc signing is not optional even so: an unsigned arm64 binary will not execute at all
on Apple Silicon.

## Building in a pinned container

For the strongest match, build in the same environment CI does, so the toolchain and sysroot
are fixed by hash rather than by whatever your distribution installed:

```sh
docker run --rm -v "$PWD:/src" -w /src \
  rust:1.93.1-alpine \
  sh -c 'apk add --no-cache musl-dev && \
         SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) TZ=UTC LC_ALL=C \
         RUSTFLAGS="--remap-path-prefix=/src=/build" \
         cargo build --locked --profile release-repro \
           --target x86_64-unknown-linux-musl -p keel-cli -p keel-agent'
```

## If your rebuild does not match

**Please report it.** A mismatch means one of:

1. **A reproducibility bug.** Something in the build depends on the environment. Worth fixing
   regardless of whether it is exploitable, because it removes the ability to check anything.
2. **A different input.** A different toolchain version, a stale `Cargo.lock`, or the wrong
   tag. Check these first.
3. **The published binary does not match the published source.** The serious case, and exactly
   what this whole exercise exists to detect.

Open a public issue with your toolchain version, platform, and the hashes you obtained. This is
a case where public discussion is right: if a published binary does not match its source, every
user needs to know quickly, and there is nothing to be gained by coordinating disclosure of a
fact the attacker already knows.

## Publishing a counter-attestation

Independent rebuilds are worth more than the maintainer's word, and they are what turn "trust
me" into "verify me". If your rebuild matches, consider recording it:

1. Fork the repository.
2. Run the `rebuild.yml` workflow against the tag.
3. Add your result to `attestations/<version>/<your-handle>.txt` and open a pull request.

Enough independent confirmations make a substituted binary detectable by anyone reading the
repository, without their having to rebuild it themselves.
