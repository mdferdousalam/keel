# Verifying a Keel release

> **No release has been signed yet.** This document describes the process that will apply
> from the first tagged release. Until then, `keel verify-release` reports that it has no
> keys compiled in and refuses — which is the correct answer, and better than reporting a
> success it cannot justify.

## Why this matters more than the rest of Keel's security

Everything else in Keel protects your vault. This protects the *program*. A backdoored
password manager makes every other protection irrelevant, because it can simply read your
passwords as you type them.

So the design goal is specific:

> **A compromise of the Keel GitHub repository, or of its build pipeline, must not be able
> to produce a release that verifies.**

That is achieved by keeping the signing keys off CI entirely. The build pipeline can produce
artifacts, checksums, and Sigstore provenance — all things an attacker who owned the pipeline
could also produce. What it cannot do is sign the checksum manifest, because those keys exist
only on maintainer hardware. An attacker with full control of GitHub Actions therefore gets an
*unsigned* release, and the verifier rejects it.

## The quickest check that is still meaningful

```sh
keel verify-release ./keel-1.0.0/
```

That single command checks both signatures over `SHA256SUMS` and then every file's hash
against it. It reports success only if **both** signatures verify.

## Doing it by hand

If you would rather not trust the binary you are verifying to verify itself — a reasonable
instinct — the same checks with independent tools:

```sh
# 1. Verify the Ed25519 signature over the manifest.
minisign -Vm SHA256SUMS -P "$KEEL_MINISIGN_PUBKEY"

# 2. Verify the checksums of everything else.
sha256sum --check SHA256SUMS
```

Step 1 must come first. Checking hashes against a manifest nobody signed is theatre: an
attacker who swapped an artifact would simply update the manifest to match.

For the ML-DSA signature there is no widely-installed command-line tool yet, which is
precisely why `keel verify-release` exists. Using a previously-verified Keel to check a new
one is the practical answer, and it is why the Ed25519 signature is also present: it can be
checked with tooling that predates this project.

## Why two signatures, and why both must pass

| Signature | Scheme | File |
|---|---|---|
| Classical | Ed25519, minisign format | `SHA256SUMS.minisig` |
| Post-quantum | ML-DSA-65 (FIPS 204) | `SHA256SUMS.mldsa.sig` |

A release signature has to resist forgery for as long as the software is trusted, which is
years. Requiring **both** means an attacker must break both schemes; the hybrid is at least as
strong as its stronger component. Requiring *either* would make it only as strong as the
weaker one, which would defeat the point of having two.

Note the asymmetry with the vault itself. Your vault needs no post-quantum work, because it
contains no public-key cryptography at all — passphrase, Argon2id, symmetric cipher, and
nothing else. Signing is the one place in this project where the post-quantum question is real.
See the README for the full argument.

## Where the public keys come from

Compiled into the `keel` binary, and published in three independent places:

1. This repository, in the README.
2. The project website.
3. The first release announcement.

Compiling them in matters: fetching a key from the same place the artifacts came from would
make the whole exercise circular. Publishing in three places matters because substituting the
key then requires compromising all three.

If you ever see a Keel public key that does not match all three, do not use the release. Key
rotation is announced in a release signed by the *old* keys; a new key appearing without that
transition is a reason to stop.

## Build provenance

Releases also carry Sigstore-backed SLSA provenance:

```sh
gh attestation verify keel-1.0.0-x86_64-unknown-linux-musl.tar.gz --repo keel-vault/keel
```

This proves which workflow, which commit, and which builder produced the artifact, and it is
recorded in a public transparency log. Treat it as **supplementary**: a compromised pipeline
can produce valid provenance too. Its real value is that a targeted backdoor cannot be
delivered to one user without leaving a public record.

The offline signatures are the trust root. Provenance is corroboration.

## The stronger check: rebuild it yourself

Signatures prove the maintainer signed those bytes. They do not prove the bytes correspond to
the published source. For that, rebuild and compare — Linux `musl` artifacts are byte-for-byte
reproducible, and CI proves it on every release by building twice in independent jobs and
requiring identical output.

See [`REPRODUCE.md`](REPRODUCE.md). If your rebuild does not match, that is important and
urgent; please report it.

## What verification cannot tell you

Being clear about the boundaries:

- **It cannot tell you the source code is honest.** It tells you the binary matches the
  source. Reading the source, or trusting people who have, is a separate exercise — which is
  the entire reason Keel is open source.
- **It cannot help if your machine is already compromised.** Malware that can modify `keel`
  can also modify the verification you run with it.
- **It says nothing about your vault.** A verified binary with a guessable passphrase is
  still a vault at risk.

## A note on operating-system warnings

Keel ships **without paid code-signing certificates**. macOS and Windows will therefore warn
about installers downloaded through a browser.

That is a funding decision, not a security one, and it is worth being clear about the
direction: reproducible builds plus offline hybrid signatures are a *stronger* integrity
guarantee than a purchased certificate, which attests only that someone paid a certificate
authority. What a certificate buys is a smoother first-run experience, not more assurance.

To avoid the warnings, install through a channel that verifies hashes and does not mark
downloads as quarantined: Homebrew on macOS, Scoop or winget on Windows, or your distribution's
package manager on Linux.
