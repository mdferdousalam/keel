# Bitting

[![CI](https://github.com/mdferdousalam/bitting/actions/workflows/ci.yml/badge.svg)](https://github.com/mdferdousalam/bitting/actions/workflows/ci.yml)
[![Security audit](https://github.com/mdferdousalam/bitting/actions/workflows/audit.yml/badge.svg)](https://github.com/mdferdousalam/bitting/actions/workflows/audit.yml)
[![CodeQL](https://github.com/mdferdousalam/bitting/actions/workflows/codeql.yml/badge.svg)](https://github.com/mdferdousalam/bitting/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/mdferdousalam/bitting/badge)](https://scorecard.dev/viewer/?uri=github.com/mdferdousalam/bitting)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/licence-AGPL--3.0--or--later-blue)](LICENSE)

A local-first, open-source password manager built for people who want to verify
their tools rather than trust them.

The *bitting* of a key is the pattern of cuts along its blade — and the code that
records those cuts, from which the key can be reproduced. It is the part that is
actually secret. Everything else about a lock can be examined in daylight, which is
roughly the argument this project makes about its own source.

> **Status: working, but pre-release.** The command line, the agent, and the MCP server all
> function — you can create a vault, store and retrieve passwords, import from another
> manager, and give an AI agent scoped access. The on-disk format is **not yet frozen** and
> there are no signed releases, so a future version may not open a vault you create today.
> Do not put passwords you cannot afford to lose in it yet.

## What Bitting is

* **Local-only.** Your vault is one encrypted file on your disk. There is no
  server, no account, no sync service, and no telemetry. If you want the file on
  several machines, put it in whatever cloud drive you already use — it is
  already encrypted before it ever touches the filesystem.
* **One vault, every surface.** A command-line tool and an MCP server for AI agents today, a
  desktop app and browser extension to come — all talking to one hardened local process that
  holds the keys. Nothing else in the system can decrypt anything, and a CI check enforces
  that rather than trusting it.
* **Auditable.** Every line is public. The security comes from the design, not
  from hiding the source.

## What "quantum-resistant" actually means here

This deserves a precise answer rather than a marketing one.

Your vault is encrypted with XChaCha20-Poly1305 using a 256-bit key. Symmetric
cryptography at that key size is **already** quantum-resistant: the best known
quantum attack is Grover's algorithm, which offers only a square-root speedup
(around 2^128 sequential operations), parallelizes badly, and would additionally
have to run our memory-hard key derivation inside a coherent quantum state.

The important consequence: **"harvest now, decrypt later" does not apply to this
vault.** That attack works by recording a public-key key exchange today and
breaking it with a quantum computer later. Bitting's confidentiality path contains
no public-key cryptography at all — your passphrase goes through Argon2id to a
symmetric key, and that is the whole chain. Someone who steals your vault file
today and waits twenty years is in exactly the position they are in now.

Where post-quantum cryptography genuinely matters for this project is **release
signing**, because a signature has to resist forgery for as long as the software
is trusted. Releases are signed with both Ed25519 and ML-DSA-65 (FIPS 204), and
verification requires both to pass.

## What Bitting does not protect against

Being honest about this is part of the design, and any password manager that
claims otherwise is misleading you.

* **Malware already running as you, on an unlocked vault.** On a normal desktop
  operating system, one program running as your user account is not isolated from
  another. Bitting raises the cost (locked memory, aggressive auto-lock, minimal
  decrypted footprint, per-request approval for AI access, an audit log) and makes
  abuse visible, but a determined attacker already executing code as you, while
  your vault is unlocked, wins.
* **Keyloggers, root or kernel compromise, malicious hypervisors, firmware
  implants.** These defeat every password manager. The defences are full-disk
  encryption, Secure Boot, and keeping your machine clean — not us.
* **A guessable master passphrase.** Argon2id at 512 MiB makes each guess
  expensive, but it cannot save a passphrase that appears in a wordlist. Bitting
  offers a one-click seven-word passphrase (~90 bits) and refuses weak ones.
* **Coercion.** There are no hidden volumes and no plausible deniability. The
  file has a magic number and a readable header; pretending otherwise would be a
  lie that could get someone hurt.

The full analysis lives in [`docs/threat-model.md`](docs/threat-model.md).

## Why the source is public

A password manager you cannot inspect is a password manager you have to take on
faith. Publishing the source does not help attackers — they reverse-engineer
binaries routinely, and every algorithm here is public and standard anyway. What
it does is let researchers, packagers, and you check that the program does what
this README claims. Hiding source code only obstructs the people trying to verify
it.

That is Kerckhoffs's principle, and it is why the security of your vault rests on
your passphrase and on published cryptography, never on a secret we keep.

## Verifying what you download

Because releases are the point where trust is actually placed, the signing key
that matters is held **offline and never reaches CI**. A compromise of this
GitHub repository or its build pipeline can therefore produce an *unsigned*
release, which the verifier rejects — it cannot produce a validly signed one.

Builds are also reproducible on Linux, so anyone can rebuild a release from
source and confirm it matches the published artifacts byte for byte. See
[`docs/VERIFY.md`](docs/VERIFY.md) and
[`docs/REPRODUCE.md`](docs/REPRODUCE.md) once releases begin.

Note that Bitting is distributed **without paid code-signing certificates**, so
macOS and Windows will show warnings on downloaded installers. Install via
Homebrew, Scoop, or your Linux package manager to avoid them, and see the install
docs for why reproducible builds plus offline signatures are a stronger integrity
guarantee than a purchased certificate.

## Trying it

```sh
git clone https://github.com/mdferdousalam/bitting
cd bitting
cargo build --release

./target/release/bitting init          # create a vault
./target/release/bitting add "Example Bank" --username you@example.com
./target/release/bitting list
./target/release/bitting show "Example Bank"     # in a native window, hidden from screen recording on macOS
bitting get "Example Bank" --show
```

`bitting add` generates a 20-character password (~129 bits) and never prints it. `bitting get`
copies rather than printing unless you pass `--show`, because a password on a terminal lives
on in scrollback.

Migrating from another manager:

```sh
bitting import ~/Downloads/passwords.csv --dry-run   # see what it found
bitting import ~/Downloads/passwords.csv --shred     # import, then delete the file
```

Filling passwords in a browser:

```sh
bitting setup-browser --extension-id <ID>   # registers the bridge; see extension/README.md
```

Nothing of Bitting's runs on a page until you click the toolbar button — there is no
`<all_urls>` permission and no content script injected on load. That rules out
detect-and-offer-on-page-load, which is the root of most extension credential-leak CVEs.
Matching is decided by the agent, not the extension: a stored entry fills its own site and
its subdomains, and never a look-alike, a different port, or an `http` page.

There is a desktop window too — `bitting-desktop` — which does everything above without a
terminal, shows the health report and the activity log, and is where approval prompts for AI
requests appear. It never receives a password: entries show as bullets, and copying is done
by the agent.

Giving an AI agent access — it starts with nothing, and you grant explicitly:

```sh
bitting grant claude-code --scope metadata --scope use --tag 'work/*' --minutes 30
bitting grants
bitting revoke claude-code

bitting approvals                          # what is waiting for you, and how to answer
bitting settings --agent-reveal on         # let agents ask to *see* a password (off by default)
```

That last one deserves a note. With it off — the shipped default — an agent can log you into
things and cannot read a password, whatever it has been granted. Turning it on does not make
reveals automatic: each one raises a prompt naming the program, its verified path, and the
entry, and approval covers exactly one request.

Checking on your passwords, and on what has been touching them:

```sh
bitting audit          # which stored passwords are reused, weak, or old
bitting log            # recent vault activity, with the audit chain verified
```

Leaving is supported, because a password manager you cannot get your data out of is a
trap:

```sh
bitting export --format csv --output ~/bitting-export.csv   # asks for your passphrase again
```

`bitting export` requires the master passphrase even though the vault is unlocked, writes
the file owner-only, refuses to overwrite anything, and records the attempt — successful
or not — in the audit log.

`bitting audit` decrypts every record to do its work, so it is available only from the
command line and the desktop app — never to an AI agent or the browser extension,
whatever they have been granted. It prints no password values. `bitting log` reports
whether the hash chain verifies; see
[the threat model](docs/threat-model.md#what-the-audit-log-does-and-does-not-prove)
for what that does and does not prove.

See [`docs/cli.md`](docs/cli.md) and [`docs/mcp.md`](docs/mcp.md).

## Building and checking

```sh
cargo test --workspace     # the test suite
cargo xtask check          # the architectural gates
cargo clippy --workspace --all-targets -- -D warnings
```

The pinned toolchain is in `rust-toolchain.toml`; rustup will honour it automatically.

`cargo xtask check` is worth understanding: it enforces two claims this README makes, rather
than leaving them to discipline. `check-layering` fails the build if any client crate gains
access to the cryptographic core, and `check-network` walks the resolved dependency graph and
fails if any HTTP or TLS crate becomes reachable from the vault. Both were verified to fail
when violated, not merely to pass when clean.

## Repository layout

| Path | Contents |
|---|---|
| `crates/bitting-crypto` | Key hierarchy, Argon2id, XChaCha20-Poly1305, generator. No I/O. |
| `crates/bitting-format` | On-disk vault format. Pure and fuzz-tested. |
| `crates/bitting-hardening` | Page locking and anti-debug. The only crate permitted `unsafe`. |
| `crates/bitting-store` | Atomic writes, locking, backups. |
| `crates/bitting-core` | Vault logic, auto-lock, audit chain, policy engine. |
| `crates/bitting-agent` | The one process that holds unlocked keys. |
| `crates/bitting-client` | Client library. Deliberately has no access to crypto. |
| `crates/bitting-cli` | The `bitting` command. |
| `crates/bitting-mcp` | MCP server for AI agents. |
| `crates/bitting-native-host` | Browser native-messaging bridge. |
| `crates/bitting-import` | CSV importers. Depends on no other Bitting crate. |
| `apps/desktop` | Tauri desktop application. Not yet built. |
| `extension` | Browser extension. Not yet built. |

Dependency direction is enforced by `cargo xtask check-layering`; see
[`docs/architecture.md`](docs/architecture.md).

## What is not built yet

Stated so nothing here is mistaken for a bug:

- **Pairing between the extension and the agent.** The plan calls for a SAS code and a Noise
  channel. Not built. Its value is against a same-user process impersonating the browser,
  which is outside the threat model the rest of Bitting is written against — but it is a real gap.
- **Hiding the reveal overlay from screen capture on Linux and Windows.** It works on macOS
  (`NSWindowSharingType::None`). Linux has no mechanism a client can use — X11 has none at all,
  and Wayland exposes nothing to opt out of a compositor's screencopy — and the Windows call is
  unwritten. The window states which of those applies rather than implying protection it does
  not have.
- **Typing a secret into the focused window.** Refused rather than approximated: without a
  check that the window receiving the keystrokes is the one you were shown, typing is
  strictly worse than the clipboard, because it delivers the password to whatever grabbed
  focus in the meantime and leaves no trace.
- **Windows — it builds and passes tests, but the agent refuses to start.** It now compiles:
  CI runs `cargo test --workspace --locked` on `windows-2022` with warnings denied, and it is
  green. What remains is that the agent has no named-pipe transport, so `Transport::bind`
  returns `Unsupported` — see `crates/bitting-agent/src/transport.rs`. The transport is specified
  in [`docs/architecture.md`](docs/architecture.md) but not written, because its load-bearing
  part is a current-user-only DACL check whose failure mode is to silently grant access, and
  that is not code to write without being able to run it. macOS and Linux work.

  This entry has now been wrong in both directions, which is worth recording rather than
  quietly editing. It first said only that the agent "refuses to start", which was too
  generous while `bitting-hardening` was importing windows-sys symbols from the wrong modules and
  the crate did not compile at all. That was fixed, the "does not build" wording outlived the
  problem, and a green Windows CI job went unnoticed against a README asserting the opposite.
  A claim about what is broken decays the same way a claim about what works does.
- **Signed releases.** No signing keys exist yet, so `bitting verify-release` refuses rather than
  pretending to verify anything.

## Licence

**AGPL-3.0-or-later**, with two deliberate exceptions. See [`LICENSE`](LICENSE) and
[`COPYRIGHT`](COPYRIGHT).

| | Licence | |
|---|---|---|
| Everything not named below — the vault core, the agent, the CLI, the apps, the extension | `AGPL-3.0-or-later` | Modify it freely; if you distribute it, or run a modified version as a network service, the source goes with it |
| `crates/bitting-proto` | `Apache-2.0` | The wire protocol. Anything may speak to the agent |
| `crates/bitting-client` | `MPL-2.0` | Embeddable in a closed application; improvements to *these files* come back |

Affero rather than plain GPL because the obvious way to monetise a password manager is to
host the sync for people, and the plain GPL does not reach someone who runs your code as a
service. This project intends to charge for hosting and support one day, and states that
here rather than letting it surface later — but the code itself stays free, and that
includes any server: **there is no paid tier that is closed source.**

The two permissive crates are the protocol and the client stub, and neither can reach key
material, the cryptographic core, or the vault format. That is not a promise, it is a
layering rule: `cargo xtask check-layering` enforces the dependency direction and
`cargo xtask check-licenses` enforces that nothing copyleft ever appears beneath them.
Every source file carries its own SPDX header, so no file's terms depend on guessing.

There is an [additional permission](LICENSE-EXCEPTION.md) for app-store distribution.
Apple's terms and the AGPL are otherwise incompatible — the reason VLC was pulled from the
App Store — which would mean no iOS build could ever exist. The permission allows exactly
that and nothing else: the source obligation is untouched, and it is granted to everyone
downstream too.

Contributions are accepted under the Developer Certificate of Origin — there is no
copyright assignment, and no CLA. Every contributor keeps their copyright, so **nobody,
the maintainers included, can relicense contributed code as proprietary software.** Stated
precisely, because the precise version is what you can rely on: what a sole author writes,
a sole author can still license twice, and that is true of any project with one author.
What makes it irreversible is other people — every contribution makes it more permanent,
and that is the direction this is going deliberately.

The licence covers the code, not the name. See [`TRADEMARK.md`](TRADEMARK.md): fork it
freely, call it something else.

## Reporting a vulnerability

Please do not open a public issue. See [`SECURITY.md`](SECURITY.md).
