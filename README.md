# Keel

A local-first, open-source password manager built for people who want to verify
their tools rather than trust them.

> **Status: early development.** The cryptographic core and the on-disk format
> are being built and are not yet frozen. There are no releases and no stable
> vault format. Do not put real passwords in it yet.

## What Keel is

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
breaking it with a quantum computer later. Keel's confidentiality path contains
no public-key cryptography at all — your passphrase goes through Argon2id to a
symmetric key, and that is the whole chain. Someone who steals your vault file
today and waits twenty years is in exactly the position they are in now.

Where post-quantum cryptography genuinely matters for this project is **release
signing**, because a signature has to resist forgery for as long as the software
is trusted. Releases are signed with both Ed25519 and ML-DSA-65 (FIPS 204), and
verification requires both to pass.

## What Keel does not protect against

Being honest about this is part of the design, and any password manager that
claims otherwise is misleading you.

* **Malware already running as you, on an unlocked vault.** On a normal desktop
  operating system, one program running as your user account is not isolated from
  another. Keel raises the cost (locked memory, aggressive auto-lock, minimal
  decrypted footprint, per-request approval for AI access, an audit log) and makes
  abuse visible, but a determined attacker already executing code as you, while
  your vault is unlocked, wins.
* **Keyloggers, root or kernel compromise, malicious hypervisors, firmware
  implants.** These defeat every password manager. The defences are full-disk
  encryption, Secure Boot, and keeping your machine clean — not us.
* **A guessable master passphrase.** Argon2id at 512 MiB makes each guess
  expensive, but it cannot save a passphrase that appears in a wordlist. Keel
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

Note that Keel is distributed **without paid code-signing certificates**, so
macOS and Windows will show warnings on downloaded installers. Install via
Homebrew, Scoop, or your Linux package manager to avoid them, and see the install
docs for why reproducible builds plus offline signatures are a stronger integrity
guarantee than a purchased certificate.

## Trying it

```sh
git clone https://github.com/keel-vault/keel
cd keel
cargo build --release

./target/release/keel init          # create a vault
./target/release/keel add "Example Bank" --username you@example.com
./target/release/keel list
./target/release/keel get "Example Bank" --show
```

`keel add` generates a 20-character password (~129 bits) and never prints it. `keel get`
copies rather than printing unless you pass `--show`, because a password on a terminal lives
on in scrollback.

Migrating from another manager:

```sh
keel import ~/Downloads/passwords.csv --dry-run   # see what it found
keel import ~/Downloads/passwords.csv --shred     # import, then delete the file
```

Giving an AI agent access — it starts with nothing, and you grant explicitly:

```sh
keel grant claude-code --scope metadata --scope use --tag 'work/*' --minutes 30
keel grants
keel revoke claude-code
```

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
| `crates/keel-crypto` | Key hierarchy, Argon2id, XChaCha20-Poly1305, generator. No I/O. |
| `crates/keel-format` | On-disk vault format. Pure and fuzz-tested. |
| `crates/keel-hardening` | Page locking and anti-debug. The only crate permitted `unsafe`. |
| `crates/keel-store` | Atomic writes, locking, backups. |
| `crates/keel-core` | Vault logic, auto-lock, audit chain, policy engine. |
| `crates/keel-agent` | The one process that holds unlocked keys. |
| `crates/keel-client` | Client library. Deliberately has no access to crypto. |
| `crates/keel-cli` | The `keel` command. |
| `crates/keel-mcp` | MCP server for AI agents. |
| `crates/keel-native-host` | Browser native-messaging bridge. |
| `crates/keel-import` | CSV importers. Depends on no other Keel crate. |
| `apps/desktop` | Tauri desktop application. Not yet built. |
| `extension` | Browser extension. Not yet built. |

Dependency direction is enforced by `cargo xtask check-layering`; see
[`docs/architecture.md`](docs/architecture.md).

## What is not built yet

Stated so nothing here is mistaken for a bug:

- **The desktop app and browser extension.** Because of that, `keel get` without `--show`
  reports that it needs the desktop app rather than silently doing nothing — a user who
  believes a password was copied and then pastes stale clipboard contents into a login form
  has been actively misled.
- **Windows.** The agent needs a named-pipe transport with a current-user-only DACL, and that
  is not written. macOS and Linux work.
- **Signed releases.** No signing keys exist yet, so `keel verify-release` refuses rather than
  pretending to verify anything.
- **`keel export` and `keel audit`.**

## Licence

GPL-3.0-or-later. See [`LICENSE`](LICENSE).

Contributions are accepted under the Developer Certificate of Origin — there is
no copyright assignment. That means no one, including the maintainers, can take
this code proprietary later.

## Reporting a vulnerability

Please do not open a public issue. See [`SECURITY.md`](SECURITY.md).
