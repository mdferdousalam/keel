# Contributing to Keel

Thanks for considering it. Keel is a password manager, which means a bug here can
expose someone's entire digital life. That shapes how this project takes changes:
slowly, with tests, and with reasoning written down.

## Before you start

**For a security vulnerability, do not open a pull request.** See
[`SECURITY.md`](SECURITY.md) — a public patch is a public disclosure.

For anything non-trivial, open an issue first. This is a solo-maintained project
and a large unsolicited pull request is likely to sit unreviewed, which wastes
your time more than mine.

## Getting set up

```sh
git clone https://github.com/mdferdousalam/keel
cd keel
cargo test --workspace      # test suite
cargo xtask check           # architectural gates
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

The toolchain is pinned in `rust-toolchain.toml`. Do not bump it in an unrelated
pull request — it is a reproducible-build input.

## Certificate of Origin, not copyright assignment

Sign your commits off:

```sh
git commit -s -m "..."
```

That adds a `Signed-off-by:` line asserting you have the right to contribute the
code, under the [Developer Certificate of Origin](https://developercertificate.org/).

There is **no contributor licence agreement**. You keep your copyright. This is
deliberate: because copyright is distributed across contributors, nobody — the
maintainers included — can relicense Keel as proprietary software later. For a
security tool, that irreversibility is a feature worth protecting.

### What you are licensing it under

Signing off contributes your work under the licence of the tree you are touching, which is
one of three. Nothing extra to sign; this is what the DCO sign-off means here.

| Where you are editing | Inbound licence |
|---|---|
| `crates/keel-proto` | `Apache-2.0` |
| `crates/keel-client` | `MPL-2.0` |
| Everywhere else | `AGPL-3.0-or-later`, **together with** the additional permission in [`LICENSE-EXCEPTION.md`](LICENSE-EXCEPTION.md) |

The additional permission needs saying explicitly. It is what allows Keel to ship through
an app store at all — Apple's terms and the AGPL are otherwise incompatible — and under
section 7 a permission like that can only be granted by *every* copyright holder. Since
there is no CLA, that means every contributor. If it were left implicit, the first
contributor who had not granted it would quietly make an iOS build impossible for everyone.

If you are not willing to grant it, say so in the pull request instead of signing off. That
is a legitimate position and it is much cheaper to hear before the patch lands than after.

Two rules follow from the split, and `cargo xtask check-licenses` enforces both:

* **`keel-proto` and `keel-client` may not gain a copyleft dependency.** A dependency's
  licence governs the combined work, so one AGPL crate underneath `keel-client` would make
  every application embedding it AGPL while the manifest still advertised MPL. The
  [layering rules](xtask/src/rules.rs) already forbid the edges that would do this.
* **Every source file carries an SPDX header** matching its tree. If you move a file
  between crates, its header moves with it and must be corrected.

## The rules that are not negotiable

These come from the threat model. A pull request that breaks one will be asked to
change, however good the rest of it is.

### 1. Secrets have types, and those types have no escape hatches

Key material and plaintext secrets live in `SecretBytes` / `SecretString`. Those
types have no `Debug`, `Display`, `Serialize`, or `Clone` on purpose, so logging or
serializing a secret is a compile error rather than something review has to catch.

Do not add those impls. Do not work around them with `format!("{}", x.expose())`
into a log. If you need a new operation on a secret, add a method that consumes it
and returns a *result*, not the value.

### 2. Layering is enforced, not advisory

`cargo xtask check-layering` encodes the dependency direction. The critical rule:
**`keel-client` must never gain `keel-crypto`, `keel-format`, or `keel-core`.**
Only `keel-agent` links the cryptographic core at runtime, and that is what makes
"where can key material be?" a question with a short answer.

If you believe a layering rule is wrong, change `xtask/src/rules.rs` in its own
commit and explain why. Do not route around it.

### 3. The vault core reaches no network

`cargo xtask check-network` walks the resolved dependency graph and fails if any
HTTP or TLS crate is reachable from the vault core. `keel-breach` is the single
exception, and it is off by default.

A new dependency that happens to pull in `reqwest` will fail CI. That is the gate
working.

### 4. Parsers assume hostile input

`keel-format`, the IPC frame decoder, and every importer parse attacker-controlled
bytes. For those:

* Validate lengths and bounds **before allocating**. A file that asks for 64 GiB
  must be rejected, not attempted.
* Never panic. `unwrap`, `expect`, `panic!`, and raw indexing are lint-warned in
  these crates; a panic on malformed input is a denial-of-service bug.
* Add a fuzz target with the parser, in the same pull request.

### 5. Cryptographic changes need test vectors

Any change to key derivation, the AEAD layer, or the on-disk format needs
known-answer tests, and existing vectors must keep passing. The vectors in
`crates/keel-format/tests/vectors/` are a compatibility contract: if a change
breaks them it changes the format, which needs a version bump and a migration
path, not a vector update.

### 6. No asymmetric cryptography without a hybrid construction

If you introduce a public-key primitive anywhere in the confidentiality path, it
must be a hybrid classical + post-quantum construction (combine shared secrets by
concatenate-then-KDF, never XOR, and bind both public keys and both ciphertexts
into the transcript). This single rule is what makes the project's post-quantum
claim defensible.

### 7. Dependencies are a budget, not a convenience

`keel-core`'s dependency tree has a ceiling of roughly 150 crates. A new
dependency in `keel-crypto`, `keel-format`, `keel-core`, or `keel-agent` needs a
sentence in the pull request explaining why writing it is worse than depending on
it. Every dependency is code that runs in the process holding your unlocked vault.

Banned outright: `openssl`/`native-tls` (use `rustls` where TLS is genuinely
needed), git dependencies, and anything whose build script touches the network.

### 8. The desktop webview never sees a secret

Plaintext must not enter the JavaScript heap. A JS engine copies strings freely,
frees them without zeroizing, and can serialize them into heap snapshots. The
webview gets opaque handles and masked placeholders; copy, fill, and type happen
in Rust; reveals render in a separate native window.

There is an integration test asserting no secret bytes appear in any Tauri command
result or IPC payload. If your change makes it fail, the change is wrong, not the
test.

## Style

`cargo fmt` decides formatting; there is nothing to discuss there. Beyond that:

* **Comments explain why, not what.** `// increment the counter` is noise. A
  comment that records a constraint, a rejected alternative, or a non-obvious
  consequence is valuable — most of the existing comments are one of those three.
* **Test names state the property.** `rejects_absurd_memory_cost_before_allocating`
  tells a reader what broke; `test_params_2` does not.
* **Errors do not leak.** No plaintext, no key material, and no distinction
  between "wrong password" and "wrong keyfile" in any user-visible error.

Conventional commit prefixes (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`) are used, with a `!` or a `BREAKING CHANGE:` footer for anything that
changes the vault format or the IPC protocol.

## Review expectations

Changes to `keel-crypto`, `keel-format`, `keel-core`, and the `keel-agent`
authentication paths are reviewed slowly and deliberately. That is not
gatekeeping — it is the cost of being the code that stands between a stolen file
and someone's bank account. Documentation, packaging, and UI changes move faster.

## What is especially welcome

* Independent rebuilds of a release that confirm (or contradict) the published
  hashes. Contradictions are urgent.
* Fuzz targets, and crashes found by them.
* Test vectors from an independent implementation of the format.
* Threat-model review — particularly anywhere the documentation claims more than
  the code delivers. Overclaiming is treated as a bug.
* Accessibility fixes. An inaccessible password manager excludes people from
  basic security.
