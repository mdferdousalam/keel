# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting: go to the **Security** tab →
**Report a vulnerability**. That creates a private advisory only the maintainers
can see.

If that is unavailable to you, email **security@bitting.example** (replace with the
real address before the first release) and, if you want the report encrypted, use
the maintainer key published in the repository root as `MAINTAINER-KEY.asc`.

### What to expect

| | Commitment |
|---|---|
| Acknowledgement | Within 72 hours |
| Initial assessment | Within 7 days |
| Coordinated disclosure | 90 days by default, sooner if the issue is being actively exploited |
| Credit | Public credit in the advisory and the changelog, unless you prefer otherwise |
| Bounty | **None.** There is no bug bounty programme. |

That last row is stated plainly on purpose. Bitting is an unfunded free-software
project, and an unspoken expectation of payment is a bad way for a good-faith
report to end.

### What helps

A version or commit hash, the platform, and the smallest reproduction you can
manage. If it involves the vault format, a crafted file is worth more than a
paragraph. If you have a suggested fix, that is welcome but never required.

## Scope

### In scope

Anything that breaks one of these properties is a vulnerability we want to hear
about:

* **Vault confidentiality at rest.** Recovering any secret from a vault file
  without the master passphrase and required factors.
* **Cryptographic implementation errors.** Nonce reuse, missing or incorrect
  associated data, key reuse across purposes, non-constant-time comparison of
  secrets, modulo bias in the generator, weak or bypassable key derivation.
* **Format parsing.** Any panic, hang, out-of-bounds access, or unbounded
  allocation triggered by a malformed vault file, IPC frame, or import file. These
  are treated as security bugs, not robustness bugs, because the input is
  attacker-controlled.
* **Rollback and tampering.** Presenting an older or spliced vault file without
  detection.
* **Secret leakage.** A secret reaching a log, an error message, a crash dump, the
  JavaScript heap in the desktop app, an IPC payload that should carry only a
  handle, or the clipboard without the expected auto-clear.
* **Authorization bypass.** Any way for a browser extension, an MCP client, or a
  local process to obtain a secret without the approval the policy engine
  requires — including prompt-injection paths that get an AI agent to exfiltrate
  data.
* **Autofill and phishing.** Filling credentials into a wrong or spoofed origin,
  a cross-origin iframe that should have been refused, or an invisible field.
* **Supply chain and release integrity.** Anything that would let a release be
  accepted by the verifier without the offline maintainer signatures.
* **Privilege boundaries that should hold.** Cross-*user* access to the agent
  socket, or remote access to it.

### Explicitly out of scope

These are documented limitations, not accepted bugs — and stating them clearly is
part of being honest about what a password manager can do. Reports about them will
be closed with a pointer here.

* **Malware running as your user account against an unlocked vault.** On a normal
  desktop OS, same-user processes are not isolated from one another. A process
  running as you can read our memory, drive our IPC, and inject code. We raise the
  cost (locked pages, `PR_SET_DUMPABLE`/`PT_DENY_ATTACH`, dump exclusion, minimal
  decrypted footprint, approval prompts, audit logging) and make abuse visible,
  but we do not claim this is a security boundary. Neither does `ssh-agent`, and
  neither does any other desktop password manager.
* **Root, kernel, hypervisor, or firmware compromise. Hardware keyloggers.**
  Out of reach of any user-space program.
* **A weak or reused master passphrase.** Argon2id makes guessing expensive; it
  cannot make a dictionary word strong.
* **Physical access to an unlocked, logged-in machine.**
* **Absence of plausible deniability.** The vault has a magic number and a
  readable header. It is obvious that it is a Bitting vault, and we do not pretend
  otherwise.
* **Cold-boot and DMA attacks against RAM.**
* **Clipboard managers capturing a copied password.** We set the platform hints
  that well-behaved managers honour (Windows clipboard-history and cloud
  exclusion, the macOS concealed-type convention) and auto-clear, but these are
  conventions, not enforcement. Prefer autofill or direct typing.
* **Screenshot capture on Wayland or X11.** Those platforms provide no
  window-level capture exclusion, unlike macOS and Windows, which we do use.
* **Missing code-signing certificates.** Bitting ships unsigned on macOS and Windows
  because it has no funding for certificates. This is a known, documented
  trade-off; integrity is provided instead by reproducible builds and offline
  hybrid signatures.

## Hardening expectations for users

Bitting's threat model assumes you have done these, and several of its guarantees are
weaker without them:

* **Full-disk encryption** (FileVault, BitLocker, LUKS). This is the mitigation
  for anything that reaches the raw disk, including swap and secure-delete
  limitations on SSDs.
* **Encrypted swap**, or enough RAM that the decrypted metadata index never pages
  out. The vault's *secrets* are decrypted only briefly, but the metadata index is
  resident while unlocked and can be paged.
* **A generated master passphrase**, ideally seven words or more.

## Cryptography

Current primitives, for reviewers:

| Purpose | Primitive |
|---|---|
| Key derivation | Argon2id (RFC 9106), default 512 MiB / t=4 / p=4, 32-byte salt |
| Factor mixing | Keyed BLAKE3, length-prefixed fields |
| Subkey derivation | HKDF-SHA-512, versioned domain-separation strings |
| Authenticated encryption | XChaCha20-Poly1305, random 192-bit nonces |
| Integrity / chaining | BLAKE3-256 |
| Constant-time comparison | `subtle` |
| Release signing | Ed25519 **and** ML-DSA-65 (both required) |

Design rules that apply to any change in this area:

1. No asymmetric primitive may enter the confidentiality path without a hybrid
   classical + post-quantum construction.
2. Domain-separation strings are versioned and never reused or repurposed.
3. Parameters read from a file are validated before any allocation.
4. Errors must not distinguish which factor was wrong.

## Supply chain

* `cargo-deny` (advisories, licences, bans, sources) and `cargo-audit` gate every
  pull request; `cargo-vet` before 1.0.
* `cargo xtask check` enforces that clients cannot link the cryptographic core and
  that no HTTP/TLS stack is reachable from the vault core.
* All GitHub Actions are pinned to full commit SHAs.
* Release artifacts require offline maintainer signatures that never exist in CI.
* Fuzzing runs continuously against every parser that touches untrusted input.

## Key rotation

If a release signing key must be rotated, the new keys will be announced in a
release signed by the old keys, and published to the same three independent
locations as the originals. Treat any new key that appears without such a
transition as suspect.
