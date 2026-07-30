# Threat model

This document says what Keel defends against, what it partly mitigates, and what
it does not defend against at all. The third list is the important one. A password
manager that claims to stop everything is lying, and a user who believes it will
make worse decisions than one who knows the boundaries.

Notation:

* **Defended** — the design stops this, and a successful attack would be a
  vulnerability. Report it.
* **Partial** — attacker cost is raised and abuse is made visible, but a
  determined attacker succeeds. Not a boundary we claim.
* **Out of scope** — not defended. Documented, not accepted as a bug.

## Assets

1. **Secrets**: passwords, TOTP seeds, notes, attachments. Losing confidentiality
   here is the worst outcome.
2. **Metadata**: entry titles, usernames, URLs, tags, timestamps. Encrypted at
   rest, but decrypted into memory for the whole time the vault is unlocked, and
   its *size* is observable (padded into coarse buckets).
3. **Vault integrity**: the guarantee that what you read back is what you wrote,
   and not an older or spliced version.
4. **Release integrity**: the guarantee that the binary you installed is the one
   built from the published source.

## Attackers

### T1 — Offline vault thief · **Defended** · *primary threat*

Has `vault.keel` (stolen laptop, a backup, a synced cloud folder, a forensic
image), unlimited offline compute, no passphrase.

**Defence.** Argon2id (512 MiB / t=4 / p=4 by default) over a 256-bit key, then
XChaCha20-Poly1305. Cracking cost is passphrase entropy multiplied by a
memory-hard function that is expensive to parallelise on GPU, FPGA, or ASIC. A
passphrase entropy floor is enforced at vault creation, with a generated
seven-word option offered as one click. An optional keyfile or hardware factor
makes the vault file alone insufficient *at any compute budget*.

**Residual risk.** Entirely the passphrase. This is why the master passphrase gets
seven words and why KDF parameters can be raised later on an existing file.

### T2 — Same-user malware, vault locked · **Defended** for confidentiality

Can read files, run programs, connect to our socket, read extension storage.

**Defence.** With the vault locked there are no keys anywhere on disk or in
memory. The optional platform "quick unlock" blob requires biometric or
user-presence confirmation, is per-device and revocable, expires after seven days,
and explicitly **cannot** authorize an MCP reveal, an export, or a passphrase
change — so phishing a biometric prompt yields a browsing session, not the vault.

**Note.** Such malware can still *steal the file*, which reduces to T1.

### T3 — Same-user malware, vault unlocked · **Partial** ⚠

Can `ptrace` us, inject code, drive our IPC, read our memory.

**This is not a boundary we claim.** On a single-user desktop operating system,
one process running as your account is not isolated from another. What we do:

* `PR_SET_DUMPABLE(0)` on Linux (also blocks same-user `ptrace` and
  `/proc/pid/mem`), `PT_DENY_ATTACH` on macOS, injection-blocking mitigation
  policies on Windows.
* `mlock`/`VirtualLock` on key pages; core dumps disabled; key pages excluded from
  Windows Error Reporting.
* **Minimal decrypted footprint** — the architectural mitigation that matters most.
  Only the metadata index is decrypted at unlock. Individual secrets are decrypted
  on demand into a small locked buffer and wiped within 60 seconds, enforced by a
  watchdog rather than by control flow.
* Aggressive auto-lock: 5 minutes idle, on screen lock, on suspend, on fast user
  switch, and a hard 8-hour cap.
* Per-request approval for AI access, and a hash-chained audit log so abuse leaves
  a trace.

**Honest limit.** A determined attacker already executing code as you, while the
vault is unlocked, wins. The mitigation is not letting that happen: full-disk
encryption, a clean machine, and locking your vault.

### T4 — Root, kernel, hypervisor, firmware, hardware keylogger · **Out of scope**

Nothing a user-space program can do. Mitigations are Secure Boot, measured boot,
SIP, and full-disk encryption.

### T5 — Malicious web page attacking the extension · **Defended**

Arbitrary JavaScript in a page or iframe, DOM manipulation, clickjacking,
look-alike domains.

**Defence.**

* No secrets in extension storage — `storage.local` is a plaintext LevelDB in the
  browser profile. It holds an instance id, pairing state, and preferences only.
* Origins come from `sender.origin` (browser-attested), never from
  `location.href` or anything the page can influence.
* Exact-origin matching by default, then registrable domain via the Public Suffix
  List. **No wildcard or substring matching, ever.** Scheme must match; an `https`
  entry never fills on `http`.
* **No autofill without a trusted user gesture.** No fill on page load, on
  `DOMContentLoaded`, or on focus. This forgoes automatic fill-on-load, which is
  the root of most extension credential-leak CVEs — a trade-off taken knowingly.
* Cross-origin iframes are refused unless the entry explicitly lists that origin,
  plus a one-time confirmation naming both origins.
* Fill is refused into `readonly`, `disabled`, zero-size, off-screen, or
  transparent fields, and the frame origin is re-verified immediately before the
  value is written (defeating navigate-during-approval races).
* No `<all_urls>` permission; content scripts inject on demand, in an isolated
  world; `web_accessible_resources` is empty so pages cannot probe us.

### T6 — Compromised dependency · **Partial**

A crates.io takeover, a typosquat, or a malicious update running code in our
process.

**Defence.** A dependency budget with written justification for additions near the
core; `cargo-deny` and `cargo-audit` on every pull request plus daily;
`cargo-vet` before 1.0; no git dependencies; no build script that touches the
network; `unsafe` confined to one crate; `cargo-auditable` metadata so users can
scan the binary they actually downloaded.

**Honest limit.** A malicious dependency inside the unlocked agent process reads
keys. Reducing the dependency count is the only real mitigation, which is why the
budget exists.

### T7 — Compromised GitHub organisation or CI · **Defended** against a *silent* backdoor

Can push commits, mint releases, and use CI secrets.

**Defence.** Release artifacts require signatures from an **offline maintainer key
that never exists in CI** (Ed25519 **and** ML-DSA-65; the verifier requires both).
CI-side Sigstore/SLSA provenance is supplementary evidence, not the trust root.
Combined with reproducible builds and a public rebuild workflow, a backdoored
release is either unsigned — and rejected by `keel verify-release` — or publicly
detectable by anyone who rebuilds.

**Honest limit.** A compromised CI can serve malware to someone who skips
verification. This is why verification instructions are three lines and why
package-manager channels (Homebrew, Scoop, distro packages) that verify hashes are
the recommended install path.

### T8 — Rogue or prompt-injected AI agent via MCP · **Defended** against bulk exfiltration

Can call any exposed tool, arbitrarily often, with attacker-authored arguments.

**Defence.**

* Deny by default: a fresh session holds no scopes.
* **No enumerate-all tool.** Search requires two characters and returns at most 25
  results, with a cap on distinct entries revealed per hour.
* Secrets are returned **by reference**. `use_secret` performs the action
  (fill/copy/type) inside the agent process, so the model never sees plaintext.
* `secret:reveal` is **disabled by default**. When enabled it requires per-request
  human approval, with a default-deny button, a mandatory delay before Allow
  becomes clickable, and a 30-second timeout.
* Approval dialogs display **ground truth from the vault** — entry title, origin,
  verified client binary path, and the concrete destination ("will be typed into:
  Chrome — `https://chase.com/login`") — not the agent's claims about them.
* Agent-authored text renders as inert plain text: truncated, control characters
  and ANSI stripped, no markup, in a box labelled as agent-supplied.
* Origin binding for browser fills is resolved through the extension, never
  supplied by the agent.
* Rate limits and a circuit breaker that revokes all grants for a client after
  repeated denials.
* Hash-chained audit log; never records secret values.

**The security story in one sentence:** in the default configuration an agent can
log you into things and manage entries, and cannot exfiltrate a single password
even if it is fully controlled by an attacker.

**Honest limit.** A user who clicks Allow on everything. The delay and the
default-deny focus fight approval fatigue; they cannot cure it.

### T9 — Clipboard sniffing, shoulder surfing, screen capture · **Partial**

**Defence.** Autofill and direct typing are preferred over the clipboard, and the
clipboard is the second option in the UI. Auto-clear after 15 seconds, and only if
the clipboard still holds our value (compared by hash, so we never wipe something
you copied since). On Windows, the clipboard-history and cloud-sync exclusion
formats are set. On macOS, the concealed-type convention marker is added. Reveal
windows are marked non-capturable (`WDA_EXCLUDEFROMCAPTURE`,
`NSWindow.sharingType = .none`). Values are masked by default.

**Honest limits.** The macOS marker is a *convention* that well-behaved clipboard
managers honour, not enforcement. Wayland and X11 offer no window-level capture
exclusion, so the reveal window can be screenshotted there.

### T10 — Future quantum adversary, harvest-now-decrypt-later · **Defended**

Stores today's vault file; runs a cryptographically relevant quantum computer in
2045.

**Defence.** The vault's confidentiality path contains **no public-key
cryptography** — passphrase → Argon2id → symmetric key → AEAD. Harvest-now-
decrypt-later is a public-key attack: it works by recording a key exchange and
solving it later with Shor's algorithm. There is no key exchange here to record.

Against the symmetric layer, Grover's algorithm gives at most a square-root
speedup (~2^128 sequential coherent evaluations), parallelises poorly (S machines
buy only √S), and each iteration would have to evaluate the full memory-hard KDF
in superposition — 512 MiB held coherent across four passes. Memory-hard KDFs are
close to the worst possible Grover target.

**Where post-quantum work is real.** Release signing uses hybrid Ed25519 +
ML-DSA-65. Any future sync or sharing feature must use a hybrid X25519 +
ML-KEM-768 KEM (concatenate-then-KDF, both public keys and both ciphertexts bound
into the transcript). The project rule: no asymmetric primitive in the
confidentiality path without a hybrid construction.

**Residual risk.** Whether the passphrase was guessable given decades of classical
compute. Same answer as T1.

### T11 — Rollback, truncation, splicing · **Defended** (detection)

Can replace the vault with an older authentic version, or splice records between
versions.

**Defence.** A strictly monotonic `write_counter` in the AAD-covered header; the
manifest binds `blake3(record_ciphertext)`, offset, and length for every record; a
whole-file footer hash; and the last-seen counter mirrored in both a sidecar file
and the OS keychain. A counter regression raises a loud, explicit warning that
names both values and requires confirmation, and is recorded in the audit chain.

Per-record AAD deliberately excludes the write counter — otherwise every save
would re-encrypt every record — so the *set* of records is bound by the manifest
instead.

A corrupt record is flagged individually and the rest of the vault still opens.
Graceful degradation beats total failure when the alternative is losing access to
every password you own.

### T12 — Coercion, rubber-hose · **Out of scope**

We do **not** claim plausible deniability. The file has a magic number and a fixed
header; claiming hidden volumes would be a lie that could get someone hurt.
Separate vault files are supported, which is honest
deniability-by-nothing-to-find.

### T13 — Local process impersonating the extension or an MCP client · **Partial**

Executes the native host or connects to the socket directly.

**Defence.** Per-install pairing with a short authentication string the user types
across two UIs; a Noise `KKpsk0` channel with mutual static-key authentication and
replay protection; a socket in a `0700` directory with a peer-UID check
(`SO_PEERCRED` / `LOCAL_PEERCRED`), or a named pipe with a current-user-only DACL
and `PIPE_REJECT_REMOTE_CLIENTS`; client binary path and code-signature recorded
for the approval dialog.

**Honest limit.** This is T3 wearing a different hat. Executable-path checks are
defeatable by time-of-check/time-of-use. The real jobs of this machinery are to
make cross-*user* and remote access impossible, to fail closed on a wrong or stale
pairing, and to surface unknown connection attempts in the audit log.

## Assumptions about the user's environment

Several guarantees are weaker without these, and the model assumes them:

* **Full-disk encryption.** This is the mitigation for swap, for secure-delete
  limitations on SSDs and copy-on-write filesystems, and for anything reaching the
  raw disk.
* **Encrypted swap**, or enough RAM that the decrypted metadata index never pages
  out.
* **A generated master passphrase.**

## Non-goals

* Sync service, web vault, or any server component. Every one would add attack
  surface and liability against the local-only design.
* Plausible deniability or hidden volumes.
* Defending an already-compromised operating system.
* FIPS certification.

## Review triggers

Revisit this document when: the vault format version changes; a new IPC client
type is added; the MCP tool surface changes; a network-capable dependency is
introduced; or any approval flow is modified.
