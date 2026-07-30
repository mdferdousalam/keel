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
* Hash-chained audit log; never records secret values. See
  [What the audit log does and does not prove](#what-the-audit-log-does-and-does-not-prove).

**The security story in one sentence:** in the default configuration an agent can
log you into things and manage entries, and cannot exfiltrate a single password
even if it is fully controlled by an attacker.

**If you turn reveal on.** `keel settings --agent-reveal on` makes plaintext reveals
*possible*; it does not make them automatic. Every one still raises a per-request prompt
that names the program, its verified path on disk, and the entry from the vault, with the
agent's own justification quarantined and labelled as untrusted. Approval is **one-shot**:
one "yes" permits one reveal, and the next request asks again. The setting is stored in the
vault, so it survives a restart — and a vault created before the setting existed migrates
with it **off**, because that vault never consented to it.

What this does not defend against, said plainly: a user who approves without reading. The
750ms arm delay on the Allow control, the focus starting on Refuse, and the absence of any
"always allow" are there to make reading the default rather than the exception, but a person
determined to click through will succeed. That is why the setting is off to begin with.

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

## Autofill, and why it refuses more than it accepts

Autofill is the feature most likely to hand a password to an attacker, because the attacker
gets to choose the page. Keel's arrangement is shaped around that.

**Nothing runs on a page until you ask.** There is no `<all_urls>` permission and no
declaratively injected content script. Clicking the toolbar button is what causes any Keel
code to touch a page. The cost is that Keel cannot notice a login form and offer to fill it as
the page loads; that convenience is where most extension credential-leak CVEs come from,
because it means privileged code parses untrusted page content on every site you visit.

**The origin comes from the browser, never the page.** `tab.url` and `sender.origin` are set
by the browser. `location.href` and `document.domain` are things a page says about itself, and
on an attacker's page they say whatever the attacker wants.

**Matching is decided in the agent.** The extension does not choose which entry fits a page;
it asks. The rules live in one module in the process that holds the vault, rather than in a
browser extension that sits much closer to hostile input: a stored origin covers its own host
and subdomains of it at a dot boundary, ports must match, and a stored `https` credential is
never filled into an `http` page. There are no wildcards and no substring matching, because
there is no safe version of either. `chase.com.evil.tld`, `evil-chase.com`, and
`chasecom.evil.tld` are all refused, and there are tests for each.

**The fill itself is checked twice more.** The injected code re-reads
`window.location.origin` before writing anything, which closes the window where a page
navigates between the popup asking and the value arriving. It refuses to fill inside a frame,
refuses a `readonly`, `disabled`, or invisible field, refuses a field that looks like a
password field but is not one, and refuses a form whose `action` posts to a different origin.

**What it does not defend against.** The extension necessarily receives the one credential it
is filling — it has to set the value of an input. So a compromised browser gets the password
for the site you are on when you click. Nothing in this design prevents that, and no design
can: at the point where a password must reach a page, whatever renders the page can see it.
What is prevented is bulk access — there is no request that returns more than the entries
matching one origin, and no request that returns a password without an origin check.

**Pairing is not built.** The plan calls for a SAS code and a Noise channel between extension
and agent, so that a same-user process cannot impersonate the browser. It is not implemented.
The `allowed_origins` field in the native-messaging manifest stops an arbitrary *extension*
from launching the bridge, and stops nothing else: any process running as you can execute the
bridge directly, or talk to the agent's socket. Same-user attackers are outside this threat
model for every other component too, which is why this is recorded as a gap rather than
treated as a hole in a claim.

## The desktop window, and the one secret that passes through it

The window is a webview, which means a browser: a garbage-collected heap whose strings
cannot be zeroized, a JIT, a DOM, and a devtools protocol. Keel therefore does not put
passwords in it.

**No secret stored in the vault ever reaches the window.** Entries arrive with their secret
fields replaced by a fixed run of bullets. Actions that need the real value — copying to the
clipboard, generating and storing a new password — are carried out by the agent, which
already holds it decrypted; the window asks for the *action* and receives a sentence
describing what happened. The value does not enter the window, and does not enter the
desktop shell process either. This is enforced by the return types in `masking.rs`, none of
which has a field capable of holding a password, and checked by a test that stores a canary
password and searches every command's serialised result for it. That test was verified to
fail when a leak was deliberately introduced.

**The master passphrase does pass through it**, on its way from the field you type it into
to the agent. There is no way around that in a webview short of a separate native prompt,
which is not built. So the precise claim is: *no secret stored in the vault is ever given to
the window.* The passphrase you are typing right now is a different thing from the hundred
passwords the vault holds, and treating them as the same would overstate what this design
achieves. The field is cleared as soon as it is sent, which shortens how long the value is
reachable from the DOM and does not scrub it from the heap — nothing in a webview can.

Revealing a stored password on screen is deliberately **not** a feature of the window itself.
It is `keel-reveal`, a separate process with no webview, no HTML, and no font parser — the font
is a hand-built bitmap, because a font library is a parser for a complex binary format and this
is the one process that holds a plaintext password.

The **agent** spawns it and writes the secret to its stdin. So the plaintext travels from the
process that already holds the vault decrypted to the process that draws it, and never enters
the desktop app at all. Not argv, which is world-readable through `ps`; not a file or an
environment variable, for the same reason.

On macOS the window sets `NSWindowSharingType::None`, which excludes it from screen recording
and from the window-capture APIs screenshots use. On Linux there is no mechanism a client can
use — X11 has none, and Wayland exposes nothing to opt out of a compositor's screencopy — and
the Windows equivalent is unwritten. **The window reports which of those applies**, because a
user who believes a window is hidden when it is not would reveal a password during a screen
share on the strength of it. And none of it stops a phone pointed at the monitor; the window
says that too.

## What the audit log does and does not prove

Every request any client makes is appended to `vault.keel.audit`, encrypted under a
subkey of the vault master key and chained: each record commits to the hash of its
predecessor. `keel log` reads it back and reports what verified.

Being precise about what that buys is worth more than the phrase "tamper-evident".

**Detected.** Editing any record, or removing or reordering records in the middle,
breaks the chain at that point. `keel log` names the sequence number and still prints
the records *before* the break, because those are the evidence — discarding a good
prefix because the file was damaged later would destroy exactly what an investigation
needs.

**Detected, but only with help.** Deleting records from the **end** is invisible to
the chain, because records 1..k form a valid chain for any k. So is rebuilding the
tail from scratch, which produces a different but internally consistent chain. Neither
is caught by chaining alone. Keel therefore stores an *anchor* — the expected record
count and chain tip — inside the vault manifest, which is authenticated under the
vault key. Anyone able to forge that anchor can already rewrite the vault itself, at
which point the audit log is the least of the problems.

**Not detected.** The anchor is refreshed when the vault is *saved*, and commits only
to records already flushed at that moment. It is a floor, not an exact count: records
appended after the last save can be removed without detection. Closing that window
completely would mean a vault write for every audit record, which is a poor trade for
a log whose purpose is to make patterns of abuse visible rather than to be evidence in
court. The practical shape of the limit: an attacker can erase the tail of a session,
not the history of one.

**Not the point at all.** The log is not a defence against an attacker who has already
compromised the machine while the vault is unlocked — such an attacker can simply
stop the agent, or read the vault directly. It exists so that abuse by something with
*legitimate but limited* access, an AI agent or a browser extension, leaves a record
the user can review. Its threat model is a misbehaving client, not a root shell.

**Availability, not confidentiality.** The log is encrypted, so a local attacker
learns nothing from reading it — but they can delete the whole file, and nothing
stops that. A missing log is conspicuous, which is the most that can be claimed.
