# Architecture

## The shape of the system

One long-lived process holds the unlocked vault. Everything else is a client.

```
 bitting (CLI) ──────────UDS──►┌──────────────────────────────────────────┐
 bitting-mcp ────────────UDS──►│  bitting-agent                              │──► vault.bitting
 bitting-native-host ────UDS──►│                                          │──► vault.audit
    ▲ stdio                 │  · VMK + subkeys (mlock'd, zeroized)     │──► vault.state
 browser extension          │  · session table, per-client policy      │
                            │  · grant / approval engine               │
 Bitting.app (Tauri) ────UDS──►│  · auto-lock, clipboard auto-clear       │
   └─ approval modals       │  · spawns bitting-reveal for plaintext      │
                            └──────────────────────────────────────────┘
```

This is the `ssh-agent` model, and it is chosen for one reason: it makes the
question "which code can touch key material?" have a short, checkable answer.
Exactly one process links the cryptographic core. The CLI, the MCP server, the
browser bridge, and the desktop shell are all pipes for data the agent has already
decided to release.

That property is enforced by `cargo xtask check-layering`, not by convention.

## Crates and dependency direction

```
bitting-crypto  → (crypto primitives only)          no I/O, no clock, no platform
bitting-format  → bitting-crypto                       parses hostile bytes; fuzzed
bitting-hardening → bitting-crypto                     the ONLY crate allowed `unsafe`
bitting-store   → bitting-crypto, bitting-format          atomic writes, locking, backups
bitting-core    → bitting-crypto, bitting-format, bitting-store
bitting-proto   → serde only                        wire types, parallel leaf
bitting-agent   → bitting-core, bitting-proto             the privileged process
bitting-client  → bitting-proto                        ← NOT bitting-crypto. The key rule.
bitting-cli / bitting-mcp / bitting-native-host / bitting-reveal / desktop → bitting-client
bitting-import  → bitting-crypto, bitting-format          CSV and browser importers
bitting-breach  → rustls, ureq                      the ONLY crate with a network dep
```

Rules worth stating explicitly, because they are load-bearing rather than
stylistic:

* **`bitting-crypto` and `bitting-proto` are leaves.** `bitting-crypto` has no filesystem,
  no network, no clock beyond timing its own calibration probe, and no platform
  code. That is what makes it fuzzable and reviewable, and it is why `mlock` lives
  behind the `PageLocker` hook that `bitting-hardening` installs rather than inside
  the crypto crate. That install is **process-global** — `bitting_hardening::init`
  registers the locker with `bitting-crypto` for the whole process — so it is the job of
  whichever binary owns the process, not of the library being protected. `bitting-agent`
  does it at the top of `main`. This is why `bitting-core` handles plaintext secrets
  while depending on `bitting-hardening` not at all: it gets the protection without the
  edge, and an unused dependency on the crate full of `unsafe` is not free.
* **`bitting-client` may depend only on `bitting-proto`.** If it ever gains
  `bitting-crypto`, `bitting-format`, or `bitting-core`, key material becomes reachable
  from four more processes and the short answer above stops being true.
* **`bitting-hardening` is the single `unsafe` boundary.** Every raw platform call in
  the project lives there, so an auditor has one file to read rather than fifteen.
* **`bitting-breach` is the single network boundary**, is opt-in, and is off by
  default. `cargo xtask check-network` walks the *resolved* dependency graph — not
  the manifests — and fails if an HTTP or TLS crate becomes reachable from any
  other crate.

These rules are encoded in `xtask/src/rules.rs`, which has a CODEOWNERS entry
because editing it edits a security boundary.

### The licence boundary is the same boundary

Bitting is `AGPL-3.0-or-later` except for two crates, and they are not chosen for
convenience — they are the two crates the layering rule above already proves cannot reach
anything worth protecting.

| Crate | Licence | Why it can afford to be |
|---|---|---|
| `bitting-proto` | `Apache-2.0` | Serde wire types. No logic, no crypto, no I/O — a leaf by rule. There is nothing here to protect, and everything that talks to the agent needs it |
| `bitting-client` | `MPL-2.0` | May depend only on `bitting-proto`, so it provably holds no key material. Third-party applications embed it; no strong copyleft would let them |

The direction of the argument matters. The licences did not come first — the dependency
rule did, and the licences follow it. `bitting-client` is publishable as embeddable *because*
`bitting-client → bitting-proto` is the only edge it is allowed, and that is checked rather than
remembered. If that rule were relaxed, the permissive licence on the crate would silently
become a promise the code no longer keeps.

So the same file encodes both, and `cargo xtask check-licenses` enforces the licence half:

* every workspace crate declares the licence `rules::expected_license` names;
* **no crate depends on an internal crate whose licence reaches further than its own** —
  transitively, because `bitting-client` → helper → `bitting-core` leaks copyleft just as
  effectively as a direct edge, and is much easier to miss in review;
* every source file carries an SPDX header matching its tree, so a file that moves between
  crates cannot keep terms that no longer apply to where it now lives.

`bitting-format` is the instructive case for why the permissive set is not larger. An open
vault format is a feature and the crate looks like an obvious candidate — but it depends on
`bitting-crypto`, so a permissive licence there would either be a lie about the combined work
or a permissive `bitting-crypto`, which is the whole vault core. The check rejects it, and the
reasoning is in `xtask/src/rules.rs` next to the rule.

See `COPYRIGHT` for the licence record and `LICENSE-EXCEPTION.md` for the app-store
additional permission.

## Transport and peer authentication

| Platform | Endpoint |
|---|---|
| Linux | `$XDG_RUNTIME_DIR/bitting/agent.sock`, directory `0700`, socket `0600` |
| macOS | `~/Library/Application Support/dev.bitting/agent.sock`, same modes |
| Windows | `\\.\pipe\dev.bitting.agent-<user-sid-hash>`, DACL for the current user SID only, `PIPE_REJECT_REMOTE_CLIENTS` |

Peer checks: `SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`LOCAL_PEERPID` on macOS,
rejecting any peer whose UID differs from ours. On Windows the DACL is the gate and
`GetNamedPipeClientProcessId` is used for audit attribution.

The base protocol is length-prefixed JSON frames of `bitting-proto` types, capped at
1 MiB, with a versioned hello. JSON rather than a compact binary format because the
browser native-messaging side is already JSON and IPC debuggability is worth more
here than bytes; the *on-disk* format uses `postcard` precisely because it is not
self-describing. The frame decoder is a fuzz target.

Extension and MCP sessions additionally run Noise `KKpsk0_25519_ChaChaPoly_BLAKE2s`
over that channel, keyed by a per-install pairing PSK derived from the vault. That
gives mutual authentication, forward secrecy, and replay protection.

Sessions declare a client type (`gui`, `cli`, `extension`, `mcp`) in the hello.
Policy defaults differ per type — an MCP session starts with no scopes at all.

**What this machinery does and does not buy** (see T13 in the threat model): it
makes cross-user and remote access impossible and makes a wrong or stale pairing
fail closed. It is *not* a boundary against same-user malware, and we do not claim
it is.

## Lifecycle

* **Spawn.** `bitting-client` connects, or spawns the agent if the socket is absent,
  guarded by a lockfile. The agent exits after an idle-and-locked timeout. Service
  units ship in `packaging/` as opt-in.
* **Unlock.** The passphrase is streamed to the agent in one frame and zeroized
  immediately after key derivation. The MCP server can never prompt for or accept a
  passphrase.
* **State.** Clients subscribe to `StateChanged{locked|unlocked}` so the tray icon,
  the extension badge, and `bitting status` all read one truth.
* **Lock.** Zeroize the master key and subkeys, drop the decrypted manifest,
  invalidate every `EntryRef`, revoke non-persisted grants, clear the clipboard if
  it still holds our value.
* **Auto-lock triggers.** 5 minutes idle; OS screen lock; suspend (locking *before*
  sleep, inside the inhibitor window); fast user switch; logout; and a hard 8-hour
  cap regardless of activity.

## Where secrets are allowed to exist

This is the invariant list. Anything outside it is a bug.

1. Inside `bitting-agent`, in `SecretBytes`/`SecretString` buffers, page-locked where
   the platform allows.
2. Briefly inside `bitting-reveal`, which receives one already-decrypted value over an
   inherited socket and renders it in a non-capturable native window.
3. In the OS clipboard, for the auto-clear window, when the user asked for that.
4. In synthetic keystrokes, when the user asked for that.

Notably **not** on that list: the Tauri webview's JavaScript heap. A JS engine
copies strings freely, frees them without zeroizing, and can serialize them into
heap snapshots. The webview receives opaque handles and masked placeholders; copy,
fill, and type are Rust-side commands returning only a status. An integration test
asserts that no secret bytes appear in any Tauri command result or IPC payload, and
a failure there is a release blocker.

## Why Tauri, given that

Pure-Rust toolkits (`egui`, `iced`, `Slint`) would keep secrets in Rust memory
end-to-end, which is the stronger memory-hygiene story. Tauri was chosen anyway,
for two reasons that outweigh it:

* **Accessibility.** Screen readers work natively in WKWebView, WebView2, and
  WebKitGTK. `AccessKit` coverage in the pure-Rust toolkits is still incomplete,
  and an inaccessible password manager excludes blind users from basic security.
  That is not an acceptable trade.
* **Packaging maturity.** Tauri's bundler produces dmg, msi, deb, rpm, and AppImage
  today. The alternative is hand-rolling all five.

The webview risk is then managed by removing the thing worth stealing: it renders
only bundled local assets under a pinned CSP with the isolation pattern enabled and
devtools disabled in release, and — per the invariant above — it never holds a
secret. Compromising it yields a policy-gated session handle, not key material.

## Data at rest

Four files beside each other:

| File | Contents |
|---|---|
| `vault.bitting` | Header, encrypted manifest, encrypted records, footer hash |
| `vault.bitting.bak.{1,2,3}` | Rotated backups, each tagged with its write counter |
| `vault.audit` | Hash-chained audit log, encrypted under a derived audit key |
| `vault.state` | Last-seen write counter and hashes, mirrored into the OS keychain |

The format is specified in [`vault-format.md`](vault-format.md). Two design points
that shape everything else:

* **Only the manifest is decrypted at unlock.** Passwords, notes, and TOTP seeds
  stay encrypted on disk until individually requested. This keeps the decrypted
  footprint small, which is the most effective mitigation available against T3, and
  it makes unlock time independent of vault size.
* **Per-record keys are derived, not stored.** `HKDF(VMK, "record/" ‖ id ‖ epoch)`
  gives full key separation for free, so a save rewrites only changed records and a
  master-password change rewrites only the header.

## Reading order for reviewers

1. `docs/threat-model.md` — what is and is not claimed.
2. `crates/bitting-crypto/src/` — key hierarchy, in the order `secret`, `kdf`,
   `subkeys`, `aead`.
3. `docs/vault-format.md` then `crates/bitting-format/src/` — the on-disk contract and
   its parser, which is the only code reading fully hostile bytes.
4. `crates/bitting-core/src/policy.rs` — the single allow/deny/ask chokepoint shared
   by the CLI, the extension, and the MCP server.
5. `crates/bitting-agent/src/` — session handling and the trust boundary.
6. `xtask/src/rules.rs` — the architectural rules, as CI sees them.

## The Windows transport, specified but not written

Windows is the one platform where `bitting-agent` refuses to start. The error says so, and this
section says what has to be built, because a specification is more useful than a plausible
implementation nobody has run.

**Why it is not written.** The transport needs the Windows security APIs, which means `unsafe`
in `bitting-hardening`, and the security-relevant part is a token-SID comparison — code where a
mistake silently *grants* access rather than failing visibly. It cannot be compiled, let alone
tested, on the machine Bitting is currently developed on. Writing it blind and committing it as
done would put an unverified security control in the tree behind a green build, which is worse
than an honest refusal.

**The design.** It mirrors the Unix side, where the file mode is a courtesy and
`SO_PEERCRED` is the control.

* **Name.** `\\.\pipe\dev.bitting.agent-<hash of the user SID>`, so two users on one machine
  cannot collide and neither can guess the other's name from their own.
* **Creation.** `CreateNamedPipeW` with `PIPE_ACCESS_DUPLEX`, `PIPE_TYPE_BYTE`,
  `PIPE_READMODE_BYTE`, `PIPE_WAIT`, and — importantly —
  **`PIPE_REJECT_REMOTE_CLIENTS`**. Named pipes are reachable over SMB by default, and
  omitting that flag turns a local-only design into a network service.
* **First instance.** `FILE_FLAG_FIRST_PIPE_INSTANCE` on the instance created at startup, so
  creation fails if the name is already claimed. Without it a second process can create
  another instance of the same pipe and receive some of the connections meant for the first —
  the Windows form of the socket-hijacking bug the Unix side had and now refuses.
* **Security descriptor: null.** That gives the pipe the creating token's default DACL, in
  practice the creating user and `SYSTEM`. This is the analogue of `0600` on the socket:
  worth having, and not what the design relies on. Hand-building a DACL adds a second thing
  to get wrong without removing the need for the next item.
* **The actual control: verify the client's user.** After `ConnectNamedPipe`, call
  `ImpersonateNamedPipeClient`, `OpenThreadToken`, and `GetTokenInformation(TokenUser)`, and
  compare the client's SID against the agent's own with `EqualSid`. **Fail closed**: if
  impersonation fails or either SID cannot be read, refuse the connection. Assuming a peer is
  the same user because the check was unavailable is the mistake that makes the check
  pointless. `RevertToSelf` on every path — a thread left impersonating a client would make
  the agent's subsequent file access run as somebody else.
* **Attribution only:** `GetNamedPipeClientProcessId` for the audit log and approval dialogs.
  A pid is a hint, not a capability — pids are reused, so nothing may be authorised on one.
* **Client side.** `bitting-client` opens the pipe with `CreateFileW` and needs
  `wait_for_socket`'s equivalent: wait until the pipe can actually be opened, not until a name
  exists. The Unix version originally waited for a path to exist and stranded users after a
  crash; the Windows version should not repeat it.

**Also outstanding on Windows**, and separate from the transport: `SetProcessMitigationPolicy`
for dynamic-code and extension-point policies, `WerRegisterExcludedMemoryBlock` to keep key
pages out of crash dumps, `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` for the reveal
overlay, and the clipboard exclusions — which `arboard` already applies, and which are the one
piece of Windows-specific behaviour in the tree that is written.
