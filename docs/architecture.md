# Architecture

## The shape of the system

One long-lived process holds the unlocked vault. Everything else is a client.

```
 keel (CLI) ──────────UDS──►┌──────────────────────────────────────────┐
 keel-mcp ────────────UDS──►│  keel-agent                              │──► vault.keel
 keel-native-host ────UDS──►│                                          │──► vault.audit
    ▲ stdio                 │  · VMK + subkeys (mlock'd, zeroized)     │──► vault.state
 browser extension          │  · session table, per-client policy      │
                            │  · grant / approval engine               │
 Keel.app (Tauri) ────UDS──►│  · auto-lock, clipboard auto-clear       │
   └─ approval modals       │  · spawns keel-reveal for plaintext      │
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
keel-crypto  → (crypto primitives only)          no I/O, no clock, no platform
keel-format  → keel-crypto                       parses hostile bytes; fuzzed
keel-hardening → keel-crypto                     the ONLY crate allowed `unsafe`
keel-store   → keel-crypto, keel-format          atomic writes, locking, backups
keel-core    → keel-crypto, keel-format, keel-store, keel-hardening
keel-proto   → serde only                        wire types, parallel leaf
keel-agent   → keel-core, keel-proto             the privileged process
keel-client  → keel-proto                        ← NOT keel-crypto. The key rule.
keel-cli / keel-mcp / keel-native-host / keel-reveal / desktop → keel-client
keel-import  → keel-crypto, keel-format          CSV and browser importers
keel-breach  → rustls, ureq                      the ONLY crate with a network dep
```

Rules worth stating explicitly, because they are load-bearing rather than
stylistic:

* **`keel-crypto` and `keel-proto` are leaves.** `keel-crypto` has no filesystem,
  no network, no clock beyond timing its own calibration probe, and no platform
  code. That is what makes it fuzzable and reviewable, and it is why `mlock` lives
  behind the `PageLocker` hook that `keel-hardening` installs rather than inside
  the crypto crate.
* **`keel-client` may depend only on `keel-proto`.** If it ever gains
  `keel-crypto`, `keel-format`, or `keel-core`, key material becomes reachable
  from four more processes and the short answer above stops being true.
* **`keel-hardening` is the single `unsafe` boundary.** Every raw platform call in
  the project lives there, so an auditor has one file to read rather than fifteen.
* **`keel-breach` is the single network boundary**, is opt-in, and is off by
  default. `cargo xtask check-network` walks the *resolved* dependency graph — not
  the manifests — and fails if an HTTP or TLS crate becomes reachable from any
  other crate.

Both rules are encoded in `xtask/src/rules.rs`, which has a CODEOWNERS entry
because editing it edits a security boundary.

## Transport and peer authentication

| Platform | Endpoint |
|---|---|
| Linux | `$XDG_RUNTIME_DIR/keel/agent.sock`, directory `0700`, socket `0600` |
| macOS | `~/Library/Application Support/dev.keel/agent.sock`, same modes |
| Windows | `\\.\pipe\dev.keel.agent-<user-sid-hash>`, DACL for the current user SID only, `PIPE_REJECT_REMOTE_CLIENTS` |

Peer checks: `SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`LOCAL_PEERPID` on macOS,
rejecting any peer whose UID differs from ours. On Windows the DACL is the gate and
`GetNamedPipeClientProcessId` is used for audit attribution.

The base protocol is length-prefixed JSON frames of `keel-proto` types, capped at
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

* **Spawn.** `keel-client` connects, or spawns the agent if the socket is absent,
  guarded by a lockfile. The agent exits after an idle-and-locked timeout. Service
  units ship in `packaging/` as opt-in.
* **Unlock.** The passphrase is streamed to the agent in one frame and zeroized
  immediately after key derivation. The MCP server can never prompt for or accept a
  passphrase.
* **State.** Clients subscribe to `StateChanged{locked|unlocked}` so the tray icon,
  the extension badge, and `keel status` all read one truth.
* **Lock.** Zeroize the master key and subkeys, drop the decrypted manifest,
  invalidate every `EntryRef`, revoke non-persisted grants, clear the clipboard if
  it still holds our value.
* **Auto-lock triggers.** 5 minutes idle; OS screen lock; suspend (locking *before*
  sleep, inside the inhibitor window); fast user switch; logout; and a hard 8-hour
  cap regardless of activity.

## Where secrets are allowed to exist

This is the invariant list. Anything outside it is a bug.

1. Inside `keel-agent`, in `SecretBytes`/`SecretString` buffers, page-locked where
   the platform allows.
2. Briefly inside `keel-reveal`, which receives one already-decrypted value over an
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
| `vault.keel` | Header, encrypted manifest, encrypted records, footer hash |
| `vault.keel.bak.{1,2,3}` | Rotated backups, each tagged with its write counter |
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
2. `crates/keel-crypto/src/` — key hierarchy, in the order `secret`, `kdf`,
   `subkeys`, `aead`.
3. `docs/vault-format.md` then `crates/keel-format/src/` — the on-disk contract and
   its parser, which is the only code reading fully hostile bytes.
4. `crates/keel-core/src/policy.rs` — the single allow/deny/ask chokepoint shared
   by the CLI, the extension, and the MCP server.
5. `crates/keel-agent/src/` — session handling and the trust boundary.
6. `xtask/src/rules.rs` — the architectural rules, as CI sees them.
