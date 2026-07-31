# Keel — Open-Source, Post-Quantum-Resistant Password Manager

## Build status

| Phase | State | Notes |
|---|---|---|
| 0 — Skeleton, CI, gates, docs | **Done** | Both gates verified to fail when violated |
| 1 — keel-crypto, keel-format, keel-hardening | **Done** | ~34M fuzz executions after the last format change, zero crashes |
| 2 — keel-store, keel-core | **Done** | Crash safety verified by SIGKILL; policy engine complete including the approval lifecycle |
| 3 — keel-proto, keel-agent, keel-client, keel-cli | **Done** | Full CLI surface |
| 3 — keel-reveal | **Done** | winit + softbuffer, hand-built bitmap font, no font parser. Excluded from screen capture on macOS, verified. The agent spawns it and pipes the secret, so plaintext never enters the GUI process. |
| 4 — Tauri desktop GUI | **Done** | Masked-only window, approval dialogs, health, activity, access, settings. Canary test verified to fail when a leak is injected. |
| 5 — CSV import | **Done** | Chrome/Firefox/Safari/Bitwarden/1Password/LastPass/KeePass dialects |
| 5 — Browser extension | **Done, minus pairing** | `keel-native-host`, MV3 extension, `keel setup-browser`. Origin matching in the agent, with every look-alike case tested. SAS pairing and the Noise channel are not built. |
| 6 — MCP server | **Done** | Both halves verified: the default cannot leak a password, and the opt-in works one request at a time |
| 7 — Release pipeline | **Mostly done** | Packaging templates written for Homebrew, Scoop, AUR, nfpm (deb/rpm), and a systemd user unit. Signing keys not generated — that is an offline ceremony whose whole value is never having been on a networked machine. |

**Working:** the whole CLI — `init`, `unlock`, `lock`, `status`, `list`, `search`, `add`, `get`,
`show`, `rotate`, `rm`, `generate`, `save`, `import`, `export`, `audit`, `log`, `settings`,
`approvals`, `grant`, `grants`, `revoke`, `setup-browser`, `verify-release`, with `--json` and
`--vault` throughout — plus the desktop window, the MCP server, the browser extension with its
native bridge, and the reveal overlay.

**594 tests**, clippy clean under `-D warnings`, both architectural gates passing, and a
full-system smoke test that exercises every command in one session with zero failures.

**Not working, deliberately loud about it:**

- **Hiding the overlay from screen capture on Linux and Windows.** Works on macOS. Linux has
  no mechanism a client can use, so this is unachievable rather than unwritten; Windows is
  unwritten along with the rest of that platform. The window says which applies.
- **Typing into the focused window.** Refused until it can verify which window has focus;
  without that it is worse than the clipboard.
- **Pairing between the extension and the agent.** SAS code plus a Noise channel, per §6.3.
  Its value is against a same-user process impersonating the browser, which is outside the
  threat model the rest of Keel is written against — recorded as a gap, not skipped quietly.
- **Windows — it does not compile.** `keel-hardening` references windows-sys symbols that do
  not resolve (`WerRegisterExcludedMemoryBlock`, `Win32::System::SystemInformation`, and two
  process-mitigation policy types), so the crate fails to build before the missing transport
  even matters. Removed from the CI matrix rather than left red on every commit; a permanently
  failing job for an unsupported platform trains people to ignore the matrix.
  The transport is *specified* in
  `docs/architecture.md` rather than implemented: it needs the Windows security APIs, the
  load-bearing part is a token-SID comparison whose failure mode is to silently grant access,
  and none of it can be compiled — let alone run — on the machine this was developed on.
  Committing unverified `unsafe` security code behind a green build is worse than an honest
  refusal, so the design is written down instead.

- **The breach Bloom filter.** The strength estimator recognises structure and ~300 famous
  passwords and says so rather than implying corpus coverage.

## Deliberate departures from this plan

Each of these was decided during implementation, and the reasoning matters more than the
choice:

1. **The GUI has no framework and no npm.** The plan specified Svelte and Vite. A build step
   is a supply chain, and this is the window between a person and every password they own;
   `npm install` is also the single largest obstacle to reproducible builds. Cost: rendering
   is explicit DOM construction. That also removes `innerHTML` from the codebase entirely,
   which removes the class of bug where an entry title — or text an AI agent wrote — becomes
   markup.
2. **The clipboard lives in the agent, not the shell.** The plan routed copies through
   `src-tauri`. Doing it in the agent means the plaintext never enters the GUI process at
   all, which is strictly stronger, and it made the clipboard work without waiting for the
   GUI.
3. **zxcvbn was not adopted.** 37 crates including a backtracking regex engine, inside the
   process holding the master key, to answer "is this obviously terrible?". A focused
   structural estimator does that job and says what it is.
4. **No Public Suffix List.** The plan called for it. It is genuinely needed to derive a
   *registrable domain from a request origin* — without it `bank.co.uk` and `evil.co.uk` both
   reduce to `co.uk`. Keel asks the opposite question: does this **stored** origin, which the
   user typed, cover this request origin? A dot-boundary suffix rule is sound in that
   direction without a suffix list, and the list becomes necessary only if entry discovery
   moves from exact lookup to registrable-domain grouping.
5. **Browser fill has its own request rather than going through `use_secret`.** `use_secret`
   promises to return no secret, and a browser fill necessarily hands one to the extension —
   it has to set the value of an input. Overloading `use_secret` would have made its contract
   a lie, so `FillCredential` says plainly what it does.
6. **Escalations are raised without a GUI attached.** The plan failed closed by refusing to
   ask when no window was open. Once `keel approvals` existed, that told users on headless
   machines to open a window that does not exist there. Failing closed is preserved by the
   timeout instead — nothing is ever auto-approved.

## Findings from implementation worth keeping

Bugs the plan did not anticipate, that only appeared under test:

1. **The approval mechanism never worked.** `resolve_reveal_approval` cleared an in-flight
   flag and nothing else, so an approved retry was escalated again forever — a reveal could
   not succeed no matter what the user did. The `ApprovalRequest` details were discarded, so
   no dialog could have been rendered either. And the setting the refusal message told users
   to change (`enable it in Settings`) did not exist: `set_mcp_reveal_enabled` was dead code.
   All three are now built and tested end to end.
2. **A timed-out escalation deadlocked the client.** `reveal_in_flight` was never cleared on
   expiry, so an unattended timeout left the client told "another reveal is already awaiting
   approval" for the rest of the session.
3. **The audit chain broke on every lock/unlock.** `AuditLog::new` restarts at sequence 1, so
   a second session appended records numbered from 1 onto an existing chain. Normal daily use
   would have reported tampering.
4. **Deleting records from the end of the audit log was undetectable.** Any prefix of a hash
   chain is a valid chain. Fixed with an anchor in the authenticated manifest committing to
   count *and* tip.
5. **The network gate reported a violation that did not exist.** It walked
   `cargo metadata`'s all-platform union, where `tauri`'s Android/iOS-only `reqwest` looks
   universal. Now checked per shipped target, which is both correct and stronger.
6. **A killed agent stranded the user**, and **a second agent could hijack a live agent's
   socket**.
7. **The AAD design bug** below, which would have made passphrase changes O(vault size).
8. **Two identical flaky tests** counted passphrase words by splitting on `-`, which is both
   the default separator and a character inside four EFF wordlist entries.
9. **The audit log was created 0644** by umask.
10. **`audit_tail` is not exposed as an MCP tool** though §7.2 contemplated it. Open decision,
    not an oversight; the tests deliberately do not assert either way.
11. **The exhaustive `match` on `Response` in keel-mcp caught five omissions** as variants
    were added, each forcing a deliberate decision about whether an agent should see the new
    data. Worth preserving rather than adding a catch-all arm.

## Findings from implementation worth keeping

Bugs that the plan did not anticipate and that only appeared under test:

1. **The audit chain broke on every lock/unlock.** `AuditLog::new` restarts at sequence 1,
   so a second session appended records numbered from 1 onto an existing chain. Normal daily
   use would have reported tampering — an integrity check that cries wolf is worse than
   none, because it trains people to ignore the one alert that matters. Fixed with
   `AuditLog::resume`.
2. **Deleting records from the end of the audit log was undetectable.** Any prefix of a hash
   chain is a valid chain. Fixed with an anchor in the authenticated manifest, committing to
   the expected count *and* tip — the tip matters because a rebuilt tail of the same length
   would otherwise pass. Residual limit, now documented in the threat model: the anchor is
   refreshed on save, so it is a floor, and an attacker can erase the tail of a session but
   not the history of one.
3. **The AAD design bug** described below, which would have made passphrase changes
   O(vault size) and destroyed the reason for the KEK/VMK split.
4. **Two identical flaky tests** counted passphrase words by splitting on `-`, which is both
   the default separator and a character inside four EFF wordlist entries. ~0.3% failure
   rate. The hazard was documented in a neighbouring test and not applied.
5. **The audit log was created 0644** by umask. Encrypted, so no content leaked, but its
   size tracks how many operations the user performed.
6. **A killed agent stranded the user.** `wait_for_socket` waited for the socket file to
   *exist*, which a socket left behind by a SIGKILL satisfies instantly — so the client
   spawned an agent, declared the socket ready, connected, and was refused. Every `keel`
   command then failed until the user worked out they had to delete a file in a directory
   they had never heard of. Now it waits until it can actually connect.
7. **A second agent could hijack a running agent's socket.** `Listener::bind` unlinked any
   existing socket file unconditionally. Unlinking a live agent's socket does not stop that
   agent — it keeps its descriptor and its keys — while every new client reaches the second
   process, leaving two agents on one vault with the first orphaned and invisible. Bind now
   probes by connecting: an answer means refuse, a refused connection means stale and safe
   to clear, and anything else (including a plain file) is left alone, since
   `KEEL_AGENT_SOCKET` is user-settable and a typo should not delete a real file. The
   pre-existing test for this simulated a stale socket with a plain file containing
   "stale", so it never exercised the case it named.
8. **The schema bump needed a migration.** The plan called for "reads old / writes new" and
   the first implementation just bumped the number, which would have refused to open any
   vault built before the change. Fixed with a `ManifestV1` struct and a decode fallback,
   verified by building the previous commit in a worktree, creating a vault with it, and
   opening it with current code — passwords intact, and intact again after the upgrade is
   written.
9. **`audit_tail` is not exposed as an MCP tool**, though §7.2 contemplated it under an
   `audit:read` scope. Open decision rather than an oversight: the log reveals which entries
   were touched and when, which is a usage pattern worth thinking about before handing it to
   an agent, and `keel log` now covers the user's own need. The rogue-agent test deliberately
   does not assert either way.
10. **The exhaustive `match` on `Response` in keel-mcp caught three omissions** as response
   variants were added, each time forcing a deliberate decision about whether an agent
   should see the new data. Worth preserving as a design property rather than adding a
   catch-all arm.

## Decisions that changed during implementation

Each of these came out of a test failure or a lint, and each is a correction to the plan
below rather than a deviation from it. They are recorded here because the reasoning matters
more than the outcome.

1. **The header needs two hashes, not one.** Binding records to the full header hash meant
   changing the master passphrase invalidated every record in the vault — destroying the
   reason the design separates the key-encryption key from the vault master key.
   `binding_hash` (wide) authenticates the wrapped key and blocks a KDF downgrade;
   `identity_hash` (narrow: format version, vault id, AEAD id) authenticates the manifest
   and records. Caught by an integration test.

2. **Records precede the manifest on disk.** The manifest stores record offsets and postcard
   varint-encodes them, so manifest length would otherwise depend on offsets that depend on
   manifest length. Records first removes the cycle.

3. **The write counter advances before encoding, not after.** Incrementing afterwards made
   the recorded "last seen" value one higher than the file's, so every reopen looked like a
   rollback.

4. **Trashed entries keep their records.** Soft delete means the record index spans live and
   trashed entries, in the encoder, the integrity check, and validation.

5. **The agent uses threads, not an async runtime.** It serialises a handful of local
   clients, and dropping tokio removes a large amount of code from the address space holding
   the master key.

6. **`fd-lock` dropped for `std::fs::File::try_lock`** (stable since 1.89). The lock is tied
   to the file descriptor, so a crash cannot leave a vault permanently locked. MSRV 1.89.

7. **Rate limits are per client type.** Applying agent limits to the desktop app capped it at
   ten clipboard copies an hour — protecting nothing, since someone with the passphrase can
   already read the whole vault, while making the app unusable.

8. **The coverage cap counts every secret-touching operation.** Counting only reveals made it
   unreachable behind a 5-per-hour reveal limit, so it was dead code. A const assertion now
   keeps the two limits consistent.

9. **Escape sequences are stripped whole.** Removing only the ESC byte left the literal text
   `[31m`, which is both noise and a way to build misleading strings out of apparently
   sanitised text.

10. **Size limits are compile-time assertions**, so an inconsistent limit fails the build.

---


## Context

Greenfield project (directory is empty). Build a free, open-source password manager engineered to the highest practical security bar: an attacker who steals the vault file, compromises GitHub, or wields a future quantum computer still cannot recover a single password without the master password.

**Honest framing — read this before writing any marketing copy.** "Unhackable" is not a real property; anyone claiming it is selling something. Overclaiming also destroys the trust this project needs. What is actually achievable, and what this plan delivers:

1. **Offline-attack immunity (the primary threat).** A stolen vault file is useless without the master password. Argon2id at 512 MiB makes brute force economically infeasible; 256-bit symmetric encryption is already quantum-resistant.
2. **Supply-chain integrity.** Reproducible builds + an offline hybrid signing key that never touches CI mean a compromised GitHub or CI cannot silently backdoor users — a malicious release is either unsigned (rejected by the verifier) or publicly recorded in a transparency log.
3. **Minimal attack surface.** Local-only vault, zero network code in the core (CI-enforced), memory hygiene, hardened IPC, strict extension origin matching, human-in-the-loop AI access.
4. **Auditability.** Full open source — security from cryptographic design (Kerckhoffs's principle), never secrecy.

**Explicitly out of scope, stated plainly in SECURITY.md and the README:** root/kernel malware, keyloggers, hypervisor attacks, and firmware-persistent evil-maid attacks defeat *any* password manager. Same-user malware against an *unlocked* vault also wins eventually — on a single-user desktop OS, same-UID isolation is not a security boundary. We raise cost and make abuse visible; we do not claim to stop it. We also do **not** claim plausible deniability (the file has magic bytes and a fixed header — claiming otherwise would be dishonest).

## Decisions locked in (user-confirmed)

| Decision | Choice |
|---|---|
| Distribution | **Fully open source** on GitHub — reproducible builds + signed releases. Source secrecy is not a security control and would forfeit auditability. |
| Language | **Rust** — one core, all frontends |
| v1 surfaces | Desktop GUI (macOS/Windows/Linux), CLI, MCP server, browser extension |
| Vault | **Local-only** single encrypted file. No sync server, no telemetry, no accounts. |
| GUI | **Tauri v2 with a masked-only webview** — the webview never receives a plaintext secret |
| Signing budget | **Zero** — no paid certificates. Trust comes from reproducible builds + offline hybrid signatures. |
| KDF default | **Balanced** (512 MiB / t=4 / p=4, ~1.2–2.0 s), with Interactive and Paranoid tiers offered |
| MCP reveal | **`secret:reveal` disabled by default** — agents can *use* secrets, not see them |

Product name: **`keel`** (CLI binary `keel`, reverse-DNS `dev.keel`). Alternates if trademark search fails: `lodeston`, `vaultkeel`. Renaming is a global find/replace — do the trademark/crates.io check in Phase 0 before writing code.

---

## 1. Architecture

**Single hardened agent** (the ssh-agent / 1Password model). One long-lived `keel-agent` process per user session owns the unlocked vault. Everything else — GUI, CLI, MCP server, browser native-messaging host — is a thin client over authenticated local IPC. Unlock happens once; key material lives in exactly one hardened process.

```
 keel (CLI) ──────UDS──►┌──────────────────────────────────────┐
 keel-mcp ────────UDS──►│  keel-agent  (only process with keys)│──► vault.keel
 keel-native-host ─────►│  · VMK + subkeys (mlock'd, zeroized) │──► vault.audit
    ▲ stdio             │  · session table + per-client policy │──► vault.state
 browser extension      │  · grant/approval engine             │
                        │  · autolock, clipboard auto-clear    │
 Keel.app (Tauri) ─────►│  · spawns keel-reveal for plaintext  │
   └─ approval modals   └──────────────────────────────────────┘
```

**The invariant that makes review tractable: only `keel-agent` links `keel-crypto`/`keel-format` at runtime.** Every other process is a pipe for already-authorized, mostly-masked data. CI enforces this (`cargo xtask check-layering`).

### Transport and peer authentication

- **Unix:** socket in a `0700` directory — `$XDG_RUNTIME_DIR/keel/agent.sock` (Linux), `~/Library/Application Support/dev.keel/agent.sock` (macOS); socket mode `0600`. Verify peer UID via `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` + `LOCAL_PEERPID` (macOS); require `uid == geteuid()`.
- **Windows:** named pipe `\\.\pipe\dev.keel.agent-<user-sid-hash>` with a DACL granting only the current user SID, `PIPE_REJECT_REMOTE_CLIENTS`, plus `GetNamedPipeClientProcessId` + image signature check for audit attribution.
- **Base wire protocol:** length-prefixed (`u32` LE) JSON frames of `keel-proto` enums, versioned hello, 1 MiB cap, fuzzed parser. JSON rather than postcard here because the native-messaging side is already JSON and debuggability matters for IPC (the *on-disk* format uses postcard — see §3).
- **Extension and MCP sessions additionally run Noise `Noise_KKpsk0_25519_ChaChaPoly_BLAKE2s`** (`snow` crate) over that channel, with per-install pairing keys (§6.3). Noise gives mutual static-key auth, forward secrecy, and monotonic nonce counters (replay protection) for free.
- Sessions declare `client_type: gui | cli | extension | mcp` in the hello; policy defaults differ per type.
- Crates: `interprocess` for transport, `rustix` / `windows-sys` for credential checks.

**Honest limitation to document:** none of this is a boundary against same-UID malware. Its real jobs are (a) making cross-user and remote access impossible, (b) failing closed on a wrong or stale pairing, (c) surfacing "an unknown client tried to connect" in the audit log.

### Lifecycle

- **Spawn:** `keel-client` connect-or-spawns the agent (found next to own executable, else `$PATH`), guarded by a lockfile against races. Agent exits after N minutes idle-and-locked. launchd/systemd-user units ship in `packaging/` as opt-in.
- **Unlock:** the passphrase is streamed to the agent in one frame and zeroized immediately after KDF. The MCP server can never prompt for or accept a master password.
- **State broadcast:** clients subscribe to `StateChanged{locked|unlocked}` — tray icon, extension badge, and `keel status` all read one truth.
- **Lock** = zeroize VMK + subkeys, drop the decrypted manifest, invalidate all `EntryRef` handles, revoke non-persisted grants, clear the clipboard if it still holds our value.
- **Autolock triggers** (all configurable): 5 min app-idle; OS screen lock (`com.apple.screenIsLocked` via `objc2`; `org.freedesktop.login1.Session.Lock` / `ScreenSaver.ActiveChanged` via `zbus`; `WM_WTSSESSION_CHANGE`/`WTS_SESSION_LOCK`); suspend (`NSWorkspaceWillSleepNotification`; logind `PrepareForSleep(true)` — lock *before* sleeping, inside the inhibitor window; `PBT_APMSUSPEND`); fast user switch; logout; **hard 8-hour session cap** regardless of activity.
- **Failed unlocks:** exponential backoff (1→60 s), full Argon2 run on every attempt (no cheap pre-check), constant-time comparison, and no error distinction between wrong password and wrong keyfile.

---

## 2. Repository layout

```
keel/
├── Cargo.toml Cargo.lock rust-toolchain.toml deny.toml supply-chain/ .cargo/config.toml
├── LICENSE SECURITY.md CONTRIBUTING.md README.md CHANGELOG.md
├── crates/
│   ├── keel-crypto/        # KDF tiers+calibration, HKDF namespace, XChaCha20 AEAD, SecretBytes,
│   │                       #   CSPRNG, password/passphrase generator. #![forbid(unsafe_code)], no I/O
│   ├── keel-format/        # on-disk binary codec: header/manifest/record, padding, AAD, DoS guards.
│   │                       #   Pure, fuzzed. THE frozen contract everything depends on.
│   ├── keel-hardening/     # THE ONLY crate allowed `unsafe`: mlock, core-dump suppression,
│   │                       #   ptrace deny, capture exclusion, panic wipe
│   ├── keel-store/         # atomic write transaction, advisory locking, backup rotation, OS paths
│   ├── keel-core/          # vault open/save, records, autolock state machine, hash-chained audit log,
│   │                       #   policy/grant engine (the single allow/deny/ask chokepoint)
│   ├── keel-proto/         # IPC wire types only (serde). Parallel leaf, no logic.
│   ├── keel-agent/         # bin `keel-agent` — the daemon; the only runtime holder of keys
│   ├── keel-client/        # connect-or-spawn + typed API. NO crypto deps.
│   ├── keel-reveal/        # bin `keel-reveal` — tiny native (winit) non-capturable overlay window
│   │                       #   that renders one plaintext secret. No webview. ~300 lines.
│   ├── keel-cli/           # bin `keel` (clap, rpassword)
│   ├── keel-mcp/           # bin `keel-mcp` (rmcp, stdio) — stateless, policy-free proxy
│   ├── keel-native-host/   # bin `keel-native-host` — browser stdio ⇄ agent proxy. Dumb pipe.
│   ├── keel-import/        # features: csv, chromium, firefox. Only crate touching rusqlite/DPAPI/NSS.
│   └── keel-breach/        # OPTIONAL HIBP client — the ONLY crate allowed a TLS/HTTP dep. Off by default.
├── apps/desktop/           # Tauri v2 app: src-tauri/ (Rust shell → keel-client) + ui/ (TS + Svelte, vite)
├── extension/              # MV3 WebExtension (TypeScript, vite + web-ext). Not in the Cargo workspace.
├── fuzz/                   # cargo-fuzz: vault_parse, ipc_frame, csv_import, nss_key4, noise_frame
├── xtask/                  # gen-native-manifests, package, check-layering, gen-proto-schema
├── docs/                   # threat-model, architecture, vault-format, REPRODUCE, VERIFY, cli, install
├── packaging/              # nfpm.yaml, AUR PKGBUILDs, homebrew tap notes, scoop/winget manifests, wix
└── .github/workflows/      # ci, audit, fuzz, release, rebuild, extension
```

### Dependency direction (CI-enforced)

```
keel-crypto  → crypto crates, zeroize, subtle, getrandom       (no I/O, no clock, no rand injection needed beyond getrandom)
keel-format  → keel-crypto, postcard, serde                    (pure; parses attacker-controlled bytes)
keel-store   → keel-format
keel-core    → keel-crypto, keel-format, keel-store, keel-hardening
keel-proto   → serde only
keel-agent   → keel-core, keel-proto, snow, tokio
keel-client  → keel-proto                                      ← crucially NOT keel-crypto
keel-cli / keel-mcp / keel-native-host / desktop → keel-client (+ keel-import for cli & desktop)
keel-breach  → rustls, ureq                                    ← the ONLY crate with a network dep
```

The "no network in core" claim is made real by a CI gate, not a promise:

```bash
cargo tree -e normal -p keel-core --prefix none \
  | grep -Ei '^(reqwest|hyper|ureq|curl|curl-sys|openssl-sys|native-tls|tokio-.*net)' && exit 1
```
plus matching `[bans] deny = [...]` in `deny.toml` scoped to the core tree.

---

## 3. Cryptography

### 3.1 Key hierarchy

```
master password ──┐
keyfile (opt) ────┤
FIDO2 hmac-secret / YubiKey HMAC (opt) ──┤
                  ▼
      pre-key mixing: BLAKE3 keyed hash          ← never string-concatenate factors
                  ▼
      Argon2id(m, t, p, salt) ──32 B──► KEK      (key-encryption key, never stored)
                  │
                  ├── unwrap ──► VMK             (Vault Master Key, 32 B random, epoch-tagged)
                  ▼
      HKDF-SHA-512(ikm = VMK, salt = vault_uuid, info = domain string)
                  │
   ┌──────────────┼───────────────┬──────────────┬───────────────┬──────────────┐
   ▼              ▼               ▼              ▼               ▼              ▼
index_key   record_key(id,epoch)  audit_key  attachment_key  pairing_root  search_key
(manifest)  (one per record)      (chain)    (per file)      (ext/MCP)     (reserved, unused in v1)
```

Domain-separation strings (versioned, never reused):
```
"keel/v1/index"      "keel/v1/record/" || record_id || LE32(key_epoch)
"keel/v1/audit"      "keel/v1/attach/" || attach_id
"keel/v1/pairing-root"                 "keel/v1/search"   (reserved)
```
HKDF-SHA-512 (`hkdf` crate) is chosen over BLAKE3's KDF mode purely because HKDF is the more auditable, standard primitive for reviewers. BLAKE3 is still used for hashing, MACing, and pre-mixing where speed matters.

### 3.2 Argon2id parameters

`argon2` crate (RustCrypto), `Algorithm::Argon2id`, `Version::V0x13`, 32-byte output, 32-byte salt from `getrandom`.

| Tier | m_cost | t_cost | p_cost | Approx. time |
|---|---|---|---|---|
| Interactive | 262144 KiB (256 MiB) | 3 | 4 | ~0.4–0.7 s |
| **Balanced (default)** | **524288 KiB (512 MiB)** | **4** | **4** | **~1.2–2.0 s** |
| Paranoid | 1048576 KiB (1 GiB) | 6 | 8 | ~4–6 s |

RFC 9106's 64 MiB and OWASP's 19 MiB are floors for *servers*. A desktop vault unlocks a handful of times per day and the agent daemon keeps it unlocked, so buy memory-hardness aggressively — GPU/FPGA/ASIC cracking cost scales with memory, not iterations.

**Calibration** at vault creation (and re-offered on unlock if stored params are below the current recommended minimum): cap `m_cost ≤ min(available_ram/4, 2 GiB)`; benchmark 256 MiB/t=1 once and extrapolate linearly in `m·t`; pick the highest tier under the user's time budget (default 1.5 s, adjustable 0.3–10 s); `p_cost = min(4, available_parallelism())`; record the measured time in the header for later "your machine changed" hints.

**Two guards that are easy to forget:**
- **Anti-downgrade:** params live in the header and are covered by AAD, so rewriting the header to `m=8 KiB` and letting the victim's own client do a cheap derivation fails the AEAD tag on the wrapped VMK.
- **Anti-DoS on parse:** a malicious vault file specifying `m_cost = 64 GiB` would OOM-kill the client. Reject on parse: `m_cost > 4 GiB`, `m_cost > 50%` of available RAM (prompt instead of allocating), `t_cost > 64`, `p_cost > 16`.

`kdf_id: u8` registry — `1 = argon2id-v0x13`, `2` reserved for a future memory-hard successor.

### 3.3 Multi-factor pre-key mixing

```
ikm = BLAKE3::keyed_hash(
        key  = blake3("keel/v1/prekey" || vault_uuid),
        data = LEN(password)||password || LEN(kf)||kf || LEN(hw)||hw )
KEK = Argon2id(password = ikm, salt = header.salt, m, t, p)
```
`kf = blake3(keyfile_bytes)`. Absent factors contribute a zero-length field, and a `factor_flags` bitfield in the header records which factors are *required*, so a stripped-factor header fails the unwrap.

- **Keyfile** — any file, BLAKE3-hashed. Docs recommend removable media, and are honest that a keyfile next to the vault adds ~nothing against a full-disk thief; its value is against partial exfiltration (a synced folder, a backup of only `~/Documents`).
- **FIDO2 `hmac-secret`** (`ctap-hid-fido2`) — **the preferred hardware factor**: 256-bit output, physical touch required per unlock, works with any modern key. Store `credential_id` + salt in the header.
- **YubiKey HMAC-SHA1 challenge-response** (`challenge_response` crate — maintained successor to `yubico_manager`) — 64-byte challenge in the header, 20-byte response as `hw`. Follow the KeePassXC model and **regenerate the challenge on every save**.
- Both hardware factors are non-backupable by design. **Require enrolling ≥2 authenticators or printing a recovery kit before the factor can be armed**, and warn loudly that old backups become unopenable otherwise.

**Platform "quick unlock" (Secure Enclave / TPM / Windows Hello) is convenience, not a factor.** Generate a non-exportable platform key requiring biometric/user presence; wrap the VMK with a key derived via ECDH against it (`security-framework` for Secure Enclave P-256; `tss-esapi` for TPM 2.0; `windows` crate CNG / `KeyCredentialManager`). Store the wrapped blob in a sidecar + OS keychain (`keyring`), never in the vault. Rules: opt-in, per-device, revocable from any device holding the password, expires after 7 days forcing a real password unlock, and **a quick-unlock session cannot grant `secret:reveal` to MCP clients, cannot export, and cannot change the master password.** That last rule means biometric-prompt-phishing malware gets a browsing session, not the vault.

### 3.4 AEAD: XChaCha20-Poly1305

`chacha20poly1305` crate with the `xchacha20poly1305` feature, `aead_id = 1`.

Reasons, in order of weight: (1) **192-bit nonces** make random nonce generation unconditionally safe (~2^96 messages), whereas AES-256-GCM's 96-bit nonce requires a persisted counter — state you must get right across crashes, syncs, and restored backups — or accepting a ~2^32-message ceiling; for a file rewritten thousands of times and copied by users, "random nonces are always fine" eliminates a catastrophic bug class. (2) ChaCha20 is **constant-time in software everywhere**; AES without AES-NI is slow or cache-timing-vulnerable, which matters for VMs, some ARM, and a future WASM core. (3) GCM's forgery behavior under nonce misuse is worse.

`aead_id = 2` reserved for AES-256-GCM (`aes-gcm`) for a hypothetical FIPS build flag — the parser must be able to decrypt it, but **do not emit it in v1**.

**Cipher cascades are explicitly rejected.** A cascade doubles the code paths and key schedules and halves throughput, in exchange for protection against the break of a 20-year-old primitive that would be the cryptographic event of the century. Our realistic failure modes are implementation bugs, weak master passwords, and endpoint compromise — a cascade makes the first *worse* and does nothing for the others. One well-implemented AEAD with an `aead_id` registry for migration is the correct call.

### 3.5 Envelope: derived per-record keys

Single random VMK, wrapped once by the KEK; every record encrypted under `record_key = HKDF(VMK, "record/"||id||epoch)`.

Not per-entry random data keys wrapped by the VMK — that costs 60+ bytes and extra failure modes per entry to buy key separation HKDF already gives free. Not a single key over one big blob — that forces decrypting every secret to read one, the opposite of minimizing the decrypted footprint.

Operational profile that falls out of this:
- **Unlock** = Argon2id + unwrap VMK + decrypt the **manifest only** → fast even at 100k entries.
- **Reveal one password** = decrypt exactly one record into an mlocked buffer, wipe on hide.
- **Save** = rewrite manifest + only changed record blobs; unchanged ciphertext is copied verbatim.
- **Future sharing** = export one derived record key, no format change.

### 3.6 On-disk format (`vault.keel`)

```
┌ HEADER (plaintext, fully covered by AAD) ───────────────────────────────┐
│ magic[8]="KEELVLT\x01" · format_version u16 · header_len u32 · flags u32
│ vault_uuid[16] · created_at u64
│ kdf_id u8 · argon2_m u32 · argon2_t u32 · argon2_p u32
│ kdf_salt_len u8 · kdf_salt[32] · measured_kdf_ms u32
│ factor_flags u8 (bit0 keyfile, bit1 yubikey, bit2 fido2) · factor_tlv var
│     keyfile: blake3 commitment[32] │ yubikey: slot u8 + challenge[64]
│     fido2:   rp_id_hash[32] + salt[32] + cred_id_len u16 + cred_id
│ aead_id u8 · vmk_epoch_cur u32 · wrapped_vmk_cnt u8 (1..=4)
│ wrapped_vmk[]: epoch u32 + nonce[24] + ct[32] + tag[16]
│ write_counter u64 (strictly monotonic)
│ manifest_off/len u64 · records_off/len u64 · reserved[32]=0
├ MANIFEST ───────────────────────────────────────────────────────────────┤
│ nonce[24] + AEAD(index_key, postcard(Manifest), A_manifest) + tag[16]
├ RECORDS (concatenated, manifest order) ─────────────────────────────────┤
│ per record: record_id[16] · key_epoch u32 · nonce[24] · ct_len u32
│             AEAD(record_key, padded_plaintext, A_record) + tag[16]
├ FOOTER ─────────────────────────────────────────────────────────────────┤
│ total_len u64 · blake3_256(all preceding bytes)[32] · magic_end[8]
└─────────────────────────────────────────────────────────────────────────┘
```

**AAD construction — the anti-downgrade / anti-splice core:**
```
H          = blake3_256(header[0 .. offset_of(wrapped_vmk)])       // params + salt + factors
A_wrap     = "keel/v1/wrap"     || vault_uuid || H || LE32(epoch)
A_manifest = "keel/v1/manifest" || vault_uuid || H || LE64(write_counter) || LE16(format_version)
A_record   = "keel/v1/record"   || vault_uuid || H || record_id || LE32(key_epoch)
```
`A_record` deliberately **excludes** `write_counter` — otherwise every save re-encrypts every record. The record *set* is instead bound by the manifest, which stores `blake3_256(record_blob)`, offset, and length per entry, so deleting, duplicating, reordering, or splicing in a record from another version of the file is detected when the manifest is verified. `A_manifest` includes `write_counter` and `format_version`, so replaying an old manifest under a new header fails and version downgrade fails.

`Manifest` plaintext (postcard — deterministic, compact, `no_std`, not self-describing; **no `serde_json` in the read path**, since self-describing formats invite parser differentials):
```rust
struct Manifest {
  schema: u16,
  entries: Vec<EntryMeta>,      // title, username, origins[], tags[], record_id, key_epoch,
                                // ct_hash[32], ct_off, ct_len, created_at, updated_at,
                                // password_changed_at, has_totp, favorite, folder_id
  folders: Vec<Folder>,
  trash: Vec<TrashedRef>,       // soft delete, purge after N days
  settings: VaultSettings,      // autolock_secs, clipboard_clear_secs, generator defaults
  paired_clients: Vec<PairedClient>,   // browsers + agents, revocable in the GUI
  grants: Vec<PersistedGrant>,  // only user-checked "remember" grants
  free_space: Vec<(u64, u64)>,  // in-place record rewrite
}
```
Record plaintext = `postcard(RecordBody { username, password: Secret, totp_secret, notes, custom_fields, attachment_refs, history: Vec<PasswordHistoryItem> })`, **padded to the next 256-byte multiple** (length suffix inside the plaintext); manifest padded to the next 4 KiB. Net effect: file size leaks a coarse entry-count bucket and nothing about which sites.

**Parse guards (all before any allocation):** `header_len ≤ 64 KiB`, `manifest_len ≤ 64 MiB`, `records_len ≤ 4 GiB`, per-record `ct_len ≤ 16 MiB`, entries ≤ 500k, every offset bounds-checked. `keel-format::decode` is **the single highest-value fuzz target in the project** — it is the only code parsing fully attacker-controlled bytes.

### 3.7 Atomic writes and rollback resistance

Write transaction (`tempfile::NamedTempFile` in the *same directory*, `fd-lock` advisory lock held throughout):

1. Take an exclusive lock on `vault.keel.lock`; fail fast with "another instance has this vault open".
2. **Re-stat the vault**; if mtime/len/footer-hash differ from what we loaded, abort with a conflict error. Never blind-overwrite — a sync client or second instance may have changed it.
3. Write `vault.keel.tmp.<rand>` with mode `0600` / current-user-only DACL.
4. `file.sync_all()`.
5. Rotate backups: `vault.keel` → `.bak.1`, shifting `.1`→`.2`→`.3` (keep 3, each tagged with its `write_counter`).
6. `fs::rename(tmp, vault.keel)` — atomic on the same filesystem, including Windows.
7. **`fsync` the directory fd** (Unix) so the rename itself is durable.
8. Update last-seen state `{vault_uuid, write_counter, header_hash, footer_hash}` in both a `vault.state` sidecar **and** the OS keychain (`keyring`).
9. Release the lock.

**Detection on open:**
- Footer `total_len` ≠ file length, or footer hash mismatch → "truncated or corrupted", offer `.bak.N` recovery.
- `file.write_counter < last_seen.write_counter` → **hard warning modal**: "This vault is older than the last version this device saw (412 vs 419). This happens after restoring a backup or a cloud-sync conflict — or it can be an attacker rolling you back to an old password." Require explicit confirmation, and record it in the audit chain.
- `vault_uuid` mismatch → different vault, don't compare counters.
- Any record `ct_hash` mismatch → flag *that record* corrupt/tampered and still open the rest. Graceful degradation beats total failure for a password manager, with a prominent banner.
- Vault path under Dropbox/iCloud/OneDrive/Google Drive → one-time warning about versioning-enabled rollback and conflict copies.
- Group/world-readable vault file → warn and offer to `chmod 0600`.

### 3.8 Rotation

- **Master password change:** new salt, recalibrated params, derive new KEK, **re-wrap the same VMK**, `write_counter += 1`, rewrite the header only. Zero record re-encryption — this is the entire reason for the KEK/VMK split. Sub-second on a 100 MB vault.
- **VMK rotation:** generate `VMK_{n+1}`; the header holds an array of wrapped VMKs by epoch (max 4). New/edited records use the new epoch; a lazy compaction pass re-encrypts stragglers, then the old wrapped VMK is dropped. Interruption-safe by construction, and it also gives "rotate just this one password" for free.
- **Format migration:** `format_version` bump reads old / writes new, keeps a pre-migration `.bak`, and **refuses to write an older version than the file already has**.

---

## 4. The quantum-resistance story (precise version)

This section is also the source text for the README, because the honest version is more convincing than the hype version.

### Symmetric crypto is already post-quantum

- **XChaCha20 / AES-256 with 256-bit keys:** Grover's algorithm gives at most a square-root speedup on unstructured key search → ~2^128 *sequential, coherent* oracle evaluations. Grover parallelizes badly: S machines buy only √S, so a billion quantum computers (S≈2^30) still leave ~2^113 sequential steps each. Add error correction (thousands of physical qubits per logical qubit, coherence maintained across ~2^128 gate layers) and you land where NIST does: **AES-256 is a PQ Category 5 primitive.** No known quantum attack on ChaCha20 beats generic search.
- **Poly1305** is a 128-bit MAC; quantum computers don't meaningfully help forgery. The attacks are online and query-based, and an attacker holding a stolen file has **no oracle to query** — they can only produce a file our client rejects.
- **Argon2id is the actual quantum defense for the password layer.** Grover *does* apply to searching a password space, but each iteration must evaluate the whole KDF **coherently, in superposition** — for our default, 512 MiB of quantum memory held coherent through 4 passes, times ~2^(n/2) iterations. That is orders of magnitude beyond any plausible machine. Memory-hard KDFs are close to the worst possible Grover target. (The classical mitigation matters more anyway: a 6–7 word passphrase, or a FIDO2 factor that removes password entropy from the equation entirely.)

### "Harvest now, decrypt later" does not apply here

HNDL threatens data whose confidentiality rests on **public-key** operations — TLS sessions, PGP messages, KEM-wrapped sync payloads — where recording a handshake today and running Shor's algorithm in 2040 retroactively decrypts everything.

**This vault's confidentiality path contains zero public-key cryptography.** Password → Argon2id → symmetric key → AEAD. There is no key exchange to record and no long-term asymmetric secret whose future compromise unlocks past ciphertexts. An attacker who harvests `vault.keel` today and waits 20 years is in exactly the position they are in today. The correct one-line statement is: **"harvest now, decrypt later" is a public-key problem, and this vault has no public-key crypto in it.** The residual risk is entirely "was the password guessable given 20 years of classical compute?" — which is why we enforce entropy floors, offer hardware factors, and let KDF params be raised on an existing file.

### Where post-quantum work is actually needed

| Surface | Asymmetric? | v1 plan |
|---|---|---|
| Vault at rest | No | Nothing to do |
| **Release signing** | Yes — a 15+ year trust anchor | **Hybrid: Ed25519 (`ed25519-dalek`) AND ML-DSA-65 (FIPS 204, `fips204` or RustCrypto `ml-dsa`). The verifier requires BOTH** (AND, not OR). ML-DSA-65 is a 1952 B key / 3309 B signature — trivial for release metadata. |
| Update metadata | Yes | Same hybrid signature over a TUF-style manifest with an expiry field (blocks freeze attacks) and monotonic version (blocks downgrade). |
| Extension ↔ agent channel | Yes (X25519 in Noise) | Localhost-only, ephemeral, no HNDL value. Keep X25519 + PSK; upgrade when it's free from the Noise library. |
| Sync / entry sharing (v2+) | Yes | **Hybrid KEM: X25519 + ML-KEM-768** (FIPS 203; `x25519-dalek` + RustCrypto `ml-kem` or formally-verified `libcrux-ml-kem`). Combine as `ss = HKDF-SHA-512(ikm = ss_x25519 ‖ ss_mlkem, info = transcript_hash)` — **concatenate-then-KDF, never XOR** — and bind both ciphertexts and both public keys into the transcript, so the construction is IND-CCA2 if *either* KEM holds. |
| Sigstore provenance | Yes, CI-side | Supplementary only; the offline hybrid key is the trust root, so a future ECDSA break can't retroactively forge our releases. |

**Rule for `CONTRIBUTING.md`: no asymmetric primitive enters the confidentiality path without a hybrid (classical + PQ) construction.** That single rule is what makes "quantum-proof" defensible for this codebase.

---

## 5. Memory hygiene

### Types and lints

```rust
pub struct SecretBytes<const N: usize>(Box<Zeroizing<[u8; N]>>);  // on mlocked pages
pub type MasterKey = SecretBytes<32>;
pub type SecretString = Zeroizing<String>;   // pre-allocated capacity, never grown
```
- `zeroize` (+ derive) on every struct transitively holding key material; **derive** `ZeroizeOnDrop`, never hand-write it.
- `secrecy` 0.10 (`SecretBox<T>`, `ExposeSecret`) at API boundaries. Its real value is that `Debug`/`Display`/`Serialize` are *absent*, so accidentally logging or serializing a secret is a **compile error**. That static guarantee is worth more than the runtime wipe.
- Lints: `#![forbid(unsafe_code)]` everywhere except `keel-hardening`; in crypto/format/core also `#![deny(clippy::print_stdout, print_stderr, dbg_macro, unwrap_used, expect_used, indexing_slicing)]`.
- **The `Zeroizing<String>` realloc trap:** growing a `String` past capacity leaves the old contents in freed heap memory unzeroized. Rule: password buffers are allocated at a fixed 1024-byte capacity up front with an enforced max length; the same applies to `Vec<u8>` (`with_capacity`, never exceed).
- No `Debug`, `Clone`, or `Serialize` derives on secret-bearing types. Audit `thiserror` variants for embedded plaintext — no panic message may contain vault data.

### Process hardening (`keel-hardening`, called before any secret exists)

| Platform | Actions |
|---|---|
| All | `setrlimit(RLIMIT_CORE, 0)`; panic hook wipes the locked-page registry then aborts; `panic = "abort"` in release (unwinding through secret buffers is worse than a fast death) |
| Linux | `prctl(PR_SET_DUMPABLE, 0)` — also blocks same-UID ptrace and `/proc/pid/mem`; `mlock` + `madvise(MADV_DONTDUMP)` on key pages; seccomp-bpf filter for the MCP and native-host processes (no `socket`, no `execve`); surface a hint if `yama/ptrace_scope` is permissive |
| macOS | `PT_DENY_ATTACH`; `mlock`; `NSWindow.sharingType = .none` on the reveal overlay. **Zero-budget caveat:** the strong protection is the Hardened Runtime without `get-task-allow`, which needs a Developer ID we're not buying — so ad-hoc sign with `--options runtime` where possible and document that FileVault is the real protection here. |
| Windows | `VirtualLock`; `WerRegisterExcludedMemoryBlock` to keep key pages out of crash dumps; `SetProcessMitigationPolicy` for `ProcessDynamicCodePolicy`, `ProcessExtensionPointDisablePolicy` (blocks AppInit/hook DLL injection), image-load policy blocking remote/low-IL DLLs; `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`; CFG via linker |

Crates: `rustix` (preferred over raw `libc`), `libc` for gaps, `windows-sys`, `region`/`memsec` for page locking. `secmem-proc` is a convenient cross-platform bundle — audit it before adopting; it is small enough to vendor or reimplement.

**`mlock` reality check, stated in docs:** Linux's default `RLIMIT_MEMLOCK` is often 64 KiB–8 MiB. Plenty for keys (hundreds of bytes), **not** for a decrypted 50 MB manifest. Hence:

### Minimizing the decrypted footprint (the real mitigation)

This is more effective than any mlock trick:
1. Only the **manifest** (titles, usernames, URLs, tags) is decrypted at unlock. Passwords, notes, and TOTP seeds stay encrypted on disk.
2. A secret is decrypted **on demand** into a small mlocked buffer and wiped the moment the reveal closes / the fill completes / the clipboard clears — 60 s hard maximum, enforced by a watchdog task, not just control flow.
3. Decrypted secrets are **never cloned**. `use_secret`-style operations consume the buffer inside `keel-agent` and return only a status.
4. Docs recommend encrypted swap (macOS: on by default; Linux: encrypted swap or zram; Windows: BitLocker, and note pagefile encryption is off by default) — because the manifest *can* page out and we cannot stop it.

### The GUI invariant (user-confirmed choice)

**No plaintext secret ever enters the JavaScript heap.** Tauri v2 is the shell, and:
- The webview receives **opaque `EntryRef` handles and masked placeholders** (`"••••••••"`, length, strength score) — never a secret value.
- **Copy / fill / type are Rust-side Tauri commands** that go `agent → src-tauri → OS clipboard/input` and return `Ok(())`. Plaintext never crosses the JS boundary.
- **"Reveal" spawns `keel-reveal`** — a tiny native winit window (no webview) that receives the secret from the agent over an inherited socket, renders it in a non-capturable window (`WDA_EXCLUDEFROMCAPTURE` / `sharingType = .none`), and wipes on close.
- Enforced by an **integration test asserting no secret bytes appear in any IPC payload or Tauri command result**, plus a review checklist item. Treat a violation as a release blocker.
- Tauri hardening: CSP pinned to `default-src 'self'`, isolation pattern on, `withGlobalTauri` off, devtools disabled in release, capabilities scoped to the minimal command set.

Same rule for IPC generally: the native-messaging host and MCP server pass handles; the only messages carrying plaintext are the deliberate, approved, single-use ones.

---

## 6. Browser extension and import

### 6.1 Topology

```
page (untrusted) ─ content script (isolated world) ─ background SW (MV3)
                                                          │ nativeMessaging
                                                          ▼
                                        keel-native-host (dumb pipe)
                                                          │ Noise_KKpsk0 over UDS / named pipe
                                                          ▼
                                                    keel-agent (holds keys)
```
The native host does framing translation and nothing else — no keys, no decryption. If the agent isn't running it returns `app_not_running`; it must **never** silently launch the app and prompt for the master password (that's a phishing vector). The extension shows "open Keel" instead.

### 6.2 MV3 hygiene

```json
{
  "manifest_version": 3,
  "permissions": ["nativeMessaging", "activeTab", "scripting", "storage", "alarms"],
  "host_permissions": [],
  "content_security_policy": { "extension_pages": "script-src 'self'; object-src 'none'; base-uri 'none'" },
  "background": { "service_worker": "sw.js", "type": "module" },
  "web_accessible_resources": []
}
```
- **No `<all_urls>`.** `activeTab` + `chrome.scripting.executeScript` on user action; content scripts injected on demand, never declaratively on every page. **Trade-off accepted:** no automatic detect-and-fill on page load — that is the root of most extension credential-leak CVEs.
- No remote code, no CDN, no `eval`, `web_accessible_resources` empty (prevents pages fingerprinting or probing us).
- `storage.local` (a plaintext LevelDB in the profile) holds **only** the instance id, pairing state, per-site preferences, and a public key. Never a secret, never a decrypted entry, never a PSK usable without the agent.
- Isolated world only; never inject into MAIN.
- **Zero third-party JS dependencies** — plain ES modules, no build-time supply chain. `lib/protocol.ts` is generated from a JSON Schema exported from `keel-proto` (`cargo xtask gen-proto-schema`), so the wire format has one source of truth.

### 6.3 Pairing (SAS flow)

`allowed_origins` / `allowed_extensions` in the native-host manifest is necessary but **not sufficient** — it only asserts that *the browser* launched us with that origin claim, and any same-UID process can exec the host directly. So, once per browser profile:

1. Extension generates an X25519 static keypair in the service worker.
2. Sends `pair_request { ext_id, ext_pubkey, browser, profile_hint }`.
3. **The GUI shows a modal with the extension id, the browser's process path + code-signature identity, and a 6-digit pairing code.** The user reads it from Keel and types it into the extension popup — SAS-style, binding both UIs to the same human and defeating a background process racing to pair.
4. Agent derives `psk = HKDF(pairing_root, "pair/" || ext_id || ext_pubkey)` and stores `{ext_id, ext_pubkey, label, created_at, last_seen}` in the manifest, visible and revocable in a "Connected browsers" settings pane.
5. Every later session runs Noise `KKpsk0`. Requests carry `{req_id, ts, ext_seq}`; reject `|ts − now| > 30 s` or non-increasing `ext_seq`; tear down the session on any decrypt failure.
6. Framing: 4-byte LE length + JSON. Cap browser→host at **256 KiB** ourselves rather than accepting Chrome's ceiling; reject oversized frames without allocating.

### 6.4 Phishing-resistant autofill

- **Origin comes from the browser, never the page:** use `sender.origin` and `sender.frameId`/`documentId`. Never trust `location.href`, `document.domain`, or any page-supplied string.
- **Matching (decided agent-side, not in the extension):** exact origin by default, then registrable domain via the Public Suffix List (`publicsuffix` crate). Scheme must match; `https` entries never fill on `http`; port must match unless the entry says otherwise. **No wildcard or substring matching, ever** — `login.evil-example.com` must not match `example.com`, and `example.com.evil.tld` must match nothing.
- **Equivalent domains** (`google.com` ↔ `youtube.com`) as an explicit per-entry user list, plus a small curated, inspectable, in-repo default list that can be disabled.
- **Trusted user gesture required:** fill only in response to a click in the extension popup or on our injected field icon with `event.isTrusted === true`. Never on load, `DOMContentLoaded`, or focus.
- **Iframes:** top-level or same-registrable-domain only by default. A cross-origin iframe requires the entry to list that origin explicitly (covers federated login widgets) plus a one-time confirmation naming both origins.
- **Field sanity:** refuse to fill a password into a visible `type="text"` without confirmation; refuse `readonly`/`disabled`/zero-size/off-screen/`opacity:0` targets (clickjacking and invisible-harvest-field defense); warn if the form's `action` is a different registrable domain; **re-verify the frame origin immediately before writing the value** (defeats navigate-during-approval races).
- **Never bulk-send.** The popup lists entries matching the current origin only, and *values* are fetched one at a time per user click. There is no API returning all credentials for a domain, and none accepting an arbitrary origin from the extension.
- Our injected UI lives in a closed shadow root with `all: initial`; multi-entry choice happens in the **browser-chrome popup**, which pages cannot overlay or read.
- Rate-limit fills (~30/min/origin); log every fill in the audit chain with origin + entry id.

### 6.5 Clipboard

`arboard`, **agent-side only** (never the extension's `navigator.clipboard` for secrets):
- Auto-clear after **15 s** (configurable 5–120 s; "never" carries a warning). Clear **only if the clipboard still holds our value** — compare `blake3(current)` against a stored hash so we never wipe something the user copied since.
- Windows: set `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory = 0`, `CanUploadToCloudClipboard = 0` — keeps secrets out of Win+V history and cross-device sync.
- macOS: add `org.nspasteboard.ConcealedType` / transient markers. Call it a **convention** honored by well-behaved clipboard managers, not a guarantee.
- Linux: X11 selections die with the owner (we clear explicitly anyway); Wayland via `wl-clipboard` semantics; document that clipboard managers may still capture.
- Prefer **direct typing** (`enigo`, agent-side, with a target-window check) or extension fill; make clipboard the *second* option in the UI.

### 6.6 Importing from browsers

Design principle: **prefer the browser's own export; treat native extraction as a convenience that degrades gracefully; never make extraction a required code path.** Extraction is where malware-shaped code lives — keep it in feature-gated `keel-import` behind one narrow API, and be transparent that "we can read Chrome's passwords" means "so can anything else running as you."

**Chromium family** (Chrome, Edge, Brave, Vivaldi, Opera) — `Login Data` SQLite via `rusqlite`, reading **a copy** (the browser holds a lock and may have WAL); table `logins`. Also check `Login Data For Account` for signed-in profiles; NULL `password_value` rows are federated logins (record as "sign in with Google", no password).

| OS | Key source | Blob |
|---|---|---|
| Windows | `Local State` → `os_crypt.encrypted_key`, base64, strip 5-byte `DPAPI` prefix, `CryptUnprotectData` | `v10` + nonce[12] + ct + tag[16], AES-256-GCM |
| macOS | Keychain generic password, service `Chrome Safe Storage` / `Microsoft Edge Safe Storage` → PBKDF2-HMAC-SHA1, salt `"saltysalt"`, **1003 iterations**, 16-byte key | `v10` + AES-128-CBC, IV = 16×`0x20` |
| Linux | Same service from Secret Service/gnome-keyring/kwallet (`v11`), or the hardcoded fallback `"peanuts"` (`v10`); PBKDF2-HMAC-SHA1, `"saltysalt"`, **1 iteration** | AES-128-CBC, IV = 16 spaces |

**Critical caveat:** Chrome 127+ on Windows added **App-Bound Encryption** (`v20` blobs) with the key held by a Chrome-specific elevation service, deliberately designed so other processes cannot decrypt it. **Do not build the import story on defeating that.** Primary path on every platform: guide the user through `chrome://password-manager/settings` → "Download file" CSV export, import it, then securely delete it. Native extraction is best-effort with a clear message when it can't help.

**Firefox** — `logins.json` (ASN.1 PKCS#7 encrypted fields) + `key4.db` (SQLite; `metaData.password` holds a PBKDF2-HMAC-SHA256 + AES-256-CBC check value; `nssPrivate` holds the wrapped master key; the primary password is the PBKDF2 password, empty string if unset). ~400 lines of ASN.1 + PBKDF2 + AES/3DES and **the highest bug density in the project**. Primary path: `about:logins` → "Export Logins" CSV. Ship the native `key4.db` reader behind `--feature firefox-native`, fuzzed, as a fallback only.

**Safari** — no supported programmatic path (per-app keychain ACLs). CSV export from the Passwords app only.

**Other managers** — KeePass/1Password/Bitwarden/LastPass CSV + JSON. These matter more for adoption than browser extraction does.

**CSV import safety** (a plaintext file of every password is the riskiest artifact this product will ever touch):
- Stream-parse with the `csv` crate into `Zeroizing` buffers; never load into a `String` that gets cloned.
- Offer **secure delete** on completion — overwrite then unlink — and be explicit in the UI that on SSDs/APFS/btrfs with copy-on-write and wear-leveling this is best-effort and full-disk encryption is the only real answer. Warn that the file landed in `~/Downloads` and may be in Spotlight/Windows Search indexes, Time Machine, and cloud sync.
- Never write an import log containing values; never leave the file in a temp dir we created.
- Dedup + conflict resolution **before** committing, so an import is one atomic vault write.
- Post-import report: reused passwords, weak passwords (offline Bloom filter, §8), sites supporting passkeys. Turns a scary step into a value moment.

---

## 7. MCP server

The core insight: **an AI agent almost never needs to see a password — it needs the password to be used.** Design the tool surface so that seeing plaintext is a rare, explicitly approved exception rather than the default primitive.

`keel-mcp` is a separate process (stdio, `rmcp` — the official Rust MCP SDK) with **no keys and no vault file access**. It connects to the agent over the same Noise-authenticated channel as the extension, and every request passes through `keel-core`'s **policy engine** — the single allow/deny/ask chokepoint shared by MCP, extension, and CLI. If the agent isn't running or the vault is locked, everything fails closed with `vault_locked`. Launch config:

```json
{ "mcpServers": { "keel": { "command": "keel-mcp" } } }
```
Client identity: capture the parent process (pid, executable path, code-signing identity, start time) and require a `--client-id` the user registered in the GUI ("Allow Claude Code to connect"). Approval modals show the registered label **and** the verified binary path, so a rogue process masquerading as `claude-code` shows a mismatched path.

### 7.1 Scopes and grants

Deny-by-default; a fresh session has **no** scopes.

| Scope | Grants | Default |
|---|---|---|
| `metadata:read` | search + non-secret fields | ask (grant + TTL) |
| `secret:use` | act with a secret without seeing it | ask (grant + TTL) |
| `secret:reveal` | receive plaintext | **disabled by default (user-confirmed)**; per-request approval when enabled |
| `entry:write` | create/update (values generated agent-side) | ask (grant + TTL) |
| `totp:read` | 6-digit codes | ask (grant + TTL) |
| `audit:read` | audit tail, no secrets | ask |

```rust
struct Grant {
  id: Uuid, client_id: String, scopes: BTreeSet<Scope>,
  filter: EntryFilter,        // tag glob / folder / explicit ids. NEVER "*" without a separate scary confirm
  expires_at: Instant,        // default 15 min, max 8 h
  max_reveals: u32,           // default 3
  max_uses: u32,              // default 25
  created_by_user_at: SystemTime,
  reason_shown: String,       // exactly what the user approved
}
```
Grants live in memory and die on lock, restart, or revoke. Only an explicit "remember for this project" tick persists one into the manifest with an absolute expiry, visible in a "Connected agents" pane.

### 7.2 Tool surface

`EntryRef` = an opaque, per-session, random 128-bit handle mapped to an entry id inside the agent. Unguessable, session-scoped, invalidated on lock — so a transcript from three days ago contains nothing usable.

| Tool | Output | Approval |
|---|---|---|
| `vault_status` | `{locked, client_id, scopes[], grant_expires_at, entry_count_bucket}` — bucket like `"51-500"`, never exact | none |
| `search_entries` | `[{ref, title, username_masked, origins[], tags[], updated_at, has_totp}]`; **min 2 chars, limit ≤ 25** | `metadata:read` |
| `get_entry_metadata` | non-secret fields + password age/strength | `metadata:read` |
| **`use_secret`** | `{ok, action_performed, target_described: "chase.com in Chrome"}` — **no secret**. Actions: `CopyToClipboard{clear_after_s}`, `TypeIntoFocusedWindow`, `FillInBrowser{tab_id}` | `secret:use`; `FillInBrowser` additionally requires the tab origin to match the entry |
| `reveal_secret` | `{value, single_use: true, expires_at}` | **per-request modal**, 30 s timer, counts against `max_reveals`. Off by default. |
| `create_entry` | `{ref, strength}` — with `secret: Generate{policy}` the agent **never sees** the value | `entry:write` |
| `update_entry` | `{ref}` — secret fields settable only to `Generate` or `Provided` | `entry:write` |
| `rotate_secret` | `{ref, changed_at}` — old value kept in history | `entry:write` + confirm |
| `generate_password` | `{value}`, or `{ref}` if `store_as` is set (prefer the ref form) | none — fresh randomness, not vault data |
| `totp_code` | `{code, valid_for_s}` | `totp:read` (auto-allow under grant is defensible: codes expire in ≤30 s and are useless without the password) |
| `trash_entry` | `{ok, restorable_until}` — **soft delete only** | `entry:write` + confirm |
| `request_grant` / `list_grants` / `revoke_grant` | grant lifecycle | modal / none / none (revoking is always allowed) |
| `audit_tail` | events, no secret values, `n ≤ 100` | `audit:read` |

**Deliberately NOT exposed, and documented as such:** `export_vault`, any unbounded enumeration (`list_all_entries`), `unlock_vault(password)`, `change_master_password`, `set_policy`/`grant_self`, `hard_delete`, anything generic (`read_file`, `exec`), `get_vault_path`, `disable_autolock`, `pair_client`, `import_from_browser`. Those happen in the GUI or CLI with a human present.

Anti-enumeration: ≥2 chars, ≤25 results, and a cap on **distinct entries revealed to a client per hour** (default 50), so walking the vault with `a`, `b`, `c`… trips the cap and the circuit breaker.

### 7.3 Prompt-injection defenses

1. **Agent-authored text is untrusted data.** The `reason` string renders as plain text, truncated to 200 chars, control characters and ANSI stripped, **no markdown or HTML**, in a visually distinct box labeled "Text supplied by the agent — it may be repeating instructions from a web page or file." No agent string ever becomes app chrome, a button label, or a link.
2. **The modal states ground truth, not the agent's claim:** entry title and origin from the vault, verified client identity and binary path, the exact field, and for `use_secret` the **concrete destination** ("will be typed into: Chrome — `https://chase.com/login`"). An injected agent cannot get a secret sent somewhere wrong without the user seeing the wrong place.
3. **Origin binding, not agent choice:** `FillInBrowser` resolves the tab origin through the extension channel and refuses on mismatch under §6.4 rules. The agent never supplies the origin.
4. **Default-deny UI:** no default-focused Allow, no Enter-to-approve, no "always allow" for reveals, and a ~750 ms delay before Allow becomes clickable (defeats approval-fatigue click-through and synthetic-click races).
5. **Circuit breaker:** ≥3 denials or ≥1 policy violation in 5 minutes → revoke all grants for that client, require a fresh unlock, notify the user.
6. **Rate limits:** search 60/min, `use_secret` 10/h, `reveal_secret` 5/h and 1 in flight, writes 20/h.
7. **Hash-chained audit log:** `vault.audit`, records `{seq, ts, client_id, tool, entry_id, decision, reason_hash, prev_hash}` encrypted under `audit_key` with BLAKE3 chaining, so truncation or edits are detectable. **Never logs secret values.** Surfaced in the GUI as "Recent agent activity" with a red badge on denials.
8. **The security story, in one sentence for the docs:** in the default configuration (`metadata:read` + `secret:use` + `totp:read`, reveal off), an agent can log you into things and manage entries, and **cannot exfiltrate a single password even if fully controlled by an attacker.**
9. Launch-time enforcement flags: `keel-mcp --client-id X --read-only --no-reveal --allow-tags 'work/*' --ttl 15m`.

---

## 8. Generator, side channels, search

**Constant-time comparison** (`subtle::ConstantTimeEq`) for pairing tokens, `EntryRef` lookups (constant-time scan or HMAC'd keys so handle-guessing has no timing signal), recovery codes, keyfile commitments, and any tag we compare ourselves. Never `==` on secret bytes. Entry *search* is not constant-time and doesn't need to be — the timing attacker here is a local process with far bigger levers.

**Logging:** `tracing` with a redaction layer. Secret types have no `Debug`/`Display`, so "log a secret" is a type error rather than a review miss. Log files never contain entry titles above `debug`; `--verbose` never lowers that bar. **No crash reporting and no telemetry** — not even opt-in.

**Password generator** (`keel-crypto::generator`):
- Entropy straight from `getrandom` (OS CSPRNG) — no userspace RNG state to leak or fork-duplicate.
- **Rejection sampling** for uniform charset selection (draw `u32`, reject ≥ `floor(2^32/n)·n`). Modulo bias is a real and embarrassing bug class here.
- Defaults: **20 chars** from an 88-char set (~129 bits); toggles for symbols/digits/ambiguous exclusion. "Must contain one of each class" is implemented as **generate → check → regenerate**, never positional substitution (which destroys entropy).
- **Diceware:** bundled EFF long wordlist (7776 words, 12.925 bits/word). Default **6 words** (77.5 bits) for sites, **7 words** (90.5 bits) recommended for the master password.
- Master-password policy at creation: `zxcvbn`, require score 4 and ≥12 chars, offer a one-click 7-word passphrase, and show estimated offline crack time **computed against our actual Argon2 params**, not zxcvbn's generic guess rate. Honest and educational.
- Per-site policy memory (some sites cap length or charset) stored on the entry so regeneration doesn't break logins.

**Breach checking — two tiers:**
1. **Default: offline Bloom filter** of the top ~10M breached passwords (~12–18 MB at 0.1% FPR), used by the strength meter and the import audit. Zero network, zero leakage, works on day one. This should be the shipped default and is a genuine differentiator.
2. **Optional `keel-breach` (off by default):** HIBP Pwned Passwords **k-anonymity range query** — SHA-1 the password, send only the first **5 hex chars**, match suffixes locally. Send `Add-Padding: true` (HIBP pads responses to defeat size correlation). Explicit user action only, never background or bulk-by-default, jittered delays, hard per-run cap, `rustls` + system roots (optionally SPKI-pinned), no cookies, fixed UA, visible network indicator. Checking the master password this way is fine and should be explained: the service sees 5 hex chars of a SHA-1, about 1/1,048,576 of the space.
- A **single global "Allow network access" switch** governs this and update checks, defaulting to *ask on first run* with "no network at all, ever" as a first-class, prominent choice.

**Search over encrypted data:**
- **v1: decrypt the metadata manifest into RAM at unlock and search in memory.** No on-disk index, no leakage beyond already-bucketed ciphertext length, trivially correct, sub-millisecond at 100k entries with an inverted index built at unlock.
- **Explicitly rejected for v1:** a persistent blind/deterministic index. Deterministic HMAC tokens on disk leak equality and frequency across saves — an attacker with two snapshots learns which entries changed and can dictionary-attack tokens for common domains. The `search_key` HKDF slot exists so a properly designed (padded, per-epoch re-randomized) encrypted index can be added later without a format break.
- Secrets and notes are **not** indexed. Full-text note search decrypts records on demand, one at a time, in a locked buffer, wiping as it goes, with a progress UI so the user knows it's happening.
- `tantivy` and friends are overkill and would write plaintext-derived structures to disk — do not use them.

**Misc:** TOTP via `totp-rs`, seeds handled exactly like passwords. Attachments encrypted per-attachment with `attachment_key`, streamed in 1 MiB chunks with per-chunk AAD (index + final flag) so truncation is detected. Keep the last 10 password values in history — rotation without history causes lockouts.

---

## 9. Supply chain and release integrity (zero-budget)

### 9.1 Dependency policy (in CONTRIBUTING.md, enforced in CI)

- **Budget: ≤150 crates** in `keel-core`'s normal-dependency tree. Every addition needs written justification in the PR and a `cargo-vet` audit or trusted import.
- **Banned:** `openssl-sys`/`native-tls` (use `rustls`), any git dependency, any `build.rs` touching the network, RUSTSEC-unmaintained crates, non-approved licenses.
- `cargo-deny check advisories bans licenses sources` blocking; `cargo-audit` on PRs plus a daily scheduled run that files an issue; `cargo-vet` with imports from Google, Mozilla, Bytecode Alliance, and ISRG (**adopt in Phase 6** — running vet from day one stalls a solo maintainer; adopting it before 1.0 with a frozen dependency set is the pragmatic sequence).
- **`cargo-auditable`** for all shipped binaries so users and distros can run `cargo audit bin keel` on the artifact they actually downloaded.
- `Cargo.lock` committed; release builds `--locked --offline` against a `cargo vendor` tree; `rust-toolchain.toml` pins an exact toolchain + components.
- `unsafe` forbidden outside `keel-hardening`; `cargo-geiger` reported in CI for dependency awareness.

### 9.2 Reproducible builds — claim only what's deliverable

Target: **byte-for-byte reproducible unsigned binaries** for Linux (all arches) and Windows; reproducible unsigned Mach-O for macOS with ad-hoc signing as a separately-verifiable, non-reproducible step. Overclaiming reproducibility damages trust more than scoping it does — say all of this plainly in `docs/REPRODUCE.md`.

- Build in a **digest-pinned container** (`ghcr.io/…@sha256:…`) or Nix; consider `repro-env` to pin toolchain + sysroot by hash.
- `SOURCE_DATE_EPOCH` = release commit timestamp; `CARGO_INCREMENTAL=0`; `RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME=/cargo"`; `LC_ALL=C`, `TZ=UTC`, fixed `HOME`. Linux CLI/agent against **musl** (static) — the most reproducible artifacts in the set.
- **Windows:** prefer `x86_64-pc-windows-gnu` for the reproducible reference artifact (MSVC embeds timestamps and nondeterministic PDB signatures; `/Brepro` helps but GNU is simpler). If the Tauri GUI needs MSVC, publish the MSVC artifact as the installer and the GNU CLI as the reproducibility reference.
- **macOS:** cross-compile with `cargo-zigbuild` or an osxcross container for determinism. `codesign` embeds a timestamp, so publish **both** hashes — `keel-macos-arm64.unsigned.sha256` (reproducible, rebuildable by anyone) and the ad-hoc-signed `.dmg` hash — and document the `codesign --remove-signature` comparison procedure.
- **`rebuild.yml`:** a workflow anyone can run on a fork against a tag that rebuilds and diffs against the published `SHA256SUMS`. Invite community rebuilders to publish counter-attestations into an in-repo `attestations/` directory. This is the mechanism that turns "trust me" into "verify me."

### 9.3 Signing — two paths, offline root

1. **Offline release key = the trust root.** Ed25519 (minisign format, `rsign2`) **and** ML-DSA-65. Both private keys live only on maintainer hardware (ideally a YubiKey or air-gapped machine) and **never enter GitHub Actions**. CI publishes artifacts + `SHA256SUMS`; the maintainer signs `SHA256SUMS` locally and uploads `SHA256SUMS.minisig` + `SHA256SUMS.mldsa.sig`. Publish the public keys in **three independent places** (repo README, project site, first release announcement). A GitHub/CI compromise therefore yields at most an *unsigned* release, which `keel verify-release` rejects.
2. **CI provenance = supplementary.** `actions/attest-build-provenance` (SLSA v1, Sigstore-backed, logged in Rekor) + `cosign`. Proves which workflow, commit, and builder produced each artifact, in a public transparency log — so a targeted backdoor cannot reach one user without a public record.

`keel verify-release <dir>` has both public keys compiled in and **requires BOTH offline signatures** (Ed25519 AND ML-DSA), optionally checking SLSA provenance when the network is allowed. Also ship CycloneDX + SPDX SBOMs (`cargo-cyclonedx`) per artifact, signed alongside. Document a key-rotation ceremony in SECURITY.md — new keys announced signed by the old ones.

`docs/VERIFY.md` gives three tiers: checksum only → `minisign -Vm SHA256SUMS -P <key>` + `sha256sum -c` → `gh attestation verify`.

### 9.4 Zero-budget distribution (the user's constraint, handled properly)

No paid certificates. The strategy is to **route users through channels where OS gatekeeping doesn't apply**, and be honest about the ones where it does.

**macOS** (no $99 Developer ID, so no notarization):
- **Ad-hoc sign everything** (`codesign -s - --options runtime`). This is free and **mandatory** — unsigned arm64 binaries will not execute at all on Apple Silicon. Do not skip it.
- **Primary channel: a Homebrew tap** (`brew install --cask keel`, `brew install keel` for the CLI). Homebrew installs are not browser-quarantined, so Gatekeeper's "damaged app" dialog never appears. This is also the path most technical macOS users already prefer.
- **Secondary: `curl | tar` install script for the CLI.** The quarantine attribute is applied by browsers, not by `curl` — so a documented curl-based install is quarantine-free by construction.
- **Tertiary: the `.dmg`,** with an honest install page: right-click → Open, or `xattr -d com.apple.quarantine`. Explain *why* (no paid Apple certificate), and point at the reproducible-build verification as the stronger alternative to a certificate. Do **not** bury this.
- Note the security cost honestly in the threat model: without a Developer ID we cannot get full Hardened Runtime protection against same-UID `task_for_pid`, so `PT_DENY_ATTACH` plus FileVault carry that load.

**Windows** (no cert, so SmartScreen applies to the installer):
- **Primary: Scoop bucket** — Scoop downloads via PowerShell and verifies hashes, so SmartScreen's browser-download reputation check doesn't fire.
- **Secondary: winget manifest** — community-repo listing plus hash verification.
- **Tertiary: portable `.zip`** (extract and run, far less friction than an installer), and the `.msi` with a documented "More info → Run anyway" walkthrough with screenshots.
- Say in release notes that builds are unsigned and why, and point at verification.

**Linux** (no gatekeeping at all — this will be the smoothest platform): `.deb` + `.rpm` via `nfpm`, AppImage, Flatpak, and an AUR PKGBUILD (`keel` from source, `keel-bin`), each with detached minisign signatures. Pursue Debian/Fedora packaging later — distro maintainers become independent reviewers, which is a security asset.

**Everywhere:** `cargo install keel-cli` builds from source with a committed lockfile.

Consider `cargo-dist` for generating the CLI's shell/PowerShell installers and per-target archives; keep GUI packaging in `tauri-action`. If donations later cover it, the $99 Apple fee is the single highest-leverage upgrade — but the reproducible-build + hybrid-offline-signature story is genuinely a *stronger integrity claim* than a code-signing certificate, just a worse first-run UX. Lead with that framing rather than apologizing.

### 9.5 Repo and CI hardening

Branch protection on `main` (PRs only, including admins; linear history; no force-push; all checks green); **required signed commits** for maintainers, DCO sign-off for contributors; `permissions: contents: read` by default with per-job escalation; **no `pull_request_target`** and no secrets exposed to fork workflows; every third-party action **pinned to a full commit SHA** and updated via reviewed Dependabot PRs; the release job in a GitHub **Environment with required reviewers**; tag protection on `v*`; `actions/cache` **never** used in the release build (cache poisoning); CODEOWNERS mapping `keel-crypto/`, `keel-format/`, `keel-core/`, `keel-agent/`, `keel-hardening/` to the maintainer; GitHub secret scanning + push protection on.

---

## 10. Testing

**v1-essential:**
- **`keel-crypto` / `keel-format` unit tests** — every path; run under **Miri** weekly (pure crates make this viable, and it catches UB in any `unsafe` zeroize glue).
- **Known-answer tests** — `crates/keel-format/tests/vectors/*.json` with RFC 8439 (ChaCha20-Poly1305) and RFC 9106 (Argon2) vectors plus our own format vectors. These double as the cross-implementation conformance suite and the "format is frozen" contract.
- **proptest** — arbitrary vault → serialize → parse → equal; **arbitrary single-byte mutation of a valid file → returns an error and never panics.** That second property is also the fuzz oracle.
- **Fuzzing** — `vault_parse`, `ipc_frame`, `csv_import`, `nss_key4`, `noise_frame`, live from the week each parser lands, not after. Apply to **OSS-Fuzz** once the format is frozen for free continuous deep fuzzing.
- **The GUI invariant test** — assert no secret bytes appear in any Tauri command result or IPC payload. Release blocker if it fails.
- **Integration** — spawn the agent on a temp socket (`KEEL_AGENT_SOCKET` override), drive via `keel-client`; CLI via `assert_cmd` for init→unlock→add→get→lock plus locked/denied exit codes, on all three OSes in CI.
- **Store** — crash simulation (kill between temp-write and rename; assert the old vault is intact), concurrent-open locking, rollback-detection scenarios.

**Post-v1, don't block release:** Playwright extension e2e (Chromium `--load-extension` + a mock native host), Tauri WebDriver GUI e2e, `cargo-mutants` on the crypto/format crates, HIBP integration tests.

---

## 11. CLI surface

```
keel init [--vault <path>] [--tier interactive|balanced|paranoid]
keel unlock [--timeout 15m]        keel lock        keel status [--json]
keel add <name> [--username u] [--url u] [--generate | --password-stdin]
keel get <name|id> [--field password|username|otp|notes] [--clip | --show] [--json]
keel list [--folder f] [--json]    keel search <query> [--json]
keel edit <name|id> [--field f --value-stdin]        keel rm <name|id> [--yes]
keel generate [--length 24 | --words 6] [--no-symbols] [--clip]
keel import <file> --format chrome-csv|firefox-csv|bitwarden|1password|keepassx|generic-csv
keel import --browser chrome|edge|firefox
keel export [--format json|csv] [--output -]     # fresh passphrase re-entry + loud warning
keel audit [--json]                # weak/reused/old, offline Bloom filter
keel agent [--foreground]          keel mcp       keel setup-browser
keel verify-release <dir>          keel completions <shell>
```

**Secret handling:**
- **No secret ever in argv.** No `--password <p>` flag exists anywhere (argv is world-readable via `ps` and lands in shell history). Inputs: interactive TTY prompt (`rpassword`), `--password-stdin` / `--value-stdin`, or `KEEL_PASSPHRASE_FILE` pointing at a `0600` file for automation. **No plain env-var passphrase** — env leaks via `/proc/<pid>/environ` and into CI logs.
- **Safe-by-default `get`:** with a TTY and no flags, `keel get x` copies to the clipboard with a 30 s **agent-performed** auto-clear (so `keel` can exit immediately) and prints nothing secret. `--show` is required to print; when stdout is a pipe, printing is allowed for scripting but `--show`/`--field` must still be explicit.
- `--json` on every read command, schema documented in `docs/cli.md`. Exit codes: `0` ok, `1` error, `2` locked, `3` not found, `4` denied.

---

## 12. Phased roadmap

**Ordering rationale:** the on-disk format must be frozen and fuzzed before anything else depends on it. Hardening comes early because it must initialize before any key exists and retrofitting is painful. CLI before GUI forces the agent API to be complete and scriptable. The GUI ships the approval-modal UI in Phase 4 *because* Phases 5 and 6 depend on it. Release engineering lands **before the first public tag** — retrofitting a trust root after users have installed unsigned builds opens a downgrade window.

| Phase | Deliverables | Exit criteria |
|---|---|---|
| **0 — Skeleton** | Trademark/crates.io name check; workspace with all crates stubbed; `rust-toolchain.toml`, `deny.toml`, `.cargo/config.toml`; `ci.yml` + `audit.yml` green on 3 OSes; layering gate + no-network gate + licence gate; LICENSE (AGPL-3.0-or-later), SECURITY.md, CONTRIBUTING.md; branch protection + signed commits | `cargo test --workspace` green on 3 OSes; `main` protected; both CI invariant gates actually failing when violated (test them) |
| **1 — crypto + format** | `keel-crypto` (Argon2id tiers + calibration, HKDF namespace, XChaCha20 wrappers, `SecretBytes`, generator); `keel-format` (header/manifest/record codec, padding, AAD, DoS guards); `keel-hardening` (mlock, core-dump suppression, panic wipe) | KATs pass; proptest round-trip + tamper-any-byte properties hold; **72 h fuzz on `vault_parse` with zero panics**; `docs/vault-format.md` written and the format declared frozen |
| **2 — store + core** | `keel-store` full atomic-write transaction; `keel-core` open/save, rollback/truncation detection, autolock state machine, hash-chained audit log, **policy/grant engine** (built now — the extension needs it too, not just MCP) | Crash-simulation tests pass; rollback-detection scenarios covered; policy engine unit-tested against every scope/grant/limit path |
| **3 — agent + CLI** | `keel-proto`, `keel-agent` (IPC, peer checks, sessions, Noise, autolock, clipboard auto-clear), `keel-client`, full CLI of §11, `keel-reveal` overlay | End-to-end init→unlock→add→get→lock on 3 OSes in CI; `ipc_frame` fuzzer live; **maintainer dogfooding daily as their real password manager** |
| **4 — Desktop GUI** | Tauri v2 app: onboarding/create-vault with tier choice, unlock, list/search/detail, add/edit, generator, settings, **approval-modal UI**, "Connected browsers/agents" panes, tray + lock state | Installable dev builds on 3 OSes; **the no-secrets-in-JS integration test passes**; a11y pass with VoiceOver and NVDA on core flows |
| **5 — Extension + import** | `keel-native-host`; MV3 extension (popup, gesture-gated autofill, SAS pairing); manifest registration from GUI first-run and `keel setup-browser`; `keel-import` (CSV dialects, Chromium mac/Linux, Firefox `key4.db` behind a feature flag, Windows-Chrome CSV steering) | Fill + save work in Chrome and Firefox from sideload; store submissions filed; `csv_import` + `nss_key4` fuzzers live |
| **6 — MCP server** | `keel-mcp` on `rmcp`/stdio, tool surface of §7.2, approval queue wired to GUI modals, rate limits + circuit breaker, audit surfacing | Claude can search and `use_secret` under a grant; `reveal_secret` requires a modal and is off by default; **fails closed with no GUI running**; injection-simulation test suite passes |
| **7 — Release hardening** | `release.yml` with SLSA attestations + offline hybrid minisign/ML-DSA flow; `rebuild.yml` + `docs/REPRODUCE.md` + double-build diff; ad-hoc macOS signing; Homebrew tap, Scoop bucket, winget, AUR, deb/rpm/AppImage/Flatpak; `keel verify-release`; `cargo-vet` adoption; OSS-Fuzz application; finalized threat model; audit-readiness package (format spec, invariants doc, fuzz corpus) | `v1.0.0` tag produces verifiable artifacts for 3 OSes; an independent rebuild reproduces the Linux hashes; extension published to Chrome Web Store ($5 one-time) and Firefox AMO (free, and mandatory — all Firefox extensions must be AMO-signed even when self-distributed) |
| **8 — Optional factors** | FIDO2 `hmac-secret` first (better primitive and UX), then YubiKey HMAC-SHA1, then platform quick-unlock | Each factor requires ≥2 enrolled authenticators or a printed recovery kit before it can be armed; `factor_flags`/TLV slots are already reserved in v1 so no format break |

---

## 13. Open-source hygiene

- **LICENSE: AGPL-3.0-or-later**, whole repo including the extension, with two carve-outs. The stated goals are community trust and preventing closed-source forks — that is copyleft's job description and the norm for this category (KeePassXC, Bitwarden). Pair with **DCO sign-off and no CLA**: contributors keep copyright, which means nobody — including the maintainer — can relicense proprietary later. That irreversibility is itself a trust signal worth advertising.
  - **Revised from GPL-3.0-or-later to AGPL.** Plain GPL does not reach someone who runs the code as a hosted service, and hosted sync is both the obvious monetisation path here and the obvious thing for a competitor to do with the code. The clause is inert until a server exists, but relicensing requires every copyright holder's consent — so it had to happen while there was one. No CLA means no proprietary enterprise tier is possible; the revenue model is hosting and support, sold as a service, with the server itself AGPL.
  - **Two crates are permissive, and the layering rule is what makes that safe.** `keel-proto` is `Apache-2.0` (wire types only — nothing to protect, and everything that speaks to the agent needs it; Apache rather than MIT for the express patent grant). `keel-client` is `MPL-2.0` (third parties embed it; per-file copyleft is the narrowest thing that permits that). Both are crates the dependency rules already prove cannot reach key material, the crypto core, or the vault format. Note this rules out a permissive `keel-format`, which depends on `keel-crypto`. Enforced by `cargo xtask check-licenses`, not by memory.
  - **An app-store additional permission** (`LICENSE-EXCEPTION.md`) under section 7. AGPL and Apple's terms are otherwise incompatible — the VLC removal — so without it no iOS build could ever ship. Also all-holders-only, hence also now rather than later; `CONTRIBUTING.md` records it as an inbound term so it survives new contributors.
  - **Trademark, separately** (`TRADEMARK.md`). The licence deliberately permits proprietary-*service* competitors to fork; what stops a rebranded clone trading on the audit story is the name, which no licence covers. Caveat recorded there: "keel" is a common word and the mark is unregistered.
- **SECURITY.md:** GitHub Private Vulnerability Reporting with an email + PGP/age fallback; acknowledgment within 72 h; 90-day coordinated disclosure by default, faster when actively exploited; **no bounty, stated explicitly** (unstated bounty expectations sour reports); public credit hall-of-fame; an explicit scope statement that same-UID local attackers and root/kernel malware are outside the boundary, linking to the threat model.
- **CONTRIBUTING.md:** dev setup, `cargo xtask` commands, the dependency budget rule, the **no-asymmetric-without-hybrid rule**, DCO, conventional commits, and a note that security-sensitive areas (`keel-crypto`, `keel-format`, `keel-agent` auth paths) carry deliberately slower review latency.
- **Solo-maintainer discipline** — you cannot require a second human reviewer, so substitute machines and friction: the branch/tag/environment protections in §9.5, plus a written pre-release checklist (fuzz clean, KATs pass, GUI invariant test green, reproducibility diff clean, SBOM generated, offline signatures applied).
- Copy this plan into `docs/architecture.md` and `docs/threat-model.md` at Phase 0 so the reasoning ships with the code and reviewers can check the implementation against its stated intent.

---

## 14. Verification (how to know it works)

Per phase, in addition to `cargo test --workspace` on all three OSes:

1. **Format integrity (Phase 1):** run the KAT suite; run `cargo fuzz run vault_parse` for 72 h with zero crashes; flip every byte of a valid vault in a proptest loop and assert every result is a clean error, never a panic or a successful decrypt.
2. **Crash safety (Phase 2):** a test harness that `SIGKILL`s mid-transaction at each step and asserts the original vault still opens and `write_counter` is intact; a rollback test that restores an old file and asserts the warning fires.
3. **End-to-end (Phase 3):** `keel init` → `unlock` → `add` → `get --show` → `lock` → `get` returns exit code 2, driven by `assert_cmd` in CI on macOS, Linux, and Windows. Then use it as your actual password manager for two weeks before Phase 4.
4. **GUI invariant (Phase 4):** the integration test that intercepts every Tauri command result and IPC frame during a scripted session (unlock, view entry, copy, reveal) and asserts no known secret byte sequence appears in any of them. Manually confirm `keel-reveal` renders as a separate native window and that a screenshot of it comes back blank on macOS and Windows.
5. **Autofill safety (Phase 5):** a local test page set that includes a look-alike domain, a cross-origin iframe, an invisible harvest field, a `readonly` password field, and an `http://` login form — assert the extension refuses each one. Verify pairing fails when the SAS code is wrong, and that a second process attempting to pair is rejected.
6. **MCP injection resistance (Phase 6):** a scripted rogue-agent suite that attempts enumeration (`search` for `a`, `b`, `c`…), requests reveals with injected `reason` text containing markdown and ANSI escapes, requests `FillInBrowser` for a mismatched origin, and hammers rate limits — assert the cap trips, the circuit breaker fires, the reason renders inert, the origin mismatch is refused, and no plaintext is ever returned without a modal.
7. **Release integrity (Phase 7):** on a clean machine that never had the source, download the release, run `keel verify-release` and confirm it **fails** when you tamper with one byte of any artifact and when either signature is removed. Independently run `rebuild.yml` on a fork and diff the Linux musl hashes against the published `SHA256SUMS`.
