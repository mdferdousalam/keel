# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Vault-format changes are always called out explicitly, since they determine
whether an older Bitting can still open your vault.

## [Unreleased]

### Changed — the project is now called Bitting

- **Renamed from Keel to Bitting.** A *bitting* is the pattern of cuts on a key: the code
  that reproduces the thing which opens the lock. The old name had to go because
  `keel-cli` and `keel-core` were already taken on crates.io by an active project also
  called Keel, which made `cargo install keel-cli` impossible, and because two further
  Keels exist in developer tooling. `bitting` was checked before adoption — the whole
  crate namespace is free, no OS package carries the name, and no company or product uses
  it.

  User-visible surface that moved:

  | Was | Is |
  |---|---|
  | `keel` | `bitting` (CLI binary) |
  | `KEEL_VAULT`, `KEEL_PASSPHRASE_FILE`, and 8 other `KEEL_*` | `BITTING_*` |
  | `dev.keel.desktop`, `dev.keel.native_host` | `dev.bitting.desktop`, `dev.bitting.native_host` |
  | `~/…/dev.keel/vault.keel` | `~/…/dev.bitting/vault.bitting` |
  | `keel-*` crates | `bitting-*` crates |

  The bundle identifier and native-messaging host name both changed, so the desktop app
  reinstalls as a new application and `bitting setup-browser` must be re-run to rewrite
  the browser manifests.

- **VAULT FORMAT: existing vaults cannot be opened by this version.** Not a side effect of
  the rename but a consequence of it, stated here because this file promises to call out
  format changes. The project name appears inside the cryptography, not just around it:

  - the four magic numbers — `KEELVLT`/`KEELEND`/`KEELAUD`/`KEELSTA` — are now
    `BITTVLT`/`BITTEND`/`BITTAUD`/`BITTSTA` (still eight bytes each);
  - every KDF and AEAD domain separator changed, `keel/v1/*` to `bitting/v1/*`. These are
    inputs to key derivation and authenticated data, so subkeys derived under the old
    names do not reproduce and old ciphertext does not authenticate.

  No migration is provided. The format was already documented as unfrozen with no signed
  releases, which is the entire reason this was done now rather than after 0.1.0. Export
  anything you care about with the previous build before upgrading.

### Added
- Cargo workspace, pinned toolchain, and CI (`ci.yml`, `audit.yml`).
- `cargo xtask check-layering`, `check-network`, and `check-licenses`: CI gates
  enforcing that no client crate can link the cryptographic core, that no HTTP/TLS
  stack is reachable from the vault core, and that the licence boundary holds — every
  source file states its terms, and no copyleft crate sits beneath the two crates
  published as embeddable. All three are verified to fail when violated.
- `COPYRIGHT`, naming the copyright holder. Nothing in the tree did: the workspace
  manifest said only "Bitting contributors", and `tauri.conf.json` had a licence
  identifier sitting in its `copyright` field. Copyleft that cannot be attributed
  cannot be enforced.
- `LICENSE-EXCEPTION.md`: an AGPL section 7 additional permission for app-store
  distribution, without which no iOS build could exist — AGPL and Apple's terms are
  otherwise incompatible. Source obligations are untouched and made stricter, and the
  permission passes downstream.
- `TRADEMARK.md`: unmodified builds may use the name, modified builds must rebrand.
  The licence deliberately permits competing forks and services, so the name is what
  stops a rebranded build trading on Bitting's audit story.
- SPDX headers on all 83 source files, so no file's terms depend on which directory a
  reader believes it is in.
- `bitting-crypto`: secret types with no `Debug`/`Serialize`/`Clone` escape hatch,
  page-locking hook, Argon2id tiers with calibration and denial-of-service guards,
  keyed-BLAKE3 factor mixing, HKDF-SHA-512 subkey namespace,
  XChaCha20-Poly1305 wrappers, and a generator using rejection sampling over an
  88-character alphabet plus the EFF long wordlist.
- `bitting-proto`: IPC wire types and length-prefixed JSON framing. The protocol has no
  request that dumps every secret, and metadata responses have nowhere to put a
  password.
- `bitting-agent`: the daemon that holds the unlocked vault. Unix domain socket in a 0700
  directory with a peer-UID check, thread per connection, opaque session-scoped entry
  handles, a watchdog that enforces auto-lock on time and retires an idle agent.
- `bitting-client`: connect-or-spawn, with `connect_existing` for callers that must not
  spawn.
- `bitting-cli`: the `bitting` command — init, unlock, lock, status, list, search, add, get,
  rotate, rm, generate, save — with `--json` on every read.
- `bitting verify-release`: checks both the Ed25519 and the ML-DSA-65 signature over
  `SHA256SUMS`, then every file's hash. Requires **both** signatures; refuses rather than
  reporting success when no keys are compiled in.
- `release.yml`: three-OS build with reproducibility flags, a double-build check that fails
  the release if two builds of the same source differ, Sigstore build provenance, an SBOM,
  and publication as a **draft** awaiting offline signatures.
- `rebuild.yml`: anyone can rebuild any tag on a fork and compare against the published
  artifacts. Also runs weekly, so a substitution after publication is noticed.
- `bitting-mcp`: an MCP server for AI agents, implemented directly on newline-delimited
  JSON-RPC rather than via the async SDK, to keep tokio out of the product. `use_secret`
  applies a password without returning it; `reveal_secret` is off by default.
- `bitting grant`, `bitting grants`, `bitting revoke`: a human authorises an automated client
  explicitly. Only a human-driven client may grant; anyone may revoke.
- `bitting-import` and `bitting import`: CSV import with automatic dialect detection for Chrome,
  Firefox, Safari, Bitwarden, 1Password, LastPass, and KeePass. Errors never carry a field
  value, `Debug` redacts even the title, and `--shred` is honest that overwriting a file on
  modern storage is best effort.
- `docs/threat-model.md`, `docs/architecture.md`, `docs/cli.md`, `docs/mcp.md`,
  `docs/VERIFY.md`, and `docs/REPRODUCE.md`.
- `SECURITY.md` with disclosure policy and an explicit out-of-scope list.

- `bitting-hardening`: the workspace's only `unsafe` crate. Core-dump suppression,
  `PR_SET_DUMPABLE`/`PT_DENY_ATTACH`, Windows injection mitigations, and
  reference-counted page locking. The refcounting matters: several 32-byte keys
  share a page, so unlocking on drop without it would unpin pages holding live
  keys. Reports which protections are actually in force rather than assuming.
- `bitting-format`: vault format v1 — authenticated header with a binding hash over
  the KDF parameters (blocking the downgrade attack), per-record AEAD, encrypted
  manifest, padded sections, and a footer corruption check. Layout is header,
  records, manifest, footer; records precede the manifest to break the circular
  dependency between the manifest's length and the offsets it stores.
- `docs/vault-format.md`: normative format specification.
- Fuzz targets for all four decoder layers, with a seed-corpus generator and a
  libFuzzer dictionary. Seeding is essential here — the footer checksum means
  random mutation would otherwise never reach the parser.

- `bitting-store`: atomic write transaction (temp file, fsync, backup rotation,
  rename, directory fsync), advisory locking via `std::fs::File::try_lock`, and
  rollback detection that distinguishes a regression from a sync-conflict fork.
  Crash safety is verified by SIGKILLing a real child process mid-write.
- `bitting-core`: vault lifecycle; the policy engine (scopes, grants, rate limits,
  coverage cap, circuit breaker, agent-text sanitisation); a hash-chained
  tamper-evident audit log; and the auto-lock state machine.

### Changed
- **Relicensed from GPL-3.0-or-later to AGPL-3.0-or-later.** Plain GPL does not reach
  someone who runs the code as a hosted service, which is both the obvious way to earn
  money from a password manager and the obvious thing for a competitor to do with the
  source. Two crates are deliberate exceptions: `bitting-proto` is Apache-2.0 (wire types
  only, and everything that talks to the agent needs it) and `bitting-client` is MPL-2.0
  (third parties embed it, and no strong copyleft permits that). The layering rule is
  what makes those safe — neither may reach `bitting-crypto`, `bitting-format`, `bitting-store`,
  or `bitting-core`. Contributions stay under the DCO with no CLA, so no proprietary tier
  is possible: paid work is hosting, support, and signed builds.
- `bitting-core` no longer depends on `bitting-hardening`. It never used it. The `PageLocker`
  install is process-global, so it belongs to the binary that owns the process —
  `bitting-agent`, at the top of `main` — and bitting-core got the protection either way. An
  unused edge into the crate that holds every `unsafe` block is not free.
- Dropped the `fd-lock` dependency in favour of `std::fs::File::try_lock`, stable
  since Rust 1.89. The lock is tied to the file descriptor, so a crash cannot
  leave a vault permanently locked. MSRV is now 1.89.
- Header authentication split into two hashes. `binding_hash` (wide) authenticates
  the wrapped master key and blocks a KDF downgrade; `identity_hash` (narrow)
  authenticates the manifest and records. Previously records were bound to the KDF
  salt and parameters, so changing the master passphrase invalidated the entire
  vault — defeating the reason the design separates the two keys.
- Vault layout is header, records, manifest, footer. Records precede the manifest
  because the manifest stores record offsets that postcard varint-encodes, so its
  length would otherwise depend on offsets that depend on its length.

### Security
- Project rule recorded in `CONTRIBUTING.md`: no asymmetric primitive may enter
  the confidentiality path without a hybrid classical + post-quantum construction.
- MCP `secret:reveal` is disabled by default. In the shipped configuration an AI
  agent can act with secrets but cannot exfiltrate one even if fully compromised.
- Rate limits are per client type. Applying agent limits to the desktop app capped
  it at ten clipboard copies an hour, protecting nothing while breaking usability.
- Failed unlock attempts back off exponentially but never lock a user out. A
  destructive attempt counter is useless against an attacker holding the file, who
  runs Argon2 offline, and catastrophic for the user who mistyped.
- Size limits are now compile-time (`const`) assertions, so an inconsistent limit
  fails the build rather than waiting for a test run.
- The format parser contains no panic paths: no indexing, no `unwrap`, and every
  length validated against a limit before it sizes an allocation.

[Unreleased]: https://github.com/mdferdousalam/bitting/commits/main
