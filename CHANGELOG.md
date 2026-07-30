# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Vault-format changes are always called out explicitly, since they determine
whether an older Keel can still open your vault.

## [Unreleased]

### Added
- Cargo workspace, pinned toolchain, and CI (`ci.yml`, `audit.yml`).
- `cargo xtask check-layering` and `check-network`: CI gates enforcing that no
  client crate can link the cryptographic core, and that no HTTP/TLS stack is
  reachable from the vault core. Both are verified to fail when violated.
- `keel-crypto`: secret types with no `Debug`/`Serialize`/`Clone` escape hatch,
  page-locking hook, Argon2id tiers with calibration and denial-of-service guards,
  keyed-BLAKE3 factor mixing, HKDF-SHA-512 subkey namespace,
  XChaCha20-Poly1305 wrappers, and a generator using rejection sampling over an
  88-character alphabet plus the EFF long wordlist.
- `keel-proto`: IPC wire types and length-prefixed JSON framing. The protocol has no
  request that dumps every secret, and metadata responses have nowhere to put a
  password.
- `keel-agent`: the daemon that holds the unlocked vault. Unix domain socket in a 0700
  directory with a peer-UID check, thread per connection, opaque session-scoped entry
  handles, a watchdog that enforces auto-lock on time and retires an idle agent.
- `keel-client`: connect-or-spawn, with `connect_existing` for callers that must not
  spawn.
- `keel-cli`: the `keel` command — init, unlock, lock, status, list, search, add, get,
  rotate, rm, generate, save — with `--json` on every read.
- `keel verify-release`: checks both the Ed25519 and the ML-DSA-65 signature over
  `SHA256SUMS`, then every file's hash. Requires **both** signatures; refuses rather than
  reporting success when no keys are compiled in.
- `release.yml`: three-OS build with reproducibility flags, a double-build check that fails
  the release if two builds of the same source differ, Sigstore build provenance, an SBOM,
  and publication as a **draft** awaiting offline signatures.
- `rebuild.yml`: anyone can rebuild any tag on a fork and compare against the published
  artifacts. Also runs weekly, so a substitution after publication is noticed.
- `docs/threat-model.md`, `docs/architecture.md`, `docs/cli.md`, `docs/VERIFY.md`, and
  `docs/REPRODUCE.md`.
- `SECURITY.md` with disclosure policy and an explicit out-of-scope list.

- `keel-hardening`: the workspace's only `unsafe` crate. Core-dump suppression,
  `PR_SET_DUMPABLE`/`PT_DENY_ATTACH`, Windows injection mitigations, and
  reference-counted page locking. The refcounting matters: several 32-byte keys
  share a page, so unlocking on drop without it would unpin pages holding live
  keys. Reports which protections are actually in force rather than assuming.
- `keel-format`: vault format v1 — authenticated header with a binding hash over
  the KDF parameters (blocking the downgrade attack), per-record AEAD, encrypted
  manifest, padded sections, and a footer corruption check. Layout is header,
  records, manifest, footer; records precede the manifest to break the circular
  dependency between the manifest's length and the offsets it stores.
- `docs/vault-format.md`: normative format specification.
- Fuzz targets for all four decoder layers, with a seed-corpus generator and a
  libFuzzer dictionary. Seeding is essential here — the footer checksum means
  random mutation would otherwise never reach the parser.

- `keel-store`: atomic write transaction (temp file, fsync, backup rotation,
  rename, directory fsync), advisory locking via `std::fs::File::try_lock`, and
  rollback detection that distinguishes a regression from a sync-conflict fork.
  Crash safety is verified by SIGKILLing a real child process mid-write.
- `keel-core`: vault lifecycle; the policy engine (scopes, grants, rate limits,
  coverage cap, circuit breaker, agent-text sanitisation); a hash-chained
  tamper-evident audit log; and the auto-lock state machine.

### Changed
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

[Unreleased]: https://github.com/keel-vault/keel/commits/main
