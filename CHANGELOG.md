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
- `docs/threat-model.md` and `docs/architecture.md`.
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

### Security
- Project rule recorded in `CONTRIBUTING.md`: no asymmetric primitive may enter
  the confidentiality path without a hybrid classical + post-quantum construction.
- Size limits are now compile-time (`const`) assertions, so an inconsistent limit
  fails the build rather than waiting for a test run.
- The format parser contains no panic paths: no indexing, no `unwrap`, and every
  length validated against a limit before it sizes an allocation.

[Unreleased]: https://github.com/keel-vault/keel/commits/main
