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

### Security
- Project rule recorded in `CONTRIBUTING.md`: no asymmetric primitive may enter
  the confidentiality path without a hybrid classical + post-quantum construction.

[Unreleased]: https://github.com/keel-vault/keel/commits/main
