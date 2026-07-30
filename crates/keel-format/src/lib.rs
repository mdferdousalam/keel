//! Keel's on-disk vault format.
//!
//! This crate is pure: it parses and produces bytes and does no I/O. It is also the
//! only code in the project that reads **fully attacker-controlled input** — anyone
//! can mail you a vault file or drop one into a synced folder — so it is written
//! defensively throughout and is the project's primary fuzz target.
//!
//! The rules it follows, all enforced by [`codec::Reader`] and [`limits`]:
//!
//! * Every length is validated against a limit **before** it is used to size an
//!   allocation.
//! * No indexing, no `unwrap`, no panics. A panic on malformed input is a
//!   denial-of-service bug, and `SECURITY.md` treats it as one.
//! * Unknown flags, factors, and algorithm identifiers are rejected rather than
//!   ignored, so a forward-compatibility mistake is loud instead of silent.
//!
//! See `docs/vault-format.md` for the byte layout and the reasoning behind it.

// Test code legitimately uses `unwrap` and indexing to keep failures readable. The
// lints exist to protect the parser, which must never panic on hostile input.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::integer_division,
        clippy::cast_possible_truncation
    )
)]

pub mod codec;
pub mod error;
pub mod header;
pub mod limits;
pub mod manifest;
pub mod padding;
pub mod record;
pub mod vault;

pub use error::{Error, Result};
pub use header::{
    FactorSet, Fido2Factor, Header, HeaderFlags, WrappedKey, YubikeyFactor, FOOTER_MAGIC,
    FORMAT_VERSION, MAGIC, UUID_LEN,
};
pub use manifest::{
    ClientKind, EntryMeta, Folder, GeneratorDefaults, Id, Manifest, PairedClient, PersistedGrant,
    Scope, TrashedEntry, VaultSettings, MANIFEST_SCHEMA,
};
pub use record::{AttachmentRef, CustomField, PasswordHistoryItem, RecordBody, RECORD_SCHEMA};
pub use vault::{
    encode, open_record, parse, seal_record, ParsedVault, RecordBlob, VaultImage, FOOTER_LEN,
};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
