// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Error types for the vault format.
//!
//! These errors are shown to users and written to logs, so they carry no plaintext
//! and no key material. They *do* name which structural check failed, because
//! "your vault is truncated" and "your vault was tampered with" call for very
//! different responses from the person reading the message.
//!
//! Note the distinction from [`keel_crypto::Error::Unlock`], which deliberately
//! refuses to say *why* authentication failed. That reticence protects the
//! passphrase; structural errors leak nothing about it.

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A vault file could not be read, written, or trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The file does not start with the Keel magic number.
    #[error("not a Keel vault file")]
    BadMagic,

    /// The format version is newer than this build understands.
    ///
    /// Kept separate from [`Error::Corrupt`] so the message can be actionable:
    /// the user needs a newer Keel, not a backup.
    #[error("vault format version {found} is newer than this version of Keel supports (max {supported})")]
    UnsupportedVersion {
        /// Version found in the file.
        found: u16,
        /// Highest version this build can read.
        supported: u16,
    },

    /// A structural field is inconsistent — a length that overruns the buffer, an
    /// offset pointing outside the file, a count that does not match the data.
    #[error("vault file is corrupt: {0}")]
    Corrupt(&'static str),

    /// The file ended before the structure did.
    #[error("vault file is truncated: expected {expected} more bytes, {available} available")]
    Truncated {
        /// Bytes the structure requires.
        expected: usize,
        /// Bytes actually left.
        available: usize,
    },

    /// A declared size exceeds the limits in [`crate::limits`].
    ///
    /// Reported before any allocation, so a hostile file cannot use a length field
    /// as a memory-exhaustion lever.
    #[error("vault file declares an implausible size: {what} is {found}, limit is {limit}")]
    TooLarge {
        /// Which field.
        what: &'static str,
        /// Declared value.
        found: u64,
        /// Accepted maximum.
        limit: u64,
    },

    /// The whole-file checksum does not match.
    ///
    /// Indicates accidental corruption or truncation. It is **not** proof of
    /// absence of tampering: the footer hash is unkeyed, so an attacker who edits
    /// the file can recompute it. Authentication comes from the AEAD tags.
    #[error("vault file checksum mismatch: the file is damaged or was modified")]
    ChecksumMismatch,

    /// A record's ciphertext does not match the hash the manifest recorded.
    ///
    /// Detects a record being deleted, duplicated, reordered, or spliced in from a
    /// different version of the file — the cases per-record associated data alone
    /// cannot catch.
    #[error("record {index} does not match the manifest: it was replaced, removed, or reordered")]
    RecordMismatch {
        /// Position in the manifest.
        index: usize,
    },

    /// An unknown algorithm identifier.
    #[error("unsupported {kind} identifier {id}")]
    UnknownAlgorithm {
        /// `"KDF"` or `"AEAD"`.
        kind: &'static str,
        /// The unrecognised value.
        id: u8,
    },

    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] keel_crypto::Error),

    /// The body of an encrypted section did not deserialize.
    ///
    /// Reaching this means the AEAD tag verified but the plaintext was still
    /// malformed, which points at a version mismatch or a bug rather than at an
    /// attacker — forging a valid tag is not on the table.
    #[error("decrypted vault contents are malformed: {0}")]
    Malformed(&'static str),

    /// A value handed to the encoder was out of range.
    #[error("cannot encode: {0}")]
    Encode(&'static str),
}

impl Error {
    /// True if this error suggests recovering from a backup would help.
    ///
    /// Drives the "restore from backup?" prompt. A version error is excluded on
    /// purpose: an older backup will not open in a build that is too old either,
    /// and offering the wrong remedy wastes the user's time at a frightening
    /// moment.
    #[must_use]
    pub const fn suggests_backup_recovery(&self) -> bool {
        matches!(
            self,
            Self::Corrupt(_)
                | Self::Truncated { .. }
                | Self::ChecksumMismatch
                | Self::RecordMismatch { .. }
        )
    }
}
