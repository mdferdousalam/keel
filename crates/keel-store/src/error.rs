//! Error types for vault storage.

use std::path::PathBuf;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A storage operation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying I/O failure, with the path that caused it.
    ///
    /// The path is always included: "permission denied" without saying *which*
    /// file is one of the least useful error messages a program can produce.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// What was being attempted.
        operation: &'static str,
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The vault path is unusable.
    #[error("invalid vault path: {0}")]
    InvalidPath(String),

    /// Another process holds the vault lock.
    ///
    /// Distinct from a generic I/O error so the UI can say "Keel is already open"
    /// rather than something alarming.
    #[error("another Keel instance has this vault open")]
    AlreadyLocked,

    /// The file changed underneath us between load and save.
    ///
    /// Raised instead of overwriting. A blind overwrite here would silently discard
    /// whatever the other writer saved — which, for a password manager, means losing
    /// a password the user believes they stored.
    #[error("the vault changed on disk since it was loaded; reload before saving")]
    ConcurrentModification,

    /// The vault file does not exist.
    #[error("no vault found at {0}")]
    NotFound(PathBuf),

    /// A vault already exists where one was about to be created.
    #[error("a vault already exists at {0}")]
    AlreadyExists(PathBuf),

    /// The rollback-detection state file is unreadable.
    ///
    /// Not fatal: the caller treats it as "no previous state" and warns, because a
    /// corrupt sidecar must not stop someone opening their vault.
    #[error("rollback state file is unreadable: {0}")]
    BadState(&'static str),

    /// A vault format error.
    #[error(transparent)]
    Format(#[from] keel_format::Error),
}

impl Error {
    /// Build an I/O error with context.
    pub fn io(operation: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    /// True if retrying later might succeed.
    ///
    /// Drives whether the UI offers a "try again" button. A lock held by another
    /// instance clears when that instance exits; a corrupt file does not.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(self, Self::AlreadyLocked | Self::ConcurrentModification)
    }
}
