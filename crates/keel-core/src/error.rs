//! Error types for vault operations.

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A vault operation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Unlock failed.
    ///
    /// Wrong passphrase, wrong keyfile, wrong hardware factor, or a tampered
    /// header — deliberately indistinguishable. Telling the user *which* factor was
    /// wrong tells an attacker which one to work on, and tells a shoulder-surfer
    /// that the passphrase was right but the key was absent.
    #[error("could not unlock the vault: check your passphrase and any keyfile or security key")]
    Unlock,

    /// The vault must be unlocked for this operation.
    #[error("the vault is locked")]
    Locked,

    /// The named entry does not exist.
    #[error("no entry with that identifier")]
    NoSuchEntry,

    /// The operation was refused by policy.
    ///
    /// Carries a reason because, unlike an unlock failure, there is no oracle
    /// concern here: the client already knows what it asked for.
    #[error("refused: {0}")]
    Denied(String),

    /// A vault must have parameters the host can actually satisfy.
    #[error("{0}")]
    HostCapability(String),

    /// Cryptographic failure.
    #[error(transparent)]
    Crypto(#[from] keel_crypto::Error),

    /// Vault format failure.
    #[error(transparent)]
    Format(#[from] keel_format::Error),

    /// Storage failure.
    #[error(transparent)]
    Store(#[from] keel_store::Error),

    /// The system clock is before the Unix epoch.
    ///
    /// Its own variant because timestamps feed the audit chain and grant expiry, so
    /// silently substituting zero would make an expired grant look permanent.
    #[error("the system clock is set before 1970; cannot record a timestamp")]
    ClockBeforeEpoch,
}

impl Error {
    /// True if this indicates the vault file itself may be damaged or tampered with.
    #[must_use]
    pub fn suggests_vault_damage(&self) -> bool {
        match self {
            Self::Format(e) => e.suggests_backup_recovery(),
            _ => false,
        }
    }
}
