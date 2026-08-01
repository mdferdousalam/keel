// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Error types.
//!
//! Every variant here is deliberately coarse. Error messages are user- and
//! log-visible, so they must never carry plaintext, key material, or anything
//! that distinguishes *why* an unlock failed — see [`Error::Unlock`].

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A cryptographic operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Unlock failed.
    ///
    /// This single variant covers a wrong password, a wrong or missing keyfile,
    /// a wrong hardware factor, and a tampered header. Distinguishing between
    /// them would tell an attacker which factor to attack, and would tell a
    /// shoulder-surfer that the password was right but the YubiKey was absent.
    /// Callers must not try to be more helpful than this.
    #[error("unlock failed")]
    Unlock,

    /// An AEAD open operation failed authentication.
    ///
    /// The ciphertext, the associated data, or the key is wrong. As with
    /// [`Error::Unlock`], we do not say which.
    #[error("authentication failed: data is corrupt or was tampered with")]
    Authentication,

    /// KDF parameters were outside the accepted range.
    ///
    /// Raised both for locally-requested nonsense and for parameters read out
    /// of a vault header. The latter is the important case: a malicious file
    /// asking for 64 GiB of memory must be rejected before we allocate, not
    /// after the OOM killer arrives.
    #[error("KDF parameters out of range: {0}")]
    KdfParams(&'static str),

    /// The KDF itself failed (allocation failure, or a parameter combination
    /// the backend rejected).
    #[error("key derivation failed")]
    KdfFailure,

    /// A buffer handed to us had the wrong length.
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Required length.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },

    /// The OS random number generator failed.
    ///
    /// Not recoverable and not worth retrying: if the kernel cannot give us
    /// entropy, we must not fall back to anything weaker.
    #[error("the operating system random number generator failed")]
    Rng,

    /// A generator policy could not be satisfied (e.g. "must contain a symbol"
    /// with symbols excluded from the alphabet).
    #[error("password policy cannot be satisfied: {0}")]
    Policy(&'static str),
}

impl Error {
    /// True if this error indicates data that failed authentication, as opposed
    /// to a usage or environment problem.
    ///
    /// Callers use this to decide whether to surface "your vault may have been
    /// tampered with" versus a generic failure.
    #[must_use]
    pub fn is_authentication_failure(&self) -> bool {
        matches!(self, Self::Authentication | Self::Unlock)
    }
}
