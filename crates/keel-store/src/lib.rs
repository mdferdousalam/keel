//! Vault file storage: atomic writes, locking, backups, and rollback detection.
//!
//! This crate owns every filesystem interaction a vault needs, and nothing else. It
//! does no cryptography — it moves already-encrypted bytes — which keeps the code that
//! must never lose data separate from the code that must never leak it.
//!
//! The guarantee it provides: **at every instant, a complete and valid vault exists on
//! disk.** A crash, a full disk, a second instance, or power loss may cost the most
//! recent save, but never the vault. See [`atomic`] for the sequence that achieves
//! that and why each step is required.
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`paths`] | Vault and companion file locations, cloud-sync detection |
//! | [`atomic`] | The write transaction, locking, backups, permissions |
//! | [`state`] | Rollback detection across saves |

// Test code may panic to keep failures readable.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )
)]

pub mod atomic;
pub mod error;
pub mod paths;
pub mod state;

pub use atomic::{
    check_permissions, read_vault, repair_permissions, write_vault, Fingerprint, PermissionStatus,
    VaultLock, WriteMode,
};
pub use error::{Error, Result};
pub use paths::{detect_cloud_sync, CloudProvider, VaultPaths, BACKUP_COUNT};
pub use state::{LastSeen, RollbackVerdict};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
