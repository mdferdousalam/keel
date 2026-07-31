// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Keel vault logic: lifecycle, policy, audit, and auto-lock.
//!
//! This crate is the one that holds an unwrapped vault master key, which is why the
//! architecture funnels everything through a single process that links it. Only
//! `keel-agent` depends on this crate, enforced by `cargo xtask check-layering`.
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`vault`] | Create, open, edit, save, lock |
//! | [`policy`] | The single allow/deny/ask chokepoint for every client |
//! | [`audit`] | Hash-chained, tamper-evident activity log |
//! | [`autolock`] | When an unlocked vault must lock itself |

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

pub mod audit;
pub mod autolock;
pub mod error;
pub mod health;
pub mod origin;
pub mod policy;
pub mod vault;

pub use audit::{AuditEvent, AuditLog, AuditRecord, AuditReport, ChainIntegrity, Outcome};
pub use autolock::{AutoLock, Event as LockEvent, LockPolicy, LockReason};
pub use error::{Error, Result};
pub use policy::{
    Client, ClientType, Decision, Destination, EntryFilter, Grant, Operation, PolicyEngine, Scope,
};
pub use vault::{
    calibrate, tier_params, EntryDraft, OpenOptions, OpenReport, UnlockFactors, UnlockedVault,
};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
