//! Keel IPC wire types. Serde only; no logic, no crypto.
//!
//! Implemented in a later phase; see PLAN.md.

/// Crate version, surfaced so binaries can report a consistent version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
