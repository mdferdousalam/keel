// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Optional offline/HIBP breach checking. The only Keel crate permitted a network dependency.
//!
//! Implemented in a later phase; see PLAN.md.

/// Crate version, surfaced so binaries can report a consistent version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
