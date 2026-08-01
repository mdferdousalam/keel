// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The Bitting agent: the only process that holds unlocked vault keys.
//!
//! Every other component — the CLI, the desktop app, the browser bridge, the MCP
//! server — is a client of this process. That concentration is the point: it means the
//! answer to "where can key material be?" is one binary, and `cargo xtask check-layering`
//! enforces that no other crate can link the cryptographic core.
//!
//! # Why threads and not an async runtime
//!
//! This process serialises a handful of local clients. A thread per connection is entirely
//! adequate, and dropping an async runtime removes a very large amount of code from the
//! address space that contains the master key. In the one process where the dependency
//! budget really matters, that trade is easy.
//!
//! # Structure
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`transport`] | The socket, framing, and peer-credential checks |
//! | [`state`] | Shared state: vault, policy, audit, handle table |
//! | [`server`] | Accept loop and request dispatch |
//! | [`clipboard`] | Copying a secret out, and taking it back off again |

// A daemon reports operational events on stderr, where the service manager collects them.
// Nothing here prints vault data: the audit log is the record of what happened, and it is
// encrypted.
#![allow(clippy::print_stderr)]
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

pub mod clipboard;
pub mod server;
pub mod state;
pub mod transport;

pub use server::{run, Agent};
pub use state::AgentState;
pub use transport::{socket_path, SOCKET_ENV};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
