//! The Keel MCP server: scoped vault access for AI agents.
//!
//! # The security story in one sentence
//!
//! In the shipped configuration an agent can log the user into things and manage entries, and
//! **cannot exfiltrate a single password even if it is entirely controlled by an attacker.**
//!
//! That holds because of three separate things, and it needs all three:
//!
//! 1. **The tool surface has no bulk accessor.** No export, no enumeration, search bounded and
//!    requiring two characters. See [`tools`].
//! 2. **`use_secret` applies a password without returning it**, so the useful operation — log
//!    the user in — never needs plaintext to reach the model.
//! 3. **`reveal_secret` is off by default** and, when enabled, needs per-request human
//!    approval with the real destination shown.
//!
//! # This process is a pipe
//!
//! It holds no keys, opens no vault, and makes no authorization decision. Every request is
//! forwarded to `keel-agent`, which owns the policy engine. A second policy implementation
//! here would be one more thing to keep in sync, and the one that mattered would still be the
//! agent's — so there is deliberately none.
//!
//! A prompt-injected agent talking to this server is therefore in exactly the same position
//! as any other client: subject to scopes, rate limits, a coverage cap, and a circuit breaker,
//! all enforced somewhere it cannot reach.
//!
//! # Configuration
//!
//! ```json
//! { "mcpServers": { "keel": { "command": "keel-mcp" } } }
//! ```

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
// A stdio server reports diagnostics on stderr; stdout is the protocol transport and nothing
// else may be written there.
#![allow(clippy::print_stderr)]

pub mod protocol;
pub mod server;
pub mod tools;

pub use server::run;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
