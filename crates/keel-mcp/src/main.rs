// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The Keel MCP server.
//!
//! Launched by an MCP host over stdio:
//!
//! ```json
//! { "mcpServers": { "keel": { "command": "keel-mcp" } } }
//! ```

// A stdio server reports diagnostics on stderr; stdout is the protocol transport.
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match keel_mcp::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("keel-mcp: {error}");
            ExitCode::FAILURE
        }
    }
}
