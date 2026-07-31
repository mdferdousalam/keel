// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The Keel agent daemon.
//!
//! Holds the unlocked vault so that unlocking happens once per session rather than once
//! per command, and so that key material lives in exactly one process.

// A daemon reports startup failures on stderr, where a service manager collects them.
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let vault_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("KEEL_VAULT").ok());

    let paths = match vault_path {
        Some(path) => keel_store::VaultPaths::new(path),
        None => keel_store::VaultPaths::default_location(),
    };
    let paths = match paths {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("keel-agent: {error}");
            return ExitCode::FAILURE;
        }
    };

    match keel_agent::run(paths) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("keel-agent: {error}");
            ExitCode::FAILURE
        }
    }
}
