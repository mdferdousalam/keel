// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The Bitting reveal overlay.
//!
//! Started by the agent with the secret on stdin; see [`bitting_reveal`] for why it is a separate
//! process, why the secret arrives that way, and what "non-capturable" does and does not mean.

// The one thing this prints is a startup failure, to the parent's stderr.
#![allow(clippy::print_stderr)]

fn main() -> std::process::ExitCode {
    match bitting_reveal::window::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Cannot carry the secret: every error path here is about stdin framing or the
            // window server, and the secret is never formatted into a message.
            eprintln!("bitting-reveal: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
