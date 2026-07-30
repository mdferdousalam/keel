//! The Keel desktop application.
//!
//! Deliberately thin: everything is in the library so it can be tested without starting a
//! webview. See `keel_desktop` for why the webview never receives a secret.

// A GUI has no console on Windows, and attaching one would flash a terminal on launch.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// The one thing this binary prints is a startup failure, on stderr, where a service manager
// or a terminal launch will pick it up. Nothing here can carry vault data: the shell never
// holds a secret, so a failure to start is about displays and webviews. Scoped to this file
// rather than the crate, so the command layer still cannot print.
#![allow(clippy::print_stderr)]

fn main() -> std::process::ExitCode {
    match keel_desktop::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Nothing here can carry vault data: the shell never holds a secret, so a
            // startup failure is about displays and webviews.
            eprintln!("keel-desktop: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
