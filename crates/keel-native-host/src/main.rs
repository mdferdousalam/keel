//! The Keel browser native-messaging bridge.
//!
//! Thin by design; see [`keel_native_host`] for what this process is and, more importantly,
//! what it deliberately cannot do.

// The one thing this binary prints is a pipe failure, to the browser's log.
#![allow(clippy::print_stderr)]

fn main() -> std::process::ExitCode {
    match keel_native_host::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // stderr goes to the browser's log, not to a user. Nothing here can carry vault
            // data: this process never holds a secret except one credential in flight, and
            // that is never formatted into a message.
            eprintln!("keel-native-host: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
