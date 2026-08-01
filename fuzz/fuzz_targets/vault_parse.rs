// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Fuzz the whole-file parser.
//!
//! The highest-value target in the project: `parse` is what runs when a user opens a
//! file, and a vault file can arrive from anywhere — a backup, a synced folder, an
//! email attachment. The property asserted is simply that it never panics, hangs, or
//! allocates without bound. Any crash here is a denial-of-service vulnerability.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Errors are the expected outcome for almost all inputs. What must never happen
    // is a panic, so the result is deliberately discarded.
    if let Ok(parsed) = bitting_format::vault::parse(data) {
        // If the structure verified, exercise the paths a caller would take next.
        // A wrong key is fine — authentication failure is a normal error, and this
        // reaches the AEAD and the length checks behind it.
        let key = bitting_crypto::SecretBytes::<32>::zeroed();
        let _ = parsed.open_manifest(&key);
        let _ = parsed.all_blobs();
    }
});
