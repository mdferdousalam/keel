// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Fuzz record-body unpadding and deserialization.
//!
//! In production this only ever runs on plaintext whose Poly1305 tag has already
//! verified, so an attacker cannot reach it directly. It is fuzzed anyway because
//! the ordering guarantee is a property of the calling code, and a decoder that
//! panics on malformed input is one refactor away from being reachable.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = keel_format::RecordBody::decode_padded(data) {
        // Anything that decodes must survive a re-encode, or a load-then-save cycle
        // would silently corrupt a user's entry.
        let _ = body.encode_padded();
    }
});
