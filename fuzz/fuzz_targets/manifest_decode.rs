//! Fuzz manifest unpadding, deserialization, and structural validation.
//!
//! Exercises the duplicate-id and overlapping-extent checks, which are the ones that
//! stop a malformed index from making two entries share ciphertext.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = keel_format::Manifest::decode_padded(data) {
        // Validation already ran inside decode; assert it is idempotent so a
        // caller re-validating after edits gets the same answer.
        assert!(manifest.validate().is_ok());
        let _ = manifest.encode_padded();
    }
});
