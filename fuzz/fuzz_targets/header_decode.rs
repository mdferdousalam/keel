// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Fuzz the header decoder in isolation.
//!
//! Separate from `vault_parse` because the whole-file parser checks the footer hash
//! first, which almost no random input satisfies. Fuzzing the header directly gets
//! past that gate and into the variable-length factor section, the cost-parameter
//! validation, and the wrapped-key array — the parts with real structure.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, len)) = bitting_format::Header::decode(data) {
        // A successful decode must be self-consistent: it cannot claim to have
        // consumed more than it was given, and re-encoding must reproduce the same
        // bytes. A mismatch would mean two different files could decode to the same
        // header, which breaks the binding hash's guarantees.
        assert!(len <= data.len());
        if let Ok(reencoded) = header.encode() {
            assert_eq!(
                reencoded.as_slice(),
                &data[..len],
                "header did not re-encode to its own bytes"
            );
        }
        // The associated-data builders run on decoded headers, so fuzz them too.
        let _ = header.binding_hash();
        let _ = header.manifest_aad();
        let _ = header.record_aad(&[0; 16], header.vmk_epoch_current);
        let _ = header.wrap_aad(header.vmk_epoch_current);
    }
});
