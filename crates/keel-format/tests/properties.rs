//! Property-based tests for the vault format.
//!
//! Two properties matter here, and between them they define what "the parser is
//! safe" means for this project:
//!
//! 1. **Round-trip fidelity.** Anything the encoder produces, the decoder reads back
//!    identically. A format that loses a field silently loses a password.
//! 2. **No panic on arbitrary input, ever.** Every byte string either decodes or
//!    returns an error. Never a panic, never a hang, never an unbounded allocation.
//!
//! The second property is also the oracle the fuzz targets use, so a failure found
//! by `cargo fuzz` can be reproduced here as an ordinary test case.

// Test code may panic and may cast freely; the lints exist to protect the parser,
// where a panic on hostile input is a denial-of-service bug.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::integer_division
)]

use keel_crypto::kdf::{Argon2Params, MIN_M_COST_KIB};
use keel_crypto::{subkeys, Key256, SecretBytes, AEAD_ID_XCHACHA20POLY1305, KDF_ID_ARGON2ID_V13};
use keel_format::header::{Fido2Factor, WrappedKey, YubikeyFactor, WRAPPED_KEY_CT_LEN};
use keel_format::manifest::{EntryMeta, Manifest};
use keel_format::vault::{self, VaultImage};
use keel_format::{FactorSet, Header, HeaderFlags, RecordBody, FORMAT_VERSION};
use proptest::prelude::*;

const UUID: [u8; 16] = [0x5A; 16];

fn vmk() -> Key256 {
    SecretBytes::<32>::from_slice(&[0x42; 32]).unwrap()
}

/// Cheap KDF parameters. Real vaults use 512 MiB; a property test running hundreds
/// of cases cannot.
fn cheap_params() -> Argon2Params {
    Argon2Params {
        m_cost_kib: MIN_M_COST_KIB,
        t_cost: 1,
        p_cost: 1,
    }
}

prop_compose! {
    fn arb_header()(
        flags_compressed in any::<bool>(),
        flags_quick in any::<bool>(),
        uuid in any::<[u8; 16]>(),
        created_at in any::<u64>(),
        salt in any::<[u8; 32]>(),
        measured_ms in any::<u32>(),
        write_counter in any::<u64>(),
        keyfile in proptest::option::of(any::<[u8; 32]>()),
        yubikey_slot in proptest::option::of(1u8..=2),
        cred_id in proptest::option::of(prop::collection::vec(any::<u8>(), 0..96)),
        epoch_count in 1usize..=4,
    ) -> Header {
        let factors = FactorSet {
            keyfile,
            yubikey: yubikey_slot.map(|slot| YubikeyFactor { slot, challenge: [0x33; 64] }),
            fido2: cred_id.map(|credential_id| Fido2Factor {
                rp_id_hash: [0x44; 32],
                salt: [0x55; 32],
                credential_id,
            }),
        };
        let wrapped_keys = (0..epoch_count)
            .map(|i| WrappedKey {
                epoch: i as u32,
                nonce: [i as u8; keel_crypto::NONCE_LEN],
                ciphertext: [i as u8; WRAPPED_KEY_CT_LEN],
            })
            .collect();
        Header {
            format_version: FORMAT_VERSION,
            flags: HeaderFlags::default()
                .with(HeaderFlags::COMPRESSED_RECORDS, flags_compressed)
                .with(HeaderFlags::QUICK_UNLOCK_ENROLLED, flags_quick),
            vault_uuid: uuid,
            created_at,
            kdf_id: KDF_ID_ARGON2ID_V13,
            kdf_params: cheap_params(),
            kdf_salt: salt,
            measured_kdf_ms: measured_ms,
            factors,
            aead_id: AEAD_ID_XCHACHA20POLY1305,
            vmk_epoch_current: (epoch_count - 1) as u32,
            wrapped_keys,
            write_counter,
            records_offset: 0,
            records_len: 0,
            manifest_offset: 0,
            manifest_len: 0,
        }
    }
}

prop_compose! {
    fn arb_record_body()(
        username in ".{0,64}",
        password in ".{0,128}",
        notes in ".{0,256}",
        totp in proptest::option::of("[A-Z2-7]{16,32}"),
    ) -> RecordBody {
        let mut body = RecordBody::new()
            .with_username(username)
            .with_password(password)
            .with_notes(notes);
        if let Some(t) = totp {
            body = body.with_totp_secret(t);
        }
        body
    }
}

fn entry_meta(id: u8, title: String, username: String) -> EntryMeta {
    EntryMeta {
        record_id: [id; 16],
        key_epoch: 0,
        blob_hash: [0; 32],
        blob_offset: 0,
        blob_len: 0,
        title,
        username,
        origins: vec!["https://example.com".to_owned()],
        tags: vec![],
        folder_id: None,
        created_at: 0,
        updated_at: 0,
        password_changed_at: 0,
        has_totp: false,
        favorite: false,
        notes_preview_len: 0,
    }
}

proptest! {
    /// Property 1: headers round-trip exactly.
    #[test]
    fn header_round_trips(header in arb_header()) {
        let bytes = header.encode().unwrap();
        let (decoded, len) = Header::decode(&bytes).unwrap();
        prop_assert_eq!(decoded, header);
        prop_assert_eq!(len, bytes.len());
    }

    /// The binding hash must be stable across an encode/decode cycle, or associated
    /// data computed before a save would not match the data computed after a load.
    #[test]
    fn binding_hash_survives_a_round_trip(header in arb_header()) {
        let bytes = header.encode().unwrap();
        let (decoded, _) = Header::decode(&bytes).unwrap();
        prop_assert_eq!(decoded.binding_hash().unwrap(), header.binding_hash().unwrap());
    }

    /// Property 2, on the header: arbitrary bytes never panic.
    #[test]
    fn header_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = Header::decode(&bytes);
    }

    /// The same, but starting from a valid magic number so the parser gets past its
    /// first check and into the interesting code.
    #[test]
    fn header_decode_never_panics_with_valid_magic(
        tail in prop::collection::vec(any::<u8>(), 0..512)
    ) {
        let mut bytes = keel_format::MAGIC.to_vec();
        bytes.extend_from_slice(&tail);
        let _ = Header::decode(&bytes);
    }

    /// Mutating any single byte of a valid header must be detected or produce a
    /// header whose binding hash differs. Silent acceptance of a modified header is
    /// the downgrade attack.
    #[test]
    fn mutated_header_is_rejected_or_visibly_different(
        header in arb_header(),
        index in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let bytes = header.encode().unwrap();
        let i = index.index(bytes.len());
        let mut bad = bytes.clone();
        bad[i] ^= xor;
        prop_assume!(bad != bytes);

        match Header::decode(&bad) {
            Err(_) => {} // rejected outright
            Ok((decoded, _)) => {
                // Accepted, so the change must be visible in the binding hash or in
                // a field that is authenticated elsewhere (counter or offsets).
                let same_binding = decoded.binding_hash().unwrap() == header.binding_hash().unwrap();
                let same_counter = decoded.write_counter == header.write_counter;
                let same_extents = decoded.records_offset == header.records_offset
                    && decoded.records_len == header.records_len
                    && decoded.manifest_offset == header.manifest_offset
                    && decoded.manifest_len == header.manifest_len;
                let same_wrapped = decoded.wrapped_keys == header.wrapped_keys;
                prop_assert!(
                    !(same_binding && same_counter && same_extents && same_wrapped),
                    "byte {} changed but nothing authenticated noticed", i
                );
            }
        }
    }

    /// Record bodies round-trip through padding and serialization.
    #[test]
    fn record_body_round_trips(body in arb_record_body()) {
        let encoded = body.encode_padded().unwrap();
        prop_assert_eq!(encoded.len() % 256, 0);
        let decoded = RecordBody::decode_padded(&encoded).unwrap();
        prop_assert_eq!(decoded, body);
    }

    #[test]
    fn record_body_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = RecordBody::decode_padded(&bytes);
    }

    #[test]
    fn manifest_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = Manifest::decode_padded(&bytes);
    }

    /// Property 2, on the whole file: arbitrary bytes never panic.
    #[test]
    fn vault_parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = vault::parse(&bytes);
    }

    /// A whole vault round-trips, and every record decrypts to what went in.
    #[test]
    fn vault_round_trips(
        header in arb_header(),
        bodies in prop::collection::vec(arb_record_body(), 0..6),
    ) {
        let v = vmk();
        let index_key = subkeys::index_key(&v, &header.vault_uuid).unwrap();

        let mut manifest = Manifest::new();
        let mut records = Vec::new();
        let mut expected = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            let id = [i as u8 + 1; 16];
            let rk = subkeys::record_key(&v, &header.vault_uuid, &id, 0).unwrap();
            records.push(vault::seal_record(&header, &rk, &id, 0, body).unwrap());
            manifest.entries.push(entry_meta(
                i as u8 + 1,
                format!("entry {i}"),
                body.username.clone(),
            ));
            expected.push(body.password.clone());
        }

        let mut image = VaultImage { header: header.clone(), manifest, records };
        let bytes = vault::encode(&mut image, &index_key).unwrap();

        let parsed = vault::parse(&bytes).unwrap();
        let loaded = parsed.open_manifest(&index_key).unwrap();
        prop_assert_eq!(loaded.entries.len(), bodies.len());

        for (entry, want) in loaded.entries.iter().zip(&expected) {
            let rk = subkeys::record_key(&v, &header.vault_uuid, &entry.record_id, entry.key_epoch)
                .unwrap();
            let body = parsed.open_record(entry, &rk).unwrap();
            prop_assert_eq!(&body.password, want);
        }
    }

    /// Truncating a valid vault at any point must be detected, never accepted and
    /// never a panic. This is the "partial write / interrupted save" case.
    #[test]
    fn truncated_vault_is_always_rejected(
        bodies in prop::collection::vec(arb_record_body(), 0..4),
        index in any::<prop::sample::Index>(),
    ) {
        let header = Header {
            format_version: FORMAT_VERSION,
            flags: HeaderFlags::default(),
            vault_uuid: UUID,
            created_at: 0,
            kdf_id: KDF_ID_ARGON2ID_V13,
            kdf_params: cheap_params(),
            kdf_salt: [1; 32],
            measured_kdf_ms: 0,
            factors: FactorSet::default(),
            aead_id: AEAD_ID_XCHACHA20POLY1305,
            vmk_epoch_current: 0,
            wrapped_keys: vec![WrappedKey {
                epoch: 0,
                nonce: [0; keel_crypto::NONCE_LEN],
                ciphertext: [0; WRAPPED_KEY_CT_LEN],
            }],
            write_counter: 1,
            records_offset: 0,
            records_len: 0,
            manifest_offset: 0,
            manifest_len: 0,
        };
        let v = vmk();
        let index_key = subkeys::index_key(&v, &UUID).unwrap();

        let mut manifest = Manifest::new();
        let mut records = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            let id = [i as u8 + 1; 16];
            let rk = subkeys::record_key(&v, &UUID, &id, 0).unwrap();
            records.push(vault::seal_record(&header, &rk, &id, 0, body).unwrap());
            manifest.entries.push(entry_meta(i as u8 + 1, format!("e{i}"), String::new()));
        }
        let mut image = VaultImage { header, manifest, records };
        let bytes = vault::encode(&mut image, &index_key).unwrap();

        let cut = index.index(bytes.len());
        prop_assert!(
            vault::parse(&bytes[..cut]).is_err(),
            "truncation to {} of {} bytes was accepted", cut, bytes.len()
        );
    }
}
