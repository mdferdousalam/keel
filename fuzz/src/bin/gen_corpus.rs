//! Generate seed corpora for the fuzz targets.
//!
//! Run with `cargo run --bin gen_corpus` from the `fuzz` directory.
//!
//! Seeding matters more here than for most fuzzers. A vault file has a magic number,
//! an authenticated header, and a whole-file BLAKE3 checksum in the footer. Random
//! mutation will essentially never produce a file that gets past the checksum, so an
//! unseeded fuzzer spends its entire budget bouncing off the first few checks. Giving
//! it real files to mutate puts it inside the header parser, the factor TLV section,
//! and the manifest decoder — where the bugs would actually be.

use std::fs;
use std::path::Path;

use keel_crypto::kdf::{Argon2Params, MIN_M_COST_KIB};
use keel_crypto::{subkeys, SecretBytes, AEAD_ID_XCHACHA20POLY1305, KDF_ID_ARGON2ID_V13, NONCE_LEN};
use keel_format::header::{Fido2Factor, WrappedKey, YubikeyFactor, WRAPPED_KEY_CT_LEN};
use keel_format::manifest::{EntryMeta, Manifest};
use keel_format::vault::{self, VaultImage};
use keel_format::{FactorSet, Header, HeaderFlags, RecordBody, FORMAT_VERSION};

fn header(uuid: [u8; 16], factors: FactorSet, epochs: u32) -> Header {
    Header {
        format_version: FORMAT_VERSION,
        flags: HeaderFlags::default(),
        vault_uuid: uuid,
        created_at: 1_700_000_000,
        kdf_id: KDF_ID_ARGON2ID_V13,
        // Cheap on purpose: the corpus generator must not spend a second per file,
        // and the parser does not care what the cost parameters say.
        kdf_params: Argon2Params {
            m_cost_kib: MIN_M_COST_KIB,
            t_cost: 1,
            p_cost: 1,
        },
        kdf_salt: [0x11; keel_crypto::SALT_LEN],
        measured_kdf_ms: 1200,
        factors,
        aead_id: AEAD_ID_XCHACHA20POLY1305,
        vmk_epoch_current: epochs - 1,
        wrapped_keys: (0..epochs)
            .map(|i| WrappedKey {
                epoch: i,
                nonce: [i as u8; NONCE_LEN],
                ciphertext: [i as u8; WRAPPED_KEY_CT_LEN],
            })
            .collect(),
        write_counter: 1,
        records_offset: 0,
        records_len: 0,
        manifest_offset: 0,
        manifest_len: 0,
    }
}

fn entry(id: u8) -> EntryMeta {
    EntryMeta {
        record_id: [id; 16],
        key_epoch: 0,
        blob_hash: [0; 32],
        blob_offset: 0,
        blob_len: 0,
        title: format!("Seed entry {id}"),
        username: "ada@example.com".to_owned(),
        origins: vec!["https://example.com".to_owned()],
        tags: vec!["seed".to_owned()],
        folder_id: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        password_changed_at: 1_700_000_000,
        has_totp: id % 2 == 0,
        favorite: false,
        notes_preview_len: 0,
    }
}

/// Build a complete, valid vault file with `count` entries.
fn build_vault(uuid: [u8; 16], factors: FactorSet, epochs: u32, count: u8) -> Vec<u8> {
    let h = header(uuid, factors, epochs);
    let vmk = SecretBytes::<32>::from_slice(&[0x42; 32]).expect("32-byte key");
    let index_key = subkeys::index_key(&vmk, &uuid).expect("index key");

    let mut manifest = Manifest::new();
    let mut records = Vec::new();
    for i in 0..count {
        let id = [i + 1; 16];
        let body = RecordBody::new()
            .with_username(format!("user-{i}"))
            .with_password(format!("seed-password-{i}"))
            .with_notes("seed notes");
        let rk = subkeys::record_key(&vmk, &uuid, &id, 0).expect("record key");
        records.push(vault::seal_record(&h, &rk, &id, 0, &body).expect("seal"));
        manifest.entries.push(entry(i + 1));
    }

    let mut image = VaultImage {
        header: h,
        manifest,
        records,
    };
    vault::encode(&mut image, &index_key).expect("encode")
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).expect("create corpus dir");
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write corpus file");
    println!("  {} ({} bytes)", path.display(), bytes.len());
}

fn main() {
    let root = Path::new("corpus");

    // Cover the shapes that change the parser's control flow: no entries, several
    // entries, each optional factor present, and multiple key epochs.
    let vaults: Vec<(&str, Vec<u8>)> = vec![
        ("empty", build_vault([0x01; 16], FactorSet::default(), 1, 0)),
        ("single", build_vault([0x02; 16], FactorSet::default(), 1, 1)),
        ("many", build_vault([0x03; 16], FactorSet::default(), 1, 12)),
        (
            "keyfile",
            build_vault(
                [0x04; 16],
                FactorSet {
                    keyfile: Some([0xAA; 32]),
                    ..FactorSet::default()
                },
                1,
                2,
            ),
        ),
        (
            "yubikey",
            build_vault(
                [0x05; 16],
                FactorSet {
                    yubikey: Some(YubikeyFactor {
                        slot: 2,
                        challenge: [0xBB; 64],
                    }),
                    ..FactorSet::default()
                },
                1,
                2,
            ),
        ),
        (
            "fido2",
            build_vault(
                [0x06; 16],
                FactorSet {
                    fido2: Some(Fido2Factor {
                        rp_id_hash: [0xCC; 32],
                        salt: [0xDD; 32],
                        credential_id: vec![0xEE; 64],
                    }),
                    ..FactorSet::default()
                },
                1,
                2,
            ),
        ),
        (
            "all-factors-multi-epoch",
            build_vault(
                [0x07; 16],
                FactorSet {
                    keyfile: Some([0xAA; 32]),
                    yubikey: Some(YubikeyFactor {
                        slot: 1,
                        challenge: [0xBB; 64],
                    }),
                    fido2: Some(Fido2Factor {
                        rp_id_hash: [0xCC; 32],
                        salt: [0xDD; 32],
                        credential_id: vec![0xEE; 32],
                    }),
                },
                4,
                3,
            ),
        ),
    ];

    println!("vault_parse and header_decode seeds:");
    for (name, bytes) in &vaults {
        write(&root.join("vault_parse"), name, bytes);
        // The header decoder takes the same files: it reads a prefix and ignores the
        // rest, so full vaults are valid seeds for it too.
        write(&root.join("header_decode"), name, bytes);
    }

    println!("record_decode seeds:");
    for (i, body) in [
        RecordBody::new(),
        RecordBody::new().with_password("short"),
        RecordBody::new()
            .with_username("ada@example.com")
            .with_password("a".repeat(300))
            .with_totp_secret("JBSWY3DPEHPK3PXP")
            .with_notes("b".repeat(1000)),
    ]
    .iter()
    .enumerate()
    {
        let bytes = body.encode_padded().expect("encode record");
        write(&root.join("record_decode"), &format!("record-{i}"), &bytes);
    }

    println!("manifest_decode seeds:");
    for (i, count) in [0u8, 1, 25].iter().enumerate() {
        let mut manifest = Manifest::new();
        for id in 0..*count {
            manifest.entries.push(EntryMeta {
                blob_offset: u64::from(id) * 512,
                blob_len: 512,
                ..entry(id + 1)
            });
        }
        let bytes = manifest.encode_padded().expect("encode manifest");
        write(&root.join("manifest_decode"), &format!("manifest-{i}"), &bytes);
    }

    println!("\nDone. Run a target with, for example:");
    println!("  cargo fuzz run vault_parse -- -dict=vault.dict");
}
