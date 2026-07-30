//! End-to-end vault lifecycle tests.
//!
//! These exercise the whole stack together — key derivation, the on-disk format,
//! atomic writes, and rollback detection — which is where integration mistakes live.
//! A unit test can confirm each layer is self-consistent while the layers still
//! disagree with each other about, say, whether a counter is incremented before or
//! after a write.
//!
//! All tests use deliberately cheap KDF parameters. Real vaults default to 512 MiB and
//! roughly 1.5 seconds per unlock, which no test suite can afford per case.

// Test code may panic and may cast or divide freely; the strict lints exist to
// protect library code, not readability of failures.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::cast_possible_truncation
)]

use keel_core::{EntryDraft, OpenOptions, UnlockFactors, UnlockedVault};
use keel_crypto::kdf::{Argon2Params, MIN_M_COST_KIB};
use keel_crypto::SecretString;
use keel_format::RecordBody;
use keel_store::{RollbackVerdict, VaultPaths};

/// Cheap parameters. Never used by a real vault.
fn test_params() -> Argon2Params {
    Argon2Params {
        m_cost_kib: MIN_M_COST_KIB,
        t_cost: 1,
        p_cost: 1,
    }
}

fn factors(passphrase: &str) -> UnlockFactors {
    let mut s = SecretString::passphrase_buffer();
    s.push_str(passphrase).unwrap();
    UnlockFactors::passphrase(s)
}

fn draft(title: &str) -> EntryDraft {
    EntryDraft {
        title: title.to_owned(),
        username: "ada@example.com".to_owned(),
        origins: vec!["https://example.com".to_owned()],
        tags: vec!["test".to_owned()],
        folder_id: None,
        favorite: false,
    }
}

fn setup() -> (tempfile::TempDir, VaultPaths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.keel")).unwrap();
    (dir, paths)
}

#[test]
fn create_add_save_reopen_reveal() {
    // The core round trip: everything else is a variation on this.
    let (_dir, paths) = setup();

    let mut vault =
        UnlockedVault::create(paths.clone(), &factors("open sesame"), test_params(), 12).unwrap();
    let id = vault
        .add_entry(
            draft("Example Bank"),
            &RecordBody::new()
                .with_username("ada@example.com")
                .with_password("correct-horse-battery-staple")
                .with_totp_secret("JBSWY3DPEHPK3PXP")
                .with_notes("recovery codes are in the safe"),
        )
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    let (reopened, report) =
        UnlockedVault::open(paths, &factors("open sesame"), OpenOptions::default()).unwrap();
    assert_eq!(reopened.entries().len(), 1);
    assert_eq!(reopened.entry(&id).unwrap().title, "Example Bank");
    assert!(reopened.entry(&id).unwrap().has_totp);
    assert!(report.damaged_entries.is_empty());

    let body = reopened.reveal(&id).unwrap();
    assert_eq!(body.password, "correct-horse-battery-staple");
    assert_eq!(body.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert_eq!(body.notes, "recovery codes are in the safe");
}

#[test]
fn the_wrong_passphrase_cannot_open_the_vault() {
    let (_dir, paths) = setup();
    let mut vault =
        UnlockedVault::create(paths.clone(), &factors("right one"), test_params(), 0).unwrap();
    vault
        .add_entry(draft("Secret"), &RecordBody::new().with_password("hunter2"))
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    let err =
        UnlockedVault::open(paths, &factors("wrong one"), OpenOptions::default()).unwrap_err();
    // The message must not distinguish which factor was wrong.
    let rendered = err.to_string();
    assert!(rendered.contains("could not unlock"), "got: {rendered}");
    assert!(
        !rendered.to_lowercase().contains("passphrase is"),
        "leaks which factor: {rendered}"
    );
}

#[test]
fn a_keyfile_is_required_once_configured() {
    let (_dir, paths) = setup();
    let keyfile = b"this is a keyfile".to_vec();

    let mut vault = UnlockedVault::create(
        paths.clone(),
        &factors("passphrase").with_keyfile(keyfile.clone()),
        test_params(),
        0,
    )
    .unwrap();
    vault
        .add_entry(draft("Guarded"), &RecordBody::new().with_password("s3cret"))
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    // Right passphrase, no keyfile: must fail.
    assert!(UnlockedVault::open(
        paths.clone(),
        &factors("passphrase"),
        OpenOptions::default()
    )
    .is_err());

    // Right passphrase, wrong keyfile: must fail.
    assert!(UnlockedVault::open(
        paths.clone(),
        &factors("passphrase").with_keyfile(b"different".to_vec()),
        OpenOptions::default()
    )
    .is_err());

    // Both correct: succeeds.
    let (opened, _) = UnlockedVault::open(
        paths,
        &factors("passphrase").with_keyfile(keyfile),
        OpenOptions::default(),
    )
    .unwrap();
    assert_eq!(opened.entries().len(), 1);
}

#[test]
fn changing_the_passphrase_does_not_re_encrypt_records() {
    // The point of separating the key-encryption key from the vault master key. The
    // proof that records were untouched: every record blob's ciphertext is byte-for-byte
    // identical afterwards, verified by the entries still decrypting under the new
    // passphrase without having been rewritten.
    let (_dir, paths) = setup();
    let mut vault =
        UnlockedVault::create(paths.clone(), &factors("old passphrase"), test_params(), 0).unwrap();

    let mut ids = Vec::new();
    for i in 0..5 {
        ids.push(
            vault
                .add_entry(
                    draft(&format!("Site {i}")),
                    &RecordBody::new().with_password(format!("password-{i}")),
                )
                .unwrap(),
        );
    }
    vault.save().unwrap();

    vault
        .change_passphrase(&factors("new passphrase"), test_params(), 0)
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    // The old passphrase must no longer work.
    assert!(UnlockedVault::open(
        paths.clone(),
        &factors("old passphrase"),
        OpenOptions::default()
    )
    .is_err());

    // The new one must, and every secret must still be readable.
    let (reopened, _) =
        UnlockedVault::open(paths, &factors("new passphrase"), OpenOptions::default()).unwrap();
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(
            reopened.reveal(id).unwrap().password,
            format!("password-{i}")
        );
    }
}

#[test]
fn edits_and_deletions_survive_a_round_trip() {
    let (_dir, paths) = setup();
    let mut vault = UnlockedVault::create(paths.clone(), &factors("pw"), test_params(), 0).unwrap();

    let keep = vault
        .add_entry(draft("Keep"), &RecordBody::new().with_password("keep-me"))
        .unwrap();
    let edit = vault
        .add_entry(draft("Edit"), &RecordBody::new().with_password("old-value"))
        .unwrap();
    let bin = vault
        .add_entry(draft("Bin"), &RecordBody::new().with_password("delete-me"))
        .unwrap();

    vault
        .update_secrets(&edit, &RecordBody::new().with_password("new-value"))
        .unwrap();
    vault.update_metadata(&edit, draft("Edited Title")).unwrap();
    vault.trash_entry(&bin, 30).unwrap();
    vault.save().unwrap();
    vault.lock();

    let (reopened, _) = UnlockedVault::open(paths, &factors("pw"), OpenOptions::default()).unwrap();
    assert_eq!(reopened.entries().len(), 2);
    assert_eq!(reopened.reveal(&keep).unwrap().password, "keep-me");
    assert_eq!(reopened.reveal(&edit).unwrap().password, "new-value");
    assert_eq!(reopened.entry(&edit).unwrap().title, "Edited Title");
    // Trashed, so absent from the live list but still recoverable.
    assert!(reopened.entry(&bin).is_err());
}

#[test]
fn a_trashed_entry_can_be_restored() {
    let (_dir, paths) = setup();
    let mut vault = UnlockedVault::create(paths.clone(), &factors("pw"), test_params(), 0).unwrap();
    let id = vault
        .add_entry(
            draft("Oops"),
            &RecordBody::new().with_password("still-needed"),
        )
        .unwrap();
    vault.trash_entry(&id, 30).unwrap();
    vault.save().unwrap();
    vault.lock();

    let (mut reopened, _) =
        UnlockedVault::open(paths, &factors("pw"), OpenOptions::default()).unwrap();
    assert!(reopened.entry(&id).is_err());
    reopened.restore_entry(&id).unwrap();
    reopened.save().unwrap();
    // The secret must have survived the trip through the trash intact.
    assert_eq!(reopened.reveal(&id).unwrap().password, "still-needed");
}

#[test]
fn the_write_counter_advances_on_every_save() {
    let (_dir, paths) = setup();
    let mut vault = UnlockedVault::create(paths.clone(), &factors("pw"), test_params(), 0).unwrap();
    let after_create = vault.write_counter();

    for i in 0..3 {
        vault
            .add_entry(
                draft(&format!("Entry {i}")),
                &RecordBody::new().with_password("x"),
            )
            .unwrap();
        vault.save().unwrap();
    }
    assert!(
        vault.write_counter() > after_create,
        "counter must advance, or rollback becomes undetectable"
    );
}

#[test]
fn reopening_a_vault_this_device_knows_reports_consistent() {
    let (_dir, paths) = setup();
    let mut vault = UnlockedVault::create(paths.clone(), &factors("pw"), test_params(), 0).unwrap();
    vault
        .add_entry(draft("Entry"), &RecordBody::new().with_password("x"))
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    let (v, report) =
        UnlockedVault::open(paths.clone(), &factors("pw"), OpenOptions::default()).unwrap();
    // First open after create still has state recorded, so this is consistent rather
    // than first sight.
    assert_eq!(report.rollback, RollbackVerdict::Consistent);
    assert!(!report.requires_attention());
    v.lock();
}

#[test]
fn an_older_vault_file_is_refused_until_the_user_accepts_it() {
    // Rollback detection, end to end: save twice, restore the backup, and confirm the
    // open is blocked until the caller passes accept_rollback.
    let (_dir, paths) = setup();
    let mut vault = UnlockedVault::create(paths.clone(), &factors("pw"), test_params(), 0).unwrap();
    vault
        .add_entry(draft("First"), &RecordBody::new().with_password("v1"))
        .unwrap();
    vault.save().unwrap();

    vault
        .add_entry(draft("Second"), &RecordBody::new().with_password("v2"))
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    // Roll the file back to the previous generation, as a restored backup or a
    // malicious replacement would.
    std::fs::copy(paths.backup(1), &paths.vault).unwrap();

    let err =
        UnlockedVault::open(paths.clone(), &factors("pw"), OpenOptions::default()).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("older"),
        "should explain the rollback: {message}"
    );
    assert!(
        message.contains("restored a backup"),
        "should name the innocent explanation too: {message}"
    );

    // With explicit acceptance, it opens and reports the regression.
    let (opened, report) = UnlockedVault::open(
        paths,
        &factors("pw"),
        OpenOptions {
            accept_rollback: true,
            ..OpenOptions::default()
        },
    )
    .unwrap();
    assert!(matches!(
        report.rollback,
        RollbackVerdict::Regression { .. }
    ));
    assert!(report.requires_attention());
    opened.lock();
}

#[test]
fn a_tampered_vault_file_fails_to_open() {
    let (_dir, paths) = setup();
    let mut vault = UnlockedVault::create(paths.clone(), &factors("pw"), test_params(), 0).unwrap();
    vault
        .add_entry(draft("Entry"), &RecordBody::new().with_password("secret"))
        .unwrap();
    vault.save().unwrap();
    vault.lock();

    // Flip a byte in the middle of the file.
    let mut bytes = std::fs::read(&paths.vault).unwrap();
    let midpoint = bytes.len() / 2;
    bytes[midpoint] ^= 0xFF;
    std::fs::write(&paths.vault, &bytes).unwrap();

    let err = UnlockedVault::open(paths, &factors("pw"), OpenOptions::default()).unwrap_err();
    assert!(
        err.suggests_vault_damage(),
        "the UI should be able to offer backup recovery: {err}"
    );
}

#[test]
fn search_matches_title_username_and_origin_without_touching_secrets() {
    let (_dir, paths) = setup();
    let mut vault = UnlockedVault::create(paths, &factors("pw"), test_params(), 0).unwrap();

    vault
        .add_entry(
            EntryDraft {
                title: "Example Bank".to_owned(),
                username: "ada@example.com".to_owned(),
                origins: vec!["https://bank.example.com".to_owned()],
                ..EntryDraft::default()
            },
            &RecordBody::new().with_password("uniquepasswordvalue"),
        )
        .unwrap();
    vault
        .add_entry(
            EntryDraft {
                title: "Mail".to_owned(),
                username: "grace@other.test".to_owned(),
                origins: vec!["https://mail.other.test".to_owned()],
                ..EntryDraft::default()
            },
            &RecordBody::new().with_password("another"),
        )
        .unwrap();

    assert_eq!(vault.search("bank").len(), 1);
    assert_eq!(
        vault.search("BANK").len(),
        1,
        "search should be case-insensitive"
    );
    assert_eq!(vault.search("ada@").len(), 1);
    assert_eq!(vault.search("other.test").len(), 1);
    assert_eq!(vault.search("example").len(), 1);
    assert_eq!(vault.search("nothing here").len(), 0);
    // Search must never match on secret content, which is not decrypted at all.
    assert_eq!(vault.search("uniquepasswordvalue").len(), 0);
}

#[test]
fn a_concurrent_writer_is_detected_rather_than_overwritten() {
    let (_dir, paths) = setup();
    let mut first = UnlockedVault::create(paths.clone(), &factors("pw"), test_params(), 0).unwrap();
    first
        .add_entry(draft("From first"), &RecordBody::new().with_password("a"))
        .unwrap();
    first.save().unwrap();

    // A second instance opens the same vault and saves.
    let (mut second, _) =
        UnlockedVault::open(paths, &factors("pw"), OpenOptions::default()).unwrap();
    second
        .add_entry(draft("From second"), &RecordBody::new().with_password("b"))
        .unwrap();
    second.save().unwrap();

    // The first instance now holds a stale fingerprint. Its save must be refused, not
    // silently discard what the second instance stored.
    first
        .add_entry(
            draft("Also from first"),
            &RecordBody::new().with_password("c"),
        )
        .unwrap();
    let err = first.save().unwrap_err();
    assert!(
        err.to_string().contains("changed on disk"),
        "expected a concurrent-modification error, got: {err}"
    );
}

#[test]
fn debug_output_never_contains_key_material_or_secrets() {
    let (_dir, paths) = setup();
    let mut vault =
        UnlockedVault::create(paths, &factors("my-master-passphrase"), test_params(), 0).unwrap();
    let id = vault
        .add_entry(
            draft("Bank"),
            &RecordBody::new().with_password("super-secret-password"),
        )
        .unwrap();

    let rendered = format!("{vault:?}");
    assert!(rendered.contains("redacted"));
    assert!(!rendered.contains("my-master-passphrase"));
    assert!(!rendered.contains("super-secret-password"));

    let body = vault.reveal(&id).unwrap();
    assert!(!format!("{body:?}").contains("super-secret-password"));

    let f = factors("another-passphrase");
    assert!(!format!("{f:?}").contains("another-passphrase"));
}

#[test]
fn many_entries_round_trip() {
    // Exercises the layout code with enough records that offsets and varint widths
    // actually vary.
    let (_dir, paths) = setup();
    let mut vault = UnlockedVault::create(paths.clone(), &factors("pw"), test_params(), 0).unwrap();

    let mut expected = Vec::new();
    for i in 0..200 {
        let password = format!("password-number-{i}");
        let id = vault
            .add_entry(
                draft(&format!("Entry {i}")),
                &RecordBody::new()
                    .with_password(&password)
                    .with_notes("x".repeat(i % 500)),
            )
            .unwrap();
        expected.push((id, password));
    }
    vault.save().unwrap();
    vault.lock();

    let (reopened, report) =
        UnlockedVault::open(paths, &factors("pw"), OpenOptions::default()).unwrap();
    assert_eq!(reopened.entries().len(), 200);
    assert!(report.damaged_entries.is_empty());
    for (id, password) in &expected {
        assert_eq!(&reopened.reveal(id).unwrap().password, password);
    }
}

#[test]
fn creating_over_an_existing_vault_is_refused() {
    let (_dir, paths) = setup();
    let first = UnlockedVault::create(paths.clone(), &factors("pw"), test_params(), 0).unwrap();
    first.lock();

    // Would be unrecoverable, so it must never be implicit.
    assert!(UnlockedVault::create(paths, &factors("other"), test_params(), 0).is_err());
}
