//! Crash-safety tests for the write transaction.
//!
//! The invariant under test: **at every instant, a complete and valid vault exists on
//! disk.** A crash may cost the most recent save, but never the vault.
//!
//! Two kinds of test here, because they catch different things:
//!
//! * **Deterministic tests** assert the specific structural properties the write
//!   sequence relies on — a leftover temporary file is harmless, an interrupted backup
//!   rotation does not corrupt anything, and the vault path never holds a partial file.
//! * **A randomised kill test** spawns a real child process writing in a loop and
//!   `SIGKILL`s it at varying moments, then checks the vault. This is the one that
//!   would actually catch a missing `fsync` or a step in the wrong order, because it
//!   makes no assumptions about where the failure lands.
//!
//! The child is this same test binary, re-invoked with an environment variable set —
//! the standard technique for testing process death without instrumenting production
//! code with abort hooks. Nothing in `keel-store` knows it is being tested.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::fs;
#[cfg(unix)]
use std::path::Path;
// Only the randomised kill test uses these, and it is `cfg(unix)` — see the note on
// `killing_a_writer_mid_save_never_corrupts_the_vault`. Ungated, they are dead code on
// Windows, and this workspace denies warnings.
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

use keel_store::{read_vault, write_vault, VaultPaths, WriteMode};

/// Environment variable that turns this binary into the crash-test child.
#[cfg(unix)]
const CHILD_ENV: &str = "KEEL_CRASH_TEST_DIR";

/// Recognisable payloads. Every valid save is one of these, so a torn write shows up
/// as a payload that is neither.
fn payload(generation: usize) -> Vec<u8> {
    let mut v = format!("KEELTEST-GEN-{generation:06}-").into_bytes();
    // Pad to something big enough to span several filesystem blocks, so a torn write
    // has room to actually be torn.
    v.resize(64 * 1024, b'.');
    v.extend_from_slice(format!("-END-{generation:06}").as_bytes());
    v
}

/// Check that a file's contents are exactly one of the payloads we ever write.
fn is_intact_payload(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"KEELTEST-GEN-") {
        return false;
    }
    let generation: usize = match std::str::from_utf8(&bytes[13..19]) {
        Ok(s) => match s.parse() {
            Ok(g) => g,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    bytes == payload(generation).as_slice()
}

// ---------------------------------------------------------------------------
// Deterministic structural tests
// ---------------------------------------------------------------------------

#[test]
fn a_leftover_temporary_file_does_not_affect_the_vault() {
    // What is on disk if the process died between creating the temp file and the
    // rename. The vault must be untouched and still readable.
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.keel")).unwrap();
    let fp = write_vault(&paths, &payload(1), WriteMode::Create, None).unwrap();

    fs::write(dir.path().join(".keel-tmp-abandoned.keel"), b"half written").unwrap();

    let (bytes, read_fp) = read_vault(&paths).unwrap();
    assert!(is_intact_payload(&bytes));
    assert_eq!(read_fp, fp);

    // And the next save still works, rather than tripping over the debris.
    write_vault(&paths, &payload(2), WriteMode::Replace, Some(fp)).unwrap();
    assert!(is_intact_payload(&read_vault(&paths).unwrap().0));
}

#[test]
fn an_interrupted_backup_rotation_leaves_a_valid_vault() {
    // Backup rotation happens before the rename. If it is interrupted, the vault is
    // still the old one and must remain readable.
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.keel")).unwrap();
    let mut fp = write_vault(&paths, &payload(1), WriteMode::Create, None).unwrap();
    fp = write_vault(&paths, &payload(2), WriteMode::Replace, Some(fp)).unwrap();

    // Simulate rotation having got half way: remove one backup, duplicate another.
    let _ = fs::remove_file(paths.backup(1));
    fs::copy(&paths.vault, paths.backup(3)).unwrap();

    let next = write_vault(&paths, &payload(3), WriteMode::Replace, Some(fp));
    assert!(
        next.is_ok(),
        "a damaged backup set must not block a save: {next:?}"
    );
    assert!(is_intact_payload(&read_vault(&paths).unwrap().0));
}

#[test]
fn a_truncated_backup_never_masquerades_as_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.keel")).unwrap();
    let fp = write_vault(&paths, &payload(1), WriteMode::Create, None).unwrap();
    write_vault(&paths, &payload(2), WriteMode::Replace, Some(fp)).unwrap();

    // Corrupt the backup. The vault itself must be unaffected.
    fs::write(paths.backup(1), b"truncated").unwrap();
    assert!(is_intact_payload(&read_vault(&paths).unwrap().0));
}

#[test]
fn every_backup_is_a_complete_previous_generation() {
    // A backup must be a whole earlier save, never a partial one — otherwise
    // "restore from backup" would hand the user a corrupt file.
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.keel")).unwrap();
    let mut fp = write_vault(&paths, &payload(0), WriteMode::Create, None).unwrap();
    for generation in 1..=6 {
        fp = write_vault(&paths, &payload(generation), WriteMode::Replace, Some(fp)).unwrap();
    }

    assert!(is_intact_payload(&fs::read(&paths.vault).unwrap()));
    for index in 1..=keel_store::BACKUP_COUNT {
        let path = paths.backup(index);
        assert!(path.exists(), "backup {index} missing");
        assert!(
            is_intact_payload(&fs::read(&path).unwrap()),
            "backup {index} is not a complete generation"
        );
    }
}

// ---------------------------------------------------------------------------
// Randomised kill test
// ---------------------------------------------------------------------------

/// Write generations in a tight loop until killed. Never returns normally.
#[cfg(unix)]
fn child_write_loop(dir: &Path) -> ! {
    let paths = VaultPaths::new(dir.join("vault.keel")).unwrap();
    let mut fingerprint = None;
    let mut generation = 0usize;
    loop {
        let mode = if fingerprint.is_none() && !paths.exists() {
            WriteMode::Create
        } else {
            WriteMode::Replace
        };
        // A stale fingerprint would abort the write; re-read when that happens.
        if mode == WriteMode::Replace && fingerprint.is_none() {
            fingerprint = read_vault(&paths).ok().map(|(_, fp)| fp);
        }
        match write_vault(&paths, &payload(generation), mode, fingerprint) {
            Ok(fp) => {
                fingerprint = Some(fp);
                generation = generation.wrapping_add(1);
            }
            Err(_) => {
                fingerprint = None;
            }
        }
    }
}

/// Unix only, and the reason is the harness rather than the property.
///
/// The delays this walks through are tuned to how long a spawned test binary takes to reach
/// its first write. Windows process startup is slow enough that at the short end the child is
/// still starting when it is killed, so it never writes a vault — and the test's own
/// self-check then fires with "only 4 of 10 rounds produced a vault; this test proved
/// nothing". It has both passed and failed on Windows depending on runner load, and a test
/// that flips is worse than one that is honestly skipped: it teaches people to re-run CI
/// instead of reading it.
///
/// The property still holds on Windows; what does not port is the timing assumption. The
/// deterministic crash tests above run everywhere and cover the structural half. Making this
/// one work there means calibrating the delays against Windows startup, which is worth doing
/// when the platform is actually supported.
#[cfg(unix)]
#[test]
fn killing_a_writer_mid_save_never_corrupts_the_vault() {
    // Child mode: the parent re-invokes this binary with the directory in the
    // environment, and this branch does the writing until it is killed.
    if let Ok(dir) = std::env::var(CHILD_ENV) {
        child_write_loop(Path::new(&dir));
    }

    let exe = std::env::current_exe().expect("test binary path");

    // Counts how many rounds actually produced a vault. Without this, a child that
    // failed to launch would make every assertion below vacuous and the test would
    // pass while testing nothing.
    let mut rounds_with_a_vault = 0usize;
    let mut generations_seen = std::collections::BTreeSet::new();

    // Vary the delay so the kill lands at different points in the transaction —
    // during the temp write, during the fsync, during rotation, during the rename.
    // Prime-ish millisecond values avoid accidentally syncing with the loop period.
    for delay_ms in [3u64, 7, 11, 17, 23, 31, 41, 53, 67, 83] {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.keel")).unwrap();

        let mut child = Command::new(&exe)
            .args([
                "--exact",
                "killing_a_writer_mid_save_never_corrupts_the_vault",
                "--nocapture",
            ])
            .env(CHILD_ENV, dir.path())
            // Keep the child's own output out of the parent's test log.
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn crash-test child");

        std::thread::sleep(Duration::from_millis(delay_ms));
        // SIGKILL: no unwinding, no destructors, no flushing. The harshest case, and
        // the one a power failure most resembles.
        let _ = child.kill();
        let _ = child.wait();

        // The vault may not exist yet if the kill beat the first save. Anything that
        // does exist must be a complete generation.
        if paths.exists() {
            let bytes = fs::read(&paths.vault).unwrap();
            assert!(
                is_intact_payload(&bytes),
                "after a kill at {delay_ms}ms the vault was a partial write ({} bytes)",
                bytes.len()
            );
            rounds_with_a_vault += 1;
            if let Ok(text) = std::str::from_utf8(&bytes[13..19]) {
                generations_seen.insert(text.to_owned());
            }
        }

        // Backups must also be whole. A partial backup would give a user a corrupt
        // file at the exact moment they need a good one.
        for index in 1..=keel_store::BACKUP_COUNT {
            let path = paths.backup(index);
            if path.exists() {
                let bytes = fs::read(&path).unwrap();
                assert!(
                    is_intact_payload(&bytes),
                    "after a kill at {delay_ms}ms backup {index} was partial"
                );
            }
        }

        // A dead writer must not leave the vault locked, or the user could never
        // reopen it. This is why the lock is tied to the file descriptor.
        let reacquired = write_vault(
            &paths,
            // A sentinel generation that still fits the six-digit payload format.
            &payload(999_999),
            if paths.exists() {
                WriteMode::Replace
            } else {
                WriteMode::Create
            },
            None,
        );
        assert!(
            reacquired.is_ok(),
            "vault stayed locked after the writer was killed at {delay_ms}ms: {reacquired:?}"
        );
    }

    // Guard against a vacuous pass. If the child never managed a save — because it
    // failed to launch, or aborted at startup — every assertion above was checking
    // nothing at all.
    assert!(
        rounds_with_a_vault >= 5,
        "only {rounds_with_a_vault} of 10 rounds produced a vault; the child process \
         is probably not running, so this test proved nothing"
    );
    // The child should have got through many generations across the rounds. Seeing
    // only one distinct generation would mean writes were not actually progressing.
    assert!(
        generations_seen.len() >= 2,
        "saw only {} distinct generation(s) {:?}; writes do not appear to be progressing",
        generations_seen.len(),
        generations_seen
    );
}
