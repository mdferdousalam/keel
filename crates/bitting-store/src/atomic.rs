// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The write transaction.
//!
//! Saving a vault is the single most dangerous thing this program does. A crash, a
//! full disk, or a second instance writing at the same moment must never be able to
//! leave the user without their passwords. Everything here exists to guarantee that
//! **at every instant, a complete and valid vault exists on disk** — either the old
//! one or the new one, never a half-written mixture.
//!
//! # The sequence, and why each step is there
//!
//! 1. **Take an advisory lock.** Two instances saving concurrently would interleave.
//! 2. **Re-check the file against what the caller loaded.** If it changed, abort
//!    rather than overwrite. Blindly overwriting would silently discard whatever the
//!    other writer saved, which for a password manager means losing a password the
//!    user believes they stored.
//! 3. **Write a temporary file in the same directory**, mode `0600`. Same directory
//!    because `rename` is only atomic within one filesystem — a temp file in `/tmp`
//!    would turn step 6 into a copy, which is not atomic at all.
//! 4. **`fsync` the temporary file.** Without this, `rename` can be durable while the
//!    contents are not, and a power failure leaves a correctly-named empty file.
//! 5. **Rotate backups**, so the previous version survives.
//! 6. **`rename` over the vault.** Atomic: any reader sees either the old file or the
//!    new one.
//! 7. **`fsync` the directory.** The rename itself is metadata and needs its own
//!    flush, or a crash can lose the rename even though the data was written.
//! 8. **Record the new write counter** for rollback detection.
//!
//! Steps 4 and 7 are the ones most often left out, and both produce failures that only
//! appear on real power loss — which is to say, they are found by users rather than by
//! tests. The crash-simulation tests in `tests/crash.rs` kill the process between each
//! step and assert a valid vault remains.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::error::{Error, Result};
use crate::paths::{VaultPaths, BACKUP_COUNT};

/// Identifies a specific version of a vault file on disk.
///
/// Compared before a write to detect that something else changed the file since it
/// was loaded. Uses length and content hash rather than modification time: `mtime`
/// has coarse resolution on some filesystems and is trivially forgeable, so two
/// different saves within the same second could compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    /// File length in bytes.
    pub len: u64,
    /// BLAKE3 hash of the whole file.
    pub hash: [u8; 32],
}

impl Fingerprint {
    /// Compute a fingerprint from file contents.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            len: bytes.len() as u64,
            hash: *blake3::hash(bytes).as_bytes(),
        }
    }

    /// Read a file and fingerprint it, or `None` if it does not exist.
    pub fn read(path: &Path) -> Result<Option<Self>> {
        match fs::read(path) {
            Ok(bytes) => Ok(Some(Self::of(&bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io("reading vault", path, e)),
        }
    }
}

/// Guard holding the advisory lock for the duration of a write.
///
/// The lock is advisory, which is worth being explicit about: it coordinates Bitting
/// instances with each other. It does not stop an unrelated program from writing to
/// the file, and it is **not** a security control. Step 2 of the write sequence — the
/// fingerprint re-check — is what actually protects against a concurrent write, and it
/// works regardless of where that write came from.
///
/// Built on `std::fs::File::try_lock`, stabilised in Rust 1.89, rather than a
/// third-party locking crate. Two properties make it the right choice here:
///
/// * The lock is tied to the file descriptor, so it is released when the process
///   exits **however** it exits. A crash cannot leave a vault permanently locked,
///   which a lockfile-with-a-PID scheme would risk.
/// * It removes a dependency from the tree, which the dependency budget in
///   `CONTRIBUTING.md` asks for.
#[derive(Debug)]
pub struct VaultLock {
    // Holding the `File` holds the lock. Dropping it releases the lock, which is why
    // this field exists despite never being read.
    _file: File,
}

impl VaultLock {
    /// Acquire the lock without blocking.
    ///
    /// Non-blocking on purpose: waiting would hang the UI, and telling the user "Bitting
    /// already has this vault open" is far better than a frozen window with no
    /// explanation.
    pub fn acquire(paths: &VaultPaths) -> Result<Self> {
        let path = paths.lock();
        ensure_directory(paths.directory())?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| Error::io("opening lock file", &path, e))?;

        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(Error::AlreadyLocked),
            Err(fs::TryLockError::Error(e)) => Err(Error::io("locking vault", &path, e)),
        }
    }
}

/// Create a directory and its parents if absent.
fn ensure_directory(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| Error::io("creating vault directory", dir, e))
}

/// Restrict a file to the owner only.
///
/// On Unix this sets mode `0600`. On Windows it is a no-op: files inherit the ACL of
/// their directory, and the per-user application data directory is already restricted
/// to the user. A bespoke DACL would be the stronger answer and is worth adding, but
/// claiming it is in place when it is not would be worse than documenting the gap.
fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|e| Error::io("restricting file permissions", path, e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Flush a directory's metadata so a rename inside it is durable.
///
/// Opening a directory as a file and calling `sync_all` is the portable Unix idiom.
/// Windows has no equivalent and does not need one: `MoveFileEx` with
/// `WRITE_THROUGH`, which `fs::rename` uses, already commits the metadata.
fn sync_directory(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let file = File::open(dir).map_err(|e| Error::io("opening directory to sync", dir, e))?;
        file.sync_all()
            .map_err(|e| Error::io("syncing directory", dir, e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Whether the caller expects the vault to already exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Creating a new vault; fail if one is already there.
    ///
    /// Guards against `bitting init` silently destroying an existing vault, which would
    /// be unrecoverable.
    Create,
    /// Replacing an existing vault, which must match `expected`.
    Replace,
}

/// Write a vault atomically.
///
/// `expected` is the fingerprint the caller observed when it loaded the vault. If the
/// file on disk no longer matches, the write is refused with
/// [`Error::ConcurrentModification`] rather than overwriting.
///
/// Returns the new file's fingerprint so the caller can carry it into the next save.
pub fn write_vault(
    paths: &VaultPaths,
    bytes: &[u8],
    mode: WriteMode,
    expected: Option<Fingerprint>,
) -> Result<Fingerprint> {
    let _lock = VaultLock::acquire(paths)?;
    ensure_directory(paths.directory())?;

    // Step 2: confirm the file is what the caller thinks it is.
    let current = Fingerprint::read(&paths.vault)?;
    match (mode, current, expected) {
        (WriteMode::Create, Some(_), _) => {
            return Err(Error::AlreadyExists(paths.vault.clone()));
        }
        (WriteMode::Replace, None, _) => {
            return Err(Error::NotFound(paths.vault.clone()));
        }
        (WriteMode::Replace, Some(on_disk), Some(expected)) if on_disk != expected => {
            return Err(Error::ConcurrentModification);
        }
        _ => {}
    }

    // Step 3: write a temporary file beside the vault, not in the system temp
    // directory, so the rename in step 6 stays within one filesystem.
    let temp = tempfile::Builder::new()
        .prefix(".bitting-tmp-")
        .suffix(".bitting")
        .tempfile_in(paths.directory())
        .map_err(|e| Error::io("creating temporary file", paths.directory(), e))?;
    restrict_permissions(temp.path())?;
    {
        let file = temp.as_file();
        let mut writer = file;
        writer
            .write_all(bytes)
            .map_err(|e| Error::io("writing vault contents", temp.path(), e))?;
        writer
            .flush()
            .map_err(|e| Error::io("flushing vault contents", temp.path(), e))?;
        // Step 4: without this, the rename can land while the contents have not.
        file.sync_all()
            .map_err(|e| Error::io("syncing vault contents", temp.path(), e))?;
    }

    // Step 5: rotate backups before the rename, so the previous version survives.
    if current.is_some() {
        rotate_backups(paths)?;
    }

    // Step 6: the atomic swap.
    let temp_path = temp.into_temp_path();
    temp_path
        .persist(&paths.vault)
        .map_err(|e| Error::io("replacing vault file", &paths.vault, e.error))?;
    restrict_permissions(&paths.vault)?;

    // Step 7: make the rename itself durable.
    sync_directory(paths.directory())?;

    Ok(Fingerprint::of(bytes))
}

/// Shift `vault.bitting` into `.bak.1`, and each backup one position older.
///
/// The oldest is discarded. Copy rather than rename for the vault itself, because a
/// rename would leave no vault on disk during the window before the new one is put in
/// place — briefly breaking the invariant this module exists to maintain.
fn rotate_backups(paths: &VaultPaths) -> Result<()> {
    // Oldest first, so nothing is overwritten before it has been moved.
    for index in (1..BACKUP_COUNT).rev() {
        let from = paths.backup(index);
        let to = paths.backup(index + 1);
        if from.exists() {
            // A failed rotation must not abort the save: keeping fewer backups is a
            // far better outcome than refusing to store a new password.
            let _ = fs::rename(&from, &to);
        }
    }
    if paths.vault.exists() {
        // Copy to a temporary file in the same directory and rename it into place, rather
        // than copying straight onto `.bak.1`.
        //
        // `fs::copy` is not atomic. Writing directly to the backup path meant a process
        // killed partway through left a **truncated backup** — a corrupt file at exactly the
        // moment a user reaches for a good one. The crash test caught this: the shifts below
        // already used `rename`, so only the copy was exposed, and it needed a kill to land
        // inside a window of a few milliseconds.
        //
        // With a temp file, a kill leaves either the old complete `.bak.1` or a stray temp
        // that nothing reads and `a_leftover_temporary_file_does_not_affect_the_vault`
        // already covers.
        let temp = tempfile::Builder::new()
            .prefix(".bitting-bak-")
            .suffix(".bitting")
            .tempfile_in(paths.directory())
            .map_err(|e| Error::io("creating temporary backup", paths.directory(), e))?;
        // Restricted before any bytes land in it, so the backup is never briefly readable by
        // anyone else — the same order the main write uses.
        restrict_permissions(temp.path())?;
        {
            let mut source = fs::File::open(&paths.vault)
                .map_err(|e| Error::io("opening vault to back up", &paths.vault, e))?;
            let file = temp.as_file();
            let mut sink = file;
            std::io::copy(&mut source, &mut sink)
                .map_err(|e| Error::io("copying vault to backup", temp.path(), e))?;
            sink.flush()
                .map_err(|e| Error::io("flushing backup", temp.path(), e))?;
            // Durable before the rename, or the rename can land while the contents have not —
            // which would produce the very partial backup this is avoiding.
            file.sync_all()
                .map_err(|e| Error::io("syncing backup", temp.path(), e))?;
        }
        temp.into_temp_path()
            .persist(paths.backup(1))
            .map_err(|e| Error::io("replacing backup", paths.backup(1), e.error))?;
        restrict_permissions(&paths.backup(1))?;
    }
    Ok(())
}

/// Read a vault file with its fingerprint.
pub fn read_vault(paths: &VaultPaths) -> Result<(Vec<u8>, Fingerprint)> {
    let bytes = match fs::read(&paths.vault) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::NotFound(paths.vault.clone()))
        }
        Err(e) => return Err(Error::io("reading vault", &paths.vault, e)),
    };
    let fingerprint = Fingerprint::of(&bytes);
    Ok((bytes, fingerprint))
}

/// How exposed a vault file's permissions are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionStatus {
    /// Readable only by the owner.
    OwnerOnly,
    /// Readable by the group or by everyone.
    ///
    /// Not a compromise on its own — the vault is encrypted — but it hands an
    /// offline-cracking attempt to anyone with an account on the machine, and it is
    /// almost always an accident (a bad `umask`, a careless `chmod -R`).
    TooOpen {
        /// The octal mode found.
        mode: u32,
    },
    /// Not determinable on this platform.
    Unknown,
}

/// Check whether the vault is readable by anyone but its owner.
pub fn check_permissions(path: &Path) -> Result<PermissionStatus> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta =
            fs::metadata(path).map_err(|e| Error::io("reading file permissions", path, e))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            Ok(PermissionStatus::TooOpen { mode })
        } else {
            Ok(PermissionStatus::OwnerOnly)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(PermissionStatus::Unknown)
    }
}

/// Tighten a vault file's permissions to owner-only.
pub fn repair_permissions(path: &Path) -> Result<()> {
    restrict_permissions(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, VaultPaths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.bitting")).unwrap();
        (dir, paths)
    }

    #[test]
    fn creates_then_replaces_a_vault() {
        let (_dir, paths) = setup();
        let fp1 = write_vault(&paths, b"version one", WriteMode::Create, None).unwrap();
        assert_eq!(fs::read(&paths.vault).unwrap(), b"version one");

        let fp2 = write_vault(&paths, b"version two", WriteMode::Replace, Some(fp1)).unwrap();
        assert_eq!(fs::read(&paths.vault).unwrap(), b"version two");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn create_refuses_to_clobber_an_existing_vault() {
        // `bitting init` over a real vault would be unrecoverable, so it must be an error.
        let (_dir, paths) = setup();
        write_vault(&paths, b"original", WriteMode::Create, None).unwrap();
        let err = write_vault(&paths, b"overwrite", WriteMode::Create, None).unwrap_err();
        assert!(matches!(err, Error::AlreadyExists(_)));
        assert_eq!(fs::read(&paths.vault).unwrap(), b"original");
    }

    #[test]
    fn replace_requires_an_existing_vault() {
        let (_dir, paths) = setup();
        let err = write_vault(&paths, b"data", WriteMode::Replace, None).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn a_concurrent_change_is_refused_rather_than_overwritten() {
        // The property that stops one instance silently discarding another's save.
        let (_dir, paths) = setup();
        let stale = write_vault(&paths, b"loaded version", WriteMode::Create, None).unwrap();

        // Something else writes in the meantime.
        write_vault(&paths, b"someone else's save", WriteMode::Replace, None).unwrap();

        let err = write_vault(&paths, b"my save", WriteMode::Replace, Some(stale)).unwrap_err();
        assert!(matches!(err, Error::ConcurrentModification));
        assert!(err.is_transient(), "the UI should offer a reload and retry");
        // The other writer's data must survive.
        assert_eq!(fs::read(&paths.vault).unwrap(), b"someone else's save");
    }

    #[test]
    fn backups_rotate_and_are_bounded() {
        let (_dir, paths) = setup();
        let mut fp = write_vault(&paths, b"save-0", WriteMode::Create, None).unwrap();
        for i in 1..=5 {
            let data = format!("save-{i}");
            fp = write_vault(&paths, data.as_bytes(), WriteMode::Replace, Some(fp)).unwrap();
        }

        assert_eq!(fs::read(&paths.vault).unwrap(), b"save-5");
        assert_eq!(fs::read(paths.backup(1)).unwrap(), b"save-4");
        assert_eq!(fs::read(paths.backup(2)).unwrap(), b"save-3");
        assert_eq!(fs::read(paths.backup(3)).unwrap(), b"save-2");
        // Old secrets must not accumulate on disk indefinitely.
        assert!(!paths.backup(4).exists());
    }

    #[test]
    fn no_temporary_files_are_left_behind() {
        let (dir, paths) = setup();
        let mut fp = write_vault(&paths, b"a", WriteMode::Create, None).unwrap();
        fp = write_vault(&paths, b"b", WriteMode::Replace, Some(fp)).unwrap();
        let _ = fp;

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("bitting-tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left temporary files: {leftovers:?}");
    }

    #[test]
    fn the_vault_is_written_owner_only() {
        let (_dir, paths) = setup();
        write_vault(&paths, b"secret", WriteMode::Create, None).unwrap();
        assert_eq!(
            check_permissions(&paths.vault).unwrap(),
            if cfg!(unix) {
                PermissionStatus::OwnerOnly
            } else {
                PermissionStatus::Unknown
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn over_permissive_files_are_detected_and_repairable() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, paths) = setup();
        write_vault(&paths, b"secret", WriteMode::Create, None).unwrap();

        fs::set_permissions(&paths.vault, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            check_permissions(&paths.vault).unwrap(),
            PermissionStatus::TooOpen { mode: 0o644 }
        );

        repair_permissions(&paths.vault).unwrap();
        assert_eq!(
            check_permissions(&paths.vault).unwrap(),
            PermissionStatus::OwnerOnly
        );
    }

    #[test]
    fn a_second_lock_holder_is_reported_as_already_open() {
        let (_dir, paths) = setup();
        let _held = VaultLock::acquire(&paths).unwrap();
        let err = VaultLock::acquire(&paths).unwrap_err();
        assert!(matches!(err, Error::AlreadyLocked));
        assert!(err.is_transient());
    }

    #[test]
    fn the_lock_is_released_when_dropped() {
        let (_dir, paths) = setup();
        {
            let _held = VaultLock::acquire(&paths).unwrap();
        }
        // Must be reacquirable, or a crash would leave the vault permanently locked.
        let _reacquired = VaultLock::acquire(&paths).unwrap();
    }

    #[test]
    fn missing_directories_are_created() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("vault.bitting");
        let paths = VaultPaths::new(nested).unwrap();
        write_vault(&paths, b"data", WriteMode::Create, None).unwrap();
        assert!(paths.exists());
    }

    #[test]
    fn read_round_trips_with_a_matching_fingerprint() {
        let (_dir, paths) = setup();
        let written = write_vault(&paths, b"contents", WriteMode::Create, None).unwrap();
        let (bytes, read) = read_vault(&paths).unwrap();
        assert_eq!(bytes, b"contents");
        assert_eq!(read, written);
    }

    #[test]
    fn reading_a_missing_vault_reports_not_found() {
        let (_dir, paths) = setup();
        assert!(matches!(read_vault(&paths), Err(Error::NotFound(_))));
    }

    #[test]
    fn fingerprints_distinguish_same_length_contents() {
        // Length alone is not enough: two saves can easily be the same size.
        let a = Fingerprint::of(b"aaaa");
        let b = Fingerprint::of(b"aaab");
        assert_eq!(a.len, b.len);
        assert_ne!(a, b);
    }
}
