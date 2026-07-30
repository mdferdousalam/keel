//! Where a vault and its companion files live.
//!
//! A vault is not one file but four, and they must travel together:
//!
//! | File | Purpose |
//! |---|---|
//! | `vault.keel` | The vault |
//! | `vault.keel.bak.{1,2,3}` | Rotated backups, each tagged with its write counter |
//! | `vault.audit` | Hash-chained audit log |
//! | `vault.state` | Last-seen write counter, for rollback detection |
//! | `vault.keel.lock` | Advisory lock held during a write |
//!
//! Companion paths are derived from the vault path rather than configured
//! separately, so a user who moves or renames a vault cannot accidentally leave its
//! rollback state pointing at the old file — which would silently disable rollback
//! detection at exactly the moment it matters.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Number of rotated backups kept.
///
/// Three, because the realistic failure is a bad save followed by the user not
/// noticing for a couple of sessions. One backup would be overwritten by the next
/// save; a dozen would keep old secrets on disk long after rotation, which is its
/// own risk.
pub const BACKUP_COUNT: usize = 3;

/// Default vault file name.
pub const DEFAULT_VAULT_NAME: &str = "vault.keel";

/// A vault path and the companion paths derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    /// The vault file itself.
    pub vault: PathBuf,
}

impl VaultPaths {
    /// Derive all companion paths from a vault file path.
    pub fn new(vault: impl Into<PathBuf>) -> Result<Self> {
        let vault = vault.into();
        if vault.parent().is_none() {
            return Err(Error::InvalidPath(
                "vault path has no parent directory".to_owned(),
            ));
        }
        if vault.file_name().is_none() {
            return Err(Error::InvalidPath(
                "vault path does not name a file".to_owned(),
            ));
        }
        Ok(Self { vault })
    }

    /// The platform's default vault location.
    ///
    /// | Platform | Location |
    /// |---|---|
    /// | Linux | `$XDG_DATA_HOME/keel/vault.keel` |
    /// | macOS | `~/Library/Application Support/dev.keel/vault.keel` |
    /// | Windows | `%APPDATA%\keel\data\vault.keel` |
    pub fn default_location() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("dev", "", "keel").ok_or_else(|| {
            Error::InvalidPath("could not determine the user's data directory".to_owned())
        })?;
        Self::new(dirs.data_dir().join(DEFAULT_VAULT_NAME))
    }

    /// Directory containing the vault.
    ///
    /// Every companion file lives here, which matters for the write transaction: a
    /// rename is only atomic within one filesystem.
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.vault.parent().unwrap_or(Path::new("."))
    }

    /// Path with an extra extension appended to the vault's file name.
    fn sibling(&self, suffix: &str) -> PathBuf {
        let mut name = self.vault.file_name().unwrap_or_default().to_os_string();
        name.push(suffix);
        self.directory().join(name)
    }

    /// Advisory lock file, held for the duration of a write transaction.
    #[must_use]
    pub fn lock(&self) -> PathBuf {
        self.sibling(".lock")
    }

    /// Rollback-detection state.
    #[must_use]
    pub fn state(&self) -> PathBuf {
        self.sibling(".state")
    }

    /// Hash-chained audit log.
    #[must_use]
    pub fn audit(&self) -> PathBuf {
        self.sibling(".audit")
    }

    /// Rotated backup path. `index` is 1-based; 1 is the most recent.
    #[must_use]
    pub fn backup(&self, index: usize) -> PathBuf {
        self.sibling(&format!(".bak.{index}"))
    }

    /// All backup paths, most recent first.
    #[must_use]
    pub fn backups(&self) -> Vec<PathBuf> {
        (1..=BACKUP_COUNT).map(|i| self.backup(i)).collect()
    }

    /// True if the vault file exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.vault.is_file()
    }
}

/// A cloud storage provider that syncs the directory holding the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    /// Apple iCloud Drive.
    ICloud,
    /// Dropbox.
    Dropbox,
    /// Microsoft OneDrive.
    OneDrive,
    /// Google Drive.
    GoogleDrive,
    /// Syncthing.
    Syncthing,
    /// Recognised as synced, but not which service.
    Unknown,
}

impl CloudProvider {
    /// Display name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ICloud => "iCloud Drive",
            Self::Dropbox => "Dropbox",
            Self::OneDrive => "OneDrive",
            Self::GoogleDrive => "Google Drive",
            Self::Syncthing => "Syncthing",
            Self::Unknown => "a cloud sync folder",
        }
    }
}

/// Detect whether the vault sits in a directory a cloud service syncs.
///
/// Storing an encrypted vault in a synced folder is a legitimate and supported way
/// to get it onto several machines — the file is encrypted before it ever reaches the
/// filesystem. But it has two consequences the user should hear about once:
///
/// * **Version history defeats rollback detection's remedy.** These services keep old
///   revisions, so an attacker with access to the account can restore an older vault.
///   Keel will still *detect* the counter regression and warn, but the attacker gets
///   to try.
/// * **Conflict copies duplicate secrets.** A `vault (conflicted copy).keel` is a
///   second full copy of every password, sitting somewhere the user is not looking.
///
/// Matching is on path components, which is heuristic. A false positive shows one
/// extra informational notice; a false negative shows none. Neither is harmful, so
/// the check errs toward being quiet.
#[must_use]
pub fn detect_cloud_sync(path: &Path) -> Option<CloudProvider> {
    let lowered: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect();

    for component in &lowered {
        // iCloud's real directory name, plus the friendly name Finder shows.
        if component.contains("mobile documents") || component.contains("com~apple~clouddocs") {
            return Some(CloudProvider::ICloud);
        }
        if component.contains("dropbox") {
            return Some(CloudProvider::Dropbox);
        }
        if component.contains("onedrive") {
            return Some(CloudProvider::OneDrive);
        }
        if component.contains("google drive") || component == "googledrive" {
            return Some(CloudProvider::GoogleDrive);
        }
        if component.contains("syncthing") {
            return Some(CloudProvider::Syncthing);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> VaultPaths {
        VaultPaths::new("/home/ada/.local/share/keel/vault.keel").unwrap()
    }

    #[test]
    fn companion_paths_derive_from_the_vault_path() {
        let p = paths();
        assert_eq!(
            p.lock(),
            Path::new("/home/ada/.local/share/keel/vault.keel.lock")
        );
        assert_eq!(
            p.state(),
            Path::new("/home/ada/.local/share/keel/vault.keel.state")
        );
        assert_eq!(
            p.audit(),
            Path::new("/home/ada/.local/share/keel/vault.keel.audit")
        );
        assert_eq!(
            p.backup(1),
            Path::new("/home/ada/.local/share/keel/vault.keel.bak.1")
        );
    }

    #[test]
    fn every_companion_file_shares_the_vault_directory() {
        // The write transaction renames within this directory, and rename is only
        // atomic inside one filesystem.
        let p = paths();
        let dir = p.directory();
        for companion in [p.lock(), p.state(), p.audit(), p.backup(1), p.backup(3)] {
            assert_eq!(
                companion.parent(),
                Some(dir),
                "{companion:?} escaped the directory"
            );
        }
    }

    #[test]
    fn backups_are_listed_most_recent_first() {
        let backups = paths().backups();
        assert_eq!(backups.len(), BACKUP_COUNT);
        assert!(backups[0].to_string_lossy().ends_with(".bak.1"));
        assert!(backups[2].to_string_lossy().ends_with(".bak.3"));
    }

    #[test]
    fn a_renamed_vault_gets_renamed_companions() {
        // The point of deriving rather than configuring: moving a vault must not
        // leave its rollback state pointing at the old file.
        let a = VaultPaths::new("/vaults/work.keel").unwrap();
        let b = VaultPaths::new("/vaults/personal.keel").unwrap();
        assert_ne!(a.state(), b.state());
        assert_ne!(a.audit(), b.audit());
    }

    #[test]
    fn rejects_a_path_that_does_not_name_a_file() {
        assert!(VaultPaths::new("/").is_err());
    }

    #[test]
    fn detects_the_common_cloud_sync_folders() {
        let cases = [
            (
                "/Users/ada/Library/Mobile Documents/com~apple~CloudDocs/vault.keel",
                CloudProvider::ICloud,
            ),
            ("/Users/ada/Dropbox/keel/vault.keel", CloudProvider::Dropbox),
            ("/Users/ada/OneDrive/vault.keel", CloudProvider::OneDrive),
            (
                "/Users/ada/Google Drive/vault.keel",
                CloudProvider::GoogleDrive,
            ),
            ("/home/ada/Syncthing/vault.keel", CloudProvider::Syncthing),
        ];
        for (path, expected) in cases {
            assert_eq!(
                detect_cloud_sync(Path::new(path)),
                Some(expected),
                "failed to detect {path}"
            );
        }
    }

    #[test]
    fn ordinary_locations_are_not_flagged() {
        for path in [
            "/home/ada/.local/share/keel/vault.keel",
            "/Users/ada/Library/Application Support/dev.keel/vault.keel",
            "C:\\Users\\ada\\AppData\\Roaming\\keel\\vault.keel",
        ] {
            assert_eq!(
                detect_cloud_sync(Path::new(path)),
                None,
                "false positive on {path}"
            );
        }
    }

    #[test]
    fn cloud_detection_is_case_insensitive() {
        assert_eq!(
            detect_cloud_sync(Path::new("/Users/ada/DROPBOX/vault.keel")),
            Some(CloudProvider::Dropbox)
        );
    }

    #[test]
    fn default_location_is_derivable_on_this_platform() {
        let p = VaultPaths::default_location().unwrap();
        assert_eq!(p.vault.file_name().unwrap(), DEFAULT_VAULT_NAME);
        assert!(p.vault.is_absolute());
    }
}
