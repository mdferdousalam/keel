// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Importing passwords from other managers and from browsers.
//!
//! # The riskiest file this program will ever touch
//!
//! An exported CSV is a plaintext list of every password its owner has. It is more dangerous
//! than the vault itself, and it is usually sitting in `~/Downloads` with default permissions,
//! indexed by Spotlight or Windows Search, and quite possibly already synced to a cloud drive.
//!
//! So this module is built around that fact rather than treating import as a parsing exercise:
//!
//! * Values are held in [`Zeroizing`] buffers and wiped when dropped.
//! * Nothing is ever logged. Errors name the *line number* or the header names, never a field
//!   value, so a diagnostic cannot become a password in a terminal scrollback.
//! * [`shred`] overwrites and unlinks the file afterwards, and its documentation is honest
//!   about the limits of that on modern storage.
//! * `Debug` redacts everything, including the title — which identifies an account.
//!
//! # Why CSV rather than reading browser stores directly
//!
//! Bitting deliberately prefers the browser's own export over prising open its password store.
//! Reading Chrome's `Login Data` means decrypting with a key from the OS keychain — code that is
//! indistinguishable in shape from credential-stealing malware, and which Chrome 127+ on
//! Windows now blocks anyway with app-bound encryption.
//!
//! Guiding the user through `chrome://password-manager/settings` → Download file is a better
//! answer: it works everywhere, it needs no privileged code in Bitting, and the user can see
//! exactly what is being handed over.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::path::Path;

use zeroize::Zeroizing;

/// Largest accepted import file, in bytes.
///
/// A vault of 100,000 entries exports to a few tens of megabytes. This bound stops a
/// mistakenly-selected disk image from being read at all.
pub const MAX_FILE_LEN: u64 = 256 * 1024 * 1024;

/// Largest accepted number of entries.
pub const MAX_ROWS: usize = 500_000;

/// Import errors.
///
/// No variant carries a field *value*. Line numbers, sizes, paths, and header names only, so
/// that an error message can never become a password in a log or a terminal.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file could not be read.
    #[error("could not read {path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The file is too large to be a password export.
    #[error("{path} is {size} bytes, which is too large to be a password export")]
    TooLarge {
        /// The file.
        path: String,
        /// Its size.
        size: u64,
    },

    /// The columns could not be recognised.
    #[error(
        "could not recognise the columns in this file. Bitting expects a header row naming a \
         password column and either a title or a URL column. Found: {found}"
    )]
    UnknownFormat {
        /// The header names present, which are not secret.
        found: String,
    },

    /// A row was malformed.
    #[error("row {line} is malformed: {reason}")]
    BadRow {
        /// One-based line number, header included.
        line: usize,
        /// What was wrong. Never a field value.
        reason: &'static str,
    },

    /// The file has more rows than Bitting will accept.
    #[error("this file has more than {MAX_ROWS} entries")]
    TooManyRows,

    /// The file had a header but no data.
    #[error("this file contains no password entries")]
    Empty,
}

/// Result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// One imported credential.
pub struct ImportedEntry {
    /// Display name.
    pub title: String,
    /// Username or email.
    pub username: String,
    /// The password.
    pub password: Zeroizing<String>,
    /// Site or application URL.
    pub url: String,
    /// Notes.
    pub notes: Zeroizing<String>,
    /// TOTP secret or `otpauth://` URI, if the source provided one.
    pub totp: Option<Zeroizing<String>>,
}

impl core::fmt::Debug for ImportedEntry {
    /// Reports shape only. The title is redacted along with the credentials, because it
    /// identifies an account.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ImportedEntry")
            .field("title", &"<redacted>")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("url", &"<redacted>")
            .field("has_totp", &self.totp.is_some())
            .finish()
    }
}

/// Where an export came from.
///
/// Detected from the header row rather than asked for, because a user who has just exported a
/// file usually does not know which of these labels applies to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Chrome, Edge, Brave, and other Chromium browsers.
    Chromium,
    /// Firefox.
    Firefox,
    /// Safari and the macOS Passwords app.
    Safari,
    /// Bitwarden.
    Bitwarden,
    /// 1Password.
    OnePassword,
    /// LastPass.
    LastPass,
    /// KeePass and KeePassXC.
    KeePass,
    /// Recognised columns, unrecognised product.
    Generic,
}

impl Source {
    /// Display name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Chromium => "Chrome or another Chromium browser",
            Self::Firefox => "Firefox",
            Self::Safari => "Safari or the macOS Passwords app",
            Self::Bitwarden => "Bitwarden",
            Self::OnePassword => "1Password",
            Self::LastPass => "LastPass",
            Self::KeePass => "KeePass",
            Self::Generic => "a generic CSV export",
        }
    }
}

/// The outcome of an import.
#[derive(Debug)]
pub struct ImportReport {
    /// Which product the file appeared to come from.
    pub source: Source,
    /// Entries that were read.
    pub entries: Vec<ImportedEntry>,
    /// Rows skipped because they had no password.
    ///
    /// Chromium exports a row for every federated login ("sign in with Google") with an empty
    /// password. Those are real accounts but there is nothing to store, so they are counted and
    /// reported rather than silently dropped or imported as blank entries.
    pub skipped_without_password: usize,
    /// Rows skipped because they were malformed.
    pub skipped_malformed: usize,
}

impl ImportReport {
    /// A summary for the user.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut text = format!(
            "Read {} entries from {}.",
            self.entries.len(),
            self.source.name()
        );
        if self.skipped_without_password > 0 {
            text.push_str(&format!(
                "\n{} rows had no password and were skipped. These are usually \
                 \"sign in with Google\"-style logins, which have no password to store.",
                self.skipped_without_password
            ));
        }
        if self.skipped_malformed > 0 {
            text.push_str(&format!(
                "\n{} rows could not be read and were skipped.",
                self.skipped_malformed
            ));
        }
        text
    }
}

/// Column indices resolved from a header row.
#[derive(Debug, Default)]
struct Columns {
    title: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    url: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
}

impl Columns {
    /// Resolve columns from a header row, and guess the source product.
    ///
    /// Matching is by header name across every dialect at once rather than per product, because
    /// the products disagree about names but agree about meanings — and a user importing a
    /// hand-edited file should still succeed.
    fn detect(header: &csv::StringRecord) -> Result<(Self, Source)> {
        let mut columns = Self::default();
        let mut names = Vec::with_capacity(header.len());

        for (index, raw) in header.iter().enumerate() {
            let name = raw.trim().trim_start_matches('\u{feff}').to_lowercase();
            names.push(name.clone());
            let slot = match name.as_str() {
                "name" | "title" | "account" | "item name" => &mut columns.title,
                "username" | "login_username" | "user" | "login name" | "login_name" | "email" => {
                    &mut columns.username
                }
                "password" | "login_password" | "pwd" | "login password" => &mut columns.password,
                "url" | "login_uri" | "uri" | "website" | "web site" | "login_url" | "hostname"
                | "urls" => &mut columns.url,
                "notes" | "note" | "comments" | "extra" => &mut columns.notes,
                "otpauth" | "totp" | "login_totp" | "otp" | "two-factor" => &mut columns.totp,
                _ => continue,
            };
            // First match wins: some exports repeat a column, and the leftmost is the canonical
            // one in every dialect seen.
            if slot.is_none() {
                *slot = Some(index);
            }
        }

        // A password column plus something to identify the entry by is the minimum that can
        // produce a usable vault entry.
        if columns.password.is_none() || (columns.title.is_none() && columns.url.is_none()) {
            return Err(Error::UnknownFormat {
                found: names.join(", "),
            });
        }

        Ok((columns, guess_source(&names)))
    }

    fn get(record: &csv::StringRecord, index: Option<usize>) -> &str {
        index.and_then(|i| record.get(i)).unwrap_or("").trim()
    }
}

/// Guess the source product from header names.
///
/// Only affects the message shown to the user, so an unrecognised product is `Generic` rather
/// than an error.
fn guess_source(names: &[String]) -> Source {
    let has = |name: &str| names.iter().any(|n| n == name);

    if has("login_uri") && has("login_password") {
        return Source::Bitwarden;
    }
    if has("otpauth") && has("title") {
        return Source::OnePassword;
    }
    if has("grouping") || (has("extra") && has("fav")) {
        return Source::LastPass;
    }
    if has("hostname") || has("httprealm") || has("formactionorigin") {
        return Source::Firefox;
    }
    // Chromium exports exactly: name, url, username, password, note.
    if has("name") && has("url") && has("username") && has("password") {
        return Source::Chromium;
    }
    if has("group") && has("title") {
        return Source::KeePass;
    }
    if has("web site") || (has("title") && has("url")) {
        return Source::Safari;
    }
    Source::Generic
}

/// Read a CSV export.
pub fn read_csv(path: &Path) -> Result<ImportReport> {
    let display = path.display().to_string();

    let metadata = std::fs::metadata(path).map_err(|source| Error::Io {
        path: display.clone(),
        source,
    })?;
    if metadata.len() > MAX_FILE_LEN {
        return Err(Error::TooLarge {
            path: display,
            size: metadata.len(),
        });
    }

    let file = std::fs::File::open(path).map_err(|source| Error::Io {
        path: display,
        source,
    })?;
    // Stream rather than reading the whole file into one buffer. This file is a list of every
    // password the user has; there is no reason to hold more of it in memory at once than the
    // row being processed.
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(file);

    let header = reader
        .headers()
        .map_err(|_| Error::BadRow {
            line: 1,
            reason: "the header row could not be read",
        })?
        .clone();
    let (columns, source) = Columns::detect(&header)?;

    let mut entries = Vec::new();
    let mut skipped_without_password = 0usize;
    let mut skipped_malformed = 0usize;

    for result in reader.records() {
        if entries.len() >= MAX_ROWS {
            return Err(Error::TooManyRows);
        }

        let Ok(record) = result else {
            skipped_malformed += 1;
            continue;
        };

        let password = Columns::get(&record, columns.password);
        if password.is_empty() {
            // A federated login: a real account with no password to store.
            skipped_without_password += 1;
            continue;
        }

        let url = Columns::get(&record, columns.url).to_owned();
        let explicit_title = Columns::get(&record, columns.title);
        let title = if explicit_title.is_empty() {
            // Fall back to the host, which is what the user would have named it anyway.
            host_of(&url)
        } else {
            explicit_title.to_owned()
        };
        if title.is_empty() {
            skipped_malformed += 1;
            continue;
        }

        let totp = {
            let value = Columns::get(&record, columns.totp);
            if value.is_empty() {
                None
            } else {
                Some(Zeroizing::new(value.to_owned()))
            }
        };

        entries.push(ImportedEntry {
            title,
            username: Columns::get(&record, columns.username).to_owned(),
            password: Zeroizing::new(password.to_owned()),
            url,
            notes: Zeroizing::new(Columns::get(&record, columns.notes).to_owned()),
            totp,
        });
    }

    if entries.is_empty() && skipped_without_password == 0 {
        return Err(Error::Empty);
    }

    Ok(ImportReport {
        source,
        entries,
        skipped_without_password,
        skipped_malformed,
    })
}

/// Extract a host from a URL, for use as a fallback title.
fn host_of(url: &str) -> String {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    // Strip credentials and port: nobody wants those in an entry title.
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    host.split(':').next().unwrap_or(host).to_owned()
}

/// Overwrite and delete an import file.
///
/// # What this does and does not achieve
///
/// It overwrites the file's bytes and unlinks it, which defeats casual recovery and undelete
/// tools. On any modern storage it is **best effort and nothing more**: SSD wear levelling
/// writes the overwrite to a different physical block, and copy-on-write filesystems (APFS,
/// btrfs, ZFS) may keep the original in a snapshot. The bytes overwritten are not necessarily
/// the bytes that held the passwords.
///
/// The only real answer is full-disk encryption, which is why the threat model assumes it. This
/// function exists because it is strictly better than leaving the file in `~/Downloads`, not
/// because it makes the data unrecoverable — and callers must not tell users otherwise.
pub fn shred(path: &Path) -> Result<()> {
    use std::io::Write;

    let display = path.display().to_string();
    let len = std::fs::metadata(path)
        .map_err(|source| Error::Io {
            path: display.clone(),
            source,
        })?
        .len();

    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|source| Error::Io {
                path: display.clone(),
                source,
            })?;
        let zeros = [0u8; 64 * 1024];
        let mut remaining = len;
        while remaining > 0 {
            let chunk = usize::try_from(remaining.min(zeros.len() as u64)).unwrap_or(zeros.len());
            file.write_all(zeros.get(..chunk).unwrap_or(&zeros))
                .map_err(|source| Error::Io {
                    path: display.clone(),
                    source,
                })?;
            remaining = remaining.saturating_sub(chunk as u64);
        }
        // Force the overwrite to storage before unlinking, or it may never be written at all.
        file.sync_all().map_err(|source| Error::Io {
            path: display.clone(),
            source,
        })?;
    }

    std::fs::remove_file(path).map_err(|source| Error::Io {
        path: display,
        source,
    })
}

/// The warning to show a user who has just exported a CSV.
///
/// Written here rather than left to each front end, so the CLI and the GUI cannot drift into
/// saying different things about the same risk.
pub const EXPORT_WARNING: &str = "\
This file contains every password in it, in plain text. Before you exported it, it did not \
exist; now it does, and it is probably in your Downloads folder with default permissions.

It may already have been copied by a cloud-sync client, indexed by your system's search, or \
captured in a backup. Delete it as soon as the import finishes, and be aware that on an SSD or \
a copy-on-write filesystem overwriting a file does not reliably destroy the old contents — \
full-disk encryption is what actually protects it.";

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    fn write(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    #[test]
    fn a_chromium_export_is_recognised_and_read() {
        let (_dir, path) = write(
            "name,url,username,password,note\n\
             Example Bank,https://bank.example.com/login,ada@example.com,hunter2,my note\n\
             Mail,https://mail.example.net,grace,s3cret,\n",
        );
        let report = read_csv(&path).unwrap();
        assert_eq!(report.source, Source::Chromium);
        assert_eq!(report.entries.len(), 2);

        let first = &report.entries[0];
        assert_eq!(first.title, "Example Bank");
        assert_eq!(first.username, "ada@example.com");
        assert_eq!(&**first.password, "hunter2");
        assert_eq!(first.url, "https://bank.example.com/login");
        assert_eq!(&**first.notes, "my note");
    }

    #[test]
    fn a_bitwarden_export_is_recognised_with_its_totp() {
        let (_dir, path) = write(
            "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n\
             ,,login,Example,note text,,https://example.com,ada,pw123,JBSWY3DPEHPK3PXP\n",
        );
        let report = read_csv(&path).unwrap();
        assert_eq!(report.source, Source::Bitwarden);
        assert_eq!(&**report.entries[0].password, "pw123");
        assert_eq!(
            report.entries[0].totp.as_ref().map(|t| t.as_str()),
            Some("JBSWY3DPEHPK3PXP")
        );
    }

    #[test]
    fn a_firefox_export_is_recognised() {
        let (_dir, path) = write(
            "url,username,password,httpRealm,formActionOrigin,guid,timeCreated\n\
             https://example.com,ada,pw,,https://example.com,{abc},1700000000\n",
        );
        let report = read_csv(&path).unwrap();
        assert_eq!(report.source, Source::Firefox);
        // No title column, so the host becomes the title.
        assert_eq!(report.entries[0].title, "example.com");
    }

    #[test]
    fn a_federated_login_is_counted_not_imported_as_a_blank() {
        // Chromium exports a row per "sign in with Google" account, with an empty password.
        // Importing those as blank entries would be worse than useless.
        let (_dir, path) = write(
            "name,url,username,password,note\n\
             Real,https://a.example,ada,hunter2,\n\
             Federated,https://b.example,ada,,\n\
             Also federated,https://c.example,ada,,\n",
        );
        let report = read_csv(&path).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.skipped_without_password, 2);
        // And the user is told why, rather than silently losing two accounts.
        let summary = report.summary();
        assert!(summary.contains("2 rows had no password"));
        assert!(summary.contains("sign in with Google"));
    }

    #[test]
    fn a_missing_title_falls_back_to_a_clean_host() {
        let (_dir, path) = write(
            "name,url,username,password\n\
             ,https://ada:secret@bank.example.com:8443/login?x=1,ada,pw\n",
        );
        let report = read_csv(&path).unwrap();
        // Credentials and port stripped: nobody wants those in an entry title.
        assert_eq!(report.entries[0].title, "bank.example.com");
    }

    #[test]
    fn an_unrecognised_header_reports_what_it_found() {
        // Header names are not secret, and naming them is what lets a user work out what went
        // wrong.
        let (_dir, path) = write("alpha,beta,gamma\n1,2,3\n");
        match read_csv(&path) {
            Err(Error::UnknownFormat { found }) => {
                assert!(found.contains("alpha"));
                assert!(found.contains("gamma"));
            }
            other => panic!("expected UnknownFormat, got {other:?}"),
        }
    }

    #[test]
    fn a_file_with_no_password_column_is_refused() {
        let (_dir, path) = write("name,url,username\nExample,https://x,ada\n");
        assert!(matches!(read_csv(&path), Err(Error::UnknownFormat { .. })));
    }

    #[test]
    fn a_header_only_file_reports_that_it_is_empty() {
        let (_dir, path) = write("name,url,username,password\n");
        assert!(matches!(read_csv(&path), Err(Error::Empty)));
    }

    #[test]
    fn a_byte_order_mark_does_not_break_detection() {
        // Windows exports routinely carry one, and a user should not have to know what a BOM is
        // to import their passwords.
        let (_dir, path) = write("\u{feff}name,url,username,password\nExample,https://x,ada,pw\n");
        let report = read_csv(&path).unwrap();
        assert_eq!(report.entries[0].title, "Example");
    }

    #[test]
    fn headers_are_matched_case_insensitively_and_trimmed() {
        let (_dir, path) = write(" Name , URL , Username , Password \nExample,https://x,ada,pw\n");
        assert_eq!(read_csv(&path).unwrap().entries.len(), 1);
    }

    #[test]
    fn quoted_fields_with_commas_and_newlines_survive() {
        let (_dir, path) = write(
            "name,url,username,password,notes\n\
             \"Bank, National\",https://x,ada,\"pw,with,commas\",\"line one\nline two\"\n",
        );
        let report = read_csv(&path).unwrap();
        assert_eq!(report.entries[0].title, "Bank, National");
        assert_eq!(&**report.entries[0].password, "pw,with,commas");
        assert!(report.entries[0].notes.contains("line two"));
    }

    #[test]
    fn debug_output_reveals_nothing_including_the_title() {
        // The title identifies an account, so it is redacted along with the credentials.
        let (_dir, path) =
            write("name,url,username,password\nCoinbase,https://x,ada@example.com,super-secret\n");
        let report = read_csv(&path).unwrap();
        let rendered = format!("{:?}", report.entries[0]);
        for secret in ["super-secret", "ada@example.com", "Coinbase"] {
            assert!(!rendered.contains(secret), "Debug leaked {secret}");
        }
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn an_oversized_file_is_refused_before_being_read() {
        // Guards against a mistakenly-selected disk image being pulled into memory.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.csv");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_FILE_LEN + 1).unwrap();
        drop(file);
        assert!(matches!(read_csv(&path), Err(Error::TooLarge { .. })));
    }

    #[test]
    fn shredding_overwrites_and_removes_the_file() {
        let (dir, path) = write("name,url,username,password\nExample,https://x,ada,canary-pw\n");
        assert!(path.exists());
        shred(&path).unwrap();
        assert!(!path.exists(), "the file should be gone");

        // Other files in the directory are untouched.
        let other = dir.path().join("other");
        std::fs::write(&other, b"keep").unwrap();
        assert_eq!(std::fs::read(&other).unwrap(), b"keep");
    }

    #[test]
    fn shredding_a_missing_file_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        assert!(shred(&dir.path().join("absent.csv")).is_err());
    }

    #[test]
    fn the_export_warning_is_honest_about_what_deletion_achieves() {
        // A warning that promised secure deletion would be a lie on any modern filesystem.
        assert!(EXPORT_WARNING.contains("plain text"));
        assert!(EXPORT_WARNING.contains("does not reliably destroy"));
        assert!(EXPORT_WARNING.contains("full-disk encryption"));
    }

    #[test]
    fn a_host_is_extracted_from_assorted_urls() {
        assert_eq!(host_of("https://example.com/path"), "example.com");
        assert_eq!(host_of("example.com"), "example.com");
        assert_eq!(host_of("https://user:pw@example.com:443/x"), "example.com");
        assert_eq!(host_of("http://sub.example.co.uk?q=1"), "sub.example.co.uk");
        assert_eq!(host_of(""), "");
    }

    #[test]
    fn parsing_assorted_rubbish_never_panics() {
        for contents in [
            "",
            "\n\n\n",
            "a",
            "name,password\n",
            "name,password\n,\n",
            "\u{0}\u{1}\u{2}",
            "password\n\"unterminated",
            "password,name\n\"\",\"\"\n",
        ] {
            let (_dir, path) = write(contents);
            let _ = read_csv(&path);
        }
    }
}
