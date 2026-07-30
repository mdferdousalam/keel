//! The vault manifest: encrypted metadata for every entry.
//!
//! The manifest is the only section decrypted at unlock. It holds titles,
//! usernames, origins, tags, and timestamps — everything needed to search and
//! browse — but **no secrets**. Passwords, TOTP seeds, and notes stay encrypted on
//! disk until an individual entry is asked for.
//!
//! Two consequences of that split, both deliberate:
//!
//! * Unlock time is independent of vault size, because only this one blob is
//!   decrypted.
//! * The decrypted footprint stays small, which is the most effective mitigation
//!   available against an attacker running code on an unlocked machine. There is no
//!   moment when every password in the vault is sitting in memory.
//!
//! # Metadata is still sensitive
//!
//! "No secrets" does not mean "not sensitive". Knowing that someone holds an account
//! at a particular bank, or a login for a specific activist forum, can matter as
//! much as the password. So the manifest is fully encrypted, its length is padded
//! into 4 KiB buckets, and the `Debug` impls here redact string content rather than
//! printing it into logs.
//!
//! # How the manifest binds the records
//!
//! Each [`EntryMeta`] stores the offset, length, and BLAKE3 hash of its record's
//! on-disk blob. Because the manifest is itself authenticated under associated data
//! that includes the write counter, this is what detects a record being deleted,
//! duplicated, reordered, or spliced in from a different version of the file — the
//! cases per-record associated data alone cannot catch. See the note in
//! [`crate::header`] on why the record associated data deliberately omits the write
//! counter.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::limits;
use crate::padding::{self, MANIFEST_BLOCK};

/// Schema version for the manifest, independent of the file format version.
pub const MANIFEST_SCHEMA: u16 = 1;

/// Identifier type used for entries, folders, and attachments.
pub type Id = [u8; 16];

/// Redaction helper for `Debug` impls in this module.
fn redacted(s: &str) -> String {
    format!("<{} chars>", s.chars().count())
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// Metadata for one vault entry.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EntryMeta {
    /// Stable identifier, and an input to the record's derived key.
    pub record_id: Id,
    /// Which master-key generation this record is encrypted under.
    pub key_epoch: u32,
    /// BLAKE3 hash of the entire on-disk record blob.
    ///
    /// Covers the record id, key epoch, nonce, ciphertext, and tag — not just the
    /// ciphertext, so tampering with a record's declared id or epoch is caught too.
    ///
    /// This is the anti-splice check: a record moved in from another version of the
    /// file will not match, even though its own AEAD tag verifies perfectly well.
    pub blob_hash: [u8; 32],
    /// Offset of the record blob from the start of the file.
    pub blob_offset: u64,
    /// Total length of the record blob on disk.
    pub blob_len: u32,
    /// Display name.
    pub title: String,
    /// Username, duplicated here so search and autofill need no record decryption.
    pub username: String,
    /// Origins this entry may be filled into.
    ///
    /// Matched exactly, or by registrable domain. Never by wildcard or substring —
    /// see the autofill rules in the threat model.
    pub origins: Vec<String>,
    /// User-assigned tags.
    pub tags: Vec<String>,
    /// Containing folder, if any.
    pub folder_id: Option<Id>,
    /// Creation time, Unix seconds.
    pub created_at: u64,
    /// Last modification time, Unix seconds.
    pub updated_at: u64,
    /// When the password was last changed, Unix seconds.
    ///
    /// Separate from `updated_at` so the audit report can flag stale passwords
    /// without being reset by an unrelated edit to the notes.
    pub password_changed_at: u64,
    /// Whether a TOTP secret is present, so the UI can show the affordance without
    /// decrypting the record.
    pub has_totp: bool,
    /// User-marked favourite.
    pub favorite: bool,
    /// Length of the notes field, for a UI hint. Never the content.
    pub notes_preview_len: u32,
}

impl core::fmt::Debug for EntryMeta {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EntryMeta")
            .field("record_id", &hex_prefix(&self.record_id))
            .field("key_epoch", &self.key_epoch)
            .field("title", &redacted(&self.title))
            .field("username", &redacted(&self.username))
            .field("origins", &self.origins.len())
            .field("tags", &self.tags.len())
            .field("blob_len", &self.blob_len)
            .field("has_totp", &self.has_totp)
            .finish()
    }
}

/// First four bytes of an id, for log correlation without full identification.
fn hex_prefix(id: &Id) -> String {
    id.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

impl EntryMeta {
    fn validate(&self) -> Result<()> {
        if self.title.len() > limits::MAX_STRING_LEN {
            return Err(Error::Malformed("entry title is too long"));
        }
        if self.username.len() > limits::MAX_STRING_LEN {
            return Err(Error::Malformed("entry username is too long"));
        }
        if self.origins.len() > limits::MAX_COLLECTION_LEN {
            return Err(Error::Malformed("entry has too many origins"));
        }
        if self.tags.len() > limits::MAX_COLLECTION_LEN {
            return Err(Error::Malformed("entry has too many tags"));
        }
        for s in self.origins.iter().chain(self.tags.iter()) {
            if s.len() > limits::MAX_STRING_LEN {
                return Err(Error::Malformed("entry origin or tag is too long"));
            }
        }
        if self.blob_len as usize > limits::MAX_RECORD_LEN {
            return Err(Error::Malformed("entry record is too large"));
        }
        Ok(())
    }

    /// The byte range this entry's record occupies.
    pub fn extent(&self) -> Result<(u64, u64)> {
        let end = self
            .blob_offset
            .checked_add(u64::from(self.blob_len))
            .ok_or(Error::Corrupt("record extent overflows"))?;
        Ok((self.blob_offset, end))
    }
}

// ---------------------------------------------------------------------------
// Supporting structures
// ---------------------------------------------------------------------------

/// A folder for organising entries.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Folder {
    /// Folder identifier.
    pub folder_id: Id,
    /// Display name.
    pub name: String,
    /// Parent folder, for nesting.
    pub parent_id: Option<Id>,
}

impl core::fmt::Debug for Folder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Folder")
            .field("folder_id", &hex_prefix(&self.folder_id))
            .field("name", &redacted(&self.name))
            .field("nested", &self.parent_id.is_some())
            .finish()
    }
}

/// A soft-deleted entry awaiting purge.
///
/// Deletion is soft because an accidental delete in a password manager can lock
/// someone out of an account permanently. The record's ciphertext stays in the file
/// until the purge deadline passes.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TrashedEntry {
    /// The entry, preserved so it can be restored intact.
    pub entry: EntryMeta,
    /// When it was moved to trash, Unix seconds.
    pub trashed_at: u64,
    /// When it becomes eligible for permanent deletion, Unix seconds.
    pub purge_after: u64,
}

impl core::fmt::Debug for TrashedEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrashedEntry")
            .field("entry", &self.entry)
            .field("purge_after", &self.purge_after)
            .finish()
    }
}

/// What kind of client a pairing belongs to.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientKind {
    /// A browser extension install.
    BrowserExtension,
    /// A registered MCP client, such as an AI coding agent.
    McpAgent,
}

/// A client that has completed the pairing handshake.
///
/// Persisted so pairings survive a restart, and so the settings UI can list and
/// revoke them. Holds only a public key — the pre-shared key is derived from the
/// vault master key on demand and never stored.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PairedClient {
    /// Stable client identifier (extension id, or a registered agent name).
    pub client_id: String,
    /// Client category, which determines its default policy.
    pub kind: ClientKind,
    /// The client's static public key.
    pub public_key: Vec<u8>,
    /// Human-readable label shown in approval dialogs and settings.
    pub label: String,
    /// When the pairing was created, Unix seconds.
    pub created_at: u64,
    /// When the client last connected, Unix seconds.
    pub last_seen_at: u64,
}

impl core::fmt::Debug for PairedClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PairedClient")
            .field("client_id", &self.client_id)
            .field("kind", &self.kind)
            .field("label", &redacted(&self.label))
            .field("last_seen_at", &self.last_seen_at)
            .finish()
    }
}

/// A capability that can be granted to a client.
///
/// Defined here rather than in `keel-core` because grants are persisted in the
/// manifest, and the on-disk schema belongs with the format. `keel-core` builds its
/// policy engine on top of these.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Search and read non-secret fields.
    MetadataRead,
    /// Act with a secret (fill, copy, type) **without receiving it**.
    ///
    /// The scope that makes AI-agent access safe: an agent can log the user in
    /// without ever seeing the password.
    SecretUse,
    /// Receive plaintext secrets.
    ///
    /// Disabled by default for MCP clients. When enabled it still requires
    /// per-request human approval; this scope only makes the request possible.
    SecretReveal,
    /// Create and update entries.
    EntryWrite,
    /// Read current TOTP codes.
    TotpRead,
    /// Read the audit log.
    AuditRead,
}

impl Scope {
    /// True if holding this scope can result in plaintext leaving the agent process.
    ///
    /// Used to decide which grants need an approval prompt rather than silent
    /// authorization.
    #[must_use]
    pub const fn exposes_plaintext(self) -> bool {
        matches!(self, Self::SecretReveal)
    }
}

/// A grant the user explicitly chose to remember across restarts.
///
/// Ordinary grants live only in memory and die when the vault locks. Only a
/// deliberate "remember this" is persisted, and it still carries an absolute
/// expiry.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PersistedGrant {
    /// Grant identifier.
    pub grant_id: Id,
    /// Which client it applies to.
    pub client_id: String,
    /// Capabilities granted.
    pub scopes: Vec<Scope>,
    /// Tag glob restricting which entries are in scope.
    ///
    /// `None` means unrestricted, which the UI requires a separate confirmation for.
    pub tag_filter: Option<String>,
    /// Absolute expiry, Unix seconds. A persisted grant is never permanent.
    pub expires_at: u64,
    /// When the user approved it, Unix seconds.
    pub granted_at: u64,
}

/// Default password-generator settings, stored per vault.
///
/// Mirrors `keel_crypto::PasswordPolicy` rather than reusing it, so that
/// `keel-crypto` stays free of a serde dependency and no secret-adjacent type in
/// that crate acquires a `Serialize` impl by accident.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneratorDefaults {
    /// Password length in characters.
    pub length: u32,
    /// Include lowercase letters.
    pub lowercase: bool,
    /// Include uppercase letters.
    pub uppercase: bool,
    /// Include digits.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
    /// Exclude easily-confused characters.
    pub exclude_ambiguous: bool,
    /// Default word count for generated passphrases.
    pub passphrase_words: u32,
}

impl Default for GeneratorDefaults {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            passphrase_words: 6,
        }
    }
}

impl GeneratorDefaults {
    /// Convert into a `keel-crypto` policy.
    #[must_use]
    pub fn to_policy(self) -> keel_crypto::PasswordPolicy {
        keel_crypto::PasswordPolicy {
            length: self.length as usize,
            lowercase: self.lowercase,
            uppercase: self.uppercase,
            digits: self.digits,
            symbols: self.symbols,
            exclude_ambiguous: self.exclude_ambiguous,
            require_each_class: false,
        }
    }
}

/// Vault-wide behaviour settings.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultSettings {
    /// Idle seconds before the vault locks itself.
    pub autolock_secs: u32,
    /// Seconds before a copied secret is cleared from the clipboard.
    pub clipboard_clear_secs: u32,
    /// Hard cap on an unlocked session, regardless of activity.
    pub max_session_secs: u32,
    /// How many previous passwords to retain per entry.
    pub password_history_keep: u32,
    /// Default generator settings.
    pub generator: GeneratorDefaults,
    /// Whether any network access is permitted, covering breach checks and update
    /// checks alike.
    ///
    /// One switch rather than several, defaulting to off, so "this program does not
    /// talk to the internet" is a single verifiable statement.
    pub allow_network: bool,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            autolock_secs: 5 * 60,
            clipboard_clear_secs: 15,
            max_session_secs: 8 * 60 * 60,
            password_history_keep: 10,
            generator: GeneratorDefaults::default(),
            allow_network: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// The decrypted vault index.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    /// Manifest schema version.
    pub schema: u16,
    /// All live entries.
    pub entries: Vec<EntryMeta>,
    /// Folder tree.
    pub folders: Vec<Folder>,
    /// Soft-deleted entries awaiting purge.
    pub trash: Vec<TrashedEntry>,
    /// Vault settings.
    pub settings: VaultSettings,
    /// Paired browsers and agents.
    pub paired_clients: Vec<PairedClient>,
    /// Grants the user chose to remember.
    pub grants: Vec<PersistedGrant>,
    /// Free byte ranges in the records section, available for reuse.
    ///
    /// Lets an edited record be written in place when it still fits, so a one-entry
    /// change does not rewrite the whole records section.
    pub free_space: Vec<(u64, u64)>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            schema: MANIFEST_SCHEMA,
            entries: Vec::new(),
            folders: Vec::new(),
            trash: Vec::new(),
            settings: VaultSettings::default(),
            paired_clients: Vec::new(),
            grants: Vec::new(),
            free_space: Vec::new(),
        }
    }
}

impl Manifest {
    /// An empty manifest at the current schema version.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a live entry by record id.
    #[must_use]
    pub fn entry(&self, record_id: &Id) -> Option<&EntryMeta> {
        self.entries.iter().find(|e| &e.record_id == record_id)
    }

    /// Serialize and pad, ready to be encrypted.
    pub fn encode_padded(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let encoded = postcard::to_allocvec(self)
            .map_err(|_| Error::Encode("manifest could not be serialized"))?;
        if encoded.len() > limits::MAX_MANIFEST_LEN {
            return Err(Error::Encode("manifest exceeds the maximum size"));
        }
        padding::pad(&encoded, MANIFEST_BLOCK)
    }

    /// Unpad and deserialize an already-decrypted, already-authenticated manifest.
    pub fn decode_padded(plaintext: &[u8]) -> Result<Self> {
        let unpadded = padding::unpad(plaintext, MANIFEST_BLOCK)?;
        let manifest: Self = postcard::from_bytes(unpadded)
            .map_err(|_| Error::Malformed("manifest could not be deserialized"))?;
        if manifest.schema == 0 || manifest.schema > MANIFEST_SCHEMA {
            return Err(Error::Malformed(
                "manifest uses an unsupported schema version",
            ));
        }
        manifest.validate()?;
        Ok(manifest)
    }

    /// Check structural invariants and size limits.
    pub fn validate(&self) -> Result<()> {
        if self.entries.len() > limits::MAX_ENTRIES {
            return Err(Error::TooLarge {
                what: "entry count",
                found: self.entries.len() as u64,
                limit: limits::MAX_ENTRIES as u64,
            });
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        for trashed in &self.trash {
            trashed.entry.validate()?;
        }

        // Duplicate record ids would make `entry()` ambiguous and could let one
        // entry's ciphertext be read as another's.
        let mut ids: Vec<&Id> = self.entries.iter().map(|e| &e.record_id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        if ids.len() != before {
            return Err(Error::Malformed("manifest contains duplicate record ids"));
        }

        // Records must not overlap. Overlapping extents would mean two entries
        // sharing ciphertext, which is either corruption or a crafted file.
        let mut extents: Vec<(u64, u64)> = self
            .entries
            .iter()
            .map(EntryMeta::extent)
            .collect::<Result<_>>()?;
        extents.sort_unstable();
        // Pattern-match rather than index. `windows(2)` always yields pairs, so
        // indexing would be correct — but this parser must contain no panic paths at
        // all, because "provably cannot panic here" degrades into "used to be able to
        // reason about it" after a few refactors.
        for pair in extents.windows(2) {
            if let [(_, first_end), (second_start, _)] = *pair {
                if second_start < first_end {
                    return Err(Error::Malformed(
                        "manifest entries claim overlapping records",
                    ));
                }
            }
        }

        if self.folders.len() > limits::MAX_COLLECTION_LEN * 16 {
            return Err(Error::Malformed("too many folders"));
        }
        for folder in &self.folders {
            if folder.name.len() > limits::MAX_STRING_LEN {
                return Err(Error::Malformed("folder name is too long"));
            }
        }
        if self.paired_clients.len() > limits::MAX_COLLECTION_LEN {
            return Err(Error::Malformed("too many paired clients"));
        }
        if self.grants.len() > limits::MAX_COLLECTION_LEN {
            return Err(Error::Malformed("too many persisted grants"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u8, offset: u64, len: u32) -> EntryMeta {
        EntryMeta {
            record_id: [id; 16],
            key_epoch: 0,
            blob_hash: [id; 32],
            blob_offset: offset,
            blob_len: len,
            title: format!("Example {id}"),
            username: "ada@example.com".to_owned(),
            origins: vec!["https://example.com".to_owned()],
            tags: vec!["work".to_owned()],
            folder_id: None,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
            password_changed_at: 1_700_000_000,
            has_totp: true,
            favorite: false,
            notes_preview_len: 12,
        }
    }

    fn sample() -> Manifest {
        let mut m = Manifest::new();
        m.entries.push(entry(1, 0, 256));
        m.entries.push(entry(2, 256, 512));
        m.folders.push(Folder {
            folder_id: [9; 16],
            name: "Banking".to_owned(),
            parent_id: None,
        });
        m.paired_clients.push(PairedClient {
            client_id: "chrome-abcdef".to_owned(),
            kind: ClientKind::BrowserExtension,
            public_key: vec![7; 32],
            label: "Chrome on this Mac".to_owned(),
            created_at: 1_700_000_000,
            last_seen_at: 1_700_000_500,
        });
        m.grants.push(PersistedGrant {
            grant_id: [3; 16],
            client_id: "claude-code".to_owned(),
            scopes: vec![Scope::MetadataRead, Scope::SecretUse],
            tag_filter: Some("work/*".to_owned()),
            expires_at: 1_700_100_000,
            granted_at: 1_700_000_000,
        });
        m
    }

    #[test]
    fn round_trips() {
        let m = sample();
        let encoded = m.encode_padded().unwrap();
        assert_eq!(Manifest::decode_padded(&encoded).unwrap(), m);
    }

    #[test]
    fn empty_manifest_round_trips() {
        let m = Manifest::new();
        let encoded = m.encode_padded().unwrap();
        assert_eq!(Manifest::decode_padded(&encoded).unwrap(), m);
    }

    #[test]
    fn encoded_manifest_is_padded_to_the_manifest_block() {
        let encoded = sample().encode_padded().unwrap();
        assert_eq!(encoded.len() % MANIFEST_BLOCK, 0);
    }

    #[test]
    fn entry_debug_redacts_titles_and_usernames() {
        // Metadata is not a secret, but it identifies accounts, so it must not land
        // in a log line verbatim.
        let rendered = format!("{:?}", entry(1, 0, 256));
        assert!(!rendered.contains("ada@example.com"));
        assert!(!rendered.contains("Example 1"));
        assert!(!rendered.contains("example.com"));
        assert!(rendered.contains("chars"));
    }

    #[test]
    fn folder_and_client_debug_redact_names() {
        let m = sample();
        let folders = format!("{:?}", m.folders);
        assert!(!folders.contains("Banking"));
        let clients = format!("{:?}", m.paired_clients);
        assert!(!clients.contains("Chrome on this Mac"));
        // The client id is an opaque identifier and is useful for correlation.
        assert!(clients.contains("chrome-abcdef"));
    }

    #[test]
    fn rejects_duplicate_record_ids() {
        let mut m = Manifest::new();
        m.entries.push(entry(1, 0, 128));
        m.entries.push(entry(1, 128, 128));
        assert!(matches!(m.validate(), Err(Error::Malformed(_))));
    }

    #[test]
    fn rejects_overlapping_record_extents() {
        // Two entries claiming the same bytes is either corruption or a crafted
        // file; either way it must not be silently accepted.
        let mut m = Manifest::new();
        m.entries.push(entry(1, 0, 512));
        m.entries.push(entry(2, 256, 512));
        assert!(matches!(m.validate(), Err(Error::Malformed(_))));
    }

    #[test]
    fn accepts_adjacent_non_overlapping_records() {
        let mut m = Manifest::new();
        m.entries.push(entry(1, 0, 256));
        m.entries.push(entry(2, 256, 256));
        m.entries.push(entry(3, 512, 256));
        m.validate().unwrap();
    }

    #[test]
    fn rejects_an_extent_that_overflows() {
        let mut m = Manifest::new();
        let mut e = entry(1, u64::MAX - 10, 256);
        e.blob_offset = u64::MAX - 10;
        m.entries.push(e);
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_oversized_strings() {
        let mut m = Manifest::new();
        let mut e = entry(1, 0, 128);
        e.title = "x".repeat(limits::MAX_STRING_LEN + 1);
        m.entries.push(e);
        assert!(matches!(m.validate(), Err(Error::Malformed(_))));
    }

    #[test]
    fn rejects_an_unsupported_schema_version() {
        let mut m = Manifest::new();
        m.schema = MANIFEST_SCHEMA + 1;
        let encoded = postcard::to_allocvec(&m).unwrap();
        let padded = padding::pad(&encoded, MANIFEST_BLOCK).unwrap();
        assert!(matches!(
            Manifest::decode_padded(&padded),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn decoding_garbage_errors_rather_than_panicking() {
        for len in [0usize, 1, 4, MANIFEST_BLOCK, MANIFEST_BLOCK * 2] {
            let buf = vec![0xFFu8; len];
            let _ = Manifest::decode_padded(&buf);
        }
    }

    #[test]
    fn lookup_finds_entries_by_id() {
        let m = sample();
        assert!(m.entry(&[1; 16]).is_some());
        assert!(m.entry(&[99; 16]).is_none());
    }

    #[test]
    fn default_settings_are_conservative() {
        let s = VaultSettings::default();
        assert_eq!(s.autolock_secs, 300);
        assert_eq!(s.clipboard_clear_secs, 15);
        assert_eq!(s.max_session_secs, 8 * 3600);
        // Network access off by default is the whole basis of the "local only"
        // claim, so it is asserted rather than assumed.
        assert!(!s.allow_network);
    }

    #[test]
    fn only_reveal_scope_exposes_plaintext() {
        assert!(Scope::SecretReveal.exposes_plaintext());
        for scope in [
            Scope::MetadataRead,
            Scope::SecretUse,
            Scope::EntryWrite,
            Scope::TotpRead,
            Scope::AuditRead,
        ] {
            assert!(
                !scope.exposes_plaintext(),
                "{scope:?} must not be treated as exposing plaintext"
            );
        }
    }

    #[test]
    fn generator_defaults_convert_to_a_valid_policy() {
        let policy = GeneratorDefaults::default().to_policy();
        assert_eq!(policy.length, 20);
        assert_eq!(policy.alphabet_size(), 88);
        keel_crypto::generate_password(&policy).unwrap();
    }
}
