// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

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
pub const MANIFEST_SCHEMA: u16 = 3;

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
    /// Whether AI agents may receive plaintext secrets at all.
    ///
    /// **Off by default, and that default is the product's central claim**: in the shipped
    /// configuration an agent can act with a password and cannot read one. Turning this on
    /// does not make reveals automatic — each one still needs a per-request approval — it
    /// only makes the escalation possible instead of an outright refusal.
    ///
    /// Persisted in the vault rather than held in memory so the answer survives a restart.
    /// A user who deliberately enabled it should not find it silently off tomorrow, and a
    /// user who never touched it should never find it on.
    pub mcp_reveal_enabled: bool,
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
            // The default that makes the headline claim true.
            mcp_reveal_enabled: false,
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
    /// Where the audit log had reached as of the last vault save.
    ///
    /// `None` in a vault that has never been saved with an audit log open.
    pub audit_anchor: Option<AuditAnchor>,
}

/// A commitment to how far the audit log had got, stored inside the manifest.
///
/// # Why this exists
///
/// A hash chain makes editing or removing a record in the *middle* of the log
/// detectable, because every record commits to its predecessor. It does nothing about
/// removing records from the **end**: records 1..k form a perfectly valid chain for any
/// k, so an attacker who does something incriminating and then deletes the last few
/// records leaves a log that verifies cleanly. That is a well-known property of bare
/// append-only chains, and it was a real hole in this design until this type existed —
/// it was found by a test that cut the log one byte at a time and noticed that cutting
/// exactly one whole record produced `Intact`.
///
/// The fix is to keep the expected length and tip somewhere the attacker also has to
/// forge. The manifest is encrypted and authenticated under a subkey of the vault master
/// key, so anyone who can rewrite this anchor can already rewrite the vault, and the
/// audit log is the least of the problems.
///
/// # What it does and does not cover
///
/// The anchor is refreshed when the vault is saved, so it is a **floor**, not an exact
/// count: it proves that at least `seq` records existed, with a given chain tip, as of
/// the last save. Records appended *after* the last save are still removable without
/// detection. Narrowing that window means anchoring more often, which costs a vault
/// write per audit record — so the honest statement, which belongs in the threat model
/// rather than in a footnote, is that tail truncation back to the last vault save is
/// detected and truncation of newer records than that is not.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditAnchor {
    /// Sequence number of the last record the vault has seen.
    pub seq: u64,
    /// Chain hash after that record.
    ///
    /// Checked as well as `seq` so that replacing the tail with a *different* set of
    /// records of the same length is caught too.
    pub tip: [u8; 32],
}

/// Settings as they were before `mcp_reveal_enabled` existed.
#[derive(Serialize, Deserialize)]
struct VaultSettingsV2 {
    autolock_secs: u32,
    clipboard_clear_secs: u32,
    max_session_secs: u32,
    password_history_keep: u32,
    generator: GeneratorDefaults,
    allow_network: bool,
}

impl VaultSettingsV2 {
    fn upgrade(self) -> VaultSettings {
        VaultSettings {
            autolock_secs: self.autolock_secs,
            clipboard_clear_secs: self.clipboard_clear_secs,
            max_session_secs: self.max_session_secs,
            password_history_keep: self.password_history_keep,
            generator: self.generator,
            allow_network: self.allow_network,
            // Off, always. A vault that predates the setting never consented to it, and
            // defaulting it on during a migration would silently weaken every existing
            // vault — the worst possible direction for a default to move on upgrade.
            mcp_reveal_enabled: false,
        }
    }
}

/// The manifest layout at schema 2: `audit_anchor` present, settings without
/// `mcp_reveal_enabled`.
#[derive(Serialize, Deserialize)]
struct ManifestV2 {
    schema: u16,
    entries: Vec<EntryMeta>,
    folders: Vec<Folder>,
    trash: Vec<TrashedEntry>,
    settings: VaultSettingsV2,
    paired_clients: Vec<PairedClient>,
    grants: Vec<PersistedGrant>,
    free_space: Vec<(u64, u64)>,
    audit_anchor: Option<AuditAnchor>,
}

impl ManifestV2 {
    fn decode(unpadded: &[u8]) -> Result<Self> {
        postcard::from_bytes(unpadded)
            .map_err(|_| Error::Malformed("manifest could not be deserialized"))
    }

    fn upgrade(self) -> Manifest {
        Manifest {
            schema: self.schema,
            entries: self.entries,
            folders: self.folders,
            trash: self.trash,
            settings: self.settings.upgrade(),
            paired_clients: self.paired_clients,
            grants: self.grants,
            free_space: self.free_space,
            audit_anchor: self.audit_anchor,
        }
    }
}

/// The manifest layout before `audit_anchor` existed.
///
/// Kept so a vault written by an earlier build still opens. It is deliberately a separate
/// struct rather than an `Option`-with-default trick: postcard encodes an `Option` as a
/// discriminant byte, so a missing trailing field is not the same as a `None` on the wire,
/// and pretending otherwise would misparse rather than fail.
///
/// This is the pattern every future schema bump should follow — read old, write new — and
/// the reason `MANIFEST_SCHEMA` exists as a number rather than a flag.
#[derive(Serialize, Deserialize)]
struct ManifestV1 {
    schema: u16,
    entries: Vec<EntryMeta>,
    folders: Vec<Folder>,
    trash: Vec<TrashedEntry>,
    settings: VaultSettingsV2,
    paired_clients: Vec<PairedClient>,
    grants: Vec<PersistedGrant>,
    free_space: Vec<(u64, u64)>,
}

impl ManifestV1 {
    fn decode(unpadded: &[u8]) -> Result<Self> {
        postcard::from_bytes(unpadded)
            .map_err(|_| Error::Malformed("manifest could not be deserialized"))
    }

    /// Carry a schema-1 manifest forward.
    ///
    /// The schema number is left as it was found. The next save writes
    /// [`MANIFEST_SCHEMA`], so the upgrade happens when the vault is next written rather
    /// than on read — which keeps opening a vault a read-only operation, and means a user
    /// who merely looked at an old vault has not silently changed it.
    fn upgrade(self) -> Manifest {
        Manifest {
            schema: self.schema,
            entries: self.entries,
            folders: self.folders,
            trash: self.trash,
            settings: self.settings.upgrade(),
            paired_clients: self.paired_clients,
            grants: self.grants,
            free_space: self.free_space,
            // No anchor: the old vault never committed to an audit-log length, and
            // inventing one would fabricate evidence about a log it never saw.
            audit_anchor: None,
        }
    }
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
            audit_anchor: None,
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
    pub fn encode_padded(&mut self) -> Result<Vec<u8>> {
        self.validate()?;
        // Writing always stamps the current schema. A manifest read from an older vault
        // keeps its original number until this point, so opening a vault stays a read-only
        // operation — but the bytes about to be written are the *current* layout, and
        // labelling them with the old number would leave a file whose declared schema does
        // not match its shape. That also implements the plan's rule that a save never
        // writes an older version than the code understands.
        self.schema = MANIFEST_SCHEMA;
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
        // Postcard is not self-describing, so a manifest written by an older version has a
        // genuinely different byte layout — a reader cannot skip a field it does not know
        // about, and cannot even find the `schema` field's meaning without committing to a
        // layout first. So the only way to read an old manifest is to try each known layout.
        //
        // Newest first, then older ones in turn. The AEAD tag has already been verified by
        // this point, so these bytes are authentic and the only question is which layout
        // produced them; trying several is not an attack surface, merely a decode attempt
        // that either matches or does not.
        let manifest: Self = match postcard::from_bytes::<Self>(unpadded) {
            Ok(manifest) => manifest,
            // Older layouts, newest first. Schema 2 predates `mcp_reveal_enabled`; schema 1
            // also predates `audit_anchor`. Each upgrade path chooses the *safe* value for
            // a field the old vault never had, never the permissive one.
            Err(_) => match ManifestV2::decode(unpadded) {
                Ok(v2) => v2.upgrade(),
                Err(_) => ManifestV1::decode(unpadded)?.upgrade(),
            },
        };
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

        // Trashed entries keep their records until purged, so they take part in both
        // checks below: a trashed record still occupies bytes and still needs a unique
        // id, or restoring it could read another entry's ciphertext.
        let all_entries = || {
            self.entries
                .iter()
                .chain(self.trash.iter().map(|t| &t.entry))
        };

        // Duplicate record ids would make `entry()` ambiguous and could let one
        // entry's ciphertext be read as another's.
        let mut ids: Vec<&Id> = all_entries().map(|e| &e.record_id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        if ids.len() != before {
            return Err(Error::Malformed("manifest contains duplicate record ids"));
        }

        // Records must not overlap. Overlapping extents would mean two entries
        // sharing ciphertext, which is either corruption or a crafted file.
        let mut extents: Vec<(u64, u64)> = all_entries()
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

    /// Settings in the pre-`mcp_reveal_enabled` shape, for building old manifests in tests.
    fn old_settings(from: &VaultSettings) -> VaultSettingsV2 {
        VaultSettingsV2 {
            autolock_secs: from.autolock_secs,
            clipboard_clear_secs: from.clipboard_clear_secs,
            max_session_secs: from.max_session_secs,
            password_history_keep: from.password_history_keep,
            generator: from.generator,
            allow_network: from.allow_network,
        }
    }

    #[test]
    fn a_schema_1_manifest_still_opens() {
        // The migration that matters. Anyone who built from source before `audit_anchor`
        // existed has a vault in this layout, and a format change that silently refused to
        // open it would look exactly like data loss.
        //
        // Built by serialising the real V1 struct, so the bytes are the old layout rather
        // than an approximation of it.
        let current = sample();
        let v1 = ManifestV1 {
            schema: 1,
            entries: current.entries.clone(),
            folders: current.folders.clone(),
            trash: current.trash.clone(),
            settings: old_settings(&current.settings),
            paired_clients: current.paired_clients.clone(),
            grants: current.grants.clone(),
            free_space: current.free_space.clone(),
        };
        let encoded = postcard::to_allocvec(&v1).unwrap();
        let padded = padding::pad(&encoded, MANIFEST_BLOCK).unwrap();

        let decoded = Manifest::decode_padded(&padded).expect("a schema-1 manifest must open");
        assert_eq!(decoded.entries, current.entries);
        assert_eq!(decoded.settings, current.settings);
        // No anchor, because the old vault never committed to an audit-log length.
        // Inventing one would fabricate evidence about a log it never saw.
        assert_eq!(decoded.audit_anchor, None);
        // The schema is left as found: opening a vault stays read-only.
        assert_eq!(decoded.schema, 1);
    }

    #[test]
    fn reading_old_then_saving_writes_the_current_layout() {
        let current = sample();
        let v1 = ManifestV1 {
            schema: 1,
            entries: current.entries.clone(),
            folders: current.folders.clone(),
            trash: current.trash.clone(),
            settings: old_settings(&current.settings),
            paired_clients: current.paired_clients.clone(),
            grants: current.grants.clone(),
            free_space: current.free_space.clone(),
        };
        let padded = padding::pad(&postcard::to_allocvec(&v1).unwrap(), MANIFEST_BLOCK).unwrap();
        let mut migrated = Manifest::decode_padded(&padded).unwrap();

        let rewritten = migrated.encode_padded().unwrap();
        assert_eq!(migrated.schema, MANIFEST_SCHEMA);
        let reread = Manifest::decode_padded(&rewritten).unwrap();
        assert_eq!(reread.schema, MANIFEST_SCHEMA);
        assert_eq!(reread.entries, current.entries);
    }

    #[test]
    fn a_schema_2_manifest_still_opens_with_agent_reveal_off() {
        // The migration that matters most for safety. A vault written before the setting
        // existed never consented to it, so the upgrade must choose the restrictive value.
        // Defaulting it on would silently weaken every existing vault — the worst direction
        // for a default to move during an upgrade nobody asked for.
        let current = sample();
        let v2 = ManifestV2 {
            schema: 2,
            entries: current.entries.clone(),
            folders: current.folders.clone(),
            trash: current.trash.clone(),
            settings: old_settings(&current.settings),
            paired_clients: current.paired_clients.clone(),
            grants: current.grants.clone(),
            free_space: current.free_space.clone(),
            audit_anchor: Some(AuditAnchor {
                seq: 7,
                tip: [3u8; 32],
            }),
        };
        let padded = padding::pad(&postcard::to_allocvec(&v2).unwrap(), MANIFEST_BLOCK).unwrap();

        let decoded = Manifest::decode_padded(&padded).expect("a schema-2 manifest must open");
        assert_eq!(decoded.entries, current.entries);
        assert!(
            !decoded.settings.mcp_reveal_enabled,
            "a migrated vault must not gain permission to reveal secrets to agents"
        );
        // The anchor it did have must survive, unlike the setting it did not.
        assert_eq!(decoded.audit_anchor.map(|a| a.seq), Some(7));
        assert_eq!(decoded.schema, 2, "reading must not rewrite the schema");
    }

    #[test]
    fn a_schema_1_manifest_also_lands_with_agent_reveal_off() {
        let current = sample();
        let v1 = ManifestV1 {
            schema: 1,
            entries: current.entries.clone(),
            folders: current.folders.clone(),
            trash: current.trash.clone(),
            settings: old_settings(&current.settings),
            paired_clients: current.paired_clients.clone(),
            grants: current.grants.clone(),
            free_space: current.free_space.clone(),
        };
        let padded = padding::pad(&postcard::to_allocvec(&v1).unwrap(), MANIFEST_BLOCK).unwrap();
        let decoded = Manifest::decode_padded(&padded).expect("a schema-1 manifest must open");
        assert!(!decoded.settings.mcp_reveal_enabled);
        assert_eq!(decoded.audit_anchor, None);
    }

    #[test]
    fn the_shipped_default_forbids_revealing_secrets_to_agents() {
        // The single line behind the product's central claim. Worth a test of its own so a
        // change to it cannot pass as an incidental edit to a settings struct.
        assert!(!VaultSettings::default().mcp_reveal_enabled);
    }

    #[test]
    fn round_trips() {
        let mut m = sample();
        let encoded = m.encode_padded().unwrap();
        assert_eq!(Manifest::decode_padded(&encoded).unwrap(), m);
    }

    #[test]
    fn empty_manifest_round_trips() {
        let mut m = Manifest::new();
        let encoded = m.encode_padded().unwrap();
        assert_eq!(Manifest::decode_padded(&encoded).unwrap(), m);
    }

    #[test]
    fn encoded_manifest_is_padded_to_the_manifest_block() {
        let encoded = sample().encode_padded().unwrap();
        assert_eq!(encoded.len() % MANIFEST_BLOCK, 0);
        // A save always writes the current layout, whatever the manifest was read as.
        let mut old = sample();
        old.schema = 1;
        let bytes = old.encode_padded().unwrap();
        assert_eq!(
            old.schema, MANIFEST_SCHEMA,
            "a save must upgrade the schema"
        );
        let unpadded = padding::unpad(&bytes, MANIFEST_BLOCK).unwrap();
        let round_tripped: Manifest = postcard::from_bytes(unpadded).unwrap();
        assert_eq!(round_tripped.schema, MANIFEST_SCHEMA);
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
