//! Wire types for talking to the Keel agent.
//!
//! Types and framing only — no logic, no cryptography, no I/O. This crate is shared by
//! the agent and by every client, so anything that arrived here would arrive in all of
//! them; keeping it a leaf is what lets `keel-client` be provably free of key material.
//!
//! # What travels over the wire
//!
//! The rule that shapes every message below: **a secret crosses this boundary only when a
//! human has deliberately asked for that specific secret to go to that specific place.**
//! Everything else moves as metadata or as an opaque [`EntryRef`].
//!
//! So [`Request::UseSecret`] asks the agent to perform an action *with* a password and
//! comes back with a status, while [`Request::Reveal`] — the one request that returns
//! plaintext — is separately scoped, rate limited, and, for automated clients, subject to
//! per-request human approval. Most clients never send it.
//!
//! # Framing
//!
//! A `u32` little-endian length, then that many bytes of JSON. JSON rather than a compact
//! binary encoding for two reasons: the browser native-messaging transport is already
//! length-prefixed JSON, so this avoids a second format at that boundary; and IPC a
//! maintainer can read with `nc` is worth more here than the bytes saved. The *on-disk*
//! format uses `postcard` precisely because it is not self-describing.
//!
//! [`MAX_FRAME_LEN`] is checked before any allocation.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )
)]

use serde::{Deserialize, Serialize};

/// Protocol version this build speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest accepted frame, in bytes.
///
/// Generous enough for a large entry, small enough that a hostile length prefix cannot be
/// used to exhaust memory. Checked before allocating.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Length of an entry identifier.
pub const ID_LEN: usize = 16;

/// A hex-encoded identifier.
///
/// Hex rather than raw bytes because JSON has no byte type, and rather than base64
/// because a human-readable protocol should stay readable.
pub type IdHex = String;

/// An opaque, session-scoped handle to an entry.
///
/// The indirection matters: a handle is unguessable, meaningless outside the session that
/// issued it, and invalidated when the vault locks. So a transcript captured
/// yesterday — an agent's conversation log, a terminal scrollback — contains nothing an
/// attacker can replay today.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryRef(pub String);

/// What kind of client is connecting.
///
/// Self-declared, and treated as such: the agent uses it to pick *restrictive* defaults,
/// never to grant privilege. A process claiming to be the GUI still has to satisfy the
/// peer-credential check and, for anything sensitive, a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// The desktop application.
    Gui,
    /// The command-line tool.
    Cli,
    /// A browser extension, via the native-messaging host.
    Extension,
    /// An AI agent, via the MCP server.
    Mcp,
}

/// Whether the vault is currently unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    /// Unlocked and usable.
    Unlocked,
    /// Locked; an unlock is required.
    Locked,
    /// No vault exists at the configured path yet.
    NoVault,
}

/// Where a secret should be applied.
///
/// A request, not an instruction: the agent resolves and validates these itself. A browser
/// origin comes from the extension, never from whoever asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretAction {
    /// Copy to the clipboard, cleared automatically.
    Clipboard,
    /// Type into the focused window.
    TypeIntoFocusedWindow,
    /// Fill into a browser tab.
    FillInBrowser {
        /// Page origin **as the browser reported it** — `sender.origin` on a content-script
        /// message, never anything the page said about itself.
        ///
        /// Accepted only from a client the agent has verified is the browser bridge. An AI
        /// agent naming its own destination would defeat the entire point of showing the
        /// destination in an approval dialog.
        origin: String,
    },
}

/// Which field of an entry is wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// The password.
    Password,
    /// The username.
    Username,
    /// A current TOTP code.
    Totp,
    /// The notes field.
    Notes,
}

/// Non-secret metadata about an entry.
///
/// The username is here because search and autofill need it and it is not a secret. The
/// password is not, and there is deliberately no field for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrySummary {
    /// Opaque handle for follow-up requests.
    pub reference: EntryRef,
    /// Display name.
    pub title: String,
    /// Username.
    pub username: String,
    /// Origins this entry may be filled into.
    pub origins: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Whether a TOTP secret exists.
    pub has_totp: bool,
    /// Last modification, Unix seconds.
    pub updated_at: u64,
    /// When the password last changed, Unix seconds.
    pub password_changed_at: u64,
}

/// Non-secret fields for creating or updating an entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInput {
    /// Display name.
    pub title: String,
    /// Username.
    pub username: String,
    /// Origins.
    #[serde(default)]
    pub origins: Vec<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Notes.
    #[serde(default)]
    pub notes: String,
}

/// How a new secret value is supplied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretSource {
    /// The agent generates it.
    ///
    /// Preferred, and the only form an AI agent should normally use: the value is created
    /// inside the agent and never crosses back over the wire, so the caller stores a
    /// password it has never seen.
    Generate {
        /// Length in characters; the vault default is used when absent.
        #[serde(default)]
        length: Option<u32>,
        /// Generate a diceware passphrase of this many words instead.
        #[serde(default)]
        words: Option<u32>,
    },
    /// The caller supplies the value.
    ///
    /// Needed for importing an existing password, and the only case where plaintext
    /// travels *toward* the agent.
    Provided {
        /// The secret value.
        value: String,
    },
}

/// A request to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Announce the client and negotiate the protocol version. Must be first.
    Hello {
        /// Protocol version the client speaks.
        protocol_version: u16,
        /// What kind of client this is.
        client_kind: ClientKind,
        /// Stable client identifier, for policy and the audit log.
        client_id: String,
        /// Client version string, for diagnostics.
        client_version: String,
    },

    /// Report lock state and session information.
    Status,

    /// Create a new vault.
    CreateVault {
        /// Master passphrase.
        passphrase: String,
        /// KDF tier: `interactive`, `balanced`, or `paranoid`.
        #[serde(default)]
        tier: Option<String>,
    },

    /// Unlock the vault.
    Unlock {
        /// Master passphrase.
        passphrase: String,
        /// Keyfile contents, if the vault requires one.
        #[serde(default)]
        keyfile: Option<Vec<u8>>,
        /// Proceed despite a rollback warning.
        ///
        /// Set only after the user has explicitly confirmed, so "I restored a backup"
        /// stays a deliberate act rather than a dialog people learn to dismiss.
        #[serde(default)]
        accept_rollback: bool,
    },

    /// Lock the vault and zeroize keys.
    Lock,

    /// Search entry metadata.
    Search {
        /// Query string.
        query: String,
        /// Maximum results.
        #[serde(default)]
        limit: Option<u32>,
    },

    /// List entry metadata.
    ///
    /// Bounded and offset-based rather than "everything", so it cannot dump a vault in one
    /// call.
    List {
        /// Maximum results.
        #[serde(default)]
        limit: Option<u32>,
        /// Offset for paging.
        #[serde(default)]
        offset: Option<u32>,
    },

    /// Read one entry's metadata.
    GetMetadata {
        /// Entry handle.
        reference: EntryRef,
    },

    /// Apply a secret without receiving it.
    ///
    /// The safe path, and the one automated clients should use: the agent performs the
    /// action and answers with a status.
    UseSecret {
        /// Entry handle.
        reference: EntryRef,
        /// Which field.
        field: Field,
        /// What to do with it.
        action: SecretAction,
    },

    /// Receive a plaintext secret.
    ///
    /// The only request that returns one. Separately scoped, rate limited, and — for
    /// automated clients — subject to per-request human approval.
    Reveal {
        /// Entry handle.
        reference: EntryRef,
        /// Which field.
        field: Field,
        /// Justification, shown to the user as untrusted text.
        #[serde(default)]
        reason: Option<String>,
    },

    /// Create an entry.
    CreateEntry {
        /// Non-secret fields.
        input: EntryInput,
        /// How the password is supplied.
        secret: SecretSource,
    },

    /// Update an entry's non-secret fields.
    UpdateEntry {
        /// Entry handle.
        reference: EntryRef,
        /// Replacement fields.
        input: EntryInput,
    },

    /// Replace an entry's password, keeping the old one in history.
    RotateSecret {
        /// Entry handle.
        reference: EntryRef,
        /// How the new password is supplied.
        secret: SecretSource,
    },

    /// Move an entry to the trash.
    ///
    /// Soft delete only. There is deliberately no hard-delete request: an accidental
    /// permanent deletion can lock someone out of an account for good.
    TrashEntry {
        /// Entry handle.
        reference: EntryRef,
    },

    /// Generate a password without storing it.
    ///
    /// Needs no vault access, so it works while locked.
    GeneratePassword {
        /// Length in characters.
        #[serde(default)]
        length: Option<u32>,
        /// Generate a diceware passphrase of this many words instead.
        #[serde(default)]
        words: Option<u32>,
    },

    /// Save pending changes to disk.
    Save,

    /// Read recent audit records.
    ///
    /// The log is encrypted under a subkey of the vault master key, so it is readable
    /// only while the vault is unlocked — and by exactly the process that could read the
    /// vault anyway.
    AuditTail {
        /// How many records, most recent first. Capped by the agent.
        #[serde(default)]
        limit: Option<u32>,
    },

    /// Entries that may be filled into a page, masked.
    ///
    /// Browser bridge only. The origin comes from the browser, and matching is decided here
    /// rather than in the extension so the rules live in one auditable place — see
    /// [`keel_core::origin`] in the agent for what they are.
    ///
    /// Returns only entries that match. There is deliberately no request that returns every
    /// entry for the extension to filter itself, because that would put the whole vault's
    /// metadata in a browser process on every page load.
    CandidatesForOrigin {
        /// The page origin, from the browser.
        origin: String,
    },

    /// Hand one credential to the browser bridge to fill into a verified page.
    ///
    /// Unlike [`Self::UseSecret`], this **does** return a secret, and saying so plainly is
    /// better than pretending otherwise: the extension has to set the value of an input, so
    /// it necessarily receives it. What makes that acceptable is everything around it — one
    /// credential, for one user gesture, into an origin the agent has checked against the
    /// entry's own stored origins, recorded in the audit log.
    ///
    /// Browser bridge only.
    FillCredential {
        /// Which entry.
        reference: EntryRef,
        /// The page origin, from the browser. Re-checked here against the entry.
        origin: String,
    },

    /// Read the vault's settings.
    ReadSettings,

    /// Change whether AI agents may ever receive plaintext secrets.
    ///
    /// Human-driven clients only, and deliberately its own request rather than part of a
    /// general settings write: this is the single switch behind the claim that an agent
    /// cannot exfiltrate a password, so it should be visible in the protocol, in the audit
    /// log, and in review — not one boolean inside a bag of preferences.
    SetMcpRevealEnabled {
        /// Whether to permit reveals to AI agents at all. Approval is still per request.
        enabled: bool,
    },

    /// List escalations waiting for the user to answer.
    ///
    /// Human-driven clients only. Letting an automated client enumerate pending prompts
    /// would tell it exactly what the user is being shown — the first thing an attacker
    /// would want in order to slip a second request under the same dialog.
    PendingApprovals,

    /// Assess the health of every stored password.
    ///
    /// Only a human-driven client may send this. Producing the report decrypts every
    /// record, and "which of these entries share a password?" answered across the whole
    /// vault is a bulk oracle — exactly what the automated-client tool surface withholds.
    /// The agent enforces that; there is no scope or grant that reaches it.
    VaultHealth,

    /// Export every secret as plaintext.
    ///
    /// Requires the master passphrase again, even though the vault is already unlocked: an
    /// unlocked vault proves only that somebody unlocked it recently, and this is the one
    /// operation that hands over everything at once. Human-driven clients only.
    Export {
        /// The master passphrase, re-entered.
        passphrase: String,
    },

    /// Grant an automated client a set of capabilities.
    ///
    /// Only a human-driven client (the GUI or the CLI) may send this: an agent granting itself
    /// permissions would make the whole scope system decorative. The agent enforces that.
    GrantAccess {
        /// Which client the grant applies to.
        client_id: String,
        /// Capability names: `metadata_read`, `secret_use`, `secret_reveal`, `entry_write`,
        /// `totp_read`, `audit_read`.
        scopes: Vec<String>,
        /// Lifetime in seconds. Capped by the agent.
        #[serde(default)]
        ttl_secs: Option<u64>,
        /// Restrict the grant to entries carrying a tag matching this pattern.
        ///
        /// `None` means every entry, which the CLI requires an explicit flag for: "all my
        /// passwords" deserves more than a default.
        #[serde(default)]
        tag_filter: Option<String>,
    },

    /// List the grants currently in force.
    ListGrants,

    /// Revoke every grant held by a client.
    ///
    /// Always permitted, from any client. Making revocation require permission would be an
    /// obvious mistake.
    RevokeAccess {
        /// Which client.
        client_id: String,
    },

    /// Resolve an outstanding approval request.
    ResolveApproval {
        /// Which request.
        approval_id: String,
        /// The user's answer.
        approved: bool,
    },
}

/// Session information reported by [`Request::Status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
    /// Lock state.
    pub state: LockState,
    /// Vault file path.
    pub vault_path: String,
    /// Scopes this client currently holds.
    pub scopes: Vec<String>,
    /// Seconds until automatic lock, if scheduled.
    pub locks_in: Option<u64>,
    /// Approximate entry count, as a range.
    ///
    /// A bucket rather than an exact number: the precise size of someone's vault is
    /// information an automated client has no need for.
    pub entry_count: Option<String>,
    /// Agent version.
    pub agent_version: String,
    /// Whether hardening measures are fully in force.
    pub hardened: bool,
    /// Human-readable hardening warnings.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Why a request failed.
///
/// A code as well as a message, so a client can react programmatically without matching
/// on prose that may be reworded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The vault is locked.
    Locked,
    /// Unlock failed.
    ///
    /// Deliberately one code for a wrong passphrase, a wrong keyfile, and a tampered
    /// header: distinguishing them would tell an attacker which factor to attack.
    UnlockFailed,
    /// No vault exists at the configured path.
    NoVault,
    /// A vault already exists there.
    VaultExists,
    /// The named entry does not exist, or the handle has expired.
    NotFound,
    /// Refused by policy.
    Denied,
    /// A rate limit or quota was reached.
    RateLimited,
    /// Approval was refused or timed out.
    ApprovalRefused,
    /// The request was malformed.
    BadRequest,
    /// The vault file appears damaged.
    VaultDamaged,
    /// The vault changed on disk; reload before saving.
    Conflict,
    /// Something else failed.
    Internal,
}

impl ErrorCode {
    /// Whether retrying the same request later might succeed.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Conflict)
    }

    /// Whether the client should prompt for an unlock.
    #[must_use]
    pub const fn needs_unlock(self) -> bool {
        matches!(self, Self::Locked)
    }

    /// Process exit code for the CLI.
    ///
    /// Defined here rather than in the CLI so scripts get stable codes and the mapping is
    /// documented in one place.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Locked => 2,
            Self::NotFound => 3,
            Self::Denied | Self::ApprovalRefused | Self::RateLimited => 4,
            _ => 1,
        }
    }
}

/// A response from the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    /// The request succeeded with no data.
    Ok,

    /// Protocol negotiation succeeded.
    Hello {
        /// Protocol version the agent speaks.
        protocol_version: u16,
        /// Agent version string.
        agent_version: String,
    },

    /// Session status.
    Status(Box<StatusInfo>),

    /// Entry metadata.
    Entries {
        /// The entries.
        entries: Vec<EntrySummary>,
        /// True if results were cut off by the limit.
        truncated: bool,
    },

    /// One entry's metadata.
    Entry(Box<EntrySummary>),

    /// A newly created entry.
    Created {
        /// Handle to the new entry.
        reference: EntryRef,
        /// Estimated entropy of the stored password, in bits.
        ///
        /// Returned so a caller that used `Generate` learns the strength of a value it
        /// never saw.
        entropy_bits: Option<f64>,
    },

    /// A secret was applied without being disclosed.
    Applied {
        /// What happened, for the user: "copied to the clipboard, cleared after 15
        /// seconds".
        description: String,
    },

    /// A plaintext secret.
    ///
    /// The only response carrying one. Clients must not log, cache, or store it.
    Secret {
        /// The value.
        value: String,
        /// Seconds after which the caller should discard it.
        expires_in: u64,
    },

    /// A generated password that was not stored.
    Generated {
        /// The value.
        value: String,
        /// Estimated entropy in bits.
        entropy_bits: f64,
    },

    /// Grants currently in force.
    Grants {
        /// The grants.
        grants: Vec<GrantSummary>,
    },

    /// Audit records.
    Audit {
        /// Records, oldest first.
        records: Vec<AuditEntry>,
        /// Whether the hash chain verified, and how it failed if not.
        chain: ChainState,
        /// Total records in the log, which may exceed the number returned.
        total: u64,
    },

    /// One credential, for one verified fill.
    Fill {
        /// Username to type.
        username: String,
        /// Password to type. The only place this protocol hands plaintext to the browser.
        password: String,
        /// The origin the agent verified, echoed so the extension can confirm the page has
        /// not navigated between asking and filling.
        origin: String,
    },

    /// The vault's settings.
    Settings(Box<SettingsView>),

    /// Escalations waiting for the user.
    PendingApprovals {
        /// Oldest first.
        approvals: Vec<PendingApprovalView>,
    },

    /// A vault health report.
    ///
    /// Carries counts, entry titles, and entropy estimates. It carries **no password
    /// value and nothing derived from one** — reuse is reported as "these entries match",
    /// never as what they match on.
    Health {
        /// Entries examined.
        examined: usize,
        /// Entries that stored no password at all.
        without_password: usize,
        /// Entries whose record could not be decrypted.
        unreadable: usize,
        /// Groups of entries sharing a password, largest first.
        reused: Vec<Vec<HealthEntry>>,
        /// Entries below the weak threshold, weakest first.
        weak: Vec<HealthEntry>,
        /// Entries whose password is older than the staleness threshold, oldest first.
        stale: Vec<HealthEntry>,
        /// Distinct entries flagged for any reason.
        flagged: usize,
    },

    /// Every entry, in plaintext.
    ///
    /// The only response in this protocol that deliberately carries secrets in bulk. It
    /// exists because a password manager you cannot leave is a trap; it is reached only
    /// from a human-driven client that has just re-entered the master passphrase.
    Exported {
        /// Every live entry, with its secrets.
        entries: Vec<ExportedEntry>,
    },

    /// The request needs human approval.
    ///
    /// The client should wait; the agent resolves it through the GUI. Carries no secret.
    ApprovalRequired {
        /// Identifier to correlate the eventual outcome.
        approval_id: String,
        /// Seconds before it times out.
        timeout_secs: u64,
    },

    /// The request failed.
    Error {
        /// Machine-readable code.
        code: ErrorCode,
        /// Human-readable explanation.
        message: String,
    },
}

/// A grant, rendered for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSummary {
    /// Which client holds it.
    pub client_id: String,
    /// Capability names.
    pub scopes: Vec<String>,
    /// Tag pattern restricting which entries are covered, if any.
    pub tag_filter: Option<String>,
    /// Absolute expiry, Unix seconds.
    pub expires_at: u64,
    /// Remaining operations before the grant is spent.
    pub uses_remaining: u32,
}

/// Whether an audit log's hash chain verified.
///
/// The distinction between the two failure modes is the point of carrying an enum here
/// rather than a boolean. A log that ends mid-record is almost always an interrupted
/// write — appends are not atomic, and a power failure produces exactly this — whereas a
/// chain that breaks in the *middle* means a record was edited or removed. Reporting the
/// first as tampering would cry wolf over a power cut; reporting the second as
/// truncation would hide an attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ChainState {
    /// Every record verified against its predecessor.
    Intact,
    /// A record was edited or removed at this point. Records before it still verify.
    BrokenAt {
        /// Sequence number where verification failed.
        seq: u64,
    },
    /// The file ends mid-record, usually an interrupted append rather than an attack.
    TruncatedAfter {
        /// Last sequence number that verified.
        seq: u64,
    },
    /// The end of the log does not match what the vault committed to.
    ///
    /// Either records were removed from the end (`found_seq < expected_seq`) or the tail
    /// was rebuilt with the same number of different records (`found_seq == expected_seq`,
    /// different chain tip). Both are invisible to the chain itself, because any prefix of
    /// a chain — and any freshly built chain — verifies. Caught only against what the
    /// vault committed to at its last save.
    ///
    /// An interrupted write leaves a *partial* record and is reported as
    /// [`TruncatedAfter`](Self::TruncatedAfter) instead, so this really is interference.
    TailAltered {
        /// Records the vault expected.
        expected_seq: u64,
        /// Records actually present.
        found_seq: u64,
    },
}

impl ChainState {
    /// Whether this indicates deliberate interference rather than an accident.
    #[must_use]
    pub const fn suggests_tampering(&self) -> bool {
        matches!(self, Self::BrokenAt { .. } | Self::TailAltered { .. })
    }
}

/// One exported entry, secrets included.
///
/// Unlike every other type here, this one is *meant* to carry plaintext. It has no
/// redacting `Debug`: a type whose whole purpose is to be written out as plaintext gains
/// nothing from hiding its contents in a log, and pretending otherwise would suggest a
/// protection that is not there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedEntry {
    /// Display title.
    pub title: String,
    /// Username.
    pub username: String,
    /// Password, in the clear.
    pub password: String,
    /// TOTP secret, in the clear, if there is one.
    pub totp_secret: Option<String>,
    /// Notes.
    pub notes: String,
    /// Origins this entry applies to.
    pub origins: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Creation time, Unix seconds.
    pub created_at: u64,
    /// When the password last changed, Unix seconds.
    pub password_changed_at: u64,
}

/// The vault's settings, as the UI should present them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsView {
    /// Seconds of inactivity before the vault locks.
    pub autolock_secs: u32,
    /// Seconds before a copied secret is cleared from the clipboard.
    pub clipboard_clear_secs: u32,
    /// Hard cap on an unlocked session, regardless of activity.
    pub max_session_secs: u32,
    /// Old passwords kept per entry.
    pub password_history_keep: u32,
    /// Whether any network access is permitted at all.
    pub allow_network: bool,
    /// Whether AI agents may ever receive plaintext. Off in the shipped configuration.
    pub mcp_reveal_enabled: bool,
}

/// An escalation as the approval dialog should present it.
///
/// Every field here is **ground truth from the agent**, not a claim by the requesting
/// client — the entry title comes from the vault, the client kind and executable from the
/// verified peer. The single exception is [`agent_text`](Self::agent_text), which is
/// attacker-controlled by construction and must be rendered as inert text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingApprovalView {
    /// Identifier to pass back when answering.
    pub approval_id: String,
    /// Which client is asking.
    pub client_id: String,
    /// Client category, as a display string.
    pub client_kind: String,
    /// Verified executable path, if known. Shown so a client masquerading under a
    /// registered name is visible by its mismatched path.
    pub executable: Option<String>,
    /// Operation name.
    pub operation: String,
    /// Entry title, read from the vault.
    pub entry_title: Option<String>,
    /// Concrete destination, for actions that send a secret somewhere.
    pub destination: Option<String>,
    /// The requesting client's own justification.
    ///
    /// **Untrusted.** It may be repeating instructions from a web page or a file the agent
    /// read. Already sanitised of control characters, ANSI sequences, bidi overrides, and
    /// zero-width characters by the policy engine, and must still be rendered as plain
    /// text — never as markup, never as a button label, never as app chrome.
    pub agent_text: Option<String>,
    /// How long the Allow control stays disabled, in milliseconds.
    ///
    /// Defeats approval-fatigue click-through and synthetic-click races. A dialog that can
    /// be dismissed the instant it appears is one that gets dismissed without being read.
    pub arm_delay_ms: u64,
    /// Seconds until this escalation times out.
    pub expires_in_secs: u64,
}

/// One entry in a health report.
///
/// Note what is absent: any field that carries or is derived from the password itself.
/// `bits` is a coarse rounded estimate, and `shared_with` is a count of matching
/// entries — neither narrows down the value. A `password` field must never be added
/// here; the whole point of the health report is that it answers questions about
/// secrets without moving them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthEntry {
    /// Opaque handle for this entry, valid for this session.
    pub reference: EntryRef,
    /// Display title.
    pub title: String,
    /// Username, to disambiguate several entries for one site.
    pub username: String,
    /// Estimated entropy in whole bits. A structural lower bound, not a guarantee.
    pub bits: u32,
    /// `critical`, `weak`, or `reasonable`.
    pub strength: String,
    /// Days since the password last changed.
    pub age_days: u64,
    /// How many other entries share this password. Zero when unique.
    pub shared_with: usize,
}

/// One audit record, rendered for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Sequence number.
    pub seq: u64,
    /// Unix seconds.
    pub timestamp: u64,
    /// Which client.
    pub client_id: String,
    /// Operation name.
    pub operation: String,
    /// Outcome.
    pub outcome: String,
    /// Entry id, hex-encoded, if the operation concerned one.
    pub entry: Option<IdHex>,
}

/// An unsolicited message from the agent.
///
/// Lets the tray icon, the extension badge, and `keel status` all reflect one truth
/// instead of each polling and disagreeing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// The lock state changed.
    StateChanged {
        /// New state.
        state: LockState,
        /// Why, if it locked automatically.
        reason: Option<String>,
    },
    /// A client is requesting something that needs approval.
    ApprovalRequested {
        /// Identifier to resolve.
        approval_id: String,
        /// Which client is asking.
        client_id: String,
        /// Client category, as a display string.
        client_kind: String,
        /// Verified executable path, if known.
        executable: Option<String>,
        /// Operation name.
        operation: String,
        /// Entry title, taken from the vault — not from the requesting client.
        entry_title: Option<String>,
        /// Concrete destination description, resolved by the agent.
        destination: Option<String>,
        /// Client-supplied text.
        ///
        /// **Untrusted.** Sanitised of control characters and escape sequences, but the
        /// renderer must still show it as inert plain text in a box labelled as coming
        /// from the client. It must never be styled as though the application said it.
        untrusted_text: Option<String>,
        /// Milliseconds before the confirm control may be used.
        arm_delay_ms: u64,
    },
    /// An approval was resolved.
    ApprovalResolved {
        /// Which request.
        approval_id: String,
        /// The answer.
        approved: bool,
    },
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// A framing or encoding failure.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The frame's declared length exceeds [`MAX_FRAME_LEN`].
    #[error("frame length {found} exceeds the limit")]
    TooLarge {
        /// Declared length.
        found: u64,
    },
    /// More bytes are needed.
    ///
    /// Not an error at the transport level: the caller reads more and tries again.
    #[error("incomplete frame: need {needed} more bytes")]
    Incomplete {
        /// Additional bytes required.
        needed: usize,
    },
    /// The payload was not valid JSON, or not a known message.
    #[error("malformed message: {0}")]
    Malformed(String),
}

/// Encode a value as a length-prefixed JSON frame.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let json = serde_json::to_vec(value).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if json.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge {
            found: json.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&u32::try_from(json.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Decode one frame from the front of `buf`.
///
/// Returns the value and how many bytes were consumed, or [`FrameError::Incomplete`] if
/// more data is needed. The length is checked against [`MAX_FRAME_LEN`] **before** any
/// allocation, so a hostile prefix cannot be used to exhaust memory.
pub fn decode_frame<T: for<'de> Deserialize<'de>>(buf: &[u8]) -> Result<(T, usize), FrameError> {
    let header = buf.get(..4).ok_or(FrameError::Incomplete {
        needed: 4usize.saturating_sub(buf.len()),
    })?;
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(header);
    let len = u32::from_le_bytes(len_bytes) as usize;

    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge { found: len as u64 });
    }
    let end = 4usize
        .checked_add(len)
        .ok_or(FrameError::TooLarge { found: len as u64 })?;
    let payload = buf.get(4..end).ok_or(FrameError::Incomplete {
        needed: end.saturating_sub(buf.len()),
    })?;

    let value =
        serde_json::from_slice(payload).map_err(|e| FrameError::Malformed(e.to_string()))?;
    Ok((value, end))
}

/// Hex-encode an identifier for the wire.
#[must_use]
pub fn id_to_hex(id: &[u8; ID_LEN]) -> IdHex {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(ID_LEN * 2);
    for byte in id {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode a hex-encoded identifier.
pub fn id_from_hex(hex: &str) -> Option<[u8; ID_LEN]> {
    if hex.len() != ID_LEN * 2 {
        return None;
    }
    let mut out = [0u8; ID_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = hex.get(i * 2..i * 2 + 2)?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let requests = vec![
            Request::Hello {
                protocol_version: PROTOCOL_VERSION,
                client_kind: ClientKind::Cli,
                client_id: "keel-cli".to_owned(),
                client_version: "0.1.0".to_owned(),
            },
            Request::Status,
            Request::Lock,
            Request::Search {
                query: "bank".to_owned(),
                limit: Some(10),
            },
            Request::UseSecret {
                reference: EntryRef("abc".to_owned()),
                field: Field::Password,
                action: SecretAction::Clipboard,
            },
            Request::Reveal {
                reference: EntryRef("abc".to_owned()),
                field: Field::Totp,
                reason: Some("logging in".to_owned()),
            },
            Request::CreateEntry {
                input: EntryInput::default(),
                secret: SecretSource::Generate {
                    length: Some(20),
                    words: None,
                },
            },
        ];
        for request in requests {
            let framed = encode_frame(&request).unwrap();
            let (decoded, consumed) = decode_frame::<Request>(&framed).unwrap();
            assert_eq!(decoded, request);
            assert_eq!(consumed, framed.len());
        }
    }

    #[test]
    fn responses_round_trip() {
        let responses = vec![
            Response::Ok,
            Response::Applied {
                description: "copied to the clipboard".to_owned(),
            },
            Response::Error {
                code: ErrorCode::Locked,
                message: "the vault is locked".to_owned(),
            },
            Response::Generated {
                value: "abc".to_owned(),
                entropy_bits: 129.2,
            },
        ];
        for response in responses {
            let framed = encode_frame(&response).unwrap();
            let (decoded, _) = decode_frame::<Response>(&framed).unwrap();
            assert_eq!(decoded, response);
        }
    }

    #[test]
    fn events_round_trip() {
        let event = Event::ApprovalRequested {
            approval_id: "a1".to_owned(),
            client_id: "claude-code".to_owned(),
            client_kind: "AI agent".to_owned(),
            executable: Some("/usr/local/bin/keel-mcp".to_owned()),
            operation: "reveal_secret".to_owned(),
            entry_title: Some("Example Bank".to_owned()),
            destination: None,
            untrusted_text: Some("the user asked me to".to_owned()),
            arm_delay_ms: 750,
        };
        let framed = encode_frame(&event).unwrap();
        let (decoded, _) = decode_frame::<Event>(&framed).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn an_oversized_length_prefix_is_refused_before_allocating() {
        // The property that stops a hostile peer from making us reserve a gigabyte.
        let mut buf = (MAX_FRAME_LEN as u32 + 1).to_le_bytes().to_vec();
        buf.extend_from_slice(b"{}");
        assert!(matches!(
            decode_frame::<Request>(&buf),
            Err(FrameError::TooLarge { .. })
        ));

        let mut huge = u32::MAX.to_le_bytes().to_vec();
        huge.extend_from_slice(b"{}");
        assert!(matches!(
            decode_frame::<Request>(&huge),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_partial_frame_asks_for_more_rather_than_failing() {
        let framed = encode_frame(&Request::Status).unwrap();
        for cut in 0..framed.len() {
            match decode_frame::<Request>(&framed[..cut]) {
                Err(FrameError::Incomplete { .. }) => {}
                other => panic!("truncation to {cut} gave {other:?}"),
            }
        }
        assert!(decode_frame::<Request>(&framed).is_ok());
    }

    #[test]
    fn trailing_bytes_are_left_for_the_next_frame() {
        let mut buf = encode_frame(&Request::Status).unwrap();
        let first_len = buf.len();
        buf.extend_from_slice(&encode_frame(&Request::Lock).unwrap());

        let (first, consumed) = decode_frame::<Request>(&buf).unwrap();
        assert_eq!(first, Request::Status);
        assert_eq!(consumed, first_len);
        let (second, _) = decode_frame::<Request>(&buf[consumed..]).unwrap();
        assert_eq!(second, Request::Lock);
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        let mut buf = 4u32.to_le_bytes().to_vec();
        buf.extend_from_slice(b"nope");
        assert!(matches!(
            decode_frame::<Request>(&buf),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn decoding_arbitrary_bytes_never_panics() {
        for len in [0usize, 1, 3, 4, 5, 100, 1000] {
            for fill in [0u8, 0xFF, 0x7B] {
                let _ = decode_frame::<Request>(&vec![fill; len]);
                let _ = decode_frame::<Response>(&vec![fill; len]);
                let _ = decode_frame::<Event>(&vec![fill; len]);
            }
        }
    }

    #[test]
    fn identifiers_round_trip_through_hex() {
        let id = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let hex = id_to_hex(&id);
        assert_eq!(hex, "00112233445566778899aabbccddeeff");
        assert_eq!(id_from_hex(&hex), Some(id));
    }

    #[test]
    fn bad_hex_identifiers_are_rejected() {
        assert_eq!(id_from_hex(""), None);
        assert_eq!(id_from_hex("abcd"), None);
        assert_eq!(id_from_hex(&"z".repeat(32)), None);
        assert_eq!(id_from_hex(&"a".repeat(31)), None);
        assert_eq!(id_from_hex(&"a".repeat(33)), None);
    }

    #[test]
    fn error_codes_map_to_stable_exit_codes() {
        // Scripts depend on these, so the mapping lives here rather than in the CLI.
        assert_eq!(ErrorCode::Locked.exit_code(), 2);
        assert_eq!(ErrorCode::NotFound.exit_code(), 3);
        assert_eq!(ErrorCode::Denied.exit_code(), 4);
        assert_eq!(ErrorCode::Internal.exit_code(), 1);
        assert!(ErrorCode::Locked.needs_unlock());
        assert!(ErrorCode::RateLimited.is_retryable());
        assert!(ErrorCode::Conflict.is_retryable());
        assert!(!ErrorCode::Denied.is_retryable());
    }

    #[test]
    fn entry_summaries_carry_no_secret_field() {
        // A structural property of the protocol: metadata responses have nowhere to put a
        // password. If someone adds one, this is what should stop them.
        let summary = EntrySummary {
            reference: EntryRef("r".to_owned()),
            title: "t".to_owned(),
            username: "u".to_owned(),
            origins: vec![],
            tags: vec![],
            has_totp: false,
            updated_at: 0,
            password_changed_at: 0,
        };
        // Check the key set rather than substring-matching the JSON: a naive
        // `contains("password")` also matches the perfectly innocent
        // `password_changed_at`, which is a timestamp.
        let value: serde_json::Value = serde_json::to_value(&summary).unwrap();
        let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        for forbidden in ["password", "secret", "value", "totp_secret", "notes"] {
            assert!(
                !keys.iter().any(|k| k.as_str() == forbidden),
                "summaries must not carry a `{forbidden}` field; keys are {keys:?}"
            );
        }
        // The safe metadata fields are present.
        assert!(keys.iter().any(|k| k.as_str() == "has_totp"));
        assert!(keys.iter().any(|k| k.as_str() == "password_changed_at"));
    }

    #[test]
    fn generated_secrets_need_not_cross_back_over_the_wire() {
        // `Generate` exists so an agent can store a strong password it has never seen.
        // The response reports entropy instead of the value.
        let source = SecretSource::Generate {
            length: Some(24),
            words: None,
        };
        let json = serde_json::to_string(&source).unwrap();
        assert!(!json.contains("value"));

        let created = Response::Created {
            reference: EntryRef("r".to_owned()),
            entropy_bits: Some(129.2),
        };
        let json = serde_json::to_string(&created).unwrap();
        assert!(json.contains("entropy_bits"));
        assert!(!json.contains("\"value\""));
    }

    #[test]
    fn a_hello_declares_the_protocol_version() {
        // Version negotiation must be first on the wire, or an old client and a new agent
        // will misinterpret each other's messages.
        let hello = Request::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_kind: ClientKind::Mcp,
            client_id: "agent".to_owned(),
            client_version: "1.0".to_owned(),
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("\"op\":\"hello\""));
        assert!(json.contains("protocol_version"));
    }

    #[test]
    fn approval_events_label_client_text_as_untrusted() {
        // The field name is part of the defence: a UI author reading this struct should be
        // unable to miss that the text is not ours.
        let event = Event::ApprovalRequested {
            approval_id: "a".to_owned(),
            client_id: "c".to_owned(),
            client_kind: "AI agent".to_owned(),
            executable: None,
            operation: "reveal_secret".to_owned(),
            entry_title: None,
            destination: None,
            untrusted_text: Some("hello".to_owned()),
            arm_delay_ms: 750,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("untrusted_text"));
    }
}
