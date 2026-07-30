//! The policy engine: one place where every request is allowed, denied, or escalated.
//!
//! Every client — the desktop app, the CLI, a browser extension, an AI agent over
//! MCP — comes through here. Having one chokepoint rather than per-client checks is
//! deliberate: a security review can read this file and know the whole authorization
//! story, and a new client cannot arrive with more access than intended, because an
//! unknown client type has no scopes at all.
//!
//! # The core insight about AI agents
//!
//! An agent almost never needs to *see* a password — it needs the password to be
//! *used*. So [`Scope::SecretUse`] lets a client trigger a fill, a copy, or a keystroke
//! sequence while the plaintext never leaves the agent process, and
//! [`Scope::SecretReveal`] — the only scope that hands over plaintext — is disabled by
//! default for MCP clients and requires per-request human approval even when enabled.
//!
//! The consequence, which is the security story for the whole MCP feature: **in the
//! default configuration an agent can log you into things and manage entries, and
//! cannot exfiltrate a single password even if it is entirely controlled by an
//! attacker.**
//!
//! # Defending against prompt injection
//!
//! A compromised agent is not hypothetical; an agent that read a malicious web page is
//! an attacker holding a legitimate session. So:
//!
//! * **No enumeration.** There is no list-everything operation, search needs at least
//!   two characters, and a per-hour cap on *distinct entries touched* means working
//!   through the vault one entry at a time trips the limit just the same.
//! * **Agent-supplied text is data, never instructions.** [`sanitize_reason`] strips
//!   control characters, escape sequences, and bidirectional overrides, and the UI
//!   renders the result as inert text labelled as agent-supplied.
//! * **Approval dialogs state ground truth**, taken from the vault and the verified
//!   client identity — never from what the agent claimed.
//! * **A circuit breaker** revokes everything for a client after repeated denials, so a
//!   scripted hunt for an unguarded path ends the session rather than continuing.
//!
//! What this cannot defend against is a user who approves everything. The default-deny
//! focus and the mandatory delay before a confirm button arms fight approval fatigue;
//! they cannot cure it, and the threat model says so.

use std::collections::{BTreeMap, BTreeSet};

use keel_format::manifest::Id;
pub use keel_format::manifest::{ClientKind, PersistedGrant, Scope};

/// Default grant lifetime, in seconds.
pub const DEFAULT_GRANT_TTL: u64 = 15 * 60;

/// Longest a grant may live, in seconds.
///
/// Matches the hard session cap: a grant must never outlive the unlocked session that
/// authorised it.
pub const MAX_GRANT_TTL: u64 = 8 * 60 * 60;

/// Default number of reveals a single grant permits.
pub const DEFAULT_MAX_REVEALS: u32 = 3;

/// Default number of operations a single grant permits.
pub const DEFAULT_MAX_USES: u32 = 25;

/// Longest accepted agent-supplied reason string, in characters.
pub const MAX_REASON_CHARS: usize = 200;

/// Maximum distinct entries whose secrets one automated client may touch per hour.
///
/// The anti-enumeration backstop. Rate limits bound *requests*; this bounds *coverage*,
/// so an agent that patiently works through the vault one new entry at a time still
/// cannot drain it.
///
/// Counts every secret-touching operation — reveal, use, and TOTP read — not just
/// reveals. Counting reveals alone would have made this dead code, since reveals are
/// separately capped at five per hour and so could never reach fifty; a TOTP read is
/// limited to sixty per hour, which is what makes the cap reachable and therefore real.
///
/// Applies only to [`ClientType::Extension`] and [`ClientType::Mcp`]. A human browsing
/// their own vault through the GUI or CLI is not enumerating it, and throttling them
/// would be a bug rather than a protection.
pub const MAX_DISTINCT_ENTRIES_PER_HOUR: usize = 50;

/// Maximum reveals one client may have approved per hour.
///
/// Far tighter than the coverage cap because reveal is the only operation that hands
/// plaintext to a caller. Named rather than inlined so the relationship to
/// [`MAX_DISTINCT_ENTRIES_PER_HOUR`] can be enforced at compile time below.
pub const MAX_REVEALS_PER_HOUR: u32 = 5;

// The reveal limit must stay well under the coverage cap. If they ever crossed, the
// coverage cap would be unreachable through reveals and the two constants would silently
// be describing different things — which is exactly the inconsistency that made an
// earlier version of the coverage cap dead code.
const _: () = assert!(
    (MAX_REVEALS_PER_HOUR as usize) < MAX_DISTINCT_ENTRIES_PER_HOUR,
    "the reveal rate limit must be lower than the coverage cap"
);

/// Minimum length of a search query.
///
/// One character would let 26 queries enumerate most of a vault.
pub const MIN_SEARCH_CHARS: usize = 2;

/// Maximum search results returned in one response.
pub const MAX_SEARCH_RESULTS: usize = 25;

/// Denials within the breaker window before a client loses everything.
pub const BREAKER_DENIAL_THRESHOLD: u32 = 3;

/// Breaker observation window, in seconds.
pub const BREAKER_WINDOW: u64 = 5 * 60;

/// Delay before an approval dialog's confirm button becomes usable, in milliseconds.
///
/// Defeats both approval-fatigue click-through and a synthetic click arriving in the
/// same frame the dialog appears.
pub const APPROVAL_ARM_DELAY_MS: u64 = 750;

/// How long an approval request waits for a human, in seconds.
pub const APPROVAL_TIMEOUT: u64 = 120;

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

/// What kind of client is asking.
///
/// Determines default scopes. An enum rather than a string compared at the call site,
/// so an unrecognised client cannot be mistaken for a privileged one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClientType {
    /// The desktop application: a human at a keyboard, and the only client that can
    /// display approval dialogs.
    Gui,
    /// The command-line tool: also a human, at a terminal.
    Cli,
    /// A paired browser extension.
    Extension,
    /// An AI agent over MCP.
    Mcp,
}

impl ClientType {
    /// Scopes this client type holds without an explicit grant.
    ///
    /// The GUI and CLI represent a human who has already proved possession of the
    /// passphrase, so they hold everything. The extension gets metadata and use — the
    /// autofill path — but never reveal. An MCP client starts with **nothing**.
    #[must_use]
    pub fn default_scopes(self) -> BTreeSet<Scope> {
        match self {
            Self::Gui | Self::Cli => [
                Scope::MetadataRead,
                Scope::SecretUse,
                Scope::SecretReveal,
                Scope::EntryWrite,
                Scope::TotpRead,
                Scope::AuditRead,
            ]
            .into_iter()
            .collect(),
            Self::Extension => [Scope::MetadataRead, Scope::SecretUse, Scope::TotpRead]
                .into_iter()
                .collect(),
            Self::Mcp => BTreeSet::new(),
        }
    }

    /// Whether this client type may ever hold [`Scope::SecretReveal`].
    ///
    /// The extension is excluded permanently: autofill never needs plaintext to cross
    /// the browser boundary, so a hostile page attacking the extension must not find a
    /// path that returns one.
    #[must_use]
    pub const fn may_hold_reveal(self) -> bool {
        matches!(self, Self::Gui | Self::Cli | Self::Mcp)
    }

    /// Whether this client speaks for a human who can answer a prompt directly.
    ///
    /// An MCP request escalates to the GUI instead; if no GUI is attached the request
    /// **fails closed** rather than being auto-approved.
    #[must_use]
    pub const fn can_prompt_user(self) -> bool {
        matches!(self, Self::Gui | Self::Cli)
    }

    /// Whether this client is a human driving the application directly.
    ///
    /// The coverage cap applies only to the ones that are not: a person scrolling their
    /// own vault is not enumerating it, and throttling them would be a bug.
    #[must_use]
    pub const fn is_human_driven(self) -> bool {
        matches!(self, Self::Gui | Self::Cli)
    }

    /// Human-readable name for dialogs and the audit log.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gui => "desktop app",
            Self::Cli => "command line",
            Self::Extension => "browser extension",
            Self::Mcp => "AI agent",
        }
    }
}

/// A connected client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// Stable identifier: an extension id, or a registered agent name.
    pub id: String,
    /// Client category.
    pub client_type: ClientType,
    /// Verified path to the client's executable, where the platform allows it.
    ///
    /// Shown in approval dialogs, so a process claiming to be `claude-code` from an
    /// unexpected location is visible. Time-of-check/time-of-use means this is
    /// evidence, not proof, and the threat model says so.
    pub executable: Option<String>,
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// What a client is asking to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Read lock state and scope information. Always answerable.
    Status,
    /// Search entry metadata.
    Search {
        /// Length of the query in characters.
        query_len: usize,
    },
    /// Read one entry's non-secret fields.
    ReadMetadata {
        /// Entry concerned.
        entry: Id,
    },
    /// Act with a secret without receiving it.
    UseSecret {
        /// Entry concerned.
        entry: Id,
        /// Where the secret is going, for the approval dialog.
        destination: Destination,
    },
    /// Receive a plaintext secret.
    RevealSecret {
        /// Entry concerned.
        entry: Id,
        /// Agent-supplied justification, sanitised before display.
        reason: String,
    },
    /// Read a current TOTP code.
    ReadTotp {
        /// Entry concerned.
        entry: Id,
    },
    /// Create or modify an entry.
    Write {
        /// Entry concerned, if it already exists.
        entry: Option<Id>,
    },
    /// Read the audit log.
    ReadAudit,
    /// Generate a password. Needs no vault access at all.
    GeneratePassword,
    /// Assess the health of every stored password.
    ///
    /// Uniquely bulk: producing the report decrypts every record in the vault. It
    /// returns statistics rather than values, but "which of these entries share a
    /// password?" answered over the whole vault is still a bulk oracle, and it is
    /// exactly the shape of question the tool surface is built to withhold from
    /// automated clients. So this is not gated by a scope that a grant could supply
    /// — it is restricted to human-driven clients outright. See
    /// [`Operation::requires_human_client`].
    VaultHealth,
    /// Export every secret in the vault as plaintext.
    ///
    /// The most dangerous operation Keel has: it produces, in one place, exactly the file
    /// an attacker would want. It exists anyway, because a password manager you cannot get
    /// your data out of is a trap, and the alternative to a supported export is users
    /// screenshotting their passwords one at a time.
    ///
    /// Restricted to human-driven clients, like [`Self::VaultHealth`], and additionally
    /// gated on re-entering the master passphrase — which the agent enforces, since an
    /// unlocked vault only proves somebody unlocked it, not that the owner is at the
    /// keyboard now.
    ExportVault,
}

impl Operation {
    /// The scope this operation requires, if any.
    #[must_use]
    pub const fn required_scope(&self) -> Option<Scope> {
        match self {
            // Status reports lock state; generation is fresh randomness. Neither reads
            // vault data, so neither needs a scope.
            // VaultHealth is deliberately not scope-gated: no grant can confer it,
            // because it is refused by client type before scopes are consulted.
            Self::Status | Self::GeneratePassword | Self::VaultHealth | Self::ExportVault => None,
            Self::Search { .. } | Self::ReadMetadata { .. } => Some(Scope::MetadataRead),
            Self::UseSecret { .. } => Some(Scope::SecretUse),
            Self::RevealSecret { .. } => Some(Scope::SecretReveal),
            Self::ReadTotp { .. } => Some(Scope::TotpRead),
            Self::Write { .. } => Some(Scope::EntryWrite),
            Self::ReadAudit => Some(Scope::AuditRead),
        }
    }

    /// Whether this operation may only be performed by a client a human is driving.
    ///
    /// Separate from the scope system on purpose. A scope is something a user can
    /// grant, and the whole point here is that this is not grantable to an automated
    /// client at all — there is no combination of approvals that lets an MCP server
    /// or a browser extension enumerate which passwords are shared.
    #[must_use]
    pub const fn requires_human_client(&self) -> bool {
        matches!(self, Self::VaultHealth | Self::ExportVault)
    }

    /// The entry this operation concerns, if any.
    #[must_use]
    pub const fn entry(&self) -> Option<&Id> {
        match self {
            Self::ReadMetadata { entry }
            | Self::UseSecret { entry, .. }
            | Self::RevealSecret { entry, .. }
            | Self::ReadTotp { entry } => Some(entry),
            Self::Write { entry } => entry.as_ref(),
            _ => None,
        }
    }

    /// Short label for rate-limit bookkeeping and the audit log.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Search { .. } => "search",
            Self::ReadMetadata { .. } => "read_metadata",
            Self::UseSecret { .. } => "use_secret",
            Self::RevealSecret { .. } => "reveal_secret",
            Self::ReadTotp { .. } => "read_totp",
            Self::Write { .. } => "write",
            Self::ReadAudit => "read_audit",
            Self::GeneratePassword => "generate_password",
            Self::VaultHealth => "vault_health",
            Self::ExportVault => "export_vault",
        }
    }
}

/// Where a secret is about to go.
///
/// Resolved by the agent process, never taken from the requesting client. An injected
/// agent must not be able to name its own destination, because the destination is the
/// one thing a user actually reads before approving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// The system clipboard, cleared after the given number of seconds.
    Clipboard {
        /// Seconds until the clipboard is cleared.
        clear_after: u32,
    },
    /// Typed into the focused window.
    TypeIntoWindow {
        /// Window title, for the dialog.
        window: String,
    },
    /// Filled into a browser tab.
    FillInBrowser {
        /// Origin resolved through the extension, not supplied by the client.
        origin: String,
        /// Browser name.
        browser: String,
    },
}

impl Destination {
    /// A concrete description for the approval dialog.
    ///
    /// Deliberately specific. "Allow access to your password?" tells a user nothing;
    /// "filled into: Chrome — https://chase.com/login" lets them notice the destination
    /// is wrong.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Clipboard { clear_after } => {
                format!("copied to the clipboard, cleared after {clear_after} seconds")
            }
            Self::TypeIntoWindow { window } => format!("typed into: {window}"),
            Self::FillInBrowser { origin, browser } => {
                format!("filled into: {browser} — {origin}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// Which entries a grant applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryFilter {
    /// Every entry.
    ///
    /// Requires its own extra confirmation in the UI, separate from the scope approval:
    /// "all my passwords" deserves more than one click.
    All,
    /// Entries carrying a tag matching this pattern.
    TagGlob(String),
    /// An explicit list of entries.
    Explicit(BTreeSet<Id>),
}

impl EntryFilter {
    /// Whether an entry with the given tags is in scope.
    #[must_use]
    pub fn matches(&self, entry: &Id, tags: &[String]) -> bool {
        match self {
            Self::All => true,
            Self::TagGlob(pattern) => tags.iter().any(|tag| glob_match(pattern, tag)),
            Self::Explicit(ids) => ids.contains(entry),
        }
    }
}

/// Match a tag against a pattern supporting a single trailing `*`.
///
/// Deliberately minimal. A full glob implementation would be another dependency and
/// another parser, and `work/*` covers what users actually ask for. More expressive
/// patterns are also harder for a user to reason about at the moment of approval, which
/// matters more here than flexibility.
fn glob_match(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

/// A capability grant issued to one client.
#[derive(Debug, Clone)]
pub struct Grant {
    /// Grant identifier.
    pub id: Id,
    /// Client this applies to.
    pub client_id: String,
    /// Capabilities granted.
    pub scopes: BTreeSet<Scope>,
    /// Entries in scope.
    pub filter: EntryFilter,
    /// Absolute expiry, Unix seconds.
    pub expires_at: u64,
    /// Reveals permitted in total.
    pub max_reveals: u32,
    /// Reveals used so far.
    pub reveals_used: u32,
    /// Operations permitted in total.
    pub max_uses: u32,
    /// Operations used so far.
    pub uses_used: u32,
    /// The text the user actually saw when approving.
    ///
    /// Kept so "what did I agree to?" has an answer that does not depend on
    /// reconstructing it from a scope list.
    pub reason_shown: String,
}

impl Grant {
    /// Create a grant with the default limits.
    #[must_use]
    pub fn new(
        id: Id,
        client_id: impl Into<String>,
        scopes: BTreeSet<Scope>,
        filter: EntryFilter,
        now: u64,
        ttl: u64,
    ) -> Self {
        Self {
            id,
            client_id: client_id.into(),
            scopes,
            filter,
            expires_at: now.saturating_add(ttl.min(MAX_GRANT_TTL)),
            max_reveals: DEFAULT_MAX_REVEALS,
            reveals_used: 0,
            max_uses: DEFAULT_MAX_USES,
            uses_used: 0,
            reason_shown: String::new(),
        }
    }

    /// Whether this grant is still valid.
    #[must_use]
    pub const fn is_live(&self, now: u64) -> bool {
        now < self.expires_at && self.uses_used < self.max_uses
    }

    /// How many reveals remain.
    #[must_use]
    pub const fn reveals_remaining(&self) -> u32 {
        self.max_reveals.saturating_sub(self.reveals_used)
    }
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// What the user is being asked to approve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Client identifier as registered.
    pub client_id: String,
    /// Client category.
    pub client_type: ClientType,
    /// Verified executable path, if known.
    pub executable: Option<String>,
    /// Operation label.
    pub operation: &'static str,
    /// Entry concerned.
    pub entry: Option<Id>,
    /// Where a secret would go, if applicable.
    pub destination: Option<Destination>,
    /// Sanitised agent-supplied text.
    ///
    /// Must be rendered as inert plain text in a box labelled as agent-supplied. It was
    /// written by something that may be under an attacker's control, and must never be
    /// styled as though the application were saying it.
    pub agent_text: Option<String>,
    /// Milliseconds before the confirm button becomes usable.
    pub arm_delay_ms: u64,
    /// Seconds before the request times out as a denial.
    pub timeout_secs: u64,
}

/// The outcome of a policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Proceed.
    Allow,
    /// Refuse, with a reason the client may see.
    Deny {
        /// Why.
        reason: String,
        /// Whether this counted toward the circuit breaker.
        counted: bool,
    },
    /// Ask the user.
    Ask(Box<ApprovalRequest>),
}

impl Decision {
    /// Was this a refusal?
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
            counted: true,
        }
    }

    /// A refusal that does not count toward the circuit breaker.
    ///
    /// For conditions the client cannot avoid — a locked vault, no GUI attached — so
    /// that ordinary operation never trips a security response.
    fn deny_uncounted(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
            counted: false,
        }
    }
}

/// Strip anything from agent-supplied text that could impersonate the application.
///
/// Removes control characters and escape sequences — which could otherwise rewrite a
/// terminal line, hide text, or inject colour so agent text looks like a system
/// prompt — strips bidirectional overrides that can visually reverse a string,
/// collapses whitespace, and truncates.
///
/// Markdown and HTML are deliberately **not** stripped, because the renderer must not
/// interpret them in the first place. Sanitising markup here would imply that rendering
/// it is otherwise acceptable.
#[must_use]
pub fn sanitize_reason(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_REASON_CHARS));
    let mut last_was_space = false;
    let mut chars = raw.chars().peekable();

    while let Some(ch) = chars.next() {
        // Escape sequences must be removed whole, not just the ESC byte. Dropping ESC
        // alone from "\x1b[31m" leaves the literal text "[31m", which is both noise and
        // a way to construct misleading strings out of what looks like sanitised text.
        if ch == '\u{1b}' {
            match chars.peek() {
                // CSI: ESC [ params intermediates final, where final is 0x40..=0x7E.
                Some('[') => {
                    chars.next();
                    for follow in chars.by_ref() {
                        if ('\u{40}'..='\u{7E}').contains(&follow) {
                            break;
                        }
                    }
                }
                // OSC: ESC ] ... terminated by BEL or ESC \.
                Some(']') => {
                    chars.next();
                    while let Some(follow) = chars.next() {
                        if follow == '\u{7}' {
                            break;
                        }
                        if follow == '\u{1b}' {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                // Any other two-character escape.
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }

        let is_dangerous = ch.is_control()
            || matches!(ch, '\u{2028}' | '\u{2029}')
            // Bidirectional overrides and isolates, which can visually reverse text so
            // the dialog reads as something other than what it says.
            || ('\u{202A}'..='\u{202E}').contains(&ch)
            || ('\u{2066}'..='\u{2069}').contains(&ch)
            // Zero-width and invisible formatting characters, which can hide content or
            // make two different strings look identical.
            || matches!(ch, '\u{200B}'..='\u{200F}' | '\u{FEFF}' | '\u{00AD}');
        if is_dangerous {
            continue;
        }
        if ch.is_whitespace() {
            if !last_was_space && !out.is_empty() {
                out.push(' ');
                last_was_space = true;
            }
            continue;
        }
        last_was_space = false;
        out.push(ch);
        if out.chars().count() >= MAX_REASON_CHARS {
            break;
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

// ---------------------------------------------------------------------------
// Rate limiting and the circuit breaker
// ---------------------------------------------------------------------------

/// Per-operation rate limits, as (max events, window in seconds).
///
/// Limits are per **client type**, because the same number means very different things
/// for a person and for a script:
///
/// * **Human-driven clients (GUI, CLI) have no limits.** The human is the rate limit.
///   An early version applied the agent limits everywhere, which capped the desktop app
///   at ten clipboard copies an hour — unusable, and a protection against nothing, since
///   a person with the passphrase can already read the whole vault.
/// * **The extension gets generous but finite limits.** Autofill is user-gesture driven,
///   and someone working through a backlog of logins can legitimately fill dozens in an
///   hour. Limits here exist to bound a *compromised* extension, not to ration normal
///   use.
/// * **MCP clients get tight limits.** An agent has no natural pace, and a
///   prompt-injected one will use every request it is given.
const fn rate_limit(client_type: ClientType, operation: &Operation) -> Option<(u32, u64)> {
    // A person cannot be usefully rate-limited, and trying makes the app worse without
    // making it safer.
    if client_type.is_human_driven() {
        return None;
    }
    let generous = matches!(client_type, ClientType::Extension);
    match operation {
        Operation::Search { .. } => Some(if generous { (240, 60) } else { (60, 60) }),
        Operation::UseSecret { .. } => Some(if generous { (120, 3600) } else { (10, 3600) }),
        // Reveal stays tight even for the extension — which cannot hold the scope at
        // all — so the number is a backstop rather than a working limit.
        Operation::RevealSecret { .. } => Some((MAX_REVEALS_PER_HOUR, 3600)),
        Operation::Write { .. } => Some(if generous { (60, 3600) } else { (20, 3600) }),
        Operation::ReadTotp { .. } => Some(if generous { (120, 3600) } else { (60, 3600) }),
        // Metadata reads follow a search that is already limited, and status is free.
        // Limiting them would break a responsive UI for no security gain; coverage is
        // bounded by MAX_DISTINCT_ENTRIES_PER_HOUR instead.
        _ => None,
    }
}

/// Timestamps of recent events.
#[derive(Debug, Default, Clone)]
struct EventLog {
    events: Vec<u64>,
}

impl EventLog {
    fn record(&mut self, now: u64) {
        self.events.push(now);
    }

    fn count_since(&self, cutoff: u64) -> u32 {
        u32::try_from(self.events.iter().filter(|&&t| t >= cutoff).count()).unwrap_or(u32::MAX)
    }

    fn prune(&mut self, cutoff: u64) {
        self.events.retain(|&t| t >= cutoff);
    }
}

/// Per-client enforcement state.
#[derive(Debug, Default, Clone)]
struct ClientState {
    rates: BTreeMap<&'static str, EventLog>,
    denials: EventLog,
    /// Distinct entries whose secrets were touched, with the time first touched.
    touched_entries: BTreeMap<Id, u64>,
    /// True once the breaker has tripped; cleared only by a fresh unlock.
    tripped: bool,
    /// Whether a reveal approval is currently outstanding.
    reveal_in_flight: bool,
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// Authorization state for one unlocked session.
///
/// Dropped when the vault locks, which is what makes every non-persisted grant vanish
/// on lock without any explicit cleanup step to forget.
#[derive(Debug, Default)]
pub struct PolicyEngine {
    grants: Vec<Grant>,
    clients: BTreeMap<String, ClientState>,
    /// Whether reveal is available to MCP clients at all.
    ///
    /// Off by default. This is the setting behind the claim that an agent cannot
    /// exfiltrate a password in the shipped configuration.
    mcp_reveal_enabled: bool,
    /// Whether a GUI session is attached and able to show approval dialogs.
    gui_attached: bool,
}

impl PolicyEngine {
    /// A fresh engine with the shipped defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable reveal for MCP clients.
    pub fn set_mcp_reveal_enabled(&mut self, enabled: bool) {
        self.mcp_reveal_enabled = enabled;
    }

    /// Whether reveal is enabled for MCP clients.
    #[must_use]
    pub const fn mcp_reveal_enabled(&self) -> bool {
        self.mcp_reveal_enabled
    }

    /// Record whether a GUI session capable of showing dialogs is attached.
    pub fn set_gui_attached(&mut self, attached: bool) {
        self.gui_attached = attached;
    }

    /// Issue a grant.
    pub fn add_grant(&mut self, grant: Grant) {
        self.grants.push(grant);
    }

    /// Revoke one grant.
    ///
    /// Always permitted from any client: making revocation itself require permission
    /// would be an obvious mistake.
    pub fn revoke_grant(&mut self, grant_id: &Id) -> bool {
        let before = self.grants.len();
        self.grants.retain(|g| &g.id != grant_id);
        self.grants.len() != before
    }

    /// Revoke every grant held by a client.
    pub fn revoke_client(&mut self, client_id: &str) -> usize {
        let before = self.grants.len();
        self.grants.retain(|g| g.client_id != client_id);
        before.saturating_sub(self.grants.len())
    }

    /// Live grants for a client.
    #[must_use]
    pub fn grants_for(&self, client_id: &str, now: u64) -> Vec<&Grant> {
        self.grants
            .iter()
            .filter(|g| g.client_id == client_id && g.is_live(now))
            .collect()
    }

    /// Effective scopes for a client: its defaults plus anything granted.
    ///
    /// The hard ceilings are enforced here rather than trusted from the grant, because
    /// a grant is data that may have been persisted by an older version or edited on
    /// disk.
    #[must_use]
    pub fn effective_scopes(&self, client: &Client, now: u64) -> BTreeSet<Scope> {
        let mut scopes = client.client_type.default_scopes();
        for grant in self.grants_for(&client.id, now) {
            scopes.extend(grant.scopes.iter().copied());
        }
        if !client.client_type.may_hold_reveal() {
            scopes.remove(&Scope::SecretReveal);
        }
        if client.client_type == ClientType::Mcp && !self.mcp_reveal_enabled {
            scopes.remove(&Scope::SecretReveal);
        }
        scopes
    }

    /// Whether the circuit breaker has tripped for a client.
    #[must_use]
    pub fn is_tripped(&self, client_id: &str) -> bool {
        self.clients.get(client_id).is_some_and(|s| s.tripped)
    }

    /// Reset a client's breaker. Called only after a fresh unlock.
    pub fn reset_breaker(&mut self, client_id: &str) {
        if let Some(state) = self.clients.get_mut(client_id) {
            state.tripped = false;
            state.denials = EventLog::default();
        }
    }

    /// Decide whether an operation may proceed.
    ///
    /// `entry_tags` supplies the tags of the entry concerned so a tag-filtered grant can
    /// be evaluated. The caller looks them up, because the engine holds no vault.
    pub fn check(
        &mut self,
        client: &Client,
        operation: &Operation,
        entry_tags: &[String],
        now: u64,
    ) -> Decision {
        let decision = self.evaluate(client, operation, entry_tags, now);
        match &decision {
            Decision::Deny { counted: true, .. } => self.record_denial(&client.id, now),
            Decision::Allow => self.record_success(&client.id, operation, now),
            // An escalation is recorded when it resolves, not when it is raised —
            // otherwise a user who refuses a prompt would also consume the quota.
            _ => {}
        }
        decision
    }

    fn evaluate(
        &mut self,
        client: &Client,
        operation: &Operation,
        entry_tags: &[String],
        now: u64,
    ) -> Decision {
        // Always answerable: a client that cannot discover it is locked out has no way
        // to tell the user why nothing is working.
        if matches!(operation, Operation::Status) {
            return Decision::Allow;
        }

        if self.is_tripped(&client.id) {
            return Decision::deny_uncounted(
                "access for this client was suspended after repeated refused requests; \
                 unlock the vault again to restore it",
            );
        }

        // Generation reads no vault data, so an agent can produce a strong password
        // without holding any access.
        if matches!(operation, Operation::GeneratePassword) {
            return Decision::Allow;
        }

        // Checked before scopes, so no grant can route around it.
        if operation.requires_human_client() && !client.client_type.is_human_driven() {
            return Decision::deny(format!(
                "the {} cannot perform {}; it reads every record, so it is available \
                 only from the Keel app or the command line",
                client.client_type.name(),
                operation.label().replace('_', " ")
            ));
        }

        if let Operation::Search { query_len } = operation {
            if *query_len < MIN_SEARCH_CHARS {
                return Decision::deny(format!(
                    "search needs at least {MIN_SEARCH_CHARS} characters"
                ));
            }
        }

        let Some(required) = operation.required_scope() else {
            return Decision::Allow;
        };
        let scopes = self.effective_scopes(client, now);
        if !scopes.contains(&required) {
            // Be specific about a missing reveal scope: "disabled by default, here is
            // the alternative" is actionable, whereas "denied" is not.
            if required == Scope::SecretReveal {
                if !client.client_type.may_hold_reveal() {
                    return Decision::deny(
                        "this client type is never permitted to receive plaintext secrets",
                    );
                }
                if client.client_type == ClientType::Mcp && !self.mcp_reveal_enabled {
                    return Decision::deny(
                        "revealing secrets to AI agents is disabled; enable it in \
                         Settings if you need it, or use an action that applies the \
                         secret without exposing it",
                    );
                }
            }
            return Decision::deny(format!("missing required permission: {required:?}"));
        }

        // A scope held only by grant must also pass that grant's entry filter.
        if !client.client_type.default_scopes().contains(&required) {
            let entry = operation.entry();
            let permitted = self.grants_for(&client.id, now).into_iter().any(|grant| {
                grant.scopes.contains(&required)
                    && entry.is_none_or(|id| grant.filter.matches(id, entry_tags))
            });
            if !permitted {
                return Decision::deny("no active grant covers this entry");
            }
        }

        if let Some(decision) = self.check_rate_limit(client, operation, now) {
            return decision;
        }

        // Every operation that touches a secret counts toward the coverage cap.
        if matches!(
            operation,
            Operation::RevealSecret { .. }
                | Operation::UseSecret { .. }
                | Operation::ReadTotp { .. }
        ) {
            if let Some(entry) = operation.entry() {
                if let Some(decision) = self.check_coverage(client, entry, now) {
                    return decision;
                }
            }
        }

        // Reveals get the extra treatment on top: one at a time, and a human in the loop.
        if let Operation::RevealSecret { entry, reason } = operation {
            if let Some(decision) = self.check_reveal_in_flight(&client.id) {
                return decision;
            }
            if !client.client_type.can_prompt_user() {
                if !self.gui_attached {
                    // Fail closed. Auto-approving because nobody is reachable would
                    // invert the entire point of the approval step.
                    return Decision::deny_uncounted(
                        "revealing a secret needs your approval, and Keel's window is \
                         not open; open Keel and try again",
                    );
                }
                return Decision::Ask(Box::new(ApprovalRequest {
                    client_id: client.id.clone(),
                    client_type: client.client_type,
                    executable: client.executable.clone(),
                    operation: operation.label(),
                    entry: Some(*entry),
                    destination: None,
                    agent_text: Some(sanitize_reason(reason)).filter(|s| !s.is_empty()),
                    arm_delay_ms: APPROVAL_ARM_DELAY_MS,
                    timeout_secs: APPROVAL_TIMEOUT,
                }));
            }
        }

        Decision::Allow
    }

    fn check_rate_limit(
        &mut self,
        client: &Client,
        operation: &Operation,
        now: u64,
    ) -> Option<Decision> {
        let (max, window) = rate_limit(client.client_type, operation)?;
        let cutoff = now.saturating_sub(window);
        let state = self.clients.entry(client.id.clone()).or_default();
        let log = state.rates.entry(operation.label()).or_default();
        log.prune(cutoff);
        if log.count_since(cutoff) >= max {
            return Some(Decision::deny(format!(
                "rate limit reached for this operation ({max} per {window} seconds)"
            )));
        }
        None
    }

    /// Enforce the coverage cap: how much of the vault an automated client may touch.
    ///
    /// Independent of the request rate limits, which bound how *often* a client asks.
    /// This bounds how *much* it reaches, which is the measure that matters for
    /// enumeration.
    fn check_coverage(&mut self, client: &Client, entry: &Id, now: u64) -> Option<Decision> {
        if client.client_type.is_human_driven() {
            return None;
        }
        let cutoff = now.saturating_sub(3600);
        let state = self.clients.entry(client.id.clone()).or_default();
        state.touched_entries.retain(|_, &mut t| t >= cutoff);

        if !state.touched_entries.contains_key(entry)
            && state.touched_entries.len() >= MAX_DISTINCT_ENTRIES_PER_HOUR
        {
            return Some(Decision::deny(format!(
                "this client has already accessed {MAX_DISTINCT_ENTRIES_PER_HOUR} \
                 different entries in the last hour"
            )));
        }
        None
    }

    /// Enforce the one-reveal-at-a-time rule.
    fn check_reveal_in_flight(&mut self, client_id: &str) -> Option<Decision> {
        let state = self.clients.entry(client_id.to_owned()).or_default();
        if state.reveal_in_flight {
            return Some(Decision::deny(
                "another reveal is already awaiting approval",
            ));
        }
        None
    }

    fn record_success(&mut self, client_id: &str, operation: &Operation, now: u64) {
        {
            let state = self.clients.entry(client_id.to_owned()).or_default();
            state
                .rates
                .entry(operation.label())
                .or_default()
                .record(now);
            if matches!(
                operation,
                Operation::RevealSecret { .. }
                    | Operation::UseSecret { .. }
                    | Operation::ReadTotp { .. }
            ) {
                if let Some(entry) = operation.entry() {
                    state.touched_entries.entry(*entry).or_insert(now);
                }
            }
        }
        // Consume one use from the soonest-expiring live grant covering this operation.
        if let Some(required) = operation.required_scope() {
            if let Some(grant) = self
                .grants
                .iter_mut()
                .filter(|g| {
                    g.client_id == client_id && g.is_live(now) && g.scopes.contains(&required)
                })
                .min_by_key(|g| g.expires_at)
            {
                grant.uses_used = grant.uses_used.saturating_add(1);
                if required == Scope::SecretReveal {
                    grant.reveals_used = grant.reveals_used.saturating_add(1);
                }
            }
        }
    }

    fn record_denial(&mut self, client_id: &str, now: u64) {
        let cutoff = now.saturating_sub(BREAKER_WINDOW);
        let tripped = {
            let state = self.clients.entry(client_id.to_owned()).or_default();
            state.denials.prune(cutoff);
            state.denials.record(now);
            if state.denials.count_since(cutoff) >= BREAKER_DENIAL_THRESHOLD {
                // Trip rather than merely throttle: a client probing for an unguarded
                // path should have its session ended, not slowed down.
                state.tripped = true;
            }
            state.tripped
        };
        if tripped {
            self.revoke_client(client_id);
        }
    }

    /// Mark that a reveal approval is outstanding for a client.
    pub fn begin_reveal_approval(&mut self, client_id: &str) {
        self.clients
            .entry(client_id.to_owned())
            .or_default()
            .reveal_in_flight = true;
    }

    /// Resolve an outstanding reveal approval.
    ///
    /// A denial counts toward the breaker, so a client that repeatedly asks for things
    /// the user refuses loses its session.
    pub fn resolve_reveal_approval(
        &mut self,
        client: &Client,
        entry: &Id,
        approved: bool,
        now: u64,
    ) {
        self.clients
            .entry(client.id.clone())
            .or_default()
            .reveal_in_flight = false;

        if approved {
            let operation = Operation::RevealSecret {
                entry: *entry,
                reason: String::new(),
            };
            self.record_success(&client.id, &operation, now);
        } else {
            self.record_denial(&client.id, now);
        }
    }

    /// Convert live grants into the persisted form.
    ///
    /// Only grants the user explicitly chose to remember should be passed here; the rest
    /// are session-scoped by design.
    #[must_use]
    pub fn persistable(&self, now: u64) -> Vec<PersistedGrant> {
        self.grants
            .iter()
            .filter(|g| g.is_live(now))
            .map(|g| PersistedGrant {
                grant_id: g.id,
                client_id: g.client_id.clone(),
                scopes: g.scopes.iter().copied().collect(),
                tag_filter: match &g.filter {
                    EntryFilter::TagGlob(p) => Some(p.clone()),
                    _ => None,
                },
                expires_at: g.expires_at,
                granted_at: now,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;
    const ENTRY: Id = [1; 16];

    #[test]
    fn a_vault_health_check_is_refused_to_automated_clients() {
        // The report decrypts every record and answers "which entries share a
        // password?" over the whole vault. That is a bulk oracle, and no approval
        // should be able to hand it to something a human is not driving.
        for client_type in [ClientType::Mcp, ClientType::Extension] {
            let mut engine = PolicyEngine::new();
            let decision = engine.check(&client(client_type), &Operation::VaultHealth, &[], 0);
            assert!(
                matches!(decision, Decision::Deny { .. }),
                "{client_type:?} should be refused, got {decision:?}"
            );
        }
    }

    #[test]
    fn a_vault_health_check_is_allowed_from_the_app_and_the_command_line() {
        for client_type in [ClientType::Gui, ClientType::Cli] {
            let mut engine = PolicyEngine::new();
            assert_eq!(
                engine.check(&client(client_type), &Operation::VaultHealth, &[], 0),
                Decision::Allow,
                "{client_type:?} should be allowed"
            );
        }
    }

    #[test]
    fn no_grant_can_confer_a_vault_health_check() {
        // The gate is checked before scopes precisely so that granting an agent
        // everything still does not reach it. If this ever fails, the check has been
        // moved below scope resolution.
        let mut engine = PolicyEngine::new();
        let mcp = client(ClientType::Mcp);
        engine.add_grant(Grant {
            id: [9u8; 16],
            client_id: mcp.id.clone(),
            scopes: [
                Scope::MetadataRead,
                Scope::SecretUse,
                Scope::SecretReveal,
                Scope::EntryWrite,
                Scope::TotpRead,
                Scope::AuditRead,
            ]
            .into_iter()
            .collect(),
            filter: EntryFilter::All,
            expires_at: 10_000,
            max_reveals: u32::MAX,
            reveals_used: 0,
            max_uses: u32::MAX,
            uses_used: 0,
            reason_shown: "everything".to_owned(),
        });
        let decision = engine.check(&mcp, &Operation::VaultHealth, &[], 0);
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "a grant of every scope must still not reach a health check, got {decision:?}"
        );
    }

    fn client(client_type: ClientType) -> Client {
        Client {
            id: format!("test-{}", client_type.name()),
            client_type,
            executable: Some("/usr/local/bin/keel-mcp".to_owned()),
        }
    }

    fn engine_with_gui() -> PolicyEngine {
        let mut e = PolicyEngine::new();
        e.set_gui_attached(true);
        e
    }

    fn reveal(entry: Id) -> Operation {
        Operation::RevealSecret {
            entry,
            reason: "the user asked me to log in".to_owned(),
        }
    }

    fn use_secret(entry: Id) -> Operation {
        Operation::UseSecret {
            entry,
            destination: Destination::FillInBrowser {
                origin: "https://example.com".to_owned(),
                browser: "Chrome".to_owned(),
            },
        }
    }

    fn grant(client: &Client, scopes: &[Scope]) -> Grant {
        Grant::new(
            [9; 16],
            &client.id,
            scopes.iter().copied().collect(),
            EntryFilter::All,
            NOW,
            DEFAULT_GRANT_TTL,
        )
    }

    // ---- defaults ---------------------------------------------------------

    #[test]
    fn an_mcp_client_starts_with_no_scopes_at_all() {
        assert!(ClientType::Mcp.default_scopes().is_empty());
    }

    #[test]
    fn reveal_is_disabled_for_agents_by_default() {
        // The claim the whole MCP design rests on.
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        e.add_grant(grant(&c, &[Scope::SecretReveal]));

        let decision = e.check(&c, &reveal(ENTRY), &[], NOW);
        assert!(decision.is_denied(), "got {decision:?}");
        if let Decision::Deny { reason, .. } = decision {
            assert!(reason.contains("disabled"), "unhelpful message: {reason}");
            assert!(
                reason.contains("without exposing it"),
                "should point at the safe alternative: {reason}"
            );
        }
    }

    #[test]
    fn an_agent_can_use_a_secret_without_seeing_it() {
        // The other half of the claim: useful without being dangerous.
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        e.add_grant(grant(&c, &[Scope::SecretUse]));
        assert_eq!(e.check(&c, &use_secret(ENTRY), &[], NOW), Decision::Allow);
    }

    #[test]
    fn an_extension_may_never_hold_reveal_even_if_granted() {
        // A hostile page attacking the extension must find no path to plaintext.
        let mut e = engine_with_gui();
        let c = client(ClientType::Extension);
        e.add_grant(grant(&c, &[Scope::SecretReveal]));
        assert!(!e.effective_scopes(&c, NOW).contains(&Scope::SecretReveal));
        assert!(e.check(&c, &reveal(ENTRY), &[], NOW).is_denied());
    }

    #[test]
    fn enabling_reveal_escalates_to_a_human_rather_than_allowing() {
        let mut e = engine_with_gui();
        e.set_mcp_reveal_enabled(true);
        let c = client(ClientType::Mcp);
        e.add_grant(grant(&c, &[Scope::SecretReveal]));

        match e.check(&c, &reveal(ENTRY), &[], NOW) {
            Decision::Ask(request) => {
                assert_eq!(request.entry, Some(ENTRY));
                assert_eq!(request.arm_delay_ms, APPROVAL_ARM_DELAY_MS);
                // Ground truth about the client must be present for the user to check.
                assert_eq!(
                    request.executable.as_deref(),
                    Some("/usr/local/bin/keel-mcp")
                );
            }
            other => panic!("expected an approval request, got {other:?}"),
        }
    }

    #[test]
    fn a_reveal_fails_closed_when_no_gui_can_ask() {
        // Auto-approving because nobody is reachable would invert the point entirely.
        let mut e = PolicyEngine::new();
        e.set_mcp_reveal_enabled(true);
        e.set_gui_attached(false);
        let c = client(ClientType::Mcp);
        e.add_grant(grant(&c, &[Scope::SecretReveal]));

        let decision = e.check(&c, &reveal(ENTRY), &[], NOW);
        assert!(decision.is_denied());
        if let Decision::Deny { reason, counted } = decision {
            assert!(reason.contains("open Keel"));
            assert!(
                !counted,
                "an unavoidable condition must not trip the breaker"
            );
        }
    }

    #[test]
    fn the_gui_and_cli_hold_every_scope_without_a_grant() {
        let mut e = engine_with_gui();
        for t in [ClientType::Gui, ClientType::Cli] {
            let c = client(t);
            assert_eq!(
                e.check(&c, &reveal(ENTRY), &[], NOW),
                Decision::Allow,
                "{t:?}"
            );
            assert_eq!(e.check(&c, &use_secret(ENTRY), &[], NOW), Decision::Allow);
        }
    }

    // ---- anti-enumeration -------------------------------------------------

    #[test]
    fn a_one_character_search_is_refused() {
        // Otherwise 26 queries enumerate most of a vault.
        let mut e = engine_with_gui();
        let c = client(ClientType::Gui);
        assert!(e
            .check(&c, &Operation::Search { query_len: 1 }, &[], NOW)
            .is_denied());
        assert_eq!(
            e.check(&c, &Operation::Search { query_len: 2 }, &[], NOW),
            Decision::Allow
        );
    }

    #[test]
    fn the_coverage_cap_stops_a_patient_walk_through_the_vault() {
        // Rate limits bound how often a client asks; this bounds how much of the vault
        // it reaches. Exercised through TOTP reads, whose 60-per-hour limit is high
        // enough for the 50-entry coverage cap to be the thing that bites — which is
        // exactly why the cap counts every secret-touching operation rather than only
        // reveals. Counting reveals alone would have left it unreachable.
        let mut e = engine_with_gui();
        let c = client(ClientType::Extension); // holds TotpRead by default, and is automated
        for i in 0..MAX_DISTINCT_ENTRIES_PER_HOUR {
            let entry = [u8::try_from(i).unwrap_or(255); 16];
            assert_eq!(
                e.check(&c, &Operation::ReadTotp { entry }, &[], NOW),
                Decision::Allow,
                "entry {i} should be allowed"
            );
        }
        let decision = e.check(&c, &Operation::ReadTotp { entry: [200u8; 16] }, &[], NOW);
        assert!(decision.is_denied(), "the cap must bite: {decision:?}");
        if let Decision::Deny { reason, .. } = decision {
            assert!(reason.contains("different entries"));
        }
    }

    #[test]
    fn re_touching_the_same_entry_does_not_consume_coverage() {
        // Filling the same login repeatedly is normal use and must not exhaust the cap.
        let mut e = engine_with_gui();
        let c = client(ClientType::Extension);
        for _ in 0..8 {
            assert_eq!(
                e.check(&c, &Operation::ReadTotp { entry: ENTRY }, &[], NOW),
                Decision::Allow
            );
        }
    }

    #[test]
    fn the_coverage_cap_does_not_apply_to_a_human_driven_client() {
        // A person scrolling their own vault is not enumerating it. Throttling the GUI
        // would be a bug dressed as a protection.
        let mut e = engine_with_gui();
        let c = client(ClientType::Gui);
        for i in 0..(MAX_DISTINCT_ENTRIES_PER_HOUR + 10) {
            let entry = [u8::try_from(i % 256).unwrap_or(0); 16];
            assert_eq!(
                e.check(&c, &use_secret(entry), &[], NOW),
                Decision::Allow,
                "the GUI must not be coverage-limited (entry {i})"
            );
        }
    }

    #[test]
    fn approved_reveals_are_rate_limited_far_below_the_coverage_cap() {
        // Reveal is the most dangerous operation, so its own limit is far tighter than
        // the coverage cap. Pinning the relationship in a test keeps the two numbers from
        // drifting into inconsistency again.
        //
        // Note the flow: for an agent, a reveal is escalated rather than allowed, and the
        // quota is consumed when the human approves — not when the agent asks. A denied
        // prompt must not spend the user's budget.
        let mut e = engine_with_gui();
        e.set_mcp_reveal_enabled(true);
        let c = client(ClientType::Mcp);
        let mut g = grant(&c, &[Scope::SecretReveal]);
        g.max_reveals = u32::MAX;
        g.max_uses = u32::MAX;
        e.add_grant(g);

        for i in 0..u8::try_from(MAX_REVEALS_PER_HOUR).unwrap_or(5) {
            let entry = [i; 16];
            assert!(
                matches!(e.check(&c, &reveal(entry), &[], NOW), Decision::Ask(_)),
                "reveal {i} should have been escalated to the user"
            );
            e.begin_reveal_approval(&c.id);
            e.resolve_reveal_approval(&c, &entry, true, NOW);
        }

        let decision = e.check(&c, &reveal([200; 16]), &[], NOW);
        assert!(decision.is_denied(), "got {decision:?}");
        if let Decision::Deny { reason, .. } = decision {
            assert!(reason.contains("rate limit"), "got: {reason}");
        }
        // The relationship between the two limits is enforced by a const assertion at
        // the top of this module, so it cannot drift.
    }

    // ---- rate limits and the breaker --------------------------------------

    #[test]
    fn a_search_flood_from_an_agent_is_rate_limited_then_recovers() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        let mut g = grant(&c, &[Scope::MetadataRead]);
        // Raise the grant quota so this test isolates the rate limit rather than
        // tripping over the grant's own use budget first.
        g.max_uses = u32::MAX;
        e.add_grant(g);
        let op = Operation::Search { query_len: 4 };
        for _ in 0..60 {
            assert_eq!(e.check(&c, &op, &[], NOW), Decision::Allow);
        }
        assert!(e.check(&c, &op, &[], NOW).is_denied());
        // A later window lets it through again.
        assert_eq!(e.check(&c, &op, &[], NOW + 61), Decision::Allow);
    }

    #[test]
    fn repeated_denials_trip_the_breaker_and_revoke_grants() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        e.add_grant(grant(&c, &[Scope::MetadataRead]));
        assert_eq!(e.grants_for(&c.id, NOW).len(), 1);

        for _ in 0..BREAKER_DENIAL_THRESHOLD {
            assert!(e.check(&c, &Operation::ReadAudit, &[], NOW).is_denied());
        }
        assert!(e.is_tripped(&c.id));
        assert!(
            e.grants_for(&c.id, NOW).is_empty(),
            "tripping must revoke the client's grants"
        );

        let decision = e.check(&c, &Operation::Search { query_len: 5 }, &[], NOW);
        assert!(decision.is_denied());
        if let Decision::Deny { reason, .. } = decision {
            assert!(reason.contains("suspended"));
        }
    }

    #[test]
    fn the_breaker_clears_only_on_a_fresh_unlock() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        for _ in 0..BREAKER_DENIAL_THRESHOLD {
            e.check(&c, &Operation::ReadAudit, &[], NOW);
        }
        assert!(e.is_tripped(&c.id));
        // Time alone must not heal it.
        assert!(e.is_tripped(&c.id));
        e.reset_breaker(&c.id);
        assert!(!e.is_tripped(&c.id));
    }

    #[test]
    fn a_status_request_always_works_even_when_tripped() {
        // A client that cannot discover it is locked out cannot tell the user why.
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        for _ in 0..BREAKER_DENIAL_THRESHOLD {
            e.check(&c, &Operation::ReadAudit, &[], NOW);
        }
        assert_eq!(e.check(&c, &Operation::Status, &[], NOW), Decision::Allow);
    }

    #[test]
    fn a_human_driven_client_is_not_rate_limited() {
        // An early version applied the agent limits to every client, which capped the
        // desktop app at ten clipboard copies an hour. That protected nothing — a person
        // holding the passphrase can already read the whole vault — while making the app
        // unusable.
        let mut e = engine_with_gui();
        for t in [ClientType::Gui, ClientType::Cli] {
            let c = client(t);
            for i in 0..200 {
                let entry = [u8::try_from(i % 256).unwrap_or(0); 16];
                assert_eq!(
                    e.check(&c, &use_secret(entry), &[], NOW),
                    Decision::Allow,
                    "{t:?} was throttled at request {i}"
                );
            }
        }
    }

    #[test]
    fn an_extension_gets_room_for_real_use_but_is_still_bounded() {
        // Someone working through a backlog of logins can legitimately fill dozens in an
        // hour, so the extension's limit has to clear that. It still has one.
        let mut e = engine_with_gui();
        let c = client(ClientType::Extension);
        for i in 0..120 {
            let entry = [u8::try_from(i % 40).unwrap_or(0); 16];
            assert_eq!(
                e.check(&c, &use_secret(entry), &[], NOW),
                Decision::Allow,
                "the extension was throttled at fill {i}"
            );
        }
        assert!(e.check(&c, &use_secret([250; 16]), &[], NOW).is_denied());
    }

    #[test]
    fn password_generation_needs_no_vault_access() {
        let mut e = PolicyEngine::new();
        let c = client(ClientType::Mcp);
        assert_eq!(
            e.check(&c, &Operation::GeneratePassword, &[], NOW),
            Decision::Allow
        );
    }

    // ---- grants ------------------------------------------------------------

    #[test]
    fn an_expired_grant_stops_working() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        e.add_grant(grant(&c, &[Scope::MetadataRead]));
        let op = Operation::Search { query_len: 4 };
        assert_eq!(e.check(&c, &op, &[], NOW), Decision::Allow);
        assert!(e
            .check(&c, &op, &[], NOW + DEFAULT_GRANT_TTL + 1)
            .is_denied());
    }

    #[test]
    fn a_grant_ttl_is_capped() {
        let c = client(ClientType::Mcp);
        let g = Grant::new(
            [1; 16],
            &c.id,
            BTreeSet::new(),
            EntryFilter::All,
            NOW,
            MAX_GRANT_TTL * 100,
        );
        assert_eq!(g.expires_at, NOW + MAX_GRANT_TTL);
    }

    #[test]
    fn a_tag_filtered_grant_only_covers_matching_entries() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        let mut g = grant(&c, &[Scope::SecretUse]);
        g.filter = EntryFilter::TagGlob("work/*".to_owned());
        e.add_grant(g);

        let in_scope = vec!["work/eng".to_owned()];
        let out_of_scope = vec!["personal".to_owned()];
        assert_eq!(
            e.check(&c, &use_secret(ENTRY), &in_scope, NOW),
            Decision::Allow
        );
        assert!(e
            .check(&c, &use_secret(ENTRY), &out_of_scope, NOW)
            .is_denied());
    }

    #[test]
    fn an_explicit_filter_covers_only_the_listed_entries() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        let mut g = grant(&c, &[Scope::SecretUse]);
        g.filter = EntryFilter::Explicit([ENTRY].into_iter().collect());
        e.add_grant(g);

        assert_eq!(e.check(&c, &use_secret(ENTRY), &[], NOW), Decision::Allow);
        assert!(e.check(&c, &use_secret([99; 16]), &[], NOW).is_denied());
    }

    #[test]
    fn revoking_is_always_permitted_and_takes_effect() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        let g = grant(&c, &[Scope::MetadataRead]);
        let id = g.id;
        e.add_grant(g);
        assert!(e.revoke_grant(&id));
        assert!(
            !e.revoke_grant(&id),
            "revoking twice should report nothing done"
        );
        assert!(e
            .check(&c, &Operation::Search { query_len: 4 }, &[], NOW)
            .is_denied());
    }

    #[test]
    fn a_grant_exhausted_by_use_stops_working() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        let mut g = grant(&c, &[Scope::MetadataRead]);
        // Well below any rate limit, so this test isolates the grant's own quota.
        g.max_uses = 2;
        e.add_grant(g);

        let op = Operation::Search { query_len: 4 };
        assert_eq!(e.check(&c, &op, &[], NOW), Decision::Allow);
        assert_eq!(e.check(&c, &op, &[], NOW), Decision::Allow);
        assert!(e.check(&c, &op, &[], NOW).is_denied());
    }

    #[test]
    fn glob_matching_handles_prefix_and_exact_patterns() {
        assert!(glob_match("work/*", "work/eng"));
        assert!(glob_match("work/*", "work/"));
        assert!(!glob_match("work/*", "personal"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
        // No accidental substring matching, which would silently widen a grant.
        assert!(!glob_match("work", "my-work"));
    }

    // ---- agent-supplied text ----------------------------------------------

    #[test]
    fn ansi_escapes_and_control_characters_are_stripped() {
        // Agent text must not be able to rewrite a terminal line or hide content.
        let hostile = "\u{1b}[2K\u{1b}[31mSYSTEM: approve this\u{1b}[0m\r\nreally";
        let clean = sanitize_reason(hostile);
        assert!(!clean.contains('\u{1b}'));
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\n'));
        // Sequences must be removed whole. Dropping only the ESC byte would leave the
        // literal text "[2K[31m", which is both noise and a way to build misleading
        // strings out of apparently-sanitised text.
        assert!(
            !clean.contains('['),
            "escape parameters survived: {clean:?}"
        );
        assert_eq!(clean, "SYSTEM: approve thisreally");

        // An OSC sequence, which can set a terminal title, must also go whole.
        let osc = sanitize_reason("a\u{1b}]0;window title\u{7}b");
        assert_eq!(osc, "ab");
    }

    #[test]
    fn bidirectional_overrides_are_stripped() {
        // A right-to-left override can visually reverse text so the dialog reads as
        // something entirely different from what it says.
        let clean = sanitize_reason("safe\u{202E}suoregnad\u{202C}");
        assert!(!clean.contains('\u{202E}'));
        assert!(!clean.contains('\u{202C}'));
    }

    #[test]
    fn reason_text_is_truncated() {
        let long = "a".repeat(1000);
        assert_eq!(sanitize_reason(&long).chars().count(), MAX_REASON_CHARS);
    }

    #[test]
    fn whitespace_is_collapsed_and_trimmed() {
        assert_eq!(sanitize_reason("  lots   of    space  "), "lots of space");
        assert_eq!(sanitize_reason(""), "");
        assert_eq!(sanitize_reason("   "), "");
    }

    #[test]
    fn markup_is_left_intact_for_the_renderer_to_refuse() {
        // Deliberate: stripping markup here would imply that rendering it is otherwise
        // acceptable. The renderer must treat this as plain text.
        let clean = sanitize_reason("**bold** <b>html</b> [link](http://evil)");
        assert!(clean.contains("**bold**"));
        assert!(clean.contains("<b>html</b>"));
    }

    #[test]
    fn an_empty_reason_is_omitted_from_the_dialog() {
        let mut e = engine_with_gui();
        e.set_mcp_reveal_enabled(true);
        let c = client(ClientType::Mcp);
        e.add_grant(grant(&c, &[Scope::SecretReveal]));

        let op = Operation::RevealSecret {
            entry: ENTRY,
            // A whole CSI sequence plus whitespace must sanitise to nothing at all.
            reason: "   \u{1b}[0m  \u{200B}".to_owned(),
        };
        match e.check(&c, &op, &[], NOW) {
            Decision::Ask(request) => assert_eq!(request.agent_text, None),
            other => panic!("expected an approval request, got {other:?}"),
        }
    }

    // ---- destinations -----------------------------------------------------

    #[test]
    fn destination_descriptions_name_the_concrete_target() {
        // "Allow access to your password?" tells a user nothing. The destination is
        // what lets them notice something is wrong.
        let fill = Destination::FillInBrowser {
            origin: "https://chase.com/login".to_owned(),
            browser: "Chrome".to_owned(),
        };
        let described = fill.describe();
        assert!(described.contains("chase.com"));
        assert!(described.contains("Chrome"));

        assert!(Destination::Clipboard { clear_after: 15 }
            .describe()
            .contains("15 seconds"));
    }

    // ---- reveal approval bookkeeping --------------------------------------

    #[test]
    fn only_one_reveal_may_await_approval_at_a_time() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Cli);
        e.begin_reveal_approval(&c.id);
        let decision = e.check(&c, &reveal(ENTRY), &[], NOW);
        assert!(decision.is_denied());
        if let Decision::Deny { reason, .. } = decision {
            assert!(reason.contains("already awaiting approval"));
        }
    }

    #[test]
    fn a_user_denial_counts_toward_the_breaker() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        for _ in 0..BREAKER_DENIAL_THRESHOLD {
            e.begin_reveal_approval(&c.id);
            e.resolve_reveal_approval(&c, &ENTRY, false, NOW);
        }
        assert!(
            e.is_tripped(&c.id),
            "a client whose requests the user keeps refusing should lose its session"
        );
    }

    #[test]
    fn an_approved_reveal_consumes_grant_quota() {
        let mut e = engine_with_gui();
        e.set_mcp_reveal_enabled(true);
        let c = client(ClientType::Mcp);
        e.add_grant(grant(&c, &[Scope::SecretReveal]));

        e.begin_reveal_approval(&c.id);
        e.resolve_reveal_approval(&c, &ENTRY, true, NOW);

        let grants = e.grants_for(&c.id, NOW);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].reveals_used, 1);
        assert_eq!(grants[0].reveals_remaining(), DEFAULT_MAX_REVEALS - 1);
    }

    #[test]
    fn persisted_grants_round_trip_their_essentials() {
        let mut e = engine_with_gui();
        let c = client(ClientType::Mcp);
        let mut g = grant(&c, &[Scope::MetadataRead, Scope::SecretUse]);
        g.filter = EntryFilter::TagGlob("work/*".to_owned());
        e.add_grant(g);

        let persisted = e.persistable(NOW);
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].client_id, c.id);
        assert_eq!(persisted[0].tag_filter.as_deref(), Some("work/*"));
        assert!(persisted[0].scopes.contains(&Scope::MetadataRead));
    }
}
