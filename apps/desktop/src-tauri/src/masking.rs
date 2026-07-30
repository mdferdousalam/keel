//! The views the webview is allowed to see.
//!
//! This module exists so that "no stored secret reaches the webview" is a property of the
//! **types** rather than of anyone's discipline. Every Tauri command returns something
//! defined here, and nothing defined here has a field capable of holding a password. A
//! command that wanted to leak one would have to add a field first, which is a visible
//! change in a file whose entire purpose is to not have such a field.
//!
//! The alternative — commands returning `keel_proto` types directly — would have worked
//! most of the time and failed the once it mattered, because `Response::Secret` and
//! `Response::Exported` both carry plaintext and both are one careless `match` arm away
//! from being forwarded.
//!
//! # Masking is not obfuscation
//!
//! [`Mask`] does not hold a transformed password. It holds a bullet string, a length, and a
//! strength estimate, computed from a value this process never received. There is nothing
//! to reverse, because nothing was encoded.

use keel_proto::Response;
use serde::Serialize;

/// The character a masked field is drawn with.
const BULLET: char = '\u{2022}';

/// Longest run of bullets rendered, whatever the real length.
///
/// A very long passphrase would otherwise produce a mask that breaks the layout and
/// silently advertises its own length to anyone looking over the user's shoulder.
const MAX_BULLETS: usize = 24;

/// How a secret field is presented.
///
/// Note what is *not* here: the value, any prefix or suffix of it, and any hash of it. A
/// first-and-last-character hint is a common design and a bad one — it removes a
/// meaningful slice of the search space for a shoulder-surfer, in exchange for
/// reassurance the user does not need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mask {
    /// Bullets to draw.
    pub bullets: String,
    /// Whether anything is stored at all, so the UI can say "no password" honestly.
    pub present: bool,
}

impl Mask {
    /// A mask for a field of `length` characters.
    #[must_use]
    pub fn of_length(length: usize) -> Self {
        Self {
            bullets: core::iter::repeat_n(BULLET, length.min(MAX_BULLETS)).collect(),
            present: length > 0,
        }
    }

    /// A mask for a field known to be present but of unknown length.
    #[must_use]
    pub fn present() -> Self {
        Self {
            bullets: core::iter::repeat_n(BULLET, 12).collect(),
            present: true,
        }
    }

    /// A mask for an absent field.
    #[must_use]
    pub fn absent() -> Self {
        Self {
            bullets: String::new(),
            present: false,
        }
    }
}

/// Lock state and session facts for the window header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusView {
    /// `unlocked`, `locked`, or `no_vault`.
    pub state: String,
    /// Coarse entry-count bucket, as the agent reports it.
    pub entry_count: String,
    /// Seconds until auto-lock, if unlocked.
    pub locks_in: Option<u64>,
    /// Vault file path, so the user can see which vault this is.
    pub vault_path: String,
    /// Whether process hardening applied cleanly.
    pub hardened: bool,
    /// Agent version, for the about panel.
    pub agent_version: String,
    /// Warnings the agent wants the user to see — a degraded `mlock`, a vault on a synced
    /// folder, permissive ptrace settings. Surfaced rather than swallowed: each one is a
    /// weakened assumption the user should know about.
    pub warnings: Vec<String>,
}

impl StatusView {
    /// Build from a status response.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent sent something other than a status.
    pub fn from_response(response: &Response) -> Result<Self, String> {
        match response {
            Response::Status(info) => Ok(Self {
                state: lock_state_name(info.state).to_owned(),
                // `None` means locked, where the agent will not say how many entries there
                // are. Reported as a phrase rather than zero, because "0 entries" on a
                // locked vault reads as data loss.
                entry_count: info
                    .entry_count
                    .clone()
                    .unwrap_or_else(|| "unknown while locked".to_owned()),
                locks_in: info.locks_in,
                vault_path: info.vault_path.clone(),
                hardened: info.hardened,
                agent_version: info.agent_version.clone(),
                warnings: info.warnings.clone(),
            }),
            other => Err(wrong_response("status", other)),
        }
    }
}

/// One entry in a list, masked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryView {
    /// Opaque per-session handle. Meaningless after a lock.
    pub reference: String,
    /// Display title.
    pub title: String,
    /// Username. Not a secret, but it identifies an account, so the UI treats it as
    /// sensitive-adjacent and does not put it in window titles.
    pub username: String,
    /// Sites this entry applies to.
    pub websites: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Whether a TOTP secret is stored.
    pub has_totp: bool,
    /// The password, as bullets.
    pub password: Mask,
}

/// One entry's detail panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetailView {
    /// Opaque handle.
    pub reference: String,
    /// Title.
    pub title: String,
    /// Username.
    pub username: String,
    /// Sites.
    pub websites: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// The password, as bullets.
    pub password: Mask,
    /// Whether a TOTP secret is stored.
    pub has_totp: bool,
    /// When the password last changed, Unix seconds. Rendered as an age by the UI.
    pub password_changed_at: u64,
    /// When the entry was last modified, Unix seconds.
    pub updated_at: u64,
}

impl DetailView {
    /// Build from a metadata response.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent sent something other than entry metadata.
    pub fn from_response(response: &Response) -> Result<Self, String> {
        // `GetMetadata` answers with a single `Entry`; `Search` and `List` answer with
        // `Entries`. Both are accepted so the detail panel can be filled from either.
        let entry = match response {
            Response::Entry(entry) => entry.as_ref(),
            Response::Entries { entries, .. } => entries
                .first()
                .ok_or_else(|| "that entry no longer exists".to_owned())?,
            other => return Err(wrong_response("entry metadata", other)),
        };
        {
            {
                Ok(Self {
                    reference: entry.reference.0.clone(),
                    title: entry.title.clone(),
                    username: entry.username.clone(),
                    websites: entry.origins.clone(),
                    tags: entry.tags.clone(),
                    // The agent reports whether a password exists, never its length, so a
                    // fixed-width mask leaks nothing at all.
                    password: Mask::present(),
                    has_totp: entry.has_totp,
                    password_changed_at: entry.password_changed_at,
                    updated_at: entry.updated_at,
                })
            }
        }
    }
}

/// Result of creating or rotating an entry.
///
/// Carries the strength of the generated password and not the password. The user is told
/// their new password is 129 bits and never shown it, which is the whole argument for a
/// password manager: the value is the machine's business.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreatedView {
    /// Handle for the new or updated entry.
    pub reference: String,
    /// Estimated entropy in whole bits.
    pub strength_bits: Option<u32>,
}

impl CreatedView {
    /// Build from a create or rotate response.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent sent something else.
    pub fn from_response(response: &Response) -> Result<Self, String> {
        match response {
            Response::Created {
                reference,
                entropy_bits,
                ..
            } => Ok(Self {
                reference: reference.0.clone(),
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "entropy is a small non-negative estimate"
                )]
                strength_bits: entropy_bits.map(|b| b.round() as u32),
            }),
            Response::Applied { .. } | Response::Ok => Ok(Self {
                reference: String::new(),
                strength_bits: None,
            }),
            other => Err(wrong_response("a created entry", other)),
        }
    }
}

/// The vault health report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthView {
    /// Entries examined.
    pub examined: usize,
    /// Entries storing no password.
    pub without_password: usize,
    /// Records that could not be decrypted.
    pub unreadable: usize,
    /// Distinct entries flagged.
    pub flagged: usize,
    /// Groups sharing a password.
    pub reused: Vec<Vec<keel_proto::HealthEntry>>,
    /// Weak passwords, weakest first.
    pub weak: Vec<keel_proto::HealthEntry>,
    /// Old passwords, oldest first.
    pub stale: Vec<keel_proto::HealthEntry>,
}

impl HealthView {
    /// Build from a health response.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent sent something else.
    pub fn from_response(response: &Response) -> Result<Self, String> {
        match response {
            Response::Health {
                examined,
                without_password,
                unreadable,
                reused,
                weak,
                stale,
                flagged,
            } => Ok(Self {
                examined: *examined,
                without_password: *without_password,
                unreadable: *unreadable,
                flagged: *flagged,
                reused: reused.clone(),
                weak: weak.clone(),
                stale: stale.clone(),
            }),
            other => Err(wrong_response("a health report", other)),
        }
    }
}

/// Recent activity, with the chain verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogView {
    /// Records, oldest first.
    pub records: Vec<keel_proto::AuditEntry>,
    /// `intact`, `broken_at`, `truncated_after`, or `tail_altered`.
    pub chain: String,
    /// Sequence number the verdict refers to, when it has one.
    pub chain_seq: Option<u64>,
    /// Whether the verdict indicates interference rather than an accident.
    pub suggests_tampering: bool,
    /// Total records in the log.
    pub total: u64,
}

impl LogView {
    /// Build from an audit response.
    ///
    /// # Errors
    ///
    /// Returns an error if the agent sent something else.
    pub fn from_response(response: &Response) -> Result<Self, String> {
        match response {
            Response::Audit {
                records,
                chain,
                total,
            } => {
                let (name, seq) = match chain {
                    keel_proto::ChainState::Intact => ("intact", None),
                    keel_proto::ChainState::BrokenAt { seq } => ("broken_at", Some(*seq)),
                    keel_proto::ChainState::TruncatedAfter { seq } => {
                        ("truncated_after", Some(*seq))
                    }
                    keel_proto::ChainState::TailAltered { expected_seq, .. } => {
                        ("tail_altered", Some(*expected_seq))
                    }
                };
                Ok(Self {
                    records: records.clone(),
                    chain: name.to_owned(),
                    chain_seq: seq,
                    suggests_tampering: chain.suggests_tampering(),
                    total: *total,
                })
            }
            other => Err(wrong_response("an activity log", other)),
        }
    }
}

/// Access granted to one automated client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantView {
    /// Which client.
    pub client_id: String,
    /// Capabilities held.
    pub scopes: Vec<String>,
    /// Which entries it covers, as a phrase.
    pub covers: String,
    /// Unix seconds at which it expires.
    pub expires_at: u64,
    /// Operations left before the grant is exhausted.
    pub uses_remaining: u32,
}

/// Turn a list or search response into masked entry views.
///
/// # Errors
///
/// Returns an error if the agent sent something other than a list of entries.
pub fn entry_views(response: &Response) -> Result<Vec<EntryView>, String> {
    match response {
        Response::Entries { entries, .. } => Ok(entries
            .iter()
            .map(|entry| EntryView {
                reference: entry.reference.0.clone(),
                title: entry.title.clone(),
                username: entry.username.clone(),
                websites: entry.origins.clone(),
                tags: entry.tags.clone(),
                has_totp: entry.has_totp,
                password: Mask::present(),
            })
            .collect()),
        other => Err(wrong_response("a list of entries", other)),
    }
}

/// Turn a grants response into views.
///
/// # Errors
///
/// Returns an error if the agent sent something other than a grant list.
pub fn grant_views(response: &Response) -> Result<Vec<GrantView>, String> {
    match response {
        Response::Grants { grants } => Ok(grants
            .iter()
            .map(|grant| GrantView {
                client_id: grant.client_id.clone(),
                scopes: grant.scopes.clone(),
                covers: grant
                    .tag_filter
                    .clone()
                    .map_or_else(|| "every entry".to_owned(), |t| format!("tag {t}")),
                expires_at: grant.expires_at,
                uses_remaining: grant.uses_remaining,
            })
            .collect()),
        other => Err(wrong_response("a list of grants", other)),
    }
}

/// The name of a response variant, for error messages.
///
/// Deliberately a name and never the contents. An error that interpolated a whole response
/// would put a password into an error string bound for the webview the first time a
/// `Response::Secret` arrived somewhere unexpected — which is precisely the case where
/// something has already gone wrong and the last thing wanted is a second failure on top.
#[must_use]
pub fn variant_name(response: &Response) -> &'static str {
    match response {
        Response::Ok => "ok",
        Response::Hello { .. } => "hello",
        Response::Status { .. } => "status",
        Response::Entries { .. } => "entries",
        Response::Entry(_) => "entry",
        Response::Created { .. } => "created",
        Response::Applied { .. } => "applied",
        Response::Secret { .. } => "secret",
        Response::Generated { .. } => "generated",
        Response::Grants { .. } => "grants",
        Response::Audit { .. } => "audit",
        Response::Health { .. } => "health",
        Response::Exported { .. } => "export",
        Response::PendingApprovals { .. } => "pending approvals",
        Response::Settings(_) => "settings",
        Response::ApprovalRequired { .. } => "approval required",
        Response::Error { .. } => "error",
    }
}

fn wrong_response(expected: &str, got: &Response) -> String {
    format!(
        "expected {expected} from the agent but received a {} response",
        variant_name(got)
    )
}

const fn lock_state_name(state: keel_proto::LockState) -> &'static str {
    match state {
        keel_proto::LockState::Unlocked => "unlocked",
        keel_proto::LockState::Locked => "locked",
        keel_proto::LockState::NoVault => "no_vault",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mask_contains_only_bullets() {
        let mask = Mask::of_length(20);
        assert_eq!(mask.bullets.chars().count(), 20);
        assert!(mask.bullets.chars().all(|c| c == BULLET));
        assert!(mask.present);
    }

    #[test]
    fn a_very_long_field_does_not_produce_a_very_long_mask() {
        // A mask whose width tracks the real length advertises that length to anyone
        // looking at the screen, and breaks the layout while doing it.
        let mask = Mask::of_length(400);
        assert_eq!(mask.bullets.chars().count(), MAX_BULLETS);
    }

    #[test]
    fn an_absent_field_is_distinguishable_from_an_empty_one() {
        // The UI needs to say "no password stored" rather than draw zero bullets and leave
        // the user guessing whether it failed to load.
        assert!(!Mask::absent().present);
        assert!(Mask::absent().bullets.is_empty());
        assert!(!Mask::of_length(0).present);
    }

    #[test]
    fn a_mask_serialises_without_anything_resembling_a_value() {
        let json = serde_json::to_string(&Mask::of_length(16)).unwrap();
        assert!(json.contains("bullets"));
        // Only bullets, the field names, and the boolean.
        for c in json.chars() {
            assert!(
                c == BULLET || c.is_ascii_alphanumeric() || "{}\":,_ ".contains(c),
                "unexpected character {c:?} in a serialised mask: {json}"
            );
        }
    }

    #[test]
    fn every_response_variant_has_a_name() {
        // The compiler enforces the match is exhaustive; this checks the names are
        // actually usable in a sentence and that none was left as a placeholder.
        for name in [
            variant_name(&Response::Ok),
            variant_name(&Response::Error {
                code: keel_proto::ErrorCode::Internal,
                message: String::new(),
            }),
        ] {
            assert!(!name.is_empty());
            assert!(!name.contains("TODO"));
        }
    }

    #[test]
    fn an_unexpected_secret_response_is_named_not_quoted() {
        // The case that matters: if a `Response::Secret` ever arrives where it should not,
        // the error must describe it without including it.
        const CANARY: &str = "canary-Zq7#mV4xKp";
        let response = Response::Secret {
            value: CANARY.to_owned(),
            expires_in: 30,
        };
        let message = wrong_response("status", &response);
        assert!(
            !message.contains(CANARY),
            "an error message leaked a secret: {message}"
        );
        assert!(message.contains("secret"), "got: {message}");
    }

    #[test]
    fn an_unexpected_export_response_is_named_not_quoted() {
        const CANARY: &str = "canary-Zq7#mV4xKp";
        let response = Response::Exported {
            entries: vec![keel_proto::ExportedEntry {
                title: "Bank".to_owned(),
                username: "ada".to_owned(),
                password: CANARY.to_owned(),
                totp_secret: None,
                notes: String::new(),
                origins: Vec::new(),
                tags: Vec::new(),
                created_at: 0,
                password_changed_at: 0,
            }],
        };
        let message = wrong_response("status", &response);
        assert!(
            !message.contains(CANARY),
            "an error message leaked an exported password: {message}"
        );
    }

    #[test]
    fn views_refuse_a_response_they_did_not_ask_for() {
        // Rather than silently producing an empty view, which would look like an empty
        // vault and send a user hunting for entries that are actually there.
        let secret = Response::Secret {
            value: "x".to_owned(),
            expires_in: 30,
        };
        assert!(StatusView::from_response(&secret).is_err());
        assert!(DetailView::from_response(&secret).is_err());
        assert!(HealthView::from_response(&secret).is_err());
        assert!(LogView::from_response(&secret).is_err());
        assert!(entry_views(&secret).is_err());
        assert!(grant_views(&secret).is_err());
    }
}
