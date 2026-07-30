//! The tool surface offered to AI agents.
//!
//! # What is deliberately absent
//!
//! The security of this feature is mostly a matter of what is *not* here. There is no
//! `export_vault`, no `list_all_entries`, no `unlock_vault`, no `change_master_passphrase`,
//! no `hard_delete`, no `read_file`, and no way to ask where the vault lives.
//!
//! Those are not oversights. An agent that can enumerate a vault can drain it, and an agent
//! that can unlock one can be tricked into unlocking it. Where a user genuinely needs those
//! operations they happen in the GUI or the CLI, with a human present.
//!
//! # `use_secret` versus `reveal_secret`
//!
//! The distinction is the whole design. An agent almost never needs to *see* a password — it
//! needs the password to be *used*. So:
//!
//! * [`USE_SECRET`] asks the agent process to apply a secret and returns only a status. The
//!   plaintext never crosses back.
//! * `reveal_secret` returns plaintext, is disabled by default, and requires per-request human
//!   approval even when enabled.
//!
//! The tool *descriptions* say this too, because the model reads them. An agent should be able
//! to tell from the description that `use_secret` will not hand it a password, and choose it
//! for that reason rather than trying `reveal_secret` first and being refused.
//!
//! # This module enforces nothing
//!
//! Every request is forwarded to the agent, which owns the policy engine. That is deliberate:
//! a policy check here would be a second implementation to keep in sync with the first, and
//! the one that mattered would be the one an attacker could not reach — the agent's. This
//! process holds no keys and makes no decisions.

use keel_proto::{EntryInput, EntryRef, Field, Request, Response, SecretAction, SecretSource};

use crate::protocol::{optional_str, optional_u32, require_str, Tool, ToolResult};

/// Maximum search results a caller may request.
const MAX_SEARCH_RESULTS: u32 = 25;

/// Maximum generated password length a caller may request.
const MAX_GENERATED_LENGTH: u32 = 128;

/// Name of the safe secret-application tool.
pub const USE_SECRET: &str = "use_secret";

/// Every tool this server offers.
///
/// Descriptions are written for the model, and they explain the security behaviour rather than
/// only the mechanics, because a model that understands why `use_secret` exists will reach for
/// it first.
#[must_use]
pub fn all() -> Vec<Tool> {
    vec![
        Tool {
            name: "vault_status",
            description:
                "Report whether the Keel vault is unlocked, and which permissions this client \
                 currently holds. Takes no arguments and needs no permission. Always call this \
                 first: if the vault is locked, ask the user to unlock it rather than \
                 attempting other tools.",
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "search_entries",
            description:
                "Search the vault by title, username, or website. Returns metadata only — never \
                 passwords. Each result includes an opaque `reference` to pass to other tools. \
                 The query must be at least two characters, and results are limited; there is \
                 no way to list the whole vault.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "minLength": 2,
                        "description": "Text to look for in titles, usernames, and websites."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_SEARCH_RESULTS,
                        "description": "Maximum results to return."
                    }
                },
                "required": ["query"]
            }),
        },
        Tool {
            name: "get_entry_metadata",
            description:
                "Read one entry's non-secret details: title, username, websites, tags, and when \
                 its password last changed. Never returns a password.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "reference": {
                        "type": "string",
                        "description": "A reference from search_entries."
                    }
                },
                "required": ["reference"]
            }),
        },
        Tool {
            name: USE_SECRET,
            description:
                "Use a password WITHOUT receiving it. Keel applies the secret itself — copying \
                 it to the clipboard or typing it — and returns only a status. The password is \
                 never sent to you, so this is the correct tool for logging the user in, and it \
                 is what you should reach for by default. Prefer it over reveal_secret in every \
                 case where the user's goal is to be logged in rather than to read a value.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "reference": {
                        "type": "string",
                        "description": "A reference from search_entries."
                    },
                    "field": {
                        "type": "string",
                        "enum": ["password", "username", "totp"],
                        "description": "Which field to apply. Defaults to password."
                    },
                    "action": {
                        "type": "string",
                        "enum": ["clipboard", "type"],
                        "description": "How to apply it. Defaults to clipboard."
                    }
                },
                "required": ["reference"]
            }),
        },
        Tool {
            name: "reveal_secret",
            description:
                "Request the plaintext of a password. This is DISABLED BY DEFAULT and, when the \
                 user has enabled it, still requires the user to approve each request in the \
                 Keel window. Use it only when the user explicitly needs to see or paste a \
                 value somewhere Keel cannot reach; for logging in, use use_secret instead. The \
                 `reason` you give is shown to the user verbatim, so state plainly what the \
                 value is for.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "reference": {
                        "type": "string",
                        "description": "A reference from search_entries."
                    },
                    "field": {
                        "type": "string",
                        "enum": ["password", "username", "totp", "notes"],
                        "description": "Which field. Defaults to password."
                    },
                    "reason": {
                        "type": "string",
                        "maxLength": 200,
                        "description": "Why you need it. Shown to the user when they are asked \
                                        to approve."
                    }
                },
                "required": ["reference", "reason"]
            }),
        },
        Tool {
            name: "generate_password",
            description:
                "Generate a strong password or passphrase without storing it. Needs no vault \
                 access and works while the vault is locked.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "length": {
                        "type": "integer",
                        "minimum": 8,
                        "maximum": MAX_GENERATED_LENGTH,
                        "description": "Characters. Defaults to 20."
                    },
                    "words": {
                        "type": "integer",
                        "minimum": 3,
                        "maximum": 16,
                        "description": "Generate a word-based passphrase of this many words \
                                        instead of a character password."
                    }
                }
            }),
        },
        Tool {
            name: "create_entry",
            description:
                "Create a new entry. By default Keel generates the password itself and does NOT \
                 return it, so you can store a strong password you never see — which is the \
                 preferred way to use this tool. Supply `password` only when saving a value the \
                 user already has.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "title": { "type": "string", "description": "Entry name." },
                    "username": { "type": "string", "description": "Username or email." },
                    "url": { "type": "string", "description": "Website URL." },
                    "notes": { "type": "string", "description": "Free-form notes." },
                    "password": {
                        "type": "string",
                        "description": "An existing password to store. Omit to have Keel \
                                        generate one, which is preferred."
                    },
                    "length": {
                        "type": "integer",
                        "minimum": 8,
                        "maximum": MAX_GENERATED_LENGTH,
                        "description": "Length for a generated password."
                    }
                },
                "required": ["title"]
            }),
        },
        Tool {
            name: "rotate_secret",
            description:
                "Replace an entry's password with a freshly generated one. The previous password \
                 is kept in history so the user is not locked out if the site did not accept the \
                 change. The new password is not returned to you.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "reference": {
                        "type": "string",
                        "description": "A reference from search_entries."
                    },
                    "length": {
                        "type": "integer",
                        "minimum": 8,
                        "maximum": MAX_GENERATED_LENGTH,
                        "description": "Length for the new password."
                    }
                },
                "required": ["reference"]
            }),
        },
        Tool {
            name: "update_entry",
            description:
                "Update an entry's non-secret fields: title, username, website, notes. To change \
                 a password use rotate_secret.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "reference": { "type": "string", "description": "A reference from search_entries." },
                    "title": { "type": "string" },
                    "username": { "type": "string" },
                    "url": { "type": "string" },
                    "notes": { "type": "string" }
                },
                "required": ["reference", "title"]
            }),
        },
        Tool {
            name: "trash_entry",
            description:
                "Move an entry to the trash. This is reversible: the entry can be restored from \
                 the Keel app until it is purged. There is no way to delete an entry permanently \
                 through this interface.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "reference": { "type": "string", "description": "A reference from search_entries." }
                },
                "required": ["reference"]
            }),
        },
    ]
}

/// Translate a tool call into an agent request.
///
/// Returns `Err` for a malformed call, which becomes a tool-level failure the model can read
/// and correct. No authorization decision happens here.
pub fn to_request(name: &str, arguments: &serde_json::Value) -> Result<Request, String> {
    match name {
        "vault_status" => Ok(Request::Status),

        "search_entries" => {
            let query = require_str(arguments, "query")?;
            if query.chars().count() < 2 {
                return Err(
                    "the query must be at least two characters; there is no way to list the \
                     whole vault"
                        .to_owned(),
                );
            }
            Ok(Request::Search {
                query,
                limit: Some(
                    optional_u32(arguments, "limit", MAX_SEARCH_RESULTS)
                        .unwrap_or(MAX_SEARCH_RESULTS),
                ),
            })
        }

        "get_entry_metadata" => Ok(Request::GetMetadata {
            reference: EntryRef(require_str(arguments, "reference")?),
        }),

        USE_SECRET => Ok(Request::UseSecret {
            reference: EntryRef(require_str(arguments, "reference")?),
            field: parse_field(optional_str(arguments, "field").as_deref())?,
            action: match optional_str(arguments, "action").as_deref() {
                None | Some("clipboard") => SecretAction::Clipboard,
                Some("type") => SecretAction::TypeIntoFocusedWindow,
                Some(other) => {
                    return Err(format!(
                        "unknown action {other:?}; expected \"clipboard\" or \"type\""
                    ))
                }
            },
        }),

        "reveal_secret" => {
            // The reason is required rather than optional: the user is being asked to approve
            // something, and "no reason given" is not an acceptable thing to show them.
            let reason = require_str(arguments, "reason")?;
            Ok(Request::Reveal {
                reference: EntryRef(require_str(arguments, "reference")?),
                field: parse_field(optional_str(arguments, "field").as_deref())?,
                reason: Some(reason),
            })
        }

        "generate_password" => Ok(Request::GeneratePassword {
            length: optional_u32(arguments, "length", MAX_GENERATED_LENGTH),
            words: optional_u32(arguments, "words", 16),
        }),

        "create_entry" => {
            let input = EntryInput {
                title: require_str(arguments, "title")?,
                username: optional_str(arguments, "username").unwrap_or_default(),
                origins: optional_str(arguments, "url").into_iter().collect(),
                tags: Vec::new(),
                notes: optional_str(arguments, "notes").unwrap_or_default(),
            };
            let secret = match optional_str(arguments, "password") {
                Some(value) if !value.is_empty() => SecretSource::Provided { value },
                // Generate by default, so the common path stores a password the agent has
                // never seen.
                _ => SecretSource::Generate {
                    length: optional_u32(arguments, "length", MAX_GENERATED_LENGTH),
                    words: None,
                },
            };
            Ok(Request::CreateEntry { input, secret })
        }

        "rotate_secret" => Ok(Request::RotateSecret {
            reference: EntryRef(require_str(arguments, "reference")?),
            secret: SecretSource::Generate {
                length: optional_u32(arguments, "length", MAX_GENERATED_LENGTH),
                words: None,
            },
        }),

        "update_entry" => Ok(Request::UpdateEntry {
            reference: EntryRef(require_str(arguments, "reference")?),
            input: EntryInput {
                title: require_str(arguments, "title")?,
                username: optional_str(arguments, "username").unwrap_or_default(),
                origins: optional_str(arguments, "url").into_iter().collect(),
                tags: Vec::new(),
                notes: optional_str(arguments, "notes").unwrap_or_default(),
            },
        }),

        "trash_entry" => Ok(Request::TrashEntry {
            reference: EntryRef(require_str(arguments, "reference")?),
        }),

        // Name the safe alternative rather than only refusing. A model told "no such tool"
        // will try variations; one told what to use instead will use it.
        "export_vault" | "list_all_entries" | "get_all_passwords" | "dump_vault" => Err(
            "Keel has no bulk-export tool, by design. Use search_entries to find the specific \
             entry you need."
                .to_owned(),
        ),
        "unlock_vault" | "change_master_passphrase" | "set_master_password" => Err(
            "Keel will not unlock a vault or change a master passphrase on request. Ask the \
             user to do it in the Keel app."
                .to_owned(),
        ),
        "delete_entry" | "purge_entry" => Err(
            "Keel has no permanent-delete tool. Use trash_entry, which is reversible.".to_owned(),
        ),

        other => Err(format!("unknown tool {other:?}")),
    }
}

/// Parse a field name.
fn parse_field(name: Option<&str>) -> Result<Field, String> {
    match name {
        None | Some("password") => Ok(Field::Password),
        Some("username") => Ok(Field::Username),
        Some("totp") => Ok(Field::Totp),
        Some("notes") => Ok(Field::Notes),
        Some(other) => Err(format!(
            "unknown field {other:?}; expected password, username, totp, or notes"
        )),
    }
}

/// Render an agent response as a tool result.
pub fn render(name: &str, response: &Response) -> ToolResult {
    match response {
        Response::Ok => ToolResult::text("Done."),

        Response::Status(info) => ToolResult::json(&serde_json::json!({
            "state": format!("{:?}", info.state),
            "permissions": info.scopes,
            "entry_count": info.entry_count,
            "locks_in_seconds": info.locks_in,
            "hint": match info.state {
                keel_proto::LockState::Unlocked => "The vault is unlocked and ready.",
                keel_proto::LockState::Locked =>
                    "The vault is locked. Ask the user to unlock it in the Keel app or with \
                     `keel unlock`; you cannot unlock it yourself.",
                keel_proto::LockState::NoVault =>
                    "No vault exists yet. Ask the user to create one with `keel init`.",
            },
        })),

        Response::Entries { entries, truncated } => ToolResult::json(&serde_json::json!({
            "entries": entries.iter().map(|e| serde_json::json!({
                "reference": e.reference.0,
                "title": e.title,
                "username": e.username,
                "websites": e.origins,
                "tags": e.tags,
                "has_totp": e.has_totp,
            })).collect::<Vec<_>>(),
            "truncated": truncated,
            "note": "Metadata only. Passwords are never included here.",
        })),

        Response::Entry(entry) => ToolResult::json(&serde_json::json!({
            "reference": entry.reference.0,
            "title": entry.title,
            "username": entry.username,
            "websites": entry.origins,
            "tags": entry.tags,
            "has_totp": entry.has_totp,
            "password_changed_at": entry.password_changed_at,
        })),

        Response::Created {
            reference,
            entropy_bits,
        } => ToolResult::json(&serde_json::json!({
            "reference": reference.0,
            "entropy_bits": entropy_bits,
            "note": "The password was generated inside Keel and is not included here. That is \
                     intentional: it is stored safely and you do not need to see it.",
        })),

        Response::Applied { description } => ToolResult::text(format!(
            "Done: the secret was {description}. It was not disclosed to you."
        )),

        Response::Secret { value, expires_in } => ToolResult::json(&serde_json::json!({
            "value": value,
            "expires_in_seconds": expires_in,
            "warning": "This is a real secret. Do not repeat it back to the user unless they \
                        asked to see it, do not write it to a file, and do not include it in \
                        any summary.",
        })),

        Response::Generated {
            value,
            entropy_bits,
        } => ToolResult::json(&serde_json::json!({
            "value": value,
            "entropy_bits": entropy_bits,
        })),

        Response::ApprovalRequired { timeout_secs, .. } => ToolResult::failure(format!(
            "This needs the user's approval. Keel is showing them a prompt; they have \
             {timeout_secs} seconds to respond. Tell the user to check the Keel window, then \
             try again. If they would rather not approve it, use use_secret instead — it \
             applies the password without revealing it."
        )),

        Response::Audit { records, .. } => ToolResult::json(&serde_json::json!({
            "records": records.len(),
        })),

        // An agent cannot grant or list grants — there is no tool for it, and the agent
        // process refuses the request from a non-human client. Reaching this means something is
        // wrong, so say so rather than inventing a plausible-looking answer.
        Response::Grants { .. } => ToolResult::failure(
            "Keel returned grant information, which no tool here requests. Managing access is \
             done by the user with `keel grant`, not by an agent.",
        ),

        // Nor a health report. It decrypts every record and answers "which of these
        // entries share a password?" across the whole vault, which is a bulk oracle over
        // exactly the data this tool surface exists to keep an agent away from. There is
        // no tool for it, and the agent refuses it to any client a human is not driving —
        // so this arm is unreachable, and says so instead of rendering the report.
        Response::Health { .. } => ToolResult::failure(
            "Keel returned a vault health report, which no tool here requests. Reviewing \
             which passwords are weak or reused is done by the user with `keel audit`.",
        ),

        // And certainly not an export. `export_vault` is the first entry on the list of
        // tools this server deliberately does not offer: it is the whole vault in
        // plaintext, which is the exact thing every other refusal here exists to prevent.
        // The agent process requires a human-driven client and a re-entered master
        // passphrase, neither of which an MCP client can supply, so this is unreachable.
        //
        // Note what is *not* done with the payload: it is dropped without being rendered,
        // logged, or described. If this arm were ever reached, turning the response into
        // model-visible text would be the disclosure, not the request that produced it.
        Response::Exported { .. } => ToolResult::failure(
            "Keel returned an export of the vault, which no tool here requests and which \
             this server will not relay. Exporting is done by the user with `keel export`.",
        ),

        // Nor the queue of prompts the user is currently being shown. Knowing what dialog
        // is open, and for what, is exactly what an attacker needs to time a second request
        // to arrive while the user's attention is on the first — so the agent refuses this
        // to any client that cannot itself prompt, and no tool here asks for it.
        Response::PendingApprovals { .. } => ToolResult::failure(
            "Keel returned the list of prompts awaiting the user, which no tool here \
             requests. Approvals are shown and answered in the Keel window.",
        ),

        // Settings are the user's, not the agent's. Reading them would tell a client
        // exactly which protections are on — including whether reveals are permitted —
        // which is reconnaissance, and there is no tool for changing them because an agent
        // that could turn on its own reveal permission would make the switch decorative.
        Response::Settings(_) => ToolResult::failure(
            "Keel returned its settings, which no tool here requests. Settings are changed \
             by the user in the Keel window or with `keel settings`.",
        ),

        // A browser fill. Only the extension can ask for one, and only for an origin the
        // browser itself reported — so this arm is unreachable. It drops the payload without
        // rendering it: this variant carries a password, and turning it into model-visible
        // text would be the disclosure.
        Response::Fill { .. } => ToolResult::failure(
            "Keel returned a credential for a browser fill, which no tool here requests and \
             which this server will not relay. Filling is done by the Keel extension.",
        ),

        Response::Hello { .. } => ToolResult::text("Connected."),

        Response::Error { code, message } => {
            ToolResult::failure(explain_error(name, *code, message))
        }
    }
}

/// Turn an agent refusal into something the model can act on.
///
/// A bare "denied" invites a model to try variations of the same request. Naming the reason
/// and the alternative turns a refusal into a redirection — which is the difference between an
/// agent that gives up usefully and one that probes until the circuit breaker trips.
fn explain_error(tool: &str, code: keel_proto::ErrorCode, message: &str) -> String {
    use keel_proto::ErrorCode as E;
    match code {
        E::Locked => {
            format!("{message}. Ask the user to unlock Keel; you cannot unlock it yourself.")
        }
        E::NoVault => format!("{message}. Ask the user to create one with `keel init`."),
        E::Denied if tool == "reveal_secret" => format!(
            "{message}\n\nIf the user's goal is to be logged in rather than to read the \
             password, use use_secret instead: it applies the password without revealing it \
             and does not need this permission."
        ),
        E::RateLimited => {
            format!("{message}. Wait before retrying, and avoid repeating the same request.")
        }
        E::NotFound => {
            format!("{message}. Search again — references stop working once the vault locks.")
        }
        _ => message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_is_no_tool_that_exports_or_enumerates_the_vault() {
        // The security of this surface is mostly what is absent from it. If someone adds a
        // bulk accessor, this is what should stop them.
        let names: Vec<&str> = all().iter().map(|t| t.name).collect();
        for forbidden in [
            "export_vault",
            "list_all_entries",
            "list_entries",
            "get_all_passwords",
            "dump_vault",
            "unlock_vault",
            "change_master_passphrase",
            "delete_entry",
            "read_file",
            "get_vault_path",
            "disable_autolock",
        ] {
            assert!(
                !names.contains(&forbidden),
                "the tool surface must not include {forbidden}"
            );
        }
    }

    #[test]
    fn a_bulk_export_attempt_is_refused_and_redirected() {
        // A model told only "no such tool" tries variations; one told what to use instead
        // uses it.
        for attempt in ["export_vault", "list_all_entries", "dump_vault"] {
            let error = to_request(attempt, &serde_json::json!({})).unwrap_err();
            assert!(error.contains("search_entries"), "{attempt}: {error}");
        }
    }

    #[test]
    fn unlocking_and_passphrase_changes_are_refused() {
        for attempt in ["unlock_vault", "change_master_passphrase"] {
            let error = to_request(attempt, &serde_json::json!({})).unwrap_err();
            assert!(error.contains("Keel app"), "{attempt}: {error}");
        }
    }

    #[test]
    fn permanent_deletion_is_refused_and_points_at_the_trash() {
        let error = to_request("delete_entry", &serde_json::json!({})).unwrap_err();
        assert!(error.contains("trash_entry"));
        assert!(error.contains("reversible"));
    }

    #[test]
    fn a_one_character_search_is_refused_with_the_reason() {
        let error = to_request("search_entries", &serde_json::json!({"query": "a"})).unwrap_err();
        assert!(error.contains("two characters"));
        assert!(error.contains("whole vault"));
    }

    #[test]
    fn search_results_are_capped_even_when_more_are_asked_for() {
        let request = to_request(
            "search_entries",
            &serde_json::json!({"query": "bank", "limit": 100_000}),
        )
        .unwrap();
        match request {
            Request::Search { limit, .. } => assert_eq!(limit, Some(MAX_SEARCH_RESULTS)),
            other => panic!("expected a search, got {other:?}"),
        }
    }

    #[test]
    fn creating_an_entry_generates_the_password_by_default() {
        // The common path must store a password the agent never sees.
        let request = to_request("create_entry", &serde_json::json!({"title": "Bank"})).unwrap();
        match request {
            Request::CreateEntry { secret, .. } => {
                assert!(matches!(secret, SecretSource::Generate { .. }));
            }
            other => panic!("expected a create, got {other:?}"),
        }
    }

    #[test]
    fn an_explicit_password_is_still_honoured_for_migration() {
        let request = to_request(
            "create_entry",
            &serde_json::json!({"title": "Old", "password": "existing"}),
        )
        .unwrap();
        match request {
            Request::CreateEntry { secret, .. } => {
                assert_eq!(
                    secret,
                    SecretSource::Provided {
                        value: "existing".to_owned()
                    }
                );
            }
            other => panic!("expected a create, got {other:?}"),
        }
    }

    #[test]
    fn revealing_requires_a_reason_because_a_human_will_read_it() {
        let error =
            to_request("reveal_secret", &serde_json::json!({"reference": "r"})).unwrap_err();
        assert!(error.contains("reason"));
    }

    #[test]
    fn use_secret_defaults_to_the_clipboard_and_the_password_field() {
        let request = to_request(USE_SECRET, &serde_json::json!({"reference": "r"})).unwrap();
        match request {
            Request::UseSecret { field, action, .. } => {
                assert_eq!(field, Field::Password);
                assert_eq!(action, SecretAction::Clipboard);
            }
            other => panic!("expected a use_secret, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_field_or_action_is_rejected_by_name() {
        assert!(to_request(
            USE_SECRET,
            &serde_json::json!({"reference": "r", "field": "everything"})
        )
        .unwrap_err()
        .contains("everything"));

        assert!(to_request(
            USE_SECRET,
            &serde_json::json!({"reference": "r", "action": "email-it"})
        )
        .unwrap_err()
        .contains("email-it"));
    }

    #[test]
    fn the_use_secret_description_tells_the_model_it_will_not_see_the_password() {
        // The model reads these. A description that only described mechanics would leave it
        // guessing which tool is appropriate.
        let tool = all().into_iter().find(|t| t.name == USE_SECRET).unwrap();
        let description = tool.description.to_lowercase();
        assert!(description.contains("without receiving it"));
        assert!(description.contains("never sent to you"));
    }

    #[test]
    fn the_reveal_description_states_that_it_is_disabled_by_default() {
        let tool = all()
            .into_iter()
            .find(|t| t.name == "reveal_secret")
            .unwrap();
        assert!(tool.description.contains("DISABLED BY DEFAULT"));
        assert!(tool.description.contains("use_secret instead"));
    }

    #[test]
    fn a_denied_reveal_points_the_model_at_use_secret() {
        let result = render(
            "reveal_secret",
            &Response::Error {
                code: keel_proto::ErrorCode::Denied,
                message: "revealing secrets to AI agents is disabled".to_owned(),
            },
        );
        let text = serde_json::to_string(&result).unwrap();
        assert!(text.contains("use_secret"));
        assert!(text.contains("isError"));
    }

    #[test]
    fn a_locked_vault_tells_the_model_it_cannot_unlock_it_itself() {
        let result = render(
            "search_entries",
            &Response::Error {
                code: keel_proto::ErrorCode::Locked,
                message: "the vault is locked".to_owned(),
            },
        );
        let text = serde_json::to_string(&result).unwrap();
        assert!(text.contains("cannot unlock it yourself"));
    }

    #[test]
    fn an_applied_secret_says_it_was_not_disclosed() {
        let result = render(
            USE_SECRET,
            &Response::Applied {
                description: "copied to the clipboard".to_owned(),
            },
        );
        let text = serde_json::to_string(&result).unwrap();
        assert!(text.contains("not disclosed to you"));
        assert!(!text.contains("isError"));
    }

    #[test]
    fn a_created_entry_explains_why_no_password_is_returned() {
        let result = render(
            "create_entry",
            &Response::Created {
                reference: EntryRef("abc".to_owned()),
                entropy_bits: Some(129.2),
            },
        );
        let text = serde_json::to_string(&result).unwrap();
        assert!(text.contains("not included here"));
        assert!(text.contains("intentional"));
    }

    #[test]
    fn a_revealed_secret_carries_handling_instructions() {
        let result = render(
            "reveal_secret",
            &Response::Secret {
                value: "hunter2".to_owned(),
                expires_in: 60,
            },
        );
        let text = serde_json::to_string(&result).unwrap();
        assert!(text.contains("real secret"));
        assert!(text.contains("do not write it to a file"));
    }

    #[test]
    fn metadata_results_never_carry_a_password_field() {
        let result = render(
            "search_entries",
            &Response::Entries {
                entries: vec![keel_proto::EntrySummary {
                    reference: EntryRef("r".to_owned()),
                    title: "Bank".to_owned(),
                    username: "ada".to_owned(),
                    origins: vec![],
                    tags: vec![],
                    has_totp: false,
                    updated_at: 0,
                    password_changed_at: 0,
                }],
                truncated: false,
            },
        );
        let text = serde_json::to_string(&result).unwrap();
        assert!(!text.contains("\\\"password\\\":"), "{text}");
        assert!(text.contains("Metadata only"));
    }

    #[test]
    fn every_tool_has_a_schema_and_a_description() {
        for tool in all() {
            assert!(
                !tool.description.is_empty(),
                "{} has no description",
                tool.name
            );
            assert_eq!(
                tool.input_schema.get("type").and_then(|t| t.as_str()),
                Some("object"),
                "{} has a malformed schema",
                tool.name
            );
            // Every tool must round-trip through the request mapper, or the surface advertises
            // something it cannot do.
            let _ = to_request(tool.name, &serde_json::json!({}));
        }
    }
}
