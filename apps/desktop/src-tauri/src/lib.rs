//! The Keel desktop shell.
//!
//! A Tauri window over the agent. It holds no keys, opens no vault, and — the part that
//! shapes every decision in this crate — **never passes a secret to the webview**.
//!
//! # The invariant
//!
//! A webview is a browser. It runs a garbage-collected language whose strings cannot be
//! zeroized, in a process with a JIT, a DOM, and a devtools protocol. Putting a password
//! in it means putting a password somewhere it can be copied by the allocator, retained by
//! the GC, and read by anything that can talk to the inspector. So passwords do not go
//! there.
//!
//! What the webview gets instead:
//!
//! * **Opaque handles.** An [`EntryRef`](keel_proto::EntryRef) is a random per-session
//!   token the agent maps back to an entry. It is meaningless after a lock, so a webview
//!   heap dumped from a crash report three days later contains nothing usable.
//! * **Masks.** A password field arrives as a run of bullets, its length, and a strength
//!   estimate. Enough to render, not enough to read.
//! * **Descriptions of completed actions.** "Copied to the clipboard, cleared after 15
//!   seconds" is a string; the password it describes never crossed the boundary.
//!
//! Every action that needs the plaintext happens in the agent, which already holds it
//! decrypted. This shell asks for the *action*, not the value — so the plaintext does not
//! enter this process either, let alone the webview. That is stronger than the original
//! design, which had the shell perform clipboard writes itself.
//!
//! [`masking`] is where this is enforced, and
//! `tests/no_secrets_in_the_webview.rs` is where it is checked: a canary password is
//! stored and every command's serialised result is searched for it.
//!
//! # The one exception, stated plainly
//!
//! The master passphrase is typed into an HTML password field, so it does enter the JS
//! heap on its way to the agent. There is no way around that short of a separate native
//! prompt, which is worth building and is not built. The invariant is therefore precisely:
//! *no secret **stored in the vault** is ever given to the webview.* The passphrase the
//! user is currently typing is a different thing from the hundred passwords the vault
//! holds, and conflating them would overstate what this design achieves. It is recorded in
//! `docs/threat-model.md` rather than left for a reader to discover.

// Tests build values and assert on them; the production lints that forbid panicking would
// only make them longer without making them safer. Matches every other crate here.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::sync::Mutex;

use keel_client::Client;
use keel_proto::{ClientKind, Field, Request, Response, SecretAction};

pub mod masking;

/// Identifier this shell presents to the agent.
const CLIENT_ID: &str = "keel-desktop";

/// The connection to the agent, shared across commands.
///
/// One connection, serialised by a mutex. The agent is local and every operation is
/// sub-millisecond apart from unlock, so there is nothing to gain from concurrency and a
/// good deal of complexity to avoid: a second connection would be a second session, with
/// its own handle table, and handles would stop resolving depending on which one a command
/// happened to use.
pub struct AgentLink {
    client: Mutex<Option<Client>>,
}

/// Written by hand rather than derived, so it reports whether a connection exists without
/// reaching into it. A derived impl would try to format the `Client`, and the point of this
/// crate is that nothing here is casually printable.
impl core::fmt::Debug for AgentLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let connected = self.client.lock().map(|c| c.is_some()).unwrap_or(false);
        f.debug_struct("AgentLink")
            .field("connected", &connected)
            .finish()
    }
}

impl Default for AgentLink {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentLink {
    /// A link that has not connected yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            client: Mutex::new(None),
        }
    }

    /// Send a request, connecting or reconnecting as needed.
    ///
    /// A dropped connection reconnects once and retries. The agent retires itself when idle,
    /// so a window left open overnight will find its connection gone in the morning; making
    /// the user restart the app for that would be indefensible.
    fn request(&self, request: &Request) -> Result<Response, String> {
        let mut guard = self
            .client
            .lock()
            .map_err(|_| "the desktop shell's connection state is unusable; restart Keel")?;

        if guard.is_none() {
            *guard = Some(connect()?);
        }

        // First attempt.
        if let Some(client) = guard.as_mut() {
            match client.request(request) {
                Ok(response) => return interpret(response),
                Err(_) => {
                    // Assume the connection died rather than that the request was bad; a
                    // genuinely bad request will fail the same way on the retry and be
                    // reported then.
                    *guard = None;
                }
            }
        }

        *guard = Some(connect()?);
        let client = guard
            .as_mut()
            .ok_or_else(|| "could not reach the Keel agent".to_owned())?;
        let response = client
            .request(request)
            .map_err(|e| format!("could not reach the Keel agent: {e}"))?;
        interpret(response)
    }
}

fn connect() -> Result<Client, String> {
    Client::connect(ClientKind::Gui, CLIENT_ID)
        .map_err(|e| format!("could not reach the Keel agent: {e}"))
}

/// Turn an agent error response into an `Err`, so commands need not check for it.
///
/// The message is the agent's own. Those messages are written to be read by a person and
/// to say what to do next, so rewording them here would only lose information.
fn interpret(response: Response) -> Result<Response, String> {
    match response {
        Response::Error { message, .. } => Err(message),
        other => Ok(other),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
//
// Every return type is a `masking::*` view. That is the enforcement point: a command
// cannot accidentally return a `keel_proto` type carrying a secret, because the views are
// the only thing the command layer knows how to build, and none of them has a field for
// one.

/// Lock state, entry count, and hardening — everything the header needs.
#[tauri::command]
fn status(link: tauri::State<'_, AgentLink>) -> Result<masking::StatusView, String> {
    let response = link.request(&Request::Status)?;
    masking::StatusView::from_response(&response)
}

/// Unlock the vault.
///
/// The passphrase arrives from the webview — see the module documentation for why that is
/// the one thing crossing that boundary, and why it is not the same as handing over a
/// stored secret.
#[tauri::command]
fn unlock(link: tauri::State<'_, AgentLink>, passphrase: String) -> Result<(), String> {
    link.request(&Request::Unlock {
        passphrase,
        keyfile: None,
        // The rollback warning is a decision for the user, so the UI must show it before
        // accepting. Never set here: silently accepting a rollback would defeat the
        // detection entirely.
        accept_rollback: false,
    })?;
    Ok(())
}

/// Create a vault, for first run.
#[tauri::command]
fn create_vault(
    link: tauri::State<'_, AgentLink>,
    passphrase: String,
    tier: String,
) -> Result<(), String> {
    link.request(&Request::CreateVault {
        passphrase,
        tier: Some(tier),
    })?;
    Ok(())
}

/// Lock the vault, wiping keys and clearing the clipboard if it still holds our value.
#[tauri::command]
fn lock(link: tauri::State<'_, AgentLink>) -> Result<(), String> {
    link.request(&Request::Lock)?;
    Ok(())
}

/// Every entry, masked.
#[tauri::command]
fn list_entries(link: tauri::State<'_, AgentLink>) -> Result<Vec<masking::EntryView>, String> {
    let response = link.request(&Request::List {
        limit: None,
        offset: None,
    })?;
    masking::entry_views(&response)
}

/// Entries matching a query, masked.
#[tauri::command]
fn search(
    link: tauri::State<'_, AgentLink>,
    query: String,
) -> Result<Vec<masking::EntryView>, String> {
    let response = link.request(&Request::Search { query, limit: None })?;
    masking::entry_views(&response)
}

/// One entry's detail, with the password represented rather than included.
#[tauri::command]
fn entry_detail(
    link: tauri::State<'_, AgentLink>,
    reference: String,
) -> Result<masking::DetailView, String> {
    let response = link.request(&Request::GetMetadata {
        reference: keel_proto::EntryRef(reference),
    })?;
    masking::DetailView::from_response(&response)
}

/// Copy a field to the clipboard.
///
/// The agent does the copying, so the plaintext never reaches this process. What comes back
/// is a sentence describing what happened, which is what the UI shows.
#[tauri::command]
fn copy_field(
    link: tauri::State<'_, AgentLink>,
    reference: String,
    field: String,
) -> Result<String, String> {
    let response = link.request(&Request::UseSecret {
        reference: keel_proto::EntryRef(reference),
        field: parse_field(&field)?,
        action: SecretAction::Clipboard,
    })?;
    match response {
        Response::Applied { description } => Ok(description),
        other => Err(unexpected(&other)),
    }
}

/// Add an entry with a generated password.
///
/// Generation happens in the agent and the value is never returned. The user does not see
/// their new password, which is the point: seeing it is what leads to writing it down.
#[tauri::command]
fn add_entry(
    link: tauri::State<'_, AgentLink>,
    title: String,
    username: String,
    url: String,
    tags: Vec<String>,
    length: Option<u32>,
    words: Option<u32>,
) -> Result<masking::CreatedView, String> {
    let origins = if url.trim().is_empty() {
        Vec::new()
    } else {
        vec![url.trim().to_owned()]
    };
    let response = link.request(&Request::CreateEntry {
        input: keel_proto::EntryInput {
            title,
            username,
            origins,
            tags,
            notes: String::new(),
        },
        secret: keel_proto::SecretSource::Generate { length, words },
    })?;
    masking::CreatedView::from_response(&response)
}

/// Replace an entry's password with a fresh generated one.
#[tauri::command]
fn rotate(
    link: tauri::State<'_, AgentLink>,
    reference: String,
) -> Result<masking::CreatedView, String> {
    let response = link.request(&Request::RotateSecret {
        reference: keel_proto::EntryRef(reference),
        secret: keel_proto::SecretSource::Generate {
            length: None,
            words: None,
        },
    })?;
    masking::CreatedView::from_response(&response)
}

/// Move an entry to the trash. Soft delete only; there is no hard delete here.
#[tauri::command]
fn trash(link: tauri::State<'_, AgentLink>, reference: String) -> Result<(), String> {
    link.request(&Request::TrashEntry {
        reference: keel_proto::EntryRef(reference),
    })?;
    Ok(())
}

/// Persist pending changes.
#[tauri::command]
fn save(link: tauri::State<'_, AgentLink>) -> Result<(), String> {
    link.request(&Request::Save)?;
    Ok(())
}

/// The vault health report: reused, weak, and old passwords. Carries no values.
#[tauri::command]
fn health(link: tauri::State<'_, AgentLink>) -> Result<masking::HealthView, String> {
    let response = link.request(&Request::VaultHealth)?;
    masking::HealthView::from_response(&response)
}

/// Recent vault activity, with the audit chain's verdict.
#[tauri::command]
fn activity(link: tauri::State<'_, AgentLink>, limit: u32) -> Result<masking::LogView, String> {
    let response = link.request(&Request::AuditTail { limit: Some(limit) })?;
    masking::LogView::from_response(&response)
}

/// Access currently granted to automated clients.
#[tauri::command]
fn grants(link: tauri::State<'_, AgentLink>) -> Result<Vec<masking::GrantView>, String> {
    let response = link.request(&Request::ListGrants)?;
    masking::grant_views(&response)
}

/// Revoke everything a client holds.
#[tauri::command]
fn revoke(link: tauri::State<'_, AgentLink>, client_id: String) -> Result<(), String> {
    link.request(&Request::RevokeAccess { client_id })?;
    Ok(())
}

/// Requests waiting for the user to allow or refuse.
///
/// Polled by the UI. Everything in the view is ground truth from the agent except
/// `agent_text`, which the UI must render as inert text.
#[tauri::command]
fn pending_approvals(
    link: tauri::State<'_, AgentLink>,
) -> Result<Vec<keel_proto::PendingApprovalView>, String> {
    let response = link.request(&Request::PendingApprovals)?;
    match response {
        Response::PendingApprovals { approvals } => Ok(approvals),
        other => Err(unexpected(&other)),
    }
}

/// Answer a pending request.
#[tauri::command]
fn resolve_approval(
    link: tauri::State<'_, AgentLink>,
    approval_id: String,
    approved: bool,
) -> Result<(), String> {
    link.request(&Request::ResolveApproval {
        approval_id,
        approved,
    })?;
    Ok(())
}

fn parse_field(field: &str) -> Result<Field, String> {
    match field {
        "password" => Ok(Field::Password),
        "username" => Ok(Field::Username),
        "totp" => Ok(Field::Totp),
        "notes" => Ok(Field::Notes),
        other => Err(format!("unknown field {other:?}")),
    }
}

fn unexpected(response: &Response) -> String {
    // Names the variant, never its contents: a mismatched `Response::Secret` would
    // otherwise put a password into an error string bound for the webview.
    format!(
        "the agent sent a {} response, which this window did not ask for",
        masking::variant_name(response)
    )
}

/// Build and run the application.
///
/// # Errors
///
/// Returns an error if the Tauri runtime cannot start — no display, or a webview the
/// platform refuses to create.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    tauri::Builder::default()
        .manage(AgentLink::new())
        .invoke_handler(tauri::generate_handler![
            status,
            unlock,
            create_vault,
            lock,
            list_entries,
            search,
            entry_detail,
            copy_field,
            add_entry,
            rotate,
            trash,
            save,
            health,
            activity,
            grants,
            revoke,
            pending_approvals,
            resolve_approval,
        ])
        .run(tauri::generate_context!())?;
    Ok(())
}
