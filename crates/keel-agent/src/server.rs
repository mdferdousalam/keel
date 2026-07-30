//! Accept loop and request dispatch.
//!
//! Every request follows the same path, and the order matters:
//!
//! 1. **Enforce auto-lock first.** A request arriving after the idle timeout must find the
//!    vault locked, not extend the session by being served. Checking afterwards would mean
//!    a client polling every minute could keep a vault unlocked indefinitely.
//! 2. **Ask the policy engine**, with the entry's real tags looked up from the vault.
//! 3. **Record the outcome** in the audit log — including refusals, which are the ones
//!    worth having later.
//! 4. **Only then** touch vault data.
//!
//! Nothing in this module decides authorization for itself; that all lives in
//! `keel_core::policy`, so there is one place to read rather than one per request type.

use std::sync::{Arc, Mutex};

use keel_core::audit::Outcome;
use keel_core::autolock::LockReason;
use keel_core::policy::{Client, Decision, Destination, Operation};
use keel_core::EntryDraft;
use keel_format::manifest::Id;
use keel_format::RecordBody;
use keel_proto::{
    ClientKind, EntryInput, EntryRef, EntrySummary, ErrorCode, Field, Request, Response,
    SecretAction, SecretSource, StatusInfo, PROTOCOL_VERSION,
};
use keel_store::VaultPaths;

use crate::clipboard;
use crate::state::{client_type_of, count_bucket, AgentState, Failure, Result, SECRET_TTL};
use crate::transport::{Connection, Listener, PeerIdentity};

/// Default page size for list and search responses.
const DEFAULT_LIMIT: u32 = 25;

/// Largest page a client may request.
const MAX_LIMIT: u32 = 100;

/// Environment variable overriding how long an idle, locked agent lingers.
pub const IDLE_EXIT_ENV: &str = "KEEL_AGENT_IDLE_EXIT_SECS";

/// Default time an idle, locked agent waits before exiting, in seconds.
///
/// Long enough that a user running a series of commands does not pay for a restart between
/// each one, short enough that a forgotten agent does not sit in the process table for
/// days. Only ever applies while the vault is *locked*: an unlocked agent is doing its job,
/// and its own auto-lock will retire it first.
pub const DEFAULT_IDLE_EXIT_SECS: u64 = 15 * 60;

/// How often the watchdog checks whether it is time to go.
const WATCHDOG_TICK: std::time::Duration = std::time::Duration::from_secs(1);

/// A running agent.
pub struct Agent {
    state: Arc<Mutex<AgentState>>,
}

impl core::fmt::Debug for Agent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Agent")
    }
}

impl Agent {
    /// Create an agent for a vault path.
    #[must_use]
    pub fn new(paths: VaultPaths, hardening: keel_hardening::HardeningReport) -> Self {
        Self {
            state: Arc::new(Mutex::new(AgentState::new(paths, hardening))),
        }
    }

    /// Shared state, for tests and for the reveal helper.
    #[must_use]
    pub fn state(&self) -> Arc<Mutex<AgentState>> {
        Arc::clone(&self.state)
    }

    /// Start the watchdog that retires an idle, locked agent.
    ///
    /// Two jobs, both of which need to happen without a client asking:
    ///
    /// * **Enforce auto-lock on time.** Without this, a vault only locks when the next
    ///   request arrives — so walking away from an unlocked vault would leave the keys in
    ///   memory indefinitely, which is precisely the case auto-lock exists for.
    /// * **Exit when idle and locked.** A daemon holding nothing has no reason to linger,
    ///   and one process per session left running is untidy at best.
    fn start_watchdog(&self) {
        let state = Arc::clone(&self.state);
        let idle_exit = std::env::var(IDLE_EXIT_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_IDLE_EXIT_SECS);
        let _ = std::thread::Builder::new()
            .name("keel-watchdog".to_owned())
            .spawn(move || {
                let mut locked_since: Option<std::time::Instant> = None;
                loop {
                    std::thread::sleep(WATCHDOG_TICK);
                    let Ok(mut guard) = state.lock() else { return };

                    if let Some(reason) = guard.enforce_autolock() {
                        eprintln!("keel-agent: locked ({})", reason.message());
                    }

                    let is_locked = !matches!(guard.lock_state(), keel_proto::LockState::Unlocked);
                    drop(guard);

                    if is_locked {
                        // Time the idle window from when the vault was first *observed*
                        // locked, so a long unlocked session does not count toward it.
                        let since = *locked_since.get_or_insert_with(std::time::Instant::now);
                        if since.elapsed().as_secs() >= idle_exit {
                            // Nothing is held and nobody is asking, so there is nothing to
                            // shut down cleanly: the vault is already locked and its keys
                            // already wiped.
                            std::process::exit(0);
                        }
                    } else {
                        locked_since = None;
                    }
                }
            });
    }

    /// Serve connections until the listener fails.
    ///
    /// A connection that dies takes only its own thread with it; a client crashing must
    /// never bring down the process holding the vault.
    pub fn serve(&self, listener: &Listener) {
        self.start_watchdog();
        loop {
            match listener.accept() {
                Ok(connection) => {
                    let state = Arc::clone(&self.state);
                    // Detached: nothing waits on a client, and a hung client must not block
                    // the accept loop.
                    let _ = std::thread::Builder::new()
                        .name("keel-client".to_owned())
                        .spawn(move || {
                            let mut session = Session::new(state, connection);
                            session.run();
                        });
                }
                Err(error) => {
                    // A refused peer is routine; log it and keep listening. Only give up if
                    // the listener itself is broken.
                    if matches!(error, crate::transport::TransportError::Io { .. }) {
                        eprintln!("keel-agent: accept failed: {error}");
                        return;
                    }
                    eprintln!("keel-agent: connection refused: {error}");
                }
            }
        }
    }
}

/// One client connection.
struct Session {
    state: Arc<Mutex<AgentState>>,
    connection: Connection,
    client: Option<Client>,
    is_gui: bool,
}

impl Session {
    fn new(state: Arc<Mutex<AgentState>>, connection: Connection) -> Self {
        Self {
            state,
            connection,
            client: None,
            is_gui: false,
        }
    }

    fn run(&mut self) {
        // A closed connection or a malformed frame ends the session: there is nothing useful
        // to say to a peer that is gone or is not speaking the protocol.
        while let Ok(request) = self.connection.receive::<Request>() {
            let response = self.dispatch(request);
            if self.connection.send(&response).is_err() {
                break;
            }
        }
        if self.is_gui {
            if let Ok(mut state) = self.state.lock() {
                state.detach_gui();
            }
        }
    }

    fn dispatch(&mut self, request: Request) -> Response {
        match self.handle(request) {
            Ok(response) => response,
            Err(failure) => Response::Error {
                code: failure.code,
                message: failure.message,
            },
        }
    }

    /// The registered client, or an error if `Hello` has not been sent.
    fn client(&self) -> Result<Client> {
        self.client.clone().ok_or_else(|| {
            Failure::new(
                ErrorCode::BadRequest,
                "send a hello message before any other request",
            )
        })
    }

    fn handle(&mut self, request: Request) -> Result<Response> {
        // `Hello` is the only request accepted before registration.
        if let Request::Hello {
            protocol_version,
            client_kind,
            client_id,
            client_version,
        } = request
        {
            return self.handle_hello(protocol_version, client_kind, &client_id, &client_version);
        }

        let client = self.client()?;

        // Auto-lock is enforced before the request is served, not after. Serving first
        // would let a client polling every minute hold a vault open indefinitely.
        let auto_locked = {
            let mut state = self.lock_state()?;
            state.enforce_autolock()
        };
        let _ = auto_locked;

        match request {
            Request::Hello { .. } => unreachable!("handled above"),
            Request::Status => self.handle_status(&client),
            Request::CreateVault { passphrase, tier } => {
                self.handle_create_vault(&client, &passphrase, tier.as_deref())
            }
            Request::Unlock {
                passphrase,
                keyfile,
                accept_rollback,
            } => self.handle_unlock(&client, &passphrase, keyfile, accept_rollback),
            Request::Lock => self.handle_lock(&client),
            Request::Search { query, limit } => self.handle_search(&client, &query, limit),
            Request::List { limit, offset } => self.handle_list(&client, limit, offset),
            Request::GetMetadata { reference } => self.handle_get_metadata(&client, &reference),
            Request::UseSecret {
                reference,
                field,
                action,
            } => self.handle_use_secret(&client, &reference, field, &action),
            Request::Reveal {
                reference,
                field,
                reason,
            } => self.handle_reveal(&client, &reference, field, reason.as_deref()),
            Request::CreateEntry { input, secret } => {
                self.handle_create_entry(&client, input, &secret)
            }
            Request::UpdateEntry { reference, input } => {
                self.handle_update_entry(&client, &reference, input)
            }
            Request::RotateSecret { reference, secret } => {
                self.handle_rotate(&client, &reference, &secret)
            }
            Request::TrashEntry { reference } => self.handle_trash(&client, &reference),
            Request::GeneratePassword { length, words } => {
                self.handle_generate(&client, length, words)
            }
            Request::Save => self.handle_save(&client),
            Request::AuditTail { limit } => self.handle_audit_tail(&client, limit),
            Request::VaultHealth => self.handle_vault_health(&client),
            Request::GrantAccess {
                client_id,
                scopes,
                ttl_secs,
                tag_filter,
            } => self.handle_grant(&client, &client_id, &scopes, ttl_secs, tag_filter),
            Request::ListGrants => self.handle_list_grants(&client),
            Request::RevokeAccess { client_id } => self.handle_revoke(&client, &client_id),
            Request::ResolveApproval {
                approval_id,
                approved,
            } => self.handle_resolve_approval(&client, &approval_id, approved),
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, AgentState>> {
        self.state.lock().map_err(|_| {
            Failure::new(
                ErrorCode::Internal,
                "the agent's internal state is unusable; restart the agent",
            )
        })
    }

    // -----------------------------------------------------------------------
    // Handlers
    // -----------------------------------------------------------------------

    fn handle_hello(
        &mut self,
        protocol_version: u16,
        client_kind: ClientKind,
        client_id: &str,
        client_version: &str,
    ) -> Result<Response> {
        if protocol_version != PROTOCOL_VERSION {
            return Err(Failure::new(
                ErrorCode::BadRequest,
                format!(
                    "protocol version mismatch: this agent speaks {PROTOCOL_VERSION}, the \
                     client speaks {protocol_version}. Update whichever is older."
                ),
            ));
        }
        if client_id.is_empty() || client_id.len() > 128 {
            return Err(Failure::new(
                ErrorCode::BadRequest,
                "a client identifier between 1 and 128 characters is required",
            ));
        }
        let _ = client_version;

        let peer: &PeerIdentity = self.connection.peer();
        self.client = Some(Client {
            id: client_id.to_owned(),
            client_type: client_type_of(client_kind),
            executable: peer.executable.clone(),
        });

        // Only a GUI can display approval dialogs, so its presence is what decides whether
        // an agent's reveal request can be escalated or must fail closed.
        if matches!(client_kind, ClientKind::Gui) {
            self.is_gui = true;
            self.lock_state()?.attach_gui();
        }

        Ok(Response::Hello {
            protocol_version: PROTOCOL_VERSION,
            agent_version: crate::VERSION.to_owned(),
        })
    }

    fn handle_status(&mut self, client: &Client) -> Result<Response> {
        let mut state = self.lock_state()?;
        let scopes = state
            .policy()
            .effective_scopes(client, crate::state::now())
            .iter()
            .map(|s| format!("{s:?}"))
            .collect();
        let entry_count = state.vault().ok().map(|v| count_bucket(v.entries().len()));
        let hardening = *state.hardening();

        Ok(Response::Status(Box::new(StatusInfo {
            state: state.lock_state(),
            vault_path: state.vault_path(),
            scopes,
            locks_in: state.locks_in(),
            entry_count,
            agent_version: crate::VERSION.to_owned(),
            hardened: hardening.protects_against_disk_leakage(),
            warnings: hardening
                .warnings()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        })))
    }

    fn handle_create_vault(
        &mut self,
        client: &Client,
        passphrase: &str,
        tier: Option<&str>,
    ) -> Result<Response> {
        let mut state = self.lock_state()?;
        state.create_vault(passphrase, tier)?;
        state.audit(client, "create_vault", None, Outcome::Allowed, None);
        state.flush_audit();
        Ok(Response::Ok)
    }

    fn handle_unlock(
        &mut self,
        client: &Client,
        passphrase: &str,
        keyfile: Option<Vec<u8>>,
        accept_rollback: bool,
    ) -> Result<Response> {
        let mut state = self.lock_state()?;
        match state.unlock(passphrase, keyfile, accept_rollback) {
            Ok(()) => {
                // A successful unlock is what clears a tripped circuit breaker, since the
                // user has just proved they hold the passphrase.
                state.policy().reset_breaker(&client.id);
                state.audit(client, "unlock", None, Outcome::Allowed, None);
                state.flush_audit();
                Ok(Response::Ok)
            }
            Err(failure) => {
                // Failures are recorded too — repeated ones are exactly what an
                // investigation needs — but only when a log exists to write to.
                state.audit(client, "unlock", None, Outcome::Denied, None);
                Err(failure)
            }
        }
    }

    fn handle_lock(&mut self, client: &Client) -> Result<Response> {
        let mut state = self.lock_state()?;
        state.audit(client, "lock", None, Outcome::Allowed, None);
        state.flush_audit();
        state.lock(LockReason::Manual);
        Ok(Response::Ok)
    }

    fn handle_search(
        &mut self,
        client: &Client,
        query: &str,
        limit: Option<u32>,
    ) -> Result<Response> {
        let operation = Operation::Search {
            query_len: query.chars().count(),
        };
        self.authorize(client, &operation, None)?;

        let limit = clamp_limit(limit);
        let mut state = self.lock_state()?;
        state.touch();
        let ids: Vec<Id> = state
            .vault()?
            .search(query)
            .into_iter()
            .map(|e| e.record_id)
            .collect();
        let truncated = ids.len() > limit as usize;
        let ids: Vec<Id> = ids.into_iter().take(limit as usize).collect();
        let entries = summaries(&mut state, &ids)?;
        Ok(Response::Entries { entries, truncated })
    }

    fn handle_list(
        &mut self,
        client: &Client,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Response> {
        // Listing is a metadata read, and it is paged rather than unbounded so it cannot be
        // used to dump a vault in one call.
        self.authorize(client, &Operation::Search { query_len: 2 }, None)?;

        let limit = clamp_limit(limit) as usize;
        let offset = offset.unwrap_or(0) as usize;
        let mut state = self.lock_state()?;
        state.touch();
        let all: Vec<Id> = state
            .vault()?
            .entries()
            .iter()
            .map(|e| e.record_id)
            .collect();
        let truncated = all.len() > offset.saturating_add(limit);
        let page: Vec<Id> = all.into_iter().skip(offset).take(limit).collect();
        let entries = summaries(&mut state, &page)?;
        Ok(Response::Entries { entries, truncated })
    }

    fn handle_get_metadata(&mut self, client: &Client, reference: &EntryRef) -> Result<Response> {
        let id = self.lock_state()?.resolve(reference)?;
        self.authorize(client, &Operation::ReadMetadata { entry: id }, Some(id))?;

        let mut state = self.lock_state()?;
        state.touch();
        let entries = summaries(&mut state, &[id])?;
        entries
            .into_iter()
            .next()
            .map(|e| Response::Entry(Box::new(e)))
            .ok_or_else(|| Failure::new(ErrorCode::NotFound, "no entry with that reference"))
    }

    fn handle_use_secret(
        &mut self,
        client: &Client,
        reference: &EntryRef,
        field: Field,
        action: &SecretAction,
    ) -> Result<Response> {
        let id = self.lock_state()?.resolve(reference)?;

        // The destination is resolved here, from what the agent knows — never taken from
        // the requesting client. An injected agent must not be able to name where a secret
        // goes, because the destination is the one thing a user reads before approving.
        let destination = self.resolve_destination(action)?;
        let operation = Operation::UseSecret {
            entry: id,
            destination: destination.clone(),
        };
        self.authorize(client, &operation, Some(id))?;

        let mut state = self.lock_state()?;
        state.touch();
        // Decrypt, apply, and drop. The value never leaves this scope, and `RecordBody`
        // wipes itself when it falls out of it.
        let body = state
            .vault()?
            .reveal(&id)
            .map_err(|e| Failure::from_core(&e))?;
        let value = field_value(&body, field)?;
        let description = apply_secret(&destination, &value, state.clipboard())?;
        drop(body);

        state.audit(client, "use_secret", Some(id), Outcome::Allowed, None);
        state.flush_audit();
        Ok(Response::Applied { description })
    }

    fn handle_reveal(
        &mut self,
        client: &Client,
        reference: &EntryRef,
        field: Field,
        reason: Option<&str>,
    ) -> Result<Response> {
        let id = self.lock_state()?.resolve(reference)?;
        let operation = Operation::RevealSecret {
            entry: id,
            reason: reason.unwrap_or_default().to_owned(),
        };

        let tags = self.lock_state()?.tags_of(&id);
        let decision = {
            let mut state = self.lock_state()?;
            state
                .policy()
                .check(client, &operation, &tags, crate::state::now())
        };

        match decision {
            Decision::Allow => {
                let mut state = self.lock_state()?;
                state.touch();
                let body = state
                    .vault()?
                    .reveal(&id)
                    .map_err(|e| Failure::from_core(&e))?;
                let value = field_value(&body, field)?;
                state.audit(client, "reveal_secret", Some(id), Outcome::Allowed, reason);
                state.flush_audit();
                Ok(Response::Secret {
                    value,
                    expires_in: SECRET_TTL,
                })
            }
            Decision::Ask(request) => {
                // The client waits; the GUI resolves it. Nothing secret is sent yet.
                let mut state = self.lock_state()?;
                state.audit(client, "reveal_secret", Some(id), Outcome::Denied, reason);
                Ok(Response::ApprovalRequired {
                    approval_id: reference.0.clone(),
                    timeout_secs: request.timeout_secs,
                })
            }
            Decision::Deny { reason: why, .. } => {
                let mut state = self.lock_state()?;
                state.audit(client, "reveal_secret", Some(id), Outcome::Denied, reason);
                state.flush_audit();
                Err(Failure::new(ErrorCode::Denied, why))
            }
        }
    }

    fn handle_create_entry(
        &mut self,
        client: &Client,
        input: EntryInput,
        secret: &SecretSource,
    ) -> Result<Response> {
        self.authorize(client, &Operation::Write { entry: None }, None)?;

        let mut state = self.lock_state()?;
        state.touch();
        let (password, entropy) = materialise_secret(secret, &state)?;
        let body = RecordBody::new()
            .with_username(&input.username)
            .with_password(&password)
            .with_notes(&input.notes);
        let draft = draft_from(input);

        let id = state
            .vault_mut()?
            .add_entry(draft, &body)
            .map_err(|e| Failure::from_core(&e))?;
        drop(body);

        let reference = state.handle_for(&id)?;
        state.audit(client, "create_entry", Some(id), Outcome::Allowed, None);
        state.flush_audit();
        Ok(Response::Created {
            reference,
            entropy_bits: entropy,
        })
    }

    fn handle_update_entry(
        &mut self,
        client: &Client,
        reference: &EntryRef,
        input: EntryInput,
    ) -> Result<Response> {
        let id = self.lock_state()?.resolve(reference)?;
        self.authorize(client, &Operation::Write { entry: Some(id) }, Some(id))?;

        let mut state = self.lock_state()?;
        state.touch();
        let draft = draft_from(input);
        state
            .vault_mut()?
            .update_metadata(&id, draft)
            .map_err(|e| Failure::from_core(&e))?;
        state.audit(client, "update_entry", Some(id), Outcome::Allowed, None);
        state.flush_audit();
        Ok(Response::Ok)
    }

    fn handle_rotate(
        &mut self,
        client: &Client,
        reference: &EntryRef,
        secret: &SecretSource,
    ) -> Result<Response> {
        let id = self.lock_state()?.resolve(reference)?;
        self.authorize(client, &Operation::Write { entry: Some(id) }, Some(id))?;

        let mut state = self.lock_state()?;
        state.touch();
        let (new_password, entropy) = materialise_secret(secret, &state)?;
        let keep = state.vault()?.settings().password_history_keep as usize;

        // Read, rotate, write back. The old password moves into history rather than being
        // discarded, because a site that silently rejected the new one would otherwise
        // leave the user with no way back.
        let mut body = state
            .vault()?
            .reveal(&id)
            .map_err(|e| Failure::from_core(&e))?;
        body.rotate_password(new_password, crate::state::now(), keep);
        state
            .vault_mut()?
            .update_secrets(&id, &body)
            .map_err(|e| Failure::from_core(&e))?;
        drop(body);

        state.audit(client, "rotate_secret", Some(id), Outcome::Allowed, None);
        state.flush_audit();
        Ok(Response::Created {
            reference: reference.clone(),
            entropy_bits: entropy,
        })
    }

    fn handle_trash(&mut self, client: &Client, reference: &EntryRef) -> Result<Response> {
        let id = self.lock_state()?.resolve(reference)?;
        self.authorize(client, &Operation::Write { entry: Some(id) }, Some(id))?;

        let mut state = self.lock_state()?;
        state.touch();
        // Soft delete: the record stays until purged, so an accidental deletion is
        // recoverable.
        state
            .vault_mut()?
            .trash_entry(&id, 30)
            .map_err(|e| Failure::from_core(&e))?;
        state.audit(client, "trash_entry", Some(id), Outcome::Allowed, None);
        state.flush_audit();
        Ok(Response::Ok)
    }

    fn handle_generate(
        &mut self,
        client: &Client,
        length: Option<u32>,
        words: Option<u32>,
    ) -> Result<Response> {
        // Needs no vault access, so it works while locked.
        self.authorize(client, &Operation::GeneratePassword, None)?;
        let (value, entropy_bits) = generate(length, words, None)?;
        Ok(Response::Generated {
            value,
            entropy_bits,
        })
    }

    fn handle_save(&mut self, client: &Client) -> Result<Response> {
        self.authorize(client, &Operation::Write { entry: None }, None)?;
        let mut state = self.lock_state()?;
        state.touch();
        state
            .vault_mut()?
            .save()
            .map_err(|e| Failure::from_core(&e))?;
        state.audit(client, "save", None, Outcome::Allowed, None);
        state.flush_audit();
        Ok(Response::Ok)
    }

    fn handle_audit_tail(&mut self, client: &Client, limit: Option<u32>) -> Result<Response> {
        self.authorize(client, &Operation::ReadAudit, None)?;
        let _ = limit;
        // Reading the log back from disk is a Phase 4 concern (the GUI shows it); the
        // request is accepted now so clients can be written against a stable protocol.
        Ok(Response::Audit {
            records: Vec::new(),
            chain_broken: false,
        })
    }

    /// Assess every stored password.
    ///
    /// The most secret-exposing operation the agent performs: it decrypts every record
    /// in the vault. Three things keep that acceptable.
    ///
    /// The policy engine refuses it outright to anything a human is not driving, checked
    /// before scopes so no grant can reach it. The decrypted bodies live in one local
    /// vector that is dropped — and therefore wiped, `RecordBody` being
    /// `ZeroizeOnDrop` — before the response is built. And the response type carries no
    /// field that could hold a password, so the assessment cannot leak one even by
    /// mistake.
    ///
    /// A record that fails to decrypt is counted rather than fatal. A damaged vault
    /// should still get a report on the entries that are readable, with the damage
    /// stated, rather than no report at all.
    fn handle_vault_health(&mut self, client: &Client) -> Result<Response> {
        self.authorize(client, &Operation::VaultHealth, None)?;

        let mut state = self.lock_state()?;
        state.touch();

        // Metadata is cloned up front because handles are allocated later through a
        // mutable borrow of the same state.
        let metas: Vec<keel_format::manifest::EntryMeta> = state.vault()?.entries().to_vec();

        let mut unreadable = 0usize;
        let mut bodies: Vec<(usize, RecordBody)> = Vec::with_capacity(metas.len());
        for (index, meta) in metas.iter().enumerate() {
            match state.vault()?.reveal(&meta.record_id) {
                Ok(body) => bodies.push((index, body)),
                // Nothing here names the entry: a decryption failure is reported as a
                // count, and the audit log already records that a health check ran.
                Err(_) => unreadable += 1,
            }
        }

        let candidates: Vec<keel_core::health::Candidate<'_>> = bodies
            .iter()
            .filter_map(|(index, body)| {
                metas.get(*index).map(|meta| keel_core::health::Candidate {
                    meta,
                    password: Some(body.password.as_str()),
                })
            })
            .collect();

        let mut report = keel_core::health::assess(&candidates, crate::state::now());
        report.unreadable = unreadable;
        // Wipe the plaintext before doing anything else. `RecordBody` zeroizes on drop,
        // and `candidates` borrows from `bodies`, so both go here together.
        drop(candidates);
        drop(bodies);

        let flagged = report.flagged();
        let mut reused = Vec::with_capacity(report.reused.len());
        for group in &report.reused {
            reused.push(health_entries(&mut state, &group.entries)?);
        }
        let weak = health_entries(&mut state, &report.weak)?;
        let stale = health_entries(&mut state, &report.stale)?;

        state.audit(client, "vault_health", None, Outcome::Allowed, None);
        state.flush_audit();

        Ok(Response::Health {
            examined: report.examined,
            without_password: report.without_password,
            unreadable: report.unreadable,
            reused,
            weak,
            stale,
            flagged,
        })
    }

    /// Issue a grant to another client.
    ///
    /// Restricted to human-driven clients. An agent that could grant itself scopes would make
    /// the entire scope system decorative, so this is the one place where the *requesting*
    /// client's type is an authorization decision rather than merely a default.
    fn handle_grant(
        &mut self,
        client: &Client,
        target: &str,
        scopes: &[String],
        ttl_secs: Option<u64>,
        tag_filter: Option<String>,
    ) -> Result<Response> {
        if !client.client_type.can_prompt_user() {
            return Err(Failure::new(
                ErrorCode::Denied,
                "only the desktop app or the command line may grant access to another client",
            ));
        }
        if target.is_empty() || target.len() > 128 {
            return Err(Failure::new(
                ErrorCode::BadRequest,
                "a client identifier between 1 and 128 characters is required",
            ));
        }
        if scopes.is_empty() {
            return Err(Failure::new(
                ErrorCode::BadRequest,
                "at least one capability is required",
            ));
        }

        let mut parsed = std::collections::BTreeSet::new();
        for name in scopes {
            parsed.insert(parse_scope(name)?);
        }

        let filter = match &tag_filter {
            Some(pattern) => keel_core::policy::EntryFilter::TagGlob(pattern.clone()),
            None => keel_core::policy::EntryFilter::All,
        };

        let mut grant_id = [0u8; 16];
        keel_crypto::fill_random(&mut grant_id).map_err(|_| {
            Failure::new(
                ErrorCode::Internal,
                "the operating system random number generator failed",
            )
        })?;

        let ttl = ttl_secs.unwrap_or(keel_core::policy::DEFAULT_GRANT_TTL);
        let now = crate::state::now();
        let grant = keel_core::policy::Grant::new(grant_id, target, parsed, filter, now, ttl);
        let expires_at = grant.expires_at;

        let mut state = self.lock_state()?;
        state.policy().add_grant(grant);
        // A fresh grant from a human also clears a tripped breaker for that client: the user has
        // just deliberately re-authorised it.
        state.policy().reset_breaker(target);
        state.audit(client, "grant_access", None, Outcome::Allowed, Some(target));
        state.flush_audit();

        Ok(Response::Grants {
            grants: vec![keel_proto::GrantSummary {
                client_id: target.to_owned(),
                scopes: scopes.to_vec(),
                tag_filter,
                expires_at,
                uses_remaining: keel_core::policy::DEFAULT_MAX_USES,
            }],
        })
    }

    /// List grants in force.
    fn handle_list_grants(&mut self, client: &Client) -> Result<Response> {
        let now = crate::state::now();
        let mut state = self.lock_state()?;
        let grants = state
            .policy()
            .persistable(now)
            .into_iter()
            .map(|g| keel_proto::GrantSummary {
                client_id: g.client_id,
                scopes: g.scopes.iter().map(|s| scope_name(*s).to_owned()).collect(),
                tag_filter: g.tag_filter,
                expires_at: g.expires_at,
                uses_remaining: 0,
            })
            .collect();
        let _ = client;
        Ok(Response::Grants { grants })
    }

    /// Revoke every grant held by a client.
    ///
    /// Deliberately available to any client, including the one losing access: nobody should
    /// have to ask permission to give up permission.
    fn handle_revoke(&mut self, client: &Client, target: &str) -> Result<Response> {
        let mut state = self.lock_state()?;
        let removed = state.policy().revoke_client(target);
        state.audit(
            client,
            "revoke_access",
            None,
            Outcome::Allowed,
            Some(target),
        );
        state.flush_audit();
        let _ = removed;
        Ok(Response::Ok)
    }

    fn handle_resolve_approval(
        &mut self,
        client: &Client,
        approval_id: &str,
        approved: bool,
    ) -> Result<Response> {
        // Only a human-driven client may answer a prompt. An agent resolving its own
        // approval would make the whole mechanism decorative.
        if !client.client_type.can_prompt_user() {
            return Err(Failure::new(
                ErrorCode::Denied,
                "only the desktop app or the command line may resolve an approval",
            ));
        }
        let reference = EntryRef(approval_id.to_owned());
        let id = self.lock_state()?.resolve(&reference)?;
        let mut state = self.lock_state()?;
        state
            .policy()
            .resolve_reveal_approval(client, &id, approved, crate::state::now());
        Ok(Response::Ok)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Run an operation past the policy engine, recording a refusal in the audit log.
    fn authorize(
        &mut self,
        client: &Client,
        operation: &Operation,
        entry: Option<Id>,
    ) -> Result<()> {
        let tags = entry.map(|id| self.lock_state().map(|s| s.tags_of(&id)));
        let tags = match tags {
            Some(Ok(tags)) => tags,
            Some(Err(failure)) => return Err(failure),
            None => Vec::new(),
        };

        let mut state = self.lock_state()?;
        match state
            .policy()
            .check(client, operation, &tags, crate::state::now())
        {
            Decision::Allow => Ok(()),
            Decision::Deny { reason, .. } => {
                state.audit(client, operation.label(), entry, Outcome::Denied, None);
                state.flush_audit();
                Err(Failure::new(ErrorCode::Denied, reason))
            }
            Decision::Ask(_) => Err(Failure::new(
                ErrorCode::Denied,
                "this operation needs your approval in the Keel window",
            )),
        }
    }

    /// Turn a requested action into a concrete, validated destination.
    fn resolve_destination(&self, action: &SecretAction) -> Result<Destination> {
        match action {
            SecretAction::Clipboard => {
                // The delay is the user's setting, clamped to the range the clipboard
                // thread will honour, so the number shown in the approval dialog is the
                // number that will actually be used. A dialog promising a 600-second
                // clear that silently becomes 120 would be a lie in the one place the
                // user is being asked to trust us.
                let configured = self
                    .lock_state()?
                    .vault()
                    .map_or(DEFAULT_CLIPBOARD_CLEAR_SECS, |v| {
                        v.settings().clipboard_clear_secs
                    });
                Ok(Destination::Clipboard {
                    clear_after: configured
                        .clamp(clipboard::MIN_CLEAR_SECS, clipboard::MAX_CLEAR_SECS),
                })
            }
            SecretAction::TypeIntoFocusedWindow => Ok(Destination::TypeIntoWindow {
                // The real window title needs platform code; until then the destination is
                // reported honestly as unknown rather than guessed, because a wrong
                // destination in an approval dialog is worse than an unspecific one.
                window: "the focused window".to_owned(),
            }),
            SecretAction::FillInBrowser { .. } => Err(Failure::new(
                ErrorCode::BadRequest,
                "browser fill requires the Keel browser extension, which is not connected",
            )),
        }
    }
}

/// Parse a capability name from the wire.
fn parse_scope(name: &str) -> Result<keel_core::policy::Scope> {
    use keel_core::policy::Scope;
    match name.to_ascii_lowercase().replace('-', "_").as_str() {
        "metadata_read" | "metadata" => Ok(Scope::MetadataRead),
        "secret_use" | "use" => Ok(Scope::SecretUse),
        "secret_reveal" | "reveal" => Ok(Scope::SecretReveal),
        "entry_write" | "write" => Ok(Scope::EntryWrite),
        "totp_read" | "totp" => Ok(Scope::TotpRead),
        "audit_read" | "audit" => Ok(Scope::AuditRead),
        other => Err(Failure::new(
            ErrorCode::BadRequest,
            format!(
                "unknown capability {other:?}; expected metadata_read, secret_use, \
                 secret_reveal, entry_write, totp_read, or audit_read"
            ),
        )),
    }
}

/// Wire name for a capability.
const fn scope_name(scope: keel_core::policy::Scope) -> &'static str {
    use keel_core::policy::Scope;
    match scope {
        Scope::MetadataRead => "metadata_read",
        Scope::SecretUse => "secret_use",
        Scope::SecretReveal => "secret_reveal",
        Scope::EntryWrite => "entry_write",
        Scope::TotpRead => "totp_read",
        Scope::AuditRead => "audit_read",
    }
}

/// Clamp a client-requested page size.
fn clamp_limit(requested: Option<u32>) -> u32 {
    requested.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// Build wire summaries for a set of entries, issuing handles as needed.
fn summaries(state: &mut AgentState, ids: &[Id]) -> Result<Vec<EntrySummary>> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let reference = state.handle_for(id)?;
        let vault = state.vault()?;
        let Ok(entry) = vault.entry(id) else { continue };
        out.push(EntrySummary {
            reference,
            title: entry.title.clone(),
            username: entry.username.clone(),
            origins: entry.origins.clone(),
            tags: entry.tags.clone(),
            has_totp: entry.has_totp,
            updated_at: entry.updated_at,
            password_changed_at: entry.password_changed_at,
        });
    }
    Ok(out)
}

/// Convert wire input into a core draft.
fn draft_from(input: EntryInput) -> EntryDraft {
    EntryDraft {
        title: input.title,
        username: input.username,
        origins: input.origins,
        tags: input.tags,
        folder_id: None,
        favorite: false,
    }
}

/// Read one field out of a decrypted record.
fn field_value(body: &RecordBody, field: Field) -> Result<String> {
    match field {
        Field::Password => Ok(body.password.clone()),
        Field::Username => Ok(body.username.clone()),
        Field::Notes => Ok(body.notes.clone()),
        Field::Totp => body
            .totp_secret
            .clone()
            .ok_or_else(|| Failure::new(ErrorCode::NotFound, "this entry has no TOTP secret")),
    }
}

/// Render health assessments for the wire, allocating a session handle for each.
///
/// Handles rather than raw ids, for the same reason every other response uses them: a
/// transcript containing one is useless after the vault locks.
fn health_entries(
    state: &mut AgentState,
    entries: &[keel_core::health::EntryHealth],
) -> Result<Vec<keel_proto::HealthEntry>> {
    entries
        .iter()
        .map(|entry| {
            Ok(keel_proto::HealthEntry {
                reference: state.handle_for(&entry.id)?,
                title: entry.title.clone(),
                username: entry.username.clone(),
                bits: entry.bits,
                strength: entry.strength.label().to_owned(),
                age_days: entry.age_days,
                shared_with: entry.shared_with,
            })
        })
        .collect()
}

/// Produce the value for a new or rotated secret.
///
/// `Generate` is the preferred form and the only one an AI agent should normally use: the
/// value is created here and never crosses back over the wire, so the caller stores a
/// password it has never seen.
fn materialise_secret(source: &SecretSource, state: &AgentState) -> Result<(String, Option<f64>)> {
    match source {
        SecretSource::Provided { value } => {
            if value.is_empty() {
                return Err(Failure::new(
                    ErrorCode::BadRequest,
                    "a password value is required",
                ));
            }
            Ok((value.clone(), None))
        }
        SecretSource::Generate { length, words } => {
            let defaults = state.vault().ok().map(|v| v.settings().generator);
            let (value, entropy) = generate(*length, *words, defaults)?;
            Ok((value, Some(entropy)))
        }
    }
}

/// Clipboard clear delay used when no vault is open to read the setting from.
///
/// Matches `VaultSettings::default`, so a copy made before the vault's own setting is
/// readable behaves the same as one made after.
const DEFAULT_CLIPBOARD_CLEAR_SECS: u32 = 15;

/// Generate a password or passphrase, returning it with its entropy.
fn generate(
    length: Option<u32>,
    words: Option<u32>,
    defaults: Option<keel_format::GeneratorDefaults>,
) -> Result<(String, f64)> {
    if let Some(words) = words {
        let policy = keel_crypto::PassphrasePolicy {
            words: words as usize,
            separator: '-',
            capitalize: false,
        };
        let phrase = keel_crypto::generate_passphrase(&policy)
            .map_err(|e| Failure::new(ErrorCode::BadRequest, e.to_string()))?;
        return Ok((phrase.expose().to_owned(), policy.entropy_bits()));
    }

    let mut policy = defaults
        .map(keel_format::GeneratorDefaults::to_policy)
        .unwrap_or_default();
    if let Some(length) = length {
        policy.length = length as usize;
    }
    let password = keel_crypto::generate_password(&policy)
        .map_err(|e| Failure::new(ErrorCode::BadRequest, e.to_string()))?;
    Ok((password.expose().to_owned(), policy.entropy_bits()))
}

/// Apply a secret to its destination, returning what to tell the user.
///
/// The returned string is what the user is told happened, so it must never describe an
/// action that did not occur. Anything that cannot be carried out returns `Err`: a user
/// who believes a password was copied, and then pastes stale clipboard contents into a
/// login form, has been actively misled.
fn apply_secret(
    destination: &Destination,
    value: &str,
    clipboard: &clipboard::Clipboard,
) -> Result<String> {
    match destination {
        Destination::Clipboard { clear_after } => {
            clipboard
                .set_secret(value, *clear_after)
                .map_err(|e| Failure::new(ErrorCode::Internal, e))?;
            Ok(destination.describe())
        }
        Destination::TypeIntoWindow { .. } => {
            // Synthetic typing needs to know which window has focus, and to be able to
            // check it is the one the user was shown before approving. Without that
            // check, typing is strictly worse than the clipboard: it delivers the secret
            // to whatever grabbed focus in the meantime, with no trace. Refusing and
            // pointing at the working alternative is the honest option.
            Err(Failure::new(
                ErrorCode::Internal,
                "typing a secret needs the desktop app, which is not connected. \
                 Copy to the clipboard instead.",
            ))
        }
        Destination::FillInBrowser { .. } => Err(Failure::new(
            ErrorCode::Internal,
            "browser fill needs the Keel browser extension, which is not connected",
        )),
    }
}

/// Bind the socket and serve until the process is stopped.
pub fn run(paths: VaultPaths) -> std::result::Result<(), crate::transport::TransportError> {
    // Hardening first, before any secret can exist.
    let hardening = keel_hardening::init();
    for warning in hardening.warnings() {
        eprintln!("keel-agent: {warning}");
    }

    let path = crate::transport::socket_path();
    let listener = Listener::bind(&path)?;
    eprintln!("keel-agent: listening on {}", listener.path().display());

    let agent = Agent::new(paths, hardening);
    agent.serve(&listener);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_sizes_are_clamped_to_a_sane_range() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(u32::MAX)), MAX_LIMIT);
    }

    #[test]
    fn generating_a_password_reports_its_entropy() {
        let (value, bits) = generate(Some(24), None, None).unwrap();
        assert_eq!(value.chars().count(), 24);
        assert!(
            bits > 150.0,
            "24 characters should exceed 150 bits, got {bits}"
        );
    }

    #[test]
    fn generating_a_passphrase_uses_words() {
        // Word count is checked by separator count, not by splitting: four words in the
        // EFF list contain a hyphen, which is also the separator, so `split('-').count()`
        // over-counts about 0.4% of seven-word phrases. That exact assertion elsewhere in
        // the workspace produced a flake that took a while to pin down.
        let (value, bits) = generate(None, Some(7), None).unwrap();
        assert!(
            value.matches('-').count() >= 6,
            "seven words need at least six separators: {value}"
        );
        assert!(!value.is_empty());
        assert!(bits > 90.0, "7 words should exceed 90 bits, got {bits}");
    }

    #[test]
    fn a_provided_empty_password_is_refused() {
        // Storing an empty password silently would leave a user believing they had one.
        let state = AgentState::new(
            VaultPaths::new("/tmp/does-not-exist/vault.keel").unwrap(),
            keel_hardening::init(),
        );
        let source = SecretSource::Provided {
            value: String::new(),
        };
        assert_eq!(
            materialise_secret(&source, &state).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn applying_a_secret_refuses_rather_than_pretending() {
        // A user who is told a password was copied, and then pastes stale clipboard
        // contents into a login form, has been actively misled. Destinations that cannot
        // be carried out must fail loudly rather than return a cheerful description.
        let clipboard = clipboard::Clipboard::start();
        for destination in [
            Destination::TypeIntoWindow {
                window: "some window".to_owned(),
            },
            Destination::FillInBrowser {
                origin: "https://example.com".to_owned(),
                browser: "Chrome".to_owned(),
            },
        ] {
            let failure = apply_secret(&destination, "secret", &clipboard).unwrap_err();
            assert_eq!(failure.code, ErrorCode::Internal);
            assert!(
                failure.message.contains("not connected"),
                "should say what is missing: {}",
                failure.message
            );
        }
    }

    #[test]
    fn a_clipboard_destination_describes_where_the_secret_went() {
        // What the user is told must name the destination and the clear delay, because
        // that description is what they read in the approval dialog. Whether the copy
        // itself works is the clipboard module's business, and is tested there against an
        // in-memory backend rather than by hijacking the developer's clipboard.
        let description = Destination::Clipboard { clear_after: 30 }.describe();
        assert!(
            description.contains("clipboard") && description.contains("30"),
            "should name the destination and the delay: {description}"
        );
    }

    #[test]
    fn reading_a_missing_totp_secret_is_a_not_found() {
        let body = RecordBody::new().with_password("p");
        assert_eq!(
            field_value(&body, Field::Totp).unwrap_err().code,
            ErrorCode::NotFound
        );
        assert_eq!(field_value(&body, Field::Password).unwrap(), "p");
    }
}
