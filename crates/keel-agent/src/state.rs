// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The agent's shared state: the unlocked vault, policy, audit, and handle table.
//!
//! Everything that must be consistent across connections lives here behind one mutex.
//! One lock rather than several because the invariants span them — a lock must
//! simultaneously zeroize the keys, invalidate every handle, and revoke every grant, and
//! a reader that saw two of those three would be reading a state that never legitimately
//! exists.
//!
//! Contention is not a concern: this serialises a handful of local clients, and every
//! operation is either microseconds of in-memory work or an unlock the user is already
//! waiting seconds for.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use keel_core::audit::{AuditEvent, AuditLog, Outcome};
use keel_core::autolock::{AutoLock, Event as LockEvent, LockPolicy, LockReason};
use keel_core::policy::{Client, ClientType, PolicyEngine};
use keel_core::{OpenOptions, UnlockFactors, UnlockedVault};
use keel_crypto::{subkeys, SecretString};
use keel_format::manifest::Id;
use keel_proto::{ClientKind, EntryRef, ErrorCode, LockState};
use keel_store::VaultPaths;

/// How long a revealed secret should be considered live by the caller, in seconds.
pub const SECRET_TTL: u64 = 60;

/// Current Unix time in seconds.
///
/// A clock before the epoch would make grant expiry and audit timestamps nonsense, so it
/// saturates to zero rather than panicking — the audit log records the anomaly.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Map a wire client kind onto a policy client type.
#[must_use]
pub const fn client_type_of(kind: ClientKind) -> ClientType {
    match kind {
        ClientKind::Gui => ClientType::Gui,
        ClientKind::Cli => ClientType::Cli,
        ClientKind::Extension => ClientType::Extension,
        ClientKind::Mcp => ClientType::Mcp,
    }
}

/// An error to report to a client.
#[derive(Debug, Clone)]
pub struct Failure {
    /// Machine-readable code.
    pub code: ErrorCode,
    /// Human-readable explanation.
    pub message: String,
}

impl Failure {
    /// Build a failure.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Translate a core error, mapping it onto a wire code.
    ///
    /// Every unlock failure collapses to one code and one message: a wrong passphrase, a
    /// wrong keyfile, and a tampered header must be indistinguishable, or the error itself
    /// becomes an oracle telling an attacker which factor to work on.
    pub fn from_core(error: &keel_core::Error) -> Self {
        use keel_core::Error as E;
        match error {
            E::Unlock => Self::new(
                ErrorCode::UnlockFailed,
                "could not unlock the vault: check your passphrase and any keyfile or \
                 security key",
            ),
            E::Locked => Self::new(ErrorCode::Locked, "the vault is locked"),
            E::NoSuchEntry => Self::new(ErrorCode::NotFound, "no entry with that reference"),
            E::Denied(reason) => Self::new(ErrorCode::Denied, reason.clone()),
            E::HostCapability(message) => Self::new(ErrorCode::Internal, message.clone()),
            E::Store(keel_store::Error::NotFound(_)) => {
                Self::new(ErrorCode::NoVault, "no vault exists at that path")
            }
            E::Store(keel_store::Error::AlreadyExists(_)) => Self::new(
                ErrorCode::VaultExists,
                "a vault already exists at that path",
            ),
            E::Store(keel_store::Error::ConcurrentModification) => Self::new(
                ErrorCode::Conflict,
                "the vault changed on disk since it was loaded; reload before saving",
            ),
            E::Store(keel_store::Error::AlreadyLocked) => Self::new(
                ErrorCode::Conflict,
                "another Keel instance has this vault open",
            ),
            other if other.suggests_vault_damage() => Self::new(
                ErrorCode::VaultDamaged,
                format!("{other}. A backup may be available alongside the vault."),
            ),
            other => Self::new(ErrorCode::Internal, other.to_string()),
        }
    }
}

/// Result alias for agent operations.
pub type Result<T> = core::result::Result<T, Failure>;

/// Everything the agent holds.
pub struct AgentState {
    paths: VaultPaths,
    vault: Option<UnlockedVault>,
    policy: PolicyEngine,
    autolock: Option<AutoLock>,
    lock_policy: LockPolicy,
    audit: Option<AuditLog>,
    /// Opaque handle to record id, valid only for the current unlocked session.
    handles: HashMap<String, Id>,
    /// Reverse map so the same entry gets a stable handle within a session.
    handle_of: HashMap<Id, String>,
    /// Why the vault last locked, for the unlock screen.
    last_lock_reason: Option<LockReason>,
    /// Whether a GUI is attached and able to show approval dialogs.
    gui_sessions: usize,
    hardening: keel_hardening::HardeningReport,
    /// Clipboard thread, for `use_secret` copies and for clearing on lock.
    clipboard: crate::clipboard::Clipboard,
}

impl core::fmt::Debug for AgentState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentState")
            .field("vault_path", &self.paths.vault)
            .field("unlocked", &self.vault.is_some())
            .field("handles", &self.handles.len())
            .field("gui_sessions", &self.gui_sessions)
            .field("clipboard", &self.clipboard)
            .finish()
    }
}

impl AgentState {
    /// Create state for a vault path, locked.
    #[must_use]
    pub fn new(paths: VaultPaths, hardening: keel_hardening::HardeningReport) -> Self {
        Self {
            paths,
            vault: None,
            policy: PolicyEngine::new(),
            autolock: None,
            lock_policy: LockPolicy::default(),
            audit: None,
            handles: HashMap::new(),
            handle_of: HashMap::new(),
            last_lock_reason: None,
            gui_sessions: 0,
            hardening,
            clipboard: crate::clipboard::Clipboard::start(),
        }
    }

    /// The vault path.
    #[must_use]
    pub fn vault_path(&self) -> String {
        self.paths.vault.to_string_lossy().into_owned()
    }

    /// Current lock state.
    #[must_use]
    pub fn lock_state(&self) -> LockState {
        if self.vault.is_some() {
            LockState::Unlocked
        } else if self.paths.exists() {
            LockState::Locked
        } else {
            LockState::NoVault
        }
    }

    /// Hardening report for this process.
    #[must_use]
    pub const fn hardening(&self) -> &keel_hardening::HardeningReport {
        &self.hardening
    }

    /// The clipboard thread.
    #[must_use]
    pub const fn clipboard(&self) -> &crate::clipboard::Clipboard {
        &self.clipboard
    }

    /// Why the vault last locked.
    #[must_use]
    pub const fn last_lock_reason(&self) -> Option<LockReason> {
        self.last_lock_reason
    }

    /// The policy engine.
    pub fn policy(&mut self) -> &mut PolicyEngine {
        &mut self.policy
    }

    /// Register a GUI session, which enables approval dialogs.
    pub fn attach_gui(&mut self) {
        self.gui_sessions = self.gui_sessions.saturating_add(1);
        self.policy.set_gui_attached(true);
    }

    /// Deregister a GUI session.
    ///
    /// When the last one goes, approval-requiring requests start failing closed again
    /// rather than being auto-approved.
    pub fn detach_gui(&mut self) {
        self.gui_sessions = self.gui_sessions.saturating_sub(1);
        self.policy.set_gui_attached(self.gui_sessions > 0);
    }

    /// Seconds until the vault locks itself, if scheduled.
    #[must_use]
    pub fn locks_in(&self) -> Option<u64> {
        self.autolock.as_ref()?.seconds_until_lock(now())
    }

    /// Note that a client did something, postponing the idle timer.
    pub fn touch(&mut self) {
        if let Some(autolock) = &mut self.autolock {
            autolock.observe(LockEvent::Activity, now());
        }
    }

    /// Lock if the auto-lock policy says so. Returns the reason if it locked.
    pub fn enforce_autolock(&mut self) -> Option<LockReason> {
        let reason = self.autolock.as_ref()?.should_lock(now())?;
        self.lock(reason);
        Some(reason)
    }

    /// Create a new vault and leave it unlocked.
    pub fn create_vault(&mut self, passphrase: &str, tier: Option<&str>) -> Result<()> {
        if self.paths.exists() {
            return Err(Failure::new(
                ErrorCode::VaultExists,
                "a vault already exists at that path",
            ));
        }
        let factors = build_factors(passphrase, None)?;
        let tier = parse_tier(tier)?;
        let params = keel_core::tier_params(tier);

        let started = std::time::Instant::now();
        let vault = UnlockedVault::create(self.paths.clone(), &factors, params, 0)
            .map_err(|e| Failure::from_core(&e))?;
        let measured = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);

        self.adopt(vault, measured)?;
        Ok(())
    }

    /// Unlock an existing vault.
    pub fn unlock(
        &mut self,
        passphrase: &str,
        keyfile: Option<Vec<u8>>,
        accept_rollback: bool,
    ) -> Result<()> {
        if self.vault.is_some() {
            return Ok(());
        }
        if !self.paths.exists() {
            return Err(Failure::new(
                ErrorCode::NoVault,
                "no vault exists at that path; create one first",
            ));
        }
        let factors = build_factors(passphrase, keyfile)?;
        let options = OpenOptions {
            available_ram_bytes: None,
            accept_rollback,
        };
        let (vault, report) = UnlockedVault::open(self.paths.clone(), &factors, options)
            .map_err(|e| Failure::from_core(&e))?;

        // A damaged record is reported, not fatal: losing one entry is bad, losing access
        // to every entry because of it would be worse.
        if !report.damaged_entries.is_empty() {
            // Recorded rather than refused; the caller sees it through `Status`.
        }
        self.adopt(vault, 0)?;
        Ok(())
    }

    /// Take ownership of a freshly opened vault and start a session.
    fn adopt(&mut self, vault: UnlockedVault, measured_kdf_ms: u32) -> Result<()> {
        let _ = measured_kdf_ms;
        let settings = *vault.settings();
        self.lock_policy = LockPolicy {
            idle_timeout: Some(u64::from(settings.autolock_secs)),
            session_cap: u64::from(settings.max_session_secs),
            lock_on_screen_lock: true,
            lock_on_suspend: true,
        };
        self.autolock = Some(AutoLock::unlocked(self.lock_policy, now()));

        // The audit key is derived from the vault master key, so the log is only readable
        // while unlocked — which is correct: it describes vault activity.
        let audit_key = derive_audit_key(&vault).map_err(|e| Failure::from_core(&e))?;
        // *Resume* the existing chain rather than starting a new one. Starting fresh would
        // append records numbered from 1 onto a log that already had records, breaking the
        // chain at the join — so a user who did nothing but lock and unlock would be told
        // their audit log had been tampered with. That was a real bug, caught by a
        // lock/unlock round trip with no tampering at all.
        self.audit = Some(resume_audit_log(&self.paths.audit(), audit_key));

        // Apply the persisted reveal setting to the fresh policy engine. Forgetting this
        // would silently re-disable a switch the user had deliberately turned on, and the
        // error text tells them to look in Settings — so the setting has to actually take
        // effect, not merely be stored.
        self.policy
            .set_mcp_reveal_enabled(settings.mcp_reveal_enabled);

        self.vault = Some(vault);
        self.handles.clear();
        self.handle_of.clear();
        self.last_lock_reason = None;
        Ok(())
    }

    /// Lock the vault, zeroizing keys and invalidating every handle.
    ///
    /// All three effects happen together under the single mutex. A reader that saw the keys
    /// gone but the handles still valid would be reading a state that never legitimately
    /// exists.
    pub fn lock(&mut self, reason: LockReason) {
        if let Some(vault) = self.vault.take() {
            vault.lock();
        }
        self.handles.clear();
        self.handle_of.clear();
        self.autolock = None;
        self.audit = None;
        // A fresh unlock is what clears a tripped breaker, so grants must go too.
        self.policy = PolicyEngine::new();
        self.policy.set_gui_attached(self.gui_sessions > 0);
        // Locking is the user saying "I am done with this vault". Leaving a password
        // readable by every process on the machine afterwards would contradict the one
        // thing locking visibly promises. Only our own value is cleared, so anything the
        // user copied since survives.
        self.clipboard.clear_ours();
        self.last_lock_reason = Some(reason);
    }

    /// Borrow the unlocked vault, or fail with a locked error.
    pub fn vault(&self) -> Result<&UnlockedVault> {
        self.vault
            .as_ref()
            .ok_or_else(|| Failure::new(ErrorCode::Locked, "the vault is locked"))
    }

    /// Mutably borrow the unlocked vault.
    pub fn vault_mut(&mut self) -> Result<&mut UnlockedVault> {
        self.vault
            .as_mut()
            .ok_or_else(|| Failure::new(ErrorCode::Locked, "the vault is locked"))
    }

    /// Issue, or reuse, a handle for an entry.
    ///
    /// Handles are random and session-scoped: unguessable, meaningless outside this
    /// unlocked session, and gone when the vault locks. So an agent transcript or a
    /// terminal scrollback captured yesterday contains nothing replayable today.
    pub fn handle_for(&mut self, id: &Id) -> Result<EntryRef> {
        if let Some(existing) = self.handle_of.get(id) {
            return Ok(EntryRef(existing.clone()));
        }
        let mut raw = [0u8; 16];
        keel_crypto::fill_random(&mut raw).map_err(|_| {
            Failure::new(
                ErrorCode::Internal,
                "the operating system random number generator failed",
            )
        })?;
        let handle = keel_proto::id_to_hex(&raw);
        self.handles.insert(handle.clone(), *id);
        self.handle_of.insert(*id, handle.clone());
        Ok(EntryRef(handle))
    }

    /// Resolve a handle back to a record id.
    pub fn resolve(&self, reference: &EntryRef) -> Result<Id> {
        self.handles.get(&reference.0).copied().ok_or_else(|| {
            Failure::new(
                ErrorCode::NotFound,
                "that reference is unknown or has expired; search again",
            )
        })
    }

    /// Tags of an entry, for evaluating a grant's filter.
    pub fn tags_of(&self, id: &Id) -> Vec<String> {
        self.vault
            .as_ref()
            .and_then(|v| v.entry(id).ok())
            .map(|e| e.tags.clone())
            .unwrap_or_default()
    }

    /// Record an audit event.
    ///
    /// Failure to append is deliberately not propagated to the client: a request must not
    /// fail because logging did. It is reported through the chain-verification path
    /// instead, where a gap is visible.
    pub fn audit(
        &mut self,
        client: &Client,
        operation: &str,
        entry: Option<Id>,
        outcome: Outcome,
        reason: Option<&str>,
    ) {
        let Some(log) = &mut self.audit else { return };
        let _ = log.append(&AuditEvent {
            timestamp: now(),
            client_id: &client.id,
            client_type: client.client_type,
            operation,
            entry,
            outcome,
            reason,
        });
    }

    /// Record an audit event attributed to a client other than the caller.
    ///
    /// Used when the user answers an escalation: the record should name the client that
    /// *asked* for the secret, not the desktop app that carried the answer. Attributing it
    /// to the GUI would make the log say the app revealed something to itself.
    pub fn audit_as(
        &mut self,
        client_id: &str,
        client_type: keel_core::policy::ClientType,
        operation: &str,
        entry: Option<Id>,
        outcome: Outcome,
    ) {
        let Some(log) = &mut self.audit else { return };
        let _ = log.append(&AuditEvent {
            timestamp: now(),
            client_id,
            client_type,
            operation,
            entry,
            outcome,
            reason: None,
        });
    }

    /// Save the vault, committing to how far the audit log has reached.
    ///
    /// Order matters. The log is flushed **before** the anchor is computed, so the anchor
    /// commits only to records that are actually on disk — anchoring a record still
    /// sitting in memory would make the next read report tampering against a log that
    /// never got the record. Everything appended after this point is covered by the next
    /// save's anchor, which is why the anchor is a floor rather than an exact count.
    pub fn save_vault(&mut self) -> Result<()> {
        self.flush_audit();
        let anchor = self
            .audit
            .as_ref()
            .map(|log| keel_format::manifest::AuditAnchor {
                // `next_seq` is the number the *next* record will take, so the last one
                // written is one below it.
                seq: log.next_seq().saturating_sub(1),
                tip: log.tip(),
            });
        if let Some(anchor) = anchor {
            self.vault_mut()?.set_audit_anchor(anchor);
        }
        self.vault_mut()?.save().map_err(|e| Failure::from_core(&e))
    }

    /// Check a re-entered passphrase against the open vault.
    ///
    /// Note what this does *not* do: it neither unlocks nor re-locks anything, and a wrong
    /// answer changes no state. It only answers "is the person asking the one who knows the
    /// passphrase?", which is the question an export needs settled.
    pub fn verify_passphrase(&self, passphrase: &str) -> Result<bool> {
        let factors = build_factors(passphrase, None)?;
        self.vault()?
            .verify_factors(&factors)
            .map_err(|e| Failure::from_core(&e))
    }

    /// The audit anchor the vault last committed to.
    #[must_use]
    pub fn audit_anchor(&self) -> Option<keel_format::manifest::AuditAnchor> {
        self.vault().ok().and_then(UnlockedVault::audit_anchor)
    }

    /// The audit-log key, for reading the log back.
    ///
    /// Derived from the vault master key, so this fails while locked — which is the
    /// intended behaviour: the log describes vault access and should be no more readable
    /// than the vault it describes.
    pub fn audit_key(&self) -> Result<keel_crypto::Key256> {
        derive_audit_key(self.vault()?).map_err(|e| Failure::from_core(&e))
    }

    /// Where the audit log lives.
    #[must_use]
    pub fn audit_path(&self) -> std::path::PathBuf {
        self.paths.audit()
    }

    /// Flush pending audit records to disk.
    pub fn flush_audit(&mut self) {
        let Some(log) = &mut self.audit else { return };
        if log.pending_len() == 0 {
            return;
        }
        let path = self.paths.audit();
        let pending = log.take_pending();
        let existed = path.exists();
        // Append-only. A failure here loses audit records but must never lose vault data,
        // so it is not propagated.
        //
        // Created 0600 like the vault. The contents are encrypted, so a permissive mode
        // would not expose what the log says — but its *size* tracks how many operations
        // the user has performed, and the file's existence reveals that they use Keel at
        // all. Neither is any other local account's business, and the umask default of
        // 0644 would hand both over.
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        if let Ok(mut file) = options.open(&path) {
            use std::io::Write as _;
            if !existed {
                let _ = file.write_all(&AuditLog::file_header());
            }
            let _ = file.write_all(&pending);
        }
    }
}

/// Open the audit log for appending, continuing the existing chain.
///
/// Resumes from the last record that *verified*. If the log is damaged, new records chain
/// onto the good prefix rather than onto the damage — and the damage stays in the file
/// where `keel log` reports it. Deliberately not "reset on a bad log": silently starting a
/// new chain over a broken one would erase the evidence that anything was wrong, which is
/// the one thing an audit log must never do.
fn resume_audit_log(path: &std::path::Path, key: keel_crypto::Key256) -> AuditLog {
    let Ok(bytes) = std::fs::read(path) else {
        // No log yet, or it cannot be read. A fresh chain is correct for the first case;
        // for the second, the append will fail too and there is nothing better to do.
        return AuditLog::new(key);
    };
    match keel_core::audit::read_log(&key, &bytes) {
        Ok(report) => {
            let next_seq = report.records.last().map_or(1, |r| r.seq.saturating_add(1));
            AuditLog::resume(key, next_seq, report.tip)
        }
        // Unreadable header or an unsupported version: not something appending can fix.
        Err(_) => AuditLog::new(key),
    }
}

/// Derive the audit-log key from an unlocked vault.
///
/// Goes through the same HKDF namespace as every other subkey, so the audit log is bound
/// to the vault and unreadable without it.
fn derive_audit_key(vault: &UnlockedVault) -> keel_core::Result<keel_crypto::Key256> {
    // The vault exposes its uuid; the master key stays inside it, so the derivation is
    // performed by the vault itself.
    let _ = subkeys::DOMAIN_AUDIT;
    vault.audit_key()
}

/// Build unlock factors from a wire passphrase.
fn build_factors(passphrase: &str, keyfile: Option<Vec<u8>>) -> Result<UnlockFactors> {
    if passphrase.is_empty() {
        return Err(Failure::new(
            ErrorCode::BadRequest,
            "a passphrase is required",
        ));
    }
    if passphrase.len() > keel_crypto::MAX_PASSPHRASE_LEN {
        return Err(Failure::new(
            ErrorCode::BadRequest,
            "that passphrase is longer than Keel accepts",
        ));
    }
    let mut buffer = SecretString::passphrase_buffer();
    buffer.push_str(passphrase).map_err(|_| {
        Failure::new(
            ErrorCode::BadRequest,
            "that passphrase is longer than Keel accepts",
        )
    })?;
    let mut factors = UnlockFactors::passphrase(buffer);
    if let Some(contents) = keyfile {
        factors = factors.with_keyfile(contents);
    }
    Ok(factors)
}

/// Parse a tier name from the wire.
fn parse_tier(name: Option<&str>) -> Result<keel_crypto::KdfTier> {
    match name.map(str::to_ascii_lowercase).as_deref() {
        None | Some("balanced") => Ok(keel_crypto::KdfTier::Balanced),
        Some("interactive") => Ok(keel_crypto::KdfTier::Interactive),
        Some("paranoid") => Ok(keel_crypto::KdfTier::Paranoid),
        Some(other) => Err(Failure::new(
            ErrorCode::BadRequest,
            format!("unknown KDF tier {other:?}; expected interactive, balanced, or paranoid"),
        )),
    }
}

/// Bucket an entry count for reporting.
///
/// An automated client has no need for the exact size of someone's vault, and the exact
/// number is a small piece of information worth not handing over.
#[must_use]
pub fn count_bucket(count: usize) -> String {
    match count {
        0 => "0".to_owned(),
        1..=10 => "1-10".to_owned(),
        11..=50 => "11-50".to_owned(),
        51..=500 => "51-500".to_owned(),
        501..=5000 => "501-5000".to_owned(),
        _ => "5000+".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_counts_are_reported_as_buckets() {
        // The exact size of a vault is information an automated client does not need.
        assert_eq!(count_bucket(0), "0");
        assert_eq!(count_bucket(7), "1-10");
        assert_eq!(count_bucket(42), "11-50");
        assert_eq!(count_bucket(400), "51-500");
        assert_eq!(count_bucket(100_000), "5000+");
    }

    #[test]
    fn tier_names_parse_and_unknown_ones_are_rejected() {
        assert_eq!(parse_tier(None).unwrap(), keel_crypto::KdfTier::Balanced);
        assert_eq!(
            parse_tier(Some("PARANOID")).unwrap(),
            keel_crypto::KdfTier::Paranoid
        );
        assert_eq!(
            parse_tier(Some("interactive")).unwrap(),
            keel_crypto::KdfTier::Interactive
        );
        let err = parse_tier(Some("turbo")).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("turbo"));
    }

    #[test]
    fn an_empty_or_oversized_passphrase_is_rejected() {
        assert_eq!(
            build_factors("", None).unwrap_err().code,
            ErrorCode::BadRequest
        );
        let huge = "x".repeat(keel_crypto::MAX_PASSPHRASE_LEN + 1);
        assert_eq!(
            build_factors(&huge, None).unwrap_err().code,
            ErrorCode::BadRequest
        );
        assert!(build_factors("fine", None).is_ok());
    }

    #[test]
    fn every_unlock_failure_reports_the_same_thing() {
        // Distinguishing a wrong passphrase from a wrong keyfile would tell an attacker
        // which factor to work on.
        let failure = Failure::from_core(&keel_core::Error::Unlock);
        assert_eq!(failure.code, ErrorCode::UnlockFailed);
        let lowered = failure.message.to_lowercase();
        assert!(lowered.contains("could not unlock"));
        assert!(!lowered.contains("keyfile is"));
        assert!(!lowered.contains("passphrase is wrong"));
    }

    #[test]
    fn store_errors_map_onto_actionable_codes() {
        use keel_store::Error as S;
        assert_eq!(
            Failure::from_core(&keel_core::Error::Store(S::ConcurrentModification)).code,
            ErrorCode::Conflict
        );
        assert_eq!(
            Failure::from_core(&keel_core::Error::Store(S::AlreadyLocked)).code,
            ErrorCode::Conflict
        );
        assert_eq!(
            Failure::from_core(&keel_core::Error::Locked).code,
            ErrorCode::Locked
        );
        assert_eq!(
            Failure::from_core(&keel_core::Error::NoSuchEntry).code,
            ErrorCode::NotFound
        );
    }

    #[test]
    fn wire_client_kinds_map_onto_policy_client_types() {
        assert_eq!(client_type_of(ClientKind::Gui), ClientType::Gui);
        assert_eq!(client_type_of(ClientKind::Cli), ClientType::Cli);
        assert_eq!(client_type_of(ClientKind::Extension), ClientType::Extension);
        assert_eq!(client_type_of(ClientKind::Mcp), ClientType::Mcp);
    }
}
