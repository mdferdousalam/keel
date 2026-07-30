//! Tamper-evident audit log.
//!
//! Records what each client asked for and what the policy engine decided. Its purpose is
//! answering the question a user asks *after* something has gone wrong: "what did that
//! agent actually do?"
//!
//! # What is and is not recorded
//!
//! | Recorded | Never recorded |
//! |---|---|
//! | Sequence number, timestamp | Any password, TOTP seed, or note |
//! | Client id and type | Entry titles, usernames, or URLs |
//! | Operation name and decision | Agent-supplied text verbatim |
//! | Entry **id** | |
//! | A hash of the agent's stated reason | |
//!
//! Entry ids rather than titles, because the log is a plaintext-adjacent artifact in the
//! user's data directory and an attacker who reads it should not learn which accounts
//! exist. The log is encrypted under a derived key regardless, but defence in depth here
//! is nearly free.
//!
//! The agent's reason is stored as a **hash**, not text. The full text was shown to the
//! user at approval time and is not needed again; keeping it would mean storing
//! attacker-authored strings that some future viewer might render. The hash still proves
//! whether two requests claimed the same justification.
//!
//! # Why the chain
//!
//! Each record commits to the previous one, so removing or editing an entry breaks
//! verification from that point on. An attacker with write access can still **truncate**
//! the log — nothing stored alongside the data it describes can prevent that — but they
//! cannot quietly delete the one line that incriminates them, and the sequence numbers
//! make a truncation visible. That is the honest limit of a local append-only log.

use keel_crypto::{aead, Key256};
use keel_format::codec::{Reader, Writer};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::policy::{ClientType, Decision};
use keel_format::manifest::Id;

/// Magic number for the audit log file.
pub const AUDIT_MAGIC: [u8; 8] = *b"KEELAUD\x01";

/// Audit record schema version.
pub const AUDIT_VERSION: u16 = 1;

/// Associated-data domain for audit records.
const AAD_AUDIT: &[u8] = b"keel/v1/audit-record";

/// Largest accepted single audit record, in bytes.
///
/// Bounds work when reading a log that may have been tampered with.
pub const MAX_RECORD_LEN: usize = 64 * 1024;

/// Largest accepted client identifier in a record, in bytes.
const MAX_CLIENT_ID_LEN: usize = 256;

/// What the policy engine decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Permitted.
    Allowed,
    /// Refused by policy.
    Denied,
    /// Escalated to the user, who approved.
    ApprovedByUser,
    /// Escalated to the user, who refused.
    RefusedByUser,
    /// Escalated but nobody answered in time.
    ///
    /// Distinguished from a refusal because an unattended timeout and a deliberate "no"
    /// mean different things when reading the log later.
    TimedOut,
}

impl Outcome {
    /// Classify a policy decision. Escalations resolve later, so they are not here.
    #[must_use]
    pub const fn from_decision(decision: &Decision) -> Option<Self> {
        match decision {
            Decision::Allow => Some(Self::Allowed),
            Decision::Deny { .. } => Some(Self::Denied),
            Decision::Ask(_) => None,
        }
    }

    /// Whether this outcome is worth surfacing in the UI as suspicious.
    #[must_use]
    pub const fn is_notable(self) -> bool {
        matches!(self, Self::Denied | Self::RefusedByUser | Self::TimedOut)
    }

    const fn code(self) -> u8 {
        match self {
            Self::Allowed => 1,
            Self::Denied => 2,
            Self::ApprovedByUser => 3,
            Self::RefusedByUser => 4,
            Self::TimedOut => 5,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Allowed),
            2 => Some(Self::Denied),
            3 => Some(Self::ApprovedByUser),
            4 => Some(Self::RefusedByUser),
            5 => Some(Self::TimedOut),
            _ => None,
        }
    }
}

const fn client_type_code(t: ClientType) -> u8 {
    match t {
        ClientType::Gui => 1,
        ClientType::Cli => 2,
        ClientType::Extension => 3,
        ClientType::Mcp => 4,
    }
}

const fn client_type_from_code(code: u8) -> Option<ClientType> {
    match code {
        1 => Some(ClientType::Gui),
        2 => Some(ClientType::Cli),
        3 => Some(ClientType::Extension),
        4 => Some(ClientType::Mcp),
        _ => None,
    }
}

/// One audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Position in the chain, starting at 1.
    pub seq: u64,
    /// When it happened, Unix seconds.
    pub timestamp: u64,
    /// Which client.
    pub client_id: String,
    /// Client category.
    pub client_type: ClientType,
    /// Operation label.
    pub operation: String,
    /// Entry concerned, by id only.
    pub entry: Option<Id>,
    /// What was decided.
    pub outcome: Outcome,
    /// BLAKE3 hash of the agent's stated reason, if there was one.
    pub reason_hash: Option<[u8; 32]>,
    /// Hash of the previous record, or zeroes for the first.
    pub prev_hash: [u8; 32],
}

impl AuditRecord {
    /// Serialize the record body, which is what gets encrypted and chained.
    fn encode_body(&self) -> Result<Vec<u8>> {
        if self.client_id.len() > MAX_CLIENT_ID_LEN || self.operation.len() > MAX_CLIENT_ID_LEN {
            return Err(Error::Denied(
                "audit field exceeds the maximum length".to_owned(),
            ));
        }
        let mut w = Writer::with_capacity(256);
        w.u16(AUDIT_VERSION);
        w.u64(self.seq);
        w.u64(self.timestamp);
        w.u8(client_type_code(self.client_type));
        w.u8(self.outcome.code());

        w.u8(u8::try_from(self.client_id.len()).unwrap_or(u8::MAX));
        w.bytes(self.client_id.as_bytes());
        w.u8(u8::try_from(self.operation.len()).unwrap_or(u8::MAX));
        w.bytes(self.operation.as_bytes());

        match &self.entry {
            Some(id) => {
                w.u8(1);
                w.bytes(id);
            }
            None => w.u8(0),
        }
        match &self.reason_hash {
            Some(hash) => {
                w.u8(1);
                w.bytes(hash);
            }
            None => w.u8(0),
        }
        w.bytes(&self.prev_hash);
        Ok(w.into_vec())
    }

    fn decode_body(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version == 0 || version > AUDIT_VERSION {
            return Err(Error::Format(keel_format::Error::Malformed(
                "audit record uses an unsupported version",
            )));
        }
        let seq = r.u64()?;
        let timestamp = r.u64()?;
        let client_type = client_type_from_code(r.u8()?).ok_or(Error::Format(
            keel_format::Error::Malformed("audit record names an unknown client type"),
        ))?;
        let outcome = Outcome::from_code(r.u8()?).ok_or(Error::Format(
            keel_format::Error::Malformed("audit record names an unknown outcome"),
        ))?;

        let client_id_len = r.u8()? as usize;
        let client_id = String::from_utf8(r.take(client_id_len)?.to_vec()).map_err(|_| {
            Error::Format(keel_format::Error::Malformed(
                "audit record client id is not valid UTF-8",
            ))
        })?;
        let operation_len = r.u8()? as usize;
        let operation = String::from_utf8(r.take(operation_len)?.to_vec()).map_err(|_| {
            Error::Format(keel_format::Error::Malformed(
                "audit record operation is not valid UTF-8",
            ))
        })?;

        let entry = if r.u8()? == 1 {
            Some(r.array::<16>()?)
        } else {
            None
        };
        let reason_hash = if r.u8()? == 1 {
            Some(r.array::<32>()?)
        } else {
            None
        };
        let prev_hash = r.array::<32>()?;

        Ok(Self {
            seq,
            timestamp,
            client_id,
            client_type,
            operation,
            entry,
            outcome,
            reason_hash,
            prev_hash,
        })
    }

    /// This record's position in the chain.
    fn chain_hash(&self) -> Result<[u8; 32]> {
        let body = self.encode_body()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"keel/v1/audit-chain");
        hasher.update(&self.prev_hash);
        hasher.update(&self.seq.to_le_bytes());
        hasher.update(&body);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Hash an agent-supplied reason for storage.
///
/// The text itself is not kept: it was shown to the user at approval time and is not
/// needed again, and storing attacker-authored strings invites a future viewer to render
/// them. The hash still lets two requests be compared.
#[must_use]
pub fn hash_reason(reason: &str) -> [u8; 32] {
    *blake3::hash(reason.as_bytes()).as_bytes()
}

/// What to record, as a single value.
///
/// A struct rather than a long parameter list: `append(now, id, ty, op, entry, outcome,
/// reason)` is seven positional arguments of which four are easy to transpose, and
/// transposing the client id with the operation name would quietly corrupt the log that
/// exists to be trustworthy.
#[derive(Debug, Clone, Copy)]
pub struct AuditEvent<'a> {
    /// When it happened, Unix seconds.
    pub timestamp: u64,
    /// Which client.
    pub client_id: &'a str,
    /// Client category.
    pub client_type: ClientType,
    /// Operation label.
    pub operation: &'a str,
    /// Entry concerned, by id only.
    pub entry: Option<Id>,
    /// What was decided.
    pub outcome: Outcome,
    /// Agent-supplied justification. Stored as a hash, never as text.
    pub reason: Option<&'a str>,
}

/// An append-only, hash-chained audit log.
#[derive(Debug)]
pub struct AuditLog {
    key: Key256,
    next_seq: u64,
    tip: [u8; 32],
    /// Encoded records, ready to append to the file.
    pending: Vec<Vec<u8>>,
}

impl AuditLog {
    /// Start a new log.
    #[must_use]
    pub fn new(key: Key256) -> Self {
        Self {
            key,
            next_seq: 1,
            tip: [0; 32],
            pending: Vec::new(),
        }
    }

    /// Sequence number the next record will take.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Current chain tip.
    #[must_use]
    pub const fn tip(&self) -> [u8; 32] {
        self.tip
    }

    /// Records written but not yet flushed to disk.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Append a record.
    ///
    /// Returns the record as stored, so a caller can display exactly what was recorded
    /// rather than reconstructing it and hoping the two agree.
    pub fn append(&mut self, event: &AuditEvent<'_>) -> Result<AuditRecord> {
        let record = AuditRecord {
            seq: self.next_seq,
            timestamp: event.timestamp,
            client_id: event.client_id.to_owned(),
            client_type: event.client_type,
            operation: event.operation.to_owned(),
            entry: event.entry,
            outcome: event.outcome,
            reason_hash: event.reason.map(hash_reason),
            prev_hash: self.tip,
        };

        let body = record.encode_body()?;
        let sealed = aead::seal(&self.key, AAD_AUDIT, &body)?;

        let mut framed = Writer::with_capacity(body.len() + 64);
        framed.len_u32(
            keel_crypto::NONCE_LEN + sealed.ciphertext.len(),
            "audit record too long",
        )?;
        framed.bytes(&sealed.nonce);
        framed.bytes(&sealed.ciphertext);
        self.pending.push(framed.into_vec());

        self.tip = record.chain_hash()?;
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(record)
    }

    /// Take the pending bytes for appending to the log file.
    #[must_use]
    pub fn take_pending(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in self.pending.drain(..) {
            out.extend_from_slice(&chunk);
        }
        out
    }

    /// The file header, written once when a log is created.
    #[must_use]
    pub fn file_header() -> Vec<u8> {
        let mut w = Writer::with_capacity(16);
        w.bytes(&AUDIT_MAGIC);
        w.u16(AUDIT_VERSION);
        w.into_vec()
    }
}

/// What reading a log produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    /// Records that verified.
    pub records: Vec<AuditRecord>,
    /// Where verification stopped, if it did.
    pub integrity: ChainIntegrity,
}

/// The result of verifying a log's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainIntegrity {
    /// Every record verified and the chain is unbroken.
    Intact,
    /// The chain broke at this sequence number.
    ///
    /// Means a record was edited or removed. Records before this point are still
    /// trustworthy, which is why they are returned rather than discarded.
    BrokenAt {
        /// Sequence number where verification failed.
        seq: u64,
    },
    /// The file ended mid-record.
    ///
    /// Usually an interrupted write rather than an attack, since appends are not atomic.
    /// Reported separately so the UI does not cry tampering over a power failure.
    Truncated {
        /// Last sequence number that verified.
        after_seq: u64,
    },
}

impl ChainIntegrity {
    /// Whether this indicates deliberate interference rather than an accident.
    #[must_use]
    pub const fn suggests_tampering(&self) -> bool {
        matches!(self, Self::BrokenAt { .. })
    }
}

/// Read and verify an audit log.
///
/// Returns every record that verified, plus where verification stopped. A broken chain
/// does not discard the good prefix: the records before the break are exactly the
/// evidence someone investigating needs.
pub fn read_log(key: &Key256, bytes: &[u8]) -> Result<AuditReport> {
    let mut r = Reader::new(bytes);
    if bytes.is_empty() {
        return Ok(AuditReport {
            records: Vec::new(),
            integrity: ChainIntegrity::Intact,
        });
    }
    if r.array::<8>()? != AUDIT_MAGIC {
        return Err(Error::Format(keel_format::Error::BadMagic));
    }
    let version = r.u16()?;
    if version == 0 || version > AUDIT_VERSION {
        return Err(Error::Format(keel_format::Error::UnsupportedVersion {
            found: version,
            supported: AUDIT_VERSION,
        }));
    }

    let mut records = Vec::new();
    let mut expected_prev = [0u8; 32];
    let mut expected_seq = 1u64;

    while !r.is_empty() {
        let Ok(len) = r.checked_len_u32("audit record", MAX_RECORD_LEN) else {
            return Ok(AuditReport {
                records,
                integrity: ChainIntegrity::Truncated {
                    after_seq: expected_seq.saturating_sub(1),
                },
            });
        };
        let Ok(frame) = r.take(len) else {
            return Ok(AuditReport {
                records,
                integrity: ChainIntegrity::Truncated {
                    after_seq: expected_seq.saturating_sub(1),
                },
            });
        };

        let mut fr = Reader::new(frame);
        let nonce = fr.array::<{ keel_crypto::NONCE_LEN }>()?;
        let ciphertext = fr.take(fr.remaining())?;
        let plaintext: Zeroizing<Vec<u8>> = match aead::open(key, &nonce, AAD_AUDIT, ciphertext) {
            Ok(p) => p,
            // A record that fails authentication was edited. Stop here and report a
            // break rather than skipping it, because skipping would let an attacker
            // corrupt one record to hide it.
            Err(_) => {
                return Ok(AuditReport {
                    records,
                    integrity: ChainIntegrity::BrokenAt { seq: expected_seq },
                })
            }
        };

        let record = AuditRecord::decode_body(&plaintext)?;
        if record.seq != expected_seq || record.prev_hash != expected_prev {
            return Ok(AuditReport {
                records,
                integrity: ChainIntegrity::BrokenAt { seq: expected_seq },
            });
        }
        expected_prev = record.chain_hash()?;
        expected_seq = expected_seq.saturating_add(1);
        records.push(record);
    }

    Ok(AuditReport {
        records,
        integrity: ChainIntegrity::Intact,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_crypto::SecretBytes;

    const NOW: u64 = 1_700_000_000;

    fn key() -> Key256 {
        SecretBytes::<32>::from_slice(&[0x77; 32]).unwrap()
    }

    fn search_event(timestamp: u64) -> AuditEvent<'static> {
        AuditEvent {
            timestamp,
            client_id: "cli",
            client_type: ClientType::Cli,
            operation: "search",
            entry: None,
            outcome: Outcome::Allowed,
            reason: None,
        }
    }

    /// Build a log file containing `count` records.
    fn build_log(count: u64) -> (Vec<u8>, Key256) {
        let mut log = AuditLog::new(key());
        let mut bytes = AuditLog::file_header();
        for i in 0..count {
            log.append(&AuditEvent {
                timestamp: NOW + i,
                client_id: "claude-code",
                client_type: ClientType::Mcp,
                operation: "reveal_secret",
                entry: Some([u8::try_from(i).unwrap_or(0); 16]),
                outcome: Outcome::ApprovedByUser,
                reason: Some("the user asked me to log in"),
            })
            .unwrap();
        }
        bytes.extend_from_slice(&log.take_pending());
        (bytes, key())
    }

    #[test]
    fn records_round_trip_and_the_chain_verifies() {
        let (bytes, k) = build_log(5);
        let report = read_log(&k, &bytes).unwrap();
        assert_eq!(report.integrity, ChainIntegrity::Intact);
        assert_eq!(report.records.len(), 5);
        for (i, record) in report.records.iter().enumerate() {
            assert_eq!(record.seq, i as u64 + 1);
            assert_eq!(record.client_id, "claude-code");
            assert_eq!(record.operation, "reveal_secret");
            assert_eq!(record.outcome, Outcome::ApprovedByUser);
        }
    }

    #[test]
    fn an_empty_log_is_intact() {
        let report = read_log(&key(), &[]).unwrap();
        assert!(report.records.is_empty());
        assert_eq!(report.integrity, ChainIntegrity::Intact);
    }

    #[test]
    fn a_header_only_log_is_intact() {
        let report = read_log(&key(), &AuditLog::file_header()).unwrap();
        assert!(report.records.is_empty());
        assert_eq!(report.integrity, ChainIntegrity::Intact);
    }

    #[test]
    fn each_record_commits_to_the_previous_one() {
        let mut log = AuditLog::new(key());
        let first = log.append(&search_event(NOW)).unwrap();
        let second = log.append(&search_event(NOW + 1)).unwrap();
        assert_eq!(
            first.prev_hash, [0; 32],
            "the first record starts the chain"
        );
        assert_eq!(
            second.prev_hash,
            first.chain_hash().unwrap(),
            "each record must commit to its predecessor"
        );
    }

    #[test]
    fn editing_a_record_breaks_the_chain_at_that_point() {
        // The property the whole design exists for: an attacker cannot quietly alter the
        // one line that incriminates them.
        let (mut bytes, k) = build_log(5);
        // Flip a byte inside the third record's ciphertext. Records are the same size, so
        // walk the frames to find it rather than guessing an offset.
        let header = AuditLog::file_header().len();
        let mut cursor = header;
        for _ in 0..2 {
            let len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4 + len;
        }
        // Now inside the third frame; corrupt a ciphertext byte.
        bytes[cursor + 4 + keel_crypto::NONCE_LEN + 1] ^= 0xFF;

        let report = read_log(&k, &bytes).unwrap();
        assert_eq!(report.integrity, ChainIntegrity::BrokenAt { seq: 3 });
        assert!(report.integrity.suggests_tampering());
        // The good prefix is preserved: it is exactly what an investigator needs.
        assert_eq!(report.records.len(), 2);
    }

    #[test]
    fn removing_a_record_breaks_the_chain() {
        let (bytes, k) = build_log(4);
        let header = AuditLog::file_header().len();
        // Drop the second record by splicing the frame out.
        let first_len = u32::from_le_bytes(bytes[header..header + 4].try_into().unwrap()) as usize;
        let second_start = header + 4 + first_len;
        let second_len =
            u32::from_le_bytes(bytes[second_start..second_start + 4].try_into().unwrap()) as usize;
        let mut spliced = bytes[..second_start].to_vec();
        spliced.extend_from_slice(&bytes[second_start + 4 + second_len..]);

        let report = read_log(&k, &spliced).unwrap();
        assert_eq!(report.integrity, ChainIntegrity::BrokenAt { seq: 2 });
        assert_eq!(report.records.len(), 1);
    }

    #[test]
    fn a_truncated_log_is_reported_as_truncated_not_tampering() {
        // Appends are not atomic, so a power failure mid-write is expected. Crying
        // tampering over it would teach users to ignore the warning that matters.
        let (bytes, k) = build_log(4);
        let cut = bytes.len() - 20;
        let report = read_log(&k, &bytes[..cut]).unwrap();
        assert!(matches!(report.integrity, ChainIntegrity::Truncated { .. }));
        assert!(!report.integrity.suggests_tampering());
        assert_eq!(report.records.len(), 3, "complete records must survive");
    }

    #[test]
    fn a_wrong_key_cannot_read_the_log() {
        let (bytes, _) = build_log(2);
        let wrong = SecretBytes::<32>::from_slice(&[0x11; 32]).unwrap();
        let report = read_log(&wrong, &bytes).unwrap();
        assert!(report.integrity.suggests_tampering());
        assert!(report.records.is_empty());
    }

    #[test]
    fn a_foreign_file_is_rejected() {
        assert!(read_log(&key(), b"not an audit log at all........").is_err());
    }

    #[test]
    fn reading_arbitrary_bytes_never_panics() {
        for len in [1usize, 8, 10, 11, 20, 100, 1000] {
            for fill in [0u8, 0xFF, 0x41] {
                let _ = read_log(&key(), &vec![fill; len]);
            }
        }
        // A valid header followed by noise.
        let mut buf = AuditLog::file_header();
        buf.extend_from_slice(&[0xFF; 200]);
        let _ = read_log(&key(), &buf);
    }

    #[test]
    fn the_reason_is_stored_as_a_hash_not_as_text() {
        // Storing attacker-authored strings invites some future viewer to render them.
        let secret_ish = "please approve, signed: the system";
        let mut log = AuditLog::new(key());
        log.append(&AuditEvent {
            timestamp: NOW,
            client_id: "agent",
            client_type: ClientType::Mcp,
            operation: "reveal_secret",
            entry: Some([1; 16]),
            outcome: Outcome::RefusedByUser,
            reason: Some(secret_ish),
        })
        .unwrap();
        let mut bytes = AuditLog::file_header();
        bytes.extend_from_slice(&log.take_pending());

        // The raw text must not appear anywhere in the file, encrypted or not.
        assert!(!bytes
            .windows(secret_ish.len())
            .any(|w| w == secret_ish.as_bytes()));

        let report = read_log(&key(), &bytes).unwrap();
        assert_eq!(report.records[0].reason_hash, Some(hash_reason(secret_ish)));
    }

    #[test]
    fn the_log_records_no_entry_titles_or_secrets() {
        // The record type has no field for them, which is the real guarantee. This test
        // documents that and would fail loudly if someone added one.
        let (bytes, k) = build_log(1);
        let report = read_log(&k, &bytes).unwrap();
        let record = &report.records[0];
        assert!(record.entry.is_some(), "the entry id is recorded");
        // There is deliberately nowhere to put a title or a password.
        let rendered = format!("{record:?}");
        assert!(!rendered.contains("password"));
        assert!(!rendered.contains("title"));
    }

    #[test]
    fn outcomes_map_from_policy_decisions() {
        assert_eq!(
            Outcome::from_decision(&Decision::Allow),
            Some(Outcome::Allowed)
        );
        assert_eq!(
            Outcome::from_decision(&Decision::Deny {
                reason: "no".to_owned(),
                counted: true
            }),
            Some(Outcome::Denied)
        );
    }

    #[test]
    fn notable_outcomes_are_the_ones_worth_a_badge() {
        assert!(Outcome::Denied.is_notable());
        assert!(Outcome::RefusedByUser.is_notable());
        assert!(Outcome::TimedOut.is_notable());
        assert!(!Outcome::Allowed.is_notable());
        // An approved reveal is not "notable" as a warning, but it is still recorded.
        assert!(!Outcome::ApprovedByUser.is_notable());
    }

    #[test]
    fn a_timeout_is_distinguishable_from_a_refusal() {
        // Unattended and "no" mean different things when reading the log later.
        assert_ne!(Outcome::TimedOut, Outcome::RefusedByUser);
    }

    #[test]
    fn every_client_type_and_outcome_survives_a_round_trip() {
        for client_type in [
            ClientType::Gui,
            ClientType::Cli,
            ClientType::Extension,
            ClientType::Mcp,
        ] {
            for outcome in [
                Outcome::Allowed,
                Outcome::Denied,
                Outcome::ApprovedByUser,
                Outcome::RefusedByUser,
                Outcome::TimedOut,
            ] {
                let mut log = AuditLog::new(key());
                log.append(&AuditEvent {
                    timestamp: NOW,
                    client_id: "c",
                    client_type,
                    operation: "op",
                    entry: None,
                    outcome,
                    reason: None,
                })
                .unwrap();
                let mut bytes = AuditLog::file_header();
                bytes.extend_from_slice(&log.take_pending());
                let report = read_log(&key(), &bytes).unwrap();
                assert_eq!(report.records[0].client_type, client_type);
                assert_eq!(report.records[0].outcome, outcome);
            }
        }
    }

    #[test]
    fn sequence_numbers_are_contiguous_from_one() {
        let (bytes, k) = build_log(10);
        let report = read_log(&k, &bytes).unwrap();
        for (i, record) in report.records.iter().enumerate() {
            assert_eq!(record.seq, i as u64 + 1);
        }
        assert_eq!(report.integrity, ChainIntegrity::Intact);
    }

    #[test]
    fn appending_across_two_flushes_keeps_the_chain_unbroken() {
        // Real use appends incrementally; the chain must survive being written in pieces.
        let mut log = AuditLog::new(key());
        let mut bytes = AuditLog::file_header();
        for i in 0..3 {
            log.append(&search_event(NOW + i)).unwrap();
        }
        bytes.extend_from_slice(&log.take_pending());
        assert_eq!(log.pending_len(), 0);

        for i in 3..6 {
            log.append(&search_event(NOW + i)).unwrap();
        }
        bytes.extend_from_slice(&log.take_pending());

        let report = read_log(&key(), &bytes).unwrap();
        assert_eq!(report.integrity, ChainIntegrity::Intact);
        assert_eq!(report.records.len(), 6);
    }
}
