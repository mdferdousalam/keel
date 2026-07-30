//! Rollback detection.
//!
//! A vault's `write_counter` increases on every save. This module remembers the last
//! value a device saw, so the next open can notice if the file has gone *backwards*.
//!
//! # Why this matters
//!
//! Every other integrity check in Keel verifies that a file is internally consistent.
//! An old vault file is perfectly consistent — it was authentic when it was written.
//! So an attacker who can replace the file (a compromised cloud account, a restored
//! backup, access to the machine while it is locked) can roll a user back to a state
//! where a password they have since rotated is still valid, and nothing about the file
//! itself gives that away.
//!
//! Detection therefore has to come from state held *outside* the file. Keel keeps it
//! in two places — a sidecar file and the OS keychain — so that deleting one is not
//! enough to silence the warning.
//!
//! # Being honest about the limits
//!
//! This is **detection**, not prevention. An attacker who deletes the sidecar and the
//! keychain entry along with the file gets a clean "first time seeing this vault",
//! which is indistinguishable from a genuine fresh install. What the mechanism
//! reliably catches is the far more common case: a partial rollback, and the ordinary
//! accidents (restoring a backup, a sync conflict) that look identical to an attack
//! and therefore deserve the same conspicuous warning.

use std::fs;
use std::path::Path;

use keel_format::codec::{Reader, Writer};
use keel_format::Header;

use crate::error::{Error, Result};

/// Magic number for the state sidecar.
const STATE_MAGIC: [u8; 8] = *b"KEELSTA\x01";

/// State-file format version.
const STATE_VERSION: u16 = 1;

/// What a device remembers about the last version of a vault it saw.
///
/// Contains no secrets — only a counter and two hashes — so it needs no encryption
/// and can be inspected by a user trying to understand a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastSeen {
    /// Which vault this refers to.
    pub vault_uuid: [u8; 16],
    /// Highest write counter observed.
    pub write_counter: u64,
    /// Binding hash of the header at that point.
    pub header_hash: [u8; 32],
    /// Whole-file hash at that point.
    ///
    /// Lets a *fork* be distinguished from a plain rollback: same counter with a
    /// different file means two devices saved independently from the same starting
    /// point, which is a sync conflict rather than an attack.
    pub footer_hash: [u8; 32],
    /// When this was recorded, Unix seconds.
    pub saved_at: u64,
}

impl LastSeen {
    /// Build from a header and the file's whole-file hash.
    pub fn from_header(header: &Header, footer_hash: [u8; 32], saved_at: u64) -> Result<Self> {
        Ok(Self {
            vault_uuid: header.vault_uuid,
            write_counter: header.write_counter,
            header_hash: header.binding_hash()?,
            footer_hash,
            saved_at,
        })
    }

    /// Encode to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128);
        w.bytes(&STATE_MAGIC);
        w.u16(STATE_VERSION);
        w.bytes(&self.vault_uuid);
        w.u64(self.write_counter);
        w.bytes(&self.header_hash);
        w.bytes(&self.footer_hash);
        w.u64(self.saved_at);
        w.into_vec()
    }

    /// Decode from bytes.
    ///
    /// Every failure is a plain error rather than a panic. This file is not
    /// attacker-*supplied* in the way a vault is, but it is attacker-*writable* by
    /// anyone who can write the vault, so it gets the same treatment.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.array::<8>().map_err(|_| Error::BadState("truncated"))?;
        if magic != STATE_MAGIC {
            return Err(Error::BadState("not a Keel state file"));
        }
        let version = r.u16().map_err(|_| Error::BadState("truncated"))?;
        if version == 0 || version > STATE_VERSION {
            return Err(Error::BadState("unsupported state file version"));
        }
        Ok(Self {
            vault_uuid: r.array::<16>().map_err(|_| Error::BadState("truncated"))?,
            write_counter: r.u64().map_err(|_| Error::BadState("truncated"))?,
            header_hash: r.array::<32>().map_err(|_| Error::BadState("truncated"))?,
            footer_hash: r.array::<32>().map_err(|_| Error::BadState("truncated"))?,
            saved_at: r.u64().map_err(|_| Error::BadState("truncated"))?,
        })
    }

    /// Read the state sidecar, if present and readable.
    ///
    /// A missing or corrupt file yields `None` rather than an error: failing to open a
    /// vault because a non-essential sidecar is damaged would be a terrible trade.
    /// The caller sees `None` and treats the vault as newly encountered, which
    /// produces a warning rather than silence.
    #[must_use]
    pub fn load(path: &Path) -> Option<Self> {
        let bytes = fs::read(path).ok()?;
        Self::decode(&bytes).ok()
    }

    /// Write the state sidecar.
    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, self.encode()).map_err(|e| Error::io("writing rollback state", path, e))
    }
}

/// The result of comparing a vault against what this device last saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackVerdict {
    /// The counter advanced, or stayed the same on an identical file. Normal.
    Consistent,

    /// No previous state for this vault.
    ///
    /// Expected on a fresh install or a newly-restored vault. Also what an attacker
    /// who deleted the state file would produce, which is why the UI mentions it on
    /// first open rather than staying silent.
    FirstSight,

    /// The state file refers to a different vault. Not suspicious.
    DifferentVault,

    /// **The file is older than what this device last saw.**
    ///
    /// Happens after restoring a backup or resolving a sync conflict — and also when
    /// someone is rolling the user back to an old password. Because those are
    /// indistinguishable from the file alone, the user has to be told and has to
    /// confirm; it must never be waved through.
    Regression {
        /// Counter this device last saw.
        last_seen: u64,
        /// Counter in the file now.
        found: u64,
    },

    /// Same counter, different contents: two devices saved independently.
    ///
    /// A sync conflict rather than an attack. Distinguished from a regression so the
    /// message can be accurate, since "your vault may have been tampered with" is the
    /// wrong thing to say about a Dropbox conflict.
    Fork {
        /// The counter both versions share.
        counter: u64,
    },
}

impl RollbackVerdict {
    /// True if the user must be shown this and must confirm before proceeding.
    #[must_use]
    pub const fn requires_confirmation(&self) -> bool {
        matches!(self, Self::Regression { .. } | Self::Fork { .. })
    }

    /// True if this should be recorded in the audit log.
    ///
    /// Includes `FirstSight`, because "this device had no memory of the vault" is
    /// exactly the trace you would want when investigating later.
    #[must_use]
    pub const fn is_noteworthy(&self) -> bool {
        !matches!(self, Self::Consistent)
    }

    /// A message for the user.
    ///
    /// Written to name both possibilities rather than accusing or reassuring. A user
    /// who restored a backup should not be frightened, and a user who is being
    /// attacked must not be soothed.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Consistent => String::new(),
            Self::FirstSight => {
                "This is the first time this device has opened this vault.".to_owned()
            }
            Self::DifferentVault => String::new(),
            Self::Regression { last_seen, found } => format!(
                "This vault is older than the last version this device saw \
                 (save {found}, previously {last_seen}).\n\n\
                 This is normal if you have just restored a backup or resolved a sync \
                 conflict. It can also mean someone replaced your vault with an older \
                 copy, to make a password you have since changed work again.\n\n\
                 If you did not restore a backup, stop and investigate before continuing."
            ),
            Self::Fork { counter } => format!(
                "Two versions of this vault were saved separately from the same point \
                 (both at save {counter}).\n\n\
                 This usually means a sync conflict: the vault was edited on two devices \
                 while they were not in sync. Check for a conflicted copy alongside the \
                 vault, because it may contain entries this one does not."
            ),
        }
    }
}

/// Compare a vault's header against remembered state.
pub fn check(
    last_seen: Option<&LastSeen>,
    header: &Header,
    footer_hash: [u8; 32],
) -> RollbackVerdict {
    let Some(seen) = last_seen else {
        return RollbackVerdict::FirstSight;
    };
    if seen.vault_uuid != header.vault_uuid {
        return RollbackVerdict::DifferentVault;
    }
    if header.write_counter < seen.write_counter {
        return RollbackVerdict::Regression {
            last_seen: seen.write_counter,
            found: header.write_counter,
        };
    }
    if header.write_counter == seen.write_counter && footer_hash != seen.footer_hash {
        return RollbackVerdict::Fork {
            counter: seen.write_counter,
        };
    }
    RollbackVerdict::Consistent
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_crypto::kdf::{Argon2Params, MIN_M_COST_KIB};
    use keel_crypto::{AEAD_ID_XCHACHA20POLY1305, KDF_ID_ARGON2ID_V13, NONCE_LEN};
    use keel_format::header::{WrappedKey, WRAPPED_KEY_CT_LEN};
    use keel_format::{FactorSet, HeaderFlags};

    fn header(uuid: u8, counter: u64) -> Header {
        Header {
            format_version: keel_format::FORMAT_VERSION,
            flags: HeaderFlags::default(),
            vault_uuid: [uuid; 16],
            created_at: 0,
            kdf_id: KDF_ID_ARGON2ID_V13,
            kdf_params: Argon2Params {
                m_cost_kib: MIN_M_COST_KIB,
                t_cost: 1,
                p_cost: 1,
            },
            kdf_salt: [1; 32],
            measured_kdf_ms: 0,
            factors: FactorSet::default(),
            aead_id: AEAD_ID_XCHACHA20POLY1305,
            vmk_epoch_current: 0,
            wrapped_keys: vec![WrappedKey {
                epoch: 0,
                nonce: [0; NONCE_LEN],
                ciphertext: [0; WRAPPED_KEY_CT_LEN],
            }],
            write_counter: counter,
            records_offset: 0,
            records_len: 0,
            manifest_offset: 0,
            manifest_len: 0,
        }
    }

    fn seen(uuid: u8, counter: u64, footer: u8) -> LastSeen {
        LastSeen::from_header(&header(uuid, counter), [footer; 32], 1_700_000_000).unwrap()
    }

    #[test]
    fn state_round_trips() {
        let s = seen(1, 42, 9);
        assert_eq!(LastSeen::decode(&s.encode()).unwrap(), s);
    }

    #[test]
    fn rejects_a_foreign_or_damaged_state_file() {
        assert!(LastSeen::decode(b"not a state file at all").is_err());
        assert!(LastSeen::decode(&[]).is_err());
        let s = seen(1, 1, 1);
        let encoded = s.encode();
        // Truncation at every length must error, never panic.
        for cut in 0..encoded.len() {
            assert!(LastSeen::decode(&encoded[..cut]).is_err());
        }
    }

    #[test]
    fn an_advancing_counter_is_consistent() {
        let s = seen(1, 10, 5);
        assert_eq!(
            check(Some(&s), &header(1, 11), [6; 32]),
            RollbackVerdict::Consistent
        );
    }

    #[test]
    fn the_identical_file_is_consistent() {
        let s = seen(1, 10, 5);
        assert_eq!(
            check(Some(&s), &header(1, 10), [5; 32]),
            RollbackVerdict::Consistent
        );
    }

    #[test]
    fn a_lower_counter_is_a_regression_requiring_confirmation() {
        let s = seen(1, 419, 5);
        let verdict = check(Some(&s), &header(1, 412), [7; 32]);
        assert_eq!(
            verdict,
            RollbackVerdict::Regression {
                last_seen: 419,
                found: 412
            }
        );
        assert!(verdict.requires_confirmation());
        assert!(verdict.is_noteworthy());
        // The message must name both explanations: frightening a user who restored a
        // backup is as wrong as reassuring one who is under attack.
        let message = verdict.message();
        assert!(message.contains("412") && message.contains("419"));
        assert!(message.contains("restored a backup"));
        assert!(message.contains("older copy"));
    }

    #[test]
    fn the_same_counter_with_different_contents_is_a_fork() {
        let s = seen(1, 10, 5);
        let verdict = check(Some(&s), &header(1, 10), [99; 32]);
        assert_eq!(verdict, RollbackVerdict::Fork { counter: 10 });
        assert!(verdict.requires_confirmation());
        // A sync conflict must not be described as tampering.
        let message = verdict.message();
        assert!(message.contains("sync conflict"));
        assert!(!message.contains("someone replaced"));
    }

    #[test]
    fn no_previous_state_is_first_sight_and_is_noteworthy() {
        let verdict = check(None, &header(1, 5), [1; 32]);
        assert_eq!(verdict, RollbackVerdict::FirstSight);
        // Deliberately not silent: an attacker who deletes the state file produces
        // exactly this, so it belongs in the audit log.
        assert!(verdict.is_noteworthy());
        assert!(!verdict.requires_confirmation());
    }

    #[test]
    fn a_different_vault_is_not_suspicious() {
        let s = seen(1, 100, 5);
        let verdict = check(Some(&s), &header(2, 1), [1; 32]);
        assert_eq!(verdict, RollbackVerdict::DifferentVault);
        assert!(!verdict.requires_confirmation());
    }

    #[test]
    fn state_survives_a_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.keel.state");
        let s = seen(3, 77, 8);
        s.save(&path).unwrap();
        assert_eq!(LastSeen::load(&path), Some(s));
    }

    #[test]
    fn a_missing_or_corrupt_state_file_loads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.state");
        assert_eq!(LastSeen::load(&missing), None);

        // A damaged sidecar must not be able to stop someone opening their vault.
        let corrupt = dir.path().join("corrupt.state");
        std::fs::write(&corrupt, b"garbage").unwrap();
        assert_eq!(LastSeen::load(&corrupt), None);
    }
}
