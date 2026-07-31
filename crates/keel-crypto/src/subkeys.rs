// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Subkey derivation from the vault master key.
//!
//! Every key in the system except the KEK is derived here, from one random
//! 32-byte vault master key (VMK), via HKDF-SHA-512 with a distinct `info`
//! string per purpose. Two consequences worth stating:
//!
//! * **Per-record keys are free.** A record key is `HKDF(VMK, "record/" ‖ id ‖
//!   epoch)`, so we get full key separation without storing a wrapped data key
//!   per entry (which would cost 60+ bytes and an extra failure mode each).
//!   Reading one password decrypts exactly one record.
//! * **Rotation is cheap.** Changing the master password re-wraps the same VMK
//!   under a new KEK; every derived key is unchanged, so not one record is
//!   re-encrypted.
//!
//! HKDF-SHA-512 is used rather than BLAKE3's own KDF mode purely because HKDF is
//! the more standard, more reviewable primitive. BLAKE3 is still used for
//! hashing, MACing, and factor pre-mixing where its speed matters.
//!
//! # Domain separation
//!
//! The `info` strings below are a versioned namespace and must never be reused
//! or reordered. Adding a purpose means adding a new string, never repurposing
//! an old one — two purposes sharing a key is how key-reuse vulnerabilities
//! start.

use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::{Error, Result};
use crate::secret::{Key256, SecretBytes};

/// Manifest (metadata index) encryption key.
pub const DOMAIN_INDEX: &[u8] = b"keel/v1/index";
/// Prefix for per-record keys; completed with the record id and key epoch.
pub const DOMAIN_RECORD_PREFIX: &[u8] = b"keel/v1/record/";
/// Audit-log encryption and chaining key.
pub const DOMAIN_AUDIT: &[u8] = b"keel/v1/audit";
/// Prefix for per-attachment keys.
pub const DOMAIN_ATTACH_PREFIX: &[u8] = b"keel/v1/attach/";
/// Root from which browser-extension and MCP-client pairing keys are derived.
pub const DOMAIN_PAIRING_ROOT: &[u8] = b"keel/v1/pairing-root";
/// Reserved for a future encrypted search index.
///
/// Unused in v1: v1 decrypts the metadata manifest into memory and searches
/// there. A persistent deterministic index would leak equality and frequency
/// across file versions, letting an attacker with two snapshots see which
/// entries changed. The slot exists so a properly padded, per-epoch
/// re-randomized index can be added later without a format break.
pub const DOMAIN_SEARCH: &[u8] = b"keel/v1/search";

/// Derive a 32-byte subkey from the VMK for an arbitrary `info` string.
///
/// The vault UUID is the HKDF salt, which binds every subkey to a specific
/// vault: two vaults that somehow shared a VMK would still not share subkeys.
fn derive(vmk: &Key256, vault_uuid: &[u8; 16], info: &[u8]) -> Result<Key256> {
    let hk = Hkdf::<Sha512>::new(Some(vault_uuid), vmk.expose());
    let mut out = SecretBytes::<32>::zeroed();
    hk.expand(info, out.expose_mut())
        .map_err(|_| Error::KdfFailure)?;
    Ok(out)
}

/// Derive the manifest encryption key.
pub fn index_key(vmk: &Key256, vault_uuid: &[u8; 16]) -> Result<Key256> {
    derive(vmk, vault_uuid, DOMAIN_INDEX)
}

/// Derive the key for a single record.
///
/// `key_epoch` lets a vault hold records encrypted under successive VMK
/// generations during a lazy rotation, so rotating the master key never requires
/// one big all-or-nothing rewrite.
pub fn record_key(
    vmk: &Key256,
    vault_uuid: &[u8; 16],
    record_id: &[u8; 16],
    key_epoch: u32,
) -> Result<Key256> {
    let mut info = Vec::with_capacity(DOMAIN_RECORD_PREFIX.len() + 16 + 4);
    info.extend_from_slice(DOMAIN_RECORD_PREFIX);
    info.extend_from_slice(record_id);
    info.extend_from_slice(&key_epoch.to_le_bytes());
    derive(vmk, vault_uuid, &info)
}

/// Derive the audit-log key.
pub fn audit_key(vmk: &Key256, vault_uuid: &[u8; 16]) -> Result<Key256> {
    derive(vmk, vault_uuid, DOMAIN_AUDIT)
}

/// Derive the key for a single attachment.
pub fn attachment_key(
    vmk: &Key256,
    vault_uuid: &[u8; 16],
    attachment_id: &[u8; 16],
) -> Result<Key256> {
    let mut info = Vec::with_capacity(DOMAIN_ATTACH_PREFIX.len() + 16);
    info.extend_from_slice(DOMAIN_ATTACH_PREFIX);
    info.extend_from_slice(attachment_id);
    derive(vmk, vault_uuid, &info)
}

/// Derive the pairing root, from which per-client pairing pre-shared keys are
/// derived.
pub fn pairing_root(vmk: &Key256, vault_uuid: &[u8; 16]) -> Result<Key256> {
    derive(vmk, vault_uuid, DOMAIN_PAIRING_ROOT)
}

/// Derive the pre-shared key for one paired client (a browser extension install
/// or a registered MCP client).
///
/// Bound to the client's identifier *and* its static public key, so a client
/// that regenerates its key cannot silently reuse the previous pairing.
pub fn pairing_psk(pairing_root: &Key256, client_id: &str, client_pubkey: &[u8]) -> Result<Key256> {
    let mut info = Vec::with_capacity(6 + client_id.len() + client_pubkey.len());
    info.extend_from_slice(b"pair/");
    info.extend_from_slice(client_id.as_bytes());
    info.push(0x1F); // unambiguous separator: not valid in a client id
    info.extend_from_slice(client_pubkey);
    let hk = Hkdf::<Sha512>::new(None, pairing_root.expose());
    let mut out = SecretBytes::<32>::zeroed();
    hk.expand(&info, out.expose_mut())
        .map_err(|_| Error::KdfFailure)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vmk() -> Key256 {
        SecretBytes::<32>::from_slice(&[0x42; 32]).unwrap()
    }

    #[test]
    fn derivation_is_deterministic() {
        let uuid = [1u8; 16];
        assert_eq!(
            index_key(&vmk(), &uuid).unwrap(),
            index_key(&vmk(), &uuid).unwrap()
        );
    }

    #[test]
    fn every_purpose_gets_a_different_key() {
        let uuid = [1u8; 16];
        let v = vmk();
        let rid = [0u8; 16];
        let keys = [
            index_key(&v, &uuid).unwrap(),
            audit_key(&v, &uuid).unwrap(),
            pairing_root(&v, &uuid).unwrap(),
            record_key(&v, &uuid, &rid, 0).unwrap(),
            attachment_key(&v, &uuid, &rid).unwrap(),
        ];
        for (i, a) in keys.iter().enumerate() {
            for (j, b) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "purposes {i} and {j} collided");
                }
            }
        }
    }

    #[test]
    fn record_keys_differ_by_id_and_epoch() {
        let uuid = [1u8; 16];
        let v = vmk();
        let a = record_key(&v, &uuid, &[1u8; 16], 0).unwrap();
        let b = record_key(&v, &uuid, &[2u8; 16], 0).unwrap();
        let c = record_key(&v, &uuid, &[1u8; 16], 1).unwrap();
        assert_ne!(a, b, "different records must not share a key");
        assert_ne!(a, c, "different epochs must not share a key");
    }

    #[test]
    fn subkeys_are_bound_to_the_vault_uuid() {
        let v = vmk();
        assert_ne!(
            index_key(&v, &[1u8; 16]).unwrap(),
            index_key(&v, &[2u8; 16]).unwrap()
        );
    }

    #[test]
    fn subkeys_change_with_the_master_key() {
        let uuid = [1u8; 16];
        let a = index_key(&SecretBytes::<32>::from_slice(&[1; 32]).unwrap(), &uuid).unwrap();
        let b = index_key(&SecretBytes::<32>::from_slice(&[2; 32]).unwrap(), &uuid).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn pairing_psk_is_bound_to_client_identity_and_key() {
        let root = pairing_root(&vmk(), &[1u8; 16]).unwrap();
        let base = pairing_psk(&root, "chrome-abc", &[9u8; 32]).unwrap();
        assert_ne!(base, pairing_psk(&root, "chrome-abd", &[9u8; 32]).unwrap());
        assert_ne!(base, pairing_psk(&root, "chrome-abc", &[8u8; 32]).unwrap());
        assert_eq!(base, pairing_psk(&root, "chrome-abc", &[9u8; 32]).unwrap());
    }

    #[test]
    fn client_id_and_pubkey_boundary_is_unambiguous() {
        // Without a separator, ("ab", [0xcd]) and ("a", [0xb0, 0xcd]) could
        // collide. The 0x1F separator prevents the id/key boundary from sliding.
        let root = pairing_root(&vmk(), &[1u8; 16]).unwrap();
        assert_ne!(
            pairing_psk(&root, "ab", &[0xcd]).unwrap(),
            pairing_psk(&root, "a", &[0xb0, 0xcd]).unwrap()
        );
    }
}
