// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Keel's cryptographic core.
//!
//! This crate performs **no I/O**: no filesystem, no network, no clock beyond
//! timing its own calibration probe, no way to reach the outside world. That
//! restriction is what makes it reviewable and fuzzable, and it is enforced by a
//! CI gate rather than trusted to discipline.
//!
//! # The key hierarchy
//!
//! ```text
//! master passphrase ──┐
//! keyfile (optional) ─┤
//! FIDO2 / YubiKey ────┤
//!                     ▼
//!        mix_factors: keyed BLAKE3, length-prefixed
//!                     ▼
//!        Argon2id(m, t, p, salt) ──32 B──► KEK   (never stored)
//!                     │
//!                     ├── unwraps ──► VMK        (random, epoch-tagged)
//!                     ▼
//!        HKDF-SHA-512(ikm = VMK, salt = vault_uuid, info = purpose)
//!                     │
//!     ┌───────────────┼──────────────┬────────────────┬──────────────┐
//!     ▼               ▼              ▼                ▼              ▼
//! index_key    record_key(id,e)  audit_key   attachment_key   pairing_root
//! ```
//!
//! The KEK/VMK split is the reason changing the master password rewrites a couple
//! of hundred header bytes instead of re-encrypting every record: the new KEK
//! re-wraps the *same* VMK, so every derived key is unchanged.
//!
//! # Post-quantum posture
//!
//! Everything in this crate is symmetric, and symmetric cryptography at 256 bits
//! is already quantum-resistant: Grover's algorithm offers at most a square-root
//! speedup (~2^128 sequential coherent evaluations), parallelizes poorly (S
//! machines buy only √S), and would have to hold the whole memory-hard KDF in
//! superposition. Consequently **"harvest now, decrypt later" does not apply to
//! this vault** — that attack targets recorded public-key key exchanges, and
//! there is no public-key cryptography anywhere in the confidentiality path.
//!
//! Post-quantum work in this project lives entirely outside this crate: release
//! signing (hybrid Ed25519 + ML-DSA-65) and, if sharing is ever added, a hybrid
//! X25519 + ML-KEM-768 KEM. The project rule is that **no asymmetric primitive
//! enters the confidentiality path without a hybrid classical+PQ construction.**
//!
//! # Layout
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`secret`] | Secret-bearing types, page locking, OS randomness |
//! | [`kdf`] | Argon2id parameters, factor mixing, calibration |
//! | [`subkeys`] | HKDF domain namespace and subkey derivation |
//! | [`aead`] | XChaCha20-Poly1305 seal/open |
//! | [`generator`] | Password and diceware passphrase generation |

// The workspace denies `unwrap`, `expect`, panics, raw indexing, and truncating
// arithmetic because in *library* code a panic on malformed input is a
// denial-of-service bug. In test code those same constructs are how a failure
// gets a readable message, so they are allowed there and only there.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::integer_division,
        clippy::cast_possible_truncation
    )
)]

pub mod aead;
pub mod error;
pub mod generator;
pub mod kdf;
pub mod secret;
pub mod strength;
pub mod subkeys;

pub use error::{Error, Result};

pub use aead::{
    open, open_sealed, seal, seal_with_nonce, Nonce, Sealed, AEAD_ID_XCHACHA20POLY1305, NONCE_LEN,
    TAG_LEN,
};
pub use generator::{
    generate_passphrase, generate_password, PassphrasePolicy, PasswordPolicy, BITS_PER_WORD,
};
pub use kdf::{
    calibrate, derive_kek, derive_kek_from_factors, hash_keyfile, mix_factors, Argon2Params,
    Calibration, Factors, KdfTier, KDF_ID_ARGON2ID_V13, SALT_LEN,
};
pub use strength::{estimate_bits, Strength, CRITICAL_BITS, WEAK_BITS};

pub use secret::{
    fill_random, install_page_locker, page_lock_degraded, Key256, PageLocker, SecretBytes,
    SecretString, MAX_PASSPHRASE_LEN,
};

/// Version of this crate, for inclusion in version strings.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Self-check that the compiled-in constants and bundled data are intact.
///
/// Called once at process startup. It cannot detect a malicious build — a
/// tampered binary would tamper with this too — but it does catch a truncated
/// embedded wordlist or a mismatched constant after a refactor, which are the
/// realistic failure modes.
pub fn self_check() -> Result<()> {
    if generator::wordlist_len() != generator::WORDLIST_LEN {
        return Err(Error::Policy("bundled wordlist is incomplete"));
    }
    if PasswordPolicy::default().alphabet_size() != 88 {
        return Err(Error::Policy("default alphabet has unexpected size"));
    }
    // Prove the AEAD round-trips before we rely on it for real data.
    let key = SecretBytes::<32>::from_slice(&[0x5A; 32])?;
    let sealed = seal(&key, b"self-check", b"keel")?;
    let opened = open_sealed(&key, b"self-check", &sealed)?;
    if opened.as_slice() != b"keel" {
        return Err(Error::Authentication);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_check_passes() {
        self_check().unwrap();
    }

    #[test]
    fn end_to_end_key_hierarchy() {
        // Walk the full path a real unlock takes: factors → KEK → unwrap VMK →
        // subkeys → decrypt a record. Cheap KDF parameters keep this fast.
        let vault_uuid = [0xABu8; 16];
        let salt = [0x11u8; SALT_LEN];
        let params = Argon2Params {
            m_cost_kib: kdf::MIN_M_COST_KIB,
            t_cost: 1,
            p_cost: 1,
        };

        // Vault creation: random VMK, wrapped under the KEK.
        let vmk = SecretBytes::<32>::random().unwrap();
        let factors = Factors {
            passphrase: b"open sesame",
            keyfile_hash: None,
            hardware_response: None,
        };
        let kek = derive_kek_from_factors(&vault_uuid, &factors, &salt, params).unwrap();
        let wrapped = seal(&kek, b"keel/v1/wrap-test", vmk.expose()).unwrap();

        // Unlock: rederive the KEK and unwrap.
        let kek2 = derive_kek_from_factors(&vault_uuid, &factors, &salt, params).unwrap();
        let unwrapped = open_sealed(&kek2, b"keel/v1/wrap-test", &wrapped).unwrap();
        let vmk2 = SecretBytes::<32>::from_slice(&unwrapped).unwrap();
        assert_eq!(vmk, vmk2);

        // A record sealed under a derived record key round-trips.
        let record_id = [7u8; 16];
        let rk = subkeys::record_key(&vmk2, &vault_uuid, &record_id, 0).unwrap();
        let record = seal(&rk, b"aad", b"hunter2").unwrap();
        let plain = open_sealed(&rk, b"aad", &record).unwrap();
        assert_eq!(&plain[..], b"hunter2");

        // A different record's key must not open it.
        let other = subkeys::record_key(&vmk2, &vault_uuid, &[8u8; 16], 0).unwrap();
        assert!(open_sealed(&other, b"aad", &record).is_err());
    }

    #[test]
    fn wrong_passphrase_cannot_unwrap_the_master_key() {
        let vault_uuid = [1u8; 16];
        let salt = [2u8; SALT_LEN];
        let params = Argon2Params {
            m_cost_kib: kdf::MIN_M_COST_KIB,
            t_cost: 1,
            p_cost: 1,
        };
        let vmk = SecretBytes::<32>::random().unwrap();
        let good = derive_kek_from_factors(
            &vault_uuid,
            &Factors {
                passphrase: b"right",
                keyfile_hash: None,
                hardware_response: None,
            },
            &salt,
            params,
        )
        .unwrap();
        let wrapped = seal(&good, b"aad", vmk.expose()).unwrap();

        let bad = derive_kek_from_factors(
            &vault_uuid,
            &Factors {
                passphrase: b"wrong",
                keyfile_hash: None,
                hardware_response: None,
            },
            &salt,
            params,
        )
        .unwrap();
        assert_eq!(
            open_sealed(&bad, b"aad", &wrapped).unwrap_err(),
            Error::Authentication
        );
    }
}
