//! Authenticated encryption: XChaCha20-Poly1305.
//!
//! # Why XChaCha20-Poly1305 rather than AES-256-GCM
//!
//! The deciding factor is the **192-bit nonce**. With a nonce that wide, picking
//! one at random is unconditionally safe (collision probability stays negligible
//! past 2^96 messages), so [`seal`] can simply generate a fresh nonce every
//! time. AES-256-GCM's 96-bit nonce forces you to either maintain a persistent
//! counter — state you must get right across crashes, restored backups, and a
//! vault file copied between machines — or accept a ceiling around 2^32
//! messages. For a file that gets rewritten thousands of times and *is expected*
//! to be copied and restored by users, "random nonces are always fine" removes
//! an entire class of catastrophic bug.
//!
//! Secondarily: ChaCha20 is constant-time in software on every platform, while
//! AES without hardware acceleration is either slow or cache-timing-vulnerable.
//!
//! # Why not a cipher cascade
//!
//! Encrypting twice under two different ciphers doubles the code paths and key
//! schedules and halves throughput, to defend against the break of a primitive
//! whose failure would be the cryptographic event of the century. Our realistic
//! failure modes are implementation bugs, weak master passwords, and endpoint
//! compromise — a cascade makes the *first* worse and does nothing for the other
//! two. Instead we version the algorithm ([`AEAD_ID_XCHACHA20POLY1305`]) so a
//! migration is possible if it is ever needed.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::{fill_random, Key256};

/// Nonce length for XChaCha20-Poly1305, in bytes.
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length, in bytes.
pub const TAG_LEN: usize = 16;

/// Algorithm identifier stored in the vault header.
pub const AEAD_ID_XCHACHA20POLY1305: u8 = 1;

/// Reserved identifier for AES-256-GCM.
///
/// Not emitted in v1. The parser should be able to grow support for it without a
/// format break if a FIPS-constrained build ever needs it.
pub const AEAD_ID_AES256GCM_RESERVED: u8 = 2;

/// A nonce for one sealed blob.
pub type Nonce = [u8; NONCE_LEN];

/// Ciphertext plus its authentication tag, and the nonce it was sealed under.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Randomly generated nonce.
    pub nonce: Nonce,
    /// Ciphertext with the 16-byte Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    /// Total on-disk size of this blob: nonce + ciphertext + tag.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        NONCE_LEN + self.ciphertext.len()
    }
}

impl core::fmt::Debug for Sealed {
    /// Ciphertext is not secret, but printing kilobytes of it in a log or a
    /// panic message is still unhelpful, so only the shape is shown.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealed")
            .field("nonce_len", &NONCE_LEN)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Encrypt `plaintext` under `key`, authenticating `aad` alongside it.
///
/// A fresh random nonce is generated for every call. See the module docs for why
/// that is safe here and would not be with a 96-bit nonce.
///
/// `aad` is not encrypted but *is* authenticated: tampering with it makes
/// [`open`] fail. This is what binds a record to its vault, its id, and its key
/// epoch, and what makes downgrading the header's KDF parameters fail rather
/// than succeed cheaply.
pub fn seal(key: &Key256, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    seal_with_nonce(key, &nonce, aad, plaintext)
}

/// Encrypt with a caller-supplied nonce.
///
/// Exists for known-answer tests and for the rare case where the nonce is
/// dictated by the format. Application code should call [`seal`]: reusing a
/// nonce with the same key is catastrophic, and this function cannot detect it.
pub fn seal_with_nonce(
    key: &Key256,
    nonce: &Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| Error::InvalidLength {
            expected: 32,
            actual: key.len(),
        })?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::KdfFailure)?;
    Ok(Sealed {
        nonce: *nonce,
        ciphertext,
    })
}

/// Decrypt and verify a sealed blob.
///
/// The returned plaintext is wrapped in [`Zeroizing`] so it is wiped when
/// dropped even on an early return or a panic further up the stack.
///
/// Returns [`Error::Authentication`] if the key, the ciphertext, or the
/// associated data is wrong. It does not say which — that distinction would be
/// an oracle.
pub fn open(
    key: &Key256,
    nonce: &Nonce,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() < TAG_LEN {
        // Too short to even contain a tag: reject before handing it to the AEAD.
        return Err(Error::Authentication);
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| Error::InvalidLength {
            expected: 32,
            actual: key.len(),
        })?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(plaintext))
}

/// Decrypt a [`Sealed`] value.
pub fn open_sealed(key: &Key256, aad: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    open(key, &sealed.nonce, aad, &sealed.ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretBytes;

    fn key(byte: u8) -> Key256 {
        SecretBytes::<32>::from_slice(&[byte; 32]).unwrap()
    }

    #[test]
    fn round_trip() {
        let k = key(1);
        let sealed = seal(&k, b"aad", b"secret message").unwrap();
        let opened = open_sealed(&k, b"aad", &sealed).unwrap();
        assert_eq!(&opened[..], b"secret message");
    }

    #[test]
    fn ciphertext_carries_the_tag() {
        let k = key(1);
        let sealed = seal(&k, b"", b"12345").unwrap();
        assert_eq!(sealed.ciphertext.len(), 5 + TAG_LEN);
        assert_eq!(sealed.encoded_len(), NONCE_LEN + 5 + TAG_LEN);
    }

    #[test]
    fn nonces_are_never_reused() {
        let k = key(1);
        let a = seal(&k, b"", b"same plaintext").unwrap();
        let b = seal(&k, b"", b"same plaintext").unwrap();
        assert_ne!(a.nonce, b.nonce, "nonce must be fresh per seal");
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "identical plaintext must not produce identical ciphertext"
        );
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let sealed = seal(&key(1), b"aad", b"msg").unwrap();
        let err = open_sealed(&key(2), b"aad", &sealed).unwrap_err();
        assert_eq!(err, Error::Authentication);
    }

    #[test]
    fn wrong_aad_fails_authentication() {
        // This is the property the whole format relies on: the associated data
        // is what binds a blob to its context. Getting it wrong must fail, not
        // silently decrypt.
        let k = key(1);
        let sealed = seal(&k, b"record-1", b"msg").unwrap();
        assert_eq!(
            open_sealed(&k, b"record-2", &sealed).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn tampering_with_any_ciphertext_byte_fails() {
        let k = key(1);
        let sealed = seal(&k, b"aad", b"a somewhat longer secret message").unwrap();
        for i in 0..sealed.ciphertext.len() {
            let mut bad = sealed.clone();
            bad.ciphertext[i] ^= 0x01;
            assert_eq!(
                open_sealed(&k, b"aad", &bad).unwrap_err(),
                Error::Authentication,
                "flipping ciphertext byte {i} was not detected"
            );
        }
    }

    #[test]
    fn tampering_with_any_nonce_byte_fails() {
        let k = key(1);
        let sealed = seal(&k, b"aad", b"secret").unwrap();
        for i in 0..NONCE_LEN {
            let mut bad = sealed.clone();
            bad.nonce[i] ^= 0x01;
            assert_eq!(
                open_sealed(&k, b"aad", &bad).unwrap_err(),
                Error::Authentication,
                "flipping nonce byte {i} was not detected"
            );
        }
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let k = key(1);
        let sealed = seal(&k, b"", b"secret").unwrap();
        for cut in 0..sealed.ciphertext.len() {
            let mut bad = sealed.clone();
            bad.ciphertext.truncate(cut);
            assert!(
                open_sealed(&k, b"", &bad).is_err(),
                "truncation to {cut} accepted"
            );
        }
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k = key(1);
        let sealed = seal(&k, b"aad", b"").unwrap();
        assert_eq!(sealed.ciphertext.len(), TAG_LEN);
        assert!(open_sealed(&k, b"aad", &sealed).unwrap().is_empty());
    }

    #[test]
    fn fixed_nonce_is_deterministic() {
        // Basis for the known-answer tests: same key, nonce, aad, and plaintext
        // must always produce the same ciphertext.
        let k = key(7);
        let nonce = [0x24u8; NONCE_LEN];
        let a = seal_with_nonce(&k, &nonce, b"aad", b"msg").unwrap();
        let b = seal_with_nonce(&k, &nonce, b"aad", b"msg").unwrap();
        assert_eq!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn debug_does_not_dump_ciphertext() {
        let sealed = seal(&key(1), b"", b"secret").unwrap();
        let rendered = format!("{sealed:?}");
        assert!(rendered.contains("ciphertext_len"));
        assert!(!rendered.contains("["), "should not render raw bytes");
    }
}
