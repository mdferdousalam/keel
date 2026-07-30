//! Record bodies: the part of a vault that actually holds secrets.
//!
//! # Why these types carry `Serialize`, when secret types must not
//!
//! `keel-crypto`'s `SecretBytes` and `SecretString` deliberately have no
//! `Serialize` impl, so that writing a key to a log or a JSON payload is a compile
//! error. [`RecordBody`] is the one exception, and it needs justifying.
//!
//! A record has to be serialized — that is how it gets written to disk. What makes
//! it safe is that the only path out of this type is
//! [`RecordBody::encode_padded`], which produces bytes that the caller immediately
//! encrypts. There is no code path that serializes a record to anywhere other than
//! into an AEAD.
//!
//! The compensating controls, given that `Serialize` is present:
//!
//! * **`Zeroize` and `ZeroizeOnDrop` are derived**, so every `String` field is
//!   wiped when the record drops.
//! * **`Debug` is hand-written and redacts everything.** Deriving it would put
//!   passwords into any panic message or log line that formatted a record.
//! * **No `Clone`.** A decrypted record is used where it is decrypted and then
//!   dropped. Wanting to clone one means the call graph is wrong.
//!
//! # Decrypt, then deserialize — never the other way round
//!
//! [`RecordBody::decode_padded`] runs on plaintext whose Poly1305 tag has already
//! verified. That ordering matters: `postcard` allocates based on lengths in its
//! input, so deserializing unauthenticated bytes would hand an attacker an
//! allocation lever. Authenticating first means a forged record never reaches the
//! deserializer at all.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::limits;
use crate::padding::{self, RECORD_BLOCK};

/// Schema version for record bodies, independent of the file format version.
///
/// Lets a field be added to a record without a whole-file format bump.
pub const RECORD_SCHEMA: u16 = 1;

/// A user-defined extra field on an entry.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct CustomField {
    /// Field label.
    pub name: String,
    /// Field value.
    pub value: String,
    /// Whether the UI should mask this value by default.
    ///
    /// Applies to security answers, PINs, and recovery codes — things that are
    /// secrets even though they are not the main password.
    #[zeroize(skip)]
    pub secret: bool,
}

impl core::fmt::Debug for CustomField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Even the *name* is withheld: "Coinbase 2FA backup code" identifies an
        // account and a security measure, which is worth protecting on its own.
        f.debug_struct("CustomField")
            .field("name", &"<redacted>")
            .field("value", &"<redacted>")
            .field("secret", &self.secret)
            .finish()
    }
}

/// A previous password, retained after rotation.
///
/// History exists because rotation without it causes lockouts: a site that silently
/// failed to accept the new password leaves the user with no way back. Ten entries
/// is enough to recover from that without becoming an archive of every secret the
/// user has ever held.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct PasswordHistoryItem {
    /// The superseded password.
    pub password: String,
    /// When it was replaced, in Unix seconds.
    #[zeroize(skip)]
    pub replaced_at: u64,
}

impl core::fmt::Debug for PasswordHistoryItem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordHistoryItem")
            .field("password", &"<redacted>")
            .field("replaced_at", &self.replaced_at)
            .finish()
    }
}

/// Reference to an encrypted attachment stored outside the record.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AttachmentRef {
    /// Attachment identifier, and the input to its derived key.
    pub attachment_id: [u8; 16],
    /// Original filename.
    pub filename: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// BLAKE3 hash of the plaintext, so a restored attachment can be verified.
    pub content_hash: [u8; 32],
}

/// The secret contents of one vault entry.
///
/// Stored encrypted under a per-record key and decrypted only when the specific
/// entry is requested — never at unlock. That is what keeps the decrypted footprint
/// small, which is the most effective mitigation available against an attacker with
/// code execution on an unlocked machine (T3 in the threat model).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct RecordBody {
    /// Record schema version.
    #[zeroize(skip)]
    pub schema: u16,
    /// Username or account identifier.
    ///
    /// Also present in the manifest for search, but kept here as the authoritative
    /// copy so an entry remains complete if the manifest is ever rebuilt.
    pub username: String,
    /// The password.
    pub password: String,
    /// TOTP shared secret, base32-encoded.
    ///
    /// Handled exactly like a password: it is a long-lived credential, and treating
    /// it as less sensitive is a common and costly mistake.
    pub totp_secret: Option<String>,
    /// Free-form notes.
    pub notes: String,
    /// User-defined extra fields.
    pub custom_fields: Vec<CustomField>,
    /// Attachments belonging to this entry.
    #[zeroize(skip)]
    pub attachments: Vec<AttachmentRef>,
    /// Previous passwords, newest first.
    pub history: Vec<PasswordHistoryItem>,
}

impl core::fmt::Debug for RecordBody {
    /// Reports only shape. There is no formatting path that reveals a secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordBody")
            .field("schema", &self.schema)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field(
                "totp_secret",
                &self.totp_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("notes_len", &self.notes.len())
            .field("custom_fields", &self.custom_fields.len())
            .field("attachments", &self.attachments.len())
            .field("history", &self.history.len())
            .finish()
    }
}

impl Default for RecordBody {
    fn default() -> Self {
        Self {
            schema: RECORD_SCHEMA,
            username: String::new(),
            password: String::new(),
            totp_secret: None,
            notes: String::new(),
            custom_fields: Vec::new(),
            attachments: Vec::new(),
            history: Vec::new(),
        }
    }
}

impl RecordBody {
    /// An empty record at the current schema version.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // Builder methods exist because deriving `ZeroizeOnDrop` implements `Drop`,
    // which makes struct-update syntax (`..RecordBody::default()`) illegal: you
    // cannot move a field out of a type that implements `Drop`. Rather than leave
    // every caller assembling all eight fields by hand, the common ones get a
    // setter. Each takes and returns `self` by value, which is permitted because
    // the whole value moves rather than an individual field.

    /// Set the username.
    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Set the password.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }

    /// Set the TOTP shared secret.
    #[must_use]
    pub fn with_totp_secret(mut self, secret: impl Into<String>) -> Self {
        self.totp_secret = Some(secret.into());
        self
    }

    /// Set the notes field.
    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    /// Append a custom field.
    #[must_use]
    pub fn with_custom_field(mut self, field: CustomField) -> Self {
        self.custom_fields.push(field);
        self
    }

    /// Serialize and pad, ready to be encrypted.
    ///
    /// The returned buffer is padded to a [`RECORD_BLOCK`] boundary so its length
    /// reveals only a coarse size bucket. Callers must encrypt it; nothing else may
    /// consume the output.
    pub fn encode_padded(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let encoded = postcard::to_allocvec(self)
            .map_err(|_| Error::Encode("record body could not be serialized"))?;
        if encoded.len() > limits::MAX_RECORD_LEN {
            return Err(Error::Encode("record body exceeds the maximum record size"));
        }
        padding::pad(&encoded, RECORD_BLOCK)
    }

    /// Unpad and deserialize an already-decrypted, already-authenticated record.
    ///
    /// Call this only on output from the AEAD. See the module documentation for why
    /// the ordering is a security property rather than a style preference.
    pub fn decode_padded(plaintext: &[u8]) -> Result<Self> {
        let unpadded = padding::unpad(plaintext, RECORD_BLOCK)?;
        let body: Self = postcard::from_bytes(unpadded)
            .map_err(|_| Error::Malformed("record body could not be deserialized"))?;
        if body.schema == 0 || body.schema > RECORD_SCHEMA {
            return Err(Error::Malformed(
                "record uses an unsupported schema version",
            ));
        }
        body.validate()?;
        Ok(body)
    }

    /// Check field sizes against [`crate::limits`].
    ///
    /// Applied on both encode and decode. On decode the bytes are already
    /// authenticated, so this is catching our own bugs and genuine corruption rather
    /// than an attacker — but a record with a million history entries would still
    /// wedge the UI, and failing cleanly beats that.
    pub fn validate(&self) -> Result<()> {
        if self.username.len() > limits::MAX_STRING_LEN {
            return Err(Error::Malformed("username is too long"));
        }
        if self.password.len() > limits::MAX_STRING_LEN {
            return Err(Error::Malformed("password is too long"));
        }
        if self.notes.len() > limits::MAX_NOTES_LEN {
            return Err(Error::Malformed("notes are too long"));
        }
        if let Some(totp) = &self.totp_secret {
            if totp.len() > limits::MAX_STRING_LEN {
                return Err(Error::Malformed("TOTP secret is too long"));
            }
        }
        if self.custom_fields.len() > limits::MAX_COLLECTION_LEN {
            return Err(Error::Malformed("too many custom fields"));
        }
        for field in &self.custom_fields {
            if field.name.len() > limits::MAX_STRING_LEN
                || field.value.len() > limits::MAX_NOTES_LEN
            {
                return Err(Error::Malformed("custom field is too long"));
            }
        }
        if self.attachments.len() > limits::MAX_COLLECTION_LEN {
            return Err(Error::Malformed("too many attachments"));
        }
        for attachment in &self.attachments {
            if attachment.filename.len() > limits::MAX_STRING_LEN {
                return Err(Error::Malformed("attachment filename is too long"));
            }
        }
        if self.history.len() > limits::MAX_HISTORY_LEN {
            return Err(Error::Malformed("too many history entries"));
        }
        Ok(())
    }

    /// Replace the password, pushing the old one onto the history.
    ///
    /// `keep` bounds the retained history. The old value is moved rather than
    /// copied, so rotation does not leave an extra copy of the previous password in
    /// memory.
    pub fn rotate_password(&mut self, new_password: String, replaced_at: u64, keep: usize) {
        let old = std::mem::replace(&mut self.password, new_password);
        if !old.is_empty() {
            self.history.insert(
                0,
                PasswordHistoryItem {
                    password: old,
                    replaced_at,
                },
            );
        }
        // `truncate` drops the excess items, and their `ZeroizeOnDrop` wipes them.
        self.history.truncate(keep.min(limits::MAX_HISTORY_LEN));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RecordBody {
        RecordBody {
            schema: RECORD_SCHEMA,
            username: "ada@example.com".to_owned(),
            password: "correct-horse-battery-staple".to_owned(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".to_owned()),
            notes: "recovery codes in the safe".to_owned(),
            custom_fields: vec![CustomField {
                name: "security answer".to_owned(),
                value: "a lie".to_owned(),
                secret: true,
            }],
            attachments: vec![AttachmentRef {
                attachment_id: [1; 16],
                filename: "recovery.pdf".to_owned(),
                size: 4096,
                content_hash: [2; 32],
            }],
            history: vec![PasswordHistoryItem {
                password: "hunter2".to_owned(),
                replaced_at: 1_600_000_000,
            }],
        }
    }

    #[test]
    fn round_trips() {
        let body = sample();
        let encoded = body.encode_padded().unwrap();
        let decoded = RecordBody::decode_padded(&encoded).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn empty_record_round_trips() {
        let body = RecordBody::default();
        let encoded = body.encode_padded().unwrap();
        assert_eq!(RecordBody::decode_padded(&encoded).unwrap(), body);
    }

    #[test]
    fn encoded_length_is_block_aligned_and_hides_small_differences() {
        let short = RecordBody::new().with_password("a");
        let longer = RecordBody::new().with_password("a".repeat(150));

        let a = short.encode_padded().unwrap();
        let b = longer.encode_padded().unwrap();
        assert_eq!(a.len() % RECORD_BLOCK, 0);
        assert_eq!(
            a.len(),
            b.len(),
            "a 1-char and a 150-char password must look alike"
        );
    }

    #[test]
    fn debug_never_reveals_any_secret() {
        let body = sample();
        let rendered = format!("{body:?}");
        for secret in [
            "correct-horse-battery-staple",
            "JBSWY3DPEHPK3PXP",
            "ada@example.com",
            "hunter2",
            "a lie",
            "security answer",
        ] {
            assert!(!rendered.contains(secret), "Debug leaked {secret:?}");
        }
        assert!(rendered.contains("redacted"));
        // Shape is still useful for diagnostics.
        assert!(rendered.contains("history: 1"));
    }

    #[test]
    fn custom_field_debug_redacts_its_name_too() {
        let field = CustomField {
            name: "Coinbase 2FA backup".to_owned(),
            value: "123456".to_owned(),
            secret: true,
        };
        let rendered = format!("{field:?}");
        assert!(!rendered.contains("Coinbase"));
        assert!(!rendered.contains("123456"));
    }

    #[test]
    fn oversized_fields_are_rejected() {
        let too_long_password =
            RecordBody::new().with_password("x".repeat(limits::MAX_STRING_LEN + 1));
        assert!(too_long_password.encode_padded().is_err());

        let too_long_notes = RecordBody::new().with_notes("x".repeat(limits::MAX_NOTES_LEN + 1));
        assert!(too_long_notes.encode_padded().is_err());

        let mut too_much_history = RecordBody::new();
        too_much_history.history = (0..=limits::MAX_HISTORY_LEN)
            .map(|i| PasswordHistoryItem {
                password: "p".to_owned(),
                replaced_at: i as u64,
            })
            .collect();
        assert!(too_much_history.encode_padded().is_err());
    }

    #[test]
    fn rejects_an_unsupported_schema_version() {
        let mut body = RecordBody::new();
        body.schema = RECORD_SCHEMA + 1;
        let encoded = postcard::to_allocvec(&body).unwrap();
        let padded = padding::pad(&encoded, RECORD_BLOCK).unwrap();
        assert!(matches!(
            RecordBody::decode_padded(&padded),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn decoding_garbage_errors_rather_than_panicking() {
        // Records are authenticated before reaching the decoder, so this should be
        // unreachable in practice. It must still fail cleanly.
        for len in [0usize, 1, 4, 255, 256, 512] {
            let buf = vec![0xFFu8; len];
            let _ = RecordBody::decode_padded(&buf);
        }
        let padded = padding::pad(&[0xFF; 100], RECORD_BLOCK).unwrap();
        assert!(RecordBody::decode_padded(&padded).is_err());
    }

    #[test]
    fn rotation_preserves_the_old_password_in_history() {
        let mut body = RecordBody::new().with_password("old-one");
        body.rotate_password("new-one".to_owned(), 1_700_000_000, 10);
        assert_eq!(body.password, "new-one");
        assert_eq!(body.history.len(), 1);
        assert_eq!(body.history[0].password, "old-one");
        assert_eq!(body.history[0].replaced_at, 1_700_000_000);
    }

    #[test]
    fn rotation_bounds_the_history() {
        let mut body = RecordBody::new().with_password("p0");
        for i in 1..20 {
            body.rotate_password(format!("p{i}"), 1_700_000_000 + i, 10);
        }
        assert_eq!(
            body.history.len(),
            10,
            "history must not grow without bound"
        );
        // Newest first.
        assert_eq!(body.history[0].password, "p18");
    }

    #[test]
    fn rotation_from_empty_does_not_record_an_empty_history_entry() {
        let mut body = RecordBody::new();
        body.rotate_password("first".to_owned(), 1, 10);
        assert!(body.history.is_empty());
    }
}
