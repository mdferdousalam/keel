// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The vault header, and the associated data that binds everything to it.
//!
//! The header is plaintext — it has to be, since it holds the parameters needed to
//! derive the key that decrypts everything else. What makes that safe is that the
//! header is **authenticated**: two hashes over its fields are fed into the AEAD
//! associated data of everything the vault contains.
//!
//! # Two hashes, and why one is not enough
//!
//! | Hash | Covers | Used by |
//! |---|---|---|
//! | [`Header::binding_hash`] | Everything: version, flags, vault id, KDF identifier, cost parameters, salt, required factors, AEAD identifier, epoch, key count | The wrapped master key |
//! | [`Header::identity_hash`] | Only format version, vault id, AEAD identifier | The manifest and every record |
//!
//! **The downgrade attack** is what the wide hash prevents. Without it, an attacker
//! who can write to your vault file rewrites the header to say `m_cost = 8 KiB`,
//! hands it back, and lets *your own client* perform a cheap key derivation they can
//! then brute-force in seconds. The parameters are not secret — there is nothing to
//! hide — but they must be impossible to change undetected. Because `binding_hash`
//! covers them and feeds the wrapped key's associated data, a rewritten header simply
//! fails to unwrap. The same mechanism blocks stripping a required factor and swapping
//! the algorithm identifiers.
//!
//! **The narrow hash exists because the wide one is too wide for records.** A
//! passphrase change rewrites the salt, the cost parameters, and the factor set. If
//! records were bound to all of that, changing the passphrase would invalidate every
//! record in the vault — destroying the entire reason the design separates the
//! key-encryption key from the vault master key, and turning a sub-second header
//! rewrite into a full re-encryption. Nothing is weakened, because an attacker who
//! tampers with the KDF parameters cannot unwrap the master key and so never reaches a
//! record at all.
//!
//! # What the associated data deliberately does not cover
//!
//! [`Header::record_aad`] excludes the write counter. Including it would be
//! tempting — it would bind each record to a specific save — but it would also mean
//! **every save re-encrypts every record**, turning a one-entry edit into a full
//! vault rewrite. Instead the *set* of records is bound by the manifest, which
//! stores a hash of every record blob. That catches deletion, duplication,
//! reordering, and splicing from another version of the file, which is what the
//! write counter would have caught, without the cost.

use keel_crypto::kdf::Argon2Params;
use keel_crypto::{Nonce, Sealed, AEAD_ID_XCHACHA20POLY1305, KDF_ID_ARGON2ID_V13, NONCE_LEN};

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::limits;

/// Magic number at the start of every vault file.
pub const MAGIC: [u8; 8] = *b"KEELVLT\x01";

/// Magic number at the very end of every vault file.
///
/// Present so that a truncated file is detected as truncated even if the length
/// field somehow agrees; a file cut short simply will not end with these bytes.
pub const FOOTER_MAGIC: [u8; 8] = *b"KEELEND\x01";

/// The format version this build writes.
pub const FORMAT_VERSION: u16 = 1;

/// Length of the vault UUID, in bytes.
pub const UUID_LEN: usize = 16;

/// Length of a wrapped master key's ciphertext, including its tag.
///
/// A 32-byte key plus a 16-byte Poly1305 tag.
pub const WRAPPED_KEY_CT_LEN: usize = 48;

/// Encoded size of one wrapped-key entry: epoch, nonce, ciphertext-with-tag.
pub const WRAPPED_KEY_LEN: usize = 4 + NONCE_LEN + WRAPPED_KEY_CT_LEN;

/// Size of the header's reserved-for-future-use region, in bytes.
pub const RESERVED_LEN: usize = 32;

/// Domain string for wrapped-key associated data.
const AAD_WRAP: &[u8] = b"keel/v1/wrap";
/// Domain string for manifest associated data.
const AAD_MANIFEST: &[u8] = b"keel/v1/manifest";
/// Domain string for record associated data.
const AAD_RECORD: &[u8] = b"keel/v1/record";

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Header feature flags.
///
/// A newtype rather than a `bitflags` dependency: two flags do not justify a crate
/// in the tree that parses the vault format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeaderFlags(u32);

impl HeaderFlags {
    /// Record bodies are compressed before encryption.
    pub const COMPRESSED_RECORDS: u32 = 1 << 0;
    /// A platform quick-unlock key is enrolled for some device.
    pub const QUICK_UNLOCK_ENROLLED: u32 = 1 << 1;

    /// All bits this version understands.
    const KNOWN: u32 = Self::COMPRESSED_RECORDS | Self::QUICK_UNLOCK_ENROLLED;

    /// Build from a raw value, rejecting unknown bits.
    ///
    /// Refusing unknown bits keeps a forward-compatibility mistake loud. Silently
    /// ignoring a flag that means "records are compressed" would produce garbage
    /// that looks like corruption.
    pub const fn from_bits(bits: u32) -> Result<Self> {
        if bits & !Self::KNOWN != 0 {
            return Err(Error::Corrupt("header sets unknown feature flags"));
        }
        Ok(Self(bits))
    }

    /// Raw bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True if the given flag is set.
    #[must_use]
    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Set or clear a flag.
    #[must_use]
    pub const fn with(self, flag: u32, on: bool) -> Self {
        if on {
            Self(self.0 | flag)
        } else {
            Self(self.0 & !flag)
        }
    }
}

// ---------------------------------------------------------------------------
// Factors
// ---------------------------------------------------------------------------

/// A YubiKey HMAC-SHA1 challenge-response factor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YubikeyFactor {
    /// Configuration slot on the key (1 or 2).
    pub slot: u8,
    /// Challenge presented to the key.
    ///
    /// Regenerated on every save, following the KeePassXC model, which means the
    /// key must be present to *write* as well as to read. The consequence is
    /// documented loudly in the UI: without a second key programmed with the same
    /// secret, an old backup becomes unopenable.
    pub challenge: [u8; 64],
}

/// A FIDO2 `hmac-secret` factor.
///
/// The preferred hardware factor: it returns 32 bytes rather than the 20 a YubiKey
/// OTP slot gives, and it requires a physical touch on every unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Factor {
    /// Hash of the relying-party id the credential was created under.
    pub rp_id_hash: [u8; 32],
    /// Salt passed to the authenticator's `hmac-secret` extension.
    pub salt: [u8; 32],
    /// Credential id to assert with.
    pub credential_id: Vec<u8>,
}

/// Which additional unlock factors this vault requires.
///
/// Recorded in the header and covered by [`Header::binding_hash`], so an attacker
/// cannot strip a factor and unlock with fewer than the owner configured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FactorSet {
    /// BLAKE3 commitment to the keyfile's contents.
    pub keyfile: Option<[u8; 32]>,
    /// YubiKey challenge-response factor.
    pub yubikey: Option<YubikeyFactor>,
    /// FIDO2 `hmac-secret` factor.
    pub fido2: Option<Fido2Factor>,
}

impl FactorSet {
    const FLAG_KEYFILE: u8 = 1 << 0;
    const FLAG_YUBIKEY: u8 = 1 << 1;
    const FLAG_FIDO2: u8 = 1 << 2;
    const KNOWN_FLAGS: u8 = Self::FLAG_KEYFILE | Self::FLAG_YUBIKEY | Self::FLAG_FIDO2;

    /// True if only the passphrase is required.
    #[must_use]
    pub const fn is_passphrase_only(&self) -> bool {
        self.keyfile.is_none() && self.yubikey.is_none() && self.fido2.is_none()
    }

    /// Number of factors beyond the passphrase.
    #[must_use]
    pub const fn extra_factor_count(&self) -> usize {
        self.keyfile.is_some() as usize
            + self.yubikey.is_some() as usize
            + self.fido2.is_some() as usize
    }

    fn flags(&self) -> u8 {
        let mut f = 0;
        if self.keyfile.is_some() {
            f |= Self::FLAG_KEYFILE;
        }
        if self.yubikey.is_some() {
            f |= Self::FLAG_YUBIKEY;
        }
        if self.fido2.is_some() {
            f |= Self::FLAG_FIDO2;
        }
        f
    }

    fn encode(&self, w: &mut Writer) -> Result<()> {
        w.u8(self.flags());
        // Order is fixed by ascending flag bit, so encode and decode cannot drift.
        if let Some(commitment) = &self.keyfile {
            w.bytes(commitment);
        }
        if let Some(yk) = &self.yubikey {
            w.u8(yk.slot);
            w.bytes(&yk.challenge);
        }
        if let Some(f2) = &self.fido2 {
            w.bytes(&f2.rp_id_hash);
            w.bytes(&f2.salt);
            w.len_u32(f2.credential_id.len(), "credential id too long")?;
            w.bytes(&f2.credential_id);
        }
        Ok(())
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let flags = r.u8()?;
        if flags & !Self::KNOWN_FLAGS != 0 {
            return Err(Error::Corrupt("header requires an unknown unlock factor"));
        }
        let keyfile = if flags & Self::FLAG_KEYFILE != 0 {
            Some(r.array::<32>()?)
        } else {
            None
        };
        let yubikey = if flags & Self::FLAG_YUBIKEY != 0 {
            Some(YubikeyFactor {
                slot: r.u8()?,
                challenge: r.array::<64>()?,
            })
        } else {
            None
        };
        let fido2 = if flags & Self::FLAG_FIDO2 != 0 {
            let rp_id_hash = r.array::<32>()?;
            let salt = r.array::<32>()?;
            let len = r.checked_len_u32("FIDO2 credential id", limits::MAX_CREDENTIAL_ID_LEN)?;
            Some(Fido2Factor {
                rp_id_hash,
                salt,
                credential_id: r.take(len)?.to_vec(),
            })
        } else {
            None
        };
        Ok(Self {
            keyfile,
            yubikey,
            fido2,
        })
    }
}

// ---------------------------------------------------------------------------
// Wrapped keys
// ---------------------------------------------------------------------------

/// The vault master key, encrypted under a key-encryption key derived from the
/// user's factors.
///
/// The header holds an array of these rather than one, so a key rotation can
/// proceed lazily: new and edited records are written under the new epoch while old
/// records stay readable, and the old wrapped key is dropped only once compaction
/// finishes. That makes rotation interruption-safe by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    /// Which key generation this wraps.
    pub epoch: u32,
    /// Nonce used to wrap it.
    pub nonce: Nonce,
    /// Wrapped key material: 32 ciphertext bytes followed by a 16-byte tag.
    pub ciphertext: [u8; WRAPPED_KEY_CT_LEN],
}

impl WrappedKey {
    /// Build from a [`Sealed`] value produced by the AEAD layer.
    pub fn from_sealed(epoch: u32, sealed: &Sealed) -> Result<Self> {
        if sealed.ciphertext.len() != WRAPPED_KEY_CT_LEN {
            return Err(Error::Encode(
                "wrapped master key has an unexpected ciphertext length",
            ));
        }
        let mut ciphertext = [0u8; WRAPPED_KEY_CT_LEN];
        ciphertext.copy_from_slice(&sealed.ciphertext);
        Ok(Self {
            epoch,
            nonce: sealed.nonce,
            ciphertext,
        })
    }

    /// Convert back into a [`Sealed`] for decryption.
    #[must_use]
    pub fn to_sealed(&self) -> Sealed {
        Sealed {
            nonce: self.nonce,
            ciphertext: self.ciphertext.to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// The plaintext, authenticated vault header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// On-disk format version.
    pub format_version: u16,
    /// Feature flags.
    pub flags: HeaderFlags,
    /// Immutable identifier for this vault, and the HKDF salt for every subkey.
    pub vault_uuid: [u8; UUID_LEN],
    /// Creation time, Unix seconds.
    pub created_at: u64,
    /// Key-derivation algorithm identifier.
    pub kdf_id: u8,
    /// Argon2id cost parameters.
    pub kdf_params: Argon2Params,
    /// Per-vault KDF salt.
    pub kdf_salt: [u8; keel_crypto::SALT_LEN],
    /// How long key derivation took when the vault was created, in milliseconds.
    ///
    /// Purely informational, so a later unlock can say "this took 1.4 s when you
    /// created the vault and takes 6 s now" rather than leaving the user wondering.
    pub measured_kdf_ms: u32,
    /// Additional required unlock factors.
    pub factors: FactorSet,
    /// AEAD algorithm identifier.
    pub aead_id: u8,
    /// Key epoch that new records are written under.
    pub vmk_epoch_current: u32,
    /// Wrapped master keys, one per live epoch.
    pub wrapped_keys: Vec<WrappedKey>,
    /// Strictly monotonic save counter, used to detect rollback.
    pub write_counter: u64,
    /// Offset of the encrypted manifest from the start of the file.
    pub manifest_offset: u64,
    /// Length of the encrypted manifest, including nonce and tag.
    pub manifest_len: u64,
    /// Offset of the records section.
    pub records_offset: u64,
    /// Length of the records section.
    pub records_len: u64,
}

impl Header {
    /// Encode the prefix that [`Header::binding_hash`] covers.
    ///
    /// Everything from the magic number through the wrapped-key count: the format
    /// version, feature flags, vault id, KDF identifier and parameters, salt,
    /// required factors, and AEAD identifier. Every field an attacker would want to
    /// weaken is inside this range.
    ///
    /// The header length is written as zero here rather than its real value. The
    /// real length depends only on the factor section, which is already covered, and
    /// leaving it out means adding a field after the prefix cannot invalidate
    /// existing vaults.
    fn encode_binding_prefix(&self) -> Result<Vec<u8>> {
        let mut w = Writer::with_capacity(256);
        w.bytes(&MAGIC);
        w.u16(self.format_version);
        w.u32(0); // header_len is excluded from the binding; see above
        w.u32(self.flags.bits());
        w.bytes(&self.vault_uuid);
        w.u64(self.created_at);
        w.u8(self.kdf_id);
        w.u32(self.kdf_params.m_cost_kib);
        w.u32(self.kdf_params.t_cost);
        w.u32(self.kdf_params.p_cost);
        w.u8(u8::try_from(self.kdf_salt.len()).map_err(|_| Error::Encode("salt too long"))?);
        w.bytes(&self.kdf_salt);
        w.u32(self.measured_kdf_ms);
        self.factors.encode(&mut w)?;
        w.u8(self.aead_id);
        w.u32(self.vmk_epoch_current);
        w.u8(u8::try_from(self.wrapped_keys.len()).map_err(|_| Error::Encode("too many keys"))?);
        Ok(w.into_vec())
    }

    /// Hash binding the key-derivation configuration.
    ///
    /// Covers the format version, flags, vault id, creation time, KDF identifier and
    /// cost parameters, salt, required factors, AEAD identifier, current epoch, and
    /// key count — every field an attacker would want to weaken in order to make key
    /// derivation cheap.
    ///
    /// Used **only** for [`Header::wrap_aad`]. See [`Header::identity_hash`] for why
    /// the manifest and records use something narrower.
    pub fn binding_hash(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.encode_binding_prefix()?).as_bytes())
    }

    /// Hash binding the fields that fix how the vault body is interpreted.
    ///
    /// Covers exactly three things, and the omissions are the point:
    ///
    /// * `format_version` — so a version downgrade cannot reinterpret the bytes.
    /// * `vault_uuid` — so a record cannot be moved between vaults.
    /// * `aead_id` — so the cipher cannot be swapped.
    ///
    /// # Why not the full binding hash
    ///
    /// [`Header::binding_hash`] covers the KDF salt and cost parameters, which is
    /// correct for the wrapped key. Using it for records too would mean that
    /// **changing the master passphrase invalidated every record in the vault**,
    /// because a passphrase change rewrites the salt and parameters. That would
    /// destroy the whole reason the design separates the key-encryption key from the
    /// vault master key, and turn a sub-second operation into a full re-encryption.
    ///
    /// Nothing is weakened by the narrower hash. An attacker who tampers with the KDF
    /// parameters cannot unwrap the master key, so they never reach the manifest or a
    /// record to begin with; `wrap_aad` is where that attack is stopped.
    ///
    /// Note that header *flags* are deliberately excluded, because they are mutable
    /// over a vault's life (enrolling a quick-unlock key sets one). If a future flag
    /// changes how record bytes are interpreted — compression, say — it must be
    /// recorded per record or gated behind a format version bump, not left in a
    /// mutable header field.
    pub fn identity_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"keel/v1/identity");
        hasher.update(&self.format_version.to_le_bytes());
        hasher.update(&self.vault_uuid);
        hasher.update(&[self.aead_id]);
        *hasher.finalize().as_bytes()
    }

    /// Associated data for the wrapped master key of a given epoch.
    ///
    /// Uses the full [`Header::binding_hash`], which is what makes a KDF-parameter
    /// downgrade fail instead of succeeding cheaply.
    pub fn wrap_aad(&self, epoch: u32) -> Result<Vec<u8>> {
        let h = self.binding_hash()?;
        let mut aad = Vec::with_capacity(AAD_WRAP.len() + UUID_LEN + 32 + 4);
        aad.extend_from_slice(AAD_WRAP);
        aad.extend_from_slice(&self.vault_uuid);
        aad.extend_from_slice(&h);
        aad.extend_from_slice(&epoch.to_le_bytes());
        Ok(aad)
    }

    /// Associated data for the encrypted manifest.
    ///
    /// Includes the write counter, so replaying an old manifest under a newer header
    /// fails.
    pub fn manifest_aad(&self) -> Result<Vec<u8>> {
        let h = self.identity_hash();
        let mut aad = Vec::with_capacity(AAD_MANIFEST.len() + UUID_LEN + 32 + 8 + 2);
        aad.extend_from_slice(AAD_MANIFEST);
        aad.extend_from_slice(&self.vault_uuid);
        aad.extend_from_slice(&h);
        aad.extend_from_slice(&self.write_counter.to_le_bytes());
        aad.extend_from_slice(&self.format_version.to_le_bytes());
        Ok(aad)
    }

    /// Associated data for one record.
    ///
    /// Excludes the write counter on purpose — see the module documentation. The
    /// record *set* is bound by the manifest's per-record blob hashes instead.
    pub fn record_aad(&self, record_id: &[u8; UUID_LEN], key_epoch: u32) -> Result<Vec<u8>> {
        let h = self.identity_hash();
        let mut aad = Vec::with_capacity(AAD_RECORD.len() + UUID_LEN + 32 + UUID_LEN + 4);
        aad.extend_from_slice(AAD_RECORD);
        aad.extend_from_slice(&self.vault_uuid);
        aad.extend_from_slice(&h);
        aad.extend_from_slice(record_id);
        aad.extend_from_slice(&key_epoch.to_le_bytes());
        Ok(aad)
    }

    /// The wrapped key for a given epoch, if present.
    #[must_use]
    pub fn wrapped_key(&self, epoch: u32) -> Option<&WrappedKey> {
        self.wrapped_keys.iter().find(|k| k.epoch == epoch)
    }

    /// Encode the header.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_for_encode()?;

        let mut w = Writer::with_capacity(limits::MAX_HEADER_LEN.min(1024));
        w.bytes(&MAGIC);
        w.u16(self.format_version);
        let header_len_offset = w.len();
        w.u32(0); // patched below
        w.u32(self.flags.bits());
        w.bytes(&self.vault_uuid);
        w.u64(self.created_at);
        w.u8(self.kdf_id);
        w.u32(self.kdf_params.m_cost_kib);
        w.u32(self.kdf_params.t_cost);
        w.u32(self.kdf_params.p_cost);
        w.u8(u8::try_from(self.kdf_salt.len()).map_err(|_| Error::Encode("salt too long"))?);
        w.bytes(&self.kdf_salt);
        w.u32(self.measured_kdf_ms);
        self.factors.encode(&mut w)?;
        w.u8(self.aead_id);
        w.u32(self.vmk_epoch_current);
        w.u8(u8::try_from(self.wrapped_keys.len()).map_err(|_| Error::Encode("too many keys"))?);

        // --- end of the binding prefix ---
        for key in &self.wrapped_keys {
            w.u32(key.epoch);
            w.bytes(&key.nonce);
            w.bytes(&key.ciphertext);
        }
        w.u64(self.write_counter);
        w.u64(self.manifest_offset);
        w.u64(self.manifest_len);
        w.u64(self.records_offset);
        w.u64(self.records_len);
        w.zeroes(RESERVED_LEN);

        let total = w.len();
        if total > limits::MAX_HEADER_LEN {
            return Err(Error::Encode("header exceeds the maximum size"));
        }
        w.patch_u32(
            header_len_offset,
            u32::try_from(total).map_err(|_| Error::Encode("header too long"))?,
        )?;
        Ok(w.into_vec())
    }

    /// Decode a header from the start of `buf`, returning it and its byte length.
    ///
    /// Every length and identifier is validated before it is used, so a malformed
    /// file produces an error rather than an allocation or a panic.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        let mut r = Reader::new(buf);

        if r.array::<8>()? != MAGIC {
            return Err(Error::BadMagic);
        }
        let format_version = r.u16()?;
        if format_version == 0 || format_version > FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: format_version,
                supported: FORMAT_VERSION,
            });
        }
        let header_len = r.checked_len_u32("header length", limits::MAX_HEADER_LEN)?;
        let flags = HeaderFlags::from_bits(r.u32()?)?;
        let vault_uuid = r.array::<UUID_LEN>()?;
        let created_at = r.u64()?;

        let kdf_id = r.u8()?;
        if kdf_id != KDF_ID_ARGON2ID_V13 {
            return Err(Error::UnknownAlgorithm {
                kind: "KDF",
                id: kdf_id,
            });
        }
        let kdf_params = Argon2Params {
            m_cost_kib: r.u32()?,
            t_cost: r.u32()?,
            p_cost: r.u32()?,
        };
        // Reject absurd cost parameters here, before anything tries to allocate
        // that much memory. This is the denial-of-service guard.
        kdf_params.validate()?;

        let salt_len = r.u8()? as usize;
        if salt_len != keel_crypto::SALT_LEN {
            return Err(Error::Corrupt("KDF salt has an unexpected length"));
        }
        let kdf_salt = r.array::<{ keel_crypto::SALT_LEN }>()?;
        let measured_kdf_ms = r.u32()?;
        let factors = FactorSet::decode(&mut r)?;

        let aead_id = r.u8()?;
        if aead_id != AEAD_ID_XCHACHA20POLY1305 {
            return Err(Error::UnknownAlgorithm {
                kind: "AEAD",
                id: aead_id,
            });
        }
        let vmk_epoch_current = r.u32()?;
        let key_count = r.u8()? as usize;
        if key_count == 0 {
            return Err(Error::Corrupt("header contains no wrapped master key"));
        }
        if key_count > limits::MAX_WRAPPED_KEYS {
            return Err(Error::TooLarge {
                what: "wrapped master keys",
                found: key_count as u64,
                limit: limits::MAX_WRAPPED_KEYS as u64,
            });
        }

        let mut wrapped_keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            wrapped_keys.push(WrappedKey {
                epoch: r.u32()?,
                nonce: r.array::<NONCE_LEN>()?,
                ciphertext: r.array::<WRAPPED_KEY_CT_LEN>()?,
            });
        }

        let write_counter = r.u64()?;
        let manifest_offset = r.u64()?;
        let manifest_len = r.u64()?;
        let records_offset = r.u64()?;
        let records_len = r.u64()?;
        r.expect_zeroes(RESERVED_LEN, "header reserved bytes are not zero")?;

        let consumed = r.position();
        if consumed != header_len {
            return Err(Error::Corrupt(
                "header length field disagrees with the header contents",
            ));
        }

        let header = Self {
            format_version,
            flags,
            vault_uuid,
            created_at,
            kdf_id,
            kdf_params,
            kdf_salt,
            measured_kdf_ms,
            factors,
            aead_id,
            vmk_epoch_current,
            wrapped_keys,
            write_counter,
            manifest_offset,
            manifest_len,
            records_offset,
            records_len,
        };
        header.validate_after_decode()?;
        Ok((header, consumed))
    }

    fn validate_for_encode(&self) -> Result<()> {
        if self.wrapped_keys.is_empty() {
            return Err(Error::Encode(
                "a vault needs at least one wrapped master key",
            ));
        }
        if self.wrapped_keys.len() > limits::MAX_WRAPPED_KEYS {
            return Err(Error::Encode("too many wrapped master keys"));
        }
        if self.wrapped_key(self.vmk_epoch_current).is_none() {
            return Err(Error::Encode(
                "no wrapped master key for the current key epoch",
            ));
        }
        self.kdf_params.validate()?;
        Ok(())
    }

    fn validate_after_decode(&self) -> Result<()> {
        // A vault with no key for the epoch it claims to be writing under cannot be
        // opened at all, so reject it here with a clear message rather than failing
        // later inside the unwrap path where the error would look like a bad
        // passphrase.
        if self.wrapped_key(self.vmk_epoch_current).is_none() {
            return Err(Error::Corrupt(
                "no wrapped master key for the vault's current key epoch",
            ));
        }
        if self.manifest_len > limits::MAX_MANIFEST_LEN as u64 {
            return Err(Error::TooLarge {
                what: "manifest",
                found: self.manifest_len,
                limit: limits::MAX_MANIFEST_LEN as u64,
            });
        }
        if self.records_len > limits::MAX_RECORDS_LEN {
            return Err(Error::TooLarge {
                what: "records section",
                found: self.records_len,
                limit: limits::MAX_RECORDS_LEN,
            });
        }
        // Sections must not overlap, or a crafted file could make the manifest and a
        // record alias the same bytes. The layout is header, records, then manifest —
        // see the note in `crate::vault` on why records come first.
        let records_end = self
            .records_offset
            .checked_add(self.records_len)
            .ok_or(Error::Corrupt("records extent overflows"))?;
        if self.manifest_offset < records_end {
            return Err(Error::Corrupt("manifest and records sections overlap"));
        }
        self.manifest_offset
            .checked_add(self.manifest_len)
            .ok_or(Error::Corrupt("manifest extent overflows"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_crypto::kdf::MIN_M_COST_KIB;

    fn sample_header() -> Header {
        Header {
            format_version: FORMAT_VERSION,
            flags: HeaderFlags::default(),
            vault_uuid: [0xAB; UUID_LEN],
            created_at: 1_700_000_000,
            kdf_id: KDF_ID_ARGON2ID_V13,
            kdf_params: Argon2Params {
                m_cost_kib: MIN_M_COST_KIB,
                t_cost: 3,
                p_cost: 4,
            },
            kdf_salt: [0x11; keel_crypto::SALT_LEN],
            measured_kdf_ms: 1420,
            factors: FactorSet::default(),
            aead_id: AEAD_ID_XCHACHA20POLY1305,
            vmk_epoch_current: 0,
            wrapped_keys: vec![WrappedKey {
                epoch: 0,
                nonce: [0x22; NONCE_LEN],
                ciphertext: [0x33; WRAPPED_KEY_CT_LEN],
            }],
            write_counter: 7,
            // Layout is header, records, then manifest.
            records_offset: 256,
            records_len: 512,
            manifest_offset: 768,
            manifest_len: 256,
        }
    }

    #[test]
    fn round_trips() {
        let h = sample_header();
        let bytes = h.encode().unwrap();
        let (decoded, len) = Header::decode(&bytes).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn round_trips_with_every_factor_present() {
        let mut h = sample_header();
        h.factors = FactorSet {
            keyfile: Some([0x44; 32]),
            yubikey: Some(YubikeyFactor {
                slot: 2,
                challenge: [0x55; 64],
            }),
            fido2: Some(Fido2Factor {
                rp_id_hash: [0x66; 32],
                salt: [0x77; 32],
                credential_id: vec![0x88; 64],
            }),
        };
        let bytes = h.encode().unwrap();
        let (decoded, _) = Header::decode(&bytes).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(decoded.factors.extra_factor_count(), 3);
        assert!(!decoded.factors.is_passphrase_only());
    }

    #[test]
    fn header_length_field_matches_the_encoding() {
        let h = sample_header();
        let bytes = h.encode().unwrap();
        let declared = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize;
        assert_eq!(declared, bytes.len());
    }

    #[test]
    fn rejects_a_foreign_file() {
        let mut bytes = sample_header().encode().unwrap();
        bytes[0] = b'X';
        assert_eq!(Header::decode(&bytes).unwrap_err(), Error::BadMagic);
    }

    #[test]
    fn rejects_a_future_format_version() {
        let mut h = sample_header();
        h.format_version = FORMAT_VERSION + 1;
        // Encode by hand: `encode` writes only the current version.
        let mut bytes = h.encode().unwrap();
        bytes[8..10].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
        assert!(matches!(
            Header::decode(&bytes),
            Err(Error::UnsupportedVersion { found: 2, .. })
        ));
    }

    #[test]
    fn rejects_absurd_kdf_parameters_from_a_hostile_file() {
        // The denial-of-service guard: a file demanding 64 GiB of Argon2 memory must
        // be refused at the parameter field, not after the allocation.
        let mut bytes = sample_header().encode().unwrap();
        // m_cost_kib sits at offset 43.
        bytes[43..47].copy_from_slice(&(64u32 * 1024 * 1024).to_le_bytes());
        assert!(matches!(
            Header::decode(&bytes),
            Err(Error::Crypto(keel_crypto::Error::KdfParams(_)))
        ));
    }

    #[test]
    fn rejects_a_header_with_no_wrapped_key() {
        let mut h = sample_header();
        h.wrapped_keys.clear();
        assert!(h.encode().is_err());
    }

    #[test]
    fn rejects_a_current_epoch_with_no_matching_key() {
        let mut h = sample_header();
        h.vmk_epoch_current = 9;
        assert!(h.encode().is_err());
    }

    #[test]
    fn rejects_overlapping_sections() {
        let mut h = sample_header();
        h.records_offset = 256;
        h.records_len = 1024;
        h.manifest_offset = 600; // inside the records section
        let bytes = h.encode().unwrap();
        assert_eq!(
            Header::decode(&bytes).unwrap_err(),
            Error::Corrupt("manifest and records sections overlap")
        );
    }

    #[test]
    fn rejects_non_zero_reserved_bytes() {
        let mut bytes = sample_header().encode().unwrap();
        let last = bytes.len() - 1;
        bytes[last] = 1;
        assert!(matches!(Header::decode(&bytes), Err(Error::Corrupt(_))));
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        // The property the fuzzer also checks, asserted here so it is covered by the
        // ordinary test run too.
        let bytes = sample_header().encode().unwrap();
        for cut in 0..bytes.len() {
            let result = Header::decode(&bytes[..cut]);
            assert!(result.is_err(), "truncation to {cut} bytes was accepted");
        }
    }

    #[test]
    fn binding_hash_covers_every_security_relevant_field() {
        let base = sample_header();
        let baseline = base.binding_hash().unwrap();

        // Each mutation must change the binding hash, which is what makes tampering
        // with it fail authentication rather than succeed.
        /// A named mutation applied to a header, for the coverage check below.
        type Mutation = (&'static str, Box<dyn Fn(&mut Header)>);

        let mutations: Vec<Mutation> = vec![
            (
                "kdf m_cost",
                Box::new(|h: &mut Header| h.kdf_params.m_cost_kib *= 2),
            ),
            (
                "kdf t_cost",
                Box::new(|h: &mut Header| h.kdf_params.t_cost += 1),
            ),
            (
                "kdf p_cost",
                Box::new(|h: &mut Header| h.kdf_params.p_cost += 1),
            ),
            ("salt", Box::new(|h: &mut Header| h.kdf_salt[0] ^= 1)),
            (
                "vault uuid",
                Box::new(|h: &mut Header| h.vault_uuid[0] ^= 1),
            ),
            (
                "flags",
                Box::new(|h: &mut Header| {
                    h.flags = h.flags.with(HeaderFlags::COMPRESSED_RECORDS, true);
                }),
            ),
            (
                "factor set",
                Box::new(|h: &mut Header| h.factors.keyfile = Some([9; 32])),
            ),
            (
                "current epoch",
                Box::new(|h: &mut Header| h.vmk_epoch_current = 1),
            ),
            ("created_at", Box::new(|h: &mut Header| h.created_at += 1)),
            (
                "measured ms",
                Box::new(|h: &mut Header| h.measured_kdf_ms += 1),
            ),
        ];

        for (what, mutate) in mutations {
            let mut h = base.clone();
            mutate(&mut h);
            assert_ne!(
                h.binding_hash().unwrap(),
                baseline,
                "changing {what} must change the binding hash"
            );
        }
    }

    #[test]
    fn binding_hash_ignores_fields_that_change_every_save() {
        // The write counter and the section offsets change on every save. If they
        // were bound, every save would have to re-encrypt every record.
        let base = sample_header();
        let baseline = base.binding_hash().unwrap();

        let mut h = base.clone();
        h.write_counter += 100;
        assert_eq!(h.binding_hash().unwrap(), baseline);

        let mut h = base.clone();
        h.manifest_offset += 64;
        h.records_offset += 64;
        assert_eq!(h.binding_hash().unwrap(), baseline);
    }

    #[test]
    fn record_and_manifest_aad_survive_a_passphrase_change() {
        // The property that makes "changing the passphrase does not re-encrypt records"
        // true. A passphrase change rewrites the salt, the cost parameters, the factor
        // set, and the wrapped key. None of that may alter the associated data used for
        // the manifest or for records, or every record in the vault would have to be
        // re-encrypted — turning a sub-second operation into a full rewrite.
        let before = sample_header();
        let record_aad_before = before.record_aad(&[7; UUID_LEN], 0).unwrap();
        let manifest_aad_before = before.manifest_aad().unwrap();

        let mut after = before.clone();
        after.kdf_salt = [0xEE; keel_crypto::SALT_LEN];
        after.kdf_params = Argon2Params {
            m_cost_kib: MIN_M_COST_KIB * 2,
            t_cost: 5,
            p_cost: 2,
        };
        after.measured_kdf_ms = 4321;
        after.factors.keyfile = Some([0xAB; 32]);
        after.wrapped_keys = vec![WrappedKey {
            epoch: 0,
            nonce: [0x77; NONCE_LEN],
            ciphertext: [0x88; WRAPPED_KEY_CT_LEN],
        }];

        assert_eq!(
            after.record_aad(&[7; UUID_LEN], 0).unwrap(),
            record_aad_before,
            "a passphrase change must not invalidate record associated data"
        );
        assert_eq!(
            after.manifest_aad().unwrap(),
            manifest_aad_before,
            "a passphrase change must not invalidate manifest associated data"
        );

        // But the wrapped-key associated data *must* change, or the downgrade
        // protection would be gone.
        assert_ne!(
            after.wrap_aad(0).unwrap(),
            before.wrap_aad(0).unwrap(),
            "the wrapped key must remain bound to the KDF configuration"
        );
    }

    #[test]
    fn identity_hash_covers_what_fixes_interpretation_of_the_body() {
        let base = sample_header();
        let baseline = base.identity_hash();

        // Changing any of these would change how the vault body must be read, so each
        // must invalidate the manifest and records.
        let mut other_vault = base.clone();
        other_vault.vault_uuid[0] ^= 1;
        assert_ne!(other_vault.identity_hash(), baseline, "vault id");

        let mut other_cipher = base.clone();
        other_cipher.aead_id = 2;
        assert_ne!(other_cipher.identity_hash(), baseline, "AEAD identifier");

        let mut other_version = base.clone();
        other_version.format_version = 2;
        assert_ne!(other_version.identity_hash(), baseline, "format version");
    }

    #[test]
    fn identity_hash_ignores_fields_that_change_during_normal_use() {
        // Header flags are mutable — enrolling a quick-unlock key sets one — so binding
        // them into record associated data would invalidate the vault on a settings
        // change. If a future flag ever changes how record bytes are interpreted, it
        // must live per-record or behind a format version bump instead.
        let base = sample_header();
        let baseline = base.identity_hash();

        let mut flagged = base.clone();
        flagged.flags = flagged.flags.with(HeaderFlags::QUICK_UNLOCK_ENROLLED, true);
        assert_eq!(flagged.identity_hash(), baseline);

        let mut advanced = base.clone();
        advanced.write_counter += 50;
        assert_eq!(advanced.identity_hash(), baseline);

        let mut rotated = base;
        rotated.created_at += 1;
        assert_eq!(rotated.identity_hash(), baseline);
    }

    #[test]
    fn associated_data_is_distinct_per_purpose() {
        let h = sample_header();
        let wrap = h.wrap_aad(0).unwrap();
        let manifest = h.manifest_aad().unwrap();
        let record = h.record_aad(&[1; UUID_LEN], 0).unwrap();
        assert_ne!(wrap, manifest);
        assert_ne!(wrap, record);
        assert_ne!(manifest, record);
    }

    #[test]
    fn record_associated_data_separates_records_and_epochs() {
        let h = sample_header();
        let a = h.record_aad(&[1; UUID_LEN], 0).unwrap();
        let b = h.record_aad(&[2; UUID_LEN], 0).unwrap();
        let c = h.record_aad(&[1; UUID_LEN], 1).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn manifest_associated_data_changes_with_the_write_counter() {
        // This is what stops an old manifest being replayed under a new header.
        let mut h = sample_header();
        let before = h.manifest_aad().unwrap();
        h.write_counter += 1;
        assert_ne!(h.manifest_aad().unwrap(), before);
    }

    #[test]
    fn record_associated_data_ignores_the_write_counter() {
        let mut h = sample_header();
        let before = h.record_aad(&[1; UUID_LEN], 0).unwrap();
        h.write_counter += 1;
        assert_eq!(h.record_aad(&[1; UUID_LEN], 0).unwrap(), before);
    }

    #[test]
    fn unknown_flags_and_factors_are_rejected() {
        assert!(HeaderFlags::from_bits(1 << 31).is_err());
        assert!(HeaderFlags::from_bits(HeaderFlags::COMPRESSED_RECORDS).is_ok());

        let mut bytes = sample_header().encode().unwrap();
        // factor_flags byte follows measured_kdf_ms at offset 92.
        bytes[92] = 1 << 7;
        assert!(matches!(Header::decode(&bytes), Err(Error::Corrupt(_))));
    }

    #[test]
    fn wrapped_key_converts_to_and_from_sealed() {
        let sealed = Sealed {
            nonce: [5; NONCE_LEN],
            ciphertext: vec![6; WRAPPED_KEY_CT_LEN],
        };
        let wrapped = WrappedKey::from_sealed(3, &sealed).unwrap();
        assert_eq!(wrapped.epoch, 3);
        assert_eq!(wrapped.to_sealed(), sealed);
    }

    #[test]
    fn wrapped_key_rejects_a_wrong_sized_ciphertext() {
        let sealed = Sealed {
            nonce: [5; NONCE_LEN],
            ciphertext: vec![6; 10],
        };
        assert!(WrappedKey::from_sealed(0, &sealed).is_err());
    }

    #[test]
    fn multiple_epochs_round_trip_for_lazy_rotation() {
        let mut h = sample_header();
        h.wrapped_keys.push(WrappedKey {
            epoch: 1,
            nonce: [0x99; NONCE_LEN],
            ciphertext: [0xAA; WRAPPED_KEY_CT_LEN],
        });
        h.vmk_epoch_current = 1;
        let bytes = h.encode().unwrap();
        let (decoded, _) = Header::decode(&bytes).unwrap();
        assert_eq!(decoded.wrapped_keys.len(), 2);
        assert!(decoded.wrapped_key(0).is_some());
        assert!(decoded.wrapped_key(1).is_some());
        assert!(decoded.wrapped_key(2).is_none());
    }
}
