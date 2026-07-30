//! Vault lifecycle: create, open, edit, save, lock.
//!
//! This is where the cryptography, the file format, and the storage layer meet. It is
//! also the only place in the project that holds an unwrapped vault master key, which
//! is why the whole architecture funnels through one process that links this crate.
//!
//! # What is held in memory while unlocked
//!
//! | Held | Not held |
//! |---|---|
//! | Vault master key and derived subkeys | Any decrypted password |
//! | Decrypted metadata manifest | Any decrypted note or TOTP seed |
//! | Record blobs, still encrypted | |
//!
//! Individual secrets are decrypted on demand by [`UnlockedVault::reveal`] and dropped
//! immediately. There is no moment when every password in the vault is in plaintext in
//! memory. That is the most effective mitigation available against an attacker who has
//! code execution on an unlocked machine (T3 in the threat model), and it is far more
//! valuable than any amount of `mlock`, because `RLIMIT_MEMLOCK` cannot cover a
//! multi-megabyte manifest anyway.
//!
//! Keeping record blobs in memory *encrypted* is what makes saving cheap: an unchanged
//! record is copied to the new file verbatim, never re-encrypted.

use std::time::{SystemTime, UNIX_EPOCH};

use keel_crypto::kdf::{Argon2Params, KdfTier};
use keel_crypto::{aead, subkeys, Factors, Key256, SecretBytes};
use keel_format::header::{Fido2Factor, WrappedKey, YubikeyFactor};
use keel_format::manifest::{EntryMeta, Id, Manifest, VaultSettings};
use keel_format::vault::{self as fmt_vault, RecordBlob, VaultImage};
use keel_format::{FactorSet, Header, HeaderFlags, RecordBody, FORMAT_VERSION};
use keel_store::{
    atomic, check_permissions, detect_cloud_sync, CloudProvider, Fingerprint, LastSeen,
    PermissionStatus, RollbackVerdict, VaultPaths, WriteMode,
};

use crate::error::{Error, Result};

/// Domain string for the wrapped-key associated data is owned by `keel-format`; this
/// crate only needs the epoch bookkeeping.
const FIRST_EPOCH: u32 = 0;

/// Current Unix time in seconds.
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::ClockBeforeEpoch)
}

/// The unlock factors a user supplies, owned rather than borrowed.
///
/// Owned so a caller can read a passphrase from a socket or a terminal, hand it over,
/// and let this type wipe it — rather than juggling lifetimes around a secret.
///
/// Deliberately has no `Default`. An accidentally-empty set of unlock factors is
/// exactly the kind of value that should require the programmer to say so out loud.
pub struct UnlockFactors {
    /// The master passphrase.
    pub passphrase: keel_crypto::SecretString,
    /// Raw keyfile contents, if a keyfile is in use.
    pub keyfile: Option<Vec<u8>>,
    /// Response from a hardware factor.
    pub hardware_response: Option<Vec<u8>>,
}

impl core::fmt::Debug for UnlockFactors {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockFactors")
            .field("passphrase", &"<redacted>")
            .field("keyfile", &self.keyfile.is_some())
            .field("hardware", &self.hardware_response.is_some())
            .finish()
    }
}

impl UnlockFactors {
    /// Build from a passphrase alone.
    #[must_use]
    pub fn passphrase(passphrase: keel_crypto::SecretString) -> Self {
        Self {
            passphrase,
            keyfile: None,
            hardware_response: None,
        }
    }

    /// Add a keyfile.
    #[must_use]
    pub fn with_keyfile(mut self, contents: Vec<u8>) -> Self {
        self.keyfile = Some(contents);
        self
    }

    /// Add a hardware-factor response.
    #[must_use]
    pub fn with_hardware_response(mut self, response: Vec<u8>) -> Self {
        self.hardware_response = Some(response);
        self
    }

    /// Derive the key-encryption key for a given header.
    fn derive_kek(&self, header: &Header) -> Result<Key256> {
        let keyfile_hash = self.keyfile.as_deref().map(keel_crypto::hash_keyfile);
        let factors = Factors {
            passphrase: self.passphrase.expose_bytes(),
            keyfile_hash: keyfile_hash.as_ref(),
            hardware_response: self.hardware_response.as_deref(),
        };
        Ok(keel_crypto::derive_kek_from_factors(
            &header.vault_uuid,
            &factors,
            &header.kdf_salt,
            header.kdf_params,
        )?)
    }

    /// The factor set to record in a new vault's header.
    fn factor_set(&self) -> FactorSet {
        FactorSet {
            keyfile: self.keyfile.as_deref().map(keel_crypto::hash_keyfile),
            // Hardware factors carry challenge material that the caller must supply
            // explicitly at enrolment; a bare response is not enough to record one.
            yubikey: None,
            fido2: None,
        }
    }
}

impl Drop for UnlockFactors {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(kf) = &mut self.keyfile {
            kf.zeroize();
        }
        if let Some(hw) = &mut self.hardware_response {
            hw.zeroize();
        }
    }
}

/// Non-secret metadata for a new or edited entry.
///
/// Deliberately holds **no** secret fields. Secrets travel in a
/// [`RecordBody`], which zeroizes itself; keeping the two apart means a metadata
/// struct can be logged or debugged without a redaction review.
#[derive(Debug, Clone, Default)]
pub struct EntryDraft {
    /// Display name.
    pub title: String,
    /// Username, duplicated into the manifest for search and autofill.
    pub username: String,
    /// Origins this entry may be filled into.
    pub origins: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Containing folder.
    pub folder_id: Option<Id>,
    /// Whether the user marked it a favourite.
    pub favorite: bool,
}

/// What was noticed while opening a vault.
///
/// Returned rather than logged, so the caller decides how prominently to show each
/// item. Several of these need a modal, not a log line.
#[derive(Debug, Clone)]
pub struct OpenReport {
    /// Rollback comparison against this device's memory of the vault.
    pub rollback: RollbackVerdict,
    /// Cloud service syncing the vault directory, if any.
    pub cloud_sync: Option<CloudProvider>,
    /// Whether the vault file is readable by others.
    pub permissions: PermissionStatus,
    /// True if the vault's KDF parameters are weaker than the current default.
    pub kdf_below_recommended: bool,
    /// Entries whose records failed their integrity check.
    ///
    /// A damaged record is reported rather than made fatal: losing access to one
    /// entry is bad, losing access to every entry because of it would be worse.
    pub damaged_entries: Vec<Id>,
}

impl OpenReport {
    /// True if the user must acknowledge something before proceeding.
    #[must_use]
    pub fn requires_attention(&self) -> bool {
        self.rollback.requires_confirmation()
            || !self.damaged_entries.is_empty()
            || matches!(self.permissions, PermissionStatus::TooOpen { .. })
    }
}

/// Options for opening a vault.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOptions {
    /// Memory available on this host, if known.
    ///
    /// Supplied by the caller because `keel-crypto` performs no I/O and cannot
    /// inspect the machine. `None` means "unknown", which never blocks an unlock — a
    /// vault the user cannot open is worse than one that swaps while opening.
    pub available_ram_bytes: Option<u64>,
    /// Proceed despite a rollback warning.
    ///
    /// The caller sets this only after the user has explicitly confirmed. It exists
    /// so that "I restored a backup" is a deliberate act rather than a dialog people
    /// learn to dismiss.
    pub accept_rollback: bool,
}

/// An open, unlocked vault.
pub struct UnlockedVault {
    paths: VaultPaths,
    header: Header,
    manifest: Manifest,
    vmk: Key256,
    index_key: Key256,
    blobs: Vec<RecordBlob>,
    fingerprint: Option<Fingerprint>,
}

impl core::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("path", &self.paths.vault)
            .field("entries", &self.manifest.entries.len())
            .field("write_counter", &self.header.write_counter)
            .field("vmk", &"<redacted>")
            .finish()
    }
}

impl UnlockedVault {
    // -----------------------------------------------------------------------
    // Creation
    // -----------------------------------------------------------------------

    /// Create a new vault and write it to disk.
    ///
    /// Fails if a vault already exists at that path. Overwriting one would be
    /// unrecoverable, so it is never done implicitly.
    pub fn create(
        paths: VaultPaths,
        factors: &UnlockFactors,
        params: Argon2Params,
        measured_kdf_ms: u32,
    ) -> Result<Self> {
        params.validate()?;
        let created_at = now()?;

        let mut vault_uuid = [0u8; 16];
        keel_crypto::fill_random(&mut vault_uuid)?;
        let mut kdf_salt = [0u8; keel_crypto::SALT_LEN];
        keel_crypto::fill_random(&mut kdf_salt)?;

        // A fresh random master key, wrapped under a key derived from the factors.
        // Every record key descends from this, so rotating the passphrase later
        // re-wraps this one value instead of touching a single record.
        let vmk = SecretBytes::<32>::random()?;

        let mut header = Header {
            format_version: FORMAT_VERSION,
            flags: HeaderFlags::default(),
            vault_uuid,
            created_at,
            kdf_id: keel_crypto::KDF_ID_ARGON2ID_V13,
            kdf_params: params,
            kdf_salt,
            measured_kdf_ms,
            factors: factors.factor_set(),
            aead_id: keel_crypto::AEAD_ID_XCHACHA20POLY1305,
            vmk_epoch_current: FIRST_EPOCH,
            // Placeholder, replaced immediately below once the KEK exists. The
            // header's binding hash covers the wrapped-key *count*, so the count
            // must be right before the key is sealed.
            wrapped_keys: vec![WrappedKey {
                epoch: FIRST_EPOCH,
                nonce: [0; keel_crypto::NONCE_LEN],
                ciphertext: [0; keel_format::header::WRAPPED_KEY_CT_LEN],
            }],
            write_counter: 1,
            records_offset: 0,
            records_len: 0,
            manifest_offset: 0,
            manifest_len: 0,
        };

        let kek = factors.derive_kek(&header)?;
        let aad = header.wrap_aad(FIRST_EPOCH)?;
        let sealed = aead::seal(&kek, &aad, vmk.expose())?;
        header.wrapped_keys = vec![WrappedKey::from_sealed(FIRST_EPOCH, &sealed)?];

        let index_key = subkeys::index_key(&vmk, &vault_uuid)?;
        let mut vault = Self {
            paths,
            header,
            manifest: Manifest::new(),
            vmk,
            index_key,
            blobs: Vec::new(),
            fingerprint: None,
        };
        vault.write(WriteMode::Create)?;
        Ok(vault)
    }

    // -----------------------------------------------------------------------
    // Opening
    // -----------------------------------------------------------------------

    /// Open and unlock an existing vault.
    pub fn open(
        paths: VaultPaths,
        factors: &UnlockFactors,
        options: OpenOptions,
    ) -> Result<(Self, OpenReport)> {
        let (bytes, fingerprint) = atomic::read_vault(&paths)?;
        let parsed = fmt_vault::parse(&bytes)?;
        let header = parsed.header.clone();

        // Cost parameters come from an untrusted file. They were already range-checked
        // during parsing; this additionally refuses parameters this machine cannot
        // satisfy, so the failure is a clear message rather than an OOM kill.
        if let Some(available) = options.available_ram_bytes {
            header
                .kdf_params
                .validate_for_host(available)
                .map_err(|e| Error::HostCapability(e.to_string()))?;
        }

        // Rollback check happens *before* key derivation. A user being rolled back
        // should be told before spending two seconds on Argon2, and before any
        // decision that depends on the file's contents.
        let last_seen = LastSeen::load(&paths.state());
        let footer_hash = fingerprint.hash;
        let rollback = keel_store::state::check(last_seen.as_ref(), &header, footer_hash);
        if rollback.requires_confirmation() && !options.accept_rollback {
            return Err(Error::Denied(rollback.message()));
        }

        let kek = factors.derive_kek(&header)?;
        let wrapped = header
            .wrapped_key(header.vmk_epoch_current)
            .ok_or(Error::Unlock)?;
        let aad = header.wrap_aad(header.vmk_epoch_current)?;
        // Any failure here is reported as a generic unlock failure: a wrong
        // passphrase, a wrong keyfile, and a tampered header must be
        // indistinguishable.
        let unwrapped = aead::open(&kek, &wrapped.nonce, &aad, &wrapped.ciphertext)
            .map_err(|_| Error::Unlock)?;
        let vmk = SecretBytes::<32>::from_slice(&unwrapped).map_err(|_| Error::Unlock)?;

        let index_key = subkeys::index_key(&vmk, &header.vault_uuid)?;
        let manifest = parsed.open_manifest(&index_key)?;
        let blobs = parsed.all_blobs()?;

        // Record integrity is checked inside `open_manifest`, which fails the whole
        // load. Re-derive which entries are unreadable so the caller can show them
        // individually rather than presenting an all-or-nothing failure.
        let damaged_entries = manifest
            .entries
            .iter()
            .filter(|entry| parsed.record_blob(entry).is_err())
            .map(|entry| entry.record_id)
            .collect();

        let report = OpenReport {
            rollback,
            cloud_sync: detect_cloud_sync(&paths.vault),
            permissions: check_permissions(&paths.vault)?,
            kdf_below_recommended: header.kdf_params.is_below_recommended(),
            damaged_entries,
        };

        let vault = Self {
            paths,
            header,
            manifest,
            vmk,
            index_key,
            blobs,
            fingerprint: Some(fingerprint),
        };
        vault.record_last_seen()?;
        Ok((vault, report))
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Entry metadata for every live entry.
    ///
    /// Metadata only. There is no method that returns every secret, by design — see
    /// the anti-enumeration rules in the threat model.
    #[must_use]
    pub fn entries(&self) -> &[EntryMeta] {
        &self.manifest.entries
    }

    /// Vault settings.
    #[must_use]
    pub fn settings(&self) -> &VaultSettings {
        &self.manifest.settings
    }

    /// Mutable vault settings.
    pub fn settings_mut(&mut self) -> &mut VaultSettings {
        &mut self.manifest.settings
    }

    /// The vault's unique identifier.
    #[must_use]
    pub fn uuid(&self) -> [u8; 16] {
        self.header.vault_uuid
    }

    /// Current save counter.
    #[must_use]
    pub fn write_counter(&self) -> u64 {
        self.header.write_counter
    }

    /// Look up one entry's metadata.
    pub fn entry(&self, id: &Id) -> Result<&EntryMeta> {
        self.manifest.entry(id).ok_or(Error::NoSuchEntry)
    }

    /// Search entry metadata.
    ///
    /// Case-insensitive substring match over title, username, and origins. Runs
    /// against the in-memory manifest, so it needs no record decryption and touches
    /// no secrets.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&EntryMeta> {
        let needle = query.to_lowercase();
        self.manifest
            .entries
            .iter()
            .filter(|e| {
                e.title.to_lowercase().contains(&needle)
                    || e.username.to_lowercase().contains(&needle)
                    || e.origins.iter().any(|o| o.to_lowercase().contains(&needle))
            })
            .collect()
    }

    /// Derive the key for one record.
    fn record_key(&self, id: &Id, epoch: u32) -> Result<Key256> {
        Ok(subkeys::record_key(
            &self.vmk,
            &self.header.vault_uuid,
            id,
            epoch,
        )?)
    }

    /// Decrypt one entry's secrets.
    ///
    /// The only way to obtain a plaintext secret. The returned [`RecordBody`] wipes
    /// itself when dropped, so callers should hold it as briefly as possible and must
    /// not clone its fields into longer-lived storage.
    pub fn reveal(&self, id: &Id) -> Result<RecordBody> {
        let entry = self.entry(id)?;
        let blob = self
            .blobs
            .iter()
            .find(|b| b.record_id == *id)
            .ok_or(Error::NoSuchEntry)?;
        let key = self.record_key(id, entry.key_epoch)?;
        Ok(fmt_vault::open_record(&self.header, &key, blob)?)
    }

    // -----------------------------------------------------------------------
    // Mutation
    // -----------------------------------------------------------------------

    /// Add an entry. Returns its new identifier.
    ///
    /// Does not save; the caller decides when to write, so a batch of changes (an
    /// import, say) becomes one atomic save rather than many.
    pub fn add_entry(&mut self, draft: EntryDraft, body: &RecordBody) -> Result<Id> {
        let mut record_id = [0u8; 16];
        keel_crypto::fill_random(&mut record_id)?;
        let timestamp = now()?;
        let epoch = self.header.vmk_epoch_current;

        let key = self.record_key(&record_id, epoch)?;
        let blob = fmt_vault::seal_record(&self.header, &key, &record_id, epoch, body)?;

        self.manifest.entries.push(EntryMeta {
            record_id,
            key_epoch: epoch,
            // Filled in by the encoder, which computes the real layout.
            blob_hash: [0; 32],
            blob_offset: 0,
            blob_len: 0,
            title: draft.title,
            username: draft.username,
            origins: draft.origins,
            tags: draft.tags,
            folder_id: draft.folder_id,
            created_at: timestamp,
            updated_at: timestamp,
            password_changed_at: timestamp,
            has_totp: body.totp_secret.is_some(),
            favorite: draft.favorite,
            notes_preview_len: u32::try_from(body.notes.len()).unwrap_or(u32::MAX),
        });
        self.blobs.push(blob);
        self.manifest.validate()?;
        Ok(record_id)
    }

    /// Replace an entry's secrets, keeping its metadata and identifier.
    pub fn update_secrets(&mut self, id: &Id, body: &RecordBody) -> Result<()> {
        let epoch = self.header.vmk_epoch_current;
        let key = self.record_key(id, epoch)?;
        let blob = fmt_vault::seal_record(&self.header, &key, id, epoch, body)?;
        let timestamp = now()?;

        let entry = self
            .manifest
            .entries
            .iter_mut()
            .find(|e| e.record_id == *id)
            .ok_or(Error::NoSuchEntry)?;
        entry.key_epoch = epoch;
        entry.updated_at = timestamp;
        entry.has_totp = body.totp_secret.is_some();
        entry.notes_preview_len = u32::try_from(body.notes.len()).unwrap_or(u32::MAX);

        let slot = self
            .blobs
            .iter_mut()
            .find(|b| b.record_id == *id)
            .ok_or(Error::NoSuchEntry)?;
        *slot = blob;
        Ok(())
    }

    /// Update an entry's metadata.
    pub fn update_metadata(&mut self, id: &Id, draft: EntryDraft) -> Result<()> {
        let timestamp = now()?;
        let entry = self
            .manifest
            .entries
            .iter_mut()
            .find(|e| e.record_id == *id)
            .ok_or(Error::NoSuchEntry)?;
        entry.title = draft.title;
        entry.username = draft.username;
        entry.origins = draft.origins;
        entry.tags = draft.tags;
        entry.folder_id = draft.folder_id;
        entry.favorite = draft.favorite;
        entry.updated_at = timestamp;
        self.manifest.validate()?;
        Ok(())
    }

    /// Move an entry to the trash.
    ///
    /// Soft delete: the record stays in the file until the purge deadline. An
    /// accidental permanent delete in a password manager can lock someone out of an
    /// account for good, so there is no hard-delete path from ordinary use.
    pub fn trash_entry(&mut self, id: &Id, retain_days: u64) -> Result<()> {
        let timestamp = now()?;
        let position = self
            .manifest
            .entries
            .iter()
            .position(|e| e.record_id == *id)
            .ok_or(Error::NoSuchEntry)?;
        let entry = self.manifest.entries.remove(position);
        self.manifest.trash.push(keel_format::TrashedEntry {
            entry,
            trashed_at: timestamp,
            purge_after: timestamp.saturating_add(retain_days.saturating_mul(86_400)),
        });
        Ok(())
    }

    /// Restore a trashed entry.
    pub fn restore_entry(&mut self, id: &Id) -> Result<()> {
        let position = self
            .manifest
            .trash
            .iter()
            .position(|t| t.entry.record_id == *id)
            .ok_or(Error::NoSuchEntry)?;
        let trashed = self.manifest.trash.remove(position);
        self.manifest.entries.push(trashed.entry);
        self.manifest.validate()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Passphrase change
    // -----------------------------------------------------------------------

    /// Change the master passphrase.
    ///
    /// Re-wraps the **same** master key under a key derived from the new factors, with
    /// a fresh salt and possibly stronger cost parameters. Not one record is
    /// re-encrypted, so this is a sub-second operation regardless of vault size. That
    /// is the entire reason the design separates the key-encryption key from the vault
    /// master key.
    pub fn change_passphrase(
        &mut self,
        new_factors: &UnlockFactors,
        params: Argon2Params,
        measured_kdf_ms: u32,
    ) -> Result<()> {
        params.validate()?;
        let mut salt = [0u8; keel_crypto::SALT_LEN];
        keel_crypto::fill_random(&mut salt)?;

        // Build the prospective header first: the binding hash covers the salt,
        // parameters, and factor flags, so the wrap must be computed against the
        // header as it will be written, not as it is now.
        let mut next = self.header.clone();
        next.kdf_salt = salt;
        next.kdf_params = params;
        next.measured_kdf_ms = measured_kdf_ms;
        next.factors = new_factors.factor_set();

        let kek = new_factors.derive_kek(&next)?;
        let aad = next.wrap_aad(next.vmk_epoch_current)?;
        let sealed = aead::seal(&kek, &aad, self.vmk.expose())?;
        next.wrapped_keys = vec![WrappedKey::from_sealed(next.vmk_epoch_current, &sealed)?];

        self.header = next;
        Ok(())
    }

    /// Record a hardware factor in the header.
    ///
    /// Separate from [`Self::change_passphrase`] because arming a hardware factor has
    /// a consequence that needs its own confirmation step in the UI: without a second
    /// enrolled authenticator or a printed recovery kit, losing the key makes every
    /// existing backup unopenable.
    pub fn set_hardware_factor(
        &mut self,
        yubikey: Option<YubikeyFactor>,
        fido2: Option<Fido2Factor>,
        factors: &UnlockFactors,
    ) -> Result<()> {
        let mut next = self.header.clone();
        next.factors.yubikey = yubikey;
        next.factors.fido2 = fido2;

        let kek = factors.derive_kek(&next)?;
        let aad = next.wrap_aad(next.vmk_epoch_current)?;
        let sealed = aead::seal(&kek, &aad, self.vmk.expose())?;
        next.wrapped_keys = vec![WrappedKey::from_sealed(next.vmk_epoch_current, &sealed)?];

        self.header = next;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Saving
    // -----------------------------------------------------------------------

    /// Write the vault to disk.
    ///
    /// Increments the save counter, which is what makes rollback detectable, and
    /// records the new counter for the next open.
    pub fn save(&mut self) -> Result<()> {
        self.write(WriteMode::Replace)
    }

    fn write(&mut self, mode: WriteMode) -> Result<()> {
        self.manifest.validate()?;

        // Advance the counter *before* encoding, so the value inside the file is the
        // value this save is identified by. Incrementing afterwards would record a
        // "last seen" counter one higher than the file actually contains, and every
        // subsequent open would then look like a rollback — which is exactly the bug
        // the lifecycle tests caught.
        //
        // A new vault keeps the counter it was created with; only replacements
        // advance it.
        if mode == WriteMode::Replace {
            self.header.write_counter = self.header.write_counter.saturating_add(1);
        }

        // Take the blobs out so `encode` can own them, then put them back. `encode`
        // rewrites the manifest's offsets and hashes to match the real layout.
        let blobs = std::mem::take(&mut self.blobs);
        let mut image = VaultImage {
            header: self.header.clone(),
            manifest: self.manifest.clone(),
            records: blobs,
        };
        let bytes = match fmt_vault::encode(&mut image, &self.index_key) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Restore state on failure so a rejected save does not leave the
                // in-memory vault missing its records.
                self.blobs = image.records;
                return Err(e.into());
            }
        };
        self.header = image.header;
        self.manifest = image.manifest;
        self.blobs = image.records;

        let fingerprint = atomic::write_vault(&self.paths, &bytes, mode, self.fingerprint)?;
        self.fingerprint = Some(fingerprint);
        // Record the counter that is now on disk. A failed write leaves the in-memory
        // counter ahead of the file, which only means the next successful save skips a
        // value — harmless, since rollback detection needs monotonicity, not density.
        self.record_last_seen()?;
        Ok(())
    }

    /// Persist the rollback-detection state for this vault version.
    fn record_last_seen(&self) -> Result<()> {
        let Some(fingerprint) = self.fingerprint else {
            return Ok(());
        };
        let seen = LastSeen::from_header(&self.header, fingerprint.hash, now()?)?;
        // A failure here weakens rollback detection but must not fail the save: the
        // user's data is already safely written by this point.
        let _ = seen.save(&self.paths.state());
        Ok(())
    }

    /// Lock the vault, zeroizing all key material.
    ///
    /// Consumes `self` so there is no way to keep using a locked vault. The keys are
    /// wiped by their own `Drop`; this method exists to make locking an explicit,
    /// grep-able act rather than something that happens when a value goes out of
    /// scope.
    pub fn lock(self) {
        drop(self);
    }
}

/// Calibrate KDF parameters for this host.
///
/// Convenience wrapper that supplies the core count. Memory is left unknown, which
/// makes calibration use its own ceiling rather than a fraction of installed RAM.
pub fn calibrate(budget: std::time::Duration) -> Result<keel_crypto::Calibration> {
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4);
    Ok(keel_crypto::calibrate(
        budget,
        0,
        u32::try_from(cores).unwrap_or(4),
    )?)
}

/// Cheap parameters for tests and for the `--tier` flag's fastest option.
#[must_use]
pub fn tier_params(tier: KdfTier) -> Argon2Params {
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4);
    tier.params(u32::try_from(cores).unwrap_or(4))
}
