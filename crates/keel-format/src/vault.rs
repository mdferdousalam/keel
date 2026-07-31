// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Whole-file assembly: encrypting, laying out, and verifying a vault.
//!
//! # File layout
//!
//! ```text
//! ┌─────────────┬──────────────────┬───────────────────┬────────┐
//! │   header    │     records      │  sealed manifest  │ footer │
//! │ (plaintext, │  (each blob      │  (nonce ‖ ct+tag) │  (48B) │
//! │authenticated)│  independently   │                   │        │
//! │             │   encrypted)     │                   │        │
//! └─────────────┴──────────────────┴───────────────────┴────────┘
//! ```
//!
//! ## Why records come before the manifest
//!
//! The obvious layout puts the manifest right after the header, so a reader can pick
//! up metadata without seeking. That layout does not work here, and the reason is
//! worth recording so nobody "fixes" it later.
//!
//! The manifest stores each record's absolute file offset, and `postcard`
//! varint-encodes integers — so a larger offset can occupy more bytes. That makes
//! the manifest's own length depend on the offsets, which depend on the manifest's
//! length. Circular. Resolving it would mean either fixed-width offsets (wasteful)
//! or iterating to a fixed point (fragile, and a bug that only appears at specific
//! vault sizes).
//!
//! Putting the records first removes the cycle entirely: the records section begins
//! immediately after the header, whose length depends only on which unlock factors
//! are configured. Nothing is lost, because the header names the manifest's offset,
//! so reading it is still one seek.
//!
//! # The footer is a corruption check, not an authentication check
//!
//! The footer holds the file length and an **unkeyed** BLAKE3 hash. It detects
//! truncation, a partial write, and bit rot. It does **not** prove the file was not
//! tampered with, because an attacker who edits the file can simply recompute the
//! hash. All authentication comes from the AEAD tags on the wrapped key, the
//! manifest, and each record. Anyone reviewing this file should be clear on that
//! division, since treating the footer as authentication would be a serious mistake.

use keel_crypto::{aead, Key256, Sealed, NONCE_LEN};
use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::header::{Header, FOOTER_MAGIC};
use crate::limits;
use crate::manifest::{EntryMeta, Id, Manifest};
use crate::record::RecordBody;

/// Size of the footer: file length, hash, magic.
pub const FOOTER_LEN: usize = 8 + 32 + 8;

/// Fixed overhead of a record blob before its ciphertext: id, epoch, nonce, length.
pub const RECORD_HEADER_LEN: usize = 16 + 4 + NONCE_LEN + 4;

/// One encrypted record as it appears on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBlob {
    /// Record identifier.
    pub record_id: Id,
    /// Master-key generation this record was encrypted under.
    pub key_epoch: u32,
    /// Nonce and ciphertext-with-tag.
    pub sealed: Sealed,
}

impl RecordBlob {
    /// Total on-disk size of this blob.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        RECORD_HEADER_LEN + self.sealed.ciphertext.len()
    }

    fn encode(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.record_id);
        w.u32(self.key_epoch);
        w.bytes(&self.sealed.nonce);
        w.len_u32(self.sealed.ciphertext.len(), "record ciphertext too long")?;
        w.bytes(&self.sealed.ciphertext);
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let record_id = r.array::<16>()?;
        let key_epoch = r.u32()?;
        let nonce = r.array::<NONCE_LEN>()?;
        let ct_len = r.checked_len_u32("record ciphertext", limits::MAX_RECORD_LEN)?;
        let ciphertext = r.take(ct_len)?.to_vec();
        if !r.is_empty() {
            return Err(Error::Corrupt("record blob has trailing bytes"));
        }
        Ok(Self {
            record_id,
            key_epoch,
            sealed: Sealed { nonce, ciphertext },
        })
    }

    /// Hash of the whole blob, as stored in the manifest.
    fn hash(&self) -> Result<[u8; 32]> {
        let mut w = Writer::with_capacity(self.encoded_len());
        self.encode(&mut w)?;
        Ok(*blake3::hash(w.as_slice()).as_bytes())
    }
}

/// Encrypt a record body under its derived per-record key.
///
/// The associated data binds the record to this vault, this record id, and this key
/// epoch, so a record cannot be moved between vaults or have its declared identity
/// changed.
pub fn seal_record(
    header: &Header,
    record_key: &Key256,
    record_id: &Id,
    key_epoch: u32,
    body: &RecordBody,
) -> Result<RecordBlob> {
    let padded = body.encode_padded()?;
    let aad = header.record_aad(record_id, key_epoch)?;
    let sealed = aead::seal(record_key, &aad, &padded)?;
    Ok(RecordBlob {
        record_id: *record_id,
        key_epoch,
        sealed,
    })
}

/// Decrypt and parse a record blob.
///
/// Authentication happens first: if the tag does not verify, the deserializer never
/// runs. See [`crate::record`] for why that ordering matters.
pub fn open_record(header: &Header, record_key: &Key256, blob: &RecordBlob) -> Result<RecordBody> {
    let aad = header.record_aad(&blob.record_id, blob.key_epoch)?;
    let plaintext = aead::open_sealed(record_key, &aad, &blob.sealed)?;
    RecordBody::decode_padded(&plaintext)
}

/// A complete vault, ready to be serialized.
#[derive(Debug)]
pub struct VaultImage {
    /// Header. Its offset and length fields are recomputed during [`encode`].
    pub header: Header,
    /// Metadata index. Entry offsets, lengths, and hashes are recomputed.
    pub manifest: Manifest,
    /// Encrypted records, in the order the manifest lists them.
    pub records: Vec<RecordBlob>,
}

/// Serialize a vault to bytes.
///
/// Recomputes the layout: record offsets, per-record hashes, section offsets, the
/// manifest ciphertext, and the footer. The caller supplies the manifest encryption
/// key, which `keel-core` derives from the vault master key.
///
/// The manifest must already contain one entry per record, matched by id; a mismatch
/// is an error rather than something silently patched up, because silently
/// reconciling a disagreement between the index and the data is how a vault loses an
/// entry.
pub fn encode(image: &mut VaultImage, index_key: &Key256) -> Result<Vec<u8>> {
    // Trashed entries keep their records: deletion is soft, so a restore has to find
    // the ciphertext still there. The record index therefore covers live *and* trashed
    // entries, and only a purge actually drops one.
    let indexed = image.manifest.entries.len() + image.manifest.trash.len();
    if indexed != image.records.len() {
        return Err(Error::Encode(
            "manifest entry count does not match the number of records",
        ));
    }

    // The header's length depends only on which unlock factors are present, not on
    // any offset, so one encode is enough to learn it.
    let header_len = image.header.encode()?.len() as u64;

    // Lay the records out immediately after the header, recording where each landed.
    let mut records_bytes = Writer::with_capacity(4096);
    let mut layout: Vec<(Id, u64, u32, [u8; 32])> = Vec::with_capacity(image.records.len());
    for blob in &image.records {
        let offset = header_len + records_bytes.len() as u64;
        let len = u32::try_from(blob.encoded_len())
            .map_err(|_| Error::Encode("record blob is too long"))?;
        layout.push((blob.record_id, offset, len, blob.hash()?));
        blob.encode(&mut records_bytes)?;
    }
    let records_bytes = records_bytes.into_vec();
    let records_len = records_bytes.len() as u64;
    if records_len > limits::MAX_RECORDS_LEN {
        return Err(Error::Encode("records section exceeds the maximum size"));
    }

    // Point each manifest entry at its record. Trashed entries are searched too, for
    // the reason given above.
    for (record_id, offset, len, hash) in layout {
        let entry = image
            .manifest
            .entries
            .iter_mut()
            .chain(image.manifest.trash.iter_mut().map(|t| &mut t.entry))
            .find(|e| e.record_id == record_id)
            .ok_or(Error::Encode("a record has no matching manifest entry"))?;
        entry.blob_offset = offset;
        entry.blob_len = len;
        entry.blob_hash = hash;
    }

    // Seal the manifest. Its associated data covers the binding hash and the write
    // counter, neither of which depends on the offsets just computed.
    let manifest_offset = header_len + records_len;
    let padded_manifest = image.manifest.encode_padded()?;
    let manifest_aad = image.header.manifest_aad()?;
    let sealed_manifest = aead::seal(index_key, &manifest_aad, &padded_manifest)?;
    let manifest_len = (NONCE_LEN + sealed_manifest.ciphertext.len()) as u64;

    // Now that every extent is known, write the real values into the header. This
    // re-encode is the same length as the first, because offsets are fixed-width.
    image.header.records_offset = header_len;
    image.header.records_len = records_len;
    image.header.manifest_offset = manifest_offset;
    image.header.manifest_len = manifest_len;
    let header_bytes = image.header.encode()?;
    if header_bytes.len() as u64 != header_len {
        return Err(Error::Encode(
            "header length changed after the layout was computed",
        ));
    }

    // `manifest_len` is bounded by MAX_MANIFEST_LEN, so this conversion cannot
    // realistically fail — but on a 32-bit target an unchecked cast would silently
    // truncate, and a truncated length here would produce a corrupt file.
    let manifest_len_usize =
        usize::try_from(manifest_len).map_err(|_| Error::Encode("manifest is too large"))?;
    let body_len = header_bytes.len() + records_bytes.len() + manifest_len_usize;
    let mut out = Writer::with_capacity(body_len + FOOTER_LEN);
    out.bytes(&header_bytes);
    out.bytes(&records_bytes);
    out.bytes(&sealed_manifest.nonce);
    out.bytes(&sealed_manifest.ciphertext);

    // Footer: total file length, then a hash over everything before the hash field.
    let total_len = (body_len + FOOTER_LEN) as u64;
    out.u64(total_len);
    let digest = blake3::hash(out.as_slice());
    out.bytes(digest.as_bytes());
    out.bytes(&FOOTER_MAGIC);

    let bytes = out.into_vec();
    debug_assert_eq!(bytes.len() as u64, total_len);
    Ok(bytes)
}

/// A vault file that has been structurally verified but not yet decrypted.
///
/// Splitting parsing from decryption lets a caller read the header — and so learn the
/// key-derivation parameters it needs to prompt for a passphrase — without holding
/// any key material.
#[derive(Debug)]
pub struct ParsedVault<'a> {
    /// The decoded header.
    pub header: Header,
    /// The raw records section.
    records: &'a [u8],
    /// The sealed manifest: nonce followed by ciphertext-and-tag.
    manifest_sealed: Sealed,
}

/// Structurally verify a vault file and decode its header.
///
/// Checks the footer magic, the declared file length, and the whole-file hash, then
/// decodes and validates the header and bounds-checks every section against the real
/// file length. No decryption and no key material involved.
pub fn parse(bytes: &[u8]) -> Result<ParsedVault<'_>> {
    if bytes.len() < FOOTER_LEN {
        return Err(Error::Truncated {
            expected: FOOTER_LEN,
            available: bytes.len(),
        });
    }

    // --- footer ---
    let footer_start = bytes.len() - FOOTER_LEN;
    let footer = bytes
        .get(footer_start..)
        .ok_or(Error::Corrupt("footer missing"))?;
    let mut fr = Reader::new(footer);
    let declared_len = fr.u64()?;
    let declared_hash = fr.array::<32>()?;
    if fr.array::<8>()? != FOOTER_MAGIC {
        // A file cut short will not end with these bytes, whatever its length field
        // claims, so this catches truncation even when the header looks plausible.
        return Err(Error::Corrupt("missing end-of-file marker"));
    }
    if declared_len != bytes.len() as u64 {
        return Err(Error::Truncated {
            expected: usize::try_from(declared_len).unwrap_or(usize::MAX),
            available: bytes.len(),
        });
    }
    let hashed_len = bytes.len() - 32 - 8;
    let hashed = bytes
        .get(..hashed_len)
        .ok_or(Error::Corrupt("footer overlaps body"))?;
    if blake3::hash(hashed).as_bytes() != &declared_hash {
        return Err(Error::ChecksumMismatch);
    }

    // --- header ---
    let (header, header_len) = Header::decode(bytes)?;

    // --- section bounds, against the real file length rather than the header's word ---
    let file_len = bytes.len() as u64;
    let section = |offset: u64, len: u64, what: &'static str| -> Result<core::ops::Range<usize>> {
        let end = offset.checked_add(len).ok_or(Error::Corrupt(what))?;
        if end > file_len {
            return Err(Error::Corrupt(what));
        }
        let start = usize::try_from(offset).map_err(|_| Error::Corrupt(what))?;
        let end = usize::try_from(end).map_err(|_| Error::Corrupt(what))?;
        Ok(start..end)
    };

    if header.records_offset != header_len as u64 {
        return Err(Error::Corrupt(
            "records section does not begin immediately after the header",
        ));
    }
    let records_range = section(
        header.records_offset,
        header.records_len,
        "records section extends past the end of the file",
    )?;
    let manifest_range = section(
        header.manifest_offset,
        header.manifest_len,
        "manifest extends past the end of the file",
    )?;
    if manifest_range.end > footer_start {
        return Err(Error::Corrupt("manifest overlaps the footer"));
    }
    if header.manifest_len < (NONCE_LEN + keel_crypto::TAG_LEN) as u64 {
        return Err(Error::Corrupt("manifest is too short to be valid"));
    }

    let records = bytes
        .get(records_range)
        .ok_or(Error::Corrupt("records section"))?;
    let manifest_bytes = bytes
        .get(manifest_range)
        .ok_or(Error::Corrupt("manifest"))?;
    let mut mr = Reader::new(manifest_bytes);
    let nonce = mr.array::<NONCE_LEN>()?;
    let ciphertext = mr.take(mr.remaining())?.to_vec();

    Ok(ParsedVault {
        header,
        records,
        manifest_sealed: Sealed { nonce, ciphertext },
    })
}

impl<'a> ParsedVault<'a> {
    /// Decrypt the manifest and verify every record against it.
    ///
    /// The verification step is what turns per-record authentication into whole-vault
    /// integrity: each record's blob hash must match what the (authenticated) manifest
    /// recorded, which detects records that were removed, duplicated, reordered, or
    /// copied in from a different version of the file.
    pub fn open_manifest(&self, index_key: &Key256) -> Result<Manifest> {
        let aad = self.header.manifest_aad()?;
        let plaintext: Zeroizing<Vec<u8>> =
            aead::open_sealed(index_key, &aad, &self.manifest_sealed)?;
        let manifest = Manifest::decode_padded(&plaintext)?;
        self.verify_records(&manifest)?;
        Ok(manifest)
    }

    /// Check that every manifest entry's record is present and unmodified.
    ///
    /// Covers trashed entries as well as live ones: a restore must not hand the user a
    /// record that was quietly swapped while it sat in the trash.
    fn verify_records(&self, manifest: &Manifest) -> Result<()> {
        let all = manifest
            .entries
            .iter()
            .chain(manifest.trash.iter().map(|t| &t.entry));
        for (index, entry) in all.enumerate() {
            let blob = self
                .blob_bytes(entry)
                .ok_or(Error::RecordMismatch { index })?;
            if blake3::hash(blob).as_bytes() != &entry.blob_hash {
                return Err(Error::RecordMismatch { index });
            }
        }
        Ok(())
    }

    /// Raw bytes of one entry's record blob, relative to the records section.
    fn blob_bytes(&self, entry: &EntryMeta) -> Option<&'a [u8]> {
        let start = entry.blob_offset.checked_sub(self.header.records_offset)?;
        let start = usize::try_from(start).ok()?;
        let end = start.checked_add(entry.blob_len as usize)?;
        self.records.get(start..end)
    }

    /// Read one entry's encrypted record without decrypting it.
    pub fn record_blob(&self, entry: &EntryMeta) -> Result<RecordBlob> {
        let bytes = self.blob_bytes(entry).ok_or(Error::Corrupt(
            "manifest entry points outside the records section",
        ))?;
        RecordBlob::decode(bytes)
    }

    /// Decrypt one entry's record.
    pub fn open_record(&self, entry: &EntryMeta, record_key: &Key256) -> Result<RecordBody> {
        let blob = self.record_blob(entry)?;
        if blob.record_id != entry.record_id || blob.key_epoch != entry.key_epoch {
            // The blob hash check in `verify_records` already covers this, but
            // checking again here means a caller who skipped that step is still safe.
            return Err(Error::Corrupt(
                "record blob disagrees with its manifest entry",
            ));
        }
        open_record(&self.header, record_key, &blob)
    }

    /// Every record blob in file order, for compaction and rotation.
    pub fn all_blobs(&self) -> Result<Vec<RecordBlob>> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        while cursor < self.records.len() {
            let rest = self
                .records
                .get(cursor..)
                .ok_or(Error::Corrupt("records section"))?;
            let mut r = Reader::new(rest);
            r.skip(16)?;
            r.u32()?;
            r.skip(NONCE_LEN)?;
            let ct_len = r.checked_len_u32("record ciphertext", limits::MAX_RECORD_LEN)?;
            let total = RECORD_HEADER_LEN
                .checked_add(ct_len)
                .ok_or(Error::Corrupt("record length overflows"))?;
            let blob_bytes = rest.get(..total).ok_or(Error::Truncated {
                expected: total,
                available: rest.len(),
            })?;
            out.push(RecordBlob::decode(blob_bytes)?);
            cursor = cursor
                .checked_add(total)
                .ok_or(Error::Corrupt("offset overflows"))?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{HeaderFlags, WrappedKey, WRAPPED_KEY_CT_LEN};
    use crate::manifest::EntryMeta;
    use keel_crypto::kdf::{Argon2Params, MIN_M_COST_KIB};
    use keel_crypto::{subkeys, SecretBytes, AEAD_ID_XCHACHA20POLY1305, KDF_ID_ARGON2ID_V13};

    const VAULT_UUID: [u8; 16] = [0xAB; 16];

    fn vmk() -> Key256 {
        SecretBytes::<32>::from_slice(&[0x42; 32]).unwrap()
    }

    fn header() -> Header {
        Header {
            format_version: crate::FORMAT_VERSION,
            flags: HeaderFlags::default(),
            vault_uuid: VAULT_UUID,
            created_at: 1_700_000_000,
            kdf_id: KDF_ID_ARGON2ID_V13,
            kdf_params: Argon2Params {
                m_cost_kib: MIN_M_COST_KIB,
                t_cost: 1,
                p_cost: 1,
            },
            kdf_salt: [0x11; keel_crypto::SALT_LEN],
            measured_kdf_ms: 1200,
            factors: crate::FactorSet::default(),
            aead_id: AEAD_ID_XCHACHA20POLY1305,
            vmk_epoch_current: 0,
            wrapped_keys: vec![WrappedKey {
                epoch: 0,
                nonce: [0x22; NONCE_LEN],
                ciphertext: [0x33; WRAPPED_KEY_CT_LEN],
            }],
            write_counter: 1,
            manifest_offset: 0,
            manifest_len: 0,
            records_offset: 0,
            records_len: 0,
        }
    }

    fn entry_meta(id: u8, title: &str) -> EntryMeta {
        EntryMeta {
            record_id: [id; 16],
            key_epoch: 0,
            blob_hash: [0; 32],
            blob_offset: 0,
            blob_len: 0,
            title: title.to_owned(),
            username: "ada@example.com".to_owned(),
            origins: vec!["https://example.com".to_owned()],
            tags: vec![],
            folder_id: None,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
            password_changed_at: 1_700_000_000,
            has_totp: false,
            favorite: false,
            notes_preview_len: 0,
        }
    }

    /// Build a vault with `n` entries whose passwords are `password-{i}`.
    fn build_vault(n: u8) -> (Vec<u8>, Key256) {
        let h = header();
        let v = vmk();
        let index_key = subkeys::index_key(&v, &VAULT_UUID).unwrap();

        let mut manifest = Manifest::new();
        let mut records = Vec::new();
        for i in 0..n {
            let id = [i + 1; 16];
            let body = RecordBody::new()
                .with_username(format!("user-{i}"))
                .with_password(format!("password-{i}"));
            let rk = subkeys::record_key(&v, &VAULT_UUID, &id, 0).unwrap();
            records.push(seal_record(&h, &rk, &id, 0, &body).unwrap());
            manifest
                .entries
                .push(entry_meta(i + 1, &format!("Site {i}")));
        }

        let mut image = VaultImage {
            header: h,
            manifest,
            records,
        };
        let bytes = encode(&mut image, &index_key).unwrap();
        (bytes, index_key)
    }

    #[test]
    fn round_trips_a_vault_with_records() {
        let (bytes, index_key) = build_vault(3);
        let parsed = parse(&bytes).unwrap();
        let manifest = parsed.open_manifest(&index_key).unwrap();
        assert_eq!(manifest.entries.len(), 3);

        let v = vmk();
        for (i, entry) in manifest.entries.iter().enumerate() {
            let rk =
                subkeys::record_key(&v, &VAULT_UUID, &entry.record_id, entry.key_epoch).unwrap();
            let body = parsed.open_record(entry, &rk).unwrap();
            assert_eq!(body.password, format!("password-{i}"));
            assert_eq!(body.username, format!("user-{i}"));
        }
    }

    #[test]
    fn round_trips_an_empty_vault() {
        let (bytes, index_key) = build_vault(0);
        let parsed = parse(&bytes).unwrap();
        let manifest = parsed.open_manifest(&index_key).unwrap();
        assert!(manifest.entries.is_empty());
    }

    #[test]
    fn records_begin_immediately_after_the_header() {
        let (bytes, _) = build_vault(2);
        let parsed = parse(&bytes).unwrap();
        let (_, header_len) = Header::decode(&bytes).unwrap();
        assert_eq!(parsed.header.records_offset, header_len as u64);
        assert_eq!(
            parsed.header.manifest_offset,
            parsed.header.records_offset + parsed.header.records_len
        );
    }

    #[test]
    fn declared_length_matches_the_file() {
        let (bytes, _) = build_vault(2);
        let declared =
            u64::from_le_bytes(bytes[bytes.len() - FOOTER_LEN..][..8].try_into().unwrap());
        assert_eq!(declared, bytes.len() as u64);
    }

    #[test]
    fn wrong_manifest_key_fails_authentication() {
        let (bytes, _) = build_vault(1);
        let parsed = parse(&bytes).unwrap();
        let wrong = SecretBytes::<32>::from_slice(&[0xFF; 32]).unwrap();
        assert!(parsed.open_manifest(&wrong).is_err());
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_panic() {
        let (bytes, _) = build_vault(2);
        for cut in 0..bytes.len() {
            assert!(
                parse(&bytes[..cut]).is_err(),
                "truncation to {cut} bytes was accepted"
            );
        }
    }

    #[test]
    fn flipping_any_single_byte_is_detected() {
        // The strongest property this format offers: no single-byte change to the
        // file can go unnoticed. Sampled rather than exhaustive to keep the suite
        // fast; the fuzz target covers the rest.
        let (bytes, index_key) = build_vault(2);
        let step = (bytes.len() / 97).max(1);
        for i in (0..bytes.len()).step_by(step) {
            let mut bad = bytes.clone();
            bad[i] ^= 0x01;
            let detected = match parse(&bad) {
                Err(_) => true,
                Ok(parsed) => parsed.open_manifest(&index_key).is_err(),
            };
            assert!(detected, "flipping byte {i} went undetected");
        }
    }

    #[test]
    fn corrupted_footer_hash_is_reported_as_a_checksum_failure() {
        let (mut bytes, _) = build_vault(1);
        let hash_start = bytes.len() - 40;
        bytes[hash_start] ^= 0xFF;
        assert_eq!(parse(&bytes).unwrap_err(), Error::ChecksumMismatch);
    }

    #[test]
    fn missing_end_marker_is_detected() {
        let (mut bytes, _) = build_vault(1);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        // The end marker is checked before the hash, so this reports the marker.
        assert!(matches!(parse(&bytes), Err(Error::Corrupt(_))));
    }

    #[test]
    fn a_deleted_record_is_detected_by_the_manifest_hash() {
        // Splice attack: rebuild the file with one record's bytes zeroed while
        // keeping the manifest intact, and fix up the footer so the corruption
        // check passes. Only the per-record hash catches this.
        let (bytes, index_key) = build_vault(3);
        let parsed = parse(&bytes).unwrap();
        let manifest = parsed.open_manifest(&index_key).unwrap();
        let victim = &manifest.entries[1];

        let mut tampered = bytes.clone();
        let start = victim.blob_offset as usize;
        let end = start + victim.blob_len as usize;
        for byte in &mut tampered[start..end] {
            *byte = 0;
        }
        // Recompute the footer so the unkeyed checksum still matches.
        let hashed_len = tampered.len() - 40;
        let digest = blake3::hash(&tampered[..hashed_len]);
        tampered[hashed_len..hashed_len + 32].copy_from_slice(digest.as_bytes());

        let reparsed = parse(&tampered).unwrap();
        assert_eq!(
            reparsed.open_manifest(&index_key).unwrap_err(),
            Error::RecordMismatch { index: 1 }
        );
    }

    #[test]
    fn swapping_two_records_is_detected() {
        // Each record's own AEAD tag still verifies after a swap, because the
        // associated data does not include position. The manifest's per-record hash
        // is what catches it.
        let (bytes, index_key) = build_vault(2);
        let parsed = parse(&bytes).unwrap();
        let manifest = parsed.open_manifest(&index_key).unwrap();
        let (a, b) = (&manifest.entries[0], &manifest.entries[1]);
        assert_eq!(a.blob_len, b.blob_len, "test needs equal-sized records");

        let mut tampered = bytes.clone();
        let a_start = a.blob_offset as usize;
        let b_start = b.blob_offset as usize;
        let len = a.blob_len as usize;
        let a_bytes = tampered[a_start..a_start + len].to_vec();
        let b_bytes = tampered[b_start..b_start + len].to_vec();
        tampered[a_start..a_start + len].copy_from_slice(&b_bytes);
        tampered[b_start..b_start + len].copy_from_slice(&a_bytes);

        let hashed_len = tampered.len() - 40;
        let digest = blake3::hash(&tampered[..hashed_len]);
        tampered[hashed_len..hashed_len + 32].copy_from_slice(digest.as_bytes());

        let reparsed = parse(&tampered).unwrap();
        assert!(matches!(
            reparsed.open_manifest(&index_key),
            Err(Error::RecordMismatch { .. })
        ));
    }

    #[test]
    fn a_record_cannot_be_decrypted_with_another_records_key() {
        let (bytes, index_key) = build_vault(2);
        let parsed = parse(&bytes).unwrap();
        let manifest = parsed.open_manifest(&index_key).unwrap();
        let v = vmk();
        let other_key =
            subkeys::record_key(&v, &VAULT_UUID, &manifest.entries[1].record_id, 0).unwrap();
        assert!(parsed
            .open_record(&manifest.entries[0], &other_key)
            .is_err());
    }

    #[test]
    fn a_record_from_another_vault_cannot_be_opened() {
        // The record associated data includes the vault uuid and the header binding
        // hash, so a blob lifted from a different vault fails even with the right
        // per-record key.
        let mut foreign_header = header();
        foreign_header.vault_uuid = [0xCD; 16];
        let v = vmk();
        let id = [1u8; 16];
        let rk = subkeys::record_key(&v, &[0xCD; 16], &id, 0).unwrap();
        let body = RecordBody::new().with_password("secret");
        let blob = seal_record(&foreign_header, &rk, &id, 0, &body).unwrap();

        let ours = header();
        let our_rk = subkeys::record_key(&v, &VAULT_UUID, &id, 0).unwrap();
        assert!(open_record(&ours, &our_rk, &blob).is_err());
    }

    #[test]
    fn all_blobs_walks_the_records_section() {
        let (bytes, _) = build_vault(4);
        let parsed = parse(&bytes).unwrap();
        let blobs = parsed.all_blobs().unwrap();
        assert_eq!(blobs.len(), 4);
        for (i, blob) in blobs.iter().enumerate() {
            assert_eq!(blob.record_id, [i as u8 + 1; 16]);
        }
    }

    #[test]
    fn encode_rejects_a_manifest_that_disagrees_with_the_records() {
        let h = header();
        let v = vmk();
        let index_key = subkeys::index_key(&v, &VAULT_UUID).unwrap();
        let id = [1u8; 16];
        let rk = subkeys::record_key(&v, &VAULT_UUID, &id, 0).unwrap();
        let blob = seal_record(&h, &rk, &id, 0, &RecordBody::new()).unwrap();

        // A record with no manifest entry: silently dropping it would lose data.
        let mut image = VaultImage {
            header: header(),
            manifest: Manifest::new(),
            records: vec![blob],
        };
        assert!(encode(&mut image, &index_key).is_err());
    }

    #[test]
    fn parsing_arbitrary_bytes_never_panics() {
        // Same property the fuzz target asserts, kept here so the normal test run
        // exercises it too.
        for len in [0usize, 1, 8, 47, 48, 49, 100, 1000] {
            for fill in [0x00u8, 0xFF, 0x41] {
                let _ = parse(&vec![fill; len]);
            }
        }
        // A valid-looking magic followed by noise.
        let mut buf = crate::MAGIC.to_vec();
        buf.extend_from_slice(&[0xFF; 200]);
        let _ = parse(&buf);
    }

    #[test]
    fn write_counter_change_invalidates_the_manifest() {
        // Rollback protection: an old manifest replayed under a new header must fail.
        let (bytes, index_key) = build_vault(1);
        let mut parsed = parse(&bytes).unwrap();
        parsed.header.write_counter += 1;
        assert!(parsed.open_manifest(&index_key).is_err());
    }
}
