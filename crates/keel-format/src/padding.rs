//! Length padding for encrypted sections.
//!
//! Ciphertext length is visible to anyone who can read the file, and an unpadded
//! record leaks its exact plaintext size. That is more informative than it sounds:
//! a 12-byte password record and a 400-byte record with notes and a TOTP seed are
//! distinguishable, and over successive saves an observer can watch individual
//! entries grow and shrink.
//!
//! Padding records to a 256-byte boundary and the manifest to 4 KiB reduces that to
//! a coarse bucket. The threat model states plainly that file size still reveals
//! roughly how many entries a vault holds; it no longer reveals anything about
//! *which* entries changed.
//!
//! # No padding oracle here
//!
//! In CBC-era protocols, padding was a notorious source of oracles: an attacker
//! submitted modified ciphertext and learned things from whether unpadding
//! succeeded. That cannot happen here because padding lives **inside** the
//! authenticated plaintext. [`unpad`] only ever runs on bytes whose Poly1305 tag has
//! already verified, so a malformed padding length means our own bug or genuine
//! corruption — never an attacker probing. That ordering is a security property, so
//! do not "optimise" it by unpadding before authenticating.

use crate::error::{Error, Result};

/// Block size for record bodies, in bytes.
pub const RECORD_BLOCK: usize = 256;

/// Block size for the manifest, in bytes.
///
/// Larger than the record block because the manifest is a single large blob whose
/// size otherwise tracks the entry count fairly precisely.
pub const MANIFEST_BLOCK: usize = 4096;

/// Bytes used by the trailing length field.
const LENGTH_SUFFIX: usize = 4;

/// Pad `plaintext` to a multiple of `block`, recording the original length.
///
/// Layout: `plaintext ‖ zero filler ‖ u32-le original length`. A trailing length
/// field is used rather than PKCS#7 byte-repetition because PKCS#7 cannot express a
/// 256-byte pad in a single byte, and because an explicit length makes [`unpad`]
/// a bounds check rather than a scan.
pub fn pad(plaintext: &[u8], block: usize) -> Result<Vec<u8>> {
    if block == 0 || !block.is_power_of_two() {
        return Err(Error::Encode("padding block size must be a power of two"));
    }
    let original_len =
        u32::try_from(plaintext.len()).map_err(|_| Error::Encode("plaintext too long to pad"))?;

    let minimum = plaintext
        .len()
        .checked_add(LENGTH_SUFFIX)
        .ok_or(Error::Encode("plaintext length overflows"))?;
    // Round up to the next multiple of `block`.
    let total = minimum
        .checked_next_multiple_of(block)
        .ok_or(Error::Encode("padded length overflows"))?;

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(plaintext);
    out.resize(total - LENGTH_SUFFIX, 0);
    out.extend_from_slice(&original_len.to_le_bytes());
    Ok(out)
}

/// Recover the original plaintext from a padded buffer.
///
/// Validates that the recorded length is consistent with the buffer: it must fit,
/// and the filler must be smaller than one block (otherwise a whole redundant block
/// was added, which our own encoder never does and which would suggest tampering
/// with a section that somehow still authenticated).
pub fn unpad(padded: &[u8], block: usize) -> Result<&[u8]> {
    if padded.len() < LENGTH_SUFFIX {
        return Err(Error::Malformed(
            "padded section is shorter than its length field",
        ));
    }
    if block == 0 || !padded.len().is_multiple_of(block) {
        return Err(Error::Malformed(
            "padded section is not a whole number of blocks",
        ));
    }

    let split = padded.len() - LENGTH_SUFFIX;
    let suffix = padded
        .get(split..)
        .ok_or(Error::Malformed("padded section is malformed"))?;
    let mut len_bytes = [0u8; LENGTH_SUFFIX];
    len_bytes.copy_from_slice(suffix);
    let original_len = u32::from_le_bytes(len_bytes) as usize;

    if original_len > split {
        return Err(Error::Malformed(
            "padding length exceeds the padded section",
        ));
    }
    // The filler must be less than a full block, or the encoder added a pointless
    // extra block and something is wrong.
    let filler = padded.len() - original_len - LENGTH_SUFFIX;
    if filler >= block {
        return Err(Error::Malformed(
            "padded section has an implausible amount of filler",
        ));
    }

    padded
        .get(..original_len)
        .ok_or(Error::Malformed("padded section is malformed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_length_is_always_a_whole_number_of_blocks() {
        for len in [0usize, 1, 5, 251, 252, 253, 255, 256, 257, 1000] {
            let data = vec![0xABu8; len];
            let padded = pad(&data, RECORD_BLOCK).unwrap();
            assert_eq!(
                padded.len() % RECORD_BLOCK,
                0,
                "length {len} padded to {} which is not block-aligned",
                padded.len()
            );
            assert!(padded.len() >= len + LENGTH_SUFFIX);
        }
    }

    #[test]
    fn round_trips_at_every_interesting_length() {
        for len in [0usize, 1, 100, 251, 252, 253, 255, 256, 257, 512, 4096] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let padded = pad(&data, RECORD_BLOCK).unwrap();
            assert_eq!(
                unpad(&padded, RECORD_BLOCK).unwrap(),
                &data[..],
                "length {len}"
            );
        }
    }

    #[test]
    fn lengths_within_a_block_become_indistinguishable() {
        // The point of the exercise: a short password and a slightly longer one must
        // produce the same ciphertext length.
        let a = pad(&[0u8; 20], RECORD_BLOCK).unwrap();
        let b = pad(&[0u8; 200], RECORD_BLOCK).unwrap();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), RECORD_BLOCK);
    }

    #[test]
    fn a_full_block_of_data_rolls_to_the_next_block() {
        // 252 bytes plus the 4-byte suffix exactly fills one block.
        assert_eq!(pad(&vec![0u8; 252], RECORD_BLOCK).unwrap().len(), 256);
        // 253 needs a second block.
        assert_eq!(pad(&vec![0u8; 253], RECORD_BLOCK).unwrap().len(), 512);
    }

    #[test]
    fn manifest_block_is_used_for_larger_sections() {
        let padded = pad(&vec![0u8; 5000], MANIFEST_BLOCK).unwrap();
        assert_eq!(padded.len(), 8192);
        assert_eq!(unpad(&padded, MANIFEST_BLOCK).unwrap().len(), 5000);
    }

    #[test]
    fn rejects_a_non_block_aligned_buffer() {
        let padded = pad(b"hello", RECORD_BLOCK).unwrap();
        assert!(unpad(&padded[..padded.len() - 1], RECORD_BLOCK).is_err());
    }

    #[test]
    fn rejects_a_length_field_larger_than_the_buffer() {
        let mut padded = pad(b"hello", RECORD_BLOCK).unwrap();
        let last = padded.len() - LENGTH_SUFFIX;
        padded[last..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            unpad(&padded, RECORD_BLOCK),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn rejects_implausible_filler() {
        // A length of 0 in a two-block buffer means 508 bytes of filler, which our
        // encoder would never produce.
        let mut padded = pad(&vec![0u8; 300], RECORD_BLOCK).unwrap();
        assert_eq!(padded.len(), 512);
        let last = padded.len() - LENGTH_SUFFIX;
        padded[last..].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            unpad(&padded, RECORD_BLOCK),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn rejects_a_buffer_too_short_to_hold_a_length() {
        assert!(unpad(&[1, 2], RECORD_BLOCK).is_err());
        assert!(unpad(&[], RECORD_BLOCK).is_err());
    }

    #[test]
    fn rejects_a_non_power_of_two_block() {
        assert!(pad(b"x", 100).is_err());
        assert!(pad(b"x", 0).is_err());
    }

    #[test]
    fn unpadding_arbitrary_bytes_never_panics() {
        // Fuzz-shaped check: unpad runs on authenticated plaintext, but it must still
        // fail cleanly rather than panic if that plaintext is somehow malformed.
        for len in 0..600usize {
            let buf: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
            let _ = unpad(&buf, RECORD_BLOCK);
        }
    }
}
