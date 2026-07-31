// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Bounds-checked primitives for reading and writing the binary format.
//!
//! [`Reader`] is the single most safety-relevant type in this crate. Every read
//! goes through [`Reader::take`], which checks the remaining length and returns an
//! error rather than panicking. Because the whole format decoder is built on it,
//! "the parser never panics on malformed input" follows from one function being
//! correct instead of from every call site remembering to check.
//!
//! This is also why the crate lints against raw indexing: `buf[offset]` on
//! attacker-controlled `offset` is exactly the bug this type exists to prevent.

use crate::error::{Error, Result};

/// A cursor over a byte slice that cannot read past the end.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current offset from the start of the buffer.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// True if the cursor is at the end.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Consume exactly `n` bytes.
    ///
    /// The one place this crate turns an offset into a slice. Returns
    /// [`Error::Truncated`] rather than panicking, and uses `get` rather than
    /// indexing so a mistake here is a compile-time-visible `Option`, not a
    /// runtime panic.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Corrupt("length overflow"))?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated {
            expected: n,
            available: self.remaining(),
        })?;
        self.pos = end;
        Ok(slice)
    }

    /// Consume a fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    /// Consume one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// Consume a little-endian `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    /// Consume a little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Consume a little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Consume a length-checked `usize` from a little-endian `u32`.
    ///
    /// `limit` is enforced here, before the caller can use the value to size an
    /// allocation. Taking the limit as an argument means every variable-length read
    /// in the format is forced to state its bound at the point of reading.
    pub fn checked_len_u32(&mut self, what: &'static str, limit: usize) -> Result<usize> {
        let raw = self.u32()?;
        let value = usize::try_from(raw).map_err(|_| Error::TooLarge {
            what,
            found: u64::from(raw),
            limit: limit as u64,
        })?;
        if value > limit {
            return Err(Error::TooLarge {
                what,
                found: value as u64,
                limit: limit as u64,
            });
        }
        Ok(value)
    }

    /// Borrow the bytes consumed so far.
    ///
    /// Used to hash the header prefix that binds the key-derivation parameters,
    /// without re-encoding it.
    #[must_use]
    pub fn consumed(&self) -> &'a [u8] {
        self.buf.get(..self.pos).unwrap_or(&[])
    }

    /// Skip `n` bytes, checking they exist.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    /// Require that all remaining bytes are zero.
    ///
    /// Applied to the header's reserved field. A future version may put meaning
    /// there, and refusing to silently ignore non-zero reserved bytes is what makes
    /// that extension detectable rather than a silent misparse.
    pub fn expect_zeroes(&mut self, n: usize, what: &'static str) -> Result<()> {
        let bytes = self.take(n)?;
        if bytes.iter().any(|&b| b != 0) {
            return Err(Error::Corrupt(what));
        }
        Ok(())
    }
}

/// An append-only byte buffer with little-endian helpers.
///
/// Deliberately mirrors [`Reader`] method-for-method so an encoder and its decoder
/// can be read side by side and checked against each other — the most common source
/// of format bugs is the two drifting apart.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Create an empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create a writer with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True if nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Append raw bytes.
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Append one byte.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Append a little-endian `u16`.
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian `u32`.
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian `u64`.
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append `n` zero bytes.
    pub fn zeroes(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }

    /// Append a length as a `u32`, failing if it does not fit.
    pub fn len_u32(&mut self, value: usize, what: &'static str) -> Result<()> {
        let v = u32::try_from(value).map_err(|_| Error::Encode(what))?;
        self.u32(v);
        Ok(())
    }

    /// Overwrite a previously written `u32`, for a length not known up front.
    ///
    /// Used for the header's own length: it is written as a placeholder and patched
    /// once the factor section has been encoded.
    pub fn patch_u32(&mut self, offset: usize, value: u32) -> Result<()> {
        let slot = self
            .buf
            .get_mut(offset..offset + 4)
            .ok_or(Error::Encode("patch offset out of range"))?;
        slot.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    /// Borrow the written bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Take ownership of the written bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_scalars() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert_eq!(r.u16().unwrap(), 0x0403);
        assert_eq!(r.u32().unwrap(), 0x0807_0605);
        assert!(r.is_empty());
    }

    #[test]
    fn round_trips_through_the_writer() {
        let mut w = Writer::new();
        w.u8(0xAB);
        w.u16(0x1234);
        w.u32(0xDEAD_BEEF);
        w.u64(0x0123_4567_89AB_CDEF);
        w.bytes(b"keel");

        let buf = w.into_vec();
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 0xAB);
        assert_eq!(r.u16().unwrap(), 0x1234);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), 0x0123_4567_89AB_CDEF);
        assert_eq!(r.take(4).unwrap(), b"keel");
        assert!(r.is_empty());
    }

    #[test]
    fn reading_past_the_end_errors_rather_than_panicking() {
        // The core safety property of this module.
        let bytes = [1u8, 2, 3];
        let mut r = Reader::new(&bytes);
        assert!(matches!(r.take(4), Err(Error::Truncated { .. })));
        // The cursor must not advance on failure, so a caller that retries or
        // reports position sees the truth.
        assert_eq!(r.position(), 0);
        assert!(matches!(r.u32(), Err(Error::Truncated { .. })));
    }

    #[test]
    fn empty_buffer_reads_fail_cleanly() {
        let mut r = Reader::new(&[]);
        assert!(r.u8().is_err());
        assert!(r.u64().is_err());
        assert!(r.array::<16>().is_err());
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn length_overflow_is_caught() {
        let bytes = [0u8; 8];
        let mut r = Reader::new(&bytes);
        r.skip(4).unwrap();
        assert!(matches!(r.take(usize::MAX), Err(Error::Corrupt(_))));
    }

    #[test]
    fn checked_length_rejects_values_above_the_limit_before_allocating() {
        // A hostile file declaring a huge length must be refused at the field, not
        // after something tries to reserve that much memory.
        let bytes = 1_000_000u32.to_le_bytes();
        let mut r = Reader::new(&bytes);
        let err = r.checked_len_u32("manifest", 4096).unwrap_err();
        assert!(matches!(
            err,
            Error::TooLarge {
                what: "manifest",
                found: 1_000_000,
                limit: 4096
            }
        ));
    }

    #[test]
    fn checked_length_accepts_values_at_the_limit() {
        let bytes = 4096u32.to_le_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.checked_len_u32("x", 4096).unwrap(), 4096);
    }

    #[test]
    fn reserved_bytes_must_be_zero() {
        let mut r = Reader::new(&[0, 0, 0, 0]);
        r.expect_zeroes(4, "reserved").unwrap();

        let mut r = Reader::new(&[0, 0, 1, 0]);
        assert!(matches!(
            r.expect_zeroes(4, "reserved"),
            Err(Error::Corrupt("reserved"))
        ));
    }

    #[test]
    fn consumed_returns_exactly_what_was_read() {
        let bytes = [1u8, 2, 3, 4, 5];
        let mut r = Reader::new(&bytes);
        r.skip(3).unwrap();
        assert_eq!(r.consumed(), &[1, 2, 3]);
    }

    #[test]
    fn patching_a_u32_replaces_it_in_place() {
        let mut w = Writer::new();
        w.bytes(b"AB");
        w.u32(0); // placeholder
        w.bytes(b"CD");
        w.patch_u32(2, 0x1122_3344).unwrap();

        let buf = w.into_vec();
        let mut r = Reader::new(&buf);
        assert_eq!(r.take(2).unwrap(), b"AB");
        assert_eq!(r.u32().unwrap(), 0x1122_3344);
        assert_eq!(r.take(2).unwrap(), b"CD");
    }

    #[test]
    fn patching_out_of_range_errors() {
        let mut w = Writer::new();
        w.u32(0);
        assert!(w.patch_u32(8, 1).is_err());
    }

    #[test]
    fn length_that_does_not_fit_in_u32_is_rejected_on_encode() {
        let mut w = Writer::new();
        assert!(w.len_u32(usize::MAX, "huge").is_err());
    }
}
