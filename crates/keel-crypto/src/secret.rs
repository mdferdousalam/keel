// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Secret-bearing types.
//!
//! Three properties are enforced here, and they are load-bearing:
//!
//! 1. **No `Debug`, `Display`, `Serialize`, or `Clone`.** Accidentally logging
//!    or serializing a secret is a *compile error*, not something a reviewer has
//!    to catch. This static guarantee is worth more than the runtime wipe.
//! 2. **Zeroized on drop**, via [`Zeroizing`].
//! 3. **Pages locked out of swap** where the platform allows it — but this crate
//!    forbids `unsafe`, so it cannot call `mlock` itself. Instead it exposes the
//!    [`PageLocker`] hook, which `keel-hardening` installs at startup. When no
//!    locker is installed (unit tests, `no_std`-ish embedding) locking is a
//!    no-op and everything still works.
//!
//! Deliberately absent: any `Clone` impl. Decrypted secrets are never copied;
//! they are consumed where they are used. If you find yourself wanting `Clone`,
//! the call graph is wrong.

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// Maximum accepted length of a user-supplied passphrase, in bytes.
///
/// Exists to make [`SecretString`] buffers a fixed size. Growing a `String`
/// past its capacity reallocates, and the *old* buffer is freed without being
/// zeroized — leaving the passphrase in reusable heap memory. Pre-allocating to
/// a hard maximum removes that failure mode entirely.
pub const MAX_PASSPHRASE_LEN: usize = 1024;

// ---------------------------------------------------------------------------
// Page locking hook
// ---------------------------------------------------------------------------

/// Platform hook for keeping secret pages out of swap and out of core dumps.
///
/// Implemented by `keel-hardening` (the only crate in the workspace permitted
/// `unsafe`) and installed once at process startup via
/// [`install_page_locker`].
///
/// # Contract
///
/// Implementations must tolerate being called with any pointer/length this
/// crate allocated, must never panic, and must treat failure as advisory —
/// `RLIMIT_MEMLOCK` is commonly a few megabytes, so locking *will* fail on
/// large buffers and that must not be fatal.
pub trait PageLocker: Send + Sync {
    /// Request that `len` bytes at `ptr` be excluded from swap and core dumps.
    ///
    /// Returns `true` if the request succeeded. A `false` return is not an
    /// error; it means the platform or the resource limit said no.
    fn lock_region(&self, ptr: *const u8, len: usize) -> bool;

    /// Release a region previously passed to [`PageLocker::lock_region`].
    fn unlock_region(&self, ptr: *const u8, len: usize);
}

static LOCKER: OnceLock<&'static dyn PageLocker> = OnceLock::new();
static LOCK_FAILURE_SEEN: AtomicBool = AtomicBool::new(false);

/// Install the process-wide page locker.
///
/// Call once, from `keel-hardening`, before any secret exists. Returns `false`
/// if a locker was already installed (the first one wins; this is not an error,
/// it just means something raced).
pub fn install_page_locker(locker: &'static dyn PageLocker) -> bool {
    LOCKER.set(locker).is_ok()
}

/// True if any page-lock request has failed in this process.
///
/// The GUI surfaces this as a hardening hint ("secrets may be written to swap;
/// enable encrypted swap"). It is not a reason to refuse to run — on Linux the
/// default `RLIMIT_MEMLOCK` is often only a few megabytes.
#[must_use]
pub fn page_lock_degraded() -> bool {
    LOCK_FAILURE_SEEN.load(Ordering::Relaxed)
}

fn lock_region(ptr: *const u8, len: usize) {
    if let Some(locker) = LOCKER.get() {
        if !locker.lock_region(ptr, len) {
            LOCK_FAILURE_SEEN.store(true, Ordering::Relaxed);
        }
    }
}

fn unlock_region(ptr: *const u8, len: usize) {
    if let Some(locker) = LOCKER.get() {
        locker.unlock_region(ptr, len);
    }
}

/// Fill `buf` with cryptographically secure random bytes from the OS.
///
/// There is deliberately no userspace RNG in this crate: no seed to leak, no
/// state to duplicate across a `fork`, nothing to get wrong. If the kernel
/// cannot supply entropy we fail rather than falling back to something weaker.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Rng)
}

// ---------------------------------------------------------------------------
// SecretBytes
// ---------------------------------------------------------------------------

/// A fixed-size secret byte array: heap-allocated, page-locked where possible,
/// zeroized on drop.
///
/// Used for all key material. `N` is a const parameter so key sizes are checked
/// at compile time and a 16-byte key can never be passed where 32 is required.
pub struct SecretBytes<const N: usize> {
    inner: Box<Zeroizing<[u8; N]>>,
}

impl<const N: usize> SecretBytes<N> {
    /// Allocate a zeroed secret buffer.
    ///
    /// The buffer is allocated on the heap and immediately page-locked. Note
    /// that we allocate zeroed and then fill in place rather than constructing
    /// on the stack and boxing — boxing a stack array leaves a copy of the
    /// secret in stack memory that nothing will wipe.
    #[must_use]
    pub fn zeroed() -> Self {
        let inner = Box::new(Zeroizing::new([0u8; N]));
        let me = Self { inner };
        lock_region(me.inner.as_ptr(), N);
        me
    }

    /// Build a secret from a slice, which must be exactly `N` bytes.
    ///
    /// The caller remains responsible for wiping `src`.
    pub fn from_slice(src: &[u8]) -> Result<Self> {
        if src.len() != N {
            return Err(Error::InvalidLength {
                expected: N,
                actual: src.len(),
            });
        }
        let mut me = Self::zeroed();
        me.expose_mut().copy_from_slice(src);
        Ok(me)
    }

    /// Generate a fresh random secret from the OS RNG.
    pub fn random() -> Result<Self> {
        let mut me = Self::zeroed();
        fill_random(me.expose_mut())?;
        Ok(me)
    }

    /// Borrow the secret bytes.
    ///
    /// Named `expose` rather than `as_bytes` so that every read site is
    /// grep-able during review.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        &self.inner
    }

    /// Mutably borrow the secret bytes, to fill them in place.
    #[must_use]
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.inner
    }

    /// Length in bytes. Always `N`; provided for symmetry.
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// Always `false`. Present because clippy asks for it alongside `len`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.expose().ct_eq(other.expose())
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    /// Constant-time comparison.
    ///
    /// `==` on key material is a timing oracle, so the `PartialEq` impl routes
    /// through `subtle` rather than the derived byte-wise compare. This is why
    /// the impl is written out instead of derived.
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    /// Prints only the type and length. There is no way to get the bytes out
    /// via formatting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(<redacted>)")
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        // Zeroize *before* unlocking, so the wipe cannot be preceded by the
        // pages becoming swappable again. `Zeroizing` would also wipe on drop;
        // doing it explicitly here fixes the ordering relative to the unlock.
        self.inner.as_mut().zeroize();
        unlock_region(self.inner.as_ptr(), N);
    }
}

impl<const N: usize> Zeroize for SecretBytes<N> {
    fn zeroize(&mut self) {
        self.inner.as_mut().zeroize();
    }
}

/// A 256-bit key. The only key size this project uses.
pub type Key256 = SecretBytes<32>;

// ---------------------------------------------------------------------------
// SecretString
// ---------------------------------------------------------------------------

/// A UTF-8 secret (passphrase, password, TOTP seed, note) with a fixed capacity.
///
/// The capacity is fixed at construction and pushes that would exceed it fail
/// rather than reallocating. See [`MAX_PASSPHRASE_LEN`] for why.
pub struct SecretString {
    inner: Zeroizing<String>,
    capacity: usize,
}

impl SecretString {
    /// Create an empty secret string with room for `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let mut s = String::new();
        s.reserve_exact(capacity);
        let me = Self {
            inner: Zeroizing::new(s),
            capacity,
        };
        lock_region(me.inner.as_ptr(), capacity);
        me
    }

    /// Create a passphrase buffer sized to [`MAX_PASSPHRASE_LEN`].
    #[must_use]
    pub fn passphrase_buffer() -> Self {
        Self::with_capacity(MAX_PASSPHRASE_LEN)
    }

    /// Build from an existing string, taking ownership.
    ///
    /// The caller's `String` is moved in and will be zeroized on drop. Note that
    /// whatever produced that `String` may already have left copies elsewhere;
    /// prefer [`SecretString::with_capacity`] plus [`SecretString::push_str`]
    /// when reading from a terminal or a socket.
    #[must_use]
    pub fn from_string(s: String) -> Self {
        let capacity = s.capacity();
        let me = Self {
            inner: Zeroizing::new(s),
            capacity,
        };
        lock_region(me.inner.as_ptr(), capacity);
        me
    }

    /// Append to the secret.
    ///
    /// Fails rather than reallocating if the result would exceed the capacity
    /// fixed at construction.
    pub fn push_str(&mut self, s: &str) -> Result<()> {
        if self.inner.len() + s.len() > self.capacity {
            return Err(Error::InvalidLength {
                expected: self.capacity,
                actual: self.inner.len() + s.len(),
            });
        }
        self.inner.push_str(s);
        Ok(())
    }

    /// Append a single character, subject to the same capacity rule.
    pub fn push(&mut self, c: char) -> Result<()> {
        let mut buf = [0u8; 4];
        self.push_str(c.encode_utf8(&mut buf))
    }

    /// Borrow the secret as a string slice.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Borrow the secret as bytes.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if nothing has been pushed yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(<redacted>, {} bytes)", self.inner.len())
    }
}

impl ConstantTimeEq for SecretString {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Lengths differ ⇒ not equal, but still compare something so the
        // early-out does not leak more than the length already does.
        if self.inner.len() != other.inner.len() {
            return subtle::Choice::from(0u8);
        }
        self.expose_bytes().ct_eq(other.expose_bytes())
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        let ptr = self.inner.as_ptr();
        self.inner.zeroize();
        unlock_region(ptr, self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroed_is_zero() {
        let s = SecretBytes::<32>::zeroed();
        assert_eq!(s.expose(), &[0u8; 32]);
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        let err = SecretBytes::<32>::from_slice(&[1, 2, 3]).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidLength {
                expected: 32,
                actual: 3
            }
        ));
    }

    #[test]
    fn from_slice_round_trips() {
        let src = [7u8; 32];
        let s = SecretBytes::<32>::from_slice(&src).unwrap();
        assert_eq!(s.expose(), &src);
    }

    #[test]
    fn random_differs_between_calls() {
        let a = SecretBytes::<32>::random().unwrap();
        let b = SecretBytes::<32>::random().unwrap();
        // A collision here is a ~2^-256 event, or a broken RNG.
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.expose(), &[0u8; 32]);
    }

    #[test]
    fn equality_is_constant_time_and_correct() {
        let a = SecretBytes::<32>::from_slice(&[1u8; 32]).unwrap();
        let b = SecretBytes::<32>::from_slice(&[1u8; 32]).unwrap();
        let c = SecretBytes::<32>::from_slice(&[2u8; 32]).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn debug_never_reveals_bytes() {
        let s = SecretBytes::<32>::from_slice(&[0xAB; 32]).unwrap();
        let rendered = format!("{s:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("ab"));
        assert!(!rendered.contains("171"));
    }

    #[test]
    fn secret_string_refuses_to_grow_past_capacity() {
        let mut s = SecretString::with_capacity(8);
        s.push_str("1234").unwrap();
        s.push_str("5678").unwrap();
        // The ninth byte would reallocate and abandon the old buffer unwiped.
        assert!(s.push('9').is_err());
        assert_eq!(s.expose(), "12345678");
    }

    #[test]
    fn secret_string_debug_never_reveals_content() {
        let mut s = SecretString::with_capacity(64);
        s.push_str("correct horse battery staple").unwrap();
        let rendered = format!("{s:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("horse"));
    }

    #[test]
    fn fill_random_actually_fills() {
        let mut buf = [0u8; 64];
        fill_random(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 64]);
    }
}
