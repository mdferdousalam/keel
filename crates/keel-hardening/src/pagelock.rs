//! Reference-counted page locking, and the panic-time wipe.
//!
//! # Why the reference counting is necessary
//!
//! `mlock` and `VirtualLock` operate on whole pages, but secrets are small — a
//! 32-byte key. Several keys therefore routinely share one page. A naive
//! implementation that called `munlock` when a key dropped would unpin a page that
//! still holds two other live keys, silently making them swappable. Worse, the bug
//! would be invisible: everything keeps working, secrets just start reaching the
//! swap file.
//!
//! So this module counts how many live secrets occupy each page and only unpins a
//! page when the last one leaves.
//!
//! # Why the exact regions are tracked separately
//!
//! In release builds the panic strategy is `abort`, which means destructors do
//! **not** run — so `SecretBytes`'s zeroize-on-drop never happens on a panic. The
//! registry keeps the exact `(address, length)` of each live secret so the panic
//! hook can wipe precisely those bytes before the process dies, rather than
//! wiping whole pages and risking a corrupted heap on the way to `abort`.

use std::collections::HashMap;
use std::sync::Mutex;

use keel_crypto::PageLocker;

use crate::platform;

/// Process-wide registry of locked pages and live secret regions.
pub struct RefCountedPageLocker {
    state: Mutex<State>,
    page_size: usize,
}

#[derive(Debug, Default)]
struct State {
    /// Page-aligned address → number of live secrets touching that page.
    pages: HashMap<usize, u32>,
    /// Exact `(address, length)` of every live secret, for the panic wipe.
    regions: Vec<(usize, usize)>,
}

impl std::fmt::Debug for RefCountedPageLocker {
    /// Reports counts only. Never the addresses, which would be a small but free
    /// gift to anyone reading a log while planning an exploit.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (pages, regions) = self.state.try_lock().map_or((usize::MAX, usize::MAX), |s| {
            (s.pages.len(), s.regions.len())
        });
        f.debug_struct("RefCountedPageLocker")
            .field("locked_pages", &pages)
            .field("live_regions", &regions)
            .field("page_size", &self.page_size)
            .finish()
    }
}

impl RefCountedPageLocker {
    /// Create a registry using the system page size.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
            page_size: platform::page_size(),
        }
    }

    /// Page-aligned addresses covered by `[ptr, ptr + len)`.
    fn pages_for(&self, addr: usize, len: usize) -> impl Iterator<Item = usize> + '_ {
        let first = addr & !(self.page_size - 1);
        // A zero-length region still touches the page its address falls in, so
        // clamp the length to at least one byte.
        let last = (addr.saturating_add(len.max(1)) - 1) & !(self.page_size - 1);
        let step = self.page_size;
        (first..=last).step_by(step)
    }

    /// Number of pages currently pinned. Exposed for tests and diagnostics.
    #[must_use]
    pub fn locked_page_count(&self) -> usize {
        self.state.lock().map_or(0, |s| s.pages.len())
    }

    /// Number of live secret regions currently registered.
    #[must_use]
    pub fn live_region_count(&self) -> usize {
        self.state.lock().map_or(0, |s| s.regions.len())
    }

    /// Wipe every registered secret region.
    ///
    /// Called from the panic hook. Uses `try_lock`: if the panic happened while
    /// the registry lock was held, taking it again would deadlock, and hanging
    /// forever is worse than failing to wipe.
    pub fn wipe_all(&self) {
        let Ok(state) = self.state.try_lock() else {
            return;
        };
        for &(addr, len) in &state.regions {
            let ptr = addr as *mut u8;
            for i in 0..len {
                // SAFETY: the region was registered by a live secret whose
                // allocation covers [addr, addr+len). Volatile writes cannot be
                // elided by the optimiser, which a plain loop or `write_bytes`
                // could be once it proves the memory is never read again.
                unsafe { std::ptr::write_volatile(ptr.add(i), 0) };
            }
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Default for RefCountedPageLocker {
    fn default() -> Self {
        Self::new()
    }
}

impl PageLocker for RefCountedPageLocker {
    fn lock_region(&self, ptr: *const u8, len: usize) -> bool {
        let addr = ptr as usize;
        let Ok(mut state) = self.state.lock() else {
            return false;
        };

        state.regions.push((addr, len));

        let mut all_locked = true;
        // Collect first: `pages_for` borrows self, and we need &mut state inside.
        let pages: Vec<usize> = self.pages_for(addr, len).collect();
        for page in pages {
            let count = state.pages.entry(page).or_insert(0);
            *count += 1;
            if *count == 1 {
                // First live secret on this page: pin it now.
                let page_ptr = page as *const u8;
                let locked = platform::lock_memory(page_ptr, self.page_size);
                if locked {
                    platform::exclude_from_core_dump(page_ptr, self.page_size);
                    platform::exclude_from_crash_dump(page_ptr, self.page_size);
                } else {
                    // Remember that this page is not actually pinned, so we do not
                    // later "unlock" something we never locked.
                    state.pages.remove(&page);
                    all_locked = false;
                }
            }
        }
        all_locked
    }

    fn unlock_region(&self, ptr: *const u8, len: usize) {
        let addr = ptr as usize;
        let Ok(mut state) = self.state.lock() else {
            return;
        };

        if let Some(pos) = state
            .regions
            .iter()
            .position(|&(a, l)| a == addr && l == len)
        {
            state.regions.swap_remove(pos);
        }

        let pages: Vec<usize> = self.pages_for(addr, len).collect();
        for page in pages {
            let Some(count) = state.pages.get_mut(&page) else {
                // Never successfully locked, so nothing to release.
                continue;
            };
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.pages.remove(&page);
                platform::unlock_memory(page as *const u8, self.page_size);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locker() -> RefCountedPageLocker {
        RefCountedPageLocker::new()
    }

    #[test]
    fn page_range_covers_a_single_page_for_a_small_region() {
        let l = locker();
        let base = l.page_size * 4;
        assert_eq!(l.pages_for(base, 32).count(), 1);
        assert_eq!(l.pages_for(base + 100, 32).count(), 1);
    }

    #[test]
    fn page_range_spans_a_page_boundary() {
        let l = locker();
        let base = l.page_size * 4;
        // Starting 8 bytes before a boundary with 32 bytes of data touches two pages.
        let pages: Vec<usize> = l.pages_for(base - 8, 32).collect();
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0], base - l.page_size);
        assert_eq!(pages[1], base);
    }

    #[test]
    fn zero_length_region_still_touches_one_page() {
        let l = locker();
        assert_eq!(l.pages_for(l.page_size * 2, 0).count(), 1);
    }

    #[test]
    fn large_region_spans_the_expected_page_count() {
        let l = locker();
        let base = l.page_size * 8;
        assert_eq!(l.pages_for(base, l.page_size * 3).count(), 3);
    }

    #[test]
    fn two_secrets_sharing_a_page_keep_it_locked_until_both_are_gone() {
        // The bug this whole module exists to prevent: dropping one key must not
        // unpin a page that another live key still occupies.
        let l = locker();
        let buf = Box::new([0u8; 128]);
        let a = buf.as_ptr();
        // Second region deliberately inside the same page as the first.
        let b = unsafe { buf.as_ptr().add(64) };

        let locked_a = l.lock_region(a, 32);
        l.lock_region(b, 32);

        if !locked_a {
            // Sandboxed CI may refuse mlock entirely; the refcount path is then
            // untestable here and the platform test already covers that case.
            return;
        }

        assert_eq!(l.locked_page_count(), 1, "both regions share one page");
        assert_eq!(l.live_region_count(), 2);

        l.unlock_region(a, 32);
        assert_eq!(
            l.locked_page_count(),
            1,
            "page must stay pinned while the second secret is live"
        );
        assert_eq!(l.live_region_count(), 1);

        l.unlock_region(b, 32);
        assert_eq!(l.locked_page_count(), 0, "page released once empty");
        assert_eq!(l.live_region_count(), 0);
    }

    #[test]
    fn unlocking_an_unregistered_region_is_harmless() {
        let l = locker();
        let buf = Box::new([0u8; 64]);
        // Must not panic, and must not try to munlock something never locked.
        l.unlock_region(buf.as_ptr(), 32);
        assert_eq!(l.locked_page_count(), 0);
    }

    #[test]
    fn wipe_all_zeroes_registered_regions() {
        let l = locker();
        let mut buf = Box::new([0xAAu8; 64]);
        l.lock_region(buf.as_ptr(), buf.len());
        l.wipe_all();
        assert_eq!(*buf, [0u8; 64], "panic wipe must clear registered secrets");
        l.unlock_region(buf.as_ptr(), 64);
        // Touch buf afterwards so the compiler cannot discard the write above.
        buf[0] = 1;
        assert_eq!(buf[0], 1);
    }

    #[test]
    fn wipe_all_leaves_unregistered_memory_alone() {
        let l = locker();
        let registered = Box::new([0xAAu8; 32]);
        let untouched = Box::new([0xBBu8; 32]);
        l.lock_region(registered.as_ptr(), registered.len());
        l.wipe_all();
        assert_eq!(
            *untouched, [0xBBu8; 32],
            "must wipe only what was registered"
        );
        l.unlock_region(registered.as_ptr(), registered.len());
    }
}
