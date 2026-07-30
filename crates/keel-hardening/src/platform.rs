//! Raw platform calls.
//!
//! Every `unsafe` block in the Keel workspace lives in this file and in
//! `pagelock.rs`. That is the point: an auditor reviewing "what raw system calls
//! does this program make?" has two files to read rather than fifteen.
//!
//! Each function here returns a plain `bool` for success rather than an error
//! type. Hardening is best-effort by nature — `RLIMIT_MEMLOCK` is commonly a few
//! megabytes, `ptrace_scope` may already be restricted, a sandbox may deny a
//! call — and a failure to harden must never stop the program from running. The
//! results are collected into a [`crate::HardeningReport`] so the UI can tell the
//! user which protections are actually in force.

/// Disable core dumps for this process.
///
/// A core dump written after a crash would contain the decrypted vault. On Linux
/// this is belt-and-braces with `set_undumpable`; on macOS it is the only
/// mechanism available to us without a Developer ID.
pub fn disable_core_dumps() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `setrlimit` writes nothing through the pointer beyond reading
        // the `rlimit` struct we own and fully initialise here. A zero limit is
        // valid for RLIMIT_CORE.
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 }
    }
    #[cfg(windows)]
    {
        // Windows has no RLIMIT_CORE. Crash dumps are handled by Windows Error
        // Reporting, and key pages are excluded from those individually — see
        // `exclude_from_crash_dump`.
        true
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Make this process undumpable, which on Linux also blocks same-user `ptrace`
/// and reads of `/proc/<pid>/mem`.
///
/// This is the single most effective anti-inspection measure available on Linux,
/// and it is why T3 in the threat model is "partial" rather than "no defence at
/// all". It does not make same-user isolation a boundary — a process can still
/// wait for us to exit and take the vault file — but it removes the trivial
/// "read the other process's memory" path.
pub fn set_undumpable() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl` with PR_SET_DUMPABLE takes an integer argument and
        // writes nothing back. Passing 0 is documented and valid.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Not applicable. Reported as unavailable rather than as a failure.
        false
    }
}

/// Ask the kernel to refuse debugger attachment (macOS only).
///
/// Defence in depth, and deliberately modest: the strong protection on macOS is
/// the Hardened Runtime without the `get-task-allow` entitlement, which blocks
/// `task_for_pid` from non-root callers. That requires a paid Developer ID, which
/// this project does not have, so `PT_DENY_ATTACH` plus full-disk encryption carry
/// that load instead. Documented in SECURITY.md rather than glossed over.
pub fn deny_ptrace_attach() -> bool {
    #[cfg(target_os = "macos")]
    {
        // PT_DENY_ATTACH is 31 on Darwin and is absent from the libc crate.
        const PT_DENY_ATTACH: libc::c_int = 31;
        // SAFETY: `ptrace` with PT_DENY_ATTACH ignores its pid, addr, and data
        // arguments. It affects only the calling process and writes nothing
        // through a pointer.
        unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Apply Windows process mitigation policies that block code injection.
///
/// Specifically: extension points (AppInit DLLs, legacy window hooks) are
/// disabled, and images loaded from remote or low-integrity sources are blocked.
/// These close the common "inject a DLL into the password manager" routes.
#[allow(clippy::missing_const_for_fn)]
pub fn apply_injection_mitigations() -> bool {
    #[cfg(windows)]
    {
        // Split across two modules, which is the whole reason this did not build: the
        // function and the policy discriminants are in `Threading`, but the policy *structs*
        // are in `SystemServices`. Importing all five from `Threading` resolved none of them.
        use windows_sys::Win32::System::SystemServices::{
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
        };
        use windows_sys::Win32::System::Threading::{
            ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, SetProcessMitigationPolicy,
        };

        let mut ok = true;

        // Block AppInit_DLLs and legacy hook DLLs from loading into us.
        let mut ext: PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY =
            unsafe { std::mem::zeroed() };
        ext.Anonymous.Flags = 1; // DisableExtensionPoints
                                 // SAFETY: we pass a pointer to a fully initialised policy struct of the
                                 // matching type, with the size the API expects.
        ok &= unsafe {
            SetProcessMitigationPolicy(
                ProcessExtensionPointDisablePolicy,
                std::ptr::addr_of!(ext).cast(),
                std::mem::size_of_val(&ext),
            ) != 0
        };

        // Refuse to load images from UNC paths or low-integrity locations.
        let mut img: PROCESS_MITIGATION_IMAGE_LOAD_POLICY = unsafe { std::mem::zeroed() };
        // NoRemoteImages (bit 0) | NoLowMandatoryLabelImages (bit 1)
        img.Anonymous.Flags = 0b11;
        // SAFETY: as above.
        ok &= unsafe {
            SetProcessMitigationPolicy(
                ProcessImageLoadPolicy,
                std::ptr::addr_of!(img).cast(),
                std::mem::size_of_val(&img),
            ) != 0
        };

        ok
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Exclude a memory region from Windows Error Reporting crash dumps.
///
/// Without this, a crash dump uploaded to Microsoft (or sitting in
/// `%LOCALAPPDATA%\CrashDumps`) can contain the vault master key.
pub fn exclude_from_crash_dump(ptr: *const u8, len: usize) -> bool {
    #[cfg(windows)]
    {
        // `ErrorReporting`, not `Diagnostics::Debug`. Windows Error Reporting is its own
        // module; the debug module holds the debugger APIs.
        use windows_sys::Win32::System::ErrorReporting::WerRegisterExcludedMemoryBlock;
        // SAFETY: the pointer and length describe a live allocation owned by the
        // caller for at least as long as the registration. The API only records
        // the range; it does not dereference it now.
        unsafe { WerRegisterExcludedMemoryBlock(ptr.cast(), len as u32) == 0 }
    }
    #[cfg(not(windows))]
    {
        let _ = (ptr, len);
        // Linux and macOS handle this with the process-wide core-dump controls
        // above, so there is nothing per-region to do.
        true
    }
}

/// Advise the kernel to omit a region from core dumps (Linux only).
///
/// Redundant with `set_undumpable` in normal operation, but `madvise` survives a
/// later `PR_SET_DUMPABLE(1)` by something else in the process, so it is cheap
/// insurance for the specific pages that hold keys.
pub fn exclude_from_core_dump(ptr: *const u8, len: usize) -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: ptr/len describe a live mapping owned by the caller. MADV_DONTDUMP
        // only sets a flag on the VMA; it does not read or write the memory.
        unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ptr, len);
        true
    }
}

/// Pin a region into physical memory so it cannot be written to swap.
///
/// Expected to fail for anything large: the default `RLIMIT_MEMLOCK` is often
/// only 64 KiB to 8 MiB. That is ample for keys (a few hundred bytes) and
/// nowhere near enough for a decrypted manifest, which is precisely why the
/// architecture keeps the decrypted footprint small instead of relying on this.
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: ptr/len describe a live allocation owned by the caller. `mlock`
        // pins pages; it does not read or write their contents.
        unsafe { libc::mlock(ptr.cast(), len) == 0 }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Memory::VirtualLock;
        // SAFETY: as above.
        unsafe { VirtualLock(ptr as *mut _, len) != 0 }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        false
    }
}

/// Release a region previously pinned by [`lock_memory`].
pub fn unlock_memory(ptr: *const u8, len: usize) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: ptr/len describe a region previously passed to `mlock` by the
        // page registry, which guarantees the allocation is still live here.
        unsafe { libc::munlock(ptr.cast(), len) == 0 }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Memory::VirtualUnlock;
        // SAFETY: as above.
        unsafe { VirtualUnlock(ptr as *mut _, len) != 0 }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        false
    }
}

/// System page size in bytes.
pub fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: `sysconf` takes an integer name and returns a long. No pointers.
        let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if v > 0 {
            usize::try_from(v).unwrap_or(4096)
        } else {
            4096
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
        // SAFETY: `GetSystemInfo` fully initialises the struct we hand it.
        let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut info) };
        let size = info.dwPageSize as usize;
        if size == 0 {
            4096
        } else {
            size
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        4096
    }
}

/// This process's effective user id.
///
/// Lives here rather than in `keel-agent` because `geteuid` is a raw libc call, and this
/// crate is the single place in the workspace permitted `unsafe`.
#[must_use]
pub fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments, dereferences nothing, and cannot fail.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Read a connected Unix socket peer's user id and, where available, its process id.
///
/// Returns `None` if the platform refuses to tell us. Callers must treat that as a
/// *foreign* peer rather than assuming it is us: failing closed is the only safe default
/// when the check itself is unavailable.
///
/// # What this proves
///
/// The uid is authoritative — the kernel supplies it, and it cannot be forged by the peer.
/// The pid is only a hint: by the time it is resolved to an executable path the process
/// may have exited and the pid been reused, so the path is evidence for a human reading an
/// approval dialog, never an authorization decision. `docs/threat-model.md` (T13) is
/// explicit about this.
#[cfg(unix)]
#[must_use]
pub fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> Option<(u32, Option<u32>)> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = core::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` is a fully-initialised struct of exactly the type SO_PEERCRED
        // writes, and `len` describes its real size. The kernel writes at most `len`
        // bytes and updates `len` to what it wrote.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                core::ptr::addr_of_mut!(cred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        let pid = u32::try_from(cred.pid).ok();
        Some((cred.uid, pid))
    }

    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: both out-parameters are live, correctly typed, and initialised.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return None;
        }

        // LOCAL_PEERPID is a Darwin extension and is absent from the libc crate.
        const LOCAL_PEERPID: libc::c_int = 0x002;
        let mut pid: libc::pid_t = 0;
        let mut len = core::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: as above; `pid` is a live, initialised i32 and `len` is its true size.
        let pid_rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                LOCAL_PEERPID,
                core::ptr::addr_of_mut!(pid).cast(),
                &mut len,
            )
        };
        let pid = if pid_rc == 0 {
            u32::try_from(pid).ok()
        } else {
            None
        };
        Some((uid, pid))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        None
    }
}

// ---------------------------------------------------------------------------
// Screen-capture exclusion
// ---------------------------------------------------------------------------

/// Ask the window server to keep a window out of screen recordings and screenshots.
///
/// Lives here because it needs `unsafe`, and `unsafe` is confined to this crate.
///
/// # Why this is a safe function
///
/// It takes a [`WindowHandle`], whose lifetime parameter borrows the window it came from. That
/// borrow *is* the proof the underlying view is alive for the duration of the call, so there is
/// no precondition left for a caller to violate and no reason to make them write `unsafe` at a
/// boundary where they have nothing to verify. An earlier version took a raw pointer and was
/// `unsafe`, which pushed the obligation onto `keel-reveal` — a crate that forbids `unsafe`
/// outright, and correctly so.
///
/// # The return value is shown to the user
///
/// It reports whether the exclusion was actually applied, and the overlay displays that. A
/// window a user believes is hidden from recording, when it is not, is worse than one they know
/// is ordinary: they would reveal a password during a screen share on the strength of it.
///
/// # Platforms
///
/// * **macOS** — `NSWindowSharingType::None`. Excludes the window from screen recording and
///   from the window-capture APIs screenshots go through.
/// * **Windows** — would be `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`. Not
///   implemented; the agent does not run on Windows yet either.
/// * **Linux** — there is no general mechanism. X11 has none at all, and Wayland exposes
///   nothing a client can use to opt out of a compositor's screencopy. Honestly unachievable
///   rather than merely unwritten, which is why the overlay warns rather than silently doing
///   nothing.
#[must_use]
pub fn exclude_window_from_capture(handle: raw_window_handle::WindowHandle<'_>) -> bool {
    #[cfg(target_os = "macos")]
    {
        use objc2::rc::Retained;
        use objc2_app_kit::{NSView, NSWindowSharingType};
        use raw_window_handle::RawWindowHandle;

        let RawWindowHandle::AppKit(appkit) = handle.as_raw() else {
            return false;
        };
        // SAFETY: `handle` borrows the window it came from, so the view pointer is live for
        // this call. `retain` takes our own reference, so the object cannot be released while
        // the messages below are sent.
        let view: Option<Retained<NSView>> =
            unsafe { Retained::retain(appkit.ns_view.as_ptr().cast::<NSView>()) };
        let Some(view) = view else {
            return false;
        };
        // A view not yet in a window has no window to exclude.
        let Some(window) = view.window() else {
            return false;
        };
        window.setSharingType(NSWindowSharingType::None);
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = handle;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_is_sane() {
        let size = page_size();
        assert!(size >= 4096, "page size {size} is implausibly small");
        assert!(
            size.is_power_of_two(),
            "page size {size} is not a power of two"
        );
    }

    #[test]
    fn locking_a_small_buffer_round_trips() {
        // A few hundred bytes is within even a restrictive RLIMIT_MEMLOCK, so this
        // should normally succeed. It is not asserted, because CI containers and
        // sandboxes legitimately deny it and hardening is best-effort by design.
        let buf = Box::new([0u8; 256]);
        if lock_memory(buf.as_ptr(), buf.len()) {
            assert!(unlock_memory(buf.as_ptr(), buf.len()));
        }
    }

    #[test]
    fn core_dumps_can_be_disabled() {
        // Must not panic or hang, whatever the platform says.
        let _ = disable_core_dumps();
    }

    #[test]
    fn current_uid_is_reported() {
        let uid = current_uid();
        // Only assert it is stable; the value itself depends on who runs the tests, and
        // root (uid 0) is a legitimate answer in a container.
        assert_eq!(uid, current_uid());
    }

    #[cfg(unix)]
    #[test]
    fn peer_credentials_report_our_own_uid_over_a_local_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            peer_credentials(&stream)
        });
        let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();

        let (uid, pid) = server
            .join()
            .unwrap()
            .expect("credentials should be readable");
        assert_eq!(uid, current_uid(), "a local peer must report our own uid");
        // The pid is a hint and may be absent; if present it must be plausible.
        if let Some(pid) = pid {
            assert!(pid > 0);
        }
    }
}
