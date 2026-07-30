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
        use windows_sys::Win32::System::Threading::{
            ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, SetProcessMitigationPolicy,
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
            PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
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
        use windows_sys::Win32::System::Diagnostics::Debug::WerRegisterExcludedMemoryBlock;
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
}
