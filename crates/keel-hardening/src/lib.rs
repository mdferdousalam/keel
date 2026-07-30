//! Process hardening for Keel.
//!
//! **This is the only crate in the workspace permitted `unsafe`.** Every raw
//! platform call the project makes lives here, so a reviewer asking "what system
//! calls does this program make, and are they sound?" has two files to read
//! ([`platform`] and [`pagelock`]) instead of a workspace to audit.
//!
//! # What this buys, honestly
//!
//! These measures make attacks harder and slower; they do not create a security
//! boundary where the operating system does not provide one. Per T3 in
//! `docs/threat-model.md`, malware already running as your user account against an
//! *unlocked* vault eventually wins. What is genuinely on offer here is:
//!
//! * Secrets stay out of swap and out of crash dumps, so they do not outlive the
//!   process on disk. This is the most valuable part by a wide margin — disk is
//!   where a leaked secret becomes permanent.
//! * Casual memory inspection (`/proc/<pid>/mem`, attaching a debugger, injecting
//!   a DLL) is blocked, so an attacker needs real effort rather than a one-liner.
//! * On `panic = "abort"` builds destructors never run, so the panic hook wipes
//!   registered secrets explicitly rather than leaving them in memory for whatever
//!   inspects the corpse.
//!
//! Every measure is best-effort. `RLIMIT_MEMLOCK` is commonly only a few
//! megabytes, a sandbox may deny `prctl`, and macOS without a paid Developer ID
//! cannot get the full Hardened Runtime protections. Failing to harden must never
//! stop the program from running, so [`init`] returns a report rather than an
//! error and the UI surfaces which protections are actually in force.

pub mod pagelock;
pub mod platform;

use std::sync::OnceLock;

pub use pagelock::RefCountedPageLocker;

static LOCKER: OnceLock<RefCountedPageLocker> = OnceLock::new();

/// Which hardening measures are in force for this process.
///
/// Surfaced in the GUI security panel and by `keel status --json`. A user who
/// cares deserves to know that memory locking failed on their machine rather than
/// assuming it worked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// Core dumps are disabled process-wide.
    pub core_dumps_disabled: bool,
    /// Process is marked undumpable (Linux), which also blocks same-user `ptrace`.
    pub undumpable: bool,
    /// Debugger attachment is denied (macOS).
    pub ptrace_denied: bool,
    /// Code-injection mitigation policies are applied (Windows).
    pub injection_mitigated: bool,
    /// Memory locking works on this host — verified by a probe, not assumed.
    pub memory_locking_available: bool,
    /// The panic hook that wipes registered secrets is installed.
    pub panic_wipe_installed: bool,
}

impl HardeningReport {
    /// True if secrets are protected from reaching disk via swap or a dump.
    ///
    /// The most important question this report answers, because disk is where a
    /// secret can outlive the process that held it.
    #[must_use]
    pub const fn protects_against_disk_leakage(&self) -> bool {
        self.core_dumps_disabled && self.memory_locking_available
    }

    /// Warnings for anything unavailable that the user could actually fix.
    ///
    /// Deliberately silent about platform-inapplicable measures — telling a macOS
    /// user that `PR_SET_DUMPABLE` is unavailable is noise they cannot act on, and
    /// noise trains people to ignore real warnings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.memory_locking_available {
            out.push(
                "Memory locking is unavailable, so secrets may be written to swap. \
                 Enable encrypted swap, or raise RLIMIT_MEMLOCK.",
            );
        }
        if !self.core_dumps_disabled {
            out.push(
                "Core dumps could not be disabled. A crash could write vault \
                 contents to disk.",
            );
        }
        out
    }
}

/// Initialise process hardening. Call once, before any secret exists.
///
/// Installs the page locker into `keel-crypto` so every `SecretBytes` and
/// `SecretString` allocated afterwards is pinned and registered for the panic
/// wipe. Secrets created *before* this call are not covered, which is why this
/// belongs at the very top of `main`.
///
/// Idempotent: a second call returns a fresh report without reinstalling anything.
pub fn init() -> HardeningReport {
    let locker = LOCKER.get_or_init(RefCountedPageLocker::new);
    // If something already installed a locker, that one wins. Either way the
    // process ends up with exactly one.
    let _ = keel_crypto::install_page_locker(locker);

    HardeningReport {
        core_dumps_disabled: platform::disable_core_dumps(),
        undumpable: platform::set_undumpable(),
        ptrace_denied: platform::deny_ptrace_attach(),
        injection_mitigated: platform::apply_injection_mitigations(),
        memory_locking_available: probe_memory_locking(),
        panic_wipe_installed: install_panic_wipe(),
    }
}

/// Test whether memory locking actually works here rather than assuming it does.
///
/// A container, a sandbox, or a low `RLIMIT_MEMLOCK` can each refuse it. Reporting
/// a protection as active when it silently failed is worse than reporting it as
/// unavailable, because the user would then skip the mitigation that would have
/// helped.
fn probe_memory_locking() -> bool {
    // Boxed rather than a stack array so the probe locks a heap page, which is what
    // real secrets live on.
    let probe = Box::new([0u8; 64]);
    if platform::lock_memory(probe.as_ptr(), probe.len()) {
        platform::unlock_memory(probe.as_ptr(), probe.len());
        true
    } else {
        false
    }
}

/// Install a panic hook that wipes registered secrets before the process dies.
///
/// Installed only when the panic strategy is `abort`, which is the release
/// configuration. Under `unwind` — how tests are built — destructors do run and
/// wipe secrets properly, and wiping from the hook would instead corrupt live
/// secrets in any test that catches a panic.
fn install_panic_wipe() -> bool {
    if !cfg!(panic = "abort") {
        return false;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(locker) = LOCKER.get() {
            locker.wipe_all();
        }
        previous(info);
    }));
    true
}

/// The installed page locker, if [`init`] has run.
///
/// The agent uses this to report how many secrets are currently resident.
#[must_use]
pub fn locker() -> Option<&'static RefCountedPageLocker> {
    LOCKER.get()
}

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use keel_crypto::SecretBytes;

    #[test]
    fn init_is_idempotent() {
        let first = init();
        let second = init();
        assert_eq!(first, second, "repeated init must be stable");
    }

    #[test]
    fn secrets_allocated_after_init_are_registered_and_deregistered() {
        init();
        let before = locker().map_or(0, RefCountedPageLocker::live_region_count);
        let secret = SecretBytes::<32>::random().expect("rng");
        let during = locker().map_or(0, RefCountedPageLocker::live_region_count);
        assert!(
            during > before,
            "allocating a secret should register a region ({before} -> {during})"
        );
        drop(secret);
        let after = locker().map_or(0, RefCountedPageLocker::live_region_count);
        assert_eq!(
            after, before,
            "dropping a secret should deregister its region"
        );
    }

    #[test]
    fn panic_wipe_is_not_installed_under_unwind() {
        // Tests build with panic=unwind, where destructors run. Wiping from the
        // hook there would corrupt live secrets in any caught panic, so it must
        // stay off.
        assert!(!init().panic_wipe_installed);
    }

    #[test]
    fn warnings_stay_silent_about_platform_inapplicable_measures() {
        let report = HardeningReport {
            core_dumps_disabled: true,
            undumpable: false,
            ptrace_denied: false,
            injection_mitigated: false,
            memory_locking_available: true,
            panic_wipe_installed: false,
        };
        assert!(report.warnings().is_empty());
        assert!(report.protects_against_disk_leakage());
    }

    #[test]
    fn missing_memory_locking_warns_about_swap() {
        let report = HardeningReport {
            core_dumps_disabled: true,
            undumpable: true,
            ptrace_denied: false,
            injection_mitigated: false,
            memory_locking_available: false,
            panic_wipe_installed: true,
        };
        assert!(!report.protects_against_disk_leakage());
        assert!(report.warnings().iter().any(|w| w.contains("swap")));
    }
}
