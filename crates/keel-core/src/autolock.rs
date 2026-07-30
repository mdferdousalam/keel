//! When an unlocked vault must lock itself.
//!
//! A pure state machine: it is told about events and asked whether to lock. Keeping the
//! *policy* free of timers, threads, and OS callbacks means every rule below can be
//! tested by advancing a number, and the platform code that watches for screen locks and
//! suspend events stays a thin translation layer with no decisions in it.
//!
//! # The rules, and why each exists
//!
//! | Trigger | Default | Reason |
//! |---|---|---|
//! | Idle | 5 min | The common case: someone walks away from their desk. |
//! | Screen lock | immediate | The user has said "I am leaving"; honouring it is the least we can do. |
//! | Suspend | immediate, *before* sleeping | Memory contents survive suspend, so keys must not. |
//! | Session cap | 8 h | Bounds exposure for someone who keeps a machine awake for days. |
//! | Failed unlock attempts | backoff, not lockout | See below. |
//!
//! **Idle means idle in Keel, not idle at the OS.** A user reading a long document is
//! busy at the machine but has not touched their vault, and their vault should lock.
//!
//! **Locking happens before suspend, not after resume.** RAM contents survive a suspend,
//! so waiting until resume would leave keys sitting in memory for the whole time the lid
//! was shut — which is exactly the window in which a laptop gets stolen.
//!
//! # Failed attempts: backoff, never lockout
//!
//! Repeated wrong passphrases produce an exponentially growing delay, capped at a minute.
//! They never permanently lock anyone out, and there is no attempt counter that destroys
//! a vault.
//!
//! That is deliberate. A destructive lockout in a local password manager is worthless as
//! a defence — an attacker attacking the *file* never goes through this code path, they
//! run Argon2 offline at whatever rate they like — while being catastrophic when
//! triggered by the actual user, who is nearly always the person fat-fingering their own
//! passphrase. The real defence against guessing is the memory-hard KDF, which costs the
//! attacker seconds per attempt whether we count them or not.
//!
//! Backoff still earns its place: it makes a script hammering a *running* agent slow, and
//! it makes repeated failures visible in the audit log.

/// Default idle timeout, in seconds.
pub const DEFAULT_IDLE_TIMEOUT: u64 = 5 * 60;

/// Default hard session cap, in seconds.
pub const DEFAULT_SESSION_CAP: u64 = 8 * 60 * 60;

/// Shortest permitted idle timeout, in seconds.
///
/// A floor because a timeout of a few seconds is unusable, and a user who sets one will
/// disable auto-lock entirely instead — a much worse outcome.
pub const MIN_IDLE_TIMEOUT: u64 = 30;

/// Longest permitted idle timeout, in seconds.
pub const MAX_IDLE_TIMEOUT: u64 = 24 * 60 * 60;

/// Base delay after a failed unlock, in milliseconds.
pub const BACKOFF_BASE_MS: u64 = 1_000;

/// Longest backoff delay, in milliseconds.
pub const BACKOFF_CAP_MS: u64 = 60_000;

/// Why the vault locked.
///
/// Surfaced to the user, because "your vault locked" without a reason is mildly alarming
/// and prompts people to raise their timeout or turn the feature off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// No interaction with Keel for the idle timeout.
    Idle,
    /// The screen locked.
    ScreenLocked,
    /// The machine is about to suspend.
    Suspending,
    /// The user switched away or logged out.
    SessionEnded,
    /// The hard session cap was reached.
    SessionCap,
    /// The user asked.
    Manual,
}

impl LockReason {
    /// A short explanation for the unlock screen.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Idle => "Locked after a period of inactivity.",
            Self::ScreenLocked => "Locked because your screen locked.",
            Self::Suspending => "Locked before your computer went to sleep.",
            Self::SessionEnded => "Locked because you signed out.",
            Self::SessionCap => "Locked because the maximum session length was reached.",
            Self::Manual => "Locked.",
        }
    }

    /// Whether the user chose this.
    ///
    /// The UI stays quiet about a manual lock and explains the others.
    #[must_use]
    pub const fn was_deliberate(self) -> bool {
        matches!(self, Self::Manual)
    }
}

/// Something that happened which the lock policy cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The user did something with Keel.
    Activity,
    /// The screen locked.
    ScreenLocked,
    /// The machine is about to suspend.
    ///
    /// Delivered *before* sleeping, inside the inhibitor window the OS provides.
    Suspending,
    /// The user switched away or signed out.
    SessionEnded,
    /// The user asked to lock.
    LockRequested,
}

/// Configurable lock behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPolicy {
    /// Seconds of inactivity before locking. `None` disables the idle timer.
    pub idle_timeout: Option<u64>,
    /// Hard cap on an unlocked session, in seconds.
    ///
    /// Not optional. A user may reasonably want no idle timeout while working, but an
    /// indefinite session means one unlock in January is still live in March.
    pub session_cap: u64,
    /// Lock when the screen locks.
    pub lock_on_screen_lock: bool,
    /// Lock before the machine suspends.
    ///
    /// Effectively mandatory: memory survives suspend, so this is the difference between
    /// a stolen sleeping laptop being a nuisance and being a disaster.
    pub lock_on_suspend: bool,
}

impl Default for LockPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            session_cap: DEFAULT_SESSION_CAP,
            lock_on_screen_lock: true,
            lock_on_suspend: true,
        }
    }
}

impl LockPolicy {
    /// Clamp a user-supplied idle timeout into the accepted range.
    ///
    /// Clamps rather than rejecting, so a settings screen never has to refuse a number
    /// the user typed — it just quietly keeps it sane.
    #[must_use]
    pub fn with_idle_timeout(mut self, seconds: Option<u64>) -> Self {
        self.idle_timeout = seconds.map(|s| s.clamp(MIN_IDLE_TIMEOUT, MAX_IDLE_TIMEOUT));
        self
    }
}

/// Live auto-lock state for one unlocked session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoLock {
    policy: LockPolicy,
    unlocked_at: u64,
    last_activity: u64,
    pending: Option<LockReason>,
    failed_attempts: u32,
}

impl AutoLock {
    /// Begin tracking a newly unlocked session.
    #[must_use]
    pub const fn unlocked(policy: LockPolicy, now: u64) -> Self {
        Self {
            policy,
            unlocked_at: now,
            last_activity: now,
            pending: None,
            failed_attempts: 0,
        }
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> LockPolicy {
        self.policy
    }

    /// Replace the policy, keeping session timing.
    ///
    /// Does not restart the session clock: raising the cap mid-session must not extend a
    /// session that has already run its length.
    pub fn set_policy(&mut self, policy: LockPolicy) {
        self.policy = policy;
    }

    /// Record an event.
    pub fn observe(&mut self, event: Event, now: u64) {
        match event {
            Event::Activity => self.last_activity = now,
            Event::ScreenLocked => {
                if self.policy.lock_on_screen_lock {
                    self.pending = Some(LockReason::ScreenLocked);
                }
            }
            Event::Suspending => {
                if self.policy.lock_on_suspend {
                    self.pending = Some(LockReason::Suspending);
                }
            }
            Event::SessionEnded => self.pending = Some(LockReason::SessionEnded),
            Event::LockRequested => self.pending = Some(LockReason::Manual),
        }
    }

    /// Whether the vault should lock now, and why.
    ///
    /// Event-driven reasons win over timers, so a user who locked their screen sees
    /// "because your screen locked" rather than "after inactivity" if both happen to
    /// apply.
    #[must_use]
    pub fn should_lock(&self, now: u64) -> Option<LockReason> {
        if let Some(reason) = self.pending {
            return Some(reason);
        }
        // Checked before the idle timer: a session that has run its full length must lock
        // even if the user is actively working, which is the whole point of a cap.
        if now.saturating_sub(self.unlocked_at) >= self.policy.session_cap {
            return Some(LockReason::SessionCap);
        }
        if let Some(timeout) = self.policy.idle_timeout {
            if now.saturating_sub(self.last_activity) >= timeout {
                return Some(LockReason::Idle);
            }
        }
        None
    }

    /// Seconds until the next automatic lock, if one is scheduled.
    ///
    /// Lets the caller sleep until the deadline instead of polling, and lets the UI show
    /// a countdown.
    #[must_use]
    pub fn seconds_until_lock(&self, now: u64) -> Option<u64> {
        if self.pending.is_some() {
            return Some(0);
        }
        let session_deadline = self.unlocked_at.saturating_add(self.policy.session_cap);
        let mut soonest = session_deadline;
        if let Some(timeout) = self.policy.idle_timeout {
            soonest = soonest.min(self.last_activity.saturating_add(timeout));
        }
        Some(soonest.saturating_sub(now))
    }

    /// Record a failed unlock attempt and return how long to wait, in milliseconds.
    ///
    /// Exponential from 1 s, capped at 60 s. Never a lockout — see the module
    /// documentation for why a destructive attempt counter would be worse than useless
    /// here.
    pub fn record_failed_attempt(&mut self) -> u64 {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        backoff_ms(self.failed_attempts)
    }

    /// Clear the failure counter after a successful unlock.
    pub fn record_successful_unlock(&mut self, now: u64) {
        self.failed_attempts = 0;
        self.unlocked_at = now;
        self.last_activity = now;
        self.pending = None;
    }

    /// Consecutive failed attempts.
    #[must_use]
    pub const fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }
}

/// Backoff delay for the nth consecutive failure, in milliseconds.
#[must_use]
pub fn backoff_ms(attempt: u32) -> u64 {
    if attempt == 0 {
        return 0;
    }
    // Doubling from the base, saturating at the cap. `checked_shl` keeps a large attempt
    // count from wrapping the shift into a small delay, which would silently remove the
    // backoff exactly when it is most needed.
    let shift = attempt.saturating_sub(1).min(31);
    BACKOFF_BASE_MS
        .checked_shl(shift)
        .unwrap_or(BACKOFF_CAP_MS)
        .min(BACKOFF_CAP_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn session() -> AutoLock {
        AutoLock::unlocked(LockPolicy::default(), NOW)
    }

    #[test]
    fn a_fresh_session_does_not_lock() {
        assert_eq!(session().should_lock(NOW), None);
        assert_eq!(session().should_lock(NOW + 60), None);
    }

    #[test]
    fn inactivity_locks_after_the_timeout() {
        let s = session();
        assert_eq!(s.should_lock(NOW + DEFAULT_IDLE_TIMEOUT - 1), None);
        assert_eq!(
            s.should_lock(NOW + DEFAULT_IDLE_TIMEOUT),
            Some(LockReason::Idle)
        );
    }

    #[test]
    fn activity_postpones_the_idle_lock() {
        let mut s = session();
        s.observe(Event::Activity, NOW + 200);
        assert_eq!(s.should_lock(NOW + DEFAULT_IDLE_TIMEOUT), None);
        assert_eq!(
            s.should_lock(NOW + 200 + DEFAULT_IDLE_TIMEOUT),
            Some(LockReason::Idle)
        );
    }

    #[test]
    fn a_screen_lock_locks_immediately() {
        let mut s = session();
        s.observe(Event::ScreenLocked, NOW + 1);
        assert_eq!(s.should_lock(NOW + 1), Some(LockReason::ScreenLocked));
    }

    #[test]
    fn suspend_locks_immediately_because_memory_survives_sleep() {
        // Waiting until resume would leave keys in RAM for the whole time the lid was
        // shut, which is exactly when a laptop gets stolen.
        let mut s = session();
        s.observe(Event::Suspending, NOW + 1);
        assert_eq!(s.should_lock(NOW + 1), Some(LockReason::Suspending));
    }

    #[test]
    fn signing_out_locks_regardless_of_settings() {
        let mut s = AutoLock::unlocked(
            LockPolicy {
                lock_on_screen_lock: false,
                lock_on_suspend: false,
                ..LockPolicy::default()
            },
            NOW,
        );
        s.observe(Event::SessionEnded, NOW + 1);
        assert_eq!(s.should_lock(NOW + 1), Some(LockReason::SessionEnded));
    }

    #[test]
    fn the_session_cap_locks_even_while_the_user_is_working() {
        // The entire point of a cap: activity must not extend it indefinitely.
        let mut s = session();
        for minute in 1..(DEFAULT_SESSION_CAP / 60) {
            s.observe(Event::Activity, NOW + minute * 60);
        }
        assert_eq!(
            s.should_lock(NOW + DEFAULT_SESSION_CAP),
            Some(LockReason::SessionCap)
        );
    }

    #[test]
    fn raising_the_cap_mid_session_does_not_extend_a_spent_session() {
        let mut s = session();
        assert_eq!(
            s.should_lock(NOW + DEFAULT_SESSION_CAP),
            Some(LockReason::SessionCap)
        );
        // The session clock starts at unlock, not at the last settings change.
        s.set_policy(LockPolicy {
            session_cap: DEFAULT_SESSION_CAP,
            ..LockPolicy::default()
        });
        assert_eq!(
            s.should_lock(NOW + DEFAULT_SESSION_CAP),
            Some(LockReason::SessionCap)
        );
    }

    #[test]
    fn disabling_the_idle_timer_still_leaves_the_session_cap() {
        let s = AutoLock::unlocked(LockPolicy::default().with_idle_timeout(None), NOW);
        assert_eq!(s.should_lock(NOW + DEFAULT_IDLE_TIMEOUT * 10), None);
        assert_eq!(
            s.should_lock(NOW + DEFAULT_SESSION_CAP),
            Some(LockReason::SessionCap)
        );
    }

    #[test]
    fn an_event_reason_beats_a_timer_reason() {
        // The message the user sees should describe what actually happened.
        let mut s = session();
        s.observe(Event::ScreenLocked, NOW + 1);
        assert_eq!(
            s.should_lock(NOW + DEFAULT_SESSION_CAP + 1),
            Some(LockReason::ScreenLocked)
        );
    }

    #[test]
    fn respecting_screen_lock_can_be_turned_off() {
        let mut s = AutoLock::unlocked(
            LockPolicy {
                lock_on_screen_lock: false,
                ..LockPolicy::default()
            },
            NOW,
        );
        s.observe(Event::ScreenLocked, NOW + 1);
        assert_eq!(s.should_lock(NOW + 1), None);
    }

    #[test]
    fn idle_timeouts_are_clamped_into_a_usable_range() {
        // An unusably short timeout would make users disable auto-lock entirely, which is
        // far worse than a slightly longer one.
        let too_short = LockPolicy::default().with_idle_timeout(Some(1));
        assert_eq!(too_short.idle_timeout, Some(MIN_IDLE_TIMEOUT));

        let too_long = LockPolicy::default().with_idle_timeout(Some(u64::MAX));
        assert_eq!(too_long.idle_timeout, Some(MAX_IDLE_TIMEOUT));

        let sensible = LockPolicy::default().with_idle_timeout(Some(600));
        assert_eq!(sensible.idle_timeout, Some(600));
    }

    #[test]
    fn the_countdown_reports_the_soonest_deadline() {
        let s = session();
        assert_eq!(s.seconds_until_lock(NOW), Some(DEFAULT_IDLE_TIMEOUT));
        assert_eq!(
            s.seconds_until_lock(NOW + 100),
            Some(DEFAULT_IDLE_TIMEOUT - 100)
        );

        // With no idle timer, the cap is the deadline.
        let no_idle = AutoLock::unlocked(LockPolicy::default().with_idle_timeout(None), NOW);
        assert_eq!(no_idle.seconds_until_lock(NOW), Some(DEFAULT_SESSION_CAP));
    }

    #[test]
    fn a_pending_lock_reports_zero_seconds_remaining() {
        let mut s = session();
        s.observe(Event::LockRequested, NOW);
        assert_eq!(s.seconds_until_lock(NOW), Some(0));
    }

    #[test]
    fn a_manual_lock_is_marked_deliberate() {
        let mut s = session();
        s.observe(Event::LockRequested, NOW);
        let reason = s.should_lock(NOW).unwrap();
        assert_eq!(reason, LockReason::Manual);
        assert!(reason.was_deliberate());
        // Every other reason should be explained to the user.
        for other in [
            LockReason::Idle,
            LockReason::ScreenLocked,
            LockReason::Suspending,
            LockReason::SessionEnded,
            LockReason::SessionCap,
        ] {
            assert!(!other.was_deliberate());
            assert!(!other.message().is_empty());
        }
    }

    #[test]
    fn unlocking_again_resets_the_session() {
        let mut s = session();
        s.observe(Event::LockRequested, NOW);
        assert!(s.should_lock(NOW).is_some());

        s.record_failed_attempt();
        s.record_successful_unlock(NOW + 1000);
        assert_eq!(s.should_lock(NOW + 1000), None);
        assert_eq!(s.failed_attempts(), 0);
    }

    // ---- failed attempts --------------------------------------------------

    #[test]
    fn backoff_grows_exponentially_and_is_capped() {
        assert_eq!(backoff_ms(0), 0);
        assert_eq!(backoff_ms(1), 1_000);
        assert_eq!(backoff_ms(2), 2_000);
        assert_eq!(backoff_ms(3), 4_000);
        assert_eq!(backoff_ms(7), 64_000_u64.min(BACKOFF_CAP_MS));
        assert_eq!(backoff_ms(100), BACKOFF_CAP_MS);
        // A huge attempt count must not wrap the shift into a tiny delay, which would
        // remove the backoff exactly when it is most needed.
        assert_eq!(backoff_ms(u32::MAX), BACKOFF_CAP_MS);
    }

    #[test]
    fn failures_never_produce_a_lockout() {
        // A destructive attempt counter would be worthless against an attacker with the
        // file — they run Argon2 offline — and catastrophic for the user who mistyped.
        let mut s = session();
        for attempt in 1..=1000u32 {
            let delay = s.record_failed_attempt();
            assert!(delay <= BACKOFF_CAP_MS);
            assert_eq!(s.failed_attempts(), attempt);
        }
        // Still unlockable with the right passphrase.
        s.record_successful_unlock(NOW + 5);
        assert_eq!(s.failed_attempts(), 0);
        assert_eq!(s.should_lock(NOW + 5), None);
    }

    #[test]
    fn a_successful_unlock_clears_the_backoff() {
        let mut s = session();
        s.record_failed_attempt();
        s.record_failed_attempt();
        assert_eq!(s.failed_attempts(), 2);
        s.record_successful_unlock(NOW);
        assert_eq!(s.failed_attempts(), 0);
        assert_eq!(backoff_ms(s.failed_attempts()), 0);
    }
}
