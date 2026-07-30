//! Putting a secret on the clipboard, and taking it back off again.
//!
//! The clipboard is the least private place a password can be — every process
//! running as the user can read it, and on some platforms it is synchronised to
//! other machines and recorded in a visible history. It is also what users
//! actually want, so the job here is to narrow the window rather than to refuse.
//!
//! Three decisions carry the weight:
//!
//! 1. **Clear only what we put there.** A timer that unconditionally wiped the
//!    clipboard would destroy whatever the user copied in the meantime — which is
//!    both infuriating and, if they cannot get it back, destructive. So we record
//!    a fingerprint of the value we wrote and clear only if the clipboard still
//!    matches it. See [`Fingerprint`] for why that is a keyed hash.
//! 2. **One thread owns the clipboard.** On X11 the clipboard is not a buffer but
//!    a protocol: contents live in the *owning process* and vanish when it exits
//!    or drops ownership. `arboard` keeps a server thread alive for as long as its
//!    handle exists, so the handle must outlive the copy — a function-local
//!    `Clipboard` would work on macOS and Windows and silently lose the value on
//!    Linux. Keeping it on one long-lived thread also sidesteps the handle not
//!    being [`Sync`].
//! 3. **A failure to copy is reported, never swallowed.** A user told that a
//!    password was copied, who then pastes stale clipboard contents into a login
//!    form, has been actively misled. Every path back to the caller distinguishes
//!    "it is on the clipboard" from "it is not".
//!
//! What this deliberately does *not* claim: on a normal desktop, another process
//! running as the user can read the clipboard during the seconds it holds a
//! secret, and a clipboard manager may keep its own copy that we cannot reach. The
//! platform notes on [`set_secret`](Clipboard::set_secret) say what is and is not
//! suppressed per OS.
//!
//! # Why the backend is a trait
//!
//! The logic worth testing here is *when to clear*, and getting it wrong is either
//! a data-loss bug (clearing the user's data) or a disclosure bug (leaving a
//! password behind). Testing that against the real system clipboard would mean
//! hijacking the clipboard of whoever runs the suite — an earlier version of this
//! module did exactly that and left a test string on the developer's clipboard.
//! [`Backend`] exists so those tests run against an in-memory fake and assert the
//! decisions directly.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// Longest a secret may sit on the clipboard, whatever the vault settings say.
///
/// A user who configures "never clear" is asking for the secret to stay readable
/// by every process on the machine indefinitely, usually without having thought
/// about it that way. Two minutes is the ceiling.
pub const MAX_CLEAR_SECS: u32 = 120;

/// Shortest clear delay. Below this, a paste into a slow-to-focus window loses the
/// race and the feature looks broken.
pub const MIN_CLEAR_SECS: u32 = 5;

/// How long a caller waits for confirmation that a copy happened.
///
/// A copy is a local operation. If it has not answered in this long something is
/// wrong, and reporting failure beats blocking a connection thread forever.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

/// A keyed fingerprint of a clipboard value.
///
/// Keyed, with a per-process random key, on purpose. An unkeyed hash of a password
/// is a verifier: anything that reads it out of our memory can test guesses
/// against it offline, at whatever rate it likes, without touching the vault. That
/// would hand an attacker a cheap oracle for a value the vault itself protects
/// with a 512 MiB KDF. The key never leaves this process and dies with it, so the
/// fingerprint is meaningless anywhere else.
///
/// Comparison is constant-time: `blake3::Hash`'s `PartialEq` is documented as
/// such, which is why the digest is kept in that type rather than as `[u8; 32]`.
struct Fingerprint {
    key: [u8; 32],
}

impl Fingerprint {
    fn new() -> Option<Self> {
        let mut key = [0u8; 32];
        keel_crypto::fill_random(&mut key).ok()?;
        Some(Self { key })
    }

    fn of(&self, value: &str) -> blake3::Hash {
        blake3::keyed_hash(&self.key, value.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// The platform clipboard, as much of it as this module needs.
///
/// Reads return [`Zeroizing`] because reading the clipboard to check whether it is
/// still ours pulls the secret back into our memory.
trait Backend {
    fn write(&mut self, value: &str) -> Result<(), String>;
    fn read(&mut self) -> Result<Zeroizing<String>, String>;
    fn clear(&mut self) -> Result<(), String>;
}

/// The real system clipboard.
///
/// Connects lazily and retries on each use rather than caching a permanent
/// failure: a display server can appear after the daemon started, which is the
/// normal case for an agent launched by systemd before the user logs in
/// graphically.
struct SystemBackend {
    handle: Option<arboard::Clipboard>,
}

impl SystemBackend {
    const fn new() -> Self {
        Self { handle: None }
    }

    fn connect(&mut self) -> Result<&mut arboard::Clipboard, String> {
        if self.handle.is_none() {
            match arboard::Clipboard::new() {
                Ok(handle) => self.handle = Some(handle),
                Err(e) => return Err(format!("no clipboard available: {e}")),
            }
        }
        self.handle
            .as_mut()
            .ok_or_else(|| "no clipboard available".to_owned())
    }
}

impl Backend for SystemBackend {
    fn write(&mut self, value: &str) -> Result<(), String> {
        let handle = self.connect()?;
        #[cfg(windows)]
        {
            // Keep the secret out of Win+V history, out of Cloud Clipboard sync to the
            // user's other devices, and out of clipboard-monitoring applications. These
            // are the only per-item suppression controls any platform offers us.
            use arboard::SetExtWindows as _;
            handle
                .set()
                .exclude_from_monitoring()
                .exclude_from_cloud()
                .exclude_from_history()
                .text(value)
                .map_err(|e| format!("could not write to the clipboard: {e}"))
        }
        #[cfg(not(windows))]
        {
            handle
                .set_text(value)
                .map_err(|e| format!("could not write to the clipboard: {e}"))
        }
    }

    fn read(&mut self) -> Result<Zeroizing<String>, String> {
        let handle = self.connect()?;
        handle
            .get_text()
            .map(Zeroizing::new)
            .map_err(|e| format!("could not read the clipboard: {e}"))
    }

    fn clear(&mut self) -> Result<(), String> {
        let handle = self.connect()?;
        handle
            .clear()
            .map_err(|e| format!("could not clear the clipboard: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// A request to the clipboard thread.
enum Command {
    /// Put a secret on the clipboard and start its clear timer.
    Set {
        value: Zeroizing<String>,
        clear_after: Duration,
        reply: Sender<Result<(), String>>,
    },
    /// Clear the clipboard if it still holds the secret we last wrote.
    ///
    /// Sent when the vault locks. Locking is the user saying "I am done"; leaving
    /// a password readable afterwards would contradict the one thing locking
    /// visibly promises.
    ClearOurs,
}

/// Handle to the clipboard thread.
///
/// Cloneable and [`Send`]: all it holds is a channel. The platform handle stays on
/// the thread.
#[derive(Clone)]
pub struct Clipboard {
    tx: Sender<Command>,
}

impl core::fmt::Debug for Clipboard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Clipboard")
    }
}

impl Clipboard {
    /// Start the clipboard thread.
    ///
    /// Does not touch the platform clipboard yet — connecting to a display server
    /// can fail, and it should fail when a user asks for a copy, where the error
    /// can be reported, rather than at daemon startup, where it would be a warning
    /// nobody reads or a refusal to start.
    #[must_use]
    pub fn start() -> Self {
        Self::spawn(SystemBackend::new())
    }

    fn spawn<B: Backend + Send + 'static>(backend: B) -> Self {
        let (tx, rx) = mpsc::channel();
        // If the thread cannot be spawned, the receiver drops and every `set_secret`
        // reports the failure. That is the correct degradation: no silent pretence that
        // a copy happened.
        let _ = thread::Builder::new()
            .name("keel-clipboard".to_owned())
            .spawn(move || worker(rx, backend));
        Self { tx }
    }

    /// Copy `value`, clearing it after `clear_after_secs` unless the user has
    /// replaced it by then.
    ///
    /// Blocks until the copy has actually happened, so the caller can report the
    /// truth. Returns `Err` with a human-readable reason if the clipboard could not
    /// be written.
    ///
    /// Platform suppression, where the OS offers any:
    ///
    /// * **Windows** — excluded from clipboard history (Win+V), from Cloud
    ///   Clipboard sync to other devices, and from clipboard monitoring
    ///   applications.
    /// * **macOS** — nothing to apply. The convention well-behaved clipboard
    ///   managers honour, `org.nspasteboard.ConcealedType`, needs a custom
    ///   pasteboard type that `arboard` does not expose, and it is a convention
    ///   rather than an enforced control in any case. Recorded as a known gap
    ///   rather than papered over.
    /// * **Linux** — X11 selections die with the owning process, so quitting the
    ///   agent also clears the secret. Clipboard managers may still have taken a
    ///   copy, and nothing we do can prevent that.
    pub fn set_secret(&self, value: &str, clear_after_secs: u32) -> Result<(), String> {
        let secs = clear_after_secs.clamp(MIN_CLEAR_SECS, MAX_CLEAR_SECS);
        self.set_for(value, Duration::from_secs(u64::from(secs)))
    }

    /// [`set_secret`](Self::set_secret) without the clamp, so tests need not sleep
    /// for [`MIN_CLEAR_SECS`].
    fn set_for(&self, value: &str, clear_after: Duration) -> Result<(), String> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(Command::Set {
                value: Zeroizing::new(value.to_owned()),
                clear_after,
                reply: reply_tx,
            })
            .map_err(|_| "the clipboard thread is not running".to_owned())?;
        reply_rx
            .recv_timeout(REPLY_TIMEOUT)
            .map_err(|_| "the clipboard did not respond".to_owned())?
    }

    /// Clear the clipboard if it still holds our secret. Called on lock.
    ///
    /// Deliberately does not wait for the result: lock runs on a connection thread
    /// and must not block on a display server.
    pub fn clear_ours(&self) {
        let _ = self.tx.send(Command::ClearOurs);
    }
}

/// Clear the clipboard, but only if it still holds the value fingerprinted by
/// `ours`.
///
/// If the read fails — the clipboard now holds an image, or is empty, or the
/// display went away — we cannot establish that the contents are ours, so we leave
/// them alone. Refusing to clear what we do not recognise is the safe direction:
/// the cost is a secret lingering until the user's next copy overwrites it, against
/// the alternative of destroying data they wanted.
fn clear_ours<B: Backend>(backend: &mut B, fingerprint: &Fingerprint, ours: blake3::Hash) {
    let Ok(current) = backend.read() else {
        return;
    };
    if fingerprint.of(&current) == ours {
        let _ = backend.clear();
    }
}

/// The clipboard thread.
///
/// Owns the platform handle for its whole life (see the X11 note in the module
/// docs) and runs the clear timer with `recv_timeout`, so a pending clear and an
/// incoming command are handled by one loop with no shared state and no second
/// timer thread to get out of step.
fn worker<B: Backend>(rx: Receiver<Command>, mut backend: B) {
    let Some(fingerprint) = Fingerprint::new() else {
        // No randomness means no fingerprint, which means no way to tell our value from
        // the user's. Rather than clear blindly, answer every request with the failure.
        // Close to unreachable: `fill_random` failing means the OS CSPRNG is
        // unavailable, and nothing else in Keel would work either.
        while let Ok(command) = rx.recv() {
            if let Command::Set { reply, .. } = command {
                let _ = reply.send(Err("no randomness available".to_owned()));
            }
        }
        return;
    };

    // What we last wrote and when it should go. `None` means nothing of ours is on the
    // clipboard, so there is nothing to clear and no deadline to wait for.
    let mut pending: Option<(Instant, blake3::Hash)> = None;

    loop {
        let command = match pending {
            Some((deadline, ours)) => {
                let now = Instant::now();
                if now >= deadline {
                    clear_ours(&mut backend, &fingerprint, ours);
                    pending = None;
                    continue;
                }
                rx.recv_timeout(deadline - now)
            }
            // Nothing of ours is out there, so block until there is something to do.
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };

        match command {
            Ok(Command::Set {
                value,
                clear_after,
                reply,
            }) => {
                // A new copy replaces the old one, so the previous deadline is
                // irrelevant: what it would have cleared is no longer there.
                match backend.write(&value) {
                    Ok(()) => {
                        pending = Some((Instant::now() + clear_after, fingerprint.of(&value)));
                        let _ = reply.send(Ok(()));
                    }
                    Err(e) => {
                        pending = None;
                        let _ = reply.send(Err(e));
                    }
                }
            }
            Ok(Command::ClearOurs) => {
                if let Some((_, ours)) = pending.take() {
                    clear_ours(&mut backend, &fingerprint, ours);
                }
            }
            // The deadline passed while waiting; the top of the loop does the clearing.
            Err(RecvTimeoutError::Timeout) => {}
            // Every handle is gone, so the agent is shutting down. Take the secret with
            // us: on X11 it would vanish anyway, and elsewhere leaving it behind after
            // the process that promised to clear it has exited is the worst outcome.
            Err(RecvTimeoutError::Disconnected) => {
                if let Some((_, ours)) = pending.take() {
                    clear_ours(&mut backend, &fingerprint, ours);
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// An in-memory clipboard.
    ///
    /// Shared with the test thread through an `Arc`, so a test can inspect what the
    /// worker did and can also play the part of the user copying something else.
    #[derive(Clone, Default)]
    struct FakeBackend {
        contents: Arc<Mutex<Option<String>>>,
        writes: Arc<Mutex<usize>>,
        clears: Arc<Mutex<usize>>,
        fail_writes: bool,
    }

    impl FakeBackend {
        fn get(&self) -> Option<String> {
            self.contents.lock().unwrap().clone()
        }

        /// The user copies something of their own.
        fn user_copies(&self, value: &str) {
            *self.contents.lock().unwrap() = Some(value.to_owned());
        }

        fn clears(&self) -> usize {
            *self.clears.lock().unwrap()
        }
    }

    impl Backend for FakeBackend {
        fn write(&mut self, value: &str) -> Result<(), String> {
            if self.fail_writes {
                return Err("no clipboard available: fake".to_owned());
            }
            *self.writes.lock().unwrap() += 1;
            *self.contents.lock().unwrap() = Some(value.to_owned());
            Ok(())
        }

        fn read(&mut self) -> Result<Zeroizing<String>, String> {
            self.contents
                .lock()
                .unwrap()
                .clone()
                .map(Zeroizing::new)
                .ok_or_else(|| "clipboard is empty".to_owned())
        }

        fn clear(&mut self) -> Result<(), String> {
            *self.clears.lock().unwrap() += 1;
            *self.contents.lock().unwrap() = None;
            Ok(())
        }
    }

    /// Poll until `condition` holds, or give up.
    ///
    /// The worker acts on its own thread, so a test cannot simply assert after
    /// sending. Polling rather than sleeping a fixed span keeps the suite fast when
    /// things work and still fails rather than hanging when they do not.
    fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
        for _ in 0..400 {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        false
    }

    fn with_fake(fail_writes: bool) -> (Clipboard, FakeBackend) {
        let backend = FakeBackend {
            fail_writes,
            ..FakeBackend::default()
        };
        (Clipboard::spawn(backend.clone()), backend)
    }

    // -- fingerprinting ----------------------------------------------------

    #[test]
    fn a_fingerprint_distinguishes_values_and_is_keyed() {
        let a = Fingerprint::new().unwrap();
        let b = Fingerprint::new().unwrap();
        assert_eq!(a.of("hunter2"), a.of("hunter2"));
        assert_ne!(a.of("hunter2"), a.of("hunter3"));
        // Different processes must not produce comparable fingerprints, or the hash
        // becomes a portable verifier for a guessed password.
        assert_ne!(a.of("hunter2"), b.of("hunter2"));
    }

    // -- the clear decision, which is the whole point ----------------------

    #[test]
    fn our_own_secret_is_cleared_when_the_timer_expires() {
        let (clipboard, backend) = with_fake(false);
        clipboard
            .set_for("s3cret", Duration::from_millis(30))
            .unwrap();
        assert_eq!(backend.get().as_deref(), Some("s3cret"));
        assert!(
            wait_until(|| backend.get().is_none()),
            "the secret should have been cleared"
        );
    }

    #[test]
    fn something_the_user_copied_since_is_never_cleared() {
        // The data-loss case. A timer that fired unconditionally would destroy work the
        // user may not be able to get back, which is worse than a secret lingering
        // until their next copy overwrites it.
        let (clipboard, backend) = with_fake(false);
        clipboard
            .set_for("s3cret", Duration::from_millis(30))
            .unwrap();
        backend.user_copies("a paragraph the user is still writing");
        thread::sleep(Duration::from_millis(120));
        assert_eq!(
            backend.get().as_deref(),
            Some("a paragraph the user is still writing"),
            "the user's own clipboard contents must survive our timer"
        );
        assert_eq!(backend.clears(), 0, "nothing should have been cleared");
    }

    #[test]
    fn locking_clears_our_secret_immediately() {
        // Locking is the user saying they are done. Waiting out the remaining timer
        // would leave the password readable after the UI says it is gone.
        let (clipboard, backend) = with_fake(false);
        clipboard
            .set_for("s3cret", Duration::from_secs(300))
            .unwrap();
        clipboard.clear_ours();
        assert!(
            wait_until(|| backend.get().is_none()),
            "lock should have cleared the secret without waiting for the timer"
        );
    }

    #[test]
    fn locking_does_not_clear_what_the_user_copied_since() {
        let (clipboard, backend) = with_fake(false);
        clipboard
            .set_for("s3cret", Duration::from_secs(300))
            .unwrap();
        backend.user_copies("an address");
        clipboard.clear_ours();
        thread::sleep(Duration::from_millis(60));
        assert_eq!(backend.get().as_deref(), Some("an address"));
        assert_eq!(backend.clears(), 0);
    }

    #[test]
    fn an_empty_or_unreadable_clipboard_is_left_alone() {
        // `read` failing means we cannot establish the contents are ours. Clearing
        // anyway would be clearing something unknown.
        let (clipboard, backend) = with_fake(false);
        clipboard
            .set_for("s3cret", Duration::from_millis(30))
            .unwrap();
        *backend.contents.lock().unwrap() = None; // e.g. the clipboard now holds an image
        thread::sleep(Duration::from_millis(120));
        assert_eq!(backend.clears(), 0);
    }

    #[test]
    fn a_second_copy_replaces_the_first_and_gets_its_own_timer() {
        let (clipboard, backend) = with_fake(false);
        clipboard
            .set_for("first", Duration::from_millis(20))
            .unwrap();
        clipboard
            .set_for("second", Duration::from_secs(300))
            .unwrap();
        // The first deadline must not clear the second value.
        thread::sleep(Duration::from_millis(120));
        assert_eq!(
            backend.get().as_deref(),
            Some("second"),
            "the first copy's timer must not clear the second copy"
        );
    }

    // -- honest failure ----------------------------------------------------

    #[test]
    fn a_failed_copy_is_reported_rather_than_swallowed() {
        let (clipboard, backend) = with_fake(true);
        let err = clipboard.set_secret("s3cret", 15).unwrap_err();
        assert!(err.contains("clipboard"), "unexpected message: {err}");
        assert_eq!(backend.get(), None, "nothing should be on the clipboard");
    }

    #[test]
    fn setting_a_secret_fails_loudly_when_the_thread_is_gone() {
        // Also what happens if the thread could not be spawned at all.
        let (tx, rx) = mpsc::channel();
        drop(rx);
        let err = Clipboard { tx }.set_secret("s3cret", 15).unwrap_err();
        assert!(err.contains("not running"), "unexpected message: {err}");
    }

    #[test]
    fn clearing_on_lock_never_blocks_the_caller() {
        // Lock runs on a connection thread and must not wait for a display server.
        let (tx, rx) = mpsc::channel();
        drop(rx);
        Clipboard { tx }.clear_ours();
    }

    #[test]
    fn shutdown_takes_our_secret_with_it() {
        // Dropping the last handle means the agent is going away. Leaving a password
        // behind after the process that promised to clear it has exited is the worst
        // outcome available.
        let (clipboard, backend) = with_fake(false);
        clipboard
            .set_for("s3cret", Duration::from_secs(300))
            .unwrap();
        drop(clipboard);
        assert!(
            wait_until(|| backend.get().is_none()),
            "shutdown should have cleared the secret"
        );
    }

    // -- bounds ------------------------------------------------------------

    #[test]
    fn clear_delay_is_clamped_at_both_ends() {
        assert_eq!(0u32.clamp(MIN_CLEAR_SECS, MAX_CLEAR_SECS), MIN_CLEAR_SECS);
        assert_eq!(
            u32::MAX.clamp(MIN_CLEAR_SECS, MAX_CLEAR_SECS),
            MAX_CLEAR_SECS
        );
        assert_eq!(30u32.clamp(MIN_CLEAR_SECS, MAX_CLEAR_SECS), 30);
    }

    #[test]
    fn the_clamp_range_is_ordered() {
        // A transposed pair would make `clamp` panic, on a path that only runs when a
        // user copies something.
        const _: () = assert!(MIN_CLEAR_SECS < MAX_CLEAR_SECS);
    }
}
