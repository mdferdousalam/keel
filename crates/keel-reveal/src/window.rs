//! The window itself: creation, capture exclusion, drawing, and closing.
//!
//! Kept apart from [`crate::draw`] so the rendering can be tested against a plain pixel buffer
//! with no window server involved — which is how the assertions about the secret actually being
//! legible, and about never writing outside the buffer, are possible at all.

// This module reports two things to the parent's log: whether the window is actually hidden from
// screen capture, and why it closed. Both are operational facts a parent needs when diagnosing
// "did it work?", and neither can carry the secret — the value is never formatted into a message.
// Scoped here rather than crate-wide so the drawing and parsing code still cannot print.
#![allow(clippy::print_stderr)]

use std::num::NonZeroU32;
use std::time::Instant;

use winit::application::ApplicationHandler;
use winit::event::{ElementState, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::{Window, WindowAttributes, WindowId, WindowLevel};

use crate::{draw, expired, remaining_secs, Canvas, Reveal};

/// Exclude a window from screen capture.
///
/// Returns whether it worked, and the caller **shows the answer to the user**. A window the
/// user believes is hidden from recording, when it is not, is worse than one they know is
/// ordinary: they would reveal a password during a screen share on the strength of it.
///
/// macOS: `NSWindowSharingType::None`, which excludes the window from screen recording and from
/// the window-capture APIs screenshots use.
///
/// Everywhere else: not implemented, and reported as such. Windows would need
/// `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`; Wayland has no general mechanism and X11
/// has none at all, so on Linux this is honestly unachievable rather than merely unwritten.
fn exclude_from_capture(window: &Window) -> bool {
    use winit::raw_window_handle::HasWindowHandle;

    // `window_handle()` borrows the window, and that borrow is what makes the call below safe:
    // `keel_hardening` takes a handle with a lifetime rather than a raw pointer, so there is no
    // precondition for this crate — which forbids `unsafe` — to have to vouch for.
    let Ok(handle) = window.window_handle() else {
        return false;
    };
    keel_hardening::platform::exclude_window_from_capture(handle)
}

/// State for the event loop.
struct Overlay {
    reveal: Reveal,
    window: Option<std::sync::Arc<Window>>,
    surface: Option<softbuffer::Surface<std::sync::Arc<Window>, std::sync::Arc<Window>>>,
    context: Option<softbuffer::Context<std::sync::Arc<Window>>>,
    shown_at: Instant,
    capture_protected: bool,
    /// Whether the window has ever held focus.
    ///
    /// Closing on the *first* `Focused(false)` seemed right and made the window vanish
    /// instantly: a window launched by a background process may never be given focus at all,
    /// so the first focus event it sees is a loss. Closing on focus loss is still correct — a
    /// window left behind a browser is a password left on a monitor — but only once it has
    /// actually been focused.
    was_focused: bool,
    /// Why setup failed, if it did.
    ///
    /// Recorded rather than swallowed. Calling `exit()` on a failed window creation and
    /// returning `Ok` made the process vanish with no output at all, which is indistinguishable
    /// from "it worked and you missed it" — the worst possible diagnostic for a window that is
    /// supposed to be showing you a password.
    failure: Option<String>,
    /// Which event ended the loop, for the parent's log.
    closed_by: Option<&'static str>,
    /// Remaining seconds at the last redraw, so the countdown only forces a repaint when the
    /// number it displays actually changes.
    last_drawn: u64,
}

impl ApplicationHandler for Overlay {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let attributes = WindowAttributes::default()
            // The title is visible to other software, so it names the entry and never the
            // secret. `Reveal::label` is already truncated for this.
            .with_title(format!("Keel — {}", self.reveal.label))
            .with_inner_size(winit::dpi::LogicalSize::new(720.0, 260.0))
            .with_resizable(false)
            // Above ordinary windows: this is a transient thing the user asked for and is
            // waiting on, and hunting for it behind a browser would be absurd.
            .with_window_level(WindowLevel::AlwaysOnTop)
            .with_decorations(true);

        let window = match event_loop.create_window(attributes) {
            Ok(window) => window,
            Err(e) => {
                self.failure = Some(format!("could not create a window: {e}"));
                event_loop.exit();
                return;
            }
        };
        let window = std::sync::Arc::new(window);

        // Applied before the first paint, so the secret is never on screen for even one frame
        // in a capturable window.
        self.capture_protected = exclude_from_capture(&window);
        // Reported to the parent's log as well as on screen. The on-screen line is for the
        // person deciding whether to reveal a password in a shared room; this one is for
        // whoever is diagnosing why it said what it said.
        eprintln!(
            "keel-reveal: hidden from screen capture: {}",
            if self.capture_protected { "yes" } else { "no" }
        );

        let context = match softbuffer::Context::new(std::sync::Arc::clone(&window)) {
            Ok(context) => context,
            Err(e) => {
                self.failure = Some(format!("no drawing context: {e}"));
                event_loop.exit();
                return;
            }
        };
        let surface = match softbuffer::Surface::new(&context, std::sync::Arc::clone(&window)) {
            Ok(surface) => surface,
            Err(e) => {
                self.failure = Some(format!("no drawing surface: {e}"));
                event_loop.exit();
                return;
            }
        };

        window.focus_window();
        self.window = Some(window);
        self.context = Some(context);
        self.surface = Some(surface);
        self.shown_at = Instant::now();
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            // Any key closes it. A password on screen should be dismissable without hunting
            // for a button, and there is nothing here worth confirming.
            WindowEvent::KeyboardInput {
                event: key_event, ..
            } if key_event.state == ElementState::Pressed => {
                self.closed_by = Some("key press");
                event_loop.exit();
            }

            WindowEvent::CloseRequested => {
                self.closed_by = Some("close requested");
                event_loop.exit();
            }
            WindowEvent::Destroyed => {
                self.closed_by = Some("destroyed");
                event_loop.exit();
            }

            WindowEvent::Focused(true) => self.was_focused = true,

            // Losing focus closes it, but only if it ever had focus. See `was_focused`.
            WindowEvent::Focused(false) => {
                if self.was_focused {
                    self.closed_by = Some("focus lost");
                    event_loop.exit();
                }
            }

            WindowEvent::RedrawRequested => self.paint(),

            _ => {}
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if expired(self.shown_at) {
            self.closed_by = Some("timed out");
            event_loop.exit();
            return;
        }
        let remaining = remaining_secs(self.shown_at);
        if remaining != self.last_drawn {
            if let Some(window) = &self.window {
                window.request_redraw();
            }
        }
        // Woken once a second for the countdown rather than spinning. A reveal overlay has no
        // business burning a core while it waits to be read.
        event_loop.set_control_flow(ControlFlow::WaitUntil(
            Instant::now() + std::time::Duration::from_millis(250),
        ));
    }
}

impl Overlay {
    fn paint(&mut self) {
        let Some(window) = &self.window else { return };
        let Some(surface) = &mut self.surface else {
            return;
        };
        let size = window.inner_size();
        let (Some(width), Some(height)) =
            (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
        else {
            return;
        };
        if surface.resize(width, height).is_err() {
            return;
        }
        let Ok(mut buffer) = surface.buffer_mut() else {
            return;
        };

        let remaining = remaining_secs(self.shown_at);
        self.last_drawn = remaining;
        {
            let mut canvas = Canvas::new(&mut buffer, size.width as usize, size.height as usize);
            draw(&mut canvas, &self.reveal, self.capture_protected, remaining);
        }
        let _ = buffer.present();
    }
}

/// Read the request from stdin and show it.
///
/// # Errors
///
/// Returns an error if stdin does not carry a well-formed request, or if the event loop cannot
/// be created.
pub fn run() -> Result<(), String> {
    // Read before opening a window: if the parent piped nothing useful there is no point
    // putting an empty window on screen, and this is also what makes the process usable in a
    // test without a display.
    let reveal = crate::read_request(&mut std::io::stdin().lock())?;

    let event_loop = EventLoop::new().map_err(|e| format!("no window system available: {e}"))?;
    event_loop.set_control_flow(ControlFlow::Wait);

    let mut overlay = Overlay {
        reveal,
        window: None,
        surface: None,
        context: None,
        shown_at: Instant::now(),
        capture_protected: false,
        was_focused: false,
        failure: None,
        closed_by: None,
        last_drawn: u64::MAX,
    };
    event_loop
        .run_app(&mut overlay)
        .map_err(|e| format!("the reveal window failed: {e}"))?;

    if let Some(failure) = overlay.failure {
        return Err(failure);
    }
    // The loop can also end without ever having been asked to create a window — a headless
    // session, or a platform that never sends `resumed`. Reported rather than passed off as
    // success, because "exited quietly" and "showed you the password" must not look the same.
    if let Some(reason) = overlay.closed_by {
        eprintln!("keel-reveal: closed ({reason})");
    }
    if overlay.window.is_none() {
        return Err(
            "no window was created; this needs a graphical session (the event loop ended \
             before the window was requested)"
                .to_owned(),
        );
    }

    // `overlay.reveal.secret` is `Zeroizing`, so the plaintext is wiped as this returns. The
    // pixel buffer belonged to the window server and is gone with the window.
    Ok(())
}
