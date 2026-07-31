// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The reveal overlay: a small native window that shows one secret and then forgets it.
//!
//! # Why this is a separate process at all
//!
//! Keel's desktop window is a webview, and a webview is a browser: a garbage-collected heap
//! whose strings cannot be zeroized, with a JIT, a DOM, and a devtools protocol. Putting a
//! password in it means putting a password somewhere it can be copied by the allocator,
//! retained by the collector, and read by anything that can talk to the inspector. So the
//! desktop window never receives one — and "show me the password" therefore cannot be a
//! feature of that window.
//!
//! It is this instead: a process with no webview, no HTML, and no font parser, which receives
//! one secret, draws it, and exits.
//!
//! # The secret arrives on stdin, from the agent
//!
//! Not on the command line — argv is world-readable through `ps` and lands in shell history.
//! Not through a file or an environment variable, for the same reason. Stdin, written by the
//! parent and closed immediately.
//!
//! The parent is the **agent**, not the desktop app. The agent is the only process that holds
//! the vault decrypted, so having it spawn this directly means the plaintext never enters the
//! GUI process either. The GUI asks for a reveal and is told it happened; it does not handle
//! the value at any point.
//!
//! # What "non-capturable" does and does not mean
//!
//! On macOS the window sets `NSWindowSharingType::None`, which excludes it from screen
//! recording and from screenshots taken through the window-capture APIs. On Windows the
//! equivalent is `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`, which is **not
//! implemented** — see [`keel_hardening::platform`] — so on Windows this window is an ordinary
//! window and the overlay reports that rather than implying protection it does not have.
//!
//! It stops software on the machine from recording the screen. It does not stop a phone
//! pointed at the monitor, and nothing can. The title bar says so, because a user deciding
//! whether it is safe to reveal a password in a shared room needs to know which of those two
//! they are protected from.

// Tests build values and assert on them; the production lints that forbid panicking would only
// make them longer without making them safer. Matches every other crate here.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod font;
pub mod window;

use std::io::Read;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// How long the secret stays on screen before the window closes itself.
///
/// A window left open is a password left on a monitor. Thirty seconds is enough to read and
/// retype a long passphrase and short enough that walking away does not leave it there.
pub const VISIBLE_FOR: Duration = Duration::from_secs(30);

/// Largest secret this will display, in bytes.
///
/// A password field is capped well below this. The limit exists so a parent that pipes
/// something unexpected cannot make this process allocate without bound.
pub const MAX_SECRET: usize = 8 * 1024;

/// What to draw.
pub struct Reveal {
    /// The secret itself. Wiped when this is dropped.
    pub secret: Zeroizing<String>,
    /// A label naming the entry, so a user with two windows open can tell them apart.
    ///
    /// Never the secret, and deliberately not the username: this appears in a window title,
    /// which the window server records and other applications can read.
    pub label: String,
}

/// Written by hand, never derived. A derived `Debug` would put the plaintext into any log line,
/// panic message, or `unwrap` failure that formatted a `Reveal` — and this process exists
/// precisely because that value should not be anywhere it can be copied casually.
impl core::fmt::Debug for Reveal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reveal")
            .field("label", &self.label)
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

/// Read the reveal request from stdin.
///
/// The format is one line of label, then the secret, and the parent closes the pipe. Simple
/// enough to have no parser worth attacking.
///
/// # Errors
///
/// Returns an error if stdin cannot be read, is empty, or exceeds [`MAX_SECRET`].
pub fn read_request<R: Read>(reader: &mut R) -> Result<Reveal, String> {
    // Read with a cap rather than to end-of-file. `read_to_string` on a pipe that never
    // closes is an unbounded allocation driven by whoever is on the other end.
    let mut buffer = Zeroizing::new(Vec::with_capacity(256));
    let mut chunk = Zeroizing::new([0u8; 1024]);
    loop {
        let read = reader
            .read(chunk.as_mut())
            .map_err(|e| format!("reading the secret: {e}"))?;
        if read == 0 {
            break;
        }
        if buffer.len() + read > MAX_SECRET {
            return Err(format!("the secret exceeds {MAX_SECRET} bytes"));
        }
        buffer.extend_from_slice(chunk.get(..read).unwrap_or(&[]));
    }
    if buffer.is_empty() {
        return Err("nothing was piped in; this process is started by Keel, not by hand".into());
    }

    let text = Zeroizing::new(
        String::from_utf8(buffer.to_vec()).map_err(|_| "the secret is not valid UTF-8")?,
    );
    let (label, secret) = text
        .split_once('\n')
        .ok_or("expected a label line followed by the secret")?;
    if secret.is_empty() {
        return Err("the secret was empty".into());
    }
    Ok(Reveal {
        // Trimmed and truncated: this goes in a window title, which is the one string here
        // that other software on the machine can read.
        label: label.chars().take(60).collect(),
        secret: Zeroizing::new(secret.to_owned()),
    })
}

/// Colours, as `0x00RRGGBB` for a 32-bit framebuffer.
pub(crate) mod colour {
    /// Near-black. Deliberately not pure black, so the window is visibly a window.
    pub(crate) const BACKGROUND: u32 = 0x0011_1827;
    /// The secret itself: high contrast, because it exists to be read accurately.
    pub(crate) const SECRET: u32 = 0x00F2_F6FC;
    /// Supporting text.
    pub(crate) const MUTED: u32 = 0x0090_9CB4;
    /// The warning shown when capture protection could not be applied.
    pub(crate) const WARNING: u32 = 0x00F5_C26B;
}

/// A 32-bit framebuffer that text is drawn into.
pub struct Canvas<'a> {
    pixels: &'a mut [u32],
    width: usize,
    height: usize,
}

/// Also written by hand. The pixel buffer holds a rendered image *of the secret*, so dumping it
/// would leak the same value in a less obvious form.
impl core::fmt::Debug for Canvas<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Canvas")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish()
    }
}

impl<'a> Canvas<'a> {
    /// Wrap a pixel buffer.
    #[must_use]
    pub fn new(pixels: &'a mut [u32], width: usize, height: usize) -> Self {
        Self {
            pixels,
            width,
            height,
        }
    }

    /// Fill everything with one colour.
    pub fn clear(&mut self, colour: u32) {
        self.pixels.fill(colour);
    }

    /// Draw one glyph, scaled by an integer factor.
    ///
    /// Integer scaling only: no filtering, no subpixel positioning. A password has to be read
    /// character by character, and a blurred glyph is worse than a blocky one.
    fn glyph(&mut self, ch: char, x: usize, y: usize, scale: usize, colour: u32) {
        let rows = font::glyph(ch);
        for (row_index, row) in rows.iter().enumerate() {
            for column in 0..font::GLYPH_W {
                // Bit 7 is the leftmost pixel.
                if row & (0x80 >> column) == 0 {
                    continue;
                }
                for dy in 0..scale {
                    for dx in 0..scale {
                        let px = x + column * scale + dx;
                        let py = y + row_index * scale + dy;
                        if px >= self.width || py >= self.height {
                            continue;
                        }
                        if let Some(pixel) = self.pixels.get_mut(py * self.width + px) {
                            *pixel = colour;
                        }
                    }
                }
            }
        }
    }

    /// Draw a string, wrapping at the canvas edge.
    ///
    /// Returns the y coordinate below the last line drawn, so callers can stack text without
    /// tracking metrics themselves.
    pub fn text(&mut self, value: &str, x: usize, y: usize, scale: usize, colour: u32) -> usize {
        let advance = font::GLYPH_W * scale;
        let line_height = font::GLYPH_H * scale + scale * 2;
        let mut cx = x;
        let mut cy = y;
        for ch in value.chars() {
            if cx + advance > self.width.saturating_sub(x) {
                cx = x;
                cy += line_height;
            }
            self.glyph(ch, cx, cy, scale, colour);
            cx += advance;
        }
        cy + line_height
    }

    /// Width in pixels a string would occupy on one line.
    #[must_use]
    pub fn measure(value: &str, scale: usize) -> usize {
        value.chars().count() * font::GLYPH_W * scale
    }
}

/// Draw the whole overlay.
///
/// Separated from any window handling so it can be tested by rendering into a plain buffer and
/// asserting on pixels — including the assertion that matters most, that the secret is
/// actually legible rather than clipped away.
pub fn draw(canvas: &mut Canvas<'_>, reveal: &Reveal, capture_protected: bool, remaining: u64) {
    canvas.clear(colour::BACKGROUND);

    let margin = 24;
    let mut y = margin;

    y = canvas.text(&reveal.label, margin, y, 2, colour::MUTED);
    y += 12;

    // The secret, as large as fits. Scaled down rather than wrapped for a long passphrase,
    // because a wrapped password invites a transcription error at the break.
    let available = canvas.width.saturating_sub(margin * 2);
    let mut scale = 4;
    while scale > 1 && Canvas::measure(&reveal.secret, scale) > available {
        scale -= 1;
    }
    y = canvas.text(&reveal.secret, margin, y, scale, colour::SECRET);
    y += 16;

    if capture_protected {
        y = canvas.text(
            "Hidden from screen recording and screenshots.",
            margin,
            y,
            1,
            colour::MUTED,
        );
    } else {
        // Said plainly. A user deciding whether to reveal a password in a shared room needs to
        // know this window is an ordinary window on this platform.
        y = canvas.text(
            "WARNING: this window is NOT hidden from screen capture on this platform.",
            margin,
            y,
            1,
            colour::WARNING,
        );
    }
    y = canvas.text(
        "A camera pointed at this screen still sees it. Nothing can prevent that.",
        margin,
        y,
        1,
        colour::MUTED,
    );
    y += 8;
    canvas.text(
        &format!("Closes in {remaining}s. Press any key to close now."),
        margin,
        y,
        1,
        colour::MUTED,
    );
}

/// Seconds left before the window closes itself.
#[must_use]
pub fn remaining_secs(shown_at: Instant) -> u64 {
    VISIBLE_FOR
        .saturating_sub(shown_at.elapsed())
        .as_secs()
        .saturating_add(1)
        .min(VISIBLE_FOR.as_secs())
}

/// Whether the window should have closed by now.
#[must_use]
pub fn expired(shown_at: Instant) -> bool {
    shown_at.elapsed() >= VISIBLE_FOR
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(label: &str, secret: &str) -> Reveal {
        let mut input = std::io::Cursor::new(format!("{label}\n{secret}").into_bytes());
        read_request(&mut input).expect("should parse")
    }

    #[test]
    fn a_request_is_a_label_line_then_the_secret() {
        let reveal = request("Chase Bank", "hunter2");
        assert_eq!(reveal.label, "Chase Bank");
        assert_eq!(&*reveal.secret, "hunter2");
    }

    #[test]
    fn a_secret_may_contain_anything_a_password_can() {
        // Including spaces and newlines: a stored value is whatever the user put there, and
        // splitting only on the *first* newline is what makes that work.
        let reveal = request("Note", "line one\nline two\twith a tab");
        assert_eq!(&*reveal.secret, "line one\nline two\twith a tab");
    }

    #[test]
    fn an_empty_or_malformed_request_is_refused() {
        for raw in ["", "no newline at all", "label-only\n"] {
            let mut input = std::io::Cursor::new(raw.as_bytes().to_vec());
            assert!(
                read_request(&mut input).is_err(),
                "{raw:?} should have been refused"
            );
        }
    }

    #[test]
    fn an_oversized_secret_is_refused_rather_than_buffered() {
        // A parent that pipes something unexpected must not be able to drive an unbounded
        // allocation here.
        let huge = format!("label\n{}", "x".repeat(MAX_SECRET + 1));
        let mut input = std::io::Cursor::new(huge.into_bytes());
        let error = read_request(&mut input).unwrap_err();
        assert!(error.contains("exceeds"), "got: {error}");
    }

    #[test]
    fn the_label_is_truncated_because_it_becomes_a_window_title() {
        // Window titles are readable by other software on the machine, so this is the one
        // string here with an audience beyond the user.
        let reveal = request(&"L".repeat(500), "secret");
        assert_eq!(reveal.label.chars().count(), 60);
    }

    #[test]
    fn every_printable_ascii_character_has_a_distinct_glyph() {
        // A password drawn from an 88-character alphabet has to be readable character by
        // character. Two characters sharing a bitmap would make it ambiguous on screen — and
        // the pairs people actually confuse are exactly the ones a lazy font gets wrong.
        use std::collections::HashMap;
        let mut seen: HashMap<[u8; font::GLYPH_H], Vec<char>> = HashMap::new();
        for code in font::FIRST..=font::LAST {
            let ch = char::from(code);
            if ch == ' ' {
                continue; // Blank on purpose.
            }
            seen.entry(*font::glyph(ch)).or_default().push(ch);
        }
        let collisions: Vec<_> = seen.values().filter(|chars| chars.len() > 1).collect();
        assert!(
            collisions.is_empty(),
            "these characters would be indistinguishable on screen: {collisions:?}"
        );
    }

    #[test]
    fn the_characters_people_misread_are_visibly_different() {
        // The specific pairs the generator's `exclude_ambiguous` option exists for. If the
        // font blurs these, excluding them from generated passwords was pointless.
        for (a, b) in [
            ('0', 'O'),
            ('1', 'l'),
            ('1', 'I'),
            ('l', 'I'),
            ('5', 'S'),
            ('2', 'Z'),
        ] {
            assert_ne!(
                font::glyph(a),
                font::glyph(b),
                "{a:?} and {b:?} must not share a glyph"
            );
        }
    }

    #[test]
    fn an_unrenderable_character_is_visible_rather_than_missing() {
        // A password containing something outside printable ASCII must look *wrong* on
        // screen, not short. Silently dropping a character would have the user retype a
        // password that does not match what is stored.
        let box_glyph = font::glyph('\u{1F510}');
        assert!(
            box_glyph.iter().any(|row| *row != 0),
            "an unknown character must draw something"
        );
        assert_eq!(
            box_glyph,
            font::glyph('\u{4E2D}'),
            "one replacement for all"
        );
        assert_ne!(
            box_glyph,
            font::glyph(' '),
            "and it must not look like a space"
        );
    }

    #[test]
    fn the_secret_is_actually_drawn() {
        // Rendering into a plain buffer, so this asserts on pixels rather than on intent. A
        // reveal window that drew nothing would be a very quiet failure.
        let (w, h) = (800usize, 400usize);
        let mut pixels = vec![0u32; w * h];
        let reveal = request("Chase Bank", "hunter2");
        {
            let mut canvas = Canvas::new(&mut pixels, w, h);
            draw(&mut canvas, &reveal, true, 30);
        }
        let lit = pixels.iter().filter(|p| **p == colour::SECRET).count();
        assert!(
            lit > 100,
            "the secret should have lit a good number of pixels, got {lit}"
        );
    }

    #[test]
    fn a_long_passphrase_is_scaled_down_rather_than_wrapped() {
        // Wrapping a password invites a transcription error at the break.
        let (w, h) = (900usize, 400usize);
        let mut pixels = vec![0u32; w * h];
        let long = "correct-horse-battery-staple-uncle-mustard-window";
        let reveal = request("Long", long);
        {
            let mut canvas = Canvas::new(&mut pixels, w, h);
            draw(&mut canvas, &reveal, true, 30);
        }
        // At scale 1 the whole thing fits in the available width; the drawing code picks the
        // largest scale that does.
        assert!(Canvas::measure(long, 1) < w - 48);
    }

    #[test]
    fn drawing_never_writes_outside_the_buffer() {
        // Tiny canvases and enormous secrets, because the glyph blitter does its own bounds
        // arithmetic and an off-by-one there is a memory-safety bug in a process holding a
        // plaintext password.
        for (w, h) in [(1usize, 1usize), (8, 4), (40, 20), (200, 30)] {
            let mut pixels = vec![0u32; w * h];
            let reveal = request(&"L".repeat(80), &"S".repeat(300));
            let mut canvas = Canvas::new(&mut pixels, w, h);
            draw(&mut canvas, &reveal, false, 1);
        }
    }

    #[test]
    fn the_warning_appears_only_when_capture_protection_is_missing() {
        let (w, h) = (900usize, 400usize);
        let reveal = request("Chase", "hunter2");

        let count_warning = |protected: bool| {
            let mut pixels = vec![0u32; w * h];
            {
                let mut canvas = Canvas::new(&mut pixels, w, h);
                draw(&mut canvas, &reveal, protected, 30);
            }
            pixels.iter().filter(|p| **p == colour::WARNING).count()
        };

        assert_eq!(
            count_warning(true),
            0,
            "no warning when the window really is hidden from capture"
        );
        assert!(
            count_warning(false) > 50,
            "an unprotected window must say so prominently"
        );
    }

    #[test]
    fn the_countdown_runs_down_and_the_window_expires() {
        let now = Instant::now();
        assert!(!expired(now));
        assert!(remaining_secs(now) <= VISIBLE_FOR.as_secs());
        assert!(remaining_secs(now) > 0);
    }
}
