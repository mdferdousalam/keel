// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! How weak is an existing password?
//!
//! [`generator`](crate::generator) knows the entropy of passwords *it* produced,
//! because it chose them uniformly and can simply state the size of the space. This
//! module answers the harder question asked of a password that came from somewhere
//! else — typed by a user years ago, or imported from a browser — where the space
//! it was drawn from is unknown and has to be inferred from the string itself.
//!
//! # What this is, and what it is not
//!
//! An attacker guesses in whatever order is cheapest for them, so the useful
//! estimate is **the cheapest model that explains the password**, not the most
//! flattering one. `Tr0ub4dor&3` looks like 11 characters over a 74-character
//! alphabet — about 68 bits — until you notice it is one dictionary word with
//! predictable substitutions, which is worth vastly less. [`estimate_bits`]
//! therefore scores a password under several models and returns the **minimum**.
//!
//! It is deliberately **not** a reimplementation of zxcvbn. zxcvbn models guess
//! *order* over large dictionaries and would be the right tool for telling a user
//! how long their master passphrase would survive; it also costs 37 crates,
//! including a backtracking regex engine and a proc-macro chain, and this code
//! runs inside the one process that holds the master key. That trade is not worth
//! making to answer "is this password obviously terrible?", which is all the vault
//! health report needs.
//!
//! Consequences, stated so nobody reads more into a number than it carries:
//!
//! * It is a **structural lower bound**. A password it scores at 70 bits is not
//!   thereby safe — it only means none of the cheap models this code knows about
//!   explains it. A password it scores low genuinely is weak.
//! * It errs toward **flagging**. For a health report, a false "check this one" is
//!   a minor annoyance; a false "this one is fine" is the failure that matters.
//! * The common-password list is ~300 entries, **not a breach corpus**. A real
//!   corpus is tens of millions of entries behind a Bloom filter, which is a
//!   separate piece of work. Absence from this list means very little.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::generator::{DIGITS, LOWERCASE, SYMBOLS, UPPERCASE};

/// Entropy at or below which a password is reported as weak.
///
/// Set where it is because of what an offline attacker can do *given they already
/// have the vault file*. Argon2id at the balanced tier costs roughly a second per
/// guess on one machine, so 40 bits — about 10^12 guesses — is out of reach for
/// almost anyone. The threshold is well above that because the estimate is a lower
/// bound with known blind spots, and because a password worth flagging is usually
/// far below the line rather than just under it.
pub const WEAK_BITS: f64 = 50.0;

/// Entropy below which a password is alarming rather than merely weak.
///
/// At this level the password falls to a wordlist or an incrementing counter, and
/// the vault's key derivation is the only thing standing between an attacker with
/// the file and the account.
pub const CRITICAL_BITS: f64 = 30.0;

const COMMON_RAW: &str = include_str!("../data/common_passwords.txt");

/// The common-password list, mapped to its guess rank (1 = tried first).
fn common() -> &'static HashMap<&'static str, usize> {
    static COMMON: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
    COMMON.get_or_init(|| {
        COMMON_RAW
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .enumerate()
            .map(|(i, word)| (word, i + 1))
            .collect()
    })
}

/// How severe a password's weakness is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// Falls to a wordlist or a counter. Change it.
    Critical,
    /// Cheap enough to guess offline that it should be replaced.
    Weak,
    /// No cheap model explains it. Not a promise that it is strong.
    Reasonable,
}

impl Strength {
    /// Classify an entropy estimate.
    #[must_use]
    pub fn of_bits(bits: f64) -> Self {
        if bits < CRITICAL_BITS {
            Self::Critical
        } else if bits < WEAK_BITS {
            Self::Weak
        } else {
            Self::Reasonable
        }
    }

    /// A short label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Weak => "weak",
            Self::Reasonable => "reasonable",
        }
    }
}

/// Estimate the entropy of `password`, in bits.
///
/// Returns the **minimum** across every model that applies, because an attacker
/// only needs the cheapest one to work. See the module documentation for what the
/// number does and does not mean.
#[must_use]
pub fn estimate_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut best = charset_bits(password);
    for candidate in [
        common_bits(password),
        segmented_bits(password),
        repeated_chunk_bits(password),
        year_bits(password),
    ]
    .into_iter()
    .flatten()
    {
        best = best.min(candidate);
    }
    // Never report less than the cost of trying the empty-to-this-length space, and
    // never report a negative number out of a log.
    best.max(0.0)
}

/// Classify `password`.
#[must_use]
pub fn strength(password: &str) -> Strength {
    Strength::of_bits(estimate_bits(password))
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

/// The naive model: length times the log of the alphabet the password draws from.
///
/// This is the *upper* bound and the starting point. It is what every password
/// strength meter that gets mocked on the internet reports on its own.
fn charset_bits(password: &str) -> f64 {
    let mut alphabet = 0usize;
    let has = |set: &str| password.chars().any(|c| set.contains(c));
    if has(LOWERCASE) {
        alphabet += LOWERCASE.chars().count();
    }
    if has(UPPERCASE) {
        alphabet += UPPERCASE.chars().count();
    }
    if has(DIGITS) {
        alphabet += DIGITS.chars().count();
    }
    if has(SYMBOLS) {
        alphabet += SYMBOLS.chars().count();
    }
    // Anything outside the four known classes — accented letters, CJK, emoji — is
    // counted conservatively rather than as the full Unicode space, which would let a
    // single emoji claim 20 bits.
    let exotic = password
        .chars()
        .filter(|c| {
            !LOWERCASE.contains(*c)
                && !UPPERCASE.contains(*c)
                && !DIGITS.contains(*c)
                && !SYMBOLS.contains(*c)
        })
        .count();
    if exotic > 0 {
        alphabet += 100;
    }

    let len = password.chars().count();
    if alphabet < 2 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    {
        (alphabet as f64).log2() * len as f64
    }
}

/// Is this a well-known password, possibly with a small decoration?
///
/// Checks the password itself, then again after case-folding and after stripping a
/// trailing digit-or-symbol tail and a leading capital — because `Password1!` is not
/// meaningfully harder to guess than `password`, and a list lookup that misses it
/// would be close to useless in practice.
fn common_bits(password: &str) -> Option<f64> {
    let list = common();
    let lower = password.to_lowercase();

    // A decoration costs the attacker a small multiplier, not a new search space:
    // they append the same handful of suffixes to every dictionary word. Charging
    // ~5 bits per decoration reflects trying a few dozen variants.
    const DECORATION_BITS: f64 = 5.0;

    let mut candidates: Vec<(&str, f64)> = vec![(lower.as_str(), 0.0)];

    // Strip a trailing run of digits and symbols: "password123!" -> "password".
    let stem = lower.trim_end_matches(|c: char| c.is_ascii_digit() || SYMBOLS.contains(c));
    if stem != lower.as_str() && !stem.is_empty() {
        candidates.push((stem, DECORATION_BITS));
    }
    // And leading decoration: "!!password" -> "password".
    let head = stem.trim_start_matches(|c: char| c.is_ascii_digit() || SYMBOLS.contains(c));
    if head != stem && !head.is_empty() {
        candidates.push((head, DECORATION_BITS * 2.0));
    }
    // Undo the obvious substitutions, so "p@ssw0rd" reaches "password". Note the
    // list also contains p@ssw0rd directly; this catches the ones it does not.
    let unleeted: String = head
        .chars()
        .map(|c| match c {
            '@' => 'a',
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '$' => 's',
            other => other,
        })
        .collect();
    if unleeted != head {
        candidates.push((unleeted.as_str(), DECORATION_BITS));
    }

    candidates
        .iter()
        .filter_map(|(candidate, penalty)| {
            list.get(*candidate).map(|rank| {
                #[allow(clippy::cast_precision_loss)]
                let rank_bits = (*rank as f64).log2();
                rank_bits + penalty
            })
        })
        .fold(None, |acc: Option<f64>, bits| {
            Some(acc.map_or(bits, |a: f64| a.min(bits)))
        })
}

/// Decompose the password into structural segments and charge for each.
///
/// The interesting model, and the one that catches most real weak passwords. A
/// cracker does not guess `123456789012` character by character; it guesses "a
/// counting run, then another counting run". So the password is split into maximal
/// segments — a run through consecutive codepoints, a repeated character, or a
/// literal — and each is charged what it costs to *describe*, not what it costs to
/// brute-force.
///
/// Two properties make this safe to take a minimum with:
///
/// * A password with no structure segments entirely into literals, so the result is
///   exactly [`charset_bits`]. The model can therefore never invent entropy — it
///   only ever discounts, which is the invariant
///   `the_estimate_never_exceeds_the_naive_model` pins.
/// * Discounts are local. A single accidental three-character run in an otherwise
///   random password costs it about ten bits out of a hundred-plus, so generated
///   passwords are not dragged below the threshold by chance.
fn segmented_bits(password: &str) -> Option<f64> {
    let chars: Vec<char> = password.chars().collect();
    let n = chars.len();
    if n < 3 {
        return None;
    }

    // Per-character cost under the naive model, so an unstructured password
    // reproduces `charset_bits` exactly.
    #[allow(clippy::cast_precision_loss)]
    let per_char = charset_bits(password) / n as f64;
    if per_char <= 0.0 {
        return None;
    }

    // Shortest structure worth recognising. Two characters in sequence happens
    // constantly by chance and means nothing.
    const MIN_STRUCTURE: usize = 3;

    /// Codepoint distance, wide enough that no pair of `char`s can overflow it.
    fn step_between(a: char, b: char) -> i64 {
        i64::from(u32::from(b)) - i64::from(u32::from(a))
    }

    let mut total = 0.0f64;
    let mut structured = false;
    // Walked as a shrinking slice rather than by index, so there is no arithmetic
    // that could run off the end.
    let mut rest: &[char] = &chars;

    while let Some((&first, tail)) = rest.split_first() {
        // Longest run of consecutive codepoints starting here, in either direction.
        let mut run = 1usize;
        if let Some(&second) = tail.first() {
            let step = step_between(first, second);
            if step == 1 || step == -1 {
                run = 2;
                while let (Some(&a), Some(&b)) = (rest.get(run - 1), rest.get(run)) {
                    if step_between(a, b) != step {
                        break;
                    }
                    run += 1;
                }
            }
        }

        // Longest repeat of one character starting here.
        let repeat = 1 + tail.iter().take_while(|&&c| c == first).count();

        #[allow(clippy::cast_precision_loss)]
        let advance = if run >= MIN_STRUCTURE && run >= repeat {
            // Choose a starting character, a direction, and a length.
            total += per_char + 1.0 + (run as f64).log2();
            structured = true;
            run
        } else if repeat >= MIN_STRUCTURE {
            // Choose a character and a length.
            total += per_char + (repeat as f64).log2();
            structured = true;
            repeat
        } else {
            total += per_char;
            1
        };
        rest = rest.get(advance..).unwrap_or(&[]);
    }

    // Nothing was found, so this is just the naive model restated. Returning None
    // keeps the caller's minimum honest about which models actually applied.
    structured.then_some(total)
}

/// A short chunk repeated to fill the length: `abcabcabc`, `123123`.
///
/// Costs the attacker the chunk, plus the repeat count — so the entropy is that of
/// the chunk alone, not of the whole string.
fn repeated_chunk_bits(password: &str) -> Option<f64> {
    let chars: Vec<char> = password.chars().collect();
    let len = chars.len();
    if len < 4 {
        return None;
    }
    // Only chunks that tile the string exactly, and at least twice. Bounded by
    // `chunk * 2 <= len` rather than `len / 2` so there is no division to justify.
    for chunk in 1..len {
        if chunk * 2 > len {
            break;
        }
        if !len.is_multiple_of(chunk) {
            continue;
        }
        let Some(unit) = chars.get(..chunk) else {
            continue;
        };
        if chars.chunks(chunk).all(|c| c == unit) {
            let unit: String = unit.iter().collect();
            // The repeat count is a handful of possibilities on top of the chunk.
            return Some(charset_bits(&unit) + 3.0);
        }
    }
    None
}

/// A bare year or date-like number: `1987`, `20240101`.
///
/// Years are the single most common numeric password, and there are not many of
/// them anyone picks.
fn year_bits(password: &str) -> Option<f64> {
    if !password.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let len = password.chars().count();
    // A four-digit number that looks like a year someone would choose.
    if len == 4 {
        let n: u32 = password.parse().ok()?;
        if (1900..=2100).contains(&n) {
            // ~200 plausible years.
            return Some(7.6);
        }
        // Any other four digits: 10^4.
        return Some(13.3);
    }
    // Longer all-digit strings: charged as pure digits, which `charset_bits` already
    // does, but dates in the common formats are a much smaller space.
    if len == 6 || len == 8 {
        // ~40000 plausible dates in ddmmyy / yyyymmdd shapes.
        return Some(15.3);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_thresholds_are_ordered() {
        const _: () = assert!(CRITICAL_BITS < WEAK_BITS);
    }

    #[test]
    fn an_empty_password_has_no_entropy() {
        assert_eq!(estimate_bits(""), 0.0);
        assert_eq!(strength(""), Strength::Critical);
    }

    #[test]
    fn the_passwords_everyone_tries_first_are_critical() {
        for password in [
            "123456", "password", "qwerty", "letmein", "iloveyou", "admin", "monkey", "dragon",
            "abc123",
        ] {
            assert_eq!(
                strength(password),
                Strength::Critical,
                "{password:?} should be critical, scored {:.1} bits",
                estimate_bits(password)
            );
        }
    }

    #[test]
    fn decorating_a_common_password_does_not_rescue_it() {
        // The lesson every password policy teaches and no attacker respects. A
        // list lookup that missed these would be close to useless in practice.
        for password in [
            "Password1",
            "password123",
            "password!",
            "Password1!",
            "p@ssw0rd",
            "P@ssw0rd!",
            "letmein1",
            "!!qwerty",
        ] {
            let bits = estimate_bits(password);
            assert!(
                bits < WEAK_BITS,
                "{password:?} should still be weak, scored {bits:.1} bits"
            );
        }
    }

    #[test]
    fn structure_is_charged_for_rather_than_counted_as_length() {
        // Each of these would look respectable to a naive length-times-alphabet
        // meter, and is worth almost nothing.
        let cases = [
            ("aaaaaaaaaaaaaaaaaaaa", "one repeated character"),
            ("abcdefghijklmnop", "an alphabet run"),
            ("123456789012", "a digit run"),
            ("abcabcabcabc", "a repeated chunk"),
            ("1987", "a year"),
        ];
        for (password, why) in cases {
            let naive = charset_bits(password);
            let actual = estimate_bits(password);
            assert!(
                actual < naive,
                "{password:?} ({why}) should score below the naive {naive:.1} bits, got {actual:.1}"
            );
            assert!(
                actual < WEAK_BITS,
                "{password:?} ({why}) should be weak, got {actual:.1} bits"
            );
        }
    }

    #[test]
    fn generated_passwords_are_not_flagged() {
        // The generator's own output must clear the bar, or the health report would
        // nag about the passwords Bitting itself produced. This is the property that
        // keeps the thresholds honest.
        let policy = crate::generator::PasswordPolicy::default();
        for _ in 0..200 {
            let password = crate::generator::generate_password(&policy).unwrap();
            let bits = estimate_bits(password.expose());
            assert!(
                bits >= WEAK_BITS,
                "generated {:?} scored only {bits:.1} bits",
                password.expose()
            );
        }
    }

    #[test]
    fn generated_passphrases_are_not_flagged() {
        let policy = crate::generator::PassphrasePolicy::default();
        for _ in 0..200 {
            let phrase = crate::generator::generate_passphrase(&policy).unwrap();
            let bits = estimate_bits(phrase.expose());
            assert!(
                bits >= WEAK_BITS,
                "generated {:?} scored only {bits:.1} bits",
                phrase.expose()
            );
        }
    }

    #[test]
    fn the_estimate_never_exceeds_the_naive_model() {
        // The whole design is "minimum across models". If any model could report
        // *more* than length-times-alphabet, it would be inventing entropy.
        for password in [
            "a",
            "ab",
            "correct horse battery staple",
            "Tr0ub4dor&3",
            "xkcd",
            "9",
            "aaaa",
            "1234",
            "zzzzzzzzzzzz",
            "P@ssw0rd",
            "sd8f7g6sd8f7g",
        ] {
            let naive = charset_bits(password);
            let actual = estimate_bits(password);
            assert!(
                actual <= naive + f64::EPSILON,
                "{password:?}: {actual:.2} bits exceeds the naive {naive:.2}"
            );
        }
    }

    #[test]
    fn estimation_never_panics_on_awkward_input() {
        // This runs over user data imported from other password managers, so it will
        // meet everything: emoji, combining marks, lone surrogates' UTF-8 cousins,
        // very long strings, and control characters.
        for password in [
            "\u{0}",
            "\u{7f}",
            "é",
            "ééééééé",
            "🔐🔐🔐",
            "a\u{301}",
            "  ",
            "\t\n",
            "ﬀ",
            "𝕡𝕒𝕤𝕤",
            "日本語のパスワード",
        ] {
            let bits = estimate_bits(password);
            assert!(bits.is_finite() && bits >= 0.0, "{password:?} -> {bits}");
        }
        let long = "a".repeat(10_000);
        assert!(estimate_bits(&long).is_finite());
        let long_mixed: String = (0..5000)
            .map(|i| char::from(b'a' + (i % 26) as u8))
            .collect();
        assert!(estimate_bits(&long_mixed).is_finite());
    }

    #[test]
    fn a_single_character_is_not_reported_as_reasonable() {
        for password in ["a", "1", "!", "Z"] {
            assert_ne!(strength(password), Strength::Reasonable, "{password:?}");
        }
    }

    #[test]
    fn the_common_list_parses_and_has_no_duplicates() {
        let list = common();
        assert!(list.len() > 250, "list shrank unexpectedly: {}", list.len());
        // A duplicate would silently take the later, weaker rank and make the list
        // shorter than it looks.
        let lines: Vec<&str> = COMMON_RAW
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert_eq!(
            lines.len(),
            list.len(),
            "the common-password list contains duplicates"
        );
        // Comments and blanks must not have become entries.
        assert!(!list.contains_key(""));
        for entry in list.keys() {
            assert!(
                !entry.starts_with('#'),
                "comment leaked into the list: {entry}"
            );
            assert_eq!(
                *entry,
                entry.to_lowercase(),
                "list entries must be lowercase: {entry}"
            );
        }
    }

    #[test]
    fn rank_order_makes_earlier_entries_weaker() {
        // "123456" is tried before "webcam", and the estimate should say so.
        assert!(estimate_bits("123456") < estimate_bits("webcam"));
    }
}
