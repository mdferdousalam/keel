//! Password and passphrase generation.
//!
//! Two details here are easy to get wrong and are the reason this module exists
//! rather than a few lines inline at each call site:
//!
//! 1. **Modulo bias.** `random_u32() % alphabet_len` is *not* uniform unless the
//!    alphabet size divides 2^32. With an 88-character alphabet the first 32
//!    characters become measurably more likely than the rest, quietly costing
//!    entropy. [`uniform_below`] uses rejection sampling instead.
//! 2. **Character-class requirements.** Satisfying "must contain a digit" by
//!    overwriting a position with a digit destroys entropy at that position and
//!    makes the result predictable in structure. We generate, check, and
//!    regenerate instead — which keeps the output uniform over exactly the set of
//!    strings that satisfy the policy.
//!
//! Entropy comes straight from the OS CSPRNG via
//! [`fill_random`](crate::secret::fill_random). There is no userspace RNG here:
//! no seed to leak, no state to duplicate across a `fork`, nothing to reseed
//! wrong.

use std::sync::OnceLock;

use crate::error::{Error, Result};
use crate::secret::{fill_random, SecretString};

/// Lowercase letters.
pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
/// Uppercase letters.
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Decimal digits.
pub const DIGITS: &str = "0123456789";

/// Symbol set: 26 characters.
///
/// Deliberately excludes the shell- and quoting-hostile characters
/// `` ` ``, `'`, `"`, `\`, `|`, `~`, and space. Those cause real breakage when a
/// password is pasted into a config file, a connection string, or a shell
/// command, and dropping them costs only a fraction of a bit per character.
pub const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{}";

/// Characters excluded when `exclude_ambiguous` is set.
///
/// These are the pairs people actually misread when transcribing a password from
/// a screen or a printed recovery sheet.
pub const AMBIGUOUS: &str = "0O1lI";

/// Number of words in the bundled EFF long wordlist.
pub const WORDLIST_LEN: usize = 7776;

/// Entropy per word from the bundled wordlist: log2(7776).
pub const BITS_PER_WORD: f64 = 12.925_452_9;

/// How many times to retry when a character-class requirement is unmet.
///
/// For a 20-character password over the full alphabet the probability of needing
/// even a second attempt is negligible; this bound exists only so a pathological
/// policy fails with an error instead of hanging.
const MAX_CLASS_ATTEMPTS: usize = 10_000;

const WORDLIST_RAW: &str = include_str!("../data/eff_long_wordlist.txt");

fn wordlist() -> &'static Vec<&'static str> {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST_RAW
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect()
    })
}

/// Draw a uniformly distributed integer in `0..n` from the OS CSPRNG.
///
/// Rejection sampling: values at or above the largest multiple of `n` that fits
/// in a `u32` are discarded and redrawn. Expected draws are under 2 for any `n`.
fn uniform_below(n: u32) -> Result<u32> {
    if n == 0 {
        return Err(Error::Policy("empty alphabet"));
    }
    let n64 = u64::from(n);
    // Largest multiple of n that fits in the u32 range. The truncating division
    // is the entire point: `bound` must be a multiple of n so that the accepted
    // range maps onto 0..n with no residue, which is what removes modulo bias.
    #[allow(clippy::integer_division)]
    let bound = (u64::from(u32::MAX) + 1) / n64 * n64;
    loop {
        let mut buf = [0u8; 4];
        fill_random(&mut buf)?;
        let x = u64::from(u32::from_le_bytes(buf));
        if x < bound {
            return Ok(u32::try_from(x % n64).unwrap_or(0));
        }
    }
}

/// Pick one uniformly random element of `items`.
fn choose<T>(items: &[T]) -> Result<&T> {
    let n = u32::try_from(items.len()).map_err(|_| Error::Policy("alphabet too large"))?;
    let idx = uniform_below(n)? as usize;
    items.get(idx).ok_or(Error::Policy("index out of range"))
}

// ---------------------------------------------------------------------------
// Character-based passwords
// ---------------------------------------------------------------------------

/// Which character classes a generated password may and must draw from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Number of characters to generate.
    pub length: usize,
    /// Include lowercase letters.
    pub lowercase: bool,
    /// Include uppercase letters.
    pub uppercase: bool,
    /// Include digits.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
    /// Drop easily-confused characters (see [`AMBIGUOUS`]).
    pub exclude_ambiguous: bool,
    /// Require at least one character from every enabled class.
    ///
    /// Enable this only when a site demands it. It slightly *reduces* entropy
    /// (the output is uniform over a subset of all strings) and its only benefit
    /// is satisfying a validator.
    pub require_each_class: bool,
}

impl Default for PasswordPolicy {
    /// 20 characters over the full 88-character alphabet: about 129 bits.
    ///
    /// Long enough that the password itself will never be the weak link, short
    /// enough to remain paste-able into fields with length limits.
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            require_each_class: false,
        }
    }
}

impl PasswordPolicy {
    /// The enabled character classes, as separate alphabets.
    ///
    /// Kept separate rather than concatenated so `require_each_class` can check
    /// membership per class.
    fn classes(&self) -> Vec<Vec<char>> {
        let mut out = Vec::new();
        for (enabled, set) in [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ] {
            if !enabled {
                continue;
            }
            let chars: Vec<char> = set
                .chars()
                .filter(|c| !(self.exclude_ambiguous && AMBIGUOUS.contains(*c)))
                .collect();
            if !chars.is_empty() {
                out.push(chars);
            }
        }
        out
    }

    /// Total alphabet size for this policy.
    #[must_use]
    pub fn alphabet_size(&self) -> usize {
        self.classes().iter().map(Vec::len).sum()
    }

    /// Estimated entropy in bits.
    ///
    /// This is `length × log2(alphabet_size)`. When `require_each_class` is set
    /// the true value is very slightly lower, because the output is uniform over
    /// the subset of strings containing every class; the difference is under a
    /// bit for realistic lengths, and this figure is an upper bound.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        let n = self.alphabet_size();
        if n < 2 || self.length == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            (n as f64).log2() * self.length as f64
        }
    }

    fn validate(&self) -> Result<()> {
        if self.length == 0 {
            return Err(Error::Policy("length must be at least 1"));
        }
        if self.length > 1024 {
            return Err(Error::Policy("length must be at most 1024"));
        }
        let classes = self.classes();
        if classes.is_empty() {
            return Err(Error::Policy(
                "at least one character class must be enabled",
            ));
        }
        if self.alphabet_size() < 2 {
            return Err(Error::Policy("alphabet must contain at least 2 characters"));
        }
        if self.require_each_class && self.length < classes.len() {
            return Err(Error::Policy(
                "length is too short to contain one character from every required class",
            ));
        }
        Ok(())
    }
}

/// Generate a password according to `policy`.
pub fn generate_password(policy: &PasswordPolicy) -> Result<SecretString> {
    policy.validate()?;
    let classes = policy.classes();
    let alphabet: Vec<char> = classes.iter().flatten().copied().collect();

    for _ in 0..MAX_CLASS_ATTEMPTS {
        let mut out = SecretString::with_capacity(policy.length * 4);
        for _ in 0..policy.length {
            out.push(*choose(&alphabet)?)?;
        }
        if !policy.require_each_class || has_every_class(out.expose(), &classes) {
            return Ok(out);
        }
        // Discard and redraw. Never patch a character into place: that would
        // fix the class at a known position and leak structure.
    }
    Err(Error::Policy(
        "could not satisfy character-class requirements; loosen the policy",
    ))
}

fn has_every_class(candidate: &str, classes: &[Vec<char>]) -> bool {
    classes
        .iter()
        .all(|class| candidate.chars().any(|c| class.contains(&c)))
}

// ---------------------------------------------------------------------------
// Passphrases
// ---------------------------------------------------------------------------

/// How to build a diceware passphrase from the bundled EFF long wordlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassphrasePolicy {
    /// Number of words. Each contributes 12.925 bits.
    pub words: usize,
    /// Character placed between words.
    ///
    /// Defaults to `-`, matching what every other password manager uses and what users expect
    /// to type. Note that four words in the bundled list contain a hyphen, so a
    /// hyphen-separated phrase cannot always be split back into its words unambiguously. That
    /// costs no entropy — words are chosen by index, never by their text — but code that needs
    /// to count words must not do it by splitting on the separator.
    pub separator: char,
    /// Capitalize the first letter of each word.
    ///
    /// Adds no entropy — it is a deterministic transform — and is offered only
    /// because some sites require an uppercase character.
    pub capitalize: bool,
}

impl Default for PassphrasePolicy {
    /// Six words: about 77.5 bits.
    fn default() -> Self {
        Self {
            words: 6,
            separator: '-',
            capitalize: false,
        }
    }
}

impl PassphrasePolicy {
    /// Recommended policy for a **master** passphrase: seven words, ~90.5 bits.
    ///
    /// The master passphrase is the one secret that is never protected by
    /// anything else, so it gets the extra word.
    #[must_use]
    pub fn master() -> Self {
        Self {
            words: 7,
            separator: '-',
            capitalize: false,
        }
    }

    /// Estimated entropy in bits.
    ///
    /// Capitalization and the separator are deterministic transforms and
    /// contribute nothing, so they are correctly absent from this calculation.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        {
            BITS_PER_WORD * self.words as f64
        }
    }

    fn validate(&self) -> Result<()> {
        if self.words == 0 {
            return Err(Error::Policy("passphrase must have at least 1 word"));
        }
        if self.words > 64 {
            return Err(Error::Policy("passphrase must have at most 64 words"));
        }
        Ok(())
    }
}

/// Generate a diceware passphrase.
///
/// Words are drawn uniformly *with* replacement. Drawing without replacement
/// would slightly increase entropy but makes the calculation harder to state
/// honestly; with replacement, `words × 12.925` is exactly right.
pub fn generate_passphrase(policy: &PassphrasePolicy) -> Result<SecretString> {
    policy.validate()?;
    let words = wordlist();
    // Longest word is 9 chars; 16 per word plus separators is generous.
    let mut out = SecretString::with_capacity(policy.words * 16 + policy.words);
    for i in 0..policy.words {
        if i > 0 {
            out.push(policy.separator)?;
        }
        let word = choose(words)?;
        if policy.capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                for c in first.to_uppercase() {
                    out.push(c)?;
                }
                out.push_str(chars.as_str())?;
            }
        } else {
            out.push_str(word)?;
        }
    }
    Ok(out)
}

/// Number of words available in the bundled wordlist.
///
/// Should always equal [`WORDLIST_LEN`]; exposed so a startup self-check can
/// confirm the embedded data was not truncated.
#[must_use]
pub fn wordlist_len() -> usize {
    wordlist().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn default_alphabet_is_88_characters() {
        // The documented "~129 bits at 20 characters" claim depends on this.
        let p = PasswordPolicy::default();
        assert_eq!(p.alphabet_size(), 88);
        assert_eq!(LOWERCASE.chars().count(), 26);
        assert_eq!(UPPERCASE.chars().count(), 26);
        assert_eq!(DIGITS.chars().count(), 10);
        assert_eq!(SYMBOLS.chars().count(), 26);
    }

    #[test]
    fn symbol_set_excludes_quoting_hazards() {
        for bad in ['\'', '"', '\\', '`', '|', '~', ' '] {
            assert!(
                !SYMBOLS.contains(bad),
                "symbol set must not contain {bad:?}"
            );
        }
    }

    #[test]
    fn default_entropy_is_about_129_bits() {
        let bits = PasswordPolicy::default().entropy_bits();
        assert!((129.0..130.0).contains(&bits), "got {bits}");
    }

    #[test]
    fn generated_password_has_requested_length_and_valid_characters() {
        let p = PasswordPolicy::default();
        let pw = generate_password(&p).unwrap();
        assert_eq!(pw.expose().chars().count(), 20);
        let allowed: HashSet<char> = p.classes().into_iter().flatten().collect();
        for c in pw.expose().chars() {
            assert!(allowed.contains(&c), "unexpected character {c:?}");
        }
    }

    #[test]
    fn passwords_do_not_repeat() {
        let p = PasswordPolicy::default();
        let mut seen = HashSet::new();
        for _ in 0..50 {
            let pw = generate_password(&p).unwrap();
            assert!(
                seen.insert(pw.expose().to_owned()),
                "generator repeated itself"
            );
        }
    }

    #[test]
    fn exclude_ambiguous_removes_exactly_those_characters() {
        let p = PasswordPolicy {
            length: 200,
            exclude_ambiguous: true,
            ..PasswordPolicy::default()
        };
        assert_eq!(p.alphabet_size(), 88 - AMBIGUOUS.chars().count());
        let pw = generate_password(&p).unwrap();
        for c in AMBIGUOUS.chars() {
            assert!(!pw.expose().contains(c), "{c:?} should have been excluded");
        }
    }

    #[test]
    fn single_class_policies_work() {
        let p = PasswordPolicy {
            length: 32,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            ..PasswordPolicy::default()
        };
        let pw = generate_password(&p).unwrap();
        assert!(pw.expose().chars().all(|c| c.is_ascii_digit()));
        assert_eq!(p.alphabet_size(), 10);
    }

    #[test]
    fn require_each_class_is_satisfied() {
        let p = PasswordPolicy {
            length: 8,
            require_each_class: true,
            ..PasswordPolicy::default()
        };
        for _ in 0..40 {
            let pw = generate_password(&p).unwrap();
            let s = pw.expose();
            assert!(
                s.chars().any(|c| LOWERCASE.contains(c)),
                "no lowercase in {s}"
            );
            assert!(
                s.chars().any(|c| UPPERCASE.contains(c)),
                "no uppercase in {s}"
            );
            assert!(s.chars().any(|c| DIGITS.contains(c)), "no digit in {s}");
            assert!(s.chars().any(|c| SYMBOLS.contains(c)), "no symbol in {s}");
        }
    }

    #[test]
    fn impossible_policies_are_rejected_not_looped() {
        // Four required classes cannot fit in three characters.
        let p = PasswordPolicy {
            length: 3,
            require_each_class: true,
            ..PasswordPolicy::default()
        };
        assert!(matches!(generate_password(&p), Err(Error::Policy(_))));

        // No classes enabled at all.
        let p = PasswordPolicy {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordPolicy::default()
        };
        assert!(matches!(generate_password(&p), Err(Error::Policy(_))));

        // Zero length.
        let p = PasswordPolicy {
            length: 0,
            ..PasswordPolicy::default()
        };
        assert!(matches!(generate_password(&p), Err(Error::Policy(_))));
    }

    #[test]
    fn wordlist_is_complete() {
        assert_eq!(wordlist_len(), WORDLIST_LEN);
        let unique: HashSet<_> = wordlist().iter().collect();
        assert_eq!(unique.len(), WORDLIST_LEN, "wordlist has duplicates");
        for w in wordlist() {
            assert!(w.len() >= 3, "suspiciously short word {w:?}");
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "unexpected characters in {w:?}"
            );
        }
    }

    #[test]
    fn passphrase_has_requested_word_count() {
        // Counted with a separator that cannot occur inside a word. Splitting on the *default*
        // separator would be wrong: four EFF words contain a hyphen ("drop-down", "felt-tip",
        // "t-shirt", "yo-yo"), so `split('-')` over-counts about 0.3% of six-word phrases.
        // An earlier version of this test did exactly that and failed once every few hundred
        // runs.
        let policy = PassphrasePolicy {
            separator: ' ',
            ..PassphrasePolicy::default()
        };
        let phrase = generate_passphrase(&policy).unwrap();
        assert_eq!(phrase.expose().split(' ').count(), 6);

        for words in [3usize, 7, 12] {
            let policy = PassphrasePolicy {
                words,
                separator: ' ',
                capitalize: false,
            };
            let phrase = generate_passphrase(&policy).unwrap();
            assert_eq!(phrase.expose().split(' ').count(), words);
        }
    }

    #[test]
    fn a_hyphen_separator_can_produce_more_hyphens_than_word_boundaries() {
        // Documents the consequence of the default separator, so nobody "fixes" a passphrase
        // counter by splitting on it again.
        //
        // Four words in the EFF list contain a hyphen, so a hyphen-separated phrase is not
        // unambiguously splittable. This costs no entropy — words are chosen by index, not by
        // their text — and the hyphen is kept as the default because it is the convention every
        // other password manager uses and what users expect to type. The only cost is that a
        // human reading a phrase back cannot always tell where one word ended.
        let hyphenated: Vec<&&str> = wordlist().iter().filter(|w| w.contains('-')).collect();
        assert!(
            !hyphenated.is_empty(),
            "this test is meaningless if the wordlist has no hyphenated words"
        );
        assert_eq!(
            hyphenated.len(),
            4,
            "wordlist changed; revisit the note above"
        );

        // Construct the situation directly rather than waiting for chance.
        let phrase = format!("alpha-{}-omega", hyphenated[0]);
        assert!(
            phrase.split('-').count() > 3,
            "a hyphenated word should split into more parts than there are words"
        );
    }

    #[test]
    fn passphrase_words_come_from_the_wordlist() {
        // Hyphen is both the default separator and a character inside four EFF
        // words, so reassemble rather than assuming a clean split.
        let list: HashSet<&str> = wordlist().iter().copied().collect();
        let p = PassphrasePolicy {
            separator: ' ',
            ..PassphrasePolicy::default()
        };
        let phrase = generate_passphrase(&p).unwrap();
        for word in phrase.expose().split(' ') {
            assert!(list.contains(word), "{word:?} is not in the wordlist");
        }
    }

    #[test]
    fn master_passphrase_entropy_exceeds_90_bits() {
        let bits = PassphrasePolicy::master().entropy_bits();
        assert!(bits > 90.0, "got {bits}");
        assert!((77.0..78.0).contains(&PassphrasePolicy::default().entropy_bits()));
    }

    #[test]
    fn capitalize_uppercases_each_word_without_changing_word_count() {
        let p = PassphrasePolicy {
            words: 4,
            separator: ' ',
            capitalize: true,
        };
        let phrase = generate_passphrase(&p).unwrap();
        let words: Vec<&str> = phrase.expose().split(' ').collect();
        assert_eq!(words.len(), 4);
        for w in words {
            let first = w.chars().next().unwrap();
            assert!(first.is_ascii_uppercase(), "{w:?} not capitalized");
        }
    }

    #[test]
    fn passphrases_do_not_repeat() {
        let p = PassphrasePolicy::default();
        let mut seen = HashSet::new();
        for _ in 0..50 {
            let phrase = generate_passphrase(&p).unwrap();
            assert!(seen.insert(phrase.expose().to_owned()));
        }
    }

    #[test]
    fn uniform_below_stays_in_range_and_covers_it() {
        // A modulo-bias bug would still stay in range, so also check that every
        // value is reachable — a biased generator usually starves the tail.
        let mut seen = HashSet::new();
        for _ in 0..4000 {
            let v = uniform_below(7).unwrap();
            assert!(v < 7);
            seen.insert(v);
        }
        assert_eq!(seen.len(), 7, "some values were never produced");
    }

    #[test]
    fn uniform_below_is_not_visibly_biased() {
        // With 88 buckets and 88_000 draws, each bucket expects 1000. A modulo
        // implementation over u32 would skew the first 32 buckets by ~0.000002%
        // which this cannot catch, but a *bad* bias (e.g. `% n` over a u8 draw)
        // shows up immediately as a 2x skew.
        const N: u32 = 88;
        const DRAWS: usize = 88_000;
        let mut counts = vec![0usize; N as usize];
        for _ in 0..DRAWS {
            let v = uniform_below(N).unwrap() as usize;
            counts[v] += 1;
        }
        let expected = DRAWS / N as usize;
        for (bucket, &count) in counts.iter().enumerate() {
            let lo = expected * 6 / 10;
            let hi = expected * 14 / 10;
            assert!(
                (lo..=hi).contains(&count),
                "bucket {bucket} got {count}, expected around {expected}"
            );
        }
    }

    #[test]
    fn uniform_below_handles_one_and_rejects_zero() {
        assert_eq!(uniform_below(1).unwrap(), 0);
        assert!(uniform_below(0).is_err());
    }

    #[test]
    fn generated_secrets_never_appear_in_debug_output() {
        let pw = generate_password(&PasswordPolicy::default()).unwrap();
        assert!(!format!("{pw:?}").contains(pw.expose()));
    }
}
