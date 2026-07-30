//! The vault health report: which stored passwords need attention.
//!
//! Three questions, in descending order of how much the answer matters:
//!
//! 1. **Which passwords are reused?** The highest-value signal in the report, and
//!    the only one no strength meter can give you. A reused password converts any
//!    single site's breach into a compromise of every account sharing it, which is
//!    how most account takeovers actually happen. It also needs no estimation and no
//!    heuristics — either two entries share a password or they do not.
//! 2. **Which passwords are weak?** See
//!    [`keel_crypto::strength`](keel_crypto::strength) for exactly how much that
//!    judgement is worth. Short version: it recognises cheap structure and a few
//!    hundred famous passwords, it is a lower bound, and it errs toward flagging.
//! 3. **Which passwords are old?** Weak evidence on its own — rotating a strong
//!    unique password on a schedule is security theatre, and NIST stopped
//!    recommending it years ago. It is included because age is genuinely
//!    informative *in combination*: a password set eight years ago predates most
//!    users' understanding of password managers, and predates the breaches whose
//!    corpora it may now sit in.
//!
//! # The rule this module exists to obey
//!
//! Producing the report requires decrypting **every record in the vault** — it is
//! the single most secret-exposing operation Keel performs. Two consequences are
//! designed in rather than hoped for:
//!
//! * **No secret value, and no derivative from which one could be recovered, ever
//!   leaves this module.** Reuse is detected by grouping *keyed* hashes, and those
//!   hashes are dropped before the report is returned. [`Report`] contains entry
//!   ids, titles, and numbers, and there is a test asserting a canary password
//!   appears nowhere in its serialised form.
//! * **It is not an operation any automated client can perform.** The policy engine
//!   restricts it to human-driven clients; see
//!   [`Operation::VaultHealth`](crate::policy::Operation::VaultHealth). An MCP
//!   client that could ask "which of these entries share a password?" would have a
//!   bulk oracle over the whole vault, which is precisely the shape of the thing
//!   the tool surface is designed to withhold.

use std::collections::HashMap;

use keel_crypto::strength::Strength;
use keel_format::manifest::EntryMeta;
use keel_format::Id;

/// Age, in days, past which a password is reported as old.
///
/// A year is long enough that a user who rotates on any deliberate schedule is not
/// nagged, and short enough that the genuinely forgotten ones surface.
pub const STALE_DAYS: u64 = 365;

/// Seconds in a day.
const DAY: u64 = 86_400;

/// One entry's assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryHealth {
    /// Which entry.
    pub id: Id,
    /// Its title, so the report is readable without a second lookup.
    pub title: String,
    /// Username, to disambiguate several entries for one site.
    pub username: String,
    /// Estimated entropy, in bits, rounded to whole bits.
    ///
    /// Rounded because a fractional bit implies a precision this estimate does not
    /// have, and because the exact value is a slightly finer fingerprint of the
    /// password than the report needs to carry.
    pub bits: u32,
    /// How bad that is.
    pub strength: Strength,
    /// Days since the password was last changed.
    pub age_days: u64,
    /// How many *other* entries share this exact password.
    ///
    /// Zero for a unique password. This is a count, never a pointer to the others:
    /// see [`Report::reused`] for the grouping.
    pub shared_with: usize,
}

impl EntryHealth {
    /// Whether this entry is worth the user's attention at all.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.shared_with > 0 || self.strength != Strength::Reasonable || self.age_days > STALE_DAYS
    }
}

/// A set of entries sharing one password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReuseGroup {
    /// The entries that share a password. Always two or more.
    ///
    /// Note what this deliberately omits: any representation of the shared value.
    /// Knowing *that* three entries match is what the user needs to act; knowing
    /// what they match on is not.
    pub entries: Vec<EntryHealth>,
}

/// The whole report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Entries examined.
    pub examined: usize,
    /// Entries whose record could not be decrypted, and were therefore skipped.
    ///
    /// Non-zero means a damaged vault, and the report says so rather than quietly
    /// producing a clean bill of health for a vault it could not fully read.
    pub unreadable: usize,
    /// Entries with no password stored at all — a note, or a federated "sign in
    /// with Google" record. Not a problem, but they are not healthy passwords
    /// either, so they are counted separately rather than scored as empty.
    pub without_password: usize,
    /// Groups of entries sharing a password, largest group first.
    pub reused: Vec<ReuseGroup>,
    /// Entries below the weak threshold, weakest first.
    pub weak: Vec<EntryHealth>,
    /// Entries older than [`STALE_DAYS`], oldest first.
    pub stale: Vec<EntryHealth>,
}

impl Report {
    /// Total entries flagged for any reason, counting each entry once.
    ///
    /// An entry can be reused *and* weak *and* old; summing the three lists would
    /// overstate the problem, and a report that inflates its own findings trains
    /// users to ignore it.
    #[must_use]
    pub fn flagged(&self) -> usize {
        let mut ids: Vec<&Id> = Vec::new();
        for group in &self.reused {
            ids.extend(group.entries.iter().map(|e| &e.id));
        }
        ids.extend(self.weak.iter().map(|e| &e.id));
        ids.extend(self.stale.iter().map(|e| &e.id));
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    }

    /// Whether anything needs the user's attention.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.reused.is_empty() && self.weak.is_empty() && self.stale.is_empty()
    }
}

/// What the caller must supply per entry: its metadata, and its password if it has
/// one.
///
/// Taking already-decrypted values rather than the vault itself keeps this module
/// free of decryption and I/O: it does no key handling, so it cannot be the thing
/// that leaks a record, and it is testable without building a vault at all. The
/// borrow means nothing is copied on the way in either.
pub struct Candidate<'a> {
    /// Entry metadata.
    pub meta: &'a EntryMeta,
    /// The decrypted password, or `None` if the entry stores no password.
    pub password: Option<&'a str>,
}

/// Written by hand, never derived.
///
/// The crate requires every public type to be `Debug`, and a derived one here would
/// put a plaintext password into any log line, panic message, or error that
/// formatted a `Candidate`. This prints whether a password is present and how long
/// it is, which is all a diagnostic needs.
impl core::fmt::Debug for Candidate<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Candidate")
            .field("meta", &self.meta)
            .field("password", &self.password.map(str::len))
            .finish()
    }
}

/// Build the report.
///
/// `now` is Unix seconds, passed in rather than read so the result is deterministic
/// and testable.
///
/// # Reuse detection
///
/// Grouping is by *keyed* BLAKE3 hash of the password, with a key generated for
/// this call and dropped with it. An unkeyed hash would be a portable verifier: it
/// could be compared against a precomputed table, or against a hash of a guess, by
/// anything that later read it out of memory or out of a log. Keying it means the
/// grouping works and the grouping key is useless the moment this function returns.
#[must_use]
pub fn assess(candidates: &[Candidate<'_>], now: u64) -> Report {
    let mut report = Report::default();

    // Per-call key: makes the hashes groupable here and meaningless anywhere else.
    // If randomness is unavailable, reuse detection is skipped rather than done with
    // a fixed key — a predictable key is exactly the verifier we are avoiding.
    let mut key = [0u8; 32];
    let keyed = keel_crypto::fill_random(&mut key).is_ok();

    let mut by_hash: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
    let mut assessed: Vec<Option<EntryHealth>> = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        report.examined += 1;
        let Some(password) = candidate.password else {
            report.without_password += 1;
            assessed.push(None);
            continue;
        };
        if password.is_empty() {
            report.without_password += 1;
            assessed.push(None);
            continue;
        }

        let bits = keel_crypto::strength::estimate_bits(password);
        let age_days = now
            .saturating_sub(candidate.meta.password_changed_at)
            .saturating_div(DAY);

        if keyed {
            let hash = *blake3::keyed_hash(&key, password.as_bytes()).as_bytes();
            by_hash.entry(hash).or_default().push(assessed.len());
        }

        assessed.push(Some(EntryHealth {
            id: candidate.meta.record_id,
            title: candidate.meta.title.clone(),
            username: candidate.meta.username.clone(),
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "bits is a non-negative estimate well under u32::MAX"
            )]
            bits: bits.round() as u32,
            strength: Strength::of_bits(bits),
            age_days,
            shared_with: 0,
        }));
    }

    // Fill in reuse counts, then build the groups.
    let mut groups: Vec<Vec<usize>> = by_hash
        .into_values()
        .filter(|indices| indices.len() > 1)
        .collect();
    for indices in &groups {
        for &i in indices {
            if let Some(Some(entry)) = assessed.get_mut(i) {
                entry.shared_with = indices.len() - 1;
            }
        }
    }
    // Largest group first: the password shared by six accounts is the urgent one.
    // Tie-broken by title so the output is stable across runs, which matters because
    // `HashMap` iteration order is not.
    groups.sort_by(|a, b| {
        b.len().cmp(&a.len()).then_with(|| {
            let title = |indices: &Vec<usize>| {
                indices
                    .first()
                    .and_then(|&i| assessed.get(i))
                    .and_then(|e| e.as_ref())
                    .map(|e| e.title.clone())
                    .unwrap_or_default()
            };
            title(a).cmp(&title(b))
        })
    });

    for indices in groups {
        let mut entries: Vec<EntryHealth> = indices
            .iter()
            .filter_map(|&i| assessed.get(i).and_then(|e| e.clone()))
            .collect();
        entries.sort_by(|a, b| a.title.cmp(&b.title));
        report.reused.push(ReuseGroup { entries });
    }

    for entry in assessed.into_iter().flatten() {
        if entry.strength != Strength::Reasonable {
            report.weak.push(entry.clone());
        }
        if entry.age_days > STALE_DAYS {
            report.stale.push(entry);
        }
    }

    // Weakest first, then by title for a stable order.
    report
        .weak
        .sort_by(|a, b| a.bits.cmp(&b.bits).then_with(|| a.title.cmp(&b.title)));
    // Oldest first.
    report.stale.sort_by(|a, b| {
        b.age_days
            .cmp(&a.age_days)
            .then_with(|| a.title.cmp(&b.title))
    });

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal entry. `EntryMeta` has no `Default` on purpose — every field is
    /// load-bearing on disk — so tests spell it out.
    fn meta(title: &str, changed_at: u64) -> EntryMeta {
        // Distinct ids per title, so `flagged`'s dedup is actually exercised.
        let mut record_id = [0u8; 16];
        for (slot, byte) in record_id.iter_mut().zip(title.bytes()) {
            *slot = byte;
        }
        EntryMeta {
            record_id,
            key_epoch: 1,
            blob_hash: [0u8; 32],
            blob_offset: 0,
            blob_len: 0,
            title: title.to_owned(),
            username: format!("{}@example.com", title.to_lowercase()),
            origins: Vec::new(),
            tags: Vec::new(),
            folder_id: None,
            created_at: changed_at,
            updated_at: changed_at,
            password_changed_at: changed_at,
            has_totp: false,
            favorite: false,
            notes_preview_len: 0,
        }
    }

    const NOW: u64 = 1_800_000_000;
    fn days_ago(days: u64) -> u64 {
        NOW - days * DAY
    }

    #[test]
    fn an_empty_vault_is_clean() {
        let report = assess(&[], NOW);
        assert!(report.is_clean());
        assert_eq!(report.examined, 0);
        assert_eq!(report.flagged(), 0);
    }

    #[test]
    fn strong_unique_recent_passwords_are_not_flagged() {
        let a = meta("Alpha", days_ago(10));
        let b = meta("Beta", days_ago(20));
        let report = assess(
            &[
                Candidate {
                    meta: &a,
                    password: Some("9Xk#mQ2vLp!7Rt4WzB@e"),
                },
                Candidate {
                    meta: &b,
                    password: Some("Tf6$nH8jCw!3YqZ5xV@d"),
                },
            ],
            NOW,
        );
        assert!(
            report.is_clean(),
            "should be clean, got weak={:?} reused={:?} stale={:?}",
            report.weak,
            report.reused,
            report.stale
        );
        assert_eq!(report.examined, 2);
    }

    #[test]
    fn a_shared_password_is_grouped() {
        let a = meta("Alpha", days_ago(1));
        let b = meta("Beta", days_ago(1));
        let c = meta("Gamma", days_ago(1));
        let shared = "Kp9#mW2xQv!8Rt5ZnB@j";
        let report = assess(
            &[
                Candidate {
                    meta: &a,
                    password: Some(shared),
                },
                Candidate {
                    meta: &b,
                    password: Some(shared),
                },
                Candidate {
                    meta: &c,
                    password: Some("Uf7$nJ4kDx!2YsZ6yC@e"),
                },
            ],
            NOW,
        );
        assert_eq!(report.reused.len(), 1);
        let group = report.reused.first().unwrap();
        assert_eq!(group.entries.len(), 2);
        let titles: Vec<&str> = group.entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, vec!["Alpha", "Beta"]);
        for entry in &group.entries {
            assert_eq!(entry.shared_with, 1);
        }
    }

    #[test]
    fn larger_reuse_groups_come_first() {
        let metas: Vec<EntryMeta> = (0..5)
            .map(|i| meta(&format!("E{i}"), days_ago(1)))
            .collect();
        // Three share one password, two share another.
        let three = "Qw9#mZ2xKv!8Rt5ZnB@j";
        let two = "Lp4$nJ7kDx!2YsZ6yC@e";
        let candidates: Vec<Candidate<'_>> = metas
            .iter()
            .enumerate()
            .map(|(i, m)| Candidate {
                meta: m,
                password: Some(if i < 3 { three } else { two }),
            })
            .collect();
        let report = assess(&candidates, NOW);
        assert_eq!(report.reused.len(), 2);
        assert_eq!(report.reused[0].entries.len(), 3);
        assert_eq!(report.reused[1].entries.len(), 2);
    }

    #[test]
    fn weak_passwords_are_reported_weakest_first() {
        let a = meta("Alpha", days_ago(1));
        let b = meta("Beta", days_ago(1));
        let report = assess(
            &[
                Candidate {
                    meta: &a,
                    password: Some("sunshine1"),
                },
                Candidate {
                    meta: &b,
                    password: Some("123456"),
                },
            ],
            NOW,
        );
        assert_eq!(report.weak.len(), 2);
        assert_eq!(
            report.weak.first().unwrap().title,
            "Beta",
            "123456 is weaker than sunshine1 and should sort first"
        );
        assert_eq!(report.weak.first().unwrap().strength, Strength::Critical);
    }

    #[test]
    fn old_passwords_are_reported_oldest_first() {
        let recent = meta("Recent", days_ago(30));
        let old = meta("Old", days_ago(400));
        let ancient = meta("Ancient", days_ago(3000));
        let strong = "Vb8#mR3xQw!9Tt6ZnC@k";
        let report = assess(
            &[
                Candidate {
                    meta: &recent,
                    password: Some(strong),
                },
                Candidate {
                    meta: &old,
                    password: Some("Hn5$pL2jFy!4WsZ8vD@m"),
                },
                Candidate {
                    meta: &ancient,
                    password: Some("Zc3#qN7bGt!6XrY9uE@n"),
                },
            ],
            NOW,
        );
        let titles: Vec<&str> = report.stale.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, vec!["Ancient", "Old"]);
        assert!(report.stale.first().unwrap().age_days >= 3000);
    }

    #[test]
    fn entries_without_a_password_are_counted_not_scored() {
        // A federated "sign in with Google" record, or a note. Scoring these as an
        // empty password would report every one of them as critically weak, burying
        // the real findings.
        let a = meta("Federated", days_ago(1));
        let b = meta("Empty", days_ago(1));
        let report = assess(
            &[
                Candidate {
                    meta: &a,
                    password: None,
                },
                Candidate {
                    meta: &b,
                    password: Some(""),
                },
            ],
            NOW,
        );
        assert_eq!(report.without_password, 2);
        assert!(report.is_clean());
        assert_eq!(report.examined, 2);
    }

    #[test]
    fn an_entry_flagged_three_ways_is_counted_once() {
        // A weak, reused, ancient password would otherwise be counted three times,
        // and a report that inflates its own findings trains users to ignore it.
        let a = meta("Alpha", days_ago(2000));
        let b = meta("Beta", days_ago(2000));
        let report = assess(
            &[
                Candidate {
                    meta: &a,
                    password: Some("password1"),
                },
                Candidate {
                    meta: &b,
                    password: Some("password1"),
                },
            ],
            NOW,
        );
        assert_eq!(report.weak.len(), 2);
        assert_eq!(report.stale.len(), 2);
        assert_eq!(report.reused.len(), 1);
        assert_eq!(report.flagged(), 2, "two entries, however many findings");
    }

    #[test]
    fn no_password_value_appears_anywhere_in_the_report() {
        // The rule this module exists to obey. Checked against the debug rendering
        // because that is the broadest surface: anything the report can print, a log
        // or an error message could also print.
        const CANARY: &str = "canary-Zq7#mV4xKp!2Rt9";
        let a = meta("Alpha", days_ago(1));
        let b = meta("Beta", days_ago(1));
        let report = assess(
            &[
                Candidate {
                    meta: &a,
                    password: Some(CANARY),
                },
                Candidate {
                    meta: &b,
                    password: Some(CANARY),
                },
            ],
            NOW,
        );
        // The canary is reused, so it is definitely in the report's subject matter.
        assert_eq!(report.reused.len(), 1);
        let rendered = format!("{report:?}");
        assert!(
            !rendered.contains(CANARY),
            "the report leaked a password value"
        );
        // Also check no substantial fragment survives.
        assert!(!rendered.contains("canary-"));
        assert!(!rendered.contains("Zq7#mV4xKp"));
    }

    #[test]
    fn reuse_grouping_is_stable_across_runs() {
        // `HashMap` iteration order is not stable, and the reuse key is random per
        // call, so without explicit sorting the report would shuffle between runs and
        // the CLI's output would be nondeterministic.
        let metas: Vec<EntryMeta> = (0..6)
            .map(|i| meta(&format!("E{i}"), days_ago(1)))
            .collect();
        let p1 = "Aa1#mZ2xKv!8Rt5ZnB@j";
        let p2 = "Bb2$nJ7kDx!2YsZ6yC@e";
        let p3 = "Cc3%oK8lEy!3ZtA7zD@f";
        let candidates: Vec<Candidate<'_>> = metas
            .iter()
            .enumerate()
            .map(|(i, m)| Candidate {
                meta: m,
                password: Some(match i % 3 {
                    0 => p1,
                    1 => p2,
                    _ => p3,
                }),
            })
            .collect();
        let first = assess(&candidates, NOW);
        for _ in 0..20 {
            assert_eq!(assess(&candidates, NOW), first, "report order is unstable");
        }
    }

    #[test]
    fn debugging_a_candidate_does_not_print_the_password() {
        // `Candidate` is the one type here that holds plaintext. A derived `Debug`
        // would put it in any log line or panic message that formatted one, which is
        // why the impl is written by hand.
        let m = meta("Alpha", days_ago(1));
        let candidate = Candidate {
            meta: &m,
            password: Some("canary-Zq7#mV4xKp!2Rt9"),
        };
        let rendered = format!("{candidate:?}");
        assert!(
            !rendered.contains("canary"),
            "Candidate's Debug leaked the password: {rendered}"
        );
        // It should still be useful for diagnosis.
        assert!(
            rendered.contains("22"),
            "should report the length: {rendered}"
        );
    }

    #[test]
    fn a_password_changed_in_the_future_does_not_underflow() {
        // Clock skew, or a vault restored from a machine with a wrong date.
        let a = meta("Future", NOW + 10 * DAY);
        let report = assess(
            &[Candidate {
                meta: &a,
                password: Some("Wd9#rP5yHu!7XsB2vF@p"),
            }],
            NOW,
        );
        assert_eq!(report.stale.len(), 0);
        assert!(report.is_clean());
    }
}
