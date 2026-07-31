// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Deciding whether a stored entry may be filled into a page.
//!
//! This is the phishing-resistance core of autofill, and the place where a mistake is worst:
//! a rule that is slightly too generous hands credentials to a look-alike domain, silently,
//! at the moment the user is most likely to be fooled.
//!
//! # Where the origin comes from
//!
//! The request origin is taken from the **browser**, via `sender.origin` on a content-script
//! message — never from anything the page said about itself. `location.href`,
//! `document.domain`, and any string the page supplies are all attacker-controlled on an
//! attacker's page. This module cannot enforce that on its own; it is enforced by the
//! extension and the native host never passing a page-supplied origin, and it is the reason
//! matching is decided here in the agent rather than in the extension.
//!
//! # The rules
//!
//! 1. **Scheme must match**, with exactly one asymmetry: a stored `http` origin may fill on
//!    `https`, because that is a strict improvement. A stored `https` origin must **never**
//!    fill on `http` — that would put a password into a cleartext request, which is the
//!    single worst thing autofill can do.
//! 2. **Host must match exactly, or be a subdomain of the stored host at a dot boundary.**
//!    So `https://example.com` covers `https://login.example.com`, and does not cover
//!    `https://evil-example.com` or `https://example.com.evil.tld`.
//! 3. **Port must match.** A missing port means the scheme's default.
//! 4. **No wildcards, no substring matching, ever.** There is no syntax for a pattern here,
//!    because there is no safe one.
//!
//! # Why there is no Public Suffix List
//!
//! The plan called for the PSL, and it is genuinely needed for one direction of this problem
//! — deriving a *registrable domain from a request origin* in order to look up candidate
//! entries. Without it, `bank.co.uk` and `evil.co.uk` both reduce to `co.uk` and become
//! interchangeable.
//!
//! This module does not do that. It asks the opposite question: *does this stored origin
//! cover this request origin?* The stored origin is data the **user** entered, not something
//! an attacker controls, so the dangerous case — a stored origin of `https://co.uk`
//! swallowing every British site — requires the user to have typed `co.uk` as their bank's
//! address. The suffix rule is therefore sound in this direction without a suffix list, and
//! the list is only needed if entry *discovery* is ever moved from exact lookup to
//! registrable-domain grouping. That trade is recorded rather than left implicit.

use keel_format::manifest::EntryMeta;

/// A parsed origin: scheme, host, port. Nothing else.
///
/// Deliberately not a general URL type. Paths, queries, and fragments are not part of an
/// origin and must not influence matching — an entry for `https://example.com/login` should
/// behave exactly like one for `https://example.com`, because the browser's notion of origin
/// does, and any difference between the two is a place for confusion to hide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// Parse an origin from a string.
    ///
    /// Accepts a bare `https://host[:port]`, and tolerates a trailing path so that an entry
    /// whose "website" field was pasted from an address bar still works. Returns `None` for
    /// anything it cannot understand — including schemes other than `http` and `https`,
    /// because filling a password into a `file://` or `data:` document is never right.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        let (scheme, rest) = raw.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            // No other scheme can hold a login worth filling, and several — `file`, `data`,
            // `javascript` — are actively dangerous to treat as an origin.
            _ => return None,
        };

        // Strip anything after the authority. Also strips credentials, which have no place
        // in a stored origin and would otherwise become part of the host.
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .rsplit('@')
            .next()
            .unwrap_or("");
        if authority.is_empty() {
            return None;
        }

        let (host, port) = match authority.rsplit_once(':') {
            // A colon with digits after it is a port. A colon with anything else is either a
            // bare IPv6 address or nonsense; neither should be split here.
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                (h, p.parse::<u16>().ok()?)
            }
            _ => (authority, default_port),
        };

        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if host.is_empty() || host.contains(char::is_whitespace) {
            return None;
        }
        // A host that is not at least one label is not a host. `..` and a trailing dot alone
        // are rejected rather than normalised, because normalising attacker-adjacent input is
        // how confusable hosts get through.
        if host == "." || host.contains("..") {
            return None;
        }
        let host = host.trim_end_matches('.').to_owned();
        if host.is_empty() {
            return None;
        }

        Some(Self { scheme, host, port })
    }

    /// The scheme, lowercased.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host, lowercased and without a trailing dot.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, defaulted from the scheme when absent.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Whether this origin is carried over a secure transport.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.scheme == "https"
    }

    /// Render canonically, for display in an approval dialog.
    ///
    /// The dialog is where a user notices that a secret is going somewhere wrong, so this is
    /// deliberately unambiguous: an explicit port whenever it is not the default, and no
    /// abbreviation.
    #[must_use]
    pub fn display(&self) -> String {
        let default = if self.scheme == "https" { 443 } else { 80 };
        if self.port == default {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }

    /// Whether `self` — a **stored** origin — permits filling into `request`.
    ///
    /// See the module documentation for the rules and for why the suffix rule is safe in
    /// this direction without a public-suffix list.
    #[must_use]
    pub fn covers(&self, request: &Origin) -> bool {
        // Scheme. The one permitted asymmetry is http → https, an upgrade. https → http is
        // refused unconditionally: it would put a password into a cleartext request.
        let scheme_ok =
            self.scheme == request.scheme || (self.scheme == "http" && request.scheme == "https");
        if !scheme_ok {
            return false;
        }

        // Port. Compared after the scheme so an http entry filling on https is compared
        // against the https default rather than against 80.
        let expected_port = if self.scheme == request.scheme {
            self.port
        } else {
            // Upgraded: the stored port only carries over if it was explicit and non-default.
            if self.port == 80 {
                443
            } else {
                self.port
            }
        };
        if expected_port != request.port {
            return false;
        }

        if self.host == request.host {
            return true;
        }
        // Subdomain, at a dot boundary. The boundary is what stops `evil-example.com` from
        // matching `example.com`, and requiring a *suffix* is what stops
        // `example.com.evil.tld`.
        request
            .host
            .strip_suffix(&self.host)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
    }
}

/// Why an entry was or was not offered for a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// The stored origin and the request origin are identical.
    Exact,
    /// The page is a subdomain of a stored origin.
    Subdomain,
}

/// An entry that may be filled into a given origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Which entry.
    pub id: keel_format::Id,
    /// How it matched.
    pub kind: MatchKind,
}

/// Entries that may be filled into `request`, best match first.
///
/// Exact matches come before subdomain matches, so a credential stored specifically for
/// `login.example.com` is offered ahead of the generic `example.com` one. Within a kind the
/// order is the manifest's, which is stable across runs.
///
/// An empty result is the normal, safe outcome for a page the user has no entry for. It must
/// never be treated as "nothing matched, so offer everything" — there is no code path here
/// that returns unmatched entries, and that is deliberate.
#[must_use]
pub fn candidates_for(entries: &[EntryMeta], request: &Origin) -> Vec<Candidate> {
    let mut exact = Vec::new();
    let mut subdomain = Vec::new();
    for entry in entries {
        let mut best: Option<MatchKind> = None;
        for raw in &entry.origins {
            let Some(stored) = Origin::parse(raw) else {
                continue;
            };
            if !stored.covers(request) {
                continue;
            }
            let kind = if stored.host == request.host && stored.scheme == request.scheme {
                MatchKind::Exact
            } else {
                MatchKind::Subdomain
            };
            // An entry listing several origins takes the strongest match among them.
            best = Some(match best {
                Some(MatchKind::Exact) => MatchKind::Exact,
                _ => kind,
            });
        }
        match best {
            Some(MatchKind::Exact) => exact.push(Candidate {
                id: entry.record_id,
                kind: MatchKind::Exact,
            }),
            Some(MatchKind::Subdomain) => subdomain.push(Candidate {
                id: entry.record_id,
                kind: MatchKind::Subdomain,
            }),
            None => {}
        }
    }
    exact.extend(subdomain);
    exact
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(raw: &str) -> Origin {
        Origin::parse(raw).unwrap_or_else(|| panic!("{raw:?} should parse"))
    }

    // -- parsing -----------------------------------------------------------

    #[test]
    fn an_origin_ignores_everything_after_the_authority() {
        // A user pastes an address bar; the path must not become part of the identity.
        let a = o("https://example.com");
        for raw in [
            "https://example.com/",
            "https://example.com/login",
            "https://example.com/login?next=/x#form",
            "https://example.com:443/login",
        ] {
            assert_eq!(o(raw), a, "{raw:?} should be the same origin");
        }
    }

    #[test]
    fn hosts_and_schemes_are_case_insensitive() {
        assert_eq!(o("HTTPS://Example.COM"), o("https://example.com"));
    }

    #[test]
    fn a_trailing_dot_is_the_same_host() {
        // `example.com.` is a fully-qualified form of the same name. Treating them as
        // different would let one bypass a rule written for the other.
        assert_eq!(o("https://example.com."), o("https://example.com"));
    }

    #[test]
    fn credentials_in_the_url_do_not_become_the_host() {
        // `https://example.com@evil.tld/` is a classic confusable. The host is evil.tld, and
        // it must be parsed as such rather than as example.com.
        assert_eq!(o("https://example.com@evil.tld/").host(), "evil.tld");
    }

    #[test]
    fn only_http_and_https_are_origins() {
        for raw in [
            "file:///etc/passwd",
            "data:text/html,<form>",
            "javascript:alert(1)",
            "ftp://example.com",
            "chrome-extension://abc",
            "about:blank",
        ] {
            assert!(
                Origin::parse(raw).is_none(),
                "{raw:?} must not parse as a fillable origin"
            );
        }
    }

    #[test]
    fn nonsense_does_not_parse() {
        for raw in [
            "",
            "   ",
            "example.com",
            "https://",
            "https:// ",
            "https://.",
            "https://..",
            "https://a..b",
            "https://exa mple.com",
        ] {
            assert!(Origin::parse(raw).is_none(), "{raw:?} must not parse");
        }
    }

    #[test]
    fn ports_are_parsed_and_defaulted() {
        assert_eq!(o("https://example.com").port(), 443);
        assert_eq!(o("http://example.com").port(), 80);
        assert_eq!(o("https://example.com:8443").port(), 8443);
        // A colon followed by something that is not a port is not a port.
        assert!(Origin::parse("https://example.com:notaport").is_some());
        assert_eq!(
            o("https://example.com:notaport").host(),
            "example.com:notaport"
        );
    }

    // -- the rules that stop phishing --------------------------------------

    #[test]
    fn an_https_entry_never_fills_on_http() {
        // The worst thing autofill can do: put a password into a cleartext request. A
        // downgrade is refused even when the host matches exactly.
        assert!(!o("https://example.com").covers(&o("http://example.com")));
    }

    #[test]
    fn an_http_entry_may_fill_on_https() {
        // An upgrade is a strict improvement, and refusing it would mean an entry saved
        // years ago stops working the day a site adopts TLS.
        assert!(o("http://example.com").covers(&o("https://example.com")));
    }

    #[test]
    fn a_lookalike_host_never_matches() {
        let stored = o("https://example.com");
        for attacker in [
            "https://evil-example.com",
            "https://examplecom.evil.tld",
            "https://example.com.evil.tld",
            "https://notexample.com",
            "https://xexample.com",
            "https://example.co",
            "https://example.com.br",
        ] {
            assert!(
                !stored.covers(&o(attacker)),
                "{attacker:?} must not match a stored example.com"
            );
        }
    }

    #[test]
    fn a_subdomain_matches_but_a_parent_does_not() {
        let stored = o("https://example.com");
        assert!(stored.covers(&o("https://login.example.com")));
        assert!(stored.covers(&o("https://a.b.example.com")));

        // The other direction must not hold: a credential stored for a specific subdomain is
        // not a credential for the whole site.
        let specific = o("https://login.example.com");
        assert!(!specific.covers(&o("https://example.com")));
        assert!(!specific.covers(&o("https://other.example.com")));
    }

    #[test]
    fn a_different_port_does_not_match() {
        assert!(!o("https://example.com:8443").covers(&o("https://example.com")));
        assert!(!o("https://example.com").covers(&o("https://example.com:8443")));
        assert!(o("https://example.com:8443").covers(&o("https://example.com:8443")));
    }

    #[test]
    fn an_upgraded_default_port_still_matches() {
        // An `http://example.com` entry has port 80. Filling it on `https://example.com`
        // means comparing against 443, not 80 — otherwise the upgrade rule above could never
        // fire.
        assert!(o("http://example.com").covers(&o("https://example.com")));
        // An explicit non-default port does carry over, so an entry for a dev server on
        // :8080 does not silently match production.
        assert!(!o("http://example.com:8080").covers(&o("https://example.com")));
    }

    #[test]
    fn there_is_no_wildcard_syntax() {
        // A stored origin containing a wildcard must simply fail to parse or fail to match —
        // never be interpreted as a pattern.
        for stored in ["https://*.example.com", "https://*", "https://.example.com"] {
            let parsed = Origin::parse(stored);
            if let Some(parsed) = parsed {
                assert!(
                    !parsed.covers(&o("https://login.example.com")),
                    "{stored:?} must not behave as a pattern"
                );
            }
        }
    }

    #[test]
    fn covering_is_reflexive_for_anything_that_parses() {
        for raw in [
            "https://example.com",
            "http://localhost:3000",
            "https://sub.domain.example.co.uk",
            "https://192.168.1.1:8443",
        ] {
            let parsed = o(raw);
            assert!(parsed.covers(&parsed), "{raw:?} should cover itself");
        }
    }

    #[test]
    fn display_is_unambiguous() {
        assert_eq!(
            o("https://example.com/login").display(),
            "https://example.com"
        );
        assert_eq!(
            o("https://example.com:8443").display(),
            "https://example.com:8443"
        );
        assert_eq!(
            o("http://localhost:3000").display(),
            "http://localhost:3000"
        );
    }

    // -- candidate selection -----------------------------------------------

    fn entry(id: u8, origins: &[&str]) -> EntryMeta {
        EntryMeta {
            record_id: [id; 16],
            key_epoch: 1,
            blob_hash: [0u8; 32],
            blob_offset: 0,
            blob_len: 0,
            title: format!("entry-{id}"),
            username: "ada".to_owned(),
            origins: origins.iter().map(|s| (*s).to_owned()).collect(),
            tags: Vec::new(),
            folder_id: None,
            created_at: 0,
            updated_at: 0,
            password_changed_at: 0,
            has_totp: false,
            favorite: false,
            notes_preview_len: 0,
        }
    }

    #[test]
    fn only_matching_entries_are_offered() {
        let entries = vec![
            entry(1, &["https://example.com"]),
            entry(2, &["https://other.tld"]),
            entry(3, &[]),
            entry(4, &["not a url at all"]),
        ];
        let found = candidates_for(&entries, &o("https://example.com"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, [1u8; 16]);
    }

    #[test]
    fn a_page_with_no_stored_entry_offers_nothing() {
        // The safe outcome, and it must never be confused with "offer everything".
        let entries = vec![entry(1, &["https://example.com"])];
        assert!(candidates_for(&entries, &o("https://unrelated.tld")).is_empty());
    }

    #[test]
    fn an_exact_match_is_offered_before_a_subdomain_match() {
        // A credential stored specifically for the login host is more likely the right one.
        let entries = vec![
            entry(1, &["https://example.com"]),
            entry(2, &["https://login.example.com"]),
        ];
        let found = candidates_for(&entries, &o("https://login.example.com"));
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].id, [2u8; 16]);
        assert_eq!(found[0].kind, MatchKind::Exact);
        assert_eq!(found[1].kind, MatchKind::Subdomain);
    }

    #[test]
    fn an_entry_with_several_origins_takes_its_strongest_match() {
        let entries = vec![entry(
            1,
            &["https://example.com", "https://login.example.com"],
        )];
        let found = candidates_for(&entries, &o("https://login.example.com"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, MatchKind::Exact);
    }

    #[test]
    fn an_unparseable_stored_origin_is_ignored_not_treated_as_a_match() {
        // Garbage in an entry's website field must narrow nothing and widen nothing.
        let entries = vec![entry(1, &["", "   ", "javascript:alert(1)", "*"])];
        assert!(candidates_for(&entries, &o("https://example.com")).is_empty());
    }
}
