// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! The architectural rules that CI enforces.
//!
//! This file is the machine-readable form of the dependency diagram in
//! `docs/architecture.md`. Changing it changes a security boundary, so it has a
//! CODEOWNERS entry and changes here should be justified in the pull request.

/// Which internal crates each workspace crate may depend on.
///
/// Returns `None` for an unknown crate, which is itself a failure: adding a crate
/// to the workspace must be a deliberate act that includes deciding where it sits
/// in the layering.
///
/// The load-bearing entries:
///
/// * `keel-crypto` and `keel-proto` depend on **nothing** internal. They are the
///   two leaves, and they stay that way.
/// * `keel-client` may depend only on `keel-proto`. It must never gain
///   `keel-crypto`, `keel-format`, or `keel-core` — that is what keeps key
///   material out of the CLI, the MCP server, the native messaging host, and the
///   desktop shell.
/// * `keel-agent` is the only crate that may depend on `keel-core`, and therefore
///   the only process that links the cryptographic core at runtime.
pub fn allowed_internal_deps(crate_name: &str) -> Option<&'static [&'static str]> {
    let deps: &[&str] = match crate_name {
        // ---- leaves -------------------------------------------------------
        // The cryptographic core answers to nobody. No I/O, no platform, no
        // protocol types: that is what makes it auditable and fuzzable.
        "keel-crypto" => &[],
        // Wire types only. Shared by the agent and every client, so a dependency
        // here would leak into everything.
        "keel-proto" => &[],
        // Only crate allowed `unsafe`. Depends on keel-crypto solely to install
        // the PageLocker hook.
        "keel-hardening" => &["keel-crypto"],

        // ---- vault core ---------------------------------------------------
        "keel-format" => &["keel-crypto"],
        "keel-store" => &["keel-crypto", "keel-format"],
        // Deliberately without `keel-hardening`. It was listed and depended on here for the
        // PageLocker hook, but nothing in keel-core ever referenced it: `keel_hardening::init`
        // installs the locker into keel-crypto *process-globally*, so the binary that owns the
        // process does it — `keel-agent`, at the top of main, which is where that function's
        // own documentation says it belongs. keel-core gets the protection either way, so the
        // dependency bought nothing and widened the graph of the crate that handles plaintext.
        "keel-core" => &["keel-crypto", "keel-format", "keel-store"],

        // ---- the one privileged process -----------------------------------
        // The agent is the only process that opens the vault file, so it is the only one
        // that needs the storage layer as well as the cryptographic core. Concentrating
        // both here is the point: it keeps "which code can touch key material or vault
        // bytes?" a question with a one-binary answer.
        "keel-agent" => &[
            "keel-core",
            "keel-crypto",
            "keel-format",
            "keel-hardening",
            "keel-proto",
            "keel-store",
        ],

        // ---- clients: no crypto, no vault format --------------------------
        "keel-client" => &["keel-proto"],
        "keel-cli" => &["keel-client", "keel-proto", "keel-import"],
        "keel-mcp" => &["keel-client", "keel-proto"],
        // The desktop shell. Same rule as every other client: wire types and the client
        // library, nothing that can decrypt. The webview it hosts never receives a secret
        // at all, so the GUI is two boundaries away from key material rather than one.
        "keel-desktop" => &["keel-client", "keel-proto"],
        "keel-native-host" => &["keel-client", "keel-proto"],
        // The reveal overlay receives one already-decrypted secret over an
        // inherited socket. It deliberately cannot open a vault itself.
        // The overlay receives one already-decrypted secret on stdin from the agent. It
        // deliberately cannot open a vault. `keel-hardening` is here for one call — excluding
        // the window from screen capture — because that needs `unsafe`, which lives there.
        "keel-reveal" => &["keel-hardening", "keel-proto"],

        // ---- leaf helpers -------------------------------------------------
        // Importers build plaintext entries for the agent to encrypt. They need
        // the entry types from keel-format but never touch keys or vault files.
        "keel-import" => &["keel-crypto", "keel-format"],
        // The only crate permitted a network stack. Kept dependency-free
        // internally so it cannot drag TLS into anything else.
        "keel-breach" => &[],

        // ---- tooling ------------------------------------------------------
        "xtask" => &[],

        _ => return None,
    };
    Some(deps)
}

// ---------------------------------------------------------------------------
// Licensing
// ---------------------------------------------------------------------------

/// The workspace default: everything that is not a deliberate exception.
pub const AGPL: &str = "AGPL-3.0-or-later";

/// The licence each workspace crate must declare.
///
/// Two crates are permissive on purpose, and the reason is worth stating where someone
/// will read it before changing it:
///
/// * `keel-proto` (Apache-2.0) is the protocol definition — serde types, no logic, no
///   crypto. Copyleft here would protect nothing and would stop anything from speaking
///   to the agent.
/// * `keel-client` (MPL-2.0) is the crate a third-party application embeds. No strong
///   copyleft permits that; MPL's per-file copyleft is the narrowest licence that does.
///
/// What makes those two safe is the layering rule in [`allowed_internal_deps`]: neither
/// may depend on `keel-crypto`, `keel-format`, `keel-store`, or `keel-core`, so the
/// permissive surface provably contains no key material, no crypto, and no vault format.
/// Widening this list without checking that closure would hand away the vault core.
///
/// Returns `None` for an unknown crate, which is a failure rather than a default, for the
/// same reason [`allowed_internal_deps`] does: adding a crate should require deciding.
pub fn expected_license(crate_name: &str) -> Option<&'static str> {
    Some(match crate_name {
        // ---- the deliberate exceptions ------------------------------------
        "keel-proto" => "Apache-2.0",
        "keel-client" => "MPL-2.0",

        // ---- everything else ----------------------------------------------
        "keel-crypto" | "keel-format" | "keel-hardening" | "keel-store" | "keel-core"
        | "keel-agent" | "keel-reveal" | "keel-cli" | "keel-mcp" | "keel-native-host"
        | "keel-import" | "keel-breach" | "keel-desktop" | "keel-fuzz" | "xtask" => AGPL,

        _ => return None,
    })
}

/// How far a licence reaches into a work that combines it.
///
/// The ordering is the whole point. A crate may depend on an internal crate whose licence
/// reaches the same distance or less, never further — because a dependency's licence
/// governs the combined work, so an AGPL crate underneath `keel-client` would silently
/// make every application that embeds `keel-client` AGPL. The promise that `keel-client`
/// is embeddable would still be written in the manifest, and would no longer be true.
///
/// This is the invariant that lets the permissive exceptions exist at all, and it is why
/// it is checked mechanically rather than remembered.
pub fn license_reach(license: &str) -> Option<u8> {
    match license {
        // Permissive: imposes nothing on the combined work beyond notice.
        "Apache-2.0" => Some(0),
        // Weak copyleft: reaches these files only, so a closed work may link it.
        "MPL-2.0" => Some(1),
        // Strong copyleft plus the network clause: reaches the entire combined work.
        AGPL => Some(2),
        _ => None,
    }
}

/// The SPDX licence every source file under a given path must declare.
///
/// Per-file headers matter here more than in a single-licence repo: this tree carries
/// three licences, so a file that has been moved between crates and states nothing is a
/// file whose terms depend on a reader correctly guessing which directory it lives in.
/// MPL-2.0 additionally *requires* the notice, in section 3.1.
///
/// Path-based rather than crate-based because two of the licensed trees are not cargo
/// crates at all — `extension/` is JavaScript, and `fuzz/` is excluded from the
/// workspace, so neither appears in `cargo metadata`.
///
/// Returns `None` for a path in no licensed tree, which fails the check: a new top-level
/// source directory should be a decision, not an oversight.
pub fn license_for_path(relative_path: &str) -> Option<&'static str> {
    // Most specific first — the two permissive crates are carved out of `crates/`.
    const TREES: &[(&str, &str)] = &[
        ("crates/keel-proto/", "Apache-2.0"),
        ("crates/keel-client/", "MPL-2.0"),
        ("crates/", AGPL),
        ("apps/", AGPL),
        ("extension/", AGPL),
        ("xtask/", AGPL),
        ("fuzz/", AGPL),
    ];
    TREES
        .iter()
        .find(|(prefix, _)| relative_path.starts_with(prefix))
        .map(|(_, license)| *license)
}

/// File extensions the header check covers.
pub const LICENSED_EXTENSIONS: &[&str] = &["rs", "js", "css", "html"];

/// Directories the header check never descends into.
pub const HEADER_SCAN_SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    "node_modules",
    "dist",
    ".github",
    "corpus",
    "artifacts",
];

/// Crates whose resolved dependency graph must contain no HTTP or TLS stack.
///
/// This is every shipped crate except `keel-breach`. Listing them individually
/// rather than "everything except" means a new crate is checked only once someone
/// decides it should be — which is the same deliberate-decision property the
/// layering table has.
pub const NETWORK_FREE_CRATES: &[&str] = &[
    "keel-crypto",
    "keel-format",
    "keel-hardening",
    "keel-store",
    "keel-core",
    "keel-proto",
    "keel-agent",
    "keel-client",
    "keel-cli",
    "keel-mcp",
    "keel-native-host",
    "keel-reveal",
    "keel-import",
    "keel-desktop",
];

/// Crate names that indicate an HTTP client or TLS implementation.
///
/// Note what is deliberately *absent*: `tokio` and `socket2`. The agent needs
/// Unix domain sockets and Windows named pipes to talk to its own clients, so
/// local socket support is expected. This list targets stacks that speak to the
/// internet, which is the property users actually care about.
/// The target triples Keel ships binaries for.
///
/// The network check runs once per triple rather than over the union of all platforms.
/// `cargo metadata` without a platform filter merges every platform's dependencies, which
/// makes a mobile-only dependency look like a universal one: `tauri` depends on `reqwest`
/// for Android and iOS, and the union therefore reported an HTTP stack inside a desktop app
/// that contains none. Verified per target, all six of these link zero HTTP crates.
///
/// Adding a platform here is a commitment that the gates are expected to hold for it.
pub const SHIPPED_PLATFORMS: &[&str] = &[
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
];

pub const BANNED_NETWORK_CRATES: &[&str] = &[
    // HTTP clients
    "reqwest",
    "hyper",
    "hyper-util",
    "h2",
    "ureq",
    "isahc",
    "attohttpc",
    "surf",
    "curl",
    "curl-sys",
    // TLS
    "rustls",
    "tokio-rustls",
    "native-tls",
    "tokio-native-tls",
    "openssl",
    "openssl-sys",
    "schannel",
    "security-framework",
    // DNS
    "hickory-resolver",
    "trust-dns-resolver",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clients_may_not_reach_the_crypto_core() {
        // The single most important layering rule. If this test ever needs
        // changing, something has gone wrong with the architecture, not the test.
        for client in ["keel-client", "keel-cli", "keel-mcp", "keel-native-host"] {
            let allowed = allowed_internal_deps(client).expect("client crate must have rules");
            for forbidden in ["keel-core", "keel-store"] {
                assert!(
                    !allowed.contains(&forbidden),
                    "{client} must not be allowed to depend on {forbidden}"
                );
            }
        }
        // keel-client specifically must hold nothing but the wire types.
        assert_eq!(
            allowed_internal_deps("keel-client"),
            Some(&["keel-proto"][..])
        );
    }

    #[test]
    fn only_the_agent_may_touch_vault_storage() {
        // Clients speak the wire protocol; they never open the vault file.
        for client in [
            "keel-client",
            "keel-cli",
            "keel-mcp",
            "keel-native-host",
            "keel-reveal",
        ] {
            let allowed = allowed_internal_deps(client).expect("client crate must have rules");
            assert!(
                !allowed.contains(&"keel-store"),
                "{client} must not be allowed to open the vault file"
            );
        }
    }

    #[test]
    fn only_the_agent_may_depend_on_the_vault_core() {
        let mut with_core = Vec::new();
        for name in NETWORK_FREE_CRATES {
            if let Some(deps) = allowed_internal_deps(name) {
                if deps.contains(&"keel-core") {
                    with_core.push(*name);
                }
            }
        }
        assert_eq!(with_core, vec!["keel-agent"]);
    }

    #[test]
    fn leaf_crates_stay_leaves() {
        assert_eq!(allowed_internal_deps("keel-crypto"), Some(&[][..]));
        assert_eq!(allowed_internal_deps("keel-proto"), Some(&[][..]));
        assert_eq!(allowed_internal_deps("keel-breach"), Some(&[][..]));
    }

    #[test]
    fn unknown_crates_are_rejected_rather_than_defaulted() {
        assert!(allowed_internal_deps("keel-something-new").is_none());
    }

    #[test]
    fn local_socket_crates_are_not_treated_as_network_stacks() {
        // The agent legitimately needs these; banning them would be wrong and
        // would push someone to weaken the gate.
        for allowed in ["tokio", "socket2", "interprocess", "mio"] {
            assert!(
                !BANNED_NETWORK_CRATES.contains(&allowed),
                "{allowed} is local IPC, not an internet stack"
            );
        }
    }

    #[test]
    fn breach_checker_is_the_only_network_exempt_crate() {
        assert!(!NETWORK_FREE_CRATES.contains(&"keel-breach"));
    }

    #[test]
    fn only_two_crates_are_permissively_licensed() {
        // If this test needs changing, someone is widening the permissive surface, which
        // is exactly the change that should not pass without an argument. Every crate that
        // can reach key material, the crypto core, or the vault format must be copyleft.
        for name in NETWORK_FREE_CRATES {
            let expected = expected_license(name).expect("every crate must have a licence");
            if *name == "keel-proto" || *name == "keel-client" {
                assert_ne!(
                    expected, AGPL,
                    "{name} is a deliberate permissive exception"
                );
            } else {
                assert_eq!(expected, AGPL, "{name} must stay copyleft");
            }
        }
    }

    #[test]
    fn the_embeddable_crate_sits_above_everything_it_may_depend_on() {
        // The invariant the whole split rests on: keel-client may only depend on crates
        // whose licence reaches no further than its own, or embedding it silently drags
        // AGPL into a closed application.
        let client = license_reach(expected_license("keel-client").unwrap()).unwrap();
        for dep in allowed_internal_deps("keel-client").unwrap() {
            let dep_reach = license_reach(expected_license(dep).unwrap()).unwrap();
            assert!(
                dep_reach <= client,
                "keel-client (reach {client}) may not depend on {dep} (reach {dep_reach})"
            );
        }
    }

    #[test]
    fn copyleft_reaches_further_than_the_permissive_licences() {
        let agpl = license_reach(AGPL).unwrap();
        assert!(license_reach("MPL-2.0").unwrap() < agpl);
        assert!(license_reach("Apache-2.0").unwrap() < license_reach("MPL-2.0").unwrap());
    }

    #[test]
    fn unranked_licences_are_rejected_rather_than_assumed_harmless() {
        // A licence nobody has ranked must not default to "permissive enough".
        assert!(license_reach("MIT").is_none());
        assert!(license_reach("").is_none());
        assert!(expected_license("keel-something-new").is_none());
    }

    #[test]
    fn the_permissive_crates_are_carved_out_before_the_general_rule() {
        // Ordering bug insurance: `crates/` also matches these paths, and if the general
        // rule won, both crates would be required to carry AGPL headers.
        assert_eq!(
            license_for_path("crates/keel-proto/src/lib.rs"),
            Some("Apache-2.0")
        );
        assert_eq!(
            license_for_path("crates/keel-client/src/lib.rs"),
            Some("MPL-2.0")
        );
        assert_eq!(
            license_for_path("crates/keel-core/src/vault.rs"),
            Some(AGPL)
        );
        assert_eq!(license_for_path("extension/popup.js"), Some(AGPL));
        assert_eq!(
            license_for_path("fuzz/fuzz_targets/vault_parse.rs"),
            Some(AGPL)
        );
    }

    #[test]
    fn source_outside_a_licensed_tree_is_not_silently_accepted() {
        assert!(license_for_path("scripts/whatever.js").is_none());
        assert!(license_for_path("newtree/src/lib.rs").is_none());
    }

    #[test]
    fn the_header_scan_never_descends_into_build_output() {
        // target/ holds copies of dependency sources with other licences; scanning it
        // would produce noise that pressures someone into loosening the check.
        assert!(HEADER_SCAN_SKIP_DIRS.contains(&"target"));
        assert!(HEADER_SCAN_SKIP_DIRS.contains(&"node_modules"));
    }
}
