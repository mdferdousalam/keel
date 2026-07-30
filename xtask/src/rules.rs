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
        "keel-core" => &["keel-crypto", "keel-format", "keel-store", "keel-hardening"],

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
}
