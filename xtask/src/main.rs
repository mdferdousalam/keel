//! Repository automation: `cargo xtask <command>`.
//!
//! The two check commands here are security controls, not style checks. Both the
//! layering rule and the no-network rule are claims the project makes in its
//! threat model, and a claim enforced only by discipline is not enforced. CI runs
//! both on every pull request.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::process::{Command, ExitCode};

mod metadata;
mod rules;

use metadata::Metadata;

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1);
    let result = match cmd.as_deref() {
        Some("check-layering") => check_layering(),
        Some("check-network") => check_network(),
        Some("check") => check_layering().and_then(|()| check_network()),
        Some("help" | "--help" | "-h") | None => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!(
            "unknown command {other:?}\n\nRun `cargo xtask help` for the command list."
        )),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("\nxtask: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "\
cargo xtask <command>

Commands:
  check-layering   Verify crate dependency direction (see xtask/src/rules.rs)
  check-network    Verify no HTTP/TLS stack reaches the vault core
  check            Run all checks
  help             Show this message"
    );
}

/// Load `cargo metadata` for the whole workspace.
fn load_metadata() -> Result<Metadata, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--all-features"])
        .output()
        .map_err(|e| format!("could not run `cargo metadata`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`cargo metadata` failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    metadata::parse(&output.stdout)
}

// ---------------------------------------------------------------------------
// Layering
// ---------------------------------------------------------------------------

/// Enforce the crate dependency direction.
///
/// The rule that matters most: `keel-client` must not depend on `keel-crypto`,
/// `keel-format`, or `keel-core`. Only `keel-agent` links the cryptographic core
/// at runtime, which is what lets "where can key material be?" have a short
/// answer during review. Every other process is a pipe for already-authorized
/// data.
fn check_layering() -> Result<(), String> {
    let meta = load_metadata()?;
    let internal: BTreeSet<String> = meta.workspace_members().map(|p| p.name.clone()).collect();

    let mut violations = Vec::new();
    let mut checked = 0usize;

    for pkg in meta.workspace_members() {
        checked += 1;
        let Some(allowed) = rules::allowed_internal_deps(&pkg.name) else {
            violations.push(format!(
                "crate `{}` has no entry in xtask/src/rules.rs.\n    \
                 Add one describing which internal crates it may depend on. A new crate \
                 near the vault core is exactly the change that should require a \
                 deliberate decision rather than passing silently.",
                pkg.name
            ));
            continue;
        };
        let allowed: BTreeSet<&str> = allowed.iter().copied().collect();

        for dep in &pkg.dependencies {
            // External crates are governed by deny.toml, not by layering.
            if !internal.contains(&dep.name) {
                continue;
            }
            // Dev-dependencies do not ship, so they do not affect the runtime
            // trust boundary this rule protects.
            if dep.kind.as_deref() == Some("dev") {
                continue;
            }
            if !allowed.contains(dep.name.as_str()) {
                violations.push(format!(
                    "`{}` depends on `{}`, which the layering rules do not allow.\n    \
                     Allowed: {}\n    \
                     If this dependency is genuinely correct, update xtask/src/rules.rs \
                     and explain why in the pull request.",
                    pkg.name,
                    dep.name,
                    if allowed.is_empty() {
                        "(nothing — this crate must stay free of internal dependencies)".to_owned()
                    } else {
                        allowed.iter().copied().collect::<Vec<_>>().join(", ")
                    }
                ));
            }
        }
    }

    if violations.is_empty() {
        println!("layering: OK ({checked} workspace crates checked)");
        Ok(())
    } else {
        Err(format!(
            "layering violations:\n\n  {}\n",
            violations.join("\n\n  ")
        ))
    }
}

// ---------------------------------------------------------------------------
// Network isolation
// ---------------------------------------------------------------------------

/// Enforce that no HTTP or TLS stack is reachable from the vault core.
///
/// "The vault makes no network connections" is a headline claim, so it is checked
/// against the real resolved dependency graph rather than the manifests. A network
/// stack arriving three levels down through a new transitive dependency fails CI
/// instead of shipping.
///
/// `keel-breach` is exempt by design: it is the opt-in, off-by-default breach
/// checker and the only crate permitted to reach the internet.
fn check_network() -> Result<(), String> {
    let meta = load_metadata()?;
    let mut failures = Vec::new();

    for root in rules::NETWORK_FREE_CRATES {
        let Some(root_pkg) = meta.package_by_name(root) else {
            return Err(format!(
                "crate `{root}` is listed in NETWORK_FREE_CRATES but was not found in the \
                 workspace. Either the crate was renamed or the list is stale."
            ));
        };

        // Breadth-first walk of the resolved graph, recording how each crate was
        // reached so the failure message names the culprit edge.
        let mut arrived_via: BTreeMap<String, String> = BTreeMap::new();
        let mut seen_ids: BTreeSet<String> = BTreeSet::new();
        let mut reachable_names: BTreeSet<String> = BTreeSet::new();
        let mut queue = VecDeque::new();

        seen_ids.insert(root_pkg.id.clone());
        queue.push_back(root_pkg.id.clone());

        while let Some(id) = queue.pop_front() {
            let from_name = meta
                .package_by_id(&id)
                .map_or_else(|| "?".to_owned(), |p| p.name.clone());
            let Some(node) = meta.resolve_node(&id) else {
                continue;
            };
            for dep_id in &node.dependencies {
                if !seen_ids.insert(dep_id.clone()) {
                    continue;
                }
                let dep_name = meta
                    .package_by_id(dep_id)
                    .map_or_else(|| "?".to_owned(), |p| p.name.clone());
                arrived_via
                    .entry(dep_name.clone())
                    .or_insert_with(|| from_name.clone());
                reachable_names.insert(dep_name);
                queue.push_back(dep_id.clone());
            }
        }

        for banned in rules::BANNED_NETWORK_CRATES {
            if reachable_names.contains(*banned) {
                let via = arrived_via
                    .get(*banned)
                    .map_or("?", std::string::String::as_str);
                failures.push(format!(
                    "`{root}` can reach the network stack `{banned}` (pulled in via `{via}`).\n    \
                     The vault core must not link an HTTP or TLS client. If this is only needed \
                     at build time or in tests, scope it so it does not appear in the normal \
                     dependency graph."
                ));
            }
        }
    }

    if failures.is_empty() {
        println!(
            "network isolation: OK ({} crates verified free of HTTP/TLS stacks)",
            rules::NETWORK_FREE_CRATES.len()
        );
        Ok(())
    } else {
        Err(format!(
            "network isolation violations:\n\n  {}\n",
            failures.join("\n\n  ")
        ))
    }
}
