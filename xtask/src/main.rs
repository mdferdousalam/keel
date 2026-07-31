// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Repository automation: `cargo xtask <command>`.
//!
//! The check commands here are security controls, not style checks. The layering rule and
//! the no-network rule are claims the project makes in its threat model, and the licence
//! rule is a claim it makes about what anyone downstream is allowed to do with the code —
//! a claim enforced only by discipline is not enforced. CI runs all three on every pull
//! request.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

mod metadata;
mod rules;

use metadata::Metadata;

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1);
    let result = match cmd.as_deref() {
        Some("check-layering") => check_layering(),
        Some("check-network") => check_network(),
        Some("check-licenses") => check_licenses(),
        Some("check") => check_layering()
            .and_then(|()| check_network())
            .and_then(|()| check_licenses()),
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
  check-licenses   Verify SPDX headers and that copyleft cannot leak into the
                   permissively licensed crates (see xtask/src/rules.rs)
  check            Run all checks
  help             Show this message"
    );
}

/// Load `cargo metadata` for the whole workspace.
///
/// `platform` restricts the resolved graph to one target triple. That matters more than it
/// looks: without it, `cargo metadata` returns the **union** of every platform's
/// dependencies, so a crate with an Android-only HTTP client appears to link HTTP
/// everywhere. `tauri` is exactly that case — it depends on `reqwest`, gated to Android and
/// non-macOS Apple targets, neither of which Keel builds for. Checking the union reported a
/// network stack in the desktop app that no shipped binary contains.
///
/// Passing `None` keeps the union, which is the right choice for the layering check: an
/// internal dependency that only exists on one platform is still an internal dependency and
/// still has to obey the direction rules.
fn load_metadata_for(platform: Option<&str>) -> Result<Metadata, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut command = Command::new(cargo);
    command.args(["metadata", "--format-version", "1", "--all-features"]);
    if let Some(triple) = platform {
        command.args(["--filter-platform", triple]);
    }
    let output = command
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

/// Load metadata for every platform, unfiltered.
fn load_metadata() -> Result<Metadata, String> {
    load_metadata_for(None)
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
    let mut failures = Vec::new();
    // Checked once per platform Keel ships, rather than once over the union of all
    // platforms. The union answers a question nobody asked — "could this crate reach HTTP on
    // *some* target, including ones we never build?" — and answering it produced a false
    // report of a network stack in the desktop app.
    for triple in rules::SHIPPED_PLATFORMS {
        let meta = load_metadata_for(Some(triple))?;
        check_network_on(&meta, triple, &mut failures)?;
    }

    if failures.is_empty() {
        println!(
            "network isolation: OK ({} crates verified free of HTTP/TLS stacks on {} platforms)",
            rules::NETWORK_FREE_CRATES.len(),
            rules::SHIPPED_PLATFORMS.len()
        );
        return Ok(());
    }
    Err(format!(
        "network isolation violations:\n\n{}",
        failures.join("\n\n")
    ))
}

fn check_network_on(
    meta: &Metadata,
    triple: &str,
    failures: &mut Vec<String>,
) -> Result<(), String> {
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
                    "`{root}` can reach the network stack `{banned}` on {triple} (pulled in \
                     via `{via}`).\n    \
                     The vault core must not link an HTTP or TLS client. If this is only \
                     needed at build time, in tests, or on a platform Keel does not ship, \
                     scope it so it does not appear in the normal dependency graph for a \
                     shipped target."
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Licensing
// ---------------------------------------------------------------------------

/// Enforce the licence boundary.
///
/// Keel is AGPL-3.0-or-later except for two crates that are permissive on purpose, so
/// that the protocol can be spoken and the client can be embedded. Both exceptions rest
/// on a single property: nothing copyleft sits underneath them. A dependency's licence
/// governs the combined work, so one AGPL crate added below `keel-client` would quietly
/// make every application embedding it AGPL — the manifest would still promise MPL, and
/// the promise would be false.
///
/// Three things are checked, in the order a reader would ask about them:
///
/// 1. every workspace crate declares the licence it is supposed to declare;
/// 2. no crate depends on an internal crate whose licence reaches further than its own;
/// 3. every source file carries a matching SPDX header.
fn check_licenses() -> Result<(), String> {
    let meta = load_metadata()?;
    let mut failures = Vec::new();

    let declared = check_declared_licenses(&meta, &mut failures);
    check_license_reach(&meta, &declared, &mut failures);
    let headers = check_license_headers(Path::new(meta.workspace_root()), &mut failures)?;

    if failures.is_empty() {
        println!(
            "licences: OK ({} crates declared as expected, {} source files carry a matching \
             SPDX header)",
            declared.len(),
            headers
        );
        return Ok(());
    }
    Err(format!(
        "licence violations:\n\n  {}\n",
        failures.join("\n\n  ")
    ))
}

/// Check that each workspace crate declares the licence `rules::expected_license` names.
///
/// Returns the licences actually declared, which the reach check then works from — it has
/// to reason about what ships, not about what was supposed to ship.
fn check_declared_licenses(
    meta: &Metadata,
    failures: &mut Vec<String>,
) -> BTreeMap<String, String> {
    let mut declared = BTreeMap::new();

    for pkg in meta.workspace_members() {
        let Some(expected) = rules::expected_license(&pkg.name) else {
            failures.push(format!(
                "crate `{}` has no entry in `expected_license` in xtask/src/rules.rs.\n    \
                 Add one. Which licence a new crate carries is a decision about what \
                 downstream users may do with it, so it should not have a default.",
                pkg.name
            ));
            continue;
        };

        match pkg.license.as_deref() {
            Some(actual) if actual == expected => {
                declared.insert(pkg.name.clone(), actual.to_owned());
            }
            Some(actual) => {
                failures.push(format!(
                    "`{}` declares `license = \"{actual}\"` but should declare \
                     `\"{expected}\"`.\n    \
                     The manifest is what crates.io and every downstream scanner reads, so \
                     this is the version of the licence that has practical effect. Fix the \
                     manifest, or change xtask/src/rules.rs if the licence really is moving.",
                    pkg.name
                ));
                declared.insert(pkg.name.clone(), actual.to_owned());
            }
            None => {
                failures.push(format!(
                    "`{}` declares no `license` field, so it should declare \
                     `\"{expected}\"`.\n    \
                     An undeclared licence is not a permissive one: it leaves recipients \
                     with no grant at all.",
                    pkg.name
                ));
            }
        }
    }

    declared
}

/// Check that no crate depends on an internal crate whose licence reaches further.
///
/// The walk is transitive, because the leak this prevents does not have to be one edge
/// long: `keel-client` → some helper → `keel-core` would be just as fatal to the
/// embeddability promise as a direct edge, and rather harder to notice in review.
///
/// Dev-dependencies are skipped, matching the layering check — they do not ship, so they
/// do not form a combined work with anything a user receives.
fn check_license_reach(
    meta: &Metadata,
    declared: &BTreeMap<String, String>,
    failures: &mut Vec<String>,
) {
    let internal: BTreeSet<String> = meta.workspace_members().map(|p| p.name.clone()).collect();

    // name -> the internal crates it depends on, non-dev only.
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for pkg in meta.workspace_members() {
        let deps = pkg
            .dependencies
            .iter()
            .filter(|d| internal.contains(&d.name) && d.kind.as_deref() != Some("dev"))
            .map(|d| d.name.as_str())
            .collect();
        edges.insert(pkg.name.as_str(), deps);
    }

    for pkg in meta.workspace_members() {
        let Some(own_license) = declared.get(&pkg.name) else {
            // Already reported as undeclared; nothing further to say about it.
            continue;
        };
        let Some(own_reach) = rules::license_reach(own_license) else {
            failures.push(format!(
                "`{}` declares `{own_license}`, which `license_reach` in \
                 xtask/src/rules.rs does not rank.\n    \
                 Rank it there before using it, so the check can tell whether it may sit \
                 above or below the other licences in this tree.",
                pkg.name
            ));
            continue;
        };

        // Breadth-first over internal crates, remembering the path so the message can
        // name the chain rather than just the endpoint.
        let mut arrived_via: BTreeMap<&str, &str> = BTreeMap::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut queue = VecDeque::new();
        seen.insert(pkg.name.as_str());
        queue.push_back(pkg.name.as_str());

        while let Some(name) = queue.pop_front() {
            for dep in edges.get(name).map(Vec::as_slice).unwrap_or_default() {
                if !seen.insert(dep) {
                    continue;
                }
                arrived_via.insert(dep, name);
                queue.push_back(dep);

                let Some(dep_license) = declared.get(*dep) else {
                    continue;
                };
                let Some(dep_reach) = rules::license_reach(dep_license) else {
                    continue; // reported when that crate is its own subject
                };
                if dep_reach > own_reach {
                    let via = arrived_via.get(dep).copied().unwrap_or("?");
                    let hop = if via == pkg.name.as_str() {
                        "directly".to_owned()
                    } else {
                        format!("via `{via}`")
                    };
                    failures.push(format!(
                        "`{}` is `{own_license}` but depends {hop} on `{dep}`, which is \
                         `{dep_license}`.\n    \
                         A dependency's licence governs the combined work, so this makes \
                         `{}` effectively `{dep_license}` no matter what its manifest \
                         says — and anything embedding it inherits that. Either drop the \
                         dependency or accept that `{}` is no longer embeddable, which is \
                         a decision for the pull request to argue, not a detail.",
                        pkg.name, pkg.name, pkg.name
                    ));
                }
            }
        }
    }
}

/// Check that every source file carries an SPDX header matching its tree.
///
/// Returns the number of files verified, so a silently-empty scan cannot pass as success.
fn check_license_headers(root: &Path, failures: &mut Vec<String>) -> Result<usize, String> {
    let mut files = Vec::new();
    collect_source_files(root, root, &mut files)?;
    files.sort();

    if files.is_empty() {
        return Err(format!(
            "the licence header scan found no source files under {}. \
             The check is not doing anything — treat this as a failure, not a pass.",
            root.display()
        ));
    }

    let mut verified = 0usize;
    for (relative, path) in &files {
        let Some(expected) = rules::license_for_path(relative) else {
            failures.push(format!(
                "`{relative}` is not inside any licensed tree listed in `license_for_path` \
                 in xtask/src/rules.rs.\n    \
                 Add the directory there with the licence its files carry. A new tree of \
                 source with no stated licence is the gap this check exists to catch."
            ));
            continue;
        };

        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?;
        // The header is at the top by construction, and bounding the search keeps an
        // SPDX identifier quoted in the middle of a file from satisfying the check.
        let head: String = text.lines().take(8).collect::<Vec<_>>().join("\n");
        let wanted = format!("SPDX-License-Identifier: {expected}");

        if head.contains(&wanted) {
            verified += 1;
        } else if let Some(found) = head
            .split_once("SPDX-License-Identifier: ")
            .map(|(_, rest)| rest.lines().next().unwrap_or("").trim().to_owned())
        {
            failures.push(format!(
                "`{relative}` declares `SPDX-License-Identifier: {found}` but is in a \
                 `{expected}` tree.\n    \
                 A file that moved between crates keeps its old header, and then two \
                 files in one crate claim different terms."
            ));
        } else {
            failures.push(format!(
                "`{relative}` has no SPDX header in its first 8 lines; it needs \
                 `SPDX-License-Identifier: {expected}`.\n    \
                 Per-file headers are what make a file's terms independent of which \
                 directory a reader thinks it is in — and MPL-2.0 section 3.1 requires \
                 the notice outright."
            ));
        }
    }

    Ok(verified)
}

/// Recursively collect source files, returning `(path relative to root, absolute path)`.
///
/// A hand-rolled walk rather than a crate: xtask has to build before the checks can run,
/// so its dependencies are a cost paid on every clean CI job.
fn collect_source_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("could not read {}: {e}", dir.display()))?;

    for entry in entries {
        let entry =
            entry.map_err(|e| format!("could not read an entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();

        let file_type = entry
            .file_type()
            .map_err(|e| format!("could not stat {}: {e}", path.display()))?;

        if file_type.is_dir() {
            if rules::HEADER_SCAN_SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            collect_source_files(root, &path, out)?;
            continue;
        }
        // Symlinks are not followed: a link into target/ would otherwise reintroduce
        // build artifacts the skip list exists to exclude.
        if !file_type.is_file() {
            continue;
        }

        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !rules::LICENSED_EXTENSIONS.contains(&extension.as_str()) {
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("{} is not under the workspace root", path.display()))?
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        out.push((relative, path));
    }
    Ok(())
}
