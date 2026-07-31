// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

//! Minimal `cargo metadata` model.
//!
//! Only the fields the checks actually need are declared. `serde` ignores the
//! rest, so this does not break when cargo adds fields.

use std::collections::HashMap;

use serde::Deserialize;

/// Parsed `cargo metadata --format-version 1` output.
#[derive(Debug)]
pub struct Metadata {
    raw: RawMetadata,
    by_id: HashMap<String, usize>,
    nodes_by_id: HashMap<String, usize>,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
    workspace_root: String,
    #[serde(default)]
    resolve: Option<Resolve>,
}

/// One package in the dependency graph.
#[derive(Debug, Deserialize)]
pub struct Package {
    /// Opaque package identifier, unique across versions and sources.
    pub id: String,
    /// Crate name.
    pub name: String,
    /// SPDX expression from the manifest's `license` field. `None` when a crate
    /// declares none, which for a workspace member is itself a failure — an
    /// undeclared licence is what crates.io and every downstream scanner reads.
    #[serde(default)]
    pub license: Option<String>,
    /// Declared dependencies from this package's manifest.
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
}

/// A manifest-declared dependency edge.
#[derive(Debug, Deserialize)]
pub struct Dependency {
    /// Dependency crate name.
    pub name: String,
    /// `None` for a normal dependency, `Some("dev")` or `Some("build")`
    /// otherwise. Cargo omits the field for normal dependencies.
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Resolve {
    nodes: Vec<ResolveNode>,
}

/// A node in the *resolved* graph, which reflects feature selection and so is the
/// authority on what actually gets linked.
#[derive(Debug, Deserialize)]
pub struct ResolveNode {
    /// Package id this node describes.
    pub id: String,
    /// Package ids this node depends on after resolution.
    #[serde(default)]
    pub dependencies: Vec<String>,
}

/// Parse `cargo metadata` JSON.
pub fn parse(bytes: &[u8]) -> Result<Metadata, String> {
    let raw: RawMetadata = serde_json::from_slice(bytes)
        .map_err(|e| format!("could not parse `cargo metadata` output: {e}"))?;

    let by_id = raw
        .packages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.id.clone(), i))
        .collect();
    let nodes_by_id = raw
        .resolve
        .as_ref()
        .map(|r| {
            r.nodes
                .iter()
                .enumerate()
                .map(|(i, n)| (n.id.clone(), i))
                .collect()
        })
        .unwrap_or_default();

    Ok(Metadata {
        raw,
        by_id,
        nodes_by_id,
    })
}

impl Metadata {
    /// Packages that belong to this workspace, in manifest order.
    pub fn workspace_members(&self) -> impl Iterator<Item = &Package> {
        self.raw
            .packages
            .iter()
            .filter(|p| self.raw.workspace_members.contains(&p.id))
    }

    /// Look up a package by its id.
    pub fn package_by_id(&self, id: &str) -> Option<&Package> {
        self.by_id.get(id).and_then(|i| self.raw.packages.get(*i))
    }

    /// Look up a workspace package by crate name.
    pub fn package_by_name(&self, name: &str) -> Option<&Package> {
        self.workspace_members().find(|p| p.name == name)
    }

    /// Absolute path to the workspace root directory.
    ///
    /// Taken from cargo rather than the process's working directory so the checks give
    /// the same answer however they were invoked.
    pub fn workspace_root(&self) -> &str {
        &self.raw.workspace_root
    }

    /// Look up a node in the resolved graph.
    pub fn resolve_node(&self, id: &str) -> Option<&ResolveNode> {
        let idx = self.nodes_by_id.get(id)?;
        self.raw.resolve.as_ref()?.nodes.get(*idx)
    }
}
