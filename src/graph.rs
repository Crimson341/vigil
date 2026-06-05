//! Dependency-graph extraction and "why is this here?" path-finding.
//!
//! A flat list of vulnerable packages isn't actionable when the package is
//! transitive — you can't `npm upgrade lodash` if you never depended on lodash
//! directly. This module reconstructs the parent→child dependency graph from the
//! lockfile (at the package-name level) and finds the shortest chain from a
//! direct dependency to a vulnerable one: `vite › esbuild › vulnerable-pkg`.
//!
//! The graph is name-level (not name@version), which is uniform across lockfile
//! formats and actionable in the overwhelming majority of cases. When two
//! versions of the same package are installed via different parents, the path is
//! one valid chain to that package name, not necessarily the one carrying the
//! exact vulnerable version — a deliberate v0.2 simplification.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::lockfile::LockfileKind;

/// A name-level dependency graph: parent package name → child package names.
#[derive(Debug, Default)]
pub struct DepGraph {
    edges: HashMap<String, HashSet<String>>,
}

impl DepGraph {
    /// Build the graph from raw lockfile content for the given format. Returns an
    /// empty graph (path-finding then yields `None`) when the format's graph
    /// cannot be recovered, so callers degrade gracefully.
    #[must_use]
    pub fn from_lockfile(content: &str, kind: LockfileKind) -> Self {
        let edges = match kind {
            LockfileKind::Pnpm => pnpm_edges(content),
            LockfileKind::Npm => npm_edges(content),
            LockfileKind::Yarn => yarn_edges(content),
            LockfileKind::Bun => bun_edges(content),
        };
        Self { edges }
    }

    /// Whether the graph has any edges (i.e. path-finding can work).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Shortest chain of package names from any `root` (a direct dependency) to
    /// `target`, inclusive of both ends. `None` if unreachable. A `target` that
    /// is itself a root returns `[target]`.
    #[must_use]
    pub fn path_to(&self, roots: &HashSet<String>, target: &str) -> Option<Vec<String>> {
        if roots.contains(target) {
            return Some(vec![target.to_string()]);
        }
        // BFS from a synthetic super-source over all roots.
        let mut prev: HashMap<&str, &str> = HashMap::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for root in roots {
            queue.push_back(root.as_str());
            seen.insert(root.as_str());
        }
        while let Some(node) = queue.pop_front() {
            if let Some(children) = self.edges.get(node) {
                for child in children {
                    if child == target {
                        // Reconstruct the chain root → … → node → target.
                        let mut chain = vec![target.to_string()];
                        let mut cur = node;
                        chain.push(cur.to_string());
                        while let Some(&p) = prev.get(cur) {
                            chain.push(p.to_string());
                            cur = p;
                        }
                        chain.reverse();
                        return Some(chain);
                    }
                    if seen.insert(child.as_str()) {
                        prev.insert(child.as_str(), node);
                        queue.push_back(child.as_str());
                    }
                }
            }
        }
        None
    }
}

/// Add a parent→child edge.
fn add(edges: &mut HashMap<String, HashSet<String>>, parent: &str, child: &str) {
    if parent.is_empty() || child.is_empty() || parent == child {
        return;
    }
    edges
        .entry(parent.to_string())
        .or_default()
        .insert(child.to_string());
}

/// Package name from a lockfile key like `@scope/pkg@1.2.3(peer)` or `lodash@4.1`.
#[must_use]
fn name_from_key(raw: &str) -> Option<String> {
    let key = raw.trim().trim_start_matches('/');
    if key.is_empty() {
        return None;
    }
    let end = if let Some(rest) = key.strip_prefix('@') {
        let slash = rest.find('/')?;
        rest[slash..].find('@').map_or(key.len(), |i| slash + i + 1)
    } else {
        key.find('@').unwrap_or(key.len())
    };
    let name = &key[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// pnpm: `snapshots` / `packages` keys carry the parent; each entry's
/// `dependencies` / `optionalDependencies` maps name children.
#[must_use]
fn pnpm_edges(content: &str) -> HashMap<String, HashSet<String>> {
    let mut edges = HashMap::new();
    let Ok(value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(content) else {
        return edges;
    };
    let Some(root) = value.as_mapping() else {
        return edges;
    };
    for section in ["snapshots", "packages"] {
        let Some(map) = root.get(section).and_then(serde_yaml_ng::Value::as_mapping) else {
            continue;
        };
        for (key, entry) in map {
            let Some(parent) = key.as_str().and_then(name_from_key) else {
                continue;
            };
            let Some(entry_map) = entry.as_mapping() else {
                continue;
            };
            for dep_section in ["dependencies", "optionalDependencies"] {
                if let Some(deps) = entry_map
                    .get(dep_section)
                    .and_then(serde_yaml_ng::Value::as_mapping)
                {
                    for child in deps.keys().filter_map(serde_yaml_ng::Value::as_str) {
                        add(&mut edges, &parent, child);
                    }
                }
            }
        }
    }
    edges
}

/// npm v2/v3: `packages` keys are `node_modules/<name>` paths; each entry's
/// `dependencies` / `optionalDependencies` maps name children.
#[must_use]
fn npm_edges(content: &str) -> HashMap<String, HashSet<String>> {
    let mut edges = HashMap::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return edges;
    };
    let Some(packages) = value.get("packages").and_then(serde_json::Value::as_object) else {
        return edges;
    };
    for (path, entry) in packages {
        // Root entry "" has no node_modules segment; its name is the project.
        let parent = if path.is_empty() {
            String::new()
        } else if let Some(tail) = path.rsplit("node_modules/").next() {
            tail.trim_matches('/').to_string()
        } else {
            continue;
        };
        for dep_section in ["dependencies", "optionalDependencies"] {
            if let Some(deps) = entry.get(dep_section).and_then(serde_json::Value::as_object) {
                for child in deps.keys() {
                    add(&mut edges, &parent, child);
                }
            }
        }
    }
    edges
}

/// yarn.lock: a descriptor header names the parent; an indented `dependencies:`
/// block lists children (both classic `name "range"` and berry `name: range`).
#[must_use]
fn yarn_edges(content: &str) -> HashMap<String, HashSet<String>> {
    let mut edges = HashMap::new();
    let mut parent: Option<String> = None;
    let mut in_deps = false;
    for line in content.lines() {
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 && line.trim_end().ends_with(':') {
            parent = yarn_name_from_descriptor(line.trim_end().trim_end_matches(':'));
            in_deps = false;
            continue;
        }
        let trimmed = line.trim();
        if indent <= 2 {
            in_deps = trimmed.starts_with("dependencies:")
                || trimmed.starts_with("optionalDependencies:");
            continue;
        }
        if in_deps && indent >= 4
            && let Some(parent) = parent.as_deref()
        {
            // `  "@scope/x" "^1.0.0"` or `  name: ^1.0.0`
            let child_raw = trimmed
                .split_once([' ', ':'])
                .map_or(trimmed, |(h, _)| h);
            let child = child_raw.trim().trim_matches('"');
            if !child.is_empty() {
                add(&mut edges, parent, child);
            }
        }
    }
    edges
}

/// Extract the parent name from a yarn descriptor header (first comma-separated
/// descriptor, version range stripped).
#[must_use]
fn yarn_name_from_descriptor(header: &str) -> Option<String> {
    let first = header.split(',').next()?.trim().trim_matches('"');
    let at = if let Some(rest) = first.strip_prefix('@') {
        let slash = rest.find('/')?;
        rest[slash..].find('@').map(|i| slash + i + 1)?
    } else {
        first.find('@')?
    };
    let name = &first[..at];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// bun.lock: each `packages` entry is an array; the object element may carry a
/// `dependencies` map naming children.
#[must_use]
fn bun_edges(content: &str) -> HashMap<String, HashSet<String>> {
    let mut edges = HashMap::new();
    let parsed: Result<Option<serde_json::Value>, _> =
        jsonc_parser::parse_to_serde_value(content, &jsonc_parser::ParseOptions::default());
    let Ok(Some(value)) = parsed else {
        return edges;
    };
    let Some(packages) = value.get("packages").and_then(serde_json::Value::as_object) else {
        return edges;
    };
    for (key, entry) in packages {
        let parent = name_from_key(key).unwrap_or_else(|| key.clone());
        let serde_json::Value::Array(arr) = entry else {
            continue;
        };
        for element in arr {
            if let Some(deps) = element.get("dependencies").and_then(serde_json::Value::as_object) {
                for child in deps.keys() {
                    add(&mut edges, &parent, child);
                }
            }
        }
    }
    edges
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn pnpm_path_finds_transitive_chain() {
        let content = "\
lockfileVersion: '9.0'
snapshots:
  vite@5.0.0:
    dependencies:
      esbuild: 0.19.0
  esbuild@0.19.0:
    dependencies:
      nanoid: 3.0.0
  nanoid@3.0.0: {}
";
        let g = DepGraph::from_lockfile(content, LockfileKind::Pnpm);
        let path = g.path_to(&roots(&["vite"]), "nanoid").unwrap();
        assert_eq!(path, vec!["vite", "esbuild", "nanoid"]);
    }

    #[test]
    fn direct_dep_path_is_itself() {
        let content = "\
lockfileVersion: '9.0'
snapshots:
  vite@5.0.0:
    dependencies:
      esbuild: 0.19.0
";
        let g = DepGraph::from_lockfile(content, LockfileKind::Pnpm);
        assert_eq!(g.path_to(&roots(&["vite"]), "vite").unwrap(), vec!["vite"]);
    }

    #[test]
    fn npm_path_finds_transitive_chain() {
        let content = r#"{
  "packages": {
    "": { "dependencies": { "vite": "^5" } },
    "node_modules/vite": { "version": "5.0.0", "dependencies": { "esbuild": "^0.19" } },
    "node_modules/esbuild": { "version": "0.19.0", "dependencies": { "nanoid": "^3" } },
    "node_modules/nanoid": { "version": "3.0.0" }
  }
}"#;
        let g = DepGraph::from_lockfile(content, LockfileKind::Npm);
        let path = g.path_to(&roots(&["vite"]), "nanoid").unwrap();
        assert_eq!(path, vec!["vite", "esbuild", "nanoid"]);
    }

    #[test]
    fn yarn_path_finds_transitive_chain() {
        let content = "\
vite@^5.0.0:
  version \"5.0.0\"
  dependencies:
    esbuild \"^0.19.0\"

esbuild@^0.19.0:
  version \"0.19.0\"
  dependencies:
    nanoid \"^3.0.0\"

nanoid@^3.0.0:
  version \"3.0.0\"
";
        let g = DepGraph::from_lockfile(content, LockfileKind::Yarn);
        let path = g.path_to(&roots(&["vite"]), "nanoid").unwrap();
        assert_eq!(path, vec!["vite", "esbuild", "nanoid"]);
    }

    #[test]
    fn unreachable_returns_none() {
        let content = "\
lockfileVersion: '9.0'
snapshots:
  vite@5.0.0: {}
";
        let g = DepGraph::from_lockfile(content, LockfileKind::Pnpm);
        assert!(g.path_to(&roots(&["vite"]), "ghost").is_none());
    }
}
