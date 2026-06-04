//! Minimal `package.json` parsing and workspace discovery.
//!
//! vigil only needs the declared dependency names (to classify findings as
//! direct vs transitive and prod vs dev) and the monorepo `workspaces` globs, so
//! this is a deliberately small subset of the full manifest.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The subset of `package.json` vigil consumes.
#[derive(Debug, Default, Deserialize)]
pub struct PackageJson {
    #[serde(default)]
    pub dependencies: Option<HashMap<String, String>>,
    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: Option<HashMap<String, String>>,
    #[serde(default, rename = "optionalDependencies")]
    pub optional_dependencies: Option<HashMap<String, String>>,
    #[serde(default, rename = "peerDependencies")]
    pub peer_dependencies: Option<HashMap<String, String>>,
    #[serde(default)]
    pub workspaces: Option<serde_json::Value>,
}

impl PackageJson {
    /// Load and parse a `package.json`. Returns `None` on read/parse failure or a
    /// leading UTF-8 BOM is stripped first.
    #[must_use]
    pub fn load(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        let content = content.trim_start_matches('\u{feff}');
        serde_json::from_str(content).ok()
    }

    /// The `workspaces` globs (array form, or object `{ packages: [...] }`).
    #[must_use]
    pub fn workspace_patterns(&self) -> Vec<String> {
        match &self.workspaces {
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(serde_json::Value::Object(obj)) => obj
                .get("packages")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

/// Discover workspace package directories under `root` by expanding the root
/// `package.json` `workspaces` globs (npm/yarn/bun) and `pnpm-workspace.yaml`
/// `packages:` globs (pnpm). Returns directories that contain a `package.json`.
#[must_use]
pub fn discover_workspace_dirs(root: &Path) -> Vec<PathBuf> {
    let mut patterns = Vec::new();
    if let Some(pkg) = PackageJson::load(&root.join("package.json")) {
        patterns.extend(pkg.workspace_patterns());
    }
    patterns.extend(pnpm_workspace_patterns(root));

    let mut dirs = Vec::new();
    for pattern in patterns {
        // A workspace glob points at package directories; append package.json so
        // the glob walk only yields real manifests.
        let joined = root.join(&pattern).join("package.json");
        let Some(glob_str) = joined.to_str() else {
            continue;
        };
        let Ok(paths) = glob::glob(glob_str) else {
            continue;
        };
        for entry in paths.flatten() {
            if let Some(dir) = entry.parent() {
                dirs.push(dir.to_path_buf());
            }
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Parse `pnpm-workspace.yaml` `packages:` globs, if present.
#[must_use]
fn pnpm_workspace_patterns(root: &Path) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(root.join("pnpm-workspace.yaml")) else {
        return Vec::new();
    };
    let Ok(value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&content) else {
        return Vec::new();
    };
    value
        .get("packages")
        .and_then(serde_yaml_ng::Value::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_patterns_array() {
        let pkg: PackageJson =
            serde_json::from_str(r#"{"workspaces": ["packages/*", "apps/*"]}"#).unwrap();
        assert_eq!(pkg.workspace_patterns(), vec!["packages/*", "apps/*"]);
    }

    #[test]
    fn workspace_patterns_object() {
        let pkg: PackageJson =
            serde_json::from_str(r#"{"workspaces": {"packages": ["packages/*"]}}"#).unwrap();
        assert_eq!(pkg.workspace_patterns(), vec!["packages/*"]);
    }

    #[test]
    fn workspace_patterns_none() {
        let pkg: PackageJson = serde_json::from_str(r#"{"name": "x"}"#).unwrap();
        assert!(pkg.workspace_patterns().is_empty());
    }

    #[test]
    fn loads_dependency_maps() {
        let pkg: PackageJson = serde_json::from_str(
            r#"{"dependencies":{"a":"^1"},"devDependencies":{"b":"^2"}}"#,
        )
        .unwrap();
        assert_eq!(pkg.dependencies.unwrap().get("a").unwrap(), "^1");
        assert_eq!(pkg.dev_dependencies.unwrap().get("b").unwrap(), "^2");
    }
}
