//! Lockfile resolution.
//!
//! Software Composition Analysis needs the *resolved installed version* of each
//! dependency, not the `package.json` range (`^1.2.3`), so version-range matching
//! against an advisory can be exact. This module parses the four common npm
//! lockfile formats into a deduped `Vec<ResolvedDep>`.
//!
//! Parsing functions are pure (they take `&str`) so they are unit-testable
//! offline; [`resolve_lockfile`] is the IO entry point that picks the
//! highest-priority lockfile present in a directory.
//!
//! Priority: `pnpm-lock.yaml` > `package-lock.json` > `yarn.lock` > `bun.lock`.
//! `bun.lockb` (the legacy binary format) is intentionally unsupported: it cannot
//! be parsed without bun itself, and modern bun emits the text `bun.lock`.

use std::collections::HashSet;
use std::path::Path;

/// A single resolved dependency from a lockfile: an exact `name@version` plus
/// whether it is dev-only (used to support `--prod-only`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedDep {
    /// The npm package name (scope preserved, e.g. `@scope/pkg`).
    pub name: String,
    /// The exact resolved version (e.g. `1.2.3`, `1.2.3-beta.1`).
    pub version: String,
    /// Whether the package is resolved only through the dev dependency tree.
    /// Best-effort: not every lockfile format records this, in which case it is
    /// `false` (treated as production, the conservative choice for a security scan).
    pub dev: bool,
}

/// Which lockfile format a directory's resolution came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileKind {
    /// `pnpm-lock.yaml`
    Pnpm,
    /// `package-lock.json`
    Npm,
    /// `yarn.lock`
    Yarn,
    /// `bun.lock`
    Bun,
}

impl LockfileKind {
    /// The on-disk filename for this lockfile kind.
    #[must_use]
    pub const fn filename(self) -> &'static str {
        match self {
            Self::Pnpm => "pnpm-lock.yaml",
            Self::Npm => "package-lock.json",
            Self::Yarn => "yarn.lock",
            Self::Bun => "bun.lock",
        }
    }

    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        self.filename()
    }
}

/// The outcome of resolving a directory's lockfile.
#[derive(Debug, Clone)]
pub struct LockfileResolution {
    /// The lockfile that was parsed.
    pub kind: LockfileKind,
    /// The deduped resolved dependencies.
    pub deps: Vec<ResolvedDep>,
}

/// Resolve the highest-priority lockfile present in `dir`.
///
/// Returns `None` when no supported lockfile is found, or when the present
/// lockfile could not be read or parsed into any entries.
#[must_use]
pub fn resolve_lockfile(dir: &Path) -> Option<LockfileResolution> {
    for kind in [
        LockfileKind::Pnpm,
        LockfileKind::Npm,
        LockfileKind::Yarn,
        LockfileKind::Bun,
    ] {
        let path = dir.join(kind.filename());
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let deps = match kind {
            LockfileKind::Pnpm => parse_pnpm_lock(&content),
            LockfileKind::Npm => parse_npm_lock(&content),
            LockfileKind::Yarn => parse_yarn_lock(&content),
            LockfileKind::Bun => parse_bun_lock(&content),
        };
        if !deps.is_empty() {
            return Some(LockfileResolution { kind, deps });
        }
    }
    None
}

/// Dedupe a list of resolved deps by `(name, version)`, preserving the first
/// occurrence's `dev` flag but downgrading to production if ANY occurrence is a
/// production dep (a package present in both trees is a production dependency).
#[must_use]
fn dedupe(mut deps: Vec<ResolvedDep>) -> Vec<ResolvedDep> {
    deps.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    let mut out: Vec<ResolvedDep> = Vec::with_capacity(deps.len());
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for dep in deps {
        let key = (dep.name.clone(), dep.version.clone());
        if seen.insert(key) {
            out.push(dep);
        } else if !dep.dev
            && let Some(existing) = out
                .iter_mut()
                .find(|d| d.name == dep.name && d.version == dep.version)
        {
            existing.dev = false;
        }
    }
    out
}

/// Split a lockfile descriptor key such as `@scope/pkg@1.2.3` or `lodash@4.17.21`
/// into `(name, version)`. The version is truncated at the first `(` (pnpm peer
/// suffix). Returns `None` for non-registry specifiers (`file:`, `link:`,
/// `workspace:`, `git`, URLs) whose "version" is not a semver string.
#[must_use]
fn split_name_version(raw: &str) -> Option<(String, String)> {
    let key = raw.trim().trim_start_matches('/');
    if key.is_empty() {
        return None;
    }
    let version_at = if let Some(rest) = key.strip_prefix('@') {
        let slash = rest.find('/')?;
        rest[slash..].find('@').map(|i| slash + i + 1)
    } else {
        key.find('@')
    }?;
    let name = &key[..version_at];
    let mut version = &key[version_at + 1..];
    if let Some(paren) = version.find('(') {
        version = &version[..paren];
    }
    if name.is_empty() || version.is_empty() {
        return None;
    }
    if version.contains(':') || version.contains('/') {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Parse `pnpm-lock.yaml`. Resolved versions live in the `packages:` (v6) or
/// `snapshots:` (v9) section keys.
#[must_use]
pub fn parse_pnpm_lock(content: &str) -> Vec<ResolvedDep> {
    let Ok(value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(content) else {
        return Vec::new();
    };
    let Some(root) = value.as_mapping() else {
        return Vec::new();
    };
    let mut deps = Vec::new();
    for section in ["packages", "snapshots"] {
        let Some(map) = root.get(section).and_then(serde_yaml_ng::Value::as_mapping) else {
            continue;
        };
        for key in map.keys().filter_map(serde_yaml_ng::Value::as_str) {
            if let Some((name, version)) = split_name_version(key) {
                deps.push(ResolvedDep {
                    name,
                    version,
                    dev: false,
                });
            }
        }
    }
    dedupe(deps)
}

/// Parse `package-lock.json` (lockfileVersion 2/3). The `packages` object keys
/// are `node_modules/<name>` paths; each value carries a `version` and an
/// optional `dev` flag.
#[must_use]
pub fn parse_npm_lock(content: &str) -> Vec<ResolvedDep> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let mut deps = Vec::new();
    if let Some(packages) = value.get("packages").and_then(serde_json::Value::as_object) {
        for (path, entry) in packages {
            let Some(name) = name_from_npm_path(path) else {
                continue;
            };
            let Some(version) = entry.get("version").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let dev = entry
                .get("dev")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            deps.push(ResolvedDep {
                name,
                version: version.to_string(),
                dev,
            });
        }
    }
    if deps.is_empty()
        && let Some(map) = value
            .get("dependencies")
            .and_then(serde_json::Value::as_object)
    {
        collect_npm_v1_dependencies(map, &mut deps);
    }
    dedupe(deps)
}

/// Extract the package name from a `package-lock.json` v2/v3 path key such as
/// `node_modules/@scope/pkg/node_modules/dep` — the name is the segment after
/// the LAST `node_modules/`.
#[must_use]
fn name_from_npm_path(path: &str) -> Option<String> {
    if !path.contains("node_modules/") {
        return None;
    }
    let tail = path.rsplit("node_modules/").next()?;
    let trimmed = tail.trim_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Recursively collect deps from a lockfileVersion-1 `dependencies` tree.
fn collect_npm_v1_dependencies(
    map: &serde_json::Map<String, serde_json::Value>,
    deps: &mut Vec<ResolvedDep>,
) {
    for (name, entry) in map {
        if let Some(version) = entry.get("version").and_then(serde_json::Value::as_str) {
            let dev = entry
                .get("dev")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            deps.push(ResolvedDep {
                name: name.clone(),
                version: version.to_string(),
                dev,
            });
        }
        if let Some(nested) = entry
            .get("dependencies")
            .and_then(serde_json::Value::as_object)
        {
            collect_npm_v1_dependencies(nested, deps);
        }
    }
}

/// Parse `yarn.lock`. Handles both classic (v1, custom syntax) and Berry (v2+,
/// valid YAML) by scanning for descriptor headers (unindented lines ending in
/// `:`) followed by an indented `version` line.
#[must_use]
pub fn parse_yarn_lock(content: &str) -> Vec<ResolvedDep> {
    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    for line in content.lines() {
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if !indented && line.trim_end().ends_with(':') {
            current_name = yarn_name_from_descriptor(line.trim_end().trim_end_matches(':'));
        } else if indented {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("version") {
                let version = rest.trim().trim_matches([':', ' ', '"']).to_string();
                if let Some(name) = current_name.take()
                    && !version.is_empty()
                {
                    deps.push(ResolvedDep {
                        name,
                        version,
                        dev: false,
                    });
                }
            }
        }
    }
    dedupe(deps)
}

/// Extract a package name from a yarn.lock descriptor header line, e.g.
/// `"@scope/pkg@npm:^1.0.0, @scope/pkg@^2.0.0"` or `lodash@^4.17.21`.
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

/// Parse the modern text `bun.lock` (JSONC). The `packages` object maps a key to
/// an array whose first element is the `name@version` descriptor.
#[must_use]
pub fn parse_bun_lock(content: &str) -> Vec<ResolvedDep> {
    let parsed: Result<Option<serde_json::Value>, _> =
        jsonc_parser::parse_to_serde_value(content, &jsonc_parser::ParseOptions::default());
    let Ok(Some(value)) = parsed else {
        return Vec::new();
    };
    let mut deps = Vec::new();
    if let Some(packages) = value.get("packages").and_then(serde_json::Value::as_object) {
        for entry in packages.values() {
            let descriptor = match entry {
                serde_json::Value::Array(arr) => arr.first().and_then(serde_json::Value::as_str),
                serde_json::Value::String(s) => Some(s.as_str()),
                _ => None,
            };
            if let Some((name, version)) = descriptor.and_then(split_name_version) {
                deps.push(ResolvedDep {
                    name,
                    version,
                    dev: false,
                });
            }
        }
    }
    dedupe(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_unscoped() {
        assert_eq!(
            split_name_version("lodash@4.17.21"),
            Some(("lodash".into(), "4.17.21".into()))
        );
    }

    #[test]
    fn split_scoped() {
        assert_eq!(
            split_name_version("@scope/pkg@1.2.3"),
            Some(("@scope/pkg".into(), "1.2.3".into()))
        );
    }

    #[test]
    fn split_strips_pnpm_peer_suffix() {
        assert_eq!(
            split_name_version("react-dom@18.2.0(react@18.2.0)"),
            Some(("react-dom".into(), "18.2.0".into()))
        );
    }

    #[test]
    fn split_rejects_non_registry() {
        assert_eq!(split_name_version("foo@file:../foo"), None);
        assert_eq!(split_name_version("foo@workspace:*"), None);
        assert_eq!(split_name_version("foo@github:user/repo"), None);
    }

    #[test]
    fn pnpm_lock_v9_snapshots() {
        let content = "\
lockfileVersion: '9.0'
packages:
  lodash@4.17.20:
    resolution: {integrity: sha512-x}
  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-y}
snapshots:
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
";
        let deps = parse_pnpm_lock(content);
        assert!(deps.contains(&ResolvedDep {
            name: "lodash".into(),
            version: "4.17.20".into(),
            dev: false
        }));
        assert!(deps.contains(&ResolvedDep {
            name: "@scope/pkg".into(),
            version: "1.2.3".into(),
            dev: false
        }));
        assert!(deps.contains(&ResolvedDep {
            name: "react-dom".into(),
            version: "18.2.0".into(),
            dev: false
        }));
    }

    #[test]
    fn npm_lock_v3_packages() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "root", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.20" },
    "node_modules/@scope/pkg": { "version": "1.2.3", "dev": true },
    "node_modules/a/node_modules/b": { "version": "2.0.0" }
  }
}"#;
        let deps = parse_npm_lock(content);
        assert!(deps.contains(&ResolvedDep {
            name: "lodash".into(),
            version: "4.17.20".into(),
            dev: false
        }));
        assert!(deps.contains(&ResolvedDep {
            name: "@scope/pkg".into(),
            version: "1.2.3".into(),
            dev: true
        }));
        assert!(deps.contains(&ResolvedDep {
            name: "b".into(),
            version: "2.0.0".into(),
            dev: false
        }));
        assert!(!deps.iter().any(|d| d.name == "root"));
    }

    #[test]
    fn yarn_lock_classic() {
        let content = "\
# yarn lockfile v1
lodash@^4.17.0:
  version \"4.17.20\"
  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz\"

\"@scope/pkg@^1.0.0\", \"@scope/pkg@^1.2.0\":
  version \"1.2.3\"
";
        let deps = parse_yarn_lock(content);
        assert!(deps.contains(&ResolvedDep {
            name: "lodash".into(),
            version: "4.17.20".into(),
            dev: false
        }));
        assert!(deps.contains(&ResolvedDep {
            name: "@scope/pkg".into(),
            version: "1.2.3".into(),
            dev: false
        }));
    }

    #[test]
    fn yarn_lock_berry() {
        let content = "\
\"lodash@npm:^4.17.0\":
  version: 4.17.20
  resolution: \"lodash@npm:4.17.20\"
";
        let deps = parse_yarn_lock(content);
        assert!(deps.contains(&ResolvedDep {
            name: "lodash".into(),
            version: "4.17.20".into(),
            dev: false
        }));
    }

    #[test]
    fn bun_lock_text() {
        let content = r#"{
  "lockfileVersion": 1,
  "packages": {
    "lodash": ["lodash@4.17.20", "", {}, "sha512-x"],
    "@scope/pkg": ["@scope/pkg@1.2.3", {}, "sha512-y"]
  }
}"#;
        let deps = parse_bun_lock(content);
        assert!(deps.contains(&ResolvedDep {
            name: "lodash".into(),
            version: "4.17.20".into(),
            dev: false
        }));
        assert!(deps.contains(&ResolvedDep {
            name: "@scope/pkg".into(),
            version: "1.2.3".into(),
            dev: false
        }));
    }

    #[test]
    fn dedupe_prefers_production() {
        let deduped = dedupe(vec![
            ResolvedDep {
                name: "a".into(),
                version: "1.0.0".into(),
                dev: true,
            },
            ResolvedDep {
                name: "a".into(),
                version: "1.0.0".into(),
                dev: false,
            },
        ]);
        assert_eq!(deduped.len(), 1);
        assert!(!deduped[0].dev);
    }

    #[test]
    fn empty_or_garbage_degrades() {
        assert!(parse_npm_lock("{ broken").is_empty());
        assert!(parse_bun_lock("{ broken").is_empty());
        assert!(parse_yarn_lock("").is_empty());
    }
}
