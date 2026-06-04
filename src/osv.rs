//! OSV.dev client, response model, on-disk cache, and severity/fix-version
//! derivation.
//!
//! OSV.dev (<https://osv.dev>) aggregates the GitHub Advisory Database, the npm
//! advisory feed, and many ecosystem sources behind one open API with no key.
//! We use the single-package `query` endpoint, which performs the affected
//! version-range matching **server-side**: a `{package, version}` query returns
//! only the advisories that actually affect that installed version. This keeps
//! the client honest (no local semver-range reimplementation for the match
//! decision) and lets the on-disk cache key on `(name, version)`.
//!
//! `semver` is used only to choose the *lowest fix version above the installed
//! one* for the upgrade hint — never for the match decision itself.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default OSV API base. Overridable via `VIGIL_OSV_API_URL` for staging/tests.
const DEFAULT_OSV_API_URL: &str = "https://api.osv.dev";

/// A normalized advisory severity tier, derived from the OSV record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdvisorySeverity {
    /// Severity could not be determined from the record.
    Unknown,
    /// CVSS < 4.0 / GHSA "LOW".
    Low,
    /// CVSS 4.0–6.9 / GHSA "MODERATE".
    Medium,
    /// CVSS 7.0–8.9 / GHSA "HIGH".
    High,
    /// CVSS ≥ 9.0 / GHSA "CRITICAL".
    Critical,
}

impl AdvisorySeverity {
    /// Lowercase label for human/CI output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Parse a GHSA-style label (`LOW`/`MODERATE`/`HIGH`/`CRITICAL`).
    #[must_use]
    fn from_ghsa_label(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "LOW" => Self::Low,
            "MODERATE" | "MEDIUM" => Self::Medium,
            "HIGH" => Self::High,
            "CRITICAL" => Self::Critical,
            _ => Self::Unknown,
        }
    }

    /// Map a numeric CVSS base score to a tier.
    #[must_use]
    fn from_cvss_score(score: f64) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::Unknown
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvSeverityEntry {
    #[serde(default)]
    score: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvEvent {
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvPackage {
    #[serde(default)]
    name: Option<String>,
}

/// A single OSV vulnerability record (subset of the schema vigil consumes).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OsvVuln {
    /// Primary OSV id (often a `GHSA-…` id for npm).
    pub id: String,
    /// One-line summary, when present.
    #[serde(default)]
    pub summary: Option<String>,
    /// Cross-ids: CVE-… and other database ids.
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverityEntry>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    database_specific: serde_json::Value,
}

impl OsvVuln {
    /// The advisory's severity tier. Prefers the GHSA `database_specific.severity`
    /// label, then a numeric CVSS score parsed from the severity vector's trailing
    /// score if present; otherwise `Unknown`.
    #[must_use]
    pub fn severity(&self) -> AdvisorySeverity {
        if let Some(label) = self
            .database_specific
            .get("severity")
            .and_then(serde_json::Value::as_str)
        {
            let tier = AdvisorySeverity::from_ghsa_label(label);
            if tier != AdvisorySeverity::Unknown {
                return tier;
            }
        }
        for entry in &self.severity {
            if let Some(score) = entry.score.as_deref().and_then(parse_cvss_score) {
                let tier = AdvisorySeverity::from_cvss_score(score);
                if tier != AdvisorySeverity::Unknown {
                    return tier;
                }
            }
        }
        AdvisorySeverity::Unknown
    }

    /// CVE ids cross-referenced by this advisory.
    #[must_use]
    pub fn cve_ids(&self) -> Vec<String> {
        self.aliases
            .iter()
            .filter(|a| a.starts_with("CVE-"))
            .cloned()
            .collect()
    }

    /// The lowest fix version strictly greater than `installed` for `name`,
    /// across this advisory's affected ranges. `None` when no fix is published or
    /// versions are unparseable as semver (the advisory is still reported).
    #[must_use]
    pub fn fixed_version(&self, name: &str, installed: &str) -> Option<String> {
        let installed_sv = semver::Version::parse(installed).ok();
        let mut best: Option<(Option<semver::Version>, String)> = None;
        for affected in &self.affected {
            let matches_name = affected
                .package
                .as_ref()
                .and_then(|p| p.name.as_deref())
                .is_none_or(|n| n == name);
            if !matches_name {
                continue;
            }
            for range in &affected.ranges {
                for event in &range.events {
                    let Some(fixed) = event.fixed.as_deref() else {
                        continue;
                    };
                    let fixed_sv = semver::Version::parse(fixed).ok();
                    if let (Some(inst), Some(fx)) = (installed_sv.as_ref(), fixed_sv.as_ref())
                        && fx <= inst
                    {
                        continue;
                    }
                    let is_lower = match (&best, &fixed_sv) {
                        (None, _) | (Some((None, _)), Some(_)) => true,
                        (Some((Some(best_sv), _)), Some(fx)) => fx < best_sv,
                        _ => false,
                    };
                    if is_lower {
                        best = Some((fixed_sv, fixed.to_string()));
                    }
                }
            }
        }
        best.map(|(_, s)| s)
    }
}

/// Parse a numeric CVSS base score. CVSS vector strings carry no base score and
/// yield `None` (severity then falls back to the GHSA label or `Unknown`).
#[must_use]
fn parse_cvss_score(score: &str) -> Option<f64> {
    score.trim().parse::<f64>().ok()
}

/// Errors from an OSV lookup.
#[derive(Debug)]
pub enum OsvError {
    /// The request could not be completed (offline, DNS, TLS, timeout, non-2xx).
    Network(String),
    /// The response body could not be decoded as an OSV query result.
    Decode(String),
}

impl std::fmt::Display for OsvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(m) => write!(f, "OSV request failed: {m}"),
            Self::Decode(m) => write!(f, "OSV response decode failed: {m}"),
        }
    }
}

impl std::error::Error for OsvError {}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CacheRecord {
    fetched_unix: u64,
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

/// OSV client with an on-disk cache. Construct once per run and reuse the agent.
pub struct OsvClient {
    agent: ureq::Agent,
    api_url: String,
    cache_dir: PathBuf,
    max_age: Duration,
    use_cache: bool,
}

impl OsvClient {
    /// Build a client. `cache_dir` is typically `<root>/.vigil/osv`.
    #[must_use]
    pub fn new(cache_dir: PathBuf, max_age: Duration, use_cache: bool) -> Self {
        let api_url = std::env::var("VIGIL_OSV_API_URL").map_or_else(
            |_| DEFAULT_OSV_API_URL.to_string(),
            |u| u.trim_end_matches('/').to_string(),
        );
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_global(Some(Duration::from_secs(20)))
            .build()
            .into();
        Self {
            agent,
            api_url,
            cache_dir,
            max_age,
            use_cache,
        }
    }

    /// Query advisories affecting `name@version` in the npm ecosystem.
    ///
    /// # Errors
    ///
    /// Returns [`OsvError`] when the request cannot be completed or decoded.
    pub fn query_npm(&self, name: &str, version: &str) -> Result<Vec<OsvVuln>, OsvError> {
        if self.use_cache
            && let Some(record) = self.read_cache(name, version)
        {
            return Ok(record);
        }
        let vulns = self.fetch_npm(name, version)?;
        self.write_cache(name, version, &vulns);
        Ok(vulns)
    }

    fn fetch_npm(&self, name: &str, version: &str) -> Result<Vec<OsvVuln>, OsvError> {
        let url = format!("{}/v1/query", self.api_url);
        let body = serde_json::json!({
            "version": version,
            "package": { "ecosystem": "npm", "name": name },
        });
        let mut response = self
            .agent
            .post(&url)
            .send_json(&body)
            .map_err(|e| OsvError::Network(e.to_string()))?;
        let parsed: OsvQueryResponse = response
            .body_mut()
            .read_json()
            .map_err(|e| OsvError::Decode(e.to_string()))?;
        Ok(parsed.vulns)
    }

    fn cache_path(&self, name: &str, version: &str) -> PathBuf {
        let safe = name.replace(['/', '\\'], "__");
        self.cache_dir.join(format!("{safe}@{version}.json"))
    }

    fn read_cache(&self, name: &str, version: &str) -> Option<Vec<OsvVuln>> {
        let path = self.cache_path(name, version);
        let content = std::fs::read_to_string(&path).ok()?;
        let record: CacheRecord = serde_json::from_str(&content).ok()?;
        let now = now_unix();
        if now.saturating_sub(record.fetched_unix) <= self.max_age.as_secs() {
            Some(record.vulns)
        } else {
            None
        }
    }

    fn write_cache(&self, name: &str, version: &str, vulns: &[OsvVuln]) {
        let _ = std::fs::create_dir_all(&self.cache_dir);
        let record = CacheRecord {
            fetched_unix: now_unix(),
            vulns: vulns.to_vec(),
        };
        if let Ok(json) = serde_json::to_string(&record) {
            let _ = std::fs::write(self.cache_path(name, version), json);
        }
    }
}

#[must_use]
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Default cache directory under a project root (`<root>/.vigil/osv`).
#[must_use]
pub fn default_cache_dir(root: &Path) -> PathBuf {
    root.join(".vigil").join("osv")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln_from(json: serde_json::Value) -> OsvVuln {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn severity_prefers_ghsa_label() {
        let v = vuln_from(serde_json::json!({
            "id": "GHSA-x",
            "database_specific": { "severity": "HIGH" }
        }));
        assert_eq!(v.severity(), AdvisorySeverity::High);
    }

    #[test]
    fn severity_falls_back_to_numeric_cvss() {
        let v = vuln_from(serde_json::json!({
            "id": "GHSA-x",
            "severity": [{ "type": "CVSS_V3", "score": "9.8" }]
        }));
        assert_eq!(v.severity(), AdvisorySeverity::Critical);
    }

    #[test]
    fn severity_unknown_when_only_vector() {
        let v = vuln_from(serde_json::json!({
            "id": "GHSA-x",
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]
        }));
        assert_eq!(v.severity(), AdvisorySeverity::Unknown);
    }

    #[test]
    fn cve_ids_filters_aliases() {
        let v = vuln_from(serde_json::json!({
            "id": "GHSA-x",
            "aliases": ["CVE-2021-1234", "GHSA-yyyy"]
        }));
        assert_eq!(v.cve_ids(), vec!["CVE-2021-1234"]);
    }

    #[test]
    fn fixed_version_picks_lowest_above_installed() {
        let v = vuln_from(serde_json::json!({
            "id": "GHSA-x",
            "affected": [{
                "package": { "ecosystem": "npm", "name": "lodash" },
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{ "introduced": "0" }, { "fixed": "4.17.21" }]
                }]
            }]
        }));
        assert_eq!(
            v.fixed_version("lodash", "4.17.20"),
            Some("4.17.21".to_string())
        );
    }

    #[test]
    fn fixed_version_ignores_fixes_at_or_below_installed() {
        let v = vuln_from(serde_json::json!({
            "id": "GHSA-x",
            "affected": [{
                "package": { "name": "lodash" },
                "ranges": [{ "events": [{ "fixed": "4.17.10" }, { "fixed": "4.17.21" }] }]
            }]
        }));
        assert_eq!(
            v.fixed_version("lodash", "4.17.15"),
            Some("4.17.21".to_string())
        );
    }

    #[test]
    fn fixed_version_none_when_no_fix() {
        let v = vuln_from(serde_json::json!({
            "id": "GHSA-x",
            "affected": [{ "package": { "name": "lodash" }, "ranges": [] }]
        }));
        assert_eq!(v.fixed_version("lodash", "4.17.20"), None);
    }

    #[test]
    fn cache_path_escapes_scope() {
        let client = OsvClient::new(PathBuf::from("/tmp/c"), Duration::ZERO, true);
        let p = client.cache_path("@scope/pkg", "1.2.3");
        assert!(p.to_string_lossy().ends_with("@scope__pkg@1.2.3.json"));
    }
}
