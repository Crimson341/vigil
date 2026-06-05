//! Suppressions via a `.vigilignore` file.
//!
//! A single unfixable transitive advisory would otherwise block every CI run, so
//! teams need a way to mute a finding — with a reason, and ideally an expiry so
//! the suppression is revisited rather than forgotten. `.vigilignore` is a
//! gitignore-style line list:
//!
//! ```text
//! # one matcher per line: an OSV id, a CVE id, or a bare package name
//! GHSA-xxxx-yyyy-zzzz                      # free-text reason after a hash
//! CVE-2021-23337   until=2026-12-31        # expires; re-surfaces after this date
//! lodash                                   # mute every advisory for a package
//! ```
//!
//! An expired suppression stops muting (the finding returns) and is reported as
//! stale, as is an active suppression that matched nothing (a dead ignore worth
//! removing).

use std::path::Path;

use crate::scan::AdvisoryFinding;

/// One parsed `.vigilignore` entry.
#[derive(Debug, Clone)]
pub struct IgnoreRule {
    /// What to match: an OSV id, a CVE id, or a package name.
    pub matcher: String,
    /// Optional human reason (text after `#`).
    pub reason: Option<String>,
    /// Optional expiry as days-from-epoch; `None` means never expires.
    pub until_days: Option<i64>,
    /// The raw expiry string, for messages.
    pub until_raw: Option<String>,
}

impl IgnoreRule {
    fn is_expired(&self, today_days: i64) -> bool {
        self.until_days.is_some_and(|d| d < today_days)
    }

    fn matches(&self, f: &AdvisoryFinding) -> bool {
        self.matcher == f.osv_id
            || self.matcher == f.package
            || f.cve_ids.iter().any(|c| c == &self.matcher)
    }
}

/// A loaded set of suppression rules.
#[derive(Debug, Default)]
pub struct IgnoreSet {
    rules: Vec<IgnoreRule>,
}

/// The result of applying suppressions to a finding set.
pub struct Evaluation {
    /// Findings that survived (not suppressed).
    pub kept: Vec<AdvisoryFinding>,
    /// How many findings were muted by an active rule.
    pub suppressed: usize,
    /// Stale-suppression warnings (expired, or matched nothing).
    pub stale: Vec<String>,
}

impl IgnoreSet {
    /// Load `.vigilignore` from `root`. Missing file → empty set.
    #[must_use]
    pub fn load(root: &Path) -> Self {
        let Ok(content) = std::fs::read_to_string(root.join(".vigilignore")) else {
            return Self::default();
        };
        let rules = content.lines().filter_map(parse_line).collect();
        Self { rules }
    }

    /// Apply suppressions. `today_days` is days-from-epoch (so expiry is testable).
    #[must_use]
    pub fn apply(&self, findings: Vec<AdvisoryFinding>, today_days: i64) -> Evaluation {
        let mut kept = Vec::new();
        let mut suppressed = 0usize;
        let mut matched = vec![false; self.rules.len()];

        for finding in findings {
            let active_hit = self.rules.iter().enumerate().find(|(_, r)| {
                r.matches(&finding) && !r.is_expired(today_days)
            });
            if let Some((idx, _)) = active_hit {
                matched[idx] = true;
                suppressed += 1;
            } else {
                // Record an expired-rule hit so we can flag it as stale.
                if let Some((idx, _)) = self
                    .rules
                    .iter()
                    .enumerate()
                    .find(|(_, r)| r.matches(&finding))
                {
                    matched[idx] = true;
                }
                kept.push(finding);
            }
        }

        let mut stale = Vec::new();
        for (idx, rule) in self.rules.iter().enumerate() {
            let reason = rule
                .reason
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default();
            if rule.is_expired(today_days) {
                stale.push(format!(
                    "ignore for '{}'{reason} expired on {} — it no longer suppresses",
                    rule.matcher,
                    rule.until_raw.as_deref().unwrap_or("?"),
                ));
            } else if !matched[idx] {
                stale.push(format!(
                    "ignore for '{}'{reason} matched nothing — safe to remove",
                    rule.matcher,
                ));
            }
        }

        Evaluation {
            kept,
            suppressed,
            stale,
        }
    }
}

/// Parse one `.vigilignore` line into a rule. `None` for blank/comment lines.
#[must_use]
fn parse_line(line: &str) -> Option<IgnoreRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // Split off a trailing `# reason`.
    let (directive, reason) = match line.split_once('#') {
        Some((d, r)) => (d.trim(), Some(r.trim().to_string())),
        None => (line, None),
    };
    let mut tokens = directive.split_whitespace();
    let matcher = tokens.next()?.to_string();
    let mut until_raw = None;
    let mut until_days = None;
    for tok in tokens {
        if let Some(date) = tok.strip_prefix("until=") {
            until_days = parse_iso_date(date);
            until_raw = Some(date.to_string());
        }
    }
    Some(IgnoreRule {
        matcher,
        reason: reason.filter(|r| !r.is_empty()),
        until_days,
        until_raw,
    })
}

/// Parse `YYYY-MM-DD` into days-from-epoch (1970-01-01). `None` if malformed.
#[must_use]
fn parse_iso_date(s: &str) -> Option<i64> {
    let mut parts = s.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Days from 1970-01-01 to the given civil date (Howard Hinnant's algorithm).
#[must_use]
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 }); // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Today as days-from-epoch, from the system clock.
#[must_use]
pub fn today_days() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs / 86_400) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::AdvisorySeverity;

    fn finding(osv: &str, pkg: &str, cves: &[&str]) -> AdvisoryFinding {
        AdvisoryFinding {
            package: pkg.to_string(),
            version: "1.0.0".to_string(),
            severity: AdvisorySeverity::High,
            osv_id: osv.to_string(),
            cve_ids: cves.iter().map(|s| (*s).to_string()).collect(),
            summary: None,
            fixed_version: None,
            advisory_url: String::new(),
            direct: true,
            dev: false,
            path: None,
        }
    }

    #[test]
    fn date_epoch_is_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
    }

    #[test]
    fn parse_line_with_reason_and_expiry() {
        let r = parse_line("CVE-2021-23337  until=2026-12-31  # no fix yet").unwrap();
        assert_eq!(r.matcher, "CVE-2021-23337");
        assert_eq!(r.reason.as_deref(), Some("no fix yet"));
        assert_eq!(r.until_days, Some(days_from_civil(2026, 12, 31)));
    }

    #[test]
    fn comment_and_blank_lines_skipped() {
        assert!(parse_line("   ").is_none());
        assert!(parse_line("# just a comment").is_none());
    }

    #[test]
    fn suppresses_by_osv_cve_and_package() {
        let rules = IgnoreSet {
            rules: vec![
                parse_line("GHSA-aaaa").unwrap(),
                parse_line("CVE-2021-1").unwrap(),
                parse_line("lodash").unwrap(),
            ],
        };
        let findings = vec![
            finding("GHSA-aaaa", "x", &[]),
            finding("GHSA-bbbb", "y", &["CVE-2021-1"]),
            finding("GHSA-cccc", "lodash", &[]),
            finding("GHSA-dddd", "kept", &[]),
        ];
        let ev = rules.apply(findings, today_days());
        assert_eq!(ev.suppressed, 3);
        assert_eq!(ev.kept.len(), 1);
        assert_eq!(ev.kept[0].package, "kept");
    }

    #[test]
    fn expired_rule_does_not_suppress_and_is_stale() {
        let rules = IgnoreSet {
            rules: vec![parse_line("GHSA-aaaa until=2000-01-01").unwrap()],
        };
        let ev = rules.apply(vec![finding("GHSA-aaaa", "x", &[])], today_days());
        assert_eq!(ev.suppressed, 0);
        assert_eq!(ev.kept.len(), 1);
        assert!(ev.stale.iter().any(|s| s.contains("expired")));
    }

    #[test]
    fn unused_rule_is_reported_stale() {
        let rules = IgnoreSet {
            rules: vec![parse_line("GHSA-nope").unwrap()],
        };
        let ev = rules.apply(vec![finding("GHSA-aaaa", "x", &[])], today_days());
        assert!(ev.stale.iter().any(|s| s.contains("matched nothing")));
    }
}
