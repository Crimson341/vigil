//! Scan orchestration: discover → resolve → query (parallel) → render.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use colored::Colorize;
use rayon::prelude::*;
use serde::Serialize;

use crate::lockfile::{self, ResolvedDep};
use crate::osv::{self, AdvisorySeverity, OsvClient, OsvError};
use crate::pkg;

/// Exit code reserved for network failures.
pub const NETWORK_EXIT_CODE: i32 = 7;

/// Output format for the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Colored, human-readable report.
    Human,
    /// Machine-readable JSON envelope.
    Json,
    /// SARIF 2.1.0 (for the GitHub Security tab and other code-scanning UIs).
    Sarif,
}

/// One vulnerable dependency: a verified match between an installed version and
/// a published advisory.
#[derive(Debug, Clone, Serialize)]
pub struct AdvisoryFinding {
    pub package: String,
    pub version: String,
    pub severity: AdvisorySeverity,
    pub osv_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
    pub advisory_url: String,
    pub direct: bool,
    pub dev: bool,
}

/// The `--format json` envelope.
#[derive(Debug, Clone, Serialize)]
pub struct ScanOutput {
    pub schema_version: &'static str,
    pub advisory_findings: Vec<AdvisoryFinding>,
    pub packages_scanned: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockfile: Option<String>,
    pub used_range_fallback: bool,
    pub query_errors: usize,
}

/// Scan options resolved from the CLI.
pub struct Options {
    pub root: PathBuf,
    pub format: OutputFormat,
    pub prod_only: bool,
    pub fail_on: Option<AdvisorySeverity>,
    pub refresh: bool,
    pub max_age_secs: u64,
    pub quiet: bool,
    pub sarif_file: Option<PathBuf>,
}

/// Run the scan. Returns the process exit code.
#[must_use]
pub fn run(opts: &Options) -> i32 {
    let declared = collect_declared(&opts.root);

    let (mut deps, lockfile_label, used_range_fallback) =
        match lockfile::resolve_lockfile(&opts.root) {
            Some(res) => (res.deps, Some(res.kind.label().to_string()), false),
            None => (range_fallback_deps(&declared), None, true),
        };

    if deps.is_empty() {
        return fail(
            "no resolvable dependencies found (no lockfile and no parseable package.json ranges)",
            2,
            opts.format,
        );
    }

    annotate_dev(&mut deps, &declared, opts.prod_only);
    if opts.prod_only {
        deps.retain(|d| !d.dev);
    }
    deps.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    deps.dedup();
    let packages_scanned = deps.len();

    let client = OsvClient::new(
        osv::default_cache_dir(&opts.root),
        std::time::Duration::from_secs(opts.max_age_secs),
        !opts.refresh,
    );
    let query_errors = AtomicUsize::new(0);
    let findings: Vec<AdvisoryFinding> = deps
        .par_iter()
        .flat_map(|dep| match client.query_npm(&dep.name, &dep.version) {
            Ok(vulns) => vulns
                .into_iter()
                .map(|vuln| build_finding(&vuln, dep, &declared.direct))
                .collect::<Vec<_>>(),
            Err(err) => {
                if matches!(err, OsvError::Network(_)) {
                    query_errors.fetch_add(1, Ordering::Relaxed);
                }
                Vec::new()
            }
        })
        .collect();
    let query_errors = query_errors.into_inner();

    if query_errors == packages_scanned && findings.is_empty() {
        return fail(
            "could not reach OSV.dev for any package (offline with a cold cache). \
             Run once online to warm the cache under .vigil/osv, or retry when connected.",
            NETWORK_EXIT_CODE,
            opts.format,
        );
    }

    let mut findings = findings;
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.package.cmp(&b.package))
            .then(a.version.cmp(&b.version))
            .then(a.osv_id.cmp(&b.osv_id))
    });
    findings.dedup_by(|a, b| a.package == b.package && a.version == b.version && a.osv_id == b.osv_id);

    let output = ScanOutput {
        schema_version: "1",
        advisory_findings: findings,
        packages_scanned,
        lockfile: lockfile_label,
        used_range_fallback,
        query_errors,
    };

    if let Some(path) = &opts.sarif_file
        && let Err(err) = std::fs::write(path, render_sarif(&output))
    {
        return fail(
            &format!("failed to write SARIF to {}: {err}", path.display()),
            2,
            opts.format,
        );
    }
    match opts.format {
        OutputFormat::Json => println!("{}", render_json(&output)),
        OutputFormat::Sarif => println!("{}", render_sarif(&output)),
        OutputFormat::Human => print_human(&output, opts.quiet),
    }

    exit_code(&output, opts.fail_on)
}

/// Declared dependency context collected from root + workspace `package.json`.
struct Declared {
    direct: std::collections::HashSet<String>,
    prod: std::collections::HashSet<String>,
    dev: std::collections::HashSet<String>,
    ranges: Vec<(String, String, bool)>,
}

fn collect_declared(root: &Path) -> Declared {
    use std::collections::HashSet;
    let mut direct = HashSet::new();
    let mut prod = HashSet::new();
    let mut dev = HashSet::new();
    let mut ranges = Vec::new();

    let mut manifests = vec![root.to_path_buf()];
    manifests.extend(pkg::discover_workspace_dirs(root));

    for dir in manifests {
        let Some(pkg) = pkg::PackageJson::load(&dir.join("package.json")) else {
            continue;
        };
        for (map, is_dev) in [
            (pkg.dependencies.as_ref(), false),
            (pkg.optional_dependencies.as_ref(), false),
            (pkg.peer_dependencies.as_ref(), false),
            (pkg.dev_dependencies.as_ref(), true),
        ] {
            let Some(map) = map else { continue };
            for (name, range) in map {
                direct.insert(name.clone());
                if is_dev {
                    dev.insert(name.clone());
                } else {
                    prod.insert(name.clone());
                }
                ranges.push((name.clone(), range.clone(), is_dev));
            }
        }
    }

    Declared {
        direct,
        prod,
        dev,
        ranges,
    }
}

fn annotate_dev(deps: &mut [ResolvedDep], declared: &Declared, prod_only: bool) {
    if !prod_only {
        return;
    }
    for dep in deps.iter_mut() {
        if dep.dev {
            continue;
        }
        if declared.dev.contains(&dep.name) && !declared.prod.contains(&dep.name) {
            dep.dev = true;
        }
    }
}

fn range_fallback_deps(declared: &Declared) -> Vec<ResolvedDep> {
    let mut deps = Vec::new();
    for (name, range, dev) in &declared.ranges {
        if let Some(version) = coerce_range_to_version(range) {
            deps.push(ResolvedDep {
                name: name.clone(),
                version,
                dev: *dev,
            });
        }
    }
    deps
}

/// Coerce a `package.json` range (`^1.2.3`, `~1.2.3`, `>=1.2.3`, `1.2.3`) into a
/// concrete version for the no-lockfile fallback.
#[must_use]
fn coerce_range_to_version(range: &str) -> Option<String> {
    let trimmed = range.trim();
    if trimmed.contains(':') || trimmed.contains('/') {
        return None;
    }
    let token = trimmed
        .split([' ', '|'])
        .next()
        .unwrap_or(trimmed)
        .trim_start_matches(['^', '~', '>', '<', '=', 'v', ' ']);
    if token.is_empty() {
        return None;
    }
    semver::Version::parse(token).ok().map(|v| v.to_string())
}

fn build_finding(
    vuln: &osv::OsvVuln,
    dep: &ResolvedDep,
    direct_names: &std::collections::HashSet<String>,
) -> AdvisoryFinding {
    AdvisoryFinding {
        package: dep.name.clone(),
        version: dep.version.clone(),
        severity: vuln.severity(),
        osv_id: vuln.id.clone(),
        cve_ids: vuln.cve_ids(),
        summary: vuln.summary.clone(),
        fixed_version: vuln.fixed_version(&dep.name, &dep.version),
        advisory_url: format!("https://osv.dev/vulnerability/{}", vuln.id),
        direct: direct_names.contains(&dep.name),
        dev: dep.dev,
    }
}

#[must_use]
fn exit_code(output: &ScanOutput, fail_on: Option<AdvisorySeverity>) -> i32 {
    if let Some(threshold) = fail_on
        && output
            .advisory_findings
            .iter()
            .any(|f| f.severity >= threshold)
    {
        return 1;
    }
    0
}

/// Print an error (JSON or plain) and return the exit code.
fn fail(message: &str, code: i32, format: OutputFormat) -> i32 {
    if format == OutputFormat::Json {
        let err = serde_json::json!({ "error": true, "message": message, "exit_code": code });
        println!("{err}");
    } else {
        eprintln!("{} {message}", "error:".red().bold());
    }
    code
}

#[must_use]
fn render_json(output: &ScanOutput) -> String {
    serde_json::to_string_pretty(output).unwrap_or_else(|_| "{}".to_string())
}

#[must_use]
fn sarif_level(severity: AdvisorySeverity) -> &'static str {
    match severity {
        AdvisorySeverity::Critical | AdvisorySeverity::High => "error",
        AdvisorySeverity::Medium => "warning",
        AdvisorySeverity::Low | AdvisorySeverity::Unknown => "note",
    }
}

#[must_use]
fn fnv_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

#[must_use]
fn render_sarif(output: &ScanOutput) -> String {
    use std::collections::HashSet;
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut seen_rules: HashSet<String> = HashSet::new();
    for finding in &output.advisory_findings {
        if !seen_rules.insert(finding.osv_id.clone()) {
            continue;
        }
        let mut tags: Vec<String> = vec!["security".to_string(), "dependency".to_string()];
        tags.extend(
            finding
                .cve_ids
                .iter()
                .map(|cve| format!("external/cve/{}", cve.to_lowercase())),
        );
        tags.push(format!("external/osv/{}", finding.osv_id.to_lowercase()));
        rules.push(serde_json::json!({
            "id": finding.osv_id,
            "shortDescription": {
                "text": finding.summary.clone().unwrap_or_else(|| {
                    format!("Known vulnerability in {}", finding.package)
                })
            },
            "helpUri": finding.advisory_url,
            "properties": { "tags": tags },
            "defaultConfiguration": { "level": sarif_level(finding.severity) }
        }));
    }

    let results: Vec<serde_json::Value> = output
        .advisory_findings
        .iter()
        .map(|finding| {
            let fix = finding
                .fixed_version
                .as_deref()
                .map_or_else(|| "no published fix".to_string(), |v| format!("upgrade to {v}"));
            let message = format!(
                "{}@{} is affected by {} ({}): {}",
                finding.package, finding.version, finding.osv_id, finding.severity.label(), fix,
            );
            let fp = fnv_hex(&format!(
                "{}@{}:{}",
                finding.package, finding.version, finding.osv_id
            ));
            serde_json::json!({
                "ruleId": finding.osv_id,
                "level": sarif_level(finding.severity),
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": { "artifactLocation": { "uri": "package.json" } }
                }],
                "partialFingerprints": { "vigil/v1": fp }
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "vigil",
                "informationUri": "https://github.com/Crimson341/vigil",
                "rules": rules
            }},
            "results": results
        }]
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

#[must_use]
fn color_severity(severity: AdvisorySeverity) -> colored::ColoredString {
    match severity {
        AdvisorySeverity::Critical => "critical".bright_red().bold(),
        AdvisorySeverity::High => "high".red().bold(),
        AdvisorySeverity::Medium => "medium".yellow(),
        AdvisorySeverity::Low => "low".cyan(),
        AdvisorySeverity::Unknown => "unknown".dimmed(),
    }
}

fn print_human(output: &ScanOutput, quiet: bool) {
    let lockfile = output
        .lockfile
        .as_deref()
        .unwrap_or("package.json ranges (no lockfile)");

    if output.advisory_findings.is_empty() {
        println!(
            "{} No known vulnerabilities in {} package(s) ({}).",
            "✓".green().bold(),
            output.packages_scanned,
            lockfile,
        );
    } else {
        let mut critical = 0u32;
        let mut high = 0u32;
        let mut other = 0u32;
        for f in &output.advisory_findings {
            match f.severity {
                AdvisorySeverity::Critical => critical += 1,
                AdvisorySeverity::High => high += 1,
                _ => other += 1,
            }
        }
        println!(
            "{} {} known vulnerabilit{} across {} package(s) ({}):",
            "!".red().bold(),
            output.advisory_findings.len(),
            if output.advisory_findings.len() == 1 { "y" } else { "ies" },
            output.packages_scanned,
            lockfile,
        );
        println!("  {critical} critical · {high} high · {other} other\n");
        for f in &output.advisory_findings {
            let scope = if f.direct { "direct" } else { "transitive" };
            let dev = if f.dev { ", dev" } else { "" };
            println!(
                "  [{}] {}@{} ({scope}{dev})",
                color_severity(f.severity),
                f.package.bold(),
                f.version,
            );
            if let Some(summary) = &f.summary {
                println!("      {summary}");
            }
            let ids = if f.cve_ids.is_empty() {
                f.osv_id.clone()
            } else {
                format!("{} ({})", f.osv_id, f.cve_ids.join(", "))
            };
            println!("      {ids}");
            match &f.fixed_version {
                Some(v) => println!("      {} {}", "fix:".green(), format!("upgrade to {v}").green()),
                None => println!("      {}", "fix: no published fix".dimmed()),
            }
            println!("      {}", f.advisory_url.dimmed());
            println!();
        }
    }

    if quiet {
        return;
    }
    if output.used_range_fallback {
        eprintln!(
            "{} No lockfile found; versions were coerced from package.json ranges. \
             A clean result is NOT a verified clean tree — commit a lockfile for exact matching.",
            "note:".yellow(),
        );
    }
    if output.query_errors > 0 {
        eprintln!(
            "{} {} package(s) could not be queried against OSV (network errors). \
             Those packages were NOT checked.",
            "note:".yellow(),
            output.query_errors,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: AdvisorySeverity, pkg: &str) -> AdvisoryFinding {
        AdvisoryFinding {
            package: pkg.to_string(),
            version: "1.0.0".to_string(),
            severity,
            osv_id: "GHSA-xxxx".to_string(),
            cve_ids: vec!["CVE-2021-1234".to_string()],
            summary: Some("Prototype pollution".to_string()),
            fixed_version: Some("1.0.1".to_string()),
            advisory_url: "https://osv.dev/vulnerability/GHSA-xxxx".to_string(),
            direct: true,
            dev: false,
        }
    }

    fn output_with(findings: Vec<AdvisoryFinding>) -> ScanOutput {
        ScanOutput {
            schema_version: "1",
            advisory_findings: findings,
            packages_scanned: 10,
            lockfile: Some("pnpm-lock.yaml".to_string()),
            used_range_fallback: false,
            query_errors: 0,
        }
    }

    #[test]
    fn coerce_range_strips_operators() {
        assert_eq!(coerce_range_to_version("^1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(coerce_range_to_version(">=1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(coerce_range_to_version("1.2.3"), Some("1.2.3".to_string()));
    }

    #[test]
    fn coerce_range_rejects_non_concrete() {
        assert_eq!(coerce_range_to_version("*"), None);
        assert_eq!(coerce_range_to_version("workspace:*"), None);
    }

    #[test]
    fn exit_code_fails_only_at_threshold() {
        let out = output_with(vec![finding(AdvisorySeverity::Medium, "a")]);
        assert_eq!(exit_code(&out, Some(AdvisorySeverity::High)), 0);
        assert_eq!(exit_code(&out, Some(AdvisorySeverity::Medium)), 1);
    }

    #[test]
    fn exit_code_advisory_is_success() {
        let out = output_with(vec![finding(AdvisorySeverity::Critical, "a")]);
        assert_eq!(exit_code(&out, None), 0);
    }

    #[test]
    fn sarif_level_maps_severity() {
        assert_eq!(sarif_level(AdvisorySeverity::Critical), "error");
        assert_eq!(sarif_level(AdvisorySeverity::Medium), "warning");
        assert_eq!(sarif_level(AdvisorySeverity::Low), "note");
    }

    #[test]
    fn sarif_carries_cve_tag_and_fingerprint() {
        let out = output_with(vec![finding(AdvisorySeverity::High, "lodash")]);
        let sarif = render_sarif(&out);
        assert!(sarif.contains("external/cve/cve-2021-1234"));
        assert!(sarif.contains("vigil/v1"));
        assert!(sarif.contains("\"level\": \"error\""));
    }

    #[test]
    fn json_carries_schema_and_findings() {
        let out = output_with(vec![finding(AdvisorySeverity::High, "lodash")]);
        let json = render_json(&out);
        assert!(json.contains("\"schema_version\": \"1\""));
        assert!(json.contains("\"package\": \"lodash\""));
        assert!(json.contains("\"fixed_version\": \"1.0.1\""));
    }
}
