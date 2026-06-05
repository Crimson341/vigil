//! Secret scanning: find API keys, tokens, and private keys committed to source.
//!
//! Walks the project (honoring `.gitignore`, skipping `node_modules`, `.git`,
//! `.vigil`, and binary/large files) and matches each line against a curated set
//! of high-signal patterns. The patterns are deliberately specific (provider
//! prefixes with exact lengths) to keep false positives low — a secret scanner
//! that cries wolf gets turned off.

use std::path::Path;
use std::sync::OnceLock;

use colored::Colorize;
use regex::Regex;
use serde::Serialize;

use crate::scan::OutputFormat;

/// One detected secret.
#[derive(Debug, Clone, Serialize)]
pub struct SecretFinding {
    /// Project-relative file path.
    pub path: String,
    /// 1-based line number.
    pub line: usize,
    /// Which rule matched (e.g. `aws-access-key`).
    pub rule: String,
    /// Human description of the secret type.
    pub description: String,
    /// The matched value with the middle masked.
    pub redacted: String,
}

/// A compiled detection rule.
struct Rule {
    id: &'static str,
    description: &'static str,
    regex: Regex,
}

/// The curated rule set, compiled once.
fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let raw: &[(&str, &str, &str)] = &[
            (
                "aws-access-key",
                "AWS access key ID",
                r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b",
            ),
            (
                "github-token",
                "GitHub token",
                r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b",
            ),
            (
                "github-fine-grained-pat",
                "GitHub fine-grained PAT",
                r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
            ),
            (
                "stripe-secret-key",
                "Stripe secret key",
                r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b",
            ),
            (
                "slack-token",
                "Slack token",
                r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
            ),
            (
                "google-api-key",
                "Google API key",
                r"\bAIza[0-9A-Za-z_\-]{35}\b",
            ),
            (
                "openai-key",
                "OpenAI API key",
                r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            ),
            (
                "npm-token",
                "npm access token",
                r"\bnpm_[A-Za-z0-9]{36}\b",
            ),
            (
                "private-key",
                "Private key block",
                r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----",
            ),
            (
                "slack-webhook",
                "Slack webhook URL",
                r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]+",
            ),
        ];
        raw.iter()
            .filter_map(|(id, description, pattern)| {
                Regex::new(pattern).ok().map(|regex| Rule {
                    id,
                    description,
                    regex,
                })
            })
            .collect()
    })
}

/// Values that look like placeholders rather than real secrets.
fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.contains("${")
        || value.contains("process.env")
        || lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("changeme")
        || lower.contains("your-")
        || lower.contains("xxxxxxxx")
}

/// Mask the middle of a secret, keeping a few chars on each end for recognition.
fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 12 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// Scan every eligible file under `root` for secrets.
#[must_use]
pub fn scan_dir(root: &Path) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false) // we want dotfiles like .env, but skip dirs below
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !matches!(
                name.as_ref(),
                "node_modules" | ".git" | ".vigil" | "target" | "dist" | "build" | ".next"
            )
        })
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if skip_file(path) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue; // binary / non-UTF-8
        };
        if content.len() > 2_000_000 {
            continue; // skip very large files
        }
        scan_text(&content, path, root, &mut findings);
    }
    findings.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    findings
}

/// Whether a file should be skipped by name/extension (lockfiles, maps, etc.).
fn skip_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if matches!(
        name.as_str(),
        "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock" | "bun.lock" | "bun.lockb"
    ) {
        return true;
    }
    let skip_ext = [
        ".min.js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff",
        ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".lock",
    ];
    skip_ext.iter().any(|ext| name.ends_with(ext))
}

/// Scan one file's text, pushing findings (path relativized to `root`).
fn scan_text(content: &str, path: &Path, root: &Path, findings: &mut Vec<SecretFinding>) {
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    for (idx, line) in content.lines().enumerate() {
        if line.len() > 4_000 {
            continue; // minified / data lines
        }
        for rule in rules() {
            if let Some(m) = rule.regex.find(line) {
                let value = m.as_str();
                if is_placeholder(value) {
                    continue;
                }
                findings.push(SecretFinding {
                    path: rel.clone(),
                    line: idx + 1,
                    rule: rule.id.to_string(),
                    description: rule.description.to_string(),
                    redacted: redact(value),
                });
            }
        }
    }
}

/// Run `vigil secrets`: scan, render, and return the exit code (1 if any secret
/// is found — a committed secret should fail CI).
#[must_use]
pub fn run(root: &Path, format: OutputFormat) -> i32 {
    let findings = scan_dir(root);
    match format {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "schema_version": "1",
                "secret_findings": findings,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        }
        // SARIF is not yet supported for secrets; fall back to human.
        OutputFormat::Human | OutputFormat::Sarif => print_human(&findings),
    }
    i32::from(!findings.is_empty())
}

fn print_human(findings: &[SecretFinding]) {
    if findings.is_empty() {
        println!("{} No secrets found.", "✓".green().bold());
        return;
    }
    println!(
        "{} {} possible secret(s) found:\n",
        "!".red().bold(),
        findings.len()
    );
    for f in findings {
        println!(
            "  {} {}:{}",
            f.description.red().bold(),
            f.path,
            f.line
        );
        println!("      {}", f.redacted.dimmed());
    }
    println!(
        "\n{}",
        "Rotate any real secret immediately — removing it from the latest commit is not enough."
            .yellow()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_str(s: &str) -> Vec<SecretFinding> {
        let mut f = Vec::new();
        scan_text(s, Path::new("/proj/file.ts"), Path::new("/proj"), &mut f);
        f
    }

    #[test]
    fn detects_aws_key() {
        let f = scan_str("const k = \"AKIAIOSFODNN7EXAMPLE\";");
        // EXAMPLE placeholder is filtered, so use a non-placeholder one:
        assert!(f.is_empty());
        // AWS access keys are AKIA + exactly 16 chars.
        let f = scan_str("const k = \"AKIA1234567890ABCDEF\";");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "aws-access-key");
        assert!(f[0].redacted.contains('…'));
    }

    #[test]
    fn detects_github_token() {
        let tok = format!("ghp_{}", "a".repeat(36));
        let f = scan_str(&format!("token = {tok}"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "github-token");
    }

    #[test]
    fn detects_stripe_and_private_key() {
        let f = scan_str(&format!("sk_live_{}", "a".repeat(30)));
        assert_eq!(f[0].rule, "stripe-secret-key");
        let f = scan_str("-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(f[0].rule, "private-key");
    }

    #[test]
    fn ignores_env_references_and_placeholders() {
        assert!(scan_str("key = process.env.GITHUB_TOKEN").is_empty());
        assert!(scan_str("key = \"AKIAIOSFODNN7EXAMPLE\"").is_empty());
        let tok = format!("ghp_{}", "x".repeat(36));
        assert!(scan_str(&format!("token = {tok} // your-example")).is_empty());
    }

    #[test]
    fn redact_masks_middle() {
        assert_eq!(redact("abcdefghijklmnop"), "abcd…mnop");
        assert_eq!(redact("short"), "*****");
    }
}
