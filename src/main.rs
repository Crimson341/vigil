//! vigil — a fast, opinionated dependency vulnerability scanner for JavaScript
//! and TypeScript projects, powered by [OSV.dev](https://osv.dev).
//!
//! It resolves the exact installed versions from your lockfile and matches them
//! against the OSV.dev advisory database (GitHub Advisories + npm feed + CVEs),
//! reporting known vulnerabilities with a real severity and a known fix version.

mod graph;
mod ignore;
mod lockfile;
mod osv;
mod pkg;
mod scan;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use osv::AdvisorySeverity;
use scan::OutputFormat;

/// Scan installed dependencies for known vulnerabilities (via OSV.dev).
#[derive(Parser)]
#[command(name = "vigil", version, about, long_about = None)]
struct Cli {
    /// Project root to scan (must contain a lockfile or package.json).
    #[arg(long, default_value = ".")]
    path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Scan only production-relevant packages (exclude dev-only dependencies).
    #[arg(long)]
    prod_only: bool,

    /// Exit 1 when any finding is at or above this severity (advisory otherwise).
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,

    /// Bypass the on-disk cache and re-query OSV.dev for every package.
    #[arg(long)]
    refresh: bool,

    /// Reuse cached OSV results younger than this many seconds.
    #[arg(long, default_value_t = 86_400)]
    max_age: u64,

    /// Also write a SARIF report to this path.
    #[arg(long)]
    sarif_file: Option<PathBuf>,

    /// Suppress the informational blind-spot notes on stderr.
    #[arg(long, short)]
    quiet: bool,

    /// Ignore the `.vigilignore` file and report every finding.
    #[arg(long)]
    no_ignore: bool,
}

/// Severity gate for `--fail-on`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum FailOn {
    Low,
    Medium,
    High,
    Critical,
}

impl FailOn {
    fn to_severity(self) -> AdvisorySeverity {
        match self {
            Self::Low => AdvisorySeverity::Low,
            Self::Medium => AdvisorySeverity::Medium,
            Self::High => AdvisorySeverity::High,
            Self::Critical => AdvisorySeverity::Critical,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = scan::run(&scan::Options {
        root: cli.path,
        format: cli.format,
        prod_only: cli.prod_only,
        fail_on: cli.fail_on.map(FailOn::to_severity),
        refresh: cli.refresh,
        max_age_secs: cli.max_age,
        quiet: cli.quiet,
        sarif_file: cli.sarif_file,
        no_ignore: cli.no_ignore,
    });
    ExitCode::from(u8::try_from(code).unwrap_or(2))
}
